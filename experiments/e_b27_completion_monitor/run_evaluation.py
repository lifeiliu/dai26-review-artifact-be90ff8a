#!/usr/bin/env python3
"""Run the frozen E-B27 completion-monitor fault and scaling evaluation."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import platform
import shutil
import statistics
import sys
import tempfile
import time
from pathlib import Path
from typing import Callable, Iterable


HERE = Path(__file__).resolve().parent
ARTIFACT = HERE.parents[1]
SOURCE = ARTIFACT / "src"
if str(SOURCE) not in sys.path:
    sys.path.insert(0, str(SOURCE))

from revocation_propagation.completion_contract import (  # noqa: E402
    CONTRACT_VERSION,
    CompletionContractMonitor,
    EffectObservation,
)
from revocation_propagation.e_b24_receiver import (  # noqa: E402
    CloudReceiverStore,
    VerifiedSet,
)


PROTOCOL = ARTIFACT / "protocols/e-b27-completion-monitor-evaluation/protocol.md"
CONFIRMATORY_GATEWAYS = (1, 8, 32, 128, 512, 1024)
CONFIRMATORY_VECTORS = (1, 225, 1000, 5000, 10000)
CONFIRMATORY_TRIALS = 3
ASSESS_WARMUPS = 10
ASSESS_REPETITIONS = 100
BASE_NS = 1_700_000_000_000_000_000


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def event(jti: str) -> VerifiedSet:
    return VerifiedSet(
        jti=jti,
        issuer="https://anonymous.invalid/issuer",
        audience="anonymous/receiver",
        delegation_id=f"delegation-{jti}",
        event_id=jti,
        sequence=27,
        encoded_sha256=hashlib.sha256(jti.encode()).hexdigest(),
        key_id="e-b27-key",
        algorithm="RS256",
        issued_at=27,
    )


def targets(count: int) -> list[dict[str, str]]:
    return [
        {"gateway_id": f"g-{index:05d}", "gateway_url": f"https://g-{index:05d}.invalid"}
        for index in range(count)
    ]


def receipt(jti: str, gateway_id: str) -> dict[str, object]:
    return {
        "applied": True,
        "delegation_id": f"delegation-{jti}",
        "event_id": jti,
        "channel": "e-b27-local",
        "sequence": 27,
        "gateway_id": gateway_id,
        "receipt_id": f"receipt-{jti}-{gateway_id}",
        "applied_at_ns": BASE_NS,
    }


def observations(count: int, gateway_count: int, *, violation: str | None = None) -> Iterable[EffectObservation]:
    for index in range(count):
        vector_id = f"v-{index:06d}"
        yield EffectObservation(
            vector_id=vector_id,
            gateway_id=f"g-{index % gateway_count:05d}",
            decision_id=f"decision-{index:06d}",
            allowed=violation == "allowed" and index == 0,
            effect_committed=violation == "committed" and index == 0,
            observed_at_ns=BASE_NS + index + 1,
        )


def new_state(root: Path, name: str, *, gateway_count: int = 2, vector_count: int = 2):
    state_dir = root / name
    receiver = CloudReceiverStore(state_dir / "receiver.sqlite3")
    jti = f"e-b27-{name}"
    receiver.persist_event(event(jti), channel="e-b27-local", gateway_targets=targets(gateway_count))
    monitor = CompletionContractMonitor(
        receiver_store=receiver,
        monitor_db=state_dir / "monitor.sqlite3",
    )
    deadline = BASE_NS + vector_count + 10
    monitor.register_contract(
        jti=jti,
        event_id=jti,
        issuer_commit_id=f"issuer-{name}",
        transmitter_queue_id=f"queue-{name}",
        transport_ack_id=f"ack-{name}",
        expected_vector_ids=[f"v-{index:06d}" for index in range(vector_count)],
        window_start_ns=BASE_NS,
        window_deadline_ns=deadline,
    )
    return receiver, monitor, jti, deadline


def add_receipts(receiver: CloudReceiverStore, jti: str, count: int) -> None:
    for item in targets(count):
        gateway_id = item["gateway_id"]
        receiver.record_receipt(jti=jti, gateway_id=gateway_id, receipt=receipt(jti, gateway_id))


def add_effects(monitor: CompletionContractMonitor, jti: str, vector_count: int, gateway_count: int, *, violation: str | None = None) -> None:
    for observation in observations(vector_count, gateway_count, violation=violation):
        monitor.record_effect(jti=jti, observation=observation)


def verdict_fields(monitor: CompletionContractMonitor, jti: str) -> dict[str, object]:
    verdict = monitor.assess(jti)
    return {
        "status": verdict.status,
        "highest_stage": verdict.highest_stage,
        "complete_for_bound": verdict.complete_for_bound,
    }


def expected_verdict(monitor: CompletionContractMonitor, jti: str, status: str, stage: str) -> dict[str, object]:
    observed = verdict_fields(monitor, jti)
    expected = {
        "status": status,
        "highest_stage": stage,
        "complete_for_bound": status == "COMPLETE_FOR_BOUND",
    }
    if observed != expected:
        raise AssertionError(f"expected {expected}, observed {observed}")
    return observed


def expect_error(action: Callable[[], object], contains: str) -> str:
    try:
        action()
    except Exception as error:
        if contains not in str(error):
            raise AssertionError(f"expected error containing {contains!r}, observed {error!r}") from error
        return f"{type(error).__name__}: {error}"
    raise AssertionError(f"operation unexpectedly succeeded; expected {contains!r}")


def run_fault_matrix(root: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []

    def record(identifier: str, assertion: Callable[[], object]) -> None:
        try:
            evidence = assertion()
            rows.append({"id": identifier, "passed": True, "evidence": evidence})
        except Exception as error:
            rows.append({"id": identifier, "passed": False, "error": f"{type(error).__name__}: {error}"})

    def row_01():
        _, monitor, jti, _ = new_state(root, "f01")
        return expected_verdict(monitor, jti, "PARTIAL_ENFORCEMENT", "C3_RECEIVER_PERSISTED")

    def row_02():
        receiver, monitor, jti, _ = new_state(root, "f02")
        receiver.record_receipt(jti=jti, gateway_id="g-00000", receipt=receipt(jti, "g-00000"))
        return expected_verdict(monitor, jti, "PARTIAL_ENFORCEMENT", "C3_RECEIVER_PERSISTED")

    def row_03():
        receiver, monitor, jti, _ = new_state(root, "f03")
        add_receipts(receiver, jti, 2)
        return expected_verdict(monitor, jti, "IN_PROGRESS", "C4_GATEWAYS_ENFORCED")

    def row_04():
        receiver, monitor, jti, deadline = new_state(root, "f04")
        add_receipts(receiver, jti, 2)
        monitor.close_window(jti=jti, closed_at_ns=deadline)
        return expected_verdict(monitor, jti, "INDETERMINATE_MISSING_EFFECT_EVIDENCE", "C4_GATEWAYS_ENFORCED")

    def row_05():
        receiver, monitor, jti, deadline = new_state(root, "f05")
        add_receipts(receiver, jti, 2)
        add_effects(monitor, jti, 2, 2)
        monitor.close_window(jti=jti, closed_at_ns=deadline)
        return expected_verdict(monitor, jti, "COMPLETE_FOR_BOUND", "C5_EFFECTS_PREVENTED")

    def row_06():
        receiver, monitor, jti, deadline = new_state(root, "f06")
        add_receipts(receiver, jti, 2)
        add_effects(monitor, jti, 2, 2, violation="allowed")
        monitor.close_window(jti=jti, closed_at_ns=deadline)
        return expected_verdict(monitor, jti, "VIOLATED", "C4_GATEWAYS_ENFORCED")

    def row_07():
        receiver, monitor, jti, deadline = new_state(root, "f07")
        add_receipts(receiver, jti, 2)
        add_effects(monitor, jti, 2, 2, violation="committed")
        monitor.close_window(jti=jti, closed_at_ns=deadline)
        return expected_verdict(monitor, jti, "VIOLATED", "C4_GATEWAYS_ENFORCED")

    def row_08():
        receiver, monitor, jti, deadline = new_state(root, "f08")
        receiver.record_receipt(jti=jti, gateway_id="g-00000", receipt=receipt(jti, "g-00000"))
        add_effects(monitor, jti, 2, 2, violation="committed")
        monitor.close_window(jti=jti, closed_at_ns=deadline)
        before = expected_verdict(monitor, jti, "VIOLATED", "C3_RECEIVER_PERSISTED")
        receiver.record_receipt(jti=jti, gateway_id="g-00001", receipt=receipt(jti, "g-00001"))
        after = expected_verdict(monitor, jti, "VIOLATED", "C4_GATEWAYS_ENFORCED")
        return {"before_late_receipt": before, "after_late_receipt": after}

    def row_09():
        receiver, monitor, jti, _ = new_state(root, "f09")
        first_receipt = receipt(jti, "g-00000")
        receiver.record_receipt(jti=jti, gateway_id="g-00000", receipt=first_receipt)
        receiver.record_receipt(jti=jti, gateway_id="g-00000", receipt=first_receipt)
        observation = next(iter(observations(1, 2)))
        monitor.record_effect(jti=jti, observation=observation)
        monitor.record_effect(jti=jti, observation=observation)
        changed_receipt = {**first_receipt, "receipt_id": "replacement"}
        changed_effect = EffectObservation(**{**observation.__dict__, "decision_id": "replacement"})
        return {
            "identical_duplicates": "accepted",
            "conflicting_receipt": expect_error(
                lambda: receiver.record_receipt(jti=jti, gateway_id="g-00000", receipt=changed_receipt),
                "immutable",
            ),
            "conflicting_effect": expect_error(
                lambda: monitor.record_effect(jti=jti, observation=changed_effect),
                "immutable",
            ),
        }

    def row_10():
        receiver, monitor, jti, deadline = new_state(root, "f10")
        add_receipts(receiver, jti, 2)
        add_effects(monitor, jti, 2, 2)
        monitor.close_window(jti=jti, closed_at_ns=deadline)
        before = monitor.assess(jti).as_dict()
        reopened_receiver = CloudReceiverStore(receiver.path)
        reopened = CompletionContractMonitor(receiver_store=reopened_receiver, monitor_db=monitor.monitor_db)
        after = reopened.assess(jti).as_dict()
        if before != after:
            raise AssertionError("verdict changed across restart")
        return {"exact_verdict_persisted": True, "status": after["status"]}

    def row_11():
        receiver, monitor, jti, _ = new_state(root, "f11")
        contract_error = expect_error(
            lambda: monitor.register_contract(
                jti=jti,
                event_id=jti,
                issuer_commit_id="issuer-f11",
                transmitter_queue_id="queue-f11",
                transport_ack_id="ack-f11",
                expected_vector_ids=["changed"],
                window_start_ns=BASE_NS,
                window_deadline_ns=BASE_NS + 12,
            ),
            "immutable",
        )
        target_error = expect_error(
            lambda: receiver.persist_event(
                event(jti), channel="e-b27-local", gateway_targets=targets(3)
            ),
            "frozen gateway target set",
        )
        return {"contract_change": contract_error, "target_change": target_error}

    def row_12():
        _, monitor, jti, deadline = new_state(root, "f12")
        early = expect_error(
            lambda: monitor.close_window(jti=jti, closed_at_ns=deadline - 1),
            "frozen deadline",
        )
        future = expect_error(
            lambda: monitor.close_window(jti=jti, closed_at_ns=time.time_ns() + 1_000_000_000),
            "future",
        )
        return {"early_close": early, "future_close": future}

    def row_13():
        _, monitor, jti, deadline = new_state(root, "f13")
        outside_set = EffectObservation("outside", "g-00000", "outside-set", False, False, BASE_NS + 1)
        outside_time = EffectObservation("v-000000", "g-00000", "outside-time", False, False, deadline + 1)
        return {
            "outside_set": expect_error(lambda: monitor.record_effect(jti=jti, observation=outside_set), "frozen vector set"),
            "outside_time": expect_error(lambda: monitor.record_effect(jti=jti, observation=outside_time), "frozen time window"),
        }

    def row_14():
        receiver = CloudReceiverStore(root / "f14/receiver.sqlite3")
        jti = "e-b27-f14"
        receiver.persist_event(event(jti), channel="e-b27-local", gateway_targets=targets(1))
        monitor = CompletionContractMonitor(receiver_store=receiver, monitor_db=root / "f14/monitor.sqlite3")
        return expect_error(
            lambda: monitor.register_contract(
                jti=jti,
                event_id=jti,
                issuer_commit_id="",
                transmitter_queue_id="queue",
                transport_ack_id="ack",
                expected_vector_ids=["v-000000"],
                window_start_ns=BASE_NS,
                window_deadline_ns=BASE_NS + 1,
            ),
            "non-empty",
        )

    for identifier, assertion in (
        ("F01_PERSISTED_NO_RECEIPTS", row_01),
        ("F02_PARTIAL_RECEIPTS", row_02),
        ("F03_ALL_RECEIPTS_OPEN", row_03),
        ("F04_CLOSED_MISSING_EFFECTS", row_04),
        ("F05_COMPLETE_BOUND", row_05),
        ("F06_ALLOWED_VIOLATION", row_06),
        ("F07_COMMITTED_VIOLATION", row_07),
        ("F08_LATE_RECEIPT_STICKY_VIOLATION", row_08),
        ("F09_DUPLICATE_IMMUTABILITY", row_09),
        ("F10_RESTART_PERSISTENCE", row_10),
        ("F11_CONTRACT_TARGET_IMMUTABILITY", row_11),
        ("F12_WINDOW_CLOSURE_GUARD", row_12),
        ("F13_EFFECT_BOUND_GUARD", row_13),
        ("F14_C0_C2_EVIDENCE_REQUIRED", row_14),
    ):
        record(identifier, assertion)
    return rows


def percentile(values: list[float], probability: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int((len(ordered) - 1) * probability + 0.999999)))
    return ordered[index]


def state_bytes(*paths: Path) -> int:
    total = 0
    for path in paths:
        for candidate in (path, Path(f"{path}-wal"), Path(f"{path}-shm")):
            if candidate.exists():
                total += candidate.stat().st_size
    return total


def measure_configuration(root: Path, *, axis: str, gateway_count: int, vector_count: int, trial: int, assess_repetitions: int) -> dict[str, object]:
    state_dir = root / f"{axis}-g{gateway_count}-v{vector_count}-t{trial}"
    receiver_path = state_dir / "receiver.sqlite3"
    monitor_path = state_dir / "monitor.sqlite3"
    jti = f"scale-{axis}-g{gateway_count}-v{vector_count}-t{trial}"
    receiver = CloudReceiverStore(receiver_path)

    started = time.perf_counter_ns()
    receiver.persist_event(event(jti), channel="e-b27-local", gateway_targets=targets(gateway_count))
    persist_ns = time.perf_counter_ns() - started

    monitor = CompletionContractMonitor(receiver_store=receiver, monitor_db=monitor_path)
    deadline = BASE_NS + vector_count + 10
    started = time.perf_counter_ns()
    monitor.register_contract(
        jti=jti,
        event_id=jti,
        issuer_commit_id=f"issuer-{jti}",
        transmitter_queue_id=f"queue-{jti}",
        transport_ack_id=f"ack-{jti}",
        expected_vector_ids=[f"v-{index:06d}" for index in range(vector_count)],
        window_start_ns=BASE_NS,
        window_deadline_ns=deadline,
    )
    register_ns = time.perf_counter_ns() - started

    started = time.perf_counter_ns()
    add_receipts(receiver, jti, gateway_count)
    receipts_ns = time.perf_counter_ns() - started

    started = time.perf_counter_ns()
    add_effects(monitor, jti, vector_count, gateway_count)
    effects_ns = time.perf_counter_ns() - started

    started = time.perf_counter_ns()
    monitor.close_window(jti=jti, closed_at_ns=deadline)
    close_ns = time.perf_counter_ns() - started
    verdict = monitor.assess(jti)
    if verdict.status != "COMPLETE_FOR_BOUND":
        raise AssertionError(f"scaling state did not complete: {verdict.as_dict()}")

    for _ in range(ASSESS_WARMUPS):
        monitor.assess(jti)
    assess_us: list[float] = []
    for _ in range(assess_repetitions):
        started = time.perf_counter_ns()
        monitor.assess(jti)
        assess_us.append((time.perf_counter_ns() - started) / 1000.0)

    started = time.perf_counter_ns()
    reopened_receiver = CloudReceiverStore(receiver_path)
    reopened_monitor = CompletionContractMonitor(receiver_store=reopened_receiver, monitor_db=monitor_path)
    restart_verdict = reopened_monitor.assess(jti)
    restart_assess_ns = time.perf_counter_ns() - started
    if restart_verdict.as_dict() != verdict.as_dict():
        raise AssertionError("scaling verdict changed after restart")

    return {
        "axis": axis,
        "gateway_count": gateway_count,
        "vector_count": vector_count,
        "trial": trial,
        "persist_receiver_ms": persist_ns / 1e6,
        "register_contract_ms": register_ns / 1e6,
        "receipt_total_ms": receipts_ns / 1e6,
        "receipt_per_item_us": receipts_ns / gateway_count / 1000.0,
        "effect_total_ms": effects_ns / 1e6,
        "effect_per_item_us": effects_ns / vector_count / 1000.0,
        "close_window_ms": close_ns / 1e6,
        "assess_p50_us": percentile(assess_us, 0.50),
        "assess_p95_us": percentile(assess_us, 0.95),
        "assess_p99_us": percentile(assess_us, 0.99),
        "restart_assess_ms": restart_assess_ns / 1e6,
        "database_bytes": state_bytes(receiver_path, monitor_path),
        "status": verdict.status,
    }


def aggregate(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    keys = [
        "persist_receiver_ms", "register_contract_ms", "receipt_total_ms",
        "receipt_per_item_us", "effect_total_ms", "effect_per_item_us",
        "close_window_ms", "assess_p50_us", "assess_p95_us", "assess_p99_us",
        "restart_assess_ms", "database_bytes",
    ]
    groups: dict[tuple[str, int, int], list[dict[str, object]]] = {}
    for row in rows:
        group = (str(row["axis"]), int(row["gateway_count"]), int(row["vector_count"]))
        groups.setdefault(group, []).append(row)
    summaries: list[dict[str, object]] = []
    for (axis, gateway_count, vector_count), items in sorted(groups.items()):
        summary: dict[str, object] = {
            "axis": axis,
            "gateway_count": gateway_count,
            "vector_count": vector_count,
            "trials": len(items),
        }
        for key in keys:
            summary[f"median_{key}"] = statistics.median(float(item[key]) for item in items)
        summaries.append(summary)
    return summaries


def run(output: Path, mode: str) -> dict[str, object]:
    if output.exists():
        raise FileExistsError(f"refusing to overwrite run directory: {output}")
    output.mkdir(parents=True)
    scratch = Path(tempfile.mkdtemp(prefix="e-b27-state-", dir=output))
    try:
        if mode == "confirmatory":
            gateway_axis = CONFIRMATORY_GATEWAYS
            vector_axis = CONFIRMATORY_VECTORS
            trials = CONFIRMATORY_TRIALS
            assess_repetitions = ASSESS_REPETITIONS
        else:
            gateway_axis = (1, 2)
            vector_axis = (1, 10)
            trials = 1
            assess_repetitions = 5

        fault_rows = run_fault_matrix(scratch / "faults")
        scaling_rows: list[dict[str, object]] = []
        for gateway_count in gateway_axis:
            for trial in range(1, trials + 1):
                scaling_rows.append(measure_configuration(
                    scratch / "scaling", axis="gateways", gateway_count=gateway_count,
                    vector_count=225 if mode == "confirmatory" else 10,
                    trial=trial, assess_repetitions=assess_repetitions,
                ))
        for vector_count in vector_axis:
            for trial in range(1, trials + 1):
                scaling_rows.append(measure_configuration(
                    scratch / "scaling", axis="vectors", gateway_count=8 if mode == "confirmatory" else 2,
                    vector_count=vector_count, trial=trial,
                    assess_repetitions=assess_repetitions,
                ))

        with (output / "fault_matrix.json").open("w", encoding="utf-8") as handle:
            json.dump(fault_rows, handle, indent=2, sort_keys=True)
            handle.write("\n")
        with (output / "scaling_raw.csv").open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(scaling_rows[0]))
            writer.writeheader()
            writer.writerows(scaling_rows)

        summary = {
            "experiment": "E-B27",
            "mode": mode,
            "protocol_sha256": sha256(PROTOCOL),
            "monitor_version": CONTRACT_VERSION,
            "parameters": {
                "gateway_axis": list(gateway_axis),
                "vector_axis": list(vector_axis),
                "fixed_vectors_on_gateway_axis": 225 if mode == "confirmatory" else 10,
                "fixed_gateways_on_vector_axis": 8 if mode == "confirmatory" else 2,
                "trials": trials,
                "assess_warmups": ASSESS_WARMUPS,
                "assess_repetitions": assess_repetitions,
            },
            "environment": {
                "python": platform.python_version(),
                "os": platform.system(),
                "os_release": platform.release(),
                "machine": platform.machine(),
                "logical_cpu_count": os.cpu_count(),
            },
            "fault_matrix": {
                "passed": sum(bool(row["passed"]) for row in fault_rows),
                "total": len(fault_rows),
                "all_passed": all(bool(row["passed"]) for row in fault_rows),
            },
            "scaling": aggregate(scaling_rows),
        }
        with (output / "summary.json").open("w", encoding="utf-8") as handle:
            json.dump(summary, handle, indent=2, sort_keys=True)
            handle.write("\n")
        return summary
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--mode", choices=("smoke", "confirmatory"), required=True)
    arguments = parser.parse_args()
    summary = run(arguments.output.resolve(), arguments.mode)
    print(canonical_json({
        "output": str(arguments.output.resolve()),
        "mode": arguments.mode,
        "fault_matrix": summary["fault_matrix"],
        "scaling_configurations": len(summary["scaling"]),
    }))


if __name__ == "__main__":
    main()
