"""Multi-process gateway/tool/log deployment harness for Paper B."""

from __future__ import annotations

import asyncio
import multiprocessing as mp
import queue
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .crypto import canonical_json_bytes, generate_keypair
from .events import create_revocation_event
from .integration_harness import (
    INTEGRATION_FAULT_SCENARIOS,
    INTEGRATION_PROTOCOL_PROFILES,
    FaultSchedule,
    GatewayState,
    IntegrationTrialResult,
    ToolState,
    _GatewayService,
    _IntegrationLogService,
    _ToolService,
    _fault_schedule,
    _protocol_request,
    _response_accepted,
    _response_rejected,
)
from .ledger_client import TransparencyLedger
from .local_end_to_end import (
    TransportCounters,
    _expect_dict,
    _request,
    _serve,
    _server_port,
    certificate_to_payload,
)
from .root_authority import RootAuthority, RootFederation


@dataclass
class MultiProcessTrialMetadata:
    process_count: int
    persistent_log_path: Path
    service_roles: tuple[str, ...]


async def run_multiprocess_gateway_tool_trial(
    *,
    seed: int,
    n_gateways: int,
    protocol_profile: str = "raw-http-json",
    fault_scenario: str = "push-drop-log-repair",
    tool_call_rate: float = 10.0,
    ttl: float = 60.0,
    task_duration: float = 60.0,
    push_delay: float = 0.05,
    poll_interval: float = 0.50,
    log_append_delay: float = 0.05,
    log_delay: float = 0.0,
    jitter: float = 0.20,
    partition_duration: float = 2.0,
    gateway_restart_at: float = 0.25,
    tool_name: str = "repo-write",
    root_count: int = 5,
    threshold: int = 3,
    output_dir: str | Path | None = None,
) -> tuple[IntegrationTrialResult, MultiProcessTrialMetadata]:
    """Run gateway/tool/log services as separate OS processes.

    The deployment remains local loopback, but each service role has separate
    process memory and the log process persists appended records to disk.
    """

    if protocol_profile not in INTEGRATION_PROTOCOL_PROFILES:
        raise ValueError(f"unknown protocol profile: {protocol_profile}")
    if fault_scenario not in INTEGRATION_FAULT_SCENARIOS:
        raise ValueError(f"unknown fault scenario: {fault_scenario}")
    if n_gateways <= 0:
        raise ValueError("n_gateways must be positive")

    output_path = Path(output_dir or Path.cwd() / "data" / "multiprocess_tmp")
    output_path.mkdir(parents=True, exist_ok=True)
    rate_label = str(tool_call_rate).replace(".", "p")
    persistent_log_path = output_path / (
        f"e_b14_persistent_log_seed_{seed}_n_{n_gateways}_rate_{rate_label}_"
        f"{protocol_profile}_{fault_scenario}.jsonl"
    )
    if persistent_log_path.exists():
        persistent_log_path.unlink()

    counters = TransportCounters()
    wall_start = time.perf_counter()
    issued_at = 0.0
    horizon = min(ttl, task_duration)
    issuer = generate_keypair()
    roots = [RootAuthority(f"root-{idx}", generate_keypair()) for idx in range(root_count)]
    federation = RootFederation({root.root_id: root.keypair.public for root in roots}, threshold=threshold)
    root_public_bytes = {root.root_id: root.keypair.public_bytes.hex() for root in roots}
    event = create_revocation_event(
        f"edge-e-b14-{seed}-{protocol_profile}-{fault_scenario}",
        issuer,
        epoch_id="epoch-multiprocess",
        issued_at=issued_at,
    )
    approvals = [root.approve_event(event) for root in roots[:threshold]]
    certificate = federation.certificate_for(event, approvals)
    event_payload = event.to_payload()
    certificate_payload = certificate_to_payload(certificate)

    processes: list[mp.Process] = []
    try:
        tool_process, tool_port = _start_process(
            _tool_process_main,
            tool_name,
        )
        processes.append(tool_process)
        log_process, log_port = _start_process(
            _log_process_main,
            str(persistent_log_path),
        )
        processes.append(log_process)

        gateway_ports: dict[str, int] = {}
        for index in range(n_gateways):
            gateway_id = f"gw-{index}"
            process, port = _start_process(
                _gateway_process_main,
                gateway_id,
                tool_port,
                issuer.public_bytes.hex(),
                root_public_bytes,
                threshold,
                protocol_profile,
            )
            processes.append(process)
            gateway_ports[gateway_id] = port

        append_response = await _request(
            log_port,
            {
                "type": "append",
                "event": event_payload,
                "certificate": certificate_payload,
                "appended_at": issued_at + log_append_delay,
                "sth_timestamp": issued_at + log_append_delay,
            },
            counters,
        )
        sth_payload = _expect_dict(append_response.get("sth"))

        schedules = tuple(
            _fault_schedule(
                gateway_id=f"gw-{index}",
                index=index,
                rng=__import__("random").Random(seed + index),
                fault_scenario=fault_scenario,
                horizon=horizon,
                push_delay=push_delay,
                poll_interval=poll_interval,
                log_append_delay=log_append_delay,
                log_delay=log_delay,
                jitter=jitter,
                partition_duration=partition_duration,
                gateway_restart_at=gateway_restart_at,
            )
            for index in range(n_gateways)
        )

        pre_revocation_allowed = 0
        sampled_revoked_calls_allowed = 0
        sampled_revoked_calls_rejected = 0
        post_repair_rejected = 0
        push_attempts = 0
        push_delivered = 0
        push_dropped = 0
        log_repairs = 0

        for schedule in schedules:
            port = gateway_ports[schedule.gateway_id]
            pre_response = await _request(
                port,
                _protocol_request(
                    protocol_profile,
                    request_id=f"{schedule.gateway_id}-pre",
                    gateway_id=schedule.gateway_id,
                    edge_id=event.edge_id,
                    tool_name=tool_name,
                    call_time=-0.001,
                ),
                counters,
            )
            if _response_accepted(protocol_profile, pre_response):
                pre_revocation_allowed += 1

            push_attempts += 1
            counters.push_attempts += 1
            if schedule.initial_via == "push":
                push_response = await _request(
                    port,
                    {
                        "type": "learn_revocation",
                        "via": "push",
                        "event": event_payload,
                        "certificate": certificate_payload,
                        "delivered_at": schedule.first_learn_at,
                    },
                    counters,
                )
                if push_response.get("accepted"):
                    push_delivered += 1
                    counters.push_delivered += 1
            else:
                push_dropped += 1
                counters.push_suppressed += 1

            for interval_index, (start, end) in enumerate(schedule.stale_intervals):
                if end <= 0.0 or start >= horizon:
                    continue
                call_time = min(horizon - 0.0001, max(start + 0.0001, (start + min(end, horizon)) / 2.0))
                response = await _request(
                    port,
                    _protocol_request(
                        protocol_profile,
                        request_id=f"{schedule.gateway_id}-stale-{interval_index}",
                        gateway_id=schedule.gateway_id,
                        edge_id=event.edge_id,
                        tool_name=tool_name,
                        call_time=call_time,
                    ),
                    counters,
                )
                if _response_accepted(protocol_profile, response):
                    sampled_revoked_calls_allowed += 1
                elif _response_rejected(protocol_profile, response):
                    sampled_revoked_calls_rejected += 1

            if schedule.restart_at is not None:
                await _request(port, {"type": "restart", "restart_at": schedule.restart_at}, counters)

            if schedule.repair_via is not None:
                latest = await _request(log_port, {"type": "latest"}, counters)
                await _request(
                    port,
                    {
                        "type": "learn_revocation",
                        "via": schedule.repair_via,
                        "event": latest.get("event"),
                        "certificate": latest.get("certificate"),
                        "sth": latest.get("sth", sth_payload),
                        "delivered_at": schedule.final_learn_at,
                    },
                    counters,
                )
                log_repairs += 1

            post_time = min(horizon, schedule.final_learn_at + 0.001)
            post_response = await _request(
                port,
                _protocol_request(
                    protocol_profile,
                    request_id=f"{schedule.gateway_id}-post",
                    gateway_id=schedule.gateway_id,
                    edge_id=event.edge_id,
                    tool_name=tool_name,
                    call_time=post_time,
                ),
                counters,
            )
            if _response_rejected(protocol_profile, post_response):
                sampled_revoked_calls_rejected += 1
                post_repair_rejected += 1
            elif _response_accepted(protocol_profile, post_response):
                sampled_revoked_calls_allowed += 1

        gateway_metrics = [
            _expect_dict((await _request(port, {"type": "metrics"}, counters)).get("state"))
            for port in gateway_ports.values()
        ]
        tool_metrics = _expect_dict((await _request(tool_port, {"type": "metrics"}, counters)).get("state"))

        result = IntegrationTrialResult(
            seed=seed,
            n_gateways=n_gateways,
            protocol_profile=protocol_profile,
            fault_scenario=fault_scenario,
            tool_name=tool_name,
            tool_call_rate=tool_call_rate,
            task_duration=task_duration,
            ttl=ttl,
            push_delay=push_delay,
            poll_interval=poll_interval,
            log_append_delay=log_append_delay,
            log_delay=log_delay,
            partition_duration=partition_duration,
            gateway_restart_at=gateway_restart_at,
            issued_at=issued_at,
            counters=counters,
            wall_time_seconds=time.perf_counter() - wall_start,
            root_count=root_count,
            root_threshold=threshold,
            event_payload_bytes=len(canonical_json_bytes(event_payload)),
            certificate_payload_bytes=len(canonical_json_bytes(certificate_payload)),
            gateway_ports=gateway_ports,
            tool_port=tool_port,
            log_port=log_port,
            stale_windows=tuple(schedule.stale_window(horizon) for schedule in schedules),
            final_learn_latencies=tuple(schedule.final_learn_at for schedule in schedules),
            recovery_latencies=tuple(
                schedule.recovery_latency for schedule in schedules if schedule.recovery_latency is not None
            ),
            pre_revocation_calls=n_gateways,
            pre_revocation_allowed=pre_revocation_allowed,
            sampled_revoked_calls_allowed=sampled_revoked_calls_allowed,
            sampled_revoked_calls_rejected=sampled_revoked_calls_rejected,
            post_repair_rejected=post_repair_rejected,
            protocol_calls=sum(int(metric.get("protocol_calls", 0)) for metric in gateway_metrics),
            protocol_schema_passes=sum(int(metric.get("protocol_schema_passes", 0)) for metric in gateway_metrics),
            forwarded_tool_calls=sum(int(metric.get("forwarded_tool_calls", 0)) for metric in gateway_metrics),
            gateway_restarts=sum(int(metric.get("restarts", 0)) for metric in gateway_metrics),
            push_attempts=push_attempts,
            push_delivered=push_delivered,
            push_dropped=push_dropped,
            log_repairs=log_repairs,
            signature_verified_events=sum(int(metric.get("signature_verified_events", 0)) for metric in gateway_metrics),
            certificate_verified_events=sum(
                int(metric.get("certificate_verified_events", 0)) for metric in gateway_metrics
            ),
            rejected_events=sum(int(metric.get("rejected_events", 0)) for metric in gateway_metrics),
            tool_accepted_invocations=int(tool_metrics.get("accepted_invocations", 0)),
            tool_rejected_invocations=int(tool_metrics.get("rejected_invocations", 0)),
            audit_evidence_gateways=sum(1 for metric in gateway_metrics if metric.get("audit_evidence_available")),
        )
        metadata = MultiProcessTrialMetadata(
            process_count=len(processes),
            persistent_log_path=persistent_log_path,
            service_roles=("tool", "log", "gateway"),
        )
        return result, metadata
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
        for process in processes:
            process.join(timeout=3)


def _start_process(target: object, *args: object) -> tuple[mp.Process, int]:
    port_queue: mp.Queue[int | str] = mp.Queue()
    process = mp.Process(target=target, args=(*args, port_queue), daemon=True)
    process.start()
    try:
        port_or_error = port_queue.get(timeout=10)
    except queue.Empty as exc:
        process.terminate()
        process.join(timeout=3)
        raise RuntimeError("service process did not report a port") from exc
    if isinstance(port_or_error, str):
        process.terminate()
        process.join(timeout=3)
        raise RuntimeError(port_or_error)
    return process, int(port_or_error)


def _tool_process_main(tool_name: str, port_queue: mp.Queue[int | str]) -> None:
    async def main() -> None:
        service = _ToolServiceWithMetrics(ToolState(tool_name=tool_name))
        server = await _serve(service.handle)
        port_queue.put(_server_port(server))
        await asyncio.Event().wait()

    _run_process_main(main, port_queue)


def _log_process_main(log_path: str, port_queue: mp.Queue[int | str]) -> None:
    async def main() -> None:
        service = _PersistentLogService(
            TransparencyLedger(generate_keypair(), log_id=f"multiprocess-log-{Path(log_path).stem}"),
            TransportCounters(),
            Path(log_path),
        )
        server = await _serve(service.handle)
        port_queue.put(_server_port(server))
        await asyncio.Event().wait()

    _run_process_main(main, port_queue)


def _gateway_process_main(
    gateway_id: str,
    tool_port: int,
    issuer_public_hex: str,
    root_public_hex: dict[str, str],
    threshold: int,
    protocol_profile: str,
    port_queue: mp.Queue[int | str],
) -> None:
    async def main() -> None:
        issuer_public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(issuer_public_hex))
        root_public_keys = {
            root_id: Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex))
            for root_id, public_hex in root_public_hex.items()
        }
        service = _GatewayService(
            GatewayState(gateway_id),
            tool_port=tool_port,
            issuer_public_key=issuer_public_key,
            federation=RootFederation(root_public_keys, threshold=threshold),
            counters=TransportCounters(),
            protocol_profile=protocol_profile,
        )
        server = await _serve(service.handle)
        port_queue.put(_server_port(server))
        await asyncio.Event().wait()

    _run_process_main(main, port_queue)


def _run_process_main(main: object, port_queue: mp.Queue[int | str]) -> None:
    try:
        asyncio.run(main())  # type: ignore[misc]
    except BaseException as exc:  # pragma: no cover - child-process diagnostics
        try:
            port_queue.put(f"{type(exc).__name__}: {exc}")
        finally:
            raise


class _ToolServiceWithMetrics(_ToolService):
    async def handle(self, request: dict[str, Any]) -> dict[str, Any]:
        if request.get("type") == "metrics":
            return {
                "ok": True,
                "state": {
                    "accepted_invocations": self.state.accepted_invocations,
                    "rejected_invocations": self.state.rejected_invocations,
                    "operation_count": len(self.state.operations),
                },
            }
        return await super().handle(request)


class _PersistentLogService(_IntegrationLogService):
    def __init__(self, ledger: TransparencyLedger, counters: TransportCounters, log_path: Path) -> None:
        super().__init__(ledger, counters)
        self.log_path = log_path

    async def handle(self, request: dict[str, Any]) -> dict[str, Any]:
        response = await super().handle(request)
        if request.get("type") == "append" and response.get("ok"):
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            with self.log_path.open("a") as handle:
                handle.write(
                    __import__("json").dumps(
                        {
                            "event": self.event_payload,
                            "certificate": self.certificate_payload,
                            "sth": self.sth_payload,
                        },
                        sort_keys=True,
                    )
                    + "\n"
                )
        if request.get("type") == "metrics":
            return {
                "ok": True,
                "state": {
                    "log_path": str(self.log_path),
                    "persistent_records": sum(1 for _ in self.log_path.open()) if self.log_path.exists() else 0,
                    "log_appends": self.counters.log_appends,
                    "log_polls": self.counters.log_polls,
                },
            }
        return response
