#!/usr/bin/env python3
"""Run the E-B24 local qualification gate with real reversible effects."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import platform
import socket
import subprocess
import sys
import time
from contextlib import AsyncExitStack
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence


HERE = Path(__file__).resolve().parent
ARTIFACT = HERE.parents[1]
SOURCE = ARTIFACT / "src"
if str(SOURCE) not in sys.path:
    sys.path.insert(0, str(SOURCE))

from revocation_propagation.keycloak_gateway_gate import ReplayVector, load_frozen_workload  # noqa: E402
from revocation_propagation.real_effect_gate import (  # noqa: E402
    DurableReceiverStore,
    FilesystemEffectStore,
    PostgresDockerEffectStore,
    canonical_json,
    evaluate_local_gate,
    write_vector_allowlist,
)
from revocation_propagation.real_llm_mcp_harness import (  # noqa: E402
    _mcp_result_payload,
    _open_mcp_session,
)


POSTGRES_IMAGE = "pgvector/pgvector:0.8.0-pg17-bookworm"
POSTGRES_DIGEST = "sha256:40b404964359299eefdd5f8518facf1886c562848cf4de13b6eaf91cb70c2b87"
POSTGRES_CONTAINER = "revprop-e-b24-local-postgres"
POSTGRES_DATABASE = "e_b24_effects"
POSTGRES_USER = "e_b24"
POSTGRES_PASSWORD = "e-b24-local-password"
GATEWAY_ID = "e-b24-local-gateway"


@dataclass(frozen=True)
class GatewayProcess:
    process: subprocess.Popen[bytes]
    port: int
    log_handle: Any

    @property
    def endpoint(self) -> str:
        return f"http://127.0.0.1:{self.port}/mcp"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def docker(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *arguments],
        check=check,
        capture_output=True,
        text=True,
    )


def remove_container() -> None:
    docker("rm", "-f", POSTGRES_CONTAINER, check=False)


def start_postgres() -> dict[str, object]:
    remove_container()
    repo_digests = json.loads(
        docker("image", "inspect", "--format", "{{json .RepoDigests}}", POSTGRES_IMAGE).stdout
    )
    pinned = any(str(item).endswith(f"@{POSTGRES_DIGEST}") for item in repo_digests)
    if not pinned:
        raise RuntimeError(f"local image does not match pinned digest {POSTGRES_DIGEST}")
    docker(
        "run",
        "--detach",
        "--name",
        POSTGRES_CONTAINER,
        "--env",
        f"POSTGRES_DB={POSTGRES_DATABASE}",
        "--env",
        f"POSTGRES_USER={POSTGRES_USER}",
        "--env",
        f"POSTGRES_PASSWORD={POSTGRES_PASSWORD}",
        POSTGRES_IMAGE,
    )
    deadline = time.monotonic() + 45
    last = ""
    while time.monotonic() < deadline:
        ready = docker(
            "exec",
            POSTGRES_CONTAINER,
            "pg_isready",
            "--username",
            POSTGRES_USER,
            "--dbname",
            POSTGRES_DATABASE,
            check=False,
        )
        last = (ready.stdout + ready.stderr).strip()
        if ready.returncode == 0:
            return {
                "pinned_postgres_used": True,
                "image": POSTGRES_IMAGE,
                "image_digest": POSTGRES_DIGEST,
                "container": POSTGRES_CONTAINER,
                "ready_output": last,
            }
        time.sleep(0.25)
    raise TimeoutError(f"PostgreSQL did not become ready: {last}")


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def start_gateway(
    *,
    output_dir: Path,
    filesystem_root: Path,
    vector_allowlist: Path,
) -> GatewayProcess:
    port = free_port()
    log_path = output_dir / "gateway.log"
    log_handle = log_path.open("wb")
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(SOURCE) + (
        os.pathsep + environment["PYTHONPATH"] if environment.get("PYTHONPATH") else ""
    )
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "revocation_propagation.real_effect_gateway_server",
            "--gateway-id",
            GATEWAY_ID,
            "--port",
            str(port),
            "--state-db",
            str(output_dir / "gateway-state.sqlite3"),
            "--filesystem-root",
            str(filesystem_root),
            "--vector-allowlist",
            str(vector_allowlist),
            "--postgres-container",
            POSTGRES_CONTAINER,
            "--postgres-database",
            POSTGRES_DATABASE,
            "--postgres-user",
            POSTGRES_USER,
            "--postgres-password",
            POSTGRES_PASSWORD,
        ],
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        env=environment,
    )
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if process.poll() is not None:
            log_handle.flush()
            raise RuntimeError(
                f"E-B24 gateway exited during startup ({process.returncode}); see {log_path}"
            )
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return GatewayProcess(process=process, port=port, log_handle=log_handle)
        except OSError:
            time.sleep(0.05)
    process.terminate()
    process.wait(timeout=5)
    log_handle.close()
    raise TimeoutError("E-B24 gateway did not listen within 30 seconds")


def stop_gateway(gateway: GatewayProcess) -> None:
    if gateway.process.poll() is None:
        gateway.process.terminate()
        try:
            gateway.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            gateway.process.kill()
            gateway.process.wait(timeout=5)
    gateway.log_handle.close()


async def call_mcp(session: Any, tool: str, arguments: Mapping[str, object]) -> dict[str, object]:
    result = await session.call_tool(tool, dict(arguments))
    if result.isError:
        raise RuntimeError(f"MCP tool {tool} returned an error: {result.content}")
    return _mcp_result_payload(result)


def effect_oracles(
    *,
    filesystem: FilesystemEffectStore,
    postgres: PostgresDockerEffectStore,
    experiment_run: str,
    arm: str,
) -> dict[str, dict[str, object]]:
    return {
        "filesystem": filesystem.oracle(experiment_run=experiment_run, arm=arm),
        "postgres": postgres.oracle(experiment_run=experiment_run, arm=arm),
    }


async def replay_phase(
    *,
    session: Any,
    vectors: Sequence[ReplayVector],
    delegation_id: str,
    experiment_run: str,
    arm: str,
    trace_handle: Any,
) -> tuple[dict[str, object], list[dict[str, object]]]:
    rows: list[dict[str, object]] = []
    for index, vector in enumerate(vectors):
        started = time.perf_counter_ns()
        response = await call_mcp(
            session,
            "execute_effect",
            {
                "delegation_id": delegation_id,
                "experiment_run": experiment_run,
                "arm": arm,
                "vector_payload": vector.payload(),
            },
        )
        row = {
            "phase": experiment_run,
            "order": index,
            "vector_id": vector.vector_id,
            "service": vector.service,
            "gateway_id": vector.gateway_id,
            "allowed": bool(response["allowed"]),
            "effect_committed": bool(
                isinstance(response.get("effect"), dict)
                and response["effect"].get("committed")
            ),
            "decision_id": response["decision_id"],
            "latency_ms": (time.perf_counter_ns() - started) / 1_000_000.0,
        }
        rows.append(row)
        trace_handle.write(canonical_json(row) + "\n")
        trace_handle.flush()
    return {
        "allowed": sum(int(row["allowed"]) for row in rows),
        "denied": sum(int(not row["allowed"]) for row in rows),
        "reported_effect_commits": sum(int(row["effect_committed"]) for row in rows),
    }, rows


async def run_gate(
    *,
    output_dir: Path,
    workload_root: Path,
) -> dict[str, object]:
    vectors, manifest = load_frozen_workload(workload_root)
    vector_allowlist = output_dir / "frozen-vector-allowlist.json"
    allowlist_manifest = write_vector_allowlist(vector_allowlist, list(vectors))
    filesystem_root = output_dir / "filesystem-effects"
    filesystem = FilesystemEffectStore(filesystem_root)
    postgres = PostgresDockerEffectStore(
        container=POSTGRES_CONTAINER,
        database=POSTGRES_DATABASE,
        user=POSTGRES_USER,
        password=POSTGRES_PASSWORD,
    )
    postgres.ensure_schema()
    gateway = start_gateway(
        output_dir=output_dir,
        filesystem_root=filesystem_root,
        vector_allowlist=vector_allowlist,
    )
    infrastructure = {
        "pinned_postgres_used": True,
        "gateway_process_isolation": gateway.process.pid != os.getpid(),
        "harness_pid": os.getpid(),
        "gateway_pid": gateway.process.pid,
        "gateway_endpoint": gateway.endpoint,
        "hostname": platform.node(),
        "platform": platform.platform(),
    }
    expected = {
        "filesystem": sorted(vector.vector_id for vector in vectors if vector.service == "filesystem"),
        "postgres": sorted(vector.vector_id for vector in vectors if vector.service == "postgres"),
    }
    phases: dict[str, dict[str, object]] = {}
    receiver_evidence: dict[str, object] = {}
    replay_rows: dict[str, list[dict[str, object]]] = {}
    trace_path = output_dir / "replay.jsonl"
    try:
        async with AsyncExitStack() as stack:
            session = await _open_mcp_session(stack, gateway.endpoint)
            with trace_path.open("w", encoding="utf-8") as trace_handle:
                active_counts, active_rows = await replay_phase(
                    session=session,
                    vectors=vectors,
                    delegation_id="e-b24-active-delegation",
                    experiment_run="active",
                    arm="local",
                    trace_handle=trace_handle,
                )
                active_oracles = effect_oracles(
                    filesystem=filesystem,
                    postgres=postgres,
                    experiment_run="active",
                    arm="local",
                )
                phases["active"] = {
                    **active_counts,
                    "filesystem_effects": active_oracles["filesystem"]["count"],
                    "postgres_effects": active_oracles["postgres"]["count"],
                    "filesystem_vector_match": active_oracles["filesystem"]["vector_ids"]
                    == expected["filesystem"],
                    "postgres_vector_match": active_oracles["postgres"]["vector_ids"]
                    == expected["postgres"],
                    "oracles": active_oracles,
                }
                replay_rows["active"] = active_rows

                revoked_receiver_path = output_dir / "receiver-revoked.sqlite3"
                revoked_receiver = DurableReceiverStore(revoked_receiver_path)
                revoked_receiver.persist_event(
                    jti="e-b24-local-revoked-jti",
                    delegation_id="e-b24-revoked-delegation",
                    event_id="e-b24-local-revoked-event",
                    channel="local-durable-receiver",
                    sequence=1,
                    encoded_set="synthetic-local-qualification-set-revoked",
                )

                async def apply_revoked(payload: dict[str, object]) -> Mapping[str, object]:
                    return await call_mcp(session, "apply_revocation", payload)

                await revoked_receiver.handoff_once_async(
                    "e-b24-local-revoked-jti", apply_revoked
                )
                revoked_counts, revoked_rows = await replay_phase(
                    session=session,
                    vectors=vectors,
                    delegation_id="e-b24-revoked-delegation",
                    experiment_run="revoked",
                    arm="local",
                    trace_handle=trace_handle,
                )
                revoked_oracles = effect_oracles(
                    filesystem=filesystem,
                    postgres=postgres,
                    experiment_run="revoked",
                    arm="local",
                )
                phases["revoked"] = {
                    **revoked_counts,
                    "filesystem_effects": revoked_oracles["filesystem"]["count"],
                    "postgres_effects": revoked_oracles["postgres"]["count"],
                    "filesystem_vector_match": revoked_oracles["filesystem"]["vector_ids"] == [],
                    "postgres_vector_match": revoked_oracles["postgres"]["vector_ids"] == [],
                    "oracles": revoked_oracles,
                }
                replay_rows["revoked"] = revoked_rows

                recovery_receiver_path = output_dir / "receiver-recovery.sqlite3"
                recovery_receiver = DurableReceiverStore(recovery_receiver_path)
                recovery_receiver.persist_event(
                    jti="e-b24-local-recovery-jti",
                    delegation_id="e-b24-recovery-delegation",
                    event_id="e-b24-local-recovery-event",
                    channel="local-durable-receiver",
                    sequence=1,
                    encoded_set="synthetic-local-qualification-set-recovery",
                )
                del recovery_receiver
                recovery_receiver = DurableReceiverStore(recovery_receiver_path)
                before_handoff = recovery_receiver.event("e-b24-local-recovery-jti")
                recovery_pre_counts, recovery_pre_rows = await replay_phase(
                    session=session,
                    vectors=vectors,
                    delegation_id="e-b24-recovery-delegation",
                    experiment_run="recovery_pre",
                    arm="local",
                    trace_handle=trace_handle,
                )
                recovery_pre_oracles = effect_oracles(
                    filesystem=filesystem,
                    postgres=postgres,
                    experiment_run="recovery_pre",
                    arm="local",
                )
                phases["recovery_pre"] = {
                    **recovery_pre_counts,
                    "filesystem_effects": recovery_pre_oracles["filesystem"]["count"],
                    "postgres_effects": recovery_pre_oracles["postgres"]["count"],
                    "filesystem_vector_match": recovery_pre_oracles["filesystem"]["vector_ids"]
                    == expected["filesystem"],
                    "postgres_vector_match": recovery_pre_oracles["postgres"]["vector_ids"]
                    == expected["postgres"],
                    "oracles": recovery_pre_oracles,
                }
                replay_rows["recovery_pre"] = recovery_pre_rows

                async def apply_recovery(payload: dict[str, object]) -> Mapping[str, object]:
                    return await call_mcp(session, "apply_revocation", payload)

                after_handoff = await recovery_receiver.handoff_once_async(
                    "e-b24-local-recovery-jti", apply_recovery
                )
                recovery_receiver = DurableReceiverStore(recovery_receiver_path)
                after_reopen = recovery_receiver.event("e-b24-local-recovery-jti")
                recovery_post_counts, recovery_post_rows = await replay_phase(
                    session=session,
                    vectors=vectors,
                    delegation_id="e-b24-recovery-delegation",
                    experiment_run="recovery_post",
                    arm="local",
                    trace_handle=trace_handle,
                )
                recovery_post_oracles = effect_oracles(
                    filesystem=filesystem,
                    postgres=postgres,
                    experiment_run="recovery_post",
                    arm="local",
                )
                phases["recovery_post"] = {
                    **recovery_post_counts,
                    "filesystem_effects": recovery_post_oracles["filesystem"]["count"],
                    "postgres_effects": recovery_post_oracles["postgres"]["count"],
                    "filesystem_vector_match": recovery_post_oracles["filesystem"]["vector_ids"] == [],
                    "postgres_vector_match": recovery_post_oracles["postgres"]["vector_ids"] == [],
                    "oracles": recovery_post_oracles,
                }
                replay_rows["recovery_post"] = recovery_post_rows
                receiver_evidence = {
                    "status_before_handoff": before_handoff["status"],
                    "reopen_verified": before_handoff["status"] == "PERSISTED",
                    "status_after_handoff": after_reopen["status"],
                    "receipt_id": after_reopen["receipt"]["receipt_id"],
                    "gateway_id": after_reopen["receipt"]["gateway_id"],
                    "receipt": after_reopen["receipt"],
                    "same_after_reopen": after_handoff["receipt"] == after_reopen["receipt"],
                }
    finally:
        stop_gateway(gateway)

    assertions = evaluate_local_gate(
        manifest=manifest,
        infrastructure=infrastructure,
        phases=phases,
        receiver=receiver_evidence,
    )
    assertions["oracle_vector_sets_match"] = all(
        bool(phase["filesystem_vector_match"] and phase["postgres_vector_match"])
        for phase in phases.values()
    )
    assertions["all_reported_effects_match_oracles"] = all(
        int(phase["reported_effect_commits"])
        == int(phase["filesystem_effects"]) + int(phase["postgres_effects"])
        for phase in phases.values()
    )
    assertions["receiver_receipt_survives_reopen"] = bool(receiver_evidence["same_after_reopen"])
    return {
        "design_version": "e-b24-design-v1",
        "verification_status": "LOCAL_QUALIFICATION",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "workload": manifest,
        "vector_allowlist": allowlist_manifest,
        "infrastructure": infrastructure,
        "phases": phases,
        "receiver": receiver_evidence,
        "assertions": assertions,
        "pass": all(assertions.values()),
        "trace_path": str(trace_path),
        "trace_sha256": sha256_file(trace_path),
        "replay_row_count": sum(len(rows) for rows in replay_rows.values()),
    }


def validation_markdown(summary: Mapping[str, object]) -> str:
    phases = summary["phases"]
    assertions = summary["assertions"]
    rows = [
        "# E-B24 Local Real-Effect Qualification",
        "",
        "## Material Passport",
        "",
        "- Origin Skill: academic-research-suite / experiment-agent",
        "- Origin Mode: run + deterministic validation",
        f"- Origin Date: {str(summary['generated_at'])[:10]}",
        "- Verification Status: VERIFIED LOCAL QUALIFICATION" if summary["pass"] else "- Verification Status: FAILED LOCAL QUALIFICATION",
        "- Version Label: e-b24-local-gate-v1",
        "",
        "## Decision",
        "",
        ("**The local gate passed.**" if summary["pass"] else "**The local gate failed.**"),
        "This result qualifies the real-effect mapper, persistent gateway, durable receiver, and effect oracles. It is not multi-host evidence and it does not repeat Keycloak PUSH/POLL.",
        "",
        "## Phase Results",
        "",
        "| Phase | Allowed | Denied | Filesystem effects | PostgreSQL effects |",
        "|---|---:|---:|---:|---:|",
    ]
    for name in ("active", "revoked", "recovery_pre", "recovery_post"):
        phase = phases[name]
        rows.append(
            f"| `{name}` | {phase['allowed']} | {phase['denied']} | "
            f"{phase['filesystem_effects']} | {phase['postgres_effects']} |"
        )
    rows.extend(["", "## Assertions", ""])
    rows.extend(f"- [{'x' if passed else ' '}] `{name}`" for name, passed in assertions.items())
    rows.extend(
        [
            "",
            "## Claim Boundary",
            "",
            "The 225 identities are an effect-carrying replay: E-B20 retained hashes and mutation labels, not raw mutation arguments. The local run proves reversible real effects and durable persisted-to-enforced state transitions on one host. It does not establish multi-host, multi-zone, production-incidence, or mechanism-superiority claims.",
            "",
        ]
    )
    return "\n".join(rows)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the E-B24 local real-effect gate.")
    parser.add_argument(
        "--workload-root",
        type=Path,
        default=ARTIFACT / "data" / "run_2026_07_14_e_b20_mcpmark_formal",
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=False)
    infrastructure: dict[str, object] | None = None
    try:
        infrastructure = start_postgres()
        summary = asyncio.run(
            run_gate(output_dir=output_dir, workload_root=args.workload_root.resolve())
        )
        summary["infrastructure"].update(infrastructure)
        summary_path = output_dir / "summary.json"
        summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        report_path = output_dir / "validation_report.md"
        report_path.write_text(validation_markdown(summary), encoding="utf-8")
        postgres = PostgresDockerEffectStore(
            container=POSTGRES_CONTAINER,
            database=POSTGRES_DATABASE,
            user=POSTGRES_USER,
            password=POSTGRES_PASSWORD,
        )
        exported = {
            phase: postgres.oracle(experiment_run=phase, arm="local")
            for phase in ("active", "revoked", "recovery_pre", "recovery_post")
        }
        export_path = output_dir / "postgres-effect-oracles.json"
        export_path.write_text(json.dumps(exported, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(canonical_json({"pass": summary["pass"], "output_dir": str(output_dir)}))
        if not summary["pass"]:
            raise SystemExit(1)
    finally:
        remove_container()


if __name__ == "__main__":
    main()

