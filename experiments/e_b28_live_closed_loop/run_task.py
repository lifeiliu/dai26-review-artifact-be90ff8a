#!/usr/bin/env python3
"""Run one frozen E-B28 MCPMark task/arm/repetition without retry."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
ARTIFACT = HERE.parents[1]
SOURCE = ARTIFACT / "src"
if str(SOURCE) not in sys.path:
    sys.path.insert(0, str(SOURCE))

from revocation_propagation.completion_contract import (  # noqa: E402
    CompletionContractMonitor,
    EffectObservation,
)
from revocation_propagation.e_b24_receiver import (  # noqa: E402
    CloudReceiverStore,
    VerifiedSet,
)
from revocation_propagation.e_b28_mcpmark_instrumentation import (  # noqa: E402
    ARMS,
    MCPMARK_COMMIT,
    PROTOCOL_VERSION,
    install_e_b28_instrumentation,
    verify_frozen_checkout,
)


FROZEN_MODEL = "openai/gpt-4.1-mini"
FROZEN_BASE_URL = "https://openrouter.ai/api/v1"
FROZEN_TARGETS = (
    "filesystem/desktop/project_management",
    "filesystem/desktop_template/file_arrangement",
    "filesystem/file_context/duplicates_searching",
    "filesystem/file_context/uppercase",
    "postgres/chinook/customer_data_migration",
    "postgres/chinook/employee_hierarchy_management",
    "postgres/chinook/sales_and_music_charts",
    "postgres/employees/employee_project_tracking",
    "postgres/employees/executive_dashboard_automation",
    "postgres/sports/team_roster_management",
)


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sanitized_path(mcpmark_root: Path, current_path: str) -> str:
    candidates = [mcpmark_root / ".venv" / "bin"]
    candidates.extend(Path(item) for item in current_path.split(os.pathsep) if item)
    kept: list[str] = []
    for candidate in candidates:
        resolved = candidate.expanduser().resolve()
        text = str(resolved)
        if resolved.is_dir() and text not in kept:
            kept.append(text)
    return os.pathsep.join(kept)


def _events(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _audience(payload: dict[str, Any]) -> str:
    raw = payload.get("aud")
    if isinstance(raw, list):
        return str(raw[0]) if raw else ""
    return str(raw or "")


def _sequence(payload: dict[str, Any]) -> int:
    events = payload.get("events")
    event = next(iter(events.values())) if isinstance(events, dict) and events else {}
    raw = event.get("event_timestamp", payload.get("iat", 0)) if isinstance(event, dict) else 0
    return int(raw)


def _completion_monitor(
    *, output_dir: Path, arm: str, events: list[dict[str, Any]]
) -> dict[str, Any]:
    post = [
        event for event in events
        if event.get("event_type") == "tool_call" and event.get("phase") == "post_barrier"
    ]
    intervention = next(
        (event for event in events if event.get("event_type") == "revocation_intervention"),
        None,
    )
    if arm == "active_sanity":
        return {"status": "NOT_APPLICABLE_ACTIVE_SANITY", "post_barrier_vectors": 0}
    if intervention is None or intervention.get("intervention_valid") is not True:
        return {"status": "INVALID_INTERVENTION", "post_barrier_vectors": len(post)}
    if not post:
        return {
            "status": "NO_EXPOSURE",
            "post_barrier_vectors": 0,
            "event_jti": intervention.get("event_jti"),
            "note": "The unchanged agent made no later MCP call, so the nonempty-vector monitor was not instantiated.",
        }

    state = intervention["receiver_state"]
    attempt = state["matching_attempts"]["receiver-b"]
    payload = attempt["payload"]
    header = attempt["jws_header"]
    jti = str(attempt["jti"])
    sequence = _sequence(payload)
    verified = VerifiedSet(
        jti=jti,
        issuer=str(payload.get("iss", "")),
        audience=_audience(payload),
        delegation_id=str(attempt["session_id"]),
        event_id=jti,
        sequence=sequence,
        encoded_sha256=str(attempt["body_sha256"]),
        key_id=str(header.get("kid", "")),
        algorithm=str(header.get("alg", "")),
        issued_at=int(payload.get("iat", 0)),
    )
    state_dir = output_dir / "completion_monitor"
    receiver = CloudReceiverStore(state_dir / "receiver.sqlite3")
    gateway_id = "g-e-b28-agent-tool"
    receiver.persist_event(
        verified,
        channel="e-b28-keycloak-push",
        gateway_targets=[{"gateway_id": gateway_id, "gateway_url": "local://e-b28-agent-tool-gateway"}],
    )
    if bool(attempt["forwarded"]):
        receiver.record_receipt(
            jti=jti,
            gateway_id=gateway_id,
            receipt={
                "applied": True,
                "delegation_id": verified.delegation_id,
                "event_id": verified.event_id,
                "channel": "e-b28-keycloak-push",
                "sequence": sequence,
                "gateway_id": gateway_id,
                "receipt_id": f"receipt-{jti}-{gateway_id}",
                "applied_at_ns": int(intervention["barrier_completed_unix_ns"]),
            },
        )

    monitor = CompletionContractMonitor(
        receiver_store=receiver,
        monitor_db=state_dir / "monitor.sqlite3",
    )
    vector_ids = [f"{event['run_id']}:call-{event['call_sequence']}" for event in post]
    start = min(int(event["call_started_unix_ns"]) for event in post)
    deadline = max(int(event["call_ended_unix_ns"]) for event in post)
    monitor.register_contract(
        jti=jti,
        event_id=jti,
        issuer_commit_id=f"keycloak-event-{jti}",
        transmitter_queue_id=f"keycloak-ssf-stream-{jti}",
        transport_ack_id=f"logout-http-{intervention['logout_http_status']}-{jti}",
        expected_vector_ids=vector_ids,
        window_start_ns=start,
        window_deadline_ns=deadline,
    )
    for event, vector_id in zip(post, vector_ids, strict=True):
        monitor.record_effect(
            jti=jti,
            observation=EffectObservation(
                vector_id=vector_id,
                gateway_id=gateway_id,
                decision_id=f"decision-{vector_id}",
                allowed=bool(event["allowed"]),
                effect_committed=bool(event.get("effect_committed")),
                observed_at_ns=int(event["call_ended_unix_ns"]),
            ),
        )
    monitor.close_window(jti=jti, closed_at_ns=deadline)
    verdict = monitor.assess(jti).as_dict()
    verdict["post_barrier_vectors"] = len(post)
    verdict["construction"] = "retrospective bounded monitor over the actual post-barrier call population"
    return verdict


def _stop_reason(messages_path: Path) -> str:
    if not messages_path.exists():
        return "messages_missing"
    try:
        messages = json.loads(messages_path.read_text(encoding="utf-8"))
    except Exception:
        return "messages_unreadable"
    if not isinstance(messages, list) or not messages:
        return "no_messages"
    final = messages[-1]
    if isinstance(final, dict):
        role = str(final.get("role", "unknown"))
        content = final.get("content")
        has_tool = bool(final.get("tool_calls"))
        return f"final_role={role};has_tool_calls={str(has_tool).lower()};content_present={str(bool(content)).lower()}"
    return "unknown_final_message"


def _summarize(
    *, output_dir: Path, target: str, arm: str, repetition: int, run_id: str
) -> dict[str, Any]:
    trace_path = output_dir / "trace.jsonl"
    events = _events(trace_path)
    calls = [event for event in events if event.get("event_type") == "tool_call"]
    post = [event for event in calls if event.get("phase") == "post_barrier"]
    task_end = next(event for event in reversed(events) if event.get("event_type") == "task_end")
    meta_paths = sorted((output_dir / "mcpmark").rglob("meta.json"))
    if len(meta_paths) != 1:
        raise RuntimeError(f"expected one MCPMark meta.json, observed {len(meta_paths)}")
    meta = json.loads(meta_paths[0].read_text(encoding="utf-8"))
    messages_path = meta_paths[0].with_name("messages.json")
    intervention = next(
        (event for event in events if event.get("event_type") == "revocation_intervention"),
        None,
    )
    monitor = _completion_monitor(output_dir=output_dir, arm=arm, events=events)
    summary = {
        "experiment": "E-B28",
        "protocol_version": PROTOCOL_VERSION,
        "run_id": run_id,
        "target": target,
        "service": target.split("/", 1)[0],
        "arm": arm,
        "repetition": repetition,
        "mcpmark_commit": MCPMARK_COMMIT,
        "agent_implementation": "unmodified MCPMarkAgent",
        "model": FROZEN_MODEL,
        "trace_valid": bool(task_end.get("trace_valid")),
        "infrastructure_error": bool(task_end.get("infrastructure_error")),
        "exposure_status": task_end.get("exposure_status"),
        "task_success": bool(task_end.get("task_success")),
        "benchmark_execution_result": meta.get("execution_result"),
        "token_usage": meta.get("token_usage", {}),
        "turn_count": meta.get("turn_count"),
        "agent_execution_time": meta.get("agent_execution_time"),
        "tool_call_count": len(calls),
        "post_barrier_call_count": len(post),
        "post_barrier_denied_calls": sum(bool(event.get("denied")) for event in post),
        "post_barrier_allowed_calls": sum(bool(event.get("allowed")) for event in post),
        "post_barrier_effect_commits": sum(event.get("effect_committed") is True for event in post),
        "post_barrier_mutating_attempts": sum(event.get("attempted_mutation") is True for event in post),
        "post_barrier_tool_switches": sum(
            post[index].get("tool_name") != post[index - 1].get("tool_name")
            for index in range(1, len(post))
        ),
        "intervention": intervention,
        "completion_monitor": monitor,
        "stop_reason": _stop_reason(messages_path),
        "trace_sha256": hashlib.sha256(trace_path.read_bytes()).hexdigest(),
        "meta_relative_path": str(meta_paths[0].relative_to(output_dir)),
        "messages_relative_path": str(messages_path.relative_to(output_dir)),
        "finished_unix_ns": time.time_ns(),
    }
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mcpmark-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--target", choices=FROZEN_TARGETS, required=True)
    parser.add_argument("--arm", choices=ARMS, required=True)
    parser.add_argument("--repetition", type=int, choices=(1, 2), required=True)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()

    output_dir = args.output_dir.resolve()
    if output_dir.exists():
        raise FileExistsError(f"E-B28 task output already exists: {output_dir}")
    output_dir.mkdir(parents=True)
    mcpmark_root = args.mcpmark_root.resolve()
    verify_frozen_checkout(mcpmark_root)
    service, task_filter = args.target.split("/", 1)
    key = os.environ.get("OPENROUTER_API_KEY")
    if not key:
        raise RuntimeError("E-B28 requires OPENROUTER_API_KEY")
    os.environ["OPENAI_API_KEY"] = key
    os.environ["OPENAI_BASE_URL"] = FROZEN_BASE_URL
    os.environ["PATH"] = _sanitized_path(mcpmark_root, os.environ.get("PATH", ""))
    os.environ["E_B28_RUN_ID"] = args.run_id
    os.environ["E_B28_ARM"] = args.arm
    os.environ["E_B28_REPETITION"] = str(args.repetition)
    if service == "postgres":
        os.environ.update(
            {
                "POSTGRES_HOST": "127.0.0.1",
                "POSTGRES_PORT": "5432",
                "POSTGRES_DATABASE": "postgres",
                "POSTGRES_USERNAME": "postgres",
                "POSTGRES_PASSWORD": "password",
            }
        )
        pipx_root = mcpmark_root / ".e_b20_pipx"
        os.environ.update(
            {
                "PIPX_HOME": str(pipx_root / "home"),
                "PIPX_BIN_DIR": str(pipx_root / "bin"),
                "PIPX_SHARED_LIBS": str(pipx_root / "shared"),
                "PIPX_LOG_DIR": str(pipx_root / "logs"),
                "PIPX_DEFAULT_PYTHON": "/Library/Frameworks/Python.framework/Versions/3.12/bin/python3.12",
            }
        )

    os.chdir(mcpmark_root)
    sys.path.insert(0, str(mcpmark_root))
    install_e_b28_instrumentation(output_dir / "trace.jsonl")
    from pipeline import main as mcpmark_main

    sys.argv = [
        "pipeline.py",
        "--mcp", service,
        "--models", FROZEN_MODEL,
        "--agent", "mcpmark",
        "--tasks", task_filter,
        "--task-suite", "standard",
        "--exp-name", args.run_id,
        "--k", "1",
        "--reasoning-effort", "default",
        "--compaction-token", "999999999",
        "--timeout", "3600",
        "--output-dir", str(output_dir / "mcpmark"),
    ]
    mcpmark_main()
    summary = _summarize(
        output_dir=output_dir,
        target=args.target,
        arm=args.arm,
        repetition=args.repetition,
        run_id=args.run_id,
    )
    (output_dir / "task_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(canonical_json({key: summary[key] for key in (
        "run_id", "trace_valid", "task_success", "tool_call_count",
        "post_barrier_call_count", "post_barrier_effect_commits",
    )}))
    return 0 if summary["trace_valid"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
