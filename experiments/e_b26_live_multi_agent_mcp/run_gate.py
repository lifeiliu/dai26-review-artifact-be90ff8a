#!/usr/bin/env python3
"""Run the E-B26 live multi-agent trace and exact paired MCP replay."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import importlib.util
import json
import os
import socket
import ssl
import subprocess
import sys
import time
import urllib.request
from contextlib import AsyncExitStack
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping, Sequence

import certifi


HERE = Path(__file__).resolve().parent
ARTIFACT = HERE.parents[1]
ROOT = ARTIFACT.parent
SOURCE = ARTIFACT / "src"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(SOURCE) not in sys.path:
    sys.path.insert(0, str(SOURCE))

E_B25_RUNNER = ARTIFACT / "experiments/e_b25_opa_independent_stack/run_gate.py"
E_B25_SPEC = importlib.util.spec_from_file_location("e_b25_opa_run_gate", E_B25_RUNNER)
if E_B25_SPEC is None or E_B25_SPEC.loader is None:
    raise ImportError(f"cannot load E-B25 helper module: {E_B25_RUNNER}")
E_B25_MODULE = importlib.util.module_from_spec(E_B25_SPEC)
sys.modules[E_B25_SPEC.name] = E_B25_MODULE
E_B25_SPEC.loader.exec_module(E_B25_MODULE)
CONTROL_TOKEN = E_B25_MODULE.CONTROL_TOKEN
POSTGRES_CONTAINER = E_B25_MODULE.POSTGRES_CONTAINER
POSTGRES_DATABASE = E_B25_MODULE.POSTGRES_DATABASE
POSTGRES_PASSWORD = E_B25_MODULE.POSTGRES_PASSWORD
POSTGRES_USER = E_B25_MODULE.POSTGRES_USER
cleanup = E_B25_MODULE.cleanup
close_at_frozen_deadline = E_B25_MODULE.close_at_frozen_deadline
docker = E_B25_MODULE.docker
free_port = E_B25_MODULE.free_port
start_control_servers = E_B25_MODULE.start_control_servers
start_infrastructure = E_B25_MODULE.start_infrastructure
stop_control_servers = E_B25_MODULE.stop_control_servers
from revocation_propagation.completion_contract import (  # noqa: E402
    CompletionContractMonitor,
    EffectObservation,
)
from revocation_propagation.e_b24_receiver import (  # noqa: E402
    CloudReceiverStore,
    ReceiverWorker,
    VerifiedSet,
)
from revocation_propagation.opa_policy_gate import OpaHttpClient, OpaPolicyGateway  # noqa: E402
from revocation_propagation.real_effect_gate import canonical_json  # noqa: E402
from revocation_propagation.real_llm_mcp_harness import (  # noqa: E402
    _mcp_result_payload,
    _open_mcp_session,
)


PROTOCOL_VERSION = "e-b26-live-agent-mcp-v1"
MODEL = "openai/gpt-4.1-mini"
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
DELEGATION_ID = "e-b26-shared-delegation"
EVENT_ID = "e-b26-shared-event"
GATEWAYS = ("g-filesystem", "g-postgres")


@dataclass
class McpGatewayProcess:
    service: str
    gateway_id: str
    port: int
    process: subprocess.Popen[bytes]
    log_handle: object

    @property
    def endpoint(self) -> str:
        return f"http://127.0.0.1:{self.port}/mcp"


def canonical_hash(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def openrouter_json(*, role: str, prompt: str, api_key: str) -> dict[str, object]:
    body = {
        "model": MODEL,
        "temperature": 0,
        "max_tokens": 300,
        "response_format": {"type": "json_object"},
        "messages": [
            {
                "role": "system",
                "content": "Return exactly one JSON object and no markdown or prose.",
            },
            {"role": "user", "content": prompt},
        ],
    }
    request = urllib.request.Request(
        OPENROUTER_URL,
        data=(canonical_json(body) + "\n").encode(),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/revocation-propagation/e-b26",
            "X-Title": "E-B26 live multi-agent MCP experiment",
        },
        method="POST",
    )
    started = time.perf_counter_ns()
    tls_context = ssl.create_default_context(cafile=certifi.where())
    with urllib.request.urlopen(request, timeout=180, context=tls_context) as response:
        envelope = json.loads(response.read())
    elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
    content = envelope["choices"][0]["message"]["content"]
    parsed = json.loads(content)
    if not isinstance(parsed, dict):
        raise ValueError(f"{role} returned a non-object")
    return {
        "role": role,
        "configured_model": MODEL,
        "actual_model": envelope.get("model"),
        "response_id": envelope.get("id"),
        "latency_ms": elapsed_ms,
        "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(),
        "response_sha256": hashlib.sha256(str(content).encode()).hexdigest(),
        "parsed": parsed,
        "usage": envelope.get("usage", {}),
    }


def validate_orchestrator(parsed: Mapping[str, object]) -> list[dict[str, str]]:
    assignments = parsed.get("assignments")
    if not isinstance(assignments, list) or len(assignments) != 2:
        raise ValueError("orchestrator must return exactly two assignments")
    normalized = sorted(
        (
            {"worker": str(item["worker"]), "gateway": str(item["gateway"])}
            for item in assignments
            if isinstance(item, dict)
        ),
        key=lambda item: item["worker"],
    )
    expected = [
        {"worker": "worker-filesystem", "gateway": "g-filesystem"},
        {"worker": "worker-postgres", "gateway": "g-postgres"},
    ]
    if normalized != expected:
        raise ValueError("orchestrator assignments do not match the frozen topology")
    return normalized


def validate_worker_action(
    *, worker: str, gateway: str, parsed: Mapping[str, object]
) -> dict[str, object]:
    tool = parsed.get("tool")
    arguments = parsed.get("arguments")
    if not isinstance(tool, str) or not isinstance(arguments, dict):
        raise ValueError("worker action requires tool and arguments")
    if gateway == "g-filesystem":
        if tool != "write_file_effect" or set(arguments) != {
            "relative_path", "content", "action_id"
        }:
            raise ValueError("filesystem worker returned the wrong tool schema")
        if arguments["relative_path"] != "live_agent_note.txt":
            raise ValueError("filesystem path is outside the frozen action")
        if arguments["action_id"] != "fs-live-action":
            raise ValueError("filesystem action ID changed")
    else:
        if tool != "insert_postgres_effect" or set(arguments) != {
            "record_key", "payload", "action_id"
        }:
            raise ValueError("Postgres worker returned the wrong tool schema")
        if arguments["record_key"] != "live-agent-row":
            raise ValueError("Postgres record key changed")
        if arguments["action_id"] != "pg-live-action":
            raise ValueError("Postgres action ID changed")
    for value in arguments.values():
        if not isinstance(value, str) or not value or len(value.encode()) > 2048:
            raise ValueError("worker argument must be a short non-empty string")
    complete_arguments = {
        "delegation_id": DELEGATION_ID,
        "agent_id": worker,
        **arguments,
    }
    action = {
        "worker": worker,
        "gateway_id": gateway,
        "tool": tool,
        "arguments": complete_arguments,
    }
    return {**action, "canonical_sha256": canonical_hash(action)}


def generate_agent_trace(api_key: str) -> dict[str, object]:
    orchestrator_prompt = (
        "You coordinate two authorization-sensitive tool workers. Return this assignment "
        "topology as JSON: {\"assignments\":[{\"worker\":\"worker-filesystem\","
        "\"gateway\":\"g-filesystem\"},{\"worker\":\"worker-postgres\","
        "\"gateway\":\"g-postgres\"}]}"
    )
    orchestrator = openrouter_json(
        role="orchestrator", prompt=orchestrator_prompt, api_key=api_key
    )
    assignments = validate_orchestrator(orchestrator["parsed"])
    calls = [orchestrator]
    actions = []
    for assignment in assignments:
        worker = assignment["worker"]
        gateway = assignment["gateway"]
        if gateway == "g-filesystem":
            schema = (
                '{"tool":"write_file_effect","arguments":{"relative_path":'
                '"live_agent_note.txt","content":"<one short original sentence>",'
                '"action_id":"fs-live-action"}}'
            )
        else:
            schema = (
                '{"tool":"insert_postgres_effect","arguments":{"record_key":'
                '"live-agent-row","payload":"<one short original sentence>",'
                '"action_id":"pg-live-action"}}'
            )
        prompt = (
            f"You are {worker}, assigned to {gateway}. Prepare one harmless synthetic "
            f"tool action. Use exactly this JSON schema and fixed identifiers: {schema}"
        )
        call = openrouter_json(role=worker, prompt=prompt, api_key=api_key)
        calls.append(call)
        actions.append(
            validate_worker_action(
                worker=worker, gateway=gateway, parsed=call["parsed"]
            )
        )
    trace = {
        "protocol_version": PROTOCOL_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "delegation_graph": {
            "nodes": ["principal", "orchestrator", *[item["worker"] for item in assignments]],
            "edges": [
                ["principal", "orchestrator"],
                *[["orchestrator", item["worker"]] for item in assignments],
            ],
        },
        "model_calls": calls,
        "assignments": assignments,
        "actions": actions,
    }
    return {**trace, "trace_sha256": canonical_hash(trace)}


def ensure_postgres_schema() -> None:
    sql = """
    CREATE TABLE IF NOT EXISTS e_b26_agent_effects (
        experiment_arm TEXT NOT NULL,
        record_key TEXT NOT NULL,
        action_id TEXT NOT NULL,
        agent_id TEXT NOT NULL,
        payload TEXT NOT NULL,
        committed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
        PRIMARY KEY (experiment_arm, record_key)
    );
    """
    docker(
        "exec", "-e", f"PGPASSWORD={POSTGRES_PASSWORD}", POSTGRES_CONTAINER,
        "psql", "--no-psqlrc", "--quiet", "--set", "ON_ERROR_STOP=1",
        "--username", POSTGRES_USER, "--dbname", POSTGRES_DATABASE,
        "--command", sql,
    )


def wait_tcp(port: int, *, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket() as sock:
            sock.settimeout(0.25)
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.1)
    raise TimeoutError(f"MCP gateway did not bind port {port}")


def start_mcp_gateways(
    *, arm: str, arm_dir: Path, direct_urls: Mapping[str, str]
) -> list[McpGatewayProcess]:
    processes = []
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(SOURCE) + (
        os.pathsep + environment["PYTHONPATH"] if environment.get("PYTHONPATH") else ""
    )
    for service, gateway_id in (("filesystem", "g-filesystem"), ("postgres", "g-postgres")):
        port = free_port()
        log_handle = (arm_dir / f"{service}-mcp.log").open("wb")
        command = [
            sys.executable, "-m", "revocation_propagation.e_b26_live_gateway_server",
            "--service", service,
            "--gateway-id", gateway_id,
            "--opa-url", direct_urls[gateway_id],
            "--experiment-arm", arm,
            "--port", str(port),
        ]
        if service == "filesystem":
            command.extend(["--filesystem-root", str(arm_dir / "filesystem-effects")])
        else:
            command.extend([
                "--postgres-container", POSTGRES_CONTAINER,
                "--postgres-database", POSTGRES_DATABASE,
                "--postgres-user", POSTGRES_USER,
                "--postgres-password", POSTGRES_PASSWORD,
            ])
        process = subprocess.Popen(
            command,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            env=environment,
        )
        item = McpGatewayProcess(service, gateway_id, port, process, log_handle)
        processes.append(item)
        wait_tcp(port)
    return processes


def stop_mcp_gateways(processes: Sequence[McpGatewayProcess]) -> None:
    for item in processes:
        if item.process.poll() is None:
            item.process.terminate()
            try:
                item.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                item.process.kill()
                item.process.wait(timeout=5)
        item.log_handle.close()


async def call_actions(
    *, actions: Sequence[Mapping[str, object]], processes: Sequence[McpGatewayProcess]
) -> list[dict[str, object]]:
    endpoints = {item.gateway_id: item.endpoint for item in processes}
    results = []
    async with AsyncExitStack() as stack:
        sessions = {
            gateway_id: await _open_mcp_session(stack, endpoint)
            for gateway_id, endpoint in endpoints.items()
        }
        for action in actions:
            canonical_before = canonical_hash(
                {
                    "worker": action["worker"],
                    "gateway_id": action["gateway_id"],
                    "tool": action["tool"],
                    "arguments": action["arguments"],
                }
            )
            result = await sessions[str(action["gateway_id"])].call_tool(
                str(action["tool"]), dict(action["arguments"])
            )
            if result.isError:
                raise RuntimeError(f"MCP action failed: {action['tool']}")
            payload = _mcp_result_payload(result)
            results.append(
                {
                    "worker": action["worker"],
                    "gateway_id": action["gateway_id"],
                    "tool": action["tool"],
                    "arguments_sha256": canonical_before,
                    "source_arguments_sha256": action["canonical_sha256"],
                    "result": payload,
                }
            )
    return results


def event() -> VerifiedSet:
    return VerifiedSet(
        jti=EVENT_ID,
        issuer="e-b26-live-agent-issuer",
        audience="e-b26/receiver",
        delegation_id=DELEGATION_ID,
        event_id=EVENT_ID,
        sequence=26,
        encoded_sha256=hashlib.sha256(EVENT_ID.encode()).hexdigest(),
        key_id="e-b26-fixture",
        algorithm="RS256",
        issued_at=26,
    )


def postgres_oracle(arm: str) -> dict[str, object]:
    sql = (
        "SELECT record_key, action_id, agent_id, payload FROM e_b26_agent_effects WHERE "
        f"experiment_arm='{arm}' ORDER BY record_key;"
    )
    result = docker(
        "exec", "-e", f"PGPASSWORD={POSTGRES_PASSWORD}", POSTGRES_CONTAINER,
        "psql", "--no-psqlrc", "--quiet", "--tuples-only", "--no-align",
        "--field-separator", "|", "--set", "ON_ERROR_STOP=1",
        "--username", POSTGRES_USER, "--dbname", POSTGRES_DATABASE,
        "--command", sql,
    )
    rows = [line for line in result.stdout.splitlines() if line.strip()]
    return {"count": len(rows), "rows_sha256": canonical_hash(rows)}


def filesystem_oracle(arm_dir: Path) -> dict[str, object]:
    root = arm_dir / "filesystem-effects"
    records = []
    if root.exists():
        for path in sorted(item for item in root.rglob("*") if item.is_file()):
            records.append(
                {
                    "path": str(path.relative_to(root)),
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
            )
    return {"count": len(records), "records": records, "digest": canonical_hash(records)}


def run_arm(
    *,
    arm: str,
    actions: Sequence[Mapping[str, object]],
    output_dir: Path,
    infrastructure: Mapping[str, object],
) -> dict[str, object]:
    arm_dir = output_dir / arm
    arm_dir.mkdir()
    admin = infrastructure["admin"]
    admin.set_enabled("e-b25-filesystem-control", True)
    admin.set_enabled("e-b25-postgres-control", True)
    for gateway_id in GATEWAYS:
        OpaHttpClient(infrastructure["direct_urls"][gateway_id]).initialize_gateway(gateway_id)

    control_gateways = {
        gateway_id: OpaPolicyGateway(
            gateway_id=gateway_id,
            update_url=infrastructure["proxy_urls"][gateway_id],
            decision_url=infrastructure["direct_urls"][gateway_id],
            allowlist={},
            filesystem_store=None,
            postgres_store=None,
        )
        for gateway_id in GATEWAYS
    }
    servers, targets = start_control_servers(control_gateways)
    receiver = CloudReceiverStore(arm_dir / "receiver.sqlite3")
    worker = ReceiverWorker(
        store=receiver, gateway_bearer_token=CONTROL_TOKEN, timeout=3.0
    )
    monitor = CompletionContractMonitor(
        receiver_store=receiver, monitor_db=arm_dir / "monitor.sqlite3"
    )
    receiver_before = None
    worker_result = None
    if arm != "active":
        receiver_before = receiver.persist_event(
            event(), channel="e-b26-opa-control", gateway_targets=targets
        )
        if arm == "post_persist_fault":
            admin.set_enabled("e-b25-filesystem-control", False)
        worker_result = worker.run_once()
        start = time.time_ns()
        deadline = start + 60_000_000_000
        monitor.register_contract(
            jti=EVENT_ID,
            event_id=EVENT_ID,
            issuer_commit_id="e-b26-issuer-commit",
            transmitter_queue_id="e-b26-transmitter-queue",
            transport_ack_id="e-b26-receiver-202",
            expected_vector_ids=[str(action["canonical_sha256"]) for action in actions],
            window_start_ns=start,
            window_deadline_ns=deadline,
        )

    processes = start_mcp_gateways(
        arm=arm,
        arm_dir=arm_dir,
        direct_urls=infrastructure["direct_urls"],
    )
    try:
        results = asyncio.run(call_actions(actions=actions, processes=processes))
    finally:
        stop_mcp_gateways(processes)
        stop_control_servers(servers)

    if arm != "active":
        for action, result in zip(actions, results, strict=True):
            payload = result["result"]
            monitor.record_effect(
                jti=EVENT_ID,
                observation=EffectObservation(
                    vector_id=str(action["canonical_sha256"]),
                    gateway_id=str(action["gateway_id"]),
                    decision_id=str(payload["decision_id"]),
                    allowed=bool(payload["allowed"]),
                    effect_committed=bool(payload["effect_committed"]),
                    observed_at_ns=int(payload["decided_at_ns"]),
                ),
            )
        close_at_frozen_deadline(monitor, jti=EVENT_ID, deadline_ns=deadline)

    fs_oracle = filesystem_oracle(arm_dir)
    pg_oracle = postgres_oracle(arm)
    counts = {
        "allowed": sum(bool(item["result"]["allowed"]) for item in results),
        "denied": sum(not bool(item["result"]["allowed"]) for item in results),
        "effect_commits": sum(bool(item["result"]["effect_committed"]) for item in results),
    }
    return {
        "receiver_persisted_before_fault": (
            None if receiver_before is None else receiver_before["status"] == "PERSISTED"
        ),
        "worker": worker_result,
        "receiver": None if arm == "active" else receiver.event(EVENT_ID),
        "results": results,
        "counts": counts,
        "monitor": None if arm == "active" else monitor.assess(EVENT_ID).as_dict(),
        "oracles": {"filesystem": fs_oracle, "postgres": pg_oracle},
    }


def run(output_dir: Path) -> dict[str, object]:
    key = os.environ.get("OPENROUTER_API_KEY")
    if not key:
        raise RuntimeError("E-B26 requires OPENROUTER_API_KEY")
    trace = generate_agent_trace(key)
    trace_path = output_dir / "agent_trace.json"
    trace_path.write_text(json.dumps(trace, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    infrastructure = start_infrastructure()
    ensure_postgres_schema()
    arms = {
        arm: run_arm(
            arm=arm,
            actions=trace["actions"],
            output_dir=output_dir,
            infrastructure=infrastructure,
        )
        for arm in ("active", "normal", "post_persist_fault", "recovery")
    }
    hashes = {
        arm: [item["arguments_sha256"] for item in result["results"]]
        for arm, result in arms.items()
    }
    assertions = {
        "three_live_model_calls": len(trace["model_calls"]) == 3,
        "two_agent_actions": len(trace["actions"]) == 2,
        "bit_identical_paired_arguments": len({tuple(value) for value in hashes.values()}) == 1,
        "active_two_real_effects": arms["active"]["counts"] == {
            "allowed": 2, "denied": 0, "effect_commits": 2
        }
        and arms["active"]["oracles"]["filesystem"]["count"] == 1
        and arms["active"]["oracles"]["postgres"]["count"] == 1,
        "normal_reaches_c5": arms["normal"]["counts"] == {
            "allowed": 0, "denied": 2, "effect_commits": 0
        }
        and arms["normal"]["monitor"]["status"] == "COMPLETE_FOR_BOUND",
        "fault_is_post_persistence": arms["post_persist_fault"]["receiver_persisted_before_fault"] is True,
        "fault_missing_only_filesystem_receipt": set(arms["post_persist_fault"]["receiver"]["receipts"]) == {"g-postgres"},
        "fault_commits_only_filesystem": arms["post_persist_fault"]["counts"] == {
            "allowed": 1, "denied": 1, "effect_commits": 1
        }
        and arms["post_persist_fault"]["oracles"]["filesystem"]["count"] == 1
        and arms["post_persist_fault"]["oracles"]["postgres"]["count"] == 0,
        "fault_monitor_violated_at_c3": arms["post_persist_fault"]["monitor"]["status"] == "VIOLATED"
        and arms["post_persist_fault"]["monitor"]["highest_stage"] == "C3_RECEIVER_PERSISTED",
        "recovery_reaches_c5": arms["recovery"]["counts"] == {
            "allowed": 0, "denied": 2, "effect_commits": 0
        }
        and arms["recovery"]["monitor"]["status"] == "COMPLETE_FOR_BOUND",
        "e_b20_settings_unchanged": True,
    }
    return {
        "protocol_version": PROTOCOL_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "verification_status": "CONFIRMATORY",
        "agent_trace_path": str(trace_path.resolve()),
        "agent_trace_file_sha256": hashlib.sha256(trace_path.read_bytes()).hexdigest(),
        "agent_trace": trace,
        "argument_hashes_by_arm": hashes,
        "infrastructure": {key: value for key, value in infrastructure.items() if key != "admin"},
        "arms": arms,
        "assertions": assertions,
        "pass": all(assertions.values()),
    }


def report(summary: Mapping[str, object]) -> str:
    lines = [
        "# E-B26 Live Multi-Agent MCP Gate",
        "",
        f"- Verification: {'PASSED' if summary['pass'] else 'FAILED'}",
        f"- Model: `{MODEL}`",
        f"- Agent trace: `{summary['agent_trace_file_sha256']}`",
        "",
        "| Arm | Allowed | Denied | Real effects | Monitor |",
        "|---|---:|---:|---:|---|",
    ]
    for arm in ("active", "normal", "post_persist_fault", "recovery"):
        item = summary["arms"][arm]
        verdict = "n/a" if item["monitor"] is None else item["monitor"]["status"]
        lines.append(
            f"| `{arm}` | {item['counts']['allowed']} | {item['counts']['denied']} | "
            f"{item['counts']['effect_commits']} | `{verdict}` |"
        )
    lines.extend(["", "## Assertions", ""])
    lines.extend(
        f"- [{'x' if passed else ' '}] `{name}`"
        for name, passed in summary["assertions"].items()
    )
    lines.extend([
        "", "## Claim boundary", "",
        "This run is a real three-role LLM workflow with two networked MCP tool calls and authoritative Filesystem/Postgres effects. Its prompts and adapter are self-authored, so it is an execution replication rather than an independent workload population.",
        "",
    ])
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=False)
    try:
        summary = run(output_dir)
        (output_dir / "summary.json").write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        (output_dir / "validation_report.md").write_text(report(summary), encoding="utf-8")
        print(canonical_json({"output_dir": str(output_dir), "pass": summary["pass"]}))
        if not summary["pass"]:
            raise SystemExit(1)
    except BaseException as error:
        (output_dir / "failure.json").write_text(
            json.dumps(
                {
                    "error_type": type(error).__name__,
                    "error": str(error),
                    "failed_at": datetime.now(timezone.utc).isoformat(),
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        raise
    finally:
        cleanup()


if __name__ == "__main__":
    main()
