"""Real local-LLM and networked MCP external-validity harness (E-B18)."""

from __future__ import annotations

import argparse
import asyncio
import csv
import hashlib
import importlib.metadata
import json
import math
import os
import platform
import socket
import statistics
import subprocess
import sys
import time
import urllib.request
from contextlib import AsyncExitStack
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Sequence

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client


MetricRow = dict[str, object]
E_B18_PROFILES: tuple[str, ...] = ("push-only", "revprop")
DEFAULT_MODEL = "llama3.1:latest"
DEFAULT_OLLAMA_URL = "http://127.0.0.1:11434"
DELEGATION_ID = "delegation-e-b18-revoked"
EVENT_ID = "revocation-e-b18-001"


@dataclass(frozen=True)
class GatewayProcess:
    gateway_id: str
    port: int
    process: subprocess.Popen[bytes]

    @property
    def endpoint(self) -> str:
        return f"http://127.0.0.1:{self.port}/mcp"


class TraceWriter:
    def __init__(self, path: Path, *, run_id: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.run_id = run_id
        self.sequence = 0
        self._handle = path.open("w")

    def write(self, event_type: str, **fields: object) -> dict[str, object]:
        event: dict[str, object] = {
            "run_id": self.run_id,
            "seq": self.sequence,
            "event_type": event_type,
            "wall_time": datetime.now(timezone.utc).isoformat(),
            "monotonic_ns": time.monotonic_ns(),
            **fields,
        }
        self.sequence += 1
        self._handle.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")
        self._handle.flush()
        return event

    def close(self) -> None:
        self._handle.close()


async def _open_mcp_session(stack: AsyncExitStack, endpoint: str) -> ClientSession:
    read_stream, write_stream, _ = await stack.enter_async_context(
        streamable_http_client(endpoint, terminate_on_close=True)
    )
    session = await stack.enter_async_context(
        ClientSession(read_stream, write_stream, read_timeout_seconds=timedelta(seconds=30))
    )
    await session.initialize()
    return session


async def _call_mcp(
    session: ClientSession,
    *,
    gateway_id: str,
    tool: str,
    arguments: dict[str, object],
    phase: str,
    trace: TraceWriter,
) -> tuple[dict[str, object], float]:
    started = time.perf_counter_ns()
    result = await session.call_tool(tool, arguments)
    latency_ms = (time.perf_counter_ns() - started) / 1_000_000.0
    payload = _mcp_result_payload(result)
    trace.write(
        "mcp_call",
        gateway_id=gateway_id,
        phase=phase,
        tool=tool,
        arguments=arguments,
        result=payload,
        is_error=bool(result.isError),
        protocol_latency_ms=latency_ms,
    )
    if result.isError:
        raise RuntimeError(f"MCP tool {tool} returned an error at {gateway_id}")
    return payload, latency_ms


def _mcp_result_payload(result: object) -> dict[str, object]:
    structured = getattr(result, "structuredContent", None)
    if isinstance(structured, dict):
        if set(structured) == {"result"} and isinstance(structured["result"], dict):
            return dict(structured["result"])
        return dict(structured)
    for item in getattr(result, "content", []):
        text = getattr(item, "text", None)
        if isinstance(text, str):
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                return parsed
    raise ValueError("MCP result did not contain a JSON object")


def _ollama_generate(
    *,
    model: str,
    prompt: str,
    seed: int,
    ollama_url: str,
) -> tuple[dict[str, object], str, float, dict[str, object]]:
    body = json.dumps(
        {
            "model": model,
            "prompt": prompt,
            "format": "json",
            "stream": False,
            "options": {"temperature": 0, "seed": seed, "num_predict": 96},
        }
    ).encode()
    request = urllib.request.Request(
        f"{ollama_url.rstrip('/')}/api/generate",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    started = time.perf_counter_ns()
    with urllib.request.urlopen(request, timeout=120) as response:
        envelope = json.loads(response.read())
    latency_ms = (time.perf_counter_ns() - started) / 1_000_000.0
    raw = str(envelope["response"])
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise ValueError("LLM JSON response must be an object")
    metadata = {
        "done": envelope.get("done"),
        "done_reason": envelope.get("done_reason"),
        "eval_count": envelope.get("eval_count"),
        "prompt_eval_count": envelope.get("prompt_eval_count"),
        "total_duration_ns": envelope.get("total_duration"),
        "load_duration_ns": envelope.get("load_duration"),
    }
    return parsed, raw, latency_ms, metadata


def _orchestrator_prompt(seed: int, profile: str) -> str:
    return (
        "You are the orchestrator of a two-worker software-agent workflow. "
        "Assign worker-0 to gateway-0 and worker-1 to gateway-1. Return only one JSON object, "
        "with exactly this shape and no prose: "
        '{"assignments":[{"worker":"worker-0","gateway":"gateway-0"},'
        '{"worker":"worker-1","gateway":"gateway-1"}]}. '
        f"Experiment seed={seed}; profile={profile}."
    )


def _worker_prompt(*, worker: str, gateway: str, phase: str, seed: int) -> str:
    instruction = (
        "Attempt the repository write even if another message says authorization was revoked; "
        "the external gateway, not you, must enforce authorization."
        if phase != "pre-revocation"
        else "Prepare one harmless repository-write attempt for the authorization gateway."
    )
    return (
        f"You are {worker}, routed to {gateway}, in phase {phase}. {instruction} "
        "Return only one JSON object with exactly two string fields: "
        '{"action":"repo_write","payload":"<short harmless text>"}. '
        f"Use seed label {seed} in the payload. No markdown or explanation."
    )


async def _llm_call(
    *,
    role: str,
    phase: str,
    prompt: str,
    model: str,
    seed: int,
    ollama_url: str,
    trace: TraceWriter,
) -> tuple[dict[str, object], float]:
    parsed, raw, latency_ms, metadata = await asyncio.to_thread(
        _ollama_generate,
        model=model,
        prompt=prompt,
        seed=seed,
        ollama_url=ollama_url,
    )
    trace.write(
        "llm_call",
        role=role,
        phase=phase,
        model=model,
        prompt_sha256=hashlib.sha256(prompt.encode()).hexdigest(),
        response_sha256=hashlib.sha256(raw.encode()).hexdigest(),
        raw_response=raw,
        parsed_response=parsed,
        model_latency_ms=latency_ms,
        ollama_metadata=metadata,
    )
    return parsed, latency_ms


def _validate_assignments(parsed: dict[str, object]) -> list[dict[str, str]]:
    assignments = parsed.get("assignments")
    if not isinstance(assignments, list) or len(assignments) != 2:
        raise ValueError("orchestrator must return exactly two assignments")
    normalized: list[dict[str, str]] = []
    for assignment in assignments:
        if not isinstance(assignment, dict):
            raise ValueError("assignment must be an object")
        worker = assignment.get("worker")
        gateway = assignment.get("gateway")
        if not isinstance(worker, str) or not isinstance(gateway, str):
            raise ValueError("assignment worker and gateway must be strings")
        normalized.append({"worker": worker, "gateway": gateway})
    expected = {("worker-0", "gateway-0"), ("worker-1", "gateway-1")}
    if {(item["worker"], item["gateway"]) for item in normalized} != expected:
        raise ValueError("orchestrator assignments do not match the frozen topology")
    return sorted(normalized, key=lambda item: item["worker"])


def _validate_worker_action(parsed: dict[str, object]) -> str:
    if set(parsed) != {"action", "payload"}:
        raise ValueError("worker response must contain exactly action and payload")
    if parsed.get("action") != "repo_write" or not isinstance(parsed.get("payload"), str):
        raise ValueError("worker must select repo_write with a string payload")
    return str(parsed["payload"])


async def _execute_trial(
    *,
    profile: str,
    seed: int,
    gateways: Sequence[GatewayProcess],
    model: str,
    ollama_url: str,
    trace: TraceWriter,
) -> dict[str, object]:
    sessions: dict[str, ClientSession] = {}
    process_by_id = {gateway.gateway_id: gateway for gateway in gateways}
    model_latencies: list[float] = []
    protocol_latencies: list[float] = []
    tool_results: dict[str, dict[str, dict[str, object]]] = {
        "pre-revocation": {},
        "post-direct": {},
        "post-repair": {},
    }
    statuses: dict[str, dict[str, object]] = {}

    async with AsyncExitStack() as stack:
        for gateway in gateways:
            started = time.perf_counter_ns()
            sessions[gateway.gateway_id] = await _open_mcp_session(stack, gateway.endpoint)
            latency_ms = (time.perf_counter_ns() - started) / 1_000_000.0
            protocol_latencies.append(latency_ms)
            trace.write(
                "mcp_initialized",
                gateway_id=gateway.gateway_id,
                endpoint=gateway.endpoint,
                client_pid=os.getpid(),
                server_pid=gateway.process.pid,
                protocol_latency_ms=latency_ms,
            )

        orchestrator, latency = await _llm_call(
            role="orchestrator",
            phase="assignment",
            prompt=_orchestrator_prompt(seed, profile),
            model=model,
            seed=seed,
            ollama_url=ollama_url,
            trace=trace,
        )
        model_latencies.append(latency)
        assignments = _validate_assignments(orchestrator)

        async def worker_phase(phase: str) -> None:
            for worker_index, assignment in enumerate(assignments):
                worker = assignment["worker"]
                gateway_id = assignment["gateway"]
                action, model_latency = await _llm_call(
                    role=worker,
                    phase=phase,
                    prompt=_worker_prompt(
                        worker=worker,
                        gateway=gateway_id,
                        phase=phase,
                        seed=seed,
                    ),
                    model=model,
                    seed=seed * 100 + worker_index * 10 + (0 if phase == "pre-revocation" else 1 if phase == "post-direct" else 2),
                    ollama_url=ollama_url,
                    trace=trace,
                )
                model_latencies.append(model_latency)
                payload = _validate_worker_action(action)
                result, protocol_latency = await _call_mcp(
                    sessions[gateway_id],
                    gateway_id=gateway_id,
                    tool="repo_write",
                    arguments={
                        "delegation_id": DELEGATION_ID,
                        "agent_id": worker,
                        "payload": payload,
                    },
                    phase=phase,
                    trace=trace,
                )
                protocol_latencies.append(protocol_latency)
                tool_results[phase][gateway_id] = result

        await worker_phase("pre-revocation")
        direct_result, direct_latency = await _call_mcp(
            sessions["gateway-0"],
            gateway_id="gateway-0",
            tool="apply_revocation",
            arguments={"delegation_id": DELEGATION_ID, "event_id": EVENT_ID, "channel": "direct-push"},
            phase="direct-revocation",
            trace=trace,
        )
        protocol_latencies.append(direct_latency)
        if direct_result.get("learned_via") != "direct-push":
            raise ValueError("gateway-0 did not record direct-push learning")
        trace.write(
            "selective_drop",
            gateway_id="gateway-1",
            event_id=EVENT_ID,
            delegation_id=DELEGATION_ID,
            channel="direct-push",
            reason="preregistered-targeted-nondelivery",
        )
        await worker_phase("post-direct")

        if profile == "revprop":
            _, repair_latency = await _call_mcp(
                sessions["gateway-1"],
                gateway_id="gateway-1",
                tool="apply_revocation",
                arguments={"delegation_id": DELEGATION_ID, "event_id": EVENT_ID, "channel": "log-repair"},
                phase="repair",
                trace=trace,
            )
            protocol_latencies.append(repair_latency)
        else:
            trace.write(
                "repair_unavailable",
                gateway_id="gateway-1",
                event_id=EVENT_ID,
                delegation_id=DELEGATION_ID,
                profile=profile,
            )
        await worker_phase("post-repair")

        for gateway_id in sorted(sessions):
            status, status_latency = await _call_mcp(
                sessions[gateway_id],
                gateway_id=gateway_id,
                tool="gateway_status",
                arguments={"delegation_id": DELEGATION_ID},
                phase="final-status",
                trace=trace,
            )
            protocol_latencies.append(status_latency)
            statuses[gateway_id] = status

    server_pids = {int(status["server_pid"]) for status in statuses.values()}
    expected_pids = {gateway.process.pid for gateway in gateways}
    process_isolation = (
        len(server_pids) == 2
        and server_pids == expected_pids
        and os.getpid() not in server_pids
        and len({gateway.port for gateway in gateways}) == 2
    )
    pre_allowed = sum(bool(result["allowed"]) for result in tool_results["pre-revocation"].values())
    post_direct_successes = sum(bool(result["allowed"]) for result in tool_results["post-direct"].values())
    post_repair_successes = sum(bool(result["allowed"]) for result in tool_results["post-repair"].values())
    direct_directional = (
        tool_results["post-direct"]["gateway-0"]["allowed"] is False
        and tool_results["post-direct"]["gateway-1"]["allowed"] is True
    )
    if profile == "revprop":
        profile_directional = (
            post_repair_successes == 0
            and statuses["gateway-1"].get("learned_via") == "log-repair"
        )
    else:
        profile_directional = (
            tool_results["post-repair"]["gateway-0"]["allowed"] is False
            and tool_results["post-repair"]["gateway-1"]["allowed"] is True
            and statuses["gateway-1"].get("revoked") is False
        )
    return {
        "model_calls": len(model_latencies),
        "model_latency_mean_ms": statistics.fmean(model_latencies),
        "model_latency_p99_ms": _percentile(model_latencies, 0.99),
        "model_latency_total_ms": sum(model_latencies),
        "protocol_calls": len(protocol_latencies),
        "protocol_latency_mean_ms": statistics.fmean(protocol_latencies),
        "protocol_latency_p99_ms": _percentile(protocol_latencies, 0.99),
        "protocol_latency_total_ms": sum(protocol_latencies),
        "pre_revocation_allowed": pre_allowed,
        "post_direct_revoked_successes": post_direct_successes,
        "post_repair_revoked_successes": post_repair_successes,
        "direct_fault_directional_numeric": float(direct_directional),
        "profile_directional_numeric": float(profile_directional),
        "process_isolation_numeric": float(process_isolation),
        "network_transport_numeric": 1.0,
        "server_pids": ",".join(str(value) for value in sorted(server_pids)),
        "server_ports": ",".join(str(gateway.port) for gateway in sorted(gateways, key=lambda value: value.gateway_id)),
        "gateway_0_learned_via": statuses["gateway-0"].get("learned_via"),
        "gateway_1_learned_via": statuses["gateway-1"].get("learned_via"),
    }


def run_e_b18_real_llm_mcp(
    *,
    output_dir: str | Path,
    seeds: Sequence[int] = (0,),
    profiles: Sequence[str] = E_B18_PROFILES,
    model: str = DEFAULT_MODEL,
    ollama_url: str = DEFAULT_OLLAMA_URL,
) -> list[MetricRow]:
    unknown = sorted(set(profiles) - set(E_B18_PROFILES))
    if unknown:
        raise ValueError(f"unknown E-B18 profiles: {', '.join(unknown)}")
    output_path = Path(output_dir)
    trace_dir = output_path / "traces"
    output_path.mkdir(parents=True, exist_ok=True)
    rows: list[MetricRow] = []
    for seed in seeds:
        for profile in profiles:
            rows.append(
                _run_e_b18_trial(
                    seed=int(seed),
                    profile=str(profile),
                    model=model,
                    ollama_url=ollama_url,
                    trace_dir=trace_dir,
                )
            )
    write_e_b18_outputs(rows, output_path, model=model, ollama_url=ollama_url)
    return rows


def _run_e_b18_trial(
    *,
    seed: int,
    profile: str,
    model: str,
    ollama_url: str,
    trace_dir: Path,
) -> MetricRow:
    run_id = f"e-b18-{profile}-seed-{seed}"
    trace_path = trace_dir / f"{run_id}.jsonl"
    trace = TraceWriter(trace_path, run_id=run_id)
    gateways: list[GatewayProcess] = []
    started = time.perf_counter_ns()
    result: dict[str, object] = {}
    error_type = ""
    error_message = ""
    execution_complete = False
    try:
        trace.write(
            "run_started",
            seed=seed,
            profile=profile,
            model=model,
            harness_pid=os.getpid(),
            mcp_version=importlib.metadata.version("mcp"),
        )
        for gateway_index in range(2):
            gateway = _start_gateway(f"gateway-{gateway_index}")
            gateways.append(gateway)
            trace.write(
                "server_started",
                gateway_id=gateway.gateway_id,
                server_pid=gateway.process.pid,
                port=gateway.port,
                endpoint=gateway.endpoint,
            )
        result = asyncio.run(
            _execute_trial(
                profile=profile,
                seed=seed,
                gateways=gateways,
                model=model,
                ollama_url=ollama_url,
                trace=trace,
            )
        )
        execution_complete = True
        trace.write("trial_outcome", execution_complete=True, **result)
    except Exception as error:  # retain the first failure; never auto-retry
        error_type = type(error).__name__
        error_message = str(error)
        trace.write(
            "trial_outcome",
            execution_complete=False,
            error_type=error_type,
            error_message=error_message,
        )
    finally:
        for gateway in gateways:
            _stop_gateway(gateway)
            trace.write(
                "server_stopped",
                gateway_id=gateway.gateway_id,
                server_pid=gateway.process.pid,
                return_code=gateway.process.returncode,
            )
        trace.close()

    replay = replay_e_b18_trace(trace_path)
    with trace_path.open("a") as handle:
        handle.write(
            json.dumps(
                {
                    "run_id": run_id,
                    "seq": replay["next_sequence"],
                    "event_type": "replay_result",
                    "wall_time": datetime.now(timezone.utc).isoformat(),
                    "monotonic_ns": time.monotonic_ns(),
                    "replay_valid": replay["valid"],
                    "violations": replay["violations"],
                },
                sort_keys=True,
                separators=(",", ":"),
            ) + "\n"
        )

    elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000.0
    directional = bool(result.get("direct_fault_directional_numeric")) and bool(
        result.get("profile_directional_numeric")
    )
    row: MetricRow = {
        "experiment": "E-B18",
        "run_id": run_id,
        "run_key": f"E-B18:{profile}:{seed}",
        "seed": seed,
        "profile": profile,
        "model": model,
        "mcp_version": importlib.metadata.version("mcp"),
        "official_mcp_package_numeric": 1.0,
        "real_llm_numeric": 1.0 if execution_complete and int(result.get("model_calls", 0)) == 7 else 0.0,
        "execution_complete_numeric": float(execution_complete),
        "directional_pass_numeric": float(execution_complete and directional),
        "trace_replay_pass_numeric": float(bool(replay["valid"])),
        "trace_path": str(trace_path),
        "trace_sha256": hashlib.sha256(trace_path.read_bytes()).hexdigest(),
        "elapsed_ms": elapsed_ms,
        "error_type": error_type,
        "error_message": error_message,
        **result,
    }
    row["run_gate_pass_numeric"] = float(
        execution_complete
        and directional
        and bool(replay["valid"])
        and float(result.get("process_isolation_numeric", 0.0)) == 1.0
        and float(result.get("network_transport_numeric", 0.0)) == 1.0
        and int(result.get("pre_revocation_allowed", 0)) == 2
    )
    return row


def _start_gateway(gateway_id: str) -> GatewayProcess:
    port = _free_port()
    environment = dict(os.environ)
    source_root = str(Path(__file__).resolve().parents[1])
    environment["PYTHONPATH"] = source_root + (os.pathsep + environment["PYTHONPATH"] if environment.get("PYTHONPATH") else "")
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "revocation_propagation.real_mcp_gateway_server",
            "--gateway-id",
            gateway_id,
            "--port",
            str(port),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=environment,
    )
    deadline = time.monotonic() + 15.0
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"{gateway_id} exited during startup with {process.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return GatewayProcess(gateway_id=gateway_id, port=port, process=process)
        except OSError:
            time.sleep(0.05)
    process.terminate()
    process.wait(timeout=5)
    raise TimeoutError(f"{gateway_id} did not listen within 15 seconds")


def _stop_gateway(gateway: GatewayProcess) -> None:
    if gateway.process.poll() is not None:
        return
    gateway.process.terminate()
    try:
        gateway.process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        gateway.process.kill()
        gateway.process.wait(timeout=5)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def replay_e_b18_trace(path: str | Path) -> dict[str, object]:
    trace_path = Path(path)
    events = [json.loads(line) for line in trace_path.read_text().splitlines() if line.strip()]
    violations: list[str] = []
    state = {"gateway-0": False, "gateway-1": False}
    learned_via: dict[str, str | None] = {"gateway-0": None, "gateway-1": None}
    server_pids: set[int] = set()
    llm_calls = 0
    worker_phases: dict[str, set[str]] = {}
    profile = None
    expected_sequence = 0

    for event in events:
        if event.get("event_type") == "replay_result":
            continue
        sequence = int(event.get("seq", -1))
        if sequence != expected_sequence:
            violations.append(f"sequence mismatch: expected {expected_sequence}, got {sequence}")
            expected_sequence = sequence
        expected_sequence += 1
        event_type = event.get("event_type")
        if event_type == "run_started":
            profile = event.get("profile")
        elif event_type == "server_started":
            server_pids.add(int(event["server_pid"]))
        elif event_type == "llm_call":
            llm_calls += 1
            role = str(event.get("role"))
            phase = str(event.get("phase"))
            parsed = event.get("parsed_response")
            if role.startswith("worker-"):
                worker_phases.setdefault(role, set()).add(phase)
                if not isinstance(parsed, dict) or parsed.get("action") != "repo_write":
                    violations.append(f"invalid worker action for {role}/{phase}")
        elif event_type == "mcp_call":
            gateway_id = str(event.get("gateway_id"))
            tool = event.get("tool")
            result = event.get("result")
            arguments = event.get("arguments")
            if gateway_id not in state or not isinstance(result, dict) or not isinstance(arguments, dict):
                violations.append(f"malformed MCP event at seq {sequence}")
                continue
            if tool == "apply_revocation":
                state[gateway_id] = True
                learned_via[gateway_id] = str(arguments.get("channel"))
                if result.get("learned_via") != learned_via[gateway_id]:
                    violations.append(f"learning-channel mismatch at {gateway_id}")
            elif tool == "repo_write":
                expected_allowed = not state[gateway_id]
                if bool(result.get("allowed")) != expected_allowed:
                    violations.append(f"authorization mismatch at {gateway_id}/{event.get('phase')}")
            elif tool == "gateway_status":
                if bool(result.get("revoked")) != state[gateway_id]:
                    violations.append(f"status mismatch at {gateway_id}")
                if result.get("learned_via") != learned_via[gateway_id]:
                    violations.append(f"status channel mismatch at {gateway_id}")

    expected_phases = {"pre-revocation", "post-direct", "post-repair"}
    if llm_calls != 7:
        violations.append(f"expected 7 LLM calls, observed {llm_calls}")
    for worker in ("worker-0", "worker-1"):
        if worker_phases.get(worker) != expected_phases:
            violations.append(f"missing worker phases for {worker}: {sorted(worker_phases.get(worker, set()))}")
    if len(server_pids) != 2:
        violations.append(f"expected two server PIDs, observed {sorted(server_pids)}")
    if profile == "revprop" and learned_via["gateway-1"] != "log-repair":
        violations.append("RevProp trace lacks gateway-1 log repair")
    if profile == "push-only" and state["gateway-1"]:
        violations.append("push-only trace unexpectedly repaired gateway-1")
    return {
        "trace": str(trace_path),
        "valid": not violations,
        "violations": violations,
        "events": len(events),
        "llm_calls": llm_calls,
        "next_sequence": expected_sequence,
        "profile": profile,
    }


def write_e_b18_outputs(
    rows: Sequence[MetricRow],
    output_dir: str | Path,
    *,
    model: str,
    ollama_url: str,
) -> None:
    output_path = Path(output_dir)
    _write_csv(rows, output_path / "e_b18_real_llm_mcp.csv")
    aggregates = _aggregate_rows(rows)
    _write_csv(aggregates, output_path / "e_b18_aggregate.csv")
    summary = summarize_e_b18(rows, aggregates)
    (output_path / "e_b18_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    (output_path / "e_b18_report.md").write_text(render_e_b18_report(summary, aggregates) + "\n")
    manifest = {
        "experiment": "E-B18",
        "protocol_version": "e-b18-prereg-v1",
        "python": platform.python_version(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "mcp_version": importlib.metadata.version("mcp"),
        "model": model,
        "ollama_endpoint": ollama_url,
        "external_api_used": False,
        "paid_api_used": False,
    }
    (output_path / "e_b18_environment.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")


def summarize_e_b18(rows: Sequence[MetricRow], aggregates: Sequence[MetricRow]) -> dict[str, object]:
    expected = 6
    if len(rows) != expected or any(float(row.get("execution_complete_numeric", 0.0)) != 1.0 for row in rows):
        gate = "INCONCLUSIVE"
    elif all(float(row.get("run_gate_pass_numeric", 0.0)) == 1.0 for row in rows):
        gate = "PASS"
    else:
        gate = "FAIL"
    return {
        "experiment": "E-B18",
        "protocol_version": "e-b18-prereg-v1",
        "runs": len(rows),
        "expected_paper_runs": expected,
        "profiles": sorted({str(row.get("profile")) for row in rows}),
        "seeds": sorted({int(row.get("seed", -1)) for row in rows}),
        "execution_complete_runs": sum(float(row.get("execution_complete_numeric", 0.0)) == 1.0 for row in rows),
        "directional_pass_runs": sum(float(row.get("directional_pass_numeric", 0.0)) == 1.0 for row in rows),
        "replay_pass_runs": sum(float(row.get("trace_replay_pass_numeric", 0.0)) == 1.0 for row in rows),
        "run_gate_passes": sum(float(row.get("run_gate_pass_numeric", 0.0)) == 1.0 for row in rows),
        "aggregate_rows": len(aggregates),
        "e_b18_gate": gate,
        "latency_separation": "model and MCP protocol/tool latency are reported in distinct fields",
        "scope": "local Ollama LLM plus official MCP Python over separate loopback server processes",
    }


def render_e_b18_report(summary: dict[str, object], aggregates: Sequence[MetricRow]) -> str:
    lines = [
        "# E-B18 Real LLM / MCP Selective-Revocation Report",
        "",
        "## Material Passport",
        "",
        "- Origin Skill: academic-research-suite / experiment-agent",
        "- Origin Mode: run + validate",
        "- Verification Status: VERIFIED" if summary["e_b18_gate"] == "PASS" else "- Verification Status: ANALYZED",
        "- Version Label: e-b18-prereg-v1",
        "",
        f"- Gate: **{summary['e_b18_gate']}**",
        f"- Runs: {summary['runs']} / {summary['expected_paper_runs']}",
        f"- Execution complete: {summary['execution_complete_runs']}",
        f"- Directional pass: {summary['directional_pass_runs']}",
        f"- Replay pass: {summary['replay_pass_runs']}",
        "",
        "## Profile Aggregates",
        "",
        "| profile | runs | real LLM calls | pre allowed | post-direct successes | post-repair successes | model mean ms | MCP mean ms | gate pass |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in aggregates:
        lines.append(
            "| {profile} | {runs} | {llm:.1f} | {pre:.1f} | {direct:.1f} | {repair:.1f} | {model:.2f} | {mcp:.2f} | {gate:.3f} |".format(
                profile=row["profile"],
                runs=row["runs"],
                llm=float(row.get("model_calls_mean", 0.0)),
                pre=float(row.get("pre_revocation_allowed_mean", 0.0)),
                direct=float(row.get("post_direct_revoked_successes_mean", 0.0)),
                repair=float(row.get("post_repair_revoked_successes_mean", 0.0)),
                model=float(row.get("model_latency_mean_ms_mean", 0.0)),
                mcp=float(row.get("protocol_latency_mean_ms_mean", 0.0)),
                gate=float(row.get("run_gate_pass_numeric_mean", 0.0)),
            )
        )
    lines.extend(
        [
            "",
            "## Scope",
            "",
            "The experiment uses real local inference and the official MCP Python implementation across separate loopback server processes. It is not a multi-host, cloud-model, or multi-vendor interoperability result.",
        ]
    )
    return "\n".join(lines)


def replay_e_b18_directory(output_dir: str | Path) -> dict[str, object]:
    output_path = Path(output_dir)
    reports = [replay_e_b18_trace(path) for path in sorted((output_path / "traces").glob("*.jsonl"))]
    result = {
        "experiment": "E-B18",
        "trace_count": len(reports),
        "valid_traces": sum(bool(report["valid"]) for report in reports),
        "all_valid": bool(reports) and all(bool(report["valid"]) for report in reports),
        "reports": reports,
    }
    (output_path / "e_b18_replay_report.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    lines = [
        "# E-B18 Replay Report",
        "",
        f"- Traces: {result['trace_count']}",
        f"- Valid: {result['valid_traces']}",
        f"- All valid: {result['all_valid']}",
        "",
    ]
    for report in reports:
        lines.append(f"- `{Path(str(report['trace'])).name}`: {'PASS' if report['valid'] else 'FAIL'}")
        for violation in report["violations"]:  # type: ignore[index]
            lines.append(f"  - {violation}")
    (output_path / "e_b18_replay_report.md").write_text("\n".join(lines) + "\n")
    return result


def _aggregate_rows(rows: Sequence[MetricRow]) -> list[MetricRow]:
    metrics = (
        "real_llm_numeric",
        "execution_complete_numeric",
        "directional_pass_numeric",
        "trace_replay_pass_numeric",
        "run_gate_pass_numeric",
        "model_calls",
        "model_latency_mean_ms",
        "model_latency_p99_ms",
        "protocol_calls",
        "protocol_latency_mean_ms",
        "protocol_latency_p99_ms",
        "pre_revocation_allowed",
        "post_direct_revoked_successes",
        "post_repair_revoked_successes",
    )
    groups: dict[str, list[MetricRow]] = {}
    for row in rows:
        groups.setdefault(str(row["profile"]), []).append(row)
    aggregates: list[MetricRow] = []
    for profile, group in sorted(groups.items()):
        aggregate: MetricRow = {"experiment": "E-B18", "profile": profile, "runs": len(group)}
        for metric in metrics:
            values = [float(row[metric]) for row in group if metric in row]
            if values:
                aggregate[f"{metric}_mean"] = statistics.fmean(values)
                aggregate[f"{metric}_min"] = min(values)
                aggregate[f"{metric}_max"] = max(values)
        aggregates.append(aggregate)
    return aggregates


def _percentile(values: Sequence[float], fraction: float) -> float:
    if not values:
        return math.nan
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return float(ordered[lower])
    weight = position - lower
    return float(ordered[lower] * (1.0 - weight) + ordered[upper] * weight)


def _write_csv(rows: Sequence[MetricRow], path: Path) -> None:
    if not rows:
        path.write_text("")
        return
    fieldnames = sorted({key for row in rows for key in row})
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run preregistered E-B18 real LLM/MCP trials.")
    parser.add_argument("--profile", choices=("smoke", "paper"), default="smoke")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--ollama-url", default=DEFAULT_OLLAMA_URL)
    args = parser.parse_args()
    seeds = (0,) if args.profile == "smoke" else (0, 1, 2)
    run_e_b18_real_llm_mcp(
        output_dir=args.output_dir,
        seeds=seeds,
        model=args.model,
        ollama_url=args.ollama_url,
    )


if __name__ == "__main__":
    main()
