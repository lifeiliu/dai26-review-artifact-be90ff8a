"""Live closed-loop revocation instrumentation for frozen MCPMark E-B28.

The hook leaves MCPMarkAgent, task prompts, tool schemas, service processes,
and verifiers unchanged.  It closes a between-call barrier after the first
actual MCP call, performs a real Keycloak logout, and changes only the later
gateway decision for the normal/recovery arms.
"""

from __future__ import annotations

import base64
import contextvars
import json
import os
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .mcpmark_external_trace import (
    MCPMARK_COMMIT,
    canonical_json_hash,
    extract_sql,
    filesystem_merkle_digest,
    postgres_sql_is_mutating,
)
from .mcpmark_instrumentation import verify_frozen_checkout


PROTOCOL_VERSION = "e-b28-live-closed-loop-v1"
ARMS = ("active_sanity", "normal_c4", "selective_c3", "recovery_c4")
REVOCATION_ARMS = ("normal_c4", "selective_c3", "recovery_c4")
KEYCLOAK_BASE = "http://127.0.0.1:18082"
RECEIVER_BASE = "http://127.0.0.1:19002"
REALM = "ssf-smoke"


@dataclass
class TaskContext:
    run_id: str
    arm: str
    repetition: int
    service: str
    category_id: str
    task_id: str
    trace_path: Path
    keycloak_base: str
    receiver_base: str
    sequence: int = 0
    barrier_closed: bool = False
    intervention_valid: bool | None = None
    enforcement_active: bool = False
    session_id: str | None = None
    event_jti: str | None = None
    receiver_state: dict[str, Any] | None = None
    observer_errors: list[str] = field(default_factory=list)


_TASK_CONTEXT: contextvars.ContextVar[TaskContext | None] = contextvars.ContextVar(
    "e_b28_task_context", default=None
)


def _append_event(context: TaskContext, event_type: str, **fields: object) -> None:
    event = {
        "protocol_version": PROTOCOL_VERSION,
        "mcpmark_commit": MCPMARK_COMMIT,
        "event_type": event_type,
        "run_id": context.run_id,
        "arm": context.arm,
        "repetition": context.repetition,
        "service": context.service,
        "category_id": context.category_id,
        "task_id": context.task_id,
        "event_wall_time": datetime.now(timezone.utc).isoformat(),
        "event_unix_ns": time.time_ns(),
        **fields,
    }
    context.trace_path.parent.mkdir(parents=True, exist_ok=True)
    with context.trace_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True, separators=(",", ":"), default=str) + "\n")


def _http_request(
    url: str,
    *,
    method: str = "GET",
    form: dict[str, str] | None = None,
    timeout: float = 20.0,
) -> tuple[int, Any]:
    headers = {"Accept": "application/json"}
    data: bytes | None = None
    if form is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        data = urllib.parse.urlencode(form).encode("ascii")
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as error:
        raw = error.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"{method} {url} -> {error.code}: {raw}") from error


def _wait_for_state(receiver_base: str, run_id: str, session_id: str) -> dict[str, Any]:
    deadline = time.monotonic() + 45.0
    last: dict[str, Any] | None = None
    url = f"{receiver_base}/state?{urllib.parse.urlencode({'run_id': run_id})}"
    while time.monotonic() < deadline:
        _, state = _http_request(url, timeout=10)
        if isinstance(state, dict):
            last = state
            matching = [
                item
                for item in state.get("attempts", [])
                if item.get("session_id") == session_id
                and item.get("is_session_revoked") is True
            ]
            by_receiver = {
                receiver: [item for item in matching if item.get("receiver") == receiver]
                for receiver in ("receiver-a", "receiver-b")
            }
            if all(len(items) == 1 for items in by_receiver.values()):
                return {**state, "matching_attempts": {key: value[0] for key, value in by_receiver.items()}}
        time.sleep(0.25)
    raise TimeoutError(f"receiver did not persist one SET per receiver for {run_id}; last={last}")


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _verify_rs256(encoded_set: str, jwks: Mapping[str, Any]) -> dict[str, Any]:
    parts = encoded_set.split(".")
    if len(parts) != 3:
        raise ValueError("SET is not a compact JWS")
    header = json.loads(_b64url_decode(parts[0]))
    if header.get("alg") != "RS256":
        raise ValueError(f"unsupported SET algorithm: {header.get('alg')}")
    key = next(
        (item for item in jwks.get("keys", []) if item.get("kid") == header.get("kid")),
        None,
    )
    if key is None:
        raise ValueError(f"no realm JWK for kid={header.get('kid')}")
    public_key = rsa.RSAPublicNumbers(
        int.from_bytes(_b64url_decode(str(key["e"])), "big"),
        int.from_bytes(_b64url_decode(str(key["n"])), "big"),
    ).public_key()
    public_key.verify(
        _b64url_decode(parts[2]),
        f"{parts[0]}.{parts[1]}".encode("ascii"),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    payload = json.loads(_b64url_decode(parts[1]))
    return {
        "verified": True,
        "algorithm": "RS256",
        "key_id": header.get("kid"),
        "jti": payload.get("jti"),
    }


def _trigger_real_revocation(context: TaskContext) -> dict[str, Any]:
    _, login = _http_request(
        f"{context.keycloak_base}/realms/{REALM}/protocol/openid-connect/token",
        method="POST",
        form={
            "grant_type": "password",
            "client_id": "workload-client",
            "username": "alice",
            "password": "alice-smoke-password",
        },
    )
    if not isinstance(login, dict) or not login.get("session_state") or not login.get("refresh_token"):
        raise RuntimeError("Keycloak login did not return session_state and refresh_token")
    session_id = str(login["session_state"])
    logout_status, _ = _http_request(
        f"{context.keycloak_base}/realms/{REALM}/protocol/openid-connect/logout",
        method="POST",
        form={"client_id": "workload-client", "refresh_token": str(login["refresh_token"])},
    )
    state = _wait_for_state(context.receiver_base, context.run_id, session_id)
    _, jwks = _http_request(
        f"{context.keycloak_base}/realms/{REALM}/protocol/openid-connect/certs"
    )
    matching = state["matching_attempts"]
    verification = {
        receiver: _verify_rs256(str(item["encoded_set"]), jwks)
        for receiver, item in matching.items()
    }
    # Keycloak emits one SET per SSF stream.  The two stream events bind the
    # same session but intentionally have independent JTIs; C4 is bound to the
    # enforcement stream's (receiver-b) event identity.
    receiver_jtis = {
        receiver: str(item["jti"]) for receiver, item in matching.items()
    }
    expected_b = context.arm != "selective_c3"
    if matching["receiver-a"].get("forwarded") is not True:
        raise RuntimeError("receiver-a did not forward")
    if bool(matching["receiver-b"].get("forwarded")) != expected_b:
        raise RuntimeError(f"receiver-b forwarding did not match arm {context.arm}")
    return {
        "session_id": session_id,
        "event_jti": receiver_jtis["receiver-b"],
        "receiver_jtis": receiver_jtis,
        "logout_http_status": logout_status,
        "receiver_state": state,
        "signature_verification": verification,
        "c2_transport_acknowledged": True,
        "c3_receiver_persisted": True,
        "c4_gateway_enforced": expected_b,
    }


def _filesystem_root(server: object) -> Path:
    params = getattr(server, "params")
    args = list(getattr(params, "args"))
    if not args:
        raise RuntimeError("filesystem MCP server has no root argument")
    return Path(args[-1])


def _postgres_lsn() -> str:
    return subprocess.check_output(
        [
            "docker", "exec", "mcpmark-postgres", "psql", "-U", "postgres", "-d", "postgres",
            "-Atc", "SELECT pg_current_wal_lsn()",
        ],
        text=True,
        timeout=15,
    ).strip()


def _result_success(result: object) -> bool:
    if isinstance(result, Mapping):
        return not bool(result.get("isError") or result.get("is_error"))
    return True


def _denial_result(context: TaskContext) -> dict[str, Any]:
    return {
        "content": [
            {
                "type": "text",
                "text": (
                    "Authorization denied: the delegation was revoked and the gateway "
                    "has durably applied the receiver-b event."
                ),
            }
        ],
        "isError": True,
        "_e_b28": {
            "run_id": context.run_id,
            "decision": "deny",
            "event_jti": context.event_jti,
            "stage": "C4_GATEWAYS_ENFORCED",
        },
    }


def _configuration(trace_path: str | Path) -> tuple[str, str, int, str, str]:
    arm = os.environ.get("E_B28_ARM", "")
    if arm not in ARMS:
        raise ValueError(f"E_B28_ARM must be one of {ARMS}, got {arm!r}")
    run_id = os.environ.get("E_B28_RUN_ID", "")
    if not run_id:
        raise ValueError("E_B28_RUN_ID is required")
    repetition = int(os.environ.get("E_B28_REPETITION", "0"))
    if repetition not in (1, 2):
        raise ValueError("E_B28_REPETITION must be 1 or 2")
    return (
        run_id,
        arm,
        repetition,
        os.environ.get("E_B28_KEYCLOAK_BASE", KEYCLOAK_BASE).rstrip("/"),
        os.environ.get("E_B28_RECEIVER_BASE", RECEIVER_BASE).rstrip("/"),
    )


def install_e_b28_instrumentation(trace_path: str | Path) -> None:
    """Install live barrier hooks after the frozen checkout is on ``sys.path``."""

    from src.agents.mcp.stdio_server import MCPStdioServer
    from src.errors import is_retryable_error
    from src.evaluator import MCPEvaluator

    run_id, arm, repetition, keycloak_base, receiver_base = _configuration(trace_path)
    trace = Path(trace_path).resolve()
    if trace.exists():
        raise FileExistsError(f"E-B28 trace already exists: {trace}")
    original_run_task = MCPEvaluator._run_single_task
    original_call_tool = MCPStdioServer.call_tool

    def traced_run_task(self: object, task: object) -> object:
        service = str(getattr(self, "mcp_service"))
        context = TaskContext(
            run_id=run_id,
            arm=arm,
            repetition=repetition,
            service=service,
            category_id=str(getattr(task, "category_id")),
            task_id=str(getattr(task, "task_id")),
            trace_path=trace,
            keycloak_base=keycloak_base,
            receiver_base=receiver_base,
        )
        token = _TASK_CONTEXT.set(context)
        _append_event(
            context,
            "task_start",
            configured_model=str(getattr(self, "model_name", "")),
            agent_name=str(getattr(self, "agent_name", "")),
            task_started_monotonic_ns=time.monotonic_ns(),
        )
        try:
            result = original_run_task(self, task)
        except BaseException as error:
            _append_event(
                context,
                "task_end",
                task_success=False,
                trace_valid=False,
                infrastructure_error=True,
                wrapper_exception_type=type(error).__name__,
                wrapper_exception=str(error),
                tool_call_count=context.sequence,
                exposure_status="EXPOSED" if context.sequence else "NO_EXPOSURE",
            )
            raise
        else:
            error_message = str(getattr(result, "error_message", "") or "")
            state_setup_failure = error_message == "State Duplication Error"
            retryable = bool(error_message and is_retryable_error(error_message))
            requires_intervention = context.arm in REVOCATION_ARMS and context.sequence > 0
            valid = (
                not state_setup_failure
                and not retryable
                and not context.observer_errors
                and (not requires_intervention or context.intervention_valid is True)
            )
            _append_event(
                context,
                "task_end",
                task_success=bool(getattr(result, "success", False)),
                trace_valid=valid,
                infrastructure_error=not valid,
                error_message=error_message or None,
                verification_error=str(getattr(result, "verification_error", "") or "") or None,
                tool_call_count=context.sequence,
                post_barrier_call_count=max(0, context.sequence - 1) if context.barrier_closed else 0,
                exposure_status="EXPOSED" if context.sequence else "NO_EXPOSURE",
                barrier_closed=context.barrier_closed,
                intervention_valid=context.intervention_valid,
                enforcement_active=context.enforcement_active,
                event_jti=context.event_jti,
                observer_errors=context.observer_errors,
                actual_model=str(getattr(self, "litellm_run_model_name", "") or ""),
            )
            return result
        finally:
            _TASK_CONTEXT.reset(token)

    async def traced_call_tool(self: object, name: str, arguments: dict[str, Any]) -> object:
        context = _TASK_CONTEXT.get()
        if context is None or context.service not in ("filesystem", "postgres"):
            return await original_call_tool(self, name, arguments)

        sequence = context.sequence
        context.sequence += 1
        phase = "active" if context.arm == "active_sanity" else (
            "pre_barrier" if sequence == 0 else "post_barrier"
        )
        state_before: str | None = None
        state_after: str | None = None
        observer_error: str | None = None
        sql_class: str | None = None
        attempted_mutation: bool | None = None
        try:
            state_before = (
                filesystem_merkle_digest(_filesystem_root(self))
                if context.service == "filesystem"
                else _postgres_lsn()
            )
        except Exception as error:
            observer_error = f"before:{type(error).__name__}:{error}"

        deny = (
            phase == "post_barrier"
            and context.arm in ("normal_c4", "recovery_c4")
            and context.enforcement_active
        )
        started_monotonic = time.monotonic_ns()
        started_unix = time.time_ns()
        result: object | None = None
        call_error: BaseException | None = None
        if deny:
            result = _denial_result(context)
        else:
            try:
                result = await original_call_tool(self, name, arguments)
            except BaseException as error:
                call_error = error
        ended_monotonic = time.monotonic_ns()
        ended_unix = time.time_ns()

        try:
            state_after = (
                filesystem_merkle_digest(_filesystem_root(self))
                if context.service == "filesystem"
                else _postgres_lsn()
            )
        except Exception as error:
            suffix = f"after:{type(error).__name__}:{error}"
            observer_error = f"{observer_error};{suffix}" if observer_error else suffix

        success = call_error is None and _result_success(result)
        if context.service == "postgres":
            sql = extract_sql(arguments)
            attempted_mutation = bool(sql and postgres_sql_is_mutating(sql))
            sql_class = "mutation-capable" if attempted_mutation else (
                "read-only" if sql else "no-sql-argument"
            )
        else:
            lowered = name.lower()
            attempted_mutation = any(
                marker in lowered
                for marker in ("write", "edit", "move", "copy", "create", "delete", "remove", "mkdir")
            )
        effect_committed = (
            state_before != state_after
            if state_before is not None and state_after is not None
            else None
        )
        if context.service == "postgres" and attempted_mutation is False:
            effect_committed = False if observer_error is None else None
        if deny and observer_error is None:
            effect_committed = False
        if observer_error:
            context.observer_errors.append(f"call-{sequence}:{observer_error}")

        _append_event(
            context,
            "tool_call",
            call_sequence=sequence,
            phase=phase,
            call_started_monotonic_ns=started_monotonic,
            call_ended_monotonic_ns=ended_monotonic,
            call_started_unix_ns=started_unix,
            call_ended_unix_ns=ended_unix,
            tool_name=name,
            arguments_sha256=canonical_json_hash(arguments),
            result_sha256=canonical_json_hash(result) if result is not None else None,
            success=success,
            denied=deny,
            allowed=not deny,
            attempted_mutation=attempted_mutation,
            effect_committed=effect_committed,
            mutation_observer=(
                "filesystem-normalized-merkle"
                if context.service == "filesystem"
                else "postgres-wal-lsn-plus-frozen-sql-classifier"
            ),
            observer_error=observer_error,
            state_before=state_before,
            state_after=state_after,
            postgres_statement_class=sql_class,
            error_type=type(call_error).__name__ if call_error else None,
            error_message=str(call_error) if call_error else None,
        )

        if sequence == 0 and context.arm in REVOCATION_ARMS:
            # Close before the first result is returned to the unchanged agent.
            context.barrier_closed = True
            barrier_started = time.time_ns()
            _append_event(context, "barrier_closed", after_call_sequence=0, barrier_started_unix_ns=barrier_started)
            try:
                evidence = _trigger_real_revocation(context)
                context.intervention_valid = True
                context.enforcement_active = bool(evidence["c4_gateway_enforced"])
                context.session_id = str(evidence["session_id"])
                context.event_jti = str(evidence["event_jti"])
                context.receiver_state = evidence["receiver_state"]
                _append_event(
                    context,
                    "revocation_intervention",
                    intervention_valid=True,
                    barrier_started_unix_ns=barrier_started,
                    barrier_completed_unix_ns=time.time_ns(),
                    **evidence,
                )
            except Exception as error:
                context.intervention_valid = False
                context.enforcement_active = False
                _append_event(
                    context,
                    "revocation_intervention",
                    intervention_valid=False,
                    barrier_started_unix_ns=barrier_started,
                    barrier_completed_unix_ns=time.time_ns(),
                    error_type=type(error).__name__,
                    error_message=str(error),
                )

        if call_error is not None:
            raise call_error
        return result

    MCPEvaluator._run_single_task = traced_run_task
    MCPStdioServer.call_tool = traced_call_tool


__all__ = [
    "ARMS",
    "MCPMARK_COMMIT",
    "PROTOCOL_VERSION",
    "install_e_b28_instrumentation",
    "verify_frozen_checkout",
]
