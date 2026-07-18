"""Runtime instrumentation adapter for the frozen MCPMark E-B20 checkout.

The adapter monkey-patches only observation points around MCPMark's existing
task loop and MCP client call. It does not replace the MCPMarkAgent decision
loop, task prompts, tool schemas, service servers, or verifiers.
"""

from __future__ import annotations

import contextvars
import json
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from .mcpmark_external_trace import (
    MCPMARK_COMMIT,
    PROTOCOL_VERSION,
    canonical_json_hash,
    extract_sql,
    filesystem_merkle_digest,
    postgres_sql_is_mutating,
)


@dataclass
class _TaskContext:
    gateway_id: str
    service: str
    category_id: str
    task_id: str
    run: int
    trace_path: Path
    sequence: int = 0


_TASK_CONTEXT: contextvars.ContextVar[_TaskContext | None] = contextvars.ContextVar(
    "e_b20_task_context", default=None
)


def verify_frozen_checkout(root: str | Path) -> str:
    root_path = Path(root)
    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=root_path, text=True
    ).strip()
    if commit != MCPMARK_COMMIT:
        raise RuntimeError(
            f"E-B20 requires MCPMark {MCPMARK_COMMIT}, checkout is {commit}"
        )
    tracked_diff = subprocess.run(
        ["git", "diff", "--quiet"], cwd=root_path, check=False
    ).returncode
    staged_diff = subprocess.run(
        ["git", "diff", "--cached", "--quiet"], cwd=root_path, check=False
    ).returncode
    if tracked_diff or staged_diff:
        raise RuntimeError("MCPMark checkout has tracked changes; E-B20 requires the frozen code")
    return commit


def prepare_new_trace_dir(trace_dir: str | Path, *, service: str | None = None) -> Path:
    path = Path(trace_dir).resolve()
    path.mkdir(parents=True, exist_ok=True)
    pattern = f"e_b20_{service}_run_*.jsonl" if service else "*.jsonl"
    existing = sorted(path.glob(pattern))
    if existing:
        raise FileExistsError(
            f"trace directory already contains JSONL files: {existing[0]}"
        )
    return path


def _append_event(context: _TaskContext, event_type: str, **fields: object) -> None:
    event = {
        "protocol_version": PROTOCOL_VERSION,
        "mcpmark_commit": MCPMARK_COMMIT,
        "event_type": event_type,
        "gateway_id": context.gateway_id,
        "service": context.service,
        "category_id": context.category_id,
        "task_id": context.task_id,
        "run": context.run,
        "event_wall_time": datetime.now(timezone.utc).isoformat(),
        **fields,
    }
    context.trace_path.parent.mkdir(parents=True, exist_ok=True)
    with context.trace_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True, separators=(",", ":"), default=str) + "\n")


def _run_number(evaluator: object) -> int:
    base = Path(getattr(evaluator, "base_experiment_dir"))
    name = base.name
    if not name.startswith("run-"):
        raise RuntimeError(f"cannot infer MCPMark run number from {base}")
    run = int(name.removeprefix("run-"))
    if run not in (1, 2, 3, 4):
        raise RuntimeError(f"E-B20 requires run number 1--4, found {run}")
    return run


def _filesystem_root(server: object) -> Path:
    params = getattr(server, "params")
    args = list(getattr(params, "args"))
    if not args:
        raise RuntimeError("filesystem MCP server has no root argument")
    return Path(args[-1])


def _result_success(result: object) -> bool:
    if isinstance(result, Mapping):
        return not bool(result.get("isError") or result.get("is_error"))
    return True


def install_mcpmark_instrumentation(trace_dir: str | Path) -> None:
    """Install E-B20 observation hooks after the frozen checkout is on sys.path."""

    from src.agents.mcp.stdio_server import MCPStdioServer
    from src.errors import is_retryable_error
    from src.evaluator import MCPEvaluator

    trace_root = Path(trace_dir).resolve()
    original_run_task = MCPEvaluator._run_single_task
    original_call_tool = MCPStdioServer.call_tool

    def traced_run_task(self: object, task: object) -> object:
        service = str(getattr(self, "mcp_service"))
        category_id = str(getattr(task, "category_id"))
        task_id = str(getattr(task, "task_id"))
        run = _run_number(self)
        context = _TaskContext(
            gateway_id=f"{service}/{category_id}/{task_id}",
            service=service,
            category_id=category_id,
            task_id=task_id,
            run=run,
            trace_path=trace_root / f"e_b20_{service}_run_{run}.jsonl",
        )
        token = _TASK_CONTEXT.set(context)
        _append_event(
            context,
            "task_start",
            task_started_monotonic_ns=time.monotonic_ns(),
            configured_model=str(getattr(self, "model_name", "")),
            agent_name=str(getattr(self, "agent_name", "")),
        )
        try:
            result = original_run_task(self, task)
        except BaseException as exc:
            _append_event(
                context,
                "task_end",
                task_ended_monotonic_ns=time.monotonic_ns(),
                task_success=False,
                trace_valid=False,
                infrastructure_error=True,
                wrapper_exception_type=type(exc).__name__,
                wrapper_exception=str(exc),
                tool_call_count=context.sequence,
            )
            raise
        else:
            error_message = str(getattr(result, "error_message", "") or "")
            verification_error = str(getattr(result, "verification_error", "") or "")
            retryable = bool(error_message and is_retryable_error(error_message))
            state_setup_failure = error_message == "State Duplication Error"
            infrastructure_error = retryable or state_setup_failure
            _append_event(
                context,
                "task_end",
                task_ended_monotonic_ns=time.monotonic_ns(),
                task_success=bool(getattr(result, "success", False)),
                trace_valid=not infrastructure_error,
                infrastructure_error=infrastructure_error,
                error_message=error_message or None,
                verification_error=verification_error or None,
                tool_call_count=context.sequence,
                actual_model=str(getattr(self, "litellm_run_model_name", "") or ""),
            )
            return result
        finally:
            _TASK_CONTEXT.reset(token)

    async def traced_call_tool(
        self: object, name: str, arguments: dict[str, Any]
    ) -> object:
        context = _TASK_CONTEXT.get()
        if context is None or context.service not in ("filesystem", "postgres"):
            return await original_call_tool(self, name, arguments)

        sequence = context.sequence
        context.sequence += 1
        before_digest: str | None = None
        after_digest: str | None = None
        observer_error: str | None = None
        sql_class: str | None = None
        if context.service == "filesystem":
            try:
                before_digest = filesystem_merkle_digest(_filesystem_root(self))
            except Exception as exc:  # retained as an invalid measurement, never guessed
                observer_error = f"before:{type(exc).__name__}:{exc}"

        started = time.monotonic_ns()
        result: object | None = None
        call_error: BaseException | None = None
        try:
            result = await original_call_tool(self, name, arguments)
        except BaseException as exc:
            call_error = exc
        ended = time.monotonic_ns()
        success = call_error is None and _result_success(result)

        mutating: bool | None
        observer: str
        if context.service == "filesystem":
            try:
                after_digest = filesystem_merkle_digest(_filesystem_root(self))
            except Exception as exc:
                suffix = f"after:{type(exc).__name__}:{exc}"
                observer_error = f"{observer_error};{suffix}" if observer_error else suffix
            mutating = (
                before_digest != after_digest
                if before_digest is not None and after_digest is not None
                else None
            )
            observer = "filesystem-normalized-merkle"
        else:
            sql = extract_sql(arguments)
            if sql is None:
                mutating = False
                sql_class = "no-sql-argument"
            else:
                classified = postgres_sql_is_mutating(sql)
                mutating = bool(success and classified)
                sql_class = "mutation-capable" if classified else "read-only"
            observer = "postgres-frozen-sql-classifier"

        _append_event(
            context,
            "tool_call",
            call_sequence=sequence,
            call_started_monotonic_ns=started,
            call_ended_monotonic_ns=ended,
            tool_name=name,
            arguments_sha256=canonical_json_hash(arguments),
            result_sha256=canonical_json_hash(result) if result is not None else None,
            success=success,
            error_type=type(call_error).__name__ if call_error else None,
            error_message=str(call_error) if call_error else None,
            mutating=mutating,
            mutation_observer=observer,
            observer_error=observer_error,
            state_digest_before=before_digest,
            state_digest_after=after_digest,
            postgres_statement_class=sql_class,
        )
        if call_error is not None:
            raise call_error
        return result

    MCPEvaluator._run_single_task = traced_run_task
    MCPStdioServer.call_tool = traced_call_tool
