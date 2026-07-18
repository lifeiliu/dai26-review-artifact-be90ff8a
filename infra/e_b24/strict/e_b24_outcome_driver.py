#!/usr/bin/env python3
"""Frozen workload-side phase runner for E-B24 confirmatory execution."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import AsyncExitStack
from pathlib import Path
from typing import Any, Mapping, Sequence

from revocation_propagation.real_llm_mcp_harness import (
    _mcp_result_payload,
    _open_mcp_session,
)


PROTOCOL_VERSION = "e-b24-prereg-v1"
EXPECTED_ALLOWLIST_SHA256 = (
    "9e76d237213e899486bfd65fad817cedd500cd0820535aa8e953519a24b8e9b2"
)
REALM = "ssf-smoke"
GATEWAY_COUNT = 8
RECEIVER_A_GATEWAYS = frozenset(range(1, 5))
RECEIVER_B_GATEWAYS = frozenset(range(5, 9))
PHASES = ("normal", "receiver_gateway_fault", "recovery")


def canonical_json(value: object) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_schedule(path: Path) -> tuple[list[dict[str, object]], dict[str, object]]:
    observed_sha256 = sha256_file(path)
    if observed_sha256 != EXPECTED_ALLOWLIST_SHA256:
        raise ValueError("frozen E-B24 allowlist digest changed")
    payload = json.loads(path.read_text(encoding="utf-8"))
    vectors = payload.get("vectors")
    if payload.get("design_version") != "e-b24-design-v1":
        raise ValueError("E-B24 allowlist design version changed")
    if not isinstance(vectors, list) or len(vectors) != 225:
        raise ValueError("E-B24 requires exactly 225 frozen vectors")
    normalized: list[dict[str, object]] = []
    vector_ids: set[str] = set()
    for index, vector in enumerate(vectors):
        if not isinstance(vector, dict):
            raise ValueError("frozen vector is not an object")
        vector_id = str(vector.get("vector_id", ""))
        if not vector_id or vector_id in vector_ids:
            raise ValueError("frozen vector IDs are empty or duplicated")
        vector_ids.add(vector_id)
        item = dict(vector)
        item["physical_gateway"] = (index % GATEWAY_COUNT) + 1
        normalized.append(item)
    service_counts = {
        service: sum(int(item.get("service") == service) for item in normalized)
        for service in ("filesystem", "postgres")
    }
    receiver_counts = {
        "receiver-a": sum(
            int(int(item["physical_gateway"]) in RECEIVER_A_GATEWAYS)
            for item in normalized
        ),
        "receiver-b": sum(
            int(int(item["physical_gateway"]) in RECEIVER_B_GATEWAYS)
            for item in normalized
        ),
    }
    receiver_service_counts = {
        receiver: {
            service: sum(
                int(
                    int(item["physical_gateway"]) in gateways
                    and item.get("service") == service
                )
                for item in normalized
            )
            for service in ("filesystem", "postgres")
        }
        for receiver, gateways in (
            ("receiver-a", RECEIVER_A_GATEWAYS),
            ("receiver-b", RECEIVER_B_GATEWAYS),
        )
    }
    if service_counts != {"filesystem": 112, "postgres": 113}:
        raise ValueError("frozen service counts changed")
    if receiver_counts != {"receiver-a": 113, "receiver-b": 112}:
        raise ValueError("physical gateway schedule changed")
    if receiver_service_counts["receiver-b"] != {
        "filesystem": 56,
        "postgres": 56,
    }:
        raise ValueError("frozen 50% receiver-B boundary changed")
    manifest = {
        "allowlist_sha256": observed_sha256,
        "vector_count": len(normalized),
        "service_counts": service_counts,
        "receiver_counts": receiver_counts,
        "receiver_service_counts": receiver_service_counts,
        "physical_assignment": "zero_based_vector_index_mod_8_plus_1",
    }
    return normalized, manifest


def _http(
    url: str,
    *,
    ca_file: Path,
    method: str = "GET",
    form: Mapping[str, str] | None = None,
) -> tuple[int, Any]:
    headers = {"Accept": "application/json"}
    data = None
    if form is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        data = urllib.parse.urlencode(dict(form)).encode("ascii")
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    context = ssl.create_default_context(cafile=str(ca_file))
    try:
        with urllib.request.urlopen(request, timeout=20, context=context) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"{method} {url} failed with HTTP {error.code}: {detail}") from error


def login(keycloak: str, ca_file: Path) -> dict[str, object]:
    status, body = _http(
        f"{keycloak}/realms/{REALM}/protocol/openid-connect/token",
        ca_file=ca_file,
        method="POST",
        form={
            "grant_type": "password",
            "client_id": "workload-client",
            "username": "alice",
            "password": "alice-smoke-password",
        },
    )
    if status != 200 or not isinstance(body, dict):
        raise RuntimeError("Keycloak login did not return a token object")
    return body


def logout(keycloak: str, ca_file: Path, refresh_token: str) -> int:
    status, _ = _http(
        f"{keycloak}/realms/{REALM}/protocol/openid-connect/logout",
        ca_file=ca_file,
        method="POST",
        form={"client_id": "workload-client", "refresh_token": refresh_token},
    )
    return status


async def call_mcp(
    session: Any, tool: str, arguments: Mapping[str, object]
) -> dict[str, object]:
    result = await session.call_tool(tool, dict(arguments))
    if result.isError:
        raise RuntimeError(f"MCP tool {tool} returned an error: {result.content}")
    return _mcp_result_payload(result)


async def gateway_statuses(
    sessions: Mapping[int, Any], delegation_id: str
) -> dict[str, dict[str, object]]:
    values = await asyncio.gather(
        *(
            call_mcp(
                sessions[index],
                "gateway_status",
                {"delegation_id": delegation_id},
            )
            for index in range(1, GATEWAY_COUNT + 1)
        )
    )
    return {f"gateway-{index}": value for index, value in enumerate(values, 1)}


def expected_revoked(phase: str) -> dict[str, bool]:
    if phase in {"normal", "recovery"}:
        return {f"gateway-{index}": True for index in range(1, GATEWAY_COUNT + 1)}
    if phase == "receiver_gateway_fault":
        return {
            f"gateway-{index}": index in RECEIVER_A_GATEWAYS
            for index in range(1, GATEWAY_COUNT + 1)
        }
    raise ValueError(f"unsupported E-B24 phase: {phase}")


async def wait_gateway_pattern(
    sessions: Mapping[int, Any],
    *,
    delegation_id: str,
    phase: str,
    timeout_seconds: float,
) -> tuple[dict[str, dict[str, object]], float]:
    expected = expected_revoked(phase)
    deadline = time.monotonic() + timeout_seconds
    started = time.monotonic()
    last: dict[str, dict[str, object]] = {}
    while time.monotonic() < deadline:
        last = await gateway_statuses(sessions, delegation_id)
        observed = {name: bool(body.get("revoked")) for name, body in last.items()}
        if observed == expected:
            return last, time.monotonic() - started
        await asyncio.sleep(0.25)
    raise TimeoutError(
        f"gateway pattern did not reach {expected}; last={last}"
    )


async def replay(
    sessions: Mapping[int, Any],
    *,
    vectors: Sequence[Mapping[str, object]],
    delegation_id: str,
    experiment_run: str,
    arm: str,
) -> list[dict[str, object]]:
    grouped = {
        index: [item for item in vectors if int(item["physical_gateway"]) == index]
        for index in range(1, GATEWAY_COUNT + 1)
    }

    async def one_gateway(index: int) -> list[dict[str, object]]:
        rows: list[dict[str, object]] = []
        for vector in grouped[index]:
            payload = {key: value for key, value in vector.items() if key != "physical_gateway"}
            started_wall_ns = time.time_ns()
            started = time.perf_counter_ns()
            response = await call_mcp(
                sessions[index],
                "execute_effect",
                {
                    "delegation_id": delegation_id,
                    "experiment_run": experiment_run,
                    "arm": arm,
                    "vector_payload": canonical_json(payload),
                },
            )
            rows.append(
                {
                    "protocol_version": PROTOCOL_VERSION,
                    "experiment_run": experiment_run,
                    "arm": arm,
                    "physical_gateway": index,
                    "vector_id": payload["vector_id"],
                    "service": payload["service"],
                    "allowed": bool(response.get("allowed")),
                    "effect_committed_reported": bool(
                        isinstance(response.get("effect"), dict)
                        and response["effect"].get("committed")
                    ),
                    "decision_id": response.get("decision_id"),
                    "started_wall_ns": started_wall_ns,
                    "finished_wall_ns": time.time_ns(),
                    "latency_ms": (time.perf_counter_ns() - started) / 1_000_000.0,
                }
            )
        return rows

    batches = await asyncio.gather(
        *(one_gateway(index) for index in range(1, GATEWAY_COUNT + 1))
    )
    rows = [row for batch in batches for row in batch]
    rows.sort(key=lambda row: str(row["vector_id"]))
    if len(rows) != 225:
        raise RuntimeError("E-B24 replay did not produce exactly 225 rows")
    return rows


async def run_phase(args: argparse.Namespace) -> dict[str, object]:
    vectors, schedule = load_schedule(args.allowlist)
    output_dir = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=False)
    keycloak = args.keycloak_url.rstrip("/")
    experiment_run = f"eb24-cf-v1-b{args.block:02d}-{args.phase}"
    arm = args.phase
    trace_path = output_dir / "replay.jsonl"
    started_ns = time.time_ns()

    async with AsyncExitStack() as stack:
        sessions = {
            index: await _open_mcp_session(
                stack, f"http://gateway-{index}:8000/mcp"
            )
            for index in range(1, GATEWAY_COUNT + 1)
        }
        logout_status: int | None = None
        if args.phase == "recovery":
            if not args.delegation_id:
                raise ValueError("recovery requires --delegation-id")
            delegation_id = args.delegation_id
            pre_statuses = await gateway_statuses(sessions, delegation_id)
        else:
            if args.delegation_id:
                raise ValueError("new logout phases cannot accept --delegation-id")
            token = login(keycloak, args.ca_file)
            delegation_id = str(token.get("session_state", ""))
            refresh_token = str(token.get("refresh_token", ""))
            if not delegation_id or not refresh_token:
                raise RuntimeError("Keycloak login omitted session identity")
            pre_statuses = await gateway_statuses(sessions, delegation_id)
            if any(bool(body.get("revoked")) for body in pre_statuses.values()):
                raise RuntimeError("fresh Keycloak delegation was already revoked")
            logout_status = logout(keycloak, args.ca_file, refresh_token)
            if logout_status not in {200, 204}:
                raise RuntimeError(f"Keycloak logout returned {logout_status}")

        pattern_statuses, pattern_elapsed = await wait_gateway_pattern(
            sessions,
            delegation_id=delegation_id,
            phase=args.phase,
            timeout_seconds=args.pattern_timeout_seconds,
        )
        rows = await replay(
            sessions,
            vectors=vectors,
            delegation_id=delegation_id,
            experiment_run=experiment_run,
            arm=arm,
        )
        final_statuses = await gateway_statuses(sessions, delegation_id)

    with trace_path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(canonical_json(row) + "\n")
    allowed = sum(int(row["allowed"]) for row in rows)
    committed = sum(int(row["effect_committed_reported"]) for row in rows)
    summary = {
        "protocol_version": PROTOCOL_VERSION,
        "block": args.block,
        "phase": args.phase,
        "experiment_run": experiment_run,
        "arm": arm,
        "delegation_id": delegation_id,
        "logout_http_status": logout_status,
        "started_ns": started_ns,
        "finished_ns": time.time_ns(),
        "gateway_pattern_elapsed_seconds": pattern_elapsed,
        "pre_statuses": pre_statuses,
        "pattern_statuses": pattern_statuses,
        "final_statuses": final_statuses,
        "schedule": schedule,
        "counts": {
            "rows": len(rows),
            "allowed": allowed,
            "denied": len(rows) - allowed,
            "effect_committed_reported": committed,
        },
        "trace_sha256": sha256_file(trace_path),
    }
    (output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(
        "e-b24-outcome-phase="
        + canonical_json(
            {
                "protocol_version": PROTOCOL_VERSION,
                "block": args.block,
                "phase": args.phase,
                "delegation_id": delegation_id,
                "experiment_run": experiment_run,
                "counts": summary["counts"],
                "trace_sha256": summary["trace_sha256"],
            }
        )
    )
    return summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--allowlist", type=Path, required=True)
    parser.add_argument("--validate-inputs-only", action="store_true")
    parser.add_argument("--phase", choices=PHASES)
    parser.add_argument("--block", type=int)
    parser.add_argument("--delegation-id")
    parser.add_argument("--keycloak-url", default="https://keycloak:8443")
    parser.add_argument("--ca-file", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--pattern-timeout-seconds", type=float, default=45.0)
    args = parser.parse_args()
    if args.validate_inputs_only:
        return args
    required = {
        "--phase": args.phase,
        "--block": args.block,
        "--ca-file": args.ca_file,
        "--output-dir": args.output_dir,
    }
    missing = [name for name, value in required.items() if value is None]
    if missing:
        parser.error(f"missing outcome arguments: {', '.join(missing)}")
    if not 1 <= args.block <= 30:
        parser.error("--block must be between 1 and 30")
    return args


def main() -> int:
    args = parse_args()
    if args.validate_inputs_only:
        _, manifest = load_schedule(args.allowlist)
        print(canonical_json({"protocol_version": PROTOCOL_VERSION, **manifest}))
        return 0
    asyncio.run(run_phase(args))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

