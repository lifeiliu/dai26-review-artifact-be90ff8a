#!/usr/bin/env python3
"""Exercise the E-B24 MCP gateway and authoritative remote effects boundary."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
from contextlib import AsyncExitStack
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from revocation_propagation.e_b24_cloud_effects import RemoteEffectStore
from revocation_propagation.e_b24_gateway_control import GatewayControlClient


EXPECTED_ALLOWLIST_SHA256 = (
    "9e76d237213e899486bfd65fad817cedd500cd0820535aa8e953519a24b8e9b2"
)


def _secret(path: Path) -> str:
    value = path.read_text(encoding="utf-8").strip()
    if not value:
        raise ValueError(f"empty secret file: {path}")
    return value


def _vector_payload(vector: dict[str, object]) -> str:
    return json.dumps(vector, sort_keys=True, separators=(",", ":"))


def _result_payload(result: Any) -> dict[str, object]:
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


async def _call(
    session: ClientSession,
    *,
    delegation_id: str,
    experiment_run: str,
    arm: str,
    vector: dict[str, object],
) -> dict[str, object]:
    result = await session.call_tool(
        "execute_effect",
        {
            "delegation_id": delegation_id,
            "experiment_run": experiment_run,
            "arm": arm,
            "vector_payload": _vector_payload(vector),
        },
    )
    if bool(getattr(result, "isError", False)):
        raise RuntimeError("MCP execute_effect returned an error")
    return _result_payload(result)


def _decision_summary(result: dict[str, object]) -> dict[str, object]:
    effect = result.get("effect")
    return {
        "allowed": result.get("allowed"),
        "reason": result.get("reason"),
        "vector_id": result.get("vector_id"),
        "event_id": result.get("event_id"),
        "learned_via": result.get("learned_via"),
        "effect_committed": (
            effect.get("committed") if isinstance(effect, dict) else None
        ),
        "effect_type": effect.get("effect_type") if isinstance(effect, dict) else None,
    }


async def run(args: argparse.Namespace) -> dict[str, object]:
    allowlist_bytes = args.allowlist.read_bytes()
    allowlist_sha256 = hashlib.sha256(allowlist_bytes).hexdigest()
    if allowlist_sha256 != EXPECTED_ALLOWLIST_SHA256:
        raise ValueError(
            "frozen allowlist hash mismatch: "
            f"expected {EXPECTED_ALLOWLIST_SHA256}, observed {allowlist_sha256}"
        )
    allowlist = json.loads(allowlist_bytes)
    if allowlist.get("vector_count") != 225:
        raise ValueError("frozen allowlist vector count changed")
    vectors = allowlist.get("vectors", [])
    selected = {
        service: next(vector for vector in vectors if vector["service"] == service)
        for service in ("filesystem", "postgres")
    }

    gateway_token = _secret(args.gateway_token_file)
    effect_token = _secret(args.effect_token_file)
    control = GatewayControlClient(
        base_url=args.gateway_control_url,
        bearer_token=gateway_token,
        ca_file=str(args.ca_file),
    )
    effects = {
        service: RemoteEffectStore(
            service=service,
            base_url=args.effect_url,
            bearer_token=effect_token,
            ca_file=str(args.ca_file),
        )
        for service in ("filesystem", "postgres")
    }

    active_run = f"{args.run_id}-active"
    revoked_run = f"{args.run_id}-revoked"
    active_arm = "normal-delivery-smoke"
    revoked_arm = "post-revocation-smoke"
    delegation_id = f"delegation-{args.run_id}"
    event_id = f"event-{args.run_id}"

    status_before = control.status(delegation_id)
    decisions: dict[str, dict[str, dict[str, object]]] = {"active": {}, "revoked": {}}
    async with AsyncExitStack() as stack:
        read_stream, write_stream, _ = await stack.enter_async_context(
            streamable_http_client(args.gateway_mcp_url, terminate_on_close=True)
        )
        session = await stack.enter_async_context(
            ClientSession(
                read_stream,
                write_stream,
                read_timeout_seconds=timedelta(seconds=30),
            )
        )
        await session.initialize()
        for service in ("filesystem", "postgres"):
            result = await _call(
                session,
                delegation_id=delegation_id,
                experiment_run=active_run,
                arm=active_arm,
                vector=selected[service],
            )
            decisions["active"][service] = _decision_summary(result)

        revocation = control.apply_revocation(
            {
                "delegation_id": delegation_id,
                "event_id": event_id,
                "channel": "direct-tls-control-smoke",
                "sequence": 1,
            }
        )
        status_after = control.status(delegation_id)

        for service in ("filesystem", "postgres"):
            result = await _call(
                session,
                delegation_id=delegation_id,
                experiment_run=revoked_run,
                arm=revoked_arm,
                vector=selected[service],
            )
            decisions["revoked"][service] = _decision_summary(result)

    oracles = {
        "active": {
            service: effects[service].oracle(
                experiment_run=active_run,
                arm=active_arm,
            )
            for service in ("filesystem", "postgres")
        },
        "revoked": {
            service: effects[service].oracle(
                experiment_run=revoked_run,
                arm=revoked_arm,
            )
            for service in ("filesystem", "postgres")
        },
    }
    assertions = {
        "frozen_allowlist_unchanged": allowlist_sha256 == EXPECTED_ALLOWLIST_SHA256,
        "status_started_active": status_before.get("revoked") is False,
        "tls_control_applied_revocation": revocation.get("applied") is True,
        "status_ended_revoked": status_after.get("revoked") is True,
        "active_filesystem_committed": (
            decisions["active"]["filesystem"]["allowed"] is True
            and decisions["active"]["filesystem"]["effect_committed"] is True
            and oracles["active"]["filesystem"].get("count") == 1
        ),
        "active_postgres_committed": (
            decisions["active"]["postgres"]["allowed"] is True
            and decisions["active"]["postgres"]["effect_committed"] is True
            and oracles["active"]["postgres"].get("count") == 1
        ),
        "revoked_filesystem_denied_without_effect": (
            decisions["revoked"]["filesystem"]["allowed"] is False
            and decisions["revoked"]["filesystem"]["effect_committed"] is None
            and oracles["revoked"]["filesystem"].get("count") == 0
        ),
        "revoked_postgres_denied_without_effect": (
            decisions["revoked"]["postgres"]["allowed"] is False
            and decisions["revoked"]["postgres"]["effect_committed"] is None
            and oracles["revoked"]["postgres"].get("count") == 0
        ),
    }
    if not all(assertions.values()):
        raise RuntimeError(f"one or more smoke assertions failed: {assertions}")
    return {
        "experiment": "E-B24 gateway-to-authoritative-effect smoke",
        "claim_boundary": (
            "Service-path smoke only: direct authenticated TLS control was used; "
            "no Keycloak SET, durable receiver, selective non-delivery, or fault arm ran."
        ),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "run_id": args.run_id,
        "frozen_allowlist_sha256": allowlist_sha256,
        "frozen_vector_count": allowlist["vector_count"],
        "selected_vectors": {
            service: vector["vector_id"] for service, vector in selected.items()
        },
        "status_before": status_before,
        "revocation": revocation,
        "status_after": status_after,
        "decisions": decisions,
        "oracles": oracles,
        "assertions": assertions,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--gateway-mcp-url", required=True)
    parser.add_argument("--gateway-control-url", required=True)
    parser.add_argument("--effect-url", required=True)
    parser.add_argument("--allowlist", type=Path, required=True)
    parser.add_argument("--ca-file", type=Path, required=True)
    parser.add_argument("--gateway-token-file", type=Path, required=True)
    parser.add_argument("--effect-token-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    evidence = asyncio.run(run(args))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"assertions": evidence["assertions"], "run_id": args.run_id}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
