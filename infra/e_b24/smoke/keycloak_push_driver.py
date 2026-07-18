#!/usr/bin/env python3
"""Exercise live Keycloak PUSH through the E-B24 durable receiver and effects."""

from __future__ import annotations

import argparse
import asyncio
import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import AsyncExitStack
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from revocation_propagation.e_b24_cloud_effects import RemoteEffectStore
from revocation_propagation.e_b24_receiver import SESSION_REVOKED


EXPECTED_ALLOWLIST_SHA256 = (
    "9e76d237213e899486bfd65fad817cedd500cd0820535aa8e953519a24b8e9b2"
)
REALM = "ssf-smoke"
RECEIVER_CLIENT = "receiver-a"


def _secret(path: Path) -> str:
    value = path.read_text(encoding="utf-8").strip()
    if not value:
        raise ValueError(f"empty secret file: {path}")
    return value


def _http(
    url: str,
    *,
    ca_file: Path,
    method: str = "GET",
    json_body: dict[str, object] | None = None,
    form: dict[str, str] | None = None,
    bearer_token: str | None = None,
) -> tuple[int, Any]:
    headers: dict[str, str] = {"Accept": "application/json"}
    data: bytes | None = None
    if json_body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(json_body).encode()
    elif form is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        data = urllib.parse.urlencode(form).encode("ascii")
    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    context = ssl.create_default_context(cafile=str(ca_file))
    try:
        with urllib.request.urlopen(request, timeout=20, context=context) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"{method} request failed with HTTP {error.code}: {detail}") from error


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


async def _tool(
    session: ClientSession, name: str, arguments: dict[str, object]
) -> dict[str, object]:
    result = await session.call_tool(name, arguments)
    if bool(getattr(result, "isError", False)):
        raise RuntimeError(f"MCP tool {name} returned an error")
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


def _status_count(stats: dict[str, object], name: str) -> int:
    statuses = stats.get("statuses", {})
    body = statuses.get(name, {}) if isinstance(statuses, dict) else {}
    return int(body.get("count", 0)) if isinstance(body, dict) else 0


async def run(args: argparse.Namespace) -> dict[str, object]:
    allowlist_bytes = args.allowlist.read_bytes()
    import hashlib

    allowlist_sha256 = hashlib.sha256(allowlist_bytes).hexdigest()
    if allowlist_sha256 != EXPECTED_ALLOWLIST_SHA256:
        raise ValueError("frozen allowlist hash mismatch")
    allowlist = json.loads(allowlist_bytes)
    if allowlist.get("vector_count") != 225:
        raise ValueError("frozen allowlist vector count changed")
    vectors = allowlist.get("vectors", [])
    selected = {
        service: next(vector for vector in vectors if vector["service"] == service)
        for service in ("filesystem", "postgres")
    }

    keycloak_base = args.keycloak_url.rstrip("/")
    admin_password = _secret(args.keycloak_admin_password_file)
    receiver_token = _secret(args.receiver_token_file)
    effect_token = _secret(args.effect_token_file)
    effects = {
        service: RemoteEffectStore(
            service=service,
            base_url=args.effect_url,
            bearer_token=effect_token,
            ca_file=str(args.ca_file),
        )
        for service in ("filesystem", "postgres")
    }

    _, token_body = _http(
        f"{keycloak_base}/realms/master/protocol/openid-connect/token",
        ca_file=args.ca_file,
        method="POST",
        form={
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": "admin",
            "password": admin_password,
        },
    )
    admin_token = str(token_body["access_token"])
    _, clients = _http(
        f"{keycloak_base}/admin/realms/{REALM}/clients?clientId={RECEIVER_CLIENT}",
        ca_file=args.ca_file,
        bearer_token=admin_token,
    )
    if not isinstance(clients, list) or len(clients) != 1:
        raise RuntimeError("expected exactly one Keycloak receiver client")
    internal_id = str(clients[0]["id"])
    _, client = _http(
        f"{keycloak_base}/admin/realms/{REALM}/clients/{internal_id}",
        ca_file=args.ca_file,
        bearer_token=admin_token,
    )
    attributes = dict(client.get("attributes", {}))
    attributes["ssf.validPushUrls"] = args.receiver_url
    client["attributes"] = attributes
    update_status, _ = _http(
        f"{keycloak_base}/admin/realms/{REALM}/clients/{internal_id}",
        ca_file=args.ca_file,
        method="PUT",
        json_body=client,
        bearer_token=admin_token,
    )

    stream_status, stream = _http(
        f"{keycloak_base}/admin/realms/{REALM}/ssf/clients/{RECEIVER_CLIENT}/stream",
        ca_file=args.ca_file,
        method="POST",
        json_body={
            "description": "E-B24 live Keycloak PUSH three-host smoke",
            "events_requested": [SESSION_REVOKED],
            "delivery": {
                "method": "urn:ietf:rfc:8935",
                "endpoint_url": args.receiver_url,
                "authorization_header": f"Bearer {receiver_token}",
            },
        },
        bearer_token=admin_token,
    )
    stream_summary = {
        "http_status": stream_status,
        "stream_id": stream.get("stream_id") or stream.get("id"),
        "delivery_method": stream.get("delivery", {}).get("method"),
        "endpoint_url": stream.get("delivery", {}).get("endpoint_url"),
    }
    stats_before = _http(
        f"{keycloak_base}/admin/realms/{REALM}/ssf/events/stats",
        ca_file=args.ca_file,
        bearer_token=admin_token,
    )[1]

    _, login = _http(
        f"{keycloak_base}/realms/{REALM}/protocol/openid-connect/token",
        ca_file=args.ca_file,
        method="POST",
        form={
            "grant_type": "password",
            "client_id": "workload-client",
            "username": "alice",
            "password": "alice-smoke-password",
        },
    )
    session_id = str(login["session_state"])
    active_run = f"{args.run_id}-active"
    revoked_run = f"{args.run_id}-revoked"
    active_arm = "normal-delivery-keycloak-push-smoke"
    revoked_arm = "post-keycloak-push-revocation-smoke"
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
        status_before = await _tool(
            session, "gateway_status", {"delegation_id": session_id}
        )
        for service in ("filesystem", "postgres"):
            result = await _tool(
                session,
                "execute_effect",
                {
                    "delegation_id": session_id,
                    "experiment_run": active_run,
                    "arm": active_arm,
                    "vector_payload": json.dumps(
                        selected[service], sort_keys=True, separators=(",", ":")
                    ),
                },
            )
            decisions["active"][service] = _decision_summary(result)

        logout_status, _ = _http(
            f"{keycloak_base}/realms/{REALM}/protocol/openid-connect/logout",
            ca_file=args.ca_file,
            method="POST",
            form={
                "client_id": "workload-client",
                "refresh_token": str(login["refresh_token"]),
            },
        )
        deadline = time.monotonic() + 45
        while True:
            status_after = await _tool(
                session, "gateway_status", {"delegation_id": session_id}
            )
            if status_after.get("revoked") is True:
                break
            if time.monotonic() >= deadline:
                raise TimeoutError("Keycloak PUSH did not reach gateway enforcement in 45 seconds")
            await asyncio.sleep(0.25)

        for service in ("filesystem", "postgres"):
            result = await _tool(
                session,
                "execute_effect",
                {
                    "delegation_id": session_id,
                    "experiment_run": revoked_run,
                    "arm": revoked_arm,
                    "vector_payload": json.dumps(
                        selected[service], sort_keys=True, separators=(",", ":")
                    ),
                },
            )
            decisions["revoked"][service] = _decision_summary(result)

    stats_deadline = time.monotonic() + 20
    while True:
        stats_after = _http(
            f"{keycloak_base}/admin/realms/{REALM}/ssf/events/stats",
            ca_file=args.ca_file,
            bearer_token=admin_token,
        )[1]
        if _status_count(stats_after, "DELIVERED") > _status_count(stats_before, "DELIVERED"):
            break
        if time.monotonic() >= stats_deadline:
            raise TimeoutError("Keycloak outbox did not report a delivered event")
        time.sleep(0.25)

    oracles = {
        "active": {
            service: effects[service].oracle(experiment_run=active_run, arm=active_arm)
            for service in ("filesystem", "postgres")
        },
        "revoked": {
            service: effects[service].oracle(experiment_run=revoked_run, arm=revoked_arm)
            for service in ("filesystem", "postgres")
        },
    }
    assertions = {
        "frozen_allowlist_unchanged": allowlist_sha256 == EXPECTED_ALLOWLIST_SHA256,
        "keycloak_client_push_url_updated": update_status == 204,
        "keycloak_rfc8935_stream_created": (
            stream_status == 201
            and stream_summary["delivery_method"] == "urn:ietf:rfc:8935"
            and stream_summary["endpoint_url"] == args.receiver_url
        ),
        "status_started_active": status_before.get("revoked") is False,
        "keycloak_logout_succeeded": logout_status in {200, 204},
        "keycloak_push_reached_gateway": (
            status_after.get("revoked") is True
            and status_after.get("learned_via") == "keycloak-push"
            and bool(status_after.get("event_id"))
        ),
        "keycloak_outbox_delivered": (
            _status_count(stats_after, "DELIVERED")
            > _status_count(stats_before, "DELIVERED")
        ),
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
        raise RuntimeError(f"one or more Keycloak PUSH assertions failed: {assertions}")
    return {
        "experiment": "E-B24 live Keycloak PUSH three-host smoke",
        "claim_boundary": (
            "Three-host service smoke only: one Keycloak PUSH, one durable receiver, "
            "one gateway, and two real effects; no selective non-delivery fault, "
            "eight-gateway topology, or confirmatory outcome ran."
        ),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "run_id": args.run_id,
        "pinned_images": {
            "keycloak": "quay.io/keycloak/keycloak:26.7.0@sha256:2eb3cd316835c990e69e26ade292ffa78f6fb0db7d5fc6377463c162e1979ac0",
            "postgres": "pgvector/pgvector:0.8.0-pg17-bookworm@sha256:40b404964359299eefdd5f8518facf1886c562848cf4de13b6eaf91cb70c2b87",
        },
        "frozen_allowlist_sha256": allowlist_sha256,
        "frozen_vector_count": allowlist["vector_count"],
        "stream": stream_summary,
        "logout_http_status": logout_status,
        "keycloak_outbox": {
            "delivered_before": _status_count(stats_before, "DELIVERED"),
            "delivered_after": _status_count(stats_after, "DELIVERED"),
            "pending_after": _status_count(stats_after, "PENDING"),
        },
        "session_id_sha256": hashlib.sha256(session_id.encode()).hexdigest(),
        "receiver_jti": status_after.get("event_id"),
        "status_before": status_before,
        "status_after": status_after,
        "decisions": decisions,
        "oracles": oracles,
        "assertions": assertions,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--keycloak-url", required=True)
    parser.add_argument("--receiver-url", required=True)
    parser.add_argument("--gateway-mcp-url", required=True)
    parser.add_argument("--effect-url", required=True)
    parser.add_argument("--allowlist", type=Path, required=True)
    parser.add_argument("--ca-file", type=Path, required=True)
    parser.add_argument("--keycloak-admin-password-file", type=Path, required=True)
    parser.add_argument("--receiver-token-file", type=Path, required=True)
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
