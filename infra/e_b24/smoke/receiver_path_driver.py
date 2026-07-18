#!/usr/bin/env python3
"""Exercise signed-SET -> durable receiver -> gateway -> real effects for E-B24."""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import ssl
import time
import urllib.error
import urllib.request
from contextlib import AsyncExitStack
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from revocation_propagation.e_b24_cloud_effects import RemoteEffectStore
from revocation_propagation.e_b24_receiver import SESSION_REVOKED


EXPECTED_ALLOWLIST_SHA256 = (
    "9e76d237213e899486bfd65fad817cedd500cd0820535aa8e953519a24b8e9b2"
)
ISSUER = "https://synthetic-issuer.e-b24.invalid/realms/smoke"
AUDIENCE = "urn:paper-b:e-b24:receiver/stream-1"
KEY_ID = "e-b24-synthetic-set-v1"


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _secret(path: Path) -> str:
    value = path.read_text(encoding="utf-8").strip()
    if not value:
        raise ValueError(f"empty secret file: {path}")
    return value


def _signed_set(*, key_path: Path, delegation_id: str, jti: str) -> str:
    private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    now = int(time.time())
    header = _b64url(
        json.dumps(
            {"alg": "RS256", "kid": KEY_ID, "typ": "secevent+jwt"},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    )
    payload = _b64url(
        json.dumps(
            {
                "iss": ISSUER,
                "aud": AUDIENCE,
                "iat": now,
                "jti": jti,
                "sub_id": {
                    "format": "complex",
                    "session": {"format": "opaque", "id": delegation_id},
                },
                "events": {
                    SESSION_REVOKED: {
                        "event_timestamp": now,
                        "reason_admin": {"en": "E-B24 synthetic receiver smoke"},
                    }
                },
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    )
    signing_input = f"{header}.{payload}".encode("ascii")
    signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{header}.{payload}.{_b64url(signature)}"


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


def _push(
    *,
    url: str,
    encoded_set: str,
    authorization: str,
    ca_file: Path,
) -> tuple[int, dict[str, object]]:
    request = urllib.request.Request(
        url,
        data=encoded_set.encode("ascii"),
        headers={
            "Authorization": authorization,
            "Content-Type": "application/secevent+jwt",
            "Accept": "application/json",
        },
        method="POST",
    )
    context = ssl.create_default_context(cafile=str(ca_file))
    try:
        with urllib.request.urlopen(request, timeout=10, context=context) as response:
            parsed = json.loads(response.read())
            return response.status, parsed
    except urllib.error.HTTPError as error:
        parsed = json.loads(error.read())
        return error.code, parsed


async def run(args: argparse.Namespace) -> dict[str, object]:
    allowlist_bytes = args.allowlist.read_bytes()
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

    delegation_id = f"delegation-{args.run_id}"
    jti = f"set-{args.run_id}"
    active_run = f"{args.run_id}-active"
    revoked_run = f"{args.run_id}-revoked"
    active_arm = "normal-delivery-receiver-smoke"
    revoked_arm = "post-receiver-revocation-smoke"
    encoded_set = _signed_set(
        key_path=args.signing_key_file,
        delegation_id=delegation_id,
        jti=jti,
    )
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
            session, "gateway_status", {"delegation_id": delegation_id}
        )
        for service in ("filesystem", "postgres"):
            result = await _tool(
                session,
                "execute_effect",
                {
                    "delegation_id": delegation_id,
                    "experiment_run": active_run,
                    "arm": active_arm,
                    "vector_payload": json.dumps(
                        selected[service], sort_keys=True, separators=(",", ":")
                    ),
                },
            )
            decisions["active"][service] = _decision_summary(result)

        unauthorized_status, unauthorized_body = _push(
            url=args.receiver_url,
            encoded_set=encoded_set,
            authorization="Bearer intentionally-invalid-smoke-token",
            ca_file=args.ca_file,
        )
        set_parts = encoded_set.split(".")
        set_parts[2] = ("A" if set_parts[2][0] != "A" else "B") + set_parts[2][1:]
        tampered = ".".join(set_parts)
        tampered_status, tampered_body = _push(
            url=args.receiver_url,
            encoded_set=tampered,
            authorization=f"Bearer {receiver_token}",
            ca_file=args.ca_file,
        )
        push_status, push_body = _push(
            url=args.receiver_url,
            encoded_set=encoded_set,
            authorization=f"Bearer {receiver_token}",
            ca_file=args.ca_file,
        )

        deadline = time.monotonic() + 20
        while True:
            status_after = await _tool(
                session, "gateway_status", {"delegation_id": delegation_id}
            )
            if status_after.get("revoked") is True:
                break
            if time.monotonic() >= deadline:
                raise TimeoutError("receiver did not enforce at the gateway within 20 seconds")
            await asyncio.sleep(0.25)

        for service in ("filesystem", "postgres"):
            result = await _tool(
                session,
                "execute_effect",
                {
                    "delegation_id": delegation_id,
                    "experiment_run": revoked_run,
                    "arm": revoked_arm,
                    "vector_payload": json.dumps(
                        selected[service], sort_keys=True, separators=(",", ":")
                    ),
                },
            )
            decisions["revoked"][service] = _decision_summary(result)

    oracles = {
        "active": {
            service: effects[service].oracle(
                experiment_run=active_run, arm=active_arm
            )
            for service in ("filesystem", "postgres")
        },
        "revoked": {
            service: effects[service].oracle(
                experiment_run=revoked_run, arm=revoked_arm
            )
            for service in ("filesystem", "postgres")
        },
    }
    assertions = {
        "frozen_allowlist_unchanged": allowlist_sha256 == EXPECTED_ALLOWLIST_SHA256,
        "status_started_active": status_before.get("revoked") is False,
        "unauthorized_push_rejected": (
            unauthorized_status == 401 and unauthorized_body.get("error") == "unauthorized"
        ),
        "invalid_signature_rejected": (
            tampered_status == 400 and tampered_body.get("error") == "InvalidSignature"
        ),
        "valid_signed_set_persisted_before_202": (
            push_status == 202
            and push_body.get("accepted") is True
            and push_body.get("status") == "PERSISTED"
        ),
        "receiver_handoff_revoked_gateway": (
            status_after.get("revoked") is True
            and status_after.get("event_id") == jti
            and status_after.get("learned_via") == "keycloak-push"
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
        raise RuntimeError(f"one or more receiver-path assertions failed: {assertions}")
    return {
        "experiment": "E-B24 synthetic signed-SET durable-receiver smoke",
        "claim_boundary": (
            "Synthetic issuer smoke only: exercises signed SET validation, persistence, "
            "receiver handoff, gateway enforcement, and real effects; it is not a "
            "Keycloak or selective-non-delivery result."
        ),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "run_id": args.run_id,
        "set_metadata": {
            "issuer": ISSUER,
            "audience": AUDIENCE,
            "key_id": KEY_ID,
            "algorithm": "RS256",
            "jti": jti,
            "encoded_sha256": hashlib.sha256(encoded_set.encode()).hexdigest(),
        },
        "frozen_allowlist_sha256": allowlist_sha256,
        "frozen_vector_count": allowlist["vector_count"],
        "selected_vectors": {
            service: vector["vector_id"] for service, vector in selected.items()
        },
        "negative_push_checks": {
            "unauthorized_http_status": unauthorized_status,
            "tampered_signature_http_status": tampered_status,
            "tampered_signature_error": tampered_body.get("error"),
        },
        "valid_push": {"http_status": push_status, "response": push_body},
        "status_before": status_before,
        "status_after": status_after,
        "decisions": decisions,
        "oracles": oracles,
        "assertions": assertions,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--gateway-mcp-url", required=True)
    parser.add_argument("--receiver-url", required=True)
    parser.add_argument("--effect-url", required=True)
    parser.add_argument("--allowlist", type=Path, required=True)
    parser.add_argument("--ca-file", type=Path, required=True)
    parser.add_argument("--receiver-token-file", type=Path, required=True)
    parser.add_argument("--effect-token-file", type=Path, required=True)
    parser.add_argument("--signing-key-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    evidence = asyncio.run(run(args))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"assertions": evidence["assertions"], "run_id": args.run_id}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
