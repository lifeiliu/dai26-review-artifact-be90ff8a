#!/usr/bin/env python3
"""Finish the private half of an adjudicated E-B24 infrastructure pilot.

The original outcome-blind pilot created receiver-a's stream and then timed out
when the workload driver correctly could not enter the Keycloak-EIP-only ALB.
This continuation creates only receiver-b's missing stream and checks private
service health. It never emits a revocation event or invokes a workload effect.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType


REALM = "ssf-smoke"
SESSION_REVOKED = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"


def _load_base(path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location("strict_infrastructure_pilot_base", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import base pilot: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-pilot", type=Path, required=True)
    parser.add_argument("--keycloak-url", required=True)
    parser.add_argument("--receiver-a-url", required=True)
    parser.add_argument("--receiver-b-url", required=True)
    parser.add_argument("--ca-file", type=Path, required=True)
    parser.add_argument("--keycloak-admin-password-file", type=Path, required=True)
    parser.add_argument("--receiver-b-token-file", type=Path, required=True)
    parser.add_argument("--source-command-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    base = _load_base(args.base_pilot)
    keycloak = args.keycloak_url.rstrip("/")
    _, discovery = base._http(
        f"{keycloak}/realms/{REALM}/.well-known/openid-configuration",
        ca_file=args.ca_file,
    )
    _, token_body = base._http(
        f"{keycloak}/realms/master/protocol/openid-connect/token",
        ca_file=args.ca_file,
        method="POST",
        form={
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": "admin",
            "password": base._secret(args.keycloak_admin_password_file),
        },
    )
    admin_token = str(token_body["access_token"])

    receiver_a_id, receiver_a_client = base._client(
        keycloak=keycloak,
        ca_file=args.ca_file,
        token=admin_token,
        client_id="receiver-a",
    )
    del receiver_a_id
    receiver_a_attributes = dict(receiver_a_client.get("attributes", {}))

    resolved_b = base._public_addresses(args.receiver_b_url)
    receiver_b_id, receiver_b_client = base._client(
        keycloak=keycloak,
        ca_file=args.ca_file,
        token=admin_token,
        client_id="receiver-b",
    )
    receiver_b_attributes = dict(receiver_b_client.get("attributes", {}))
    receiver_b_attributes["ssf.validPushUrls"] = args.receiver_b_url
    receiver_b_client["attributes"] = receiver_b_attributes
    update_status, _ = base._http(
        f"{keycloak}/admin/realms/{REALM}/clients/{receiver_b_id}",
        ca_file=args.ca_file,
        method="PUT",
        json_body=receiver_b_client,
        bearer_token=admin_token,
    )
    stream_status, stream = base._http(
        f"{keycloak}/admin/realms/{REALM}/ssf/clients/receiver-b/stream",
        ca_file=args.ca_file,
        method="POST",
        json_body={
            "description": "E-B24 adjudicated outcome-blind infrastructure pilot",
            "events_requested": [SESSION_REVOKED],
            "delivery": {
                "method": "urn:ietf:rfc:8935",
                "endpoint_url": args.receiver_b_url,
                "authorization_header": (
                    f"Bearer {base._secret(args.receiver_b_token_file)}"
                ),
            },
        },
        bearer_token=admin_token,
    )

    private_health_urls = {
        **{
            f"gateway-{index}": f"https://gateway-{index}:9444/health"
            for index in range(1, 9)
        },
        "filesystem-effects": "https://filesystem-effects:9443/health",
        "postgres-effects": "https://postgres-effects:9443/health",
        "receiver-a-private": "https://receiver-a:8443/health",
        "receiver-b-private": "https://receiver-b:8443/health",
    }
    private_health: dict[str, object] = {}
    for name, url in private_health_urls.items():
        status, body = base._http(url, ca_file=args.ca_file)
        private_health[name] = {"http_status": status, "body": body}

    assertions = {
        "keycloak_discovery_realm_matches": discovery.get("issuer")
        == f"{keycloak}/realms/{REALM}",
        "receiver_a_exact_url_persisted_by_source_command": receiver_a_attributes.get(
            "ssf.validPushUrls"
        )
        == args.receiver_a_url,
        "receiver_b_hostname_resolves_only_global": bool(resolved_b),
        "receiver_b_exact_push_url_accepted": update_status == 204
        and stream_status in {200, 201}
        and bool(stream.get("stream_id") or stream.get("id"))
        and stream.get("delivery", {}).get("method") == "urn:ietf:rfc:8935"
        and stream.get("delivery", {}).get("endpoint_url") == args.receiver_b_url,
        "all_private_service_health_checks_pass": all(
            item["http_status"] == 200 for item in private_health.values()
        ),
    }
    if not all(assertions.values()):
        raise RuntimeError(f"private continuation assertions failed: {assertions}")

    report = {
        "experiment": "E-B24 adjudicated strict infrastructure pilot continuation",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_command_id": args.source_command_id,
        "claim_boundary": (
            "Infrastructure qualification only. No logout/revocation, workload "
            "replay, gateway decision contrast, or effect mutation was executed."
        ),
        "deviation": (
            "Public ALB health is checked separately from the Keycloak host because "
            "the strict ALB ingress intentionally excludes the workload driver."
        ),
        "receiver_a": {
            "exact_url_persisted": True,
            "stream_creation_basis": (
                "The source command reached its post-stream ALB health call without "
                "an earlier exception."
            ),
        },
        "receiver_b": {
            "resolved_public_addresses": resolved_b,
            "client_update_http_status": update_status,
            "stream_create_http_status": stream_status,
            "stream_id_present": bool(stream.get("stream_id") or stream.get("id")),
            "delivery_method": stream.get("delivery", {}).get("method"),
            "endpoint_url_matches": (
                stream.get("delivery", {}).get("endpoint_url") == args.receiver_b_url
            ),
        },
        "private_service_health": private_health,
        "assertions": assertions,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps({"report": str(args.output), "passed": True}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
