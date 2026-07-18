#!/usr/bin/env python3
"""Driver-side, outcome-blind qualification for the strict E-B24 topology."""

from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REALM = "ssf-smoke"
SESSION_REVOKED = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"


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
        data = json.dumps(json_body).encode("utf-8")
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
        raise RuntimeError(f"{method} {url} failed with HTTP {error.code}: {detail}") from error


def _http_probe_status(url: str) -> int:
    """Return an HTTP status without supplying MCP session or protocol headers."""

    request = urllib.request.Request(
        url,
        headers={"Accept": "application/json"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            response.read()
            return response.status
    except urllib.error.HTTPError as error:
        error.read()
        return error.code


def _http_optional_get(
    url: str, *, ca_file: Path, bearer_token: str
) -> tuple[int, Any]:
    """Read an optional resource, returning ``(404, None)`` when absent."""

    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {bearer_token}",
        },
        method="GET",
    )
    context = ssl.create_default_context(cafile=str(ca_file))
    try:
        with urllib.request.urlopen(request, timeout=20, context=context) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")
        if error.code == 404:
            return 404, None
        raise RuntimeError(f"GET {url} failed with HTTP {error.code}: {detail}") from error


def _client(
    *, keycloak: str, ca_file: Path, token: str, client_id: str
) -> tuple[str, dict[str, object]]:
    _, clients = _http(
        f"{keycloak}/admin/realms/{REALM}/clients?clientId={client_id}",
        ca_file=ca_file,
        bearer_token=token,
    )
    if not isinstance(clients, list) or len(clients) != 1:
        raise RuntimeError(f"expected exactly one Keycloak client {client_id}")
    internal_id = str(clients[0]["id"])
    _, client = _http(
        f"{keycloak}/admin/realms/{REALM}/clients/{internal_id}",
        ca_file=ca_file,
        bearer_token=token,
    )
    if not isinstance(client, dict):
        raise RuntimeError(f"Keycloak returned a malformed client {client_id}")
    return internal_id, client


def _stream_id_present(stream: dict[str, object]) -> bool:
    """Recognize receiver and Keycloak-admin SSF stream wire schemas."""

    return any(bool(stream.get(field)) for field in ("stream_id", "streamId", "id"))


def _public_addresses(url: str) -> list[str]:
    hostname = urllib.parse.urlparse(url).hostname
    if not hostname:
        raise ValueError(f"URL has no hostname: {url}")
    addresses = sorted({item[4][0] for item in socket.getaddrinfo(hostname, None)})
    if not addresses:
        raise RuntimeError(f"hostname did not resolve: {hostname}")
    for address in addresses:
        parsed = ipaddress.ip_address(address)
        if not parsed.is_global:
            raise RuntimeError(f"PUSH hostname resolved to a non-global address: {address}")
    return addresses


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--keycloak-url", required=True)
    parser.add_argument("--receiver-a-url", required=True)
    parser.add_argument("--receiver-b-url", required=True)
    parser.add_argument("--ca-file", type=Path, required=True)
    parser.add_argument("--keycloak-admin-password-file", type=Path, required=True)
    parser.add_argument("--receiver-a-token-file", type=Path, required=True)
    parser.add_argument("--receiver-b-token-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    keycloak = args.keycloak_url.rstrip("/")
    _, discovery = _http(
        f"{keycloak}/realms/{REALM}/.well-known/openid-configuration",
        ca_file=args.ca_file,
    )
    _, token_body = _http(
        f"{keycloak}/realms/master/protocol/openid-connect/token",
        ca_file=args.ca_file,
        method="POST",
        form={
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": "admin",
            "password": _secret(args.keycloak_admin_password_file),
        },
    )
    admin_token = str(token_body["access_token"])

    receivers = {
        "receiver-a": (args.receiver_a_url, _secret(args.receiver_a_token_file)),
        "receiver-b": (args.receiver_b_url, _secret(args.receiver_b_token_file)),
    }
    stream_results: dict[str, object] = {}
    resolved: dict[str, list[str]] = {}
    for client_id, (endpoint, receiver_token) in receivers.items():
        resolved[client_id] = _public_addresses(endpoint)
        internal_id, client = _client(
            keycloak=keycloak,
            ca_file=args.ca_file,
            token=admin_token,
            client_id=client_id,
        )
        attributes = dict(client.get("attributes", {}))
        attributes["ssf.validPushUrls"] = endpoint
        client["attributes"] = attributes
        update_status, _ = _http(
            f"{keycloak}/admin/realms/{REALM}/clients/{internal_id}",
            ca_file=args.ca_file,
            method="PUT",
            json_body=client,
            bearer_token=admin_token,
        )
        stream_url = (
            f"{keycloak}/admin/realms/{REALM}/ssf/clients/{client_id}/stream"
        )
        stream_status, stream = _http_optional_get(
            stream_url, ca_file=args.ca_file, bearer_token=admin_token
        )
        stream_operation = "read_existing"
        if stream_status == 404:
            stream_status, stream = _http(
                stream_url,
                ca_file=args.ca_file,
                method="POST",
                json_body={
                    "description": "E-B24 outcome-blind strict infrastructure pilot",
                    "events_requested": [SESSION_REVOKED],
                    "delivery": {
                        "method": "urn:ietf:rfc:8935",
                        "endpoint_url": endpoint,
                        "authorization_header": f"Bearer {receiver_token}",
                    },
                },
                bearer_token=admin_token,
            )
            stream_operation = "created"
        if not isinstance(stream, dict):
            raise RuntimeError(f"Keycloak returned a malformed stream for {client_id}")
        stream_results[client_id] = {
            "client_update_http_status": update_status,
            "stream_config_http_status": stream_status,
            "stream_operation": stream_operation,
            "stream_id_present": _stream_id_present(stream),
            "delivery_method": stream.get("delivery", {}).get("method"),
            "endpoint_url_matches": stream.get("delivery", {}).get("endpoint_url") == endpoint,
        }
    private_health_urls = {
        "receiver-a-private": "https://receiver-a:8443/health",
        "receiver-b-private": "https://receiver-b:8443/health",
    }
    private_health: dict[str, object] = {}
    for name, url in private_health_urls.items():
        status, body = _http(url, ca_file=args.ca_file)
        private_health[name] = {"http_status": status, "body": body}

    gateway_mcp_probe_status = {
        f"gateway-{index}": _http_probe_status(f"http://gateway-{index}:8000/mcp")
        for index in range(1, 9)
    }

    assertions = {
        "keycloak_discovery_realm_matches": discovery.get("issuer")
        == f"{keycloak}/realms/{REALM}",
        "both_push_hostnames_resolve_only_global": all(resolved.values()),
        "both_exact_push_urls_accepted": all(
            result["client_update_http_status"] == 204
            and result["stream_config_http_status"] in {200, 201}
            and result["stream_id_present"]
            and result["delivery_method"] == "urn:ietf:rfc:8935"
            and result["endpoint_url_matches"]
            for result in stream_results.values()
        ),
        "both_private_receiver_health_checks_pass": all(
            item["http_status"] == 200 for item in private_health.values()
        ),
        "all_eight_mcp_endpoints_reachable_without_tool_invocation": all(
            status == 406 for status in gateway_mcp_probe_status.values()
        ),
    }
    report = {
        "experiment": "E-B24 strict outcome-blind infrastructure pilot",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "passed": all(assertions.values()),
        "claim_boundary": (
            "Infrastructure qualification only. No revocation event, workload replay, "
            "tool invocation, gateway decision contrast, or effect mutation was executed."
        ),
        "keycloak_url": keycloak,
        "push_endpoints": {name: endpoint for name, (endpoint, _) in receivers.items()},
        "resolved_public_addresses": resolved,
        "stream_results": stream_results,
        "private_receiver_health": private_health,
        "gateway_mcp_probe_http_status": gateway_mcp_probe_status,
        "assertions": assertions,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("e-b24-driver-report=" + json.dumps(report, separators=(",", ":"), sort_keys=True))
    if not report["passed"]:
        raise RuntimeError(f"strict infrastructure assertions failed: {assertions}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
