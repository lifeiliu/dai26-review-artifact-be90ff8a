#!/usr/bin/env python3
"""Run the frozen E-B23 Keycloak RFC 8936 POLL gateway gate."""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import AsyncExitStack
from pathlib import Path
from typing import Any, Callable, Sequence

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


HERE = Path(__file__).resolve().parent
ARTIFACT = HERE.parents[1]
SOURCE = ARTIFACT / "src"
if str(SOURCE) not in sys.path:
    sys.path.insert(0, str(SOURCE))

from revocation_propagation.keycloak_gateway_gate import ReplayVector, load_frozen_workload  # noqa: E402
from revocation_propagation.keycloak_poll_gate import (  # noqa: E402
    E_B23_PROTOCOL_VERSION,
    POLL_METHOD,
    PUSH_METHOD,
    REQUIRED_SSF_SCOPES,
    SESSION_REVOKED,
    evaluate_e_b23_assertions,
    poll_request,
    poll_stream_request,
    push_stream_request,
    replay_counts,
)
from revocation_propagation.real_llm_mcp_harness import (  # noqa: E402
    GatewayProcess,
    _mcp_result_payload,
    _open_mcp_session,
    _start_gateway,
    _stop_gateway,
)


KEYCLOAK_IMAGE = "quay.io/keycloak/keycloak:26.7.0"
KEYCLOAK_DIGEST = "sha256:2eb3cd316835c990e69e26ade292ffa78f6fb0db7d5fc6377463c162e1979ac0"
POSTGRES_IMAGE = "pgvector/pgvector:0.8.0-pg17-bookworm"
POSTGRES_DIGEST = "sha256:40b404964359299eefdd5f8518facf1886c562848cf4de13b6eaf91cb70c2b87"
KEYCLOAK_CONTAINER = "revprop-keycloak-e-b23"
POSTGRES_CONTAINER = "revprop-keycloak-e-b23-postgres"
DOCKER_NETWORK = "revprop-keycloak-e-b23-network"
BASE = "http://127.0.0.1:18083"
RELAY_BASE = "http://127.0.0.1:19003"
REALM = "ssf-smoke"
RECEIVERS = ("receiver-a", "receiver-b")
CLIENT_SECRETS = {
    "receiver-a": "receiver-a-e-b23-secret",
    "receiver-b": "receiver-b-e-b23-secret",
}


class HttpFailure(RuntimeError):
    pass


def http_request(
    url: str,
    *,
    method: str = "GET",
    json_body: dict[str, Any] | None = None,
    form: dict[str, str] | None = None,
    token: str | None = None,
    basic_auth: tuple[str, str] | None = None,
    timeout: float = 15.0,
) -> tuple[int, Any, int, int]:
    headers: dict[str, str] = {"Accept": "application/json"}
    data: bytes | None = None
    if json_body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(json_body, separators=(",", ":")).encode("utf-8")
    elif form is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        data = urllib.parse.urlencode(form).encode("ascii")
    elif method in {"POST", "PUT", "PATCH"}:
        data = b""
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if basic_auth:
        encoded = base64.b64encode(f"{basic_auth[0]}:{basic_auth[1]}".encode()).decode("ascii")
        headers["Authorization"] = f"Basic {encoded}"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
            body = json.loads(raw) if raw else None
            return response.status, body, len(data or b""), len(raw)
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            body: Any = json.loads(raw)
        except json.JSONDecodeError:
            body = raw
        raise HttpFailure(f"{method} {url} -> {exc.code}: {body}") from exc


def wait_for(predicate: Callable[[], bool], timeout: float, description: str) -> None:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            if predicate():
                return
        except Exception as exc:
            last_error = exc
        time.sleep(0.25)
    suffix = f"; last error: {last_error}" if last_error else ""
    raise TimeoutError(f"timed out waiting for {description}{suffix}")


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def decode_set(encoded_set: str) -> dict[str, Any]:
    return json.loads(b64url_decode(encoded_set.split(".")[1]))


def verify_rs256(encoded_set: str, jwks: dict[str, Any]) -> dict[str, Any]:
    protected, _, signature = encoded_set.split(".")
    header = json.loads(b64url_decode(protected))
    if header.get("alg") != "RS256":
        raise RuntimeError(f"unsupported E-B23 JWS algorithm: {header.get('alg')}")
    jwk = next((key for key in jwks["keys"] if key.get("kid") == header.get("kid")), None)
    if jwk is None:
        raise RuntimeError(f"no realm JWK for kid={header.get('kid')}")
    public_key = rsa.RSAPublicNumbers(
        int.from_bytes(b64url_decode(jwk["e"]), "big"),
        int.from_bytes(b64url_decode(jwk["n"]), "big"),
    ).public_key()
    signing_input = ".".join(encoded_set.split(".")[:2]).encode("ascii")
    public_key.verify(b64url_decode(signature), signing_input, padding.PKCS1v15(), hashes.SHA256())
    return {"verified": True, "alg": header["alg"], "kid": header.get("kid")}


def item_session_id(item: dict[str, Any]) -> str | None:
    sub_id = item.get("sub_id")
    session = sub_id.get("session") if isinstance(sub_id, dict) else None
    value = session.get("id") if isinstance(session, dict) else None
    return value if isinstance(value, str) else None


def set_session_id(encoded_set: str) -> str | None:
    payload = decode_set(encoded_set)
    sub_id = payload.get("sub_id")
    session = sub_id.get("session") if isinstance(sub_id, dict) else None
    value = session.get("id") if isinstance(session, dict) else None
    return value if isinstance(value, str) else None


def admin_token() -> str:
    return str(
        http_request(
            f"{BASE}/realms/master/protocol/openid-connect/token",
            method="POST",
            form={
                "grant_type": "password",
                "client_id": "admin-cli",
                "username": "admin",
                "password": "admin-e-b23-password",
            },
        )[1]["access_token"]
    )


def login_session() -> dict[str, Any]:
    return http_request(
        f"{BASE}/realms/{REALM}/protocol/openid-connect/token",
        method="POST",
        form={
            "grant_type": "password",
            "client_id": "workload-client",
            "username": "alice",
            "password": "alice-smoke-password",
        },
    )[1]


def logout_session(refresh_token: str) -> int:
    return http_request(
        f"{BASE}/realms/{REALM}/protocol/openid-connect/logout",
        method="POST",
        form={"client_id": "workload-client", "refresh_token": refresh_token},
    )[0]


def assign_optional_scopes(client_id: str, token: str) -> dict[str, Any]:
    clients = http_request(
        f"{BASE}/admin/realms/{REALM}/clients?clientId={urllib.parse.quote(client_id)}",
        token=token,
    )[1]
    if len(clients) != 1:
        raise RuntimeError(f"expected one Keycloak client for {client_id}, found {len(clients)}")
    internal_id = str(clients[0]["id"])
    all_scopes = http_request(f"{BASE}/admin/realms/{REALM}/client-scopes", token=token)[1]
    scope_ids = {scope["name"]: scope["id"] for scope in all_scopes}
    for scope_name in REQUIRED_SSF_SCOPES:
        if scope_name not in scope_ids:
            raise RuntimeError(f"missing Keycloak client scope {scope_name}")
        http_request(
            f"{BASE}/admin/realms/{REALM}/clients/{internal_id}/optional-client-scopes/{scope_ids[scope_name]}",
            method="PUT",
            token=token,
        )
    assigned = http_request(
        f"{BASE}/admin/realms/{REALM}/clients/{internal_id}/optional-client-scopes",
        token=token,
    )[1]
    assigned_names = sorted(scope["name"] for scope in assigned)
    if not set(REQUIRED_SSF_SCOPES).issubset(assigned_names):
        raise RuntimeError(f"SSF optional scopes not assigned to {client_id}: {assigned_names}")
    return {"internal_id": internal_id, "optional_scopes": assigned_names}


def receiver_token(client_id: str) -> dict[str, Any]:
    return http_request(
        f"{BASE}/realms/{REALM}/protocol/openid-connect/token",
        method="POST",
        form={
            "grant_type": "client_credentials",
            "scope": " ".join(REQUIRED_SSF_SCOPES),
        },
        basic_auth=(client_id, CLIENT_SECRETS[client_id]),
    )[1]


def create_stream(client_token: str, payload: dict[str, object]) -> dict[str, Any]:
    status, body, _, _ = http_request(
        f"{BASE}/realms/{REALM}/ssf/transmitter/streams",
        method="POST",
        json_body=payload,
        token=client_token,
    )
    if status != 201:
        raise RuntimeError(f"stream creation returned {status}: {body}")
    return body


def relay_state() -> dict[str, Any]:
    return http_request(f"{RELAY_BASE}/state")[1]


def push_items_for_session(state: dict[str, Any], session_id: str) -> list[dict[str, Any]]:
    return [
        item
        for item in state.get("attempts", [])
        if item.get("receiver") == "receiver-a"
        and item.get("is_session_revoked") is True
        and item_session_id(item) == session_id
    ]


def poll_keycloak(
    *, endpoint: str, token: str, ack: Sequence[str] = ()
) -> tuple[dict[str, Any], dict[str, int]]:
    status, body, request_bytes, response_bytes = http_request(
        endpoint,
        method="POST",
        json_body=poll_request(ack=ack),
        token=token,
    )
    return body, {
        "http_status": status,
        "request_bytes": request_bytes,
        "response_bytes": response_bytes,
    }


async def call_mcp(session: Any, tool: str, arguments: dict[str, object]) -> dict[str, object]:
    result = await session.call_tool(tool, arguments)
    if result.isError:
        raise RuntimeError(f"MCP tool {tool} returned an error")
    return _mcp_result_payload(result)


async def paired_control_calls(
    gateways: Sequence[GatewayProcess], delegation_id: str, phase: str
) -> dict[str, dict[str, object]]:
    results: dict[str, dict[str, object]] = {}
    async with AsyncExitStack() as stack:
        for gateway, receiver in zip(gateways, RECEIVERS, strict=True):
            session = await _open_mcp_session(stack, gateway.endpoint)
            results[receiver] = await call_mcp(
                session,
                "repo_write",
                {
                    "delegation_id": delegation_id,
                    "agent_id": f"e-b23-{phase}",
                    "payload": f"matched {phase} control call",
                },
            )
    return results


async def apply_revocation(
    gateway: GatewayProcess, *, delegation_id: str, event_id: str, channel: str
) -> dict[str, object]:
    async with AsyncExitStack() as stack:
        session = await _open_mcp_session(stack, gateway.endpoint)
        return await call_mcp(
            session,
            "apply_revocation",
            {"delegation_id": delegation_id, "event_id": event_id, "channel": channel},
        )


async def replay_workload(
    *,
    gateways: Sequence[GatewayProcess],
    delegation_id: str,
    vectors: Sequence[ReplayVector],
    replay_path: Path,
) -> tuple[list[dict[str, object]], dict[str, dict[str, object]]]:
    rows: list[dict[str, object]] = []
    statuses: dict[str, dict[str, object]] = {}
    async with AsyncExitStack() as stack:
        sessions = {
            receiver: await _open_mcp_session(stack, gateway.endpoint)
            for receiver, gateway in zip(RECEIVERS, gateways, strict=True)
        }
        with replay_path.open("a", encoding="utf-8") as handle:
            for receiver in RECEIVERS:
                for vector in vectors:
                    result = await call_mcp(
                        sessions[receiver],
                        "repo_write",
                        {
                            "delegation_id": delegation_id,
                            "agent_id": vector.gateway_id,
                            "payload": vector.payload(),
                        },
                    )
                    row: dict[str, object] = {
                        "receiver": receiver,
                        "delegation_id": delegation_id,
                        "vector_id": vector.vector_id,
                        "service": vector.service,
                        "source_gateway_id": vector.gateway_id,
                        "run": vector.run,
                        "call_sequence": vector.call_sequence,
                        "tool_name": vector.tool_name,
                        "arguments_sha256": vector.arguments_sha256,
                        "allowed": bool(result["allowed"]),
                        "reason": result["reason"],
                        "enforcement_gateway_id": result["gateway_id"],
                        "event_id": result.get("event_id"),
                        "learned_via": result.get("learned_via"),
                        "server_pid": result["server_pid"],
                    }
                    rows.append(row)
                    handle.write(json.dumps(row, sort_keys=True) + "\n")
        for receiver in RECEIVERS:
            statuses[receiver] = await call_mcp(
                sessions[receiver],
                "gateway_status",
                {"delegation_id": delegation_id},
            )
    return rows, statuses


def docker_cleanup() -> None:
    for container in (KEYCLOAK_CONTAINER, POSTGRES_CONTAINER):
        subprocess.run(["docker", "rm", "-f", container], check=False, capture_output=True)
    subprocess.run(["docker", "network", "rm", DOCKER_NETWORK], check=False, capture_output=True)


def start_postgres() -> str:
    subprocess.check_output(["docker", "network", "create", DOCKER_NETWORK], text=True)
    return subprocess.check_output(
        [
            "docker", "run", "-d", "--rm", "--name", POSTGRES_CONTAINER,
            "--network", DOCKER_NETWORK,
            "-e", "POSTGRES_DB=keycloak",
            "-e", "POSTGRES_USER=keycloak",
            "-e", "POSTGRES_PASSWORD=keycloak-e-b23-password",
            f"{POSTGRES_IMAGE}@{POSTGRES_DIGEST}",
        ],
        text=True,
    ).strip()


def start_keycloak(realm_file: Path) -> str:
    return subprocess.check_output(
        [
            "docker", "run", "-d", "--rm", "--name", KEYCLOAK_CONTAINER,
            "--network", DOCKER_NETWORK, "-p", "18083:8080",
            "-e", "KC_BOOTSTRAP_ADMIN_USERNAME=admin",
            "-e", "KC_BOOTSTRAP_ADMIN_PASSWORD=admin-e-b23-password",
            "-e", "KC_DB=postgres",
            "-e", f"KC_DB_URL=jdbc:postgresql://{POSTGRES_CONTAINER}:5432/keycloak",
            "-e", "KC_DB_USERNAME=keycloak",
            "-e", "KC_DB_PASSWORD=keycloak-e-b23-password",
            "-v", f"{realm_file}:/opt/keycloak/data/import/ssf-smoke-realm.json:ro",
            f"{KEYCLOAK_IMAGE}@{KEYCLOAK_DIGEST}",
            "start-dev", "--import-realm", "--features=ssf",
            "--spi-ssf-transmitter--default--allow-insecure-push-targets=true",
        ],
        text=True,
    ).strip()


def save_container_logs(output_dir: Path) -> None:
    for container, filename in (
        (KEYCLOAK_CONTAINER, "keycloak.log"),
        (POSTGRES_CONTAINER, "postgres.log"),
    ):
        completed = subprocess.run(
            ["docker", "logs", container], capture_output=True, text=True, check=False
        )
        (output_dir / filename).write_text(completed.stdout + completed.stderr, encoding="utf-8")


def run(*, output_dir: Path, workload_root: Path, keep_infrastructure: bool = False) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    vectors, manifest = load_frozen_workload(workload_root)
    (output_dir / "input_manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    replay_path = output_dir / "replay_results.jsonl"
    replay_path.write_text("", encoding="utf-8")
    receiver_attempts = output_dir / "receiver_attempts.jsonl"
    receiver_log_handle = (output_dir / "receiver.log").open("w", encoding="utf-8")
    relay_script = HERE.parent / "e_b22_keycloak_gateway_gate" / "receiver_relay.py"
    receiver_process = subprocess.Popen(
        [
            sys.executable, str(relay_script), "--port", "19003",
            "--evidence-jsonl", str(receiver_attempts),
        ],
        stdout=receiver_log_handle,
        stderr=subprocess.STDOUT,
    )
    gateways: list[GatewayProcess] = []
    summary: dict[str, Any] = {
        "experiment": "E-B23",
        "protocol_version": E_B23_PROTOCOL_VERSION,
        "started_unix_ns": time.time_ns(),
        "keycloak_image": KEYCLOAK_IMAGE,
        "keycloak_image_digest": KEYCLOAK_DIGEST,
        "keycloak_source_tag_commit": "6c73e3027811d9c7b22683edd825e839272e9547",
        "postgres_image": POSTGRES_IMAGE,
        "postgres_image_digest": POSTGRES_DIGEST,
        "workload": manifest,
        "delivery_paths": {"receiver-a": PUSH_METHOD, "receiver-b": POLL_METHOD},
        "poll_long_wait_used": False,
        "keycloak_retry_curve_changed": False,
        "keycloak_max_attempts_changed": False,
    }
    docker_cleanup()
    try:
        wait_for(lambda: http_request(f"{RELAY_BASE}/health")[0] == 200, 10, "E-B23 relay health")
        gateways = [_start_gateway("gateway-a"), _start_gateway("gateway-b")]
        summary["gateway_processes"] = {
            receiver: {"gateway_id": gateway.gateway_id, "pid": gateway.process.pid, "port": gateway.port}
            for receiver, gateway in zip(RECEIVERS, gateways, strict=True)
        }
        summary["postgres_container_id"] = start_postgres()
        wait_for(
            lambda: subprocess.run(
                ["docker", "exec", POSTGRES_CONTAINER, "pg_isready", "-U", "keycloak", "-d", "keycloak"],
                capture_output=True,
            ).returncode == 0,
            30,
            "E-B23 PostgreSQL readiness",
        )
        summary["keycloak_container_id"] = start_keycloak(HERE / "realm-e-b23.json")
        wait_for(
            lambda: http_request(f"{BASE}/realms/{REALM}/.well-known/ssf-configuration")[0] == 200,
            150,
            "Keycloak E-B23 SSF discovery",
        )

        admin = admin_token()
        summary["scope_assignments"] = {
            receiver: assign_optional_scopes(receiver, admin) for receiver in RECEIVERS
        }
        token_envelopes = {receiver: receiver_token(receiver) for receiver in RECEIVERS}
        summary["receiver_token_scopes"] = {
            receiver: envelope.get("scope") for receiver, envelope in token_envelopes.items()
        }
        streams = {
            "receiver-a": create_stream(
                str(token_envelopes["receiver-a"]["access_token"]),
                push_stream_request("http://host.docker.internal:19003/receiver-a"),
            ),
            "receiver-b": create_stream(
                str(token_envelopes["receiver-b"]["access_token"]),
                poll_stream_request(),
            ),
        }
        summary["streams"] = streams
        if streams["receiver-a"]["delivery"]["method"] != PUSH_METHOD:
            raise RuntimeError("receiver A stream is not PUSH")
        if streams["receiver-b"]["delivery"]["method"] != POLL_METHOD:
            raise RuntimeError("receiver B stream is not POLL")
        poll_endpoint = str(streams["receiver-b"]["delivery"]["endpoint_url"])
        if not poll_endpoint.startswith(BASE):
            raise RuntimeError(f"unexpected Keycloak POLL endpoint: {poll_endpoint}")

        jwks = http_request(f"{BASE}/realms/{REALM}/protocol/openid-connect/certs")[1]
        login = login_session()
        session_id = str(login["session_state"])
        delegation_id = f"delegation-e-b23-{session_id}"
        summary["session_id"] = session_id
        summary["delegation_id"] = delegation_id
        pre_revocation = asyncio.run(paired_control_calls(gateways, delegation_id, "pre-revocation"))
        summary["pre_revocation"] = pre_revocation
        if not all(bool(value.get("allowed")) for value in pre_revocation.values()):
            raise RuntimeError("E-B23 pre-revocation allow control failed")

        summary["logout_http_status"] = logout_session(str(login["refresh_token"]))
        wait_for(
            lambda: len(push_items_for_session(relay_state(), session_id)) >= 1,
            45,
            "receiver-A PUSH for E-B23 session",
        )
        push_items = push_items_for_session(relay_state(), session_id)
        if len(push_items) != 1:
            raise RuntimeError(f"expected one receiver-A PUSH, observed {len(push_items)}")
        push_item = push_items[0]
        push_verification = verify_rs256(str(push_item["encoded_set"]), jwks)
        push_event = {
            **push_item,
            "signature_verified": push_verification["verified"],
            "signature_alg": push_verification["alg"],
        }
        summary["push_event"] = push_event
        asyncio.run(
            apply_revocation(
                gateways[0],
                delegation_id=delegation_id,
                event_id=str(push_item["jti"]),
                channel="direct-push",
            )
        )

        pre_poll_controls = asyncio.run(paired_control_calls(gateways, delegation_id, "pre-poll"))
        summary["pre_poll_controls"] = pre_poll_controls
        if pre_poll_controls["receiver-a"].get("allowed") is not False:
            raise RuntimeError("gateway A did not deny before receiver B poll")
        if pre_poll_controls["receiver-b"].get("allowed") is not True:
            raise RuntimeError("gateway B was not stale/active before poll")

        stats_before_poll = http_request(
            f"{BASE}/admin/realms/{REALM}/ssf/events/stats", token=admin
        )[1]
        first_body, first_wire = poll_keycloak(
            endpoint=poll_endpoint,
            token=str(token_envelopes["receiver-b"]["access_token"]),
        )
        sets = first_body.get("sets", {})
        if not isinstance(sets, dict) or len(sets) != 1:
            raise RuntimeError(f"first POLL must return exactly one SET, observed {len(sets)}")
        poll_jti, encoded_poll_set = next(iter(sets.items()))
        poll_payload = decode_set(str(encoded_poll_set))
        poll_verification = verify_rs256(str(encoded_poll_set), jwks)
        first_poll = {
            **first_wire,
            "set_count": len(sets),
            "more_available": bool(first_body.get("moreAvailable")),
            "jti": poll_jti,
            "signature_verified": poll_verification["verified"],
            "signature_alg": poll_verification["alg"],
            "is_session_revoked": SESSION_REVOKED in poll_payload.get("events", {}),
            "session_id": set_session_id(str(encoded_poll_set)),
            "session_matches": set_session_id(str(encoded_poll_set)) == session_id,
            "token_scope": token_envelopes["receiver-b"].get("scope", ""),
            "response_body_sha256": hashlib.sha256(
                json.dumps(first_body, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
        }
        summary["first_poll"] = first_poll
        asyncio.run(
            apply_revocation(
                gateways[1],
                delegation_id=delegation_id,
                event_id=str(poll_jti),
                channel="keycloak-poll",
            )
        )

        rows, final_statuses = asyncio.run(
            replay_workload(
                gateways=gateways,
                delegation_id=delegation_id,
                vectors=vectors,
                replay_path=replay_path,
            )
        )
        counts = replay_counts(rows)
        summary["replay_counts"] = counts
        summary["final_statuses"] = final_statuses

        second_body, second_wire = poll_keycloak(
            endpoint=poll_endpoint,
            token=str(token_envelopes["receiver-b"]["access_token"]),
            ack=[str(poll_jti)],
        )
        second_sets = second_body.get("sets", {})
        second_poll = {
            **second_wire,
            "set_count": len(second_sets) if isinstance(second_sets, dict) else -1,
            "more_available": bool(second_body.get("moreAvailable")),
            "ack": [str(poll_jti)],
            "ack_matches_first_jti": True,
            "response_body_sha256": hashlib.sha256(
                json.dumps(second_body, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
        }
        summary["second_poll"] = second_poll
        stats_after_ack = http_request(
            f"{BASE}/admin/realms/{REALM}/ssf/events/stats", token=admin
        )[1]
        pending_after_ack = int(stats_after_ack.get("statuses", {}).get("PENDING", {}).get("count", 0))
        path_audit = {
            "poll_request_count": 2,
            "poll_request_bytes": first_wire["request_bytes"] + second_wire["request_bytes"],
            "poll_response_bytes": first_wire["response_bytes"] + second_wire["response_bytes"],
            "receiver_b_state_source": "keycloak-rfc8936-poll",
            "receiver_b_push_handoff": False,
            "receiver_b_log_repair": False,
            "receiver_b_admin_event_read": False,
            "receiver_b_self_authored_event_store": False,
            "poll_pending_after_ack": pending_after_ack,
            "stats_before_poll": stats_before_poll,
            "stats_after_ack": stats_after_ack,
        }
        summary["path_audit"] = path_audit

        server_pids = {int(status["server_pid"]) for status in final_statuses.values()}
        expected_pids = {gateway.process.pid for gateway in gateways}
        infrastructure = {
            "pinned_postgres_used": True,
            "gateway_process_isolation": server_pids == expected_pids
            and len(server_pids) == 2
            and os.getpid() not in server_pids,
            "harness_pid": os.getpid(),
            "server_pids": sorted(server_pids),
        }
        summary["infrastructure"] = infrastructure
        assertions = evaluate_e_b23_assertions(
            manifest=manifest,
            infrastructure=infrastructure,
            pre_revocation=pre_revocation,
            pre_poll_controls=pre_poll_controls,
            push_event=push_event,
            first_poll=first_poll,
            second_poll=second_poll,
            final_statuses=final_statuses,
            counts=counts,
            path_audit=path_audit,
        )
        summary["assertions"] = assertions
        summary["passed"] = all(assertions.values())
        summary["replay_results_sha256"] = hashlib.sha256(replay_path.read_bytes()).hexdigest()
        return summary
    finally:
        summary["finished_unix_ns"] = time.time_ns()
        try:
            save_container_logs(output_dir)
        finally:
            if not keep_infrastructure:
                docker_cleanup()
            for gateway in gateways:
                _stop_gateway(gateway)
            receiver_process.terminate()
            try:
                receiver_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                receiver_process.kill()
                receiver_process.wait(timeout=5)
            receiver_log_handle.close()
            (output_dir / "summary.json").write_text(
                json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--workload-root",
        type=Path,
        default=ARTIFACT / "data" / "run_2026_07_14_e_b20_mcpmark_formal",
    )
    parser.add_argument("--validate-inputs-only", action="store_true")
    parser.add_argument("--keep-infrastructure", action="store_true")
    args = parser.parse_args()
    output_dir = args.output_dir.resolve()
    if args.validate_inputs_only:
        _, manifest = load_frozen_workload(args.workload_root)
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "input_manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(json.dumps({"validated": True, "vector_count": manifest["vector_count"]}, indent=2))
        return 0
    try:
        summary = run(
            output_dir=output_dir,
            workload_root=args.workload_root.resolve(),
            keep_infrastructure=args.keep_infrastructure,
        )
    except Exception as exc:
        print(f"E-B23 ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"passed": summary["passed"], "assertions": summary["assertions"]}, indent=2))
    return 0 if summary["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())

