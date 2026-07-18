#!/usr/bin/env python3
"""Run the frozen E-B22 Keycloak PUSH to MCP gateway deny-state gate."""

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

from revocation_propagation.keycloak_gateway_gate import (  # noqa: E402
    E_B22_PROTOCOL_VERSION,
    ReplayVector,
    condition_counts,
    evaluate_e_b22_assertions,
    load_frozen_workload,
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
KEYCLOAK_CONTAINER = "revprop-keycloak-e-b22"
POSTGRES_CONTAINER = "revprop-keycloak-e-b22-postgres"
DOCKER_NETWORK = "revprop-keycloak-e-b22-network"
BASE = "http://127.0.0.1:18082"
RELAY_BASE = "http://127.0.0.1:19002"
REALM = "ssf-smoke"
SESSION_REVOKED = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
CONDITIONS = ("normal-delivery", "receiver-selective-nondelivery")
RECEIVERS = ("receiver-a", "receiver-b")


class HttpFailure(RuntimeError):
    pass


def http_request(
    url: str,
    *,
    method: str = "GET",
    json_body: dict[str, Any] | None = None,
    form: dict[str, str] | None = None,
    token: str | None = None,
    timeout: float = 15.0,
) -> tuple[int, Any]:
    headers: dict[str, str] = {"Accept": "application/json"}
    data: bytes | None = None
    if json_body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(json_body).encode("utf-8")
    elif form is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        data = urllib.parse.urlencode(form).encode("ascii")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else None
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


def verify_rs256(encoded_set: str, jwks: dict[str, Any]) -> dict[str, Any]:
    protected, _, signature = encoded_set.split(".")
    header = json.loads(b64url_decode(protected))
    if header.get("alg") != "RS256":
        raise RuntimeError(f"unsupported E-B22 JWS algorithm: {header.get('alg')}")
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


def admin_token() -> str:
    return http_request(
        f"{BASE}/realms/master/protocol/openid-connect/token",
        method="POST",
        form={
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": "admin",
            "password": "admin-e-b22-password",
        },
    )[1]["access_token"]


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
    status, _ = http_request(
        f"{BASE}/realms/{REALM}/protocol/openid-connect/logout",
        method="POST",
        form={"client_id": "workload-client", "refresh_token": refresh_token},
    )
    return status


def create_stream(receiver: str, token: str) -> dict[str, Any]:
    payload = {
        "description": f"E-B22 frozen gateway gate for {receiver}",
        "events_requested": [SESSION_REVOKED],
        "delivery": {
            "method": "urn:ietf:rfc:8935",
            "endpoint_url": f"http://host.docker.internal:19002/{receiver}",
            "authorization_header": f"Bearer {receiver}-e-b22",
        },
    }
    status, body = http_request(
        f"{BASE}/admin/realms/{REALM}/ssf/clients/{receiver}/stream",
        method="POST",
        json_body=payload,
        token=token,
    )
    if status != 201:
        raise RuntimeError(f"stream creation returned {status}: {body}")
    return body


def relay_state() -> dict[str, Any]:
    return http_request(f"{RELAY_BASE}/state")[1]


def item_session_id(item: dict[str, Any]) -> str | None:
    sub_id = item.get("sub_id")
    if not isinstance(sub_id, dict):
        return None
    session = sub_id.get("session")
    if not isinstance(session, dict):
        return None
    value = session.get("id")
    return value if isinstance(value, str) else None


def attempts_for_session(state: dict[str, Any], session_id: str) -> list[dict[str, Any]]:
    return [
        item
        for item in state.get("attempts", [])
        if item.get("is_session_revoked") is True and item_session_id(item) == session_id
    ]


def attempts_by_receiver(state: dict[str, Any], session_id: str) -> dict[str, dict[str, Any]]:
    matching = attempts_for_session(state, session_id)
    by_receiver: dict[str, list[dict[str, Any]]] = {
        receiver: [item for item in matching if item.get("receiver") == receiver]
        for receiver in RECEIVERS
    }
    counts = {receiver: len(items) for receiver, items in by_receiver.items()}
    if counts != {"receiver-a": 1, "receiver-b": 1}:
        raise RuntimeError(f"expected one SET attempt per receiver for session {session_id}, observed {counts}")
    return {receiver: items[0] for receiver, items in by_receiver.items()}


async def call_mcp(session: Any, tool: str, arguments: dict[str, object]) -> dict[str, object]:
    result = await session.call_tool(tool, arguments)
    if result.isError:
        raise RuntimeError(f"MCP tool {tool} returned an error")
    return _mcp_result_payload(result)


async def precondition_calls(
    gateways: Sequence[GatewayProcess], delegation_id: str
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
                    "agent_id": "e-b22-precondition",
                    "payload": "frozen pre-revocation allow check",
                },
            )
    return results


async def apply_and_replay(
    *,
    condition: str,
    gateways: Sequence[GatewayProcess],
    delegation_id: str,
    receiver_items: dict[str, dict[str, Any]],
    vectors: Sequence[ReplayVector],
    replay_path: Path,
) -> tuple[list[dict[str, object]], dict[str, dict[str, object]]]:
    rows: list[dict[str, object]] = []
    statuses: dict[str, dict[str, object]] = {}
    async with AsyncExitStack() as stack:
        sessions: dict[str, Any] = {}
        for gateway, receiver in zip(gateways, RECEIVERS, strict=True):
            sessions[receiver] = await _open_mcp_session(stack, gateway.endpoint)

        for receiver in RECEIVERS:
            item = receiver_items[receiver]
            if item["forwarded"]:
                await call_mcp(
                    sessions[receiver],
                    "apply_revocation",
                    {
                        "delegation_id": delegation_id,
                        "event_id": str(item["jti"]),
                        "channel": "direct-push",
                    },
                )

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
                        "condition": condition,
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
    image = f"{POSTGRES_IMAGE}@{POSTGRES_DIGEST}"
    container_id = subprocess.check_output(
        [
            "docker",
            "run",
            "-d",
            "--rm",
            "--name",
            POSTGRES_CONTAINER,
            "--network",
            DOCKER_NETWORK,
            "-e",
            "POSTGRES_DB=keycloak",
            "-e",
            "POSTGRES_USER=keycloak",
            "-e",
            "POSTGRES_PASSWORD=keycloak-e-b22-password",
            image,
        ],
        text=True,
    ).strip()
    wait_for(
        lambda: subprocess.run(
            ["docker", "exec", POSTGRES_CONTAINER, "pg_isready", "-U", "keycloak", "-d", "keycloak"],
            capture_output=True,
        ).returncode
        == 0,
        30,
        "E-B22 PostgreSQL readiness",
    )
    return container_id


def start_keycloak(realm_file: Path) -> str:
    image = f"{KEYCLOAK_IMAGE}@{KEYCLOAK_DIGEST}"
    return subprocess.check_output(
        [
            "docker",
            "run",
            "-d",
            "--rm",
            "--name",
            KEYCLOAK_CONTAINER,
            "--network",
            DOCKER_NETWORK,
            "-p",
            "18082:8080",
            "-e",
            "KC_BOOTSTRAP_ADMIN_USERNAME=admin",
            "-e",
            "KC_BOOTSTRAP_ADMIN_PASSWORD=admin-e-b22-password",
            "-e",
            "KC_DB=postgres",
            "-e",
            f"KC_DB_URL=jdbc:postgresql://{POSTGRES_CONTAINER}:5432/keycloak",
            "-e",
            "KC_DB_USERNAME=keycloak",
            "-e",
            "KC_DB_PASSWORD=keycloak-e-b22-password",
            "-v",
            f"{realm_file}:/opt/keycloak/data/import/ssf-smoke-realm.json:ro",
            image,
            "start-dev",
            "--import-realm",
            "--features=ssf",
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
        (output_dir / filename).write_text(
            completed.stdout + completed.stderr, encoding="utf-8"
        )


def run(
    *, output_dir: Path, workload_root: Path, keep_infrastructure: bool = False
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    vectors, manifest = load_frozen_workload(workload_root)
    (output_dir / "input_manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    replay_path = output_dir / "replay_results.jsonl"
    replay_path.write_text("", encoding="utf-8")
    relay_attempts = output_dir / "receiver_attempts.jsonl"
    receiver_log_handle = (output_dir / "receiver.log").open("w", encoding="utf-8")
    receiver_process = subprocess.Popen(
        [
            sys.executable,
            str(HERE / "receiver_relay.py"),
            "--evidence-jsonl",
            str(relay_attempts),
        ],
        stdout=receiver_log_handle,
        stderr=subprocess.STDOUT,
    )
    gateways: list[GatewayProcess] = []
    summary: dict[str, Any] = {
        "experiment": "E-B22",
        "protocol_version": E_B22_PROTOCOL_VERSION,
        "started_unix_ns": time.time_ns(),
        "keycloak_image": KEYCLOAK_IMAGE,
        "keycloak_image_digest": KEYCLOAK_DIGEST,
        "keycloak_source_tag_commit": "6c73e3027811d9c7b22683edd825e839272e9547",
        "postgres_image": POSTGRES_IMAGE,
        "postgres_image_digest": POSTGRES_DIGEST,
        "workload": manifest,
        "poll_used": False,
        "keycloak_retry_curve_changed": False,
        "keycloak_max_attempts_changed": False,
        "conditions": {},
    }
    docker_cleanup()
    try:
        wait_for(
            lambda: http_request(f"{RELAY_BASE}/health")[0] == 200,
            10,
            "E-B22 relay health",
        )
        gateways = [_start_gateway("gateway-a"), _start_gateway("gateway-b")]
        summary["gateway_processes"] = {
            receiver: {
                "gateway_id": gateway.gateway_id,
                "pid": gateway.process.pid,
                "port": gateway.port,
            }
            for receiver, gateway in zip(RECEIVERS, gateways, strict=True)
        }
        summary["postgres_container_id"] = start_postgres()
        realm_file = HERE / "realm-e-b22.json"
        summary["keycloak_container_id"] = start_keycloak(realm_file)
        wait_for(
            lambda: http_request(f"{BASE}/realms/{REALM}/.well-known/ssf-configuration")[0]
            == 200,
            150,
            "Keycloak E-B22 SSF discovery",
        )
        token = admin_token()
        summary["streams"] = {receiver: create_stream(receiver, token) for receiver in RECEIVERS}
        jwks = http_request(f"{BASE}/realms/{REALM}/protocol/openid-connect/certs")[1]

        all_rows: list[dict[str, object]] = []
        receiver_events: dict[str, dict[str, dict[str, object]]] = {}
        gateway_statuses: dict[str, dict[str, dict[str, object]]] = {}
        preconditions: dict[str, dict[str, dict[str, object]]] = {}

        for condition in CONDITIONS:
            http_request(f"{RELAY_BASE}/control/receiver-a/forward", method="POST")
            action = "forward" if condition == "normal-delivery" else "withhold"
            http_request(f"{RELAY_BASE}/control/receiver-b/{action}", method="POST")

            login = login_session()
            session_id = str(login["session_state"])
            delegation_id = f"delegation-e-b22-{session_id}"
            precondition = asyncio.run(precondition_calls(gateways, delegation_id))
            preconditions[condition] = precondition
            if not all(bool(result.get("allowed")) for result in precondition.values()):
                raise RuntimeError(f"pre-revocation gateway allow check failed for {condition}")

            logout_status = logout_session(str(login["refresh_token"]))
            wait_for(
                lambda: len(attempts_for_session(relay_state(), session_id)) >= 2,
                45,
                f"two E-B22 receiver attempts for {condition}",
            )
            items = attempts_by_receiver(relay_state(), session_id)
            normalized_events: dict[str, dict[str, object]] = {}
            for receiver, item in items.items():
                verification = verify_rs256(str(item["encoded_set"]), jwks)
                normalized_events[receiver] = {
                    **item,
                    "signature_verified": verification["verified"],
                    "signature_alg": verification["alg"],
                    "attempt_count_for_session": len(
                        [
                            candidate
                            for candidate in attempts_for_session(relay_state(), session_id)
                            if candidate.get("receiver") == receiver
                        ]
                    ),
                }
            receiver_events[condition] = normalized_events

            rows, statuses = asyncio.run(
                apply_and_replay(
                    condition=condition,
                    gateways=gateways,
                    delegation_id=delegation_id,
                    receiver_items=items,
                    vectors=vectors,
                    replay_path=replay_path,
                )
            )
            all_rows.extend(rows)
            gateway_statuses[condition] = statuses
            summary["conditions"][condition] = {
                "session_id": session_id,
                "delegation_id": delegation_id,
                "logout_http_status": logout_status,
                "receiver_events": normalized_events,
                "gateway_statuses": statuses,
                "outbox_stats": http_request(
                    f"{BASE}/admin/realms/{REALM}/ssf/events/stats", token=token
                )[1],
            }

        replay_counts = condition_counts(all_rows)
        server_pids = {
            int(status["server_pid"])
            for by_condition in gateway_statuses.values()
            for status in by_condition.values()
        }
        expected_pids = {gateway.process.pid for gateway in gateways}
        infrastructure = {
            "pinned_postgres_used": True,
            "gateway_process_isolation": server_pids == expected_pids
            and len(server_pids) == 2
            and os.getpid() not in server_pids,
            "server_pids": sorted(server_pids),
            "harness_pid": os.getpid(),
        }
        assertions = evaluate_e_b22_assertions(
            manifest=manifest,
            replay_counts=replay_counts,
            receiver_events=receiver_events,
            gateway_statuses=gateway_statuses,
            infrastructure=infrastructure,
        )
        assertions["pre_revocation_both_allow"] = all(
            bool(result.get("allowed"))
            for by_condition in preconditions.values()
            for result in by_condition.values()
        )
        assertions["no_selective_b_retry"] = (
            int(
                receiver_events["receiver-selective-nondelivery"]["receiver-b"][
                    "attempt_count_for_session"
                ]
            )
            == 1
        )
        summary["preconditions"] = preconditions
        summary["replay_counts"] = replay_counts
        summary["infrastructure"] = infrastructure
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
        print(f"E-B22 ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"passed": summary["passed"], "assertions": summary["assertions"]}, indent=2))
    return 0 if summary["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
