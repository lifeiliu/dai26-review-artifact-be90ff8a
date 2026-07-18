#!/usr/bin/env python3
"""Run a reproducible Keycloak 26.7 SSF PUSH and selective-failure smoke test."""

from __future__ import annotations

import argparse
import base64
import json
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


KEYCLOAK_IMAGE = "quay.io/keycloak/keycloak:26.7.0"
KEYCLOAK_IMAGE_DIGEST = "sha256:2eb3cd316835c990e69e26ade292ffa78f6fb0db7d5fc6377463c162e1979ac0"
CONTAINER = "revprop-keycloak-ssf-smoke"
BASE = "http://127.0.0.1:18080"
RECEIVER_BASE = "http://127.0.0.1:19001"
REALM = "ssf-smoke"
SESSION_REVOKED = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"


class HttpFailure(RuntimeError):
    pass


def http_request(
    url: str,
    *,
    method: str = "GET",
    json_body: dict[str, Any] | None = None,
    form: dict[str, str] | None = None,
    token: str | None = None,
    timeout: float = 10.0,
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
        except Exception as exc:  # readiness probes are expected to fail transiently
            last_error = exc
        time.sleep(0.25)
    suffix = f"; last error: {last_error}" if last_error else ""
    raise TimeoutError(f"timed out waiting for {description}{suffix}")


def receiver_state() -> dict[str, Any]:
    return http_request(f"{RECEIVER_BASE}/state")[1]


def session_items(state: dict[str, Any], key: str, receiver: str) -> list[dict[str, Any]]:
    return [
        item
        for item in state[key]
        if item["receiver"] == receiver and item["is_session_revoked"]
    ]


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def verify_rs256(encoded_set: str, jwks: dict[str, Any]) -> dict[str, Any]:
    protected, _, signature = encoded_set.split(".")
    header = json.loads(b64url_decode(protected))
    if header.get("alg") != "RS256":
        raise RuntimeError(f"unsupported smoke-test JWS algorithm: {header.get('alg')}")
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
    body = http_request(
        f"{BASE}/realms/master/protocol/openid-connect/token",
        method="POST",
        form={
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": "admin",
            "password": "admin-smoke-password",
        },
    )[1]
    return body["access_token"]


def trigger_logout() -> dict[str, Any]:
    token_body = http_request(
        f"{BASE}/realms/{REALM}/protocol/openid-connect/token",
        method="POST",
        form={
            "grant_type": "password",
            "client_id": "workload-client",
            "username": "alice",
            "password": "alice-smoke-password",
        },
    )[1]
    status, _ = http_request(
        f"{BASE}/realms/{REALM}/protocol/openid-connect/logout",
        method="POST",
        form={
            "client_id": "workload-client",
            "refresh_token": token_body["refresh_token"],
        },
    )
    return {"logout_http_status": status, "session_state": token_body.get("session_state")}


def create_stream(receiver: str, token: str) -> dict[str, Any]:
    endpoint = f"http://host.docker.internal:19001/{receiver}"
    payload = {
        "description": f"E-B21 smoke stream for {receiver}",
        "events_requested": [SESSION_REVOKED],
        "delivery": {
            "method": "urn:ietf:rfc:8935",
            "endpoint_url": endpoint,
            "authorization_header": f"Bearer {receiver}-smoke",
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


def run(output_dir: Path, keep_container: bool) -> dict[str, Any]:
    here = Path(__file__).resolve().parent
    realm_file = here / "realm-smoke.json"
    output_dir.mkdir(parents=True, exist_ok=True)
    evidence_jsonl = output_dir / "receiver_attempts.jsonl"
    receiver_log_path = output_dir / "receiver.log"
    keycloak_log_path = output_dir / "keycloak.log"
    receiver_log = receiver_log_path.open("w", encoding="utf-8")
    receiver = subprocess.Popen(
        [
            sys.executable,
            str(here / "receiver.py"),
            "--evidence-jsonl",
            str(evidence_jsonl),
        ],
        stdout=receiver_log,
        stderr=subprocess.STDOUT,
    )
    subprocess.run(["docker", "rm", "-f", CONTAINER], check=False, capture_output=True)
    summary: dict[str, Any] = {
        "experiment": "E-B21 Keycloak SSF transmitter smoke",
        "started_unix_ns": time.time_ns(),
        "keycloak_image": KEYCLOAK_IMAGE,
        "keycloak_image_digest": KEYCLOAK_IMAGE_DIGEST,
        "keycloak_source_tag_commit": "6c73e3027811d9c7b22683edd825e839272e9547",
        "delivery_method": "RFC 8935 PUSH",
        "event_type": SESSION_REVOKED,
        "smoke_only": True,
        "formal_latency_evidence": False,
        "frozen_paper_risk_policy_or_threshold_changed": False,
        "keycloak_retry_curve_changed": False,
        "keycloak_max_attempts_changed": False,
        "smoke_acceleration": {"outbox_drainer_interval": "500ms", "production_default": "30s"},
    }
    try:
        wait_for(
            lambda: http_request(f"{RECEIVER_BASE}/health")[0] == 200,
            10,
            "receiver health",
        )
        docker_run = [
            "docker",
            "run",
            "-d",
            "--rm",
            "--name",
            CONTAINER,
            "-p",
            "18080:8080",
            "-e",
            "KC_BOOTSTRAP_ADMIN_USERNAME=admin",
            "-e",
            "KC_BOOTSTRAP_ADMIN_PASSWORD=admin-smoke-password",
            "-v",
            f"{realm_file}:/opt/keycloak/data/import/ssf-smoke-realm.json:ro",
            KEYCLOAK_IMAGE,
            "start-dev",
            "--import-realm",
            "--features=ssf",
            "--spi-ssf-transmitter--default--allow-insecure-push-targets=true",
            "--spi-ssf-transmitter--default--outbox-drainer-interval=500ms",
        ]
        container_id = subprocess.check_output(docker_run, text=True).strip()
        summary["container_id"] = container_id
        wait_for(
            lambda: http_request(
                f"{BASE}/realms/{REALM}/.well-known/ssf-configuration"
            )[0]
            == 200,
            90,
            "Keycloak SSF discovery",
        )
        summary["discovery"] = http_request(
            f"{BASE}/realms/{REALM}/.well-known/ssf-configuration"
        )[1]

        token = admin_token()
        summary["streams"] = {
            receiver_name: create_stream(receiver_name, token)
            for receiver_name in ("receiver-a", "receiver-b")
        }

        before = receiver_state()
        base_counts = {
            name: len(session_items(before, "deliveries", name))
            for name in ("receiver-a", "receiver-b")
        }
        summary["normal_logout"] = trigger_logout()
        wait_for(
            lambda: all(
                len(session_items(receiver_state(), "deliveries", name))
                >= base_counts[name] + 1
                for name in ("receiver-a", "receiver-b")
            ),
            20,
            "normal session-revoked delivery to both receivers",
        )
        normal_state = receiver_state()
        summary["normal_delivery"] = {
            name: session_items(normal_state, "deliveries", name)[-1]
            for name in ("receiver-a", "receiver-b")
        }
        jwks = http_request(
            f"{BASE}/realms/{REALM}/protocol/openid-connect/certs"
        )[1]
        summary["signature_verification"] = {
            name: verify_rs256(summary["normal_delivery"][name]["encoded_set"], jwks)
            for name in ("receiver-a", "receiver-b")
        }

        http_request(f"{RECEIVER_BASE}/control/receiver-b/fail", method="POST")
        selective_before = receiver_state()
        selective_counts = {
            name: len(session_items(selective_before, "deliveries", name))
            for name in ("receiver-a", "receiver-b")
        }
        attempts_b_before = len(session_items(selective_before, "attempts", "receiver-b"))
        summary["selective_logout"] = trigger_logout()
        wait_for(
            lambda: len(session_items(receiver_state(), "deliveries", "receiver-a"))
            >= selective_counts["receiver-a"] + 1,
            20,
            "healthy receiver-a delivery during receiver-b failure",
        )
        wait_for(
            lambda: len(session_items(receiver_state(), "attempts", "receiver-b"))
            >= attempts_b_before + 1,
            20,
            "failed receiver-b delivery attempt",
        )
        failed_state = receiver_state()
        failed_attempt = session_items(failed_state, "attempts", "receiver-b")[-1]
        summary["selective_non_delivery"] = {
            "receiver_a_delivery_delta": len(
                session_items(failed_state, "deliveries", "receiver-a")
            )
            - selective_counts["receiver-a"],
            "receiver_b_delivery_delta": len(
                session_items(failed_state, "deliveries", "receiver-b")
            )
            - selective_counts["receiver-b"],
            "receiver_b_failed_attempt": failed_attempt,
        }
        summary["outbox_stats_during_failure"] = http_request(
            f"{BASE}/admin/realms/{REALM}/ssf/events/stats", token=token
        )[1]
        failed_jti = failed_attempt.get("jti")
        if failed_jti:
            summary["receiver_b_pending_event"] = http_request(
                f"{BASE}/admin/realms/{REALM}/ssf/clients/receiver-b/pending-events/{failed_jti}",
                token=token,
            )[1]

        http_request(f"{RECEIVER_BASE}/control/receiver-b/recover", method="POST")
        wait_for(
            lambda: len(session_items(receiver_state(), "deliveries", "receiver-b"))
            >= selective_counts["receiver-b"] + 1,
            15,
            "native retry delivery to recovered receiver-b",
        )
        recovered_state = receiver_state()
        recovered = session_items(recovered_state, "deliveries", "receiver-b")[-1]
        summary["native_retry_recovery"] = {
            "recovered": True,
            "delivery": recovered,
            "same_jti_as_failed_attempt": recovered.get("jti") == failed_jti,
            "same_body_sha256_as_failed_attempt": recovered.get("body_sha256")
            == failed_attempt.get("body_sha256"),
            "signature_verification": verify_rs256(recovered["encoded_set"], jwks),
        }
        summary["outbox_stats_after_recovery"] = http_request(
            f"{BASE}/admin/realms/{REALM}/ssf/events/stats", token=token
        )[1]
        summary["assertions"] = {
            "normal_delivery_to_a": bool(summary["normal_delivery"]["receiver-a"]),
            "normal_delivery_to_b": bool(summary["normal_delivery"]["receiver-b"]),
            "healthy_receiver_not_blocked": summary["selective_non_delivery"][
                "receiver_a_delivery_delta"
            ]
            >= 1,
            "selected_receiver_not_delivered": summary["selective_non_delivery"][
                "receiver_b_delivery_delta"
            ]
            == 0,
            "keycloak_recorded_pending_failure": summary.get("receiver_b_pending_event", {}).get(
                "status"
            )
            == "PENDING",
            "native_retry_delivered_same_set": summary["native_retry_recovery"][
                "same_jti_as_failed_attempt"
            ]
            and summary["native_retry_recovery"]["same_body_sha256_as_failed_attempt"],
            "set_signatures_verified": all(
                item["verified"] for item in summary["signature_verification"].values()
            )
            and summary["native_retry_recovery"]["signature_verification"]["verified"],
        }
        summary["passed"] = all(summary["assertions"].values())
        return summary
    finally:
        summary["finished_unix_ns"] = time.time_ns()
        try:
            keycloak_logs = subprocess.run(
                ["docker", "logs", CONTAINER], capture_output=True, text=True, check=False
            )
            keycloak_log_path.write_text(
                keycloak_logs.stdout + keycloak_logs.stderr, encoding="utf-8"
            )
        finally:
            if not keep_container:
                subprocess.run(
                    ["docker", "rm", "-f", CONTAINER], check=False, capture_output=True
                )
            receiver.terminate()
            try:
                receiver.wait(timeout=5)
            except subprocess.TimeoutExpired:
                receiver.kill()
            receiver_log.close()
            (output_dir / "summary.json").write_text(
                json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--keep-container", action="store_true")
    args = parser.parse_args()
    try:
        summary = run(args.output_dir.resolve(), args.keep_container)
    except Exception as exc:
        print(f"SMOKE ERROR: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"passed": summary["passed"], "assertions": summary["assertions"]}, indent=2))
    return 0 if summary["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
