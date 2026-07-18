import base64
import json
import threading
import time
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from revocation_propagation.e_b24_gateway_control import build_gateway_control_server
from revocation_propagation.e_b24_receiver import (
    SESSION_REVOKED,
    CloudReceiverStore,
    ReceiverWorker,
    SetVerifier,
    VerifiedSet,
    build_receiver_ingress_server,
)
from revocation_propagation.real_effect_gate import PersistentEffectGateway


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def signed_set(*, audience: str = "receiver-smoke/stream-1"):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private_key.public_key().public_numbers()
    jwks = {
        "keys": [
            {
                "kty": "RSA",
                "kid": "test-key",
                "alg": "RS256",
                "n": b64url(public.n.to_bytes((public.n.bit_length() + 7) // 8, "big")),
                "e": b64url(public.e.to_bytes((public.e.bit_length() + 7) // 8, "big")),
            }
        ]
    }
    now = int(time.time())
    header = b64url(json.dumps({"alg": "RS256", "kid": "test-key"}).encode())
    payload = b64url(
        json.dumps(
            {
                "iss": "https://keycloak.internal/realms/ssf-smoke",
                "aud": audience,
                "iat": now,
                "jti": "event-jti-1",
                "sub_id": {
                    "format": "complex",
                    "session": {"format": "opaque", "id": "delegation-session-1"},
                },
                "events": {
                    SESSION_REVOKED: {
                        "event_timestamp": now,
                        "reason_admin": {"en": "User logout"},
                    }
                },
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    )
    signing_input = f"{header}.{payload}".encode("ascii")
    signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{header}.{payload}.{b64url(signature)}", jwks


def test_set_verifier_binds_issuer_audience_session_and_signature() -> None:
    encoded, jwks = signed_set()
    verifier = SetVerifier(
        issuer="https://keycloak.internal/realms/ssf-smoke",
        audience_prefix="receiver-smoke/",
        jwks=jwks,
    )
    verified = verifier.verify(encoded)
    assert verified.jti == "event-jti-1"
    assert verified.delegation_id == "delegation-session-1"
    assert verified.audience == "receiver-smoke/stream-1"
    assert verified.algorithm == "RS256"


def test_receiver_ingress_persists_before_202_and_worker_survives_reopen(tmp_path: Path) -> None:
    gateway = PersistentEffectGateway(
        gateway_id="smoke-gateway-1",
        state_db=tmp_path / "gateway.sqlite3",
        allowlist={},
        filesystem_store=None,
        postgres_store=None,
    )
    control = build_gateway_control_server(
        host="127.0.0.1",
        port=0,
        gateway=gateway,
        bearer_token="gateway-token",
    )
    control_thread = threading.Thread(target=control.serve_forever, daemon=True)
    control_thread.start()
    control_url = f"http://127.0.0.1:{control.server_address[1]}"

    encoded, jwks = signed_set()
    store_path = tmp_path / "receiver.sqlite3"
    store = CloudReceiverStore(store_path)
    ingress = build_receiver_ingress_server(
        host="127.0.0.1",
        port=0,
        store=store,
        verifier=SetVerifier(
            issuer="https://keycloak.internal/realms/ssf-smoke",
            audience_prefix="receiver-smoke/",
            jwks=jwks,
        ),
        gateway_targets=[
            {"gateway_id": "smoke-gateway-1", "gateway_url": control_url}
        ],
        push_authorization="Bearer receiver-push-token",
        evidence_path=tmp_path / "receiver-evidence.jsonl",
    )
    ingress_thread = threading.Thread(target=ingress.serve_forever, daemon=True)
    ingress_thread.start()
    try:
        request = urllib.request.Request(
            f"http://127.0.0.1:{ingress.server_address[1]}/events",
            data=encoded.encode("utf-8"),
            headers={
                "Authorization": "Bearer receiver-push-token",
                "Content-Type": "application/secevent+jwt",
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            body = json.loads(response.read())
            assert response.status == 202
        assert body["status"] == "PERSISTED"
        assert CloudReceiverStore(store_path).event("event-jti-1")["status"] == "PERSISTED"

        reopened = CloudReceiverStore(store_path)
        result = ReceiverWorker(
            store=reopened,
            gateway_bearer_token="gateway-token",
        ).run_once()
        event = CloudReceiverStore(store_path).event("event-jti-1")
        assert result == {"attempted": 1, "enforced": 1, "failed": 0}
        assert event["status"] == "ENFORCED"
        assert event["receipts"]["smoke-gateway-1"]["receipt_id"]
        assert gateway.status("delegation-session-1")["revoked"] is True
    finally:
        ingress.shutdown()
        ingress.server_close()
        ingress_thread.join(timeout=5)
        control.shutdown()
        control.server_close()
        control_thread.join(timeout=5)


def test_receiver_requires_every_gateway_receipt(tmp_path: Path) -> None:
    event = VerifiedSet(
        jti="jti",
        issuer="https://issuer",
        audience="receiver/stream",
        delegation_id="d",
        event_id="jti",
        sequence=7,
        encoded_sha256="a" * 64,
        key_id="kid",
        algorithm="RS256",
        issued_at=7,
    )
    store = CloudReceiverStore(tmp_path / "receiver.sqlite3")
    store.persist_event(
        event,
        channel="keycloak-push",
        gateway_targets=[
            {"gateway_id": "g1", "gateway_url": "https://g1"},
            {"gateway_id": "g2", "gateway_url": "https://g2"},
        ],
    )

    common = {
        "applied": True,
        "delegation_id": "d",
        "event_id": "jti",
        "channel": "keycloak-push",
        "sequence": 7,
        "applied_at_ns": 1,
    }
    first = store.record_receipt(
        jti="jti",
        gateway_id="g1",
        receipt={**common, "gateway_id": "g1", "receipt_id": "r1"},
    )
    second = store.record_receipt(
        jti="jti",
        gateway_id="g2",
        receipt={**common, "gateway_id": "g2", "receipt_id": "r2"},
    )
    assert first["status"] == "PERSISTED"
    assert second["status"] == "ENFORCED"
    assert set(second["receipts"]) == {"g1", "g2"}

    duplicate = store.record_receipt(
        jti="jti",
        gateway_id="g2",
        receipt={**common, "gateway_id": "g2", "receipt_id": "r2"},
    )
    assert duplicate["receipts"]["g2"]["receipt_id"] == "r2"

    try:
        store.record_receipt(
            jti="jti",
            gateway_id="g2",
            receipt={**common, "gateway_id": "g2", "receipt_id": "replacement"},
        )
    except ValueError as error:
        assert "immutable" in str(error)
    else:
        raise AssertionError("conflicting receipt overwrote durable evidence")
