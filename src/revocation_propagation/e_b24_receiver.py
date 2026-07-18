"""Durable Keycloak SET receiver and independent gateway handoff worker."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import sqlite3
import ssl
import threading
import time
import urllib.request
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping, Sequence

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .e_b24_gateway_control import GatewayControlClient
from .real_effect_gate import canonical_json


SESSION_REVOKED = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
MAX_SET_BYTES = 1_048_576


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


@dataclass(frozen=True)
class VerifiedSet:
    jti: str
    issuer: str
    audience: str
    delegation_id: str
    event_id: str
    sequence: int
    encoded_sha256: str
    key_id: str
    algorithm: str
    issued_at: int

    def metadata(self) -> dict[str, object]:
        return {
            "jti": self.jti,
            "issuer": self.issuer,
            "audience": self.audience,
            "delegation_id": self.delegation_id,
            "event_id": self.event_id,
            "sequence": self.sequence,
            "encoded_sha256": self.encoded_sha256,
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "issued_at": self.issued_at,
            "event_type": SESSION_REVOKED,
        }


class SetVerifier:
    def __init__(
        self,
        *,
        issuer: str,
        audience_prefix: str,
        jwks_url: str | None = None,
        jwks: Mapping[str, object] | None = None,
        ca_file: str | None = None,
        timeout: float = 10.0,
    ) -> None:
        if not jwks_url and jwks is None:
            raise ValueError("a JWKS URL or object is required")
        self.issuer = issuer.rstrip("/")
        self.audience_prefix = audience_prefix
        self.jwks_url = jwks_url
        self._jwks = dict(jwks) if jwks is not None else None
        self.ssl_context = ssl.create_default_context(cafile=ca_file) if ca_file else None
        self.timeout = timeout

    def _keys(self, *, refresh: bool = False) -> Mapping[str, object]:
        if self._jwks is not None and not refresh:
            return self._jwks
        if not self.jwks_url:
            if self._jwks is None:
                raise RuntimeError("JWKS is unavailable")
            return self._jwks
        with urllib.request.urlopen(
            self.jwks_url,
            timeout=self.timeout,
            context=self.ssl_context,
        ) as response:
            parsed = json.loads(response.read())
        if not isinstance(parsed, dict):
            raise RuntimeError("JWKS endpoint returned a non-object response")
        self._jwks = parsed
        return parsed

    def verify(self, encoded_set: str) -> VerifiedSet:
        parts = encoded_set.split(".")
        if len(parts) != 3:
            raise ValueError("SET is not a compact JWS")
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        if header.get("alg") != "RS256" or not header.get("kid"):
            raise ValueError("SET must use RS256 with a key ID")

        def find_key(keys: Mapping[str, object]) -> Mapping[str, object] | None:
            candidates = keys.get("keys", [])
            if not isinstance(candidates, list):
                return None
            return next(
                (
                    item
                    for item in candidates
                    if isinstance(item, dict) and item.get("kid") == header["kid"]
                ),
                None,
            )

        keys = self._keys()
        jwk = find_key(keys)
        if jwk is None and self.jwks_url:
            jwk = find_key(self._keys(refresh=True))
        if jwk is None:
            raise ValueError(f"no JWK for SET kid={header['kid']}")
        public_key = rsa.RSAPublicNumbers(
            int.from_bytes(_b64url_decode(str(jwk["e"])), "big"),
            int.from_bytes(_b64url_decode(str(jwk["n"])), "big"),
        ).public_key()
        public_key.verify(
            _b64url_decode(parts[2]),
            f"{parts[0]}.{parts[1]}".encode("ascii"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )

        issuer = str(payload.get("iss", "")).rstrip("/")
        if issuer != self.issuer:
            raise ValueError(f"unexpected SET issuer: {issuer}")
        raw_audience = payload.get("aud")
        audiences = raw_audience if isinstance(raw_audience, list) else [raw_audience]
        audience = next(
            (
                value
                for value in audiences
                if isinstance(value, str) and value.startswith(self.audience_prefix)
            ),
            None,
        )
        if audience is None:
            raise ValueError("SET audience does not match the receiver stream")
        events = payload.get("events")
        if not isinstance(events, dict) or SESSION_REVOKED not in events:
            raise ValueError("SET is not a session-revoked event")
        event = events[SESSION_REVOKED]
        if not isinstance(event, dict):
            raise ValueError("session-revoked event body is malformed")
        sub_id = payload.get("sub_id")
        session = sub_id.get("session") if isinstance(sub_id, dict) else None
        delegation_id = session.get("id") if isinstance(session, dict) else None
        if not isinstance(delegation_id, str) or not delegation_id:
            raise ValueError("SET does not contain an opaque session ID")
        jti = payload.get("jti")
        issued_at = payload.get("iat")
        sequence = event.get("event_timestamp", issued_at)
        if not isinstance(jti, str) or not jti:
            raise ValueError("SET does not contain a JTI")
        if not isinstance(issued_at, int) or not isinstance(sequence, int):
            raise ValueError("SET does not contain integer event time")
        return VerifiedSet(
            jti=jti,
            issuer=issuer,
            audience=audience,
            delegation_id=delegation_id,
            event_id=jti,
            sequence=sequence,
            encoded_sha256=hashlib.sha256(encoded_set.encode("utf-8")).hexdigest(),
            key_id=str(header["kid"]),
            algorithm="RS256",
            issued_at=issued_at,
        )


class CloudReceiverStore:
    """Durable inbox with one required receipt per physical gateway target."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS inbox (
                    jti TEXT PRIMARY KEY,
                    delegation_id TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    channel TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    set_sha256 TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('PERSISTED', 'ENFORCED')),
                    persisted_at_ns INTEGER NOT NULL,
                    enforced_at_ns INTEGER
                );
                CREATE TABLE IF NOT EXISTS gateway_targets (
                    jti TEXT NOT NULL REFERENCES inbox(jti),
                    gateway_id TEXT NOT NULL,
                    gateway_url TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT,
                    PRIMARY KEY (jti, gateway_id)
                );
                CREATE TABLE IF NOT EXISTS enforcement_receipts (
                    jti TEXT NOT NULL REFERENCES inbox(jti),
                    gateway_id TEXT NOT NULL,
                    receipt_id TEXT NOT NULL,
                    receipt_json TEXT NOT NULL,
                    recorded_at_ns INTEGER NOT NULL,
                    PRIMARY KEY (jti, gateway_id)
                );
                """
            )

    def persist_event(
        self,
        event: VerifiedSet,
        *,
        channel: str,
        gateway_targets: Sequence[Mapping[str, str]],
    ) -> dict[str, object]:
        if not gateway_targets:
            raise ValueError("receiver requires at least one gateway target")
        normalized = sorted(
            (str(item["gateway_id"]), str(item["gateway_url"]).rstrip("/"))
            for item in gateway_targets
        )
        if len({gateway_id for gateway_id, _ in normalized}) != len(normalized):
            raise ValueError("receiver gateway IDs must be unique")
        now = time.time_ns()
        with self._connect() as connection:
            existing = connection.execute(
                "SELECT set_sha256 FROM inbox WHERE jti=?", (event.jti,)
            ).fetchone()
            if existing is None:
                connection.execute(
                    "INSERT INTO inbox VALUES (?, ?, ?, ?, ?, ?, ?, 'PERSISTED', ?, NULL)",
                    (
                        event.jti,
                        event.delegation_id,
                        event.event_id,
                        channel,
                        event.sequence,
                        event.encoded_sha256,
                        canonical_json(event.metadata()),
                        now,
                    ),
                )
                connection.executemany(
                    "INSERT INTO gateway_targets (jti, gateway_id, gateway_url) VALUES (?, ?, ?)",
                    [(event.jti, gateway_id, url) for gateway_id, url in normalized],
                )
            else:
                if existing["set_sha256"] != event.encoded_sha256:
                    raise ValueError("receiver JTI collision with different SET content")
                observed = connection.execute(
                    "SELECT gateway_id, gateway_url FROM gateway_targets WHERE jti=? ORDER BY gateway_id",
                    (event.jti,),
                ).fetchall()
                if [(row["gateway_id"], row["gateway_url"]) for row in observed] != normalized:
                    raise ValueError("receiver duplicate changed the frozen gateway target set")
        return self.event(event.jti)

    def event(self, jti: str) -> dict[str, object]:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM inbox WHERE jti=?", (jti,)).fetchone()
            if row is None:
                raise KeyError(jti)
            targets = connection.execute(
                "SELECT gateway_id, gateway_url, attempts, last_error FROM gateway_targets "
                "WHERE jti=? ORDER BY gateway_id",
                (jti,),
            ).fetchall()
            receipts = connection.execute(
                "SELECT gateway_id, receipt_json FROM enforcement_receipts "
                "WHERE jti=? ORDER BY gateway_id",
                (jti,),
            ).fetchall()
        result = dict(row)
        result["metadata"] = json.loads(result.pop("metadata_json"))
        result["targets"] = [dict(item) for item in targets]
        result["receipts"] = {
            item["gateway_id"]: json.loads(item["receipt_json"]) for item in receipts
        }
        return result

    def pending_deliveries(self, *, limit: int = 100) -> list[dict[str, object]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT i.jti, i.delegation_id, i.event_id, i.channel, i.sequence, "
                "t.gateway_id, t.gateway_url FROM inbox i "
                "JOIN gateway_targets t ON t.jti=i.jti "
                "LEFT JOIN enforcement_receipts r ON r.jti=t.jti AND r.gateway_id=t.gateway_id "
                "WHERE i.status='PERSISTED' AND r.receipt_id IS NULL "
                "ORDER BY i.persisted_at_ns, t.gateway_id LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def record_failure(self, *, jti: str, gateway_id: str, error: BaseException) -> None:
        with self._connect() as connection:
            connection.execute(
                "UPDATE gateway_targets SET attempts=attempts+1, last_error=? "
                "WHERE jti=? AND gateway_id=?",
                (f"{type(error).__name__}: {error}", jti, gateway_id),
            )

    def record_receipt(
        self,
        *,
        jti: str,
        gateway_id: str,
        receipt: Mapping[str, object],
    ) -> dict[str, object]:
        with self._connect() as connection:
            inbox = connection.execute("SELECT * FROM inbox WHERE jti=?", (jti,)).fetchone()
            target = connection.execute(
                "SELECT gateway_id FROM gateway_targets WHERE jti=? AND gateway_id=?",
                (jti, gateway_id),
            ).fetchone()
            if inbox is None or target is None:
                raise ValueError("receipt does not match a persisted receiver target")
            expected = {
                "delegation_id": inbox["delegation_id"],
                "event_id": inbox["event_id"],
                "channel": inbox["channel"],
                "sequence": inbox["sequence"],
                "gateway_id": gateway_id,
            }
            for field, value in expected.items():
                if receipt.get(field) != value:
                    raise ValueError(f"enforcement receipt does not bind expected {field}")
            if receipt.get("applied") is not True or not receipt.get("receipt_id"):
                raise ValueError("incomplete enforcement receipt")
            encoded_receipt = canonical_json(dict(receipt))
            existing = connection.execute(
                "SELECT receipt_id, receipt_json FROM enforcement_receipts "
                "WHERE jti=? AND gateway_id=?",
                (jti, gateway_id),
            ).fetchone()
            now = time.time_ns()
            if existing is None:
                connection.execute(
                    "INSERT INTO enforcement_receipts VALUES (?, ?, ?, ?, ?)",
                    (jti, gateway_id, receipt["receipt_id"], encoded_receipt, now),
                )
                connection.execute(
                    "UPDATE gateway_targets SET attempts=attempts+1, last_error=NULL "
                    "WHERE jti=? AND gateway_id=?",
                    (jti, gateway_id),
                )
            elif (
                existing["receipt_id"] != receipt["receipt_id"]
                or existing["receipt_json"] != encoded_receipt
            ):
                raise ValueError("enforcement receipt for a gateway is immutable")
            remaining = connection.execute(
                "SELECT COUNT(*) FROM gateway_targets t "
                "LEFT JOIN enforcement_receipts r ON r.jti=t.jti AND r.gateway_id=t.gateway_id "
                "WHERE t.jti=? AND r.receipt_id IS NULL",
                (jti,),
            ).fetchone()[0]
            if remaining == 0:
                connection.execute(
                    "UPDATE inbox SET status='ENFORCED', enforced_at_ns=? WHERE jti=?",
                    (now, jti),
                )
        return self.event(jti)


class ReceiverWorker:
    def __init__(
        self,
        *,
        store: CloudReceiverStore,
        gateway_bearer_token: str,
        gateway_ca_file: str | None = None,
        timeout: float = 10.0,
    ) -> None:
        self.store = store
        self.gateway_bearer_token = gateway_bearer_token
        self.gateway_ca_file = gateway_ca_file
        self.timeout = timeout

    def run_once(self, *, limit: int = 100) -> dict[str, int]:
        counts = {"attempted": 0, "enforced": 0, "failed": 0}
        for delivery in self.store.pending_deliveries(limit=limit):
            counts["attempted"] += 1
            client = GatewayControlClient(
                base_url=str(delivery["gateway_url"]),
                bearer_token=self.gateway_bearer_token,
                ca_file=self.gateway_ca_file,
                timeout=self.timeout,
            )
            payload = {
                "delegation_id": delivery["delegation_id"],
                "event_id": delivery["event_id"],
                "channel": delivery["channel"],
                "sequence": delivery["sequence"],
            }
            try:
                receipt = client.apply_revocation(payload)
                event = self.store.record_receipt(
                    jti=str(delivery["jti"]),
                    gateway_id=str(delivery["gateway_id"]),
                    receipt=receipt,
                )
                counts["enforced"] += int(event["status"] == "ENFORCED")
            except Exception as error:
                self.store.record_failure(
                    jti=str(delivery["jti"]),
                    gateway_id=str(delivery["gateway_id"]),
                    error=error,
                )
                counts["failed"] += 1
        return counts


def build_receiver_ingress_server(
    *,
    host: str,
    port: int,
    store: CloudReceiverStore,
    verifier: SetVerifier,
    gateway_targets: Sequence[Mapping[str, str]],
    push_authorization: str,
    evidence_path: str | Path,
    tls_cert: str | None = None,
    tls_key: str | None = None,
) -> ThreadingHTTPServer:
    expected_authorization = push_authorization.encode("utf-8")
    evidence = Path(evidence_path)
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence_lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        server_version = "E-B24DurableReceiver/1.0"

        def log_message(self, fmt: str, *args: object) -> None:
            return

        def _send(self, status: int, body: Mapping[str, object]) -> None:
            encoded = (canonical_json(dict(body)) + "\n").encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/health":
                self._send(200, {"status": "ok"})
                return
            self._send(404, {"error": "not_found"})

        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/events":
                self._send(404, {"error": "not_found"})
                return
            supplied = self.headers.get("Authorization", "").encode("utf-8")
            if not hmac.compare_digest(supplied, expected_authorization):
                self._send(401, {"error": "unauthorized"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length <= 0 or length > MAX_SET_BYTES:
                    raise ValueError("invalid SET request size")
                encoded_set = self.rfile.read(length).decode("utf-8")
                verified = verifier.verify(encoded_set)
                event = store.persist_event(
                    verified,
                    channel="keycloak-push",
                    gateway_targets=gateway_targets,
                )
                record = {
                    "observed_at_ns": time.time_ns(),
                    **verified.metadata(),
                    "receiver_status": event["status"],
                    "target_gateway_ids": [
                        item["gateway_id"] for item in event["targets"]
                    ],
                    "http_response": 202,
                }
                with evidence_lock:
                    with evidence.open("a", encoding="utf-8") as handle:
                        handle.write(canonical_json(record) + "\n")
                self._send(
                    202,
                    {
                        "accepted": True,
                        "jti": verified.jti,
                        "status": event["status"],
                    },
                )
            except Exception as error:
                self._send(400, {"error": type(error).__name__, "detail": str(error)})

    server = ThreadingHTTPServer((host, port), Handler)
    if tls_cert or tls_key:
        if not tls_cert or not tls_key:
            raise ValueError("both TLS certificate and key are required")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(tls_cert, tls_key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    return server


def _secret(path: str) -> str:
    value = Path(path).read_text(encoding="utf-8").strip()
    if not value:
        raise ValueError(f"empty secret file: {path}")
    return value


def _targets(path: str) -> list[dict[str, str]]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, list) or not payload:
        raise ValueError("gateway target file must be a non-empty JSON list")
    return [
        {"gateway_id": str(item["gateway_id"]), "gateway_url": str(item["gateway_url"])}
        for item in payload
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description="Run an E-B24 receiver ingress or worker.")
    subparsers = parser.add_subparsers(dest="mode", required=True)
    ingress = subparsers.add_parser("ingress")
    ingress.add_argument("--host", default="0.0.0.0")
    ingress.add_argument("--port", type=int, required=True)
    ingress.add_argument("--state-db", required=True)
    ingress.add_argument("--issuer", required=True)
    ingress.add_argument("--audience-prefix", required=True)
    ingress.add_argument("--jwks-url", required=True)
    ingress.add_argument("--jwks-ca-file")
    ingress.add_argument("--gateway-targets", required=True)
    ingress.add_argument("--push-authorization-file", required=True)
    ingress.add_argument("--evidence-jsonl", required=True)
    ingress.add_argument("--tls-cert", required=True)
    ingress.add_argument("--tls-key", required=True)
    worker = subparsers.add_parser("worker")
    worker.add_argument("--state-db", required=True)
    worker.add_argument("--gateway-bearer-token-file", required=True)
    worker.add_argument("--gateway-ca-file")
    worker.add_argument("--interval-seconds", type=float, default=0.5)
    args = parser.parse_args()

    store = CloudReceiverStore(args.state_db)
    if args.mode == "ingress":
        verifier = SetVerifier(
            issuer=args.issuer,
            audience_prefix=args.audience_prefix,
            jwks_url=args.jwks_url,
            ca_file=args.jwks_ca_file,
        )
        server = build_receiver_ingress_server(
            host=args.host,
            port=args.port,
            store=store,
            verifier=verifier,
            gateway_targets=_targets(args.gateway_targets),
            push_authorization=_secret(args.push_authorization_file),
            evidence_path=args.evidence_jsonl,
            tls_cert=args.tls_cert,
            tls_key=args.tls_key,
        )
        server.serve_forever()
    else:
        worker_process = ReceiverWorker(
            store=store,
            gateway_bearer_token=_secret(args.gateway_bearer_token_file),
            gateway_ca_file=args.gateway_ca_file,
        )
        while True:
            worker_process.run_once()
            time.sleep(args.interval_seconds)


if __name__ == "__main__":
    main()
