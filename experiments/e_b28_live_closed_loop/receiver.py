#!/usr/bin/env python3
"""Durable two-receiver relay for E-B28 live closed-loop trials."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import sqlite3
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


SESSION_REVOKED = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
RECEIVERS = ("receiver-a", "receiver-b")
ARMS = ("normal_c4", "selective_c3", "recovery_c4")
MAX_BODY_BYTES = 1_048_576


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def decode_jws_part(encoded: str, part: int) -> dict[str, Any]:
    try:
        value = encoded.split(".")[part]
        value += "=" * (-len(value) % 4)
        decoded = json.loads(base64.urlsafe_b64decode(value.encode("ascii")))
        return decoded if isinstance(decoded, dict) else {}
    except (IndexError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return {}


def session_id_from_payload(payload: dict[str, Any]) -> str | None:
    sub_id = payload.get("sub_id")
    session = sub_id.get("session") if isinstance(sub_id, dict) else None
    value = session.get("id") if isinstance(session, dict) else None
    return value if isinstance(value, str) and value else None


class DurableRelayStore:
    """SQLite evidence store; each HTTP 202 follows a FULL-synchronous commit."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS registrations (
                    run_id TEXT PRIMARY KEY,
                    arm TEXT NOT NULL,
                    receiver_b_action TEXT NOT NULL CHECK(receiver_b_action IN ('forward','withhold')),
                    registered_at_ns INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS active_registration (
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    run_id TEXT NOT NULL REFERENCES registrations(run_id)
                );
                CREATE TABLE IF NOT EXISTS attempts (
                    attempt_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL REFERENCES registrations(run_id),
                    observed_at_ns INTEGER NOT NULL,
                    receiver TEXT NOT NULL,
                    forwarded INTEGER NOT NULL CHECK(forwarded IN (0,1)),
                    http_response INTEGER NOT NULL,
                    authorization_valid INTEGER NOT NULL CHECK(authorization_valid IN (0,1)),
                    content_type TEXT,
                    body_sha256 TEXT NOT NULL,
                    encoded_set TEXT NOT NULL,
                    jws_header_json TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    jti TEXT,
                    session_id TEXT,
                    is_session_revoked INTEGER NOT NULL CHECK(is_session_revoked IN (0,1)),
                    UNIQUE(run_id, receiver, jti)
                );
                """
            )

    def register(self, *, run_id: str, arm: str, receiver_b_action: str) -> dict[str, Any]:
        if not run_id:
            raise ValueError("run_id must be non-empty")
        if arm not in ARMS:
            raise ValueError(f"unsupported E-B28 arm: {arm}")
        expected = "withhold" if arm == "selective_c3" else "forward"
        if receiver_b_action != expected:
            raise ValueError(f"{arm} requires receiver-b action {expected}")
        now = time.time_ns()
        with self.lock, self._connect() as connection:
            existing = connection.execute(
                "SELECT arm, receiver_b_action FROM registrations WHERE run_id=?", (run_id,)
            ).fetchone()
            if existing is not None:
                raise ValueError(f"run is already registered: {run_id}")
            connection.execute(
                "INSERT INTO registrations VALUES (?, ?, ?, ?)",
                (run_id, arm, receiver_b_action, now),
            )
            connection.execute(
                "INSERT INTO active_registration(singleton,run_id) VALUES (1,?) "
                "ON CONFLICT(singleton) DO UPDATE SET run_id=excluded.run_id",
                (run_id,),
            )
        return self.state(run_id)

    def _active(self, connection: sqlite3.Connection) -> sqlite3.Row:
        row = connection.execute(
            "SELECT r.* FROM active_registration a JOIN registrations r ON r.run_id=a.run_id "
            "WHERE a.singleton=1"
        ).fetchone()
        if row is None:
            raise RuntimeError("no E-B28 run is registered")
        return row

    def record(
        self,
        *,
        receiver: str,
        authorization_valid: bool,
        content_type: str | None,
        raw: bytes,
    ) -> dict[str, Any]:
        if receiver not in RECEIVERS:
            raise ValueError(f"unknown receiver: {receiver}")
        encoded_set = raw.decode("utf-8")
        header = decode_jws_part(encoded_set, 0)
        payload = decode_jws_part(encoded_set, 1)
        event_types = sorted(
            str(item) for item in (payload.get("events") or {})
        ) if isinstance(payload.get("events"), dict) else []
        revoked = SESSION_REVOKED in event_types
        if not revoked:
            raise ValueError("request is not a session-revoked SET")
        jti = payload.get("jti")
        if not isinstance(jti, str) or not jti:
            raise ValueError("SET has no JTI")
        session_id = session_id_from_payload(payload)
        if not session_id:
            raise ValueError("SET has no session identifier")
        observed = time.time_ns()
        with self.lock, self._connect() as connection:
            registration = self._active(connection)
            action = (
                str(registration["receiver_b_action"])
                if receiver == "receiver-b"
                else "forward"
            )
            forwarded = action == "forward"
            connection.execute(
                "INSERT INTO attempts(run_id,observed_at_ns,receiver,forwarded,http_response,"
                "authorization_valid,content_type,body_sha256,encoded_set,jws_header_json,"
                "payload_json,jti,session_id,is_session_revoked) "
                "VALUES (?,?,?,?,202,?,?,?,?,?,?,?,?,1)",
                (
                    registration["run_id"],
                    observed,
                    receiver,
                    int(forwarded),
                    int(authorization_valid),
                    content_type,
                    hashlib.sha256(raw).hexdigest(),
                    encoded_set,
                    canonical_json(header),
                    canonical_json(payload),
                    jti,
                    session_id,
                ),
            )
            # Leaving the context commits the FULL-synchronous transaction before 202.
            run_id = str(registration["run_id"])
        return {
            "accepted": True,
            "run_id": run_id,
            "receiver": receiver,
            "forwarded": forwarded,
            "jti": jti,
            "session_id": session_id,
            "persisted_at_ns": observed,
        }

    def state(self, run_id: str) -> dict[str, Any]:
        with self._connect() as connection:
            registration = connection.execute(
                "SELECT * FROM registrations WHERE run_id=?", (run_id,)
            ).fetchone()
            if registration is None:
                raise KeyError(run_id)
            rows = connection.execute(
                "SELECT * FROM attempts WHERE run_id=? ORDER BY attempt_id", (run_id,)
            ).fetchall()
        attempts: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["forwarded"] = bool(item["forwarded"])
            item["authorization_valid"] = bool(item["authorization_valid"])
            item["is_session_revoked"] = bool(item["is_session_revoked"])
            item["jws_header"] = json.loads(item.pop("jws_header_json"))
            item["payload"] = json.loads(item.pop("payload_json"))
            attempts.append(item)
        result = dict(registration)
        result["attempts"] = attempts
        result["attempt_count"] = len(attempts)
        return result


def make_handler(store: DurableRelayStore) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "RevPropE-B28Relay/1.0"

        def log_message(self, fmt: str, *args: object) -> None:
            return

        def send_json(self, status: int, body: dict[str, Any]) -> None:
            encoded = (canonical_json(body) + "\n").encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def read_json(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > MAX_BODY_BYTES:
                raise ValueError("invalid request size")
            body = json.loads(self.rfile.read(length))
            if not isinstance(body, dict):
                raise ValueError("request body must be a JSON object")
            return body

        def do_GET(self) -> None:  # noqa: N802
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path == "/health":
                self.send_json(200, {"status": "ok", "sqlite": str(store.path)})
                return
            if parsed.path == "/state":
                run_id = urllib.parse.parse_qs(parsed.query).get("run_id", [""])[0]
                try:
                    self.send_json(200, store.state(run_id))
                except KeyError:
                    self.send_json(404, {"error": "unknown_run", "run_id": run_id})
                return
            self.send_json(404, {"error": "not_found"})

        def do_POST(self) -> None:  # noqa: N802
            if self.path == "/control/register":
                try:
                    body = self.read_json()
                    state = store.register(
                        run_id=str(body.get("run_id", "")),
                        arm=str(body.get("arm", "")),
                        receiver_b_action=str(body.get("receiver_b_action", "")),
                    )
                    self.send_json(201, state)
                except Exception as error:
                    self.send_json(409, {"error": type(error).__name__, "detail": str(error)})
                return

            receiver = self.path.strip("/")
            if receiver not in RECEIVERS:
                self.send_json(404, {"error": "unknown_receiver"})
                return
            expected = f"Bearer {receiver}-e-b22".encode("utf-8")
            supplied = self.headers.get("Authorization", "").encode("utf-8")
            authorization_valid = hmac.compare_digest(expected, supplied)
            if not authorization_valid:
                self.send_json(401, {"error": "unauthorized"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length <= 0 or length > MAX_BODY_BYTES:
                    raise ValueError("invalid SET size")
                evidence = store.record(
                    receiver=receiver,
                    authorization_valid=authorization_valid,
                    content_type=self.headers.get("Content-Type"),
                    raw=self.rfile.read(length),
                )
                self.send_json(202, evidence)
            except Exception as error:
                self.send_json(400, {"error": type(error).__name__, "detail": str(error)})

    return Handler


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=19002)
    parser.add_argument("--sqlite", type=Path, required=True)
    args = parser.parse_args()
    store = DurableRelayStore(args.sqlite)
    ThreadingHTTPServer((args.host, args.port), make_handler(store)).serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
