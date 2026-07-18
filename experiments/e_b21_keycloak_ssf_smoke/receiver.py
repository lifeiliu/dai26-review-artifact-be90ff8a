#!/usr/bin/env python3
"""Minimal observable RFC 8935 endpoint for the Keycloak SSF smoke test."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


SESSION_REVOKED = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"


def decode_jws_part(encoded: str, part: int) -> dict[str, Any]:
    try:
        payload = encoded.split(".")[part]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload.encode("ascii")))
    except (IndexError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return {}


class State:
    def __init__(self, evidence_path: Path) -> None:
        self.lock = threading.Lock()
        self.failed: set[str] = set()
        self.attempts: list[dict[str, Any]] = []
        self.deliveries: list[dict[str, Any]] = []
        self.evidence_path = evidence_path

    def record(self, item: dict[str, Any], delivered: bool) -> None:
        with self.lock:
            self.attempts.append(item)
            if delivered:
                self.deliveries.append(item)
            with self.evidence_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(item, sort_keys=True) + "\n")

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return {
                "failed_receivers": sorted(self.failed),
                "attempts": list(self.attempts),
                "deliveries": list(self.deliveries),
            }


def make_handler(state: State) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "RevPropSsfSmokeReceiver/1.0"

        def log_message(self, fmt: str, *args: object) -> None:
            return

        def send_json(self, status: int, body: dict[str, Any]) -> None:
            encoded = json.dumps(body, sort_keys=True).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/health":
                self.send_json(200, {"status": "ok"})
                return
            if self.path == "/state":
                self.send_json(200, state.snapshot())
                return
            self.send_json(404, {"error": "not_found"})

        def do_POST(self) -> None:  # noqa: N802
            if self.path.startswith("/control/"):
                parts = self.path.strip("/").split("/")
                if len(parts) != 3 or parts[0] != "control":
                    self.send_json(400, {"error": "bad_control_path"})
                    return
                receiver, action = parts[1], parts[2]
                with state.lock:
                    if action == "fail":
                        state.failed.add(receiver)
                    elif action == "recover":
                        state.failed.discard(receiver)
                    else:
                        self.send_json(400, {"error": "bad_action"})
                        return
                self.send_json(200, {"receiver": receiver, "action": action})
                return

            receiver = self.path.strip("/")
            if receiver not in {"receiver-a", "receiver-b"}:
                self.send_json(404, {"error": "unknown_receiver"})
                return

            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length)
            encoded_set = raw.decode("utf-8", errors="replace")
            decoded = decode_jws_part(encoded_set, 1)
            protected_header = decode_jws_part(encoded_set, 0)
            event_types = sorted(decoded.get("events", {}).keys())
            with state.lock:
                blocked = receiver in state.failed
            status = 503 if blocked else 202
            item = {
                "observed_unix_ns": time.time_ns(),
                "receiver": receiver,
                "blocked": blocked,
                "http_response": status,
                "content_type": self.headers.get("Content-Type"),
                "authorization": self.headers.get("Authorization"),
                "body_sha256": hashlib.sha256(raw).hexdigest(),
                "encoded_set": encoded_set,
                "jws_header": protected_header,
                "jti": decoded.get("jti"),
                "iss": decoded.get("iss"),
                "aud": decoded.get("aud"),
                "sub_id": decoded.get("sub_id"),
                "event_types": event_types,
                "is_session_revoked": SESSION_REVOKED in event_types,
            }
            state.record(item, delivered=not blocked)
            self.send_json(status, {"accepted": not blocked})

    return Handler


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=19001)
    parser.add_argument("--evidence-jsonl", type=Path, required=True)
    args = parser.parse_args()
    args.evidence_jsonl.parent.mkdir(parents=True, exist_ok=True)
    args.evidence_jsonl.write_text("", encoding="utf-8")
    state = State(args.evidence_jsonl)
    server = ThreadingHTTPServer((args.host, args.port), make_handler(state))
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
