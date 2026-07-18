#!/usr/bin/env python3
"""Observable RFC 8935 relay for the frozen E-B22 receiver fault."""

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
        self.withheld: set[str] = set()
        self.attempts: list[dict[str, Any]] = []
        self.evidence_path = evidence_path

    def record(self, item: dict[str, Any]) -> None:
        with self.lock:
            self.attempts.append(item)
            with self.evidence_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(item, sort_keys=True) + "\n")

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return {"withheld_receivers": sorted(self.withheld), "attempts": list(self.attempts)}


def make_handler(state: State) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "RevPropE-B22Relay/1.0"

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
                if receiver not in {"receiver-a", "receiver-b"}:
                    self.send_json(404, {"error": "unknown_receiver"})
                    return
                with state.lock:
                    if action == "withhold":
                        state.withheld.add(receiver)
                    elif action == "forward":
                        state.withheld.discard(receiver)
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
                withheld = receiver in state.withheld
            item = {
                "observed_unix_ns": time.time_ns(),
                "receiver": receiver,
                "withheld": withheld,
                "forwarded": not withheld,
                "http_response": 202,
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
            state.record(item)
            self.send_json(202, {"accepted": True, "forwarded": not withheld})

    return Handler


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=19002)
    parser.add_argument("--evidence-jsonl", type=Path, required=True)
    args = parser.parse_args()
    args.evidence_jsonl.parent.mkdir(parents=True, exist_ok=True)
    args.evidence_jsonl.write_text("", encoding="utf-8")
    state = State(args.evidence_jsonl)
    ThreadingHTTPServer((args.host, args.port), make_handler(state)).serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

