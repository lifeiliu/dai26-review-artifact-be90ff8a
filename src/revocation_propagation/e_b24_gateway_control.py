"""Authenticated receiver-to-gateway control boundary for E-B24."""

from __future__ import annotations

import hmac
import json
import ssl
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Mapping

from .real_effect_gate import PersistentEffectGateway, canonical_json


MAX_REQUEST_BYTES = 262_144


def build_gateway_control_server(
    *,
    host: str,
    port: int,
    gateway: PersistentEffectGateway,
    bearer_token: str,
    tls_cert: str | None = None,
    tls_key: str | None = None,
) -> ThreadingHTTPServer:
    token = bearer_token.encode("utf-8")

    class Handler(BaseHTTPRequestHandler):
        server_version = "E-B24GatewayControl/1.0"

        def log_message(self, fmt: str, *args: object) -> None:
            return

        def _send(self, status: int, body: Mapping[str, object]) -> None:
            encoded = (canonical_json(dict(body)) + "\n").encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def _authorized(self) -> bool:
            supplied = self.headers.get("Authorization", "").encode("utf-8")
            return hmac.compare_digest(supplied, b"Bearer " + token)

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/health":
                self._send(200, {"status": "ok", "gateway_id": gateway.gateway_id})
                return
            self._send(404, {"error": "not_found"})

        def do_POST(self) -> None:  # noqa: N802
            if not self._authorized():
                self._send(401, {"error": "unauthorized"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length <= 0 or length > MAX_REQUEST_BYTES:
                    raise ValueError("invalid gateway control request size")
                body = json.loads(self.rfile.read(length))
                if not isinstance(body, dict):
                    raise ValueError("gateway control request must be an object")
                if self.path == "/v1/revocations":
                    result = gateway.apply_revocation(
                        delegation_id=str(body["delegation_id"]),
                        event_id=str(body["event_id"]),
                        channel=str(body["channel"]),
                        sequence=int(body["sequence"]),
                    )
                elif self.path == "/v1/status":
                    result = gateway.status(str(body["delegation_id"]))
                else:
                    self._send(404, {"error": "not_found"})
                    return
                self._send(200, result)
            except (KeyError, ValueError, json.JSONDecodeError) as error:
                self._send(400, {"error": type(error).__name__, "detail": str(error)})
            except Exception as error:  # pragma: no cover - operational boundary
                self._send(500, {"error": type(error).__name__, "detail": str(error)})

    server = ThreadingHTTPServer((host, port), Handler)
    if tls_cert or tls_key:
        if not tls_cert or not tls_key:
            raise ValueError("both TLS certificate and key are required")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(tls_cert, tls_key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    return server


class GatewayControlClient:
    def __init__(
        self,
        *,
        base_url: str,
        bearer_token: str,
        ca_file: str | None = None,
        timeout: float = 10.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.bearer_token = bearer_token
        self.timeout = timeout
        self.ssl_context = ssl.create_default_context(cafile=ca_file) if ca_file else None

    def _post(self, path: str, body: Mapping[str, object]) -> dict[str, object]:
        request = urllib.request.Request(
            f"{self.base_url}{path}",
            data=(canonical_json(dict(body)) + "\n").encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.bearer_token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(
                request,
                timeout=self.timeout,
                context=self.ssl_context,
            ) as response:
                parsed = json.loads(response.read())
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"gateway control returned {error.code}: {detail}") from error
        if not isinstance(parsed, dict):
            raise RuntimeError("gateway control returned a non-object response")
        return parsed

    def apply_revocation(self, payload: Mapping[str, object]) -> dict[str, object]:
        return self._post("/v1/revocations", payload)

    def status(self, delegation_id: str) -> dict[str, object]:
        return self._post("/v1/status", {"delegation_id": delegation_id})
