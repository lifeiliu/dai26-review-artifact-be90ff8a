import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote

from revocation_propagation.keycloak_gateway_gate import ReplayVector
from revocation_propagation.opa_policy_gate import OpaHttpClient, OpaPolicyGateway
from revocation_propagation.real_effect_gate import FilesystemEffectStore


def _fake_opa():
    state = {"gateway_id": "g-filesystem", "revocations": {}}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            return

        def _json(self, status, body):
            encoded = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def do_GET(self):
            if self.path == "/health":
                self._json(200, {})
                return
            prefix = "/v1/data/revocation/revocations/"
            if self.path.startswith(prefix):
                key = unquote(self.path[len(prefix):])
                value = state["revocations"].get(key)
                self._json(200, {} if value is None else {"result": value})
                return
            self._json(404, {})

        def do_PUT(self):
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length)
            if self.path == "/v1/data/revocation":
                state.update(json.loads(body))
            elif self.path.startswith("/v1/data/revocation/revocations/"):
                key = unquote(self.path.rsplit("/", 1)[1])
                state["revocations"][key] = json.loads(body)
            self._json(200, {})

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(length))
            supplied = body["input"]
            allowed = (
                supplied["gateway_id"] == state["gateway_id"]
                and supplied["delegation_id"] not in state["revocations"]
            )
            self._json(200, {"result": allowed})

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def test_opa_client_and_gateway_use_policy_decision_for_real_effect(tmp_path: Path) -> None:
    server, thread = _fake_opa()
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}"
        client = OpaHttpClient(url)
        assert client.health()
        client.initialize_gateway("g-filesystem")
        vector = ReplayVector(
            service="filesystem",
            gateway_id="g-filesystem",
            run=3,
            call_sequence=1,
            tool_name="write_file",
            arguments_sha256="a" * 64,
        )
        gateway = OpaPolicyGateway(
            gateway_id="g-filesystem",
            update_url=url,
            decision_url=url,
            allowlist={vector.vector_id: vector},
            filesystem_store=FilesystemEffectStore(tmp_path / "effects"),
            postgres_store=None,
        )
        before = gateway.execute_effect(
            delegation_id="d/1",
            experiment_run="before",
            arm="test",
            vector_payload=vector.payload(),
        )
        assert before["allowed"] is True
        assert before["effect"]["committed"] is True

        receipt = gateway.apply_revocation(
            delegation_id="d/1",
            event_id="e1",
            channel="test",
            sequence=1,
        )
        after = gateway.execute_effect(
            delegation_id="d/1",
            experiment_run="after",
            arm="test",
            vector_payload=vector.payload(),
        )
        assert receipt["applied"] is True
        assert after["allowed"] is False
        assert after["effect"] is None
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
