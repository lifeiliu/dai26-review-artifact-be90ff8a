"""Independent-process MCP gateway used by the preregistered E-B18 path."""

from __future__ import annotations

import argparse
import os
import threading
import time

from mcp.server.fastmcp import FastMCP


def build_server(*, gateway_id: str, host: str, port: int) -> FastMCP:
    server = FastMCP(
        f"revprop-{gateway_id}",
        instructions="Revocation-enforcing agent tool gateway for E-B18.",
        host=host,
        port=port,
        streamable_http_path="/mcp",
        json_response=True,
        stateless_http=False,
        log_level="WARNING",
    )
    revoked: dict[str, dict[str, object]] = {}
    lock = threading.Lock()
    calls = {"allowed": 0, "denied": 0, "control": 0}

    @server.tool()
    def repo_write(delegation_id: str, agent_id: str, payload: str) -> dict[str, object]:
        """Attempt a guarded repository write without mutating the filesystem."""

        started = time.perf_counter_ns()
        with lock:
            record = revoked.get(delegation_id)
            allowed = record is None
            calls["allowed" if allowed else "denied"] += 1
        return {
            "allowed": allowed,
            "agent_id": agent_id,
            "delegation_id": delegation_id,
            "gateway_id": gateway_id,
            "payload_hash_input_length": len(payload.encode()),
            "reason": "active-delegation" if allowed else "revoked-delegation",
            "learned_via": None if record is None else record["channel"],
            "event_id": None if record is None else record["event_id"],
            "server_pid": os.getpid(),
            "server_processing_ms": (time.perf_counter_ns() - started) / 1_000_000.0,
        }

    @server.tool()
    def apply_revocation(delegation_id: str, event_id: str, channel: str) -> dict[str, object]:
        """Apply the same revocation record through a disclosed delivery channel."""

        if channel not in {"direct-push", "log-repair", "keycloak-poll"}:
            raise ValueError("channel must be direct-push, log-repair, or keycloak-poll")
        with lock:
            revoked[delegation_id] = {
                "event_id": event_id,
                "channel": channel,
                "learned_at_ns": time.monotonic_ns(),
            }
            calls["control"] += 1
        return {
            "applied": True,
            "delegation_id": delegation_id,
            "event_id": event_id,
            "gateway_id": gateway_id,
            "learned_via": channel,
            "server_pid": os.getpid(),
        }

    @server.tool()
    def gateway_status(delegation_id: str) -> dict[str, object]:
        """Return local revocation state and call counters for replay checking."""

        with lock:
            record = revoked.get(delegation_id)
            snapshot = dict(calls)
        return {
            "gateway_id": gateway_id,
            "delegation_id": delegation_id,
            "revoked": record is not None,
            "event_id": None if record is None else record["event_id"],
            "learned_via": None if record is None else record["channel"],
            "calls": snapshot,
            "server_pid": os.getpid(),
        }

    return server


def main() -> None:
    parser = argparse.ArgumentParser(description="Run one E-B18 MCP gateway process.")
    parser.add_argument("--gateway-id", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", required=True, type=int)
    args = parser.parse_args()
    build_server(gateway_id=args.gateway_id, host=args.host, port=args.port).run("streamable-http")


if __name__ == "__main__":
    main()
