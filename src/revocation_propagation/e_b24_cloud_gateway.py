"""Cloud entry point for an E-B24 MCP gateway plus HTTPS control plane."""

from __future__ import annotations

import argparse
import threading
from pathlib import Path

from .e_b24_cloud_effects import RemoteEffectStore
from .e_b24_gateway_control import build_gateway_control_server
from .real_effect_gate import PersistentEffectGateway, load_vector_allowlist
from .real_effect_gateway_server import _mcp_server


def _secret(path: str) -> str:
    value = Path(path).read_text(encoding="utf-8").strip()
    if not value:
        raise ValueError(f"empty secret file: {path}")
    return value


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run an E-B24 MCP gateway with a separate HTTPS receiver handoff API."
    )
    parser.add_argument("--gateway-id", required=True)
    parser.add_argument("--mcp-host", default="0.0.0.0")
    parser.add_argument("--mcp-port", type=int, required=True)
    parser.add_argument("--control-host", default="0.0.0.0")
    parser.add_argument("--control-port", type=int, required=True)
    parser.add_argument("--control-tls-cert", required=True)
    parser.add_argument("--control-tls-key", required=True)
    parser.add_argument("--control-bearer-token-file", required=True)
    parser.add_argument("--state-db", required=True)
    parser.add_argument("--vector-allowlist", required=True)
    parser.add_argument("--filesystem-effect-url", required=True)
    parser.add_argument("--postgres-effect-url", required=True)
    parser.add_argument("--effect-ca-file", required=True)
    parser.add_argument("--effect-bearer-token-file", required=True)
    args = parser.parse_args()

    effect_token = _secret(args.effect_bearer_token_file)
    gateway = PersistentEffectGateway(
        gateway_id=args.gateway_id,
        state_db=args.state_db,
        allowlist=load_vector_allowlist(args.vector_allowlist),
        filesystem_store=RemoteEffectStore(
            service="filesystem",
            base_url=args.filesystem_effect_url,
            bearer_token=effect_token,
            ca_file=args.effect_ca_file,
        ),
        postgres_store=RemoteEffectStore(
            service="postgres",
            base_url=args.postgres_effect_url,
            bearer_token=effect_token,
            ca_file=args.effect_ca_file,
        ),
    )
    control = build_gateway_control_server(
        host=args.control_host,
        port=args.control_port,
        gateway=gateway,
        bearer_token=_secret(args.control_bearer_token_file),
        tls_cert=args.control_tls_cert,
        tls_key=args.control_tls_key,
    )
    control_thread = threading.Thread(
        target=control.serve_forever,
        name="e-b24-gateway-control",
        daemon=True,
    )
    control_thread.start()
    try:
        _mcp_server(
            gateway=gateway,
            gateway_id=args.gateway_id,
            host=args.mcp_host,
            port=args.mcp_port,
        ).run("streamable-http")
    finally:
        control.shutdown()
        control.server_close()
        control_thread.join(timeout=5)


if __name__ == "__main__":
    main()
