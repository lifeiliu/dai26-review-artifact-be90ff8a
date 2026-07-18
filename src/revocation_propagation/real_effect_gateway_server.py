"""Process-isolated MCP gateway that commits E-B24 Filesystem/PostgreSQL effects."""

from __future__ import annotations

import argparse
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from .e_b24_cloud_effects import RemoteEffectStore
from .real_effect_gate import (
    FilesystemEffectStore,
    PersistentEffectGateway,
    PostgresDockerEffectStore,
    load_vector_allowlist,
)


def build_server(
    *,
    gateway_id: str,
    host: str,
    port: int,
    state_db: str,
    filesystem_root: str,
    vector_allowlist: str,
    postgres_container: str,
    postgres_database: str,
    postgres_user: str,
    postgres_password: str,
) -> FastMCP:
    postgres = PostgresDockerEffectStore(
        container=postgres_container,
        database=postgres_database,
        user=postgres_user,
        password=postgres_password,
    )
    postgres.ensure_schema()
    gateway = PersistentEffectGateway(
        gateway_id=gateway_id,
        state_db=state_db,
        allowlist=load_vector_allowlist(vector_allowlist),
        filesystem_store=FilesystemEffectStore(filesystem_root),
        postgres_store=postgres,
    )
    return _mcp_server(
        gateway=gateway,
        gateway_id=gateway_id,
        host=host,
        port=port,
    )


def build_remote_server(
    *,
    gateway_id: str,
    host: str,
    port: int,
    state_db: str,
    vector_allowlist: str,
    filesystem_effect_url: str,
    postgres_effect_url: str,
    effect_bearer_token: str,
    effect_ca_file: str | None,
) -> FastMCP:
    gateway = PersistentEffectGateway(
        gateway_id=gateway_id,
        state_db=state_db,
        allowlist=load_vector_allowlist(vector_allowlist),
        filesystem_store=RemoteEffectStore(
            service="filesystem",
            base_url=filesystem_effect_url,
            bearer_token=effect_bearer_token,
            ca_file=effect_ca_file,
        ),
        postgres_store=RemoteEffectStore(
            service="postgres",
            base_url=postgres_effect_url,
            bearer_token=effect_bearer_token,
            ca_file=effect_ca_file,
        ),
    )
    return _mcp_server(
        gateway=gateway,
        gateway_id=gateway_id,
        host=host,
        port=port,
    )


def _mcp_server(
    *,
    gateway: PersistentEffectGateway,
    gateway_id: str,
    host: str,
    port: int,
) -> FastMCP:
    server = FastMCP(
        f"e-b24-{gateway_id}",
        instructions="Persistent revocation gateway with reversible real-effect oracles.",
        host=host,
        port=port,
        streamable_http_path="/mcp",
        json_response=True,
        stateless_http=False,
        log_level="WARNING",
    )

    @server.tool()
    def execute_effect(
        delegation_id: str,
        experiment_run: str,
        arm: str,
        vector_payload: str,
    ) -> dict[str, object]:
        return gateway.execute_effect(
            delegation_id=delegation_id,
            experiment_run=experiment_run,
            arm=arm,
            vector_payload=vector_payload,
        )

    @server.tool()
    def apply_revocation(
        delegation_id: str,
        event_id: str,
        channel: str,
        sequence: int,
    ) -> dict[str, object]:
        return gateway.apply_revocation(
            delegation_id=delegation_id,
            event_id=event_id,
            channel=channel,
            sequence=sequence,
        )

    @server.tool()
    def gateway_status(delegation_id: str) -> dict[str, object]:
        return gateway.status(delegation_id)

    return server


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the E-B24 real-effect MCP gateway.")
    parser.add_argument("--gateway-id", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--state-db", required=True)
    parser.add_argument("--filesystem-root")
    parser.add_argument("--vector-allowlist", required=True)
    parser.add_argument("--postgres-container")
    parser.add_argument("--postgres-database")
    parser.add_argument("--postgres-user")
    parser.add_argument("--postgres-password")
    parser.add_argument("--filesystem-effect-url")
    parser.add_argument("--postgres-effect-url")
    parser.add_argument("--effect-bearer-token-file")
    parser.add_argument("--effect-ca-file")
    args = parser.parse_args()
    remote = any((args.filesystem_effect_url, args.postgres_effect_url))
    if remote:
        required = {
            "--filesystem-effect-url": args.filesystem_effect_url,
            "--postgres-effect-url": args.postgres_effect_url,
            "--effect-bearer-token-file": args.effect_bearer_token_file,
        }
        missing = [name for name, value in required.items() if not value]
        if missing:
            parser.error(f"missing remote effect arguments: {', '.join(missing)}")
        effect_bearer_token = Path(args.effect_bearer_token_file).read_text(
            encoding="utf-8"
        ).strip()
        if not effect_bearer_token:
            parser.error("effect bearer token file is empty")
        server = build_remote_server(
            gateway_id=args.gateway_id,
            host=args.host,
            port=args.port,
            state_db=args.state_db,
            vector_allowlist=args.vector_allowlist,
            filesystem_effect_url=args.filesystem_effect_url,
            postgres_effect_url=args.postgres_effect_url,
            effect_bearer_token=effect_bearer_token,
            effect_ca_file=args.effect_ca_file,
        )
    else:
        required = {
            "--filesystem-root": args.filesystem_root,
            "--postgres-container": args.postgres_container,
            "--postgres-database": args.postgres_database,
            "--postgres-user": args.postgres_user,
            "--postgres-password": args.postgres_password,
        }
        missing = [name for name, value in required.items() if not value]
        if missing:
            parser.error(f"missing local effect arguments: {', '.join(missing)}")
        server = build_server(
            gateway_id=args.gateway_id,
            host=args.host,
            port=args.port,
            state_db=args.state_db,
            filesystem_root=args.filesystem_root,
            vector_allowlist=args.vector_allowlist,
            postgres_container=args.postgres_container,
            postgres_database=args.postgres_database,
            postgres_user=args.postgres_user,
            postgres_password=args.postgres_password,
        )
    server.run("streamable-http")


if __name__ == "__main__":
    main()
