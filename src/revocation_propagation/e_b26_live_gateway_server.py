"""Networked MCP gateway with OPA decisions and real E-B26 effects."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from .opa_policy_gate import OpaHttpClient
from .real_effect_gate import canonical_json, sha256_text


def _sql_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def build_server(
    *,
    service: str,
    gateway_id: str,
    opa_url: str,
    experiment_arm: str,
    host: str,
    port: int,
    filesystem_root: str | None = None,
    postgres_container: str | None = None,
    postgres_database: str | None = None,
    postgres_user: str | None = None,
    postgres_password: str | None = None,
) -> FastMCP:
    if service not in {"filesystem", "postgres"}:
        raise ValueError("service must be filesystem or postgres")
    opa = OpaHttpClient(opa_url)
    root = Path(filesystem_root).resolve() if filesystem_root else None
    if root is not None:
        root.mkdir(parents=True, exist_ok=True)

    server = FastMCP(
        f"e-b26-{service}-{gateway_id}",
        instructions="OPA-enforced real-effect gateway for the frozen E-B26 agent trace.",
        host=host,
        port=port,
        streamable_http_path="/mcp",
        json_response=True,
        stateless_http=False,
        log_level="WARNING",
    )

    def decision(delegation_id: str, action_id: str) -> tuple[bool, str, int]:
        decided_at_ns = time.time_ns()
        allowed, response = opa.allowed(
            gateway_id=gateway_id, delegation_id=delegation_id
        )
        decision_id = sha256_text(
            canonical_json(
                {
                    "gateway_id": gateway_id,
                    "delegation_id": delegation_id,
                    "action_id": action_id,
                    "allowed": allowed,
                    "opa_response": response,
                    "decided_at_ns": decided_at_ns,
                }
            )
        )
        return allowed, decision_id, decided_at_ns

    @server.tool()
    def write_file_effect(
        delegation_id: str,
        agent_id: str,
        relative_path: str,
        content: str,
        action_id: str,
    ) -> dict[str, object]:
        """Write one guarded file when OPA authorizes the delegation."""

        if service != "filesystem" or root is None:
            raise ValueError("write_file_effect is not available at this gateway")
        destination = (root / relative_path).resolve()
        if root != destination and root not in destination.parents:
            raise ValueError("relative_path escapes the E-B26 sandbox")
        allowed, decision_id, decided_at_ns = decision(delegation_id, action_id)
        committed = False
        if allowed:
            destination.parent.mkdir(parents=True, exist_ok=True)
            body = (content + "\n").encode("utf-8")
            temporary = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
            with temporary.open("wb") as handle:
                handle.write(body)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, destination)
            directory_fd = os.open(destination.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            committed = destination.read_bytes() == body
        return {
            "allowed": allowed,
            "effect_committed": committed,
            "effect_type": "filesystem",
            "gateway_id": gateway_id,
            "delegation_id": delegation_id,
            "agent_id": agent_id,
            "action_id": action_id,
            "decision_id": decision_id,
            "decided_at_ns": decided_at_ns,
            "path": str(destination),
        }

    @server.tool()
    def insert_postgres_effect(
        delegation_id: str,
        agent_id: str,
        record_key: str,
        payload: str,
        action_id: str,
    ) -> dict[str, object]:
        """Insert one guarded PostgreSQL row when OPA authorizes the delegation."""

        required = (
            postgres_container,
            postgres_database,
            postgres_user,
            postgres_password,
        )
        if service != "postgres" or not all(required):
            raise ValueError("insert_postgres_effect is not available at this gateway")
        allowed, decision_id, decided_at_ns = decision(delegation_id, action_id)
        committed = False
        if allowed:
            sql = (
                "INSERT INTO e_b26_agent_effects "
                "(experiment_arm, record_key, action_id, agent_id, payload) VALUES ("
                f"{_sql_literal(experiment_arm)}, {_sql_literal(record_key)}, "
                f"{_sql_literal(action_id)}, {_sql_literal(agent_id)}, {_sql_literal(payload)}) "
                "ON CONFLICT (experiment_arm, record_key) DO NOTHING RETURNING record_key;"
            )
            completed = subprocess.run(
                [
                    "docker", "exec", "-e", f"PGPASSWORD={postgres_password}",
                    str(postgres_container), "psql", "--no-psqlrc", "--quiet",
                    "--tuples-only", "--no-align", "--set", "ON_ERROR_STOP=1",
                    "--username", str(postgres_user), "--dbname", str(postgres_database),
                    "--command", sql,
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            committed = record_key in completed.stdout.splitlines()
        return {
            "allowed": allowed,
            "effect_committed": committed,
            "effect_type": "postgres",
            "gateway_id": gateway_id,
            "delegation_id": delegation_id,
            "agent_id": agent_id,
            "action_id": action_id,
            "decision_id": decision_id,
            "decided_at_ns": decided_at_ns,
            "record_key": record_key,
        }

    return server


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--service", choices=("filesystem", "postgres"), required=True)
    parser.add_argument("--gateway-id", required=True)
    parser.add_argument("--opa-url", required=True)
    parser.add_argument("--experiment-arm", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--filesystem-root")
    parser.add_argument("--postgres-container")
    parser.add_argument("--postgres-database")
    parser.add_argument("--postgres-user")
    parser.add_argument("--postgres-password")
    args = parser.parse_args()
    build_server(**vars(args)).run("streamable-http")


if __name__ == "__main__":
    main()
