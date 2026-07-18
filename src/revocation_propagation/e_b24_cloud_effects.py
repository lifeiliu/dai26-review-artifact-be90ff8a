"""Network effect boundary for the E-B24 multi-host qualification.

The existing E-B24 local gate deliberately uses a Docker-local PostgreSQL
adapter.  This module adds a separate network boundary without changing that
qualification path: gateways call this service over HTTP(S), while the service
is the only process allowed to commit Filesystem or PostgreSQL effects.
"""

from __future__ import annotations

import argparse
import hmac
import json
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping

from .keycloak_gateway_gate import ReplayVector
from .real_effect_gate import (
    EffectPlan,
    FilesystemEffectStore,
    canonical_json,
    load_vector_allowlist,
    parse_replay_vector,
    sha256_text,
)


MAX_REQUEST_BYTES = 1_048_576


class PostgresNetworkEffectStore:
    """PostgreSQL effect store reached through Psycopg/libpq over TCP.

    The formal deployment mounts a root-readable password file and passes its
    content directly to libpq. SQL values remain parameterized and credentials
    are never placed on a command line or process environment.
    """

    def __init__(
        self,
        *,
        host: str,
        port: int,
        database: str,
        user: str,
        password: str,
        sslmode: str = "require",
        connect: Any | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.database = database
        self.user = user
        self.password = password
        self.sslmode = sslmode
        if connect is None:
            from psycopg import connect as psycopg_connect

            connect = psycopg_connect
        self.connect = connect

    def _connection(self) -> Any:
        return self.connect(
            host=self.host,
            port=self.port,
            dbname=self.database,
            user=self.user,
            password=self.password,
            sslmode=self.sslmode,
            connect_timeout=15,
            autocommit=True,
        )

    def ensure_schema(self) -> None:
        with self._connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS effect_commits (
                        experiment_run TEXT NOT NULL,
                        arm TEXT NOT NULL,
                        vector_id TEXT NOT NULL,
                        gateway_id TEXT NOT NULL,
                        delegation_id TEXT NOT NULL,
                        payload_sha256 TEXT NOT NULL,
                        payload_json JSONB NOT NULL,
                        committed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
                        PRIMARY KEY (experiment_run, arm, vector_id)
                    );
                    """
                )

    def commit(
        self,
        plan: EffectPlan,
        *,
        experiment_run: str,
        arm: str,
        delegation_id: str,
    ) -> dict[str, object]:
        record = plan.record(
            experiment_run=experiment_run,
            arm=arm,
            delegation_id=delegation_id,
        )
        payload = canonical_json(record)
        payload_sha256 = sha256_text(payload)
        with self._connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO effect_commits
                    (experiment_run, arm, vector_id, gateway_id, delegation_id,
                     payload_sha256, payload_json)
                    VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb)
                    ON CONFLICT (experiment_run, arm, vector_id) DO NOTHING
                    RETURNING vector_id;
                    """,
                    (
                        experiment_run,
                        arm,
                        plan.vector_id,
                        plan.gateway_id,
                        delegation_id,
                        payload_sha256,
                        payload,
                    ),
                )
                row = cursor.fetchone()
        committed = bool(row and row[0] == plan.vector_id)
        return {
            "committed": committed,
            "effect_type": "postgres",
            "vector_id": plan.vector_id,
            "payload_sha256": payload_sha256,
            "committed_at_ns": time.time_ns(),
        }

    def oracle(self, *, experiment_run: str, arm: str) -> dict[str, object]:
        with self._connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT vector_id, payload_sha256
                    FROM effect_commits
                    WHERE experiment_run = %s AND arm = %s
                    ORDER BY vector_id;
                    """,
                    (experiment_run, arm),
                )
                rows = cursor.fetchall()
        records = [
            {"vector_id": str(vector_id), "payload_sha256": str(payload_sha256)}
            for vector_id, payload_sha256 in rows
        ]
        return {
            "effect_type": "postgres",
            "count": len(records),
            "vector_ids": [item["vector_id"] for item in records],
            "digest_sha256": sha256_text(canonical_json(records)),
        }


class EffectBoundary:
    """Validates the frozen vector again at the authoritative effect host."""

    def __init__(
        self,
        *,
        allowlist: Mapping[str, ReplayVector],
        filesystem_store: Any | None,
        postgres_store: Any | None,
    ) -> None:
        self.allowlist = dict(allowlist)
        self.stores = {
            "filesystem": filesystem_store,
            "postgres": postgres_store,
        }

    def _plan(self, payload: str | Mapping[str, object]) -> EffectPlan:
        vector = parse_replay_vector(payload)
        expected = self.allowlist.get(vector.vector_id)
        if expected is None or vector != expected:
            raise ValueError("vector is not an exact member of the frozen E-B24 allowlist")
        if self.stores.get(vector.service) is None:
            raise ValueError(f"effect service is disabled for {vector.service}")
        return EffectPlan.from_vector(vector)

    def commit(self, request: Mapping[str, object]) -> dict[str, object]:
        vector_payload = request.get("vector")
        if not isinstance(vector_payload, Mapping):
            raise ValueError("effect request is missing a vector object")
        plan = self._plan(vector_payload)
        experiment_run = str(request.get("experiment_run", ""))
        arm = str(request.get("arm", ""))
        delegation_id = str(request.get("delegation_id", ""))
        if not experiment_run or not arm or not delegation_id:
            raise ValueError("effect request is missing run, arm, or delegation identity")
        return self.stores[plan.service].commit(
            plan,
            experiment_run=experiment_run,
            arm=arm,
            delegation_id=delegation_id,
        )

    def oracle(self, request: Mapping[str, object]) -> dict[str, object]:
        service = str(request.get("service", ""))
        experiment_run = str(request.get("experiment_run", ""))
        arm = str(request.get("arm", ""))
        store = self.stores.get(service)
        if store is None:
            raise ValueError(f"effect service is disabled for {service}")
        if not experiment_run or not arm:
            raise ValueError("oracle request is missing run or arm")
        return store.oracle(experiment_run=experiment_run, arm=arm)


def build_effect_http_server(
    *,
    host: str,
    port: int,
    boundary: EffectBoundary,
    bearer_token: str,
    tls_cert: str | None = None,
    tls_key: str | None = None,
) -> ThreadingHTTPServer:
    token = bearer_token.encode("utf-8")

    class Handler(BaseHTTPRequestHandler):
        server_version = "E-B24EffectBoundary/1.0"

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
            supplied = self.headers.get("Authorization", "")
            expected = b"Bearer " + token
            return hmac.compare_digest(supplied.encode("utf-8"), expected)

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/health":
                self._send(200, {"status": "ok"})
                return
            self._send(404, {"error": "not_found"})

        def do_POST(self) -> None:  # noqa: N802
            if not self._authorized():
                self._send(401, {"error": "unauthorized"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length <= 0 or length > MAX_REQUEST_BYTES:
                    raise ValueError("invalid effect request size")
                body = json.loads(self.rfile.read(length))
                if not isinstance(body, dict):
                    raise ValueError("effect request must be a JSON object")
                if self.path == "/v1/commit":
                    result = boundary.commit(body)
                elif self.path == "/v1/oracle":
                    result = boundary.oracle(body)
                else:
                    self._send(404, {"error": "not_found"})
                    return
                self._send(200, result)
            except (ValueError, KeyError, json.JSONDecodeError) as error:
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


class RemoteEffectStore:
    """Synchronous adapter used by the persistent MCP gateway."""

    def __init__(
        self,
        *,
        service: str,
        base_url: str,
        bearer_token: str,
        ca_file: str | None = None,
        timeout: float = 15.0,
    ) -> None:
        if service not in {"filesystem", "postgres"}:
            raise ValueError(f"unsupported remote effect service: {service}")
        self.service = service
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
            raise RuntimeError(f"remote effect boundary returned {error.code}: {detail}") from error
        if not isinstance(parsed, dict):
            raise RuntimeError("remote effect boundary returned a non-object response")
        return parsed

    def commit(
        self,
        plan: EffectPlan,
        *,
        experiment_run: str,
        arm: str,
        delegation_id: str,
    ) -> dict[str, object]:
        if plan.service != self.service:
            raise ValueError(
                f"remote {self.service} store received a {plan.service} vector"
            )
        return self._post(
            "/v1/commit",
            {
                "experiment_run": experiment_run,
                "arm": arm,
                "delegation_id": delegation_id,
                "vector": asdict(plan),
            },
        )

    def oracle(self, *, experiment_run: str, arm: str) -> dict[str, object]:
        return self._post(
            "/v1/oracle",
            {
                "service": self.service,
                "experiment_run": experiment_run,
                "arm": arm,
            },
        )


def _secret(path: str) -> str:
    value = Path(path).read_text(encoding="utf-8").strip()
    if not value:
        raise ValueError(f"empty secret file: {path}")
    return value


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the E-B24 remote effect boundary.")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--vector-allowlist", required=True)
    parser.add_argument("--bearer-token-file", required=True)
    parser.add_argument("--tls-cert", required=True)
    parser.add_argument("--tls-key", required=True)
    parser.add_argument("--service", choices=("filesystem", "postgres", "both"), required=True)
    parser.add_argument("--filesystem-root")
    parser.add_argument("--postgres-host")
    parser.add_argument("--postgres-port", type=int, default=5432)
    parser.add_argument("--postgres-database")
    parser.add_argument("--postgres-user")
    parser.add_argument("--postgres-password-file")
    parser.add_argument("--postgres-sslmode", default="require")
    args = parser.parse_args()

    filesystem = None
    postgres = None
    if args.service in {"filesystem", "both"}:
        if not args.filesystem_root:
            parser.error("--filesystem-root is required for filesystem effects")
        filesystem = FilesystemEffectStore(args.filesystem_root)
    if args.service in {"postgres", "both"}:
        required = {
            "--postgres-host": args.postgres_host,
            "--postgres-database": args.postgres_database,
            "--postgres-user": args.postgres_user,
            "--postgres-password-file": args.postgres_password_file,
        }
        missing = [name for name, value in required.items() if not value]
        if missing:
            parser.error(f"missing PostgreSQL arguments: {', '.join(missing)}")
        postgres = PostgresNetworkEffectStore(
            host=args.postgres_host,
            port=args.postgres_port,
            database=args.postgres_database,
            user=args.postgres_user,
            password=_secret(args.postgres_password_file),
            sslmode=args.postgres_sslmode,
        )
        postgres.ensure_schema()

    boundary = EffectBoundary(
        allowlist=load_vector_allowlist(args.vector_allowlist),
        filesystem_store=filesystem,
        postgres_store=postgres,
    )
    server = build_effect_http_server(
        host=args.host,
        port=args.port,
        boundary=boundary,
        bearer_token=_secret(args.bearer_token_file),
        tls_cert=args.tls_cert,
        tls_key=args.tls_key,
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
