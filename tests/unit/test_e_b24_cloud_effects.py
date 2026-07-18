import threading
from pathlib import Path

import pytest

from revocation_propagation.e_b24_cloud_effects import (
    EffectBoundary,
    PostgresNetworkEffectStore,
    RemoteEffectStore,
    build_effect_http_server,
)
from revocation_propagation.keycloak_gateway_gate import ReplayVector
from revocation_propagation.real_effect_gate import (
    EffectPlan,
    FilesystemEffectStore,
    PersistentEffectGateway,
)


class MemoryPostgresStore:
    def __init__(self) -> None:
        self.records: dict[tuple[str, str, str], dict[str, object]] = {}

    def commit(self, plan, *, experiment_run, arm, delegation_id):
        key = (experiment_run, arm, plan.vector_id)
        self.records[key] = plan.record(
            experiment_run=experiment_run,
            arm=arm,
            delegation_id=delegation_id,
        )
        return {
            "committed": True,
            "effect_type": "postgres",
            "vector_id": plan.vector_id,
        }

    def oracle(self, *, experiment_run, arm):
        vector_ids = sorted(
            vector_id
            for run, record_arm, vector_id in self.records
            if run == experiment_run and record_arm == arm
        )
        return {
            "effect_type": "postgres",
            "count": len(vector_ids),
            "vector_ids": vector_ids,
            "digest_sha256": "memory-test",
        }


class FakePostgresCursor:
    def __init__(self, connector) -> None:
        self.connector = connector
        self.one = None

    def __enter__(self):
        return self

    def __exit__(self, *_args) -> None:
        return None

    def execute(self, sql, parameters=None) -> None:
        self.connector.statements.append((sql, parameters))
        if "RETURNING vector_id" in sql:
            self.one = (parameters[2],)

    def fetchone(self):
        return self.one

    def fetchall(self):
        return list(self.connector.oracle_rows)


class FakePostgresConnection:
    def __init__(self, connector) -> None:
        self.connector = connector

    def __enter__(self):
        return self

    def __exit__(self, *_args) -> None:
        return None

    def cursor(self):
        return FakePostgresCursor(self.connector)


class FakePostgresConnect:
    def __init__(self) -> None:
        self.calls = []
        self.statements = []
        self.oracle_rows = [("vector-a", "hash-a"), ("vector-b", "hash-b")]

    def __call__(self, **kwargs):
        self.calls.append(kwargs)
        return FakePostgresConnection(self)


def test_postgres_network_store_uses_parameterized_psycopg_connection() -> None:
    connector = FakePostgresConnect()
    store = PostgresNetworkEffectStore(
        host="postgres.internal",
        port=5432,
        database="effects",
        user="effect-writer",
        password="not-on-a-command-line",
        sslmode="verify-full",
        connect=connector,
    )
    vector = ReplayVector(
        "postgres",
        "postgres/task",
        4,
        2,
        "execute_sql",
        "b" * 64,
    )

    store.ensure_schema()
    committed = store.commit(
        EffectPlan.from_vector(vector),
        experiment_run="run-with-'quote",
        arm="healthy",
        delegation_id="delegation-1",
    )
    oracle = store.oracle(experiment_run="run-with-'quote", arm="healthy")

    assert committed["committed"] is True
    assert oracle["vector_ids"] == ["vector-a", "vector-b"]
    assert all(call["password"] == "not-on-a-command-line" for call in connector.calls)
    insert = next(item for item in connector.statements if "INSERT INTO" in item[0])
    assert "%s" in insert[0]
    assert "run-with-'quote" not in insert[0]
    assert insert[1][0] == "run-with-'quote"

@pytest.fixture()
def remote_boundary(tmp_path: Path):
    fs = ReplayVector("filesystem", "filesystem/task", 3, 1, "write", "a" * 64)
    pg = ReplayVector("postgres", "postgres/task", 4, 2, "execute_sql", "b" * 64)
    boundary = EffectBoundary(
        allowlist={vector.vector_id: vector for vector in (fs, pg)},
        filesystem_store=FilesystemEffectStore(tmp_path / "effects"),
        postgres_store=MemoryPostgresStore(),
    )
    server = build_effect_http_server(
        host="127.0.0.1",
        port=0,
        boundary=boundary,
        bearer_token="test-boundary-token",
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, fs, pg
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_remote_effect_boundary_commits_and_reports_oracles(remote_boundary) -> None:
    server, fs, pg = remote_boundary
    base_url = f"http://127.0.0.1:{server.server_address[1]}"
    filesystem = RemoteEffectStore(
        service="filesystem",
        base_url=base_url,
        bearer_token="test-boundary-token",
    )
    postgres = RemoteEffectStore(
        service="postgres",
        base_url=base_url,
        bearer_token="test-boundary-token",
    )

    fs_result = filesystem.commit(
        EffectPlan.from_vector(fs),
        experiment_run="run-1",
        arm="healthy",
        delegation_id="d",
    )
    pg_result = postgres.commit(
        EffectPlan.from_vector(pg),
        experiment_run="run-1",
        arm="healthy",
        delegation_id="d",
    )

    assert fs_result["committed"] is True
    assert pg_result["committed"] is True
    assert filesystem.oracle(experiment_run="run-1", arm="healthy")["vector_ids"] == [
        fs.vector_id
    ]
    assert postgres.oracle(experiment_run="run-1", arm="healthy")["vector_ids"] == [
        pg.vector_id
    ]


def test_remote_boundary_rejects_bad_bearer_and_wrong_service(remote_boundary) -> None:
    server, fs, _ = remote_boundary
    base_url = f"http://127.0.0.1:{server.server_address[1]}"
    bad_token = RemoteEffectStore(
        service="filesystem",
        base_url=base_url,
        bearer_token="wrong",
    )
    with pytest.raises(RuntimeError, match="401"):
        bad_token.commit(
            EffectPlan.from_vector(fs),
            experiment_run="run-1",
            arm="healthy",
            delegation_id="d",
        )

    postgres_client = RemoteEffectStore(
        service="postgres",
        base_url=base_url,
        bearer_token="test-boundary-token",
    )
    with pytest.raises(ValueError, match="received a filesystem vector"):
        postgres_client.commit(
            EffectPlan.from_vector(fs),
            experiment_run="run-1",
            arm="healthy",
            delegation_id="d",
        )


def test_persistent_gateway_uses_remote_effect_oracle(remote_boundary, tmp_path: Path) -> None:
    server, fs, pg = remote_boundary
    base_url = f"http://127.0.0.1:{server.server_address[1]}"
    gateway = PersistentEffectGateway(
        gateway_id="remote-gateway",
        state_db=tmp_path / "gateway.sqlite3",
        allowlist={vector.vector_id: vector for vector in (fs, pg)},
        filesystem_store=RemoteEffectStore(
            service="filesystem",
            base_url=base_url,
            bearer_token="test-boundary-token",
        ),
        postgres_store=RemoteEffectStore(
            service="postgres",
            base_url=base_url,
            bearer_token="test-boundary-token",
        ),
    )

    fs_result = gateway.execute_effect(
        delegation_id="d",
        experiment_run="run-2",
        arm="healthy",
        vector_payload=fs.payload(),
    )
    pg_result = gateway.execute_effect(
        delegation_id="d",
        experiment_run="run-2",
        arm="healthy",
        vector_payload=pg.payload(),
    )
    gateway.apply_revocation(
        delegation_id="d",
        event_id="event-1",
        channel="receiver-push",
        sequence=1,
    )
    denied = gateway.execute_effect(
        delegation_id="d",
        experiment_run="run-2-revoked",
        arm="treatment",
        vector_payload=fs.payload(),
    )

    assert fs_result["effect"]["effect_type"] == "filesystem"
    assert pg_result["effect"]["effect_type"] == "postgres"
    assert denied["allowed"] is False
    assert denied["effect"] is None
