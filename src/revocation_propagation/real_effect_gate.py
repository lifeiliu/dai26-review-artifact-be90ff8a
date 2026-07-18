"""E-B24 real-effect mapping, persistent gateway, and durable receiver primitives."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sqlite3
import subprocess
import threading
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable, Mapping

from .keycloak_gateway_gate import ReplayVector


E_B24_DESIGN_VERSION = "e-b24-design-v1"


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _safe_component(value: str) -> str:
    """Use readable safe components while preventing path traversal."""

    if value and all(character.isalnum() or character in {"-", "_", "."} for character in value):
        return value
    return sha256_text(value)


def parse_replay_vector(payload: str | Mapping[str, object]) -> ReplayVector:
    body = json.loads(payload) if isinstance(payload, str) else dict(payload)
    vector = ReplayVector(
        service=str(body["service"]),
        gateway_id=str(body["gateway_id"]),
        run=int(body["run"]),
        call_sequence=int(body["call_sequence"]),
        tool_name=str(body["tool_name"]),
        arguments_sha256=str(body["arguments_sha256"]),
    )
    supplied = body.get("vector_id")
    if supplied != vector.vector_id:
        raise ValueError(
            f"vector identity mismatch: supplied={supplied!r}, recomputed={vector.vector_id}"
        )
    return vector


def write_vector_allowlist(path: str | Path, vectors: list[ReplayVector]) -> dict[str, object]:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    records = [json.loads(vector.payload()) for vector in vectors]
    payload = {
        "design_version": E_B24_DESIGN_VERSION,
        "vector_count": len(records),
        "vectors": records,
    }
    destination.write_text(canonical_json(payload) + "\n", encoding="utf-8")
    return {
        "path": str(destination.resolve()),
        "sha256": hashlib.sha256(destination.read_bytes()).hexdigest(),
        "vector_count": len(records),
    }


def load_vector_allowlist(path: str | Path) -> dict[str, ReplayVector]:
    body = json.loads(Path(path).read_text(encoding="utf-8"))
    if body.get("design_version") != E_B24_DESIGN_VERSION:
        raise ValueError("E-B24 vector allowlist design version mismatch")
    vectors = [parse_replay_vector(item) for item in body.get("vectors", [])]
    allowlist = {vector.vector_id: vector for vector in vectors}
    if len(allowlist) != len(vectors) or len(vectors) != int(body.get("vector_count", -1)):
        raise ValueError("E-B24 vector allowlist contains a count mismatch or duplicate")
    return allowlist


@dataclass(frozen=True)
class EffectPlan:
    vector_id: str
    service: str
    gateway_id: str
    run: int
    call_sequence: int
    tool_name: str
    arguments_sha256: str

    @classmethod
    def from_vector(cls, vector: ReplayVector) -> "EffectPlan":
        return cls(vector_id=vector.vector_id, **asdict(vector))

    def record(
        self,
        *,
        experiment_run: str,
        arm: str,
        delegation_id: str,
    ) -> dict[str, object]:
        return {
            "design_version": E_B24_DESIGN_VERSION,
            "experiment_run": experiment_run,
            "arm": arm,
            "delegation_id": delegation_id,
            **asdict(self),
        }


class FilesystemEffectStore:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, *, experiment_run: str, arm: str, vector_id: str) -> Path:
        run = _safe_component(experiment_run)
        safe_arm = _safe_component(arm)
        destination = self.root / run / safe_arm / vector_id[:2] / f"{vector_id}.json"
        resolved_parent = destination.parent.resolve()
        if self.root != resolved_parent and self.root not in resolved_parent.parents:
            raise ValueError("filesystem effect escaped its sandbox")
        return destination

    def commit(self, plan: EffectPlan, *, experiment_run: str, arm: str, delegation_id: str) -> dict[str, object]:
        record = plan.record(
            experiment_run=experiment_run,
            arm=arm,
            delegation_id=delegation_id,
        )
        body = (canonical_json(record) + "\n").encode("utf-8")
        destination = self._path(
            experiment_run=experiment_run,
            arm=arm,
            vector_id=plan.vector_id,
        )
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.tmp")
        try:
            with temporary.open("xb") as handle:
                handle.write(body)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, destination)
            directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            directory_fd = os.open(destination.parent, directory_flags)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            temporary.unlink(missing_ok=True)
        return {
            "committed": True,
            "effect_type": "filesystem",
            "vector_id": plan.vector_id,
            "path": str(destination),
            "content_sha256": hashlib.sha256(body).hexdigest(),
            "committed_at_ns": time.time_ns(),
        }

    def oracle(self, *, experiment_run: str, arm: str) -> dict[str, object]:
        namespace = self.root / _safe_component(experiment_run) / _safe_component(arm)
        records: list[dict[str, str]] = []
        if namespace.is_dir():
            for path in sorted(namespace.rglob("*.json")):
                body = path.read_bytes()
                parsed = json.loads(body)
                records.append(
                    {
                        "vector_id": str(parsed["vector_id"]),
                        "content_sha256": hashlib.sha256(body).hexdigest(),
                    }
                )
        records.sort(key=lambda item: item["vector_id"])
        return {
            "effect_type": "filesystem",
            "count": len(records),
            "vector_ids": [item["vector_id"] for item in records],
            "digest_sha256": sha256_text(canonical_json(records)),
        }


def _sql_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


class PostgresDockerEffectStore:
    """PostgreSQL effect store accessed through the pinned container's psql."""

    def __init__(self, *, container: str, database: str, user: str, password: str) -> None:
        self.container = container
        self.database = database
        self.user = user
        self.password = password

    def _psql(self, sql: str, *, tuples: bool = False) -> str:
        command = [
            "docker",
            "exec",
            "-e",
            f"PGPASSWORD={self.password}",
            self.container,
            "psql",
            "--no-psqlrc",
            "--quiet",
            "--set",
            "ON_ERROR_STOP=1",
            "--username",
            self.user,
            "--dbname",
            self.database,
        ]
        if tuples:
            command.extend(["--tuples-only", "--no-align", "--field-separator", "|"])
        command.extend(["--command", sql])
        completed = subprocess.run(command, check=True, capture_output=True, text=True)
        return completed.stdout.strip()

    def ensure_schema(self) -> None:
        self._psql(
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

    def commit(self, plan: EffectPlan, *, experiment_run: str, arm: str, delegation_id: str) -> dict[str, object]:
        record = plan.record(
            experiment_run=experiment_run,
            arm=arm,
            delegation_id=delegation_id,
        )
        payload = canonical_json(record)
        payload_sha256 = sha256_text(payload)
        output = self._psql(
            "INSERT INTO effect_commits "
            "(experiment_run, arm, vector_id, gateway_id, delegation_id, payload_sha256, payload_json) VALUES ("
            f"{_sql_literal(experiment_run)}, {_sql_literal(arm)}, {_sql_literal(plan.vector_id)}, "
            f"{_sql_literal(plan.gateway_id)}, {_sql_literal(delegation_id)}, "
            f"{_sql_literal(payload_sha256)}, {_sql_literal(payload)}::jsonb) "
            "ON CONFLICT (experiment_run, arm, vector_id) DO NOTHING RETURNING vector_id;",
            tuples=True,
        )
        committed = output.splitlines()[-1].strip() == plan.vector_id if output else False
        return {
            "committed": committed,
            "effect_type": "postgres",
            "vector_id": plan.vector_id,
            "payload_sha256": payload_sha256,
            "committed_at_ns": time.time_ns(),
        }

    def oracle(self, *, experiment_run: str, arm: str) -> dict[str, object]:
        output = self._psql(
            "SELECT vector_id, payload_sha256 FROM effect_commits WHERE "
            f"experiment_run={_sql_literal(experiment_run)} AND arm={_sql_literal(arm)} "
            "ORDER BY vector_id;",
            tuples=True,
        )
        records: list[dict[str, str]] = []
        for line in output.splitlines():
            if not line.strip():
                continue
            vector_id, payload_sha256 = line.strip().split("|", 1)
            records.append({"vector_id": vector_id, "payload_sha256": payload_sha256})
        return {
            "effect_type": "postgres",
            "count": len(records),
            "vector_ids": [item["vector_id"] for item in records],
            "digest_sha256": sha256_text(canonical_json(records)),
        }


class PersistentEffectGateway:
    def __init__(
        self,
        *,
        gateway_id: str,
        state_db: str | Path,
        allowlist: Mapping[str, ReplayVector],
        filesystem_store: FilesystemEffectStore,
        postgres_store: Any,
    ) -> None:
        self.gateway_id = gateway_id
        self.state_db = Path(state_db)
        self.state_db.parent.mkdir(parents=True, exist_ok=True)
        self.allowlist = dict(allowlist)
        self.filesystem_store = filesystem_store
        self.postgres_store = postgres_store
        self.lock = threading.RLock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.state_db, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS revocations (
                    delegation_id TEXT PRIMARY KEY,
                    sequence INTEGER NOT NULL,
                    event_id TEXT NOT NULL,
                    channel TEXT NOT NULL,
                    applied_at_ns INTEGER NOT NULL,
                    receipt_id TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS decisions (
                    decision_id TEXT PRIMARY KEY,
                    experiment_run TEXT NOT NULL,
                    arm TEXT NOT NULL,
                    delegation_id TEXT NOT NULL,
                    vector_id TEXT NOT NULL,
                    allowed INTEGER NOT NULL,
                    effect_committed INTEGER NOT NULL,
                    decided_at_ns INTEGER NOT NULL
                );
                """
            )

    def _validated_plan(self, vector_payload: str) -> EffectPlan:
        vector = parse_replay_vector(vector_payload)
        expected = self.allowlist.get(vector.vector_id)
        if expected is None or expected != vector:
            raise ValueError("vector is not an exact member of the frozen E-B24 allowlist")
        return EffectPlan.from_vector(vector)

    def execute_effect(
        self,
        *,
        delegation_id: str,
        experiment_run: str,
        arm: str,
        vector_payload: str,
    ) -> dict[str, object]:
        plan = self._validated_plan(vector_payload)
        with self.lock:
            with self._connect() as connection:
                revocation = connection.execute(
                    "SELECT event_id, channel FROM revocations WHERE delegation_id=?",
                    (delegation_id,),
                ).fetchone()
            allowed = revocation is None
            effect: dict[str, object] | None = None
            if allowed:
                if plan.service == "filesystem":
                    effect = self.filesystem_store.commit(
                        plan,
                        experiment_run=experiment_run,
                        arm=arm,
                        delegation_id=delegation_id,
                    )
                elif plan.service == "postgres":
                    effect = self.postgres_store.commit(
                        plan,
                        experiment_run=experiment_run,
                        arm=arm,
                        delegation_id=delegation_id,
                    )
                else:
                    raise ValueError(f"unsupported frozen effect service: {plan.service}")
            decided_at_ns = time.time_ns()
            decision_material = {
                "gateway_id": self.gateway_id,
                "delegation_id": delegation_id,
                "experiment_run": experiment_run,
                "arm": arm,
                "vector_id": plan.vector_id,
                "decided_at_ns": decided_at_ns,
            }
            decision_id = sha256_text(canonical_json(decision_material))
            with self._connect() as connection:
                connection.execute(
                    "INSERT INTO decisions VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        decision_id,
                        experiment_run,
                        arm,
                        delegation_id,
                        plan.vector_id,
                        int(allowed),
                        int(bool(effect and effect.get("committed"))),
                        decided_at_ns,
                    ),
                )
        return {
            "allowed": allowed,
            "reason": "active-delegation" if allowed else "revoked-delegation",
            "gateway_id": self.gateway_id,
            "delegation_id": delegation_id,
            "vector_id": plan.vector_id,
            "decision_id": decision_id,
            "event_id": None if revocation is None else revocation["event_id"],
            "learned_via": None if revocation is None else revocation["channel"],
            "effect": effect,
        }

    def apply_revocation(
        self,
        *,
        delegation_id: str,
        event_id: str,
        channel: str,
        sequence: int,
    ) -> dict[str, object]:
        if sequence < 0:
            raise ValueError("revocation sequence must be non-negative")
        with self.lock:
            with self._connect() as connection:
                existing = connection.execute(
                    "SELECT * FROM revocations WHERE delegation_id=?",
                    (delegation_id,),
                ).fetchone()
                if existing is not None and int(existing["sequence"]) > sequence:
                    raise ValueError("non-monotonic revocation sequence")
                if existing is not None and int(existing["sequence"]) == sequence:
                    if existing["event_id"] != event_id:
                        raise ValueError("same revocation sequence reused by a different event")
                    applied_at_ns = int(existing["applied_at_ns"])
                    receipt_id = str(existing["receipt_id"])
                else:
                    applied_at_ns = time.time_ns()
                    receipt_material = {
                        "gateway_id": self.gateway_id,
                        "delegation_id": delegation_id,
                        "event_id": event_id,
                        "channel": channel,
                        "sequence": sequence,
                        "applied_at_ns": applied_at_ns,
                    }
                    receipt_id = sha256_text(canonical_json(receipt_material))
                    connection.execute(
                        "INSERT INTO revocations VALUES (?, ?, ?, ?, ?, ?) "
                        "ON CONFLICT(delegation_id) DO UPDATE SET "
                        "sequence=excluded.sequence, event_id=excluded.event_id, "
                        "channel=excluded.channel, applied_at_ns=excluded.applied_at_ns, "
                        "receipt_id=excluded.receipt_id",
                        (delegation_id, sequence, event_id, channel, applied_at_ns, receipt_id),
                    )
        return {
            "applied": True,
            "receipt_id": receipt_id,
            "gateway_id": self.gateway_id,
            "delegation_id": delegation_id,
            "event_id": event_id,
            "channel": channel,
            "sequence": sequence,
            "applied_at_ns": applied_at_ns,
        }

    def status(self, delegation_id: str) -> dict[str, object]:
        with self._connect() as connection:
            revocation = connection.execute(
                "SELECT * FROM revocations WHERE delegation_id=?",
                (delegation_id,),
            ).fetchone()
            counts = connection.execute(
                "SELECT allowed, COUNT(*) AS n FROM decisions GROUP BY allowed"
            ).fetchall()
        decisions = {"allowed": 0, "denied": 0}
        for row in counts:
            decisions["allowed" if int(row["allowed"]) else "denied"] = int(row["n"])
        return {
            "gateway_id": self.gateway_id,
            "delegation_id": delegation_id,
            "revoked": revocation is not None,
            "event_id": None if revocation is None else revocation["event_id"],
            "learned_via": None if revocation is None else revocation["channel"],
            "receipt_id": None if revocation is None else revocation["receipt_id"],
            "decisions": decisions,
            "server_pid": os.getpid(),
        }


class DurableReceiverStore:
    """Durable receiver inbox with a separate enforcement-completion receipt."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS inbox (
                    jti TEXT PRIMARY KEY,
                    delegation_id TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    channel TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    set_sha256 TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('PERSISTED', 'ENFORCED')),
                    persisted_at_ns INTEGER NOT NULL,
                    enforced_at_ns INTEGER,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT
                );
                CREATE TABLE IF NOT EXISTS enforcement_receipts (
                    jti TEXT PRIMARY KEY REFERENCES inbox(jti),
                    receipt_id TEXT NOT NULL,
                    gateway_id TEXT NOT NULL,
                    receipt_json TEXT NOT NULL,
                    recorded_at_ns INTEGER NOT NULL
                );
                """
            )

    def persist_event(
        self,
        *,
        jti: str,
        delegation_id: str,
        event_id: str,
        channel: str,
        sequence: int,
        encoded_set: str,
    ) -> dict[str, object]:
        set_sha256 = sha256_text(encoded_set)
        persisted_at_ns = time.time_ns()
        with self._connect() as connection:
            existing = connection.execute("SELECT * FROM inbox WHERE jti=?", (jti,)).fetchone()
            if existing is not None:
                if existing["set_sha256"] != set_sha256 or existing["event_id"] != event_id:
                    raise ValueError("receiver jti collision with different event content")
            else:
                connection.execute(
                    "INSERT INTO inbox "
                    "(jti, delegation_id, event_id, channel, sequence, set_sha256, status, persisted_at_ns) "
                    "VALUES (?, ?, ?, ?, ?, ?, 'PERSISTED', ?)",
                    (
                        jti,
                        delegation_id,
                        event_id,
                        channel,
                        sequence,
                        set_sha256,
                        persisted_at_ns,
                    ),
                )
        return self.event(jti)

    def event(self, jti: str) -> dict[str, object]:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM inbox WHERE jti=?", (jti,)).fetchone()
            receipt = connection.execute(
                "SELECT receipt_json FROM enforcement_receipts WHERE jti=?", (jti,)
            ).fetchone()
        if row is None:
            raise KeyError(jti)
        result = dict(row)
        result["receipt"] = None if receipt is None else json.loads(receipt["receipt_json"])
        return result

    def handoff_payload(self, jti: str) -> dict[str, object]:
        event = self.event(jti)
        return {
            "delegation_id": event["delegation_id"],
            "event_id": event["event_id"],
            "channel": event["channel"],
            "sequence": event["sequence"],
        }

    def mark_enforced(self, jti: str, receipt: Mapping[str, object]) -> dict[str, object]:
        event = self.event(jti)
        expected = self.handoff_payload(jti)
        for field in ("delegation_id", "event_id", "channel", "sequence"):
            if receipt.get(field) != expected[field]:
                raise ValueError(f"enforcement receipt does not bind expected {field}")
        if receipt.get("applied") is not True or not receipt.get("receipt_id") or not receipt.get("gateway_id"):
            raise ValueError("incomplete enforcement receipt")
        enforced_at_ns = time.time_ns()
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO enforcement_receipts VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(jti) DO UPDATE SET receipt_id=excluded.receipt_id, "
                "gateway_id=excluded.gateway_id, receipt_json=excluded.receipt_json, "
                "recorded_at_ns=excluded.recorded_at_ns",
                (
                    jti,
                    receipt["receipt_id"],
                    receipt["gateway_id"],
                    canonical_json(dict(receipt)),
                    enforced_at_ns,
                ),
            )
            connection.execute(
                "UPDATE inbox SET status='ENFORCED', enforced_at_ns=?, attempts=attempts+1, "
                "last_error=NULL WHERE jti=?",
                (enforced_at_ns, jti),
            )
        return self.event(jti)

    def record_failure(self, jti: str, error: BaseException) -> dict[str, object]:
        with self._connect() as connection:
            connection.execute(
                "UPDATE inbox SET attempts=attempts+1, last_error=? WHERE jti=?",
                (f"{type(error).__name__}: {error}", jti),
            )
        return self.event(jti)

    async def handoff_once_async(
        self,
        jti: str,
        apply: Callable[[dict[str, object]], Awaitable[Mapping[str, object]]],
    ) -> dict[str, object]:
        event = self.event(jti)
        if event["status"] == "ENFORCED":
            return event
        try:
            receipt = await apply(self.handoff_payload(jti))
        except BaseException as error:
            self.record_failure(jti, error)
            raise
        return self.mark_enforced(jti, receipt)


def evaluate_local_gate(
    *,
    manifest: Mapping[str, object],
    infrastructure: Mapping[str, object],
    phases: Mapping[str, Mapping[str, object]],
    receiver: Mapping[str, object],
) -> dict[str, bool]:
    def phase(name: str, field: str, default: object = -1) -> object:
        return phases.get(name, {}).get(field, default)

    return {
        "frozen_vectors_match": int(manifest.get("vector_count", -1)) == 225
        and manifest.get("service_counts") == {"filesystem": 112, "postgres": 113}
        and manifest.get("workload_identity_sha256")
        == "75ce415ae238fb0d973e9cbf25d13c81bbecf574d409cf782054e487c33027ae",
        "frozen_configuration_unchanged": not any(
            bool(manifest.get(field))
            for field in (
                "risk_index_changed",
                "target_policy_changed",
                "target_membership_changed",
                "mutation_labels_changed",
                "target_fraction_changed",
                "effect_threshold_changed",
            )
        ),
        "pinned_postgres_used": bool(infrastructure.get("pinned_postgres_used")),
        "gateway_process_isolation": bool(infrastructure.get("gateway_process_isolation")),
        "active_allows_and_commits": phase("active", "allowed") == 225
        and phase("active", "denied") == 0
        and phase("active", "filesystem_effects") == 112
        and phase("active", "postgres_effects") == 113,
        "revoked_denies_without_effect": phase("revoked", "allowed") == 0
        and phase("revoked", "denied") == 225
        and phase("revoked", "filesystem_effects") == 0
        and phase("revoked", "postgres_effects") == 0,
        "persisted_before_handoff_commits": phase("recovery_pre", "allowed") == 225
        and phase("recovery_pre", "filesystem_effects") == 112
        and phase("recovery_pre", "postgres_effects") == 113,
        "recovery_enforces_without_effect": phase("recovery_post", "allowed") == 0
        and phase("recovery_post", "denied") == 225
        and phase("recovery_post", "filesystem_effects") == 0
        and phase("recovery_post", "postgres_effects") == 0,
        "receiver_reopen_persisted": receiver.get("status_before_handoff") == "PERSISTED"
        and bool(receiver.get("reopen_verified")),
        "enforcement_receipt_persisted": receiver.get("status_after_handoff") == "ENFORCED"
        and bool(receiver.get("receipt_id"))
        and bool(receiver.get("gateway_id")),
    }
