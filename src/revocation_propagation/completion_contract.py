"""Executable C0--C5 completion contract for bounded revocation trials.

The monitor deliberately separates receiver persistence (C3), enforcement at
every declared gateway (C4), and absence of committed effects in a closed,
predeclared observation window (C5).  It does not make an unbounded claim
about every possible future tool call.
"""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import asdict, dataclass
from enum import IntEnum
from pathlib import Path
from typing import Mapping, Sequence

from .e_b24_receiver import CloudReceiverStore
from .real_effect_gate import canonical_json


CONTRACT_VERSION = "c0-c5-bounded-v2"


class CompletionStage(IntEnum):
    NONE = -1
    C0_ISSUER_COMMITTED = 0
    C1_TRANSMITTER_QUEUED = 1
    C2_TRANSPORT_ACKNOWLEDGED = 2
    C3_RECEIVER_PERSISTED = 3
    C4_GATEWAYS_ENFORCED = 4
    C5_EFFECTS_PREVENTED = 5


@dataclass(frozen=True)
class EffectObservation:
    vector_id: str
    gateway_id: str
    decision_id: str
    allowed: bool
    effect_committed: bool
    observed_at_ns: int


@dataclass(frozen=True)
class CompletionVerdict:
    contract_version: str
    jti: str
    event_id: str
    status: str
    highest_stage: str
    complete_for_bound: bool
    expected_gateway_ids: tuple[str, ...]
    receipt_gateway_ids: tuple[str, ...]
    missing_gateway_ids: tuple[str, ...]
    expected_vector_ids: tuple[str, ...]
    observed_vector_ids: tuple[str, ...]
    missing_vector_ids: tuple[str, ...]
    violating_vector_ids: tuple[str, ...]
    window_start_ns: int
    window_deadline_ns: int
    window_closed_at_ns: int | None

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


class CompletionContractMonitor:
    """Persistent monitor joining receiver receipts with bounded effects."""

    def __init__(
        self,
        *,
        receiver_store: CloudReceiverStore,
        monitor_db: str | Path,
    ) -> None:
        self.receiver_store = receiver_store
        self.monitor_db = Path(monitor_db)
        self.monitor_db.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.monitor_db, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS contracts (
                    jti TEXT PRIMARY KEY,
                    event_id TEXT NOT NULL,
                    issuer_commit_id TEXT NOT NULL,
                    transmitter_queue_id TEXT NOT NULL,
                    transport_ack_id TEXT NOT NULL,
                    expected_vectors_json TEXT NOT NULL,
                    window_start_ns INTEGER NOT NULL,
                    window_deadline_ns INTEGER NOT NULL,
                    window_closed_at_ns INTEGER
                );
                CREATE TABLE IF NOT EXISTS effect_observations (
                    jti TEXT NOT NULL REFERENCES contracts(jti),
                    vector_id TEXT NOT NULL,
                    gateway_id TEXT NOT NULL,
                    decision_id TEXT NOT NULL,
                    allowed INTEGER NOT NULL CHECK(allowed IN (0, 1)),
                    effect_committed INTEGER NOT NULL CHECK(effect_committed IN (0, 1)),
                    observed_at_ns INTEGER NOT NULL,
                    PRIMARY KEY (jti, vector_id),
                    UNIQUE (jti, decision_id)
                );
                """
            )

    def register_contract(
        self,
        *,
        jti: str,
        event_id: str,
        issuer_commit_id: str,
        transmitter_queue_id: str,
        transport_ack_id: str,
        expected_vector_ids: Sequence[str],
        window_start_ns: int,
        window_deadline_ns: int,
    ) -> None:
        evidence = (issuer_commit_id, transmitter_queue_id, transport_ack_id)
        if not all(evidence):
            raise ValueError("C0--C2 evidence identifiers must be non-empty")
        expected = sorted(str(item) for item in expected_vector_ids)
        if not expected or len(set(expected)) != len(expected):
            raise ValueError("the bounded contract needs unique expected vectors")
        if window_deadline_ns < window_start_ns:
            raise ValueError("effect window deadline precedes its start")
        receiver = self.receiver_store.event(jti)
        if receiver["event_id"] != event_id:
            raise ValueError("contract event does not match the persisted receiver event")
        values = (
            jti,
            event_id,
            *evidence,
            canonical_json(expected),
            window_start_ns,
            window_deadline_ns,
        )
        with self._connect() as connection:
            existing = connection.execute(
                "SELECT * FROM contracts WHERE jti=?", (jti,)
            ).fetchone()
            if existing is None:
                connection.execute(
                    "INSERT INTO contracts VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)",
                    values,
                )
            else:
                observed = tuple(existing[key] for key in (
                    "jti", "event_id", "issuer_commit_id", "transmitter_queue_id",
                    "transport_ack_id", "expected_vectors_json", "window_start_ns",
                    "window_deadline_ns",
                ))
                if observed != values:
                    raise ValueError("registered completion contract is immutable")

    def record_effect(self, *, jti: str, observation: EffectObservation) -> None:
        with self._connect() as connection:
            contract = connection.execute(
                "SELECT expected_vectors_json, window_start_ns, window_deadline_ns "
                "FROM contracts WHERE jti=?", (jti,)
            ).fetchone()
            if contract is None:
                raise KeyError(jti)
            expected = set(json.loads(contract["expected_vectors_json"]))
            if observation.vector_id not in expected:
                raise ValueError("effect observation is outside the frozen vector set")
            if not (
                int(contract["window_start_ns"])
                <= observation.observed_at_ns
                <= int(contract["window_deadline_ns"])
            ):
                raise ValueError("effect observation is outside the frozen time window")
            values = (
                jti,
                observation.vector_id,
                observation.gateway_id,
                observation.decision_id,
                int(observation.allowed),
                int(observation.effect_committed),
                observation.observed_at_ns,
            )
            existing = connection.execute(
                "SELECT * FROM effect_observations WHERE jti=? AND vector_id=?",
                (jti, observation.vector_id),
            ).fetchone()
            if existing is None:
                connection.execute(
                    "INSERT INTO effect_observations VALUES (?, ?, ?, ?, ?, ?, ?)",
                    values,
                )
            else:
                observed = tuple(existing[key] for key in (
                    "jti", "vector_id", "gateway_id", "decision_id", "allowed",
                    "effect_committed", "observed_at_ns",
                ))
                if observed != values:
                    raise ValueError("effect evidence for a vector is immutable")

    def close_window(self, *, jti: str, closed_at_ns: int | None = None) -> None:
        closed = time.time_ns() if closed_at_ns is None else closed_at_ns
        observed_now = time.time_ns()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT window_start_ns, window_deadline_ns, window_closed_at_ns "
                "FROM contracts WHERE jti=?", (jti,)
            ).fetchone()
            if row is None:
                raise KeyError(jti)
            if closed < int(row["window_deadline_ns"]):
                raise ValueError("window cannot close before its frozen deadline")
            if closed > observed_now:
                raise ValueError("window cannot close in the future")
            prior = row["window_closed_at_ns"]
            if prior is not None and int(prior) != closed:
                raise ValueError("closed completion window is immutable")
            connection.execute(
                "UPDATE contracts SET window_closed_at_ns=? WHERE jti=?",
                (closed, jti),
            )

    def assess(self, jti: str) -> CompletionVerdict:
        receiver = self.receiver_store.event(jti)
        with self._connect() as connection:
            contract = connection.execute(
                "SELECT * FROM contracts WHERE jti=?", (jti,)
            ).fetchone()
            if contract is None:
                raise KeyError(jti)
            rows = connection.execute(
                "SELECT * FROM effect_observations WHERE jti=? ORDER BY vector_id",
                (jti,),
            ).fetchall()

        expected_gateways = tuple(
            sorted(str(item["gateway_id"]) for item in receiver["targets"])
        )
        receipt_gateways = tuple(sorted(str(item) for item in receiver["receipts"]))
        missing_gateways = tuple(sorted(set(expected_gateways) - set(receipt_gateways)))
        expected_vectors = tuple(json.loads(contract["expected_vectors_json"]))
        observed_vectors = tuple(str(row["vector_id"]) for row in rows)
        missing_vectors = tuple(sorted(set(expected_vectors) - set(observed_vectors)))
        violating_vectors = tuple(
            str(row["vector_id"])
            for row in rows
            if bool(row["allowed"]) or bool(row["effect_committed"])
        )

        stage = CompletionStage.C2_TRANSPORT_ACKNOWLEDGED
        if receiver["status"] in {"PERSISTED", "ENFORCED"}:
            stage = CompletionStage.C3_RECEIVER_PERSISTED
        if receiver["status"] == "ENFORCED" and not missing_gateways:
            stage = CompletionStage.C4_GATEWAYS_ENFORCED

        closed = contract["window_closed_at_ns"] is not None
        bounded_complete = (
            stage >= CompletionStage.C4_GATEWAYS_ENFORCED
            and closed
            and not missing_vectors
            and not violating_vectors
        )
        if bounded_complete:
            stage = CompletionStage.C5_EFFECTS_PREVENTED
            status = "COMPLETE_FOR_BOUND"
        elif violating_vectors:
            status = "VIOLATED"
        elif closed and missing_vectors:
            status = "INDETERMINATE_MISSING_EFFECT_EVIDENCE"
        elif missing_gateways:
            status = "PARTIAL_ENFORCEMENT"
        else:
            status = "IN_PROGRESS"

        return CompletionVerdict(
            contract_version=CONTRACT_VERSION,
            jti=jti,
            event_id=str(contract["event_id"]),
            status=status,
            highest_stage=stage.name,
            complete_for_bound=bounded_complete,
            expected_gateway_ids=expected_gateways,
            receipt_gateway_ids=receipt_gateways,
            missing_gateway_ids=missing_gateways,
            expected_vector_ids=expected_vectors,
            observed_vector_ids=observed_vectors,
            missing_vector_ids=missing_vectors,
            violating_vector_ids=violating_vectors,
            window_start_ns=int(contract["window_start_ns"]),
            window_deadline_ns=int(contract["window_deadline_ns"]),
            window_closed_at_ns=(
                None
                if contract["window_closed_at_ns"] is None
                else int(contract["window_closed_at_ns"])
            ),
        )


def lower_bound_indistinguishability_witness() -> dict[str, object]:
    """Return two executions equal through C3 and different at C4/C5.

    This is an executable witness for the lower-bound argument: any predicate
    whose input is restricted to the C0--C3 prefix produces the same answer for
    both executions, although their bounded effect outcomes differ.
    """

    shared_prefix: Mapping[str, str] = {
        "C0": "issuer-commit-7",
        "C1": "transmitter-queue-7",
        "C2": "transport-ack-202",
        "C3": "receiver-fsync-7",
    }
    safe = {
        "prefix": dict(shared_prefix),
        "C4": {"g1": "receipt-1", "g2": "receipt-2"},
        "C5": {"v1": "denied", "v2": "denied"},
    }
    unsafe = {
        "prefix": dict(shared_prefix),
        "C4": {"g1": "receipt-1", "g2": None},
        "C5": {"v1": "denied", "v2": "committed"},
    }
    return {
        "contract_version": CONTRACT_VERSION,
        "prefix_equal": safe["prefix"] == unsafe["prefix"],
        "bounded_outcome_equal": safe["C5"] == unsafe["C5"],
        "safe_execution": safe,
        "unsafe_execution": unsafe,
    }
