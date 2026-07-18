import asyncio
from pathlib import Path

import pytest

from revocation_propagation.keycloak_gateway_gate import ReplayVector, load_frozen_workload
from revocation_propagation.real_effect_gate import (
    DurableReceiverStore,
    EffectPlan,
    FilesystemEffectStore,
    PersistentEffectGateway,
    evaluate_local_gate,
    load_vector_allowlist,
    parse_replay_vector,
    write_vector_allowlist,
)


ARTIFACT = Path(__file__).resolve().parents[2]
WORKLOAD = ARTIFACT / "data" / "run_2026_07_14_e_b20_mcpmark_formal"


class MemoryPostgresStore:
    def __init__(self) -> None:
        self.records: dict[tuple[str, str, str], dict[str, object]] = {}

    def commit(self, plan: EffectPlan, *, experiment_run: str, arm: str, delegation_id: str):
        key = (experiment_run, arm, plan.vector_id)
        self.records[key] = plan.record(
            experiment_run=experiment_run,
            arm=arm,
            delegation_id=delegation_id,
        )
        return {"committed": True, "effect_type": "postgres", "vector_id": plan.vector_id}


def test_effect_allowlist_preserves_all_frozen_vectors(tmp_path: Path) -> None:
    vectors, manifest = load_frozen_workload(WORKLOAD)
    path = tmp_path / "allowlist.json"
    result = write_vector_allowlist(path, vectors)
    loaded = load_vector_allowlist(path)
    assert result["vector_count"] == 225
    assert len(loaded) == 225
    assert manifest["service_counts"] == {"filesystem": 112, "postgres": 113}
    assert set(loaded) == {vector.vector_id for vector in vectors}


def test_vector_identity_tampering_is_rejected() -> None:
    vector = ReplayVector("filesystem", "g", 3, 1, "write", "a" * 64)
    body = vector.payload().replace(vector.vector_id, "0" * 64)
    with pytest.raises(ValueError, match="vector identity mismatch"):
        parse_replay_vector(body)


def test_filesystem_effect_is_real_and_oracle_visible(tmp_path: Path) -> None:
    vector = ReplayVector("filesystem", "filesystem/task", 3, 1, "write", "a" * 64)
    store = FilesystemEffectStore(tmp_path / "effects")
    result = store.commit(
        EffectPlan.from_vector(vector),
        experiment_run="active",
        arm="local",
        delegation_id="d",
    )
    oracle = store.oracle(experiment_run="active", arm="local")
    assert result["committed"] is True
    assert Path(result["path"]).is_file()
    assert oracle["count"] == 1
    assert oracle["vector_ids"] == [vector.vector_id]


def test_persistent_gateway_denies_after_receipt(tmp_path: Path) -> None:
    fs_vector = ReplayVector("filesystem", "filesystem/task", 3, 1, "write", "a" * 64)
    pg_vector = ReplayVector("postgres", "postgres/task", 4, 2, "execute_sql", "b" * 64)
    allowlist = {vector.vector_id: vector for vector in (fs_vector, pg_vector)}
    gateway = PersistentEffectGateway(
        gateway_id="g",
        state_db=tmp_path / "gateway.sqlite3",
        allowlist=allowlist,
        filesystem_store=FilesystemEffectStore(tmp_path / "effects"),
        postgres_store=MemoryPostgresStore(),
    )
    allowed = gateway.execute_effect(
        delegation_id="d",
        experiment_run="active",
        arm="local",
        vector_payload=fs_vector.payload(),
    )
    receipt = gateway.apply_revocation(
        delegation_id="d", event_id="e", channel="receiver", sequence=1
    )
    denied = gateway.execute_effect(
        delegation_id="d",
        experiment_run="revoked",
        arm="local",
        vector_payload=pg_vector.payload(),
    )
    reopened = PersistentEffectGateway(
        gateway_id="g",
        state_db=tmp_path / "gateway.sqlite3",
        allowlist=allowlist,
        filesystem_store=FilesystemEffectStore(tmp_path / "effects"),
        postgres_store=MemoryPostgresStore(),
    )
    assert allowed["allowed"] is True
    assert denied["allowed"] is False
    assert receipt["receipt_id"] == reopened.status("d")["receipt_id"]


def test_durable_receiver_survives_reopen_and_binds_receipt(tmp_path: Path) -> None:
    path = tmp_path / "receiver.sqlite3"
    receiver = DurableReceiverStore(path)
    receiver.persist_event(
        jti="j",
        delegation_id="d",
        event_id="e",
        channel="receiver",
        sequence=1,
        encoded_set="set",
    )
    receiver = DurableReceiverStore(path)
    assert receiver.event("j")["status"] == "PERSISTED"

    async def apply(payload):
        return {
            "applied": True,
            "receipt_id": "r",
            "gateway_id": "g",
            "applied_at_ns": 1,
            **payload,
        }

    asyncio.run(receiver.handoff_once_async("j", apply))
    receiver = DurableReceiverStore(path)
    event = receiver.event("j")
    assert event["status"] == "ENFORCED"
    assert event["receipt"]["receipt_id"] == "r"


def test_local_gate_contract() -> None:
    manifest = {
        "vector_count": 225,
        "service_counts": {"filesystem": 112, "postgres": 113},
        "workload_identity_sha256": "75ce415ae238fb0d973e9cbf25d13c81bbecf574d409cf782054e487c33027ae",
        "risk_index_changed": False,
        "target_policy_changed": False,
        "target_membership_changed": False,
        "mutation_labels_changed": False,
        "target_fraction_changed": False,
        "effect_threshold_changed": False,
    }
    phases = {
        "active": {"allowed": 225, "denied": 0, "filesystem_effects": 112, "postgres_effects": 113},
        "revoked": {"allowed": 0, "denied": 225, "filesystem_effects": 0, "postgres_effects": 0},
        "recovery_pre": {"allowed": 225, "denied": 0, "filesystem_effects": 112, "postgres_effects": 113},
        "recovery_post": {"allowed": 0, "denied": 225, "filesystem_effects": 0, "postgres_effects": 0},
    }
    assertions = evaluate_local_gate(
        manifest=manifest,
        infrastructure={"pinned_postgres_used": True, "gateway_process_isolation": True},
        phases=phases,
        receiver={
            "status_before_handoff": "PERSISTED",
            "reopen_verified": True,
            "status_after_handoff": "ENFORCED",
            "receipt_id": "r",
            "gateway_id": "g",
        },
    )
    assert all(assertions.values())

