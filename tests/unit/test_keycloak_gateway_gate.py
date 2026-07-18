import json
from pathlib import Path

from revocation_propagation.keycloak_gateway_gate import (
    EXPECTED_VECTOR_COUNT,
    condition_counts,
    evaluate_e_b22_assertions,
    load_frozen_workload,
)


ARTIFACT = Path(__file__).resolve().parents[2]
WORKLOAD = ARTIFACT / "data" / "run_2026_07_14_e_b20_mcpmark_formal"


def test_frozen_e_b22_workload_lock() -> None:
    vectors, manifest = load_frozen_workload(WORKLOAD)
    assert len(vectors) == EXPECTED_VECTOR_COUNT
    assert manifest["service_counts"] == {"filesystem": 112, "postgres": 113}
    assert manifest["zero_vector_targets"] == ["filesystem/file_context/duplicates_searching"]
    assert len({vector.vector_id for vector in vectors}) == EXPECTED_VECTOR_COUNT


def test_e_b22_realm_allowlists_the_frozen_relay() -> None:
    realm_path = ARTIFACT / "experiments" / "e_b22_keycloak_gateway_gate" / "realm-e-b22.json"
    realm = json.loads(realm_path.read_text())
    clients = {client["clientId"]: client for client in realm["clients"]}
    assert clients["receiver-a"]["attributes"]["ssf.validPushUrls"] == (
        "http://host.docker.internal:19002/receiver-a"
    )
    assert clients["receiver-b"]["attributes"]["ssf.validPushUrls"] == (
        "http://host.docker.internal:19002/receiver-b"
    )


def test_e_b22_deterministic_gate_contract() -> None:
    rows = []
    for condition in ("normal-delivery", "receiver-selective-nondelivery"):
        for receiver in ("receiver-a", "receiver-b"):
            allowed = condition == "receiver-selective-nondelivery" and receiver == "receiver-b"
            rows.extend(
                {"condition": condition, "receiver": receiver, "allowed": allowed}
                for _ in range(EXPECTED_VECTOR_COUNT)
            )
    replay_counts = condition_counts(rows)
    receiver_events = {
        "normal-delivery": {
            "receiver-a": {"signature_verified": True, "forwarded": True, "http_response": 202},
            "receiver-b": {"signature_verified": True, "forwarded": True, "http_response": 202},
        },
        "receiver-selective-nondelivery": {
            "receiver-a": {"signature_verified": True, "forwarded": True, "http_response": 202},
            "receiver-b": {"signature_verified": True, "forwarded": False, "http_response": 202},
        },
    }
    gateway_statuses = {
        "normal-delivery": {
            "receiver-a": {"revoked": True},
            "receiver-b": {"revoked": True},
        },
        "receiver-selective-nondelivery": {
            "receiver-a": {"revoked": True},
            "receiver-b": {"revoked": False},
        },
    }
    manifest = {
        "vector_count": EXPECTED_VECTOR_COUNT,
        "target_count": 10,
        "risk_index_changed": False,
        "target_policy_changed": False,
        "target_membership_changed": False,
        "mutation_labels_changed": False,
        "target_fraction_changed": False,
        "effect_threshold_changed": False,
    }
    assertions = evaluate_e_b22_assertions(
        manifest=manifest,
        replay_counts=replay_counts,
        receiver_events=receiver_events,
        gateway_statuses=gateway_statuses,
        infrastructure={"pinned_postgres_used": True, "gateway_process_isolation": True},
    )
    assert all(assertions.values())
