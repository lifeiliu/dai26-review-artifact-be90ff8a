import json
from pathlib import Path

from revocation_propagation.keycloak_gateway_gate import EXPECTED_VECTOR_COUNT, load_frozen_workload
from revocation_propagation.keycloak_poll_gate import (
    POLL_METHOD,
    PUSH_METHOD,
    evaluate_e_b23_assertions,
    poll_request,
    poll_stream_request,
    push_stream_request,
    replay_counts,
)


ARTIFACT = Path(__file__).resolve().parents[2]
WORKLOAD = ARTIFACT / "data" / "run_2026_07_14_e_b20_mcpmark_formal"


def test_e_b23_reuses_exact_frozen_workload() -> None:
    vectors, manifest = load_frozen_workload(WORKLOAD)
    assert len(vectors) == EXPECTED_VECTOR_COUNT
    assert manifest["workload_identity_sha256"] == (
        "75ce415ae238fb0d973e9cbf25d13c81bbecf574d409cf782054e487c33027ae"
    )


def test_e_b23_wire_requests_are_frozen() -> None:
    push = push_stream_request("http://host.docker.internal:19003/receiver-a")
    poll = poll_stream_request()
    assert push["delivery"]["method"] == PUSH_METHOD
    assert poll["delivery"] == {"method": POLL_METHOD}
    assert poll_request() == {"maxEvents": 100, "returnImmediately": True, "ack": []}
    assert poll_request(ack=["jti-1"])["ack"] == ["jti-1"]


def test_e_b23_realm_pins_push_and_poll_receivers() -> None:
    path = ARTIFACT / "experiments" / "e_b23_keycloak_poll_gateway" / "realm-e-b23.json"
    realm = json.loads(path.read_text())
    clients = {client["clientId"]: client for client in realm["clients"]}
    assert clients["receiver-a"]["attributes"]["ssf.validPushUrls"] == (
        "http://host.docker.internal:19003/receiver-a"
    )
    assert "ssf.validPushUrls" not in clients["receiver-b"]["attributes"]


def test_e_b23_deterministic_gate_contract() -> None:
    rows = [
        {"receiver": receiver, "allowed": False}
        for receiver in ("receiver-a", "receiver-b")
        for _ in range(EXPECTED_VECTOR_COUNT)
    ]
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
    assertions = evaluate_e_b23_assertions(
        manifest=manifest,
        infrastructure={"pinned_postgres_used": True, "gateway_process_isolation": True},
        pre_revocation={"receiver-a": {"allowed": True}, "receiver-b": {"allowed": True}},
        pre_poll_controls={"receiver-a": {"allowed": False}, "receiver-b": {"allowed": True}},
        push_event={
            "signature_verified": True,
            "forwarded": True,
            "http_response": 202,
            "is_session_revoked": True,
        },
        first_poll={
            "http_status": 200,
            "set_count": 1,
            "more_available": False,
            "signature_verified": True,
            "is_session_revoked": True,
            "session_matches": True,
            "token_scope": "openid ssf.manage ssf.read",
        },
        second_poll={
            "http_status": 200,
            "set_count": 0,
            "more_available": False,
            "ack_matches_first_jti": True,
        },
        final_statuses={
            "receiver-a": {"revoked": True, "learned_via": "direct-push"},
            "receiver-b": {"revoked": True, "learned_via": "keycloak-poll"},
        },
        counts=replay_counts(rows),
        path_audit={
            "poll_request_count": 2,
            "poll_request_bytes": 100,
            "poll_response_bytes": 500,
            "receiver_b_state_source": "keycloak-rfc8936-poll",
            "receiver_b_push_handoff": False,
            "receiver_b_log_repair": False,
            "receiver_b_admin_event_read": False,
            "receiver_b_self_authored_event_store": False,
            "poll_pending_after_ack": 0,
        },
    )
    assert all(assertions.values())

