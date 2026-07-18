"""Deterministic contract helpers for the frozen E-B23 POLL gate."""

from __future__ import annotations

from typing import Iterable, Mapping, Sequence

from .keycloak_gateway_gate import EXPECTED_TARGET_COUNT, EXPECTED_VECTOR_COUNT


E_B23_PROTOCOL_VERSION = "e-b23-prereg-v1"
REQUIRED_SSF_SCOPES = ("ssf.manage", "ssf.read")
SESSION_REVOKED = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
PUSH_METHOD = "urn:ietf:rfc:8935"
POLL_METHOD = "urn:ietf:rfc:8936"


def push_stream_request(endpoint_url: str) -> dict[str, object]:
    return {
        "description": "E-B23 receiver-A PUSH stream",
        "events_requested": [SESSION_REVOKED],
        "delivery": {
            "method": PUSH_METHOD,
            "endpoint_url": endpoint_url,
            "authorization_header": "Bearer receiver-a-e-b23",
        },
    }


def poll_stream_request() -> dict[str, object]:
    return {
        "description": "E-B23 receiver-B POLL stream",
        "events_requested": [SESSION_REVOKED],
        "delivery": {"method": POLL_METHOD},
    }


def poll_request(*, ack: Sequence[str] = ()) -> dict[str, object]:
    return {
        "maxEvents": 100,
        "returnImmediately": True,
        "ack": list(ack),
    }


def replay_counts(rows: Iterable[Mapping[str, object]]) -> dict[str, dict[str, int]]:
    counts: dict[str, dict[str, int]] = {}
    for row in rows:
        receiver = str(row["receiver"])
        bucket = counts.setdefault(receiver, {"allowed": 0, "denied": 0, "total": 0})
        bucket["allowed" if bool(row["allowed"]) else "denied"] += 1
        bucket["total"] += 1
    return counts


def evaluate_e_b23_assertions(
    *,
    manifest: Mapping[str, object],
    infrastructure: Mapping[str, object],
    pre_revocation: Mapping[str, Mapping[str, object]],
    pre_poll_controls: Mapping[str, Mapping[str, object]],
    push_event: Mapping[str, object],
    first_poll: Mapping[str, object],
    second_poll: Mapping[str, object],
    final_statuses: Mapping[str, Mapping[str, object]],
    counts: Mapping[str, Mapping[str, int]],
    path_audit: Mapping[str, object],
) -> dict[str, bool]:
    n = EXPECTED_VECTOR_COUNT

    def count(receiver: str, field: str) -> int:
        return int(counts.get(receiver, {}).get(field, -1))

    unchanged_fields = (
        "risk_index_changed",
        "target_policy_changed",
        "target_membership_changed",
        "mutation_labels_changed",
        "target_fraction_changed",
        "effect_threshold_changed",
    )
    token_scopes = set(str(first_poll.get("token_scope", "")).split())
    return {
        "frozen_inputs_match": int(manifest.get("vector_count", -1)) == n
        and int(manifest.get("target_count", -1)) == EXPECTED_TARGET_COUNT,
        "frozen_configuration_unchanged": not any(
            bool(manifest.get(field)) for field in unchanged_fields
        ),
        "pinned_postgres_used": bool(infrastructure.get("pinned_postgres_used")),
        "gateway_process_isolation": bool(infrastructure.get("gateway_process_isolation")),
        "pre_revocation_both_allow": all(
            bool(pre_revocation.get(receiver, {}).get("allowed"))
            for receiver in ("receiver-a", "receiver-b")
        ),
        "push_a_valid_and_forwarded": bool(push_event.get("signature_verified"))
        and bool(push_event.get("forwarded"))
        and int(push_event.get("http_response", -1)) == 202
        and bool(push_event.get("is_session_revoked")),
        "pre_poll_direction": pre_poll_controls.get("receiver-a", {}).get("allowed") is False
        and pre_poll_controls.get("receiver-b", {}).get("allowed") is True,
        "poll_token_scopes_present": set(REQUIRED_SSF_SCOPES).issubset(token_scopes),
        "first_poll_exact_matching_set": int(first_poll.get("http_status", -1)) == 200
        and int(first_poll.get("set_count", -1)) == 1
        and first_poll.get("more_available") is False
        and bool(first_poll.get("signature_verified"))
        and bool(first_poll.get("is_session_revoked"))
        and bool(first_poll.get("session_matches")),
        "post_delivery_a_denies_all": count("receiver-a", "denied") == n
        and count("receiver-a", "allowed") == 0
        and final_statuses.get("receiver-a", {}).get("revoked") is True,
        "post_poll_b_denies_all": count("receiver-b", "denied") == n
        and count("receiver-b", "allowed") == 0
        and final_statuses.get("receiver-b", {}).get("revoked") is True
        and final_statuses.get("receiver-b", {}).get("learned_via") == "keycloak-poll",
        "second_poll_acks_and_empty": int(second_poll.get("http_status", -1)) == 200
        and int(second_poll.get("set_count", -1)) == 0
        and second_poll.get("more_available") is False
        and bool(second_poll.get("ack_matches_first_jti")),
        "two_poll_requests_accounted": int(path_audit.get("poll_request_count", -1)) == 2
        and int(path_audit.get("poll_request_bytes", -1)) > 0
        and int(path_audit.get("poll_response_bytes", -1)) > 0,
        "native_poll_only_for_b": path_audit.get("receiver_b_state_source") == "keycloak-rfc8936-poll"
        and not bool(path_audit.get("receiver_b_push_handoff"))
        and not bool(path_audit.get("receiver_b_log_repair"))
        and not bool(path_audit.get("receiver_b_admin_event_read"))
        and not bool(path_audit.get("receiver_b_self_authored_event_store")),
        "poll_row_no_longer_pending": int(path_audit.get("poll_pending_after_ack", -1)) == 0,
    }
