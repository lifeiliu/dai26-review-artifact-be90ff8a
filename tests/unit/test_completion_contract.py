import time
from pathlib import Path

from revocation_propagation.completion_contract import (
    CompletionContractMonitor,
    EffectObservation,
    lower_bound_indistinguishability_witness,
)
from revocation_propagation.e_b24_receiver import CloudReceiverStore, VerifiedSet


def _event() -> VerifiedSet:
    return VerifiedSet(
        jti="jti-25",
        issuer="https://issuer",
        audience="receiver/stream",
        delegation_id="delegation-25",
        event_id="jti-25",
        sequence=25,
        encoded_sha256="a" * 64,
        key_id="kid",
        algorithm="RS256",
        issued_at=25,
    )


def _receipt(gateway_id: str) -> dict[str, object]:
    return {
        "applied": True,
        "delegation_id": "delegation-25",
        "event_id": "jti-25",
        "channel": "keycloak-push",
        "sequence": 25,
        "gateway_id": gateway_id,
        "receipt_id": f"receipt-{gateway_id}",
        "applied_at_ns": 1,
    }


def _monitor(tmp_path: Path) -> tuple[CloudReceiverStore, CompletionContractMonitor, int]:
    receiver = CloudReceiverStore(tmp_path / "receiver.sqlite3")
    receiver.persist_event(
        _event(),
        channel="keycloak-push",
        gateway_targets=[
            {"gateway_id": "g1", "gateway_url": "https://g1"},
            {"gateway_id": "g2", "gateway_url": "https://g2"},
        ],
    )
    monitor = CompletionContractMonitor(
        receiver_store=receiver,
        monitor_db=tmp_path / "monitor.sqlite3",
    )
    now = time.time_ns()
    monitor.register_contract(
        jti="jti-25",
        event_id="jti-25",
        issuer_commit_id="issuer-commit",
        transmitter_queue_id="queue-record",
        transport_ack_id="http-202",
        expected_vector_ids=["v1", "v2"],
        window_start_ns=now - 1_000_000,
        window_deadline_ns=now,
    )
    return receiver, monitor, now


def test_c3_is_never_reported_as_complete(tmp_path: Path) -> None:
    _, monitor, _ = _monitor(tmp_path)
    verdict = monitor.assess("jti-25")
    assert verdict.highest_stage == "C3_RECEIVER_PERSISTED"
    assert verdict.status == "PARTIAL_ENFORCEMENT"
    assert verdict.complete_for_bound is False
    assert verdict.missing_gateway_ids == ("g1", "g2")


def test_c5_requires_all_receipts_all_effects_and_closed_window(tmp_path: Path) -> None:
    receiver, monitor, now = _monitor(tmp_path)
    receiver.record_receipt(jti="jti-25", gateway_id="g1", receipt=_receipt("g1"))
    receiver.record_receipt(jti="jti-25", gateway_id="g2", receipt=_receipt("g2"))
    for offset, vector_id, gateway_id in ((1, "v1", "g1"), (2, "v2", "g2")):
        monitor.record_effect(
            jti="jti-25",
            observation=EffectObservation(
                vector_id=vector_id,
                gateway_id=gateway_id,
                decision_id=f"decision-{vector_id}",
                allowed=False,
                effect_committed=False,
                observed_at_ns=now - offset,
            ),
        )
    assert monitor.assess("jti-25").highest_stage == "C4_GATEWAYS_ENFORCED"
    monitor.close_window(jti="jti-25", closed_at_ns=now)
    verdict = monitor.assess("jti-25")
    assert verdict.status == "COMPLETE_FOR_BOUND"
    assert verdict.highest_stage == "C5_EFFECTS_PREVENTED"
    assert verdict.complete_for_bound is True


def test_committed_effect_is_a_contract_violation(tmp_path: Path) -> None:
    receiver, monitor, now = _monitor(tmp_path)
    receiver.record_receipt(jti="jti-25", gateway_id="g1", receipt=_receipt("g1"))
    monitor.record_effect(
        jti="jti-25",
        observation=EffectObservation(
            vector_id="v2",
            gateway_id="g2",
            decision_id="decision-v2",
            allowed=True,
            effect_committed=True,
            observed_at_ns=now - 1,
        ),
    )
    monitor.close_window(jti="jti-25", closed_at_ns=now)
    verdict = monitor.assess("jti-25")
    assert verdict.status == "VIOLATED"
    assert verdict.highest_stage == "C3_RECEIVER_PERSISTED"
    assert verdict.violating_vector_ids == ("v2",)


def test_lower_bound_witness_has_same_c0_c3_prefix_and_different_outcome() -> None:
    witness = lower_bound_indistinguishability_witness()
    assert witness["prefix_equal"] is True
    assert witness["bounded_outcome_equal"] is False


def test_window_cannot_close_before_deadline_or_in_future(tmp_path: Path) -> None:
    _, monitor, now = _monitor(tmp_path)
    try:
        monitor.close_window(jti="jti-25", closed_at_ns=now - 1)
    except ValueError as error:
        assert "frozen deadline" in str(error)
    else:
        raise AssertionError("early closure was accepted")

    try:
        monitor.close_window(jti="jti-25", closed_at_ns=time.time_ns() + 1_000_000_000)
    except ValueError as error:
        assert "future" in str(error)
    else:
        raise AssertionError("future closure was accepted")
