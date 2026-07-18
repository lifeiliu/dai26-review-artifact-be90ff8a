from revocation_propagation.crypto import generate_keypair
from revocation_propagation.events import create_revocation_event
from revocation_propagation.ledger_client import TransparencyLedger
from revocation_propagation.propagator import FaultPolicy, PropagationConfig, Propagator


def test_push_only_leaves_suppressed_party_undelivered() -> None:
    issuer = generate_keypair()
    event = create_revocation_event("edge-1", issuer, issued_at=0.0)
    ledger = TransparencyLedger(generate_keypair())
    parties = ["rp-0", "rp-1", "rp-2"]
    result = Propagator(PropagationConfig(max_time=1.0)).propagate(
        event,
        ledger=ledger,
        party_ids=parties,
        strategy="push",
        fault_policy=FaultPolicy(suppress_push_to=frozenset({"rp-2"})),
    )

    assert result.completeness == 2 / 3
    assert result.undelivered == ("rp-2",)


def test_hybrid_recovers_from_push_suppression() -> None:
    issuer = generate_keypair()
    event = create_revocation_event("edge-1", issuer, issued_at=0.0)
    ledger = TransparencyLedger(generate_keypair())
    parties = ["rp-0", "rp-1", "rp-2"]
    result = Propagator(PropagationConfig(max_time=2.0)).propagate(
        event,
        ledger=ledger,
        party_ids=parties,
        strategy="hybrid",
        fault_policy=FaultPolicy(suppress_push_to=frozenset({"rp-2"})),
    )

    assert result.completeness == 1.0
    assert not result.undelivered
    assert result.suppression_detected_at is not None
    assert {record.party_id: record.via for record in result.records}["rp-2"] in {"gossip", "log"}


def test_composite_strategy_records_overhead_and_p99() -> None:
    issuer = generate_keypair()
    event = create_revocation_event("edge-1", issuer, issued_at=0.0)
    ledger = TransparencyLedger(generate_keypair())
    result = Propagator(PropagationConfig(max_time=2.0, random_seed=7)).propagate(
        event,
        ledger=ledger,
        party_ids=["rp-0", "rp-1", "rp-2", "rp-3"],
        strategy="push-gossip",
        fault_policy=FaultPolicy(suppress_push_to=frozenset({"rp-3"})),
    )

    assert result.completeness == 1.0
    assert result.p99_delta is not None
    assert result.overhead.push_messages > 0
    assert result.overhead.gossip_messages > 0
