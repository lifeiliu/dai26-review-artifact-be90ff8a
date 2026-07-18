from revocation_propagation.crypto import generate_keypair
from revocation_propagation.events import create_revocation_event
from revocation_propagation.ledger_client import (
    ConsistencyProof,
    InclusionProof,
    TransparencyLedger,
    verify_consistency,
    verify_inclusion,
    verify_sth,
)


def test_ledger_inclusion_and_consistency() -> None:
    issuer = generate_keypair()
    log_key = generate_keypair()
    ledger = TransparencyLedger(log_key)
    first = create_revocation_event("edge-1", issuer, issued_at=1.0)
    second = create_revocation_event("edge-2", issuer, issued_at=2.0)

    ledger.append(first, appended_at=1.1)
    old_sth = ledger.latest_sth(timestamp=1.2)
    ledger.append(second, appended_at=2.1)
    new_sth = ledger.latest_sth(timestamp=2.2)

    assert verify_sth(old_sth, log_key.public)
    assert verify_sth(new_sth, log_key.public)
    assert verify_inclusion(ledger.inclusion_proof(1), new_sth)
    assert verify_consistency(ledger.consistency_proof(old_sth.size), old_sth, new_sth)


def test_ledger_rejects_tampered_inclusion_and_prefix_consistency_evidence() -> None:
    issuer = generate_keypair()
    log_key = generate_keypair()
    ledger = TransparencyLedger(log_key)
    ledger.append(create_revocation_event("edge-1", issuer, issued_at=1.0), appended_at=1.1)
    old_sth = ledger.latest_sth(timestamp=1.2)
    ledger.append(create_revocation_event("edge-2", issuer, issued_at=2.0), appended_at=2.1)
    new_sth = ledger.latest_sth(timestamp=2.2)

    inclusion = ledger.inclusion_proof(1)
    direction, sibling = inclusion.path[0]
    tampered_inclusion = InclusionProof(
        tree_size=inclusion.tree_size,
        leaf_index=inclusion.leaf_index,
        leaf_hash=inclusion.leaf_hash,
        root_hash=inclusion.root_hash,
        path=((direction, ("0" if sibling[0] != "0" else "1") + sibling[1:]),) + inclusion.path[1:],
    )
    assert not verify_inclusion(tampered_inclusion, new_sth)

    consistency = ledger.consistency_proof(old_sth.size)
    tampered_new = list(consistency.new_leaf_hashes)
    tampered_new[0] = ("0" if tampered_new[0][0] != "0" else "1") + tampered_new[0][1:]
    tampered_consistency = ConsistencyProof(
        old_size=consistency.old_size,
        new_size=consistency.new_size,
        old_leaf_hashes=consistency.old_leaf_hashes,
        new_leaf_hashes=tuple(tampered_new),
    )
    assert not verify_consistency(tampered_consistency, old_sth, new_sth)


def test_same_size_equivocation_has_different_root() -> None:
    issuer = generate_keypair()
    key = generate_keypair()
    left = TransparencyLedger(key)
    right = TransparencyLedger(key)

    left.append(create_revocation_event("edge-left", issuer, issued_at=1.0), appended_at=1.1)
    right.append(create_revocation_event("edge-right", issuer, issued_at=1.0), appended_at=1.1)

    left_sth = left.latest_sth(timestamp=2.0)
    right_sth = right.latest_sth(timestamp=2.0)

    assert left_sth.size == right_sth.size
    assert left_sth.root_hash != right_sth.root_hash
