from revocation_propagation.crypto import generate_keypair
from revocation_propagation.events import create_revocation_event, verify_revocation_event


def test_event_signature_verifies_and_tamper_fails() -> None:
    issuer = generate_keypair()
    event = create_revocation_event("edge-1", issuer, issued_at=1.0)

    assert verify_revocation_event(event, issuer.public, expected_issuer_key_id=issuer.key_id)

    tampered = create_revocation_event("edge-2", issuer, issued_at=1.0)
    tampered = type(event)(
        edge_id=tampered.edge_id,
        epoch_id=tampered.epoch_id,
        issuer_key_id=tampered.issuer_key_id,
        issued_at=tampered.issued_at,
        sequence=tampered.sequence,
        target_type=tampered.target_type,
        reason=tampered.reason,
        signature=event.signature,
    )

    assert not verify_revocation_event(tampered, issuer.public)
