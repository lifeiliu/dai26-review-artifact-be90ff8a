from revocation_propagation.crypto import generate_keypair
from revocation_propagation.events import create_revocation_event
from revocation_propagation.root_authority import RootApproval, RootAuthority, RootFederation


def test_quorum_certificate_requires_m_of_n_unique_roots() -> None:
    issuer = generate_keypair()
    event = create_revocation_event("edge-1", issuer, issued_at=1.0)
    authorities = [RootAuthority(f"root-{i}", generate_keypair()) for i in range(5)]
    federation = RootFederation(
        {authority.root_id: authority.keypair.public for authority in authorities},
        threshold=3,
    )

    assert federation.verify_certificate(
        federation.certificate_for(event, [authority.approve_event(event) for authority in authorities[:3]])
    )
    assert not federation.verify_certificate(
        federation.certificate_for(event, [authority.approve_event(event) for authority in authorities[:2]])
    )


def test_root_key_id_must_match_configured_public_key() -> None:
    issuer = generate_keypair()
    event = create_revocation_event("edge-1", issuer, issued_at=1.0)
    authority = RootAuthority("root-0", generate_keypair())
    federation = RootFederation({"root-0": authority.keypair.public}, threshold=1)
    approval = authority.approve_event(event)
    forged_key_id = RootApproval(
        root_id=approval.root_id,
        root_key_id="not-the-key",
        event_id=approval.event_id,
        signature=approval.signature,
    )

    assert not federation.verify_certificate(federation.certificate_for(event, [forged_key_id]))


def test_duplicate_root_approvals_do_not_satisfy_quorum() -> None:
    issuer = generate_keypair()
    event = create_revocation_event("edge-duplicate", issuer, issued_at=1.0)
    authorities = [RootAuthority(f"root-{index}", generate_keypair()) for index in range(3)]
    federation = RootFederation(
        {authority.root_id: authority.keypair.public for authority in authorities},
        threshold=2,
    )
    duplicated = authorities[0].approve_event(event)

    assert not federation.verify_certificate(
        federation.certificate_for(event, [duplicated, duplicated])
    )
