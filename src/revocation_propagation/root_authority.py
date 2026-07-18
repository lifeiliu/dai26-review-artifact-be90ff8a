"""M-of-N root federation approval for revocation propagation."""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .crypto import KeyPair, canonical_json_bytes, public_key_id, sign, verify
from .events import RevocationEvent


@dataclass(frozen=True)
class RootAuthority:
    root_id: str
    keypair: KeyPair

    def approve_event(self, event: RevocationEvent) -> "RootApproval":
        payload = approval_payload(self.root_id, self.keypair.key_id, event.event_id)
        return RootApproval(
            root_id=self.root_id,
            root_key_id=self.keypair.key_id,
            event_id=event.event_id,
            signature=sign(self.keypair.private, canonical_json_bytes(payload)),
        )


@dataclass(frozen=True)
class RootApproval:
    root_id: str
    root_key_id: str
    event_id: str
    signature: str


@dataclass(frozen=True)
class RootCertificate:
    event_id: str
    threshold: int
    approvals: tuple[RootApproval, ...]


class RootFederation:
    """Verifier for M-of-N individual-signature quorum certificates."""

    def __init__(self, roots: dict[str, Ed25519PublicKey], *, threshold: int) -> None:
        if threshold <= 0:
            raise ValueError("threshold must be positive")
        if threshold > len(roots):
            raise ValueError("threshold cannot exceed root count")
        self.roots = dict(roots)
        self.threshold = threshold

    def certificate_for(
        self,
        event: RevocationEvent,
        approvals: list[RootApproval],
    ) -> RootCertificate:
        return RootCertificate(
            event_id=event.event_id,
            threshold=self.threshold,
            approvals=tuple(approvals),
        )

    def verify_certificate(self, certificate: RootCertificate) -> bool:
        if certificate.threshold != self.threshold:
            return False
        valid_roots: set[str] = set()
        for approval in certificate.approvals:
            if approval.event_id != certificate.event_id:
                continue
            public_key = self.roots.get(approval.root_id)
            if public_key is None:
                continue
            if approval.root_key_id != public_key_id(public_key):
                continue
            payload = approval_payload(
                approval.root_id,
                approval.root_key_id,
                approval.event_id,
            )
            if verify(public_key, canonical_json_bytes(payload), approval.signature):
                valid_roots.add(approval.root_id)
        return len(valid_roots) >= self.threshold


def approval_payload(root_id: str, root_key_id: str, event_id: str) -> dict[str, str]:
    return {
        "event_id": event_id,
        "root_id": root_id,
        "root_key_id": root_key_id,
    }
