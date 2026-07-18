"""Signed Paper A-compatible edge revocation events."""

from __future__ import annotations

import time
from dataclasses import dataclass, replace
from typing import Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .crypto import KeyPair, canonical_json_bytes, sha256_hex, sign, verify

TargetType = Literal["edge"]


@dataclass(frozen=True)
class RevocationEvent:
    """Signed event naming a Paper A edge-level revocation target."""

    edge_id: str
    epoch_id: str
    issuer_key_id: str
    issued_at: float
    sequence: int = 0
    target_type: TargetType = "edge"
    reason: str = ""
    signature: str = ""

    def signable_payload(self) -> dict[str, object]:
        return {
            "edge_id": self.edge_id,
            "epoch_id": self.epoch_id,
            "issued_at": self.issued_at,
            "issuer_key_id": self.issuer_key_id,
            "reason": self.reason,
            "sequence": self.sequence,
            "target_type": self.target_type,
        }

    def signable_bytes(self) -> bytes:
        return canonical_json_bytes(self.signable_payload())

    @property
    def event_id(self) -> str:
        if not self.signature:
            return sha256_hex(self.signable_bytes())
        return sha256_hex(self.signable_bytes() + bytes.fromhex(self.signature))

    @property
    def event_hash(self) -> str:
        return sha256_hex(canonical_json_bytes(self.to_payload()))

    def to_payload(self) -> dict[str, object]:
        payload = self.signable_payload()
        payload["event_id"] = self.event_id
        payload["signature"] = self.signature
        return payload


def create_revocation_event(
    edge_id: str,
    keypair: KeyPair,
    *,
    epoch_id: str = "epoch-0",
    issued_at: float | None = None,
    sequence: int = 0,
    reason: str = "",
) -> RevocationEvent:
    event = RevocationEvent(
        edge_id=edge_id,
        epoch_id=epoch_id,
        issuer_key_id=keypair.key_id,
        issued_at=time.time() if issued_at is None else issued_at,
        sequence=sequence,
        reason=reason,
    )
    return replace(event, signature=sign(keypair.private, event.signable_bytes()))


def verify_revocation_event(
    event: RevocationEvent,
    public_key: Ed25519PublicKey,
    *,
    expected_issuer_key_id: str | None = None,
) -> bool:
    if expected_issuer_key_id is not None and event.issuer_key_id != expected_issuer_key_id:
        return False
    unsigned = replace(event, signature="")
    return verify(public_key, unsigned.signable_bytes(), event.signature)
