"""Append-only transparency ledger used by the propagation prototype.

This is a compact in-process stand-in for Trillian or an equivalent log. It
supports signed tree heads, inclusion proofs, and a bulky prefix-consistency proof
that is useful for experiments. The production paper can replace this module with
a real log client without changing propagator semantics.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Literal, Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .crypto import KeyPair, canonical_json_bytes, sha256_hex, sign, verify
from .events import RevocationEvent

ZERO_HASH = "0" * 64
Direction = Literal["left", "right"]


def _hash_pair(left: str, right: str) -> str:
    return sha256_hex(bytes.fromhex(left) + bytes.fromhex(right))


def merkle_root(leaf_hashes: Sequence[str]) -> str:
    if not leaf_hashes:
        return sha256_hex(b"")
    level = list(leaf_hashes)
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        level = [_hash_pair(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


@dataclass(frozen=True)
class LedgerEntry:
    index: int
    event: RevocationEvent
    event_hash: str
    previous_hash: str
    appended_at: float
    entry_hash: str

    @staticmethod
    def create(
        *,
        index: int,
        event: RevocationEvent,
        previous_hash: str,
        appended_at: float,
    ) -> "LedgerEntry":
        payload = {
            "appended_at": appended_at,
            "event_hash": event.event_hash,
            "event_id": event.event_id,
            "index": index,
            "previous_hash": previous_hash,
        }
        return LedgerEntry(
            index=index,
            event=event,
            event_hash=event.event_hash,
            previous_hash=previous_hash,
            appended_at=appended_at,
            entry_hash=sha256_hex(canonical_json_bytes(payload)),
        )


@dataclass(frozen=True)
class SignedTreeHead:
    size: int
    root_hash: str
    timestamp: float
    previous_sth_hash: str
    log_id: str
    signer_key_id: str
    signature: str

    def signable_payload(self) -> dict[str, object]:
        return {
            "log_id": self.log_id,
            "previous_sth_hash": self.previous_sth_hash,
            "root_hash": self.root_hash,
            "signer_key_id": self.signer_key_id,
            "size": self.size,
            "timestamp": self.timestamp,
        }

    def signable_bytes(self) -> bytes:
        return canonical_json_bytes(self.signable_payload())

    @property
    def sth_hash(self) -> str:
        return sha256_hex(self.signable_bytes() + bytes.fromhex(self.signature))


@dataclass(frozen=True)
class InclusionProof:
    tree_size: int
    leaf_index: int
    leaf_hash: str
    root_hash: str
    path: tuple[tuple[Direction, str], ...]


@dataclass(frozen=True)
class ConsistencyProof:
    old_size: int
    new_size: int
    old_leaf_hashes: tuple[str, ...]
    new_leaf_hashes: tuple[str, ...]


class TransparencyLedger:
    """Single-log append-only ledger with signed checkpoints."""

    def __init__(self, keypair: KeyPair, *, log_id: str = "paper-b-log") -> None:
        self.keypair = keypair
        self.log_id = log_id
        self._entries: list[LedgerEntry] = []
        self._checkpoints: list[SignedTreeHead] = []

    @property
    def entries(self) -> tuple[LedgerEntry, ...]:
        return tuple(self._entries)

    def append(self, event: RevocationEvent, *, appended_at: float | None = None) -> LedgerEntry:
        previous_hash = self._entries[-1].entry_hash if self._entries else ZERO_HASH
        entry = LedgerEntry.create(
            index=len(self._entries),
            event=event,
            previous_hash=previous_hash,
            appended_at=time.time() if appended_at is None else appended_at,
        )
        self._entries.append(entry)
        return entry

    def latest_sth(self, *, timestamp: float | None = None) -> SignedTreeHead:
        previous = self._checkpoints[-1].sth_hash if self._checkpoints else ZERO_HASH
        unsigned = SignedTreeHead(
            size=len(self._entries),
            root_hash=merkle_root([entry.entry_hash for entry in self._entries]),
            timestamp=time.time() if timestamp is None else timestamp,
            previous_sth_hash=previous,
            log_id=self.log_id,
            signer_key_id=self.keypair.key_id,
            signature="",
        )
        signed = SignedTreeHead(
            size=unsigned.size,
            root_hash=unsigned.root_hash,
            timestamp=unsigned.timestamp,
            previous_sth_hash=unsigned.previous_sth_hash,
            log_id=unsigned.log_id,
            signer_key_id=unsigned.signer_key_id,
            signature=sign(self.keypair.private, unsigned.signable_bytes()),
        )
        self._checkpoints.append(signed)
        return signed

    def event_by_id(self, event_id: str) -> RevocationEvent | None:
        for entry in self._entries:
            if entry.event.event_id == event_id:
                return entry.event
        return None

    def inclusion_proof(self, leaf_index: int) -> InclusionProof:
        if leaf_index < 0 or leaf_index >= len(self._entries):
            raise IndexError("leaf index out of range")
        leaves = [entry.entry_hash for entry in self._entries]
        path: list[tuple[Direction, str]] = []
        idx = leaf_index
        level = list(leaves)
        while len(level) > 1:
            if len(level) % 2 == 1:
                level.append(level[-1])
            sibling_idx = idx ^ 1
            direction: Direction = "left" if idx % 2 else "right"
            path.append((direction, level[sibling_idx]))
            idx //= 2
            level = [_hash_pair(level[i], level[i + 1]) for i in range(0, len(level), 2)]
        return InclusionProof(
            tree_size=len(leaves),
            leaf_index=leaf_index,
            leaf_hash=leaves[leaf_index],
            root_hash=merkle_root(leaves),
            path=tuple(path),
        )

    def consistency_proof(self, old_size: int, new_size: int | None = None) -> ConsistencyProof:
        if new_size is None:
            new_size = len(self._entries)
        if old_size < 0 or new_size < old_size or new_size > len(self._entries):
            raise ValueError("invalid consistency proof sizes")
        leaves = [entry.entry_hash for entry in self._entries]
        return ConsistencyProof(
            old_size=old_size,
            new_size=new_size,
            old_leaf_hashes=tuple(leaves[:old_size]),
            new_leaf_hashes=tuple(leaves[:new_size]),
        )


def verify_sth(sth: SignedTreeHead, public_key: Ed25519PublicKey) -> bool:
    unsigned = SignedTreeHead(
        size=sth.size,
        root_hash=sth.root_hash,
        timestamp=sth.timestamp,
        previous_sth_hash=sth.previous_sth_hash,
        log_id=sth.log_id,
        signer_key_id=sth.signer_key_id,
        signature="",
    )
    return verify(public_key, unsigned.signable_bytes(), sth.signature)


def verify_inclusion(proof: InclusionProof, sth: SignedTreeHead) -> bool:
    if proof.tree_size != sth.size or proof.root_hash != sth.root_hash:
        return False
    idx = proof.leaf_index
    computed = proof.leaf_hash
    for direction, sibling in proof.path:
        if direction == "left":
            computed = _hash_pair(sibling, computed)
        else:
            computed = _hash_pair(computed, sibling)
        idx //= 2
    return computed == sth.root_hash


def verify_consistency(
    proof: ConsistencyProof,
    old_sth: SignedTreeHead,
    new_sth: SignedTreeHead,
) -> bool:
    if proof.old_size != old_sth.size or proof.new_size != new_sth.size:
        return False
    if proof.old_size > proof.new_size:
        return False
    if proof.new_leaf_hashes[: proof.old_size] != proof.old_leaf_hashes:
        return False
    return (
        merkle_root(proof.old_leaf_hashes) == old_sth.root_hash
        and merkle_root(proof.new_leaf_hashes) == new_sth.root_hash
    )
