"""Small Ed25519 and hashing helpers shared by the Paper B prototype."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def canonical_json_bytes(payload: dict[str, Any]) -> bytes:
    """Return deterministic JSON bytes for signatures and hashes."""

    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class KeyPair:
    private: Ed25519PrivateKey
    public: Ed25519PublicKey
    key_id: str

    @property
    def public_bytes(self) -> bytes:
        return self.public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )


def generate_keypair() -> KeyPair:
    private = Ed25519PrivateKey.generate()
    public = private.public_key()
    pub_raw = public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return KeyPair(private=private, public=public, key_id=sha256_hex(pub_raw)[:16])


def public_key_id(public: Ed25519PublicKey) -> str:
    pub_raw = public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return sha256_hex(pub_raw)[:16]


def sign(private: Ed25519PrivateKey, data: bytes) -> str:
    return private.sign(data).hex()


def verify(public: Ed25519PublicKey, data: bytes, signature_hex: str) -> bool:
    try:
        public.verify(bytes.fromhex(signature_hex), data)
        return True
    except (InvalidSignature, ValueError):
        return False
