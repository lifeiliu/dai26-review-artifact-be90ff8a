#!/usr/bin/env python3
"""Create an ephemeral synthetic SET signer without retaining its private key locally."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


PARAMETER_ROOT = "/paper-b/e-b24/smoke"
KEY_ID = "e-b24-synthetic-set-v1"


def _b64url_integer(value: int) -> str:
    encoded = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(encoded).rstrip(b"=").decode("ascii")


def _run(*command: str) -> str:
    return subprocess.run(command, check=True, capture_output=True, text=True).stdout


def _put_parameter(
    *, profile: str, region: str, name: str, value: str, kind: str, expiry: str
) -> None:
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as handle:
        json.dump(
            {
                "Name": name,
                "Value": value,
                "Type": kind,
                "Overwrite": True,
                "Tier": "Standard",
                "DataType": "text",
            },
            handle,
        )
        request = Path(handle.name)
    os.chmod(request, 0o600)
    try:
        _run(
            "aws",
            "ssm",
            "put-parameter",
            "--profile",
            profile,
            "--region",
            region,
            "--cli-input-json",
            f"file://{request}",
        )
    finally:
        request.unlink(missing_ok=True)
    _run(
        "aws",
        "ssm",
        "add-tags-to-resource",
        "--profile",
        profile,
        "--region",
        region,
        "--resource-type",
        "Parameter",
        "--resource-id",
        name,
        "--tags",
        "Key=Project,Value=paper-b-e-b24",
        "Key=Stage,Value=smoke",
        f"Key=Expiry,Value={expiry}",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--bucket", required=True)
    parser.add_argument("--expiry", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    public = private_key.public_key().public_numbers()
    jwks = {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": KEY_ID,
                "n": _b64url_integer(public.n),
                "e": _b64url_integer(public.e),
            }
        ]
    }
    jwks_bytes = (json.dumps(jwks, sort_keys=True, separators=(",", ":")) + "\n").encode()
    jwks_sha256 = hashlib.sha256(jwks_bytes).hexdigest()
    jwks_key = f"smoke/config/synthetic-jwks/{jwks_sha256}/jwks.json"

    with tempfile.NamedTemporaryFile(mode="wb", delete=False) as handle:
        handle.write(jwks_bytes)
        jwks_path = Path(handle.name)
    try:
        _run(
            "aws",
            "s3",
            "cp",
            "--profile",
            args.profile,
            "--region",
            args.region,
            str(jwks_path),
            f"s3://{args.bucket}/{jwks_key}",
            "--only-show-errors",
        )
    finally:
        jwks_path.unlink(missing_ok=True)

    _put_parameter(
        profile=args.profile,
        region=args.region,
        name=f"{PARAMETER_ROOT}/config/synthetic-jwks-key",
        value=jwks_key,
        kind="String",
        expiry=args.expiry,
    )
    _put_parameter(
        profile=args.profile,
        region=args.region,
        name=f"{PARAMETER_ROOT}/secrets/synthetic-set-private-key",
        value=private_pem,
        kind="SecureString",
        expiry=args.expiry,
    )
    private_key = None
    private_pem = ""

    manifest = {
        "purpose": "synthetic receiver-path smoke only; not a Keycloak claim",
        "key_id": KEY_ID,
        "algorithm": "RS256",
        "jwks_sha256": jwks_sha256,
        "jwks_s3_key": jwks_key,
        "private_key_parameter": (
            f"{PARAMETER_ROOT}/secrets/synthetic-set-private-key"
        ),
        "expiry": args.expiry,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(json.dumps(manifest, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
