#!/usr/bin/env python3
"""Prepare ephemeral E-B24 smoke PKI, parameters, and frozen allowlist."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import subprocess
import tempfile
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[3]
BOOTSTRAP = REPO_ROOT / "infra" / "e_b24" / "bootstrap"
SMOKE = REPO_ROOT / "infra" / "e_b24" / "smoke"
ALLOWLIST = (
    REPO_ROOT
    / "artifact"
    / "data"
    / "run_2026_07_16_e_b24_local_real_effect_gate"
    / "frozen-vector-allowlist.json"
)
EXPECTED_ALLOWLIST_SHA256 = "9e76d237213e899486bfd65fad817cedd500cd0820535aa8e953519a24b8e9b2"
PARAMETER_ROOT = "/paper-b/e-b24/smoke"


def _run(*command: str, capture: bool = True) -> str:
    completed = subprocess.run(command, check=True, capture_output=capture, text=True)
    return completed.stdout if capture else ""


def _terraform_output(directory: Path, name: str) -> Any:
    return json.loads(_run("terraform", f"-chdir={directory}", "output", "-json", name))


def _put_parameter(
    *,
    profile: str,
    region: str,
    name: str,
    value: str,
    kind: str,
    work: Path,
    expiry: str,
) -> None:
    payload = {
        "Name": name,
        "Value": value,
        "Type": kind,
        "Overwrite": True,
        "Tier": "Standard",
        "DataType": "text",
    }
    request = work / "put-parameter.json"
    request.write_text(json.dumps(payload), encoding="utf-8")
    os.chmod(request, 0o600)
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
    request.unlink()
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


def _certificate_fingerprint(path: Path) -> str:
    output = _run(
        "openssl",
        "x509",
        "-in",
        str(path),
        "-noout",
        "-fingerprint",
        "-sha256",
    ).strip()
    return output.split("=", 1)[1].replace(":", "").lower()


def _leaf(*, work: Path, name: str, private_ip: str, ca_key: Path, ca_cert: Path) -> tuple[Path, Path]:
    key = work / f"{name}.key"
    csr = work / f"{name}.csr"
    cert = work / f"{name}.crt"
    extensions = work / f"{name}.ext"
    extensions.write_text(
        "basicConstraints=CA:FALSE\n"
        "keyUsage=digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth,clientAuth\n"
        f"subjectAltName=DNS:{name},IP:{private_ip}\n",
        encoding="utf-8",
    )
    _run(
        "openssl",
        "genpkey",
        "-algorithm",
        "EC",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-out",
        str(key),
    )
    _run(
        "openssl",
        "req",
        "-new",
        "-key",
        str(key),
        "-subj",
        f"/CN={name}",
        "-out",
        str(csr),
    )
    _run(
        "openssl",
        "x509",
        "-req",
        "-in",
        str(csr),
        "-CA",
        str(ca_cert),
        "-CAkey",
        str(ca_key),
        "-CAcreateserial",
        "-days",
        "14",
        "-sha256",
        "-extfile",
        str(extensions),
        "-out",
        str(cert),
    )
    return cert, key


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--expiry", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    allowlist_sha256 = hashlib.sha256(ALLOWLIST.read_bytes()).hexdigest()
    if allowlist_sha256 != EXPECTED_ALLOWLIST_SHA256:
        raise RuntimeError("frozen E-B24 allowlist digest changed")
    topology = _terraform_output(SMOKE, "topology_manifest")
    hosts = topology["hosts"]
    bucket = _run(
        "terraform",
        f"-chdir={BOOTSTRAP}",
        "output",
        "-raw",
        "evidence_bucket_name",
    ).strip()
    allowlist_key = f"smoke/config/{allowlist_sha256}/frozen-vector-allowlist.json"
    _run(
        "aws",
        "s3",
        "cp",
        "--profile",
        args.profile,
        "--region",
        args.region,
        str(ALLOWLIST),
        f"s3://{bucket}/{allowlist_key}",
        "--only-show-errors",
    )

    parameters: dict[str, str] = {}
    fingerprints: dict[str, str] = {}
    with tempfile.TemporaryDirectory(prefix="e-b24-smoke-materials-") as temporary:
        work = Path(temporary)
        ca_key = work / "ca.key"
        ca_cert = work / "ca.crt"
        _run(
            "openssl",
            "genpkey",
            "-algorithm",
            "EC",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-out",
            str(ca_key),
        )
        _run(
            "openssl",
            "req",
            "-x509",
            "-new",
            "-key",
            str(ca_key),
            "-sha256",
            "-days",
            "14",
            "-subj",
            "/CN=E-B24 smoke private CA",
            "-out",
            str(ca_cert),
        )
        material: dict[str, tuple[str, str]] = {
            f"{PARAMETER_ROOT}/pki/ca-cert": (ca_cert.read_text(), "String"),
            f"{PARAMETER_ROOT}/config/evidence-bucket": (bucket, "String"),
            f"{PARAMETER_ROOT}/config/allowlist-key": (allowlist_key, "String"),
        }
        for host in ("smoke-1", "smoke-2", "smoke-3"):
            cert, key = _leaf(
                work=work,
                name=host,
                private_ip=hosts[host]["private_ip"],
                ca_key=ca_key,
                ca_cert=ca_cert,
            )
            material[f"{PARAMETER_ROOT}/pki/{host}-cert"] = (cert.read_text(), "String")
            material[f"{PARAMETER_ROOT}/pki/{host}-key"] = (key.read_text(), "SecureString")
            fingerprints[host] = _certificate_fingerprint(cert)
        for name in (
            "effect-token",
            "gateway-token",
            "receiver-token",
            "keycloak-admin-password",
            "keycloak-db-password",
            "effect-db-password",
        ):
            material[f"{PARAMETER_ROOT}/secrets/{name}"] = (
                secrets.token_hex(32),
                "SecureString",
            )
        for name, (value, kind) in material.items():
            _put_parameter(
                profile=args.profile,
                region=args.region,
                name=name,
                value=value,
                kind=kind,
                work=work,
                expiry=args.expiry,
            )
            parameters[name] = kind

    args.output_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "parameter_root": PARAMETER_ROOT,
        "parameters": parameters,
        "certificate_sha256_fingerprints": fingerprints,
        "ca_certificate_sha256_fingerprint": _certificate_fingerprint(ca_cert)
        if ca_cert.exists()
        else None,
        "allowlist": {
            "sha256": allowlist_sha256,
            "vector_count": 225,
            "s3_key": allowlist_key,
        },
        "expiry": args.expiry,
    }
    # The CA temp file is gone here, so derive its fingerprint from the public
    # parameter value without retaining any key material locally.
    ca_value = _run(
        "aws",
        "ssm",
        "get-parameter",
        "--profile",
        args.profile,
        "--region",
        args.region,
        "--name",
        f"{PARAMETER_ROOT}/pki/ca-cert",
        "--query",
        "Parameter.Value",
        "--output",
        "text",
    )
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as handle:
        handle.write(ca_value)
        ca_public = Path(handle.name)
    try:
        manifest["ca_certificate_sha256_fingerprint"] = _certificate_fingerprint(ca_public)
    finally:
        ca_public.unlink(missing_ok=True)
    path = args.output_dir / "smoke-materials-manifest.json"
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"manifest": str(path), "parameter_count": len(parameters)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
