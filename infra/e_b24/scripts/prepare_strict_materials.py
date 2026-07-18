#!/usr/bin/env python3
"""Prepare ephemeral PKI and SSM material for the E-B24 strict pilot.

Run only after the front-door bootstrap plan has been checked and applied. The
script imports one short-lived ALB certificate into ACM, stores service keys in
SSM SecureString parameters, and deletes all local private material with its
temporary directory.
"""

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
STRICT = REPO_ROOT / "infra" / "e_b24" / "strict"
ALLOWLIST = (
    REPO_ROOT
    / "artifact"
    / "data"
    / "run_2026_07_16_e_b24_local_real_effect_gate"
    / "frozen-vector-allowlist.json"
)
KEYCLOAK_REALM_TEMPLATE = (
    REPO_ROOT
    / "artifact"
    / "experiments"
    / "e_b22_keycloak_gateway_gate"
    / "realm-e-b22.json"
)
SERVICE_BOOTSTRAP = REPO_ROOT / "infra" / "e_b24" / "strict" / "service-bootstrap.sh"
INFRASTRUCTURE_PILOT = REPO_ROOT / "infra" / "e_b24" / "strict" / "infrastructure_pilot.py"
EXPECTED_ALLOWLIST_SHA256 = "9e76d237213e899486bfd65fad817cedd500cd0820535aa8e953519a24b8e9b2"
PARAMETER_ROOT = "/paper-b/e-b24/strict"
HOSTS = {
    "gateway-1": "10.24.1.11",
    "gateway-2": "10.24.1.12",
    "gateway-3": "10.24.1.13",
    "gateway-4": "10.24.2.11",
    "gateway-5": "10.24.2.12",
    "gateway-6": "10.24.2.13",
    "gateway-7": "10.24.3.11",
    "gateway-8": "10.24.3.12",
    "keycloak": "10.24.1.20",
    "keycloak-postgres": "10.24.2.20",
    "receiver-a": "10.24.1.21",
    "receiver-b": "10.24.3.20",
    "filesystem-effects": "10.24.2.21",
    "postgres-effects": "10.24.3.21",
    "workload-driver": "10.24.1.22",
    "fault-controller": "10.24.2.22",
}


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
    request = work / "put-parameter.json"
    request.write_text(
        json.dumps(
            {
                "Name": name,
                "Value": value,
                "Type": kind,
                "Overwrite": True,
                "Tier": "Standard",
                "DataType": "text",
            }
        ),
        encoding="utf-8",
    )
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
        "Key=Stage,Value=pilot",
        f"Key=Expiry,Value={expiry}",
    )


def _certificate_fingerprint(path: Path) -> str:
    output = _run(
        "openssl", "x509", "-in", str(path), "-noout", "-fingerprint", "-sha256"
    ).strip()
    return output.split("=", 1)[1].replace(":", "").lower()


def _leaf(
    *,
    work: Path,
    name: str,
    dns_names: list[str],
    ip_addresses: list[str],
    ca_key: Path,
    ca_cert: Path,
) -> tuple[Path, Path]:
    key = work / f"{name}.key"
    csr = work / f"{name}.csr"
    cert = work / f"{name}.crt"
    extensions = work / f"{name}.ext"
    sans = [*(f"DNS:{value}" for value in dns_names), *(f"IP:{value}" for value in ip_addresses)]
    extensions.write_text(
        "basicConstraints=CA:FALSE\n"
        "keyUsage=digitalSignature\n"
        "extendedKeyUsage=serverAuth,clientAuth\n"
        f"subjectAltName={','.join(sans)}\n",
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
    _run("openssl", "req", "-new", "-key", str(key), "-subj", f"/CN={dns_names[0]}", "-out", str(csr))
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


def _import_alb_certificate(
    *,
    profile: str,
    region: str,
    cert: Path,
    key: Path,
    ca_cert: Path,
    expiry: str,
) -> str:
    body = json.loads(
        _run(
            "aws",
            "acm",
            "import-certificate",
            "--profile",
            profile,
            "--region",
            region,
            "--certificate",
            f"fileb://{cert}",
            "--private-key",
            f"fileb://{key}",
            "--certificate-chain",
            f"fileb://{ca_cert}",
            "--tags",
            "Key=Project,Value=paper-b-e-b24",
            "Key=Stage,Value=pilot",
            f"Key=Expiry,Value={expiry}",
        )
    )
    arn = body.get("CertificateArn")
    if not isinstance(arn, str) or ":acm:" not in arn:
        raise RuntimeError("ACM did not return a certificate ARN")
    return arn


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

    alb_dns_name = _terraform_output(STRICT, "push_alb_dns_name")
    if not isinstance(alb_dns_name, str) or not alb_dns_name.endswith(".elb.amazonaws.com"):
        raise RuntimeError("strict front-door bootstrap has no expected AWS ALB DNS output")
    bucket = _terraform_output(BOOTSTRAP, "evidence_bucket_name")
    allowlist_key = f"pilot/config/{allowlist_sha256}/frozen-vector-allowlist.json"
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

    realm = json.loads(KEYCLOAK_REALM_TEMPLATE.read_text(encoding="utf-8"))
    receiver_urls = {
        "receiver-a": f"https://{alb_dns_name}:443/events",
        "receiver-b": f"https://{alb_dns_name}:8443/events",
    }
    clients = {client.get("clientId"): client for client in realm.get("clients", [])}
    if set(receiver_urls) - set(clients):
        raise RuntimeError("Keycloak realm template lost a strict receiver client")
    for client_id, endpoint in receiver_urls.items():
        clients[client_id].setdefault("attributes", {})["ssf.validPushUrls"] = endpoint
    realm_bytes = (json.dumps(realm, indent=2, sort_keys=True) + "\n").encode("utf-8")
    realm_sha256 = hashlib.sha256(realm_bytes).hexdigest()
    realm_key = f"pilot/config/{realm_sha256}/keycloak-realm.json"
    with tempfile.NamedTemporaryFile(mode="wb", delete=False) as handle:
        handle.write(realm_bytes)
        realm_path = Path(handle.name)
    try:
        _run(
            "aws",
            "s3",
            "cp",
            "--profile",
            args.profile,
            "--region",
            args.region,
            str(realm_path),
            f"s3://{bucket}/{realm_key}",
            "--only-show-errors",
        )
    finally:
        realm_path.unlink(missing_ok=True)

    service_bootstrap_sha256 = hashlib.sha256(SERVICE_BOOTSTRAP.read_bytes()).hexdigest()
    service_bootstrap_key = f"pilot/config/{service_bootstrap_sha256}/service-bootstrap.sh"
    _run(
        "aws",
        "s3",
        "cp",
        "--profile",
        args.profile,
        "--region",
        args.region,
        str(SERVICE_BOOTSTRAP),
        f"s3://{bucket}/{service_bootstrap_key}",
        "--only-show-errors",
    )
    infrastructure_pilot_sha256 = hashlib.sha256(INFRASTRUCTURE_PILOT.read_bytes()).hexdigest()
    infrastructure_pilot_key = f"pilot/config/{infrastructure_pilot_sha256}/infrastructure-pilot.py"
    _run(
        "aws",
        "s3",
        "cp",
        "--profile",
        args.profile,
        "--region",
        args.region,
        str(INFRASTRUCTURE_PILOT),
        f"s3://{bucket}/{infrastructure_pilot_key}",
        "--only-show-errors",
    )

    parameters: dict[str, str] = {}
    fingerprints: dict[str, str] = {}
    with tempfile.TemporaryDirectory(prefix="e-b24-strict-materials-") as temporary:
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
            "/CN=E-B24 strict pilot private CA",
            "-out",
            str(ca_cert),
        )
        ca_fingerprint = _certificate_fingerprint(ca_cert)

        alb_cert, alb_key = _leaf(
            work=work,
            name="push-alb",
            dns_names=[alb_dns_name],
            ip_addresses=[],
            ca_key=ca_key,
            ca_cert=ca_cert,
        )
        acm_arn = _import_alb_certificate(
            profile=args.profile,
            region=args.region,
            cert=alb_cert,
            key=alb_key,
            ca_cert=ca_cert,
            expiry=args.expiry,
        )
        fingerprints["push-alb"] = _certificate_fingerprint(alb_cert)

        material: dict[str, tuple[str, str]] = {
            f"{PARAMETER_ROOT}/pki/ca-cert": (ca_cert.read_text(), "String"),
            f"{PARAMETER_ROOT}/config/evidence-bucket": (str(bucket), "String"),
            f"{PARAMETER_ROOT}/config/allowlist-key": (allowlist_key, "String"),
            f"{PARAMETER_ROOT}/config/keycloak-realm-key": (realm_key, "String"),
            f"{PARAMETER_ROOT}/config/service-bootstrap-key": (service_bootstrap_key, "String"),
            f"{PARAMETER_ROOT}/config/infrastructure-pilot-key": (
                infrastructure_pilot_key,
                "String",
            ),
            f"{PARAMETER_ROOT}/config/push-alb-dns-name": (alb_dns_name, "String"),
            f"{PARAMETER_ROOT}/config/receiver-a-url": (receiver_urls["receiver-a"], "String"),
            f"{PARAMETER_ROOT}/config/receiver-b-url": (receiver_urls["receiver-b"], "String"),
        }
        for host, private_ip in HOSTS.items():
            cert, key = _leaf(
                work=work,
                name=host,
                dns_names=[host, f"{host}.e-b24.internal"],
                ip_addresses=[private_ip],
                ca_key=ca_key,
                ca_cert=ca_cert,
            )
            material[f"{PARAMETER_ROOT}/pki/{host}-cert"] = (cert.read_text(), "String")
            material[f"{PARAMETER_ROOT}/pki/{host}-key"] = (key.read_text(), "SecureString")
            fingerprints[host] = _certificate_fingerprint(cert)

        for name in (
            "effect-token",
            "gateway-token",
            "receiver-a-token",
            "receiver-b-token",
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
        "ca_certificate_sha256_fingerprint": ca_fingerprint,
        "acm_certificate_arn": acm_arn,
        "push_alb_dns_name": alb_dns_name,
        "receiver_urls": {
            "receiver-a": receiver_urls["receiver-a"],
            "receiver-b": receiver_urls["receiver-b"],
        },
        "keycloak_realm": {"sha256": realm_sha256, "s3_key": realm_key},
        "service_bootstrap": {
            "sha256": service_bootstrap_sha256,
            "s3_key": service_bootstrap_key,
        },
        "infrastructure_pilot": {
            "sha256": infrastructure_pilot_sha256,
            "s3_key": infrastructure_pilot_key,
        },
        "allowlist": {
            "sha256": allowlist_sha256,
            "vector_count": 225,
            "s3_key": allowlist_key,
        },
        "expiry": args.expiry,
        "private_material_retained_locally": False,
    }
    path = args.output_dir / "strict-materials-manifest.json"
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "manifest": str(path),
                "parameter_count": len(parameters),
                "acm_certificate_arn": acm_arn,
                "private_material_retained_locally": False,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
