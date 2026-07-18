#!/usr/bin/env python3
"""Collect and sanitize the E-B24 three-host qualification evidence."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[3]
BOOTSTRAP = REPO_ROOT / "infra" / "e_b24" / "bootstrap"
SMOKE = REPO_ROOT / "infra" / "e_b24" / "smoke"


def _run(*command: str) -> str:
    return subprocess.run(command, check=True, capture_output=True, text=True).stdout


def _json(*command: str) -> Any:
    return json.loads(_run(*command))


def _sanitize(value: Any, replacements: dict[str, str]) -> Any:
    if isinstance(value, str):
        for source, target in replacements.items():
            value = value.replace(source, target)
        return value
    if isinstance(value, list):
        return [_sanitize(item, replacements) for item in value]
    if isinstance(value, dict):
        return {key: _sanitize(item, replacements) for key, item in value.items()}
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--bootstrap-command", required=True)
    parser.add_argument("--image-command", required=True)
    parser.add_argument("--auth-command", required=True)
    parser.add_argument("--nft-command", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    topology = _json(
        "terraform",
        f"-chdir={SMOKE}",
        "output",
        "-json",
        "topology_manifest",
    )
    account_id = _run(
        "aws",
        "sts",
        "get-caller-identity",
        "--profile",
        args.profile,
        "--query",
        "Account",
        "--output",
        "text",
    ).strip()
    instance_to_host = {
        body["instance_id"]: host for host, body in topology["hosts"].items()
    }
    replacements = {account_id: "<account-id>", **instance_to_host}

    runtime_image = topology.pop("runtime_image")
    topology["runtime_image"] = "paper-b-e-b24/runtime@" + runtime_image.split("@", 1)[1]
    for body in topology["hosts"].values():
        body.pop("instance_id", None)

    commands: dict[str, Any] = {}
    for label, command_id in {
        "bootstrap": args.bootstrap_command,
        "runtime_image": args.image_command,
        "credential_cleanup": args.auth_command,
        "nftables_control": args.nft_command,
    }.items():
        invocations = _json(
            "aws",
            "ssm",
            "list-command-invocations",
            "--profile",
            args.profile,
            "--region",
            args.region,
            "--command-id",
            command_id,
            "--details",
            "--output",
            "json",
        )["CommandInvocations"]
        commands[label] = [
            {
                "host": instance_to_host[item["InstanceId"]],
                "status": item["Status"],
                "response_code": item["CommandPlugins"][0]["ResponseCode"],
                "output": item["CommandPlugins"][0].get("Output", ""),
            }
            for item in invocations
        ]

    now = dt.datetime.now(dt.timezone.utc)
    evidence = _sanitize(
        {
            "experiment": "E-B24 three-host infrastructure qualification",
            "claim_boundary": (
                "Infrastructure-only: no Keycloak SET, receiver-to-gateway TLS, "
                "real effect, or paper outcome was executed."
            ),
            "generated_at": now.isoformat(),
            "topology": topology,
            "commands": commands,
        },
        replacements,
    )
    if any(
        invocation["status"] != "Success" or invocation["response_code"] != 0
        for invocations in commands.values()
        for invocation in invocations
    ):
        raise RuntimeError("one or more qualification commands did not succeed")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    evidence_path = args.output_dir / "host-qualification.json"
    evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    digest = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
    manifest_path = args.output_dir / "SHA256SUMS"
    manifest_path.write_text(f"{digest}  {evidence_path.name}\n")

    bucket = _run(
        "terraform",
        f"-chdir={BOOTSTRAP}",
        "output",
        "-raw",
        "evidence_bucket_name",
    ).strip()
    prefix = now.strftime("smoke/host-qualification/%Y%m%dT%H%M%SZ")
    for path in (evidence_path, manifest_path):
        subprocess.run(
            [
                "aws",
                "s3",
                "cp",
                "--profile",
                args.profile,
                "--region",
                args.region,
                str(path),
                f"s3://{bucket}/{prefix}/{path.name}",
                "--only-show-errors",
            ],
            check=True,
        )
    print(json.dumps({"sha256": digest, "s3_prefix": prefix}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
