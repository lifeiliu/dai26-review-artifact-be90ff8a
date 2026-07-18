#!/usr/bin/env python3
"""Freeze one clean E-B24 reproduction after infrastructure qualification."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
STRICT = REPO_ROOT / "infra" / "e_b24" / "strict"
ALLOWLIST = (
    REPO_ROOT
    / "artifact"
    / "data"
    / "run_2026_07_16_e_b24_local_real_effect_gate"
    / "frozen-vector-allowlist.json"
)
SOURCE_FILES = (
    "artifact/data/run_2026_07_16_e_b24_local_real_effect_gate/frozen-vector-allowlist.json",
    "infra/e_b24/scripts/run_e_b24_confirmatory.py",
    "infra/e_b24/strict/cloud-init.yaml.tftpl",
    "infra/e_b24/strict/e_b24_effect_oracle_export.py",
    "infra/e_b24/strict/e_b24_fault_controller.py",
    "infra/e_b24/strict/e_b24_outcome_driver.py",
    "infra/e_b24/strict/e_b24_receiver_export.py",
    "infra/e_b24/strict/infrastructure_pilot.py",
    "infra/e_b24/strict/main.tf",
    "infra/e_b24/strict/outputs.tf",
    "infra/e_b24/strict/service-bootstrap.sh",
    "infra/e_b24/strict/variables.tf",
)


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def terraform_output(name: str) -> object:
    output = subprocess.run(
        ["terraform", f"-chdir={STRICT}", "output", "-json", name],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return json.loads(output)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--materials-manifest", type=Path, required=True)
    parser.add_argument("--bootstrap-report", type=Path, required=True)
    parser.add_argument("--clean-pilot", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    materials = json.loads(args.materials_manifest.read_text(encoding="utf-8"))
    bootstrap = json.loads(args.bootstrap_report.read_text(encoding="utf-8"))
    pilot = json.loads(args.clean_pilot.read_text(encoding="utf-8"))
    if materials["allowlist"]["sha256"] != sha256_file(ALLOWLIST):
        raise RuntimeError("reproduction allowlist differs from E-B24")
    if bootstrap.get("failed") is not False or bootstrap.get("host_count") != 16:
        raise RuntimeError("reproduction bootstrap did not pass 16 hosts")
    if pilot.get("passed") is not True or not all(pilot.get("assertions", {}).values()):
        raise RuntimeError("reproduction clean infrastructure pilot did not pass")

    topology = terraform_output("topology_manifest")
    hosts = topology.get("hosts", {})
    if len(hosts) != 16:
        raise RuntimeError("reproduction topology is not 16 hosts")
    gateway_placement: dict[str, list[str]] = {}
    for name, body in hosts.items():
        if str(name).startswith("gateway-"):
            gateway_placement.setdefault(str(body["zone_id"]), []).append(str(name))
    for names in gateway_placement.values():
        names.sort()

    manifest = {
        "protocol_version": "e-b24-prereg-v1",
        "run_id": args.run_id,
        "verification_status": "PRE-EXECUTION-FROZEN",
        "frozen_at": datetime.now(timezone.utc).isoformat(),
        "block_count": 30,
        "clock_bound_seconds": 0.01,
        "execution_attempt": 1,
        "reproduction_of": "eb24-confirmatory-v2-20260717",
        "continuation": None,
        "completed_phases_replayed": False,
        "runtime_image_digest": str(topology["runtime_image"]).rsplit("@", 1)[1],
        "inherited_configuration": {
            "risk_index_changed": False,
            "target_policy_changed": False,
            "target_membership_changed": False,
            "mutation_labels_changed": False,
            "target_fraction": 0.2,
            "effect_threshold": 0.3,
        },
        "physical_assignment": {
            "rule": "zero_based_vector_index_mod_8_plus_1",
            "receiver-a": {
                "gateways": [1, 2, 3, 4],
                "vectors": 113,
                "filesystem": 56,
                "postgres": 57,
            },
            "receiver-b": {
                "gateways": [5, 6, 7, 8],
                "vectors": 112,
                "filesystem": 56,
                "postgres": 56,
            },
        },
        "source_sha256": {
            relative: sha256_file(REPO_ROOT / relative) for relative in SOURCE_FILES
        },
        "material_sha256": {
            "allowlist": sha256_file(ALLOWLIST),
            "strict_materials_manifest": sha256_file(args.materials_manifest),
            "strict_service_bootstrap_report": sha256_file(args.bootstrap_report),
            "clean_infrastructure_pilot": sha256_file(args.clean_pilot),
            "topology_manifest_canonical": hashlib.sha256(
                canonical_json(topology).encode()
            ).hexdigest(),
            "experiment_ca_fingerprint": materials["ca_certificate_sha256_fingerprint"],
            "push_alb_leaf_fingerprint": materials["certificate_sha256_fingerprints"]["push-alb"],
            "keycloak_realm": materials["keycloak_realm"]["sha256"],
        },
        "topology": {
            "region": topology["region"],
            "ami_id": topology["ami_id"],
            "host_count": len(hosts),
            "instances": {name: body["instance_id"] for name, body in hosts.items()},
            "gateway_placement": gateway_placement,
            "push_alb_dns_name": topology["push_front_door"]["alb_dns_name"],
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        canonical_json(
            {
                "output": str(args.output),
                "run_id": args.run_id,
                "sha256": sha256_file(args.output),
                "source_count": len(SOURCE_FILES),
            }
        )
    )


if __name__ == "__main__":
    main()
