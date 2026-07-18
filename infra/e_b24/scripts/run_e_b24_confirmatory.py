#!/usr/bin/env python3
"""One-shot, preregistered E-B24 AWS confirmatory orchestrator."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence


REPO_ROOT = Path(__file__).resolve().parents[3]
STRICT = REPO_ROOT / "infra" / "e_b24" / "strict"
PROTOCOL_VERSION = "e-b24-prereg-v1"
DEFAULT_RUN_ID = "eb24-confirmatory-v2-20260717"
RUN_ID = DEFAULT_RUN_ID
BLOCK_COUNT = 30
CLOCK_BOUND_SECONDS = 0.010
TERMINAL = {"Success", "Cancelled", "TimedOut", "Failed", "Cancelling"}
MATERIALS = {
    "outcome-driver": STRICT / "e_b24_outcome_driver.py",
    "receiver-export": STRICT / "e_b24_receiver_export.py",
    "effect-oracle-export": STRICT / "e_b24_effect_oracle_export.py",
    "fault-controller": STRICT / "e_b24_fault_controller.py",
}
RESUME_BLOCK_1 = {
    "pre_clock": "a326926e-e6a0-4091-963e-2c48ef5dea20",
    "normal_phase": "c4206798-59f6-473a-ac84-7a517560837a",
    "normal_receiver_a": "9b9f394c-aa76-4045-a034-06dd15ea6fb0",
    "normal_receiver_b": "2c68340b-ff3f-4866-8df0-77d6d01c36a2",
    "normal_oracle": "0076ce2b-8532-4a67-96d1-29c794838bba",
    "fault_apply": "d28d4808-53ea-49af-a047-d03b2df5ef16",
    "treatment_phase": "1c42d9a2-8b8d-48d5-90e3-dc42abac9768",
    "treatment_receiver_a": "9c2d6d37-08e9-4dba-b3b2-64dc07722056",
    "treatment_receiver_b": "5d5310f7-1e73-403f-86c5-035af92a1462",
    "treatment_oracle": "dda99e25-3a1c-4b91-868b-67025694be2c",
    "fault_clear": "651eddef-dbe6-4041-9c69-38902bea46e8",
}
COMPLETED_BLOCK_1_SHA256 = (
    "4bcaca7a346aa65b40f275fd31e7efd3aca4b213cebc13719b85f48b9a2022a5"
)
RESUME_BLOCK_2 = {
    "pre_clock": "a59927f4-a09b-4fc9-8424-97b89fce4238",
    "fault_apply": "5c9d0690-bcbb-47a9-9f55-ea05388b9f22",
    "treatment_phase": "663d5f1d-4ba2-4e45-a0a3-70b2463b65be",
    "treatment_receiver_a": "48f6c351-66aa-4bdb-b6a8-dfe672166576",
    "treatment_receiver_b": "2cf0fcdd-adc8-40c4-803d-ec31dcbc53e9",
    "treatment_oracle": "02e35ba9-b430-4e43-9001-1b1d98cf71b8",
    "fault_clear": "e2a8e5e4-0ee4-4b91-823d-1f675a5080f0",
    "phase_finished_ns": 1784330158669945565,
}
COMPLETED_REPORT_26_SHA256 = (
    "3fb99189eadd305224948fcc0e535e1a7c47dc80e4c2e5603d0a03119e5ba0f9"
)
RESUME_BLOCK_27 = {
    "pre_clock": "12684c5d-bc1b-4be7-9f48-ace526794709",
    "normal_phase": "f9409b09-6cad-460d-8f66-2edc9727d255",
    "normal_receiver_a": "709d8cfb-7046-4b63-a0f4-7402703f48fa",
    "normal_receiver_b": "87b064b4-75ec-449a-a325-6a158bab243f",
    "normal_oracle": "2d6c2eec-4e5e-4715-bd8e-d120e355d794",
    "cancelled_fault_apply": "f1f4b3d4-14cc-481b-968e-45554caf4ad8",
}


class ConfirmatoryError(RuntimeError):
    pass


def canonical_json(value: object) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run(*command: str) -> str:
    completed = subprocess.run(command, check=True, capture_output=True, text=True)
    return completed.stdout


def _aws_json(profile: str, region: str, *arguments: str) -> Any:
    return json.loads(
        _run(
            "aws",
            *arguments,
            "--profile",
            profile,
            "--region",
            region,
            "--output",
            "json",
        )
    )


def _terraform_output(name: str) -> Any:
    return json.loads(
        _run("terraform", f"-chdir={STRICT}", "output", "-json", name)
    )


def _send_commands(
    *,
    profile: str,
    region: str,
    instance_ids: Sequence[str],
    commands: Sequence[str],
    comment: str,
    timeout: int,
) -> tuple[str, list[dict[str, object]]]:
    request = {
        "DocumentName": "AWS-RunShellScript",
        "InstanceIds": list(instance_ids),
        "Comment": comment,
        "TimeoutSeconds": timeout,
        "MaxConcurrency": str(len(instance_ids)),
        "MaxErrors": "0",
        "Parameters": {
            "commands": list(commands),
            "executionTimeout": [str(timeout)],
        },
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as handle:
        json.dump(request, handle)
        request_path = Path(handle.name)
    try:
        sent = _aws_json(
            profile,
            region,
            "ssm",
            "send-command",
            "--cli-input-json",
            f"file://{request_path}",
        )
    finally:
        request_path.unlink(missing_ok=True)
    command_id = str(sent["Command"]["CommandId"])
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = _aws_json(
            profile,
            region,
            "ssm",
            "list-command-invocations",
            "--command-id",
            command_id,
            "--details",
        )
        invocations = result.get("CommandInvocations", [])
        if len(invocations) == len(instance_ids) and all(
            item.get("Status") in TERMINAL for item in invocations
        ):
            normalized = []
            for item in invocations:
                plugins = item.get("CommandPlugins", [])
                plugin = plugins[0] if plugins else {}
                normalized.append(
                    {
                        "command_id": command_id,
                        "instance_id": item.get("InstanceId"),
                        "status": item.get("Status"),
                        "response_code": plugin.get("ResponseCode"),
                        "output": plugin.get("Output", ""),
                    }
                )
            if any(
                item["status"] != "Success" or item["response_code"] != 0
                for item in normalized
            ):
                raise ConfirmatoryError(f"SSM command failed: {normalized}")
            return command_id, normalized
        time.sleep(2)
    raise TimeoutError(f"SSM command {command_id} exceeded {timeout}s")


def _json_line(output: str, prefix: str | None = None) -> dict[str, object]:
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if prefix is not None:
        lines = [line[len(prefix) :] for line in lines if line.startswith(prefix)]
    if len(lines) != 1:
        raise ConfirmatoryError(
            f"expected one JSON line for prefix={prefix!r}, observed {len(lines)}"
        )
    parsed = json.loads(lines[0])
    if not isinstance(parsed, dict):
        raise ConfirmatoryError("remote evidence line is not a JSON object")
    return parsed


def existing_invocations(
    *, profile: str, region: str, command_id: str
) -> list[dict[str, object]]:
    result = _aws_json(
        profile,
        region,
        "ssm",
        "list-command-invocations",
        "--command-id",
        command_id,
        "--details",
    )
    normalized = []
    for item in result.get("CommandInvocations", []):
        plugins = item.get("CommandPlugins", [])
        plugin = plugins[0] if plugins else {}
        normalized.append(
            {
                "command_id": command_id,
                "instance_id": item.get("InstanceId"),
                "status": item.get("Status"),
                "response_code": plugin.get("ResponseCode"),
                "output": plugin.get("Output", ""),
            }
        )
    if not normalized or any(
        item["status"] != "Success" or item["response_code"] != 0
        for item in normalized
    ):
        raise ConfirmatoryError(f"frozen prior command is unavailable: {command_id}")
    return normalized


def _write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def verify_freeze_manifest(path: Path) -> dict[str, object]:
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if manifest.get("protocol_version") != PROTOCOL_VERSION:
        raise ConfirmatoryError("preregistration manifest version mismatch")
    if manifest.get("run_id") != RUN_ID or manifest.get("block_count") != BLOCK_COUNT:
        raise ConfirmatoryError("preregistration run identity or sample size mismatch")
    for relative, expected in manifest.get("source_sha256", {}).items():
        observed = sha256_file(REPO_ROOT / relative)
        if observed != expected:
            raise ConfirmatoryError(f"frozen source changed: {relative}")
    return manifest


def topology() -> tuple[dict[str, object], dict[str, str]]:
    manifest = _terraform_output("topology_manifest")
    hosts = manifest.get("hosts", {})
    if not isinstance(hosts, dict) or len(hosts) != 16:
        raise ConfirmatoryError("strict topology is not 16 hosts")
    by_name = {name: str(body["instance_id"]) for name, body in hosts.items()}
    required = {
        *(f"gateway-{index}" for index in range(1, 9)),
        "receiver-a",
        "receiver-b",
        "workload-driver",
        "fault-controller",
        "filesystem-effects",
        "postgres-effects",
        "keycloak",
        "keycloak-postgres",
    }
    if set(by_name) != required:
        raise ConfirmatoryError("strict topology host inventory changed")
    return manifest, by_name


def install_frozen_materials(
    *, profile: str, region: str, bucket: str, hosts: Mapping[str, str]
) -> dict[str, object]:
    uploaded = {}
    for name, path in MATERIALS.items():
        digest = sha256_file(path)
        key = f"confirmatory/config/{digest}/{path.name}"
        _run(
            "aws",
            "s3",
            "cp",
            str(path),
            f"s3://{bucket}/{key}",
            "--profile",
            profile,
            "--region",
            region,
            "--sse",
            "AES256",
            "--only-show-errors",
        )
        uploaded[name] = {"sha256": digest, "key": key, "filename": path.name}
    placements = {
        "outcome-driver": ["workload-driver"],
        "receiver-export": ["receiver-a", "receiver-b"],
        "effect-oracle-export": ["gateway-1"],
        "fault-controller": ["fault-controller"],
    }
    deployments = {}
    for name, target_names in placements.items():
        body = uploaded[name]
        destination = f"/etc/e-b24/materials/{body['filename']}"
        command_id, invocations = _send_commands(
            profile=profile,
            region=region,
            instance_ids=[hosts[target] for target in target_names],
            commands=[
                "set -euo pipefail",
                f"aws s3 cp s3://{bucket}/{body['key']} {destination} --only-show-errors",
                f"chmod 0555 {destination}",
                f"echo '{body['sha256']}  {destination}' | sha256sum -c -",
            ],
            comment=f"E-B24 frozen confirmatory material: {name}",
            timeout=180,
        )
        deployments[name] = {"command_id": command_id, "invocations": invocations}
    return {"uploaded": uploaded, "deployments": deployments}


def _clock_snapshot_result(
    *, label: str, command_id: str, invocations: Sequence[Mapping[str, object]]
) -> dict[str, object]:
    offsets = {}
    for item in invocations:
        output = str(item["output"])
        match = re.search(r"System time\s*:\s*([0-9.]+) seconds (fast|slow)", output)
        leap = re.search(r"Leap status\s*:\s*(.+)", output)
        if match is None or leap is None:
            raise ConfirmatoryError("clock snapshot omitted offset or leap status")
        offset = float(match.group(1)) * (1 if match.group(2) == "fast" else -1)
        offsets[str(item["instance_id"])] = {
            "system_time_offset_seconds": offset,
            "leap_status": leap.group(1).strip(),
            "within_bound": abs(offset) <= CLOCK_BOUND_SECONDS
            and leap.group(1).strip() == "Normal",
        }
    return {
        "label": label,
        "command_id": command_id,
        "clock_bound_seconds": CLOCK_BOUND_SECONDS,
        "offsets": offsets,
        "all_within_bound": all(item["within_bound"] for item in offsets.values()),
        "invocations": invocations,
    }


def clock_snapshot(
    *, profile: str, region: str, hosts: Mapping[str, str], label: str
) -> dict[str, object]:
    command_id, invocations = _send_commands(
        profile=profile,
        region=region,
        instance_ids=list(hosts.values()),
        commands=[
            "set -euo pipefail",
            "chronyc tracking",
            "chronyc sources -v",
            "printf 'e-b24-clock-host='; jq -r .host /etc/e-b24/host.json",
        ],
        comment=f"E-B24 frozen clock snapshot: {label}",
        timeout=180,
    )
    return _clock_snapshot_result(
        label=label, command_id=command_id, invocations=invocations
    )


def existing_clock_snapshot(
    *, profile: str, region: str, command_id: str, label: str
) -> dict[str, object]:
    return _clock_snapshot_result(
        label=label,
        command_id=command_id,
        invocations=existing_invocations(
            profile=profile, region=region, command_id=command_id
        ),
    )


def fault(
    *,
    profile: str,
    region: str,
    hosts: Mapping[str, str],
    mode: str,
) -> dict[str, object]:
    command_id, invocations = _send_commands(
        profile=profile,
        region=region,
        instance_ids=[hosts["fault-controller"]],
        commands=[
            "set -euo pipefail",
            (
                "python3 /etc/e-b24/materials/e_b24_fault_controller.py "
                f"--receiver-instance-id {hosts['receiver-b']} --mode {mode}"
            ),
        ],
        comment=f"E-B24 independent frozen fault controller: {mode}",
        timeout=240,
    )
    nested = _json_line(str(invocations[0]["output"]))
    return {"controller_command_id": command_id, "nested": nested}


def run_remote_phase(
    *,
    profile: str,
    region: str,
    bucket: str,
    hosts: Mapping[str, str],
    runtime_image: str,
    block: int,
    phase: str,
    delegation_id: str | None = None,
) -> dict[str, object]:
    phase_dir = (
        f"/var/lib/e-b24/confirmatory/{RUN_ID}/block-{block:02d}/{phase}"
    )
    s3_prefix = f"confirmatory/raw/{RUN_ID}/block-{block:02d}/{phase}/driver"
    add_hosts = " ".join(
        ["--add-host keycloak:10.24.1.20"]
        + [
            f"--add-host gateway-{index}:{ip}"
            for index, ip in enumerate(
                (
                    "10.24.1.11",
                    "10.24.1.12",
                    "10.24.1.13",
                    "10.24.2.11",
                    "10.24.2.12",
                    "10.24.2.13",
                    "10.24.3.11",
                    "10.24.3.12",
                ),
                1,
            )
        ]
    )
    recovery_arg = f" --delegation-id={delegation_id}" if delegation_id else ""
    docker_command = (
        f"docker run --rm --network host {add_hosts} "
        "--mount type=bind,src=/etc/e-b24/materials/e_b24_outcome_driver.py,dst=/run/e-b24/outcome-driver.py,readonly "
        "--mount type=bind,src=/etc/e-b24/materials/frozen-vector-allowlist.json,dst=/run/e-b24/frozen-vector-allowlist.json,readonly "
        "--mount type=bind,src=/etc/e-b24/materials/ca.crt,dst=/run/e-b24/ca.crt,readonly "
        f"--mount type=bind,src={phase_dir},dst=/run/e-b24/output "
        f"{runtime_image} /run/e-b24/outcome-driver.py "
        "--allowlist /run/e-b24/frozen-vector-allowlist.json "
        f"--phase {phase} --block {block} --ca-file /run/e-b24/ca.crt "
        f"--output-dir /run/e-b24/output/result{recovery_arg}"
    )
    command_id, invocations = _send_commands(
        profile=profile,
        region=region,
        instance_ids=[hosts["workload-driver"]],
        commands=[
            "set -euo pipefail",
            f"test ! -e {phase_dir}",
            f"install -d -m 0777 {phase_dir}",
            "set +e",
            f"{docker_command} >{phase_dir}/phase.stdout 2>{phase_dir}/phase.stderr",
            "phase_rc=$?",
            "set -e",
            f"sha256sum {phase_dir}/phase.stdout {phase_dir}/phase.stderr >{phase_dir}/transport-sha256.txt",
            f"aws s3 cp {phase_dir} s3://{bucket}/{s3_prefix}/ --recursive --sse AES256 --only-show-errors",
            f"cat {phase_dir}/phase.stdout",
            "exit ${phase_rc}",
        ],
        comment=f"E-B24 confirmatory block {block:02d} phase {phase}",
        timeout=900,
    )
    phase_summary = _json_line(
        str(invocations[0]["output"]), prefix="e-b24-outcome-phase="
    )
    return {
        "command_id": command_id,
        "invocation": invocations[0],
        "phase_summary": phase_summary,
        "s3_prefix": s3_prefix,
    }


def validate_runtime_output_mount(
    *,
    profile: str,
    region: str,
    hosts: Mapping[str, str],
    runtime_image: str,
) -> dict[str, object]:
    """Exercise only the container bind-mount write path; perform no workload I/O."""
    preflight_dir = f"/var/lib/e-b24/preflight/{RUN_ID}-output-mount"
    marker = f"{preflight_dir}/result/write-ok"
    command_id, invocations = _send_commands(
        profile=profile,
        region=region,
        instance_ids=[hosts["workload-driver"]],
        commands=[
            "set -euo pipefail",
            f"rm -rf {preflight_dir}",
            f"install -d -m 0777 {preflight_dir}",
            (
                "docker run --rm "
                f"--mount type=bind,src={preflight_dir},dst=/run/e-b24/output "
                f"{runtime_image} -c \"from pathlib import Path; "
                "p=Path('/run/e-b24/output/result'); "
                "p.mkdir(parents=True, exist_ok=False); "
                "(p/'write-ok').write_text('ok\\n', encoding='utf-8')\""
            ),
            f"test \"$(cat {marker})\" = ok",
            f"stat -c '%U:%G %a %n' {preflight_dir} {preflight_dir}/result {marker}",
        ],
        comment="E-B24 outcome-blind runtime output-mount preflight",
        timeout=180,
    )
    return {
        "command_id": command_id,
        "invocation": invocations[0],
        "scientific_operations": 0,
    }


def receiver_export(
    *,
    profile: str,
    region: str,
    hosts: Mapping[str, str],
    receiver: str,
    delegation_id: str,
) -> dict[str, object]:
    command_id, invocations = _send_commands(
        profile=profile,
        region=region,
        instance_ids=[hosts[receiver]],
        commands=[
            "set -euo pipefail",
            (
                "python3 /etc/e-b24/materials/e_b24_receiver_export.py "
                "--state-db /var/lib/e-b24/receiver/receiver.sqlite3 "
                "--evidence-jsonl /var/lib/e-b24/receiver/receiver-events.jsonl "
                f"--delegation-id={delegation_id}"
            ),
        ],
        comment=f"E-B24 read-only receiver export: {receiver}",
        timeout=120,
    )
    return {
        "command_id": command_id,
        "evidence": _json_line(str(invocations[0]["output"])),
    }


def effect_oracle(
    *,
    profile: str,
    region: str,
    bucket: str,
    hosts: Mapping[str, str],
    experiment_run: str,
    arm: str,
) -> dict[str, object]:
    oracle_dir = f"/var/lib/e-b24/confirmatory/{RUN_ID}/oracles"
    oracle_file = f"{oracle_dir}/{experiment_run}.json"
    digest_file = f"{oracle_file}.sha256"
    s3_prefix = f"confirmatory/raw/{RUN_ID}/oracles/{experiment_run}"
    jq_filter = (
        "{arm,experiment_run,filesystem:{count:.filesystem.count,"
        "digest_sha256:.filesystem.digest_sha256,effect_type:.filesystem.effect_type,"
        "vector_count:(.filesystem.vector_ids|length)},postgres:{count:.postgres.count,"
        "digest_sha256:.postgres.digest_sha256,effect_type:.postgres.effect_type,"
        "vector_count:(.postgres.vector_ids|length)}}"
    )
    command_id, invocations = _send_commands(
        profile=profile,
        region=region,
        instance_ids=[hosts["gateway-1"]],
        commands=[
            "set -euo pipefail",
            f"install -d -m 0700 {oracle_dir}",
            f"test ! -e {oracle_file}",
            (
                "python3 /etc/e-b24/materials/e_b24_effect_oracle_export.py "
                "--ca-file /etc/e-b24/materials/ca.crt "
                "--token-file /etc/e-b24/materials/effect-token "
                f"--experiment-run {experiment_run} --arm {arm} >{oracle_file}"
            ),
            f"sha256sum {oracle_file} >{digest_file}",
            (
                f"aws s3 cp {oracle_file} s3://{bucket}/{s3_prefix}/oracle.json "
                "--sse AES256 --only-show-errors"
            ),
            (
                f"aws s3 cp {digest_file} s3://{bucket}/{s3_prefix}/oracle.sha256 "
                "--sse AES256 --only-show-errors"
            ),
            (
                "printf 'e-b24-effect-oracle='; "
                f"jq -c '{jq_filter}' {oracle_file}"
            ),
        ],
        comment=f"E-B24 authoritative effect oracle: {experiment_run}",
        timeout=120,
    )
    return {
        "command_id": command_id,
        "evidence": _json_line(
            str(invocations[0]["output"]), prefix="e-b24-effect-oracle="
        ),
        "s3_prefix": s3_prefix,
    }


def phase_evidence(
    *,
    profile: str,
    region: str,
    bucket: str,
    hosts: Mapping[str, str],
    phase_result: Mapping[str, object],
) -> dict[str, object]:
    summary = phase_result["phase_summary"]
    delegation_id = str(summary["delegation_id"])
    return {
        "receiver-a": receiver_export(
            profile=profile,
            region=region,
            hosts=hosts,
            receiver="receiver-a",
            delegation_id=delegation_id,
        ),
        "receiver-b": receiver_export(
            profile=profile,
            region=region,
            hosts=hosts,
            receiver="receiver-b",
            delegation_id=delegation_id,
        ),
        "effect_oracle": effect_oracle(
            profile=profile,
            region=region,
            bucket=bucket,
            hosts=hosts,
            experiment_run=str(summary["experiment_run"]),
            arm=str(summary["phase"]),
        ),
    }


def existing_phase_result(
    *,
    profile: str,
    region: str,
    command_id: str,
    block: int,
    phase: str,
) -> dict[str, object]:
    invocation = existing_invocations(
        profile=profile, region=region, command_id=command_id
    )[0]
    return {
        "command_id": command_id,
        "invocation": invocation,
        "phase_summary": _json_line(
            str(invocation["output"]), prefix="e-b24-outcome-phase="
        ),
        "s3_prefix": (
            f"confirmatory/raw/{RUN_ID}/block-{block:02d}/{phase}/driver"
        ),
        "reconstructed_from_completed_phase": True,
    }


def existing_json_evidence(
    *, profile: str, region: str, command_id: str, prefix: str | None = None
) -> dict[str, object]:
    invocation = existing_invocations(
        profile=profile, region=region, command_id=command_id
    )[0]
    return {
        "command_id": command_id,
        "evidence": _json_line(str(invocation["output"]), prefix=prefix),
        "reconstructed_from_completed_read": True,
    }


def project_receiver_evidence_as_of(
    wrapper: Mapping[str, object], cutoff_ns: int
) -> dict[str, object]:
    projected = json.loads(json.dumps(wrapper))
    evidence = projected["evidence"]
    if not evidence.get("found") or int(evidence["persisted_at_ns"]) > cutoff_ns:
        projected["evidence"] = {
            "delegation_id": evidence.get("delegation_id"),
            "found": False,
        }
    else:
        evidence["ingress_records"] = [
            item
            for item in evidence.get("ingress_records", [])
            if int(item.get("observed_at_ns", 0)) <= cutoff_ns
        ]
        evidence["receipts"] = [
            item
            for item in evidence.get("receipts", [])
            if int(item.get("recorded_at_ns", 0)) <= cutoff_ns
        ]
        enforced_at = evidence.get("enforced_at_ns")
        enforced_by_cutoff = enforced_at is not None and int(enforced_at) <= cutoff_ns
        evidence["status"] = "ENFORCED" if enforced_by_cutoff else "PERSISTED"
        if not enforced_by_cutoff:
            evidence["enforced_at_ns"] = None
            for target in evidence.get("targets", []):
                target["attempts"] = 0
                target["last_error"] = None
    projected["projected_as_of_ns"] = cutoff_ns
    projected["projection_rule"] = "durable_timestamp_lte_phase_finished_ns"
    return projected


def existing_fault_result(
    *, profile: str, region: str, command_id: str
) -> dict[str, object]:
    invocation = existing_invocations(
        profile=profile, region=region, command_id=command_id
    )[0]
    return {
        "controller_command_id": command_id,
        "nested": _json_line(str(invocation["output"])),
        "reconstructed_from_completed_operation": True,
    }


def validate_phase(
    phase: str,
    result: Mapping[str, object],
    evidence: Mapping[str, object],
) -> dict[str, bool]:
    counts = result["phase_summary"]["counts"]
    oracle = evidence["effect_oracle"]["evidence"]
    receivers = {
        name: evidence[name]["evidence"] for name in ("receiver-a", "receiver-b")
    }
    expected = {
        "normal": (0, 0, 0, 0),
        "receiver_gateway_fault": (112, 112, 56, 56),
        "recovery": (0, 0, 0, 0),
    }[phase]
    expected_allowed, expected_committed, expected_fs, expected_pg = expected
    assertions = {
        "driver_has_225_rows": counts["rows"] == 225,
        "driver_allowed_matches": counts["allowed"] == expected_allowed,
        "driver_commits_match": counts["effect_committed_reported"]
        == expected_committed,
        "filesystem_oracle_matches": oracle["filesystem"]["count"] == expected_fs,
        "postgres_oracle_matches": oracle["postgres"]["count"] == expected_pg,
        "receiver_a_persisted": receivers["receiver-a"].get("found") is True,
        "receiver_a_enforced": receivers["receiver-a"].get("status") == "ENFORCED",
        "receiver_a_has_four_receipts": len(receivers["receiver-a"].get("receipts", []))
        == 4,
        "receiver_b_persisted": receivers["receiver-b"].get("found") is True,
        "receiver_b_http_202_recorded": any(
            item.get("http_response") == 202
            for item in receivers["receiver-b"].get("ingress_records", [])
        ),
    }
    if phase == "receiver_gateway_fault":
        assertions.update(
            {
                "receiver_b_remains_persisted": receivers["receiver-b"].get("status")
                == "PERSISTED",
                "receiver_b_has_zero_receipts": len(
                    receivers["receiver-b"].get("receipts", [])
                )
                == 0,
            }
        )
    else:
        assertions.update(
            {
                "receiver_b_enforced": receivers["receiver-b"].get("status")
                == "ENFORCED",
                "receiver_b_has_four_receipts": len(
                    receivers["receiver-b"].get("receipts", [])
                )
                == 4,
            }
        )
    return assertions


def execute(args: argparse.Namespace) -> dict[str, object]:
    freeze = verify_freeze_manifest(args.freeze_manifest)
    identity = _aws_json(args.profile, args.region, "sts", "get-caller-identity")
    if str(identity.get("Account")) != "000000000000":
        raise ConfirmatoryError("unexpected AWS account")
    topology_manifest, hosts = topology()
    runtime_image = str(topology_manifest["runtime_image"])
    if not runtime_image.endswith(
        "@sha256:63703056236d0bba22ad0d8673470469825cb2e27b28c1f5cc208e2b4a271d42"
    ):
        raise ConfirmatoryError("runtime digest changed")
    bucket = str(_terraform_output_from_bootstrap("evidence_bucket_name"))
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=False)
    completed_block_1 = None
    completed_blocks_26 = None
    if args.resume_v2_block2:
        if args.completed_block1_json is None:
            raise ConfirmatoryError("block-2 continuation requires completed block 1")
        if sha256_file(args.completed_block1_json) != COMPLETED_BLOCK_1_SHA256:
            raise ConfirmatoryError("completed block-1 evidence digest changed")
        completed_block_1 = json.loads(
            args.completed_block1_json.read_text(encoding="utf-8")
        )
        if (
            completed_block_1.get("block") != 1
            or completed_block_1.get("categorical_pass") is not True
        ):
            raise ConfirmatoryError("completed block-1 evidence contract failed")
    if args.resume_v2_block27:
        if args.completed_report_json is None:
            raise ConfirmatoryError("block-27 continuation requires completed report")
        if sha256_file(args.completed_report_json) != COMPLETED_REPORT_26_SHA256:
            raise ConfirmatoryError("completed blocks 1-26 report digest changed")
        completed_report = json.loads(
            args.completed_report_json.read_text(encoding="utf-8")
        )
        completed_blocks_26 = completed_report.get("blocks")
        if (
            not isinstance(completed_blocks_26, list)
            or [item.get("block") for item in completed_blocks_26]
            != list(range(1, 27))
            or not all(item.get("categorical_pass") is True for item in completed_blocks_26)
        ):
            raise ConfirmatoryError("completed blocks 1-26 evidence contract failed")
    report: dict[str, object] = {
        "protocol_version": PROTOCOL_VERSION,
        "run_id": RUN_ID,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "aws_identity": identity,
        "freeze_manifest": freeze,
        "topology": topology_manifest,
        "blocks": [],
        "verification_status": "RUNNING",
        "continuation_mode": bool(
            args.resume_v2_block1
            or args.resume_v2_block2
            or args.resume_v2_block27
        ),
        "completed_block1_sha256": (
            COMPLETED_BLOCK_1_SHA256 if completed_block_1 is not None else None
        ),
        "completed_report_26_sha256": (
            COMPLETED_REPORT_26_SHA256 if completed_blocks_26 is not None else None
        ),
    }
    _write(output_dir / "run-report.json", report)
    report["materials"] = install_frozen_materials(
        profile=args.profile,
        region=args.region,
        bucket=bucket,
        hosts=hosts,
    )
    initial_fault = fault(
        profile=args.profile, region=args.region, hosts=hosts, mode="clear"
    )
    report["initial_fault_clear"] = initial_fault
    report["runtime_output_mount_preflight"] = validate_runtime_output_mount(
        profile=args.profile,
        region=args.region,
        hosts=hosts,
        runtime_image=runtime_image,
    )

    try:
        for block in range(1, BLOCK_COUNT + 1):
            if args.resume_v2_block27 and block <= 26:
                assert completed_blocks_26 is not None
                completed_block = completed_blocks_26[block - 1]
                report["blocks"].append(completed_block)
                _write(
                    output_dir / "blocks" / f"block-{block:02d}.json",
                    completed_block,
                )
                _write(output_dir / "run-report.json", report)
                continue
            if args.resume_v2_block2 and block == 1:
                assert completed_block_1 is not None
                report["blocks"].append(completed_block_1)
                _write(output_dir / "blocks" / "block-01.json", completed_block_1)
                _write(output_dir / "run-report.json", report)
                continue
            resuming_block_1 = bool(args.resume_v2_block1 and block == 1)
            resuming_block_2 = bool(args.resume_v2_block2 and block == 2)
            resuming_block_27 = bool(args.resume_v2_block27 and block == 27)
            block_result: dict[str, object] = {
                "block": block,
                "order": (
                    ["normal", "receiver_gateway_fault"]
                    if block % 2 == 1
                    else ["receiver_gateway_fault", "normal"]
                ),
                "pre_clock": (
                    existing_clock_snapshot(
                        profile=args.profile,
                        region=args.region,
                        command_id=RESUME_BLOCK_1["pre_clock"],
                        label="block-01-pre",
                    )
                    if resuming_block_1
                    else existing_clock_snapshot(
                        profile=args.profile,
                        region=args.region,
                        command_id=RESUME_BLOCK_2["pre_clock"],
                        label="block-02-pre",
                    )
                    if resuming_block_2
                    else existing_clock_snapshot(
                        profile=args.profile,
                        region=args.region,
                        command_id=RESUME_BLOCK_27["pre_clock"],
                        label="block-27-pre",
                    )
                    if resuming_block_27
                    else clock_snapshot(
                        profile=args.profile,
                        region=args.region,
                        hosts=hosts,
                        label=f"block-{block:02d}-pre",
                    )
                ),
                "phases": {},
                "continued_without_phase_replay": (
                    resuming_block_1 or resuming_block_2 or resuming_block_27
                ),
            }
            for arm in block_result["order"]:
                if arm == "normal":
                    if resuming_block_1:
                        normal = existing_phase_result(
                            profile=args.profile,
                            region=args.region,
                            command_id=RESUME_BLOCK_1["normal_phase"],
                            block=1,
                            phase="normal",
                        )
                        normal_evidence = {
                            "receiver-a": existing_json_evidence(
                                profile=args.profile,
                                region=args.region,
                                command_id=RESUME_BLOCK_1["normal_receiver_a"],
                            ),
                            "receiver-b": existing_json_evidence(
                                profile=args.profile,
                                region=args.region,
                                command_id=RESUME_BLOCK_1["normal_receiver_b"],
                            ),
                            "effect_oracle": existing_json_evidence(
                                profile=args.profile,
                                region=args.region,
                                command_id=RESUME_BLOCK_1["normal_oracle"],
                            ),
                        }
                    elif resuming_block_27:
                        normal = existing_phase_result(
                            profile=args.profile,
                            region=args.region,
                            command_id=RESUME_BLOCK_27["normal_phase"],
                            block=27,
                            phase="normal",
                        )
                        normal_evidence = {
                            "receiver-a": existing_json_evidence(
                                profile=args.profile,
                                region=args.region,
                                command_id=RESUME_BLOCK_27["normal_receiver_a"],
                            ),
                            "receiver-b": existing_json_evidence(
                                profile=args.profile,
                                region=args.region,
                                command_id=RESUME_BLOCK_27["normal_receiver_b"],
                            ),
                            "effect_oracle": existing_json_evidence(
                                profile=args.profile,
                                region=args.region,
                                command_id=RESUME_BLOCK_27["normal_oracle"],
                                prefix="e-b24-effect-oracle=",
                            ),
                        }
                    else:
                        normal = run_remote_phase(
                            profile=args.profile,
                            region=args.region,
                            bucket=bucket,
                            hosts=hosts,
                            runtime_image=runtime_image,
                            block=block,
                            phase="normal",
                        )
                        normal_evidence = phase_evidence(
                            profile=args.profile,
                            region=args.region,
                            bucket=bucket,
                            hosts=hosts,
                            phase_result=normal,
                        )
                    block_result["phases"]["normal"] = {
                        "result": normal,
                        "evidence": normal_evidence,
                        "assertions": validate_phase("normal", normal, normal_evidence),
                    }
                else:
                    if resuming_block_1:
                        applied = existing_fault_result(
                            profile=args.profile,
                            region=args.region,
                            command_id=RESUME_BLOCK_1["fault_apply"],
                        )
                        treatment = existing_phase_result(
                            profile=args.profile,
                            region=args.region,
                            command_id=RESUME_BLOCK_1["treatment_phase"],
                            block=1,
                            phase="receiver_gateway_fault",
                        )
                        treatment_evidence = {
                            "receiver-a": existing_json_evidence(
                                profile=args.profile,
                                region=args.region,
                                command_id=RESUME_BLOCK_1["treatment_receiver_a"],
                            ),
                            "receiver-b": existing_json_evidence(
                                profile=args.profile,
                                region=args.region,
                                command_id=RESUME_BLOCK_1["treatment_receiver_b"],
                            ),
                            "effect_oracle": existing_json_evidence(
                                profile=args.profile,
                                region=args.region,
                                command_id=RESUME_BLOCK_1["treatment_oracle"],
                                prefix="e-b24-effect-oracle=",
                            ),
                        }
                    elif resuming_block_2:
                        applied = existing_fault_result(
                            profile=args.profile,
                            region=args.region,
                            command_id=RESUME_BLOCK_2["fault_apply"],
                        )
                        treatment = existing_phase_result(
                            profile=args.profile,
                            region=args.region,
                            command_id=RESUME_BLOCK_2["treatment_phase"],
                            block=2,
                            phase="receiver_gateway_fault",
                        )
                        treatment_evidence = {
                            "receiver-a": project_receiver_evidence_as_of(
                                existing_json_evidence(
                                    profile=args.profile,
                                    region=args.region,
                                    command_id=RESUME_BLOCK_2[
                                        "treatment_receiver_a"
                                    ],
                                ),
                                int(RESUME_BLOCK_2["phase_finished_ns"]),
                            ),
                            "receiver-b": project_receiver_evidence_as_of(
                                existing_json_evidence(
                                    profile=args.profile,
                                    region=args.region,
                                    command_id=RESUME_BLOCK_2[
                                        "treatment_receiver_b"
                                    ],
                                ),
                                int(RESUME_BLOCK_2["phase_finished_ns"]),
                            ),
                            "effect_oracle": existing_json_evidence(
                                profile=args.profile,
                                region=args.region,
                                command_id=RESUME_BLOCK_2["treatment_oracle"],
                                prefix="e-b24-effect-oracle=",
                            ),
                        }
                    else:
                        applied = fault(
                            profile=args.profile,
                            region=args.region,
                            hosts=hosts,
                            mode="apply",
                        )
                        treatment = run_remote_phase(
                            profile=args.profile,
                            region=args.region,
                            bucket=bucket,
                            hosts=hosts,
                            runtime_image=runtime_image,
                            block=block,
                            phase="receiver_gateway_fault",
                        )
                        treatment_evidence = phase_evidence(
                            profile=args.profile,
                            region=args.region,
                            bucket=bucket,
                            hosts=hosts,
                            phase_result=treatment,
                        )
                    treatment_assertions = validate_phase(
                        "receiver_gateway_fault", treatment, treatment_evidence
                    )
                    cleared = (
                        existing_fault_result(
                            profile=args.profile,
                            region=args.region,
                            command_id=RESUME_BLOCK_1["fault_clear"],
                        )
                        if resuming_block_1
                        else existing_fault_result(
                            profile=args.profile,
                            region=args.region,
                            command_id=RESUME_BLOCK_2["fault_clear"],
                        )
                        if resuming_block_2
                        else fault(
                            profile=args.profile,
                            region=args.region,
                            hosts=hosts,
                            mode="clear",
                        )
                    )
                    recovery = run_remote_phase(
                        profile=args.profile,
                        region=args.region,
                        bucket=bucket,
                        hosts=hosts,
                        runtime_image=runtime_image,
                        block=block,
                        phase="recovery",
                        delegation_id=str(
                            treatment["phase_summary"]["delegation_id"]
                        ),
                    )
                    recovery_evidence = phase_evidence(
                        profile=args.profile,
                        region=args.region,
                        bucket=bucket,
                        hosts=hosts,
                        phase_result=recovery,
                    )
                    block_result["phases"]["receiver_gateway_fault"] = {
                        "fault_apply": applied,
                        "result": treatment,
                        "evidence": treatment_evidence,
                        "assertions": treatment_assertions,
                    }
                    block_result["phases"]["recovery"] = {
                        "fault_clear": cleared,
                        "result": recovery,
                        "evidence": recovery_evidence,
                        "assertions": validate_phase(
                            "recovery", recovery, recovery_evidence
                        ),
                    }
            block_result["post_clock"] = clock_snapshot(
                profile=args.profile,
                region=args.region,
                hosts=hosts,
                label=f"block-{block:02d}-post",
            )
            block_result["categorical_pass"] = all(
                all(phase["assertions"].values())
                for phase in block_result["phases"].values()
            )
            block_result["latency_clock_valid"] = bool(
                block_result["pre_clock"]["all_within_bound"]
                and block_result["post_clock"]["all_within_bound"]
            )
            report["blocks"].append(block_result)
            _write(output_dir / "blocks" / f"block-{block:02d}.json", block_result)
            _write(output_dir / "run-report.json", report)
        report["verification_status"] = "VERIFIED"
        report["categorical_pass"] = all(
            bool(block["categorical_pass"]) for block in report["blocks"]
        )
        report["latency_valid_blocks"] = sum(
            int(block["latency_clock_valid"]) for block in report["blocks"]
        )
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        _write(output_dir / "run-report.json", report)
        _run(
            "aws",
            "s3",
            "cp",
            str(output_dir),
            f"s3://{bucket}/confirmatory/assembled/{RUN_ID}/",
            "--recursive",
            "--sse",
            "AES256",
            "--profile",
            args.profile,
            "--region",
            args.region,
            "--only-show-errors",
        )
        return report
    except BaseException as error:
        report["verification_status"] = "ABORTED"
        report["error"] = f"{type(error).__name__}: {error}"
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        _write(output_dir / "run-report.json", report)
        try:
            fault(profile=args.profile, region=args.region, hosts=hosts, mode="clear")
        finally:
            _run(
                "aws",
                "s3",
                "cp",
                str(output_dir),
                f"s3://{bucket}/confirmatory/assembled/{RUN_ID}/",
                "--recursive",
                "--sse",
                "AES256",
                "--profile",
                args.profile,
                "--region",
                args.region,
                "--only-show-errors",
            )
        raise


def _terraform_output_from_bootstrap(name: str) -> Any:
    directory = REPO_ROOT / "infra" / "e_b24" / "bootstrap"
    return json.loads(
        _run("terraform", f"-chdir={directory}", "output", "-json", name)
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", required=True)
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--run-id", default=DEFAULT_RUN_ID)
    parser.add_argument("--freeze-manifest", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--resume-v2-block1", action="store_true")
    parser.add_argument("--resume-v2-block2", action="store_true")
    parser.add_argument("--completed-block1-json", type=Path)
    parser.add_argument("--resume-v2-block27", action="store_true")
    parser.add_argument("--completed-report-json", type=Path)
    return parser.parse_args()


def main() -> int:
    global RUN_ID
    args = parse_args()
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,79}", args.run_id):
        raise ConfirmatoryError("run ID must be a lowercase S3/path-safe identifier")
    RUN_ID = args.run_id
    freeze = verify_freeze_manifest(args.freeze_manifest)
    topology_manifest, _ = topology()
    if not args.execute:
        print(
            canonical_json(
                {
                    "protocol_version": PROTOCOL_VERSION,
                    "run_id": RUN_ID,
                    "block_count": BLOCK_COUNT,
                    "freeze_manifest_sha256": sha256_file(args.freeze_manifest),
                    "runtime_image": topology_manifest["runtime_image"],
                    "validated": True,
                    "freeze": freeze,
                }
            )
        )
        return 0
    report = execute(args)
    print(
        canonical_json(
            {
                "verification_status": report["verification_status"],
                "categorical_pass": report["categorical_pass"],
                "blocks": len(report["blocks"]),
                "output_dir": str(args.output_dir.resolve()),
            }
        )
    )
    return 0 if report["categorical_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
