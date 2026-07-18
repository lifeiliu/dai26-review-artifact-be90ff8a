#!/usr/bin/env python3
"""Qualify E-B24 hosts, then start strict services through SSM Run Command.

The script never retries a failed command. It records each command result and
stops before launching dependent roles when a wave fails.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[3]
STRICT = REPO_ROOT / "infra" / "e_b24" / "strict"
PARAMETER_ROOT = "/paper-b/e-b24/strict"
TERMINAL = {"Success", "Cancelled", "TimedOut", "Failed", "Cancelling"}
IMPLEMENTATION_VERSION = "strict-bootstrap-v5-bounded-package-retry"


class InfrastructureGateError(RuntimeError):
    """Fail-closed infrastructure gate carrying its auditable result."""

    def __init__(self, stage: str, message: str, result: dict[str, Any]) -> None:
        super().__init__(message)
        self.stage = stage
        self.result = result


def _run(*command: str) -> str:
    completed = subprocess.run(command, check=True, capture_output=True, text=True)
    return completed.stdout


def _terraform_output(name: str) -> Any:
    return json.loads(_run("terraform", f"-chdir={STRICT}", "output", "-json", name))


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


def _wait_wave(
    *, profile: str, region: str, command_id: str, expected: int, timeout: int
) -> list[dict[str, Any]]:
    deadline = time.monotonic() + timeout
    while True:
        body = _aws_json(
            profile,
            region,
            "ssm",
            "list-command-invocations",
            "--command-id",
            command_id,
            "--details",
        )
        invocations = body.get("CommandInvocations", [])
        if len(invocations) == expected and all(
            item.get("Status") in TERMINAL for item in invocations
        ):
            return invocations
        if time.monotonic() >= deadline:
            raise TimeoutError(f"SSM command {command_id} did not finish within {timeout}s")
        time.sleep(5)


def _send_command_request(
    *, profile: str, region: str, request: dict[str, Any]
) -> str:
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
    return str(sent["Command"]["CommandId"])


def _wait_ssm_online(
    *,
    profile: str,
    region: str,
    instance_ids: list[str],
    timeout: int,
) -> dict[str, Any]:
    expected = set(instance_ids)
    started = time.monotonic()
    deadline = started + timeout
    last_online: set[str] = set()
    filters = json.dumps([{"Key": "InstanceIds", "Values": sorted(expected)}])
    while True:
        body = _aws_json(
            profile,
            region,
            "ssm",
            "describe-instance-information",
            "--filters",
            filters,
        )
        last_online = {
            str(item["InstanceId"])
            for item in body.get("InstanceInformationList", [])
            if item.get("PingStatus") == "Online"
        }
        if last_online == expected:
            return {
                "passed": True,
                "expected_host_count": len(expected),
                "online_host_count": len(last_online),
                "instance_ids": sorted(last_online),
                "elapsed_seconds": round(time.monotonic() - started, 3),
            }
        if time.monotonic() >= deadline:
            result = {
                "passed": False,
                "expected_host_count": len(expected),
                "online_host_count": len(last_online),
                "online_instance_ids": sorted(last_online),
                "missing_instance_ids": sorted(expected - last_online),
                "elapsed_seconds": round(time.monotonic() - started, 3),
            }
            raise InfrastructureGateError(
                "ssm_online_gate",
                f"SSM did not report 16/16 hosts Online within {timeout}s",
                result,
            )
        time.sleep(5)


def _run_host_readiness_gate(
    *,
    profile: str,
    region: str,
    by_name: dict[str, str],
    timeout: int,
) -> dict[str, Any]:
    commands = [
        "set -euo pipefail",
        "cloud-init status --wait --long",
        "cloud_init_status=$(cloud-init status --long)",
        "printf '%s\\n' \"$cloud_init_status\"",
        "case \"$cloud_init_status\" in *'status: done'*) ;; *) exit 1 ;; esac",
        "command -v docker",
        "docker --version",
        "systemctl is-active --quiet docker",
        "test -S /var/run/docker.sock",
        "docker info --format 'server={{.ServerVersion}}'",
        "chrony_status=$(chronyc tracking)",
        "printf '%s\\n' \"$chrony_status\"",
        "case \"$chrony_status\" in *'Leap status'*'Normal'*) ;; *) exit 1 ;; esac",
        "printf 'e-b24-readiness=passed\\n'",
    ]
    ordered_names = sorted(by_name)
    request = {
        "DocumentName": "AWS-RunShellScript",
        "InstanceIds": [by_name[name] for name in ordered_names],
        "Comment": "E-B24 strict pilot 16-of-16 host readiness gate",
        "TimeoutSeconds": timeout,
        "Parameters": {"commands": commands, "executionTimeout": [str(timeout)]},
    }
    command_id = _send_command_request(
        profile=profile, region=region, request=request
    )
    invocations = _wait_wave(
        profile=profile,
        region=region,
        command_id=command_id,
        expected=len(by_name),
        timeout=timeout,
    )
    name_by_id = {instance_id: name for name, instance_id in by_name.items()}
    summaries: list[dict[str, Any]] = []
    for item in invocations:
        plugins = item.get("CommandPlugins") or [{}]
        plugin = plugins[0]
        instance_id = str(item.get("InstanceId"))
        summaries.append(
            {
                "host": name_by_id.get(instance_id, "unknown"),
                "instance_id": instance_id,
                "status": item.get("Status"),
                "status_details": item.get("StatusDetails"),
                "response_code": plugin.get("ResponseCode"),
                "output": plugin.get("Output", ""),
            }
        )
    summaries.sort(key=lambda item: item["host"])
    passed = len(summaries) == 16 and all(
        item["status"] == "Success" and item["response_code"] == 0
        for item in summaries
    )
    result = {
        "passed": passed,
        "command_id": command_id,
        "expected_host_count": 16,
        "ready_host_count": sum(
            item["status"] == "Success" and item["response_code"] == 0
            for item in summaries
        ),
        "contract": [
            "cloud-init status is done",
            "Docker CLI exists",
            "Docker daemon is active and its socket responds",
            "chrony leap status is Normal",
        ],
        "hosts": summaries,
    }
    if not passed:
        raise InfrastructureGateError(
            "host_readiness_gate",
            f"strict host readiness failed: {result['ready_host_count']}/16 passed",
            result,
        )
    return result


def _run_wave(
    *,
    profile: str,
    region: str,
    name: str,
    instance_ids: list[str],
    timeout: int,
) -> dict[str, Any]:
    commands = [
        "set -euo pipefail",
        f"region={region}",
        f"parameter_root={PARAMETER_ROOT}",
        'bucket=$(aws ssm get-parameter --region "$region" --name "$parameter_root/config/evidence-bucket" --query Parameter.Value --output text)',
        'key=$(aws ssm get-parameter --region "$region" --name "$parameter_root/config/service-bootstrap-key" --query Parameter.Value --output text)',
        'expected=$(basename "$(dirname "$key")")',
        'aws s3 cp --region "$region" --only-show-errors "s3://$bucket/$key" /var/tmp/e-b24-strict-service-bootstrap.sh',
        'observed=$(sha256sum /var/tmp/e-b24-strict-service-bootstrap.sh | awk \'{print $1}\')',
        'test "$observed" = "$expected"',
        "chmod 0700 /var/tmp/e-b24-strict-service-bootstrap.sh",
        'AWS_REGION="$region" /var/tmp/e-b24-strict-service-bootstrap.sh',
    ]
    request = {
        "DocumentName": "AWS-RunShellScript",
        "InstanceIds": instance_ids,
        "Comment": f"E-B24 strict pilot service bootstrap wave: {name}",
        "TimeoutSeconds": timeout,
        "Parameters": {"commands": commands, "executionTimeout": [str(timeout)]},
    }
    command_id = _send_command_request(
        profile=profile, region=region, request=request
    )
    invocations = _wait_wave(
        profile=profile,
        region=region,
        command_id=command_id,
        expected=len(instance_ids),
        timeout=timeout,
    )
    summary = [
        {
            "instance_id": item.get("InstanceId"),
            "status": item.get("Status"),
            "status_details": item.get("StatusDetails"),
            "response_code": (
                item.get("CommandPlugins", [{}])[0].get("ResponseCode")
                if item.get("CommandPlugins")
                else None
            ),
        }
        for item in invocations
    ]
    if any(item["status"] != "Success" for item in summary):
        raise RuntimeError(f"strict service bootstrap wave {name} failed: {summary}")
    return {"wave": name, "command_id": command_id, "invocations": summary}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=900)
    args = parser.parse_args()

    topology = _terraform_output("topology_manifest")
    hosts = topology.get("hosts", {})
    if len(hosts) != 16:
        raise RuntimeError(f"strict topology is not fully applied: observed {len(hosts)} hosts")
    by_name = {name: str(body["instance_id"]) for name, body in hosts.items()}
    waves = [
        (
            "state-and-effect-services",
            ["keycloak-postgres", "filesystem-effects", "postgres-effects"],
        ),
        ("eight-gateways", [f"gateway-{index}" for index in range(1, 9)]),
        ("keycloak", ["keycloak"]),
        ("durable-receivers", ["receiver-a", "receiver-b"]),
        ("controllers", ["workload-driver", "fault-controller"]),
    ]
    report: dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "implementation_version": IMPLEMENTATION_VERSION,
        "topology_stage": topology.get("protocol_stage"),
        "host_count": len(hosts),
        "waves": [],
        "claim_boundary": "Outcome-blind infrastructure bootstrap only; not a paper result.",
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    report_path = args.output_dir / "strict-service-bootstrap.json"
    try:
        report["ssm_online_gate"] = _wait_ssm_online(
            profile=args.profile,
            region=args.region,
            instance_ids=list(by_name.values()),
            timeout=args.timeout_seconds,
        )
        report_path.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        report["host_readiness_gate"] = _run_host_readiness_gate(
            profile=args.profile,
            region=args.region,
            by_name=by_name,
            timeout=args.timeout_seconds,
        )
        report_path.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        for wave_name, names in waves:
            result = _run_wave(
                profile=args.profile,
                region=args.region,
                name=wave_name,
                instance_ids=[by_name[name] for name in names],
                timeout=args.timeout_seconds,
            )
            report["waves"].append(result)
            report_path.write_text(
                json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
    except InfrastructureGateError as error:
        report[error.stage] = error.result
        report["failed"] = True
        report["error"] = f"{type(error).__name__}: {error}"
        report_path.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        raise
    except Exception as error:
        report["failed"] = True
        report["error"] = f"{type(error).__name__}: {error}"
        report_path.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        raise

    report["failed"] = False
    report_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps({"report": str(report_path), "waves": len(report["waves"])}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
