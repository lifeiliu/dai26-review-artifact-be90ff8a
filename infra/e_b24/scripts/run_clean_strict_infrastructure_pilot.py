#!/usr/bin/env python3
"""Run one role-correct, outcome-blind E-B24 strict infrastructure pilot.

The runner sends each read-only check from a host whose strict security-group
role permits that path. It never retries a failed command and never emits a
revocation event, invokes an MCP tool, or requests an effect mutation.
"""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[3]
STRICT = REPO_ROOT / "infra" / "e_b24" / "strict"
TERMINAL = {"Success", "Cancelled", "TimedOut", "Failed", "Cancelling"}
IMPLEMENTATION_VERSION = "strict-clean-pilot-v1-role-correct"
SIGPIPE_SAFE_BOOTSTRAP_VERSIONS = frozenset(
    {
        "strict-bootstrap-v3-no-sigpipe",
        "strict-bootstrap-v4-keycloak-360s",
        "strict-bootstrap-v5-bounded-package-retry",
    }
)


class PilotGateError(RuntimeError):
    """Fail-closed pilot error with the partial result preserved on disk."""


def _is_sigpipe_safe_bootstrap(version: Any) -> bool:
    """Accept only audited bootstrap versions that retain the SIGPIPE fix."""

    return isinstance(version, str) and version in SIGPIPE_SAFE_BOOTSTRAP_VERSIONS


def _run(*command: str) -> str:
    completed = subprocess.run(command, check=True, capture_output=True, text=True)
    return completed.stdout


def _run_json(*command: str) -> Any:
    return json.loads(_run(*command))


def _terraform_output(directory: Path, name: str) -> Any:
    return _run_json("terraform", f"-chdir={directory}", "output", "-json", name)


def _aws_json(profile: str, region: str, *arguments: str) -> Any:
    return _run_json(
        "aws",
        *arguments,
        "--profile",
        profile,
        "--region",
        region,
        "--output",
        "json",
    )


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


def _wait_command(
    *, profile: str, region: str, command_id: str, timeout: int
) -> dict[str, Any]:
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
        if len(invocations) == 1 and invocations[0].get("Status") in TERMINAL:
            item = invocations[0]
            plugin = (item.get("CommandPlugins") or [{}])[0]
            return {
                "command_id": command_id,
                "instance_id": item.get("InstanceId"),
                "status": item.get("Status"),
                "status_details": item.get("StatusDetails"),
                "response_code": plugin.get("ResponseCode"),
                "output": plugin.get("Output", ""),
            }
        if time.monotonic() >= deadline:
            raise TimeoutError(f"SSM command {command_id} did not finish within {timeout}s")
        time.sleep(5)


def _role_commands(receiver_urls: dict[str, str]) -> dict[str, list[str]]:
    receiver_a = shlex.quote(receiver_urls["receiver-a"])
    receiver_b = shlex.quote(receiver_urls["receiver-b"])
    materials = "/etc/e-b24/materials"
    return {
        "driver": [
            "set -euo pipefail",
            (
                f"python3 {materials}/infrastructure-pilot.py "
                "--keycloak-url https://keycloak:8443 "
                f"--receiver-a-url {receiver_a} "
                f"--receiver-b-url {receiver_b} "
                f"--ca-file {materials}/ca.crt "
                f"--keycloak-admin-password-file {materials}/keycloak-admin-password "
                f"--receiver-a-token-file {materials}/receiver-a-token "
                f"--receiver-b-token-file {materials}/receiver-b-token "
                "--output /var/tmp/e-b24-clean-driver-pilot.json"
            ),
            "printf 'driver-role-check=passed\\n'",
        ],
        "keycloak": [
            "set -euo pipefail",
            f"curl --silent --show-error --fail --cacert {materials}/ca.crt {shlex.quote(receiver_urls['receiver-a'].rsplit('/events', 1)[0] + '/health')}",
            "printf '\\n'",
            f"curl --silent --show-error --fail --cacert {materials}/ca.crt {shlex.quote(receiver_urls['receiver-b'].rsplit('/events', 1)[0] + '/health')}",
            "printf '\\nkeycloak-alb-health=passed\\n'",
        ],
        "receiver": [
            "set -euo pipefail",
            (
                f"for index in $(seq 1 8); do curl --silent --show-error --fail "
                f"--cacert {materials}/ca.crt https://gateway-${{index}}:9444/health; "
                "printf '\\n'; done"
            ),
            "printf 'receiver-gateway-control-health=passed\\n'",
        ],
        "gateway": [
            "set -euo pipefail",
            f"curl --silent --show-error --fail --cacert {materials}/ca.crt https://filesystem-effects:9443/health",
            "printf '\\n'",
            f"curl --silent --show-error --fail --cacert {materials}/ca.crt https://postgres-effects:9443/health",
            "printf '\\ngateway-effect-health=passed\\n'",
        ],
    }


def _run_role(
    *,
    profile: str,
    region: str,
    role: str,
    instance_id: str,
    commands: list[str],
    timeout: int,
) -> dict[str, Any]:
    request = {
        "DocumentName": "AWS-RunShellScript",
        "InstanceIds": [instance_id],
        "Comment": f"E-B24 clean outcome-blind pilot role check: {role}",
        "TimeoutSeconds": timeout,
        "Parameters": {"commands": commands, "executionTimeout": [str(timeout)]},
    }
    command_id = _send_command_request(profile=profile, region=region, request=request)
    result = _wait_command(
        profile=profile,
        region=region,
        command_id=command_id,
        timeout=timeout,
    )
    return result


def _healthy_target_group(*, profile: str, region: str, name: str) -> bool:
    groups = _aws_json(
        profile,
        region,
        "elbv2",
        "describe-target-groups",
        "--names",
        name,
    )
    arn = groups["TargetGroups"][0]["TargetGroupArn"]
    health = _aws_json(
        profile,
        region,
        "elbv2",
        "describe-target-health",
        "--target-group-arn",
        arn,
    )
    descriptions = health.get("TargetHealthDescriptions", [])
    return (
        len(descriptions) == 1
        and descriptions[0].get("TargetHealth", {}).get("State") == "healthy"
    )


def _wait_target_groups_healthy(
    *, profile: str, region: str, timeout: int
) -> dict[str, Any]:
    started = time.monotonic()
    deadline = started + timeout
    names = ("paper-b-eb24-recv-a", "paper-b-eb24-recv-b")
    while True:
        health = {
            name: _healthy_target_group(profile=profile, region=region, name=name)
            for name in names
        }
        if all(health.values()):
            return {
                "passed": True,
                "target_groups": health,
                "elapsed_seconds": round(time.monotonic() - started, 3),
            }
        if time.monotonic() >= deadline:
            raise PilotGateError(
                f"ALB target readiness did not converge within {timeout}s: {health}"
            )
        time.sleep(5)


def _driver_report(output: str) -> dict[str, Any]:
    prefix = "e-b24-driver-report="
    matches = [line[len(prefix) :] for line in output.splitlines() if line.startswith(prefix)]
    if len(matches) != 1:
        raise PilotGateError("driver output did not contain exactly one sanitized report")
    parsed = json.loads(matches[0])
    if not isinstance(parsed, dict):
        raise PilotGateError("driver report was not a JSON object")
    return parsed


def _write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--terraform-dir", type=Path, default=STRICT)
    parser.add_argument("--bootstrap-report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=900)
    args = parser.parse_args()

    topology = _terraform_output(args.terraform_dir, "topology_manifest")
    receiver_urls = _terraform_output(args.terraform_dir, "push_receiver_urls")
    hosts = topology.get("hosts", {})
    bootstrap = json.loads(args.bootstrap_report.read_text(encoding="utf-8"))
    bootstrap_assertions = {
        "strict_topology_has_sixteen_hosts": len(hosts) == 16,
        "ssm_online_gate_is_sixteen_of_sixteen": bootstrap.get(
            "ssm_online_gate", {}
        ).get("online_host_count")
        == 16,
        "readiness_gate_is_clean_sixteen_of_sixteen": bootstrap.get(
            "host_readiness_gate", {}
        ).get("ready_host_count")
        == 16
        and bootstrap.get("host_readiness_gate", {}).get("passed") is True,
        "all_five_service_waves_succeeded": bootstrap.get("failed") is False
        and len(bootstrap.get("waves", [])) == 5,
        "sigpipe_safe_bootstrap_version_used": _is_sigpipe_safe_bootstrap(
            bootstrap.get("implementation_version")
        ),
    }
    if not all(bootstrap_assertions.values()):
        raise PilotGateError(f"bootstrap report failed clean-pilot gate: {bootstrap_assertions}")

    report: dict[str, Any] = {
        "experiment": "E-B24 clean strict outcome-blind infrastructure pilot",
        "implementation_version": IMPLEMENTATION_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "verification_status": "RUNNING",
        "passed": False,
        "claim_boundary": (
            "Infrastructure qualification only. No revocation event, workload replay, "
            "MCP tool invocation, gateway treatment contrast, Filesystem mutation, or "
            "PostgreSQL mutation is authorized or observed."
        ),
        "bootstrap_assertions": bootstrap_assertions,
        "alb_target_readiness": {},
        "role_checks": {},
        "assertions": {},
    }
    _write_report(args.output, report)

    by_name = {name: str(body["instance_id"]) for name, body in hosts.items()}
    commands = _role_commands(receiver_urls)
    role_hosts = {
        "driver": "workload-driver",
        "keycloak": "keycloak",
        "receiver": "receiver-a",
        "gateway": "gateway-1",
    }
    try:
        report["alb_target_readiness"] = _wait_target_groups_healthy(
            profile=args.profile,
            region=args.region,
            timeout=args.timeout_seconds,
        )
        _write_report(args.output, report)
        for role in ("driver", "keycloak", "receiver", "gateway"):
            report["role_checks"][role] = _run_role(
                profile=args.profile,
                region=args.region,
                role=role,
                instance_id=by_name[role_hosts[role]],
                commands=commands[role],
                timeout=args.timeout_seconds,
            )
            _write_report(args.output, report)
            result = report["role_checks"][role]
            if result["status"] != "Success" or result["response_code"] != 0:
                raise PilotGateError(f"{role} role check failed: {result}")

        driver = _driver_report(report["role_checks"]["driver"]["output"])
        keycloak_output = report["role_checks"]["keycloak"]["output"]
        receiver_output = report["role_checks"]["receiver"]["output"]
        gateway_output = report["role_checks"]["gateway"]["output"]
        assertions = {
            **bootstrap_assertions,
            "driver_role_assertions_pass": all(driver.get("assertions", {}).values()),
            "keycloak_reaches_both_alb_routes": (
                "keycloak-alb-health=passed" in keycloak_output
                and keycloak_output.count('{"status":"ok"}') == 2
            ),
            "receiver_reaches_all_eight_gateway_controls": (
                "receiver-gateway-control-health=passed" in receiver_output
                and all(
                    f'"gateway_id":"gateway-{index}"' in receiver_output
                    for index in range(1, 9)
                )
            ),
            "gateway_reaches_both_effect_services": (
                "gateway-effect-health=passed" in gateway_output
                and gateway_output.count('{"status":"ok"}') == 2
            ),
            "both_alb_targets_are_healthy": _healthy_target_group(
                profile=args.profile,
                region=args.region,
                name="paper-b-eb24-recv-a",
            )
            and _healthy_target_group(
                profile=args.profile,
                region=args.region,
                name="paper-b-eb24-recv-b",
            ),
        }
        report["driver_report"] = driver
        report["assertions"] = assertions
        report["passed"] = all(assertions.values())
        report["verification_status"] = "VERIFIED" if report["passed"] else "FAILED"
        if not report["passed"]:
            raise PilotGateError(f"clean pilot assertions failed: {assertions}")
    except Exception as error:
        report["verification_status"] = "FAILED"
        report["error"] = f"{type(error).__name__}: {error}"
        _write_report(args.output, report)
        raise

    _write_report(args.output, report)
    print(json.dumps({"output": str(args.output), "passed": True}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
