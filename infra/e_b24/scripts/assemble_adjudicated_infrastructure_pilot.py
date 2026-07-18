#!/usr/bin/env python3
"""Assemble and validate the adjudicated E-B24 infrastructure pilot report."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _run_json(*command: str) -> Any:
    completed = subprocess.run(command, check=True, capture_output=True, text=True)
    return json.loads(completed.stdout)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _invocation(
    *, profile: str, region: str, command_id: str, instance_id: str
) -> dict[str, Any]:
    return _run_json(
        "aws",
        "ssm",
        "get-command-invocation",
        "--profile",
        profile,
        "--region",
        region,
        "--command-id",
        command_id,
        "--instance-id",
        instance_id,
        "--output",
        "json",
    )


def _healthy_target_group(*, profile: str, region: str, name: str) -> bool:
    groups = _run_json(
        "aws",
        "elbv2",
        "describe-target-groups",
        "--profile",
        profile,
        "--region",
        region,
        "--names",
        name,
        "--output",
        "json",
    )
    arn = groups["TargetGroups"][0]["TargetGroupArn"]
    health = _run_json(
        "aws",
        "elbv2",
        "describe-target-health",
        "--profile",
        profile,
        "--region",
        region,
        "--target-group-arn",
        arn,
        "--output",
        "json",
    )
    descriptions = health.get("TargetHealthDescriptions", [])
    return len(descriptions) == 1 and descriptions[0]["TargetHealth"]["State"] == "healthy"


def _success(invocation: dict[str, Any], marker: str) -> bool:
    return (
        invocation.get("Status") == "Success"
        and invocation.get("ResponseCode") == 0
        and marker in invocation.get("StandardOutputContent", "")
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--terraform-dir", type=Path, required=True)
    parser.add_argument("--readiness-report", type=Path, required=True)
    parser.add_argument("--service-report", type=Path, required=True)
    parser.add_argument("--readiness-diagnostic-command", required=True)
    parser.add_argument("--source-pilot-command", required=True)
    parser.add_argument("--private-continuation-command", required=True)
    parser.add_argument("--keycloak-alb-command", required=True)
    parser.add_argument("--receiver-gateway-command", required=True)
    parser.add_argument("--gateway-effect-command", required=True)
    parser.add_argument("--driver-data-plane-command", required=True)
    parser.add_argument("--base-pilot-source", type=Path, required=True)
    parser.add_argument("--private-continuation-source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    topology = _run_json(
        "terraform",
        f"-chdir={args.terraform_dir}",
        "output",
        "-json",
        "topology_manifest",
    )
    hosts = topology["hosts"]
    readiness = json.loads(args.readiness_report.read_text(encoding="utf-8"))
    services = json.loads(args.service_report.read_text(encoding="utf-8"))

    invocations = {
        "readiness_diagnostic": _invocation(
            profile=args.profile,
            region=args.region,
            command_id=args.readiness_diagnostic_command,
            instance_id=hosts["gateway-4"]["instance_id"],
        ),
        "source_pilot": _invocation(
            profile=args.profile,
            region=args.region,
            command_id=args.source_pilot_command,
            instance_id=hosts["workload-driver"]["instance_id"],
        ),
        "private_continuation": _invocation(
            profile=args.profile,
            region=args.region,
            command_id=args.private_continuation_command,
            instance_id=hosts["workload-driver"]["instance_id"],
        ),
        "keycloak_alb": _invocation(
            profile=args.profile,
            region=args.region,
            command_id=args.keycloak_alb_command,
            instance_id=hosts["keycloak"]["instance_id"],
        ),
        "receiver_gateway": _invocation(
            profile=args.profile,
            region=args.region,
            command_id=args.receiver_gateway_command,
            instance_id=hosts["receiver-a"]["instance_id"],
        ),
        "gateway_effect": _invocation(
            profile=args.profile,
            region=args.region,
            command_id=args.gateway_effect_command,
            instance_id=hosts["gateway-1"]["instance_id"],
        ),
        "driver_data_plane": _invocation(
            profile=args.profile,
            region=args.region,
            command_id=args.driver_data_plane_command,
            instance_id=hosts["workload-driver"]["instance_id"],
        ),
    }

    readiness_diag_output = invocations["readiness_diagnostic"].get(
        "StandardOutputContent", ""
    )
    source_error = invocations["source_pilot"].get("StandardErrorContent", "")
    continuation_error = invocations["private_continuation"].get(
        "StandardErrorContent", ""
    )
    receiver_gateway_output = invocations["receiver_gateway"].get(
        "StandardOutputContent", ""
    )
    driver_output = invocations["driver_data_plane"].get(
        "StandardOutputContent", ""
    )
    assertions = {
        "strict_topology_has_sixteen_hosts": len(hosts) == 16,
        "readiness_adjudication_is_sixteen_of_sixteen": readiness.get(
            "host_readiness_gate", {}
        ).get("ready_host_count")
        == 15
        and _success(invocations["readiness_diagnostic"], "Leap status     : Normal")
        and "docker_socket_status=0" in readiness_diag_output,
        "all_five_service_waves_succeeded": services.get("failed") is False
        and len(services.get("waves", [])) == 5
        and services.get("readiness_adjudication", {}).get("passed") is True,
        "receiver_a_stream_and_exact_url_precede_expected_alb_path_block": (
            invocations["source_pilot"].get("Status") == "Failed"
            and 'infrastructure-pilot.py", line 173' in source_error
            and "urlopen error timed out" in source_error
        ),
        "receiver_b_stream_and_exact_url_precede_expected_control_path_block": (
            invocations["private_continuation"].get("Status") == "Failed"
            and 'infrastructure_pilot_private_continuation.py", line 121'
            in continuation_error
            and "urlopen error timed out" in continuation_error
        ),
        "keycloak_reaches_both_alb_routes": _success(
            invocations["keycloak_alb"], "keycloak-alb-health=passed"
        )
        and invocations["keycloak_alb"].get("StandardOutputContent", "").count(
            '{"status":"ok"}'
        )
        == 2,
        "receiver_reaches_all_eight_gateway_controls": _success(
            invocations["receiver_gateway"],
            "receiver-gateway-control-health=passed",
        )
        and all(
            f'"gateway_id":"gateway-{index}"' in receiver_gateway_output
            for index in range(1, 9)
        ),
        "gateway_reaches_both_effect_services": _success(
            invocations["gateway_effect"], "gateway-effect-health=passed"
        )
        and invocations["gateway_effect"].get("StandardOutputContent", "").count(
            '{"status":"ok"}'
        )
        == 2,
        "driver_reaches_both_receivers": _success(
            invocations["driver_data_plane"], "driver-data-plane-health=passed"
        )
        and driver_output.count('{"status":"ok"}') == 2,
        "driver_reaches_all_eight_gateway_mcp_endpoints": all(
            f"gateway-{index}-mcp-http=" in driver_output
            and f"gateway-{index}-mcp-http=000" not in driver_output
            for index in range(1, 9)
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
    passed = all(assertions.values())
    report = {
        "experiment": "E-B24 strict outcome-blind infrastructure pilot",
        "verification_status": "VERIFIED" if passed else "FAILED",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "passed": passed,
        "claim_boundary": (
            "Infrastructure qualification only. No logout/revocation, workload "
            "replay, gateway treatment contrast, Filesystem mutation, or PostgreSQL "
            "mutation was executed or observed."
        ),
        "deviations": [
            "One readiness grep pipeline returned exit 141 under pipefail; the same host passed an independent read-only diagnostic.",
            "Public ALB health was checked from Keycloak because ingress is intentionally Keycloak-EIP-only.",
            "Gateway control health was checked from a receiver because the driver is intentionally limited to MCP port 8000.",
            "Stream success is bound to content-addressed control flow reaching the subsequent expected blocked health call.",
        ],
        "source_sha256": {
            "readiness_report": _sha256(args.readiness_report),
            "service_report": _sha256(args.service_report),
            "base_pilot": _sha256(args.base_pilot_source),
            "private_continuation": _sha256(args.private_continuation_source),
        },
        "command_ids": {
            "readiness_diagnostic": args.readiness_diagnostic_command,
            "source_pilot": args.source_pilot_command,
            "private_continuation": args.private_continuation_command,
            "keycloak_alb": args.keycloak_alb_command,
            "receiver_gateway": args.receiver_gateway_command,
            "gateway_effect": args.gateway_effect_command,
            "driver_data_plane": args.driver_data_plane_command,
        },
        "assertions": assertions,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps({"output": str(args.output), "passed": passed}))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
