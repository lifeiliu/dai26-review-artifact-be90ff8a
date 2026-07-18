#!/usr/bin/env python3
"""Continue E-B24 service waves after an explicit readiness adjudication.

This does not retry or rewrite the failed readiness command. It accepts only the
observed 15/16 + exit-141 pattern and an independent successful diagnostic for
the same host, then runs the unchanged dependency waves once.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from bootstrap_strict_services import _aws_json, _run_wave, _terraform_output


REQUIRED_DIAGNOSTIC_SNIPPETS = (
    "status: done",
    "/usr/bin/docker",
    "Docker version",
    "active",
    "docker_socket_status=0",
    "server=",
    "Leap status     : Normal",
)


def _write_report(path: Path, report: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _source_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _adjudicate(
    *,
    profile: str,
    region: str,
    source: dict[str, Any],
    diagnostic_command_id: str,
) -> dict[str, Any]:
    gate = source.get("host_readiness_gate", {})
    failed_hosts = [
        host
        for host in gate.get("hosts", [])
        if host.get("status") != "Success" or host.get("response_code") != 0
    ]
    if not source.get("failed") or source.get("waves") != []:
        raise RuntimeError("source report is not a stopped pre-wave readiness run")
    if gate.get("ready_host_count") != 15 or len(failed_hosts) != 1:
        raise RuntimeError("source report is not the approved 15/16 pattern")
    failed_host = failed_hosts[0]
    if failed_host.get("response_code") != 141:
        raise RuntimeError("failed host did not have the approved exit-141 pattern")
    if "status: done" not in failed_host.get("output", ""):
        raise RuntimeError("failed command did not establish cloud-init done")

    body = _aws_json(
        profile,
        region,
        "ssm",
        "list-command-invocations",
        "--command-id",
        diagnostic_command_id,
        "--details",
    )
    invocations = body.get("CommandInvocations", [])
    if len(invocations) != 1:
        raise RuntimeError("diagnostic command must have exactly one invocation")
    invocation = invocations[0]
    plugins = invocation.get("CommandPlugins") or [{}]
    plugin = plugins[0]
    if invocation.get("InstanceId") != failed_host.get("instance_id"):
        raise RuntimeError("diagnostic targeted a different host")
    if invocation.get("Status") != "Success" or plugin.get("ResponseCode") != 0:
        raise RuntimeError("diagnostic command was not successful")
    output = str(plugin.get("Output", ""))
    missing = [item for item in REQUIRED_DIAGNOSTIC_SNIPPETS if item not in output]
    if missing:
        raise RuntimeError(f"diagnostic is missing readiness evidence: {missing}")

    return {
        "passed": True,
        "decision": "approved false-negative continuation",
        "basis": "15 original readiness successes plus one independent read-only diagnostic success",
        "original_readiness_command_id": gate.get("command_id"),
        "diagnostic_command_id": diagnostic_command_id,
        "adjudicated_host": failed_host.get("host"),
        "adjudicated_instance_id": failed_host.get("instance_id"),
        "original_response_code": failed_host.get("response_code"),
        "required_diagnostic_snippets": list(REQUIRED_DIAGNOSTIC_SNIPPETS),
        "diagnostic_output": output,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--source-report", type=Path, required=True)
    parser.add_argument("--diagnostic-command-id", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=900)
    args = parser.parse_args()

    source = json.loads(args.source_report.read_text(encoding="utf-8"))
    topology = _terraform_output("topology_manifest")
    hosts = topology.get("hosts", {})
    if len(hosts) != 16:
        raise RuntimeError(f"strict topology is not fully applied: {len(hosts)} hosts")
    by_name = {name: str(body["instance_id"]) for name, body in hosts.items()}
    source_ids = {
        str(host["instance_id"])
        for host in source.get("host_readiness_gate", {}).get("hosts", [])
    }
    if source_ids != set(by_name.values()):
        raise RuntimeError("current topology does not match the stopped readiness run")

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
        "implementation_version": "strict-bootstrap-v2-adjudicated-continuation",
        "source_report": str(args.source_report),
        "source_report_sha256": _source_sha256(args.source_report),
        "topology_stage": topology.get("protocol_stage"),
        "host_count": len(hosts),
        "waves": [],
        "claim_boundary": "Outcome-blind infrastructure continuation only; not a paper result.",
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    report_path = args.output_dir / "strict-service-bootstrap-adjudicated.json"
    try:
        report["readiness_adjudication"] = _adjudicate(
            profile=args.profile,
            region=args.region,
            source=source,
            diagnostic_command_id=args.diagnostic_command_id,
        )
        _write_report(report_path, report)
        for wave_name, names in waves:
            result = _run_wave(
                profile=args.profile,
                region=args.region,
                name=wave_name,
                instance_ids=[by_name[name] for name in names],
                timeout=args.timeout_seconds,
            )
            report["waves"].append(result)
            _write_report(report_path, report)
    except Exception as error:
        report["failed"] = True
        report["error"] = f"{type(error).__name__}: {error}"
        _write_report(report_path, report)
        raise

    report["failed"] = False
    _write_report(report_path, report)
    print(json.dumps({"report": str(report_path), "waves": len(report["waves"])}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
