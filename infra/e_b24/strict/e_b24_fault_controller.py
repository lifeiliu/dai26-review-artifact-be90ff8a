#!/usr/bin/env python3
"""Independent controller for the frozen receiver-B-to-gateway packet fault."""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any


TERMINAL = {"Success", "Cancelled", "TimedOut", "Failed", "Cancelling"}
GATEWAY_IPS = (
    "10.24.1.11",
    "10.24.1.12",
    "10.24.1.13",
    "10.24.2.11",
    "10.24.2.12",
    "10.24.2.13",
    "10.24.3.11",
    "10.24.3.12",
)


def _aws_json(*arguments: str) -> Any:
    completed = subprocess.run(
        ["aws", *arguments, "--region", "us-east-1", "--output", "json"],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(completed.stdout)


def _commands(mode: str) -> list[str]:
    if mode == "apply":
        addresses = ", ".join(GATEWAY_IPS)
        return [
            "set -euo pipefail",
            "nft delete table inet e_b24_rx_fault 2>/dev/null || true",
            "nft add table inet e_b24_rx_fault",
            "nft 'add chain inet e_b24_rx_fault output { type filter hook output priority -100; policy accept; }'",
            f"nft 'add rule inet e_b24_rx_fault output ip daddr {{ {addresses} }} tcp dport 9444 counter drop'",
            "nft -a list table inet e_b24_rx_fault",
        ]
    if mode == "clear":
        return [
            "set -euo pipefail",
            "nft delete table inet e_b24_rx_fault 2>/dev/null || true",
            "if nft list table inet e_b24_rx_fault >/dev/null 2>&1; then exit 1; fi",
            "printf 'e-b24-receiver-gateway-fault=cleared\\n'",
        ]
    if mode == "status":
        return [
            "if nft list table inet e_b24_rx_fault; then exit 0; fi",
            "printf 'e-b24-receiver-gateway-fault=absent\\n'",
        ]
    raise ValueError(mode)


def run_fault(instance_id: str, mode: str, timeout: int) -> dict[str, object]:
    request = {
        "DocumentName": "AWS-RunShellScript",
        "InstanceIds": [instance_id],
        "Comment": f"E-B24 preregistered receiver-to-gateway fault: {mode}",
        "TimeoutSeconds": timeout,
        "Parameters": {
            "commands": _commands(mode),
            "executionTimeout": [str(timeout)],
        },
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as handle:
        json.dump(request, handle)
        request_path = Path(handle.name)
    try:
        sent = _aws_json("ssm", "send-command", "--cli-input-json", f"file://{request_path}")
    finally:
        request_path.unlink(missing_ok=True)
    command_id = str(sent["Command"]["CommandId"])
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            details = _aws_json(
                "ssm",
                "get-command-invocation",
                "--command-id",
                command_id,
                "--instance-id",
                instance_id,
            )
        except subprocess.CalledProcessError as error:
            if (
                error.returncode == 254
                and "InvocationDoesNotExist" in (error.stderr or "")
            ):
                time.sleep(2)
                continue
            raise
        if details.get("Status") in TERMINAL:
            result = {
                "mode": mode,
                "command_id": command_id,
                "instance_id": instance_id,
                "status": details.get("Status"),
                "response_code": details.get("ResponseCode"),
                "stdout": details.get("StandardOutputContent", ""),
                "stderr": details.get("StandardErrorContent", ""),
            }
            if result["status"] != "Success" or result["response_code"] != 0:
                raise RuntimeError(f"fault command failed: {result}")
            return result
        time.sleep(2)
    raise TimeoutError(f"fault command {command_id} exceeded {timeout}s")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--receiver-instance-id", required=True)
    parser.add_argument("--mode", choices=("apply", "clear", "status"), required=True)
    parser.add_argument("--timeout-seconds", type=int, default=120)
    args = parser.parse_args()
    print(
        json.dumps(
            run_fault(args.receiver_instance_id, args.mode, args.timeout_seconds),
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
