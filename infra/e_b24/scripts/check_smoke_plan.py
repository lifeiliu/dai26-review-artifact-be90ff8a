#!/usr/bin/env python3
"""Fail closed unless a Terraform plan preserves the E-B24 smoke invariants."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: check_smoke_plan.py <terraform-plan.json>")
    body = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    changes = body.get("resource_changes", [])
    creates = [
        change
        for change in changes
        if "create" in change.get("change", {}).get("actions", [])
    ]
    instances = [item for item in creates if item.get("type") == "aws_instance"]
    forbidden_types = {
        "aws_eip",
        "aws_lb",
        "aws_nat_gateway",
        "aws_db_instance",
        "aws_spot_instance_request",
    }
    forbidden = [item for item in creates if item.get("type") in forbidden_types]
    problems: list[str] = []
    if len(instances) != 3:
        problems.append(f"expected exactly 3 EC2 creates, observed {len(instances)}")
    if forbidden:
        problems.append(
            "forbidden resource creates: "
            + ", ".join(f"{item['type']}.{item['name']}" for item in forbidden)
        )
    expected_types = {"t3.large": 1, "t3.medium": 2}
    observed_types: dict[str, int] = {}
    zones: set[str] = set()
    for item in instances:
        after = item.get("change", {}).get("after", {}) or {}
        instance_type = after.get("instance_type")
        observed_types[instance_type] = observed_types.get(instance_type, 0) + 1
        subnet_key = item.get("index")
        if isinstance(subnet_key, str):
            zones.add(subnet_key)
        if after.get("associate_public_ip_address") is not True:
            problems.append(f"{item.get('address')} lacks the explicit smoke public IPv4 gate")
        metadata = after.get("metadata_options") or []
        if not metadata or metadata[0].get("http_tokens") != "required":
            problems.append(f"{item.get('address')} does not require IMDSv2")
        credits = after.get("credit_specification") or []
        if not credits or credits[0].get("cpu_credits") != "standard":
            problems.append(f"{item.get('address')} does not freeze T3 Standard credits")
        user_data = after.get("user_data") or ""
        if "@sha256:" not in user_data:
            problems.append(f"{item.get('address')} does not pin the runtime image digest")
    if observed_types != expected_types:
        problems.append(f"instance types changed: expected {expected_types}, observed {observed_types}")
    if zones != {"smoke-1", "smoke-2", "smoke-3"}:
        problems.append(f"host keys changed: {sorted(zones)}")

    ingress = [
        item
        for item in creates
        if item.get("type") == "aws_vpc_security_group_ingress_rule"
    ]
    for item in ingress:
        after = item.get("change", {}).get("after", {}) or {}
        if after.get("from_port") == 22 or after.get("to_port") == 22:
            problems.append(f"SSH ingress appears in {item.get('address')}")
        if after.get("cidr_ipv4") == "0.0.0.0/0":
            problems.append(f"public ingress appears in {item.get('address')}")

    report = {
        "passed": not problems,
        "ec2_creates": len(instances),
        "instance_types": observed_types,
        "forbidden_creates": len(forbidden),
        "problems": problems,
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if not problems else 1


if __name__ == "__main__":
    raise SystemExit(main())
