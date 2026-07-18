#!/usr/bin/env python3
"""Fail closed unless a Terraform plan preserves the E-B24 strict topology."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


EXPECTED_HOSTS = {
    "gateway-1",
    "gateway-2",
    "gateway-3",
    "gateway-4",
    "gateway-5",
    "gateway-6",
    "gateway-7",
    "gateway-8",
    "keycloak",
    "keycloak-postgres",
    "receiver-a",
    "receiver-b",
    "filesystem-effects",
    "postgres-effects",
    "workload-driver",
    "fault-controller",
}
EXPECTED_TYPES = {"t3.small": 13, "t3.medium": 3}
EXPECTED_GATEWAY_AZ_KEYS = {"a": 3, "b": 3, "c": 2}


def _resources(module: dict[str, Any]) -> Iterable[dict[str, Any]]:
    yield from module.get("resources", [])
    for child in module.get("child_modules", []):
        yield from _resources(child)


def _index(address: str) -> str | None:
    if "[\"" not in address:
        return None
    return address.rsplit("[\"", 1)[1].split("\"]", 1)[0]


def _values(resource: dict[str, Any]) -> dict[str, Any]:
    body = resource.get("values")
    return body if isinstance(body, dict) else {}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("plan", type=Path)
    parser.add_argument(
        "--mode",
        choices=("front-door-bootstrap", "full-pilot"),
        required=True,
    )
    args = parser.parse_args()

    body = json.loads(args.plan.read_text(encoding="utf-8"))
    root = body.get("planned_values", {}).get("root_module", {})
    resources = list(_resources(root))
    by_type: dict[str, list[dict[str, Any]]] = {}
    for resource in resources:
        by_type.setdefault(str(resource.get("type")), []).append(resource)

    problems: list[str] = []
    forbidden_types = {
        "aws_db_instance",
        "aws_key_pair",
        "aws_nat_gateway",
        "aws_spot_instance_request",
    }
    for resource_type in forbidden_types:
        if by_type.get(resource_type):
            problems.append(f"forbidden resource type present: {resource_type}")

    instances = by_type.get("aws_instance", [])
    albs = by_type.get("aws_lb", [])
    listeners = by_type.get("aws_lb_listener", [])
    eips = by_type.get("aws_eip", [])
    target_attachments = by_type.get("aws_lb_target_group_attachment", [])

    if args.mode == "front-door-bootstrap":
        if instances:
            problems.append(f"front-door bootstrap must have 0 EC2 instances, observed {len(instances)}")
        if len(albs) != 1:
            problems.append(f"front-door bootstrap requires 1 ALB, observed {len(albs)}")
        if listeners:
            problems.append("front-door bootstrap must not create HTTPS listeners before certificate import")
        if eips:
            problems.append("front-door bootstrap must not allocate an EIP while compute is disabled")
        if target_attachments:
            problems.append("front-door bootstrap must not attach receiver targets")
    else:
        if len(instances) != 16:
            problems.append(f"full pilot requires exactly 16 EC2 instances, observed {len(instances)}")
        if len(albs) != 1:
            problems.append(f"full pilot requires exactly 1 ALB, observed {len(albs)}")
        if len(listeners) != 2:
            problems.append(f"full pilot requires exactly 2 HTTPS listeners, observed {len(listeners)}")
        if len(eips) != 1:
            problems.append(f"full pilot requires exactly 1 stable Keycloak EIP, observed {len(eips)}")
        if len(target_attachments) != 2:
            problems.append(
                f"full pilot requires exactly 2 one-to-one receiver target attachments, observed {len(target_attachments)}"
            )

    hosts: set[str] = set()
    instance_types: Counter[str] = Counter()
    gateway_placement: Counter[str] = Counter()
    for instance in instances:
        values = _values(instance)
        host = _index(str(instance.get("address")))
        if host:
            hosts.add(host)
        instance_types[str(values.get("instance_type"))] += 1
        if host and host.startswith("gateway-"):
            private_ip = str(values.get("private_ip", ""))
            az_key = {"10.24.1.": "a", "10.24.2.": "b", "10.24.3.": "c"}.get(
                private_ip[:8]
            )
            if az_key is None:
                problems.append(f"{host} has unexpected private IP {private_ip}")
            else:
                gateway_placement[az_key] += 1
        if values.get("associate_public_ip_address") is not True:
            problems.append(f"{host or instance.get('address')} lacks explicit pilot public IPv4")
        metadata = values.get("metadata_options") or []
        if not metadata or metadata[0].get("http_tokens") != "required":
            problems.append(f"{host or instance.get('address')} does not require IMDSv2")
        credits = values.get("credit_specification") or []
        if not credits or credits[0].get("cpu_credits") != "standard":
            problems.append(f"{host or instance.get('address')} does not freeze T3 Standard credits")
        roots = values.get("root_block_device") or []
        if not roots or roots[0].get("encrypted") is not True:
            problems.append(f"{host or instance.get('address')} lacks encrypted root storage")
        user_data = str(values.get("user_data", ""))
        if "@sha256:" not in user_data:
            problems.append(f"{host or instance.get('address')} lacks a digest-pinned runtime image")
        if "allow-insecure-push-targets" in user_data:
            problems.append(f"{host or instance.get('address')} enables forbidden insecure PUSH targets")

    if args.mode == "full-pilot":
        if hosts != EXPECTED_HOSTS:
            problems.append(f"host inventory changed: expected {sorted(EXPECTED_HOSTS)}, observed {sorted(hosts)}")
        if dict(instance_types) != EXPECTED_TYPES:
            problems.append(f"instance types changed: expected {EXPECTED_TYPES}, observed {dict(instance_types)}")
        if dict(gateway_placement) != EXPECTED_GATEWAY_AZ_KEYS:
            problems.append(
                f"gateway placement changed: expected {EXPECTED_GATEWAY_AZ_KEYS}, observed {dict(gateway_placement)}"
            )

    for alb in albs:
        values = _values(alb)
        if values.get("internal") is not False:
            problems.append("PUSH ALB must be internet-facing so Keycloak does not resolve a private target")
        if values.get("load_balancer_type") != "application":
            problems.append("PUSH front door must remain an Application Load Balancer")

    listener_ports: set[int] = set()
    for listener in listeners:
        values = _values(listener)
        port = values.get("port")
        if isinstance(port, int):
            listener_ports.add(port)
        if values.get("protocol") != "HTTPS":
            problems.append(f"non-HTTPS PUSH listener: {listener.get('address')}")
        certificate = str(values.get("certificate_arn", ""))
        if not certificate.startswith("arn:") or ":acm:" not in certificate:
            problems.append(f"listener lacks imported ACM certificate: {listener.get('address')}")
    if args.mode == "full-pilot" and listener_ports != {443, 8443}:
        problems.append(f"PUSH listener ports changed: {sorted(listener_ports)}")

    for ingress in by_type.get("aws_vpc_security_group_ingress_rule", []):
        values = _values(ingress)
        address = str(ingress.get("address"))
        ports = {values.get("from_port"), values.get("to_port")}
        if 22 in ports:
            problems.append(f"SSH ingress appears in {address}")
        if values.get("cidr_ipv4") == "0.0.0.0/0":
            problems.append(f"unrestricted public ingress appears in {address}")
        if values.get("cidr_ipv4") and "push_alb" not in address:
            problems.append(f"CIDR ingress outside the Keycloak-only ALB edge appears in {address}")

    serialized = json.dumps(body, sort_keys=True)
    if "allow-insecure-push-targets" in serialized:
        problems.append("forbidden Keycloak insecure PUSH switch appears anywhere in the plan")
    if "aws_key_pair" in serialized or '"from_port":22' in serialized:
        problems.append("SSH material appears anywhere in the plan")

    report = {
        "passed": not problems,
        "mode": args.mode,
        "ec2_instances": len(instances),
        "hosts": sorted(hosts),
        "instance_types": dict(instance_types),
        "gateway_placement": dict(gateway_placement),
        "albs": len(albs),
        "listeners": len(listeners),
        "eips": len(eips),
        "target_attachments": len(target_attachments),
        "problems": problems,
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if not problems else 1


if __name__ == "__main__":
    raise SystemExit(main())
