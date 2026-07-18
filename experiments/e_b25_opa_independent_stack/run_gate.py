#!/usr/bin/env python3
"""Run E-B25 with independent OPA decisions and a Toxiproxy control fault."""

from __future__ import annotations

import argparse
import hashlib
import json
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping, Sequence


HERE = Path(__file__).resolve().parent
ARTIFACT = HERE.parents[1]
SOURCE = ARTIFACT / "src"
if str(SOURCE) not in sys.path:
    sys.path.insert(0, str(SOURCE))

from revocation_propagation.completion_contract import (  # noqa: E402
    CompletionContractMonitor,
    EffectObservation,
)
from revocation_propagation.e_b24_gateway_control import build_gateway_control_server  # noqa: E402
from revocation_propagation.e_b24_receiver import (  # noqa: E402
    CloudReceiverStore,
    ReceiverWorker,
    VerifiedSet,
)
from revocation_propagation.keycloak_gateway_gate import (  # noqa: E402
    ReplayVector,
    load_frozen_workload,
)
from revocation_propagation.opa_policy_gate import (  # noqa: E402
    E_B25_POLICY_VERSION,
    OPA_POLICY,
    OpaHttpClient,
    OpaPolicyGateway,
)
from revocation_propagation.real_effect_gate import (  # noqa: E402
    FilesystemEffectStore,
    PostgresDockerEffectStore,
    canonical_json,
)


OPA_IMAGE = "openpolicyagent/opa:1.17.0-static"
OPA_DIGEST = "sha256:94830e998dd9df8e49a61826f1ad03d8a68d3ecd52f105e06a2adb93b459ad46"
TOXIPROXY_IMAGE = "ghcr.io/shopify/toxiproxy:2.12.0"
TOXIPROXY_DIGEST = "sha256:9378ed52a28bc50edc1350f936f518f31fa95f0d15917d6eb40b8e376d1a214e"
POSTGRES_IMAGE = "pgvector/pgvector:0.8.0-pg17-bookworm"
POSTGRES_DIGEST = "sha256:40b404964359299eefdd5f8518facf1886c562848cf4de13b6eaf91cb70c2b87"
NETWORK = "revprop-e-b25"
OPA_CONTAINERS = {"g-filesystem": "revprop-e-b25-opa-fs", "g-postgres": "revprop-e-b25-opa-pg"}
TOXI_CONTAINER = "revprop-e-b25-toxiproxy"
POSTGRES_CONTAINER = "revprop-e-b25-postgres"
POSTGRES_DATABASE = "e_b25_effects"
POSTGRES_USER = "e_b25"
POSTGRES_PASSWORD = "e-b25-local-password"
CONTROL_TOKEN = "e-b25-receiver-to-gateway"


def docker(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *arguments],
        check=check,
        capture_output=True,
        text=True,
    )


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def image_has_digest(image: str, digest: str) -> bool:
    body = docker("image", "inspect", "--format", "{{json .RepoDigests}}", image).stdout
    return any(str(item).endswith(f"@{digest}") for item in json.loads(body))


def cleanup() -> None:
    for name in (*OPA_CONTAINERS.values(), TOXI_CONTAINER, POSTGRES_CONTAINER):
        docker("rm", "-f", name, check=False)
    docker("network", "rm", NETWORK, check=False)


def wait_http(url: str, *, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                if response.status == 200:
                    return
        except Exception as error:  # readiness boundary
            last = f"{type(error).__name__}: {error}"
        time.sleep(0.2)
    raise TimeoutError(f"endpoint did not become ready: {url}: {last}")


def close_at_frozen_deadline(
    monitor: CompletionContractMonitor, *, jti: str, deadline_ns: int
) -> None:
    """Wait out a registered window before asking the v2 monitor to close it."""
    remaining_ns = deadline_ns - time.time_ns()
    if remaining_ns > 0:
        time.sleep(remaining_ns / 1_000_000_000)
    monitor.close_window(jti=jti)


class ToxiproxyAdmin:
    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.configs: dict[str, dict[str, object]] = {}

    def _request(self, method: str, path: str, body: object | None = None) -> object:
        data = None if body is None else (canonical_json(body) + "\n").encode()
        request = urllib.request.Request(
            f"{self.base_url}{path}",
            data=data,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                payload = response.read()
        except urllib.error.HTTPError as error:
            raise RuntimeError(error.read().decode(errors="replace")) from error
        return {} if not payload else json.loads(payload)

    def create(self, *, name: str, listen: str, upstream: str) -> None:
        config: dict[str, object] = {
            "name": name,
            "listen": listen,
            "upstream": upstream,
            "enabled": True,
        }
        self._request("POST", "/proxies", config)
        self.configs[name] = config

    def set_enabled(self, name: str, enabled: bool) -> None:
        config = {**self.configs[name], "enabled": enabled}
        self._request("POST", f"/proxies/{urllib.parse.quote(name)}", config)
        self.configs[name] = config


def start_infrastructure() -> dict[str, object]:
    for image, digest in (
        (OPA_IMAGE, OPA_DIGEST),
        (TOXIPROXY_IMAGE, TOXIPROXY_DIGEST),
        (POSTGRES_IMAGE, POSTGRES_DIGEST),
    ):
        if not image_has_digest(image, digest):
            raise RuntimeError(f"image {image} does not match frozen digest {digest}")

    cleanup()
    docker("network", "create", NETWORK)
    direct_ports = {gateway: free_port() for gateway in OPA_CONTAINERS}
    for gateway, container in OPA_CONTAINERS.items():
        docker(
            "run", "--detach", "--name", container, "--network", NETWORK,
            "--publish", f"127.0.0.1:{direct_ports[gateway]}:8181",
            OPA_IMAGE, "run", "--server", "--addr=0.0.0.0:8181", "--log-level=error",
        )

    admin_port, fs_proxy_port, pg_proxy_port = free_port(), free_port(), free_port()
    docker(
        "run", "--detach", "--name", TOXI_CONTAINER, "--network", NETWORK,
        "--publish", f"127.0.0.1:{admin_port}:8474",
        "--publish", f"127.0.0.1:{fs_proxy_port}:8666",
        "--publish", f"127.0.0.1:{pg_proxy_port}:8667",
        TOXIPROXY_IMAGE,
    )
    docker(
        "run", "--detach", "--name", POSTGRES_CONTAINER,
        "--env", f"POSTGRES_DB={POSTGRES_DATABASE}",
        "--env", f"POSTGRES_USER={POSTGRES_USER}",
        "--env", f"POSTGRES_PASSWORD={POSTGRES_PASSWORD}",
        POSTGRES_IMAGE,
    )

    direct_urls = {
        gateway: f"http://127.0.0.1:{port}" for gateway, port in direct_ports.items()
    }
    for url in direct_urls.values():
        wait_http(f"{url}/health")
    wait_http(f"http://127.0.0.1:{admin_port}/version")
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        ready = docker(
            "exec", POSTGRES_CONTAINER, "pg_isready", "--username", POSTGRES_USER,
            "--dbname", POSTGRES_DATABASE, check=False,
        )
        if ready.returncode == 0:
            break
        time.sleep(0.25)
    else:
        raise TimeoutError("Postgres did not become ready")

    admin = ToxiproxyAdmin(f"http://127.0.0.1:{admin_port}")
    admin.create(
        name="e-b25-filesystem-control",
        listen="0.0.0.0:8666",
        upstream=f"{OPA_CONTAINERS['g-filesystem']}:8181",
    )
    admin.create(
        name="e-b25-postgres-control",
        listen="0.0.0.0:8667",
        upstream=f"{OPA_CONTAINERS['g-postgres']}:8181",
    )
    proxy_urls = {
        "g-filesystem": f"http://127.0.0.1:{fs_proxy_port}",
        "g-postgres": f"http://127.0.0.1:{pg_proxy_port}",
    }
    for gateway, direct_url in direct_urls.items():
        client = OpaHttpClient(direct_url)
        client.install_policy(OPA_POLICY)
        client.initialize_gateway(gateway)
        allowed, _ = client.allowed(gateway_id=gateway, delegation_id="readiness")
        if not allowed:
            raise RuntimeError(f"OPA readiness decision failed for {gateway}")
    return {
        "admin": admin,
        "direct_urls": direct_urls,
        "proxy_urls": proxy_urls,
        "images": {
            "opa": {"image": OPA_IMAGE, "digest": OPA_DIGEST},
            "toxiproxy": {"image": TOXIPROXY_IMAGE, "digest": TOXIPROXY_DIGEST},
            "postgres": {"image": POSTGRES_IMAGE, "digest": POSTGRES_DIGEST},
        },
    }


def verified_event(name: str, sequence: int) -> VerifiedSet:
    jti = f"e-b25-{name}-event"
    return VerifiedSet(
        jti=jti,
        issuer="e-b25-local-issuer",
        audience="e-b25/receiver",
        delegation_id=f"e-b25-{name}-delegation",
        event_id=jti,
        sequence=sequence,
        encoded_sha256=hashlib.sha256(jti.encode()).hexdigest(),
        key_id="e-b25-fixture",
        algorithm="RS256",
        issued_at=sequence,
    )


def start_control_servers(gateways: Mapping[str, OpaPolicyGateway]):
    servers = []
    targets = []
    for gateway_id, gateway in gateways.items():
        server = build_gateway_control_server(
            host="127.0.0.1", port=0, gateway=gateway, bearer_token=CONTROL_TOKEN
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        servers.append((server, thread))
        targets.append({
            "gateway_id": gateway_id,
            "gateway_url": f"http://127.0.0.1:{server.server_address[1]}",
        })
    return servers, sorted(targets, key=lambda item: item["gateway_id"])


def stop_control_servers(servers) -> None:
    for server, thread in servers:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def replay(
    *,
    condition: str,
    delegation_id: str,
    vectors: Sequence[ReplayVector],
    gateways: Mapping[str, OpaPolicyGateway],
    monitor: CompletionContractMonitor | None,
    jti: str | None,
    trace_handle,
) -> dict[str, object]:
    counts = {"allowed": 0, "denied": 0, "effect_commits": 0}
    for vector in vectors:
        physical = "g-filesystem" if vector.service == "filesystem" else "g-postgres"
        result = gateways[physical].execute_effect(
            delegation_id=delegation_id,
            experiment_run=condition,
            arm="e-b25",
            vector_payload=vector.payload(),
        )
        counts["allowed" if result["allowed"] else "denied"] += 1
        committed = bool(result["effect"] and result["effect"].get("committed"))
        counts["effect_commits"] += int(committed)
        record = {"condition": condition, "physical_gateway_id": physical, **result}
        trace_handle.write(canonical_json(record) + "\n")
        if monitor is not None and jti is not None:
            monitor.record_effect(
                jti=jti,
                observation=EffectObservation(
                    vector_id=vector.vector_id,
                    gateway_id=physical,
                    decision_id=str(result["decision_id"]),
                    allowed=bool(result["allowed"]),
                    effect_committed=committed,
                    observed_at_ns=int(result["decided_at_ns"]),
                ),
            )
    return counts


def run(output_dir: Path, workload_root: Path) -> dict[str, object]:
    vectors, workload = load_frozen_workload(workload_root)
    infrastructure = start_infrastructure()
    postgres = PostgresDockerEffectStore(
        container=POSTGRES_CONTAINER,
        database=POSTGRES_DATABASE,
        user=POSTGRES_USER,
        password=POSTGRES_PASSWORD,
    )
    postgres.ensure_schema()
    filesystem = FilesystemEffectStore(output_dir / "filesystem-effects")
    gateways = {
        "g-filesystem": OpaPolicyGateway(
            gateway_id="g-filesystem",
            update_url=infrastructure["proxy_urls"]["g-filesystem"],
            decision_url=infrastructure["direct_urls"]["g-filesystem"],
            allowlist={v.vector_id: v for v in vectors if v.service == "filesystem"},
            filesystem_store=filesystem,
            postgres_store=None,
        ),
        "g-postgres": OpaPolicyGateway(
            gateway_id="g-postgres",
            update_url=infrastructure["proxy_urls"]["g-postgres"],
            decision_url=infrastructure["direct_urls"]["g-postgres"],
            allowlist={v.vector_id: v for v in vectors if v.service == "postgres"},
            filesystem_store=None,
            postgres_store=postgres,
        ),
    }
    servers, targets = start_control_servers(gateways)
    receiver = CloudReceiverStore(output_dir / "receiver.sqlite3")
    monitor = CompletionContractMonitor(
        receiver_store=receiver,
        monitor_db=output_dir / "completion-monitor.sqlite3",
    )
    worker = ReceiverWorker(
        store=receiver,
        gateway_bearer_token=CONTROL_TOKEN,
        timeout=3.0,
    )
    conditions: dict[str, object] = {}
    trace_path = output_dir / "decisions.jsonl"
    try:
        with trace_path.open("w", encoding="utf-8") as trace_handle:
            conditions["active"] = replay(
                condition="active",
                delegation_id="e-b25-active-delegation",
                vectors=vectors,
                gateways=gateways,
                monitor=None,
                jti=None,
                trace_handle=trace_handle,
            )

            for name, sequence in (("normal", 1), ("post_persist_fault", 2)):
                event = verified_event(name, sequence)
                persisted = receiver.persist_event(
                    event,
                    channel="e-b25-opa-control",
                    gateway_targets=targets,
                )
                if persisted["status"] != "PERSISTED":
                    raise AssertionError("receiver did not persist before handoff")
                if name == "post_persist_fault":
                    infrastructure["admin"].set_enabled(
                        "e-b25-filesystem-control", False
                    )
                worker_result = worker.run_once()
                after_worker = receiver.event(event.jti)
                start = time.time_ns()
                deadline = start + 120_000_000_000
                monitor.register_contract(
                    jti=event.jti,
                    event_id=event.event_id,
                    issuer_commit_id=f"issuer-{sequence}",
                    transmitter_queue_id=f"queue-{sequence}",
                    transport_ack_id=f"receiver-202-{sequence}",
                    expected_vector_ids=[v.vector_id for v in vectors],
                    window_start_ns=start,
                    window_deadline_ns=deadline,
                )
                replay_counts = replay(
                    condition=name,
                    delegation_id=event.delegation_id,
                    vectors=vectors,
                    gateways=gateways,
                    monitor=monitor,
                    jti=event.jti,
                    trace_handle=trace_handle,
                )
                close_at_frozen_deadline(monitor, jti=event.jti, deadline_ns=deadline)
                conditions[name] = {
                    "persisted_before_fault": persisted["status"] == "PERSISTED",
                    "worker": worker_result,
                    "receiver_after_worker": after_worker,
                    "replay": replay_counts,
                    "monitor_before_recovery": monitor.assess(event.jti).as_dict(),
                    "oracles": {
                        "filesystem": filesystem.oracle(experiment_run=name, arm="e-b25"),
                        "postgres": postgres.oracle(experiment_run=name, arm="e-b25"),
                    },
                }

            infrastructure["admin"].set_enabled("e-b25-filesystem-control", True)
            fault_recovery_worker = worker.run_once()
            fault_jti = verified_event("post_persist_fault", 2).jti
            conditions["post_persist_fault"]["late_recovery_worker"] = fault_recovery_worker
            conditions["post_persist_fault"]["receiver_after_recovery"] = receiver.event(fault_jti)
            conditions["post_persist_fault"]["monitor_after_recovery"] = monitor.assess(fault_jti).as_dict()

            recovery = verified_event("recovery", 3)
            persisted = receiver.persist_event(
                recovery,
                channel="e-b25-opa-control",
                gateway_targets=targets,
            )
            recovery_worker = worker.run_once()
            start = time.time_ns()
            deadline = start + 120_000_000_000
            monitor.register_contract(
                jti=recovery.jti,
                event_id=recovery.event_id,
                issuer_commit_id="issuer-3",
                transmitter_queue_id="queue-3",
                transport_ack_id="receiver-202-3",
                expected_vector_ids=[v.vector_id for v in vectors],
                window_start_ns=start,
                window_deadline_ns=deadline,
            )
            recovery_counts = replay(
                condition="recovery",
                delegation_id=recovery.delegation_id,
                vectors=vectors,
                gateways=gateways,
                monitor=monitor,
                jti=recovery.jti,
                trace_handle=trace_handle,
            )
            close_at_frozen_deadline(monitor, jti=recovery.jti, deadline_ns=deadline)
            conditions["recovery"] = {
                "persisted_before_handoff": persisted["status"] == "PERSISTED",
                "worker": recovery_worker,
                "receiver_after_worker": receiver.event(recovery.jti),
                "replay": recovery_counts,
                "monitor": monitor.assess(recovery.jti).as_dict(),
                "oracles": {
                    "filesystem": filesystem.oracle(experiment_run="recovery", arm="e-b25"),
                    "postgres": postgres.oracle(experiment_run="recovery", arm="e-b25"),
                },
            }
    finally:
        stop_control_servers(servers)

    active = conditions["active"]
    normal = conditions["normal"]
    fault = conditions["post_persist_fault"]
    recovery = conditions["recovery"]
    assertions = {
        "frozen_225_vectors": workload["vector_count"] == 225
        and workload["service_counts"] == {"filesystem": 112, "postgres": 113},
        "frozen_configuration_unchanged": not any(
            workload.get(field, True)
            for field in (
                "risk_index_changed", "target_policy_changed", "target_membership_changed",
                "mutation_labels_changed", "target_fraction_changed", "effect_threshold_changed",
            )
        ),
        "active_allows_and_commits_all": active == {
            "allowed": 225, "denied": 0, "effect_commits": 225
        },
        "normal_has_two_receipts": normal["receiver_after_worker"]["status"] == "ENFORCED"
        and len(normal["receiver_after_worker"]["receipts"]) == 2,
        "normal_c5_zero_effects": normal["replay"] == {
            "allowed": 0, "denied": 225, "effect_commits": 0
        }
        and normal["monitor_before_recovery"]["status"] == "COMPLETE_FOR_BOUND",
        "fault_occurs_after_persistence": fault["persisted_before_fault"] is True,
        "fault_missing_only_filesystem_receipt": fault["receiver_after_worker"]["status"] == "PERSISTED"
        and set(fault["receiver_after_worker"]["receipts"]) == {"g-postgres"},
        "fault_stale_opa_commits_112": fault["replay"] == {
            "allowed": 112, "denied": 113, "effect_commits": 112
        }
        and fault["oracles"]["filesystem"]["count"] == 112
        and fault["oracles"]["postgres"]["count"] == 0,
        "fault_monitor_reports_violation": fault["monitor_before_recovery"]["status"] == "VIOLATED"
        and fault["monitor_before_recovery"]["highest_stage"] == "C3_RECEIVER_PERSISTED",
        "late_receipt_does_not_erase_violation": fault["receiver_after_recovery"]["status"] == "ENFORCED"
        and fault["monitor_after_recovery"]["status"] == "VIOLATED"
        and fault["monitor_after_recovery"]["highest_stage"] == "C4_GATEWAYS_ENFORCED",
        "recovery_c5_zero_effects": recovery["replay"] == {
            "allowed": 0, "denied": 225, "effect_commits": 0
        }
        and recovery["monitor"]["status"] == "COMPLETE_FOR_BOUND",
    }
    return {
        "protocol_version": "e-b25-opa-independent-v1",
        "policy_version": E_B25_POLICY_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "verification_status": "CONFIRMATORY",
        "workload": workload,
        "infrastructure": {key: value for key, value in infrastructure.items() if key != "admin"},
        "conditions": conditions,
        "assertions": assertions,
        "pass": all(assertions.values()),
        "trace_path": str(trace_path.resolve()),
        "trace_sha256": hashlib.sha256(trace_path.read_bytes()).hexdigest(),
    }


def report(summary: Mapping[str, object]) -> str:
    conditions = summary["conditions"]
    lines = [
        "# E-B25 Independent OPA Stack",
        "",
        f"- Verification: {'PASSED' if summary['pass'] else 'FAILED'}",
        f"- Generated: {summary['generated_at']}",
        "- Policy engine: OPA 1.17.0",
        "- Fault injector: Toxiproxy 2.12.0",
        "",
        "| Condition | Allowed | Denied | Effects | Monitor |",
        "|---|---:|---:|---:|---|",
    ]
    for name in ("normal", "post_persist_fault", "recovery"):
        item = conditions[name]
        verdict = item.get("monitor", item.get("monitor_before_recovery"))
        lines.append(
            f"| `{name}` | {item['replay']['allowed']} | {item['replay']['denied']} | "
            f"{item['replay']['effect_commits']} | `{verdict['status']}` |"
        )
    lines.extend(["", "## Assertions", ""])
    lines.extend(
        f"- [{'x' if passed else ' '}] `{name}`"
        for name, passed in summary["assertions"].items()
    )
    lines.extend([
        "", "## Claim boundary", "",
        "This one-host result independently replicates the persisted-but-not-enforced boundary in OPA under an externally injected control-path fault. It does not measure production incidence or establish multi-host independence.",
        "",
    ])
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--workload-root",
        type=Path,
        default=ARTIFACT / "data" / "run_2026_07_14_e_b20_mcpmark_formal",
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=False)
    try:
        summary = run(output_dir, args.workload_root.resolve())
        (output_dir / "summary.json").write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        (output_dir / "validation_report.md").write_text(report(summary), encoding="utf-8")
        print(canonical_json({"output_dir": str(output_dir), "pass": summary["pass"]}))
        if not summary["pass"]:
            raise SystemExit(1)
    finally:
        cleanup()


if __name__ == "__main__":
    main()
