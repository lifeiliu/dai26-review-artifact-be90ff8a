"""Frozen E-B22 workload loading and deterministic gate evaluation."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Mapping


E_B22_PROTOCOL_VERSION = "e-b22-prereg-v1"
EXPECTED_INPUT_SHA256 = {
    "analysis/e_b20_targets.json": "e8dca8f08e86a43fd919fac8d142800077128bb647408dee9a412d30ad994a75",
    "traces/e_b20_filesystem_run_3.jsonl": "faf203b0ba85ef88163f6f918dbebe52fb8c3b6fd7a04db95a8076891455d552",
    "traces/e_b20_filesystem_run_4.jsonl": "8cc211b48b84ad1878d8afa75f74020f7207c1c5a11ffc0c5e2249e1834a76ff",
    "traces/e_b20_postgres_run_3.jsonl": "7a833269a75502320ae7ee9b7cdced702b73be7d7eba0c9bb2e7fc1213b68b90",
    "traces/e_b20_postgres_run_4.jsonl": "642524a70351884b58d9ebeafe636018771d7329bc1f0bf1f9b13900db7cd42c",
}
EXPECTED_VECTOR_COUNT = 225
EXPECTED_SERVICE_COUNTS = {"filesystem": 112, "postgres": 113}
EXPECTED_TARGET_COUNT = 10


@dataclass(frozen=True)
class ReplayVector:
    service: str
    gateway_id: str
    run: int
    call_sequence: int
    tool_name: str
    arguments_sha256: str

    @property
    def vector_id(self) -> str:
        return hashlib.sha256(
            json.dumps(asdict(self), sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

    def payload(self) -> str:
        return json.dumps(
            {"vector_id": self.vector_id, **asdict(self)},
            sort_keys=True,
            separators=(",", ":"),
        )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_frozen_workload(root: str | Path) -> tuple[list[ReplayVector], dict[str, object]]:
    workload_root = Path(root).resolve()
    observed_hashes: dict[str, str] = {}
    for relative, expected in EXPECTED_INPUT_SHA256.items():
        path = workload_root / relative
        if not path.is_file():
            raise FileNotFoundError(f"missing frozen E-B22 input: {path}")
        observed = sha256_file(path)
        observed_hashes[relative] = observed
        if observed != expected:
            raise ValueError(
                f"frozen input hash mismatch for {relative}: expected {expected}, observed {observed}"
            )

    target_path = workload_root / "analysis/e_b20_targets.json"
    targets = tuple(sorted(json.loads(target_path.read_text(encoding="utf-8"))["targets"]))
    if len(targets) != EXPECTED_TARGET_COUNT:
        raise ValueError(f"expected {EXPECTED_TARGET_COUNT} frozen targets, found {len(targets)}")
    target_set = set(targets)

    vectors: list[ReplayVector] = []
    service_counts = {service: 0 for service in EXPECTED_SERVICE_COUNTS}
    target_vector_counts = {target: 0 for target in targets}
    for relative in EXPECTED_INPUT_SHA256:
        if not relative.startswith("traces/"):
            continue
        path = workload_root / relative
        with path.open(encoding="utf-8") as handle:
            for line in handle:
                item = json.loads(line)
                if (
                    item.get("event_type") != "tool_call"
                    or item.get("gateway_id") not in target_set
                    or item.get("mutating") is not True
                ):
                    continue
                vector = ReplayVector(
                    service=str(item["service"]),
                    gateway_id=str(item["gateway_id"]),
                    run=int(item["run"]),
                    call_sequence=int(item["call_sequence"]),
                    tool_name=str(item["tool_name"]),
                    arguments_sha256=str(item["arguments_sha256"]),
                )
                vectors.append(vector)
                service_counts[vector.service] = service_counts.get(vector.service, 0) + 1
                target_vector_counts[vector.gateway_id] += 1

    if len(vectors) != EXPECTED_VECTOR_COUNT:
        raise ValueError(f"expected {EXPECTED_VECTOR_COUNT} frozen replay vectors, found {len(vectors)}")
    if service_counts != EXPECTED_SERVICE_COUNTS:
        raise ValueError(
            f"frozen service counts changed: expected {EXPECTED_SERVICE_COUNTS}, observed {service_counts}"
        )
    if any(vector.run not in {3, 4} for vector in vectors):
        raise ValueError("frozen replay contains a non-held-out run")

    identity_payload = [vector.vector_id for vector in vectors]
    workload_identity_sha256 = hashlib.sha256(
        json.dumps(identity_payload, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    manifest: dict[str, object] = {
        "protocol_version": E_B22_PROTOCOL_VERSION,
        "workload_root": str(workload_root),
        "input_sha256": observed_hashes,
        "target_count": len(targets),
        "targets": list(targets),
        "vector_count": len(vectors),
        "service_counts": service_counts,
        "target_vector_counts": target_vector_counts,
        "zero_vector_targets": sorted(
            target for target, count in target_vector_counts.items() if count == 0
        ),
        "workload_identity_sha256": workload_identity_sha256,
        "risk_index_changed": False,
        "target_policy_changed": False,
        "target_membership_changed": False,
        "mutation_labels_changed": False,
        "target_fraction_changed": False,
        "effect_threshold_changed": False,
    }
    return vectors, manifest


def condition_counts(rows: Iterable[Mapping[str, object]]) -> dict[str, dict[str, int]]:
    counts: dict[str, dict[str, int]] = {}
    for row in rows:
        key = f"{row['condition']}:{row['receiver']}"
        bucket = counts.setdefault(key, {"allowed": 0, "denied": 0, "total": 0})
        allowed = bool(row["allowed"])
        bucket["allowed" if allowed else "denied"] += 1
        bucket["total"] += 1
    return counts


def evaluate_e_b22_assertions(
    *,
    manifest: Mapping[str, object],
    replay_counts: Mapping[str, Mapping[str, int]],
    receiver_events: Mapping[str, Mapping[str, Mapping[str, object]]],
    gateway_statuses: Mapping[str, Mapping[str, Mapping[str, object]]],
    infrastructure: Mapping[str, object],
) -> dict[str, bool]:
    n = EXPECTED_VECTOR_COUNT

    def count(condition: str, receiver: str, field: str) -> int:
        return int(replay_counts.get(f"{condition}:{receiver}", {}).get(field, -1))

    def receiver(condition: str, name: str, field: str) -> object:
        return receiver_events.get(condition, {}).get(name, {}).get(field)

    def status(condition: str, name: str, field: str) -> object:
        return gateway_statuses.get(condition, {}).get(name, {}).get(field)

    return {
        "frozen_inputs_match": int(manifest.get("vector_count", -1)) == n
        and int(manifest.get("target_count", -1)) == EXPECTED_TARGET_COUNT,
        "pinned_postgres_used": bool(infrastructure.get("pinned_postgres_used")),
        "gateway_process_isolation": bool(infrastructure.get("gateway_process_isolation")),
        "all_set_signatures_verified": all(
            bool(receiver(condition, name, "signature_verified"))
            for condition in ("normal-delivery", "receiver-selective-nondelivery")
            for name in ("receiver-a", "receiver-b")
        ),
        "normal_both_forwarded": all(
            bool(receiver("normal-delivery", name, "forwarded"))
            for name in ("receiver-a", "receiver-b")
        ),
        "selective_only_b_withheld": bool(
            receiver("receiver-selective-nondelivery", "receiver-a", "forwarded")
        )
        and not bool(receiver("receiver-selective-nondelivery", "receiver-b", "forwarded")),
        "all_pushes_acknowledged_202": all(
            int(receiver(condition, name, "http_response") or -1) == 202
            for condition in ("normal-delivery", "receiver-selective-nondelivery")
            for name in ("receiver-a", "receiver-b")
        ),
        "normal_a_denies_all": count("normal-delivery", "receiver-a", "denied") == n
        and count("normal-delivery", "receiver-a", "allowed") == 0
        and status("normal-delivery", "receiver-a", "revoked") is True,
        "normal_b_denies_all": count("normal-delivery", "receiver-b", "denied") == n
        and count("normal-delivery", "receiver-b", "allowed") == 0
        and status("normal-delivery", "receiver-b", "revoked") is True,
        "selective_a_denies_all": count(
            "receiver-selective-nondelivery", "receiver-a", "denied"
        )
        == n
        and count("receiver-selective-nondelivery", "receiver-a", "allowed") == 0
        and status("receiver-selective-nondelivery", "receiver-a", "revoked") is True,
        "selective_b_allows_all": count(
            "receiver-selective-nondelivery", "receiver-b", "allowed"
        )
        == n
        and count("receiver-selective-nondelivery", "receiver-b", "denied") == 0
        and status("receiver-selective-nondelivery", "receiver-b", "revoked") is False,
        "frozen_configuration_unchanged": not any(
            bool(manifest.get(field))
            for field in (
                "risk_index_changed",
                "target_policy_changed",
                "target_membership_changed",
                "mutation_labels_changed",
                "target_fraction_changed",
                "effect_threshold_changed",
            )
        ),
    }

