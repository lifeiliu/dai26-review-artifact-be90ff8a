#!/usr/bin/env python3
"""Independently validate a frozen E-B27 confirmatory output."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import statistics
from pathlib import Path


HERE = Path(__file__).resolve().parent
ARTIFACT = HERE.parents[1]
PROTOCOL = ARTIFACT / "protocols/e-b27-completion-monitor-evaluation/protocol.md"
EXPECTED_FAULT_IDS = {
    "F01_PERSISTED_NO_RECEIPTS",
    "F02_PARTIAL_RECEIPTS",
    "F03_ALL_RECEIPTS_OPEN",
    "F04_CLOSED_MISSING_EFFECTS",
    "F05_COMPLETE_BOUND",
    "F06_ALLOWED_VIOLATION",
    "F07_COMMITTED_VIOLATION",
    "F08_LATE_RECEIPT_STICKY_VIOLATION",
    "F09_DUPLICATE_IMMUTABILITY",
    "F10_RESTART_PERSISTENCE",
    "F11_CONTRACT_TARGET_IMMUTABILITY",
    "F12_WINDOW_CLOSURE_GUARD",
    "F13_EFFECT_BOUND_GUARD",
    "F14_C0_C2_EVIDENCE_REQUIRED",
}
GATEWAYS = (1, 8, 32, 128, 512, 1024)
VECTORS = (1, 225, 1000, 5000, 10000)
NUMERIC_FIELDS = (
    "persist_receiver_ms", "register_contract_ms", "receipt_total_ms",
    "receipt_per_item_us", "effect_total_ms", "effect_per_item_us",
    "close_window_ms", "assess_p50_us", "assess_p95_us", "assess_p99_us",
    "restart_assess_ms", "database_bytes",
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def matching_summary(summary_rows: list[dict[str, object]], axis: str, gateways: int, vectors: int) -> dict[str, object]:
    matches = [
        row for row in summary_rows
        if row["axis"] == axis
        and int(row["gateway_count"]) == gateways
        and int(row["vector_count"]) == vectors
    ]
    require(len(matches) == 1, f"missing or duplicate summary for {axis}/{gateways}/{vectors}")
    return matches[0]


def validate(run_dir: Path) -> dict[str, object]:
    summary_path = run_dir / "summary.json"
    faults_path = run_dir / "fault_matrix.json"
    scaling_path = run_dir / "scaling_raw.csv"
    for path in (summary_path, faults_path, scaling_path):
        require(path.is_file(), f"missing required evidence: {path.name}")

    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    faults = json.loads(faults_path.read_text(encoding="utf-8"))
    with scaling_path.open(encoding="utf-8", newline="") as handle:
        scaling = list(csv.DictReader(handle))

    require(summary["experiment"] == "E-B27", "unexpected experiment ID")
    require(summary["mode"] == "confirmatory", "run is not confirmatory")
    require(summary["monitor_version"] == "c0-c5-bounded-v2", "unexpected monitor version")
    require(summary["protocol_sha256"] == sha256(PROTOCOL), "protocol hash mismatch")
    parameters = summary["parameters"]
    require(parameters == {
        "gateway_axis": list(GATEWAYS),
        "vector_axis": list(VECTORS),
        "fixed_vectors_on_gateway_axis": 225,
        "fixed_gateways_on_vector_axis": 8,
        "trials": 3,
        "assess_warmups": 10,
        "assess_repetitions": 100,
    }, "confirmatory parameter freeze mismatch")

    require(len(faults) == 14, "fault matrix does not contain 14 rows")
    require({row["id"] for row in faults} == EXPECTED_FAULT_IDS, "fault IDs do not match freeze")
    require(all(row.get("passed") is True for row in faults), "one or more fault rows failed")
    require(summary["fault_matrix"] == {"passed": 14, "total": 14, "all_passed": True}, "summary fault counts mismatch")

    expected_configs = {
        *(('gateways', count, 225) for count in GATEWAYS),
        *(('vectors', 8, count) for count in VECTORS),
    }
    observed_configs = {
        (row["axis"], int(row["gateway_count"]), int(row["vector_count"]))
        for row in scaling
    }
    require(observed_configs == expected_configs, "scaling configurations differ from freeze")
    require(len(scaling) == len(expected_configs) * 3, "scaling trial count mismatch")
    require(all(row["status"] == "COMPLETE_FOR_BOUND" for row in scaling), "a scaling state did not complete")
    for config in expected_configs:
        trials = sorted(
            int(row["trial"]) for row in scaling
            if (row["axis"], int(row["gateway_count"]), int(row["vector_count"])) == config
        )
        require(trials == [1, 2, 3], f"trial IDs mismatch for {config}")
    for row in scaling:
        for field in NUMERIC_FIELDS:
            value = float(row[field])
            require(math.isfinite(value) and value >= 0, f"invalid {field} in raw scaling data")

    summary_rows = summary["scaling"]
    require(len(summary_rows) == len(expected_configs), "scaling summary count mismatch")
    for axis, gateways, vectors in expected_configs:
        source_rows = [
            row for row in scaling
            if row["axis"] == axis
            and int(row["gateway_count"]) == gateways
            and int(row["vector_count"]) == vectors
        ]
        reported = matching_summary(summary_rows, axis, gateways, vectors)
        require(int(reported["trials"]) == 3, "summary does not report three trials")
        for field in NUMERIC_FIELDS:
            expected = statistics.median(float(row[field]) for row in source_rows)
            observed = float(reported[f"median_{field}"])
            require(math.isclose(expected, observed, rel_tol=1e-12, abs_tol=1e-12), f"median mismatch: {axis}/{gateways}/{vectors}/{field}")

    gateway_max = matching_summary(summary_rows, "gateways", 1024, 225)
    vector_max = matching_summary(summary_rows, "vectors", 8, 10000)
    result = {
        "validated": True,
        "fault_rows_passed": 14,
        "fault_rows_total": 14,
        "scaling_configurations": len(expected_configs),
        "scaling_trials": len(scaling),
        "protocol_sha256": summary["protocol_sha256"],
        "evidence_sha256": {
            "summary.json": sha256(summary_path),
            "fault_matrix.json": sha256(faults_path),
            "scaling_raw.csv": sha256(scaling_path),
        },
        "largest_gateway_configuration": gateway_max,
        "largest_vector_configuration": vector_max,
    }
    (run_dir / "validation.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def write_report(run_dir: Path, validation: dict[str, object]) -> None:
    gateway = validation["largest_gateway_configuration"]
    vector = validation["largest_vector_configuration"]
    hashes = validation["evidence_sha256"]
    report = f"""# E-B27 Confirmatory Validation

## Material Passport

- **Material:** synthetic completion-contract events, bound gateway receipts,
  effect observations, verdicts, and local timing measurements generated by the
  repository's `c0-c5-bounded-v2` monitor.
- **Origin and ownership:** first-party generated evidence; no human-subject,
  customer, production, or third-party payload data.
- **Coverage:** 14 frozen fault rows; 11 scaling configurations; 3 independent
  database trials per configuration; 100 timed assessments after 10 warm-ups.
- **Transformations:** JSON/CSV serialization and median aggregation only. Raw
  per-trial measurements are retained in `scaling_raw.csv`.
- **Identity/privacy:** synthetic identifiers only; environment capture excludes
  hostname, username, email, network address, AWS account, and AWS role.
- **Known limits:** one Python/SQLite implementation on one local ARM64 host;
  descriptive overhead only, with no production SLO or distributed-consensus
  claim.

## Validation outcome

PASS. The independent validator reproduced the frozen protocol hash, observed
14/14 exact fault-matrix passes, found all 33 scaling trials and all 11 frozen
configurations, recomputed every reported median, and confirmed that every
scaling state ended `COMPLETE_FOR_BOUND`.

At the largest gateway point (1,024 gateways, 225 vectors), the median
steady-state assessment p95 was {float(gateway['median_assess_p95_us']):.1f} us,
restart-plus-first-assessment was {float(gateway['median_restart_assess_ms']):.2f}
ms, and durable state occupied {int(float(gateway['median_database_bytes']))}
bytes. At the largest vector point (8 gateways, 10,000 vectors), the
corresponding values were {float(vector['median_assess_p95_us']):.1f} us,
{float(vector['median_restart_assess_ms']):.2f} ms, and
{int(float(vector['median_database_bytes']))} bytes. These are local engineering
measurements, not latency guarantees.

## Evidence checksums

- `summary.json`: `{hashes['summary.json']}`
- `fault_matrix.json`: `{hashes['fault_matrix.json']}`
- `scaling_raw.csv`: `{hashes['scaling_raw.csv']}`
- frozen protocol: `{validation['protocol_sha256']}`
"""
    (run_dir / "validation_report.md").write_text(report, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("run_dir", type=Path)
    args = parser.parse_args()
    run_dir = args.run_dir.resolve()
    validation = validate(run_dir)
    write_report(run_dir, validation)
    print(json.dumps({"run_dir": str(run_dir), **validation}, sort_keys=True))


if __name__ == "__main__":
    main()
