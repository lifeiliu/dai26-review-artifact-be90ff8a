"""Reusable experiment runners for the Paper B evaluation tracks."""

from __future__ import annotations

import csv
import asyncio
import importlib.metadata
import importlib.util
import json
import math
import platform
import random
import statistics
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Literal, Sequence

from .a2a_adapter import (
    a2a_agent_card,
    agent_card_extension,
    agent_card_supports_revocation,
    task_lifecycle_revocation_binding,
    task_status_update_binding,
    validate_task_lifecycle_revocation_binding,
)
from .crypto import canonical_json_bytes, generate_keypair
from .damage import unauthorized_ops_expected, unauthorized_ops_worst
from .events import create_revocation_event
from .integration_harness import (
    INTEGRATION_FAULT_SCENARIOS,
    INTEGRATION_PROTOCOL_PROFILES,
    IntegrationTrialResult,
    run_gateway_tool_integration_trial,
)
from .ledger_client import TransparencyLedger
from .local_end_to_end import run_local_end_to_end_trial
from .agent_path_harness import AGENT_TOOL_PATH_PROFILES, run_agent_tool_path_trials
from .multiprocess_harness import run_multiprocess_gateway_tool_trial
from .paper_a_bridge import (
    build_paper_a_agent_system_bridge_rows,
    render_paper_a_agent_system_bridge_report,
    summarize_paper_a_agent_system_bridge,
)
from .propagator import (
    FaultPolicy,
    PropagationConfig,
    PropagationResult,
    PropagationStrategy,
    Propagator,
    RelyingParty,
)
from .root_authority import RootAuthority, RootFederation
from .status_baseline_harness import (
    STATUS_BASELINE_STRATEGIES,
    STATUS_FAULT_SCENARIOS,
    run_status_outage_baseline_trials,
)
from .matched_baseline_harness import run_e_b17_p0_matched_baselines

MetricRow = dict[str, object]

BASELINE_STRATEGIES: tuple[PropagationStrategy, ...] = (
    "push",
    "gossip",
    "log",
    "ttl-rcc",
    "push-gossip",
    "push-log",
    "gossip-log",
    "hybrid",
)

LOCAL_TRANSPORT_STRATEGIES: tuple[PropagationStrategy, ...] = ("push", "log", "push-gossip", "hybrid")
AGENT_TOOL_STRATEGIES: tuple[PropagationStrategy, ...] = (
    "push",
    "ttl-rcc",
    "push-gossip",
    "log",
    "hybrid",
)
A2A_LIFECYCLE_COMPATIBILITY_CELLS: tuple[str, ...] = (
    "new-client-new-server",
    "new-client-old-server",
    "old-client-new-server",
    "old-client-old-server",
)

DeliveryRegime = Literal[
    "full-snapshot",
    "request-time-check",
    "request-time-fail-open",
    "compact-delta",
    "dns-log-poll",
    "hybrid",
]

DELIVERY_REGIMES: tuple[DeliveryRegime, ...] = (
    "full-snapshot",
    "request-time-check",
    "request-time-fail-open",
    "compact-delta",
    "dns-log-poll",
    "hybrid",
)


@dataclass(frozen=True)
class Scenario:
    n_parties: int = 40
    ttl: float = 60.0
    velocity: float = 10.0
    push_suppression: float = 0.2
    gossip_suppression: float = 0.0
    log_suppression: float = 0.0
    max_time: float = 8.0
    seed: int = 0
    push_delay: float = 0.05
    gossip_delay: float = 0.10
    gossip_interval: float = 0.25
    poll_interval: float = 0.50
    log_append_delay: float = 0.05
    jitter: float = 0.20
    gossip_fanout: int | None = None


def run_all_experiments(*, profile: str = "smoke") -> dict[str, list[MetricRow]]:
    """Run all Paper B experiment lines.

    The default profile is intentionally small enough for local iteration.
    It exercises the full measurement surface without pretending to be the
    final paper-scale sweep.
    """

    if profile not in {"smoke", "paper"}:
        raise ValueError("profile must be 'smoke' or 'paper'")
    if profile == "paper":
        seeds = tuple(range(30))
        n_parties = 200
        integration_seeds = tuple(range(10))
        integration_n_parties = 30
        delivery_regimes: tuple[DeliveryRegime, ...] = DELIVERY_REGIMES
        status_suppression_values = (0.0, 0.2, 0.5)
        watcher_counts = (1, 2, 4, 8)
        watcher_coverages = (0.25, 0.50, 0.75, 1.0)
        watcher_intervals = (0.25, 0.50, 1.0, 2.0)
        tool_call_rates = (1.0, 10.0, 100.0)
    else:
        seeds = (0, 1, 2)
        n_parties = 40
        integration_seeds = (0, 1)
        integration_n_parties = 5
        delivery_regimes = ("full-snapshot", "request-time-fail-open", "compact-delta", "dns-log-poll", "hybrid")
        status_suppression_values = (0.0, 0.2)
        watcher_counts = (1, 4)
        watcher_coverages = (0.50, 1.0)
        watcher_intervals = (0.50,)
        tool_call_rates = (1.0, 10.0)

    e_b2 = run_e_b2_delta_prop_baselines(
        seeds=seeds,
        n_parties=n_parties,
        delivery_regimes=delivery_regimes,
        status_suppression_values=status_suppression_values,
    )
    return {
        "e_b1_byzantine_sweep": run_e_b1_byzantine_sweep(seeds=seeds, n_parties=n_parties),
        "e_b2_delta_prop_baselines": e_b2,
        "e_b3_damage_budget": run_e_b3_damage_budget(measured_rows=e_b2),
        "e_b4_equivocation_resistance": run_e_b4_equivocation_resistance(
            seeds=seeds,
            watcher_counts=watcher_counts,
            watcher_coverages=watcher_coverages,
            watcher_observation_intervals=watcher_intervals,
        ),
        "e_b5_thin_a2a": run_e_b5_thin_a2a(seeds=seeds),
        "e_b6_local_e2e": run_e_b6_local_end_to_end(seeds=seeds, n_parties_values=(5,)),
        "e_b7_reproducibility_sensitivity": run_e_b7_reproducibility_sensitivity(seeds=seeds, n_parties_values=(40,)),
        "e_b8_agent_tool_gateway": run_e_b8_agent_tool_gateway(
            seeds=seeds,
            n_parties_values=(n_parties,),
            tool_call_rates=tool_call_rates,
        ),
        "e_b9_a2a_lifecycle_binding": run_e_b9_a2a_lifecycle_binding(
            seeds=seeds,
            n_parties_values=(n_parties,),
            tool_call_rates=tool_call_rates,
        ),
        "e_b10_real_gateway_tool_path": run_e_b10_real_gateway_tool_path(
            seeds=integration_seeds,
            n_parties_values=(integration_n_parties,),
            tool_call_rates=tool_call_rates[:2],
        ),
        "e_b11_protocol_boundary_path": run_e_b11_protocol_boundary_path(
            seeds=integration_seeds,
            n_parties_values=(integration_n_parties,),
            tool_call_rates=tool_call_rates[:2],
        ),
        "e_b12_fault_injection_path": run_e_b12_fault_injection_path(
            seeds=integration_seeds,
            n_parties_values=(integration_n_parties,),
            tool_call_rates=tool_call_rates[:2],
        ),
        "e_b17_p0_matched_baselines": run_e_b17_p0_matched_baselines(
            seeds=seeds,
            n_gateways_values=(1000 if profile == "paper" else n_parties,),
        ),
    }


def write_experiment_bundle(results: dict[str, list[MetricRow]], output_dir: str | Path) -> None:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    for experiment_name, rows in results.items():
        write_rows_csv(rows, output_path / f"{experiment_name}.csv")
    (output_path / "summary.json").write_text(json.dumps(_summary(results), indent=2, sort_keys=True) + "\n")


def write_rows_csv(rows: Sequence[MetricRow], path: str | Path) -> None:
    if not rows:
        Path(path).write_text("")
        return
    fieldnames = sorted({key for row in rows for key in row})
    with Path(path).open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def read_rows_csv(path: str | Path) -> list[MetricRow]:
    csv_path = Path(path)
    if not csv_path.exists() or csv_path.stat().st_size == 0:
        return []
    with csv_path.open(newline="") as handle:
        return list(csv.DictReader(handle))


def stream_rows_csv(
    rows: Iterable[MetricRow],
    path: str | Path,
    *,
    key_field: str = "run_key",
    resume: bool = True,
) -> int:
    """Append rows as they complete and optionally skip rows already present."""

    csv_path = Path(path)
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    existing_keys: set[str] = set()
    fieldnames: list[str] | None = None
    if resume and csv_path.exists() and csv_path.stat().st_size > 0:
        with csv_path.open(newline="") as handle:
            reader = csv.DictReader(handle)
            fieldnames = list(reader.fieldnames or [])
            for row in reader:
                if row.get(key_field):
                    existing_keys.add(str(row[key_field]))

    written = 0
    handle = None
    writer: csv.DictWriter[str] | None = None
    try:
        for row in rows:
            key = str(row.get(key_field, ""))
            if key and key in existing_keys:
                continue
            if writer is None:
                if fieldnames is None:
                    fieldnames = sorted(row)
                    handle = csv_path.open("w", newline="")
                    writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
                    writer.writeheader()
                else:
                    handle = csv_path.open("a", newline="")
                    writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
            writer.writerow(row)
            written += 1
            if key:
                existing_keys.add(key)
            if handle is not None:
                handle.flush()
    finally:
        if handle is not None:
            handle.close()
    return written


def write_e_b1_outputs(
    rows: Sequence[MetricRow],
    output_dir: str | Path,
    *,
    run_config: dict[str, object] | None = None,
) -> None:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    write_rows_csv(rows, output_path / "e_b1_byzantine_sweep.csv")
    write_e_b1_reports(rows, output_path, run_config=run_config)


def write_e_b1_reports(
    rows: Sequence[MetricRow],
    output_dir: str | Path,
    *,
    run_config: dict[str, object] | None = None,
) -> None:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    aggregates = aggregate_rows(
        rows,
        group_by=("experiment", "n_parties", "push_suppression", "gossip_suppression", "log_suppression"),
        metrics=(
            "completeness",
            "p50_delta",
            "p95_delta",
            "p99_delta",
            "p999_delta",
            "max_delta",
            "channel_messages",
            "gossip_messages",
            "log_polls",
            "detection_required_numeric",
            "suppression_detected_numeric",
            "detected_within_budget_numeric",
            "detection_requirement_satisfied_numeric",
            "budget_requirement_satisfied_numeric",
            "undelivered_count",
        ),
    )
    write_rows_csv(aggregates, output_path / "e_b1_aggregate.csv")
    summary = summarize_e_b1(rows, aggregates, run_config=run_config)
    (output_path / "e_b1_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    (output_path / "e_b1_report.md").write_text(render_e_b1_markdown_report(summary, aggregates) + "\n")


def write_e_b1_reports_from_csv(
    output_dir: str | Path,
    *,
    run_config: dict[str, object] | None = None,
) -> None:
    output_path = Path(output_dir)
    rows = read_rows_csv(output_path / "e_b1_byzantine_sweep.csv")
    write_e_b1_reports(rows, output_path, run_config=run_config)


def write_e_b2_outputs(
    rows: Sequence[MetricRow],
    output_dir: str | Path,
    *,
    run_config: dict[str, object] | None = None,
) -> None:
    """Write raw rows, aggregate tables, JSON summary, and a Markdown report."""

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    write_rows_csv(rows, output_path / "e_b2_delta_prop_baselines.csv")
    aggregates = aggregate_rows(
        rows,
        group_by=(
            "experiment",
            "baseline_family",
            "strategy",
            "delivery_regime",
            "n_parties",
            "push_suppression",
            "status_suppression",
        ),
        metrics=(
            "completeness",
            "p50_delta",
            "p95_delta",
            "p99_delta",
            "p999_delta",
            "max_delta",
            "channel_messages",
            "push_messages",
            "gossip_messages",
            "log_polls",
            "status_messages",
            "delivery_bytes_total",
            "delivery_bytes_per_party",
            "per_party_state_bytes",
            "status_availability_loss_rate",
            "stale_acceptance_window",
            "unauthorized_ops_expected",
            "unauthorized_ops_worst",
            "undelivered_count",
        ),
    )
    write_rows_csv(aggregates, output_path / "e_b2_aggregate.csv")
    summary = summarize_e_b2(rows, aggregates, run_config=run_config)
    (output_path / "e_b2_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    (output_path / "e_b2_report.md").write_text(render_e_b2_markdown_report(summary, aggregates) + "\n")


def write_e_b3_outputs(
    rows: Sequence[MetricRow],
    output_dir: str | Path,
    *,
    run_config: dict[str, object] | None = None,
) -> None:
    """Write damage-budget raw rows, aggregates, JSON summary, and Markdown report."""

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    write_rows_csv(rows, output_path / "e_b3_damage_budget.csv")
    aggregates = aggregate_rows(
        rows,
        group_by=("experiment", "strategy", "n_parties", "ttl", "velocity", "budget"),
        metrics=(
            "delta_prop_for_damage",
            "unauthorized_ops_expected",
            "unauthorized_ops_worst",
            "budget_margin_expected",
            "budget_margin_worst",
            "expected_exceeds_budget_numeric",
            "worst_exceeds_budget_numeric",
            "propagation_share_expected",
            "propagation_share_worst",
            "source_completeness",
            "source_p99_delta",
            "source_max_delta",
            "undelivered_count",
        ),
    )
    write_rows_csv(aggregates, output_path / "e_b3_aggregate.csv")
    summary = summarize_e_b3(rows, aggregates, run_config=run_config)
    (output_path / "e_b3_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    (output_path / "e_b3_report.md").write_text(render_e_b3_markdown_report(summary, aggregates) + "\n")


def write_e_b4_outputs(
    rows: Sequence[MetricRow],
    output_dir: str | Path,
    *,
    run_config: dict[str, object] | None = None,
) -> None:
    """Write equivocation-resistance raw rows, aggregates, JSON summary, and Markdown report."""

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    write_rows_csv(rows, output_path / "e_b4_equivocation_resistance.csv")
    aggregates = aggregate_rows(
        rows,
        group_by=(
            "experiment",
            "scenario",
            "scenario_category",
            "root_count",
            "threshold",
            "corrupt_roots",
            "watcher_count",
            "watcher_coverage",
            "observation_interval",
            "party_reporting_fraction",
            "selective_disclosure",
            "partition_duration",
        ),
        metrics=(
            "certificate_accepted_numeric",
            "equivocation_detected_numeric",
            "outcome_success_numeric",
            "false_positive_numeric",
            "baseline_misses_attack_numeric",
            "detection_latency",
            "cross_observation_delay",
            "watcher_effective_reports",
            "watcher_detection_probability_model",
            "evidence_bytes",
        ),
    )
    write_rows_csv(aggregates, output_path / "e_b4_aggregate.csv")
    summary = summarize_e_b4(rows, aggregates, run_config=run_config)
    (output_path / "e_b4_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    (output_path / "e_b4_report.md").write_text(render_e_b4_markdown_report(summary, aggregates) + "\n")


def write_e_b5_outputs(
    rows: Sequence[MetricRow],
    output_dir: str | Path,
    *,
    run_config: dict[str, object] | None = None,
) -> None:
    """Write thin-A2A raw rows, aggregates, JSON summary, and Markdown report."""

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    write_rows_csv(rows, output_path / "e_b5_thin_a2a.csv")
    aggregates = aggregate_rows(
        rows,
        group_by=("experiment", "strategy", "n_parties", "a2a_transport_mode", "a2a_sdk_available"),
        metrics=(
            "completeness",
            "p50_delta",
            "p95_delta",
            "p99_delta",
            "max_delta",
            "channel_messages",
            "a2a_payload_bytes",
            "a2a_transport_delay_model",
            "unauthorized_ops_expected",
            "unauthorized_ops_worst",
            "undelivered_count",
        ),
    )
    write_rows_csv(aggregates, output_path / "e_b5_aggregate.csv")
    summary = summarize_e_b5(rows, aggregates, run_config=run_config)
    (output_path / "e_b5_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    (output_path / "e_b5_report.md").write_text(render_e_b5_markdown_report(summary, aggregates) + "\n")


def write_e_b6_outputs(
    rows: Sequence[MetricRow],
    output_dir: str | Path,
    *,
    run_config: dict[str, object] | None = None,
) -> None:
    """Write local end-to-end transport raw rows, aggregates, summary, and report."""

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    write_rows_csv(rows, output_path / "e_b6_local_e2e.csv")
    aggregates = aggregate_rows(
        rows,
        group_by=("experiment", "strategy", "n_parties", "service_model"),
        metrics=(
            "completeness",
            "p50_delta",
            "p95_delta",
            "p99_delta",
            "max_delta",
            "wall_time_seconds",
            "transport_requests",
            "transport_errors",
            "transport_bytes_sent",
            "transport_bytes_received",
            "push_delivered",
            "gossip_delivered",
            "log_polls",
            "root_certificate_verified_rate",
            "signature_verified_rate",
            "undelivered_count",
        ),
    )
    write_rows_csv(aggregates, output_path / "e_b6_aggregate.csv")
    summary = summarize_e_b6(rows, aggregates, run_config=run_config)
    (output_path / "e_b6_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    (output_path / "e_b6_report.md").write_text(render_e_b6_markdown_report(summary, aggregates) + "\n")


def write_e_b7_outputs(
    rows: Sequence[MetricRow],
    output_dir: str | Path,
    *,
    run_config: dict[str, object] | None = None,
) -> None:
    """Write reproducibility/sensitivity raw rows, aggregates, summary, manifest, and report."""

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    write_rows_csv(rows, output_path / "e_b7_sensitivity.csv")
    aggregates = aggregate_rows(
        rows,
        group_by=("experiment", "config_id", "sensitivity_axis", "n_parties", "gossip_fanout", "poll_interval", "jitter", "delay_scale"),
        metrics=(
            "completeness",
            "p50_delta",
            "p95_delta",
            "p99_delta",
            "max_delta",
            "channel_messages",
            "gossip_messages",
            "log_polls",
            "undelivered_count",
        ),
    )
    write_rows_csv(aggregates, output_path / "e_b7_aggregate.csv")
    summary = summarize_e_b7(rows, aggregates, run_config=run_config)
    manifest = reproducibility_manifest(rows, run_config=run_config)
    (output_path / "e_b7_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    (output_path / "reproducibility_manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    (output_path / "e_b7_report.md").write_text(render_e_b7_markdown_report(summary, aggregates, manifest) + "\n")


def write_e_b8_outputs(
    rows: Sequence[MetricRow],
    output_dir: str | Path,
    *,
    run_config: dict[str, object] | None = None,
) -> None:
    """Write agent-tool gateway raw rows, aggregates, summary, and report."""

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    write_rows_csv(rows, output_path / "e_b8_agent_tool_gateway.csv")
    aggregates = aggregate_rows(
        rows,
        group_by=(
            "experiment",
            "agent_runtime_model",
            "strategy",
            "n_parties",
            "ttl",
            "tool_call_rate",
            "push_suppression",
        ),
        metrics=(
            "completeness",
            "p99_delta",
            "stale_capability_window_mean",
            "stale_capability_window_p99",
            "stale_capability_window_max",
            "revoked_tool_calls_allowed",
            "revoked_tool_calls_prevented",
            "prevented_fraction",
            "audit_evidence_available_numeric",
            "channel_messages",
            "gateway_state_bytes",
            "undelivered_count",
        ),
    )
    write_rows_csv(aggregates, output_path / "e_b8_aggregate.csv")
    summary = summarize_e_b8(rows, aggregates, run_config=run_config)
    (output_path / "e_b8_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    (output_path / "e_b8_report.md").write_text(render_e_b8_markdown_report(summary, aggregates) + "\n")


def write_e_b9_outputs(
    rows: Sequence[MetricRow],
    output_dir: str | Path,
    *,
    run_config: dict[str, object] | None = None,
) -> None:
    """Write A2A lifecycle-binding raw rows, aggregates, summary, and report."""

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    write_rows_csv(rows, output_path / "e_b9_a2a_lifecycle_binding.csv")
    aggregates = aggregate_rows(
        rows,
        group_by=(
            "experiment",
            "compatibility_cell",
            "client_profile",
            "server_profile",
            "strategy",
            "n_parties",
            "ttl",
            "tool_call_rate",
            "fallback_policy",
        ),
        metrics=(
            "compatibility_correct_numeric",
            "schema_conformance_pass_numeric",
            "lifecycle_binding_success_numeric",
            "revocation_enforced_numeric",
            "task_available_numeric",
            "availability_loss_numeric",
            "effective_enforcement_latency",
            "client_abort_latency",
            "server_enforcement_latency",
            "revoked_tool_calls_allowed",
            "revoked_tool_calls_prevented",
            "prevented_fraction",
            "agent_card_bytes",
            "lifecycle_event_bytes",
            "channel_messages",
            "undelivered_count",
        ),
    )
    write_rows_csv(aggregates, output_path / "e_b9_aggregate.csv")
    summary = summarize_e_b9(rows, aggregates, run_config=run_config)
    (output_path / "e_b9_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    (output_path / "e_b9_report.md").write_text(render_e_b9_markdown_report(summary, aggregates) + "\n")


def write_e_b10_outputs(
    rows: Sequence[MetricRow],
    output_dir: str | Path,
    *,
    run_config: dict[str, object] | None = None,
) -> None:
    """Write real gateway/tool path raw rows, aggregates, summary, and report."""

    _write_integration_outputs(
        rows,
        output_dir,
        raw_filename="e_b10_real_gateway_tool_path.csv",
        aggregate_filename="e_b10_aggregate.csv",
        summary_filename="e_b10_summary.json",
        report_filename="e_b10_report.md",
        summarize=summarize_e_b10,
        render=render_e_b10_markdown_report,
        run_config=run_config,
    )


def write_e_b11_outputs(
    rows: Sequence[MetricRow],
    output_dir: str | Path,
    *,
    run_config: dict[str, object] | None = None,
) -> None:
    """Write protocol-boundary path raw rows, aggregates, summary, and report."""

    _write_integration_outputs(
        rows,
        output_dir,
        raw_filename="e_b11_protocol_boundary_path.csv",
        aggregate_filename="e_b11_aggregate.csv",
        summary_filename="e_b11_summary.json",
        report_filename="e_b11_report.md",
        summarize=summarize_e_b11,
        render=render_e_b11_markdown_report,
        run_config=run_config,
    )


def write_e_b12_outputs(
    rows: Sequence[MetricRow],
    output_dir: str | Path,
    *,
    run_config: dict[str, object] | None = None,
) -> None:
    """Write fault-injection path raw rows, aggregates, summary, and report."""

    _write_integration_outputs(
        rows,
        output_dir,
        raw_filename="e_b12_fault_injection_path.csv",
        aggregate_filename="e_b12_aggregate.csv",
        summary_filename="e_b12_summary.json",
        report_filename="e_b12_report.md",
        summarize=summarize_e_b12,
        render=render_e_b12_markdown_report,
        run_config=run_config,
    )


def write_e_b13_outputs(
    rows: Sequence[MetricRow],
    output_dir: str | Path,
    *,
    run_config: dict[str, object] | None = None,
) -> None:
    """Write Paper A agent-system bridge raw rows, aggregates, summary, and report."""

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    write_rows_csv(rows, output_path / "e_b13_paper_a_agent_system_bridge.csv")
    aggregates = _paper_a_bridge_aggregates(rows)
    write_rows_csv(aggregates, output_path / "e_b13_aggregate.csv")
    summary = summarize_e_b13(rows, aggregates, run_config=run_config)
    (output_path / "e_b13_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    (output_path / "e_b13_report.md").write_text(render_e_b13_markdown_report(summary, aggregates) + "\n")


def write_e_b14_outputs(
    rows: Sequence[MetricRow],
    output_dir: str | Path,
    *,
    run_config: dict[str, object] | None = None,
) -> None:
    """Write multi-process deployment raw rows, aggregates, summary, and report."""

    _write_integration_outputs(
        rows,
        output_dir,
        raw_filename="e_b14_multiprocess_deployment.csv",
        aggregate_filename="e_b14_aggregate.csv",
        summary_filename="e_b14_summary.json",
        report_filename="e_b14_report.md",
        summarize=summarize_e_b14,
        render=render_e_b14_markdown_report,
        run_config=run_config,
    )


def write_e_b15_outputs(
    rows: Sequence[MetricRow],
    output_dir: str | Path,
    *,
    run_config: dict[str, object] | None = None,
) -> None:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    write_rows_csv(rows, output_path / "e_b15_real_agent_tool_path.csv")
    aggregates = _agent_path_aggregates(rows)
    write_rows_csv(aggregates, output_path / "e_b15_aggregate.csv")
    summary = summarize_e_b15(rows, aggregates, run_config=run_config)
    (output_path / "e_b15_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    (output_path / "e_b15_report.md").write_text(render_e_b15_markdown_report(summary, aggregates) + "\n")


def write_e_b16_outputs(
    rows: Sequence[MetricRow],
    output_dir: str | Path,
    *,
    run_config: dict[str, object] | None = None,
) -> None:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    write_rows_csv(rows, output_path / "e_b16_status_outage_baselines.csv")
    aggregates = _status_baseline_aggregates(rows)
    write_rows_csv(aggregates, output_path / "e_b16_aggregate.csv")
    summary = summarize_e_b16(rows, aggregates, run_config=run_config)
    (output_path / "e_b16_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    (output_path / "e_b16_report.md").write_text(render_e_b16_markdown_report(summary, aggregates) + "\n")


def _write_integration_outputs(
    rows: Sequence[MetricRow],
    output_dir: str | Path,
    *,
    raw_filename: str,
    aggregate_filename: str,
    summary_filename: str,
    report_filename: str,
    summarize: object,
    render: object,
    run_config: dict[str, object] | None,
) -> None:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    write_rows_csv(rows, output_path / raw_filename)
    aggregates = _integration_aggregates(rows)
    write_rows_csv(aggregates, output_path / aggregate_filename)
    summary = summarize(rows, aggregates, run_config=run_config)  # type: ignore[operator]
    (output_path / summary_filename).write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    (output_path / report_filename).write_text(render(summary, aggregates) + "\n")  # type: ignore[operator]


def _integration_aggregates(rows: Sequence[MetricRow]) -> list[MetricRow]:
    return aggregate_rows(
        rows,
        group_by=(
            "experiment",
            "integration_surface",
            "protocol_profile",
            "fault_scenario",
            "n_parties",
            "ttl",
            "tool_call_rate",
        ),
        metrics=(
            "integration_success_numeric",
            "protocol_schema_pass_rate",
            "pre_revocation_allowed_rate",
            "post_repair_reject_rate",
            "stale_capability_window_mean",
            "stale_capability_window_p99",
            "stale_capability_window_max",
            "effective_enforcement_latency",
            "fault_recovery_latency_p99",
            "revoked_tool_calls_allowed",
            "revoked_tool_calls_prevented",
            "prevented_fraction",
            "sampled_revoked_calls_allowed",
            "sampled_revoked_calls_rejected",
            "transport_requests",
            "transport_errors",
            "transport_bytes_sent",
            "transport_bytes_received",
            "forwarded_tool_calls",
            "gateway_restarts",
            "log_repairs",
            "audit_evidence_available_numeric",
        ),
    )


def _paper_a_bridge_aggregates(rows: Sequence[MetricRow]) -> list[MetricRow]:
    return aggregate_rows(
        rows,
        group_by=(
            "experiment",
            "source_experiment",
            "framework_surface",
            "evidence_class",
            "real_agent_framework_runtime_numeric",
            "executable_agent_runtime_numeric",
            "production_deployment_numeric",
        ),
        metrics=(
            "trace_units",
            "signed_delegation_events",
            "valid_signed_delegation_events",
            "valid_signed_delegation_rate",
            "alternate_parent_cases",
            "alternate_parent_preserved_by_edge_target",
            "alternate_parent_wrongly_revoked_by_tree",
            "cross_domain_target_cases",
            "cross_domain_under_revoked_by_scoped",
            "multiparent_trace_fraction",
            "cross_deployer_trace_fraction",
            "proof_verified_rate",
            "authorized_revocation_verified_rate",
            "unauthorized_rejected_rate",
            "omission_rejected_rate",
            "cross_deployer_revocation_verified_rate",
            "tasks_configured",
            "task_callbacks_observed",
            "llm_calls_observed",
        ),
    )


def _agent_path_aggregates(rows: Sequence[MetricRow]) -> list[MetricRow]:
    return aggregate_rows(
        rows,
        group_by=(
            "experiment",
            "path_profile",
            "agent_runtime",
            "protocol_profile",
            "fault_scenario",
            "n_gateways",
            "tool_call_rate",
        ),
        metrics=(
            "integration_success_numeric",
            "real_mcp_package_numeric",
            "mcp_calltool_request_validated_numeric",
            "real_langgraph_runtime_numeric",
            "langgraph_workflow_completed_numeric",
            "protocol_schema_pass_rate",
            "pre_revocation_allowed_rate",
            "post_repair_reject_rate",
            "stale_capability_window_mean",
            "stale_capability_window_p99",
            "stale_capability_window_max",
            "revoked_tool_calls_allowed",
            "revoked_tool_calls_prevented",
            "prevented_fraction",
            "transport_requests",
            "transport_errors",
            "tool_calls_observed",
        ),
    )


def _status_baseline_aggregates(rows: Sequence[MetricRow]) -> list[MetricRow]:
    return aggregate_rows(
        rows,
        group_by=(
            "experiment",
            "strategy",
            "baseline_family",
            "fault_scenario",
            "n_gateways",
            "tool_call_rate",
        ),
        metrics=(
            "integration_success_numeric",
            "status_service_boundary_numeric",
            "outage_injected_numeric",
            "pre_revocation_allowed_rate",
            "post_repair_reject_rate",
            "status_queries",
            "status_errors",
            "availability_loss_rate",
            "stale_capability_window_mean",
            "stale_capability_window_p99",
            "stale_capability_window_max",
            "revoked_tool_calls_allowed",
            "revoked_tool_calls_prevented",
            "prevented_fraction",
            "transport_requests",
            "transport_errors",
        ),
    )


def aggregate_rows(
    rows: Sequence[MetricRow],
    *,
    group_by: Sequence[str],
    metrics: Sequence[str],
) -> list[MetricRow]:
    groups: dict[tuple[object, ...], list[MetricRow]] = {}
    for row in rows:
        key = tuple(row.get(field) for field in group_by)
        groups.setdefault(key, []).append(row)

    aggregates: list[MetricRow] = []
    for key, group in sorted(groups.items(), key=lambda item: tuple(str(part) for part in item[0])):
        aggregate: MetricRow = {field: value for field, value in zip(group_by, key, strict=True)}
        aggregate["runs"] = len(group)
        for metric in metrics:
            values = [_as_float(row.get(metric)) for row in group]
            values = [value for value in values if value is not None]
            if not values:
                continue
            aggregate[f"{metric}_mean"] = statistics.fmean(values)
            aggregate[f"{metric}_min"] = min(values)
            aggregate[f"{metric}_max"] = max(values)
            if len(values) > 1:
                stdev = statistics.stdev(values)
                aggregate[f"{metric}_stdev"] = stdev
                aggregate[f"{metric}_ci95"] = 1.96 * stdev / math.sqrt(len(values))
            else:
                aggregate[f"{metric}_stdev"] = 0.0
                aggregate[f"{metric}_ci95"] = 0.0
        aggregates.append(aggregate)
    return aggregates


def summarize_e_b2(
    rows: Sequence[MetricRow],
    aggregates: Sequence[MetricRow] | None = None,
    *,
    run_config: dict[str, object] | None = None,
) -> dict[str, object]:
    aggregates = list(aggregates) if aggregates is not None else aggregate_rows(
        rows,
        group_by=(
            "experiment",
            "baseline_family",
            "strategy",
            "delivery_regime",
            "n_parties",
            "push_suppression",
            "status_suppression",
        ),
        metrics=(
            "completeness",
            "p99_delta",
            "channel_messages",
            "delivery_bytes_per_party",
            "per_party_state_bytes",
            "status_availability_loss_rate",
            "stale_acceptance_window",
            "undelivered_count",
        ),
    )

    def family(row: MetricRow) -> str:
        value = row.get("baseline_family")
        return "propagation-strategy" if value in {None, ""} else str(value)

    propagation_aggregates = [row for row in aggregates if family(row) == "propagation-strategy"]
    delivery_aggregates = [row for row in aggregates if family(row) == "delivery-regime"]

    by_n: dict[str, list[MetricRow]] = {}
    for aggregate in propagation_aggregates:
        by_n.setdefault(str(aggregate.get("n_parties")), []).append(aggregate)

    strategy_summaries: list[dict[str, object]] = []
    for aggregate in aggregates:
        strategy_summaries.append(
            {
                "baseline_family": family(aggregate),
                "strategy": aggregate.get("strategy"),
                "delivery_regime": aggregate.get("delivery_regime"),
                "n_parties": aggregate.get("n_parties"),
                "push_suppression": aggregate.get("push_suppression"),
                "status_suppression": aggregate.get("status_suppression"),
                "runs": aggregate.get("runs"),
                "completeness_mean": aggregate.get("completeness_mean"),
                "completeness_ci95": aggregate.get("completeness_ci95"),
                "p99_delta_mean": aggregate.get("p99_delta_mean"),
                "p99_delta_ci95": aggregate.get("p99_delta_ci95"),
                "channel_messages_mean": aggregate.get("channel_messages_mean"),
                "channel_messages_ci95": aggregate.get("channel_messages_ci95"),
                "delivery_bytes_per_party_mean": aggregate.get("delivery_bytes_per_party_mean"),
                "per_party_state_bytes_mean": aggregate.get("per_party_state_bytes_mean"),
                "stale_acceptance_window_mean": aggregate.get("stale_acceptance_window_mean"),
                "status_availability_loss_rate_mean": aggregate.get("status_availability_loss_rate_mean"),
                "undelivered_count_mean": aggregate.get("undelivered_count_mean"),
            }
        )

    comparisons: list[dict[str, object]] = []
    for n_parties, grouped in by_n.items():
        lookup = {str(row.get("strategy")): row for row in grouped}
        hybrid = lookup.get("hybrid")
        push_gossip = lookup.get("push-gossip")
        ttl = lookup.get("ttl-rcc")
        log = lookup.get("log")
        push = lookup.get("push")
        if hybrid is not None:
            comparison: dict[str, object] = {
                "n_parties": int(float(n_parties)),
                "hybrid_p99_delta_mean": hybrid.get("p99_delta_mean"),
                "hybrid_completeness_mean": hybrid.get("completeness_mean"),
                "hybrid_channel_messages_mean": hybrid.get("channel_messages_mean"),
            }
            if push_gossip is not None:
                comparison["hybrid_minus_push_gossip_p99"] = _sub(
                    hybrid.get("p99_delta_mean"),
                    push_gossip.get("p99_delta_mean"),
                )
                comparison["hybrid_over_push_gossip_messages"] = _ratio(
                    hybrid.get("channel_messages_mean"),
                    push_gossip.get("channel_messages_mean"),
                )
            if log is not None:
                comparison["hybrid_minus_log_p99"] = _sub(hybrid.get("p99_delta_mean"), log.get("p99_delta_mean"))
            if ttl is not None:
                comparison["hybrid_minus_ttl_rcc_p99"] = _sub(
                    hybrid.get("p99_delta_mean"),
                    ttl.get("p99_delta_mean"),
                )
            if push is not None:
                comparison["push_completeness_mean"] = push.get("completeness_mean")
            comparisons.append(comparison)

    delivery_by_cell: dict[tuple[str, str], dict[str, MetricRow]] = {}
    for aggregate in delivery_aggregates:
        key = (str(aggregate.get("n_parties")), str(aggregate.get("status_suppression")))
        regime = str(aggregate.get("delivery_regime") or aggregate.get("strategy"))
        delivery_by_cell.setdefault(key, {})[regime] = aggregate

    delivery_comparisons: list[dict[str, object]] = []
    for (n_parties, status_suppression), lookup in sorted(
        delivery_by_cell.items(),
        key=lambda item: (float(item[0][0]), str(item[0][1])),
    ):
        hybrid = lookup.get("hybrid")
        if hybrid is None:
            continue
        comparison: dict[str, object] = {
            "n_parties": _coerce_number(n_parties),
            "status_suppression": _coerce_number(status_suppression),
            "hybrid_p99_delta_mean": hybrid.get("p99_delta_mean"),
            "hybrid_stale_acceptance_window_mean": hybrid.get("stale_acceptance_window_mean"),
            "hybrid_delivery_bytes_per_party_mean": hybrid.get("delivery_bytes_per_party_mean"),
            "hybrid_per_party_state_bytes_mean": hybrid.get("per_party_state_bytes_mean"),
        }
        for regime in ("full-snapshot", "request-time-check", "request-time-fail-open", "compact-delta", "dns-log-poll"):
            baseline = lookup.get(regime)
            if baseline is None:
                continue
            key_prefix = regime.replace("-", "_")
            comparison[f"hybrid_over_{key_prefix}_stale_window"] = _ratio(
                hybrid.get("stale_acceptance_window_mean"),
                baseline.get("stale_acceptance_window_mean"),
            )
            comparison[f"hybrid_over_{key_prefix}_bytes"] = _ratio(
                hybrid.get("delivery_bytes_per_party_mean"),
                baseline.get("delivery_bytes_per_party_mean"),
            )
            comparison[f"{key_prefix}_p99_delta_mean"] = baseline.get("p99_delta_mean")
            comparison[f"{key_prefix}_stale_acceptance_window_mean"] = baseline.get(
                "stale_acceptance_window_mean"
            )
        delivery_comparisons.append(comparison)

    return {
        "experiment": "E-B2",
        "run_config": run_config or {},
        "raw_rows": len(rows),
        "aggregate_rows": len(aggregates),
        "strategy_summaries": strategy_summaries,
        "comparisons": comparisons,
        "delivery_regime_comparisons": delivery_comparisons,
        "claim_note": (
            "Hybrid should be framed as near push-gossip latency with log-backed auditability, "
            "not as an unconditional latency winner. Delivery-regime baselines are mechanism-level "
            "simulations for related-work comparison, not faithful reimplementations of CRLite, "
            "Clubcards, RevDNS, OCSP, or VC status-list systems."
        ),
    }


def render_e_b2_markdown_report(summary: dict[str, object], aggregates: Sequence[MetricRow]) -> str:
    lines = [
        "# E-B2 Delta Propagation Baseline Report",
        "",
        f"Raw rows: {summary['raw_rows']}",
        f"Aggregate rows: {summary['aggregate_rows']}",
        "",
        "## Run Config",
        "",
    ]
    run_config = summary.get("run_config", {})
    if isinstance(run_config, dict) and run_config:
        for key in sorted(run_config):
            lines.append(f"- `{key}`: `{run_config[key]}`")
    else:
        lines.append("- No run config recorded.")
    lines.extend(
        [
            "",
            "## Strategy Aggregates",
            "",
            "| family | n | strategy/regime | push drop | status drop | runs | completeness mean +- ci95 | p99 delta mean +- ci95 | messages mean +- ci95 | stale window | bytes/party | state/party | undelivered mean |",
            "|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for row in sorted(
        aggregates,
        key=lambda item: (
            str(item.get("baseline_family")),
            float(item.get("n_parties", 0)),
            str(item.get("strategy")),
            str(item.get("delivery_regime")),
            str(item.get("status_suppression")),
        ),
    ):
        family = row.get("baseline_family") or "propagation-strategy"
        label = row.get("delivery_regime") or row.get("strategy")
        lines.append(
            "| {family} | {n} | {label} | {push} | {status} | {runs} | {comp} +- {comp_ci} | {p99} +- {p99_ci} | {msg} +- {msg_ci} | {stale} | {bytes_per_party} | {state} | {undelivered} |".format(
                family=family,
                n=_fmt(row.get("n_parties"), 0),
                label=label,
                push=_fmt(row.get("push_suppression"), 2),
                status=_fmt(row.get("status_suppression"), 2),
                runs=row.get("runs"),
                comp=_fmt(row.get("completeness_mean"), 4),
                comp_ci=_fmt(row.get("completeness_ci95"), 4),
                p99=_fmt(row.get("p99_delta_mean"), 4),
                p99_ci=_fmt(row.get("p99_delta_ci95"), 4),
                msg=_fmt(row.get("channel_messages_mean"), 1),
                msg_ci=_fmt(row.get("channel_messages_ci95"), 1),
                stale=_fmt(row.get("stale_acceptance_window_mean"), 4),
                bytes_per_party=_fmt(row.get("delivery_bytes_per_party_mean"), 1),
                state=_fmt(row.get("per_party_state_bytes_mean"), 1),
                undelivered=_fmt(row.get("undelivered_count_mean"), 2),
            )
        )
    lines.extend(["", "## Hybrid Comparisons", ""])
    comparisons = summary.get("comparisons", [])
    if isinstance(comparisons, list) and comparisons:
        lines.extend(
            [
                "| n | hybrid p99 | hybrid - push-gossip p99 | hybrid - log p99 | hybrid - TTL p99 | hybrid / push-gossip messages |",
                "|---:|---:|---:|---:|---:|---:|",
            ]
        )
        for comparison in comparisons:
            lines.append(
                "| {n} | {hybrid} | {pg} | {log} | {ttl} | {msgs} |".format(
                    n=comparison.get("n_parties"),
                    hybrid=_fmt(comparison.get("hybrid_p99_delta_mean"), 4),
                    pg=_fmt(comparison.get("hybrid_minus_push_gossip_p99"), 4),
                    log=_fmt(comparison.get("hybrid_minus_log_p99"), 4),
                    ttl=_fmt(comparison.get("hybrid_minus_ttl_rcc_p99"), 4),
                    msgs=_fmt(comparison.get("hybrid_over_push_gossip_messages"), 3),
                )
            )
    else:
        lines.append("No hybrid comparison rows available.")
    lines.extend(["", "## Delivery Regime Comparisons", ""])
    delivery_comparisons = summary.get("delivery_regime_comparisons", [])
    if isinstance(delivery_comparisons, list) and delivery_comparisons:
        lines.extend(
            [
                "| n | status drop | hybrid stale window | hybrid/full snapshot stale | hybrid/fail-open stale | hybrid/compact delta stale | hybrid/dns-poll stale | hybrid/full snapshot bytes |",
                "|---:|---:|---:|---:|---:|---:|---:|---:|",
            ]
        )
        for comparison in delivery_comparisons:
            lines.append(
                "| {n} | {status} | {hybrid_stale} | {full_stale} | {fail_open_stale} | {delta_stale} | {dns_stale} | {full_bytes} |".format(
                    n=_fmt(comparison.get("n_parties"), 0),
                    status=_fmt(comparison.get("status_suppression"), 2),
                    hybrid_stale=_fmt(comparison.get("hybrid_stale_acceptance_window_mean"), 4),
                    full_stale=_fmt(comparison.get("hybrid_over_full_snapshot_stale_window"), 3),
                    fail_open_stale=_fmt(comparison.get("hybrid_over_request_time_fail_open_stale_window"), 3),
                    delta_stale=_fmt(comparison.get("hybrid_over_compact_delta_stale_window"), 3),
                    dns_stale=_fmt(comparison.get("hybrid_over_dns_log_poll_stale_window"), 3),
                    full_bytes=_fmt(comparison.get("hybrid_over_full_snapshot_bytes"), 3),
                )
            )
    else:
        lines.append("No delivery-regime comparison rows available.")
    lines.extend(["", "## Interpretation", "", str(summary.get("claim_note", ""))])
    return "\n".join(lines)


def summarize_e_b3(
    rows: Sequence[MetricRow],
    aggregates: Sequence[MetricRow] | None = None,
    *,
    run_config: dict[str, object] | None = None,
) -> dict[str, object]:
    aggregates = list(aggregates) if aggregates is not None else aggregate_rows(
        rows,
        group_by=("experiment", "strategy", "n_parties", "ttl", "velocity", "budget"),
        metrics=(
            "delta_prop_for_damage",
            "unauthorized_ops_expected",
            "unauthorized_ops_worst",
            "expected_exceeds_budget_numeric",
            "worst_exceeds_budget_numeric",
            "source_completeness",
            "undelivered_count",
        ),
    )

    strategy_summaries: list[dict[str, object]] = []
    for aggregate in aggregates:
        strategy_summaries.append(
            {
                "strategy": aggregate.get("strategy"),
                "n_parties": aggregate.get("n_parties"),
                "ttl": aggregate.get("ttl"),
                "velocity": aggregate.get("velocity"),
                "budget": aggregate.get("budget"),
                "runs": aggregate.get("runs"),
                "delta_prop_for_damage_mean": aggregate.get("delta_prop_for_damage_mean"),
                "unauthorized_ops_expected_mean": aggregate.get("unauthorized_ops_expected_mean"),
                "unauthorized_ops_worst_mean": aggregate.get("unauthorized_ops_worst_mean"),
                "expected_exceeds_budget_rate": aggregate.get("expected_exceeds_budget_numeric_mean"),
                "worst_exceeds_budget_rate": aggregate.get("worst_exceeds_budget_numeric_mean"),
                "source_completeness_mean": aggregate.get("source_completeness_mean"),
                "undelivered_count_mean": aggregate.get("undelivered_count_mean"),
            }
        )

    grouped: dict[tuple[str, str, str, str], dict[str, MetricRow]] = {}
    for aggregate in aggregates:
        key = (
            str(aggregate.get("n_parties")),
            str(aggregate.get("ttl")),
            str(aggregate.get("velocity")),
            str(aggregate.get("budget")),
        )
        grouped.setdefault(key, {})[str(aggregate.get("strategy"))] = aggregate

    comparisons: list[dict[str, object]] = []
    hybrid_safe_baseline_worst_exceeds = 0
    hybrid_safe_baseline_expected_exceeds = 0
    for (n_parties, ttl, velocity, budget), lookup in sorted(grouped.items()):
        hybrid = lookup.get("hybrid")
        if hybrid is None:
            continue
        comparison: dict[str, object] = {
            "n_parties": _coerce_number(n_parties),
            "ttl": _coerce_number(ttl),
            "velocity": _coerce_number(velocity),
            "budget": _coerce_number(budget),
            "hybrid_expected_mean": hybrid.get("unauthorized_ops_expected_mean"),
            "hybrid_worst_mean": hybrid.get("unauthorized_ops_worst_mean"),
            "hybrid_expected_exceeds_rate": hybrid.get("expected_exceeds_budget_numeric_mean"),
            "hybrid_worst_exceeds_rate": hybrid.get("worst_exceeds_budget_numeric_mean"),
        }
        hybrid_expected_safe = _as_float(hybrid.get("expected_exceeds_budget_numeric_mean")) == 0.0
        hybrid_worst_safe = _as_float(hybrid.get("worst_exceeds_budget_numeric_mean")) == 0.0
        for baseline_name in ("push", "ttl-rcc", "push-gossip"):
            baseline = lookup.get(baseline_name)
            if baseline is None:
                continue
            expected_key = baseline_name.replace("-", "_")
            comparison[f"hybrid_over_{expected_key}_expected"] = _ratio(
                hybrid.get("unauthorized_ops_expected_mean"),
                baseline.get("unauthorized_ops_expected_mean"),
            )
            comparison[f"hybrid_over_{expected_key}_worst"] = _ratio(
                hybrid.get("unauthorized_ops_worst_mean"),
                baseline.get("unauthorized_ops_worst_mean"),
            )
            comparison[f"{expected_key}_expected_exceeds_rate"] = baseline.get(
                "expected_exceeds_budget_numeric_mean"
            )
            comparison[f"{expected_key}_worst_exceeds_rate"] = baseline.get("worst_exceeds_budget_numeric_mean")
        push = lookup.get("push")
        ttl_rcc = lookup.get("ttl-rcc")
        if hybrid_worst_safe and (
            _as_float(push.get("worst_exceeds_budget_numeric_mean") if push else None) == 1.0
            or _as_float(ttl_rcc.get("worst_exceeds_budget_numeric_mean") if ttl_rcc else None) == 1.0
        ):
            hybrid_safe_baseline_worst_exceeds += 1
        if hybrid_expected_safe and (
            _as_float(push.get("expected_exceeds_budget_numeric_mean") if push else None) == 1.0
            or _as_float(ttl_rcc.get("expected_exceeds_budget_numeric_mean") if ttl_rcc else None) == 1.0
        ):
            hybrid_safe_baseline_expected_exceeds += 1
        comparisons.append(comparison)

    return {
        "experiment": "E-B3",
        "run_config": run_config or {},
        "raw_rows": len(rows),
        "aggregate_rows": len(aggregates),
        "strategy_summaries": strategy_summaries,
        "comparisons": comparisons,
        "hybrid_safe_baseline_expected_exceeds_cells": hybrid_safe_baseline_expected_exceeds,
        "hybrid_safe_baseline_worst_exceeds_cells": hybrid_safe_baseline_worst_exceeds,
        "max_expected_damage": _max_metric(rows, "unauthorized_ops_expected"),
        "max_worst_damage": _max_metric(rows, "unauthorized_ops_worst"),
        "claim_note": (
            "E-B3 maps measured propagation delay into stale-authority damage. "
            "Report both expected and worst-case budget violations because TTL fallback can make "
            "push-only and TTL-RCC differ from hybrid mainly in the worst-case region."
        ),
    }


def render_e_b3_markdown_report(summary: dict[str, object], aggregates: Sequence[MetricRow]) -> str:
    lines = [
        "# E-B3 Damage Budget Report",
        "",
        f"Raw rows: {summary['raw_rows']}",
        f"Aggregate rows: {summary['aggregate_rows']}",
        f"Hybrid safe while baseline expected exceeds cells: {summary['hybrid_safe_baseline_expected_exceeds_cells']}",
        f"Hybrid safe while baseline worst exceeds cells: {summary['hybrid_safe_baseline_worst_exceeds_cells']}",
        f"Maximum expected damage: {_fmt(summary.get('max_expected_damage'), 2)}",
        f"Maximum worst-case damage: {_fmt(summary.get('max_worst_damage'), 2)}",
        "",
        "## Run Config",
        "",
    ]
    run_config = summary.get("run_config", {})
    if isinstance(run_config, dict) and run_config:
        for key in sorted(run_config):
            lines.append(f"- `{key}`: `{run_config[key]}`")
    else:
        lines.append("- No run config recorded.")

    focus = [
        row
        for row in aggregates
        if _as_float(row.get("ttl")) == 60.0
        and _as_float(row.get("velocity")) == 10.0
        and _as_float(row.get("budget")) == 1000.0
    ]
    lines.extend(
        [
            "",
            "## Focus Slice: TTL=60, velocity=10, budget=1000",
            "",
            "| n | strategy | runs | expected mean | worst mean | expected exceed | worst exceed | damage delta | source completeness |",
            "|---:|---|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for row in sorted(focus, key=lambda item: (float(item.get("n_parties", 0)), str(item.get("strategy")))):
        lines.append(
            "| {n} | {strategy} | {runs} | {expected} | {worst} | {expected_exceed} | {worst_exceed} | {delta} | {completeness} |".format(
                n=_fmt(row.get("n_parties"), 0),
                strategy=row.get("strategy"),
                runs=row.get("runs"),
                expected=_fmt(row.get("unauthorized_ops_expected_mean"), 2),
                worst=_fmt(row.get("unauthorized_ops_worst_mean"), 2),
                expected_exceed=_fmt(row.get("expected_exceeds_budget_numeric_mean"), 2),
                worst_exceed=_fmt(row.get("worst_exceeds_budget_numeric_mean"), 2),
                delta=_fmt(row.get("delta_prop_for_damage_mean"), 4),
                completeness=_fmt(row.get("source_completeness_mean"), 4),
            )
        )

    comparisons = summary.get("comparisons", [])
    evidence_rows = []
    if isinstance(comparisons, list):
        for comparison in comparisons:
            hybrid_worst = _as_float(comparison.get("hybrid_worst_exceeds_rate"))
            push_worst = _as_float(comparison.get("push_worst_exceeds_rate"))
            ttl_worst = _as_float(comparison.get("ttl_rcc_worst_exceeds_rate"))
            if hybrid_worst == 0.0 and (push_worst == 1.0 or ttl_worst == 1.0):
                evidence_rows.append(comparison)
    lines.extend(
        [
            "",
            "## H4 Evidence Cells",
            "",
            "| n | ttl | velocity | budget | hybrid expected | hybrid worst | hybrid/push expected | hybrid/ttl expected |",
            "|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for comparison in evidence_rows[:24]:
        lines.append(
            "| {n} | {ttl} | {velocity} | {budget} | {expected} | {worst} | {push_ratio} | {ttl_ratio} |".format(
                n=_fmt(comparison.get("n_parties"), 0),
                ttl=_fmt(comparison.get("ttl"), 0),
                velocity=_fmt(comparison.get("velocity"), 0),
                budget=_fmt(comparison.get("budget"), 0),
                expected=_fmt(comparison.get("hybrid_expected_mean"), 2),
                worst=_fmt(comparison.get("hybrid_worst_mean"), 2),
                push_ratio=_fmt(comparison.get("hybrid_over_push_expected"), 3),
                ttl_ratio=_fmt(comparison.get("hybrid_over_ttl_rcc_expected"), 3),
            )
        )
    if not evidence_rows:
        lines.append("|  |  |  |  |  |  |  |  |")

    lines.extend(["", "## Interpretation", "", str(summary.get("claim_note", ""))])
    return "\n".join(lines)


def summarize_e_b4(
    rows: Sequence[MetricRow],
    aggregates: Sequence[MetricRow] | None = None,
    *,
    run_config: dict[str, object] | None = None,
) -> dict[str, object]:
    aggregates = list(aggregates) if aggregates is not None else aggregate_rows(
        rows,
        group_by=(
            "experiment",
            "scenario",
            "scenario_category",
            "root_count",
            "threshold",
            "corrupt_roots",
            "watcher_count",
            "watcher_coverage",
            "observation_interval",
            "party_reporting_fraction",
            "selective_disclosure",
            "partition_duration",
        ),
        metrics=(
            "certificate_accepted_numeric",
            "equivocation_detected_numeric",
            "outcome_success_numeric",
            "false_positive_numeric",
            "baseline_misses_attack_numeric",
            "detection_latency",
            "cross_observation_delay",
            "watcher_effective_reports",
            "watcher_detection_probability_model",
            "evidence_bytes",
        ),
    )
    below_threshold = [
        row
        for row in rows
        if row.get("scenario_category") == "root-threshold"
        and _as_float(row.get("expected_certificate_accepted_numeric")) == 0.0
    ]
    split_view = [row for row in rows if row.get("scenario_category") in {"split-view", "partition-heal"}]
    benign = [row for row in rows if row.get("scenario_category") == "benign"]
    baseline_attacks = [row for row in rows if _as_float(row.get("baseline_misses_attack_numeric")) == 1.0]
    watcher_rows = [row for row in rows if row.get("scenario_category") == "watcher-coverage"]

    scenario_summaries: list[dict[str, object]] = []
    for aggregate in aggregates:
        scenario_summaries.append(
            {
                "scenario": aggregate.get("scenario"),
                "scenario_category": aggregate.get("scenario_category"),
                "root_count": aggregate.get("root_count"),
                "threshold": aggregate.get("threshold"),
                "corrupt_roots": aggregate.get("corrupt_roots"),
                "watcher_count": aggregate.get("watcher_count"),
                "watcher_coverage": aggregate.get("watcher_coverage"),
                "observation_interval": aggregate.get("observation_interval"),
                "party_reporting_fraction": aggregate.get("party_reporting_fraction"),
                "selective_disclosure": aggregate.get("selective_disclosure"),
                "partition_duration": aggregate.get("partition_duration"),
                "runs": aggregate.get("runs"),
                "certificate_acceptance_rate": aggregate.get("certificate_accepted_numeric_mean"),
                "equivocation_detection_rate": aggregate.get("equivocation_detected_numeric_mean"),
                "outcome_success_rate": aggregate.get("outcome_success_numeric_mean"),
                "false_positive_rate": aggregate.get("false_positive_numeric_mean"),
                "baseline_miss_rate": aggregate.get("baseline_misses_attack_numeric_mean"),
                "detection_latency_mean": aggregate.get("detection_latency_mean"),
                "detection_latency_max": aggregate.get("detection_latency_max"),
                "watcher_effective_reports_mean": aggregate.get("watcher_effective_reports_mean"),
                "watcher_detection_probability_model_mean": aggregate.get(
                    "watcher_detection_probability_model_mean"
                ),
                "evidence_bytes_mean": aggregate.get("evidence_bytes_mean"),
            }
        )

    watcher_aggregates = [row for row in aggregates if row.get("scenario_category") == "watcher-coverage"]
    full_detection_coverages = [
        _as_float(row.get("watcher_coverage"))
        for row in watcher_aggregates
        if _as_float(row.get("equivocation_detected_numeric_mean")) == 1.0
    ]
    full_detection_coverages = [value for value in full_detection_coverages if value is not None]

    return {
        "experiment": "E-B4",
        "run_config": run_config or {},
        "raw_rows": len(rows),
        "aggregate_rows": len(aggregates),
        "below_threshold_rejection_rate": _mean(
            [1.0 - float(row["certificate_accepted_numeric"]) for row in below_threshold]
        ),
        "split_view_detection_rate": _mean([row.get("equivocation_detected_numeric") for row in split_view]),
        "benign_false_positive_rate": _mean([row.get("false_positive_numeric") for row in benign]),
        "baseline_miss_rate": _mean([row.get("baseline_misses_attack_numeric") for row in baseline_attacks]),
        "max_detection_latency": _max_metric(split_view, "detection_latency"),
        "mean_evidence_bytes": _mean([row.get("evidence_bytes") for row in split_view]),
        "watcher_detection_rate": _mean([row.get("equivocation_detected_numeric") for row in watcher_rows]),
        "watcher_max_detection_latency": _max_metric(watcher_rows, "detection_latency"),
        "min_watcher_coverage_for_full_detection": min(full_detection_coverages) if full_detection_coverages else None,
        "scenario_summaries": scenario_summaries,
        "claim_note": (
            "E-B4 supports the root-threshold plus STH cross-observation story: below-threshold roots fail "
            "certificate verification, while quorum-certified split views are detected after honest observers "
            "compare same-size STHs. The watcher-coverage extension measures how strongly this depends on "
            "observer count, reporting coverage, observation interval, and selective disclosure."
        ),
    }


def render_e_b4_markdown_report(summary: dict[str, object], aggregates: Sequence[MetricRow]) -> str:
    lines = [
        "# E-B4 Equivocation Resistance Report",
        "",
        f"Raw rows: {summary['raw_rows']}",
        f"Aggregate rows: {summary['aggregate_rows']}",
        f"Below-threshold rejection rate: {_fmt(summary.get('below_threshold_rejection_rate'), 4)}",
        f"Split-view detection rate: {_fmt(summary.get('split_view_detection_rate'), 4)}",
        f"Benign false-positive rate: {_fmt(summary.get('benign_false_positive_rate'), 4)}",
        f"Baseline miss rate: {_fmt(summary.get('baseline_miss_rate'), 4)}",
        f"Max detection latency: {_fmt(summary.get('max_detection_latency'), 4)}",
        f"Mean evidence bytes: {_fmt(summary.get('mean_evidence_bytes'), 1)}",
        f"Watcher detection rate: {_fmt(summary.get('watcher_detection_rate'), 4)}",
        f"Watcher max detection latency: {_fmt(summary.get('watcher_max_detection_latency'), 4)}",
        f"Min watcher coverage for a full-detection aggregate cell: {_fmt(summary.get('min_watcher_coverage_for_full_detection'), 4)}",
        "",
        "## Run Config",
        "",
    ]
    run_config = summary.get("run_config", {})
    if isinstance(run_config, dict) and run_config:
        for key in sorted(run_config):
            lines.append(f"- `{key}`: `{run_config[key]}`")
    else:
        lines.append("- No run config recorded.")
    lines.extend(
        [
            "",
            "## Scenario Aggregates",
            "",
            "| scenario | roots | threshold | corrupt | runs | cert accept | detect | success | false positive | latency mean/max | evidence bytes |",
            "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for row in sorted(
        [row for row in aggregates if row.get("scenario_category") != "watcher-coverage"],
        key=lambda item: (
            str(item.get("scenario")),
            float(item.get("root_count", 0)),
            float(item.get("threshold", 0)),
            float(item.get("corrupt_roots", 0)),
        ),
    ):
        lines.append(
            "| {scenario} | {roots} | {threshold} | {corrupt} | {runs} | {accepted} | {detected} | {success} | {fp} | {latency}/{latency_max} | {evidence} |".format(
                scenario=row.get("scenario"),
                roots=_fmt(row.get("root_count"), 0),
                threshold=_fmt(row.get("threshold"), 0),
                corrupt=_fmt(row.get("corrupt_roots"), 0),
                runs=row.get("runs"),
                accepted=_fmt(row.get("certificate_accepted_numeric_mean"), 4),
                detected=_fmt(row.get("equivocation_detected_numeric_mean"), 4),
                success=_fmt(row.get("outcome_success_numeric_mean"), 4),
                fp=_fmt(row.get("false_positive_numeric_mean"), 4),
                latency=_fmt(row.get("detection_latency_mean"), 4),
                latency_max=_fmt(row.get("detection_latency_max"), 4),
                evidence=_fmt(row.get("evidence_bytes_mean"), 1),
            )
        )
    watcher_rows = [row for row in aggregates if row.get("scenario_category") == "watcher-coverage"]
    lines.extend(
        [
            "",
            "## Watcher Coverage Aggregates",
            "",
            "| watchers | coverage | interval | reporting | selective disclosure | partition | runs | detect | latency mean/max | model detect prob | effective reports |",
            "|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    if watcher_rows:
        for row in sorted(
            watcher_rows,
            key=lambda item: (
                float(item.get("watcher_count", 0)),
                float(item.get("watcher_coverage", 0)),
                float(item.get("observation_interval", 0)),
                float(item.get("party_reporting_fraction", 0)),
                float(item.get("selective_disclosure", 0)),
                float(item.get("partition_duration", 0)),
            ),
        ):
            lines.append(
                "| {watchers} | {coverage} | {interval} | {reporting} | {selective} | {partition} | {runs} | {detect} | {latency}/{latency_max} | {model} | {reports} |".format(
                    watchers=_fmt(row.get("watcher_count"), 0),
                    coverage=_fmt(row.get("watcher_coverage"), 2),
                    interval=_fmt(row.get("observation_interval"), 2),
                    reporting=_fmt(row.get("party_reporting_fraction"), 2),
                    selective=_fmt(row.get("selective_disclosure"), 2),
                    partition=_fmt(row.get("partition_duration"), 2),
                    runs=row.get("runs"),
                    detect=_fmt(row.get("equivocation_detected_numeric_mean"), 4),
                    latency=_fmt(row.get("detection_latency_mean"), 4),
                    latency_max=_fmt(row.get("detection_latency_max"), 4),
                    model=_fmt(row.get("watcher_detection_probability_model_mean"), 4),
                    reports=_fmt(row.get("watcher_effective_reports_mean"), 2),
                )
            )
    else:
        lines.append("|  |  |  |  |  |  |  |  |  |  |  |")
    lines.extend(["", "## Interpretation", "", str(summary.get("claim_note", ""))])
    return "\n".join(lines)


def summarize_e_b5(
    rows: Sequence[MetricRow],
    aggregates: Sequence[MetricRow] | None = None,
    *,
    run_config: dict[str, object] | None = None,
) -> dict[str, object]:
    aggregates = list(aggregates) if aggregates is not None else aggregate_rows(
        rows,
        group_by=("experiment", "strategy", "n_parties", "a2a_transport_mode", "a2a_sdk_available"),
        metrics=("completeness", "p99_delta", "channel_messages", "a2a_payload_bytes", "undelivered_count"),
    )
    by_n: dict[str, dict[str, MetricRow]] = {}
    for aggregate in aggregates:
        by_n.setdefault(str(aggregate.get("n_parties")), {})[str(aggregate.get("strategy"))] = aggregate

    comparisons: list[dict[str, object]] = []
    ordering_success = 0
    ordering_total = 0
    for n_parties, lookup in sorted(by_n.items(), key=lambda item: float(item[0])):
        hybrid = lookup.get("hybrid")
        push = lookup.get("push")
        log = lookup.get("log")
        if hybrid is None:
            continue
        comparison: dict[str, object] = {
            "n_parties": _coerce_number(n_parties),
            "hybrid_completeness_mean": hybrid.get("completeness_mean"),
            "hybrid_p99_delta_mean": hybrid.get("p99_delta_mean"),
            "hybrid_channel_messages_mean": hybrid.get("channel_messages_mean"),
            "a2a_payload_bytes_mean": hybrid.get("a2a_payload_bytes_mean"),
            "a2a_transport_delay_model_mean": hybrid.get("a2a_transport_delay_model_mean"),
        }
        ordering_ok = True
        if push is not None:
            comparison["push_completeness_mean"] = push.get("completeness_mean")
            comparison["hybrid_minus_push_completeness"] = _sub(
                hybrid.get("completeness_mean"),
                push.get("completeness_mean"),
            )
            ordering_ok = ordering_ok and (
                _as_float(hybrid.get("completeness_mean")) is not None
                and _as_float(push.get("completeness_mean")) is not None
                and float(hybrid["completeness_mean"]) >= float(push["completeness_mean"])
            )
        if log is not None:
            comparison["log_p99_delta_mean"] = log.get("p99_delta_mean")
            comparison["hybrid_minus_log_p99"] = _sub(hybrid.get("p99_delta_mean"), log.get("p99_delta_mean"))
            ordering_ok = ordering_ok and (
                _as_float(hybrid.get("p99_delta_mean")) is not None
                and _as_float(log.get("p99_delta_mean")) is not None
                and float(hybrid["p99_delta_mean"]) <= float(log["p99_delta_mean"])
            )
        comparison["ordering_success"] = ordering_ok
        comparisons.append(comparison)
        ordering_total += 1
        if ordering_ok:
            ordering_success += 1

    return {
        "experiment": "E-B5",
        "run_config": run_config or {},
        "raw_rows": len(rows),
        "aggregate_rows": len(aggregates),
        "a2a_sdk_available": any(bool(row.get("a2a_sdk_available")) for row in rows),
        "a2a_sdk_versions": sorted({str(row.get("a2a_sdk_version")) for row in rows if row.get("a2a_sdk_version")}),
        "a2a_transport_modes": sorted({str(row.get("a2a_transport_mode")) for row in rows}),
        "mean_payload_bytes": _mean([row.get("a2a_payload_bytes") for row in rows]),
        "mean_transport_delay_model": _mean([row.get("a2a_transport_delay_model") for row in rows]),
        "ordering_success_rate": ordering_success / ordering_total if ordering_total else None,
        "comparisons": comparisons,
        "claim_note": (
            "E-B5 validates the thin A2A binding surface and local payload/transport overhead model. "
            "It is a deployability check, not a standards or multi-implementation interoperability claim."
        ),
    }


def render_e_b5_markdown_report(summary: dict[str, object], aggregates: Sequence[MetricRow]) -> str:
    lines = [
        "# E-B5 Thin A2A Deployability Report",
        "",
        f"Raw rows: {summary['raw_rows']}",
        f"Aggregate rows: {summary['aggregate_rows']}",
        f"A2A SDK available: {summary['a2a_sdk_available']}",
        f"A2A SDK versions: {summary['a2a_sdk_versions']}",
        f"Transport modes: {summary['a2a_transport_modes']}",
        f"Ordering success rate: {_fmt(summary.get('ordering_success_rate'), 4)}",
        f"Mean payload bytes: {_fmt(summary.get('mean_payload_bytes'), 1)}",
        f"Mean transport delay model: {_fmt(summary.get('mean_transport_delay_model'), 6)}",
        "",
        "## Run Config",
        "",
    ]
    run_config = summary.get("run_config", {})
    if isinstance(run_config, dict) and run_config:
        for key in sorted(run_config):
            lines.append(f"- `{key}`: `{run_config[key]}`")
    else:
        lines.append("- No run config recorded.")
    lines.extend(
        [
            "",
            "## Strategy Aggregates",
            "",
            "| n | strategy | runs | completeness | p99 delta | messages | payload bytes | transport delay | undelivered |",
            "|---:|---|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for row in sorted(aggregates, key=lambda item: (float(item.get("n_parties", 0)), str(item.get("strategy")))):
        lines.append(
            "| {n} | {strategy} | {runs} | {comp} | {p99} | {messages} | {payload} | {delay} | {undelivered} |".format(
                n=_fmt(row.get("n_parties"), 0),
                strategy=row.get("strategy"),
                runs=row.get("runs"),
                comp=_fmt(row.get("completeness_mean"), 4),
                p99=_fmt(row.get("p99_delta_mean"), 4),
                messages=_fmt(row.get("channel_messages_mean"), 1),
                payload=_fmt(row.get("a2a_payload_bytes_mean"), 1),
                delay=_fmt(row.get("a2a_transport_delay_model_mean"), 6),
                undelivered=_fmt(row.get("undelivered_count_mean"), 2),
            )
        )
    lines.extend(
        [
            "",
            "## Ordering Checks",
            "",
            "| n | hybrid completeness | push completeness | hybrid p99 | log p99 | ordering preserved |",
            "|---:|---:|---:|---:|---:|---|",
        ]
    )
    comparisons = summary.get("comparisons", [])
    if isinstance(comparisons, list):
        for comparison in comparisons:
            lines.append(
                "| {n} | {hcomp} | {pcomp} | {hp99} | {lp99} | {ok} |".format(
                    n=_fmt(comparison.get("n_parties"), 0),
                    hcomp=_fmt(comparison.get("hybrid_completeness_mean"), 4),
                    pcomp=_fmt(comparison.get("push_completeness_mean"), 4),
                    hp99=_fmt(comparison.get("hybrid_p99_delta_mean"), 4),
                    lp99=_fmt(comparison.get("log_p99_delta_mean"), 4),
                    ok=comparison.get("ordering_success"),
                )
            )
    lines.extend(["", "## Interpretation", "", str(summary.get("claim_note", ""))])
    return "\n".join(lines)


def summarize_e_b6(
    rows: Sequence[MetricRow],
    aggregates: Sequence[MetricRow] | None = None,
    *,
    run_config: dict[str, object] | None = None,
) -> dict[str, object]:
    aggregates = list(aggregates) if aggregates is not None else aggregate_rows(
        rows,
        group_by=("experiment", "strategy", "n_parties", "service_model"),
        metrics=("completeness", "p99_delta", "transport_errors", "root_certificate_verified_rate"),
    )
    comparisons: list[dict[str, object]] = []
    by_n: dict[str, dict[str, MetricRow]] = {}
    for aggregate in aggregates:
        by_n.setdefault(str(aggregate.get("n_parties")), {})[str(aggregate.get("strategy"))] = aggregate
    for n_parties, lookup in sorted(by_n.items(), key=lambda item: float(item[0])):
        hybrid = lookup.get("hybrid")
        push = lookup.get("push")
        log = lookup.get("log")
        push_gossip = lookup.get("push-gossip")
        if hybrid is None:
            continue
        comparison: dict[str, object] = {
            "n_parties": _coerce_number(n_parties),
            "hybrid_completeness_mean": hybrid.get("completeness_mean"),
            "hybrid_p99_delta_mean": hybrid.get("p99_delta_mean"),
            "hybrid_transport_errors_mean": hybrid.get("transport_errors_mean"),
        }
        if push is not None:
            comparison["push_completeness_mean"] = push.get("completeness_mean")
            comparison["hybrid_minus_push_completeness"] = _sub(
                hybrid.get("completeness_mean"),
                push.get("completeness_mean"),
            )
        if log is not None:
            comparison["log_p99_delta_mean"] = log.get("p99_delta_mean")
            comparison["hybrid_minus_log_p99"] = _sub(hybrid.get("p99_delta_mean"), log.get("p99_delta_mean"))
        if push_gossip is not None:
            comparison["push_gossip_p99_delta_mean"] = push_gossip.get("p99_delta_mean")
            comparison["hybrid_minus_push_gossip_p99"] = _sub(
                hybrid.get("p99_delta_mean"),
                push_gossip.get("p99_delta_mean"),
            )
        comparisons.append(comparison)
    return {
        "experiment": "E-B6",
        "run_config": run_config or {},
        "raw_rows": len(rows),
        "aggregate_rows": len(aggregates),
        "service_models": sorted({str(row.get("service_model")) for row in rows}),
        "strategies": sorted({str(row.get("strategy")) for row in rows}),
        "n_parties_values": sorted({_coerce_number(row.get("n_parties")) for row in rows}, key=lambda value: float(value)),
        "mean_transport_errors": _mean([row.get("transport_errors") for row in rows]),
        "min_completeness": _min_metric(rows, "completeness"),
        "max_p99_delta": _max_metric(rows, "p99_delta"),
        "mean_root_certificate_verified_rate": _mean([row.get("root_certificate_verified_rate") for row in rows]),
        "mean_signature_verified_rate": _mean([row.get("signature_verified_rate") for row in rows]),
        "comparisons": comparisons,
        "claim_note": (
            "E-B6 upgrades the evidence type from an in-process simulator to a real loopback JSONL transport "
            "prototype. Services still run in one asyncio process, so this is not a production deployment, "
            "but every propagation step crosses TCP and JSON serialization boundaries."
        ),
    }


def render_e_b6_markdown_report(summary: dict[str, object], aggregates: Sequence[MetricRow]) -> str:
    lines = [
        "# E-B6 Local End-to-End Transport Report",
        "",
        f"Raw rows: {summary['raw_rows']}",
        f"Aggregate rows: {summary['aggregate_rows']}",
        f"Service models: {summary['service_models']}",
        f"Strategies: {summary['strategies']}",
        f"Mean transport errors: {_fmt(summary.get('mean_transport_errors'), 4)}",
        f"Minimum completeness: {_fmt(summary.get('min_completeness'), 4)}",
        f"Maximum p99 delta: {_fmt(summary.get('max_p99_delta'), 4)}",
        f"Mean root-certificate verification rate: {_fmt(summary.get('mean_root_certificate_verified_rate'), 4)}",
        "",
        "## Run Config",
        "",
    ]
    run_config = summary.get("run_config", {})
    if isinstance(run_config, dict) and run_config:
        for key in sorted(run_config):
            lines.append(f"- `{key}`: `{run_config[key]}`")
    else:
        lines.append("- No run config recorded.")
    lines.extend(
        [
            "",
            "## Aggregates",
            "",
            "| n | strategy | runs | completeness | p99 delta | max delta | requests | errors | bytes sent | cert verify | undelivered |",
            "|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for row in sorted(aggregates, key=lambda item: (float(item.get("n_parties", 0)), str(item.get("strategy")))):
        lines.append(
            "| {n} | {strategy} | {runs} | {comp} | {p99} | {max_delta} | {requests} | {errors} | {bytes_sent} | {cert} | {undelivered} |".format(
                n=_fmt(row.get("n_parties"), 0),
                strategy=row.get("strategy"),
                runs=row.get("runs"),
                comp=_fmt(row.get("completeness_mean"), 4),
                p99=_fmt(row.get("p99_delta_mean"), 4),
                max_delta=_fmt(row.get("max_delta_mean"), 4),
                requests=_fmt(row.get("transport_requests_mean"), 1),
                errors=_fmt(row.get("transport_errors_mean"), 2),
                bytes_sent=_fmt(row.get("transport_bytes_sent_mean"), 0),
                cert=_fmt(row.get("root_certificate_verified_rate_mean"), 4),
                undelivered=_fmt(row.get("undelivered_count_mean"), 2),
            )
        )
    lines.extend(["", "## Interpretation", "", str(summary.get("claim_note", ""))])
    return "\n".join(lines)


def summarize_e_b7(
    rows: Sequence[MetricRow],
    aggregates: Sequence[MetricRow] | None = None,
    *,
    run_config: dict[str, object] | None = None,
) -> dict[str, object]:
    aggregates = list(aggregates) if aggregates is not None else aggregate_rows(
        rows,
        group_by=("experiment", "config_id", "sensitivity_axis", "n_parties", "gossip_fanout", "poll_interval", "jitter", "delay_scale"),
        metrics=("completeness", "p99_delta", "channel_messages", "undelivered_count"),
    )
    baseline_by_n = {
        str(row.get("n_parties")): row
        for row in aggregates
        if row.get("config_id") == "baseline"
    }
    sensitivity: list[dict[str, object]] = []
    for row in aggregates:
        n_key = str(row.get("n_parties"))
        baseline = baseline_by_n.get(n_key)
        sensitivity.append(
            {
                "config_id": row.get("config_id"),
                "sensitivity_axis": row.get("sensitivity_axis"),
                "n_parties": row.get("n_parties"),
                "runs": row.get("runs"),
                "completeness_mean": row.get("completeness_mean"),
                "p99_delta_mean": row.get("p99_delta_mean"),
                "p99_over_baseline": _ratio(
                    row.get("p99_delta_mean"),
                    baseline.get("p99_delta_mean") if baseline else None,
                ),
                "messages_over_baseline": _ratio(
                    row.get("channel_messages_mean"),
                    baseline.get("channel_messages_mean") if baseline else None,
                ),
            }
        )
    p99_ratios = [_as_float(item.get("p99_over_baseline")) for item in sensitivity]
    p99_ratios = [value for value in p99_ratios if value is not None]
    return {
        "experiment": "E-B7",
        "run_config": run_config or {},
        "raw_rows": len(rows),
        "aggregate_rows": len(aggregates),
        "config_ids": sorted({str(row.get("config_id")) for row in rows}),
        "min_completeness": _min_metric(rows, "completeness"),
        "max_p99_delta": _max_metric(rows, "p99_delta"),
        "max_p99_over_baseline": max(p99_ratios) if p99_ratios else None,
        "sensitivity": sensitivity,
        "claim_note": (
            "E-B7 turns hidden simulator assumptions into explicit reproducibility and sensitivity variables. "
            "It uses a single-factor design around the paper baseline so each changed parameter has a clear "
            "interpretation."
        ),
    }


def reproducibility_manifest(
    rows: Sequence[MetricRow],
    *,
    run_config: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "python_version": sys.version,
        "platform": platform.platform(),
        "package": "revocation-propagation",
        "run_config": run_config or {},
        "raw_rows": len(rows),
        "row_count_by_experiment": {
            experiment: sum(1 for row in rows if row.get("experiment") == experiment)
            for experiment in sorted({str(row.get("experiment")) for row in rows})
        },
        "commands": {
            "e_b6_smoke": "python3 experiments/e_b_research_suite.py --experiment e-b6 --profile smoke --output-dir data/run_e_b6_smoke",
            "e_b6_paper": "python3 experiments/e_b_research_suite.py --experiment e-b6 --profile paper --seeds 0:10 --n-parties 10,30,100 --output-dir data/run_e_b6_paper",
            "e_b7_smoke": "python3 experiments/e_b_research_suite.py --experiment e-b7 --profile smoke --output-dir data/run_e_b7_smoke",
            "e_b7_paper": "python3 experiments/e_b_research_suite.py --experiment e-b7 --profile paper --seeds 0:10 --n-parties 100,300 --output-dir data/run_e_b7_paper",
        },
        "expected_files": [
            "e_b6_local_e2e.csv",
            "e_b6_aggregate.csv",
            "e_b6_summary.json",
            "e_b6_report.md",
            "e_b7_sensitivity.csv",
            "e_b7_aggregate.csv",
            "e_b7_summary.json",
            "e_b7_report.md",
            "reproducibility_manifest.json",
        ],
    }


def render_e_b7_markdown_report(
    summary: dict[str, object],
    aggregates: Sequence[MetricRow],
    manifest: dict[str, object],
) -> str:
    lines = [
        "# E-B7 Reproducibility and Sensitivity Report",
        "",
        f"Raw rows: {summary['raw_rows']}",
        f"Aggregate rows: {summary['aggregate_rows']}",
        f"Config IDs: {summary['config_ids']}",
        f"Minimum completeness: {_fmt(summary.get('min_completeness'), 4)}",
        f"Maximum p99 delta: {_fmt(summary.get('max_p99_delta'), 4)}",
        f"Maximum p99/baseline ratio: {_fmt(summary.get('max_p99_over_baseline'), 3)}",
        "",
        "## Run Config",
        "",
    ]
    run_config = summary.get("run_config", {})
    if isinstance(run_config, dict) and run_config:
        for key in sorted(run_config):
            lines.append(f"- `{key}`: `{run_config[key]}`")
    else:
        lines.append("- No run config recorded.")
    lines.extend(
        [
            "",
            "## Sensitivity Aggregates",
            "",
            "| n | config | axis | runs | fanout | poll | jitter | delay scale | completeness | p99 delta | messages |",
            "|---:|---|---|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for row in sorted(
        aggregates,
        key=lambda item: (float(item.get("n_parties", 0)), str(item.get("sensitivity_axis")), str(item.get("config_id"))),
    ):
        lines.append(
            "| {n} | {config} | {axis} | {runs} | {fanout} | {poll} | {jitter} | {scale} | {comp} | {p99} | {messages} |".format(
                n=_fmt(row.get("n_parties"), 0),
                config=row.get("config_id"),
                axis=row.get("sensitivity_axis"),
                runs=row.get("runs"),
                fanout=_fmt(row.get("gossip_fanout"), 0),
                poll=_fmt(row.get("poll_interval"), 2),
                jitter=_fmt(row.get("jitter"), 2),
                scale=_fmt(row.get("delay_scale"), 2),
                comp=_fmt(row.get("completeness_mean"), 4),
                p99=_fmt(row.get("p99_delta_mean"), 4),
                messages=_fmt(row.get("channel_messages_mean"), 1),
            )
        )
    lines.extend(
        [
            "",
            "## Reproducibility Manifest",
            "",
            f"- Python: `{manifest.get('python_version')}`",
            f"- Platform: `{manifest.get('platform')}`",
            "- Commands:",
        ]
    )
    commands = manifest.get("commands", {})
    if isinstance(commands, dict):
        for name, command in commands.items():
            lines.append(f"  - `{name}`: `{command}`")
    lines.extend(["", "## Interpretation", "", str(summary.get("claim_note", ""))])
    return "\n".join(lines)


def summarize_e_b8(
    rows: Sequence[MetricRow],
    aggregates: Sequence[MetricRow] | None = None,
    *,
    run_config: dict[str, object] | None = None,
) -> dict[str, object]:
    aggregates = list(aggregates) if aggregates is not None else aggregate_rows(
        rows,
        group_by=("experiment", "agent_runtime_model", "strategy", "n_parties", "ttl", "tool_call_rate", "push_suppression"),
        metrics=(
            "completeness",
            "p99_delta",
            "stale_capability_window_p99",
            "stale_capability_window_max",
            "revoked_tool_calls_allowed",
            "revoked_tool_calls_prevented",
            "prevented_fraction",
            "audit_evidence_available_numeric",
            "channel_messages",
            "undelivered_count",
        ),
    )
    by_cell: dict[tuple[str, str, str, str], dict[str, MetricRow]] = {}
    for aggregate in aggregates:
        key = (
            str(aggregate.get("n_parties")),
            str(aggregate.get("ttl")),
            str(aggregate.get("tool_call_rate")),
            str(aggregate.get("push_suppression")),
        )
        by_cell.setdefault(key, {})[str(aggregate.get("strategy"))] = aggregate

    comparisons: list[dict[str, object]] = []
    hybrid_better_than_ttl_cells = 0
    hybrid_auditable_low_latency_cells = 0
    for (n_parties, ttl, tool_call_rate, push_suppression), lookup in sorted(by_cell.items()):
        hybrid = lookup.get("hybrid")
        if hybrid is None:
            continue
        comparison: dict[str, object] = {
            "n_parties": _coerce_number(n_parties),
            "ttl": _coerce_number(ttl),
            "tool_call_rate": _coerce_number(tool_call_rate),
            "push_suppression": _coerce_number(push_suppression),
            "hybrid_revoked_tool_calls_allowed_mean": hybrid.get("revoked_tool_calls_allowed_mean"),
            "hybrid_prevented_fraction_mean": hybrid.get("prevented_fraction_mean"),
            "hybrid_stale_capability_window_p99_mean": hybrid.get("stale_capability_window_p99_mean"),
            "hybrid_audit_evidence_available_rate": hybrid.get("audit_evidence_available_numeric_mean"),
        }
        for baseline_name in ("ttl-rcc", "push", "push-gossip", "log"):
            baseline = lookup.get(baseline_name)
            if baseline is None:
                continue
            prefix = baseline_name.replace("-", "_")
            comparison[f"hybrid_over_{prefix}_allowed"] = _ratio(
                hybrid.get("revoked_tool_calls_allowed_mean"),
                baseline.get("revoked_tool_calls_allowed_mean"),
            )
            comparison[f"hybrid_minus_{prefix}_p99_stale"] = _sub(
                hybrid.get("stale_capability_window_p99_mean"),
                baseline.get("stale_capability_window_p99_mean"),
            )
            comparison[f"{prefix}_audit_evidence_available_rate"] = baseline.get(
                "audit_evidence_available_numeric_mean"
            )
        ttl_row = lookup.get("ttl-rcc")
        if _ratio(
            hybrid.get("revoked_tool_calls_allowed_mean"),
            ttl_row.get("revoked_tool_calls_allowed_mean") if ttl_row else None,
        ) not in {None, 0.0}:
            ratio = _ratio(
                hybrid.get("revoked_tool_calls_allowed_mean"),
                ttl_row.get("revoked_tool_calls_allowed_mean") if ttl_row else None,
            )
            if ratio is not None and ratio < 0.25:
                hybrid_better_than_ttl_cells += 1
        push_gossip = lookup.get("push-gossip")
        if (
            _as_float(hybrid.get("audit_evidence_available_numeric_mean")) == 1.0
            and push_gossip is not None
            and abs(
                _sub(hybrid.get("stale_capability_window_p99_mean"), push_gossip.get("stale_capability_window_p99_mean"))
                or 0.0
            )
            < 0.05
        ):
            hybrid_auditable_low_latency_cells += 1
        comparisons.append(comparison)

    return {
        "experiment": "E-B8",
        "run_config": run_config or {},
        "raw_rows": len(rows),
        "aggregate_rows": len(aggregates),
        "agent_runtime_models": sorted({str(row.get("agent_runtime_model")) for row in rows}),
        "tool_names": sorted({str(row.get("tool_name")) for row in rows}),
        "max_revoked_tool_calls_allowed": _max_metric(rows, "revoked_tool_calls_allowed"),
        "mean_prevented_fraction": _mean([row.get("prevented_fraction") for row in rows]),
        "hybrid_mean_prevented_fraction": _mean(
            [row.get("prevented_fraction") for row in rows if row.get("strategy") == "hybrid"]
        ),
        "hybrid_max_stale_capability_window": _max_metric(
            [row for row in rows if row.get("strategy") == "hybrid"],
            "stale_capability_window_max",
        ),
        "hybrid_better_than_ttl_cells": hybrid_better_than_ttl_cells,
        "hybrid_auditable_low_latency_cells": hybrid_auditable_low_latency_cells,
        "comparisons": comparisons,
        "claim_note": (
            "E-B8 reframes revocation as an agent-tool gateway problem: a delegated tool capability "
            "continues to authorize tool calls until the gateway learns the revocation or the token TTL expires. "
            "The metric is revoked tool calls allowed/prevented, not generic network latency. The experiment "
            "is a gateway model over the existing propagation simulator; it is not a live LLM-agent benchmark."
        ),
    }


def render_e_b8_markdown_report(summary: dict[str, object], aggregates: Sequence[MetricRow]) -> str:
    lines = [
        "# E-B8 Agent-Tool Gateway Report",
        "",
        f"Raw rows: {summary['raw_rows']}",
        f"Aggregate rows: {summary['aggregate_rows']}",
        f"Agent runtime models: {summary['agent_runtime_models']}",
        f"Tool names: {summary['tool_names']}",
        f"Max revoked tool calls allowed: {_fmt(summary.get('max_revoked_tool_calls_allowed'), 2)}",
        f"Mean prevented fraction: {_fmt(summary.get('mean_prevented_fraction'), 4)}",
        f"Hybrid mean prevented fraction: {_fmt(summary.get('hybrid_mean_prevented_fraction'), 4)}",
        f"Hybrid max stale capability window: {_fmt(summary.get('hybrid_max_stale_capability_window'), 4)}",
        f"Hybrid <25% of TTL baseline cells: {summary['hybrid_better_than_ttl_cells']}",
        f"Hybrid auditable low-latency cells: {summary['hybrid_auditable_low_latency_cells']}",
        "",
        "## Run Config",
        "",
    ]
    run_config = summary.get("run_config", {})
    if isinstance(run_config, dict) and run_config:
        for key in sorted(run_config):
            lines.append(f"- `{key}`: `{run_config[key]}`")
    else:
        lines.append("- No run config recorded.")
    lines.extend(
        [
            "",
            "## Gateway Aggregates",
            "",
            "| n | calls/s/gateway | strategy | runs | completeness | p99 stale | max stale | allowed calls | prevented fraction | audit evidence | messages |",
            "|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for row in sorted(
        aggregates,
        key=lambda item: (
            float(item.get("n_parties", 0)),
            float(item.get("tool_call_rate", 0)),
            str(item.get("strategy")),
        ),
    ):
        lines.append(
            "| {n} | {rate} | {strategy} | {runs} | {comp} | {p99} | {max_stale} | {allowed} | {prevented} | {audit} | {messages} |".format(
                n=_fmt(row.get("n_parties"), 0),
                rate=_fmt(row.get("tool_call_rate"), 2),
                strategy=row.get("strategy"),
                runs=row.get("runs"),
                comp=_fmt(row.get("completeness_mean"), 4),
                p99=_fmt(row.get("stale_capability_window_p99_mean"), 4),
                max_stale=_fmt(row.get("stale_capability_window_max_mean"), 4),
                allowed=_fmt(row.get("revoked_tool_calls_allowed_mean"), 2),
                prevented=_fmt(row.get("prevented_fraction_mean"), 4),
                audit=_fmt(row.get("audit_evidence_available_numeric_mean"), 2),
                messages=_fmt(row.get("channel_messages_mean"), 1),
            )
        )
    lines.extend(
        [
            "",
            "## Hybrid Comparisons",
            "",
            "| n | calls/s/gateway | hybrid allowed | hybrid prevented | hybrid/TTL allowed | hybrid/push allowed | hybrid/push+gossip allowed | hybrid-log p99 stale delta |",
            "|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    comparisons = summary.get("comparisons", [])
    if isinstance(comparisons, list):
        for comparison in comparisons:
            lines.append(
                "| {n} | {rate} | {allowed} | {prevented} | {ttl} | {push} | {pg} | {log_delta} |".format(
                    n=_fmt(comparison.get("n_parties"), 0),
                    rate=_fmt(comparison.get("tool_call_rate"), 2),
                    allowed=_fmt(comparison.get("hybrid_revoked_tool_calls_allowed_mean"), 2),
                    prevented=_fmt(comparison.get("hybrid_prevented_fraction_mean"), 4),
                    ttl=_fmt(comparison.get("hybrid_over_ttl_rcc_allowed"), 3),
                    push=_fmt(comparison.get("hybrid_over_push_allowed"), 3),
                    pg=_fmt(comparison.get("hybrid_over_push_gossip_allowed"), 3),
                    log_delta=_fmt(comparison.get("hybrid_minus_log_p99_stale"), 4),
                )
            )
    lines.extend(["", "## Interpretation", "", str(summary.get("claim_note", ""))])
    return "\n".join(lines)


def summarize_e_b9(
    rows: Sequence[MetricRow],
    aggregates: Sequence[MetricRow] | None = None,
    *,
    run_config: dict[str, object] | None = None,
) -> dict[str, object]:
    aggregates = list(aggregates) if aggregates is not None else aggregate_rows(
        rows,
        group_by=(
            "experiment",
            "compatibility_cell",
            "client_profile",
            "server_profile",
            "strategy",
            "n_parties",
            "ttl",
            "tool_call_rate",
            "fallback_policy",
        ),
        metrics=(
            "compatibility_correct_numeric",
            "schema_conformance_pass_numeric",
            "lifecycle_binding_success_numeric",
            "revocation_enforced_numeric",
            "task_available_numeric",
            "availability_loss_numeric",
            "effective_enforcement_latency",
            "client_abort_latency",
            "server_enforcement_latency",
            "revoked_tool_calls_allowed",
            "revoked_tool_calls_prevented",
            "prevented_fraction",
            "agent_card_bytes",
            "lifecycle_event_bytes",
            "channel_messages",
            "undelivered_count",
        ),
    )
    cell_summaries: list[dict[str, object]] = []
    for aggregate in sorted(
        aggregates,
        key=lambda item: (
            str(item.get("compatibility_cell")),
            float(item.get("tool_call_rate", 0)),
            float(item.get("n_parties", 0)),
        ),
    ):
        cell_summaries.append(
            {
                "compatibility_cell": aggregate.get("compatibility_cell"),
                "client_profile": aggregate.get("client_profile"),
                "server_profile": aggregate.get("server_profile"),
                "n_parties": aggregate.get("n_parties"),
                "tool_call_rate": aggregate.get("tool_call_rate"),
                "compatibility_pass_rate": aggregate.get("compatibility_correct_numeric_mean"),
                "schema_conformance_pass_rate": aggregate.get("schema_conformance_pass_numeric_mean"),
                "lifecycle_binding_success_rate": aggregate.get("lifecycle_binding_success_numeric_mean"),
                "revocation_enforced_rate": aggregate.get("revocation_enforced_numeric_mean"),
                "task_available_rate": aggregate.get("task_available_numeric_mean"),
                "effective_enforcement_latency_mean": aggregate.get("effective_enforcement_latency_mean"),
                "revoked_tool_calls_allowed_mean": aggregate.get("revoked_tool_calls_allowed_mean"),
                "prevented_fraction_mean": aggregate.get("prevented_fraction_mean"),
            }
        )

    new_new_rows = [row for row in rows if row.get("compatibility_cell") == "new-client-new-server"]
    old_new_rows = [row for row in rows if row.get("compatibility_cell") == "old-client-new-server"]
    old_old_rows = [row for row in rows if row.get("compatibility_cell") == "old-client-old-server"]
    new_old_rows = [row for row in rows if row.get("compatibility_cell") == "new-client-old-server"]
    return {
        "experiment": "E-B9",
        "run_config": run_config or {},
        "raw_rows": len(rows),
        "aggregate_rows": len(aggregates),
        "compatibility_cells": sorted({str(row.get("compatibility_cell")) for row in rows}),
        "compatibility_pass_rate": _mean([row.get("compatibility_correct_numeric") for row in rows]),
        "schema_conformance_pass_rate": _mean([row.get("schema_conformance_pass_numeric") for row in rows]),
        "lifecycle_binding_success_rate": _mean([row.get("lifecycle_binding_success_numeric") for row in rows]),
        "revocation_enforced_rate": _mean([row.get("revocation_enforced_numeric") for row in rows]),
        "new_new_mean_effective_enforcement_latency": _mean(
            [row.get("effective_enforcement_latency") for row in new_new_rows]
        ),
        "old_new_mean_server_enforcement_latency": _mean(
            [row.get("server_enforcement_latency") for row in old_new_rows]
        ),
        "new_old_mean_availability_loss": _mean([row.get("availability_loss_numeric") for row in new_old_rows]),
        "old_old_mean_revoked_tool_calls_allowed": _mean(
            [row.get("revoked_tool_calls_allowed") for row in old_old_rows]
        ),
        "max_lifecycle_event_bytes": _max_metric(rows, "lifecycle_event_bytes"),
        "cell_summaries": cell_summaries,
        "claim_note": (
            "E-B9 thickens the A2A deployability claim from payload shape to lifecycle binding. "
            "It evaluates Agent Card discovery plus TaskStatusUpdateEvent-like cancellation behavior across "
            "new/new, new/old, old/new, and old/old compatibility cells. The experiment is a local conformance "
            "and propagation model, not an interoperability test against third-party A2A servers."
        ),
    }


def render_e_b9_markdown_report(summary: dict[str, object], aggregates: Sequence[MetricRow]) -> str:
    lines = [
        "# E-B9 A2A Lifecycle Binding Report",
        "",
        f"Raw rows: {summary['raw_rows']}",
        f"Aggregate rows: {summary['aggregate_rows']}",
        f"Compatibility cells: {summary['compatibility_cells']}",
        f"Compatibility pass rate: {_fmt(summary.get('compatibility_pass_rate'), 4)}",
        f"Schema conformance pass rate: {_fmt(summary.get('schema_conformance_pass_rate'), 4)}",
        f"Lifecycle binding success rate: {_fmt(summary.get('lifecycle_binding_success_rate'), 4)}",
        f"Revocation enforced rate: {_fmt(summary.get('revocation_enforced_rate'), 4)}",
        f"New/new mean effective enforcement latency: {_fmt(summary.get('new_new_mean_effective_enforcement_latency'), 4)}",
        f"Old/new mean server enforcement latency: {_fmt(summary.get('old_new_mean_server_enforcement_latency'), 4)}",
        f"New/old mean availability loss: {_fmt(summary.get('new_old_mean_availability_loss'), 4)}",
        f"Old/old mean revoked tool calls allowed: {_fmt(summary.get('old_old_mean_revoked_tool_calls_allowed'), 2)}",
        f"Max lifecycle event bytes: {_fmt(summary.get('max_lifecycle_event_bytes'), 0)}",
        "",
        "## Run Config",
        "",
    ]
    run_config = summary.get("run_config", {})
    if isinstance(run_config, dict) and run_config:
        for key in sorted(run_config):
            lines.append(f"- `{key}`: `{run_config[key]}`")
    else:
        lines.append("- No run config recorded.")
    lines.extend(
        [
            "",
            "## Compatibility Aggregates",
            "",
            "| n | calls/s/gateway | cell | runs | compat | schema | lifecycle | enforced | available | latency | allowed calls | prevented |",
            "|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for row in sorted(
        aggregates,
        key=lambda item: (
            float(item.get("n_parties", 0)),
            float(item.get("tool_call_rate", 0)),
            str(item.get("compatibility_cell")),
        ),
    ):
        lines.append(
            "| {n} | {rate} | {cell} | {runs} | {compat} | {schema} | {lifecycle} | {enforced} | {available} | {latency} | {allowed} | {prevented} |".format(
                n=_fmt(row.get("n_parties"), 0),
                rate=_fmt(row.get("tool_call_rate"), 2),
                cell=row.get("compatibility_cell"),
                runs=row.get("runs"),
                compat=_fmt(row.get("compatibility_correct_numeric_mean"), 4),
                schema=_fmt(row.get("schema_conformance_pass_numeric_mean"), 4),
                lifecycle=_fmt(row.get("lifecycle_binding_success_numeric_mean"), 4),
                enforced=_fmt(row.get("revocation_enforced_numeric_mean"), 4),
                available=_fmt(row.get("task_available_numeric_mean"), 4),
                latency=_fmt(row.get("effective_enforcement_latency_mean"), 4),
                allowed=_fmt(row.get("revoked_tool_calls_allowed_mean"), 2),
                prevented=_fmt(row.get("prevented_fraction_mean"), 4),
            )
        )
    lines.extend(["", "## Interpretation", "", str(summary.get("claim_note", ""))])
    return "\n".join(lines)


def summarize_e_b10(
    rows: Sequence[MetricRow],
    aggregates: Sequence[MetricRow] | None = None,
    *,
    run_config: dict[str, object] | None = None,
) -> dict[str, object]:
    return _summarize_integration(
        "E-B10",
        rows,
        aggregates,
        run_config=run_config,
        claim_note=(
            "E-B10 exercises the revocation decision across live loopback gateway, tool, and log services. "
            "Every agent call crosses a TCP JSONL gateway boundary and accepted calls are forwarded across a "
            "second TCP JSONL tool boundary. The evidence upgrades E-B8 from a pure simulator to a local "
            "prototype path, but it is still not a multi-process, multi-host, or production deployment."
        ),
    )


def summarize_e_b11(
    rows: Sequence[MetricRow],
    aggregates: Sequence[MetricRow] | None = None,
    *,
    run_config: dict[str, object] | None = None,
) -> dict[str, object]:
    return _summarize_integration(
        "E-B11",
        rows,
        aggregates,
        run_config=run_config,
        claim_note=(
            "E-B11 holds the gateway/tool enforcement logic fixed while changing the outer protocol envelope "
            "across raw JSON, MCP-style JSON-RPC, and A2A task-lifecycle shaped requests. The measured claim "
            "is protocol-envelope binding and schema handling on the local prototype, not third-party protocol "
            "interoperability certification."
        ),
    )


def summarize_e_b12(
    rows: Sequence[MetricRow],
    aggregates: Sequence[MetricRow] | None = None,
    *,
    run_config: dict[str, object] | None = None,
) -> dict[str, object]:
    return _summarize_integration(
        "E-B12",
        rows,
        aggregates,
        run_config=run_config,
        claim_note=(
            "E-B12 injects concrete failure paths in the local prototype: dropped push delivery, delayed log "
            "repair, partition healing, and gateway restart with log recovery. The evidence supports bounded "
            "recovery-path behavior for the prototype fault model; it does not claim production-grade chaos "
            "testing or large-scale distributed fault tolerance."
        ),
    )


def _summarize_integration(
    experiment: str,
    rows: Sequence[MetricRow],
    aggregates: Sequence[MetricRow] | None,
    *,
    run_config: dict[str, object] | None,
    claim_note: str,
) -> dict[str, object]:
    aggregate_rows_value = list(aggregates) if aggregates is not None else _integration_aggregates(rows)
    surface_summaries: list[dict[str, object]] = []
    for aggregate in sorted(
        aggregate_rows_value,
        key=lambda item: (
            str(item.get("protocol_profile")),
            str(item.get("fault_scenario")),
            float(item.get("tool_call_rate", 0)),
            float(item.get("n_parties", 0)),
        ),
    ):
        surface_summaries.append(
            {
                "protocol_profile": aggregate.get("protocol_profile"),
                "fault_scenario": aggregate.get("fault_scenario"),
                "n_parties": aggregate.get("n_parties"),
                "tool_call_rate": aggregate.get("tool_call_rate"),
                "success_rate": aggregate.get("integration_success_numeric_mean"),
                "schema_pass_rate": aggregate.get("protocol_schema_pass_rate_mean"),
                "post_repair_reject_rate": aggregate.get("post_repair_reject_rate_mean"),
                "p99_stale_window": aggregate.get("stale_capability_window_p99_mean"),
                "allowed_calls_mean": aggregate.get("revoked_tool_calls_allowed_mean"),
                "prevented_fraction_mean": aggregate.get("prevented_fraction_mean"),
                "transport_errors_mean": aggregate.get("transport_errors_mean"),
            }
        )

    return {
        "experiment": experiment,
        "run_config": run_config or {},
        "raw_rows": len(rows),
        "aggregate_rows": len(aggregate_rows_value),
        "protocol_profiles": sorted({str(row.get("protocol_profile")) for row in rows}),
        "fault_scenarios": sorted({str(row.get("fault_scenario")) for row in rows}),
        "integration_success_rate": _mean([row.get("integration_success_numeric") for row in rows]),
        "protocol_schema_pass_rate": _mean([row.get("protocol_schema_pass_rate") for row in rows]),
        "pre_revocation_allowed_rate": _mean([row.get("pre_revocation_allowed_rate") for row in rows]),
        "post_repair_reject_rate": _mean([row.get("post_repair_reject_rate") for row in rows]),
        "mean_prevented_fraction": _mean([row.get("prevented_fraction") for row in rows]),
        "max_revoked_tool_calls_allowed": _max_metric(rows, "revoked_tool_calls_allowed"),
        "max_stale_capability_window": _max_metric(rows, "stale_capability_window_max"),
        "max_fault_recovery_latency": _max_metric(rows, "fault_recovery_latency_p99"),
        "transport_error_count": sum(int(row.get("transport_errors", 0) or 0) for row in rows),
        "loopback_service_boundary_rate": _mean([row.get("loopback_service_boundary_numeric") for row in rows]),
        "separate_os_process_rate": _mean([row.get("separate_os_processes_numeric") for row in rows]),
        "surface_summaries": surface_summaries,
        "claim_note": claim_note,
    }


def render_e_b10_markdown_report(summary: dict[str, object], aggregates: Sequence[MetricRow]) -> str:
    return _render_integration_markdown_report("# E-B10 Real Gateway/Tool Path Report", summary, aggregates)


def render_e_b11_markdown_report(summary: dict[str, object], aggregates: Sequence[MetricRow]) -> str:
    return _render_integration_markdown_report("# E-B11 Protocol Boundary Path Report", summary, aggregates)


def render_e_b12_markdown_report(summary: dict[str, object], aggregates: Sequence[MetricRow]) -> str:
    return _render_integration_markdown_report("# E-B12 Fault Injection Path Report", summary, aggregates)


def summarize_e_b13(
    rows: Sequence[MetricRow],
    aggregates: Sequence[MetricRow] | None = None,
    *,
    run_config: dict[str, object] | None = None,
) -> dict[str, object]:
    return summarize_paper_a_agent_system_bridge(rows, aggregates, run_config=run_config)


def render_e_b13_markdown_report(summary: dict[str, object], aggregates: Sequence[MetricRow]) -> str:
    return render_paper_a_agent_system_bridge_report(summary, aggregates)


def summarize_e_b14(
    rows: Sequence[MetricRow],
    aggregates: Sequence[MetricRow] | None = None,
    *,
    run_config: dict[str, object] | None = None,
) -> dict[str, object]:
    summary = _summarize_integration(
        "E-B14",
        rows,
        aggregates,
        run_config=run_config,
        claim_note=(
            "E-B14 runs gateway, tool, and log roles in separate OS processes with a persisted log file. "
            "The deployment upgrades E-B10--E-B12 from single-process loopback to multi-process service "
            "isolation, but it remains a local artifact deployment, not a production multi-host cluster."
        ),
    )
    summary["separate_os_process_rate"] = _mean([row.get("separate_os_processes_numeric") for row in rows])
    summary["persistent_log_rate"] = _mean([row.get("persistent_log_numeric") for row in rows])
    summary["max_process_count"] = _max_metric(rows, "process_count")
    return summary


def render_e_b14_markdown_report(summary: dict[str, object], aggregates: Sequence[MetricRow]) -> str:
    return _render_integration_markdown_report("# E-B14 Multi-Process Deployment Report", summary, aggregates)


def summarize_e_b15(
    rows: Sequence[MetricRow],
    aggregates: Sequence[MetricRow] | None = None,
    *,
    run_config: dict[str, object] | None = None,
) -> dict[str, object]:
    aggregate_rows_value = list(aggregates) if aggregates is not None else _agent_path_aggregates(rows)
    return {
        "experiment": "E-B15",
        "run_config": run_config or {},
        "raw_rows": len(rows),
        "aggregate_rows": len(aggregate_rows_value),
        "path_profiles": sorted({str(row.get("path_profile")) for row in rows}),
        "fault_scenarios": sorted({str(row.get("fault_scenario")) for row in rows}),
        "integration_success_rate": _mean([row.get("integration_success_numeric") for row in rows]),
        "mcp_calltool_validation_rate": _mean([row.get("mcp_calltool_request_validated_numeric") for row in rows if row.get("path_profile") == "mcp-python-tools-call"]),
        "langgraph_completion_rate": _mean([row.get("langgraph_workflow_completed_numeric") for row in rows if row.get("path_profile") == "langgraph-stategraph-tool-call"]),
        "mean_prevented_fraction": _mean([row.get("prevented_fraction") for row in rows]),
        "max_stale_capability_window": _max_metric(rows, "stale_capability_window_max"),
        "transport_error_count": sum(int(row.get("transport_errors", 0) or 0) for row in rows),
        "surface_summaries": [
            {
                "path_profile": row.get("path_profile"),
                "fault_scenario": row.get("fault_scenario"),
                "n_gateways": row.get("n_gateways"),
                "tool_call_rate": row.get("tool_call_rate"),
                "success_rate": row.get("integration_success_numeric_mean"),
                "prevented_fraction": row.get("prevented_fraction_mean"),
                "stale_p99": row.get("stale_capability_window_p99_mean"),
            }
            for row in aggregate_rows_value
        ],
        "claim_note": (
            "E-B15 exercises real agent-facing package/runtime surfaces: the MCP Python CallToolRequest "
            "type for tools/call and a compiled LangGraph StateGraph tool workflow. It strengthens the "
            "agent-system path evidence, while remaining a local artifact path rather than third-party "
            "MCP interoperability or a live LLM planner benchmark."
        ),
    }


def render_e_b15_markdown_report(summary: dict[str, object], aggregates: Sequence[MetricRow]) -> str:
    lines = [
        "# E-B15 Real Agent Tool Path Report",
        "",
        f"Raw rows: {summary['raw_rows']}",
        f"Aggregate rows: {summary['aggregate_rows']}",
        f"Path profiles: {summary['path_profiles']}",
        f"Fault scenarios: {summary['fault_scenarios']}",
        f"Integration success rate: {_fmt(summary.get('integration_success_rate'), 4)}",
        f"MCP tools/call validation rate: {_fmt(summary.get('mcp_calltool_validation_rate'), 4)}",
        f"LangGraph completion rate: {_fmt(summary.get('langgraph_completion_rate'), 4)}",
        f"Mean prevented fraction: {_fmt(summary.get('mean_prevented_fraction'), 4)}",
        f"Max stale capability window: {_fmt(summary.get('max_stale_capability_window'), 4)}",
        f"Transport error count: {summary.get('transport_error_count')}",
        "",
        "## Path Aggregates",
        "",
        "| path | fault | n | rate | runs | success | stale p99 | prevented | errors |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in sorted(aggregates, key=lambda item: (str(item.get("path_profile")), str(item.get("fault_scenario")))):
        lines.append(
            "| {path} | {fault} | {n} | {rate} | {runs} | {success} | {stale} | {prevented} | {errors} |".format(
                path=row.get("path_profile"),
                fault=row.get("fault_scenario"),
                n=_fmt(row.get("n_gateways"), 0),
                rate=_fmt(row.get("tool_call_rate"), 2),
                runs=row.get("runs"),
                success=_fmt(row.get("integration_success_numeric_mean"), 4),
                stale=_fmt(row.get("stale_capability_window_p99_mean"), 4),
                prevented=_fmt(row.get("prevented_fraction_mean"), 4),
                errors=_fmt(row.get("transport_errors_mean"), 2),
            )
        )
    lines.extend(["", "## Interpretation", "", str(summary.get("claim_note", ""))])
    return "\n".join(lines)


def summarize_e_b16(
    rows: Sequence[MetricRow],
    aggregates: Sequence[MetricRow] | None = None,
    *,
    run_config: dict[str, object] | None = None,
) -> dict[str, object]:
    aggregate_rows_value = list(aggregates) if aggregates is not None else _status_baseline_aggregates(rows)
    outage_rows = [row for row in rows if row.get("fault_scenario") != "none"]
    return {
        "experiment": "E-B16",
        "run_config": run_config or {},
        "raw_rows": len(rows),
        "aggregate_rows": len(aggregate_rows_value),
        "strategies": sorted({str(row.get("strategy")) for row in rows}),
        "fault_scenarios": sorted({str(row.get("fault_scenario")) for row in rows}),
        "integration_success_rate": _mean([row.get("integration_success_numeric") for row in rows]),
        "status_error_count": sum(int(row.get("status_errors", 0) or 0) for row in rows),
        "max_availability_loss_rate": _max_metric(rows, "availability_loss_rate"),
        "max_stale_capability_window": _max_metric(rows, "stale_capability_window_max"),
        "mean_outage_prevented_fraction": _mean([row.get("prevented_fraction") for row in outage_rows]),
        "surface_summaries": [
            {
                "strategy": row.get("strategy"),
                "fault_scenario": row.get("fault_scenario"),
                "n_gateways": row.get("n_gateways"),
                "tool_call_rate": row.get("tool_call_rate"),
                "availability_loss": row.get("availability_loss_rate_mean"),
                "stale_window": row.get("stale_capability_window_max_mean"),
                "prevented_fraction": row.get("prevented_fraction_mean"),
            }
            for row in aggregate_rows_value
        ],
        "claim_note": (
            "E-B16 compares RevProp against synchronous status-check baselines under local status-service "
            "outages. Fail-closed minimizes stale authorization but loses availability during outages; "
            "fail-open preserves availability but admits stale authority until recovery; TTL cache remains "
            "bounded by the token lifetime."
        ),
    }


def render_e_b16_markdown_report(summary: dict[str, object], aggregates: Sequence[MetricRow]) -> str:
    lines = [
        "# E-B16 Synchronous Status Outage Baselines Report",
        "",
        f"Raw rows: {summary['raw_rows']}",
        f"Aggregate rows: {summary['aggregate_rows']}",
        f"Strategies: {summary['strategies']}",
        f"Fault scenarios: {summary['fault_scenarios']}",
        f"Integration success rate: {_fmt(summary.get('integration_success_rate'), 4)}",
        f"Status error count: {summary.get('status_error_count')}",
        f"Max availability loss rate: {_fmt(summary.get('max_availability_loss_rate'), 4)}",
        f"Max stale capability window: {_fmt(summary.get('max_stale_capability_window'), 4)}",
        f"Mean outage prevented fraction: {_fmt(summary.get('mean_outage_prevented_fraction'), 4)}",
        "",
        "## Baseline Aggregates",
        "",
        "| strategy | fault | n | rate | runs | availability loss | stale max | prevented | status errors |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in sorted(aggregates, key=lambda item: (str(item.get("strategy")), str(item.get("fault_scenario")))):
        lines.append(
            "| {strategy} | {fault} | {n} | {rate} | {runs} | {availability} | {stale} | {prevented} | {errors} |".format(
                strategy=row.get("strategy"),
                fault=row.get("fault_scenario"),
                n=_fmt(row.get("n_gateways"), 0),
                rate=_fmt(row.get("tool_call_rate"), 2),
                runs=row.get("runs"),
                availability=_fmt(row.get("availability_loss_rate_mean"), 4),
                stale=_fmt(row.get("stale_capability_window_max_mean"), 4),
                prevented=_fmt(row.get("prevented_fraction_mean"), 4),
                errors=_fmt(row.get("status_errors_mean"), 2),
            )
        )
    lines.extend(["", "## Interpretation", "", str(summary.get("claim_note", ""))])
    return "\n".join(lines)


def _render_integration_markdown_report(
    title: str,
    summary: dict[str, object],
    aggregates: Sequence[MetricRow],
) -> str:
    lines = [
        title,
        "",
        f"Raw rows: {summary['raw_rows']}",
        f"Aggregate rows: {summary['aggregate_rows']}",
        f"Protocol profiles: {summary['protocol_profiles']}",
        f"Fault scenarios: {summary['fault_scenarios']}",
        f"Integration success rate: {_fmt(summary.get('integration_success_rate'), 4)}",
        f"Protocol schema pass rate: {_fmt(summary.get('protocol_schema_pass_rate'), 4)}",
        f"Pre-revocation allowed rate: {_fmt(summary.get('pre_revocation_allowed_rate'), 4)}",
        f"Post-repair reject rate: {_fmt(summary.get('post_repair_reject_rate'), 4)}",
        f"Mean prevented fraction: {_fmt(summary.get('mean_prevented_fraction'), 4)}",
        f"Max revoked tool calls allowed: {_fmt(summary.get('max_revoked_tool_calls_allowed'), 2)}",
        f"Max stale capability window: {_fmt(summary.get('max_stale_capability_window'), 4)}",
        f"Max fault recovery latency: {_fmt(summary.get('max_fault_recovery_latency'), 4)}",
        f"Transport error count: {summary.get('transport_error_count')}",
        f"Loopback service boundary rate: {_fmt(summary.get('loopback_service_boundary_rate'), 4)}",
        f"Separate OS process rate: {_fmt(summary.get('separate_os_process_rate'), 4)}",
        "",
        "## Run Config",
        "",
    ]
    run_config = summary.get("run_config", {})
    if isinstance(run_config, dict) and run_config:
        for key in sorted(run_config):
            lines.append(f"- `{key}`: `{run_config[key]}`")
    else:
        lines.append("- No run config recorded.")
    lines.extend(
        [
            "",
            "## Integration Aggregates",
            "",
            "| n | calls/s/gateway | protocol | fault | runs | success | schema | stale p99 | recovery p99 | allowed calls | prevented | errors |",
            "|---:|---:|---|---|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for row in sorted(
        aggregates,
        key=lambda item: (
            float(item.get("n_parties", 0)),
            float(item.get("tool_call_rate", 0)),
            str(item.get("protocol_profile")),
            str(item.get("fault_scenario")),
        ),
    ):
        lines.append(
            "| {n} | {rate} | {protocol} | {fault} | {runs} | {success} | {schema} | {stale} | {recovery} | {allowed} | {prevented} | {errors} |".format(
                n=_fmt(row.get("n_parties"), 0),
                rate=_fmt(row.get("tool_call_rate"), 2),
                protocol=row.get("protocol_profile"),
                fault=row.get("fault_scenario"),
                runs=row.get("runs"),
                success=_fmt(row.get("integration_success_numeric_mean"), 4),
                schema=_fmt(row.get("protocol_schema_pass_rate_mean"), 4),
                stale=_fmt(row.get("stale_capability_window_p99_mean"), 4),
                recovery=_fmt(row.get("fault_recovery_latency_p99_mean"), 4),
                allowed=_fmt(row.get("revoked_tool_calls_allowed_mean"), 2),
                prevented=_fmt(row.get("prevented_fraction_mean"), 4),
                errors=_fmt(row.get("transport_errors_mean"), 2),
            )
        )
    lines.extend(["", "## Interpretation", "", str(summary.get("claim_note", ""))])
    return "\n".join(lines)


def summarize_e_b1(
    rows: Sequence[MetricRow],
    aggregates: Sequence[MetricRow] | None = None,
    *,
    run_config: dict[str, object] | None = None,
) -> dict[str, object]:
    aggregates = list(aggregates) if aggregates is not None else aggregate_rows(
        rows,
        group_by=("experiment", "n_parties", "push_suppression", "gossip_suppression", "log_suppression"),
        metrics=(
            "completeness",
            "p99_delta",
            "channel_messages",
            "detection_required_numeric",
            "suppression_detected_numeric",
            "detected_within_budget_numeric",
            "detection_requirement_satisfied_numeric",
            "budget_requirement_satisfied_numeric",
        ),
    )
    operating_region: list[dict[str, object]] = []
    failure_region: list[dict[str, object]] = []
    for aggregate in aggregates:
        row = {
            "n_parties": aggregate.get("n_parties"),
            "push_suppression": aggregate.get("push_suppression"),
            "gossip_suppression": aggregate.get("gossip_suppression"),
            "log_suppression": aggregate.get("log_suppression"),
            "runs": aggregate.get("runs"),
            "completeness_mean": aggregate.get("completeness_mean"),
            "completeness_min": aggregate.get("completeness_min"),
            "p99_delta_mean": aggregate.get("p99_delta_mean"),
            "detection_required": aggregate.get("detection_required_numeric_mean"),
            "detection_probability": aggregate.get("suppression_detected_numeric_mean"),
            "detection_requirement_satisfied": aggregate.get("detection_requirement_satisfied_numeric_mean"),
            "budget_requirement_satisfied": aggregate.get("budget_requirement_satisfied_numeric_mean"),
            "budget_hit_rate": aggregate.get("detected_within_budget_numeric_mean"),
            "channel_messages_mean": aggregate.get("channel_messages_mean"),
            "undelivered_count_mean": aggregate.get("undelivered_count_mean"),
        }
        completeness_ok = _as_float(row["completeness_mean"]) is not None and float(row["completeness_mean"]) >= 0.99
        detection_ok = (
            _as_float(row["detection_requirement_satisfied"]) is not None
            and float(row["detection_requirement_satisfied"]) >= 0.99
        )
        budget_ok = (
            _as_float(row["budget_requirement_satisfied"]) is not None
            and float(row["budget_requirement_satisfied"]) >= 0.99
        )
        row["operating_region"] = completeness_ok and detection_ok and budget_ok
        if row["operating_region"]:
            operating_region.append(row)
        else:
            failure_region.append(row)

    return {
        "experiment": "E-B1",
        "run_config": run_config or {},
        "raw_rows": len(rows),
        "aggregate_rows": len(aggregates),
        "operating_region_rows": len(operating_region),
        "failure_region_rows": len(failure_region),
        "min_completeness": _min_metric(rows, "completeness"),
        "max_p99_delta": _max_metric(rows, "p99_delta"),
        "mean_detection_probability": _mean([row.get("suppression_detected_numeric") for row in rows]),
        "mean_budget_hit_rate": _mean([row.get("detected_within_budget_numeric") for row in rows]),
        "mean_detection_requirement_satisfied": _mean([row.get("detection_requirement_satisfied_numeric") for row in rows]),
        "mean_budget_requirement_satisfied": _mean([row.get("budget_requirement_satisfied_numeric") for row in rows]),
        "operating_region": operating_region,
        "failure_region": failure_region,
        "claim_note": (
            "E-B1 identifies the adversary region where hybrid satisfies completeness, detection, "
            "and bounded-latency budgets; failed regions are theorem-assumption boundaries."
        ),
    }


def render_e_b1_markdown_report(summary: dict[str, object], aggregates: Sequence[MetricRow]) -> str:
    lines = [
        "# E-B1 Byzantine Suppression Sweep Report",
        "",
        f"Raw rows: {summary['raw_rows']}",
        f"Aggregate rows: {summary['aggregate_rows']}",
        f"Operating-region rows: {summary['operating_region_rows']}",
        f"Failure-region rows: {summary['failure_region_rows']}",
        f"Minimum completeness: {_fmt(summary.get('min_completeness'), 4)}",
        f"Maximum p99 delta_prop: {_fmt(summary.get('max_p99_delta'), 4)}",
        "",
        "## Run Config",
        "",
    ]
    run_config = summary.get("run_config", {})
    if isinstance(run_config, dict) and run_config:
        for key in sorted(run_config):
            lines.append(f"- `{key}`: `{run_config[key]}`")
    else:
        lines.append("- No run config recorded.")
    lines.extend(
        [
            "",
            "## Operating Region Aggregate",
            "",
            "| n | push drop | gossip drop | log drop | runs | completeness mean/min | detection req | budget req | p99 mean | messages mean |",
            "|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for row in sorted(
        aggregates,
        key=lambda item: (
            float(item.get("n_parties", 0)),
            float(item.get("push_suppression", 0)),
            float(item.get("gossip_suppression", 0)),
            float(item.get("log_suppression", 0)),
        ),
    ):
        lines.append(
            "| {n} | {push} | {gossip} | {log} | {runs} | {comp}/{comp_min} | {detect} | {budget} | {p99} | {messages} |".format(
                n=_fmt(row.get("n_parties"), 0),
                push=_fmt(row.get("push_suppression"), 2),
                gossip=_fmt(row.get("gossip_suppression"), 2),
                log=_fmt(row.get("log_suppression"), 2),
                runs=row.get("runs"),
                comp=_fmt(row.get("completeness_mean"), 4),
                comp_min=_fmt(row.get("completeness_min"), 4),
                detect=_fmt(row.get("detection_requirement_satisfied_numeric_mean"), 4),
                budget=_fmt(row.get("budget_requirement_satisfied_numeric_mean"), 4),
                p99=_fmt(row.get("p99_delta_mean"), 4),
                messages=_fmt(row.get("channel_messages_mean"), 1),
            )
        )
    lines.extend(["", "## Interpretation", "", str(summary.get("claim_note", ""))])
    return "\n".join(lines)


def run_e_b1_byzantine_sweep(
    *,
    seeds: Iterable[int] = (0, 1, 2),
    n_parties: int = 40,
    push_suppression_values: Sequence[float] = (0.0, 0.2, 0.4),
    gossip_suppression_values: Sequence[float] = (0.0, 0.1),
    log_suppression_values: Sequence[float] = (0.0, 0.1),
    ttl: float = 60.0,
    velocity: float = 10.0,
    max_time: float = 8.0,
    push_delay: float = 0.05,
    gossip_delay: float = 0.10,
    gossip_interval: float = 0.25,
    poll_interval: float = 0.50,
    log_append_delay: float = 0.05,
    jitter: float = 0.20,
    gossip_fanout: int | None = None,
) -> list[MetricRow]:
    return list(
        iter_e_b1_byzantine_sweep_rows(
            seeds=seeds,
            n_parties=n_parties,
            push_suppression_values=push_suppression_values,
            gossip_suppression_values=gossip_suppression_values,
            log_suppression_values=log_suppression_values,
            ttl=ttl,
            velocity=velocity,
            max_time=max_time,
            push_delay=push_delay,
            gossip_delay=gossip_delay,
            gossip_interval=gossip_interval,
            poll_interval=poll_interval,
            log_append_delay=log_append_delay,
            jitter=jitter,
            gossip_fanout=gossip_fanout,
        )
    )


def iter_e_b1_byzantine_sweep_rows(
    *,
    seeds: Iterable[int] = (0, 1, 2),
    n_parties: int = 40,
    push_suppression_values: Sequence[float] = (0.0, 0.2, 0.4),
    gossip_suppression_values: Sequence[float] = (0.0, 0.1),
    log_suppression_values: Sequence[float] = (0.0, 0.1),
    ttl: float = 60.0,
    velocity: float = 10.0,
    max_time: float = 8.0,
    push_delay: float = 0.05,
    gossip_delay: float = 0.10,
    gossip_interval: float = 0.25,
    poll_interval: float = 0.50,
    log_append_delay: float = 0.05,
    jitter: float = 0.20,
    gossip_fanout: int | None = None,
    skip_keys: set[str] | None = None,
) -> Iterable[MetricRow]:
    skip_keys = skip_keys or set()
    for seed in seeds:
        for push_suppression in push_suppression_values:
            for gossip_suppression in gossip_suppression_values:
                for log_suppression in log_suppression_values:
                    run_key = _e_b1_run_key_from_params(
                        n_parties=n_parties,
                        seed=seed,
                        push_suppression=push_suppression,
                        gossip_suppression=gossip_suppression,
                        log_suppression=log_suppression,
                        ttl=ttl,
                        max_time=max_time,
                        push_delay=push_delay,
                        gossip_delay=gossip_delay,
                        gossip_interval=gossip_interval,
                        poll_interval=poll_interval,
                        log_append_delay=log_append_delay,
                        jitter=jitter,
                        gossip_fanout=gossip_fanout,
                    )
                    if run_key in skip_keys:
                        continue
                    scenario = Scenario(
                        n_parties=n_parties,
                        ttl=ttl,
                        velocity=velocity,
                        seed=seed,
                        push_suppression=push_suppression,
                        gossip_suppression=gossip_suppression,
                        log_suppression=log_suppression,
                        max_time=max_time,
                        push_delay=push_delay,
                        gossip_delay=gossip_delay,
                        gossip_interval=gossip_interval,
                        poll_interval=poll_interval,
                        log_append_delay=log_append_delay,
                        jitter=jitter,
                        gossip_fanout=gossip_fanout,
                    )
                    row = run_metric_trial("hybrid", scenario)
                    row["experiment"] = "E-B1"
                    row["adversary"] = "drop-suppress"
                    row["detection_budget"] = max(scenario.gossip_interval + scenario.gossip_delay, scenario.poll_interval)
                    detected_within_budget = _within_budget(row["suppression_detected_at"], row["detection_budget"])
                    row["detected_within_budget"] = detected_within_budget
                    detection_required = scenario.push_suppression > 0.0 or scenario.log_suppression > 0.0
                    row["suppression_detected_numeric"] = 1.0 if row["suppression_detected_at"] is not None else 0.0
                    row["detected_within_budget_numeric"] = 1.0 if detected_within_budget is True else 0.0
                    row["detection_required_numeric"] = 1.0 if detection_required else 0.0
                    row["detection_requirement_satisfied_numeric"] = (
                        row["suppression_detected_numeric"] if detection_required else 1.0
                    )
                    row["budget_requirement_satisfied_numeric"] = (
                        row["detected_within_budget_numeric"] if detection_required else 1.0
                    )
                    row["run_key"] = run_key
                    yield row


def run_e_b2_delta_prop_baselines(
    *,
    seeds: Iterable[int] = (0, 1, 2),
    n_parties: int = 40,
    ttl: float = 60.0,
    velocity: float = 10.0,
    push_suppression: float = 0.2,
    gossip_suppression: float = 0.0,
    log_suppression: float = 0.0,
    max_time: float = 8.0,
    push_delay: float = 0.05,
    gossip_delay: float = 0.10,
    gossip_interval: float = 0.25,
    poll_interval: float = 0.50,
    log_append_delay: float = 0.05,
    jitter: float = 0.20,
    gossip_fanout: int | None = None,
    strategies: Sequence[PropagationStrategy] = BASELINE_STRATEGIES,
    delivery_regimes: Sequence[DeliveryRegime] | None = None,
    status_suppression_values: Sequence[float] = (0.0,),
    snapshot_period: float = 300.0,
    delta_interval: float = 30.0,
    dns_poll_interval: float = 60.0,
    request_time_latency: float = 0.05,
) -> list[MetricRow]:
    rows: list[MetricRow] = []
    for seed in seeds:
        for strategy in strategies:
            scenario = Scenario(
                n_parties=n_parties,
                ttl=ttl,
                velocity=velocity,
                seed=seed,
                push_suppression=push_suppression,
                gossip_suppression=gossip_suppression,
                log_suppression=log_suppression,
                max_time=max_time,
                push_delay=push_delay,
                gossip_delay=gossip_delay,
                gossip_interval=gossip_interval,
                poll_interval=poll_interval,
                log_append_delay=log_append_delay,
                jitter=jitter,
                gossip_fanout=gossip_fanout,
            )
            row = run_metric_trial(strategy, scenario)
            row["experiment"] = "E-B2"
            row["baseline_family"] = "propagation-strategy"
            row["delivery_regime"] = ""
            row["status_suppression"] = None
            rows.append(row)
        if delivery_regimes:
            rows.extend(
                run_e_b2_delivery_regime_baselines(
                    seeds=(int(seed),),
                    n_parties=n_parties,
                    ttl=ttl,
                    velocity=velocity,
                    push_suppression=push_suppression,
                    gossip_suppression=gossip_suppression,
                    status_suppression_values=status_suppression_values,
                    max_time=max_time,
                    push_delay=push_delay,
                    gossip_delay=gossip_delay,
                    gossip_interval=gossip_interval,
                    poll_interval=poll_interval,
                    log_append_delay=log_append_delay,
                    jitter=jitter,
                    gossip_fanout=gossip_fanout,
                    delivery_regimes=delivery_regimes,
                    snapshot_period=snapshot_period,
                    delta_interval=delta_interval,
                    dns_poll_interval=dns_poll_interval,
                    request_time_latency=request_time_latency,
                )
            )
    return rows


def run_e_b2_delivery_regime_baselines(
    *,
    seeds: Iterable[int] = (0, 1, 2),
    n_parties: int = 40,
    ttl: float = 60.0,
    velocity: float = 10.0,
    push_suppression: float = 0.2,
    gossip_suppression: float = 0.0,
    status_suppression_values: Sequence[float] = (0.0,),
    max_time: float = 8.0,
    push_delay: float = 0.05,
    gossip_delay: float = 0.10,
    gossip_interval: float = 0.25,
    poll_interval: float = 0.50,
    log_append_delay: float = 0.05,
    jitter: float = 0.20,
    gossip_fanout: int | None = None,
    delivery_regimes: Sequence[DeliveryRegime] = DELIVERY_REGIMES,
    snapshot_period: float = 300.0,
    delta_interval: float = 30.0,
    dns_poll_interval: float = 60.0,
    request_time_latency: float = 0.05,
    status_universe_entries: int = 1_000_000,
) -> list[MetricRow]:
    """Run mechanism-level delivery baselines inspired by revocation related work.

    These rows emulate delivery regimes, not full cryptographic systems. They
    provide matched metrics for CRL/bitstring, OCSP, compact-delta, DNS/log-poll,
    and hybrid families under the same relying-party population.
    """

    rows: list[MetricRow] = []
    for seed in seeds:
        for status_suppression in status_suppression_values:
            for regime in delivery_regimes:
                if regime == "hybrid":
                    scenario = Scenario(
                        n_parties=n_parties,
                        ttl=ttl,
                        velocity=velocity,
                        seed=int(seed),
                        push_suppression=push_suppression,
                        gossip_suppression=gossip_suppression,
                        log_suppression=float(status_suppression),
                        max_time=max_time,
                        push_delay=push_delay,
                        gossip_delay=gossip_delay,
                        gossip_interval=gossip_interval,
                        poll_interval=poll_interval,
                        log_append_delay=log_append_delay,
                        jitter=jitter,
                        gossip_fanout=gossip_fanout,
                    )
                    row = run_metric_trial("hybrid", scenario)
                    row["experiment"] = "E-B2"
                    row["baseline_family"] = "delivery-regime"
                    row["delivery_regime"] = "hybrid"
                    row["status_suppression"] = float(status_suppression)
                    row["status_messages"] = row.get("log_polls")
                    row["delivery_bytes_total"] = float(row.get("channel_messages", 0)) * 512.0
                    row["delivery_bytes_per_party"] = _ratio(row["delivery_bytes_total"], n_parties)
                    row["per_party_state_bytes"] = 2048.0
                    row["status_availability_loss_rate"] = float(status_suppression)
                    row["stale_acceptance_window"] = row.get("delta_prop_for_damage")
                    row["mechanism_model"] = "paper-hybrid-push-gossip-log"
                    rows.append(row)
                    continue

                rows.append(
                    _delivery_regime_model_row(
                        regime,
                        seed=int(seed),
                        n_parties=n_parties,
                        ttl=ttl,
                        velocity=velocity,
                        status_suppression=float(status_suppression),
                        snapshot_period=snapshot_period,
                        delta_interval=delta_interval,
                        dns_poll_interval=dns_poll_interval,
                        request_time_latency=request_time_latency,
                        status_universe_entries=status_universe_entries,
                    )
                )
    return rows


def _delivery_regime_model_row(
    regime: DeliveryRegime,
    *,
    seed: int,
    n_parties: int,
    ttl: float,
    velocity: float,
    status_suppression: float,
    snapshot_period: float,
    delta_interval: float,
    dns_poll_interval: float,
    request_time_latency: float,
    status_universe_entries: int,
) -> MetricRow:
    regime_index = DELIVERY_REGIMES.index(regime)
    rng = random.Random(seed * 100_003 + regime_index * 997 + int(status_suppression * 10_000))
    party_ids = [f"rp-{idx}" for idx in range(n_parties)]
    suppressed = set(_select_fraction(party_ids, status_suppression, rng, exclude={"rp-0"}))
    delivery_deltas: list[float] = []
    stale_windows: list[float] = []
    availability_loss = 0.0

    full_snapshot_bytes = float(math.ceil(status_universe_entries / 8))
    if regime == "full-snapshot":
        payload_bytes = full_snapshot_bytes
        per_party_state_bytes = full_snapshot_bytes
        message_multiplier = 1
        for party_id in party_ids:
            offset = rng.uniform(0.0, snapshot_period)
            if party_id in suppressed:
                offset = max(offset, ttl)
            delivery_deltas.append(offset)
            stale_windows.append(offset)
    elif regime == "request-time-check":
        payload_bytes = 900.0
        per_party_state_bytes = 256.0
        message_multiplier = 1
        for party_id in party_ids:
            if party_id in suppressed:
                availability_loss += 1.0
                stale_windows.append(0.0)
                continue
            delivery_deltas.append(request_time_latency)
            stale_windows.append(request_time_latency)
    elif regime == "request-time-fail-open":
        payload_bytes = 900.0
        per_party_state_bytes = 256.0
        message_multiplier = 1
        for party_id in party_ids:
            delta = ttl if party_id in suppressed else request_time_latency
            delivery_deltas.append(delta)
            stale_windows.append(delta)
    elif regime == "compact-delta":
        payload_bytes = 1024.0
        per_party_state_bytes = 4096.0
        message_multiplier = 1
        for party_id in party_ids:
            offset = rng.uniform(0.0, delta_interval)
            if party_id in suppressed:
                offset = max(offset, min(ttl, 2.0 * delta_interval))
            delivery_deltas.append(offset)
            stale_windows.append(offset)
    elif regime == "dns-log-poll":
        payload_bytes = 512.0
        per_party_state_bytes = 2048.0
        message_multiplier = 2
        for party_id in party_ids:
            offset = rng.uniform(0.0, dns_poll_interval)
            if party_id in suppressed:
                offset = max(offset, ttl)
            delivery_deltas.append(offset)
            stale_windows.append(offset)
    else:
        raise ValueError(f"unsupported delivery regime: {regime}")

    delivered = len(delivery_deltas)
    messages = n_parties * message_multiplier
    delivery_bytes_total = messages * payload_bytes
    expected_window = _mean(stale_windows) or 0.0
    worst_window = max(stale_windows) if stale_windows else 0.0
    return {
        "experiment": "E-B2",
        "baseline_family": "delivery-regime",
        "strategy": regime,
        "delivery_regime": regime,
        "seed": seed,
        "n_parties": n_parties,
        "ttl": ttl,
        "velocity": velocity,
        "push_suppression": None,
        "gossip_suppression": None,
        "log_suppression": status_suppression,
        "status_suppression": status_suppression,
        "completeness": delivered / n_parties if n_parties else 1.0,
        "p50_delta": _percentile(delivery_deltas, 0.50),
        "p95_delta": _percentile(delivery_deltas, 0.95),
        "p99_delta": _percentile(delivery_deltas, 0.99),
        "p999_delta": _percentile(delivery_deltas, 0.999),
        "max_delta": max(delivery_deltas) if delivery_deltas else None,
        "undelivered_count": n_parties - delivered,
        "suppression_detected_at": None,
        "equivocation_detected_at": None,
        "channel_messages": messages,
        "push_messages": 0,
        "gossip_messages": 0,
        "log_polls": messages if regime in {"full-snapshot", "compact-delta", "dns-log-poll"} else 0,
        "log_appends": 0,
        "sth_observations": 0,
        "status_messages": messages,
        "delivery_bytes_total": delivery_bytes_total,
        "delivery_bytes_per_party": delivery_bytes_total / n_parties if n_parties else 0.0,
        "per_party_state_bytes": per_party_state_bytes,
        "status_availability_loss_rate": availability_loss / n_parties if n_parties else 0.0,
        "stale_acceptance_window": worst_window,
        "damage_delta_model": "delivery_regime_stale_window",
        "delta_prop_for_damage": worst_window,
        "unauthorized_ops_expected": velocity * expected_window,
        "unauthorized_ops_worst": velocity * worst_window,
        "mechanism_model": "mechanism-level-related-work-baseline",
    }


def run_e_b3_damage_budget(
    *,
    measured_rows: Sequence[MetricRow] | None = None,
    ttls: Sequence[float] = (10.0, 60.0, 300.0),
    velocities: Sequence[float] = (1.0, 10.0, 100.0),
    budget: float = 1000.0,
    budgets: Sequence[float] | None = None,
) -> list[MetricRow]:
    if measured_rows is None:
        measured_rows = run_e_b2_delta_prop_baselines(strategies=("push", "ttl-rcc", "hybrid"))
    budget_values = tuple(budgets) if budgets is not None else (budget,)

    rows: list[MetricRow] = []
    for measured in measured_rows:
        for ttl in ttls:
            for velocity in velocities:
                for budget_value in budget_values:
                    delta = _damage_delta_ttl_fallback(measured, ttl)
                    expected = unauthorized_ops_expected(ttl, velocity, delta)
                    worst = unauthorized_ops_worst(ttl, velocity, delta)
                    expected_window = ttl / 2.0 + delta
                    worst_window = ttl + delta
                    expected_exceeds = expected > budget_value
                    worst_exceeds = worst > budget_value
                    rows.append(
                        {
                            "experiment": "E-B3",
                            "source_experiment": measured.get("experiment"),
                            "strategy": measured["strategy"],
                            "seed": measured["seed"],
                            "n_parties": measured["n_parties"],
                            "ttl": ttl,
                            "velocity": velocity,
                            "damage_delta_model": "ttl_fallback_for_undelivered",
                            "delta_prop_for_damage": delta,
                            "unauthorized_ops_expected": expected,
                            "unauthorized_ops_worst": worst,
                            "budget": budget_value,
                            "budget_margin_expected": budget_value - expected,
                            "budget_margin_worst": budget_value - worst,
                            "expected_exceeds_budget": expected_exceeds,
                            "worst_exceeds_budget": worst_exceeds,
                            "expected_exceeds_budget_numeric": 1.0 if expected_exceeds else 0.0,
                            "worst_exceeds_budget_numeric": 1.0 if worst_exceeds else 0.0,
                            "propagation_share_expected": delta / expected_window if expected_window > 0.0 else 0.0,
                            "propagation_share_worst": delta / worst_window if worst_window > 0.0 else 0.0,
                            "undelivered_count": measured["undelivered_count"],
                            "source_completeness": measured.get("completeness"),
                            "source_p99_delta": measured.get("p99_delta"),
                            "source_max_delta": measured.get("max_delta"),
                            "source_push_suppression": measured.get("push_suppression"),
                            "source_gossip_suppression": measured.get("gossip_suppression"),
                            "source_log_suppression": measured.get("log_suppression"),
                        }
                    )
    return rows


def run_e_b4_equivocation_resistance(
    *,
    seeds: Iterable[int] = (0, 1, 2),
    root_counts: Sequence[int] = (5,),
    thresholds: Sequence[int] = (3,),
    observation_delays: Sequence[float] = (0.55,),
    partition_heal_delays: Sequence[float] = (),
    include_benign: bool = True,
    watcher_counts: Sequence[int] = (),
    watcher_coverages: Sequence[float] = (),
    watcher_observation_intervals: Sequence[float] = (),
    party_reporting_fractions: Sequence[float] = (1.0,),
    selective_disclosure_values: Sequence[float] = (0.0,),
    watcher_partition_durations: Sequence[float] = (0.0,),
) -> list[MetricRow]:
    rows: list[MetricRow] = []
    for seed in seeds:
        for root_count in root_counts:
            for threshold in thresholds:
                if threshold > root_count:
                    continue
                rows.extend(
                    _run_equivocation_seed(
                        seed,
                        root_count=root_count,
                        threshold=threshold,
                        observation_delays=observation_delays,
                        partition_heal_delays=partition_heal_delays,
                        include_benign=include_benign,
                        watcher_counts=watcher_counts,
                        watcher_coverages=watcher_coverages,
                        watcher_observation_intervals=watcher_observation_intervals,
                        party_reporting_fractions=party_reporting_fractions,
                        selective_disclosure_values=selective_disclosure_values,
                        watcher_partition_durations=watcher_partition_durations,
                    )
                )
    return rows


def run_e_b5_thin_a2a(
    *,
    seeds: Iterable[int] = (0, 1, 2),
    n_parties_values: Sequence[int] = (3, 10, 30),
    strategies: Sequence[PropagationStrategy] = ("push", "log", "hybrid"),
    transport_mode: str = "local-a2a-shaped-json",
) -> list[MetricRow]:
    rows: list[MetricRow] = []
    sdk_available = importlib.util.find_spec("a2a") is not None
    sdk_version = None
    if sdk_available:
        try:
            sdk_version = importlib.metadata.version("a2a-sdk")
        except importlib.metadata.PackageNotFoundError:
            sdk_version = "unknown"
    for seed in seeds:
        issuer = generate_keypair()
        event = create_revocation_event("edge-a2a", issuer, epoch_id="epoch-a2a", issued_at=0.0)
        agent_card = agent_card_extension(
            revocation_log_url="https://example.invalid/revocation-log",
            root_threshold=3,
            root_ids=["root-0", "root-1", "root-2", "root-3", "root-4"],
        )
        status_update = task_status_update_binding(event)
        payload_bytes = len(canonical_json_bytes({"agentCard": agent_card, "statusUpdate": status_update}))
        transport_delay = 0.001 + payload_bytes / 1_000_000.0
        for n_parties in n_parties_values:
            for strategy in strategies:
                scenario = Scenario(
                    n_parties=n_parties,
                    seed=seed,
                    push_suppression=0.2,
                    push_delay=0.05 + transport_delay,
                    gossip_delay=0.10 + transport_delay,
                    log_append_delay=0.05 + transport_delay,
                    poll_interval=0.50 + transport_delay,
                )
                row = run_metric_trial(strategy, scenario)
                row["experiment"] = "E-B5"
                row["a2a_sdk_available"] = sdk_available
                row["a2a_sdk_version"] = sdk_version
                row["a2a_transport_mode"] = transport_mode
                row["a2a_payload_bytes"] = payload_bytes
                row["a2a_transport_delay_model"] = transport_delay
                rows.append(row)
    return rows


def run_e_b6_local_end_to_end(
    *,
    seeds: Iterable[int] = (0, 1, 2),
    n_parties_values: Sequence[int] = (5, 10),
    strategies: Sequence[PropagationStrategy] = LOCAL_TRANSPORT_STRATEGIES,
    push_suppression: float = 0.2,
    gossip_suppression: float = 0.0,
    log_suppression: float = 0.0,
    duration: float = 1.5,
    push_delay: float = 0.02,
    gossip_interval: float = 0.10,
    poll_interval: float = 0.15,
    gossip_fanout: int = 4,
) -> list[MetricRow]:
    rows: list[MetricRow] = []
    for seed in seeds:
        for n_parties in n_parties_values:
            for strategy in strategies:
                result = asyncio.run(
                    run_local_end_to_end_trial(
                        seed=int(seed),
                        n_parties=int(n_parties),
                        strategy=strategy,
                        push_suppression=push_suppression,
                        gossip_suppression=gossip_suppression,
                        log_suppression=log_suppression,
                        duration=duration,
                        push_delay=push_delay,
                        gossip_interval=gossip_interval,
                        poll_interval=poll_interval,
                        gossip_fanout=gossip_fanout,
                    )
                )
                rows.append(_e_b6_row(result, push_suppression, gossip_suppression, log_suppression, duration))
    return rows


def run_e_b7_reproducibility_sensitivity(
    *,
    seeds: Iterable[int] = (0, 1, 2),
    n_parties_values: Sequence[int] = (40,),
    fanout_values: Sequence[int] = (4, 8, 16),
    poll_interval_values: Sequence[float] = (0.25, 0.50, 1.0),
    jitter_values: Sequence[float] = (0.0, 0.20, 0.40),
    delay_scale_values: Sequence[float] = (0.5, 1.0, 2.0),
    push_suppression: float = 0.2,
    max_time: float = 8.0,
) -> list[MetricRow]:
    rows: list[MetricRow] = []
    configs = _e_b7_single_factor_configs(
        fanout_values=fanout_values,
        poll_interval_values=poll_interval_values,
        jitter_values=jitter_values,
        delay_scale_values=delay_scale_values,
    )
    for seed in seeds:
        for n_parties in n_parties_values:
            for config in configs:
                delay_scale = float(config["delay_scale"])
                scenario = Scenario(
                    n_parties=int(n_parties),
                    seed=int(seed),
                    push_suppression=push_suppression,
                    gossip_suppression=0.0,
                    log_suppression=0.0,
                    max_time=max_time,
                    push_delay=0.05 * delay_scale,
                    gossip_delay=0.10 * delay_scale,
                    gossip_interval=0.25,
                    poll_interval=float(config["poll_interval"]),
                    log_append_delay=0.05 * delay_scale,
                    jitter=float(config["jitter"]),
                    gossip_fanout=int(config["gossip_fanout"]),
                )
                row = run_metric_trial("hybrid", scenario)
                row["experiment"] = "E-B7"
                row["config_id"] = config["config_id"]
                row["sensitivity_axis"] = config["sensitivity_axis"]
                row["delay_scale"] = delay_scale
                row["gossip_fanout"] = int(config["gossip_fanout"])
                row["poll_interval"] = float(config["poll_interval"])
                row["jitter"] = float(config["jitter"])
                row["max_time"] = max_time
                row["push_delay"] = scenario.push_delay
                row["gossip_delay"] = scenario.gossip_delay
                row["log_append_delay"] = scenario.log_append_delay
                row["run_key"] = "|".join(
                    (
                        "E-B7",
                        str(seed),
                        str(n_parties),
                        str(config["config_id"]),
                    )
                )
                rows.append(row)
    return rows


def run_e_b8_agent_tool_gateway(
    *,
    seeds: Iterable[int] = (0, 1, 2),
    n_parties_values: Sequence[int] = (40,),
    strategies: Sequence[PropagationStrategy] = AGENT_TOOL_STRATEGIES,
    tool_call_rates: Sequence[float] = (1.0, 10.0),
    ttl: float = 60.0,
    task_duration: float = 60.0,
    push_suppression: float = 0.2,
    gossip_suppression: float = 0.0,
    log_suppression: float = 0.0,
    max_time: float = 8.0,
    push_delay: float = 0.05,
    gossip_delay: float = 0.10,
    gossip_interval: float = 0.25,
    poll_interval: float = 0.50,
    log_append_delay: float = 0.05,
    jitter: float = 0.20,
    gossip_fanout: int | None = None,
    tool_name: str = "repo-write",
    agent_runtime_model: str = "tool-gateway-cached-capability",
) -> list[MetricRow]:
    """Model stale delegated tool authority at agent-runtime gateways.

    Each relying party is a gateway that will keep accepting a revoked
    capability until it receives revocation evidence or the capability TTL
    expires. The workload is represented as expected revoked tool invocations
    per gateway per second during a fixed post-revocation task window.
    """

    rows: list[MetricRow] = []
    for seed in seeds:
        for n_parties in n_parties_values:
            for tool_call_rate in tool_call_rates:
                for strategy in strategies:
                    scenario = Scenario(
                        n_parties=int(n_parties),
                        ttl=ttl,
                        velocity=float(tool_call_rate),
                        seed=int(seed),
                        push_suppression=push_suppression,
                        gossip_suppression=gossip_suppression,
                        log_suppression=log_suppression,
                        max_time=max_time,
                        push_delay=push_delay,
                        gossip_delay=gossip_delay,
                        gossip_interval=gossip_interval,
                        poll_interval=poll_interval,
                        log_append_delay=log_append_delay,
                        jitter=jitter,
                        gossip_fanout=gossip_fanout,
                    )
                    result = _run_propagation_result(strategy, scenario)
                    row = _metric_row(strategy, scenario, result)
                    row.update(
                        _agent_tool_gateway_metrics(
                            strategy=strategy,
                            scenario=scenario,
                            result=result,
                            tool_call_rate=float(tool_call_rate),
                            task_duration=task_duration,
                            tool_name=tool_name,
                            agent_runtime_model=agent_runtime_model,
                        )
                    )
                    rows.append(row)
    return rows


def run_e_b9_a2a_lifecycle_binding(
    *,
    seeds: Iterable[int] = (0, 1, 2),
    n_parties_values: Sequence[int] = (40,),
    compatibility_cells: Sequence[str] = A2A_LIFECYCLE_COMPATIBILITY_CELLS,
    strategy: PropagationStrategy = "hybrid",
    tool_call_rates: Sequence[float] = (1.0, 10.0),
    ttl: float = 60.0,
    task_duration: float = 60.0,
    push_suppression: float = 0.2,
    gossip_suppression: float = 0.0,
    log_suppression: float = 0.0,
    max_time: float = 8.0,
    push_delay: float = 0.05,
    gossip_delay: float = 0.10,
    gossip_interval: float = 0.25,
    poll_interval: float = 0.50,
    log_append_delay: float = 0.05,
    jitter: float = 0.20,
    gossip_fanout: int | None = None,
    fallback_policy: str = "fail-closed",
    request_time_latency: float = 0.05,
    tool_name: str = "repo-write",
) -> list[MetricRow]:
    """Evaluate A2A Agent Card discovery plus task-lifecycle revocation binding."""

    unknown_cells = sorted(set(compatibility_cells) - set(A2A_LIFECYCLE_COMPATIBILITY_CELLS))
    if unknown_cells:
        raise ValueError(f"unknown A2A lifecycle compatibility cells: {', '.join(unknown_cells)}")
    if fallback_policy not in {"fail-closed", "allow-ttl"}:
        raise ValueError("fallback_policy must be 'fail-closed' or 'allow-ttl'")

    rows: list[MetricRow] = []
    for seed in seeds:
        for n_parties in n_parties_values:
            for tool_call_rate in tool_call_rates:
                for cell in compatibility_cells:
                    scenario = Scenario(
                        n_parties=int(n_parties),
                        ttl=ttl,
                        velocity=float(tool_call_rate),
                        seed=int(seed),
                        push_suppression=push_suppression,
                        gossip_suppression=gossip_suppression,
                        log_suppression=log_suppression,
                        max_time=max_time,
                        push_delay=push_delay,
                        gossip_delay=gossip_delay,
                        gossip_interval=gossip_interval,
                        poll_interval=poll_interval,
                        log_append_delay=log_append_delay,
                        jitter=jitter,
                        gossip_fanout=gossip_fanout,
                    )
                    client_supports, server_supports = _a2a_lifecycle_cell_support(cell)
                    if server_supports:
                        result = _run_propagation_result(strategy, scenario)
                        row = _metric_row(strategy, scenario, result)
                    else:
                        result = None
                        row = _a2a_no_revocation_transport_row(strategy, scenario)
                    row.update(
                        _a2a_lifecycle_binding_metrics(
                            compatibility_cell=cell,
                            client_supports=client_supports,
                            server_supports=server_supports,
                            strategy=strategy,
                            scenario=scenario,
                            result=result,
                            tool_call_rate=float(tool_call_rate),
                            task_duration=task_duration,
                            fallback_policy=fallback_policy,
                            request_time_latency=request_time_latency,
                            tool_name=tool_name,
                        )
                    )
                    rows.append(row)
    return rows


def run_e_b10_real_gateway_tool_path(
    *,
    seeds: Iterable[int] = (0, 1),
    n_parties_values: Sequence[int] = (5,),
    protocol_profiles: Sequence[str] = ("raw-http-json",),
    fault_scenarios: Sequence[str] = ("none", "push-drop-log-repair"),
    tool_call_rates: Sequence[float] = (1.0, 10.0),
    ttl: float = 60.0,
    task_duration: float = 60.0,
    push_delay: float = 0.05,
    poll_interval: float = 0.50,
    log_append_delay: float = 0.05,
    log_delay: float = 0.0,
    jitter: float = 0.20,
    partition_duration: float = 2.0,
    gateway_restart_at: float = 0.25,
    tool_name: str = "repo-write",
) -> list[MetricRow]:
    """Exercise real loopback gateway/tool/log enforcement paths."""

    return _run_integration_experiment(
        experiment="E-B10",
        integration_surface="real-gateway-tool-loopback",
        seeds=seeds,
        n_parties_values=n_parties_values,
        protocol_profiles=protocol_profiles,
        fault_scenarios=fault_scenarios,
        tool_call_rates=tool_call_rates,
        ttl=ttl,
        task_duration=task_duration,
        push_delay=push_delay,
        poll_interval=poll_interval,
        log_append_delay=log_append_delay,
        log_delay=log_delay,
        jitter=jitter,
        partition_duration=partition_duration,
        gateway_restart_at=gateway_restart_at,
        tool_name=tool_name,
    )


def run_e_b11_protocol_boundary_path(
    *,
    seeds: Iterable[int] = (0, 1),
    n_parties_values: Sequence[int] = (5,),
    protocol_profiles: Sequence[str] = INTEGRATION_PROTOCOL_PROFILES,
    fault_scenarios: Sequence[str] = ("none",),
    tool_call_rates: Sequence[float] = (1.0, 10.0),
    ttl: float = 60.0,
    task_duration: float = 60.0,
    push_delay: float = 0.05,
    poll_interval: float = 0.50,
    log_append_delay: float = 0.05,
    log_delay: float = 0.0,
    jitter: float = 0.20,
    partition_duration: float = 2.0,
    gateway_restart_at: float = 0.25,
    tool_name: str = "repo-write",
) -> list[MetricRow]:
    """Sweep protocol envelopes while holding gateway/tool behavior fixed."""

    return _run_integration_experiment(
        experiment="E-B11",
        integration_surface="protocol-boundary-loopback",
        seeds=seeds,
        n_parties_values=n_parties_values,
        protocol_profiles=protocol_profiles,
        fault_scenarios=fault_scenarios,
        tool_call_rates=tool_call_rates,
        ttl=ttl,
        task_duration=task_duration,
        push_delay=push_delay,
        poll_interval=poll_interval,
        log_append_delay=log_append_delay,
        log_delay=log_delay,
        jitter=jitter,
        partition_duration=partition_duration,
        gateway_restart_at=gateway_restart_at,
        tool_name=tool_name,
    )


def run_e_b12_fault_injection_path(
    *,
    seeds: Iterable[int] = (0, 1),
    n_parties_values: Sequence[int] = (5,),
    protocol_profiles: Sequence[str] = ("raw-http-json",),
    fault_scenarios: Sequence[str] = (
        "push-drop-log-repair",
        "log-delay",
        "partition-heal",
        "gateway-restart",
    ),
    tool_call_rates: Sequence[float] = (1.0, 10.0),
    ttl: float = 60.0,
    task_duration: float = 60.0,
    push_delay: float = 0.05,
    poll_interval: float = 0.50,
    log_append_delay: float = 0.05,
    log_delay: float = 1.0,
    jitter: float = 0.20,
    partition_duration: float = 2.0,
    gateway_restart_at: float = 0.25,
    tool_name: str = "repo-write",
) -> list[MetricRow]:
    """Run local fault paths through the gateway/tool/log prototype."""

    return _run_integration_experiment(
        experiment="E-B12",
        integration_surface="fault-injection-loopback",
        seeds=seeds,
        n_parties_values=n_parties_values,
        protocol_profiles=protocol_profiles,
        fault_scenarios=fault_scenarios,
        tool_call_rates=tool_call_rates,
        ttl=ttl,
        task_duration=task_duration,
        push_delay=push_delay,
        poll_interval=poll_interval,
        log_append_delay=log_append_delay,
        log_delay=log_delay,
        jitter=jitter,
        partition_duration=partition_duration,
        gateway_restart_at=gateway_restart_at,
        tool_name=tool_name,
    )


def run_e_b13_paper_a_agent_system_bridge(
    *,
    paper_a_experiments_dir: str | Path | None = None,
) -> list[MetricRow]:
    """Summarize Paper A E16-E19 as agent-system evidence for Paper B."""

    return build_paper_a_agent_system_bridge_rows(paper_a_experiments_dir)


def run_e_b14_multiprocess_deployment(
    *,
    seeds: Iterable[int] = (0, 1),
    n_parties_values: Sequence[int] = (5,),
    protocol_profiles: Sequence[str] = ("raw-http-json",),
    fault_scenarios: Sequence[str] = ("none", "push-drop-log-repair"),
    tool_call_rates: Sequence[float] = (1.0, 10.0),
    ttl: float = 60.0,
    task_duration: float = 60.0,
    push_delay: float = 0.05,
    poll_interval: float = 0.50,
    log_append_delay: float = 0.05,
    log_delay: float = 0.0,
    jitter: float = 0.20,
    partition_duration: float = 2.0,
    gateway_restart_at: float = 0.25,
    tool_name: str = "repo-write",
    output_dir: str | Path | None = None,
) -> list[MetricRow]:
    """Run gateway, tool, and log roles in separate local OS processes."""

    rows: list[MetricRow] = []
    for seed in seeds:
        for n_parties in n_parties_values:
            for tool_call_rate in tool_call_rates:
                for protocol_profile in protocol_profiles:
                    for fault_scenario in fault_scenarios:
                        result, metadata = asyncio.run(
                            run_multiprocess_gateway_tool_trial(
                                seed=int(seed),
                                n_gateways=int(n_parties),
                                protocol_profile=str(protocol_profile),
                                fault_scenario=str(fault_scenario),
                                tool_call_rate=float(tool_call_rate),
                                ttl=ttl,
                                task_duration=task_duration,
                                push_delay=push_delay,
                                poll_interval=poll_interval,
                                log_append_delay=log_append_delay,
                                log_delay=log_delay,
                                jitter=jitter,
                                partition_duration=partition_duration,
                                gateway_restart_at=gateway_restart_at,
                                tool_name=tool_name,
                                output_dir=output_dir,
                            )
                        )
                        persistent_log_records = (
                            sum(1 for _ in metadata.persistent_log_path.open())
                            if metadata.persistent_log_path.exists()
                            else 0
                        )
                        row = _integration_trial_row(
                            result,
                            experiment="E-B14",
                            integration_surface="multiprocess-persistent-gateway-tool-log",
                        )
                        row.update(
                            {
                                "service_model": "multiprocess-tcp-jsonl-gateway-tool-log",
                                "separate_os_processes": True,
                                "separate_os_processes_numeric": 1.0,
                                "persistent_log": True,
                                "persistent_log_numeric": 1.0,
                                "persistent_log_path": str(metadata.persistent_log_path),
                                "persistent_log_records": persistent_log_records,
                                "process_count": metadata.process_count,
                                "service_roles": ",".join(metadata.service_roles),
                                "distributed_deployment": False,
                                "distributed_deployment_numeric": 0.0,
                                "claim_scope": (
                                    "multi-process local artifact deployment with persistent log; "
                                    "not a production multi-host cluster"
                                ),
                            }
                        )
                        rows.append(row)
    return rows


def run_e_b15_real_agent_tool_path(
    *,
    seeds: Iterable[int] = (0, 1),
    n_parties_values: Sequence[int] = (3,),
    path_profiles: Sequence[str] = AGENT_TOOL_PATH_PROFILES,
    fault_scenarios: Sequence[str] = ("none", "push-drop-log-repair"),
    tool_call_rates: Sequence[float] = (1.0, 10.0),
    ttl: float = 60.0,
    task_duration: float = 60.0,
    tool_name: str = "repo-write",
) -> list[MetricRow]:
    """Exercise real MCP Python and LangGraph agent-facing tool-call surfaces."""

    return run_agent_tool_path_trials(
        seeds=seeds,
        n_gateways_values=n_parties_values,
        path_profiles=path_profiles,
        fault_scenarios=fault_scenarios,
        tool_call_rates=tool_call_rates,
        ttl=ttl,
        task_duration=task_duration,
        tool_name=tool_name,
    )


def run_e_b16_status_outage_baselines(
    *,
    seeds: Iterable[int] = (0, 1),
    n_parties_values: Sequence[int] = (30,),
    strategies: Sequence[str] = STATUS_BASELINE_STRATEGIES,
    fault_scenarios: Sequence[str] = STATUS_FAULT_SCENARIOS,
    tool_call_rates: Sequence[float] = (1.0, 10.0),
    ttl: float = 60.0,
    task_duration: float = 60.0,
    status_latency: float = 0.05,
    outage_duration: float = 2.0,
) -> list[MetricRow]:
    """Compare synchronous status-check policies under local outage faults."""

    return run_status_outage_baseline_trials(
        seeds=seeds,
        n_gateways_values=n_parties_values,
        strategies=strategies,
        fault_scenarios=fault_scenarios,
        tool_call_rates=tool_call_rates,
        ttl=ttl,
        task_duration=task_duration,
        status_latency=status_latency,
        outage_duration=outage_duration,
    )


def _run_integration_experiment(
    *,
    experiment: str,
    integration_surface: str,
    seeds: Iterable[int],
    n_parties_values: Sequence[int],
    protocol_profiles: Sequence[str],
    fault_scenarios: Sequence[str],
    tool_call_rates: Sequence[float],
    ttl: float,
    task_duration: float,
    push_delay: float,
    poll_interval: float,
    log_append_delay: float,
    log_delay: float,
    jitter: float,
    partition_duration: float,
    gateway_restart_at: float,
    tool_name: str,
) -> list[MetricRow]:
    unknown_protocols = sorted(set(protocol_profiles) - set(INTEGRATION_PROTOCOL_PROFILES))
    if unknown_protocols:
        raise ValueError(f"unknown integration protocol profiles: {', '.join(unknown_protocols)}")
    unknown_faults = sorted(set(fault_scenarios) - set(INTEGRATION_FAULT_SCENARIOS))
    if unknown_faults:
        raise ValueError(f"unknown integration fault scenarios: {', '.join(unknown_faults)}")

    rows: list[MetricRow] = []
    for seed in seeds:
        for n_parties in n_parties_values:
            for tool_call_rate in tool_call_rates:
                for protocol_profile in protocol_profiles:
                    for fault_scenario in fault_scenarios:
                        result = asyncio.run(
                            run_gateway_tool_integration_trial(
                                seed=int(seed),
                                n_gateways=int(n_parties),
                                protocol_profile=str(protocol_profile),
                                fault_scenario=str(fault_scenario),
                                tool_call_rate=float(tool_call_rate),
                                ttl=ttl,
                                task_duration=task_duration,
                                push_delay=push_delay,
                                poll_interval=poll_interval,
                                log_append_delay=log_append_delay,
                                log_delay=log_delay,
                                jitter=jitter,
                                partition_duration=partition_duration,
                                gateway_restart_at=gateway_restart_at,
                                tool_name=tool_name,
                            )
                        )
                        rows.append(
                            _integration_trial_row(
                                result,
                                experiment=experiment,
                                integration_surface=integration_surface,
                            )
                        )
    return rows


def _integration_trial_row(
    result: IntegrationTrialResult,
    *,
    experiment: str,
    integration_surface: str,
) -> MetricRow:
    stale_windows = list(result.stale_windows)
    final_learn_latencies = list(result.final_learn_latencies)
    recovery_latencies = list(result.recovery_latencies)
    verification_denominator = max(1, result.push_delivered + result.log_repairs)
    return {
        "experiment": experiment,
        "run_id": (
            f"{experiment.lower()}-{result.protocol_profile}-{result.fault_scenario}-"
            f"seed-{result.seed}-n-{result.n_gateways}-rate-{result.tool_call_rate}"
        ),
        "run_key": (
            f"{experiment}:{result.protocol_profile}:{result.fault_scenario}:"
            f"{result.seed}:{result.n_gateways}:{result.tool_call_rate}"
        ),
        "integration_surface": integration_surface,
        "service_model": "asyncio-tcp-jsonl-gateway-tool-log",
        "strategy": "gateway-push-log-repair",
        "seed": result.seed,
        "n_parties": result.n_gateways,
        "n_gateways": result.n_gateways,
        "protocol_profile": result.protocol_profile,
        "fault_scenario": result.fault_scenario,
        "tool_name": result.tool_name,
        "tool_call_rate": result.tool_call_rate,
        "task_duration": result.task_duration,
        "ttl": result.ttl,
        "horizon": result.horizon,
        "push_delay": result.push_delay,
        "poll_interval": result.poll_interval,
        "log_append_delay": result.log_append_delay,
        "log_delay": result.log_delay,
        "partition_duration": result.partition_duration,
        "gateway_restart_at": result.gateway_restart_at,
        "root_count": result.root_count,
        "root_threshold": result.root_threshold,
        "event_payload_bytes": result.event_payload_bytes,
        "certificate_payload_bytes": result.certificate_payload_bytes,
        "completeness": result.post_repair_reject_rate,
        "p50_delta": _percentile(final_learn_latencies, 0.50),
        "p95_delta": _percentile(final_learn_latencies, 0.95),
        "p99_delta": _percentile(final_learn_latencies, 0.99),
        "max_delta": max(final_learn_latencies) if final_learn_latencies else None,
        "effective_enforcement_latency": _percentile(final_learn_latencies, 0.99),
        "stale_capability_window_mean": _mean(stale_windows),
        "stale_capability_window_p50": _percentile(stale_windows, 0.50),
        "stale_capability_window_p95": _percentile(stale_windows, 0.95),
        "stale_capability_window_p99": _percentile(stale_windows, 0.99),
        "stale_capability_window_max": max(stale_windows) if stale_windows else 0.0,
        "fault_recovery_latency_mean": _mean(recovery_latencies),
        "fault_recovery_latency_p99": _percentile(recovery_latencies, 0.99),
        "revoked_tool_calls_baseline_ttl": result.revoked_tool_calls_baseline_ttl,
        "revoked_tool_calls_allowed": result.revoked_tool_calls_allowed,
        "revoked_tool_calls_prevented": result.revoked_tool_calls_prevented,
        "prevented_fraction": result.prevented_fraction,
        "sampled_revoked_calls_allowed": result.sampled_revoked_calls_allowed,
        "sampled_revoked_calls_rejected": result.sampled_revoked_calls_rejected,
        "pre_revocation_calls": result.pre_revocation_calls,
        "pre_revocation_allowed": result.pre_revocation_allowed,
        "pre_revocation_allowed_rate": result.pre_revocation_allowed_rate,
        "post_repair_rejected": result.post_repair_rejected,
        "post_repair_reject_rate": result.post_repair_reject_rate,
        "protocol_calls": result.protocol_calls,
        "protocol_schema_passes": result.protocol_schema_passes,
        "protocol_schema_pass_rate": result.protocol_schema_pass_rate,
        "forwarded_tool_calls": result.forwarded_tool_calls,
        "gateway_restarts": result.gateway_restarts,
        "push_attempts": result.push_attempts,
        "push_delivered": result.push_delivered,
        "push_dropped": result.push_dropped,
        "log_repairs": result.log_repairs,
        "log_polls": result.counters.log_polls,
        "log_appends": result.counters.log_appends,
        "transport_requests": result.counters.requests,
        "transport_errors": result.counters.errors,
        "transport_bytes_sent": result.counters.bytes_sent,
        "transport_bytes_received": result.counters.bytes_received,
        "channel_messages": result.counters.requests,
        "tool_accepted_invocations": result.tool_accepted_invocations,
        "tool_rejected_invocations": result.tool_rejected_invocations,
        "signature_verified_events": result.signature_verified_events,
        "certificate_verified_events": result.certificate_verified_events,
        "rejected_events": result.rejected_events,
        "signature_verified_rate": result.signature_verified_events / verification_denominator,
        "root_certificate_verified_rate": result.certificate_verified_events / verification_denominator,
        "audit_evidence_gateways": result.audit_evidence_gateways,
        "audit_evidence_available": result.audit_evidence_gateways > 0,
        "audit_evidence_available_numeric": result.audit_evidence_gateways / result.n_gateways,
        "live_gateway_tool_success": result.integration_success,
        "integration_success_numeric": 1.0 if result.integration_success else 0.0,
        "gateway_tool_boundary_crossed": True,
        "gateway_tool_boundary_crossed_numeric": 1.0,
        "protocol_boundary_crossed": True,
        "protocol_boundary_crossed_numeric": 1.0,
        "loopback_service_boundary": True,
        "loopback_service_boundary_numeric": 1.0,
        "separate_os_processes": False,
        "separate_os_processes_numeric": 0.0,
        "distributed_deployment": False,
        "distributed_deployment_numeric": 0.0,
        "wall_time_seconds": result.wall_time_seconds,
        "claim_scope": "local loopback prototype; not multi-vendor, multi-process, or large-scale distributed deployment",
    }


def run_metric_trial(strategy: PropagationStrategy, scenario: Scenario) -> MetricRow:
    result = _run_propagation_result(strategy, scenario)
    return _metric_row(strategy, scenario, result)


def _run_propagation_result(strategy: PropagationStrategy, scenario: Scenario) -> PropagationResult:
    issuer = generate_keypair()
    log_key = generate_keypair()
    event = create_revocation_event(
        f"edge-{scenario.seed}-{strategy}",
        issuer,
        epoch_id="epoch-1",
        issued_at=0.0,
    )
    ledger = TransparencyLedger(log_key)
    party_ids = [f"rp-{idx}" for idx in range(scenario.n_parties)]
    policy = _fault_policy(party_ids, scenario)
    config = _propagation_config(scenario)
    result = Propagator(config).propagate(
        event,
        ledger=ledger,
        party_ids=party_ids,
        strategy=strategy,
        fault_policy=policy,
        ttl=scenario.ttl,
    )
    return result


def _agent_tool_gateway_metrics(
    *,
    strategy: PropagationStrategy,
    scenario: Scenario,
    result: PropagationResult,
    tool_call_rate: float,
    task_duration: float,
    tool_name: str,
    agent_runtime_model: str,
) -> MetricRow:
    seen_by_party = {record.party_id: record.delta_prop for record in result.records}
    horizon = min(scenario.ttl, task_duration)
    stale_windows: list[float] = []
    for idx in range(scenario.n_parties):
        party_id = f"rp-{idx}"
        delta = seen_by_party.get(party_id)
        if delta is None:
            stale_window = horizon
        else:
            stale_window = min(max(0.0, delta), horizon)
        stale_windows.append(stale_window)

    baseline_allowed = scenario.n_parties * tool_call_rate * horizon
    actual_allowed = sum(tool_call_rate * window for window in stale_windows)
    prevented = max(0.0, baseline_allowed - actual_allowed)
    audit_evidence_available = strategy in {"log", "push-log", "gossip-log", "hybrid"} and result.overhead.log_appends > 0
    return {
        "experiment": "E-B8",
        "agent_runtime_model": agent_runtime_model,
        "tool_name": tool_name,
        "tool_call_rate": tool_call_rate,
        "task_duration": task_duration,
        "stale_capability_window_mean": _mean(stale_windows),
        "stale_capability_window_p50": _percentile(stale_windows, 0.50),
        "stale_capability_window_p95": _percentile(stale_windows, 0.95),
        "stale_capability_window_p99": _percentile(stale_windows, 0.99),
        "stale_capability_window_max": max(stale_windows) if stale_windows else 0.0,
        "revoked_tool_calls_baseline_ttl": baseline_allowed,
        "revoked_tool_calls_allowed": actual_allowed,
        "revoked_tool_calls_prevented": prevented,
        "prevented_fraction": prevented / baseline_allowed if baseline_allowed > 0.0 else 1.0,
        "audit_evidence_available": audit_evidence_available,
        "audit_evidence_available_numeric": 1.0 if audit_evidence_available else 0.0,
        "gateway_state_bytes": 2048 + 96 * scenario.n_parties,
        "gateway_policy": "deny-after-revocation-or-ttl",
        "workload_model": "expected-tool-calls-per-gateway",
        "claim_scope": "agent-tool gateway model; not live LLM-agent benchmark",
    }


def _a2a_lifecycle_cell_support(cell: str) -> tuple[bool, bool]:
    return cell.startswith("new-client"), cell.endswith("new-server")


def _a2a_no_revocation_transport_row(strategy: PropagationStrategy, scenario: Scenario) -> MetricRow:
    return {
        "experiment": "E-B9",
        "run_id": f"{strategy}-seed-{scenario.seed}-n-{scenario.n_parties}-a2a-no-revocation",
        "strategy": strategy,
        "seed": scenario.seed,
        "n_parties": scenario.n_parties,
        "ttl": scenario.ttl,
        "velocity": scenario.velocity,
        "push_suppression": scenario.push_suppression,
        "gossip_suppression": scenario.gossip_suppression,
        "log_suppression": scenario.log_suppression,
        "completeness": 0.0,
        "p50_delta": None,
        "p95_delta": None,
        "p99_delta": None,
        "p999_delta": None,
        "max_delta": None,
        "undelivered_count": scenario.n_parties,
        "suppression_detected_at": None,
        "equivocation_detected_at": None,
        "channel_messages": 0,
        "push_messages": 0,
        "gossip_messages": 0,
        "log_polls": 0,
        "log_appends": 0,
        "sth_observations": 0,
        "damage_delta_model": "ttl_fallback_without_lifecycle_support",
        "delta_prop_for_damage": scenario.ttl,
        "unauthorized_ops_expected": unauthorized_ops_expected(scenario.ttl, scenario.velocity, scenario.ttl),
        "unauthorized_ops_worst": unauthorized_ops_worst(scenario.ttl, scenario.velocity, scenario.ttl),
    }


def _a2a_lifecycle_binding_metrics(
    *,
    compatibility_cell: str,
    client_supports: bool,
    server_supports: bool,
    strategy: PropagationStrategy,
    scenario: Scenario,
    result: PropagationResult | None,
    tool_call_rate: float,
    task_duration: float,
    fallback_policy: str,
    request_time_latency: float,
    tool_name: str,
) -> MetricRow:
    server_card = a2a_agent_card(
        agent_name=f"server-{compatibility_cell}",
        endpoint_url="https://example.invalid/a2a",
        revocation_log_url="https://example.invalid/revocations",
        root_threshold=3,
        root_ids=["root-0", "root-1", "root-2", "root-3", "root-4"],
        supports_revocation=server_supports,
    )
    support_detected = agent_card_supports_revocation(server_card)
    lifecycle_payload: dict[str, object] | None = None
    if server_supports:
        event = create_revocation_event(
            f"a2a-edge-{scenario.seed}-{compatibility_cell}",
            generate_keypair(),
            epoch_id="epoch-a2a",
            issued_at=0.0,
        )
        lifecycle_payload = task_lifecycle_revocation_binding(
            event,
            task_id=f"task-{scenario.seed}-{scenario.n_parties}-{compatibility_cell}",
            context_id=f"context-{scenario.seed}",
        )
    payload_valid = (
        validate_task_lifecycle_revocation_binding(lifecycle_payload)
        if lifecycle_payload is not None
        else not server_supports
    )
    lifecycle_event_bytes = len(canonical_json_bytes(lifecycle_payload)) if lifecycle_payload is not None else 0
    agent_card_bytes = len(canonical_json_bytes(server_card))
    processing_latency = 0.001 + (lifecycle_event_bytes / 1_000_000.0 if lifecycle_event_bytes else 0.0)
    horizon = min(scenario.ttl, task_duration)
    baseline_allowed = scenario.n_parties * tool_call_rate * horizon
    stale_windows = _stale_windows_from_result(result, scenario, horizon)
    server_latency = _percentile(stale_windows, 0.99) if server_supports else None
    if server_latency is not None:
        server_latency += processing_latency

    if client_supports and server_supports:
        client_abort_latency = server_latency
        effective_latency = server_latency
        actual_allowed = _allowed_calls_from_windows(stale_windows, tool_call_rate, processing_latency, horizon)
        task_available = True
        revocation_enforced = True
        lifecycle_binding_success = support_detected and payload_valid
        compatibility_correct = support_detected and payload_valid and revocation_enforced
        behavior = "client-parses-agent-card-and-aborts-task"
    elif client_supports and not server_supports:
        client_abort_latency = request_time_latency if fallback_policy == "fail-closed" else None
        server_latency = None
        effective_latency = request_time_latency if fallback_policy == "fail-closed" else horizon
        actual_allowed = 0.0 if fallback_policy == "fail-closed" else baseline_allowed
        task_available = fallback_policy != "fail-closed"
        revocation_enforced = fallback_policy == "fail-closed"
        lifecycle_binding_success = False
        compatibility_correct = not support_detected
        behavior = "new-client-downgrades-on-unsupported-server"
    elif not client_supports and server_supports:
        client_abort_latency = None
        effective_latency = server_latency
        actual_allowed = _allowed_calls_from_windows(stale_windows, tool_call_rate, processing_latency, horizon)
        task_available = True
        revocation_enforced = True
        lifecycle_binding_success = False
        compatibility_correct = support_detected and payload_valid and revocation_enforced
        behavior = "old-client-ignores-card-server-enforces"
    else:
        client_abort_latency = None
        server_latency = None
        effective_latency = horizon
        actual_allowed = baseline_allowed
        task_available = True
        revocation_enforced = False
        lifecycle_binding_success = False
        compatibility_correct = not support_detected
        behavior = "legacy-ttl-only"

    prevented = max(0.0, baseline_allowed - actual_allowed)
    return {
        "experiment": "E-B9",
        "compatibility_cell": compatibility_cell,
        "client_profile": "revprop-a2a-client" if client_supports else "legacy-a2a-client",
        "server_profile": "revprop-a2a-server" if server_supports else "legacy-a2a-server",
        "agent_runtime_model": "a2a-task-lifecycle-binding",
        "tool_name": tool_name,
        "tool_call_rate": tool_call_rate,
        "task_duration": task_duration,
        "fallback_policy": fallback_policy,
        "request_time_latency": request_time_latency,
        "client_supports_revocation": client_supports,
        "server_supports_revocation": server_supports,
        "agent_card_support_detected": support_detected,
        "lifecycle_event_emitted": lifecycle_payload is not None,
        "lifecycle_event_parsed": bool(client_supports and payload_valid and lifecycle_payload is not None),
        "compatibility_correct": compatibility_correct,
        "compatibility_correct_numeric": 1.0 if compatibility_correct else 0.0,
        "schema_conformance_pass": payload_valid,
        "schema_conformance_pass_numeric": 1.0 if payload_valid else 0.0,
        "lifecycle_binding_success": lifecycle_binding_success,
        "lifecycle_binding_success_numeric": 1.0 if lifecycle_binding_success else 0.0,
        "revocation_enforced": revocation_enforced,
        "revocation_enforced_numeric": 1.0 if revocation_enforced else 0.0,
        "task_available": task_available,
        "task_available_numeric": 1.0 if task_available else 0.0,
        "availability_loss_numeric": 0.0 if task_available else 1.0,
        "effective_enforcement_latency": effective_latency,
        "client_abort_latency": client_abort_latency,
        "server_enforcement_latency": server_latency,
        "stale_capability_window_mean": _mean(stale_windows),
        "stale_capability_window_p99": _percentile(stale_windows, 0.99),
        "stale_capability_window_max": max(stale_windows) if stale_windows else horizon,
        "revoked_tool_calls_baseline_ttl": baseline_allowed,
        "revoked_tool_calls_allowed": actual_allowed,
        "revoked_tool_calls_prevented": prevented,
        "prevented_fraction": prevented / baseline_allowed if baseline_allowed > 0.0 else 1.0,
        "agent_card_bytes": agent_card_bytes,
        "lifecycle_event_bytes": lifecycle_event_bytes,
        "a2a_binding_behavior": behavior,
        "gateway_policy": "deny-after-revocation-or-ttl",
        "workload_model": "expected-tool-calls-per-gateway",
        "claim_scope": "A2A Agent Card and lifecycle binding model; not third-party interoperability",
        "run_key": "|".join(
            (
                "E-B9",
                compatibility_cell,
                strategy,
                str(scenario.seed),
                str(scenario.n_parties),
                f"{tool_call_rate:.6g}",
                fallback_policy,
            )
        ),
    }


def _stale_windows_from_result(
    result: PropagationResult | None,
    scenario: Scenario,
    horizon: float,
) -> list[float]:
    if result is None:
        return [horizon for _ in range(scenario.n_parties)]
    seen_by_party = {record.party_id: record.delta_prop for record in result.records}
    stale_windows: list[float] = []
    for idx in range(scenario.n_parties):
        delta = seen_by_party.get(f"rp-{idx}")
        stale_windows.append(horizon if delta is None else min(max(0.0, delta), horizon))
    return stale_windows


def _allowed_calls_from_windows(
    stale_windows: Sequence[float],
    tool_call_rate: float,
    processing_latency: float,
    horizon: float,
) -> float:
    return sum(tool_call_rate * min(horizon, window + processing_latency) for window in stale_windows)


def _e_b6_row(
    result: object,
    push_suppression: float,
    gossip_suppression: float,
    log_suppression: float,
    duration: float,
) -> MetricRow:
    counters = result.counters
    delivered = len(result.first_seen)
    verified_rate = (
        0.0
        if delivered == 0
        else (
            1.0
            if result.rejected_events == 0
            else max(0, delivered - result.rejected_events) / delivered
        )
    )
    return {
        "experiment": "E-B6",
        "run_id": f"{result.strategy}-seed-{result.seed}-n-{result.n_parties}-local-e2e",
        "service_model": result.service_model,
        "strategy": result.strategy,
        "seed": result.seed,
        "n_parties": result.n_parties,
        "duration": duration,
        "push_suppression": push_suppression,
        "gossip_suppression": gossip_suppression,
        "log_suppression": log_suppression,
        "root_count": result.root_count,
        "root_threshold": result.root_threshold,
        "completeness": result.completeness,
        "p50_delta": result.percentile_delta(0.50),
        "p95_delta": result.percentile_delta(0.95),
        "p99_delta": result.percentile_delta(0.99),
        "max_delta": max(result.deltas) if result.deltas else None,
        "undelivered_count": result.undelivered_count,
        "wall_time_seconds": result.wall_time_seconds,
        "transport_requests": counters.requests,
        "transport_errors": counters.errors,
        "transport_bytes_sent": counters.bytes_sent,
        "transport_bytes_received": counters.bytes_received,
        "push_attempts": counters.push_attempts,
        "push_delivered": counters.push_delivered,
        "push_suppressed": counters.push_suppressed,
        "gossip_attempts": counters.gossip_attempts,
        "gossip_delivered": counters.gossip_delivered,
        "gossip_suppressed": counters.gossip_suppressed,
        "log_polls": counters.log_polls,
        "log_poll_suppressed": counters.log_poll_suppressed,
        "log_appends": counters.log_appends,
        "event_payload_bytes": result.event_payload_bytes,
        "certificate_payload_bytes": result.certificate_payload_bytes,
        "signature_verified_events": result.signature_verified_events,
        "certificate_verified_events": result.certificate_verified_events,
        "rejected_events": result.rejected_events,
        "signature_verified_rate": verified_rate,
        "root_certificate_verified_rate": verified_rate,
        "live_transport_success": counters.errors == 0 and delivered > 0,
    }


def _e_b7_single_factor_configs(
    *,
    fanout_values: Sequence[int],
    poll_interval_values: Sequence[float],
    jitter_values: Sequence[float],
    delay_scale_values: Sequence[float],
) -> list[dict[str, object]]:
    baseline = {
        "config_id": "baseline",
        "sensitivity_axis": "baseline",
        "gossip_fanout": 8,
        "poll_interval": 0.50,
        "jitter": 0.20,
        "delay_scale": 1.0,
    }
    configs: list[dict[str, object]] = [baseline]
    seen = {"baseline"}

    def add(axis: str, value: object, **overrides: object) -> None:
        config = dict(baseline)
        config.update(overrides)
        config_id = f"{axis}={value}"
        if config_id in seen or config == baseline:
            return
        config["config_id"] = config_id
        config["sensitivity_axis"] = axis
        configs.append(config)
        seen.add(config_id)

    for fanout in fanout_values:
        add("fanout", fanout, gossip_fanout=int(fanout))
    for poll_interval in poll_interval_values:
        add("poll_interval", poll_interval, poll_interval=float(poll_interval))
    for jitter in jitter_values:
        add("jitter", jitter, jitter=float(jitter))
    for delay_scale in delay_scale_values:
        add("delay_scale", delay_scale, delay_scale=float(delay_scale))
    return configs


def _propagation_config(scenario: Scenario) -> PropagationConfig:
    fanout = scenario.gossip_fanout
    if fanout is None and scenario.n_parties > 30:
        fanout = min(8, scenario.n_parties - 1)
    return PropagationConfig(
        push_delay=scenario.push_delay,
        push_jitter=scenario.jitter,
        gossip_delay=scenario.gossip_delay,
        gossip_jitter=scenario.jitter,
        gossip_interval=scenario.gossip_interval,
        gossip_interval_jitter=scenario.jitter / 2.0,
        gossip_fanout=fanout,
        poll_interval=scenario.poll_interval,
        poll_jitter=scenario.jitter / 2.0,
        log_append_delay=scenario.log_append_delay,
        log_append_jitter=scenario.jitter,
        max_time=scenario.max_time,
        random_seed=scenario.seed,
    )


def _fault_policy(party_ids: Sequence[str], scenario: Scenario) -> FaultPolicy:
    rng = random.Random(scenario.seed)
    return FaultPolicy(
        suppress_push_to=frozenset(_select_fraction(party_ids, scenario.push_suppression, rng, exclude={"rp-0"})),
        suppress_gossip_to=frozenset(_select_fraction(party_ids, scenario.gossip_suppression, rng, exclude={"rp-0"})),
        suppress_log_to=frozenset(_select_fraction(party_ids, scenario.log_suppression, rng, exclude={"rp-0"})),
    )


def _select_fraction(
    party_ids: Sequence[str],
    fraction: float,
    rng: random.Random,
    *,
    exclude: set[str] | None = None,
) -> list[str]:
    if fraction <= 0.0:
        return []
    excluded = exclude or set()
    population = [party_id for party_id in party_ids if party_id not in excluded]
    count = min(len(population), int(round(len(party_ids) * fraction)))
    if count <= 0:
        return []
    return sorted(rng.sample(population, count))


def _metric_row(strategy: PropagationStrategy, scenario: Scenario, result: PropagationResult) -> MetricRow:
    delta_for_damage = _damage_delta_ttl_fallback(
        {
            "max_delta": result.max_delta,
            "undelivered_count": len(result.undelivered),
        },
        scenario.ttl,
    )
    return {
        "experiment": "",
        "run_id": f"{strategy}-seed-{scenario.seed}-n-{scenario.n_parties}",
        "strategy": strategy,
        "seed": scenario.seed,
        "n_parties": scenario.n_parties,
        "ttl": scenario.ttl,
        "velocity": scenario.velocity,
        "push_suppression": scenario.push_suppression,
        "gossip_suppression": scenario.gossip_suppression,
        "log_suppression": scenario.log_suppression,
        "completeness": result.completeness,
        "p50_delta": result.p50_delta,
        "p95_delta": result.p95_delta,
        "p99_delta": result.p99_delta,
        "p999_delta": result.p999_delta,
        "max_delta": result.max_delta,
        "undelivered_count": len(result.undelivered),
        "suppression_detected_at": result.suppression_detected_at,
        "equivocation_detected_at": result.equivocation_detected_at,
        "channel_messages": result.overhead.channel_messages,
        "push_messages": result.overhead.push_messages,
        "gossip_messages": result.overhead.gossip_messages,
        "log_polls": result.overhead.log_polls,
        "log_appends": result.overhead.log_appends,
        "sth_observations": result.overhead.sth_observations,
        "damage_delta_model": "ttl_fallback_for_undelivered",
        "delta_prop_for_damage": delta_for_damage,
        "unauthorized_ops_expected": unauthorized_ops_expected(scenario.ttl, scenario.velocity, delta_for_damage),
        "unauthorized_ops_worst": unauthorized_ops_worst(scenario.ttl, scenario.velocity, delta_for_damage),
    }


def _damage_delta_ttl_fallback(row: MetricRow, ttl: float) -> float:
    if str(row.get("strategy")) == "ttl-rcc":
        return ttl
    max_delta = row.get("max_delta")
    delivered_delta = 0.0 if max_delta is None else float(max_delta)
    if int(row.get("undelivered_count", 0)) > 0:
        return max(delivered_delta, ttl)
    return delivered_delta


def _within_budget(value: object, budget: object) -> bool | None:
    if value is None:
        return None
    return float(value) <= float(budget)


def _run_equivocation_seed(
    seed: int,
    *,
    root_count: int = 5,
    threshold: int = 3,
    observation_delays: Sequence[float] = (0.55,),
    partition_heal_delays: Sequence[float] = (),
    include_benign: bool = True,
    watcher_counts: Sequence[int] = (),
    watcher_coverages: Sequence[float] = (),
    watcher_observation_intervals: Sequence[float] = (),
    party_reporting_fractions: Sequence[float] = (1.0,),
    selective_disclosure_values: Sequence[float] = (0.0,),
    watcher_partition_durations: Sequence[float] = (0.0,),
) -> list[MetricRow]:
    issuer = generate_keypair()
    log_key = generate_keypair()
    left = TransparencyLedger(log_key, log_id="forked-log")
    right = TransparencyLedger(log_key, log_id="forked-log")
    left_event = create_revocation_event("edge-left", issuer, epoch_id="epoch-eq", issued_at=0.0)
    right_event = create_revocation_event("edge-right", issuer, epoch_id="epoch-eq", issued_at=0.0)
    left.append(left_event, appended_at=0.10)
    right.append(right_event, appended_at=0.10)
    left_sth = left.latest_sth(timestamp=0.20)
    right_sth = right.latest_sth(timestamp=0.20)

    roots = [RootAuthority(f"root-{idx}", generate_keypair()) for idx in range(root_count)]
    federation = RootFederation({root.root_id: root.keypair.public for root in roots}, threshold=threshold)

    evidence_bytes = len(
        canonical_json_bytes(
            {
                "left_sth": left_sth.signable_payload(),
                "right_sth": right_sth.signable_payload(),
                "left_signature": left_sth.signature,
                "right_signature": right_sth.signature,
            }
        )
    )
    rows: list[MetricRow] = []

    rows.append(
        _e_b4_row(
            seed=seed,
            scenario="single-root-baseline",
            scenario_category="baseline",
            root_count=1,
            threshold=1,
            corrupt_roots=1,
            certificate_accepted=True,
            equivocation_detected=False,
            expected_certificate_accepted=True,
            expected_equivocation_detected=False,
            detection_latency=None,
            cross_observation_delay=None,
            evidence_bytes=0,
            baseline_misses_attack=True,
            notes="Single-root baseline has no threshold protection.",
        )
    )

    for corrupt_roots in range(1, threshold):
        approvals = [root.approve_event(left_event) for root in roots[:corrupt_roots]]
        certificate = federation.certificate_for(left_event, approvals)
        accepted = federation.verify_certificate(certificate)
        if root_count == 5 and threshold == 3 and corrupt_roots == 1:
            scenario = "below-threshold-root-fork"
        elif root_count == 5 and threshold == 3 and corrupt_roots == 2:
            scenario = "two-of-five-root-fork"
        else:
            scenario = "below-threshold-root-fork"
        rows.append(
            _e_b4_row(
                seed=seed,
                scenario=scenario,
                scenario_category="root-threshold",
                root_count=root_count,
                threshold=threshold,
                corrupt_roots=corrupt_roots,
                certificate_accepted=accepted,
                equivocation_detected=False,
                expected_certificate_accepted=False,
                expected_equivocation_detected=False,
                detection_latency=None,
                cross_observation_delay=None,
                evidence_bytes=0,
                baseline_misses_attack=False,
                notes="Below-threshold root collusion must fail certificate verification.",
            )
        )

    threshold_approvals = [root.approve_event(left_event) for root in roots[:threshold]]
    threshold_certificate = federation.certificate_for(left_event, threshold_approvals)
    threshold_accepted = federation.verify_certificate(threshold_certificate)
    rows.append(
        _e_b4_row(
            seed=seed,
            scenario="threshold-without-sth-cross-observation",
            scenario_category="baseline",
            root_count=root_count,
            threshold=threshold,
            corrupt_roots=threshold,
            certificate_accepted=threshold_accepted,
            equivocation_detected=False,
            expected_certificate_accepted=True,
            expected_equivocation_detected=False,
            detection_latency=None,
            cross_observation_delay=None,
            evidence_bytes=0,
            baseline_misses_attack=True,
            notes="M-of-N without STH cross-observation accepts quorum-certified forks but lacks split-view evidence.",
        )
    )

    for observation_delay in observation_delays:
        party = RelyingParty(f"observer-{seed}-split-{observation_delay}")
        first_observed_at = 0.30
        second_observed_at = first_observed_at + observation_delay
        party.observe_sth(left_sth, now=first_observed_at)
        party.observe_sth(right_sth, now=second_observed_at)
        detected = party.equivocation_detected_at is not None
        rows.append(
            _e_b4_row(
                seed=seed,
                scenario="threshold-plus-split-view-log",
                scenario_category="split-view",
                root_count=root_count,
                threshold=threshold,
                corrupt_roots=threshold,
                certificate_accepted=threshold_accepted,
                equivocation_detected=detected,
                expected_certificate_accepted=True,
                expected_equivocation_detected=True,
                detection_latency=party.equivocation_detected_at,
                cross_observation_delay=observation_delay,
                evidence_bytes=evidence_bytes,
                baseline_misses_attack=False,
                notes="Threshold corruption can sign, but same-size STH cross-observation exposes the split view.",
            )
        )

    for heal_delay in partition_heal_delays:
        party = RelyingParty(f"observer-{seed}-partition-{heal_delay}")
        first_observed_at = 0.30
        second_observed_at = first_observed_at + heal_delay
        party.observe_sth(left_sth, now=first_observed_at)
        party.observe_sth(right_sth, now=second_observed_at)
        detected = party.equivocation_detected_at is not None
        rows.append(
            _e_b4_row(
                seed=seed,
                scenario="partition-heal-split-view",
                scenario_category="partition-heal",
                root_count=root_count,
                threshold=threshold,
                corrupt_roots=threshold,
                certificate_accepted=threshold_accepted,
                equivocation_detected=detected,
                expected_certificate_accepted=True,
                expected_equivocation_detected=True,
                detection_latency=party.equivocation_detected_at,
                cross_observation_delay=heal_delay,
                evidence_bytes=evidence_bytes,
                baseline_misses_attack=False,
                notes="During partition the fork can persist; detection occurs when honest observers exchange STHs after healing.",
            )
        )

    if watcher_counts and watcher_coverages and watcher_observation_intervals:
        rows.extend(
            _e_b4_watcher_coverage_rows(
                seed=seed,
                root_count=root_count,
                threshold=threshold,
                threshold_accepted=threshold_accepted,
                evidence_bytes=evidence_bytes,
                watcher_counts=watcher_counts,
                watcher_coverages=watcher_coverages,
                watcher_observation_intervals=watcher_observation_intervals,
                party_reporting_fractions=party_reporting_fractions,
                selective_disclosure_values=selective_disclosure_values,
                watcher_partition_durations=watcher_partition_durations,
            )
        )

    if include_benign:
        benign = TransparencyLedger(generate_keypair(), log_id="benign-log")
        benign_event_a = create_revocation_event(f"edge-benign-a-{seed}", issuer, epoch_id="epoch-benign", issued_at=0.0)
        benign_event_b = create_revocation_event(f"edge-benign-b-{seed}", issuer, epoch_id="epoch-benign", issued_at=0.0)
        benign.append(benign_event_a, appended_at=0.10)
        old_sth = benign.latest_sth(timestamp=0.20)
        benign.append(benign_event_b, appended_at=0.30)
        new_sth = benign.latest_sth(timestamp=0.40)
        party = RelyingParty(f"observer-{seed}-benign")
        party.observe_sth(new_sth, now=0.50)
        party.observe_sth(old_sth, now=0.60)
        detected = party.equivocation_detected_at is not None
        rows.append(
            _e_b4_row(
                seed=seed,
                scenario="benign-sth-reordering",
                scenario_category="benign",
                root_count=root_count,
                threshold=threshold,
                corrupt_roots=0,
                certificate_accepted=True,
                equivocation_detected=detected,
                expected_certificate_accepted=True,
                expected_equivocation_detected=False,
                detection_latency=party.equivocation_detected_at,
                cross_observation_delay=0.10,
                evidence_bytes=0,
                baseline_misses_attack=False,
                notes="Different-size STH reordering is benign and should not trigger same-size split-view evidence.",
            )
        )

    return rows


def _e_b4_watcher_coverage_rows(
    *,
    seed: int,
    root_count: int,
    threshold: int,
    threshold_accepted: bool,
    evidence_bytes: int,
    watcher_counts: Sequence[int],
    watcher_coverages: Sequence[float],
    watcher_observation_intervals: Sequence[float],
    party_reporting_fractions: Sequence[float],
    selective_disclosure_values: Sequence[float],
    watcher_partition_durations: Sequence[float],
) -> list[MetricRow]:
    rows: list[MetricRow] = []
    for watcher_count in watcher_counts:
        for watcher_coverage in watcher_coverages:
            for observation_interval in watcher_observation_intervals:
                for reporting_fraction in party_reporting_fractions:
                    for selective_disclosure in selective_disclosure_values:
                        for partition_duration in watcher_partition_durations:
                            rows.append(
                                _e_b4_watcher_coverage_row(
                                    seed=seed,
                                    root_count=root_count,
                                    threshold=threshold,
                                    threshold_accepted=threshold_accepted,
                                    evidence_bytes=evidence_bytes,
                                    watcher_count=int(watcher_count),
                                    watcher_coverage=float(watcher_coverage),
                                    observation_interval=float(observation_interval),
                                    reporting_fraction=float(reporting_fraction),
                                    selective_disclosure=float(selective_disclosure),
                                    partition_duration=float(partition_duration),
                                )
                            )
    return rows


def _e_b4_watcher_coverage_row(
    *,
    seed: int,
    root_count: int,
    threshold: int,
    threshold_accepted: bool,
    evidence_bytes: int,
    watcher_count: int,
    watcher_coverage: float,
    observation_interval: float,
    reporting_fraction: float,
    selective_disclosure: float,
    partition_duration: float,
) -> MetricRow:
    coverage = min(1.0, max(0.0, watcher_coverage))
    reporting = min(1.0, max(0.0, reporting_fraction))
    disclosure = min(1.0, max(0.0, selective_disclosure))
    per_watcher_cross_prob = coverage * reporting * (1.0 - disclosure)
    detection_probability_model = 1.0 - (1.0 - per_watcher_cross_prob) ** max(0, watcher_count)
    rng = random.Random(
        seed * 1_000_003
        + watcher_count * 10_007
        + int(coverage * 10_000) * 101
        + int(observation_interval * 10_000)
        + int(reporting * 10_000) * 17
        + int(disclosure * 10_000) * 31
        + int(partition_duration * 10_000) * 43
    )
    detected_watchers = 0
    earliest_detection: float | None = None
    for watcher_idx in range(watcher_count):
        if rng.random() >= per_watcher_cross_prob:
            continue
        detected_watchers += 1
        detection = partition_duration + observation_interval * (1.0 + rng.random())
        detection += disclosure * observation_interval
        if earliest_detection is None or detection < earliest_detection:
            earliest_detection = detection

    detected = detected_watchers > 0
    row = _e_b4_row(
        seed=seed,
        scenario="watcher-coverage-split-view",
        scenario_category="watcher-coverage",
        root_count=root_count,
        threshold=threshold,
        corrupt_roots=threshold,
        certificate_accepted=threshold_accepted,
        equivocation_detected=detected,
        expected_certificate_accepted=True,
        expected_equivocation_detected=detected,
        detection_latency=earliest_detection,
        cross_observation_delay=earliest_detection,
        evidence_bytes=evidence_bytes + detected_watchers * 64,
        baseline_misses_attack=not detected,
        notes="Stochastic watcher coverage model for quorum-certified split-view observability.",
    )
    row["watcher_count"] = watcher_count
    row["watcher_coverage"] = coverage
    row["observation_interval"] = observation_interval
    row["party_reporting_fraction"] = reporting
    row["selective_disclosure"] = disclosure
    row["partition_duration"] = partition_duration
    row["watcher_effective_reports"] = detected_watchers
    row["watcher_cross_probability"] = per_watcher_cross_prob
    row["watcher_detection_probability_model"] = detection_probability_model
    row["watcher_model"] = "independent-cross-observation"
    return row


def _e_b4_row(
    *,
    seed: int,
    scenario: str,
    scenario_category: str,
    root_count: int,
    threshold: int,
    corrupt_roots: int,
    certificate_accepted: bool,
    equivocation_detected: bool,
    expected_certificate_accepted: bool,
    expected_equivocation_detected: bool,
    detection_latency: float | None,
    cross_observation_delay: float | None,
    evidence_bytes: int,
    baseline_misses_attack: bool,
    notes: str,
) -> MetricRow:
    false_positive = equivocation_detected and not expected_equivocation_detected
    outcome_success = (
        certificate_accepted == expected_certificate_accepted
        and equivocation_detected == expected_equivocation_detected
        and not false_positive
    )
    return {
        "experiment": "E-B4",
        "seed": seed,
        "scenario": scenario,
        "scenario_category": scenario_category,
        "root_count": root_count,
        "threshold": threshold,
        "corrupt_roots": corrupt_roots,
        "honest_roots": max(0, root_count - corrupt_roots),
        "certificate_accepted": certificate_accepted,
        "certificate_accepted_numeric": 1.0 if certificate_accepted else 0.0,
        "expected_certificate_accepted": expected_certificate_accepted,
        "expected_certificate_accepted_numeric": 1.0 if expected_certificate_accepted else 0.0,
        "equivocation_detected": equivocation_detected,
        "equivocation_detected_numeric": 1.0 if equivocation_detected else 0.0,
        "expected_equivocation_detected": expected_equivocation_detected,
        "expected_equivocation_detected_numeric": 1.0 if expected_equivocation_detected else 0.0,
        "detection_latency": detection_latency,
        "cross_observation_delay": cross_observation_delay,
        "evidence_bytes": evidence_bytes,
        "false_positive": false_positive,
        "false_positive_numeric": 1.0 if false_positive else 0.0,
        "baseline_misses_attack": baseline_misses_attack,
        "baseline_misses_attack_numeric": 1.0 if baseline_misses_attack else 0.0,
        "outcome_success": outcome_success,
        "outcome_success_numeric": 1.0 if outcome_success else 0.0,
        "notes": notes,
    }


def _summary(results: dict[str, list[MetricRow]]) -> dict[str, object]:
    summary: dict[str, object] = {}
    for experiment, rows in results.items():
        summary[experiment] = {
            "rows": len(rows),
            "mean_completeness": _mean([row.get("completeness") for row in rows]),
            "mean_p99_delta": _mean([row.get("p99_delta") for row in rows]),
            "mean_channel_messages": _mean([row.get("channel_messages") for row in rows]),
        }
    return summary


def _mean(values: Iterable[object]) -> float | None:
    numeric = [_as_float(value) for value in values]
    numeric = [value for value in numeric if value is not None]
    if not numeric:
        return None
    return sum(numeric) / len(numeric)


def _percentile(values: Sequence[float], quantile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    idx = min(len(ordered) - 1, int(quantile * (len(ordered) - 1)))
    return ordered[idx]


def _min_metric(rows: Sequence[MetricRow], metric: str) -> float | None:
    values = [_as_float(row.get(metric)) for row in rows]
    values = [value for value in values if value is not None]
    return min(values) if values else None


def _max_metric(rows: Sequence[MetricRow], metric: str) -> float | None:
    values = [_as_float(row.get(metric)) for row in rows]
    values = [value for value in values if value is not None]
    return max(values) if values else None


def _e_b1_run_key_from_params(
    *,
    n_parties: int,
    seed: int,
    push_suppression: float,
    gossip_suppression: float,
    log_suppression: float,
    ttl: float,
    max_time: float,
    push_delay: float,
    gossip_delay: float,
    gossip_interval: float,
    poll_interval: float,
    log_append_delay: float,
    jitter: float,
    gossip_fanout: int | None,
) -> str:
    return "|".join(
        (
            "E-B1",
            "hybrid",
            str(n_parties),
            str(seed),
            f"{push_suppression:.6g}",
            f"{gossip_suppression:.6g}",
            f"{log_suppression:.6g}",
            f"{ttl:.6g}",
            f"{max_time:.6g}",
            f"{push_delay:.6g}",
            f"{gossip_delay:.6g}",
            f"{gossip_interval:.6g}",
            f"{poll_interval:.6g}",
            f"{log_append_delay:.6g}",
            f"{jitter:.6g}",
            str(gossip_fanout),
        )
    )


def _as_float(value: object) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return float(value)
    try:
        text = str(value)
        if not text:
            return None
        return float(text)
    except ValueError:
        return None


def _coerce_number(value: object) -> int | float | object:
    numeric = _as_float(value)
    if numeric is None:
        return value
    if numeric.is_integer():
        return int(numeric)
    return numeric


def _sub(left: object, right: object) -> float | None:
    left_float = _as_float(left)
    right_float = _as_float(right)
    if left_float is None or right_float is None:
        return None
    return left_float - right_float


def _ratio(numerator: object, denominator: object) -> float | None:
    numerator_float = _as_float(numerator)
    denominator_float = _as_float(denominator)
    if numerator_float is None or denominator_float in {None, 0.0}:
        return None
    return numerator_float / denominator_float


def _fmt(value: object, places: int) -> str:
    numeric = _as_float(value)
    if numeric is None:
        return ""
    if places <= 0:
        return str(int(round(numeric)))
    return f"{numeric:.{places}f}"
