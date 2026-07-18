"""Preregistered P0 strongest-mechanism matched-baseline experiment (E-B17).

The module implements disclosed mechanism-level models over common random
traces.  It does not claim source compatibility with the referenced protocols.
The frozen design and verdict rule live in
``protocols/e-b17-p0-matched-baselines/protocol.md``.
"""

from __future__ import annotations

import csv
import hashlib
import json
import math
import random
import statistics
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence


MetricRow = dict[str, object]

P0_MECHANISMS: tuple[str, ...] = (
    "aip-03",
    "drp-10-60",
    "drp-10-300",
    "hbhc",
    "caep-ssf",
    "status-list",
    "ttl-cache",
    "sync-fail-open",
    "sync-fail-closed",
    "revprop",
)
P0_PROFILES: tuple[str, ...] = ("recommended", "matched")
P0_FAULT_SCENARIOS: tuple[str, ...] = ("none", "selective-operator", "correlated-all")
P0_SUPPRESSION_VALUES: tuple[float, ...] = (0.0, 0.2, 0.5)

CONFIRMATORY_PROFILE = "matched"
CONFIRMATORY_FAULT = "selective-operator"
CONFIRMATORY_SUPPRESSION = (0.2, 0.5)
MESSAGE_BUDGET = 8.1
BYTE_BUDGET = 8192.0
AVAILABILITY_BUDGET = 0.01
COMPLETENESS_FLOOR = 0.99
AUDIT_FLOOR = 0.99


@dataclass(frozen=True)
class GatewayTrace:
    gateway_id: int
    suppression_rank: float
    direct_phase: float
    log_phase: float
    gossip_phase: float
    heartbeat_phase: float
    request_phase: float


@dataclass(frozen=True)
class MechanismOutcome:
    event_time: float | None
    enforcement_time: float
    signed_event: bool
    audit_evidence: bool
    independent_repair: bool
    availability_denied_calls: int


def run_e_b17_p0_matched_baselines(
    *,
    seeds: Iterable[int] = (0, 1, 2),
    n_gateways_values: Sequence[int] = (40,),
    profiles: Sequence[str] = P0_PROFILES,
    fault_scenarios: Sequence[str] = P0_FAULT_SCENARIOS,
    suppression_values: Sequence[float] = P0_SUPPRESSION_VALUES,
    mechanisms: Sequence[str] = P0_MECHANISMS,
    horizon: float = 60.0,
    tool_call_rate: float = 10.0,
    ttl: float = 60.0,
) -> list[MetricRow]:
    """Run E-B17 over paired traces and return one row per mechanism/cell/seed."""

    _validate_choices(profiles, P0_PROFILES, "profiles")
    _validate_choices(fault_scenarios, P0_FAULT_SCENARIOS, "fault scenarios")
    _validate_choices(mechanisms, P0_MECHANISMS, "mechanisms")
    if horizon <= 0 or tool_call_rate <= 0 or ttl <= 0:
        raise ValueError("horizon, tool_call_rate, and ttl must be positive")

    rows: list[MetricRow] = []
    for seed in seeds:
        for n_gateways in n_gateways_values:
            traces = _paired_gateway_traces(int(seed), int(n_gateways))
            for profile in profiles:
                for fault_scenario in fault_scenarios:
                    for suppression in suppression_values:
                        suppression = float(suppression)
                        if fault_scenario == "none" and suppression != 0.0:
                            continue
                        if fault_scenario != "none" and suppression == 0.0:
                            continue
                        for mechanism in mechanisms:
                            rows.append(
                                _run_trial(
                                    mechanism,
                                    traces=traces,
                                    seed=int(seed),
                                    profile=str(profile),
                                    fault_scenario=str(fault_scenario),
                                    suppression=suppression,
                                    horizon=float(horizon),
                                    tool_call_rate=float(tool_call_rate),
                                    ttl=float(ttl),
                                )
                            )
    return rows


def _paired_gateway_traces(seed: int, n_gateways: int) -> tuple[GatewayTrace, ...]:
    if n_gateways <= 0:
        raise ValueError("n_gateways must be positive")
    rng = random.Random(seed * 1_000_003 + n_gateways * 97)
    suppression_scores = [rng.random() for _ in range(n_gateways)]
    ordered = sorted(range(n_gateways), key=lambda index: suppression_scores[index])
    exact_ranks = {index: (rank + 0.5) / n_gateways for rank, index in enumerate(ordered)}
    return tuple(
        GatewayTrace(
            gateway_id=index,
            suppression_rank=exact_ranks[index],
            direct_phase=rng.random(),
            log_phase=rng.random(),
            gossip_phase=rng.random(),
            heartbeat_phase=rng.random(),
            request_phase=rng.random(),
        )
        for index in range(n_gateways)
    )


def _run_trial(
    mechanism: str,
    *,
    traces: Sequence[GatewayTrace],
    seed: int,
    profile: str,
    fault_scenario: str,
    suppression: float,
    horizon: float,
    tool_call_rate: float,
    ttl: float,
) -> MetricRow:
    outcomes: list[MechanismOutcome] = []
    stale_calls = 0
    total_benign_calls = 0
    for trace in traces:
        targeted = trace.suppression_rank < suppression
        outcome = _mechanism_outcome(
            mechanism,
            trace=trace,
            profile=profile,
            fault_scenario=fault_scenario,
            targeted=targeted,
            horizon=horizon,
            ttl=ttl,
            tool_call_rate=tool_call_rate,
        )
        outcomes.append(outcome)
        stale_calls += _calls_before(
            outcome.enforcement_time,
            request_phase=trace.request_phase,
            rate=tool_call_rate,
            horizon=horizon,
        )
        total_benign_calls += _calls_before(
            horizon,
            request_phase=trace.request_phase,
            rate=tool_call_rate,
            horizon=horizon,
        )

    n_gateways = len(traces)
    event_times = [outcome.event_time for outcome in outcomes]
    censored_event_times = [horizon if value is None else min(value, horizon) for value in event_times]
    enforcement_times = [min(outcome.enforcement_time, horizon) for outcome in outcomes]
    explicit_count = sum(value is not None and value <= horizon for value in event_times)
    enforcement_count = sum(outcome.enforcement_time <= horizon for outcome in outcomes)
    signed_count = sum(outcome.signed_event and outcome.event_time is not None for outcome in outcomes)
    audit_count = sum(outcome.audit_evidence and outcome.event_time is not None for outcome in outcomes)
    independent_count = sum(outcome.independent_repair for outcome in outcomes)
    denied_benign_calls = sum(outcome.availability_denied_calls for outcome in outcomes)
    costs = _mechanism_costs(
        mechanism,
        profile=profile,
        fault_scenario=fault_scenario,
        suppression=suppression,
        horizon=horizon,
        tool_call_rate=tool_call_rate,
        n_gateways=n_gateways,
    )
    parameterization = _parameterization(mechanism, profile)

    return {
        "experiment": "E-B17",
        "run_id": (
            f"e-b17-{profile}-{fault_scenario}-drop-{suppression:.2f}-"
            f"{mechanism}-seed-{seed}-n-{n_gateways}"
        ),
        "run_key": (
            f"E-B17:{profile}:{fault_scenario}:{suppression:.2f}:"
            f"{mechanism}:{seed}:{n_gateways}"
        ),
        "seed": seed,
        "n_gateways": n_gateways,
        "n_parties": n_gateways,
        "mechanism": mechanism,
        "strategy": mechanism,
        "mechanism_family": _mechanism_family(mechanism),
        "profile": profile,
        "fault_scenario": fault_scenario,
        "suppression_fraction": suppression,
        "horizon": horizon,
        "ttl": ttl,
        "tool_call_rate": tool_call_rate,
        "confirmatory_cell_numeric": float(
            profile == CONFIRMATORY_PROFILE
            and fault_scenario == CONFIRMATORY_FAULT
            and suppression in CONFIRMATORY_SUPPRESSION
        ),
        "parameterization": json.dumps(parameterization, sort_keys=True, separators=(",", ":")),
        "rescaled_numeric": float(profile == "matched" and mechanism not in {"hbhc", "caep-ssf", "ttl-cache"}),
        "explicit_event_completeness": explicit_count / n_gateways,
        "enforcement_completeness": enforcement_count / n_gateways,
        "signed_event_rate": signed_count / n_gateways,
        "audit_evidence_rate": audit_count / n_gateways,
        "independent_repair_rate": independent_count / n_gateways,
        "event_p50_censored": _percentile(censored_event_times, 0.50),
        "event_p95_censored": _percentile(censored_event_times, 0.95),
        "event_p99_censored": _percentile(censored_event_times, 0.99),
        "enforcement_p50": _percentile(enforcement_times, 0.50),
        "enforcement_p95": _percentile(enforcement_times, 0.95),
        "enforcement_p99": _percentile(enforcement_times, 0.99),
        "stale_window_max": max(enforcement_times),
        "stale_tool_calls": stale_calls,
        "stale_tool_calls_per_gateway": stale_calls / n_gateways,
        "availability_denied_calls": denied_benign_calls,
        "availability_loss_rate": denied_benign_calls / total_benign_calls if total_benign_calls else 0.0,
        "control_messages_total": costs["messages_per_gateway"] * n_gateways,
        "control_messages_per_gateway": costs["messages_per_gateway"],
        "control_bytes_total": costs["bytes_per_gateway"] * n_gateways,
        "control_bytes_per_gateway": costs["bytes_per_gateway"],
        "message_budget": MESSAGE_BUDGET,
        "byte_budget": BYTE_BUDGET,
        "availability_budget": AVAILABILITY_BUDGET,
        "message_budget_pass_numeric": float(costs["messages_per_gateway"] <= MESSAGE_BUDGET),
        "byte_budget_pass_numeric": float(costs["bytes_per_gateway"] <= BYTE_BUDGET),
        "availability_budget_pass_numeric": float(
            denied_benign_calls / total_benign_calls <= AVAILABILITY_BUDGET if total_benign_calls else True
        ),
        "model_scope": "preregistered-mechanism-level-common-trace-simulation",
    }


def _mechanism_outcome(
    mechanism: str,
    *,
    trace: GatewayTrace,
    profile: str,
    fault_scenario: str,
    targeted: bool,
    horizon: float,
    ttl: float,
    tool_call_rate: float,
) -> MechanismOutcome:
    operator_blocked = targeted and fault_scenario in {"selective-operator", "correlated-all"}
    independent_blocked = targeted and fault_scenario == "correlated-all"
    peer_blocked = targeted and fault_scenario == "correlated-all"
    event_time: float | None = None
    signed_event = False
    audit_evidence = False
    independent_repair = False
    availability_denied_calls = 0

    if mechanism == "aip-03":
        first_attempt = 5.0 * trace.direct_phase
        if not operator_blocked:
            event_time = first_attempt
            signed_event = True
        enforcement_time = event_time if event_time is not None else ttl

    elif mechanism in {"drp-10-60", "drp-10-300"}:
        interval = _parameterization(mechanism, profile)["poll_interval"]
        candidate = 0.05 + float(interval) * trace.log_phase
        if not independent_blocked and candidate <= horizon:
            event_time = candidate
            signed_event = True
            audit_evidence = True
            independent_repair = operator_blocked
        enforcement_time = event_time if event_time is not None else ttl

    elif mechanism == "hbhc":
        params = _parameterization(mechanism, profile)
        enforcement_time = float(params["max_age"]) + float(params["heartbeat_interval"]) * trace.heartbeat_phase
        if targeted and fault_scenario == "correlated-all":
            availability_denied_calls = _calls_between(
                enforcement_time,
                horizon,
                request_phase=trace.request_phase,
                rate=tool_call_rate,
                horizon=horizon,
            )

    elif mechanism == "caep-ssf":
        if not operator_blocked:
            event_time = 0.02 + 0.03 * trace.direct_phase
            signed_event = True
        enforcement_time = event_time if event_time is not None else ttl

    elif mechanism == "status-list":
        interval = float(_parameterization(mechanism, profile)["poll_interval"])
        candidate = interval * trace.log_phase
        if not operator_blocked and candidate <= horizon:
            event_time = candidate
            signed_event = True
        enforcement_time = event_time if event_time is not None else ttl

    elif mechanism == "ttl-cache":
        enforcement_time = ttl

    elif mechanism == "sync-fail-open":
        enforcement_time = horizon if operator_blocked else 0.04 + 0.02 * trace.direct_phase

    elif mechanism == "sync-fail-closed":
        enforcement_time = 0.04 + 0.02 * trace.direct_phase
        if operator_blocked:
            availability_denied_calls = _calls_before(
                horizon,
                request_phase=trace.request_phase,
                rate=tool_call_rate,
                horizon=horizon,
            )

    elif mechanism == "revprop":
        if not operator_blocked:
            event_time = 0.02 + 0.03 * trace.direct_phase
            signed_event = True
            audit_evidence = True
        else:
            params = _parameterization(mechanism, profile)
            candidates: list[float] = []
            if not independent_blocked:
                candidates.append(float(params["log_append_delay"]) + float(params["poll_interval"]) * trace.log_phase)
            if not peer_blocked:
                candidates.append(0.10 + 0.40 * trace.gossip_phase)
            if candidates:
                candidate = min(candidates)
                if candidate <= horizon:
                    event_time = candidate
                    signed_event = True
                    audit_evidence = True
                    independent_repair = True
        enforcement_time = event_time if event_time is not None else ttl

    else:  # pragma: no cover - guarded by public validation
        raise ValueError(f"unsupported mechanism: {mechanism}")

    return MechanismOutcome(
        event_time=event_time,
        enforcement_time=float(enforcement_time),
        signed_event=signed_event,
        audit_evidence=audit_evidence,
        independent_repair=independent_repair,
        availability_denied_calls=availability_denied_calls,
    )


def _mechanism_costs(
    mechanism: str,
    *,
    profile: str,
    fault_scenario: str,
    suppression: float,
    horizon: float,
    tool_call_rate: float,
    n_gateways: int,
) -> dict[str, float]:
    targeted = suppression if fault_scenario != "none" else 0.0
    params = _parameterization(mechanism, profile)
    append_share = 1.0 / n_gateways

    if mechanism == "aip-03":
        attempts = (1.0 - targeted) + 4.0 * targeted
        fallback_polls = targeted * horizon / float(params["fallback_poll_interval"])
        return {
            "messages_per_gateway": attempts + fallback_polls,
            "bytes_per_gateway": attempts * 1200.0 + fallback_polls * 512.0,
        }
    if mechanism in {"drp-10-60", "drp-10-300"}:
        polls = horizon / float(params["poll_interval"])
        return {
            "messages_per_gateway": polls + append_share,
            "bytes_per_gateway": polls * 512.0 + append_share * 1200.0,
        }
    if mechanism == "hbhc":
        base = horizon / float(params["heartbeat_interval"])
        peer_repair = targeted * float(params["gossip_fanout"]) * base if fault_scenario == "selective-operator" else 0.0
        messages = base + peer_repair
        return {"messages_per_gateway": messages, "bytes_per_gateway": messages * 168.0}
    if mechanism == "caep-ssf":
        return {"messages_per_gateway": 1.0, "bytes_per_gateway": 1200.0}
    if mechanism == "status-list":
        polls = horizon / float(params["poll_interval"])
        return {"messages_per_gateway": polls, "bytes_per_gateway": polls * 125_000.0}
    if mechanism == "ttl-cache":
        return {"messages_per_gateway": 0.0, "bytes_per_gateway": 0.0}
    if mechanism in {"sync-fail-open", "sync-fail-closed"}:
        queries = horizon * tool_call_rate
        return {"messages_per_gateway": queries, "bytes_per_gateway": queries * 512.0}
    if mechanism == "revprop":
        polls = horizon / float(params["poll_interval"])
        gossip = targeted * float(params["gossip_fanout"]) if fault_scenario == "selective-operator" else 0.0
        messages = 1.0 + polls + gossip + append_share
        byte_cost = 1200.0 + polls * 256.0 + gossip * 1200.0 + append_share * 1200.0
        return {"messages_per_gateway": messages, "bytes_per_gateway": byte_cost}
    raise ValueError(f"unsupported mechanism: {mechanism}")


def _parameterization(mechanism: str, profile: str) -> dict[str, float | int | str]:
    if mechanism == "aip-03":
        return {
            "first_attempt_ceiling": 5.0,
            "retry_1": 1.0,
            "retry_2": 2.0,
            "retry_3": 4.0,
            "fallback_poll_interval": 10.0 if profile == "matched" else 60.0,
            "source": "draft-singla-agent-identity-protocol-03; fallback period is an artifact setting",
        }
    if mechanism in {"drp-10-60", "drp-10-300"}:
        recommended = 60.0 if mechanism.endswith("60") else 300.0
        return {
            "poll_interval": 10.0 if profile == "matched" else recommended,
            "recommended_poll_interval": recommended,
            "source": "draft-nelson-agent-delegation-receipts-10",
        }
    if mechanism == "hbhc":
        return {
            "heartbeat_interval": 10.0,
            "max_age": 30.0,
            "gossip_fanout": 5,
            "source": "arXiv:2605.20704 default and connected-overlay threshold",
        }
    if mechanism == "caep-ssf":
        return {
            "stream_delay": 0.05,
            "source": "OpenID CAEP/SSF draft 04; delay is an artifact setting, not a normative SLA",
        }
    if mechanism == "status-list":
        return {
            "poll_interval": 10.0 if profile == "matched" else 60.0,
            "universe_entries": 1_000_000,
            "source": "signed snapshot/status-list mechanism model",
        }
    if mechanism == "ttl-cache":
        return {"ttl": 60.0, "source": "local expiry baseline"}
    if mechanism in {"sync-fail-open", "sync-fail-closed"}:
        return {"status_latency": 0.05, "source": "request-time status policy baseline"}
    if mechanism == "revprop":
        return {
            "push_delay": 0.05,
            "gossip_interval": 0.25,
            "gossip_fanout": 5,
            "poll_interval": 10.0 if profile == "matched" else 0.5,
            "log_append_delay": 0.05,
            "source": "RevProp artifact configuration",
        }
    raise ValueError(f"unsupported mechanism: {mechanism}")


def analyze_e_b17(
    rows: Sequence[MetricRow],
    *,
    bootstrap_samples: int = 10_000,
) -> dict[str, object]:
    """Apply the frozen E-B17 feasibility, bootstrap, Holm, and Pareto rules."""

    if bootstrap_samples < 100:
        raise ValueError("bootstrap_samples must be at least 100")
    aggregates = aggregate_e_b17(rows)
    aggregate_lookup = {
        _cell_key(row, include_mechanism=True): row
        for row in aggregates
    }
    raw_lookup: dict[tuple[object, ...], dict[int, MetricRow]] = {}
    for row in rows:
        raw_lookup.setdefault(_cell_key(row, include_mechanism=True), {})[int(row["seed"])] = row

    comparisons: list[dict[str, object]] = []
    cells: list[dict[str, object]] = []
    for suppression in CONFIRMATORY_SUPPRESSION:
        cell_aggregates = [
            row
            for row in aggregates
            if row.get("profile") == CONFIRMATORY_PROFILE
            and row.get("fault_scenario") == CONFIRMATORY_FAULT
            and math.isclose(float(row.get("suppression_fraction", -1.0)), suppression)
        ]
        for n_gateways in sorted({int(row["n_gateways"]) for row in cell_aggregates}):
            mechanism_rows = [row for row in cell_aggregates if int(row["n_gateways"]) == n_gateways]
            feasibility = {
                str(row["mechanism"]): _feasibility(row)
                for row in mechanism_rows
            }
            feasible_baselines = sorted(
                mechanism
                for mechanism, passed in feasibility.items()
                if mechanism != "revprop" and passed
            )
            frontier = _pareto_frontier(mechanism_rows)
            rev_key = (
                CONFIRMATORY_PROFILE,
                CONFIRMATORY_FAULT,
                suppression,
                n_gateways,
                "revprop",
            )
            rev_rows = raw_lookup.get(rev_key, {})
            cell_comparisons: list[dict[str, object]] = []
            for baseline in feasible_baselines:
                base_key = (
                    CONFIRMATORY_PROFILE,
                    CONFIRMATORY_FAULT,
                    suppression,
                    n_gateways,
                    baseline,
                )
                baseline_rows = raw_lookup.get(base_key, {})
                paired_seeds = sorted(set(rev_rows) & set(baseline_rows))
                diffs = [
                    float(rev_rows[seed]["stale_tool_calls_per_gateway"])
                    - float(baseline_rows[seed]["stale_tool_calls_per_gateway"])
                    for seed in paired_seeds
                ]
                comparison = _paired_bootstrap(
                    diffs,
                    baseline_mean=statistics.fmean(
                        float(baseline_rows[seed]["stale_tool_calls_per_gateway"])
                        for seed in paired_seeds
                    ) if paired_seeds else math.nan,
                    samples=bootstrap_samples,
                    seed=_stable_seed(f"{suppression}:{n_gateways}:{baseline}"),
                )
                comparison.update(
                    {
                        "profile": CONFIRMATORY_PROFILE,
                        "fault_scenario": CONFIRMATORY_FAULT,
                        "suppression_fraction": suppression,
                        "n_gateways": n_gateways,
                        "baseline": baseline,
                        "paired_seeds": len(paired_seeds),
                    }
                )
                comparisons.append(comparison)
                cell_comparisons.append(comparison)

            cells.append(
                {
                    "profile": CONFIRMATORY_PROFILE,
                    "fault_scenario": CONFIRMATORY_FAULT,
                    "suppression_fraction": suppression,
                    "n_gateways": n_gateways,
                    "feasibility": feasibility,
                    "feasible_baselines": feasible_baselines,
                    "pareto_frontier": frontier,
                    "revprop_feasible": feasibility.get("revprop", False),
                    "revprop_on_frontier": "revprop" in frontier,
                    "comparison_refs": cell_comparisons,
                }
            )

    _holm_adjust(comparisons)
    for cell in cells:
        cell_comparisons = cell.pop("comparison_refs")
        comparison_pass = bool(cell_comparisons) and all(
            int(comparison["paired_seeds"]) == 30
            and float(comparison["ci95_high"]) < 0.0
            and float(comparison["holm_adjusted_p"]) < 0.05
            and float(comparison["relative_reduction"]) >= 0.20
            for comparison in cell_comparisons
        )
        cell["comparison_count"] = len(cell_comparisons)
        cell["statistics_pass"] = comparison_pass
        cell["e_b17_cell_pass"] = bool(
            cell["revprop_feasible"]
            and cell["feasible_baselines"]
            and cell["revprop_on_frontier"]
            and comparison_pass
        )

    complete_seed_counts = [int(comparison["paired_seeds"]) for comparison in comparisons]
    if not cells or not comparisons or any(count < 30 for count in complete_seed_counts):
        verdict = "INCONCLUSIVE"
    elif any(bool(cell["e_b17_cell_pass"]) for cell in cells):
        verdict = "E_B17_CONSTRAINED_ADVANTAGE"
    else:
        verdict = "NO_MATCHED_ADVANTAGE_PIVOT"

    return {
        "experiment": "E-B17",
        "protocol_version": "e-b17-prereg-v1",
        "raw_rows": len(rows),
        "aggregate_rows": len(aggregates),
        "bootstrap_samples": bootstrap_samples,
        "multiple_comparison_correction": "Holm FWER over all confirmatory cell-by-baseline tests",
        "right_censoring": "non-delivery encoded at 60-second horizon",
        "confirmatory_cells": cells,
        "comparisons": comparisons,
        "e_b17_verdict": verdict,
        "final_verdict_note": (
            "E-B17 alone cannot produce SUPPORTED_CONSTRAINED_ADVANTAGE; "
            "the preregistration additionally requires E-B18, P0-3, and P0-5 gates."
        ),
    }


def aggregate_e_b17(rows: Sequence[MetricRow]) -> list[MetricRow]:
    group_fields = (
        "experiment",
        "mechanism",
        "mechanism_family",
        "profile",
        "fault_scenario",
        "suppression_fraction",
        "n_gateways",
        "horizon",
        "tool_call_rate",
    )
    metrics = (
        "explicit_event_completeness",
        "enforcement_completeness",
        "signed_event_rate",
        "audit_evidence_rate",
        "independent_repair_rate",
        "event_p99_censored",
        "enforcement_p99",
        "stale_window_max",
        "stale_tool_calls_per_gateway",
        "availability_loss_rate",
        "control_messages_per_gateway",
        "control_bytes_per_gateway",
    )
    groups: dict[tuple[object, ...], list[MetricRow]] = {}
    for row in rows:
        groups.setdefault(tuple(row.get(field) for field in group_fields), []).append(row)
    aggregates: list[MetricRow] = []
    for key, group in sorted(groups.items(), key=lambda item: tuple(str(value) for value in item[0])):
        aggregate: MetricRow = dict(zip(group_fields, key, strict=True))
        aggregate["runs"] = len(group)
        for metric in metrics:
            values = [float(row[metric]) for row in group]
            mean = statistics.fmean(values)
            aggregate[f"{metric}_mean"] = mean
            aggregate[f"{metric}_min"] = min(values)
            aggregate[f"{metric}_max"] = max(values)
            if len(values) > 1:
                stdev = statistics.stdev(values)
                aggregate[f"{metric}_stdev"] = stdev
                aggregate[f"{metric}_ci95"] = 1.96 * stdev / math.sqrt(len(values))
            else:
                aggregate[f"{metric}_stdev"] = 0.0
                aggregate[f"{metric}_ci95"] = 0.0
        aggregate["feasible_numeric"] = float(_feasibility(aggregate))
        aggregates.append(aggregate)
    return aggregates


def write_e_b17_outputs(
    rows: Sequence[MetricRow],
    output_dir: str | Path,
    *,
    run_config: dict[str, object] | None = None,
    bootstrap_samples: int = 10_000,
) -> None:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    aggregates = aggregate_e_b17(rows)
    summary = analyze_e_b17(rows, bootstrap_samples=bootstrap_samples)
    summary["run_config"] = run_config or {}
    _write_csv(rows, output_path / "e_b17_p0_matched_baselines.csv")
    _write_csv(aggregates, output_path / "e_b17_aggregate.csv")
    (output_path / "e_b17_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    (output_path / "e_b17_decision.json").write_text(
        json.dumps(
            {
                "protocol_version": summary["protocol_version"],
                "e_b17_verdict": summary["e_b17_verdict"],
                "confirmatory_cells": summary["confirmatory_cells"],
                "comparisons": summary["comparisons"],
                "external_gates_required": ["P0-3", "E-B18", "P0-5"],
            },
            indent=2,
            sort_keys=True,
        ) + "\n"
    )
    (output_path / "e_b17_report.md").write_text(render_e_b17_report(summary, aggregates) + "\n")


def render_e_b17_report(summary: dict[str, object], aggregates: Sequence[MetricRow]) -> str:
    lines = [
        "# E-B17 P0 Matched Strongest-Mechanism Report",
        "",
        "## Material Passport",
        "",
        "- Origin Skill: academic-research-suite / experiment-agent",
        "- Origin Mode: run + validate",
        "- Verification Status: ANALYZED",
        "- Version Label: e-b17-prereg-v1",
        "",
        f"- Raw rows: {summary['raw_rows']}",
        f"- Aggregate rows: {summary['aggregate_rows']}",
        f"- E-B17 verdict: **{summary['e_b17_verdict']}**",
        "",
        "## Confirmatory Cells",
        "",
        "| drop | n | feasible baselines | RevProp feasible | frontier | statistics | cell pass |",
        "|---:|---:|---|---:|---:|---:|---:|",
    ]
    for cell in summary["confirmatory_cells"]:  # type: ignore[index]
        assert isinstance(cell, dict)
        lines.append(
            "| {drop:.2f} | {n} | {baselines} | {feasible} | {frontier} | {stats} | {passed} |".format(
                drop=float(cell["suppression_fraction"]),
                n=cell["n_gateways"],
                baselines=", ".join(cell["feasible_baselines"]),
                feasible=int(bool(cell["revprop_feasible"])),
                frontier=int(bool(cell["revprop_on_frontier"])),
                stats=int(bool(cell["statistics_pass"])),
                passed=int(bool(cell["e_b17_cell_pass"])),
            )
        )
    lines.extend(
        [
            "",
            "## Paired Confirmatory Comparisons",
            "",
            "| drop | baseline | seeds | mean diff | 95% CI | relative reduction | superiority | Holm p |",
            "|---:|---|---:|---:|---|---:|---:|---:|",
        ]
    )
    for comparison in summary["comparisons"]:  # type: ignore[index]
        assert isinstance(comparison, dict)
        lines.append(
            "| {drop:.2f} | {baseline} | {seeds} | {diff:.4f} | [{low:.4f}, {high:.4f}] | {relative:.3f} | {superiority:.3f} | {p:.6f} |".format(
                drop=float(comparison["suppression_fraction"]),
                baseline=comparison["baseline"],
                seeds=comparison["paired_seeds"],
                diff=float(comparison["mean_difference"]),
                low=float(comparison["ci95_low"]),
                high=float(comparison["ci95_high"]),
                relative=float(comparison["relative_reduction"]),
                superiority=float(comparison["probability_revprop_better"]),
                p=float(comparison["holm_adjusted_p"]),
            )
        )
    lines.extend(
        [
            "",
            "## Matched-Profile Aggregate Surface",
            "",
            "| fault | drop | mechanism | explicit | audit | stale calls/gw | availability loss | messages/gw | bytes/gw | feasible |",
            "|---|---:|---|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    matched = [row for row in aggregates if row.get("profile") == "matched"]
    for row in sorted(
        matched,
        key=lambda value: (
            str(value["fault_scenario"]),
            float(value["suppression_fraction"]),
            str(value["mechanism"]),
        ),
    ):
        lines.append(
            "| {fault} | {drop:.2f} | {mechanism} | {explicit:.4f} | {audit:.4f} | {stale:.3f} | {availability:.4f} | {messages:.3f} | {bytes:.1f} | {feasible:.0f} |".format(
                fault=row["fault_scenario"],
                drop=float(row["suppression_fraction"]),
                mechanism=row["mechanism"],
                explicit=float(row["explicit_event_completeness_mean"]),
                audit=float(row["audit_evidence_rate_mean"]),
                stale=float(row["stale_tool_calls_per_gateway_mean"]),
                availability=float(row["availability_loss_rate_mean"]),
                messages=float(row["control_messages_per_gateway_mean"]),
                bytes=float(row["control_bytes_per_gateway_mean"]),
                feasible=float(row["feasible_numeric"]),
            )
        )
    lines.extend(
        [
            "",
            "## Scope",
            "",
            "E-B17 is a preregistered common-trace mechanism simulation. It does not establish production interoperability or mechanism novelty. The final RevProp verdict additionally requires P0-3, E-B18, and P0-5.",
        ]
    )
    return "\n".join(lines)


def _paired_bootstrap(
    diffs: Sequence[float],
    *,
    baseline_mean: float,
    samples: int,
    seed: int,
) -> dict[str, object]:
    if not diffs:
        return {
            "mean_difference": math.nan,
            "ci95_low": math.nan,
            "ci95_high": math.nan,
            "bootstrap_p": math.nan,
            "relative_reduction": math.nan,
            "probability_revprop_better": math.nan,
        }
    rng = random.Random(seed)
    n = len(diffs)
    bootstrap_means = [
        statistics.fmean(diffs[rng.randrange(n)] for _ in range(n))
        for _ in range(samples)
    ]
    lower_or_equal = sum(value <= 0.0 for value in bootstrap_means)
    greater_or_equal = sum(value >= 0.0 for value in bootstrap_means)
    tail = min((lower_or_equal + 1) / (samples + 1), (greater_or_equal + 1) / (samples + 1))
    p_value = min(1.0, 2.0 * tail)
    mean_difference = statistics.fmean(diffs)
    return {
        "mean_difference": mean_difference,
        "ci95_low": _percentile(bootstrap_means, 0.025),
        "ci95_high": _percentile(bootstrap_means, 0.975),
        "bootstrap_p": p_value,
        "relative_reduction": -mean_difference / baseline_mean if baseline_mean > 0 else 0.0,
        "probability_revprop_better": (
            sum(value < 0 for value in diffs) + 0.5 * sum(value == 0 for value in diffs)
        ) / n,
    }


def _holm_adjust(comparisons: Sequence[dict[str, object]]) -> None:
    ordered = sorted(enumerate(comparisons), key=lambda item: float(item[1]["bootstrap_p"]))
    running = 0.0
    total = len(ordered)
    for rank, (_, comparison) in enumerate(ordered):
        adjusted = min(1.0, (total - rank) * float(comparison["bootstrap_p"]))
        running = max(running, adjusted)
        comparison["holm_adjusted_p"] = running


def _feasibility(row: MetricRow) -> bool:
    return bool(
        float(row.get("explicit_event_completeness_mean", row.get("explicit_event_completeness", 0.0)))
        >= COMPLETENESS_FLOOR
        and float(row.get("audit_evidence_rate_mean", row.get("audit_evidence_rate", 0.0))) >= AUDIT_FLOOR
        and float(row.get("availability_loss_rate_mean", row.get("availability_loss_rate", 1.0)))
        <= AVAILABILITY_BUDGET
        and float(row.get("control_messages_per_gateway_mean", row.get("control_messages_per_gateway", math.inf)))
        <= MESSAGE_BUDGET
        and float(row.get("control_bytes_per_gateway_mean", row.get("control_bytes_per_gateway", math.inf)))
        <= BYTE_BUDGET
    )


def _pareto_frontier(rows: Sequence[MetricRow]) -> list[str]:
    vectors: dict[str, tuple[float, ...]] = {}
    for row in rows:
        vectors[str(row["mechanism"])] = (
            -float(row["explicit_event_completeness_mean"]),
            float(row["stale_tool_calls_per_gateway_mean"]),
            float(row["availability_loss_rate_mean"]),
            -float(row["audit_evidence_rate_mean"]),
            float(row["control_messages_per_gateway_mean"]),
            float(row["control_bytes_per_gateway_mean"]),
        )
    frontier: list[str] = []
    for mechanism, vector in vectors.items():
        dominated = False
        for other, other_vector in vectors.items():
            if other == mechanism:
                continue
            no_worse = all(left <= right + 1e-12 for left, right in zip(other_vector, vector, strict=True))
            strictly_better = any(left < right - 1e-12 for left, right in zip(other_vector, vector, strict=True))
            if no_worse and strictly_better:
                dominated = True
                break
        if not dominated:
            frontier.append(mechanism)
    return sorted(frontier)


def _cell_key(row: MetricRow, *, include_mechanism: bool) -> tuple[object, ...]:
    values: list[object] = [
        row.get("profile"),
        row.get("fault_scenario"),
        float(row.get("suppression_fraction", 0.0)),
        int(row.get("n_gateways", 0)),
    ]
    if include_mechanism:
        values.append(row.get("mechanism"))
    return tuple(values)


def _calls_before(time_value: float, *, request_phase: float, rate: float, horizon: float) -> int:
    stop = min(max(time_value, 0.0), horizon)
    first = request_phase / rate
    if stop <= first:
        return 0
    return int(math.ceil((stop - first) * rate - 1e-12))


def _calls_between(
    start: float,
    stop: float,
    *,
    request_phase: float,
    rate: float,
    horizon: float,
) -> int:
    return max(
        0,
        _calls_before(stop, request_phase=request_phase, rate=rate, horizon=horizon)
        - _calls_before(start, request_phase=request_phase, rate=rate, horizon=horizon),
    )


def _percentile(values: Sequence[float], fraction: float) -> float:
    if not values:
        return math.nan
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return float(ordered[lower])
    weight = position - lower
    return float(ordered[lower] * (1.0 - weight) + ordered[upper] * weight)


def _stable_seed(value: str) -> int:
    return int.from_bytes(hashlib.sha256(value.encode()).digest()[:8], "big")


def _mechanism_family(mechanism: str) -> str:
    if mechanism.startswith("drp"):
        return "authoritative-log"
    if mechanism in {"aip-03", "caep-ssf"}:
        return "operator-event-delivery"
    if mechanism == "hbhc":
        return "implicit-heartbeat-expiry"
    if mechanism == "status-list":
        return "signed-status-snapshot"
    if mechanism == "ttl-cache":
        return "local-expiry"
    if mechanism.startswith("sync-"):
        return "request-time-status"
    return "multi-channel-positive-event"


def _validate_choices(values: Sequence[str], allowed: Sequence[str], label: str) -> None:
    unknown = sorted(set(values) - set(allowed))
    if unknown:
        raise ValueError(f"unknown {label}: {', '.join(unknown)}")


def _write_csv(rows: Sequence[MetricRow], path: Path) -> None:
    if not rows:
        path.write_text("")
        return
    fieldnames = sorted({key for row in rows for key in row})
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
