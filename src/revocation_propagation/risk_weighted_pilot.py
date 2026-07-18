"""E-B19 risk-weighted selective-omission pilot experiments.

The frozen exploratory protocol lives in
``protocols/e-b19-risk-weighted-pilots/protocol.md``.  The module intentionally
keeps the two pilot rounds separate so the Round-1 decision can be inspected
before interpreting the Round-2 policy result.
"""

from __future__ import annotations

import argparse
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

RISK_PROFILES: tuple[str, ...] = ("uniform", "zipf-rate", "zipf-correlated")
HEAVY_TAIL_PROFILES: tuple[str, ...] = ("zipf-rate", "zipf-correlated")
TARGET_POLICIES: tuple[str, ...] = ("random", "top-rate", "top-severity", "top-risk")
ROUND1_MECHANISMS: tuple[str, ...] = ("push-only", "log-poll", "push-repair")
ROUND2_POLICIES: tuple[str, ...] = ("uniform", "rate-aware", "risk-aware")
SUPPRESSION_VALUES: tuple[float, ...] = (0.10, 0.20, 0.30)

HORIZON = 60.0
POLL_INTERVAL = 10.0
GOSSIP_FANOUT = 5
MESSAGE_BUDGET = 8.1
BYTE_BUDGET = 8192.0


@dataclass(frozen=True)
class GatewayRiskTrace:
    gateway_id: int
    suppression_rank: float
    call_rate: float
    effect_severity: float
    direct_delay: float
    log_delay: float

    @property
    def risk(self) -> float:
        return self.call_rate * self.effect_severity


def run_round1_targeted_omission(
    *,
    seeds: Iterable[int] = range(30),
    n_gateways: int = 1000,
    risk_profiles: Sequence[str] = RISK_PROFILES,
    target_policies: Sequence[str] = TARGET_POLICIES,
    suppression_values: Sequence[float] = SUPPRESSION_VALUES,
    mechanisms: Sequence[str] = ROUND1_MECHANISMS,
) -> list[MetricRow]:
    """Run the Round-1 target-selection stress over paired traces."""

    _validate_choices(risk_profiles, RISK_PROFILES, "risk profiles")
    _validate_choices(target_policies, TARGET_POLICIES, "target policies")
    _validate_choices(mechanisms, ROUND1_MECHANISMS, "mechanisms")
    if n_gateways <= 0:
        raise ValueError("n_gateways must be positive")

    rows: list[MetricRow] = []
    for seed in seeds:
        for risk_profile in risk_profiles:
            traces = _gateway_traces(int(seed), n_gateways, risk_profile)
            for suppression in suppression_values:
                suppression = float(suppression)
                for target_policy in target_policies:
                    targets = _select_targets(traces, suppression, target_policy)
                    for mechanism in mechanisms:
                        rows.append(
                            _round1_trial(
                                traces,
                                seed=int(seed),
                                risk_profile=risk_profile,
                                target_policy=target_policy,
                                targets=targets,
                                suppression=suppression,
                                mechanism=mechanism,
                            )
                        )
    return rows


def run_round2_budgeted_repair(
    *,
    seeds: Iterable[int] = range(30),
    n_gateways: int = 1000,
    risk_profiles: Sequence[str] = HEAVY_TAIL_PROFILES,
    target_policies: Sequence[str] = ("random", "top-risk"),
    repair_policies: Sequence[str] = ROUND2_POLICIES,
    suppression: float = 0.20,
) -> list[MetricRow]:
    """Run equal-message-budget repair allocation policies."""

    _validate_choices(risk_profiles, HEAVY_TAIL_PROFILES, "Round-2 risk profiles")
    _validate_choices(target_policies, ("random", "top-risk"), "Round-2 target policies")
    _validate_choices(repair_policies, ROUND2_POLICIES, "repair policies")
    if n_gateways <= 0:
        raise ValueError("n_gateways must be positive")

    rows: list[MetricRow] = []
    for seed in seeds:
        for risk_profile in risk_profiles:
            traces = _gateway_traces(int(seed), n_gateways, risk_profile)
            for target_policy in target_policies:
                targets = _select_targets(traces, suppression, target_policy)
                for repair_policy in repair_policies:
                    allocations = _repair_allocations(traces, targets, repair_policy)
                    rows.append(
                        _round2_trial(
                            traces,
                            seed=int(seed),
                            risk_profile=risk_profile,
                            target_policy=target_policy,
                            targets=targets,
                            suppression=float(suppression),
                            repair_policy=repair_policy,
                            allocations=allocations,
                        )
                    )
    return rows


def analyze_round1(rows: Sequence[MetricRow], *, bootstrap_samples: int = 10_000) -> dict[str, object]:
    """Apply the frozen Round-1 amplification gate."""

    if bootstrap_samples < 100:
        raise ValueError("bootstrap_samples must be at least 100")
    aggregates = _aggregate(
        rows,
        group_fields=("experiment", "risk_profile", "target_policy", "suppression_fraction", "mechanism"),
    )
    raw = _index_by_seed(
        rows,
        key_fields=("risk_profile", "target_policy", "suppression_fraction", "mechanism"),
    )
    comparisons: list[dict[str, object]] = []
    for profile in HEAVY_TAIL_PROFILES:
        random_rows = raw[(profile, "random", 0.2, "push-repair")]
        top_rows = raw[(profile, "top-risk", 0.2, "push-repair")]
        seeds = sorted(set(random_rows) & set(top_rows))
        paired = [
            (
                float(top_rows[seed]["suppression_attributable_weighted_harm"]),
                float(random_rows[seed]["suppression_attributable_weighted_harm"]),
            )
            for seed in seeds
        ]
        top_mean = statistics.fmean(value[0] for value in paired)
        random_mean = statistics.fmean(value[1] for value in paired)
        diffs = [top - baseline for top, baseline in paired]
        bootstrap = _paired_bootstrap_difference(
            diffs,
            samples=bootstrap_samples,
            seed=_stable_seed(f"round1:{profile}"),
        )
        comparison: dict[str, object] = {
            "risk_profile": profile,
            "target_policy": "top-risk-vs-random",
            "suppression_fraction": 0.2,
            "mechanism": "push-repair",
            "paired_seeds": len(seeds),
            "top_risk_mean_harm": top_mean,
            "random_mean_harm": random_mean,
            "amplification": top_mean / random_mean if random_mean else math.inf,
            "mean_difference": bootstrap["mean_difference"],
            "ci95_low": bootstrap["ci95_low"],
            "ci95_high": bootstrap["ci95_high"],
            "sign_test_p": _exact_sign_test(diffs),
        }
        comparisons.append(comparison)
    _holm_adjust(comparisons, p_field="sign_test_p", output_field="holm_adjusted_p")
    for comparison in comparisons:
        comparison["profile_pass"] = bool(
            int(comparison["paired_seeds"]) == 30
            and float(comparison["amplification"]) >= 3.0
            and float(comparison["ci95_low"]) > 0.0
        )

    ranking_diagnostics = _round1_rankings(aggregates)
    gate_pass = len(comparisons) == 2 and all(bool(item["profile_pass"]) for item in comparisons)
    return {
        "experiment": "E-B19-R1",
        "protocol_version": "e-b19-pilot-prereg-v1",
        "raw_rows": len(rows),
        "aggregate_rows": len(aggregates),
        "bootstrap_samples": bootstrap_samples,
        "primary_comparisons": comparisons,
        "ranking_diagnostics": ranking_diagnostics,
        "round1_gate_pass": gate_pass,
        "round1_verdict": "TARGETED_RISK_AMPLIFICATION_SUPPORTED" if gate_pass else "TARGETED_RISK_AMPLIFICATION_NOT_SUPPORTED",
        "aggregates": aggregates,
    }


def analyze_round2(rows: Sequence[MetricRow], *, bootstrap_samples: int = 10_000) -> dict[str, object]:
    """Apply the frozen Round-2 equal-budget risk-aware gate."""

    if bootstrap_samples < 100:
        raise ValueError("bootstrap_samples must be at least 100")
    aggregates = _aggregate(
        rows,
        group_fields=("experiment", "risk_profile", "target_policy", "suppression_fraction", "repair_policy"),
    )
    raw = _index_by_seed(
        rows,
        key_fields=("risk_profile", "target_policy", "suppression_fraction", "repair_policy"),
    )
    diagnostics: list[dict[str, object]] = []
    for profile in HEAVY_TAIL_PROFILES:
        for target_policy in ("random", "top-risk"):
            uniform_rows = raw[(profile, target_policy, 0.2, "uniform")]
            for repair_policy in ("rate-aware", "risk-aware"):
                policy_rows = raw[(profile, target_policy, 0.2, repair_policy)]
                seeds = sorted(set(uniform_rows) & set(policy_rows))
                paired = [
                    (
                        float(policy_rows[seed]["weighted_stale_effects_total"]),
                        float(uniform_rows[seed]["weighted_stale_effects_total"]),
                    )
                    for seed in seeds
                ]
                policy_mean = statistics.fmean(value[0] for value in paired)
                uniform_mean = statistics.fmean(value[1] for value in paired)
                diffs = [policy - baseline for policy, baseline in paired]
                bootstrap = _paired_bootstrap_difference(
                    diffs,
                    samples=bootstrap_samples,
                    seed=_stable_seed(f"round2:{profile}:{target_policy}:{repair_policy}"),
                )
                diagnostics.append(
                    {
                        "risk_profile": profile,
                        "target_policy": target_policy,
                        "repair_policy": repair_policy,
                        "paired_seeds": len(seeds),
                        "policy_mean_harm": policy_mean,
                        "uniform_mean_harm": uniform_mean,
                        "relative_reduction": 1.0 - policy_mean / uniform_mean,
                        "mean_difference": bootstrap["mean_difference"],
                        "ci95_low": bootstrap["ci95_low"],
                        "ci95_high": bootstrap["ci95_high"],
                        "sign_test_p": _exact_sign_test(diffs),
                    }
                )

    primary = next(
        item
        for item in diagnostics
        if item["risk_profile"] == "zipf-correlated"
        and item["target_policy"] == "top-risk"
        and item["repair_policy"] == "risk-aware"
    )
    primary_uniform = raw[("zipf-correlated", "top-risk", 0.2, "uniform")]
    primary_policy = raw[("zipf-correlated", "top-risk", 0.2, "risk-aware")]
    paired_seeds = sorted(set(primary_uniform) & set(primary_policy))
    exact_cost_match = all(
        float(primary_uniform[seed]["control_messages_per_gateway"])
        == float(primary_policy[seed]["control_messages_per_gateway"])
        and float(primary_uniform[seed]["control_bytes_per_gateway"])
        == float(primary_policy[seed]["control_bytes_per_gateway"])
        for seed in paired_seeds
    )
    outcome_contract_match = all(
        float(row["explicit_event_completeness"]) == 1.0
        and float(row["audit_evidence_rate"]) == 1.0
        and float(row["availability_loss_rate"]) == 0.0
        for seed in paired_seeds
        for row in (primary_uniform[seed], primary_policy[seed])
    )
    gate_pass = bool(
        len(paired_seeds) == 30
        and float(primary["relative_reduction"]) >= 0.30
        and float(primary["ci95_high"]) < 0.0
        and exact_cost_match
        and outcome_contract_match
    )
    primary["exact_cost_match"] = exact_cost_match
    primary["outcome_contract_match"] = outcome_contract_match
    primary["primary_pass"] = gate_pass
    return {
        "experiment": "E-B19-R2",
        "protocol_version": "e-b19-pilot-prereg-v1",
        "raw_rows": len(rows),
        "aggregate_rows": len(aggregates),
        "bootstrap_samples": bootstrap_samples,
        "primary_comparison": primary,
        "diagnostic_comparisons": diagnostics,
        "round2_gate_pass": gate_pass,
        "round2_verdict": "EQUAL_BUDGET_RISK_AWARE_REPAIR_SUPPORTED" if gate_pass else "EQUAL_BUDGET_RISK_AWARE_REPAIR_NOT_SUPPORTED",
        "aggregates": aggregates,
    }


def write_round1_outputs(rows: Sequence[MetricRow], output_dir: str | Path, *, bootstrap_samples: int = 10_000) -> None:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    summary = analyze_round1(rows, bootstrap_samples=bootstrap_samples)
    aggregates = list(summary.pop("aggregates"))
    _write_csv(rows, output_path / "e_b19_round1_targeted_omission.csv")
    _write_csv(aggregates, output_path / "e_b19_round1_aggregate.csv")
    (output_path / "e_b19_round1_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n"
    )
    (output_path / "e_b19_round1_report.md").write_text(_round1_report(summary) + "\n")


def write_round2_outputs(rows: Sequence[MetricRow], output_dir: str | Path, *, bootstrap_samples: int = 10_000) -> None:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    summary = analyze_round2(rows, bootstrap_samples=bootstrap_samples)
    aggregates = list(summary.pop("aggregates"))
    _write_csv(rows, output_path / "e_b19_round2_budgeted_repair.csv")
    _write_csv(aggregates, output_path / "e_b19_round2_aggregate.csv")
    (output_path / "e_b19_round2_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n"
    )
    (output_path / "e_b19_round2_report.md").write_text(_round2_report(summary) + "\n")


def _gateway_traces(seed: int, n_gateways: int, risk_profile: str) -> tuple[GatewayRiskTrace, ...]:
    system_rng = random.Random(seed * 1_000_003 + n_gateways * 97 + 19)
    suppression_scores = [system_rng.random() for _ in range(n_gateways)]
    suppression_order = sorted(range(n_gateways), key=lambda index: suppression_scores[index])
    suppression_ranks = {index: (rank + 0.5) / n_gateways for rank, index in enumerate(suppression_order)}
    direct_delays = [0.02 + 0.03 * system_rng.random() for _ in range(n_gateways)]
    log_delays = [0.05 + POLL_INTERVAL * system_rng.random() for _ in range(n_gateways)]

    risk_order = list(range(n_gateways))
    risk_rng = random.Random(seed * 1_000_033 + n_gateways * 193 + 29)
    risk_rng.shuffle(risk_order)
    rank_for_gateway = {gateway_id: rank + 1 for rank, gateway_id in enumerate(risk_order)}

    if risk_profile == "uniform":
        rates = [10.0] * n_gateways
        severities = [1.0] * n_gateways
    elif risk_profile == "zipf-rate":
        raw_rates = [rank_for_gateway[index] ** -1.2 for index in range(n_gateways)]
        rates = _normalize_mean(raw_rates, 10.0)
        severities = [1.0] * n_gateways
    elif risk_profile == "zipf-correlated":
        raw_rates = [rank_for_gateway[index] ** -1.1 for index in range(n_gateways)]
        rates = _normalize_mean(raw_rates, 10.0)
        severities = _normalize_mean([rate**0.75 for rate in rates], 1.0)
    else:  # pragma: no cover - public validation guards this
        raise ValueError(f"unsupported risk profile: {risk_profile}")

    return tuple(
        GatewayRiskTrace(
            gateway_id=index,
            suppression_rank=suppression_ranks[index],
            call_rate=rates[index],
            effect_severity=severities[index],
            direct_delay=direct_delays[index],
            log_delay=log_delays[index],
        )
        for index in range(n_gateways)
    )


def _select_targets(
    traces: Sequence[GatewayRiskTrace],
    suppression: float,
    target_policy: str,
) -> frozenset[int]:
    count = int(round(len(traces) * suppression))
    if count <= 0:
        return frozenset()
    if target_policy == "random":
        ordered = sorted(traces, key=lambda trace: (trace.suppression_rank, trace.gateway_id))
    elif target_policy == "top-rate":
        ordered = sorted(traces, key=lambda trace: (-trace.call_rate, trace.gateway_id))
    elif target_policy == "top-severity":
        ordered = sorted(traces, key=lambda trace: (-trace.effect_severity, trace.gateway_id))
    elif target_policy == "top-risk":
        ordered = sorted(traces, key=lambda trace: (-trace.risk, trace.gateway_id))
    else:  # pragma: no cover - public validation guards this
        raise ValueError(f"unsupported target policy: {target_policy}")
    return frozenset(trace.gateway_id for trace in ordered[:count])


def _round1_trial(
    traces: Sequence[GatewayRiskTrace],
    *,
    seed: int,
    risk_profile: str,
    target_policy: str,
    targets: frozenset[int],
    suppression: float,
    mechanism: str,
) -> MetricRow:
    total_risk = sum(trace.risk for trace in traces)
    total_rate = sum(trace.call_rate for trace in traces)
    target_risk = sum(trace.risk for trace in traces if trace.gateway_id in targets)
    target_rate = sum(trace.call_rate for trace in traces if trace.gateway_id in targets)
    weighted_effects = 0.0
    stale_calls = 0.0
    suppression_harm = 0.0
    for trace in traces:
        targeted = trace.gateway_id in targets
        if mechanism == "push-only":
            delay = HORIZON if targeted else trace.direct_delay
            no_fault_delay = trace.direct_delay
        elif mechanism == "log-poll":
            delay = trace.log_delay
            no_fault_delay = trace.log_delay
        elif mechanism == "push-repair":
            repair_delay = min(_repair_delay(seed, trace.gateway_id, attempt) for attempt in range(GOSSIP_FANOUT))
            delay = min(trace.log_delay, repair_delay) if targeted else trace.direct_delay
            no_fault_delay = trace.direct_delay
        else:  # pragma: no cover - public validation guards this
            raise ValueError(f"unsupported mechanism: {mechanism}")
        weighted_effects += trace.risk * delay
        stale_calls += trace.call_rate * delay
        if targeted:
            suppression_harm += trace.risk * max(0.0, delay - no_fault_delay)

    costs = _round1_costs(mechanism, suppression, len(traces))
    completeness = 1.0 - suppression if mechanism == "push-only" else 1.0
    audit_rate = 0.0 if mechanism == "push-only" else 1.0
    feasible = bool(
        completeness >= 0.99
        and audit_rate >= 0.99
        and costs["messages_per_gateway"] <= MESSAGE_BUDGET
        and costs["bytes_per_gateway"] <= BYTE_BUDGET
    )
    return {
        "experiment": "E-B19-R1",
        "seed": seed,
        "n_gateways": len(traces),
        "risk_profile": risk_profile,
        "target_policy": target_policy,
        "suppression_fraction": suppression,
        "mechanism": mechanism,
        "target_count": len(targets),
        "target_risk_share": target_risk / total_risk,
        "target_rate_share": target_rate / total_rate,
        "weighted_stale_effects_total": weighted_effects,
        "risk_weighted_stale_window": weighted_effects / total_risk,
        "stale_calls_total": stale_calls,
        "suppression_attributable_weighted_harm": suppression_harm,
        "explicit_event_completeness": completeness,
        "audit_evidence_rate": audit_rate,
        "availability_loss_rate": 0.0,
        "control_messages_per_gateway": costs["messages_per_gateway"],
        "control_bytes_per_gateway": costs["bytes_per_gateway"],
        "message_budget_pass_numeric": float(costs["messages_per_gateway"] <= MESSAGE_BUDGET),
        "byte_budget_pass_numeric": float(costs["bytes_per_gateway"] <= BYTE_BUDGET),
        "feasible_numeric": float(feasible),
    }


def _round2_trial(
    traces: Sequence[GatewayRiskTrace],
    *,
    seed: int,
    risk_profile: str,
    target_policy: str,
    targets: frozenset[int],
    suppression: float,
    repair_policy: str,
    allocations: dict[int, int],
) -> MetricRow:
    total_risk = sum(trace.risk for trace in traces)
    weighted_effects = 0.0
    stale_calls = 0.0
    suppression_harm = 0.0
    for trace in traces:
        if trace.gateway_id in targets:
            attempts = allocations[trace.gateway_id]
            repair_delay = min(_repair_delay(seed, trace.gateway_id, attempt) for attempt in range(attempts))
            delay = min(trace.log_delay, repair_delay)
            suppression_harm += trace.risk * max(0.0, delay - trace.direct_delay)
        else:
            delay = trace.direct_delay
        weighted_effects += trace.risk * delay
        stale_calls += trace.call_rate * delay

    total_attempts = sum(allocations.values())
    append_share = 1.0 / len(traces)
    attempts_per_gateway = total_attempts / len(traces)
    messages = 1.0 + HORIZON / POLL_INTERVAL + attempts_per_gateway + append_share
    bytes_per_gateway = (
        1200.0
        + HORIZON / POLL_INTERVAL * 256.0
        + attempts_per_gateway * 1200.0
        + append_share * 1200.0
    )
    return {
        "experiment": "E-B19-R2",
        "seed": seed,
        "n_gateways": len(traces),
        "risk_profile": risk_profile,
        "target_policy": target_policy,
        "suppression_fraction": suppression,
        "repair_policy": repair_policy,
        "target_count": len(targets),
        "repair_attempts_total": total_attempts,
        "repair_attempts_min": min(allocations.values()),
        "repair_attempts_max": max(allocations.values()),
        "weighted_stale_effects_total": weighted_effects,
        "risk_weighted_stale_window": weighted_effects / total_risk,
        "stale_calls_total": stale_calls,
        "suppression_attributable_weighted_harm": suppression_harm,
        "explicit_event_completeness": 1.0,
        "audit_evidence_rate": 1.0,
        "availability_loss_rate": 0.0,
        "control_messages_per_gateway": messages,
        "control_bytes_per_gateway": bytes_per_gateway,
        "message_budget_pass_numeric": float(messages <= MESSAGE_BUDGET),
        "byte_budget_pass_numeric": float(bytes_per_gateway <= BYTE_BUDGET),
        "feasible_numeric": float(messages <= MESSAGE_BUDGET and bytes_per_gateway <= BYTE_BUDGET),
    }


def _repair_allocations(
    traces: Sequence[GatewayRiskTrace],
    targets: frozenset[int],
    repair_policy: str,
) -> dict[int, int]:
    target_traces = [trace for trace in traces if trace.gateway_id in targets]
    total_attempts = GOSSIP_FANOUT * len(target_traces)
    if repair_policy == "uniform":
        return {trace.gateway_id: GOSSIP_FANOUT for trace in target_traces}
    if repair_policy == "rate-aware":
        weights = {trace.gateway_id: math.sqrt(trace.call_rate) for trace in target_traces}
    elif repair_policy == "risk-aware":
        weights = {trace.gateway_id: math.sqrt(trace.risk) for trace in target_traces}
    else:  # pragma: no cover - public validation guards this
        raise ValueError(f"unsupported repair policy: {repair_policy}")

    allocations = {trace.gateway_id: 1 for trace in target_traces}
    remaining = total_attempts - len(target_traces)
    weight_total = sum(weights.values())
    raw_extra = {gateway_id: remaining * weight / weight_total for gateway_id, weight in weights.items()}
    floor_extra = {gateway_id: int(math.floor(value)) for gateway_id, value in raw_extra.items()}
    for gateway_id, value in floor_extra.items():
        allocations[gateway_id] += value
    leftovers = remaining - sum(floor_extra.values())
    order = sorted(
        raw_extra,
        key=lambda gateway_id: (-(raw_extra[gateway_id] - floor_extra[gateway_id]), gateway_id),
    )
    for gateway_id in order[:leftovers]:
        allocations[gateway_id] += 1
    if sum(allocations.values()) != total_attempts:
        raise AssertionError("repair allocation does not preserve total attempts")
    return allocations


def _round1_costs(mechanism: str, suppression: float, n_gateways: int) -> dict[str, float]:
    append_share = 1.0 / n_gateways
    if mechanism == "push-only":
        return {"messages_per_gateway": 1.0, "bytes_per_gateway": 1200.0}
    if mechanism == "log-poll":
        polls = HORIZON / POLL_INTERVAL
        return {
            "messages_per_gateway": polls + append_share,
            "bytes_per_gateway": polls * 512.0 + append_share * 1200.0,
        }
    if mechanism == "push-repair":
        polls = HORIZON / POLL_INTERVAL
        gossip = suppression * GOSSIP_FANOUT
        return {
            "messages_per_gateway": 1.0 + polls + gossip + append_share,
            "bytes_per_gateway": 1200.0 + polls * 256.0 + gossip * 1200.0 + append_share * 1200.0,
        }
    raise ValueError(f"unsupported mechanism: {mechanism}")


def _repair_delay(seed: int, gateway_id: int, attempt: int) -> float:
    return 0.10 + 0.40 * _unit_float(f"repair:{seed}:{gateway_id}:{attempt}")


def _unit_float(label: str) -> float:
    digest = hashlib.blake2b(label.encode("utf-8"), digest_size=8).digest()
    integer = int.from_bytes(digest, "big")
    return (integer + 0.5) / 2**64


def _normalize_mean(values: Sequence[float], target_mean: float) -> list[float]:
    scale = target_mean / statistics.fmean(values)
    return [value * scale for value in values]


def _aggregate(rows: Sequence[MetricRow], *, group_fields: Sequence[str]) -> list[MetricRow]:
    metric_fields = (
        "target_risk_share",
        "target_rate_share",
        "weighted_stale_effects_total",
        "risk_weighted_stale_window",
        "stale_calls_total",
        "suppression_attributable_weighted_harm",
        "explicit_event_completeness",
        "audit_evidence_rate",
        "availability_loss_rate",
        "control_messages_per_gateway",
        "control_bytes_per_gateway",
        "feasible_numeric",
        "repair_attempts_total",
        "repair_attempts_min",
        "repair_attempts_max",
    )
    groups: dict[tuple[object, ...], list[MetricRow]] = {}
    for row in rows:
        groups.setdefault(tuple(row[field] for field in group_fields), []).append(row)
    aggregates: list[MetricRow] = []
    for key, group in sorted(groups.items(), key=lambda item: tuple(str(value) for value in item[0])):
        aggregate: MetricRow = dict(zip(group_fields, key, strict=True))
        aggregate["runs"] = len(group)
        for metric in metric_fields:
            values = [float(row[metric]) for row in group if metric in row]
            if not values:
                continue
            aggregate[f"{metric}_mean"] = statistics.fmean(values)
            aggregate[f"{metric}_min"] = min(values)
            aggregate[f"{metric}_max"] = max(values)
            aggregate[f"{metric}_stdev"] = statistics.stdev(values) if len(values) > 1 else 0.0
        aggregates.append(aggregate)
    return aggregates


def _index_by_seed(
    rows: Sequence[MetricRow],
    *,
    key_fields: Sequence[str],
) -> dict[tuple[object, ...], dict[int, MetricRow]]:
    output: dict[tuple[object, ...], dict[int, MetricRow]] = {}
    for row in rows:
        key = tuple(row[field] for field in key_fields)
        output.setdefault(key, {})[int(row["seed"])] = row
    return output


def _paired_bootstrap_difference(diffs: Sequence[float], *, samples: int, seed: int) -> dict[str, float]:
    if not diffs:
        return {"mean_difference": math.nan, "ci95_low": math.nan, "ci95_high": math.nan}
    rng = random.Random(seed)
    n = len(diffs)
    boot = [statistics.fmean(diffs[rng.randrange(n)] for _ in range(n)) for _ in range(samples)]
    boot.sort()
    return {
        "mean_difference": statistics.fmean(diffs),
        "ci95_low": _percentile(boot, 0.025),
        "ci95_high": _percentile(boot, 0.975),
    }


def _exact_sign_test(diffs: Sequence[float]) -> float:
    nonzero = [value for value in diffs if not math.isclose(value, 0.0, abs_tol=1e-15)]
    n = len(nonzero)
    if n == 0:
        return 1.0
    positives = sum(value > 0.0 for value in nonzero)
    tail = min(positives, n - positives)
    probability = sum(math.comb(n, index) for index in range(tail + 1)) / 2**n
    return min(1.0, 2.0 * probability)


def _holm_adjust(rows: Sequence[dict[str, object]], *, p_field: str, output_field: str) -> None:
    ordered = sorted(enumerate(rows), key=lambda item: float(item[1][p_field]))
    adjusted: dict[int, float] = {}
    running = 0.0
    total = len(ordered)
    for rank, (original_index, row) in enumerate(ordered):
        candidate = min(1.0, (total - rank) * float(row[p_field]))
        running = max(running, candidate)
        adjusted[original_index] = running
    for index, row in enumerate(rows):
        row[output_field] = adjusted[index]


def _round1_rankings(aggregates: Sequence[MetricRow]) -> list[dict[str, object]]:
    output: list[dict[str, object]] = []
    for profile in RISK_PROFILES:
        for target_policy in TARGET_POLICIES:
            cells = [
                row
                for row in aggregates
                if row["risk_profile"] == profile
                and row["target_policy"] == target_policy
                and math.isclose(float(row["suppression_fraction"]), 0.2)
            ]
            ranked = sorted(cells, key=lambda row: float(row["risk_weighted_stale_window_mean"]))
            feasible = [row for row in ranked if float(row["feasible_numeric_mean"]) == 1.0]
            output.append(
                {
                    "risk_profile": profile,
                    "target_policy": target_policy,
                    "harm_ranking": [row["mechanism"] for row in ranked],
                    "feasible_harm_ranking": [row["mechanism"] for row in feasible],
                }
            )
    return output


def _percentile(values: Sequence[float], q: float) -> float:
    if not values:
        return math.nan
    position = (len(values) - 1) * q
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return float(values[lower])
    weight = position - lower
    return float(values[lower] * (1.0 - weight) + values[upper] * weight)


def _stable_seed(label: str) -> int:
    return int.from_bytes(hashlib.sha256(label.encode("utf-8")).digest()[:8], "big")


def _validate_choices(values: Sequence[str], allowed: Sequence[str], label: str) -> None:
    unknown = sorted(set(values) - set(allowed))
    if unknown:
        raise ValueError(f"unknown {label}: {unknown}")


def _write_csv(rows: Sequence[MetricRow], path: Path) -> None:
    if not rows:
        raise ValueError("cannot write an empty result set")
    fields = sorted({field for row in rows for field in row})
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def _round1_report(summary: dict[str, object]) -> str:
    lines = [
        "# E-B19 Round-1 Targeted-Omission Pilot",
        "",
        "## Material Passport",
        "",
        "- Origin Skill: academic-research-suite / experiment-agent",
        "- Origin Mode: run + validate",
        "- Origin Date: 2026-07-14",
        "- Verification Status: ANALYZED",
        "- Version Label: e-b19-pilot-prereg-v1",
        "",
        f"- Raw rows: {summary['raw_rows']}",
        f"- Aggregate rows: {summary['aggregate_rows']}",
        f"- Verdict: **{summary['round1_verdict']}**",
        "",
        "## Primary Comparisons",
        "",
        "| risk profile | amplification | difference 95% CI | sign p | Holm p | pass |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for item in summary["primary_comparisons"]:
        lines.append(
            f"| {item['risk_profile']} | {float(item['amplification']):.4f} | "
            f"[{float(item['ci95_low']):.4f}, {float(item['ci95_high']):.4f}] | "
            f"{float(item['sign_test_p']):.3g} | {float(item['holm_adjusted_p']):.3g} | "
            f"{item['profile_pass']} |"
        )
    lines.extend(
        [
            "",
            "## Boundary",
            "",
            "Passing this synthetic stress gate supports Round 2 only. It does not establish that production agent-tool risk follows either frozen Zipf profile.",
        ]
    )
    return "\n".join(lines)


def _round2_report(summary: dict[str, object]) -> str:
    primary = summary["primary_comparison"]
    lines = [
        "# E-B19 Round-2 Equal-Budget Repair Pilot",
        "",
        "## Material Passport",
        "",
        "- Origin Skill: academic-research-suite / experiment-agent",
        "- Origin Mode: run + validate",
        "- Origin Date: 2026-07-14",
        "- Verification Status: ANALYZED",
        "- Version Label: e-b19-pilot-prereg-v1",
        "",
        f"- Raw rows: {summary['raw_rows']}",
        f"- Aggregate rows: {summary['aggregate_rows']}",
        f"- Verdict: **{summary['round2_verdict']}**",
        "",
        "## Primary Comparison",
        "",
        f"- Relative reduction: {float(primary['relative_reduction']):.4%}",
        f"- Paired difference 95% CI: [{float(primary['ci95_low']):.4f}, {float(primary['ci95_high']):.4f}]",
        f"- Exact cost match: {primary['exact_cost_match']}",
        f"- Outcome-contract match: {primary['outcome_contract_match']}",
        f"- Gate pass: {primary['primary_pass']}",
        "",
        "## Diagnostic Comparisons",
        "",
        "| risk profile | targets | policy | reduction | difference 95% CI |",
        "|---|---|---|---:|---:|",
    ]
    for item in summary["diagnostic_comparisons"]:
        lines.append(
            f"| {item['risk_profile']} | {item['target_policy']} | {item['repair_policy']} | "
            f"{float(item['relative_reduction']):.2%} | "
            f"[{float(item['ci95_low']):.4f}, {float(item['ci95_high']):.4f}] |"
        )
    return "\n".join(lines)


def _parse_seed_range(value: str) -> range:
    start_text, stop_text = value.split(":", 1)
    return range(int(start_text), int(stop_text))


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Run E-B19 risk-weighted omission pilots")
    parser.add_argument("--round", choices=("1", "2"), required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--seeds", default="0:30", help="half-open range, for example 0:30")
    parser.add_argument("--n-gateways", type=int, default=1000)
    parser.add_argument("--bootstrap-samples", type=int, default=10_000)
    args = parser.parse_args(argv)
    seeds = _parse_seed_range(args.seeds)
    if args.round == "1":
        rows = run_round1_targeted_omission(seeds=seeds, n_gateways=args.n_gateways)
        write_round1_outputs(rows, args.output_dir, bootstrap_samples=args.bootstrap_samples)
    else:
        rows = run_round2_budgeted_repair(seeds=seeds, n_gateways=args.n_gateways)
        write_round2_outputs(rows, args.output_dir, bootstrap_samples=args.bootstrap_samples)


if __name__ == "__main__":
    main()
