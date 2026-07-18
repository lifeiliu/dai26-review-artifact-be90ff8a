from revocation_propagation.risk_weighted_pilot import (
    _gateway_traces,
    _repair_allocations,
    _select_targets,
    analyze_round1,
    analyze_round2,
    run_round1_targeted_omission,
    run_round2_budgeted_repair,
    write_round1_outputs,
    write_round2_outputs,
)


def test_top_risk_targets_capture_more_risk_than_random_targets() -> None:
    traces = _gateway_traces(0, 1000, "zipf-correlated")
    random_targets = _select_targets(traces, 0.2, "random")
    top_targets = _select_targets(traces, 0.2, "top-risk")
    random_share = sum(trace.risk for trace in traces if trace.gateway_id in random_targets)
    top_share = sum(trace.risk for trace in traces if trace.gateway_id in top_targets)

    assert len(random_targets) == len(top_targets) == 200
    assert top_share > random_share


def test_risk_aware_allocation_preserves_attempt_budget_and_floor() -> None:
    traces = _gateway_traces(0, 1000, "zipf-correlated")
    targets = _select_targets(traces, 0.2, "top-risk")
    uniform = _repair_allocations(traces, targets, "uniform")
    risk_aware = _repair_allocations(traces, targets, "risk-aware")

    assert sum(uniform.values()) == sum(risk_aware.values()) == 1000
    assert min(risk_aware.values()) >= 1
    assert max(risk_aware.values()) > 5


def test_round1_is_deterministic_and_writes_outputs(tmp_path) -> None:
    kwargs = {
        "seeds": range(3),
        "n_gateways": 100,
        "risk_profiles": ("zipf-rate", "zipf-correlated"),
        "target_policies": ("random", "top-risk"),
        "suppression_values": (0.2,),
        "mechanisms": ("push-repair",),
    }
    rows = run_round1_targeted_omission(**kwargs)
    assert rows == run_round1_targeted_omission(**kwargs)
    write_round1_outputs(rows, tmp_path, bootstrap_samples=200)

    assert (tmp_path / "e_b19_round1_targeted_omission.csv").exists()
    assert (tmp_path / "e_b19_round1_aggregate.csv").exists()
    assert (tmp_path / "e_b19_round1_summary.json").exists()
    assert (tmp_path / "e_b19_round1_report.md").exists()


def test_round2_equal_budget_contract_and_analysis(tmp_path) -> None:
    rows = run_round2_budgeted_repair(seeds=range(30), n_gateways=200)
    by_cell = {}
    for row in rows:
        key = (row["seed"], row["risk_profile"], row["target_policy"])
        by_cell.setdefault(key, []).append(row)
    for cell in by_cell.values():
        assert len({row["repair_attempts_total"] for row in cell}) == 1
        assert len({row["control_messages_per_gateway"] for row in cell}) == 1
        assert len({row["control_bytes_per_gateway"] for row in cell}) == 1
        assert all(row["explicit_event_completeness"] == 1.0 for row in cell)
        assert all(row["audit_evidence_rate"] == 1.0 for row in cell)

    summary = analyze_round2(rows, bootstrap_samples=200)
    assert summary["primary_comparison"]["exact_cost_match"] is True
    assert summary["primary_comparison"]["outcome_contract_match"] is True
    write_round2_outputs(rows, tmp_path, bootstrap_samples=200)
    assert (tmp_path / "e_b19_round2_summary.json").exists()


def test_round1_full_analysis_has_two_frozen_primary_profiles() -> None:
    rows = run_round1_targeted_omission(
        seeds=range(30),
        n_gateways=200,
        risk_profiles=("zipf-rate", "zipf-correlated"),
        target_policies=("random", "top-risk"),
        suppression_values=(0.2,),
        mechanisms=("push-repair",),
    )
    summary = analyze_round1(rows, bootstrap_samples=200)

    assert len(summary["primary_comparisons"]) == 2
    assert {item["risk_profile"] for item in summary["primary_comparisons"]} == {
        "zipf-rate",
        "zipf-correlated",
    }
