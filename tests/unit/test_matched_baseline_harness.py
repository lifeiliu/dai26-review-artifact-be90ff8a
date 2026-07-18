import json

from revocation_propagation.matched_baseline_harness import (
    P0_MECHANISMS,
    analyze_e_b17,
    run_e_b17_p0_matched_baselines,
    write_e_b17_outputs,
)


def test_e_b17_models_all_preregistered_mechanisms_on_common_targets() -> None:
    rows = run_e_b17_p0_matched_baselines(
        seeds=(0,),
        n_gateways_values=(100,),
        profiles=("matched",),
        fault_scenarios=("selective-operator",),
        suppression_values=(0.2,),
    )
    by_mechanism = {row["mechanism"]: row for row in rows}

    assert set(by_mechanism) == set(P0_MECHANISMS)
    assert by_mechanism["aip-03"]["explicit_event_completeness"] == 0.8
    assert by_mechanism["aip-03"]["event_p99_censored"] == 60.0
    assert by_mechanism["drp-10-60"]["explicit_event_completeness"] == 1.0
    assert by_mechanism["drp-10-60"]["audit_evidence_rate"] == 1.0
    assert by_mechanism["hbhc"]["explicit_event_completeness"] == 0.0
    assert by_mechanism["sync-fail-closed"]["availability_loss_rate"] == 0.2
    assert by_mechanism["revprop"]["explicit_event_completeness"] == 1.0
    assert by_mechanism["revprop"]["independent_repair_rate"] == 0.2


def test_e_b17_cost_gate_is_selective_suppression_sensitive() -> None:
    rows = run_e_b17_p0_matched_baselines(
        seeds=(0,),
        n_gateways_values=(1000,),
        profiles=("matched",),
        fault_scenarios=("selective-operator",),
        suppression_values=(0.2, 0.5),
        mechanisms=("revprop",),
    )
    by_drop = {row["suppression_fraction"]: row for row in rows}

    assert by_drop[0.2]["control_messages_per_gateway"] <= 8.1
    assert by_drop[0.2]["message_budget_pass_numeric"] == 1.0
    assert by_drop[0.5]["control_messages_per_gateway"] > 8.1
    assert by_drop[0.5]["message_budget_pass_numeric"] == 0.0


def test_e_b17_frozen_rule_finds_only_the_budget_feasible_cell() -> None:
    rows = run_e_b17_p0_matched_baselines(
        seeds=range(30),
        n_gateways_values=(100,),
        profiles=("matched",),
        fault_scenarios=("selective-operator",),
        suppression_values=(0.2, 0.5),
    )
    summary = analyze_e_b17(rows, bootstrap_samples=500)
    cells = {cell["suppression_fraction"]: cell for cell in summary["confirmatory_cells"]}

    assert summary["e_b17_verdict"] == "E_B17_CONSTRAINED_ADVANTAGE"
    assert cells[0.2]["e_b17_cell_pass"] is True
    assert cells[0.5]["e_b17_cell_pass"] is False
    assert all(comparison["paired_seeds"] == 30 for comparison in summary["comparisons"])
    assert all(comparison["ci95_high"] < 0.0 for comparison in summary["comparisons"])


def test_e_b17_outputs_preserve_inconclusive_small_smoke(tmp_path) -> None:
    rows = run_e_b17_p0_matched_baselines(
        seeds=(0, 1, 2),
        n_gateways_values=(40,),
        profiles=("matched",),
        fault_scenarios=("selective-operator",),
        suppression_values=(0.2,),
    )
    write_e_b17_outputs(rows, tmp_path, bootstrap_samples=200)
    decision = json.loads((tmp_path / "e_b17_decision.json").read_text())

    assert decision["e_b17_verdict"] == "INCONCLUSIVE"
    assert (tmp_path / "e_b17_p0_matched_baselines.csv").exists()
    assert (tmp_path / "e_b17_aggregate.csv").exists()
    assert (tmp_path / "e_b17_summary.json").exists()
    assert (tmp_path / "e_b17_report.md").exists()
