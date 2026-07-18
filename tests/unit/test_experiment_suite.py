import json

from revocation_propagation.experiment_suite import (
    aggregate_rows,
    iter_e_b1_byzantine_sweep_rows,
    read_rows_csv,
    run_all_experiments,
    run_e_b1_byzantine_sweep,
    run_e_b2_delta_prop_baselines,
    run_e_b3_damage_budget,
    run_e_b4_equivocation_resistance,
    run_e_b5_thin_a2a,
    run_e_b6_local_end_to_end,
    run_e_b7_reproducibility_sensitivity,
    run_e_b8_agent_tool_gateway,
    run_e_b9_a2a_lifecycle_binding,
    run_e_b10_real_gateway_tool_path,
    run_e_b11_protocol_boundary_path,
    run_e_b12_fault_injection_path,
    run_e_b13_paper_a_agent_system_bridge,
    run_e_b14_multiprocess_deployment,
    run_e_b15_real_agent_tool_path,
    run_e_b16_status_outage_baselines,
    run_e_b2_delivery_regime_baselines,
    stream_rows_csv,
    summarize_e_b6,
    summarize_e_b7,
    summarize_e_b8,
    summarize_e_b9,
    summarize_e_b10,
    summarize_e_b11,
    summarize_e_b12,
    summarize_e_b13,
    summarize_e_b14,
    summarize_e_b15,
    summarize_e_b16,
    summarize_e_b5,
    summarize_e_b4,
    summarize_e_b3,
    summarize_e_b2,
    write_e_b1_reports_from_csv,
    write_e_b2_outputs,
    write_e_b3_outputs,
    write_e_b4_outputs,
    write_e_b5_outputs,
    write_e_b6_outputs,
    write_e_b7_outputs,
    write_e_b8_outputs,
    write_e_b9_outputs,
    write_e_b10_outputs,
    write_e_b11_outputs,
    write_e_b12_outputs,
    write_e_b13_outputs,
    write_e_b14_outputs,
    write_e_b15_outputs,
    write_e_b16_outputs,
)


def test_e_b1_reports_detection_budget_surface() -> None:
    rows = run_e_b1_byzantine_sweep(
        seeds=(0,),
        n_parties=8,
        push_suppression_values=(0.25,),
        gossip_suppression_values=(0.0,),
        log_suppression_values=(0.0,),
    )

    assert len(rows) == 1
    assert rows[0]["experiment"] == "E-B1"
    assert rows[0]["strategy"] == "hybrid"
    assert "detected_within_budget" in rows[0]


def test_e_b1_streaming_resume_skips_existing_keys(tmp_path) -> None:
    raw_path = tmp_path / "e_b1_byzantine_sweep.csv"
    first_rows = iter_e_b1_byzantine_sweep_rows(
        seeds=(0,),
        n_parties=8,
        push_suppression_values=(0.2,),
        gossip_suppression_values=(0.0,),
        log_suppression_values=(0.0,),
    )
    written = stream_rows_csv(first_rows, raw_path)
    existing = {row["run_key"] for row in read_rows_csv(raw_path)}
    second_rows = iter_e_b1_byzantine_sweep_rows(
        seeds=(0,),
        n_parties=8,
        push_suppression_values=(0.2,),
        gossip_suppression_values=(0.0,),
        log_suppression_values=(0.0,),
        skip_keys=existing,
    )
    written_again = stream_rows_csv(second_rows, raw_path)
    write_e_b1_reports_from_csv(tmp_path)

    assert written == 1
    assert written_again == 0
    assert len(read_rows_csv(raw_path)) == 1
    assert (tmp_path / "e_b1_aggregate.csv").exists()
    assert (tmp_path / "e_b1_summary.json").exists()
    assert (tmp_path / "e_b1_report.md").exists()


def test_e_b2_runs_matched_strategy_matrix() -> None:
    rows = run_e_b2_delta_prop_baselines(
        seeds=(0,),
        n_parties=8,
        strategies=("push", "push-gossip", "push-log", "gossip-log", "hybrid"),
    )
    by_strategy = {row["strategy"]: row for row in rows}

    assert set(by_strategy) == {"push", "push-gossip", "push-log", "gossip-log", "hybrid"}
    assert by_strategy["hybrid"]["channel_messages"] > 0
    assert by_strategy["push"]["undelivered_count"] > 0


def test_e_b2_accepts_scenario_parameters_and_reports_aggregates(tmp_path) -> None:
    rows = run_e_b2_delta_prop_baselines(
        seeds=(0, 1),
        n_parties=12,
        push_suppression=0.25,
        gossip_fanout=4,
        max_time=4.0,
        strategies=("push", "hybrid"),
    )
    aggregates = aggregate_rows(
        rows,
        group_by=("strategy", "n_parties"),
        metrics=("completeness", "p99_delta", "channel_messages"),
    )
    summary = summarize_e_b2(rows)
    write_e_b2_outputs(rows, tmp_path, run_config={"seeds": "0:2", "n_parties": "12"})

    assert len(rows) == 4
    assert len(aggregates) == 2
    assert summary["raw_rows"] == 4
    assert (tmp_path / "e_b2_delta_prop_baselines.csv").exists()
    assert (tmp_path / "e_b2_aggregate.csv").exists()
    assert (tmp_path / "e_b2_summary.json").exists()
    assert (tmp_path / "e_b2_report.md").exists()


def test_e_b2_adds_related_work_delivery_regime_surface(tmp_path) -> None:
    rows = run_e_b2_delta_prop_baselines(
        seeds=(0,),
        n_parties=12,
        strategies=("hybrid",),
        delivery_regimes=("full-snapshot", "request-time-fail-open", "compact-delta", "dns-log-poll", "hybrid"),
        status_suppression_values=(0.0, 0.5),
    )
    delivery_rows = [row for row in rows if row.get("baseline_family") == "delivery-regime"]
    by_regime = {row["delivery_regime"] for row in delivery_rows}
    summary = summarize_e_b2(rows)
    write_e_b2_outputs(rows, tmp_path, run_config={"delivery_regimes": "related-work-smoke"})

    assert by_regime == {"full-snapshot", "request-time-fail-open", "compact-delta", "dns-log-poll", "hybrid"}
    assert any(row["delivery_regime"] == "full-snapshot" and row["delivery_bytes_per_party"] > 1000 for row in delivery_rows)
    assert summary["delivery_regime_comparisons"]
    assert (tmp_path / "e_b2_aggregate.csv").exists()
    assert "delivery-regime" in (tmp_path / "e_b2_report.md").read_text()


def test_e_b2_delivery_regime_runner_models_fail_open_stale_window() -> None:
    rows = run_e_b2_delivery_regime_baselines(
        seeds=(0,),
        n_parties=10,
        delivery_regimes=("request-time-check", "request-time-fail-open"),
        status_suppression_values=(0.5,),
        ttl=60.0,
    )
    by_regime = {row["delivery_regime"]: row for row in rows}

    assert by_regime["request-time-check"]["status_availability_loss_rate"] > 0.0
    assert by_regime["request-time-fail-open"]["stale_acceptance_window"] == 60.0
    assert by_regime["request-time-fail-open"]["unauthorized_ops_worst"] > by_regime["request-time-check"]["unauthorized_ops_worst"]


def test_e_b3_assigns_ttl_fallback_damage_to_undelivered_rows() -> None:
    measured = [
        {
            "experiment": "E-B2",
            "strategy": "push",
            "seed": 0,
            "n_parties": 8,
            "max_delta": 0.05,
            "undelivered_count": 2,
        }
    ]
    rows = run_e_b3_damage_budget(measured_rows=measured, ttls=(60.0,), velocities=(10.0,), budget=1000.0)

    assert rows[0]["delta_prop_for_damage"] == 60.0
    assert rows[0]["unauthorized_ops_worst"] == 1200.0
    assert rows[0]["worst_exceeds_budget"] is True


def test_e_b3_uses_counterfactual_ttl_for_ttl_rcc_and_reports(tmp_path) -> None:
    measured = [
        {
            "experiment": "E-B2",
            "strategy": "ttl-rcc",
            "seed": 0,
            "n_parties": 8,
            "completeness": 1.0,
            "p99_delta": 60.0,
            "max_delta": 60.0,
            "undelivered_count": 0,
        },
        {
            "experiment": "E-B2",
            "strategy": "hybrid",
            "seed": 0,
            "n_parties": 8,
            "completeness": 1.0,
            "p99_delta": 0.4,
            "max_delta": 0.5,
            "undelivered_count": 0,
        },
    ]
    rows = run_e_b3_damage_budget(
        measured_rows=measured,
        ttls=(10.0,),
        velocities=(10.0,),
        budgets=(100.0, 1000.0),
    )
    ttl_row = next(row for row in rows if row["strategy"] == "ttl-rcc" and row["budget"] == 100.0)
    summary = summarize_e_b3(rows)
    write_e_b3_outputs(rows, tmp_path, run_config={"ttls": (10.0,)})

    assert ttl_row["delta_prop_for_damage"] == 10.0
    assert len(rows) == 4
    assert summary["raw_rows"] == 4
    assert (tmp_path / "e_b3_damage_budget.csv").exists()
    assert (tmp_path / "e_b3_aggregate.csv").exists()
    assert (tmp_path / "e_b3_summary.json").exists()
    assert (tmp_path / "e_b3_report.md").exists()


def test_e_b4_distinguishes_threshold_and_split_view_detection() -> None:
    rows = run_e_b4_equivocation_resistance(seeds=(0,))
    by_scenario = {row["scenario"]: row for row in rows}

    assert by_scenario["below-threshold-root-fork"]["certificate_accepted"] is False
    assert by_scenario["two-of-five-root-fork"]["certificate_accepted"] is False
    assert by_scenario["threshold-plus-split-view-log"]["certificate_accepted"] is True
    assert by_scenario["threshold-plus-split-view-log"]["equivocation_detected"] is True


def test_e_b4_reports_partition_and_false_positive_surface(tmp_path) -> None:
    rows = run_e_b4_equivocation_resistance(
        seeds=(0, 1),
        observation_delays=(0.25, 0.5),
        partition_heal_delays=(1.0,),
    )
    summary = summarize_e_b4(rows)
    write_e_b4_outputs(rows, tmp_path, run_config={"seeds": (0, 1)})

    assert summary["below_threshold_rejection_rate"] == 1.0
    assert summary["split_view_detection_rate"] == 1.0
    assert summary["benign_false_positive_rate"] == 0.0
    assert (tmp_path / "e_b4_equivocation_resistance.csv").exists()
    assert (tmp_path / "e_b4_aggregate.csv").exists()
    assert (tmp_path / "e_b4_summary.json").exists()
    assert (tmp_path / "e_b4_report.md").exists()


def test_e_b4_adds_watcher_coverage_surface(tmp_path) -> None:
    rows = run_e_b4_equivocation_resistance(
        seeds=tuple(range(4)),
        watcher_counts=(1, 4),
        watcher_coverages=(0.25, 1.0),
        watcher_observation_intervals=(0.5,),
        party_reporting_fractions=(1.0,),
        selective_disclosure_values=(0.0,),
        watcher_partition_durations=(2.0,),
    )
    watcher_rows = [row for row in rows if row.get("scenario_category") == "watcher-coverage"]
    summary = summarize_e_b4(rows)
    write_e_b4_outputs(rows, tmp_path, run_config={"watcher_counts": (1, 4)})

    assert watcher_rows
    assert all("watcher_detection_probability_model" in row for row in watcher_rows)
    assert summary["watcher_detection_rate"] is not None
    assert summary["watcher_max_detection_latency"] is not None
    assert "Watcher Coverage Aggregates" in (tmp_path / "e_b4_report.md").read_text()


def test_e_b5_thin_a2a_adds_payload_and_transport_fields() -> None:
    rows = run_e_b5_thin_a2a(seeds=(0,), n_parties_values=(3,), strategies=("hybrid",))

    assert rows[0]["experiment"] == "E-B5"
    assert rows[0]["a2a_payload_bytes"] > 0
    assert rows[0]["a2a_transport_delay_model"] > 0.0
    assert rows[0]["a2a_transport_mode"] == "local-a2a-shaped-json"


def test_e_b5_reports_ordering_surface(tmp_path) -> None:
    rows = run_e_b5_thin_a2a(seeds=(0, 1), n_parties_values=(3, 10), strategies=("push", "log", "hybrid"))
    summary = summarize_e_b5(rows)
    write_e_b5_outputs(rows, tmp_path, run_config={"seeds": (0, 1)})

    assert summary["ordering_success_rate"] == 1.0
    assert summary["raw_rows"] == 12
    assert (tmp_path / "e_b5_thin_a2a.csv").exists()
    assert (tmp_path / "e_b5_aggregate.csv").exists()
    assert (tmp_path / "e_b5_summary.json").exists()
    assert (tmp_path / "e_b5_report.md").exists()


def test_e_b6_local_e2e_uses_loopback_transport_and_reports(tmp_path) -> None:
    rows = run_e_b6_local_end_to_end(
        seeds=(0,),
        n_parties_values=(4,),
        strategies=("push", "hybrid"),
        duration=0.45,
        gossip_fanout=2,
    )
    by_strategy = {row["strategy"]: row for row in rows}
    summary = summarize_e_b6(rows)
    write_e_b6_outputs(rows, tmp_path, run_config={"duration": 0.45})

    assert len(rows) == 2
    assert by_strategy["hybrid"]["service_model"] == "asyncio-tcp-jsonl"
    assert by_strategy["hybrid"]["transport_requests"] > 0
    assert by_strategy["hybrid"]["root_certificate_verified_rate"] == 1.0
    assert by_strategy["push"]["completeness"] < 1.0
    assert summary["raw_rows"] == 2
    assert (tmp_path / "e_b6_local_e2e.csv").exists()
    assert (tmp_path / "e_b6_aggregate.csv").exists()
    assert (tmp_path / "e_b6_summary.json").exists()
    assert (tmp_path / "e_b6_report.md").exists()


def test_e_b7_sensitivity_writes_manifest(tmp_path) -> None:
    rows = run_e_b7_reproducibility_sensitivity(
        seeds=(0,),
        n_parties_values=(12,),
        fanout_values=(2, 4),
        poll_interval_values=(0.25, 0.50),
        jitter_values=(0.0, 0.20),
        delay_scale_values=(1.0, 2.0),
        max_time=3.0,
    )
    summary = summarize_e_b7(rows)
    write_e_b7_outputs(rows, tmp_path, run_config={"max_time": 3.0})

    assert any(row["config_id"] == "baseline" for row in rows)
    assert any(row["sensitivity_axis"] == "fanout" for row in rows)
    assert summary["raw_rows"] == len(rows)
    assert (tmp_path / "e_b7_sensitivity.csv").exists()
    assert (tmp_path / "e_b7_aggregate.csv").exists()
    assert (tmp_path / "e_b7_summary.json").exists()
    assert (tmp_path / "e_b7_report.md").exists()
    assert (tmp_path / "reproducibility_manifest.json").exists()


def test_e_b8_agent_tool_gateway_counts_revoked_tool_calls() -> None:
    rows = run_e_b8_agent_tool_gateway(
        seeds=(0,),
        n_parties_values=(12,),
        strategies=("push", "ttl-rcc", "hybrid"),
        tool_call_rates=(10.0,),
        ttl=60.0,
    )
    by_strategy = {row["strategy"]: row for row in rows}

    assert by_strategy["hybrid"]["experiment"] == "E-B8"
    assert by_strategy["hybrid"]["agent_runtime_model"] == "tool-gateway-cached-capability"
    assert by_strategy["ttl-rcc"]["revoked_tool_calls_allowed"] == by_strategy["ttl-rcc"]["revoked_tool_calls_baseline_ttl"]
    assert by_strategy["hybrid"]["revoked_tool_calls_allowed"] < by_strategy["ttl-rcc"]["revoked_tool_calls_allowed"]
    assert by_strategy["hybrid"]["audit_evidence_available"] is True
    assert by_strategy["push"]["audit_evidence_available"] is False


def test_e_b8_reports_agent_tool_gateway_surface(tmp_path) -> None:
    rows = run_e_b8_agent_tool_gateway(
        seeds=(0, 1),
        n_parties_values=(12,),
        strategies=("push", "ttl-rcc", "push-gossip", "log", "hybrid"),
        tool_call_rates=(1.0, 10.0),
    )
    summary = summarize_e_b8(rows)
    write_e_b8_outputs(rows, tmp_path, run_config={"tool_call_rates": (1.0, 10.0)})

    assert summary["raw_rows"] == 20
    assert summary["hybrid_mean_prevented_fraction"] > 0.0
    assert (tmp_path / "e_b8_agent_tool_gateway.csv").exists()
    assert (tmp_path / "e_b8_aggregate.csv").exists()
    assert (tmp_path / "e_b8_summary.json").exists()
    assert (tmp_path / "e_b8_report.md").exists()
    assert "Agent-Tool Gateway" in (tmp_path / "e_b8_report.md").read_text()


def test_e_b9_a2a_lifecycle_binding_compatibility_matrix() -> None:
    rows = run_e_b9_a2a_lifecycle_binding(
        seeds=(0,),
        n_parties_values=(12,),
        tool_call_rates=(10.0,),
        ttl=60.0,
    )
    by_cell = {row["compatibility_cell"]: row for row in rows}

    assert set(by_cell) == {
        "new-client-new-server",
        "new-client-old-server",
        "old-client-new-server",
        "old-client-old-server",
    }
    assert by_cell["new-client-new-server"]["lifecycle_binding_success"] is True
    assert by_cell["new-client-new-server"]["revoked_tool_calls_allowed"] < by_cell["old-client-old-server"]["revoked_tool_calls_allowed"]
    assert by_cell["new-client-old-server"]["task_available"] is False
    assert by_cell["new-client-old-server"]["revoked_tool_calls_allowed"] == 0.0
    assert by_cell["old-client-new-server"]["revocation_enforced"] is True
    assert by_cell["old-client-old-server"]["revocation_enforced"] is False
    assert all(row["compatibility_correct"] is True for row in rows)


def test_e_b9_reports_a2a_lifecycle_surface(tmp_path) -> None:
    rows = run_e_b9_a2a_lifecycle_binding(
        seeds=(0, 1),
        n_parties_values=(12,),
        tool_call_rates=(1.0, 10.0),
    )
    summary = summarize_e_b9(rows)
    write_e_b9_outputs(rows, tmp_path, run_config={"tool_call_rates": (1.0, 10.0)})

    assert summary["raw_rows"] == 16
    assert summary["compatibility_pass_rate"] == 1.0
    assert summary["new_new_mean_effective_enforcement_latency"] is not None
    assert (tmp_path / "e_b9_a2a_lifecycle_binding.csv").exists()
    assert (tmp_path / "e_b9_aggregate.csv").exists()
    assert (tmp_path / "e_b9_summary.json").exists()
    assert (tmp_path / "e_b9_report.md").exists()
    assert "A2A Lifecycle Binding" in (tmp_path / "e_b9_report.md").read_text()


def test_e_b10_real_gateway_tool_path_crosses_loopback_services(tmp_path) -> None:
    rows = run_e_b10_real_gateway_tool_path(
        seeds=(0,),
        n_parties_values=(3,),
        fault_scenarios=("none", "push-drop-log-repair"),
        tool_call_rates=(10.0,),
    )
    by_fault = {row["fault_scenario"]: row for row in rows}
    summary = summarize_e_b10(rows)
    write_e_b10_outputs(rows, tmp_path, run_config={"n_parties_values": (3,)})

    assert set(by_fault) == {"none", "push-drop-log-repair"}
    assert all(row["experiment"] == "E-B10" for row in rows)
    assert all(row["loopback_service_boundary"] is True for row in rows)
    assert all(row["gateway_tool_boundary_crossed"] is True for row in rows)
    assert all(row["pre_revocation_allowed_rate"] == 1.0 for row in rows)
    assert all(row["post_repair_reject_rate"] == 1.0 for row in rows)
    assert by_fault["push-drop-log-repair"]["log_repairs"] == 3
    assert by_fault["push-drop-log-repair"]["audit_evidence_available_numeric"] == 1.0
    assert summary["integration_success_rate"] == 1.0
    assert (tmp_path / "e_b10_real_gateway_tool_path.csv").exists()
    assert (tmp_path / "e_b10_aggregate.csv").exists()
    assert (tmp_path / "e_b10_summary.json").exists()
    assert (tmp_path / "e_b10_report.md").exists()


def test_e_b11_protocol_boundary_profiles_pass_schema() -> None:
    rows = run_e_b11_protocol_boundary_path(
        seeds=(0,),
        n_parties_values=(2,),
        protocol_profiles=("raw-http-json", "mcp-style-jsonrpc", "a2a-task-lifecycle"),
        tool_call_rates=(1.0,),
    )
    by_protocol = {row["protocol_profile"]: row for row in rows}
    summary = summarize_e_b11(rows)

    assert set(by_protocol) == {"raw-http-json", "mcp-style-jsonrpc", "a2a-task-lifecycle"}
    assert all(row["experiment"] == "E-B11" for row in rows)
    assert all(row["protocol_schema_pass_rate"] == 1.0 for row in rows)
    assert all(row["integration_success_numeric"] == 1.0 for row in rows)
    assert summary["protocol_schema_pass_rate"] == 1.0


def test_e_b12_fault_injection_recovers_and_reports(tmp_path) -> None:
    rows = run_e_b12_fault_injection_path(
        seeds=(0,),
        n_parties_values=(3,),
        fault_scenarios=("push-drop-log-repair", "gateway-restart"),
        tool_call_rates=(1.0,),
        log_delay=0.25,
    )
    by_fault = {row["fault_scenario"]: row for row in rows}
    summary = summarize_e_b12(rows)
    write_e_b12_outputs(rows, tmp_path, run_config={"fault_scenarios": ("push-drop-log-repair", "gateway-restart")})

    assert by_fault["push-drop-log-repair"]["log_repairs"] == 3
    assert by_fault["gateway-restart"]["gateway_restarts"] == 3
    assert by_fault["gateway-restart"]["sampled_revoked_calls_allowed"] > 0
    assert all(row["post_repair_reject_rate"] == 1.0 for row in rows)
    assert summary["integration_success_rate"] == 1.0
    assert (tmp_path / "e_b12_fault_injection_path.csv").exists()
    assert (tmp_path / "e_b12_aggregate.csv").exists()
    assert (tmp_path / "e_b12_summary.json").exists()
    assert (tmp_path / "e_b12_report.md").exists()


def test_e_b11_reports_protocol_boundary_surface(tmp_path) -> None:
    rows = run_e_b11_protocol_boundary_path(
        seeds=(0,),
        n_parties_values=(2,),
        protocol_profiles=("raw-http-json", "mcp-style-jsonrpc"),
        tool_call_rates=(1.0,),
    )
    write_e_b11_outputs(rows, tmp_path, run_config={"protocol_profiles": ("raw-http-json", "mcp-style-jsonrpc")})

    assert (tmp_path / "e_b11_protocol_boundary_path.csv").exists()
    assert (tmp_path / "e_b11_aggregate.csv").exists()
    assert (tmp_path / "e_b11_summary.json").exists()
    assert (tmp_path / "e_b11_report.md").exists()


def test_e_b13_bridges_paper_a_agent_system_evidence(tmp_path) -> None:
    paper_a_dir = tmp_path / "paper_a_experiments"
    _write_json(
        paper_a_dir / "e16_framework_trace_replay" / "e16_results.json",
        {
            "collection": {"raw_events": 30},
            "normalization": {"signed_delegation_events": 6, "valid_signed_delegation_events": 6},
            "outcomes": {
                "traces": 3,
                "traces_with_multiparent": 2,
                "traces_with_cross_deployer_multiparent": 1,
                "single_edge_conformance": {"semantic_survivors": 2, "tree_wrongly_revoked": 2},
                "proof_verified": {"passed": 3, "total": 3},
                "authorized_revocation_verified": {"passed": 3, "total": 3},
                "unauthorized_rejected": {"passed": 3, "total": 3},
                "omission_rejected": {"passed": 2, "total": 2},
                "cross_deployer_revocation_verified": {"passed": 1, "total": 1},
                "replay_ms": {"mean": 1.5},
                "proof_bytes": {"mean": 128},
            },
        },
    )
    _write_json(
        paper_a_dir / "e16_framework_trace_replay" / "e16_baseline_expressiveness.json",
        {
            "alternate_parent_cases": 2,
            "cross_domain_target_cases": {"cases": 4, "scoped_under_cases": 4},
        },
    )
    _write_json(
        paper_a_dir / "e17_a2a_protocol_demo" / "e17_results.json",
        {
            "trace_units": 2,
            "signed_delegation_events": 8,
            "valid_signed_delegation_events": 8,
            "alternate_parent_cases": 1,
            "alternate_parent_preserved_by_edge_target": 1,
            "alternate_parent_wrongly_revoked_by_tree": 1,
            "cross_domain_target_cases": 6,
            "cross_domain_under_revoked_by_scoped": 6,
        },
    )
    _write_json(
        paper_a_dir / "e18_cross_framework_agent_demo" / "e18_results.json",
        {
            "trace_units": 2,
            "signed_delegation_events": 10,
            "valid_signed_delegation_events": 10,
            "alternate_parent_cases": 2,
            "alternate_parent_preserved_by_edge_target": 2,
            "alternate_parent_wrongly_revoked_by_tree": 2,
            "cross_domain_target_cases": 3,
            "cross_domain_under_revoked_by_scoped": 3,
        },
    )
    _write_json(
        paper_a_dir / "e19_crewai_executable_demo" / "e19_results.json",
        {
            "trace_units": 5,
            "signed_delegation_events": 35,
            "valid_signed_delegation_events": 35,
            "crew_kickoff_completed": True,
            "crewai_version": "1.15.1",
            "tasks_configured": 40,
            "task_callbacks_observed": 40,
            "llm_calls_observed": 40,
            "alternate_parent_cases": 5,
            "alternate_parent_preserved_by_edge_target": 5,
            "alternate_parent_wrongly_revoked_by_tree": 5,
            "cross_domain_target_cases": 10,
            "cross_domain_under_revoked_by_scoped": 10,
        },
    )

    rows = run_e_b13_paper_a_agent_system_bridge(paper_a_experiments_dir=paper_a_dir)
    summary = summarize_e_b13(rows)
    write_e_b13_outputs(rows, tmp_path, run_config={"paper_a_experiments_dir": str(paper_a_dir)})

    assert len(rows) == 4
    assert summary["weighted_valid_signed_delegation_rate"] == 1.0
    assert summary["real_agent_framework_runtime_rows"] == 2
    assert summary["production_deployment_rows"] == 0
    assert summary["crewai_kickoff_completed"] is True
    assert rows[0]["proof_verified_rate"] == 1.0
    assert (tmp_path / "e_b13_paper_a_agent_system_bridge.csv").exists()
    assert (tmp_path / "e_b13_aggregate.csv").exists()
    assert (tmp_path / "e_b13_summary.json").exists()
    assert "Production deployment rows: 0" in (tmp_path / "e_b13_report.md").read_text()


def test_e_b14_multiprocess_deployment_persists_log_and_reports(tmp_path) -> None:
    rows = run_e_b14_multiprocess_deployment(
        seeds=(0,),
        n_parties_values=(2,),
        protocol_profiles=("raw-http-json",),
        fault_scenarios=("push-drop-log-repair",),
        tool_call_rates=(1.0,),
        output_dir=tmp_path,
    )
    summary = summarize_e_b14(rows)
    write_e_b14_outputs(rows, tmp_path, run_config={"n_parties_values": (2,)})

    assert len(rows) == 1
    assert rows[0]["experiment"] == "E-B14"
    assert rows[0]["separate_os_processes_numeric"] == 1.0
    assert rows[0]["persistent_log_records"] >= 1
    assert rows[0]["post_repair_reject_rate"] == 1.0
    assert summary["persistent_log_rate"] == 1.0
    assert (tmp_path / "e_b14_multiprocess_deployment.csv").exists()
    assert (tmp_path / "e_b14_aggregate.csv").exists()
    assert (tmp_path / "e_b14_summary.json").exists()
    assert (tmp_path / "e_b14_report.md").exists()


def test_e_b15_real_agent_tool_paths_validate_mcp_and_langgraph(tmp_path) -> None:
    rows = run_e_b15_real_agent_tool_path(
        seeds=(0,),
        n_parties_values=(2,),
        path_profiles=("mcp-python-tools-call", "langgraph-stategraph-tool-call"),
        fault_scenarios=("none",),
        tool_call_rates=(1.0,),
    )
    by_path = {row["path_profile"]: row for row in rows}
    summary = summarize_e_b15(rows)
    write_e_b15_outputs(rows, tmp_path, run_config={"path_profiles": tuple(by_path)})

    assert set(by_path) == {"mcp-python-tools-call", "langgraph-stategraph-tool-call"}
    assert by_path["mcp-python-tools-call"]["mcp_calltool_request_validated_numeric"] == 1.0
    assert by_path["langgraph-stategraph-tool-call"]["langgraph_workflow_completed_numeric"] == 1.0
    assert summary["integration_success_rate"] == 1.0
    assert (tmp_path / "e_b15_real_agent_tool_path.csv").exists()
    assert (tmp_path / "e_b15_aggregate.csv").exists()
    assert (tmp_path / "e_b15_summary.json").exists()
    assert (tmp_path / "e_b15_report.md").exists()


def test_e_b16_status_outage_baselines_separate_safety_and_availability(tmp_path) -> None:
    rows = run_e_b16_status_outage_baselines(
        seeds=(0,),
        n_parties_values=(2,),
        strategies=("sync-fail-closed", "sync-fail-open", "sync-status-cache-ttl", "revprop-hybrid"),
        fault_scenarios=("status-outage",),
        tool_call_rates=(1.0,),
        outage_duration=2.0,
    )
    by_strategy = {row["strategy"]: row for row in rows}
    summary = summarize_e_b16(rows)
    write_e_b16_outputs(rows, tmp_path, run_config={"fault_scenarios": ("status-outage",)})

    assert by_strategy["sync-fail-closed"]["availability_loss_rate"] == 1.0
    assert by_strategy["sync-fail-closed"]["stale_capability_window_max"] == 0.0
    assert by_strategy["sync-fail-open"]["availability_loss_rate"] == 0.0
    assert by_strategy["sync-fail-open"]["stale_capability_window_max"] == 2.0
    assert by_strategy["sync-status-cache-ttl"]["stale_capability_window_max"] == 60.0
    assert by_strategy["revprop-hybrid"]["stale_capability_window_max"] < 1.0
    assert summary["max_availability_loss_rate"] == 1.0
    assert (tmp_path / "e_b16_status_outage_baselines.csv").exists()
    assert (tmp_path / "e_b16_aggregate.csv").exists()
    assert (tmp_path / "e_b16_summary.json").exists()
    assert (tmp_path / "e_b16_report.md").exists()


def test_all_experiments_smoke_profile_covers_thirteen_tracks() -> None:
    results = run_all_experiments(profile="smoke")

    assert set(results) == {
        "e_b1_byzantine_sweep",
        "e_b2_delta_prop_baselines",
        "e_b3_damage_budget",
        "e_b4_equivocation_resistance",
        "e_b5_thin_a2a",
        "e_b6_local_e2e",
        "e_b7_reproducibility_sensitivity",
        "e_b8_agent_tool_gateway",
        "e_b9_a2a_lifecycle_binding",
        "e_b10_real_gateway_tool_path",
        "e_b11_protocol_boundary_path",
        "e_b12_fault_injection_path",
        "e_b17_p0_matched_baselines",
    }
    assert all(results[name] for name in results)


def _write_json(path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data) + "\n")
