"""Command-line entry point for Paper B experiment tracks."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .experiment_suite import (
    AGENT_TOOL_PATH_PROFILES,
    BASELINE_STRATEGIES,
    DELIVERY_REGIMES,
    STATUS_BASELINE_STRATEGIES,
    STATUS_FAULT_SCENARIOS,
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
    stream_rows_csv,
    write_experiment_bundle,
    write_e_b1_outputs,
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
    write_rows_csv,
)
from .propagator import PropagationStrategy
from .matched_baseline_harness import (
    P0_FAULT_SCENARIOS,
    P0_MECHANISMS,
    P0_PROFILES,
    P0_SUPPRESSION_VALUES,
    run_e_b17_p0_matched_baselines,
    write_e_b17_outputs,
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Paper B revocation propagation experiments.")
    parser.add_argument(
        "--experiment",
        choices=(
            "all",
            "e-b1",
            "e-b2",
            "e-b3",
            "e-b4",
            "e-b5",
            "e-b6",
            "e-b7",
            "e-b8",
            "e-b9",
            "e-b10",
            "e-b11",
            "e-b12",
            "e-b13",
            "e-b14",
            "e-b15",
            "e-b16",
            "e-b17",
        ),
        default="all",
    )
    parser.add_argument("--profile", choices=("smoke", "paper"), default="smoke")
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--json", action="store_true", help="Print JSON to stdout instead of CSV paths.")
    parser.add_argument("--seeds", default=None, help="Seed list or range, e.g. '0,1,2' or '0:30'.")
    parser.add_argument("--n-parties", default=None, help="Party-count list, e.g. '100,1000'.")
    parser.add_argument("--strategies", default=None, help="Comma-separated strategies for E-B2.")
    parser.add_argument("--delivery-regimes", default=None, help="Comma-separated related-work delivery regimes for E-B2.")
    parser.add_argument("--push-suppression", type=float, default=None)
    parser.add_argument("--gossip-suppression", type=float, default=None)
    parser.add_argument("--log-suppression", type=float, default=None)
    parser.add_argument("--status-suppression", type=float, default=None)
    parser.add_argument("--status-suppression-grid", default=None, help="Comma-separated E-B2 status-service suppression values.")
    parser.add_argument("--snapshot-period", type=float, default=None, help="E-B2 full-snapshot publication period.")
    parser.add_argument("--delta-interval", type=float, default=None, help="E-B2 compact-delta publication interval.")
    parser.add_argument("--dns-poll-interval", type=float, default=None, help="E-B2 DNS/log polling interval.")
    parser.add_argument("--request-time-latency", type=float, default=None, help="E-B2 request-time status-check latency.")
    parser.add_argument("--push-suppression-grid", default=None, help="Comma-separated E-B1 push suppression values.")
    parser.add_argument("--gossip-suppression-grid", default=None, help="Comma-separated E-B1 gossip suppression values.")
    parser.add_argument("--log-suppression-grid", default=None, help="Comma-separated E-B1 log suppression values.")
    parser.add_argument("--ttl", type=float, default=None)
    parser.add_argument("--ttl-grid", default=None, help="Comma-separated E-B3 TTL values.")
    parser.add_argument("--velocity", type=float, default=None)
    parser.add_argument("--velocity-grid", default=None, help="Comma-separated E-B3 velocity values.")
    parser.add_argument("--budget", type=float, default=None)
    parser.add_argument("--budget-grid", default=None, help="Comma-separated E-B3 budget thresholds.")
    parser.add_argument("--measured-csv", default=None, help="Measured E-B2/E-B1 raw CSV to use as E-B3 input.")
    parser.add_argument("--root-counts", default=None, help="Comma-separated E-B4 root counts.")
    parser.add_argument("--thresholds", default=None, help="Comma-separated E-B4 threshold values.")
    parser.add_argument("--observation-delay-grid", default=None, help="Comma-separated E-B4 STH observation delays.")
    parser.add_argument("--partition-heal-grid", default=None, help="Comma-separated E-B4 partition heal delays.")
    parser.add_argument("--watcher-counts", default=None, help="Comma-separated E-B4 watcher counts.")
    parser.add_argument("--watcher-coverage-grid", default=None, help="Comma-separated E-B4 watcher coverage fractions.")
    parser.add_argument("--watcher-observation-interval-grid", default=None, help="Comma-separated E-B4 watcher observation intervals.")
    parser.add_argument("--party-reporting-fraction-grid", default=None, help="Comma-separated E-B4 party reporting fractions.")
    parser.add_argument("--selective-disclosure-grid", default=None, help="Comma-separated E-B4 selective-disclosure fractions.")
    parser.add_argument("--watcher-partition-duration-grid", default=None, help="Comma-separated E-B4 watcher partition durations.")
    parser.add_argument("--transport-mode", default=None, help="E-B5 transport mode label.")
    parser.add_argument("--duration", type=float, default=None, help="E-B6 local transport run duration.")
    parser.add_argument("--fanout-grid", default=None, help="Comma-separated E-B7 gossip fanout values.")
    parser.add_argument("--poll-interval-grid", default=None, help="Comma-separated E-B7 poll interval values.")
    parser.add_argument("--jitter-grid", default=None, help="Comma-separated E-B7 jitter values.")
    parser.add_argument("--delay-scale-grid", default=None, help="Comma-separated E-B7 delay scale values.")
    parser.add_argument("--tool-call-rate", type=float, default=None, help="E-B8 expected revoked tool calls per gateway per second.")
    parser.add_argument("--tool-call-rate-grid", default=None, help="Comma-separated E-B8 tool-call rates.")
    parser.add_argument("--agent-task-duration", type=float, default=None, help="E-B8 post-revocation task window.")
    parser.add_argument("--tool-name", default=None, help="E-B8 delegated tool name.")
    parser.add_argument("--a2a-compatibility-cells", default=None, help="Comma-separated E-B9 A2A compatibility cells.")
    parser.add_argument("--fallback-policy", choices=("fail-closed", "allow-ttl"), default=None, help="E-B9 behavior when a new client sees an old server.")
    parser.add_argument("--protocol-profiles", default=None, help="Comma-separated E-B10/E-B11/E-B12 protocol profiles.")
    parser.add_argument("--fault-scenarios", default=None, help="Comma-separated E-B10/E-B12 fault scenarios.")
    parser.add_argument("--partition-duration", type=float, default=None, help="E-B12 partition duration before log repair.")
    parser.add_argument("--gateway-restart-at", type=float, default=None, help="E-B12 gateway restart time.")
    parser.add_argument("--log-delay", type=float, default=None, help="E-B10/E-B12 extra log repair delay.")
    parser.add_argument("--paper-a-experiments-dir", default=None, help="Paper A experiments directory for E-B13.")
    parser.add_argument("--agent-path-profiles", default=None, help="Comma-separated E-B15 agent path profiles.")
    parser.add_argument(
        "--status-baseline-strategies",
        default=None,
        help="Comma-separated E-B16 synchronous status baseline strategies.",
    )
    parser.add_argument("--status-fault-scenarios", default=None, help="Comma-separated E-B16 status fault scenarios.")
    parser.add_argument("--status-latency", type=float, default=None, help="E-B16 status-check latency.")
    parser.add_argument("--outage-duration", type=float, default=None, help="E-B16 outage duration.")
    parser.add_argument("--p0-profiles", default=None, help="Comma-separated E-B17 profiles.")
    parser.add_argument("--p0-mechanisms", default=None, help="Comma-separated E-B17 mechanisms.")
    parser.add_argument("--p0-suppression-grid", default=None, help="Comma-separated E-B17 suppression fractions.")
    parser.add_argument("--bootstrap-samples", type=int, default=None, help="E-B17 paired bootstrap resamples.")
    parser.add_argument("--max-time", type=float, default=None)
    parser.add_argument("--push-delay", type=float, default=None)
    parser.add_argument("--gossip-delay", type=float, default=None)
    parser.add_argument("--gossip-interval", type=float, default=None)
    parser.add_argument("--poll-interval", type=float, default=None)
    parser.add_argument("--log-append-delay", type=float, default=None)
    parser.add_argument("--jitter", type=float, default=None)
    parser.add_argument("--gossip-fanout", type=int, default=None)
    parser.add_argument("--stream", action="store_true", help="Stream rows to CSV as each run finishes.")
    parser.add_argument("--resume", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--no-report", action="store_true", help="Only write raw CSV for single-experiment outputs.")
    args = parser.parse_args()

    options = _options_from_args(args)
    if args.experiment == "e-b1" and args.stream and args.output_dir is not None and not args.json:
        _run_e_b1_streaming(args.profile, Path(args.output_dir), options, resume=args.resume, report=not args.no_report)
        return

    results = _run_selected(args.experiment, args.profile, options)
    if args.json or args.output_dir is None:
        print(json.dumps(results, indent=2, sort_keys=True))
        return

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    if args.experiment == "all":
        write_experiment_bundle(results, output_dir)
    else:
        rows = next(iter(results.values()))
        if args.experiment == "e-b1" and not args.no_report:
            write_e_b1_outputs(rows, output_dir, run_config=options)
        elif args.experiment == "e-b2" and not args.no_report:
            write_e_b2_outputs(rows, output_dir, run_config=options)
        elif args.experiment == "e-b3" and not args.no_report:
            write_e_b3_outputs(rows, output_dir, run_config=options)
        elif args.experiment == "e-b4" and not args.no_report:
            write_e_b4_outputs(rows, output_dir, run_config=options)
        elif args.experiment == "e-b5" and not args.no_report:
            write_e_b5_outputs(rows, output_dir, run_config=options)
        elif args.experiment == "e-b6" and not args.no_report:
            write_e_b6_outputs(rows, output_dir, run_config=options)
        elif args.experiment == "e-b7" and not args.no_report:
            write_e_b7_outputs(rows, output_dir, run_config=options)
        elif args.experiment == "e-b8" and not args.no_report:
            write_e_b8_outputs(rows, output_dir, run_config=options)
        elif args.experiment == "e-b9" and not args.no_report:
            write_e_b9_outputs(rows, output_dir, run_config=options)
        elif args.experiment == "e-b10" and not args.no_report:
            write_e_b10_outputs(rows, output_dir, run_config=options)
        elif args.experiment == "e-b11" and not args.no_report:
            write_e_b11_outputs(rows, output_dir, run_config=options)
        elif args.experiment == "e-b12" and not args.no_report:
            write_e_b12_outputs(rows, output_dir, run_config=options)
        elif args.experiment == "e-b13" and not args.no_report:
            write_e_b13_outputs(rows, output_dir, run_config=options)
        elif args.experiment == "e-b14" and not args.no_report:
            write_e_b14_outputs(rows, output_dir, run_config=options)
        elif args.experiment == "e-b15" and not args.no_report:
            write_e_b15_outputs(rows, output_dir, run_config=options)
        elif args.experiment == "e-b16" and not args.no_report:
            write_e_b16_outputs(rows, output_dir, run_config=options)
        elif args.experiment == "e-b17" and not args.no_report:
            write_e_b17_outputs(
                rows,
                output_dir,
                run_config=options,
                bootstrap_samples=int(options.get("bootstrap_samples", 10_000)),
            )
        else:
            write_rows_csv(rows, output_dir / f"{args.experiment}.csv")


def _run_selected(
    experiment: str,
    profile: str,
    options: dict[str, object] | None = None,
) -> dict[str, list[dict[str, object]]]:
    options = options or {}
    if experiment == "all":
        return run_all_experiments(profile=profile)
    if experiment == "e-b13":
        return {
            "e_b13_paper_a_agent_system_bridge": run_e_b13_paper_a_agent_system_bridge(
                paper_a_experiments_dir=options.get("paper_a_experiments_dir")
            )
        }
    if profile == "paper":
        seeds = tuple(range(30))
        n_parties_values = (1000,)
    else:
        seeds = (0, 1, 2)
        n_parties_values = (40,)

    seeds = tuple(options.get("seeds", seeds))
    n_parties_values = tuple(options.get("n_parties_values", n_parties_values))
    n_parties = int(n_parties_values[0])

    if experiment == "e-b1":
        rows: list[dict[str, object]] = []
        for n_value in n_parties_values:
            rows.extend(
                run_e_b1_byzantine_sweep(
                    seeds=seeds,
                    n_parties=int(n_value),
                    push_suppression_values=tuple(options.get("push_suppression_values", (0.0, 0.2, 0.4))),
                    gossip_suppression_values=tuple(options.get("gossip_suppression_values", (0.0, 0.1))),
                    log_suppression_values=tuple(options.get("log_suppression_values", (0.0, 0.1))),
                    ttl=float(options.get("ttl", 60.0)),
                    velocity=float(options.get("velocity", 10.0)),
                    max_time=float(options.get("max_time", 8.0)),
                    push_delay=float(options.get("push_delay", 0.05)),
                    gossip_delay=float(options.get("gossip_delay", 0.10)),
                    gossip_interval=float(options.get("gossip_interval", 0.25)),
                    poll_interval=float(options.get("poll_interval", 0.50)),
                    log_append_delay=float(options.get("log_append_delay", 0.05)),
                    jitter=float(options.get("jitter", 0.20)),
                    gossip_fanout=options.get("gossip_fanout"),
                )
            )
        return {"e_b1_byzantine_sweep": rows}
    if experiment == "e-b2":
        rows: list[dict[str, object]] = []
        for n_value in n_parties_values:
            rows.extend(
                run_e_b2_delta_prop_baselines(
                    seeds=seeds,
                    n_parties=int(n_value),
                    ttl=float(options.get("ttl", 60.0)),
                    velocity=float(options.get("velocity", 10.0)),
                    push_suppression=float(options.get("push_suppression", 0.2)),
                    gossip_suppression=float(options.get("gossip_suppression", 0.0)),
                    log_suppression=float(options.get("log_suppression", 0.0)),
                    max_time=float(options.get("max_time", 8.0)),
                    push_delay=float(options.get("push_delay", 0.05)),
                    gossip_delay=float(options.get("gossip_delay", 0.10)),
                    gossip_interval=float(options.get("gossip_interval", 0.25)),
                    poll_interval=float(options.get("poll_interval", 0.50)),
                    log_append_delay=float(options.get("log_append_delay", 0.05)),
                    jitter=float(options.get("jitter", 0.20)),
                    gossip_fanout=options.get("gossip_fanout"),
                    strategies=tuple(options.get("strategies", BASELINE_STRATEGIES)),
                    delivery_regimes=options.get("delivery_regimes"),
                    status_suppression_values=tuple(options.get("status_suppression_values", (0.0,))),
                    snapshot_period=float(options.get("snapshot_period", 300.0)),
                    delta_interval=float(options.get("delta_interval", 30.0)),
                    dns_poll_interval=float(options.get("dns_poll_interval", 60.0)),
                    request_time_latency=float(options.get("request_time_latency", 0.05)),
                )
            )
        return {"e_b2_delta_prop_baselines": rows}
    if experiment == "e-b3":
        measured_csv = options.get("measured_csv")
        if measured_csv is not None:
            measured = read_rows_csv(Path(str(measured_csv)))
        else:
            measured = []
            for n_value in n_parties_values:
                measured.extend(
                    run_e_b2_delta_prop_baselines(
                        seeds=seeds,
                        n_parties=int(n_value),
                        ttl=float(options.get("ttl", 60.0)),
                        velocity=float(options.get("velocity", 10.0)),
                        push_suppression=float(options.get("push_suppression", 0.2)),
                        gossip_suppression=float(options.get("gossip_suppression", 0.0)),
                        log_suppression=float(options.get("log_suppression", 0.0)),
                        max_time=float(options.get("max_time", 8.0)),
                        push_delay=float(options.get("push_delay", 0.05)),
                        gossip_delay=float(options.get("gossip_delay", 0.10)),
                        gossip_interval=float(options.get("gossip_interval", 0.25)),
                        poll_interval=float(options.get("poll_interval", 0.50)),
                        log_append_delay=float(options.get("log_append_delay", 0.05)),
                        jitter=float(options.get("jitter", 0.20)),
                        gossip_fanout=options.get("gossip_fanout"),
                        strategies=tuple(options.get("strategies", BASELINE_STRATEGIES)),
                        delivery_regimes=options.get("delivery_regimes"),
                        status_suppression_values=tuple(options.get("status_suppression_values", (0.0,))),
                        snapshot_period=float(options.get("snapshot_period", 300.0)),
                        delta_interval=float(options.get("delta_interval", 30.0)),
                        dns_poll_interval=float(options.get("dns_poll_interval", 60.0)),
                        request_time_latency=float(options.get("request_time_latency", 0.05)),
                    )
                )
        return {
            "e_b3_damage_budget": run_e_b3_damage_budget(
                measured_rows=measured,
                ttls=tuple(options.get("ttls", (10.0, 60.0, 300.0))),
                velocities=tuple(options.get("velocities", (1.0, 10.0, 100.0))),
                budgets=tuple(options.get("budgets", (float(options.get("budget", 1000.0)),))),
            )
        }
    if experiment == "e-b4":
        return {
            "e_b4_equivocation_resistance": run_e_b4_equivocation_resistance(
                seeds=seeds,
                root_counts=tuple(options.get("root_counts", (5,))),
                thresholds=tuple(options.get("thresholds", (3,))),
                observation_delays=tuple(options.get("observation_delays", (0.55,))),
                partition_heal_delays=tuple(options.get("partition_heal_delays", ())),
                watcher_counts=tuple(options.get("watcher_counts", ())),
                watcher_coverages=tuple(options.get("watcher_coverages", ())),
                watcher_observation_intervals=tuple(options.get("watcher_observation_intervals", ())),
                party_reporting_fractions=tuple(options.get("party_reporting_fractions", (1.0,))),
                selective_disclosure_values=tuple(options.get("selective_disclosure_values", (0.0,))),
                watcher_partition_durations=tuple(options.get("watcher_partition_durations", (0.0,))),
            )
        }
    if experiment == "e-b5":
        return {
            "e_b5_thin_a2a": run_e_b5_thin_a2a(
                seeds=seeds,
                n_parties_values=n_parties_values,
                strategies=tuple(options.get("strategies", ("push", "log", "hybrid"))),
                transport_mode=str(options.get("transport_mode", "local-a2a-shaped-json")),
            )
        }
    if experiment == "e-b6":
        return {
            "e_b6_local_e2e": run_e_b6_local_end_to_end(
                seeds=seeds,
                n_parties_values=n_parties_values,
                strategies=tuple(options.get("strategies", ("push", "log", "push-gossip", "hybrid"))),
                push_suppression=float(options.get("push_suppression", 0.2)),
                gossip_suppression=float(options.get("gossip_suppression", 0.0)),
                log_suppression=float(options.get("log_suppression", 0.0)),
                duration=float(options.get("duration", 1.5)),
                push_delay=float(options.get("push_delay", 0.02)),
                gossip_interval=float(options.get("gossip_interval", 0.10)),
                poll_interval=float(options.get("poll_interval", 0.15)),
                gossip_fanout=int(options.get("gossip_fanout", 4)),
            )
        }
    if experiment == "e-b7":
        return {
            "e_b7_reproducibility_sensitivity": run_e_b7_reproducibility_sensitivity(
                seeds=seeds,
                n_parties_values=n_parties_values,
                fanout_values=tuple(options.get("fanout_values", (4, 8, 16))),
                poll_interval_values=tuple(options.get("poll_interval_values", (0.25, 0.50, 1.0))),
                jitter_values=tuple(options.get("jitter_values", (0.0, 0.20, 0.40))),
                delay_scale_values=tuple(options.get("delay_scale_values", (0.5, 1.0, 2.0))),
                push_suppression=float(options.get("push_suppression", 0.2)),
                max_time=float(options.get("max_time", 8.0)),
            )
        }
    if experiment == "e-b8":
        return {
            "e_b8_agent_tool_gateway": run_e_b8_agent_tool_gateway(
                seeds=seeds,
                n_parties_values=n_parties_values,
                strategies=tuple(options.get("strategies", ("push", "ttl-rcc", "push-gossip", "log", "hybrid"))),
                tool_call_rates=tuple(options.get("tool_call_rates", (1.0, 10.0))),
                ttl=float(options.get("ttl", 60.0)),
                task_duration=float(options.get("task_duration", 60.0)),
                push_suppression=float(options.get("push_suppression", 0.2)),
                gossip_suppression=float(options.get("gossip_suppression", 0.0)),
                log_suppression=float(options.get("log_suppression", 0.0)),
                max_time=float(options.get("max_time", 8.0)),
                push_delay=float(options.get("push_delay", 0.05)),
                gossip_delay=float(options.get("gossip_delay", 0.10)),
                gossip_interval=float(options.get("gossip_interval", 0.25)),
                poll_interval=float(options.get("poll_interval", 0.50)),
                log_append_delay=float(options.get("log_append_delay", 0.05)),
                jitter=float(options.get("jitter", 0.20)),
                gossip_fanout=options.get("gossip_fanout"),
                tool_name=str(options.get("tool_name", "repo-write")),
            )
        }
    if experiment == "e-b9":
        return {
            "e_b9_a2a_lifecycle_binding": run_e_b9_a2a_lifecycle_binding(
                seeds=seeds,
                n_parties_values=n_parties_values,
                compatibility_cells=tuple(
                    options.get(
                        "a2a_compatibility_cells",
                        (
                            "new-client-new-server",
                            "new-client-old-server",
                            "old-client-new-server",
                            "old-client-old-server",
                        ),
                    )
                ),
                strategy=tuple(options.get("strategies", ("hybrid",)))[0],
                tool_call_rates=tuple(options.get("tool_call_rates", (1.0, 10.0))),
                ttl=float(options.get("ttl", 60.0)),
                task_duration=float(options.get("task_duration", 60.0)),
                push_suppression=float(options.get("push_suppression", 0.2)),
                gossip_suppression=float(options.get("gossip_suppression", 0.0)),
                log_suppression=float(options.get("log_suppression", 0.0)),
                max_time=float(options.get("max_time", 8.0)),
                push_delay=float(options.get("push_delay", 0.05)),
                gossip_delay=float(options.get("gossip_delay", 0.10)),
                gossip_interval=float(options.get("gossip_interval", 0.25)),
                poll_interval=float(options.get("poll_interval", 0.50)),
                log_append_delay=float(options.get("log_append_delay", 0.05)),
                jitter=float(options.get("jitter", 0.20)),
                gossip_fanout=options.get("gossip_fanout"),
                fallback_policy=str(options.get("fallback_policy", "fail-closed")),
                request_time_latency=float(options.get("request_time_latency", 0.05)),
                tool_name=str(options.get("tool_name", "repo-write")),
            )
        }
    if experiment == "e-b10":
        integration_seeds = tuple(options.get("seeds", tuple(range(10)) if profile == "paper" else (0, 1)))
        integration_n_parties_values = tuple(options.get("n_parties_values", (30,) if profile == "paper" else (5,)))
        return {
            "e_b10_real_gateway_tool_path": run_e_b10_real_gateway_tool_path(
                seeds=integration_seeds,
                n_parties_values=integration_n_parties_values,
                protocol_profiles=tuple(options.get("protocol_profiles", ("raw-http-json",))),
                fault_scenarios=tuple(options.get("fault_scenarios", ("none", "push-drop-log-repair"))),
                tool_call_rates=tuple(options.get("tool_call_rates", (1.0, 10.0))),
                ttl=float(options.get("ttl", 60.0)),
                task_duration=float(options.get("task_duration", 60.0)),
                push_delay=float(options.get("push_delay", 0.05)),
                poll_interval=float(options.get("poll_interval", 0.50)),
                log_append_delay=float(options.get("log_append_delay", 0.05)),
                log_delay=float(options.get("log_delay", 0.0)),
                jitter=float(options.get("jitter", 0.20)),
                partition_duration=float(options.get("partition_duration", 2.0)),
                gateway_restart_at=float(options.get("gateway_restart_at", 0.25)),
                tool_name=str(options.get("tool_name", "repo-write")),
            )
        }
    if experiment == "e-b11":
        integration_seeds = tuple(options.get("seeds", tuple(range(10)) if profile == "paper" else (0, 1)))
        integration_n_parties_values = tuple(options.get("n_parties_values", (30,) if profile == "paper" else (5,)))
        return {
            "e_b11_protocol_boundary_path": run_e_b11_protocol_boundary_path(
                seeds=integration_seeds,
                n_parties_values=integration_n_parties_values,
                protocol_profiles=tuple(
                    options.get("protocol_profiles", ("raw-http-json", "mcp-style-jsonrpc", "a2a-task-lifecycle"))
                ),
                fault_scenarios=tuple(options.get("fault_scenarios", ("none",))),
                tool_call_rates=tuple(options.get("tool_call_rates", (1.0, 10.0))),
                ttl=float(options.get("ttl", 60.0)),
                task_duration=float(options.get("task_duration", 60.0)),
                push_delay=float(options.get("push_delay", 0.05)),
                poll_interval=float(options.get("poll_interval", 0.50)),
                log_append_delay=float(options.get("log_append_delay", 0.05)),
                log_delay=float(options.get("log_delay", 0.0)),
                jitter=float(options.get("jitter", 0.20)),
                partition_duration=float(options.get("partition_duration", 2.0)),
                gateway_restart_at=float(options.get("gateway_restart_at", 0.25)),
                tool_name=str(options.get("tool_name", "repo-write")),
            )
        }
    if experiment == "e-b12":
        integration_seeds = tuple(options.get("seeds", tuple(range(10)) if profile == "paper" else (0, 1)))
        integration_n_parties_values = tuple(options.get("n_parties_values", (30,) if profile == "paper" else (5,)))
        return {
            "e_b12_fault_injection_path": run_e_b12_fault_injection_path(
                seeds=integration_seeds,
                n_parties_values=integration_n_parties_values,
                protocol_profiles=tuple(options.get("protocol_profiles", ("raw-http-json",))),
                fault_scenarios=tuple(
                    options.get(
                        "fault_scenarios",
                        ("push-drop-log-repair", "log-delay", "partition-heal", "gateway-restart"),
                    )
                ),
                tool_call_rates=tuple(options.get("tool_call_rates", (1.0, 10.0))),
                ttl=float(options.get("ttl", 60.0)),
                task_duration=float(options.get("task_duration", 60.0)),
                push_delay=float(options.get("push_delay", 0.05)),
                poll_interval=float(options.get("poll_interval", 0.50)),
                log_append_delay=float(options.get("log_append_delay", 0.05)),
                log_delay=float(options.get("log_delay", 1.0)),
                jitter=float(options.get("jitter", 0.20)),
                partition_duration=float(options.get("partition_duration", 2.0)),
                gateway_restart_at=float(options.get("gateway_restart_at", 0.25)),
                tool_name=str(options.get("tool_name", "repo-write")),
            )
        }
    if experiment == "e-b14":
        integration_seeds = tuple(options.get("seeds", tuple(range(5)) if profile == "paper" else (0, 1)))
        integration_n_parties_values = tuple(options.get("n_parties_values", (8,) if profile == "paper" else (3,)))
        return {
            "e_b14_multiprocess_deployment": run_e_b14_multiprocess_deployment(
                seeds=integration_seeds,
                n_parties_values=integration_n_parties_values,
                protocol_profiles=tuple(options.get("protocol_profiles", ("raw-http-json",))),
                fault_scenarios=tuple(options.get("fault_scenarios", ("none", "push-drop-log-repair"))),
                tool_call_rates=tuple(options.get("tool_call_rates", (1.0, 10.0))),
                ttl=float(options.get("ttl", 60.0)),
                task_duration=float(options.get("task_duration", 60.0)),
                push_delay=float(options.get("push_delay", 0.05)),
                poll_interval=float(options.get("poll_interval", 0.50)),
                log_append_delay=float(options.get("log_append_delay", 0.05)),
                log_delay=float(options.get("log_delay", 0.0)),
                jitter=float(options.get("jitter", 0.20)),
                partition_duration=float(options.get("partition_duration", 2.0)),
                gateway_restart_at=float(options.get("gateway_restart_at", 0.25)),
                tool_name=str(options.get("tool_name", "repo-write")),
                output_dir=options.get("output_dir"),
            )
        }
    if experiment == "e-b15":
        integration_seeds = tuple(options.get("seeds", tuple(range(10)) if profile == "paper" else (0, 1)))
        integration_n_parties_values = tuple(options.get("n_parties_values", (30,) if profile == "paper" else (3,)))
        return {
            "e_b15_real_agent_tool_path": run_e_b15_real_agent_tool_path(
                seeds=integration_seeds,
                n_parties_values=integration_n_parties_values,
                path_profiles=tuple(options.get("agent_path_profiles", AGENT_TOOL_PATH_PROFILES)),
                fault_scenarios=tuple(options.get("fault_scenarios", ("none", "push-drop-log-repair"))),
                tool_call_rates=tuple(options.get("tool_call_rates", (1.0, 10.0))),
                ttl=float(options.get("ttl", 60.0)),
                task_duration=float(options.get("task_duration", 60.0)),
                tool_name=str(options.get("tool_name", "repo-write")),
            )
        }
    if experiment == "e-b16":
        status_seeds = tuple(options.get("seeds", tuple(range(10)) if profile == "paper" else (0, 1)))
        status_n_parties_values = tuple(options.get("n_parties_values", (30,) if profile == "paper" else (3,)))
        return {
            "e_b16_status_outage_baselines": run_e_b16_status_outage_baselines(
                seeds=status_seeds,
                n_parties_values=status_n_parties_values,
                strategies=tuple(options.get("status_baseline_strategies", STATUS_BASELINE_STRATEGIES)),
                fault_scenarios=tuple(options.get("status_fault_scenarios", STATUS_FAULT_SCENARIOS)),
                tool_call_rates=tuple(options.get("tool_call_rates", (1.0, 10.0))),
                ttl=float(options.get("ttl", 60.0)),
                task_duration=float(options.get("task_duration", 60.0)),
                status_latency=float(options.get("status_latency", 0.05)),
                outage_duration=float(options.get("outage_duration", 2.0)),
            )
        }
    if experiment == "e-b17":
        return {
            "e_b17_p0_matched_baselines": run_e_b17_p0_matched_baselines(
                seeds=seeds,
                n_gateways_values=n_parties_values,
                profiles=tuple(options.get("p0_profiles", P0_PROFILES)),
                fault_scenarios=tuple(options.get("fault_scenarios", P0_FAULT_SCENARIOS)),
                suppression_values=tuple(options.get("p0_suppression_values", P0_SUPPRESSION_VALUES)),
                mechanisms=tuple(options.get("p0_mechanisms", P0_MECHANISMS)),
                horizon=float(options.get("task_duration", 60.0)),
                tool_call_rate=float(tuple(options.get("tool_call_rates", (10.0,)))[0]),
                ttl=float(options.get("ttl", 60.0)),
            )
        }
    raise ValueError(f"unknown experiment: {experiment}")


def _options_from_args(args: argparse.Namespace) -> dict[str, object]:
    options: dict[str, object] = {}
    if args.output_dir is not None:
        options["output_dir"] = args.output_dir
    if args.seeds is not None:
        options["seeds"] = _parse_int_list(args.seeds)
    if args.n_parties is not None:
        options["n_parties_values"] = _parse_int_list(args.n_parties)
    if args.strategies is not None:
        options["strategies"] = _parse_strategy_list(args.strategies)
    if args.delivery_regimes is not None:
        options["delivery_regimes"] = _parse_delivery_regime_list(args.delivery_regimes)
    if args.push_suppression_grid is not None:
        options["push_suppression_values"] = _parse_float_list(args.push_suppression_grid)
    if args.gossip_suppression_grid is not None:
        options["gossip_suppression_values"] = _parse_float_list(args.gossip_suppression_grid)
    if args.log_suppression_grid is not None:
        options["log_suppression_values"] = _parse_float_list(args.log_suppression_grid)
    if args.status_suppression_grid is not None:
        options["status_suppression_values"] = _parse_float_list(args.status_suppression_grid)
    elif args.status_suppression is not None:
        options["status_suppression_values"] = (args.status_suppression,)
    if args.snapshot_period is not None:
        options["snapshot_period"] = args.snapshot_period
    if args.delta_interval is not None:
        options["delta_interval"] = args.delta_interval
    if args.dns_poll_interval is not None:
        options["dns_poll_interval"] = args.dns_poll_interval
    if args.request_time_latency is not None:
        options["request_time_latency"] = args.request_time_latency
    if args.ttl_grid is not None:
        options["ttls"] = _parse_float_list(args.ttl_grid)
    elif args.ttl is not None:
        options["ttls"] = (args.ttl,)
    if args.velocity_grid is not None:
        options["velocities"] = _parse_float_list(args.velocity_grid)
    elif args.velocity is not None:
        options["velocities"] = (args.velocity,)
    if args.budget_grid is not None:
        options["budgets"] = _parse_float_list(args.budget_grid)
    elif args.budget is not None:
        options["budgets"] = (args.budget,)
    if args.measured_csv is not None:
        options["measured_csv"] = args.measured_csv
    if args.root_counts is not None:
        options["root_counts"] = _parse_int_list(args.root_counts)
    if args.thresholds is not None:
        options["thresholds"] = _parse_int_list(args.thresholds)
    if args.observation_delay_grid is not None:
        options["observation_delays"] = _parse_float_list(args.observation_delay_grid)
    if args.partition_heal_grid is not None:
        options["partition_heal_delays"] = _parse_float_list(args.partition_heal_grid)
    if args.watcher_counts is not None:
        options["watcher_counts"] = _parse_int_list(args.watcher_counts)
    if args.watcher_coverage_grid is not None:
        options["watcher_coverages"] = _parse_float_list(args.watcher_coverage_grid)
    if args.watcher_observation_interval_grid is not None:
        options["watcher_observation_intervals"] = _parse_float_list(args.watcher_observation_interval_grid)
    if args.party_reporting_fraction_grid is not None:
        options["party_reporting_fractions"] = _parse_float_list(args.party_reporting_fraction_grid)
    if args.selective_disclosure_grid is not None:
        options["selective_disclosure_values"] = _parse_float_list(args.selective_disclosure_grid)
    if args.watcher_partition_duration_grid is not None:
        options["watcher_partition_durations"] = _parse_float_list(args.watcher_partition_duration_grid)
    if args.transport_mode is not None:
        options["transport_mode"] = args.transport_mode
    if args.duration is not None:
        options["duration"] = args.duration
    if args.fanout_grid is not None:
        options["fanout_values"] = _parse_int_list(args.fanout_grid)
    if args.poll_interval_grid is not None:
        options["poll_interval_values"] = _parse_float_list(args.poll_interval_grid)
    if args.jitter_grid is not None:
        options["jitter_values"] = _parse_float_list(args.jitter_grid)
    if args.delay_scale_grid is not None:
        options["delay_scale_values"] = _parse_float_list(args.delay_scale_grid)
    if args.tool_call_rate_grid is not None:
        options["tool_call_rates"] = _parse_float_list(args.tool_call_rate_grid)
    elif args.tool_call_rate is not None:
        options["tool_call_rates"] = (args.tool_call_rate,)
    if args.agent_task_duration is not None:
        options["task_duration"] = args.agent_task_duration
    if args.tool_name is not None:
        options["tool_name"] = args.tool_name
    if args.a2a_compatibility_cells is not None:
        options["a2a_compatibility_cells"] = _parse_string_list(args.a2a_compatibility_cells)
    if args.fallback_policy is not None:
        options["fallback_policy"] = args.fallback_policy
    if args.protocol_profiles is not None:
        options["protocol_profiles"] = _parse_string_list(args.protocol_profiles)
    if args.fault_scenarios is not None:
        options["fault_scenarios"] = _parse_string_list(args.fault_scenarios)
    if args.partition_duration is not None:
        options["partition_duration"] = args.partition_duration
    if args.gateway_restart_at is not None:
        options["gateway_restart_at"] = args.gateway_restart_at
    if args.log_delay is not None:
        options["log_delay"] = args.log_delay
    if args.paper_a_experiments_dir is not None:
        options["paper_a_experiments_dir"] = args.paper_a_experiments_dir
    if args.agent_path_profiles is not None:
        options["agent_path_profiles"] = _parse_string_list(args.agent_path_profiles)
    if args.status_baseline_strategies is not None:
        options["status_baseline_strategies"] = _parse_string_list(args.status_baseline_strategies)
    if args.status_fault_scenarios is not None:
        options["status_fault_scenarios"] = _parse_string_list(args.status_fault_scenarios)
    if args.status_latency is not None:
        options["status_latency"] = args.status_latency
    if args.outage_duration is not None:
        options["outage_duration"] = args.outage_duration
    if args.p0_profiles is not None:
        options["p0_profiles"] = _parse_string_list(args.p0_profiles)
    if args.p0_mechanisms is not None:
        options["p0_mechanisms"] = _parse_string_list(args.p0_mechanisms)
    if args.p0_suppression_grid is not None:
        options["p0_suppression_values"] = _parse_float_list(args.p0_suppression_grid)
    if args.bootstrap_samples is not None:
        options["bootstrap_samples"] = args.bootstrap_samples
    for name in (
        "push_suppression",
        "gossip_suppression",
        "log_suppression",
        "status_suppression",
        "ttl",
        "velocity",
        "budget",
        "max_time",
        "push_delay",
        "gossip_delay",
        "gossip_interval",
        "poll_interval",
        "log_append_delay",
        "jitter",
    ):
        value = getattr(args, name)
        if value is not None:
            options[name] = value
    if args.gossip_fanout is not None:
        options["gossip_fanout"] = args.gossip_fanout
    if args.profile == "paper":
        options.setdefault("seeds", tuple(range(30)))
        options.setdefault("n_parties_values", (1000,))
        if args.experiment == "e-b1":
            options.setdefault("push_suppression_values", (0.0, 0.1, 0.2, 0.4, 0.6))
            options.setdefault("gossip_suppression_values", (0.0, 0.1, 0.2))
            options.setdefault("log_suppression_values", (0.0, 0.1, 0.2))
        if args.experiment == "e-b2":
            options.setdefault("delivery_regimes", DELIVERY_REGIMES)
            options.setdefault("status_suppression_values", (0.0, 0.2, 0.5))
            options.setdefault("snapshot_period", 300.0)
            options.setdefault("delta_interval", 30.0)
            options.setdefault("dns_poll_interval", 60.0)
            options.setdefault("request_time_latency", 0.05)
        if args.experiment == "e-b3":
            options.setdefault("ttls", (10.0, 30.0, 60.0, 300.0, 3600.0))
            options.setdefault("velocities", (1.0, 10.0, 100.0, 1000.0))
            options.setdefault("budgets", (100.0, 1000.0, 10000.0))
        if args.experiment == "e-b4":
            options.setdefault("root_counts", (5,))
            options.setdefault("thresholds", (3,))
            options.setdefault("observation_delays", (0.25, 0.5, 1.0, 2.0))
            options.setdefault("partition_heal_delays", (0.5, 2.0, 5.0))
            options.setdefault("watcher_counts", (1, 2, 4, 8))
            options.setdefault("watcher_coverages", (0.25, 0.50, 0.75, 1.0))
            options.setdefault("watcher_observation_intervals", (0.25, 0.50, 1.0, 2.0))
            options.setdefault("party_reporting_fractions", (0.25, 0.50, 1.0))
            options.setdefault("selective_disclosure_values", (0.0, 0.25, 0.50))
            options.setdefault("watcher_partition_durations", (0.0, 2.0, 5.0))
        if args.experiment == "e-b5":
            options.setdefault("n_parties_values", (3, 10, 30))
            options.setdefault("strategies", ("push", "log", "hybrid"))
            options.setdefault("transport_mode", "local-a2a-shaped-json")
        if args.experiment == "e-b6":
            options.setdefault("seeds", tuple(range(10)))
            options.setdefault("n_parties_values", (10, 30, 100))
            options.setdefault("strategies", ("push", "log", "push-gossip", "hybrid"))
            options.setdefault("duration", 1.5)
            options.setdefault("gossip_fanout", 4)
        if args.experiment == "e-b7":
            options.setdefault("seeds", tuple(range(10)))
            options.setdefault("n_parties_values", (100, 300))
            options.setdefault("fanout_values", (4, 8, 16))
            options.setdefault("poll_interval_values", (0.25, 0.50, 1.0))
            options.setdefault("jitter_values", (0.0, 0.20, 0.40))
            options.setdefault("delay_scale_values", (0.5, 1.0, 2.0))
        if args.experiment == "e-b8":
            options.setdefault("seeds", tuple(range(30)))
            options.setdefault("n_parties_values", (1000,))
            options.setdefault("strategies", ("push", "ttl-rcc", "push-gossip", "log", "hybrid"))
            options.setdefault("tool_call_rates", (1.0, 10.0, 100.0))
            options.setdefault("ttl", 60.0)
            options.setdefault("task_duration", 60.0)
            options.setdefault("push_suppression", 0.2)
            options.setdefault("tool_name", "repo-write")
        if args.experiment == "e-b9":
            if args.seeds is None:
                options["seeds"] = tuple(range(30))
            if args.n_parties is None:
                options["n_parties_values"] = (300,)
            options.setdefault(
                "a2a_compatibility_cells",
                (
                    "new-client-new-server",
                    "new-client-old-server",
                    "old-client-new-server",
                    "old-client-old-server",
                ),
            )
            options.setdefault("tool_call_rates", (1.0, 10.0, 100.0))
            options.setdefault("ttl", 60.0)
            options.setdefault("task_duration", 60.0)
            options.setdefault("push_suppression", 0.2)
            options.setdefault("fallback_policy", "fail-closed")
            options.setdefault("tool_name", "repo-write")
        if args.experiment == "e-b10":
            if args.seeds is None:
                options["seeds"] = tuple(range(10))
            if args.n_parties is None:
                options["n_parties_values"] = (30,)
            options.setdefault("protocol_profiles", ("raw-http-json",))
            options.setdefault("fault_scenarios", ("none", "push-drop-log-repair"))
            options.setdefault("tool_call_rates", (1.0, 10.0))
            options.setdefault("ttl", 60.0)
            options.setdefault("task_duration", 60.0)
            options.setdefault("tool_name", "repo-write")
        if args.experiment == "e-b11":
            if args.seeds is None:
                options["seeds"] = tuple(range(10))
            if args.n_parties is None:
                options["n_parties_values"] = (30,)
            options.setdefault("protocol_profiles", ("raw-http-json", "mcp-style-jsonrpc", "a2a-task-lifecycle"))
            options.setdefault("fault_scenarios", ("none",))
            options.setdefault("tool_call_rates", (1.0, 10.0))
            options.setdefault("ttl", 60.0)
            options.setdefault("task_duration", 60.0)
            options.setdefault("tool_name", "repo-write")
        if args.experiment == "e-b12":
            if args.seeds is None:
                options["seeds"] = tuple(range(10))
            if args.n_parties is None:
                options["n_parties_values"] = (30,)
            options.setdefault("protocol_profiles", ("raw-http-json",))
            options.setdefault(
                "fault_scenarios",
                ("push-drop-log-repair", "log-delay", "partition-heal", "gateway-restart"),
            )
            options.setdefault("tool_call_rates", (1.0, 10.0))
            options.setdefault("ttl", 60.0)
            options.setdefault("task_duration", 60.0)
            options.setdefault("log_delay", 1.0)
            options.setdefault("partition_duration", 2.0)
            options.setdefault("gateway_restart_at", 0.25)
            options.setdefault("tool_name", "repo-write")
        if args.experiment == "e-b14":
            if args.seeds is None:
                options["seeds"] = tuple(range(5))
            if args.n_parties is None:
                options["n_parties_values"] = (8,)
            options.setdefault("protocol_profiles", ("raw-http-json",))
            options.setdefault("fault_scenarios", ("none", "push-drop-log-repair"))
            options.setdefault("tool_call_rates", (1.0, 10.0))
            options.setdefault("ttl", 60.0)
            options.setdefault("task_duration", 60.0)
            options.setdefault("tool_name", "repo-write")
        if args.experiment == "e-b15":
            if args.seeds is None:
                options["seeds"] = tuple(range(10))
            if args.n_parties is None:
                options["n_parties_values"] = (30,)
            options.setdefault("agent_path_profiles", AGENT_TOOL_PATH_PROFILES)
            options.setdefault("fault_scenarios", ("none", "push-drop-log-repair"))
            options.setdefault("tool_call_rates", (1.0, 10.0))
            options.setdefault("ttl", 60.0)
            options.setdefault("task_duration", 60.0)
            options.setdefault("tool_name", "repo-write")
        if args.experiment == "e-b16":
            if args.seeds is None:
                options["seeds"] = tuple(range(10))
            if args.n_parties is None:
                options["n_parties_values"] = (30,)
            options.setdefault("status_baseline_strategies", STATUS_BASELINE_STRATEGIES)
            options.setdefault("status_fault_scenarios", STATUS_FAULT_SCENARIOS)
            options.setdefault("tool_call_rates", (1.0, 10.0))
            options.setdefault("ttl", 60.0)
            options.setdefault("task_duration", 60.0)
            options.setdefault("status_latency", 0.05)
            options.setdefault("outage_duration", 2.0)
        if args.experiment == "e-b17":
            options.setdefault("p0_profiles", P0_PROFILES)
            options.setdefault("p0_mechanisms", P0_MECHANISMS)
            options.setdefault("fault_scenarios", P0_FAULT_SCENARIOS)
            options.setdefault("p0_suppression_values", P0_SUPPRESSION_VALUES)
            options.setdefault("tool_call_rates", (10.0,))
            options.setdefault("ttl", 60.0)
            options.setdefault("task_duration", 60.0)
            options.setdefault("bootstrap_samples", 10_000)
    return options


def _run_e_b1_streaming(
    profile: str,
    output_dir: Path,
    options: dict[str, object],
    *,
    resume: bool,
    report: bool,
) -> None:
    if profile == "paper":
        seeds = tuple(range(30))
        n_parties_values = (1000,)
    else:
        seeds = (0, 1, 2)
        n_parties_values = (40,)
    seeds = tuple(options.get("seeds", seeds))
    n_parties_values = tuple(options.get("n_parties_values", n_parties_values))
    raw_path = output_dir / "e_b1_byzantine_sweep.csv"
    existing_keys = {str(row["run_key"]) for row in read_rows_csv(raw_path) if row.get("run_key")} if resume else set()

    def rows():
        for n_value in n_parties_values:
            yield from iter_e_b1_byzantine_sweep_rows(
                seeds=seeds,
                n_parties=int(n_value),
                push_suppression_values=tuple(options.get("push_suppression_values", (0.0, 0.2, 0.4))),
                gossip_suppression_values=tuple(options.get("gossip_suppression_values", (0.0, 0.1))),
                log_suppression_values=tuple(options.get("log_suppression_values", (0.0, 0.1))),
                ttl=float(options.get("ttl", 60.0)),
                velocity=float(options.get("velocity", 10.0)),
                max_time=float(options.get("max_time", 8.0)),
                push_delay=float(options.get("push_delay", 0.05)),
                gossip_delay=float(options.get("gossip_delay", 0.10)),
                gossip_interval=float(options.get("gossip_interval", 0.25)),
                poll_interval=float(options.get("poll_interval", 0.50)),
                log_append_delay=float(options.get("log_append_delay", 0.05)),
                jitter=float(options.get("jitter", 0.20)),
                gossip_fanout=options.get("gossip_fanout"),
                skip_keys=existing_keys,
            )

    written = stream_rows_csv(rows(), raw_path, resume=resume)
    if report:
        write_e_b1_reports_from_csv(output_dir, run_config={**options, "stream_written_rows": written})


def _parse_int_list(value: str) -> tuple[int, ...]:
    if ":" in value:
        parts = [int(part) for part in value.split(":")]
        if len(parts) == 2:
            start, stop = parts
            step = 1
        elif len(parts) == 3:
            start, stop, step = parts
        else:
            raise ValueError(f"invalid range: {value}")
        if step == 0:
            raise ValueError("range step cannot be zero")
        return tuple(range(start, stop, step))
    return tuple(int(part.strip()) for part in value.split(",") if part.strip())


def _parse_float_list(value: str) -> tuple[float, ...]:
    return tuple(float(part.strip()) for part in value.split(",") if part.strip())


def _parse_string_list(value: str) -> tuple[str, ...]:
    return tuple(part.strip() for part in value.split(",") if part.strip())


def _parse_strategy_list(value: str) -> tuple[PropagationStrategy, ...]:
    valid = set(BASELINE_STRATEGIES)
    strategies = tuple(part.strip() for part in value.split(",") if part.strip())
    unknown = sorted(set(strategies) - valid)
    if unknown:
        raise ValueError(f"unknown strategies: {', '.join(unknown)}")
    return strategies  # type: ignore[return-value]


def _parse_delivery_regime_list(value: str) -> tuple[str, ...]:
    valid = set(DELIVERY_REGIMES)
    regimes = tuple(part.strip() for part in value.split(",") if part.strip())
    unknown = sorted(set(regimes) - valid)
    if unknown:
        raise ValueError(f"unknown delivery regimes: {', '.join(unknown)}")
    return regimes


if __name__ == "__main__":
    main()
