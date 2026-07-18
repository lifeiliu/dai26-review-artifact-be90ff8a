"""Bridge Paper A agent-system experiments into Paper B evidence reports."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Sequence

MetricRow = dict[str, object]


def build_paper_a_agent_system_bridge_rows(
    paper_a_experiments_dir: str | Path | None = None,
) -> list[MetricRow]:
    """Load Paper A E16-E19 outputs and expose their agent-system evidence boundary."""

    if paper_a_experiments_dir is None:
        raise ValueError(
            "E-B13 requires Paper A outputs; pass --paper-a-experiments-dir "
            "or call the runner with paper_a_experiments_dir=..."
        )
    base = Path(paper_a_experiments_dir)
    e16 = _load_json(base / "e16_framework_trace_replay" / "e16_results.json")
    e16_baselines = _load_json(base / "e16_framework_trace_replay" / "e16_baseline_expressiveness.json")
    e17 = _load_json(base / "e17_a2a_protocol_demo" / "e17_results.json")
    e18 = _load_json(base / "e18_cross_framework_agent_demo" / "e18_results.json")
    e19 = _load_json(base / "e19_crewai_executable_demo" / "e19_results.json")

    return [
        _e16_row(e16, e16_baselines, base),
        _portability_row(
            "E17",
            "a2a-task-handoff-shaped",
            "A2A-shaped task handoff",
            "schema-portability-demo",
            e17,
            base / "e17_a2a_protocol_demo" / "e17_results.json",
            real_runtime=False,
            executable_runtime=False,
            claim_scope=(
                "A2A-shaped handoffs emit the same signed delegation schema; this is a small portability "
                "demo, not third-party A2A interoperability or production prevalence evidence."
            ),
        ),
        _portability_row(
            "E18",
            "cross-framework-agent-shaped",
            "AutoGen-shaped, CrewAI-shaped",
            "schema-portability-demo",
            e18,
            base / "e18_cross_framework_agent_demo" / "e18_results.json",
            real_runtime=False,
            executable_runtime=False,
            claim_scope=(
                "AutoGen- and CrewAI-shaped task handoffs fit the same signed delegation schema; this is "
                "framework-shape portability evidence, not a real framework execution."
            ),
        ),
        _portability_row(
            "E19",
            "crewai-executable-workflows",
            "CrewAI",
            "real-framework-executable-adapter",
            e19,
            base / "e19_crewai_executable_demo" / "e19_results.json",
            real_runtime=True,
            executable_runtime=True,
            claim_scope=(
                "Executable CrewAI workflows with a deterministic local BaseLLM normalize task-context "
                "handoffs into signed delegation events. The evidence is local and offline, not production "
                "deployment evidence."
            ),
        ),
    ]


def summarize_paper_a_agent_system_bridge(
    rows: Sequence[MetricRow],
    aggregates: Sequence[MetricRow] | None = None,
    *,
    run_config: dict[str, object] | None = None,
) -> dict[str, object]:
    aggregate_rows = list(aggregates or [])
    total_signed = sum(_int(row.get("signed_delegation_events")) for row in rows)
    total_valid = sum(_int(row.get("valid_signed_delegation_events")) for row in rows)
    real_runtime_rows = sum(_int(row.get("real_agent_framework_runtime_numeric")) for row in rows)
    executable_rows = sum(_int(row.get("executable_agent_runtime_numeric")) for row in rows)
    production_rows = sum(_int(row.get("production_deployment_numeric")) for row in rows)

    return {
        "experiment": "E-B13",
        "run_config": run_config or {},
        "raw_rows": len(rows),
        "aggregate_rows": len(aggregate_rows),
        "source_experiments": [str(row.get("source_experiment")) for row in rows],
        "framework_surfaces": [str(row.get("framework_surface")) for row in rows],
        "total_trace_units": sum(_int(row.get("trace_units")) for row in rows),
        "total_signed_delegation_events": total_signed,
        "weighted_valid_signed_delegation_rate": _rate(total_valid, total_signed),
        "real_agent_framework_runtime_rows": real_runtime_rows,
        "executable_agent_runtime_rows": executable_rows,
        "production_deployment_rows": production_rows,
        "total_alternate_parent_cases": sum(_int(row.get("alternate_parent_cases")) for row in rows),
        "total_tree_wrongly_revoked_cases": sum(
            _int(row.get("alternate_parent_wrongly_revoked_by_tree")) for row in rows
        ),
        "total_cross_domain_target_cases": sum(_int(row.get("cross_domain_target_cases")) for row in rows),
        "total_cross_domain_under_revoked_by_scoped": sum(
            _int(row.get("cross_domain_under_revoked_by_scoped")) for row in rows
        ),
        "langgraph_trace_units": _source_metric(rows, "E16", "trace_units"),
        "crewai_trace_units": _source_metric(rows, "E19", "trace_units"),
        "crewai_kickoff_completed": bool(_source_metric(rows, "E19", "framework_kickoff_completed_numeric")),
        "claim_note": (
            "E-B13 does not add a new propagation mechanism. It bridges Paper A's agent-system evidence into "
            "Paper B by showing that the delegated edges propagated by Paper B can be produced by real "
            "LangGraph traces and executable CrewAI workflows, plus A2A/cross-framework shaped handoffs. "
            "The bridge reduces the multi-agent-system evidence gap but still leaves production deployment, "
            "multi-vendor interop, and multi-host scale as explicit non-claims."
        ),
    }


def render_paper_a_agent_system_bridge_report(
    summary: dict[str, object],
    aggregates: Sequence[MetricRow],
) -> str:
    lines = [
        "# E-B13 Paper A Agent-System Bridge Report",
        "",
        f"Raw rows: {summary['raw_rows']}",
        f"Aggregate rows: {summary['aggregate_rows']}",
        f"Source experiments: {summary['source_experiments']}",
        f"Framework surfaces: {summary['framework_surfaces']}",
        f"Total trace units: {summary['total_trace_units']}",
        f"Total signed delegation events: {summary['total_signed_delegation_events']}",
        f"Weighted valid signed delegation rate: {_fmt(summary.get('weighted_valid_signed_delegation_rate'), 4)}",
        f"Real agent-framework runtime rows: {summary['real_agent_framework_runtime_rows']}",
        f"Executable agent runtime rows: {summary['executable_agent_runtime_rows']}",
        f"Production deployment rows: {summary['production_deployment_rows']}",
        f"Alternate-parent cases: {summary['total_alternate_parent_cases']}",
        f"Tree-over-revocation cases: {summary['total_tree_wrongly_revoked_cases']}",
        f"Cross-domain target cases: {summary['total_cross_domain_target_cases']}",
        f"Deployer-scoped under-revocation cases: {summary['total_cross_domain_under_revoked_by_scoped']}",
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
            "## Source Surfaces",
            "",
            "| source | surface | traces | signed | valid | real runtime | executable | alt-parent | tree wrong | scoped under |",
            "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for row in sorted(aggregates, key=lambda item: str(item.get("source_experiment"))):
        lines.append(
            "| {source} | {surface} | {traces} | {signed} | {valid} | {runtime} | {exec} | {alt} | {tree} | {scoped} |".format(
                source=row.get("source_experiment"),
                surface=row.get("framework_surface"),
                traces=_fmt(row.get("trace_units_mean"), 0),
                signed=_fmt(row.get("signed_delegation_events_mean"), 0),
                valid=_fmt(row.get("valid_signed_delegation_rate_mean"), 4),
                runtime=_fmt(
                    row.get("real_agent_framework_runtime_numeric_mean", row.get("real_agent_framework_runtime_numeric")),
                    0,
                ),
                exec=_fmt(
                    row.get("executable_agent_runtime_numeric_mean", row.get("executable_agent_runtime_numeric")),
                    0,
                ),
                alt=_fmt(row.get("alternate_parent_cases_mean"), 0),
                tree=_fmt(row.get("alternate_parent_wrongly_revoked_by_tree_mean"), 0),
                scoped=_fmt(row.get("cross_domain_under_revoked_by_scoped_mean"), 0),
            )
        )
    lines.extend(["", "## Interpretation", "", str(summary.get("claim_note", ""))])
    return "\n".join(lines)


def _e16_row(e16: dict[str, object], baselines: dict[str, object], base: Path) -> MetricRow:
    collection = _dict(e16.get("collection"))
    normalization = _dict(e16.get("normalization"))
    outcomes = _dict(e16.get("outcomes"))
    signed = _int(normalization.get("signed_delegation_events"))
    valid = _int(normalization.get("valid_signed_delegation_events"))
    traces = _int(outcomes.get("traces"))
    multiparent_traces = _int(outcomes.get("traces_with_multiparent"))
    cross_deployer_traces = _int(outcomes.get("traces_with_cross_deployer_multiparent"))
    single_edge = _dict(outcomes.get("single_edge_conformance"))
    cross_domain = _dict(baselines.get("cross_domain_target_cases"))

    return {
        "experiment": "E-B13",
        "source_paper": "Paper A",
        "source_experiment": "E16",
        "source_result_path": str(base / "e16_framework_trace_replay" / "e16_results.json"),
        "framework_surface": "langgraph-runtime-trace-replay",
        "frameworks": "LangGraph",
        "evidence_class": "real-framework-runtime-trace",
        "trace_units": traces,
        "raw_events": _int(collection.get("raw_events")),
        "signed_delegation_events": signed,
        "valid_signed_delegation_events": valid,
        "valid_signed_delegation_rate": _rate(valid, signed),
        "real_agent_framework_runtime_numeric": 1,
        "executable_agent_runtime_numeric": 1,
        "production_deployment_numeric": 0,
        "multi_agent_runtime_numeric": 1,
        "multiparent_traces": multiparent_traces,
        "multiparent_trace_fraction": _rate(multiparent_traces, traces),
        "cross_deployer_multiparent_traces": cross_deployer_traces,
        "cross_deployer_trace_fraction": _rate(cross_deployer_traces, traces),
        "alternate_parent_cases": _int(baselines.get("alternate_parent_cases")),
        "alternate_parent_preserved_by_edge_target": _int(single_edge.get("semantic_survivors")),
        "alternate_parent_wrongly_revoked_by_tree": _int(single_edge.get("tree_wrongly_revoked")),
        "cross_domain_target_cases": _int(cross_domain.get("cases")),
        "cross_domain_under_revoked_by_scoped": _int(cross_domain.get("scoped_under_cases")),
        "proof_verified_rate": _verified_rate(outcomes.get("proof_verified")),
        "authorized_revocation_verified_rate": _verified_rate(outcomes.get("authorized_revocation_verified")),
        "unauthorized_rejected_rate": _verified_rate(outcomes.get("unauthorized_rejected")),
        "omission_rejected_rate": _verified_rate(outcomes.get("omission_rejected")),
        "cross_deployer_revocation_verified_rate": _verified_rate(outcomes.get("cross_deployer_revocation_verified")),
        "replay_ms_mean": _nested_float(outcomes, "replay_ms", "mean"),
        "proof_bytes_mean": _nested_float(outcomes, "proof_bytes", "mean"),
        "framework_kickoff_completed_numeric": 1,
        "claim_scope": (
            "Real LangGraph runtime event-stream traces normalize into signed delegation edges and replay "
            "multi-parent/cross-deployer revocation cases. This is framework trace-replay evidence, not "
            "production prevalence."
        ),
    }


def _portability_row(
    source_experiment: str,
    framework_surface: str,
    frameworks: str,
    evidence_class: str,
    data: dict[str, object],
    result_path: Path,
    *,
    real_runtime: bool,
    executable_runtime: bool,
    claim_scope: str,
) -> MetricRow:
    signed = _int(data.get("signed_delegation_events"))
    valid = _int(data.get("valid_signed_delegation_events"))
    return {
        "experiment": "E-B13",
        "source_paper": "Paper A",
        "source_experiment": source_experiment,
        "source_result_path": str(result_path),
        "framework_surface": framework_surface,
        "frameworks": frameworks,
        "evidence_class": evidence_class,
        "trace_units": _int(data.get("trace_units")),
        "raw_events": "",
        "signed_delegation_events": signed,
        "valid_signed_delegation_events": valid,
        "valid_signed_delegation_rate": _rate(valid, signed),
        "real_agent_framework_runtime_numeric": int(real_runtime),
        "executable_agent_runtime_numeric": int(executable_runtime),
        "production_deployment_numeric": 0,
        "multi_agent_runtime_numeric": 1,
        "multiparent_traces": "",
        "multiparent_trace_fraction": "",
        "cross_deployer_multiparent_traces": "",
        "cross_deployer_trace_fraction": "",
        "alternate_parent_cases": _int(data.get("alternate_parent_cases")),
        "alternate_parent_preserved_by_edge_target": _int(data.get("alternate_parent_preserved_by_edge_target")),
        "alternate_parent_wrongly_revoked_by_tree": _int(data.get("alternate_parent_wrongly_revoked_by_tree")),
        "cross_domain_target_cases": _int(data.get("cross_domain_target_cases")),
        "cross_domain_under_revoked_by_scoped": _int(data.get("cross_domain_under_revoked_by_scoped")),
        "proof_verified_rate": "",
        "authorized_revocation_verified_rate": "",
        "unauthorized_rejected_rate": "",
        "omission_rejected_rate": "",
        "cross_deployer_revocation_verified_rate": "",
        "replay_ms_mean": "",
        "proof_bytes_mean": "",
        "framework_kickoff_completed_numeric": int(bool(data.get("crew_kickoff_completed", executable_runtime))),
        "tasks_configured": _int(data.get("tasks_configured")),
        "task_callbacks_observed": _int(data.get("task_callbacks_observed")),
        "llm_calls_observed": _int(data.get("llm_calls_observed")),
        "crewai_version": data.get("crewai_version", ""),
        "claim_scope": claim_scope,
    }


def _load_json(path: Path) -> dict[str, object]:
    if not path.exists():
        raise FileNotFoundError(f"missing Paper A experiment result: {path}")
    return json.loads(path.read_text())


def _dict(value: object) -> dict[str, object]:
    return value if isinstance(value, dict) else {}


def _int(value: object) -> int:
    if value in (None, ""):
        return 0
    return int(float(value))


def _rate(numerator: int, denominator: int) -> float | None:
    if denominator == 0:
        return None
    return numerator / denominator


def _verified_rate(value: object) -> float | None:
    record = _dict(value)
    if not record:
        return None
    passed = record.get("verified", record.get("passed", 0))
    return _rate(_int(passed), _int(record.get("total")))


def _nested_float(value: dict[str, object], outer: str, inner: str) -> float | None:
    nested = _dict(value.get(outer))
    raw = nested.get(inner)
    if raw in (None, ""):
        return None
    return float(raw)


def _source_metric(rows: Sequence[MetricRow], source_experiment: str, metric: str) -> int:
    for row in rows:
        if row.get("source_experiment") == source_experiment:
            return _int(row.get(metric))
    return 0


def _fmt(value: object, digits: int = 4) -> str:
    if value in (None, ""):
        return "n/a"
    number = float(value)
    if digits == 0:
        return str(int(round(number)))
    return f"{number:.{digits}f}"
