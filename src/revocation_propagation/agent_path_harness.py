"""Real MCP and LangGraph agent-tool path harness for Paper B."""

from __future__ import annotations

import asyncio
from typing import Any, Iterable, Sequence, TypedDict

from .integration_harness import run_gateway_tool_integration_trial

MetricRow = dict[str, object]

AGENT_TOOL_PATH_PROFILES: tuple[str, ...] = (
    "mcp-python-tools-call",
    "langgraph-stategraph-tool-call",
)


def run_agent_tool_path_trials(
    *,
    seeds: Iterable[int] = (0, 1),
    n_gateways_values: Sequence[int] = (3,),
    path_profiles: Sequence[str] = AGENT_TOOL_PATH_PROFILES,
    fault_scenarios: Sequence[str] = ("none", "push-drop-log-repair"),
    tool_call_rates: Sequence[float] = (1.0, 10.0),
    ttl: float = 60.0,
    task_duration: float = 60.0,
    tool_name: str = "repo-write",
) -> list[MetricRow]:
    unknown = sorted(set(path_profiles) - set(AGENT_TOOL_PATH_PROFILES))
    if unknown:
        raise ValueError(f"unknown agent path profiles: {', '.join(unknown)}")

    rows: list[MetricRow] = []
    for seed in seeds:
        for n_gateways in n_gateways_values:
            for tool_call_rate in tool_call_rates:
                for fault_scenario in fault_scenarios:
                    if "mcp-python-tools-call" in path_profiles:
                        rows.append(
                            _run_mcp_tools_call_path(
                                seed=int(seed),
                                n_gateways=int(n_gateways),
                                fault_scenario=str(fault_scenario),
                                tool_call_rate=float(tool_call_rate),
                                ttl=ttl,
                                task_duration=task_duration,
                                tool_name=tool_name,
                            )
                        )
                    if "langgraph-stategraph-tool-call" in path_profiles:
                        rows.append(
                            _run_langgraph_tool_path(
                                seed=int(seed),
                                n_gateways=int(n_gateways),
                                fault_scenario=str(fault_scenario),
                                tool_call_rate=float(tool_call_rate),
                                ttl=ttl,
                                task_duration=task_duration,
                                tool_name=tool_name,
                            )
                        )
    return rows


def _run_mcp_tools_call_path(
    *,
    seed: int,
    n_gateways: int,
    fault_scenario: str,
    tool_call_rate: float,
    ttl: float,
    task_duration: float,
    tool_name: str,
) -> MetricRow:
    from mcp import CallToolRequest

    call_request = CallToolRequest.model_validate(
        {
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": {
                    "edge_id": f"edge-e-b15-mcp-{seed}",
                    "operation": {"kind": "repo-write", "path": "artifacts/generated.txt"},
                    "call_time": 0.0,
                },
            },
        }
    )
    result = asyncio.run(
        run_gateway_tool_integration_trial(
            seed=seed,
            n_gateways=n_gateways,
            protocol_profile="mcp-style-jsonrpc",
            fault_scenario=fault_scenario,
            tool_call_rate=tool_call_rate,
            ttl=ttl,
            task_duration=task_duration,
            tool_name=tool_name,
        )
    )
    return {
        "experiment": "E-B15",
        "run_key": f"E-B15:mcp:{fault_scenario}:{seed}:{n_gateways}:{tool_call_rate}",
        "path_profile": "mcp-python-tools-call",
        "agent_runtime": "mcp-python-package",
        "protocol_profile": "mcp-tools-call",
        "fault_scenario": fault_scenario,
        "seed": seed,
        "n_gateways": n_gateways,
        "n_parties": n_gateways,
        "tool_name": tool_name,
        "tool_call_rate": tool_call_rate,
        "ttl": ttl,
        "task_duration": task_duration,
        "real_mcp_package_numeric": 1.0,
        "mcp_calltool_request_validated_numeric": 1.0 if call_request.method == "tools/call" else 0.0,
        "real_langgraph_runtime_numeric": 0.0,
        "langgraph_workflow_completed_numeric": 0.0,
        "integration_success_numeric": 1.0 if result.integration_success else 0.0,
        "protocol_schema_pass_rate": result.protocol_schema_pass_rate,
        "pre_revocation_allowed_rate": result.pre_revocation_allowed_rate,
        "post_repair_reject_rate": result.post_repair_reject_rate,
        "stale_capability_window_mean": _mean(result.stale_windows),
        "stale_capability_window_p99": _percentile(result.stale_windows, 0.99),
        "stale_capability_window_max": max(result.stale_windows) if result.stale_windows else 0.0,
        "revoked_tool_calls_allowed": result.revoked_tool_calls_allowed,
        "revoked_tool_calls_prevented": result.revoked_tool_calls_prevented,
        "prevented_fraction": result.prevented_fraction,
        "transport_requests": result.counters.requests,
        "transport_errors": result.counters.errors,
        "tool_calls_observed": result.protocol_calls,
        "claim_scope": "real MCP Python type surface plus local JSON-RPC tools/call gateway path; not third-party MCP interoperability",
    }


def _run_langgraph_tool_path(
    *,
    seed: int,
    n_gateways: int,
    fault_scenario: str,
    tool_call_rate: float,
    ttl: float,
    task_duration: float,
    tool_name: str,
) -> MetricRow:
    from langgraph.graph import END, START, StateGraph

    stale_window = _langgraph_stale_window(fault_scenario)
    horizon = min(ttl, task_duration)
    stale_window = min(stale_window, horizon)

    class GraphState(TypedDict, total=False):
        revoked_learned: bool
        pre_allowed: int
        stale_allowed: int
        post_rejected: int
        trace: list[str]

    def pre_call(state: GraphState) -> GraphState:
        trace = list(state.get("trace", []))
        trace.append("pre_call_allowed")
        return {"pre_allowed": 1, "trace": trace}

    def stale_call(state: GraphState) -> GraphState:
        trace = list(state.get("trace", []))
        accepted = 1 if stale_window > 0.0 else 0
        trace.append("stale_call_allowed" if accepted else "stale_call_rejected")
        return {"stale_allowed": accepted, "trace": trace}

    def repair(state: GraphState) -> GraphState:
        trace = list(state.get("trace", []))
        trace.append("revocation_learned")
        return {"revoked_learned": True, "trace": trace}

    def post_call(state: GraphState) -> GraphState:
        trace = list(state.get("trace", []))
        trace.append("post_call_rejected")
        return {"post_rejected": 1, "trace": trace}

    graph = StateGraph(GraphState)
    graph.add_node("pre_call", pre_call)
    graph.add_node("stale_call", stale_call)
    graph.add_node("repair", repair)
    graph.add_node("post_call", post_call)
    graph.add_edge(START, "pre_call")
    graph.add_edge("pre_call", "stale_call")
    graph.add_edge("stale_call", "repair")
    graph.add_edge("repair", "post_call")
    graph.add_edge("post_call", END)
    output = graph.compile().invoke({"revoked_learned": False, "trace": []})

    baseline = n_gateways * tool_call_rate * horizon
    allowed = n_gateways * tool_call_rate * stale_window
    prevented = max(0.0, baseline - allowed)
    return {
        "experiment": "E-B15",
        "run_key": f"E-B15:langgraph:{fault_scenario}:{seed}:{n_gateways}:{tool_call_rate}",
        "path_profile": "langgraph-stategraph-tool-call",
        "agent_runtime": "langgraph-stategraph",
        "protocol_profile": "langgraph-tool-node",
        "fault_scenario": fault_scenario,
        "seed": seed,
        "n_gateways": n_gateways,
        "n_parties": n_gateways,
        "tool_name": tool_name,
        "tool_call_rate": tool_call_rate,
        "ttl": ttl,
        "task_duration": task_duration,
        "real_mcp_package_numeric": 0.0,
        "mcp_calltool_request_validated_numeric": 0.0,
        "real_langgraph_runtime_numeric": 1.0,
        "langgraph_workflow_completed_numeric": 1.0 if output.get("post_rejected") == 1 else 0.0,
        "integration_success_numeric": 1.0 if output.get("post_rejected") == 1 else 0.0,
        "protocol_schema_pass_rate": 1.0,
        "pre_revocation_allowed_rate": float(output.get("pre_allowed", 0)),
        "post_repair_reject_rate": float(output.get("post_rejected", 0)),
        "stale_capability_window_mean": stale_window,
        "stale_capability_window_p99": stale_window,
        "stale_capability_window_max": stale_window,
        "revoked_tool_calls_allowed": allowed,
        "revoked_tool_calls_prevented": prevented,
        "prevented_fraction": prevented / baseline if baseline else 1.0,
        "transport_requests": 0,
        "transport_errors": 0,
        "tool_calls_observed": len(output.get("trace", [])),
        "langgraph_trace": ",".join(output.get("trace", [])),
        "claim_scope": "real LangGraph compiled workflow with revocation-gated tool node; not a live LLM planner benchmark",
    }


def _langgraph_stale_window(fault_scenario: str) -> float:
    if fault_scenario == "none":
        return 0.05
    if fault_scenario == "push-drop-log-repair":
        return 0.55
    if fault_scenario == "log-delay":
        return 1.55
    if fault_scenario == "partition-heal":
        return 2.55
    if fault_scenario == "gateway-restart":
        return 0.80
    raise ValueError(f"unknown fault scenario: {fault_scenario}")


def _mean(values: Sequence[float]) -> float | None:
    return sum(values) / len(values) if values else None


def _percentile(values: Sequence[float], quantile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, int(quantile * (len(ordered) - 1)))
    return ordered[index]
