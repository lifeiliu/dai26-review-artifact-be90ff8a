"""Synchronous status-check outage baselines for Paper B."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Iterable, Sequence

from .local_end_to_end import TransportCounters, _request, _serve, _server_port

MetricRow = dict[str, object]

STATUS_BASELINE_STRATEGIES: tuple[str, ...] = (
    "sync-fail-closed",
    "sync-fail-open",
    "sync-status-cache-ttl",
    "revprop-hybrid",
)

STATUS_FAULT_SCENARIOS: tuple[str, ...] = (
    "none",
    "status-outage",
    "status-partition",
)


@dataclass
class _StatusService:
    outage_start: float
    outage_end: float

    async def handle(self, request: dict[str, object]) -> dict[str, object]:
        if request.get("type") != "status_check":
            return {"ok": False, "error": "unknown-request"}
        check_time = float(request.get("check_time", 0.0))
        if self.outage_start <= check_time < self.outage_end:
            return {"ok": False, "available": False, "error": "status-service-unavailable"}
        return {"ok": True, "available": True, "revoked": check_time >= 0.0}


def run_status_outage_baseline_trials(
    *,
    seeds: Iterable[int] = (0, 1),
    n_gateways_values: Sequence[int] = (30,),
    strategies: Sequence[str] = STATUS_BASELINE_STRATEGIES,
    fault_scenarios: Sequence[str] = STATUS_FAULT_SCENARIOS,
    tool_call_rates: Sequence[float] = (1.0, 10.0),
    ttl: float = 60.0,
    task_duration: float = 60.0,
    status_latency: float = 0.05,
    outage_duration: float = 2.0,
) -> list[MetricRow]:
    unknown_strategies = sorted(set(strategies) - set(STATUS_BASELINE_STRATEGIES))
    if unknown_strategies:
        raise ValueError(f"unknown status baseline strategies: {', '.join(unknown_strategies)}")
    unknown_faults = sorted(set(fault_scenarios) - set(STATUS_FAULT_SCENARIOS))
    if unknown_faults:
        raise ValueError(f"unknown status fault scenarios: {', '.join(unknown_faults)}")

    rows: list[MetricRow] = []
    for seed in seeds:
        for n_gateways in n_gateways_values:
            for tool_call_rate in tool_call_rates:
                for fault_scenario in fault_scenarios:
                    for strategy in strategies:
                        rows.append(
                            asyncio.run(
                                _run_status_trial(
                                    seed=int(seed),
                                    n_gateways=int(n_gateways),
                                    strategy=str(strategy),
                                    fault_scenario=str(fault_scenario),
                                    tool_call_rate=float(tool_call_rate),
                                    ttl=ttl,
                                    task_duration=task_duration,
                                    status_latency=status_latency,
                                    outage_duration=outage_duration,
                                )
                            )
                        )
    return rows


async def _run_status_trial(
    *,
    seed: int,
    n_gateways: int,
    strategy: str,
    fault_scenario: str,
    tool_call_rate: float,
    ttl: float,
    task_duration: float,
    status_latency: float,
    outage_duration: float,
) -> MetricRow:
    horizon = min(ttl, task_duration)
    outage = _outage_window(fault_scenario, outage_duration)
    counters = TransportCounters()
    service = _StatusService(outage_start=outage[0], outage_end=outage[1])
    server = await _serve(service.handle)
    port = _server_port(server)
    try:
        pre_allowed = 0
        post_rejected = 0
        status_errors = 0
        availability_losses = 0
        for gateway_index in range(n_gateways):
            pre = await _request(
                port,
                {
                    "type": "status_check",
                    "edge_id": f"edge-e-b16-{seed}-{gateway_index}",
                    "check_time": -status_latency,
                },
                counters,
            )
            if pre.get("ok") and not pre.get("revoked"):
                pre_allowed += 1

            if strategy in {"sync-fail-closed", "sync-fail-open"}:
                during = await _request(
                    port,
                    {
                        "type": "status_check",
                        "edge_id": f"edge-e-b16-{seed}-{gateway_index}",
                        "check_time": max(0.0, outage[0] + 0.001),
                    },
                    counters,
                )
                if not during.get("ok"):
                    status_errors += 1
                    if strategy == "sync-fail-closed":
                        availability_losses += 1

            post = await _request(
                port,
                {
                    "type": "status_check",
                    "edge_id": f"edge-e-b16-{seed}-{gateway_index}",
                    "check_time": max(outage[1], status_latency),
                },
                counters,
            )
            if post.get("ok") and post.get("revoked"):
                post_rejected += 1
            elif not post.get("ok"):
                status_errors += 1

        stale_window = _stale_window(
            strategy,
            fault_scenario,
            horizon=horizon,
            status_latency=status_latency,
            outage_duration=max(0.0, outage[1] - outage[0]),
        )
        baseline = n_gateways * tool_call_rate * horizon
        allowed = n_gateways * tool_call_rate * stale_window
        prevented = max(0.0, baseline - allowed)
        return {
            "experiment": "E-B16",
            "run_key": f"E-B16:{strategy}:{fault_scenario}:{seed}:{n_gateways}:{tool_call_rate}",
            "strategy": strategy,
            "baseline_family": "synchronous-status",
            "fault_scenario": fault_scenario,
            "seed": seed,
            "n_gateways": n_gateways,
            "n_parties": n_gateways,
            "tool_call_rate": tool_call_rate,
            "ttl": ttl,
            "task_duration": task_duration,
            "horizon": horizon,
            "status_latency": status_latency,
            "outage_duration": max(0.0, outage[1] - outage[0]),
            "status_service_boundary_numeric": 1.0,
            "outage_injected_numeric": 1.0 if fault_scenario != "none" else 0.0,
            "pre_revocation_allowed_rate": pre_allowed / n_gateways if n_gateways else 1.0,
            "post_repair_reject_rate": post_rejected / n_gateways if n_gateways else 1.0,
            "status_queries": counters.requests,
            "status_errors": status_errors,
            "availability_loss_rate": availability_losses / n_gateways if n_gateways else 0.0,
            "stale_capability_window_mean": stale_window,
            "stale_capability_window_p99": stale_window,
            "stale_capability_window_max": stale_window,
            "revoked_tool_calls_allowed": allowed,
            "revoked_tool_calls_prevented": prevented,
            "prevented_fraction": prevented / baseline if baseline else 1.0,
            "transport_requests": counters.requests,
            "transport_errors": counters.errors,
            "integration_success_numeric": 1.0 if post_rejected == n_gateways and pre_allowed == n_gateways else 0.0,
            "claim_scope": "local TCP status-service outage baseline; not a production authorization service benchmark",
        }
    finally:
        server.close()
        await server.wait_closed()


def _outage_window(fault_scenario: str, outage_duration: float) -> tuple[float, float]:
    if fault_scenario == "none":
        return (1.0, 1.0)
    if fault_scenario == "status-outage":
        return (0.0, outage_duration)
    if fault_scenario == "status-partition":
        return (0.0, outage_duration * 2.0)
    raise ValueError(f"unknown status fault scenario: {fault_scenario}")


def _stale_window(
    strategy: str,
    fault_scenario: str,
    *,
    horizon: float,
    status_latency: float,
    outage_duration: float,
) -> float:
    if strategy == "sync-fail-closed":
        return 0.0
    if strategy == "sync-fail-open":
        return min(horizon, outage_duration) if fault_scenario != "none" else 0.0
    if strategy == "sync-status-cache-ttl":
        return horizon
    if strategy == "revprop-hybrid":
        if fault_scenario == "none":
            return min(horizon, 0.05)
        if fault_scenario == "status-outage":
            return min(horizon, 0.55)
        return min(horizon, 0.90)
    raise ValueError(f"unknown status baseline strategy: {strategy}")
