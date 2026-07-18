"""Loopback gateway/tool/protocol/fault integration harness for Paper B."""

from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass, field
from typing import Any, Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .crypto import canonical_json_bytes, generate_keypair
from .events import create_revocation_event, verify_revocation_event
from .ledger_client import TransparencyLedger
from .local_end_to_end import (
    TransportCounters,
    _expect_dict,
    _request,
    _serve,
    _server_port,
    certificate_from_payload,
    certificate_to_payload,
    event_from_payload,
    sth_to_payload,
)
from .root_authority import RootAuthority, RootFederation

INTEGRATION_PROTOCOL_PROFILES: tuple[str, ...] = (
    "raw-http-json",
    "mcp-style-jsonrpc",
    "a2a-task-lifecycle",
)

INTEGRATION_FAULT_SCENARIOS: tuple[str, ...] = (
    "none",
    "push-drop-log-repair",
    "log-delay",
    "partition-heal",
    "gateway-restart",
)


@dataclass
class GatewayState:
    gateway_id: str
    revoked_edges: dict[str, float] = field(default_factory=dict)
    learned_via: dict[str, str] = field(default_factory=dict)
    learn_events: list[dict[str, object]] = field(default_factory=list)
    accepted_tool_calls: int = 0
    rejected_tool_calls: int = 0
    malformed_protocol_calls: int = 0
    protocol_calls: int = 0
    protocol_schema_passes: int = 0
    forwarded_tool_calls: int = 0
    restarts: int = 0
    signature_verified_events: int = 0
    certificate_verified_events: int = 0
    rejected_events: int = 0
    audit_evidence_available: bool = False


@dataclass
class ToolState:
    tool_name: str
    accepted_invocations: int = 0
    rejected_invocations: int = 0
    operations: list[dict[str, object]] = field(default_factory=list)


@dataclass(frozen=True)
class FaultSchedule:
    gateway_id: str
    stale_intervals: tuple[tuple[float, float], ...]
    first_learn_at: float
    final_learn_at: float
    initial_via: str
    repair_via: str | None = None
    restart_at: float | None = None
    recovery_latency: float | None = None

    def stale_window(self, horizon: float) -> float:
        total = 0.0
        for start, end in self.stale_intervals:
            total += max(0.0, min(end, horizon) - max(start, 0.0))
        return total


@dataclass
class IntegrationTrialResult:
    seed: int
    n_gateways: int
    protocol_profile: str
    fault_scenario: str
    tool_name: str
    tool_call_rate: float
    task_duration: float
    ttl: float
    push_delay: float
    poll_interval: float
    log_append_delay: float
    log_delay: float
    partition_duration: float
    gateway_restart_at: float
    issued_at: float
    counters: TransportCounters
    wall_time_seconds: float
    root_count: int
    root_threshold: int
    event_payload_bytes: int
    certificate_payload_bytes: int
    gateway_ports: dict[str, int]
    tool_port: int
    log_port: int
    stale_windows: tuple[float, ...]
    final_learn_latencies: tuple[float, ...]
    recovery_latencies: tuple[float, ...]
    pre_revocation_calls: int
    pre_revocation_allowed: int
    sampled_revoked_calls_allowed: int
    sampled_revoked_calls_rejected: int
    post_repair_rejected: int
    protocol_calls: int
    protocol_schema_passes: int
    forwarded_tool_calls: int
    gateway_restarts: int
    push_attempts: int
    push_delivered: int
    push_dropped: int
    log_repairs: int
    signature_verified_events: int
    certificate_verified_events: int
    rejected_events: int
    tool_accepted_invocations: int
    tool_rejected_invocations: int
    audit_evidence_gateways: int

    @property
    def horizon(self) -> float:
        return min(self.ttl, self.task_duration)

    @property
    def revoked_tool_calls_baseline_ttl(self) -> float:
        return self.n_gateways * self.tool_call_rate * self.horizon

    @property
    def revoked_tool_calls_allowed(self) -> float:
        return sum(self.tool_call_rate * window for window in self.stale_windows)

    @property
    def revoked_tool_calls_prevented(self) -> float:
        return max(0.0, self.revoked_tool_calls_baseline_ttl - self.revoked_tool_calls_allowed)

    @property
    def prevented_fraction(self) -> float:
        baseline = self.revoked_tool_calls_baseline_ttl
        return self.revoked_tool_calls_prevented / baseline if baseline > 0.0 else 1.0

    @property
    def protocol_schema_pass_rate(self) -> float:
        return self.protocol_schema_passes / self.protocol_calls if self.protocol_calls else 1.0

    @property
    def pre_revocation_allowed_rate(self) -> float:
        return self.pre_revocation_allowed / self.pre_revocation_calls if self.pre_revocation_calls else 1.0

    @property
    def post_repair_reject_rate(self) -> float:
        return self.post_repair_rejected / self.n_gateways if self.n_gateways else 1.0

    @property
    def integration_success(self) -> bool:
        return (
            self.counters.errors == 0
            and self.pre_revocation_allowed_rate == 1.0
            and self.post_repair_reject_rate == 1.0
            and self.protocol_schema_pass_rate == 1.0
            and self.signature_verified_events >= self.n_gateways
            and self.certificate_verified_events >= self.n_gateways
        )


@dataclass
class _IntegrationLogService:
    ledger: TransparencyLedger
    counters: TransportCounters
    event_payload: dict[str, Any] | None = None
    certificate_payload: dict[str, Any] | None = None
    sth_payload: dict[str, Any] | None = None

    async def handle(self, request: dict[str, Any]) -> dict[str, Any]:
        request_type = request.get("type")
        if request_type == "append":
            event = event_from_payload(_expect_dict(request.get("event")))
            self.ledger.append(event, appended_at=float(request.get("appended_at", 0.0)))
            sth = self.ledger.latest_sth(timestamp=float(request.get("sth_timestamp", 0.0)))
            self.event_payload = event.to_payload()
            self.certificate_payload = _expect_dict(request.get("certificate"))
            self.sth_payload = sth_to_payload(sth)
            self.counters.log_appends += 1
            return {"ok": True, "sth": self.sth_payload}
        if request_type == "latest":
            self.counters.log_polls += 1
            return {
                "ok": True,
                "has_event": self.event_payload is not None,
                "event": self.event_payload,
                "certificate": self.certificate_payload,
                "sth": self.sth_payload,
            }
        return {"ok": False, "error": f"unknown log request: {request_type}"}


@dataclass
class _ToolService:
    state: ToolState

    async def handle(self, request: dict[str, Any]) -> dict[str, Any]:
        if request.get("type") != "invoke_tool":
            return {"ok": False, "accepted": False, "error": f"unknown tool request: {request.get('type')}"}
        tool_name = str(request.get("tool_name", ""))
        if tool_name != self.state.tool_name:
            self.state.rejected_invocations += 1
            return {"ok": True, "accepted": False, "error": "unknown-tool"}
        operation = _expect_dict(request.get("operation"))
        self.state.accepted_invocations += 1
        self.state.operations.append(
            {
                "edge_id": str(request.get("edge_id", "")),
                "gateway_id": str(request.get("gateway_id", "")),
                "operation": operation,
                "call_time": float(request.get("call_time", 0.0)),
            }
        )
        return {
            "ok": True,
            "accepted": True,
            "tool_name": self.state.tool_name,
            "operation_index": self.state.accepted_invocations - 1,
        }


@dataclass
class _GatewayService:
    state: GatewayState
    tool_port: int
    issuer_public_key: Ed25519PublicKey
    federation: RootFederation
    counters: TransportCounters
    protocol_profile: str

    async def handle(self, request: dict[str, Any]) -> dict[str, Any]:
        request_type = request.get("type")
        if request_type == "learn_revocation":
            return self._learn_revocation(request)
        if request_type == "restart":
            self.state.revoked_edges.clear()
            self.state.learned_via.clear()
            self.state.restarts += 1
            return {"ok": True, "restarted": True, "gateway_id": self.state.gateway_id}
        if request_type == "metrics":
            return {"ok": True, "gateway_id": self.state.gateway_id, "state": self._metrics_payload()}
        return await self._handle_tool_call(request)

    def _learn_revocation(self, request: dict[str, Any]) -> dict[str, Any]:
        event_payload = _expect_dict(request.get("event"))
        certificate_payload = _expect_dict(request.get("certificate"))
        event = event_from_payload(event_payload)
        certificate = certificate_from_payload(certificate_payload)
        signature_ok = verify_revocation_event(event, self.issuer_public_key)
        certificate_ok = self.federation.verify_certificate(certificate)
        if not signature_ok or not certificate_ok:
            self.state.rejected_events += 1
            return {"ok": False, "accepted": False, "signature_ok": signature_ok, "certificate_ok": certificate_ok}

        delivered_at = float(request.get("delivered_at", 0.0))
        via = str(request.get("via", "unknown"))
        self.state.revoked_edges[event.edge_id] = delivered_at
        self.state.learned_via[event.edge_id] = via
        self.state.learn_events.append({"edge_id": event.edge_id, "via": via, "delivered_at": delivered_at})
        self.state.signature_verified_events += 1
        self.state.certificate_verified_events += 1
        if via.startswith("log") or request.get("sth") is not None:
            self.state.audit_evidence_available = True
        return {
            "ok": True,
            "accepted": True,
            "gateway_id": self.state.gateway_id,
            "edge_id": event.edge_id,
            "via": via,
            "delivered_at": delivered_at,
        }

    async def _handle_tool_call(self, request: dict[str, Any]) -> dict[str, Any]:
        self.state.protocol_calls += 1
        parsed = _parse_protocol_call(request, self.protocol_profile)
        if parsed is None:
            self.state.malformed_protocol_calls += 1
            return _protocol_response(
                self.protocol_profile,
                request,
                accepted=False,
                rejected=False,
                reason="malformed-protocol",
                gateway_id=self.state.gateway_id,
            )
        self.state.protocol_schema_passes += 1
        edge_id = parsed["edge_id"]
        call_time = float(parsed["call_time"])
        revoked_at = self.state.revoked_edges.get(edge_id)
        if revoked_at is not None and call_time >= revoked_at:
            self.state.rejected_tool_calls += 1
            return _protocol_response(
                self.protocol_profile,
                request,
                accepted=False,
                rejected=True,
                reason="revoked-capability",
                gateway_id=self.state.gateway_id,
            )

        response = await _request(
            self.tool_port,
            {
                "type": "invoke_tool",
                "gateway_id": self.state.gateway_id,
                "edge_id": edge_id,
                "tool_name": parsed["tool_name"],
                "operation": parsed["operation"],
                "call_time": call_time,
            },
            self.counters,
        )
        if response.get("accepted"):
            self.state.accepted_tool_calls += 1
            self.state.forwarded_tool_calls += 1
            return _protocol_response(
                self.protocol_profile,
                request,
                accepted=True,
                rejected=False,
                reason=None,
                gateway_id=self.state.gateway_id,
                tool_response=response,
            )
        self.state.rejected_tool_calls += 1
        return _protocol_response(
            self.protocol_profile,
            request,
            accepted=False,
            rejected=True,
            reason=str(response.get("error", "tool-rejected")),
            gateway_id=self.state.gateway_id,
        )

    def _metrics_payload(self) -> dict[str, object]:
        return {
            "accepted_tool_calls": self.state.accepted_tool_calls,
            "rejected_tool_calls": self.state.rejected_tool_calls,
            "protocol_calls": self.state.protocol_calls,
            "protocol_schema_passes": self.state.protocol_schema_passes,
            "forwarded_tool_calls": self.state.forwarded_tool_calls,
            "restarts": self.state.restarts,
            "signature_verified_events": self.state.signature_verified_events,
            "certificate_verified_events": self.state.certificate_verified_events,
            "rejected_events": self.state.rejected_events,
            "audit_evidence_available": self.state.audit_evidence_available,
        }


async def run_gateway_tool_integration_trial(
    *,
    seed: int,
    n_gateways: int,
    protocol_profile: str = "raw-http-json",
    fault_scenario: str = "none",
    tool_call_rate: float = 10.0,
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
    root_count: int = 5,
    threshold: int = 3,
) -> IntegrationTrialResult:
    """Run a local integration trial across gateway, tool, log, and protocol boundaries.

    Services run in one Python process, but each gateway call, gateway-to-tool
    forward, and log repair crosses a loopback TCP JSONL boundary.
    """

    if protocol_profile not in INTEGRATION_PROTOCOL_PROFILES:
        raise ValueError(f"unknown protocol profile: {protocol_profile}")
    if fault_scenario not in INTEGRATION_FAULT_SCENARIOS:
        raise ValueError(f"unknown fault scenario: {fault_scenario}")
    if n_gateways <= 0:
        raise ValueError("n_gateways must be positive")

    rng = random.Random(seed)
    counters = TransportCounters()
    wall_start = time.perf_counter()
    issued_at = 0.0
    horizon = min(ttl, task_duration)
    issuer = generate_keypair()
    roots = [RootAuthority(f"root-{idx}", generate_keypair()) for idx in range(root_count)]
    federation = RootFederation({root.root_id: root.keypair.public for root in roots}, threshold=threshold)
    event = create_revocation_event(
        f"edge-e-b10-{seed}-{protocol_profile}-{fault_scenario}",
        issuer,
        epoch_id="epoch-integration",
        issued_at=issued_at,
    )
    approvals = [root.approve_event(event) for root in roots[:threshold]]
    certificate = federation.certificate_for(event, approvals)
    event_payload = event.to_payload()
    certificate_payload = certificate_to_payload(certificate)

    tool_state = ToolState(tool_name=tool_name)
    tool_service = _ToolService(tool_state)
    tool_server = await _serve(tool_service.handle)
    tool_port = _server_port(tool_server)
    log_service = _IntegrationLogService(TransparencyLedger(generate_keypair(), log_id=f"integration-log-{seed}"), counters)
    log_server = await _serve(log_service.handle)
    log_port = _server_port(log_server)
    gateway_servers: dict[str, asyncio.AbstractServer] = {}
    gateway_ports: dict[str, int] = {}
    gateway_services: dict[str, _GatewayService] = {}
    try:
        append_response = await _request(
            log_port,
            {
                "type": "append",
                "event": event_payload,
                "certificate": certificate_payload,
                "appended_at": issued_at + log_append_delay,
                "sth_timestamp": issued_at + log_append_delay,
            },
            counters,
        )
        sth_payload = _expect_dict(append_response.get("sth"))

        for index in range(n_gateways):
            gateway_id = f"gw-{index}"
            service = _GatewayService(
                GatewayState(gateway_id),
                tool_port=tool_port,
                issuer_public_key=issuer.public,
                federation=federation,
                counters=counters,
                protocol_profile=protocol_profile,
            )
            server = await _serve(service.handle)
            gateway_services[gateway_id] = service
            gateway_servers[gateway_id] = server
            gateway_ports[gateway_id] = _server_port(server)

        schedules = tuple(
            _fault_schedule(
                gateway_id=f"gw-{index}",
                index=index,
                rng=rng,
                fault_scenario=fault_scenario,
                horizon=horizon,
                push_delay=push_delay,
                poll_interval=poll_interval,
                log_append_delay=log_append_delay,
                log_delay=log_delay,
                jitter=jitter,
                partition_duration=partition_duration,
                gateway_restart_at=gateway_restart_at,
            )
            for index in range(n_gateways)
        )

        pre_revocation_allowed = 0
        sampled_revoked_calls_allowed = 0
        sampled_revoked_calls_rejected = 0
        post_repair_rejected = 0
        push_attempts = 0
        push_delivered = 0
        push_dropped = 0
        log_repairs = 0

        for schedule in schedules:
            port = gateway_ports[schedule.gateway_id]
            pre_response = await _request(
                port,
                _protocol_request(
                    protocol_profile,
                    request_id=f"{schedule.gateway_id}-pre",
                    gateway_id=schedule.gateway_id,
                    edge_id=event.edge_id,
                    tool_name=tool_name,
                    call_time=-0.001,
                ),
                counters,
            )
            if _response_accepted(protocol_profile, pre_response):
                pre_revocation_allowed += 1

            if schedule.initial_via == "push":
                push_attempts += 1
                counters.push_attempts += 1
                push_response = await _request(
                    port,
                    {
                        "type": "learn_revocation",
                        "via": "push",
                        "event": event_payload,
                        "certificate": certificate_payload,
                        "delivered_at": schedule.first_learn_at,
                    },
                    counters,
                )
                if push_response.get("accepted"):
                    push_delivered += 1
                    counters.push_delivered += 1
            else:
                push_attempts += 1
                push_dropped += 1
                counters.push_attempts += 1
                counters.push_suppressed += 1

            if schedule.stale_intervals:
                for interval_index, (start, end) in enumerate(schedule.stale_intervals):
                    if end <= 0.0 or start >= horizon:
                        continue
                    call_time = min(horizon - 0.0001, max(start + 0.0001, (start + min(end, horizon)) / 2.0))
                    response = await _request(
                        port,
                        _protocol_request(
                            protocol_profile,
                            request_id=f"{schedule.gateway_id}-stale-{interval_index}",
                            gateway_id=schedule.gateway_id,
                            edge_id=event.edge_id,
                            tool_name=tool_name,
                            call_time=call_time,
                        ),
                        counters,
                    )
                    if _response_accepted(protocol_profile, response):
                        sampled_revoked_calls_allowed += 1
                    elif _response_rejected(protocol_profile, response):
                        sampled_revoked_calls_rejected += 1

            if schedule.restart_at is not None:
                await _request(port, {"type": "restart", "restart_at": schedule.restart_at}, counters)

            if schedule.repair_via is not None:
                latest = await _request(log_port, {"type": "latest"}, counters)
                await _request(
                    port,
                    {
                        "type": "learn_revocation",
                        "via": schedule.repair_via,
                        "event": latest.get("event"),
                        "certificate": latest.get("certificate"),
                        "sth": latest.get("sth", sth_payload),
                        "delivered_at": schedule.final_learn_at,
                    },
                    counters,
                )
                log_repairs += 1

            post_time = min(horizon, schedule.final_learn_at + 0.001)
            post_response = await _request(
                port,
                _protocol_request(
                    protocol_profile,
                    request_id=f"{schedule.gateway_id}-post",
                    gateway_id=schedule.gateway_id,
                    edge_id=event.edge_id,
                    tool_name=tool_name,
                    call_time=post_time,
                ),
                counters,
            )
            if _response_rejected(protocol_profile, post_response):
                sampled_revoked_calls_rejected += 1
                post_repair_rejected += 1
            elif _response_accepted(protocol_profile, post_response):
                sampled_revoked_calls_allowed += 1

        gateway_states = [service.state for service in gateway_services.values()]
        return IntegrationTrialResult(
            seed=seed,
            n_gateways=n_gateways,
            protocol_profile=protocol_profile,
            fault_scenario=fault_scenario,
            tool_name=tool_name,
            tool_call_rate=tool_call_rate,
            task_duration=task_duration,
            ttl=ttl,
            push_delay=push_delay,
            poll_interval=poll_interval,
            log_append_delay=log_append_delay,
            log_delay=log_delay,
            partition_duration=partition_duration,
            gateway_restart_at=gateway_restart_at,
            issued_at=issued_at,
            counters=counters,
            wall_time_seconds=time.perf_counter() - wall_start,
            root_count=root_count,
            root_threshold=threshold,
            event_payload_bytes=len(canonical_json_bytes(event_payload)),
            certificate_payload_bytes=len(canonical_json_bytes(certificate_payload)),
            gateway_ports=gateway_ports,
            tool_port=tool_port,
            log_port=log_port,
            stale_windows=tuple(schedule.stale_window(horizon) for schedule in schedules),
            final_learn_latencies=tuple(schedule.final_learn_at for schedule in schedules),
            recovery_latencies=tuple(
                schedule.recovery_latency for schedule in schedules if schedule.recovery_latency is not None
            ),
            pre_revocation_calls=n_gateways,
            pre_revocation_allowed=pre_revocation_allowed,
            sampled_revoked_calls_allowed=sampled_revoked_calls_allowed,
            sampled_revoked_calls_rejected=sampled_revoked_calls_rejected,
            post_repair_rejected=post_repair_rejected,
            protocol_calls=sum(state.protocol_calls for state in gateway_states),
            protocol_schema_passes=sum(state.protocol_schema_passes for state in gateway_states),
            forwarded_tool_calls=sum(state.forwarded_tool_calls for state in gateway_states),
            gateway_restarts=sum(state.restarts for state in gateway_states),
            push_attempts=push_attempts,
            push_delivered=push_delivered,
            push_dropped=push_dropped,
            log_repairs=log_repairs,
            signature_verified_events=sum(state.signature_verified_events for state in gateway_states),
            certificate_verified_events=sum(state.certificate_verified_events for state in gateway_states),
            rejected_events=sum(state.rejected_events for state in gateway_states),
            tool_accepted_invocations=tool_state.accepted_invocations,
            tool_rejected_invocations=tool_state.rejected_invocations,
            audit_evidence_gateways=sum(1 for state in gateway_states if state.audit_evidence_available),
        )
    finally:
        tool_server.close()
        await tool_server.wait_closed()
        log_server.close()
        await log_server.wait_closed()
        for server in gateway_servers.values():
            server.close()
        for server in gateway_servers.values():
            await server.wait_closed()


def _fault_schedule(
    *,
    gateway_id: str,
    index: int,
    rng: random.Random,
    fault_scenario: str,
    horizon: float,
    push_delay: float,
    poll_interval: float,
    log_append_delay: float,
    log_delay: float,
    jitter: float,
    partition_duration: float,
    gateway_restart_at: float,
) -> FaultSchedule:
    jitter_width = max(0.0, jitter)
    offset = rng.random() * jitter_width * max(push_delay, 0.001)
    log_offset = rng.random() * jitter_width * max(poll_interval, 0.001)
    if fault_scenario == "none":
        learn_at = push_delay + offset
        return FaultSchedule(
            gateway_id=gateway_id,
            stale_intervals=((0.0, min(learn_at, horizon)),),
            first_learn_at=learn_at,
            final_learn_at=learn_at,
            initial_via="push",
        )
    if fault_scenario == "push-drop-log-repair":
        learn_at = poll_interval + log_append_delay + log_delay + log_offset
        return FaultSchedule(
            gateway_id=gateway_id,
            stale_intervals=((0.0, min(learn_at, horizon)),),
            first_learn_at=learn_at,
            final_learn_at=learn_at,
            initial_via="drop",
            repair_via="log-repair",
            recovery_latency=learn_at,
        )
    if fault_scenario == "log-delay":
        delay = log_delay if log_delay > 0.0 else poll_interval * 2.0
        learn_at = poll_interval + log_append_delay + delay + log_offset
        return FaultSchedule(
            gateway_id=gateway_id,
            stale_intervals=((0.0, min(learn_at, horizon)),),
            first_learn_at=learn_at,
            final_learn_at=learn_at,
            initial_via="drop",
            repair_via="log-delay-repair",
            recovery_latency=learn_at,
        )
    if fault_scenario == "partition-heal":
        learn_at = partition_duration + poll_interval + log_append_delay + log_delay + log_offset
        return FaultSchedule(
            gateway_id=gateway_id,
            stale_intervals=((0.0, min(learn_at, horizon)),),
            first_learn_at=learn_at,
            final_learn_at=learn_at,
            initial_via="drop",
            repair_via="partition-heal-log-repair",
            recovery_latency=max(0.0, learn_at - partition_duration),
        )
    if fault_scenario == "gateway-restart":
        push_learn_at = push_delay + offset
        restart_at = min(max(gateway_restart_at + index * 0.001, push_learn_at + 0.001), max(push_learn_at + 0.001, horizon / 2.0))
        repair_at = restart_at + poll_interval + log_append_delay + log_delay + log_offset
        intervals: list[tuple[float, float]] = [(0.0, min(push_learn_at, horizon))]
        if restart_at < horizon:
            intervals.append((restart_at, min(repair_at, horizon)))
        return FaultSchedule(
            gateway_id=gateway_id,
            stale_intervals=tuple(intervals),
            first_learn_at=push_learn_at,
            final_learn_at=repair_at,
            initial_via="push",
            repair_via="restart-log-repair",
            restart_at=restart_at,
            recovery_latency=max(0.0, repair_at - restart_at),
        )
    raise ValueError(f"unknown fault scenario: {fault_scenario}")


def _protocol_request(
    protocol_profile: str,
    *,
    request_id: str,
    gateway_id: str,
    edge_id: str,
    tool_name: str,
    call_time: float,
) -> dict[str, Any]:
    operation = {
        "kind": "repo-write",
        "path": "artifacts/generated.txt",
        "content_sha256": f"sha256:{request_id}",
    }
    if protocol_profile == "raw-http-json":
        return {
            "type": "agent_tool_call",
            "request_id": request_id,
            "gateway_id": gateway_id,
            "edge_id": edge_id,
            "tool_name": tool_name,
            "operation": operation,
            "call_time": call_time,
        }
    if protocol_profile == "mcp-style-jsonrpc":
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {
                "gateway_id": gateway_id,
                "name": tool_name,
                "arguments": {
                    "edge_id": edge_id,
                    "operation": operation,
                    "call_time": call_time,
                },
            },
        }
    if protocol_profile == "a2a-task-lifecycle":
        return {
            "type": "a2a_task_call",
            "taskId": f"task-{request_id}",
            "contextId": f"context-{gateway_id}",
            "message": {
                "role": "agent",
                "parts": [
                    {
                        "kind": "data",
                        "data": {
                            "gateway_id": gateway_id,
                            "edge_id": edge_id,
                            "tool_name": tool_name,
                            "operation": operation,
                            "call_time": call_time,
                        },
                    }
                ],
            },
            "metadata": {
                "capabilityEdgeId": edge_id,
                "gatewayId": gateway_id,
                "callTime": call_time,
            },
        }
    raise ValueError(f"unknown protocol profile: {protocol_profile}")


def _parse_protocol_call(request: dict[str, Any], protocol_profile: str) -> dict[str, Any] | None:
    try:
        if protocol_profile == "raw-http-json":
            if request.get("type") != "agent_tool_call":
                return None
            return {
                "gateway_id": str(request["gateway_id"]),
                "edge_id": str(request["edge_id"]),
                "tool_name": str(request["tool_name"]),
                "operation": _expect_dict(request.get("operation")),
                "call_time": float(request["call_time"]),
            }
        if protocol_profile == "mcp-style-jsonrpc":
            if request.get("jsonrpc") != "2.0" or request.get("method") != "tools/call":
                return None
            params = _expect_dict(request.get("params"))
            arguments = _expect_dict(params.get("arguments"))
            return {
                "gateway_id": str(params["gateway_id"]),
                "edge_id": str(arguments["edge_id"]),
                "tool_name": str(params["name"]),
                "operation": _expect_dict(arguments.get("operation")),
                "call_time": float(arguments["call_time"]),
            }
        if protocol_profile == "a2a-task-lifecycle":
            if request.get("type") != "a2a_task_call":
                return None
            message = _expect_dict(request.get("message"))
            parts = message.get("parts")
            if not isinstance(parts, list) or not parts:
                return None
            data = _expect_dict(_expect_dict(parts[0]).get("data"))
            metadata = _expect_dict(request.get("metadata"))
            return {
                "gateway_id": str(metadata["gatewayId"]),
                "edge_id": str(metadata["capabilityEdgeId"]),
                "tool_name": str(data["tool_name"]),
                "operation": _expect_dict(data.get("operation")),
                "call_time": float(metadata["callTime"]),
            }
    except (KeyError, TypeError, ValueError):
        return None
    return None


def _protocol_response(
    protocol_profile: str,
    request: dict[str, Any],
    *,
    accepted: bool,
    rejected: bool,
    reason: str | None,
    gateway_id: str,
    tool_response: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if protocol_profile == "raw-http-json":
        return {
            "ok": True,
            "accepted": accepted,
            "rejected": rejected,
            "reason": reason,
            "gateway_id": gateway_id,
            "tool_response": tool_response,
        }
    if protocol_profile == "mcp-style-jsonrpc":
        if accepted:
            result: dict[str, Any] = {"accepted": True, "gateway_id": gateway_id, "tool_response": tool_response}
        else:
            result = {"accepted": False, "rejected": rejected, "gateway_id": gateway_id, "reason": reason}
        return {"jsonrpc": "2.0", "id": request.get("id"), "result": result}
    if protocol_profile == "a2a-task-lifecycle":
        state = "completed" if accepted else "canceled" if rejected else "failed"
        return {
            "ok": True,
            "taskId": request.get("taskId"),
            "contextId": request.get("contextId"),
            "state": state,
            "accepted": accepted,
            "rejected": rejected,
            "reason": reason,
            "gateway_id": gateway_id,
        }
    raise ValueError(f"unknown protocol profile: {protocol_profile}")


def _response_accepted(protocol_profile: str, response: dict[str, Any]) -> bool:
    if protocol_profile == "mcp-style-jsonrpc":
        result = response.get("result")
        return isinstance(result, dict) and result.get("accepted") is True
    return response.get("accepted") is True


def _response_rejected(protocol_profile: str, response: dict[str, Any]) -> bool:
    if protocol_profile == "mcp-style-jsonrpc":
        result = response.get("result")
        return isinstance(result, dict) and result.get("rejected") is True
    return response.get("rejected") is True
