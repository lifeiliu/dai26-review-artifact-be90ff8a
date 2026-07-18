"""Byzantine propagation harness and baseline matrix."""

from __future__ import annotations

from dataclasses import dataclass

from .crypto import generate_keypair
from .damage import unauthorized_ops_expected, unauthorized_ops_worst
from .events import create_revocation_event
from .ledger_client import TransparencyLedger
from .propagator import FaultPolicy, PropagationConfig, PropagationResult, PropagationStrategy, Propagator


@dataclass(frozen=True)
class TrialParams:
    n_parties: int = 10
    ttl: float = 60.0
    velocity: float = 10.0
    suppressed_push_fraction: float = 0.2
    max_time: float = 5.0


@dataclass(frozen=True)
class TrialMetrics:
    strategy: PropagationStrategy
    completeness: float
    p50_delta: float | None
    p95_delta: float | None
    p99_delta: float | None
    max_delta: float | None
    unauthorized_ops_worst: float | None
    unauthorized_ops_expected: float | None
    undelivered: tuple[str, ...]
    suppression_detected_at: float | None
    channel_messages: int = 0
    push_messages: int = 0
    gossip_messages: int = 0
    log_polls: int = 0


def run_trial(
    strategy: PropagationStrategy,
    params: TrialParams | None = None,
    *,
    config: PropagationConfig | None = None,
) -> tuple[PropagationResult, TrialMetrics]:
    params = params or TrialParams()
    config = config or PropagationConfig(max_time=params.max_time)
    issuer = generate_keypair()
    log_key = generate_keypair()
    event = create_revocation_event("edge-alpha-to-worker", issuer, epoch_id="epoch-1", issued_at=0.0)
    ledger = TransparencyLedger(log_key)
    party_ids = [f"rp-{i}" for i in range(params.n_parties)]
    suppressed_count = int(params.n_parties * params.suppressed_push_fraction)
    suppressed = frozenset(party_ids[-suppressed_count:]) if suppressed_count else frozenset()
    policy = FaultPolicy(suppress_push_to=suppressed)
    result = Propagator(config).propagate(
        event,
        ledger=ledger,
        party_ids=party_ids,
        strategy=strategy,
        fault_policy=policy,
        ttl=params.ttl,
    )
    delta_for_damage = None if result.undelivered else result.max_delta
    metrics = TrialMetrics(
        strategy=strategy,
        completeness=result.completeness,
        p50_delta=result.p50_delta,
        p95_delta=result.p95_delta,
        p99_delta=result.p99_delta,
        max_delta=result.max_delta,
        unauthorized_ops_worst=(
            None
            if delta_for_damage is None
            else unauthorized_ops_worst(params.ttl, params.velocity, delta_for_damage)
        ),
        unauthorized_ops_expected=(
            None
            if delta_for_damage is None
            else unauthorized_ops_expected(params.ttl, params.velocity, delta_for_damage)
        ),
        undelivered=result.undelivered,
        suppression_detected_at=result.suppression_detected_at,
        channel_messages=result.overhead.channel_messages,
        push_messages=result.overhead.push_messages,
        gossip_messages=result.overhead.gossip_messages,
        log_polls=result.overhead.log_polls,
    )
    return result, metrics


def run_baseline_matrix(params: TrialParams | None = None) -> list[TrialMetrics]:
    params = params or TrialParams()
    return [
        run_trial(strategy, params)[1]
        for strategy in ("push", "gossip", "log", "ttl-rcc", "hybrid")
    ]
