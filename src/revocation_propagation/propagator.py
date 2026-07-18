"""Discrete-event push/gossip/log propagation simulation."""

from __future__ import annotations

import heapq
import random
import statistics
from dataclasses import dataclass, field
from typing import Literal

from .events import RevocationEvent
from .ledger_client import SignedTreeHead, TransparencyLedger

PropagationStrategy = Literal[
    "push",
    "gossip",
    "log",
    "ttl-rcc",
    "push-gossip",
    "push-log",
    "gossip-log",
    "hybrid",
]


@dataclass(frozen=True)
class PropagationConfig:
    push_delay: float = 0.05
    push_jitter: float = 0.0
    gossip_delay: float = 0.10
    gossip_jitter: float = 0.0
    gossip_interval: float = 0.25
    gossip_interval_jitter: float = 0.0
    gossip_fanout: int | None = None
    poll_interval: float = 0.50
    poll_jitter: float = 0.0
    log_append_delay: float = 0.05
    log_append_jitter: float = 0.0
    max_time: float = 5.0
    random_seed: int | None = None


@dataclass(frozen=True)
class FaultPolicy:
    """Fault switches for propagation experiments."""

    suppress_push_to: frozenset[str] = frozenset()
    suppress_gossip_to: frozenset[str] = frozenset()
    suppress_log_to: frozenset[str] = frozenset()

    def drops(self, channel: str, party_id: str) -> bool:
        if channel == "push":
            return party_id in self.suppress_push_to
        if channel == "gossip":
            return party_id in self.suppress_gossip_to
        if channel == "log":
            return party_id in self.suppress_log_to
        return False


@dataclass
class RelyingParty:
    party_id: str
    received: dict[str, float] = field(default_factory=dict)
    via: dict[str, str] = field(default_factory=dict)
    observed_sths: dict[int, SignedTreeHead] = field(default_factory=dict)
    equivocation_detected_at: float | None = None

    def receive_event(self, event: RevocationEvent, *, now: float, via: str, event_id: str | None = None) -> bool:
        event_key = event.event_id if event_id is None else event_id
        if event_key in self.received:
            return False
        self.received[event_key] = now
        self.via[event_key] = via
        return True

    def observe_sth(self, sth: SignedTreeHead, *, now: float) -> None:
        prior = self.observed_sths.get(sth.size)
        if prior is not None and prior.root_hash != sth.root_hash:
            if self.equivocation_detected_at is None:
                self.equivocation_detected_at = now
        self.observed_sths[sth.size] = sth


@dataclass(frozen=True)
class DeliveryRecord:
    party_id: str
    first_seen_at: float
    delta_prop: float
    via: str


@dataclass(frozen=True)
class PropagationOverhead:
    scheduled_events: int = 0
    push_messages: int = 0
    gossip_messages: int = 0
    log_polls: int = 0
    log_appends: int = 0
    sth_observations: int = 0

    @property
    def channel_messages(self) -> int:
        return self.push_messages + self.gossip_messages + self.log_polls


@dataclass(frozen=True)
class PropagationResult:
    strategy: PropagationStrategy
    issued_at: float
    records: tuple[DeliveryRecord, ...]
    undelivered: tuple[str, ...]
    suppression_detected_at: float | None = None
    equivocation_detected_at: float | None = None
    overhead: PropagationOverhead = field(default_factory=PropagationOverhead)

    @property
    def completeness(self) -> float:
        total = len(self.records) + len(self.undelivered)
        if total == 0:
            return 1.0
        return len(self.records) / total

    @property
    def deltas(self) -> tuple[float, ...]:
        return tuple(record.delta_prop for record in self.records)

    @property
    def max_delta(self) -> float | None:
        if not self.records:
            return None
        return max(self.deltas)

    @property
    def p50_delta(self) -> float | None:
        if not self.records:
            return None
        return statistics.median(self.deltas)

    @property
    def p95_delta(self) -> float | None:
        return self.percentile_delta(0.95)

    @property
    def p99_delta(self) -> float | None:
        return self.percentile_delta(0.99)

    @property
    def p999_delta(self) -> float | None:
        return self.percentile_delta(0.999)

    def percentile_delta(self, quantile: float) -> float | None:
        if not self.records:
            return None
        if quantile < 0 or quantile > 1:
            raise ValueError("quantile must be between 0 and 1")
        ordered = sorted(self.deltas)
        idx = min(len(ordered) - 1, int(quantile * (len(ordered) - 1)))
        return ordered[idx]


@dataclass(order=True)
class _Scheduled:
    at: float
    order: int
    kind: str = field(compare=False)
    source: str = field(compare=False)
    dest: str = field(compare=False)


class Propagator:
    """Run a discrete-event propagation trial over relying parties."""

    def __init__(self, config: PropagationConfig | None = None) -> None:
        self.config = config or PropagationConfig()

    def propagate(
        self,
        event: RevocationEvent,
        *,
        ledger: TransparencyLedger,
        party_ids: list[str],
        strategy: PropagationStrategy,
        fault_policy: FaultPolicy | None = None,
        source_party_id: str | None = None,
        ttl: float | None = None,
    ) -> PropagationResult:
        if not party_ids:
            return PropagationResult(strategy=strategy, issued_at=event.issued_at, records=(), undelivered=())
        policy = fault_policy or FaultPolicy()
        source = source_party_id or party_ids[0]
        parties = {party_id: RelyingParty(party_id) for party_id in party_ids}
        queue: list[_Scheduled] = []
        counter = 0
        rng = random.Random(self.config.random_seed)
        log_appended = False
        latest_sth: SignedTreeHead | None = None
        suppression_detected_at: float | None = None
        scheduled_events = 0
        push_messages = 0
        gossip_messages = 0
        log_polls = 0
        log_appends = 0
        sth_observations = 0

        def schedule(at: float, kind: str, source_id: str, dest_id: str) -> None:
            nonlocal counter, scheduled_events
            if at <= self.config.max_time:
                counter += 1
                scheduled_events += 1
                heapq.heappush(queue, _Scheduled(at, counter, kind, source_id, dest_id))

        def sample(base: float, jitter: float) -> float:
            if jitter <= 0.0:
                return base
            lower = max(0.0, base * (1.0 - jitter))
            upper = max(lower, base * (1.0 + jitter))
            return rng.uniform(lower, upper)

        def next_gossip_interval() -> float:
            return sample(self.config.gossip_interval, self.config.gossip_interval_jitter)

        def next_poll_interval() -> float:
            return sample(self.config.poll_interval, self.config.poll_jitter)

        uses_push = strategy in {"push", "push-gossip", "push-log", "hybrid"}
        uses_gossip = strategy in {"gossip", "push-gossip", "gossip-log", "hybrid"}
        uses_log = strategy in {"log", "push-log", "gossip-log", "hybrid"}
        event_id = event.event_id

        if strategy == "ttl-rcc":
            observed_at = event.issued_at + (ttl if ttl is not None else self.config.max_time)
            records = tuple(
                DeliveryRecord(
                    party_id=party_id,
                    first_seen_at=observed_at,
                    delta_prop=observed_at - event.issued_at,
                    via="ttl",
                )
                for party_id in party_ids
            )
            return PropagationResult(strategy=strategy, issued_at=event.issued_at, records=records, undelivered=())

        if uses_gossip:
            parties[source].receive_event(event, now=event.issued_at, via="source", event_id=event_id)
            schedule(event.issued_at + next_gossip_interval(), "gossip_tick", source, source)

        if uses_push:
            for party_id in party_ids:
                schedule(event.issued_at + sample(self.config.push_delay, self.config.push_jitter), "push", source, party_id)

        if uses_log:
            schedule(event.issued_at + sample(self.config.log_append_delay, self.config.log_append_jitter), "append_log", source, source)
            for party_id in party_ids:
                schedule(event.issued_at + next_poll_interval(), "poll_log", party_id, party_id)

        while queue:
            item = heapq.heappop(queue)
            now = item.at
            if item.kind == "append_log":
                if not log_appended:
                    ledger.append(event, appended_at=now)
                    latest_sth = ledger.latest_sth(timestamp=now)
                    log_appended = True
                    log_appends += 1
                continue

            if item.kind == "push":
                push_messages += 1
                if not policy.drops("push", item.dest):
                    parties[item.dest].receive_event(event, now=now, via="push", event_id=event_id)
                    if uses_gossip:
                        schedule(now + next_gossip_interval(), "gossip_tick", item.dest, item.dest)
                continue

            if item.kind == "poll_log":
                log_polls += 1
                if latest_sth is not None:
                    parties[item.dest].observe_sth(latest_sth, now=now)
                    sth_observations += 1
                if log_appended and not policy.drops("log", item.dest):
                    got_new = parties[item.dest].receive_event(event, now=now, via="log", event_id=event_id)
                    if got_new and uses_gossip:
                        schedule(now + next_gossip_interval(), "gossip_tick", item.dest, item.dest)
                elif log_appended and policy.drops("log", item.dest):
                    if suppression_detected_at is None:
                        suppression_detected_at = now
                schedule(now + next_poll_interval(), "poll_log", item.dest, item.dest)
                continue

            if item.kind == "gossip_tick":
                if event_id not in parties[item.source].received:
                    continue
                peers = [party_id for party_id in party_ids if party_id != item.source]
                if self.config.gossip_fanout is not None and self.config.gossip_fanout < len(peers):
                    peers = rng.sample(peers, max(0, self.config.gossip_fanout))
                for peer_id in peers:
                    schedule(now + sample(self.config.gossip_delay, self.config.gossip_jitter), "gossip_msg", item.source, peer_id)
                schedule(now + next_gossip_interval(), "gossip_tick", item.source, item.source)
                continue

            if item.kind == "gossip_msg":
                gossip_messages += 1
                if policy.drops("gossip", item.dest):
                    continue
                got_new = parties[item.dest].receive_event(event, now=now, via="gossip", event_id=event_id)
                if got_new:
                    if (
                        uses_push
                        and suppression_detected_at is None
                        and item.dest in policy.suppress_push_to
                    ):
                        suppression_detected_at = now
                    schedule(now + next_gossip_interval(), "gossip_tick", item.dest, item.dest)

        records: list[DeliveryRecord] = []
        undelivered: list[str] = []
        equivocation_times: list[float] = []
        for party_id in party_ids:
            party = parties[party_id]
            if party.equivocation_detected_at is not None:
                equivocation_times.append(party.equivocation_detected_at)
            seen = party.received.get(event_id)
            if seen is None:
                undelivered.append(party_id)
            else:
                records.append(
                    DeliveryRecord(
                        party_id=party_id,
                        first_seen_at=seen,
                        delta_prop=seen - event.issued_at,
                        via=party.via[event_id],
                    )
                )
        records.sort(key=lambda record: record.party_id)
        return PropagationResult(
            strategy=strategy,
            issued_at=event.issued_at,
            records=tuple(records),
            undelivered=tuple(sorted(undelivered)),
            suppression_detected_at=suppression_detected_at,
            equivocation_detected_at=min(equivocation_times) if equivocation_times else None,
            overhead=PropagationOverhead(
                scheduled_events=scheduled_events,
                push_messages=push_messages,
                gossip_messages=gossip_messages,
                log_polls=log_polls,
                log_appends=log_appends,
                sth_observations=sth_observations,
            ),
        )
