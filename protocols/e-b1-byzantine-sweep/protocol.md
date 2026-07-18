# E-B1 Protocol: Byzantine Suppression Sweep

Status: protocol draft, not yet run.

## Research Questions

- RQ1: Can revocation events reach relying parties under drop, selective suppression, replay, and equivocation attempts?
- RQ3: Can suppression/equivocation be detected within bounded time?

## Hypotheses

- H2: Suppression detection latency is bounded by a small multiple of the gossip interval or log poll interval when the honest relying-party overlay remains connected.

## Confirmatory Prediction

For connected honest overlays and adversary strength up to a predeclared threshold, hybrid should maintain completeness >= 0.99 and detection probability >= 0.99. Detection latency should track `min(gossip_repair_time, log_poll_interval + log_append_delay)` rather than TTL.

## Independent Variables

- `n_parties`: 10, 100, 1000, 10000 if runtime permits.
- Push suppression fraction: 0.0, 0.1, 0.2, 0.4, 0.6.
- Gossip suppression fraction: 0.0, 0.1, 0.2, 0.4.
- Log suppression or poll failure fraction: 0.0, 0.1, 0.2.
- Network partitions: none, short partition, long partition with recovery.
- Replay window: none, stale event replay, stale STH replay.
- Seeds: at least 30 for fast sweeps, 100 for final reported configurations.

## Metrics

- Propagation completeness.
- Detection probability.
- Detection latency p50/p95/p99.
- Recovery latency p50/p95/p99.
- Undelivered count and identity class.
- Message overhead by channel.
- Log poll count and STH/proof bytes.

## Sanity Checks

- With adversary strength 0, all live strategies that should deliver must deliver.
- Push-only must degrade when push suppression increases.
- TTL-only must ignore suppression but pay TTL-scale delay.
- Replayed events must not overwrite newer accepted revocation state.

## Analysis Plan

Plot completeness and detection latency versus adversary strength. Mark the operating region where hybrid satisfies the budget. Record configurations where the theorem assumptions break.

