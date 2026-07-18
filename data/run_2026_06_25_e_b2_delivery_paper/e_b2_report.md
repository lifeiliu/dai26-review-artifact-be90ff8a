# E-B2 Delta Propagation Baseline Report

Raw rows: 780
Aggregate rows: 26

## Run Config

- `delivery_regimes`: `('full-snapshot', 'request-time-check', 'request-time-fail-open', 'compact-delta', 'dns-log-poll', 'hybrid')`
- `delta_interval`: `30.0`
- `dns_poll_interval`: `60.0`
- `n_parties_values`: `(1000,)`
- `request_time_latency`: `0.05`
- `seeds`: `(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29)`
- `snapshot_period`: `300.0`
- `status_suppression_values`: `(0.0, 0.2, 0.5)`

## Strategy Aggregates

| family | n | strategy/regime | push drop | status drop | runs | completeness mean +- ci95 | p99 delta mean +- ci95 | messages mean +- ci95 | stale window | bytes/party | state/party | undelivered mean |
|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| delivery-regime | 1000 | compact-delta |  | 0.00 | 30 | 1.0000 +- 0.0000 | 29.6440 +- 0.0370 | 1000.0 +- 0.0 | 29.9660 | 1024.0 | 4096.0 | 0.00 |
| delivery-regime | 1000 | compact-delta |  | 0.20 | 30 | 1.0000 +- 0.0000 | 60.0000 +- 0.0000 | 1000.0 +- 0.0 | 60.0000 | 1024.0 | 4096.0 | 0.00 |
| delivery-regime | 1000 | compact-delta |  | 0.50 | 30 | 1.0000 +- 0.0000 | 60.0000 +- 0.0000 | 1000.0 +- 0.0 | 60.0000 | 1024.0 | 4096.0 | 0.00 |
| delivery-regime | 1000 | dns-log-poll |  | 0.00 | 30 | 1.0000 +- 0.0000 | 59.3362 +- 0.0547 | 2000.0 +- 0.0 | 59.9287 | 1024.0 | 2048.0 | 0.00 |
| delivery-regime | 1000 | dns-log-poll |  | 0.20 | 30 | 1.0000 +- 0.0000 | 60.0000 +- 0.0000 | 2000.0 +- 0.0 | 60.0000 | 1024.0 | 2048.0 | 0.00 |
| delivery-regime | 1000 | dns-log-poll |  | 0.50 | 30 | 1.0000 +- 0.0000 | 60.0000 +- 0.0000 | 2000.0 +- 0.0 | 60.0000 | 1024.0 | 2048.0 | 0.00 |
| delivery-regime | 1000 | full-snapshot |  | 0.00 | 30 | 1.0000 +- 0.0000 | 296.6642 +- 0.3073 | 1000.0 +- 0.0 | 299.7189 | 125000.0 | 125000.0 | 0.00 |
| delivery-regime | 1000 | full-snapshot |  | 0.20 | 30 | 1.0000 +- 0.0000 | 296.6969 +- 0.3690 | 1000.0 +- 0.0 | 299.7616 | 125000.0 | 125000.0 | 0.00 |
| delivery-regime | 1000 | full-snapshot |  | 0.50 | 30 | 1.0000 +- 0.0000 | 296.8725 +- 0.4498 | 1000.0 +- 0.0 | 299.7426 | 125000.0 | 125000.0 | 0.00 |
| delivery-regime | 1000 | hybrid | 0.20 | 0.00 | 30 | 1.0000 +- 0.0000 | 0.3983 +- 0.0007 | 262069.6 +- 30.8 | 0.4293 | 134179.6 | 2048.0 | 0.00 |
| delivery-regime | 1000 | hybrid | 0.20 | 0.20 | 30 | 1.0000 +- 0.0000 | 0.3983 +- 0.0007 | 262077.2 +- 31.8 | 0.4387 | 134183.5 | 2048.0 | 0.00 |
| delivery-regime | 1000 | hybrid | 0.20 | 0.50 | 30 | 1.0000 +- 0.0000 | 0.3983 +- 0.0007 | 262080.1 +- 32.7 | 0.4420 | 134185.0 | 2048.0 | 0.00 |
| delivery-regime | 1000 | request-time-check |  | 0.00 | 30 | 1.0000 +- 0.0000 | 0.0500 +- 0.0000 | 1000.0 +- 0.0 | 0.0500 | 900.0 | 256.0 | 0.00 |
| delivery-regime | 1000 | request-time-check |  | 0.20 | 30 | 0.8000 +- 0.0000 | 0.0500 +- 0.0000 | 1000.0 +- 0.0 | 0.0500 | 900.0 | 256.0 | 200.00 |
| delivery-regime | 1000 | request-time-check |  | 0.50 | 30 | 0.5000 +- 0.0000 | 0.0500 +- 0.0000 | 1000.0 +- 0.0 | 0.0500 | 900.0 | 256.0 | 500.00 |
| delivery-regime | 1000 | request-time-fail-open |  | 0.00 | 30 | 1.0000 +- 0.0000 | 0.0500 +- 0.0000 | 1000.0 +- 0.0 | 0.0500 | 900.0 | 256.0 | 0.00 |
| delivery-regime | 1000 | request-time-fail-open |  | 0.20 | 30 | 1.0000 +- 0.0000 | 60.0000 +- 0.0000 | 1000.0 +- 0.0 | 60.0000 | 900.0 | 256.0 | 0.00 |
| delivery-regime | 1000 | request-time-fail-open |  | 0.50 | 30 | 1.0000 +- 0.0000 | 60.0000 +- 0.0000 | 1000.0 +- 0.0 | 60.0000 | 900.0 | 256.0 | 0.00 |
| propagation-strategy | 1000 | gossip | 0.20 |  | 30 | 1.0000 +- 0.0000 | 1.4410 +- 0.0078 | 212901.0 +- 198.5 |  |  |  | 0.00 |
| propagation-strategy | 1000 | gossip-log | 0.20 |  | 30 | 1.0000 +- 0.0000 | 0.5489 +- 0.0001 | 248223.4 +- 43.1 |  |  |  | 0.00 |
| propagation-strategy | 1000 | hybrid | 0.20 |  | 30 | 1.0000 +- 0.0000 | 0.3983 +- 0.0007 | 262069.6 +- 30.8 |  |  |  | 0.00 |
| propagation-strategy | 1000 | log | 0.20 |  | 30 | 1.0000 +- 0.0000 | 0.5489 +- 0.0001 | 15504.5 +- 4.8 |  |  |  | 0.00 |
| propagation-strategy | 1000 | push | 0.20 |  | 30 | 0.8000 +- 0.0000 | 0.0598 +- 0.0000 | 1000.0 +- 0.0 |  |  |  | 200.00 |
| propagation-strategy | 1000 | push-gossip | 0.20 |  | 30 | 1.0000 +- 0.0000 | 0.3982 +- 0.0009 | 246548.7 +- 38.0 |  |  |  | 0.00 |
| propagation-strategy | 1000 | push-log | 0.20 |  | 30 | 1.0000 +- 0.0000 | 0.5444 +- 0.0005 | 16505.3 +- 4.7 |  |  |  | 0.00 |
| propagation-strategy | 1000 | ttl-rcc | 0.20 |  | 30 | 1.0000 +- 0.0000 | 60.0000 +- 0.0000 | 0.0 +- 0.0 |  |  |  | 0.00 |

## Hybrid Comparisons

| n | hybrid p99 | hybrid - push-gossip p99 | hybrid - log p99 | hybrid - TTL p99 | hybrid / push-gossip messages |
|---:|---:|---:|---:|---:|---:|
| 1000 | 0.3983 | 0.0001 | -0.1506 | -59.6017 | 1.063 |

## Delivery Regime Comparisons

| n | status drop | hybrid stale window | hybrid/full snapshot stale | hybrid/fail-open stale | hybrid/compact delta stale | hybrid/dns-poll stale | hybrid/full snapshot bytes |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 1000 | 0.00 | 0.4293 | 0.001 | 8.587 | 0.014 | 0.007 | 1.073 |
| 1000 | 0.20 | 0.4387 | 0.001 | 0.007 | 0.007 | 0.007 | 1.073 |
| 1000 | 0.50 | 0.4420 | 0.001 | 0.007 | 0.007 | 0.007 | 1.073 |

## Interpretation

Hybrid should be framed as near push-gossip latency with log-backed auditability, not as an unconditional latency winner. Delivery-regime baselines are mechanism-level simulations for related-work comparison, not faithful reimplementations of CRLite, Clubcards, RevDNS, OCSP, or VC status-list systems.
