# E-B2 Delta Propagation Baseline Report

Raw rows: 28
Aggregate rows: 14

## Run Config

- `delivery_regimes`: `('full-snapshot', 'request-time-check', 'request-time-fail-open', 'compact-delta', 'dns-log-poll', 'hybrid')`
- `n_parties_values`: `(24,)`
- `seeds`: `(0, 1)`
- `status_suppression_values`: `(0.0, 0.5)`
- `strategies`: `('hybrid', 'push-gossip')`

## Strategy Aggregates

| family | n | strategy/regime | push drop | status drop | runs | completeness mean +- ci95 | p99 delta mean +- ci95 | messages mean +- ci95 | stale window | bytes/party | state/party | undelivered mean |
|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| delivery-regime | 24 | compact-delta |  | 0.00 | 2 | 1.0000 +- 0.0000 | 26.8617 +- 1.4537 | 24.0 +- 0.0 | 27.3240 | 1024.0 | 4096.0 | 0.00 |
| delivery-regime | 24 | compact-delta |  | 0.50 | 2 | 1.0000 +- 0.0000 | 60.0000 +- 0.0000 | 24.0 +- 0.0 | 60.0000 | 1024.0 | 4096.0 | 0.00 |
| delivery-regime | 24 | dns-log-poll |  | 0.00 | 2 | 1.0000 +- 0.0000 | 55.8353 +- 0.6213 | 48.0 +- 0.0 | 57.6701 | 1024.0 | 2048.0 | 0.00 |
| delivery-regime | 24 | dns-log-poll |  | 0.50 | 2 | 1.0000 +- 0.0000 | 60.0000 +- 0.0000 | 48.0 +- 0.0 | 60.0000 | 1024.0 | 2048.0 | 0.00 |
| delivery-regime | 24 | full-snapshot |  | 0.00 | 2 | 1.0000 +- 0.0000 | 271.9694 +- 1.8708 | 24.0 +- 0.0 | 293.4537 | 125000.0 | 125000.0 | 0.00 |
| delivery-regime | 24 | full-snapshot |  | 0.50 | 2 | 1.0000 +- 0.0000 | 281.8505 +- 9.4224 | 24.0 +- 0.0 | 293.7524 | 125000.0 | 125000.0 | 0.00 |
| delivery-regime | 24 | hybrid | 0.20 | 0.00 | 2 | 1.0000 +- 0.0000 | 0.3492 +- 0.0376 | 18062.5 +- 55.9 | 0.3542 | 385333.3 | 2048.0 | 0.00 |
| delivery-regime | 24 | hybrid | 0.20 | 0.50 | 2 | 1.0000 +- 0.0000 | 0.3492 +- 0.0376 | 18062.5 +- 55.9 | 0.3542 | 385333.3 | 2048.0 | 0.00 |
| delivery-regime | 24 | request-time-check |  | 0.00 | 2 | 1.0000 +- 0.0000 | 0.0500 +- 0.0000 | 24.0 +- 0.0 | 0.0500 | 900.0 | 256.0 | 0.00 |
| delivery-regime | 24 | request-time-check |  | 0.50 | 2 | 0.5000 +- 0.0000 | 0.0500 +- 0.0000 | 24.0 +- 0.0 | 0.0500 | 900.0 | 256.0 | 12.00 |
| delivery-regime | 24 | request-time-fail-open |  | 0.00 | 2 | 1.0000 +- 0.0000 | 0.0500 +- 0.0000 | 24.0 +- 0.0 | 0.0500 | 900.0 | 256.0 | 0.00 |
| delivery-regime | 24 | request-time-fail-open |  | 0.50 | 2 | 1.0000 +- 0.0000 | 60.0000 +- 0.0000 | 24.0 +- 0.0 | 60.0000 | 900.0 | 256.0 | 0.00 |
| propagation-strategy | 24 | hybrid | 0.20 |  | 2 | 1.0000 +- 0.0000 | 0.3492 +- 0.0376 | 18062.5 +- 55.9 |  |  |  | 0.00 |
| propagation-strategy | 24 | push-gossip | 0.20 |  | 2 | 1.0000 +- 0.0000 | 0.3552 +- 0.0161 | 17652.0 +- 23.5 |  |  |  | 0.00 |

## Hybrid Comparisons

| n | hybrid p99 | hybrid - push-gossip p99 | hybrid - log p99 | hybrid - TTL p99 | hybrid / push-gossip messages |
|---:|---:|---:|---:|---:|---:|
| 24 | 0.3492 | -0.0060 |  |  | 1.023 |

## Delivery Regime Comparisons

| n | status drop | hybrid stale window | hybrid/full snapshot stale | hybrid/fail-open stale | hybrid/compact delta stale | hybrid/dns-poll stale | hybrid/full snapshot bytes |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 24 | 0.00 | 0.3542 | 0.001 | 7.084 | 0.013 | 0.006 | 3.083 |
| 24 | 0.50 | 0.3542 | 0.001 | 0.006 | 0.006 | 0.006 | 3.083 |

## Interpretation

Hybrid should be framed as near push-gossip latency with log-backed auditability, not as an unconditional latency winner. Delivery-regime baselines are mechanism-level simulations for related-work comparison, not faithful reimplementations of CRLite, Clubcards, RevDNS, OCSP, or VC status-list systems.
