# E-B5 Thin A2A Deployability Report

Raw rows: 270
Aggregate rows: 9
A2A SDK available: True
A2A SDK versions: ['1.1.0']
Transport modes: ['local-a2a-shaped-json']
Ordering success rate: 1.0000
Mean payload bytes: 485.0
Mean transport delay model: 0.001485

## Run Config

- `n_parties_values`: `(3, 10, 30)`
- `seeds`: `(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29)`
- `strategies`: `('push', 'log', 'hybrid')`
- `transport_mode`: `local-a2a-shaped-json`

## Strategy Aggregates

| n | strategy | runs | completeness | p99 delta | messages | payload bytes | transport delay | undelivered |
|---:|---|---:|---:|---:|---:|---:|---:|---:|
| 3 | hybrid | 30 | 1.0000 | 0.0522 | 294.7 | 485.0 | 0.001485 | 0.00 |
| 3 | log | 30 | 1.0000 | 0.5026 | 46.3 | 485.0 | 0.001485 | 0.00 |
| 3 | push | 30 | 0.6667 | 0.0493 | 3.0 | 485.0 | 0.001485 | 1.00 |
| 10 | hybrid | 30 | 1.0000 | 0.3450 | 3201.2 | 485.0 | 0.001485 | 0.00 |
| 10 | log | 30 | 1.0000 | 0.5324 | 155.1 | 485.0 | 0.001485 | 0.00 |
| 10 | push | 30 | 0.8000 | 0.0563 | 10.0 | 485.0 | 0.001485 | 2.00 |
| 30 | hybrid | 30 | 1.0000 | 0.3574 | 28089.5 | 485.0 | 0.001485 | 0.00 |
| 30 | log | 30 | 1.0000 | 0.5461 | 462.6 | 485.0 | 0.001485 | 0.00 |
| 30 | push | 30 | 0.8000 | 0.0603 | 30.0 | 485.0 | 0.001485 | 6.00 |

## Ordering Checks

| n | hybrid completeness | push completeness | hybrid p99 | log p99 | ordering preserved |
|---:|---:|---:|---:|---:|---|
| 3 | 1.0000 | 0.6667 | 0.0522 | 0.5026 | True |
| 10 | 1.0000 | 0.8000 | 0.3450 | 0.5324 | True |
| 30 | 1.0000 | 0.8000 | 0.3574 | 0.5461 | True |

## Interpretation

E-B5 validates the thin A2A binding surface and local payload/transport overhead model. It is a deployability check, not a standards or multi-implementation interoperability claim.
