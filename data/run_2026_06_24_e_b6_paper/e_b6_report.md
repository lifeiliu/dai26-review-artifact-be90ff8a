# E-B6 Local End-to-End Transport Report

Raw rows: 120
Aggregate rows: 12
Service models: ['asyncio-tcp-jsonl']
Strategies: ['hybrid', 'log', 'push', 'push-gossip']
Mean transport errors: 0.0000
Minimum completeness: 0.8000
Maximum p99 delta: 1.7697
Mean root-certificate verification rate: 1.0000

## Run Config

- `duration`: `1.5`
- `gossip_fanout`: `4`
- `n_parties_values`: `(10, 30, 100)`
- `seeds`: `(0, 1, 2, 3, 4, 5, 6, 7, 8, 9)`
- `strategies`: `('push', 'log', 'push-gossip', 'hybrid')`

## Aggregates

| n | strategy | runs | completeness | p99 delta | max delta | requests | errors | bytes sent | cert verify | undelivered |
|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 10 | hybrid | 10 | 1.0000 | 0.1690 | 0.2068 | 342.1 | 0.00 | 384520 | 1.0000 | 0.00 |
| 10 | log | 10 | 1.0000 | 0.1704 | 0.1706 | 153.0 | 0.00 | 110022 | 1.0000 | 0.00 |
| 10 | push | 10 | 0.8000 | 0.0538 | 0.0574 | 9.0 | 0.00 | 12735 | 1.0000 | 2.00 |
| 10 | push-gossip | 10 | 1.0000 | 0.1712 | 0.1960 | 232.8 | 0.00 | 331772 | 1.0000 | 0.00 |
| 30 | hybrid | 10 | 1.0000 | 0.3068 | 0.3074 | 545.1 | 0.00 | 541168 | 1.0000 | 0.00 |
| 30 | log | 10 | 1.0000 | 0.1881 | 0.1886 | 340.6 | 0.00 | 242087 | 1.0000 | 0.00 |
| 30 | push | 10 | 0.8000 | 0.1152 | 0.1191 | 25.0 | 0.00 | 35364 | 1.0000 | 6.00 |
| 30 | push-gossip | 10 | 0.9967 | 0.4016 | 0.5061 | 310.6 | 0.00 | 442591 | 1.0000 | 0.10 |
| 100 | hybrid | 10 | 1.0000 | 0.5778 | 0.5783 | 782.7 | 0.00 | 703197 | 1.0000 | 0.00 |
| 100 | log | 10 | 1.0000 | 0.2378 | 0.2378 | 691.0 | 0.00 | 487646 | 1.0000 | 0.00 |
| 100 | push | 10 | 0.8000 | 0.3323 | 0.3357 | 81.0 | 0.00 | 114595 | 1.0000 | 20.00 |
| 100 | push-gossip | 10 | 0.9830 | 1.2514 | 1.3800 | 340.4 | 0.00 | 484765 | 1.0000 | 1.70 |

## Interpretation

E-B6 upgrades the evidence type from an in-process simulator to a real loopback JSONL transport prototype. Services still run in one asyncio process, so this is not a production deployment, but every propagation step crosses TCP and JSON serialization boundaries.
