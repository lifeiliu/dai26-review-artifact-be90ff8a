# E-B3 Damage Budget Report

Raw rows: 28800
Aggregate rows: 960
Hybrid safe while baseline expected exceeds cells: 6
Hybrid safe while baseline worst exceeds cells: 6
Maximum expected damage: 5400000.00
Maximum worst-case damage: 7200000.00

## Run Config

- `budgets`: `(100.0, 1000.0, 10000.0)`
- `gossip_suppression_values`: `(0.0, 0.1, 0.2)`
- `log_suppression_values`: `(0.0, 0.1, 0.2)`
- `measured_csv`: `data/run_2026_06_23_e_b2_paper/e_b2_delta_prop_baselines.csv`
- `n_parties_values`: `(1000,)`
- `push_suppression_values`: `(0.0, 0.1, 0.2, 0.4, 0.6)`
- `seeds`: `(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29)`
- `ttls`: `(10.0, 30.0, 60.0, 300.0, 3600.0)`
- `velocities`: `(1.0, 10.0, 100.0, 1000.0)`

## Focus Slice: TTL=60, velocity=10, budget=1000

| n | strategy | runs | expected mean | worst mean | expected exceed | worst exceed | damage delta | source completeness |
|---:|---|---:|---:|---:|---:|---:|---:|---:|
| 100 | gossip | 30 | 310.91 | 610.91 | 0.00 | 0.00 | 1.0907 | 1.0000 |
| 100 | gossip-log | 30 | 305.49 | 605.49 | 0.00 | 0.00 | 0.5494 | 1.0000 |
| 100 | hybrid | 30 | 304.01 | 604.01 | 0.00 | 0.00 | 0.4008 | 1.0000 |
| 100 | log | 30 | 305.49 | 605.49 | 0.00 | 0.00 | 0.5495 | 1.0000 |
| 100 | push | 30 | 900.00 | 1200.00 | 0.00 | 1.00 | 60.0000 | 0.8000 |
| 100 | push-gossip | 30 | 304.07 | 604.07 | 0.00 | 0.00 | 0.4067 | 1.0000 |
| 100 | push-log | 30 | 305.44 | 605.44 | 0.00 | 0.00 | 0.5441 | 1.0000 |
| 100 | ttl-rcc | 30 | 900.00 | 1200.00 | 0.00 | 1.00 | 60.0000 | 1.0000 |
| 1000 | gossip | 30 | 315.94 | 615.94 | 0.00 | 0.00 | 1.5943 | 1.0000 |
| 1000 | gossip-log | 30 | 305.50 | 605.50 | 0.00 | 0.00 | 0.5499 | 1.0000 |
| 1000 | hybrid | 30 | 304.29 | 604.29 | 0.00 | 0.00 | 0.4293 | 1.0000 |
| 1000 | log | 30 | 305.50 | 605.50 | 0.00 | 0.00 | 0.5499 | 1.0000 |
| 1000 | push | 30 | 900.00 | 1200.00 | 0.00 | 1.00 | 60.0000 | 0.8000 |
| 1000 | push-gossip | 30 | 304.92 | 604.92 | 0.00 | 0.00 | 0.4919 | 1.0000 |
| 1000 | push-log | 30 | 305.49 | 605.49 | 0.00 | 0.00 | 0.5495 | 1.0000 |
| 1000 | ttl-rcc | 30 | 900.00 | 1200.00 | 0.00 | 1.00 | 60.0000 | 1.0000 |

## H4 Evidence Cells

| n | ttl | velocity | budget | hybrid expected | hybrid worst | hybrid/push expected | hybrid/ttl expected |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 100 | 60 | 1 | 100 | 30.40 | 60.40 | 0.338 | 0.338 |
| 100 | 60 | 10 | 1000 | 304.01 | 604.01 | 0.338 | 0.338 |
| 100 | 60 | 100 | 10000 | 3040.08 | 6040.08 | 0.338 | 0.338 |
| 1000 | 60 | 1 | 100 | 30.43 | 60.43 | 0.338 | 0.338 |
| 1000 | 60 | 10 | 1000 | 304.29 | 604.29 | 0.338 | 0.338 |
| 1000 | 60 | 100 | 10000 | 3042.93 | 6042.93 | 0.338 | 0.338 |

## Interpretation

E-B3 maps measured propagation delay into stale-authority damage. Report both expected and worst-case budget violations because TTL fallback can make push-only and TTL-RCC differ from hybrid mainly in the worst-case region.
