# E-B4 Equivocation Resistance Report

Raw rows: 360
Aggregate rows: 7
Below-threshold rejection rate: 1.0000
Split-view detection rate: 1.0000
Benign false-positive rate: 0.0000
Baseline miss rate: 1.0000
Max detection latency: 5.3000
Mean evidence bytes: 821.0

## Run Config

- `n_parties_values`: `(1000,)`
- `observation_delays`: `(0.25, 0.5, 1.0, 2.0)`
- `partition_heal_delays`: `(0.5, 2.0, 5.0)`
- `root_counts`: `(5,)`
- `seeds`: `(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29)`
- `thresholds`: `(3,)`

## Scenario Aggregates

| scenario | roots | threshold | corrupt | runs | cert accept | detect | success | false positive | latency mean/max | evidence bytes |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| below-threshold-root-fork | 5 | 3 | 1 | 30 | 0.0000 | 0.0000 | 1.0000 | 0.0000 | / | 0.0 |
| benign-sth-reordering | 5 | 3 | 0 | 30 | 1.0000 | 0.0000 | 1.0000 | 0.0000 | / | 0.0 |
| partition-heal-split-view | 5 | 3 | 3 | 90 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 2.8000/5.3000 | 821.0 |
| single-root-baseline | 1 | 1 | 1 | 30 | 1.0000 | 0.0000 | 1.0000 | 0.0000 | / | 0.0 |
| threshold-plus-split-view-log | 5 | 3 | 3 | 120 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 1.2375/2.3000 | 821.0 |
| threshold-without-sth-cross-observation | 5 | 3 | 3 | 30 | 1.0000 | 0.0000 | 1.0000 | 0.0000 | / | 0.0 |
| two-of-five-root-fork | 5 | 3 | 2 | 30 | 0.0000 | 0.0000 | 1.0000 | 0.0000 | / | 0.0 |

## Interpretation

E-B4 supports the root-quorum plus STH cross-observation story: below-threshold roots fail certificate verification, while quorum-certified split views are detected after honest observers compare same-size STHs. The result is conditional on eventual cross-observation after partitions heal.
