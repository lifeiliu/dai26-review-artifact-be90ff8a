# E-B7 Protocol: Reproducibility and Sensitivity Experiment

Status: paper-scale run complete on 2026-06-24.

## Research Question

RQ7: Are the main propagation conclusions robust to the simulator's exposed
fanout, polling, jitter, and delay-scale parameters, and are runs reproducible
from saved metadata?

## Hypothesis

- H7: Around the E-B2 baseline, single-factor variation changes the
  latency/overhead tradeoff but does not break completeness in the tested local
  parameter range.

## Scope Lock

In scope:

- Single-factor sensitivity design around the E-B2 hybrid baseline.
- Deterministic seeds and run keys.
- Saved reproducibility manifest with command, Python/platform metadata, row
  counts, output files, and parameter values.

Out of scope:

- Production trace calibration.
- Multi-factor interaction sweep.
- Adaptive tuning policy.

## Variables

- Number of relying parties: 100, 300.
- Seeds: 0..9.
- Baseline: hybrid, fanout=8, poll interval=0.5s, jitter=0.2, delay scale=1.0.
- Fanout values: 4, 8, 16.
- Poll interval values: 0.25s, 0.5s, 1.0s.
- Jitter values: 0.0, 0.2, 0.4.
- Delay scale values: 0.5, 1.0, 2.0.

## Metrics

- Completeness.
- p50/p95/p99/max `delta_prop`.
- Channel messages, gossip messages, log polls, and log appends.
- Undelivered count.
- p99 ratio versus same-`n` baseline.
- Completeness delta versus same-`n` baseline.

## Paper-Scale Run

- Output directory: `data/run_2026_06_24_e_b7_paper`
- Raw rows: 180
- Aggregate rows: 18
- Runtime: 170.78s
- Command:

```bash
python3 experiments/e_b_research_suite.py \
  --experiment e-b7 \
  --profile paper \
  --seeds 0:10 \
  --n-parties 100,300 \
  --fanout-grid 4,8,16 \
  --poll-interval-grid 0.25,0.5,1.0 \
  --jitter-grid 0,0.2,0.4 \
  --delay-scale-grid 0.5,1,2 \
  --output-dir data/run_2026_06_24_e_b7_paper
```

## Result Summary

H7 is supported for the tested local range:

- Minimum completeness: 1.0.
- Maximum p99 `delta_prop`: 0.5296s.
- Maximum p99 over same-`n` baseline: 1.3248x.
- Baseline n=300 p99 `delta_prop`: 0.3957s.
- Delay scale 2.0, n=300 p99 `delta_prop`: 0.5242s.
- Fanout 16, n=300 p99 `delta_prop`: 0.3841s, with mean channel messages
  152681.2.
- Fanout 4, n=300 p99 `delta_prop`: 0.4314s, with mean channel messages
  41863.7.

The result supports sensitivity coverage, not production trace realism. The
paper should keep the workload-trace limitation and use E-B7 to show that key
simulator knobs are explicit and measured.
