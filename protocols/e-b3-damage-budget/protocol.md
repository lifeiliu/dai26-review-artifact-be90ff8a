# E-B3 Protocol: Damage Budget Evaluation

Status: paper-scale run complete on 2026-06-23.

## Research Question

RQ4: How much unauthorized-ops damage accumulates during the propagation window, using Paper A's `v * (TTL + delta_prop)` formula?

## Hypothesis

- H4: Hybrid keeps expected stale-authority damage under an operator budget for regimes where TTL-only and push-only exceed it.

## Pre-Run Decision

Define undelivered-party accounting before running confirmatory experiments:

1. TTL fallback model: undelivered parties discover by TTL expiration.
2. Lower/upper-bound model: lower bound excludes undelivered; upper bound assigns max observation window or infinity.
3. Service-risk model: report probability of violating a max stale-window SLO.

Use all three in exploratory analysis if needed, but choose one primary model for confirmatory plots.

## Variables

- TTL: 10s, 30s, 60s, 300s, 3600s.
- Velocity `v`: 1, 10, 100, 1000 unauthorized operations per second.
- Operator damage budget: predeclared thresholds, for example 100, 1000, 10000 unauthorized operations.
- `delta_prop`: measured from E-B2, not hand-set.

## Metrics

- Expected unauthorized operations.
- Worst-case unauthorized operations.
- Probability of exceeding operator budget.
- Contribution of propagation delay versus TTL.

## Analysis Plan

Plot damage versus TTL and adversary strength. The main claim should be threshold-based: "hybrid stays under budget B in region R; baseline X violates it."

## Paper-Scale Run

- Output directory: `data/run_2026_06_23_e_b3_paper`
- Source measurements: `data/run_2026_06_23_e_b2_paper/e_b2_delta_prop_baselines.csv`
- Raw rows: 28800
- Aggregate rows: 960
- Runtime: 0.97s

## Result Summary

H4 is supported as a budget-frontier claim, not a global guarantee.

At TTL=60, velocity=10, and budget=1000:

- n=1000 hybrid expected/worst unauthorized ops: 304.29 / 604.29
- n=1000 push expected/worst unauthorized ops: 900 / 1200
- n=1000 TTL-RCC expected/worst unauthorized ops: 900 / 1200

Hybrid remains below the worst-case budget while push and TTL-RCC exceed it. However, for sufficiently high velocity or long TTL, all strategies can exceed smaller budgets, so the paper should report budget frontiers.
