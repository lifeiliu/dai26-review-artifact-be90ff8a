# E-B2 Protocol: delta_prop Baseline Matrix

Status: protocol draft, not yet run.

## Research Question

RQ2: What is `delta_prop` in practice, and how does hybrid bound it versus push-only, gossip-only, log-only, and TTL-RCC baselines?

## Hypothesis

- H1: P3 hybrid achieves completeness >= 0.99 and lower p99 `delta_prop` than every single-channel baseline under moderate selective suppression.

## Confirmatory Prediction

Under matched network models, hybrid should behave like push for unsuppressed parties and like the faster of gossip/log repair for suppressed parties. Push-only should have low latency for delivered parties but incomplete delivery. TTL-RCC should have full eventual completeness but high `delta_prop`.

## Matched Strategies

- Push-only.
- Gossip-only.
- Log-only.
- TTL-RCC.
- Push+gossip.
- Push+log.
- Gossip+log.
- Full hybrid.

## Network Model

Replace deterministic constants with sampled delays:

- Push delay distribution: log-normal or empirical local RPC distribution.
- Gossip interval distribution: fixed interval plus jitter.
- Log append delay: fixed plus queueing model.
- Poll interval: configured sweep.
- Loss model: independent loss plus targeted suppression.

## Metrics

- `delta_prop` p50/p95/p99/p999.
- Completeness.
- Time-to-first-90-percent and time-to-first-99-percent.
- Message count per delivered revocation.
- Log load per relying party.
- CPU time and wall-clock simulation time.

## Raw Output

Save one row per strategy, seed, and configuration in `data/e_b2_delta_prop_sweep.csv`.

## Analysis Plan

Use CDF plots and budget-threshold plots. Report whether hybrid is Pareto-superior or whether it trades latency for overhead.

