# E-B19 Risk-Weighted Selective-Omission Pilots

## Material Passport

- Origin Skill: academic-research-suite / experiment-agent
- Origin Mode: plan
- Origin Date: 2026-07-14
- Verification Status: UNVERIFIED
- Version Label: e-b19-pilot-prereg-v1

## Status

This protocol was frozen before either pilot was executed. The pilots are
exploratory go/no-go tests for a possible paper pivot; they do not replace the
preregistered E-B17 result.

## Research Question

Does receiver-count suppression conceal materially different post-revocation
harm when selective omission is correlated with tool-call rate or effect
severity, and can a fixed repair-message budget reduce that harm by allocating
repair attempts according to gateway risk?

## Common Setup

- Gateways: 1,000.
- Seeds: 0--29.
- Horizon: 60 seconds.
- Confirmatory suppression fraction: 0.20.
- Diagnostic suppression fractions: 0.10 and 0.30.
- Direct delivery delay: `0.02 + 0.03 * U(0, 1)` seconds.
- Independent log observation delay: `0.05 + 10 * U(0, 1)` seconds.
- Fast repair delay: minimum of allocated attempts, where attempt `j` has
  delay `0.10 + 0.40 * U_j(0, 1)` seconds.
- Every random variate is derived deterministically from the seed, gateway,
  and attempt index and is paired across target-selection and repair policies.

The risk-weighted stale-effect metric is

`sum_g(call_rate_g * effect_severity_g * enforcement_delay_g)`.

It is also reported after division by total gateway risk, yielding a
risk-weighted mean stale window in seconds.

Round 1 additionally reports suppression-attributable harm by subtracting the
paired no-fault direct-delivery delay at every targeted gateway:

`sum_targeted risk_g * max(0, enforcement_delay_g - direct_delay_g)`.

This subtraction prevents the common direct-delivery latency, which exists
even without omission, from diluting the risk-concentration measurement.

## Risk Profiles

1. `uniform`: call rate 10 and severity 1 at every gateway.
2. `zipf-rate`: call rates follow rank exponent 1.2 and are normalized to mean
   10; severity is 1.
3. `zipf-correlated`: call rates follow rank exponent 1.1 and are normalized to
   mean 10; severity is proportional to `call_rate ** 0.75` and normalized to
   mean 1. This is an explicitly adversarial concentration stress, not a claim
   that production traffic follows this distribution.

Risk ranks are randomly permuted over gateway identities for every seed.

## Target-Selection Policies

- `random`: paired uniform rank.
- `top-rate`: highest call-rate gateways.
- `top-severity`: highest effect-severity gateways.
- `top-risk`: highest `call_rate * effect_severity` gateways.

Each policy suppresses exactly `round(suppression_fraction * n_gateways)`
gateways.

## Round 1: Targeted-Omission Stress

### Mechanism Models

- `push-only`: direct delivery to non-targets; targets remain stale to the
  horizon.
- `log-poll`: every gateway observes the independent log; target identity has
  no effect on enforcement delay.
- `push-repair`: direct delivery to non-targets; targets enforce at the minimum
  of independent log observation and five uniformly allocated fast-repair
  attempts. Its accounting remains matched to E-B17: five repair messages per
  suppressed gateway.

### Primary Comparison

For `push-repair`, compare `top-risk` with `random` at 20% suppression within
each heavy-tail profile. Define amplification as the ratio of
suppression-attributable risk-weighted harm under the two target policies.

### Round-1 Go/No-Go Rule

Round 1 supports continuing to Round 2 when:

1. mean amplification is at least 3.0 in both `zipf-rate` and
   `zipf-correlated`; and
2. the paired 95% percentile-bootstrap interval for the top-risk minus random
   harm difference is entirely above zero in both profiles.

Mechanism ranking and the feasible Pareto set are diagnostic. They are not
required for the Round-1 gate and must be reported even if unchanged.

## Round 2: Equal-Budget Risk-Aware Repair

Round 2 uses the 20% suppression cell, the two heavy-tail profiles, and the
`random` and `top-risk` target policies. A missing direct-delivery
acknowledgement identifies the suppressed set before the fast-repair attempts
are allocated. This observability assumption is part of the pilot boundary.

Each suppressed gateway receives at least one fast-repair attempt. The total
number of attempts is fixed at five times the number of suppressed gateways,
matching the E-B17 repair-message accounting.

- `uniform`: exactly five attempts per suppressed gateway.
- `rate-aware`: one attempt per suppressed gateway, with remaining attempts
  allocated by largest remainder in proportion to `sqrt(call_rate)`.
- `risk-aware`: one attempt per suppressed gateway, with remaining attempts
  allocated by largest remainder in proportion to
  `sqrt(call_rate * effect_severity)`.

The square-root rule is frozen because, under the attempt-delay model,
`E[min delay | k] = 0.10 + 0.40 / (k + 1)`; the continuous relaxation of
weighted delay minimization allocates `k + 1` proportional to square-root
risk.

All policies retain identical direct push, independent log polling, append
share, message count, byte count, explicit convergence, audit evidence, and
benign availability behavior.

### Round-2 Go/No-Go Rule

Round 2 supports the risk-aware-repair idea when, in the `zipf-correlated`,
`top-risk`, 20% cell:

1. risk-aware repair reduces mean risk-weighted stale effects by at least 30%
   relative to uniform repair;
2. the paired 95% percentile-bootstrap interval for risk-aware minus uniform
   harm is entirely below zero;
3. message and byte counts match exactly; and
4. both policies retain 1.0 explicit convergence, 1.0 audit-evidence rate, and
   0 benign availability loss.

The `zipf-rate` cell and rate-aware ablation are diagnostic and must be
reported without changing the gate.

## Analysis and Multiplicity

- Thirty paired seeds per cell.
- 10,000 paired percentile-bootstrap resamples for primary differences.
- Two-sided exact sign tests are reported descriptively.
- Round-1 heavy-tail profile tests receive Holm correction across the two
  primary comparisons.
- This is an exploratory pilot. Passing the gate supports investment in real
  agent-tool workloads and multi-host validation; it does not establish an
  externally valid distributional claim.

## Reproducibility

The harness is deterministic for a fixed command, seed range, and code
version. A successful validation rerun must reproduce primary JSON summaries
and CSV outputs byte-for-byte. Timing metadata, if any, is excluded from the
comparison.
