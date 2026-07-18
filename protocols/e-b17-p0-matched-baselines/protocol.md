# E-B17 Protocol: P0 Matched Strongest-Mechanism Baselines

## Material Passport

- Origin Skill: academic-research-suite / experiment-agent
- Origin Mode: plan
- Origin Date: 2026-07-14T13:56:48-07:00
- Verification Status: PREREGISTERED
- Version Label: e-b17-prereg-v1
- Frozen Against Git Parent: `7fb7a05`

## Freeze Statement

This protocol is frozen before E-B17 implementation and before any E-B17 result
is observed. Confirmatory cells, thresholds, exclusions, and the RevProp verdict
rule may not be changed after a result is generated. Later changes must create a
new version, preserve this file, and label the new analysis exploratory.

## Objective and Research Question

E-B17 tests whether RevProp has a **constrained empirical advantage**, not
mechanism-level novelty, over the strongest adjacent delivery mechanisms under
selective non-delivery at cached agent tool gateways.

RQ-P0: Under identical relying-party identities, suppression targets, request
traces, horizon, and cost accounting, does RevProp reduce post-revocation stale
tool calls while preserving explicit-event convergence, benign availability,
and independently checkable audit evidence within a matched resource budget?

## Mechanisms

The comparison includes all of the following mechanism-level models:

1. `aip-03`: signed webhook notification, first attempt within 5 seconds,
   retries after 1/2/4 seconds, then CRL/live-status fallback.
2. `drp-10-60`: authoritative signed revocation log with a 60-second polling
   policy and independently checkable log evidence.
3. `drp-10-300`: the corresponding 300-second relaxed polling policy.
4. `hbhc`: implicit fail-closed heartbeat cessation with the paper's default
   10-second heartbeat interval and 30-second maximum age, including multipath
   gossip cost. It does not count as positive-event convergence.
5. `caep-ssf`: signed CAEP session-revoked SET over an SSF push stream. SSF does
   not define a universal latency or retry SLA; the delay below is an explicit
   experiment setting, not a standards recommendation.
6. `status-list`: signed snapshot/status-list polling.
7. `ttl-cache`: local credential expiry without a positive revocation event.
8. `sync-fail-open`: request-time status checking that permits on error.
9. `sync-fail-closed`: request-time status checking that denies on error.
10. `revprop`: quorum-approved positive event over direct push, bounded gossip,
    and a transparency-inspired independently readable repair log.

These are disclosed mechanism models, not claims of source-compatible
reimplementation, production interoperability, or cryptographic equivalence to
the cited systems.

## Profiles

Each mechanism is run under two profiles.

### `recommended`

- AIP: 5-second first-attempt ceiling, 1/2/4-second retries, 60-second fallback
  poll used as an explicitly disclosed artifact setting because the draft does
  not mandate a CRL polling period.
- DRP: 60-second and 300-second policies exactly as named.
- HBHC: `Delta_h = 10 s`, `W_max = 30 s`.
- CAEP/SSF: 50-ms local stream delivery and no invented independent fallback.
- Status list and TTL: 60 seconds.
- RevProp: artifact defaults: 50-ms direct push, 250-ms gossip round, 500-ms log
  poll, and 50-ms log append.

### `matched`

All mechanisms face the same per-gateway, 60-second resource ceilings:

- mean control messages: at most **8.1**;
- mean control bytes: at most **8,192**;
- benign availability loss: at most **1%**.

Polling mechanisms are rescaled to a 10-second poll interval where needed and
the rescaling is recorded in every raw row. HBHC retains its published 10/30-s
configuration. RevProp uses 10-second log polling and gossip fan-out 5. A model
that inherently exceeds a ceiling is retained in the table but is infeasible
for the confirmatory verdict; it is not silently normalized or removed.

The cost unit is a transmitted control message. Bytes include the complete
modeled event, proof, heartbeat, status response, or snapshot payload. CPU and
model inference are outside E-B17 and are measured separately in E-B18.

## Paired Experimental Design

- Type: deterministic discrete-event simulation with stochastic paired traces.
- Seeds: `0..29`.
- Gateways: `1,000`.
- Revocation time: `t = 0`.
- Observation and task horizon: 60 seconds.
- Revoked tool-call rate: 10 calls per gateway per second.
- Common random numbers: each seed creates one set of gateway delay variates,
  request traces, and suppression ranks reused by every mechanism.
- Suppression targets: identical gateway IDs for all mechanisms in a cell.
- Suppression fractions: 0%, 20%, and 50%.
- Fault schedules:
  - `none`: no channel suppression;
  - `selective-operator`: the targeted gateways do not receive operator-owned
    direct notifications, streams, or status responses; independently readable
    logs and peer paths remain reachable;
  - `correlated-all`: direct, operator-status, independent-log, and peer repair
    paths are blocked for the targeted gateways.

The **confirmatory cells** are only `profile=matched`,
`fault=selective-operator`, `suppression in {0.20, 0.50}`. All other cells are
diagnostic or external-validity context and cannot rescue a failed verdict.

## Outcomes

Primary outcomes, evaluated per seed and mechanism:

- `explicit_event_completeness`: fraction receiving a positive revocation fact
  by 60 seconds. HBHC, TTL, and request-time status policies score zero by
  definition even if they enforce denial.
- `stale_tool_calls`: total revoked calls admitted before enforcement.
- `availability_loss_rate`: false denial rate on a paired benign no-revocation
  trace under the same channel fault.
- `audit_evidence_rate`: fraction holding independently checkable signed-log
  evidence for the positive revocation by 60 seconds. A signed push/SET alone
  does not satisfy this field.
- `control_messages_per_gateway` and `control_bytes_per_gateway`.

Secondary outcomes include enforcement completeness, censored event p99,
enforcement p99, signed-event rate, independent-repair rate, and worst stale
window. Non-delivery is censored at the 60-second horizon for latency summaries;
it is never dropped from the denominator.

## Confirmatory Feasibility Gate

A mechanism is feasible in a confirmatory cell only if its 30-seed mean meets
all conditions:

- explicit-event completeness >= 0.99;
- audit-evidence rate >= 0.99;
- benign availability loss <= 0.01;
- control messages per gateway <= 8.1;
- control bytes per gateway <= 8,192.

At least one non-RevProp mechanism must be feasible. Otherwise the cell is
`INCONCLUSIVE`, not a RevProp win.

## Statistical Analysis

For each feasible baseline in each confirmatory cell:

1. pair RevProp and baseline by seed;
2. compute the mean paired difference in stale tool calls
   (`RevProp - baseline`), relative reduction, and probability of superiority;
3. obtain a two-sided 95% percentile interval from 10,000 deterministic paired
   bootstrap resamples;
4. compute a two-sided bootstrap p-value with the finite-resample correction;
5. apply Holm family-wise correction across all confirmatory
   cell-by-baseline comparisons.

The analysis also reports the Pareto frontier over explicit convergence,
stale calls, availability loss, audit evidence, messages, and bytes. A point is
dominated only when another point is no worse on all six dimensions and
strictly better on at least one.

## Frozen RevProp Verdict Rule

RevProp has a `SUPPORTED_CONSTRAINED_ADVANTAGE` only if at least one
confirmatory cell satisfies all of the following:

1. RevProp passes the feasibility gate;
2. at least one non-RevProp mechanism passes the same gate;
3. RevProp is on the six-dimensional Pareto frontier;
4. against **every** feasible non-RevProp baseline in that cell, the paired
   stale-call difference favors RevProp, its 95% interval is strictly below
   zero, Holm-adjusted `p < 0.05`, and relative reduction is at least 20%;
5. E-B18's real LLM/MCP workflow shows the same directional enforcement result
   under selective fault injection, with no post-repair revoked tool success;
6. P0-3 claim-boundary checks and the P0-5 literature refresh pass.

The verdict is `NO_MATCHED_ADVANTAGE_PIVOT` if no confirmatory cell passes and
all required runs complete. It is `INCONCLUSIVE` if required evidence is
missing, a real-system run is blocked, or fewer than 30 paired seeds survive.

The named-system framing must pivot to a benchmark/SoK contribution for either
`NO_MATCHED_ADVANTAGE_PIVOT` or `INCONCLUSIVE`; only
`SUPPORTED_CONSTRAINED_ADVANTAGE` permits retaining RevProp as an evaluated
instantiation, and even then no mechanism-first novelty claim is permitted.

## Exclusions and Missing Data

- No seed or mechanism row may be removed for an unfavorable result.
- A deterministic implementation crash invalidates the cell until diagnosed;
  it is not automatically retried or imputed.
- Timing out before 60 seconds is encoded as censored non-delivery, not missing.
- Exploratory parameter sweeps must be written to a separate directory and may
  not alter the confirmatory summary.

## Exact Planned Commands

Working directory: `artifact/`.

```bash
python3 -m pytest -q
python3 experiments/e_b_research_suite.py --experiment e-b17 --profile smoke --output-dir _outputs/e_b17_smoke
python3 experiments/e_b_research_suite.py --experiment e-b17 --profile paper --output-dir data/run_2026_07_14_e_b17_p0_matched
python3 scripts/validate_e_b17.py data/run_2026_07_14_e_b17_p0_matched
```

Expected outputs are raw CSV, aggregate CSV, JSON summary, Markdown report,
validation report, and a machine-readable decision JSON. Success requires exit
code zero, 30 paired seeds in every confirmatory mechanism/cell, and a verdict
computed exactly from this protocol.
