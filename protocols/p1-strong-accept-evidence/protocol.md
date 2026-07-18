# P1 Protocol Design: External Evidence for RevProp

## Material Passport

- Origin Skill: academic-research-suite / experiment-agent
- Origin Mode: plan
- Origin Date: 2026-07-14T14:51:13-07:00
- Verification Status: DESIGN — NOT YET PREREGISTERED
- Version Label: p1-design-v1
- Input Verdict: `SUPPORTED_CONSTRAINED_ADVANTAGE`

## Status and Freeze Requirements

This document is an experiment design, not a preregistration and not evidence
that any P1 claim has passed. Before the first pilot or confirmatory observation:

1. pin source commits, SDK versions, container digests, machine types, and the
   complete topology manifest;
2. implement the planned entry points and verify dry-run output schemas;
3. freeze fault schedules, trace-source eligibility, primary comparisons,
   resource caps, exclusions, and the power-analysis procedure in a new protocol
   version;
4. commit that version before generating P1 results;
5. keep pilots in a separate directory and exclude them from confirmation.

No post-result threshold change may alter the confirmatory verdict. A changed
mechanism, including adaptive polling or a different gossip fan-out, receives a
new system version and a separate exploratory analysis.

## Objective

P0 established a constrained advantage in a common-trace mechanism simulation
at 20% selective operator suppression and a directional result on a local real
LLM/MCP path. P1 tests whether that advantage survives the four strongest
remaining validity threats:

1. real multi-host scheduling and network behavior;
2. independently implemented protocol paths and production-grade transparency
   proofs;
3. trace-calibrated agent/tool workloads and heterogeneous runtimes;
4. clean-room reproducibility and adversarial audit.

P1 does not test mechanism novelty. Known push, polling, lease, gossip,
transparency, and quorum primitives remain prior art.

## Research Questions and Hypotheses

### RQ-P1A — Multi-host generalization

Under the same identities, requests, suppression targets, and control-plane
budgets, does RevProp retain a practically meaningful stale-call advantage over
the strongest feasible baselines on a real multi-host network?

- **H1A**: in the 20% selective-operator cell, RevProp is feasible and reduces
  stale calls by at least 20% against every feasible confirmatory baseline, with
  the paired 95% interval excluding zero effect.
- **Falsifier**: no feasible baseline remains, RevProp violates a frozen budget,
  any feasible baseline has an interval crossing zero, or the practical effect
  is below 20%.

### RQ-P1B — Independent evidence-plane validity

Do independently implemented clients and a separately deployed transparency
service reproduce RevProp's repair and audit properties without sharing the
prototype's authorization or Merkle-proof code?

- **H1B**: all conforming implementations accept valid events/proofs, reject all
  tampered test vectors, detect every scripted fork within the frozen
  cross-observation bound, and preserve H1A's effect direction.
- **Falsifier**: a forged, replayed, reordered, duplicate-signer, invalid
  inclusion, or invalid consistency proof is accepted; a scripted fork is not
  detected; or an implementation disagrees on authorization state.

### RQ-P1C — Workload external validity

Does the 20% advantage generalize to at least two independently sourced,
trace-calibrated agent/tool workloads and heterogeneous LLM/framework stacks?

- **H1C**: each eligible trace source independently shows the same stale-call
  direction, no source violates feasibility, and the pooled estimate meets the
  20% practical-effect gate.
- **Falsifier**: either source reverses direction, the pooled result only passes
  by masking a failed source, or results depend on one model/runtime family.

### RQ-P1D — Reproducibility under separation

Can a clean environment reproduce the primary aggregate table and verdict from
the published manifest, traces, and replay tools without editing core code?

- **H1D**: the clean-room run reproduces the categorical verdict and all primary
  aggregates within the frozen stochastic tolerance.
- **Falsifier**: undocumented manual repair, unavailable inputs, schema drift,
  replay mismatch, or a primary aggregate outside tolerance.

## Priority and Decision Value

| Priority | Work package | Main validity threat removed | Required for external-advantage verdict |
|---:|---|---|---:|
| 1 | E-B19 / P1-A: multi-host matched deployment | single-host and simulated-network bias | yes |
| 2 | E-B20 / P1-B: independent implementation + hardened log | self-authored mechanism/evidence plane | yes |
| 3 | E-B21 / P1-C: trace-calibrated heterogeneous workload | synthetic workload and one-model/runtime bias | yes |
| 4 | E-B22 / P1-D: clean-room reproduction + adversarial audit | artifact-specific and operator-dependent reproducibility | recommended; mandatory for a reproducibility claim |

Execute the packages in order. Stop the named-system escalation after a failed
required package, preserve the failure, and evaluate the benchmark/SoK pivot.

## Shared Experimental Contract

### Unit of inference

The independent unit is a complete paired cluster run identified by
`topology_id`, `trace_source`, `network_regime`, `fault_cell`, and `seed`.
Requests, gateways, tool calls, and LLM turns within one cluster run are not
independent samples and must not inflate the sample size.

### Common inputs

Every mechanism in a paired run must reuse:

- relying-party, agent, delegation, and tool identities;
- request times, tool choices, revocation time, and delegation graph;
- suppression target IDs and network-fault schedule;
- topology, machine allocation, container resources, and warm-up period;
- observation horizon and cost-accounting rules.

Mechanism order is randomized within a block. Fresh namespaces and state stores
are used between mechanisms. The randomization schedule is frozen and logged.

### Confirmatory mechanisms

At minimum, the real deployment includes:

1. `revprop-v1`: the exact P0 push + bounded gossip + independent log-repair
   configuration;
2. `drp-10-matched`: the feasible 10-second-rescaled member of the P0 DRP log
   family; DRP-60 and DRP-300 are not counted as independent comparisons after
   identical rescaling;
3. `aip-03`: signed push/retry with disclosed live-status fallback;
4. `hbhc`: fail-closed heartbeat/lease with multipath gossip;
5. `caep-ssf`: signed event-stream delivery without an invented independent
   repair path;
6. `sync-fail-closed`: request-time authorization as the availability/security
   reference point.

Adapters are mechanism-level test implementations unless the source project
provides compatible maintained code. Reports must not call them source-compatible
reimplementations without conformance evidence.

### Fault cells

- `none`: diagnostic benign condition.
- `selective-operator-20`: primary confirmatory cell; operator-owned direct and
  status channels are withheld from the same 20% of gateways while independent
  peer/log paths remain reachable.
- `selective-operator-50`: mandatory boundary cell; it cannot establish a win
  unless every frozen feasibility gate passes. The known P0 cost failure must
  remain visible.
- `correlated-all-20`: diagnostic impossibility/control cell in which direct,
  status, peer, and log paths are unavailable to targets.

Suppression is enforced at network boundaries, not by a mechanism-specific
branch inside the gateway. Firewall, proxy, or network-emulation rules and
packet counters become part of the saved evidence.

### Network regimes

The exact values are frozen after a hardware-only pilot, without outcome
inspection. The confirmatory design must contain at least:

- same-region low-latency conditions;
- cross-region WAN conditions;
- a stressed but connected regime with delay, jitter, and packet loss.

Each report publishes the empirical RTT/loss distribution rather than relying
only on configured network-emulator values.

### Shared outcomes

Primary:

- admitted revoked tool calls per gateway;
- explicit-event completeness by the frozen horizon;
- independently verifiable audit-evidence rate;
- benign availability loss;
- control messages and bytes per gateway.

Secondary:

- event and enforcement p50/p95/p99 with censoring retained;
- protocol-only latency and end-to-end tool-call latency, reported separately;
- throughput and CPU/memory/network overhead;
- independent-repair rate, fork-detection latency, and proof-verification rate;
- effect by network regime, trace source, runtime, model family, and risk class.

### Shared feasibility gates

Carry forward the P0 gates unless the preregistration justifies a stricter cap:

- explicit-event completeness `>= 0.99`;
- audit-evidence rate `>= 0.99`;
- benign availability loss `<= 0.01`;
- control messages/gateway/60 s `<= 8.1`;
- control bytes/gateway/60 s `<= 8,192`.

For the real deployment also require, relative to the same mechanism with the
revocation control plane disabled:

- throughput loss `<= 5%`;
- tool-call p99 latency inflation `<= 10%`.

Absolute latency is reported but not used to favor hardware with a faster base
rate. If a cap proves physically meaningless during the outcome-blind hardware
pilot, revise it once, document the reason, and commit the preregistration
before the confirmatory run.

## E-B19 / P1-A — Multi-host Matched Deployment

### Topology

- At least eight gateway hosts across at least three independently faultable
  network zones.
- Root authority, transparency/log service, two watchers, workload driver, and
  fault controller run on hosts distinct from the gateways and from one another
  where the role affects the tested failure.
- At least 1,000 logical gateways are evenly assigned across hosts; resource
  limits and placement are saved in the topology manifest.
- Every admitted tool action crosses a real MCP network boundary. Hostnames,
  IPs, credentials, and cloud account identifiers are anonymized before release.
- Clock offset is measured continuously. Causal event order comes from signed
  sequence identifiers; wall-clock latency is invalidated when the frozen clock
  error bound is exceeded.

### Design and sample size

Run ten outcome-blind pilot seeds solely to estimate paired-run variance and
infrastructure failure rate. Exclude these seeds from confirmation. Determine
confirmatory `N` for 90% power at family-wise alpha 0.05 against the minimum
20% stale-call reduction, with a floor of 30 paired seeds and a ceiling of 100.
If the required `N` exceeds 100, label the experiment underpowered instead of
lowering the effect threshold.

Block by network regime and pair all mechanisms within each seed. The primary
analysis is `selective-operator-20`; the 50% and correlated-all cells test the
failure boundary and cannot rescue the primary result.

### P1-A pass rule

For every feasible confirmatory baseline in every preregistered primary network
regime:

1. RevProp passes all shared feasibility gates;
2. at least one non-RevProp baseline is feasible;
3. RevProp lies on the six-dimensional convergence/damage/availability/audit/
   message/byte Pareto frontier;
4. the upper two-sided 95% confidence bound for `RevProp - baseline` stale
   calls is below zero;
5. the lower 95% confidence bound for relative reduction is above 20%;
6. no primary network regime has a reversed effect.

Failure in one primary regime is reported as failed generalization; pooling may
not hide it.

### Planned interface

Working directory: `artifact/`.

```bash
python3 experiments/e_b19_multihost.py \
  --manifest configs/p1/topology.yaml \
  --profile pilot \
  --output-dir _outputs/e_b19_pilot

python3 experiments/e_b19_multihost.py \
  --manifest configs/p1/topology.yaml \
  --profile confirmatory \
  --output-dir data/run_<date>_e_b19_multihost

python3 scripts/validate_e_b19.py data/run_<date>_e_b19_multihost
```

These commands are interface requirements; they do not yet exist. Their exact
arguments and schemas must be frozen before preregistration.

## E-B20 / P1-B — Independent Implementation and Hardened Log

### Independence requirements

- Use at least two independently maintained MCP SDK implementations in different
  languages, pinned by version and source commit.
- Implement one RevProp producer and one consumer/verifier without sharing
  authorization-state, signature-validation, or Merkle-proof source code.
  Sharing the frozen wire schema and public test vectors is allowed.
- Select an independently maintained RFC 6962-style transparency implementation
  that exposes inclusion and consistency proofs and can be pinned by container
  digest. A custom in-process Merkle tree cannot satisfy this gate.
- Deploy at least two independent witnesses/monitors that cross-observe signed
  tree heads through a path distinct from the operator notification channel.

### Conformance and adversarial matrix

The frozen test-vector suite must cover:

- valid issuance, revocation, descendant invalidation, and duplicate delivery;
- bad issuer, wrong audience, expired event, replayed sequence, and reordered
  epoch;
- insufficient quorum, duplicate signer, invalid Ed25519 signature, and signer
  outside the active root set;
- missing, malformed, or wrong-leaf inclusion proof;
- inconsistent, truncated, stale, or wrong-size consistency proof;
- scripted split views delivered to disjoint gateway/watcher sets;
- one log replica unavailable and one witness unavailable.

### P1-B pass rule

1. Both implementations reach identical authorization state for every valid
   vector and reject every invalid vector: zero false accepts.
2. Inclusion and consistency verification uses the selected external log's
   native proof contract, not the prototype prefix check.
3. Every scripted split view is detected by at least one independent witness
   within two cross-observation rounds and within the frozen wall-clock bound.
4. One log or witness outage does not exceed the 1% benign availability-loss
   gate.
5. Repeating the E-B19 20% primary cell with the hardened evidence plane
   preserves P1-A's direction and practical-effect gate.

Security tests are exact enumerations; no p-value is used for zero-tolerance
acceptance properties.

### Planned interface

```bash
python3 experiments/e_b20_interop_log.py \
  --manifest configs/p1/interop-log.yaml \
  --profile conformance \
  --output-dir _outputs/e_b20_conformance

python3 experiments/e_b20_interop_log.py \
  --manifest configs/p1/interop-log.yaml \
  --profile confirmatory \
  --output-dir data/run_<date>_e_b20_interop_log

python3 scripts/validate_e_b20.py data/run_<date>_e_b20_interop_log
```

## E-B21 / P1-C — Trace-Calibrated Heterogeneous Workloads

### Trace eligibility

Use two independent sources:

1. one fully releasable public or generated-by-public-benchmark agent/tool trace
   corpus; and
2. one de-identified operational or field trace corpus collected independently
   of the P0 simulator.

Each source must contain at least 100 independent workflow episodes and, across
the two sources, at least 100,000 tool invocations and 1,000 distinct delegated
edges. Preserve interarrival times, fan-out, delegation lifetime, retry bursts,
and tool-risk labels while removing prompts, payloads, secrets, user content,
hostnames, and stable organization identifiers.

If the operational source cannot be obtained or released even as an aggregate
manifest, run the public source but mark P1-C and the external-advantage verdict
`INCONCLUSIVE`; do not relabel a synthetic workload as production evidence.

### Heterogeneity

- At least three independently maintained model families, including one local
  and one remotely served family if policy permits.
- At least two agent/workflow runtimes and two MCP SDK language implementations.
- Identical authorization decisions are enforced at the gateway; model output
  affects workload generation, not whether a revoked call is allowed.
- Model latency, protocol latency, and authorization latency are separately
  recorded.

### Revocation injection

Observed revocations are retained. Because field traces may contain too few
revocations for inference, add counterfactual revocations using a schedule
frozen before outcomes: uniform episode position and predeclared high-risk
tool-transition positions. Reuse the same injected event and suppression target
for every mechanism. Report observed and injected events separately.

### P1-C pass rule

1. Both trace sources pass data-quality, privacy, replay, and provenance checks.
2. In the 20% cell, each source independently favors RevProp against every
   feasible baseline; a pooled effect cannot rescue a reversed source.
3. The pooled lower 95% confidence bound for relative stale-call reduction is
   above 20%, with all shared feasibility gates satisfied.
4. Leave-one-runtime and leave-one-model-family sensitivity analyses preserve
   direction.
5. Risk-weighted damage is secondary and uses weights frozen without observing
   mechanism outcomes; the unweighted primary result remains visible.

### Planned interface

```bash
python3 scripts/prepare_p1_traces.py \
  --manifest configs/p1/trace-sources.yaml \
  --output-dir _outputs/p1_traces

python3 experiments/e_b21_trace_replay.py \
  --manifest configs/p1/trace-sources.yaml \
  --profile confirmatory \
  --output-dir data/run_<date>_e_b21_trace_replay

python3 scripts/validate_e_b21.py data/run_<date>_e_b21_trace_replay
```

## E-B22 / P1-D — Clean-Room Reproduction and Adversarial Audit

### Procedure

1. Build from a fresh clone using only the anonymous artifact instructions and
   pinned container images.
2. Validate checksums, schemas, dependency locks, topology inventory, and
   anonymization before running.
3. Execute one preregistered primary E-B19 block and the complete E-B20
   conformance/adversarial suite without editing core source.
4. Replay all event logs and recompute aggregate tables from raw records.
5. Run mutation tests that alter one event, signer, proof, fault target, or
   aggregate row and require the integrity/replay checks to fail.

An external researcher is preferred. If only an internal clean-room operator is
available, record that limitation and do not use the word "independent" for the
personnel-level replication.

### P1-D pass rule

- environment build succeeds from the documented commands;
- categorical verdicts match;
- deterministic files match byte for byte;
- stochastic primary aggregates stay within the preregistered tolerance and
  preserve every effect direction;
- all mutation tests are detected;
- no undocumented input, credential, manual repair, or local path is required.

## Statistical Analysis Plan

### Estimands

The primary estimand is the paired cluster-run difference in admitted revoked
tool calls per gateway, `RevProp - baseline`. Report the paired absolute
difference, relative reduction, probability of superiority, and per-regime
effect. Availability, audit evidence, messages, and bytes are co-primary
feasibility outcomes, not optional secondary metrics.

### Inference

- Use a paired sign-flip randomization/permutation test under the sharp null;
  do not reuse the P0 observed-distribution bootstrap p-value.
- Use a two-sided 95% paired BCa bootstrap interval with at least 10,000
  deterministic resamples for effect size, plus the exact sign test as a
  robustness check.
- Apply Holm family-wise correction across the frozen baseline-by-primary-regime
  comparisons.
- Fit a negative-binomial mixed model only as a sensitivity analysis, with
  run/topology/trace source modeled explicitly; it cannot override the paired
  primary analysis.
- Report all confirmatory cells, including infeasible and unfavorable cells.

### Missingness and failures

- Non-delivery is right-censored at the horizon and remains in completeness and
  damage denominators.
- A mechanism crash or infrastructure loss is not silently retried. One
  preregistered replacement run may use the same seed only when the fault is
  proven mechanism-independent; both attempts remain in the trace.
- More than 10% mechanism-independent infrastructure failures invalidates the
  affected block.
- Mechanism-caused failures count against that mechanism and are not excluded.

### Fallacy controls

- no gateway/request-level pseudoreplication;
- no pooling that masks a failed network regime or trace source;
- no feasibility filtering after observing the primary outcome;
- no duplicate DRP rescalings counted as independent confirmations;
- no HARKed adaptive policy promoted into the RevProp-v1 confirmatory result;
- no claim that correlation across model/runtime families establishes
  production causality.

## Required Evidence Bundle

Every package must produce:

- immutable protocol and Git commit binding;
- environment, dependency, container-digest, hardware, topology, clock, and
  network manifests;
- seed, randomization, request, revocation, suppression, and fault schedules;
- append-only raw event traces with schema version and per-file SHA-256;
- per-run cost ledger and censored outcome table;
- proof/conformance vectors and verifier outputs where applicable;
- replay report, statistical validation report, fallacy scan, and machine-readable
  verdict;
- anonymization report and an explicit private/public data manifest;
- exact commands for smoke, pilot, confirmation, replay, and validation.

Raw inputs are immutable. Derived reports are regenerated from raw records and
must fail closed on schema, identity, count, or checksum disagreement.

## Global P1 Decision Rule

After all required runs complete, emit exactly one verdict:

- `EXTERNALLY_SUPPORTED_ADVANTAGE`: P1-A, P1-B, and P1-C all pass; P1-D is
  reported separately as reproduced or pending. The paper may claim an
  externally supported, trace-calibrated multi-host advantage within the frozen
  20% fault scope, but still not mechanism novelty or universal superiority.
- `FUNCTIONAL_ADVANTAGE_ONLY`: P1-A passes but P1-B or P1-C is incomplete.
  Retain the P0 constrained claim; no Strong Accept escalation.
- `ADVANTAGE_NOT_GENERALIZED`: any completed required package fails its primary
  hypothesis. Preserve RevProp as a studied point in the benchmark and pivot the
  paper away from named-system superiority.
- `INCONCLUSIVE`: required evidence is unavailable, underpowered, or invalidated
  by infrastructure failures. Do not treat missing evidence as support.

The 50% boundary is always reported separately. A passing adaptive RevProp
variant cannot retroactively convert RevProp-v1's P0 failure into a win.

## Completion Order

1. Implement E-B19 topology/fault manifests and run the outcome-blind pilot.
2. Freeze E-B19 sample size and execute the multi-host primary experiment.
3. Only if E-B19 passes, implement/freeze E-B20 independent clients and external
   log/witness deployment.
4. In parallel with E-B20 engineering, obtain and privacy-review eligible E-B21
   trace sources; do not inspect mechanism outcomes during preprocessing.
5. Execute E-B21 only after trace eligibility and injection schedules are
   committed.
6. Package the immutable bundle and run E-B22 clean-room reproduction.
7. Refresh the closest-work audit within 72 hours of submission before changing
   any paper claim.
