# E-B24 Design: Multi-Host Revocation Completion with Real Effects

## Material Passport

- Origin Skill: academic-research-suite / experiment-agent
- Origin Mode: plan
- Origin Date: 2026-07-16
- Verification Status: DESIGN — NOT YET PREREGISTERED
- Version Label: e-b24-design-v1
- Frozen Workload Ancestor: E-B20 MCPMark held-out mutating-call vectors
- Execution Ancestors: E-B22 Keycloak PUSH and E-B23 Keycloak POLL

## Status

This document stores the E-B24 route before implementation. It is not a
preregistration and does not authorize a paper claim. A confirmatory version
must pin the cloud inventory, image digests, receiver and gateway commits,
fault rules, host placement, clock-error bound, pilot exclusions, sample size,
and analysis before the first confirmatory outcome is observed.

The local gate described below is an implementation qualification test. Its
results cannot satisfy the multi-host claim.

## Research Object

E-B24 tests when an agent revocation is complete at the effect boundary. It
distinguishes the following states:

1. `C0 ISSUER_COMMITTED`: the issuer commits the revocation;
2. `C1 TRANSMITTER_QUEUED`: the transmitter durably queues the event;
3. `C2 TRANSPORT_ACKNOWLEDGED`: PUSH returns HTTP 202 or POLL is acknowledged;
4. `C3 RECEIVER_PERSISTED`: the receiver durably stores the verified event;
5. `C4 GATEWAY_ENFORCED`: the gateway durably applies deny state and emits an
   enforcement receipt; and
6. `C5 EFFECT_PREVENTED`: the guarded Filesystem or PostgreSQL mutation does
   not commit.

The primary execution-level question is whether `C2` or `C3` can be mistaken
for `C4/C5` when the receiver-to-gateway path fails.

## Frozen Inheritance from E-B20

E-B24 must load and hash-check the exact E-B20 inputs already frozen by E-B22:

- ten target task/gateway identities, including the zero-vector target;
- 225 unique held-out mutating-call vector identities;
- 112 Filesystem and 113 PostgreSQL vectors;
- the original service, task/gateway ID, held-out run, call sequence, tool
  name, argument hash, and within-task timing where used;
- the original risk index, target policy, target membership, mutation labels,
  20% target fraction, and 30% E-B20 threshold.

E-B24 does not rerun or rescue E-B20's failed risk-aware 30% outcome gate.
The 30% threshold remains unchanged but is not a decision threshold for the
new completion experiment.

E-B20 did not retain raw mutation arguments. E-B24 therefore uses an
**effect-carrying replay**, not a replay of the original task mutations. Each
frozen vector is mapped deterministically to one unique, reversible effect:

- Filesystem: one canonical JSON file under an experiment sandbox; or
- PostgreSQL: one committed row in a dedicated effect table.

The paper must preserve this distinction.

## Local Qualification Gate: Steps 1--4

### Step 1 — Store the route

Keep this design and the dated implementation decision in the repository.
Do not label either document `PRE-EXECUTION-FROZEN` until the cloud topology
and confirmatory analysis are complete.

### Step 2 — Implement the real-effect mapper

For every frozen vector, generate a canonical effect plan containing the
vector ID and all retained identity fields. Paths and SQL keys are derived
only from canonical hashes. The gateway rejects vectors outside the frozen
allowlist or whose identity does not recompute to the supplied vector ID.

Filesystem commits use write, flush, `fsync`, atomic rename, and directory
`fsync`. PostgreSQL commits use a dedicated table keyed by experiment run,
arm, and vector ID.

### Step 3 — Prove the local active/revoked effect direction

Run a process-isolated MCP gateway against a real Filesystem sandbox and the
pinned PostgreSQL 17 container.

| Local condition | Gateway state | Expected allowed/denied | Expected FS/PG effects |
|---|---|---:|---:|
| active positive control | active | 225 / 0 | 112 / 113 |
| receiver-enforced revocation | revoked | 0 / 225 | 0 / 0 |

Counts, vector sets, and content digests must be verified independently of the
gateway return value.

### Step 4 — Implement durable receiver and enforcement receipt

The local receiver stores an event in SQLite with status `PERSISTED`, closes
and reopens the database to demonstrate recovery, then hands the event to the
gateway. It marks the event `ENFORCED` only after receiving a gateway receipt.
The receipt binds gateway ID, delegation ID, event ID, channel, and apply time.

The recovery qualification adds two phases:

| Recovery phase | Receiver state | Gateway state | Expected FS/PG effects |
|---|---|---|---:|
| before handoff | persisted | active | 112 / 113 |
| after handoff and fresh namespace | enforced | revoked | 0 / 0 |

The local gate uses a synthetic event envelope and does not repeat the
Keycloak claim already tested in E-B22/E-B23.

## Planned Multi-Host Topology

The strict topology retains the earlier P1 requirement of at least eight
gateway hosts across three independently faultable zones. Supporting roles
are separated where their failure is part of the treatment:

- Keycloak 26.7 SSF transmitter;
- Keycloak PostgreSQL database;
- two identical durable receiver instances;
- eight gateway hosts across three zones;
- Filesystem MCP effect service;
- PostgreSQL MCP effect service and effect database;
- workload driver; and
- independent fault controller.

Logical gateways may be replicated across the eight hosts, but fewer than
eight physical/VM gateway hosts cannot satisfy the existing strict P1 gate.

## Fault Cells

All faults are injected outside mechanism code and recorded with rule and
packet/process evidence.

1. `normal`: Keycloak delivery, receiver persistence, gateway apply, and
   effect prevention all complete.
2. `transmitter-to-receiver`: Keycloak cannot deliver to receiver B. This is
   a visible delivery-failure control and must remain `PENDING`, not a false
   completion.
3. `receiver-to-gateway`: receiver B persists and acknowledges the event, but
   an external network rule blocks its gateway handoff. This is the primary
   false-completion cell.
4. `receiver-worker-crash`: ingress persists and acknowledges the event, then
   the asynchronous worker is stopped externally before gateway apply.
5. `recovery`: remove the fault, require an enforcement receipt, then replay
   the same vector identities in a fresh effect namespace.

The mechanism, receiver, and gateway code must contain no condition-specific
drop branch.

## Primary Outcomes

- real Filesystem effects committed after revocation;
- real PostgreSQL effects committed after revocation;
- false-completion rate for each observer state;
- `C4 - C2` enforcement-completion gap;
- last unauthorized-effect time relative to `C0`;
- stale admission count and committed-effect count;
- benign availability loss;
- control messages and bytes; and
- gateway/tool latency and throughput overhead.

Gateway returns are not the effect oracle. The Filesystem Merkle manifest and
PostgreSQL committed-row digest are authoritative.

## Planned Statistical Unit and Confirmation

The independent unit is a complete paired cluster run, not a vector, tool
call, gateway, or replay seed. Run outcome-blind infrastructure pilots first.
The confirmatory sample-size rule is frozen after the pilot with a floor of 30
paired cluster runs. Healthy and treatment arms reuse the same event, vector
schedule, placement block, and network regime. Pooling may not hide a reversed
primary regime.

Exact safety gates require zero post-enforcement admissions and zero
post-enforcement effects. Count and latency contrasts use paired cluster
intervals and report effect sizes, not only p-values.

## Implementation Order

1. Store this design and the dated route decision.
2. Implement and unit-test the frozen vector-to-effect mapper.
3. Implement a new persistent MCP effect gateway without changing the E-B18,
   E-B22, or E-B23 gateway.
4. Implement the durable receiver inbox and enforcement receipt.
5. Run and validate the local qualification gate.
6. Build a three-host infrastructure smoke with no paper outcome.
7. Provision eight gateway hosts across three zones and supporting hosts.
8. Freeze topology, images, fault schedules, placement, time sync, pilots,
   sample size, exclusions, and analysis in `e-b24-prereg-v1`.
9. Run pilot-only seeds, finalize the predeclared sample size, and execute the
   confirmatory paired runs without changing the mechanism or E-B20 inputs.
10. Run an independent validator and clean-room reproduction.

## Claim Boundary

A local pass establishes only that the frozen vector identities can drive real
reversible Filesystem/PostgreSQL effects and that a durable receiver can close
the local persisted-to-enforced transition with a receipt. It does not prove
Keycloak multi-host behavior, real-network false-completion incidence,
multi-zone generalization, production safety, or mechanism superiority.

