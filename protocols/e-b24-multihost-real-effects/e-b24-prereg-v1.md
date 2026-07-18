# E-B24 Preregistration: Selective Receiver-to-Gateway Non-Delivery

## Material Passport

- Origin Skill: academic-research-suite / experiment-agent
- Origin Mode: pre-execution freeze
- Freeze Date: 2026-07-17 America/Los_Angeles
- Verification Status: PRE-EXECUTION-FROZEN
- Version Label: `e-b24-prereg-v1`
- Run ID: `eb24-confirmatory-v1-20260717`
- Frozen Workload Ancestor: E-B20 MCPMark held-out mutating-call vectors
- Execution Ancestors: E-B22 Keycloak PUSH, E-B23 Keycloak POLL, and the E-B24 local real-effect gate

This document and `freeze-manifest.json` were frozen after outcome-blind
infrastructure qualification and before any E-B24 logout, revocation outcome,
gateway treatment contrast, or confirmatory Filesystem/PostgreSQL mutation was
executed on the AWS topology.

## Confirmatory Question

Does a transport acknowledgment and durable receiver record establish
revocation completion at the gateway/effect boundary when one receiver's
handoff path is selectively unavailable?

The joint outcome contract distinguishes:

- `C2 TRANSPORT_ACKNOWLEDGED`: Keycloak PUSH receives HTTP 202;
- `C3 RECEIVER_PERSISTED`: the verified SET is durable in the receiver inbox;
- `C4 GATEWAY_ENFORCED`: every gateway assigned to that receiver has a durable
  receipt; and
- `C5 EFFECT_PREVENTED`: the authoritative Filesystem/PostgreSQL oracles show
  no committed mutation in a fresh phase namespace.

The primary contrast is `normal` versus `receiver_gateway_fault`. `recovery`
tests whether clearing the external fault closes C3→C4 and prevents effects in
a fresh namespace.

## Frozen Scientific Inputs

The exact allowlist SHA-256 is
`9e76d237213e899486bfd65fad817cedd500cd0820535aa8e953519a24b8e9b2`.
It contains 225 unique held-out identities: 112 Filesystem and 113 PostgreSQL.
E-B24 does not recover the original mutation arguments; it uses the previously
declared deterministic effect-carrying mapping.

The E-B20 risk index, target policy, target membership, mutation labels, 20%
target fraction, and 30% threshold are inherited unchanged. The 30% threshold
is reported as an inherited boundary and is not refit or used as the E-B24
decision threshold.

## Frozen Physical Assignment and 50% Boundary

Vector index `i` in the frozen allowlist is assigned to physical gateway
`(i mod 8) + 1`. Receiver A is assigned gateways 1–4; receiver B is assigned
gateways 5–8. This yields:

| Receiver | Calls | Filesystem | PostgreSQL |
|---|---:|---:|---:|
| receiver A / gateways 1–4 | 113 | 56 | 57 |
| receiver B / gateways 5–8 | 112 | 56 | 56 |

Thus selective failure of receiver B's handoff path predicts exactly 112/225
(49.78%) stale admissions and effects if C3 is incorrectly treated as C4/C5.
This count is fixed by topology and vector order; it is not estimated from an
outcome pilot.

## Frozen Topology

The run uses 16 on-demand EC2 instances in `us-east-1`, with eight physical
gateways placed 3/3/2 across `use1-az1`, `use1-az2`, and `use1-az4`. It retains
separate Keycloak, Keycloak PostgreSQL, receiver A/B, Filesystem effect,
PostgreSQL effect/database, workload-driver, and independent fault-controller
hosts. The AMI is `ami-ba555e3fa8ae1f57e`.

The runtime is pinned to:

`sha256:63703056236d0bba22ad0d8673470469825cb2e27b28c1f5cc208e2b4a271d42`

The public-address PUSH front door is
`paper-b-eb24-push-1918302644.us-east-1.elb.amazonaws.com`; listener 443 maps
only to receiver A and listener 8443 only to receiver B. The experiment CA
fingerprint is
`e69bfa4b47069c83e3fc10c589e07472e95562b25f1331f2a797543dd1bb29a7`;
the ALB leaf fingerprint is
`9095ae21f4d70fc844062784701bd5c33a2779385ef9fa081cf84df8fd7f82f5`.

The canonical Terraform-output topology digest is
`44f70cdeacdd18698b779d4fbd5decdbe6d50002f7bf989e8cbef85c31a1f838`.
The complete host inventory and source hashes are in `freeze-manifest.json`.

## Frozen Fault

The dedicated fault-controller instance uses its tagged-instance SSM authority
to create one host-level nftables output chain on receiver B. The rule drops
only TCP destination port 9444 to the eight frozen gateway private IPs. It does
not block Keycloak→receiver PUSH, driver→MCP, gateway→effect, DNS, NTP, SSM, or
receiver ingress. The mechanism, receiver, gateway, and workload code contain
no arm-dependent drop branch.

The fault is applied before the treatment logout and remains active while the
receiver/effect evidence is captured. Clearing the table precedes recovery.
Every apply/clear operation records the outer controller command, nested target
command, exact ruleset, packet counter, and status.

## Sample Size, Blocking, and Order

The independent unit is one paired cluster block. Exactly 30 blocks are run;
there is no adaptive stopping or sample-size revision. Odd blocks execute
`normal` before `receiver_gateway_fault`; even blocks reverse that order. Each
treatment is followed by `recovery` for the same delegation in a fresh effect
namespace.

Each new arm creates one real Keycloak session, verifies that all eight gateway
states are initially active, performs real OIDC logout, waits at most 45 seconds
for the predeclared gateway pattern, and replays all 225 vectors. The recovery
phase waits for all eight enforcement receipts and replays the same 225 vector
identities under a fresh namespace. Observation polling is not a rerun; a phase
that misses its frozen pattern aborts the one-shot experiment and is preserved.

## Primary Outcomes and Exact Contracts

Gateway return values are recorded but are not the authoritative effect oracle.
The remote Filesystem Merkle-style manifest and committed PostgreSQL row export
provide the effect counts and vector identities.

Per block, the frozen categorical contracts are:

| Phase | Expected allowed/effects | Expected FS/PG oracle counts | Receiver B state |
|---|---:|---:|---|
| normal | 0 / 225 | 0 / 0 | ENFORCED, 4 receipts |
| receiver_gateway_fault | 112 / 225 | 56 / 56 | PERSISTED, 0 receipts, HTTP 202 recorded |
| recovery | 0 / 225 | 0 / 0 | ENFORCED, 4 receipts |

The primary estimands are the paired differences in stale-admission fraction
and committed-effect fraction between normal and receiver-gateway-fault arms.
The exact safety outcomes are zero post-enforcement admissions and zero
post-enforcement authoritative effects. We report all 30 block outcomes,
paired empirical intervals, the number and timing of C2/C3/C4 transitions, and
the recovery result. A failed exact contract is a result, not grounds to tune
or rerun.

## Time, Performance, and Exclusions

All 16 hosts use Amazon Time Sync through chrony. `chronyc tracking` and
`chronyc sources -v` are captured before and after every block. The frozen
clock bound is an absolute `System time` offset of 10 ms with `Leap status:
Normal` on every host. A block outside that bound remains in all categorical
state/effect analyses but is excluded from cross-host wall-clock latency
analysis. T3 credit mode remains `standard`; CPU-credit exhaustion, if any, is
reported and invalidates performance but not categorical causal evidence.

No initiated block is silently excluded. Loss of the causal delegation/vector
identity or irrecoverable evidence corruption aborts the run and preserves all
partial material. Infrastructure or mechanism failures are reported in the
phase where they occur. The same run ID or phase directory is never retried.

## Analysis and Claim Boundary

The experiment can establish whether receiver-selective handoff failure creates
a gap between acknowledged/persisted revocation and enforced/effect-preventing
revocation in this 16-host, three-zone implementation, and whether recovery
closes that gap. It does not estimate population incidence, prove production
safety, compare mechanism superiority, replay original mutation arguments, or
rescue E-B20's failed risk-aware 30% gate.

