# E-B25 Protocol: Independent OPA Enforcement under a Post-Persistence Fault

## Material passport

- Origin: academic-research-suite / experiment-agent
- Version: `e-b25-opa-independent-v1`
- Status: PRE-EXECUTION-FROZEN
- Independent policy engine: Open Policy Agent `v1.17.0`
- OPA image: `openpolicyagent/opa@sha256:94830e998dd9df8e49a61826f1ad03d8a68d3ecd52f105e06a2adb93b459ad46`
- Independent fault injector: Shopify Toxiproxy `v2.12.0`
- Toxiproxy image: `ghcr.io/shopify/toxiproxy@sha256:9378ed52a28bc50edc1350f936f518f31fa95f0d15917d6eb40b8e376d1a214e`
- Effect stores: E-B24's pinned PostgreSQL image and fsync/rename filesystem store
- Workload: the exact 225 E-B20 held-out mutating vectors inherited by E-B22--E-B24

## Frozen question

After a receiver durably persists and acknowledges one revocation, can an
external control-path failure leave an independently implemented policy engine
stale while its decision path remains live, and can the C0--C5 monitor
distinguish this state from completion?

## Stack and authorship boundary

Two physical gateways use distinct OPA servers. OPA evaluates the Rego
allow/deny rule and stores revocation data. A thin local adapter validates the
frozen vector identity, writes revocation data through OPA's Data API, verifies
readback plus a deny decision, emits a bound receipt, and commits an effect
only when OPA returns `allow=true`. The adapter and completion monitor are
self-authored; the policy engine and fault injector are independently
maintained.

Filesystem's 112 vectors are owned by physical gateway `g-filesystem`; the 113
Postgres vectors are owned by `g-postgres`. This is a fixed service partition,
not a fitted risk partition.

## Conditions

1. `active`: before revocation, both OPA instances must allow all 225 calls and
   both authoritative stores must record the corresponding effects.
2. `normal`: persist one event, deliver it through both control proxies, require
   two readback-bound receipts, then replay all vectors. Every call must be
   denied and both effect oracles must remain empty.
3. `post_persist_fault`: persist one event first, externally disable only the
   Filesystem OPA control proxy, run the unchanged receiver worker, and replay
   all vectors. The direct OPA decision path remains live. Postgres must deny
   its 113 calls; the stale Filesystem OPA must allow and commit its 112 calls.
4. `recovery`: re-enable the proxy and finish the pending handoff without
   deleting fault evidence. Then use a fresh event/delegation and require all
   225 calls to be denied with zero effects.

No experimental task is retried. Readiness polling is infrastructure setup,
not an experimental retry. Any condition failure is preserved.

## Frozen invariants and outcome contract

E-B25 must hash-check E-B20's target file and four held-out traces. It may not
change the risk index, policy, target membership, mutation labels, 20% target
fraction, or 30% E-B20 gate. These fields are reported as unchanged even though
E-B25's endpoint-completion question does not reuse the failed 30% comparison
as a success criterion.

The P0 monitor registers the exact two physical gateways and all 225 vectors.
`normal` and `recovery` pass only at bounded C5. The fault condition passes only
if it remains partial at C3 during the fault, produces exactly 112 committed
Filesystem effects, and is labeled `VIOLATED`. A late receipt may advance its
highest observed stage to C4 but may not erase the C5 violation.

## Claim boundary

Passing E-B25 establishes the boundary on one Docker host using independent
OPA and Toxiproxy implementations. It does not establish production incidence,
multi-host network independence, universal gateway coverage, or superiority of
one revocation transport.
