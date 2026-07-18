# E-B22 Protocol: Keycloak PUSH to Agent-Tool Gateway Deny State

## Material Passport

- Origin Skill: academic-research-suite / experiment-agent
- Origin Mode: plan
- Origin Date: 2026-07-15
- Verification Status: PRE-EXECUTION-FROZEN
- Version Label: e-b22-prereg-v1
- Upstream Smoke: E-B21 Keycloak 26.7.0 SSF PUSH
- Frozen Workload: E-B20 MCPMark held-out mutating-call vectors

## Freeze Statement

This protocol is frozen before the first E-B22 Keycloak logout or replayed
agent-tool call. E-B22 may not change E-B20's risk index, target policy,
target membership, held-out runs, mutation labels, 20% omission fraction, or
30% confirmatory threshold. E-B22 does not re-estimate any of them and does
not use the 30% threshold to manufacture a new mechanism win.

Keycloak POLL is deliberately excluded. It is a later, separately frozen gate
and cannot repair or overwrite the PUSH-only E-B22 result.

## Research Question

Does a signed Keycloak CAEP `session-revoked` event change the deny state of a
real agent-tool MCP gateway under normal PUSH delivery, and does a
receiver-selective non-delivery leave the selected gateway accepting the same
frozen workload while a paired healthy receiver still denies it?

## Pinned Components

- Keycloak image: `quay.io/keycloak/keycloak:26.7.0`
- Keycloak image digest:
  `sha256:2eb3cd316835c990e69e26ade292ffa78f6fb0db7d5fc6377463c162e1979ac0`
- Keycloak source tag commit: `6c73e3027811d9c7b22683edd825e839272e9547`
- Event: CAEP `session-revoked` over RFC 8935 PUSH
- Database image: `pgvector/pgvector:0.8.0-pg17-bookworm`
- Database image digest:
  `sha256:40b404964359299eefdd5f8518facf1886c562848cf4de13b6eaf91cb70c2b87`
- Enforcement surface: the existing independent-process MCP gateway
  `revocation_propagation.real_mcp_gateway_server`
- Gateway tool: `repo_write`
- Gateway state transition: `apply_revocation(..., channel="direct-push")`

The Keycloak native retry curve and maximum attempts remain unchanged. The
receiver relay returns HTTP 202 in both conditions. In the selective condition
it acknowledges receiver B's SET but withholds the local handoff to gateway B;
therefore Keycloak PUSH has no failure response from which to initiate native
retry. This is a receiver-local selective non-delivery fault, not a transport
503 and not a Keycloak POLL failure.

## Frozen Workload Inputs

Use E-B20's exact frozen target file and held-out trace files:

| input | SHA-256 |
|---|---|
| `analysis/e_b20_targets.json` | `e8dca8f08e86a43fd919fac8d142800077128bb647408dee9a412d30ad994a75` |
| `traces/e_b20_filesystem_run_3.jsonl` | `04dfbfbdb1a006af63585b6e55bffa3e89091e5db995be95faa1cbcda4bef4e5` |
| `traces/e_b20_filesystem_run_4.jsonl` | `5ea662765d19d513d5f8587e6afd31ad646eb48e5c5bd271d9b9b51b9221052d` |
| `traces/e_b20_postgres_run_3.jsonl` | `7a833269a75502320ae7ee9b7cdced702b73be7d7eba0c9bb2e7fc1213b68b90` |
| `traces/e_b20_postgres_run_4.jsonl` | `642524a70351884b58d9ebeafe636018771d7329bc1f0bf1f9b13900db7cd42c` |

Retain every `tool_call` with `mutating=true`, held-out run in `{3,4}`, and
`gateway_id` in the frozen top-10 set. This produces exactly 225 replay
vectors: 112 Filesystem and 113 Postgres. One frozen target has zero held-out
mutating calls and remains in the population manifest rather than being
silently removed.

Replay preserves each vector's service, task/gateway ID, run, call sequence,
tool name, and argument hash. It does not repeat the original mutation. The
vector becomes the payload of the existing guarded `repo_write` tool so the
experiment isolates authorization enforcement from benchmark side effects.

## Conditions

Each condition uses a fresh Keycloak login/session and therefore a fresh
delegation ID derived from the opaque Keycloak session ID.

1. **normal-delivery**: receiver A and receiver B both forward their verified
   SET to their paired MCP gateway before workload replay.
2. **receiver-selective-nondelivery**: receiver A forwards its verified SET;
   receiver B returns HTTP 202 to Keycloak but withholds the SET from gateway
   B. No repair is applied before or during workload replay.

The exact same ordered 225-vector workload is sent to gateway A and gateway B
in both conditions.

## Outcomes

For each condition and receiver/gateway pair record:

- SET signature verification and CAEP event type;
- receiver observation, acknowledgement, and local-forwarding status;
- gateway `revoked`, `event_id`, and `learned_via` state;
- allowed and denied replay calls;
- replay-vector identity hash and exact count;
- Keycloak outbox status after HTTP 202 acknowledgement.

## Deterministic Gate

E-B22 passes only if all of the following hold:

1. all five frozen workload hashes match and exactly 225 replay vectors load;
2. Keycloak uses the pinned PostgreSQL container and both MCP gateways run in
   processes distinct from the harness;
3. both gateways allow a pre-revocation control call for each fresh delegation;
4. all forwarded SETs verify as RS256 and contain CAEP `session-revoked`;
5. in `normal-delivery`, gateway A and B both enter deny state and deny
   225/225 matched calls;
6. in `receiver-selective-nondelivery`, gateway A enters deny state and denies
   225/225 calls, while gateway B remains non-revoked and allows 225/225;
7. the healthy A result is invariant across conditions, and the only changed
   treatment is receiver B's local forwarding decision;
8. both Keycloak PUSH requests receive HTTP 202, so no retry or POLL result is
   conflated with the selective-non-delivery contrast; and
9. risk index, target policy, targets, mutation labels, 20% fraction, and 30%
   threshold are unchanged.

Any input mismatch, partial workload, signature failure, unintended gateway
state, native retry into gateway B, or non-202 receiver response makes the run
`INVALID`, not a partial pass.

## Claim Boundary

A pass establishes an end-to-end functional dependence between independent
Keycloak PUSH delivery and a real MCP gateway's enforcement state under a
frozen external agent-tool workload. It does not establish multi-host
production latency, general mechanism superiority, POLL repair, transparent
network-failure handling, or a new revocation mechanism.
