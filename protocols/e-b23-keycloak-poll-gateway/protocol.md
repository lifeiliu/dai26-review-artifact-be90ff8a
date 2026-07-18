# E-B23 Protocol: Keycloak POLL to Agent-Tool Gateway Deny State

## Material Passport

- Origin Skill: academic-research-suite / experiment-agent
- Origin Mode: plan
- Origin Date: 2026-07-16
- Verification Status: PRE-EXECUTION-FROZEN
- Version Label: e-b23-prereg-v1
- Predecessor: E-B22 Keycloak PUSH gateway-deny gate
- Frozen Workload: E-B20 MCPMark held-out mutating-call vectors

## Freeze Statement

This protocol is frozen before the first E-B23 logout, RFC 8936 poll, or
workload replay. E-B23 reuses E-B22's five exact input hashes, ten frozen
targets, and 225 ordered replay vectors. It may not change E-B20's risk index,
target policy, target membership, held-out runs, mutation labels, 20% omission
fraction, or 30% threshold.

E-B23 does not claim that POLL repairs E-B22's acknowledged PUSH. Keycloak
stores PUSH and POLL under separate outbox kinds, and a receiver owns one
delivery method per stream. A PUSH row acknowledged with HTTP 202 is
`DELIVERED` and is not later available to native POLL. E-B23 therefore tests
POLL as an independently initiated delivery path.

## Research Question

Can Keycloak 26.7's native authenticated RFC 8936 POLL path deliver a signed
CAEP `session-revoked` SET that changes the existing MCP agent-tool gateway
from allow to deny on the exact frozen E-B22 workload?

## Pinned Components

- Keycloak image and digest: identical to E-B22;
- PostgreSQL image and digest: identical to E-B22;
- Keycloak source tag commit: identical to E-B22;
- receiver A stream: RFC 8935 PUSH;
- receiver B stream: RFC 8936 POLL;
- POLL endpoint returned by Keycloak:
  `/realms/{realm}/ssf/transmitter/receivers/{clientId}/streams/{streamId}/poll`;
- receiver B authentication: OAuth client credentials with `ssf.read` and
  `ssf.manage` optional scopes explicitly assigned;
- poll body: `maxEvents=100`, `returnImmediately=true`, `ack=[]`;
- enforcement surface: the same two independent-process MCP gateways and
  `repo_write`/`apply_revocation` tools used in E-B22.

HTTP long polling is not used: Keycloak 26.7 parses
`returnImmediately=false` but does not honour it. E-B23 makes one explicit
fetch poll and one explicit acknowledgement poll. It reports control messages
and bytes but makes no polling-latency claim.

## Frozen Workload

Use E-B22's exact input hashes and workload identity:

- vectors: 225 total, 112 Filesystem and 113 Postgres;
- ordered workload identity SHA-256:
  `75ce415ae238fb0d973e9cbf25d13c81bbecf574d409cf782054e487c33027ae`;
- frozen targets: 10/10, including the one zero-vector target.

No model inference or original mutation is repeated. Each independent call
identity is replayed through the guarded no-side-effect MCP enforcement tool.

## Execution

1. Start pinned PostgreSQL, Keycloak, receiver-A relay, and MCP gateways A/B.
2. Configure receiver A as PUSH and receiver B as POLL for
   `session-revoked`.
3. Create one Keycloak login/session and derive the fresh delegation ID from
   its opaque session ID.
4. Confirm both gateways allow one pre-revocation control call.
5. Logout the session.
6. Verify and apply A's PUSH SET; confirm A denies a matched control call.
7. Before any B poll, confirm B still allows the same matched control call.
8. Receiver B performs one authenticated Keycloak POLL. Require exactly one
   SET, `moreAvailable=false`, a valid RS256 signature, CAEP
   `session-revoked`, and the same opaque session ID.
9. Apply the polled SET to gateway B.
10. Replay all 225 ordered vectors through A and B.
11. Receiver B performs a second poll with `ack=[jti]`. Require an empty
    `sets` object and a delivered outbox state.

## Deterministic Gate

E-B23 passes only if:

1. all frozen hashes, targets, counts, ordering, and configuration flags match;
2. pinned PostgreSQL and process-isolated gateways are used;
3. both gateways allow before revocation;
4. A's signed PUSH SET is applied and A denies before B polls;
5. B allows before its first poll;
6. the first authenticated B poll returns exactly one valid signed matching
   SET and no unrelated SET;
7. after applying it, A and B each deny 225/225 paired vectors;
8. the second poll acknowledges the returned jti, returns no SET, and the
   Keycloak POLL row is no longer pending;
9. exactly two receiver-initiated POLL requests are counted and their request
   and response bytes are reported; and
10. no PUSH handoff, log repair, admin pending-event read, or self-authored
    event store is used to change B's deny state.

Any authentication/scope failure, extra/missing SET, input mismatch, partial
replay, wrong session, signature failure, or unintended B state transition
makes the run `INVALID`.

## Claim Boundary

A pass establishes that Keycloak's independently implemented RFC 8936 POLL
path can drive the same real gateway deny state and frozen workload outcome as
PUSH. It does not establish that POLL repairs an acknowledged PUSH, provide a
multi-host or latency comparison, or support mechanism superiority.

