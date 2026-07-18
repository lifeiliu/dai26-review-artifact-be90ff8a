# E-B24 Local Real-Effect Qualification

## Material Passport

- Origin Skill: academic-research-suite / experiment-agent
- Origin Mode: run + deterministic validation
- Origin Date: 2026-07-16
- Verification Status: VERIFIED LOCAL QUALIFICATION
- Version Label: e-b24-local-gate-v1

## Decision

**The local gate passed.**
This result qualifies the real-effect mapper, persistent gateway, durable receiver, and effect oracles. It is not multi-host evidence and it does not repeat Keycloak PUSH/POLL.

## Phase Results

| Phase | Allowed | Denied | Filesystem effects | PostgreSQL effects |
|---|---:|---:|---:|---:|
| `active` | 225 | 0 | 112 | 113 |
| `revoked` | 0 | 225 | 0 | 0 |
| `recovery_pre` | 225 | 0 | 112 | 113 |
| `recovery_post` | 0 | 225 | 0 | 0 |

## Assertions

- [x] `frozen_vectors_match`
- [x] `frozen_configuration_unchanged`
- [x] `pinned_postgres_used`
- [x] `gateway_process_isolation`
- [x] `active_allows_and_commits`
- [x] `revoked_denies_without_effect`
- [x] `persisted_before_handoff_commits`
- [x] `recovery_enforces_without_effect`
- [x] `receiver_reopen_persisted`
- [x] `enforcement_receipt_persisted`
- [x] `oracle_vector_sets_match`
- [x] `all_reported_effects_match_oracles`
- [x] `receiver_receipt_survives_reopen`

## Claim Boundary

The 225 identities are an effect-carrying replay: E-B20 retained hashes and mutation labels, not raw mutation arguments. The local run proves reversible real effects and durable persisted-to-enforced state transitions on one host. It does not establish multi-host, multi-zone, production-incidence, or mechanism-superiority claims.
