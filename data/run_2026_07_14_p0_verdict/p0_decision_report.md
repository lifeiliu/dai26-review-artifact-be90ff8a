# Paper B P0 Final Decision

## Material Passport

- Origin Skill: academic-research-suite / academic-pipeline
- Origin Mode: synthesize + validate
- Origin Date: 2026-07-14T14:42:23-07:00
- Verification Status: VERIFIED
- Version Label: p0-final-v1

## Verdict: SUPPORTED_CONSTRAINED_ADVANTAGE

RevProp has a constrained empirical advantage in one frozen regime. This is not mechanism novelty or universal superiority.

| Gate | Status |
|---|---:|
| p0_2_matched_baselines | PASS |
| p0_3_claim_boundary | PASS |
| p0_4_real_llm_mcp | PASS |
| p0_5_literature_refresh | PASS |

## Allowed claim

In the preregistered matched simulation at 20% selective operator suppression, RevProp reduces stale calls relative to the feasible rescaled DRP log family while meeting the frozen convergence, audit, availability, message, and byte gates; a six-run local LLM/MCP experiment confirms the directional repair outcome.

## Boundary conditions

- Passing cell: matched selective-operator, suppression=0.20, 1000 gateways, 30 paired seeds.
- Failed cell: suppression=0.50 fails 8.1-message/gateway budget (RevProp=9.501).
- External-validity scope: local Ollama LLM plus official MCP Python over separate loopback server processes.
- Statistical caution: The deterministic paired effect and percentile interval reproduce exactly, and an exact sign test confirms direction. The preregistered bootstrap p-value is not null-centered and is retained only as a protocol-compliance statistic.

## Forbidden claims

- RevProp is a novel revocation, gossip, transparency, or quorum primitive.
- RevProp universally dominates AIP, DRP, HBHC, CAEP/SSF, status, TTL, or synchronous checks.
- The result establishes multi-host, multi-vendor, production, or population-level LLM validity.
- The 50% selective-suppression cell is a RevProp win.
