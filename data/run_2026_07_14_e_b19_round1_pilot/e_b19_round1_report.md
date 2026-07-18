# E-B19 Round-1 Targeted-Omission Pilot

## Material Passport

- Origin Skill: academic-research-suite / experiment-agent
- Origin Mode: run + validate
- Origin Date: 2026-07-14
- Verification Status: ANALYZED
- Version Label: e-b19-pilot-prereg-v1

- Raw rows: 3240
- Aggregate rows: 108
- Verdict: **TARGETED_RISK_AMPLIFICATION_SUPPORTED**

## Primary Comparisons

| risk profile | amplification | difference 95% CI | sign p | Holm p | pass |
|---|---:|---:|---:|---:|---:|
| zipf-rate | 4.4510 | [808.0261, 933.9930] | 1.86e-09 | 3.73e-09 | True |
| zipf-correlated | 5.2703 | [19065.4164, 24940.1406] | 1.86e-09 | 3.73e-09 | True |

## Boundary

Passing this synthetic stress gate supports Round 2 only. It does not establish that production agent-tool risk follows either frozen Zipf profile.
