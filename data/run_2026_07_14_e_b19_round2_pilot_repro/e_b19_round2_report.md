# E-B19 Round-2 Equal-Budget Repair Pilot

## Material Passport

- Origin Skill: academic-research-suite / experiment-agent
- Origin Mode: run + validate
- Origin Date: 2026-07-14
- Verification Status: ANALYZED
- Version Label: e-b19-pilot-prereg-v1

- Raw rows: 360
- Aggregate rows: 12
- Verdict: **EQUAL_BUDGET_RISK_AWARE_REPAIR_SUPPORTED**

## Primary Comparison

- Relative reduction: 30.7211%
- Paired difference 95% CI: [-13065.0240, -8500.9782]
- Exact cost match: True
- Outcome-contract match: True
- Gate pass: True

## Diagnostic Comparisons

| risk profile | targets | policy | reduction | difference 95% CI |
|---|---|---|---:|---:|
| zipf-rate | random | rate-aware | 10.82% | [-91.4605, -44.5788] |
| zipf-rate | random | risk-aware | 10.82% | [-90.9469, -44.8058] |
| zipf-rate | top-risk | rate-aware | 17.16% | [-303.4182, -206.1047] |
| zipf-rate | top-risk | risk-aware | 17.16% | [-303.9254, -205.8700] |
| zipf-correlated | random | rate-aware | 13.79% | [-3141.2125, -834.5521] |
| zipf-correlated | random | risk-aware | 15.83% | [-3380.1317, -1059.5203] |
| zipf-correlated | top-risk | rate-aware | 25.90% | [-11396.5543, -6885.6680] |
| zipf-correlated | top-risk | risk-aware | 30.72% | [-13065.0240, -8500.9782] |
