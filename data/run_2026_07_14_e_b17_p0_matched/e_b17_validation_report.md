# E-B17 Validation Report

## Material Passport

- Origin Skill: academic-research-suite / experiment-agent
- Origin Mode: validate + reproduce
- Origin Date: 2026-07-14T14:42:16-07:00
- Verification Status: VERIFIED
- Version Label: e-b17-validation-v1

## Validation Report

- **Source**: E-B17 / e-b17-prereg-v1
- **Overall Confidence**: CAUTION
- **Reproducibility**: REPRODUCIBLE
- **Saved verdict preserved**: True

### Statistical Findings

| drop | baseline | pairs | mean difference | relative reduction | signs (-/+) | exact sign p | RevProp feasible |
|---:|---|---:|---:|---:|---:|---:|---:|
| 0.20 | drp-10-300 | 30 | -49.6724 | 0.983 | 30/0 | 1.86e-09 | 1 |
| 0.20 | drp-10-60 | 30 | -49.6724 | 0.983 | 30/0 | 1.86e-09 | 1 |
| 0.50 | drp-10-300 | 30 | -48.8866 | 0.967 | 30/0 | 1.86e-09 | 0 |
| 0.50 | drp-10-60 | 30 | -48.8866 | 0.967 | 30/0 | 1.86e-09 | 0 |

The preregistered percentile-bootstrap intervals are stable and the saved files reproduce exactly. The reported bootstrap p-value is retained for protocol compliance, but it is an observed-distribution tail probability rather than a null-centered bootstrap test; it should not be the sole inferential basis. The independent exact sign test gives the same direction. DRP-60 and DRP-300 are one matched mechanism family because both are intentionally rescaled to 10 seconds.

### Warnings

| Type | Detail | Affected |
|---|---|---|
| Statistical calibration | Bootstrap confidence intervals are suitable effect summaries, but the frozen bootstrap p-value is not null-centered. | p-values only; effect direction and exact reproduction are unaffected |
| Model dependence | Repair delays and costs are mechanism-level assumptions, so the 98.3% reduction is conditional on the frozen simulator. | external magnitude |
| Duplicate matched family | DRP-60 and DRP-300 share the same 10-second matched configuration. | comparison count, not direction |
| Boundary failure | RevProp uses 8.001 messages/gateway at 20% but 9.501 at 50%, exceeding the 8.1 cap. | universal-superiority claim |

### Fallacy Scan

- **Coverage**: 11/11 fallacy types checked

| Fallacy | Severity | Detail | Recommendation |
|---|---|---|---|
| Simpson's paradox | NOTE | The two frozen suppression strata are reported separately: 20% passes and 50% fails the cost gate; they are not pooled into a rescue claim. | Keep both stratum decisions visible. |
| Ecological fallacy | NOTE | The estimand is a mechanism-by-cell gateway aggregate; no claim about an individual gateway or human population is inferred. | Retain mechanism/cell-level language. |
| Berkson's bias | NOTE | All preregistered mechanism, cell, and seed rows are retained; feasibility filtering is part of the frozen estimand and not post-outcome sampling. | Do not drop infeasible or unfavorable rows. |
| Collider bias | NOTE | No regression or covariate adjustment conditions on a common effect of mechanism and outcome. | No action required. |
| Base-rate neglect | CAUTION | The 10 calls/s/gateway workload and one revocation event are synthetic; they do not estimate field prevalence or predictive value. | Scope damage magnitudes to the frozen workload and add production-trace calibration as future work. |
| Regression to the mean | NOTE | Seeds 0--29 and cells were frozen before results; no extreme pilot run was selected for confirmation. | Preserve the preregistration commits. |
| Survivorship bias | NOTE | Non-delivery is right-censored at 60 seconds and remains in completeness and damage denominators; 3,000/3,000 rows survive. | Keep censoring explicit in tables. |
| Look-elsewhere effect | CAUTION | Only two cells are confirmatory and Holm correction covers four recorded comparisons, but DRP-60 and DRP-300 collapse to the same 10-second matched parameterization. | Treat the duplicate DRP rows as one mechanism family in interpretation; report both only for protocol traceability. |
| Forking paths / HARKing | NOTE | Thresholds and verdict rules were committed before E-B17 implementation, and E-B18 was committed before its first inference. | Label any later sweep exploratory. |
| Correlation implies causation | CAUTION | Common random traces support a within-model causal comparison of mechanism choices, not a causal claim about production deployments. | Use 'in the matched simulation' and pair it with E-B18's directional check. |
| Reverse causality | NOTE | Mechanism assignment and the revocation fault precede all enforcement and stale-call outcomes by construction. | No action required. |

### Reproducibility

- **Method**: deterministic full re-run with seeds 0--29 and byte-for-byte file comparison
- **Verdict**: REPRODUCIBLE

| File | Original SHA-256 | Re-run SHA-256 | Status |
|---|---|---|---|
| e_b17_p0_matched_baselines.csv | `d9ca0aaa9baa443da31c5239f595dc2200171f78be4eef984b34226e0df4ec61` | `d9ca0aaa9baa443da31c5239f595dc2200171f78be4eef984b34226e0df4ec61` | MATCH |
| e_b17_aggregate.csv | `d242d5681f5b8f019933aa3883aa1bb60c098b9e5ad6009d0531763428416803` | `d242d5681f5b8f019933aa3883aa1bb60c098b9e5ad6009d0531763428416803` | MATCH |
| e_b17_summary.json | `606f7b81ba3f83cb2c81099b67568d3faf2103b3f8e11de23ad5bf53b8bee516` | `606f7b81ba3f83cb2c81099b67568d3faf2103b3f8e11de23ad5bf53b8bee516` | MATCH |
| e_b17_decision.json | `a5521a6adfb9d9ba2bae45d9a141b0ab57662b80260a8948287dda34bd891949` | `a5521a6adfb9d9ba2bae45d9a141b0ab57662b80260a8948287dda34bd891949` | MATCH |
| e_b17_report.md | `e3b7a8b27b7ea9733b1cd6565d98351d7e6296a90a0f8a4f613c0e6c3bc1f2c6` | `e3b7a8b27b7ea9733b1cd6565d98351d7e6296a90a0f8a4f613c0e6c3bc1f2c6` | MATCH |
