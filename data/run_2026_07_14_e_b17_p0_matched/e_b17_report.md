# E-B17 P0 Matched Strongest-Mechanism Report

## Material Passport

- Origin Skill: academic-research-suite / experiment-agent
- Origin Mode: run + validate
- Verification Status: ANALYZED
- Version Label: e-b17-prereg-v1

- Raw rows: 3000
- Aggregate rows: 100
- E-B17 verdict: **E_B17_CONSTRAINED_ADVANTAGE**

## Confirmatory Cells

| drop | n | feasible baselines | RevProp feasible | frontier | statistics | cell pass |
|---:|---:|---|---:|---:|---:|---:|
| 0.20 | 1000 | drp-10-300, drp-10-60 | 1 | 1 | 1 | 1 |
| 0.50 | 1000 | drp-10-300, drp-10-60 | 0 | 1 | 1 | 0 |

## Paired Confirmatory Comparisons

| drop | baseline | seeds | mean diff | 95% CI | relative reduction | superiority | Holm p |
|---:|---|---:|---:|---|---:|---:|---:|
| 0.20 | drp-10-300 | 30 | -49.6724 | [-49.9415, -49.3913] | 0.983 | 1.000 | 0.000800 |
| 0.20 | drp-10-60 | 30 | -49.6724 | [-49.9400, -49.3960] | 0.983 | 1.000 | 0.000800 |
| 0.50 | drp-10-300 | 30 | -48.8866 | [-49.1607, -48.6087] | 0.967 | 1.000 | 0.000800 |
| 0.50 | drp-10-60 | 30 | -48.8866 | [-49.1591, -48.6092] | 0.967 | 1.000 | 0.000800 |

## Matched-Profile Aggregate Surface

| fault | drop | mechanism | explicit | audit | stale calls/gw | availability loss | messages/gw | bytes/gw | feasible |
|---|---:|---|---:|---:|---:|---:|---:|---:|---:|
| correlated-all | 0.20 | aip-03 | 0.8000 | 0.0000 | 140.056 | 0.0000 | 2.800 | 2534.4 | 0 |
| correlated-all | 0.20 | caep-ssf | 0.8000 | 0.0000 | 120.281 | 0.0000 | 1.000 | 1200.0 | 0 |
| correlated-all | 0.20 | drp-10-300 | 0.8000 | 0.8000 | 160.537 | 0.0000 | 6.001 | 3073.2 | 0 |
| correlated-all | 0.20 | drp-10-60 | 0.8000 | 0.8000 | 160.537 | 0.0000 | 6.001 | 3073.2 | 0 |
| correlated-all | 0.20 | hbhc | 0.0000 | 0.0000 | 350.134 | 0.0834 | 6.000 | 1008.0 | 0 |
| correlated-all | 0.20 | revprop | 0.8000 | 0.8000 | 120.281 | 0.0000 | 7.001 | 2737.2 | 0 |
| correlated-all | 0.20 | status-list | 0.8000 | 0.0000 | 160.134 | 0.0000 | 6.000 | 750000.0 | 0 |
| correlated-all | 0.20 | sync-fail-closed | 0.0000 | 0.0000 | 0.504 | 0.2000 | 600.000 | 307200.0 | 0 |
| correlated-all | 0.20 | sync-fail-open | 0.0000 | 0.0000 | 120.404 | 0.0000 | 600.000 | 307200.0 | 0 |
| correlated-all | 0.20 | ttl-cache | 0.0000 | 0.0000 | 600.000 | 0.0000 | 0.000 | 0.0 | 0 |
| correlated-all | 0.50 | aip-03 | 0.5000 | 0.0000 | 312.606 | 0.0000 | 5.500 | 4536.0 | 0 |
| correlated-all | 0.50 | caep-ssf | 0.5000 | 0.0000 | 300.178 | 0.0000 | 1.000 | 1200.0 | 0 |
| correlated-all | 0.50 | drp-10-300 | 0.5000 | 0.5000 | 325.295 | 0.0000 | 6.001 | 3073.2 | 0 |
| correlated-all | 0.50 | drp-10-60 | 0.5000 | 0.5000 | 325.295 | 0.0000 | 6.001 | 3073.2 | 0 |
| correlated-all | 0.50 | hbhc | 0.0000 | 0.0000 | 350.134 | 0.2083 | 6.000 | 1008.0 | 0 |
| correlated-all | 0.50 | revprop | 0.5000 | 0.5000 | 300.178 | 0.0000 | 7.001 | 2737.2 | 0 |
| correlated-all | 0.50 | status-list | 0.5000 | 0.0000 | 325.044 | 0.0000 | 6.000 | 750000.0 | 0 |
| correlated-all | 0.50 | sync-fail-closed | 0.0000 | 0.0000 | 0.504 | 0.5000 | 600.000 | 307200.0 | 0 |
| correlated-all | 0.50 | sync-fail-open | 0.0000 | 0.0000 | 300.254 | 0.0000 | 600.000 | 307200.0 | 0 |
| correlated-all | 0.50 | ttl-cache | 0.0000 | 0.0000 | 600.000 | 0.0000 | 0.000 | 0.0 | 0 |
| none | 0.00 | aip-03 | 1.0000 | 0.0000 | 25.133 | 0.0000 | 1.000 | 1200.0 | 0 |
| none | 0.00 | caep-ssf | 1.0000 | 0.0000 | 0.352 | 0.0000 | 1.000 | 1200.0 | 0 |
| none | 0.00 | drp-10-300 | 1.0000 | 1.0000 | 50.549 | 0.0000 | 6.001 | 3073.2 | 1 |
| none | 0.00 | drp-10-60 | 1.0000 | 1.0000 | 50.549 | 0.0000 | 6.001 | 3073.2 | 1 |
| none | 0.00 | hbhc | 0.0000 | 0.0000 | 350.134 | 0.0000 | 6.000 | 1008.0 | 0 |
| none | 0.00 | revprop | 1.0000 | 1.0000 | 0.352 | 0.0000 | 7.001 | 2737.2 | 1 |
| none | 0.00 | status-list | 1.0000 | 0.0000 | 50.045 | 0.0000 | 6.000 | 750000.0 | 0 |
| none | 0.00 | sync-fail-closed | 0.0000 | 0.0000 | 0.504 | 0.0000 | 600.000 | 307200.0 | 0 |
| none | 0.00 | sync-fail-open | 0.0000 | 0.0000 | 0.504 | 0.0000 | 600.000 | 307200.0 | 0 |
| none | 0.00 | ttl-cache | 0.0000 | 0.0000 | 600.000 | 0.0000 | 0.000 | 0.0 | 0 |
| selective-operator | 0.20 | aip-03 | 0.8000 | 0.0000 | 140.056 | 0.0000 | 2.800 | 2534.4 | 0 |
| selective-operator | 0.20 | caep-ssf | 0.8000 | 0.0000 | 120.281 | 0.0000 | 1.000 | 1200.0 | 0 |
| selective-operator | 0.20 | drp-10-300 | 1.0000 | 1.0000 | 50.549 | 0.0000 | 6.001 | 3073.2 | 1 |
| selective-operator | 0.20 | drp-10-60 | 1.0000 | 1.0000 | 50.549 | 0.0000 | 6.001 | 3073.2 | 1 |
| selective-operator | 0.20 | hbhc | 0.0000 | 0.0000 | 350.134 | 0.0000 | 12.000 | 2016.0 | 0 |
| selective-operator | 0.20 | revprop | 1.0000 | 1.0000 | 0.877 | 0.0000 | 8.001 | 3937.2 | 1 |
| selective-operator | 0.20 | status-list | 0.8000 | 0.0000 | 160.134 | 0.0000 | 6.000 | 750000.0 | 0 |
| selective-operator | 0.20 | sync-fail-closed | 0.0000 | 0.0000 | 0.504 | 0.2000 | 600.000 | 307200.0 | 0 |
| selective-operator | 0.20 | sync-fail-open | 0.0000 | 0.0000 | 120.404 | 0.0000 | 600.000 | 307200.0 | 0 |
| selective-operator | 0.20 | ttl-cache | 0.0000 | 0.0000 | 600.000 | 0.0000 | 0.000 | 0.0 | 0 |
| selective-operator | 0.50 | aip-03 | 0.5000 | 0.0000 | 312.606 | 0.0000 | 5.500 | 4536.0 | 0 |
| selective-operator | 0.50 | caep-ssf | 0.5000 | 0.0000 | 300.178 | 0.0000 | 1.000 | 1200.0 | 0 |
| selective-operator | 0.50 | drp-10-300 | 1.0000 | 1.0000 | 50.549 | 0.0000 | 6.001 | 3073.2 | 1 |
| selective-operator | 0.50 | drp-10-60 | 1.0000 | 1.0000 | 50.549 | 0.0000 | 6.001 | 3073.2 | 1 |
| selective-operator | 0.50 | hbhc | 0.0000 | 0.0000 | 350.134 | 0.0000 | 21.000 | 3528.0 | 0 |
| selective-operator | 0.50 | revprop | 1.0000 | 1.0000 | 1.663 | 0.0000 | 9.501 | 5737.2 | 0 |
| selective-operator | 0.50 | status-list | 0.5000 | 0.0000 | 325.044 | 0.0000 | 6.000 | 750000.0 | 0 |
| selective-operator | 0.50 | sync-fail-closed | 0.0000 | 0.0000 | 0.504 | 0.5000 | 600.000 | 307200.0 | 0 |
| selective-operator | 0.50 | sync-fail-open | 0.0000 | 0.0000 | 300.254 | 0.0000 | 600.000 | 307200.0 | 0 |
| selective-operator | 0.50 | ttl-cache | 0.0000 | 0.0000 | 600.000 | 0.0000 | 0.000 | 0.0 | 0 |

## Scope

E-B17 is a preregistered common-trace mechanism simulation. It does not establish production interoperability or mechanism novelty. The final RevProp verdict additionally requires P0-3, E-B18, and P0-5.
