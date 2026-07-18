# E-B18 Real LLM / MCP Selective-Revocation Report

## Material Passport

- Origin Skill: academic-research-suite / experiment-agent
- Origin Mode: run + validate
- Verification Status: VERIFIED
- Version Label: e-b18-prereg-v1

- Gate: **PASS**
- Runs: 6 / 6
- Execution complete: 6
- Directional pass: 6
- Replay pass: 6

## Profile Aggregates

| profile | runs | real LLM calls | pre allowed | post-direct successes | post-repair successes | model mean ms | MCP mean ms | gate pass |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| push-only | 3 | 7.0 | 2.0 | 1.0 | 1.0 | 1240.41 | 22.78 | 1.000 |
| revprop | 3 | 7.0 | 2.0 | 1.0 | 0.0 | 1157.03 | 23.14 | 1.000 |

## Scope

The experiment uses real local inference and the official MCP Python implementation across separate loopback server processes. It is not a multi-host, cloud-model, or multi-vendor interoperability result.
