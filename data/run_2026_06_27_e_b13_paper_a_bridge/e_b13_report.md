# E-B13 Paper A Agent-System Bridge Report

Raw rows: 4
Aggregate rows: 4
Source experiments: ['E16', 'E17', 'E18', 'E19']
Framework surfaces: ['langgraph-runtime-trace-replay', 'a2a-task-handoff-shaped', 'cross-framework-agent-shaped', 'crewai-executable-workflows']
Total trace units: 509
Total signed delegation events: 2053
Weighted valid signed delegation rate: 1.0000
Real agent-framework runtime rows: 2
Executable agent runtime rows: 2
Production deployment rows: 0
Alternate-parent cases: 328
Tree-over-revocation cases: 328
Cross-domain target cases: 899
Deployer-scoped under-revocation cases: 899

## Run Config

- No run config recorded.

## Source Surfaces

| source | surface | traces | signed | valid | real runtime | executable | alt-parent | tree wrong | scoped under |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| E16 | langgraph-runtime-trace-replay | 500 | 2000 | 1.0000 | 1 | 1 | 320 | 320 | 880 |
| E17 | a2a-task-handoff-shaped | 2 | 8 | 1.0000 | 0 | 0 | 1 | 1 | 6 |
| E18 | cross-framework-agent-shaped | 2 | 10 | 1.0000 | 0 | 0 | 2 | 2 | 3 |
| E19 | crewai-executable-workflows | 5 | 35 | 1.0000 | 1 | 1 | 5 | 5 | 10 |

## Interpretation

E-B13 does not add a new propagation mechanism. It bridges Paper A's agent-system evidence into Paper B by showing that the delegated edges propagated by Paper B can be produced by real LangGraph traces and executable CrewAI workflows, plus A2A/cross-framework shaped handoffs. The bridge reduces the multi-agent-system evidence gap but still leaves production deployment, multi-vendor interop, and multi-host scale as explicit non-claims.
