# E-B8 Agent-Tool Gateway Report

Raw rows: 450
Aggregate rows: 15
Agent runtime models: ['tool-gateway-cached-capability']
Tool names: ['repo-write']
Max revoked tool calls allowed: 1800000.00
Mean prevented fraction: 0.7574
Hybrid mean prevented fraction: 0.9981
Hybrid max stale capability window: 0.5136
Hybrid <25% of TTL baseline cells: 3
Hybrid auditable low-latency cells: 3

## Run Config

- `n_parties_values`: `(300,)`
- `push_suppression`: `0.2`
- `seeds`: `(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29)`
- `strategies`: `('push', 'ttl-rcc', 'push-gossip', 'log', 'hybrid')`
- `task_duration`: `60.0`
- `tool_call_rates`: `(1.0, 10.0, 100.0)`
- `tool_name`: `repo-write`
- `ttl`: `60.0`

## Gateway Aggregates

| n | calls/s/gateway | strategy | runs | completeness | p99 stale | max stale | allowed calls | prevented fraction | audit evidence | messages |
|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 300 | 1.00 | hybrid | 30 | 1.0000 | 0.3971 | 0.4166 | 34.51 | 0.9981 | 1.00 | 78780.6 |
| 300 | 1.00 | log | 30 | 1.0000 | 0.5489 | 0.5498 | 149.93 | 0.9917 | 1.00 | 4649.4 |
| 300 | 1.00 | push | 30 | 0.8000 | 60.0000 | 60.0000 | 3611.98 | 0.7993 | 0.00 | 300.0 |
| 300 | 1.00 | push-gossip | 30 | 1.0000 | 0.3975 | 0.4557 | 34.56 | 0.9981 | 0.00 | 74138.9 |
| 300 | 1.00 | ttl-rcc | 30 | 1.0000 | 60.0000 | 60.0000 | 18000.00 | 0.0000 | 0.00 | 0.0 |
| 300 | 10.00 | hybrid | 30 | 1.0000 | 0.3971 | 0.4166 | 345.06 | 0.9981 | 1.00 | 78780.6 |
| 300 | 10.00 | log | 30 | 1.0000 | 0.5489 | 0.5498 | 1499.32 | 0.9917 | 1.00 | 4649.4 |
| 300 | 10.00 | push | 30 | 0.8000 | 60.0000 | 60.0000 | 36119.84 | 0.7993 | 0.00 | 300.0 |
| 300 | 10.00 | push-gossip | 30 | 1.0000 | 0.3975 | 0.4557 | 345.57 | 0.9981 | 0.00 | 74138.9 |
| 300 | 10.00 | ttl-rcc | 30 | 1.0000 | 60.0000 | 60.0000 | 180000.00 | 0.0000 | 0.00 | 0.0 |
| 300 | 100.00 | hybrid | 30 | 1.0000 | 0.3971 | 0.4166 | 3450.62 | 0.9981 | 1.00 | 78780.6 |
| 300 | 100.00 | log | 30 | 1.0000 | 0.5489 | 0.5498 | 14993.19 | 0.9917 | 1.00 | 4649.4 |
| 300 | 100.00 | push | 30 | 0.8000 | 60.0000 | 60.0000 | 361198.40 | 0.7993 | 0.00 | 300.0 |
| 300 | 100.00 | push-gossip | 30 | 1.0000 | 0.3975 | 0.4557 | 3455.73 | 0.9981 | 0.00 | 74138.9 |
| 300 | 100.00 | ttl-rcc | 30 | 1.0000 | 60.0000 | 60.0000 | 1800000.00 | 0.0000 | 0.00 | 0.0 |

## Hybrid Comparisons

| n | calls/s/gateway | hybrid allowed | hybrid prevented | hybrid/TTL allowed | hybrid/push allowed | hybrid/push+gossip allowed | hybrid-log p99 stale delta |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 300 | 1.00 | 34.51 | 0.9981 | 0.002 | 0.010 | 0.999 | -0.1518 |
| 300 | 10.00 | 345.06 | 0.9981 | 0.002 | 0.010 | 0.999 | -0.1518 |
| 300 | 100.00 | 3450.62 | 0.9981 | 0.002 | 0.010 | 0.999 | -0.1518 |

## Interpretation

E-B8 reframes revocation as an agent-tool gateway problem: a delegated tool capability continues to authorize tool calls until the gateway learns the revocation or the token TTL expires. The metric is revoked tool calls allowed/prevented, not generic network latency. The experiment is a gateway model over the existing propagation simulator; it is not a live LLM-agent benchmark.
