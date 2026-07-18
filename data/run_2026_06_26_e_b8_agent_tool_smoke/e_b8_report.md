# E-B8 Agent-Tool Gateway Report

Raw rows: 30
Aggregate rows: 10
Agent runtime models: ['tool-gateway-cached-capability']
Tool names: ['repo-write']
Max revoked tool calls allowed: 24000.00
Mean prevented fraction: 0.7574
Hybrid mean prevented fraction: 0.9981
Hybrid max stale capability window: 0.4014
Hybrid <25% of TTL baseline cells: 2
Hybrid auditable low-latency cells: 2

## Run Config

- No run config recorded.

## Gateway Aggregates

| n | calls/s/gateway | strategy | runs | completeness | p99 stale | max stale | allowed calls | prevented fraction | audit evidence | messages |
|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 40 | 1.00 | hybrid | 3 | 1.0000 | 0.3849 | 0.3948 | 4.51 | 0.9981 | 1.00 | 10723.7 |
| 40 | 1.00 | log | 3 | 1.0000 | 0.5469 | 0.5491 | 20.06 | 0.9916 | 1.00 | 620.3 |
| 40 | 1.00 | push | 3 | 0.8000 | 60.0000 | 60.0000 | 481.62 | 0.7993 | 0.00 | 40.0 |
| 40 | 1.00 | push-gossip | 3 | 1.0000 | 0.3819 | 0.3847 | 4.52 | 0.9981 | 0.00 | 10122.3 |
| 40 | 1.00 | ttl-rcc | 3 | 1.0000 | 60.0000 | 60.0000 | 2400.00 | 0.0000 | 0.00 | 0.0 |
| 40 | 10.00 | hybrid | 3 | 1.0000 | 0.3849 | 0.3948 | 45.05 | 0.9981 | 1.00 | 10723.7 |
| 40 | 10.00 | log | 3 | 1.0000 | 0.5469 | 0.5491 | 200.64 | 0.9916 | 1.00 | 620.3 |
| 40 | 10.00 | push | 3 | 0.8000 | 60.0000 | 60.0000 | 4816.22 | 0.7993 | 0.00 | 40.0 |
| 40 | 10.00 | push-gossip | 3 | 1.0000 | 0.3819 | 0.3847 | 45.23 | 0.9981 | 0.00 | 10122.3 |
| 40 | 10.00 | ttl-rcc | 3 | 1.0000 | 60.0000 | 60.0000 | 24000.00 | 0.0000 | 0.00 | 0.0 |

## Hybrid Comparisons

| n | calls/s/gateway | hybrid allowed | hybrid prevented | hybrid/TTL allowed | hybrid/push allowed | hybrid/push+gossip allowed | hybrid-log p99 stale delta |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 40 | 1.00 | 4.51 | 0.9981 | 0.002 | 0.009 | 0.996 | -0.1620 |
| 40 | 10.00 | 45.05 | 0.9981 | 0.002 | 0.009 | 0.996 | -0.1620 |

## Interpretation

E-B8 reframes revocation as an agent-tool gateway problem: a delegated tool capability continues to authorize tool calls until the gateway learns the revocation or the token TTL expires. The metric is revoked tool calls allowed/prevented, not generic network latency. The experiment is a gateway model over the existing propagation simulator; it is not a live LLM-agent benchmark.
