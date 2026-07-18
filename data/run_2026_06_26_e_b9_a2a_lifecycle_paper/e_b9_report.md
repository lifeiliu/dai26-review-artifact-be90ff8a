# E-B9 A2A Lifecycle Binding Report

Raw rows: 360
Aggregate rows: 12
Compatibility cells: ['new-client-new-server', 'new-client-old-server', 'old-client-new-server', 'old-client-old-server']
Compatibility pass rate: 1.0000
Schema conformance pass rate: 1.0000
Lifecycle binding success rate: 0.2500
Revocation enforced rate: 0.7500
New/new mean effective enforcement latency: 0.3986
Old/new mean server enforcement latency: 0.3986
New/old mean availability loss: 1.0000
Old/old mean revoked tool calls allowed: 666000.00
Max lifecycle event bytes: 573

## Run Config

- `a2a_compatibility_cells`: `('new-client-new-server', 'new-client-old-server', 'old-client-new-server', 'old-client-old-server')`
- `fallback_policy`: `fail-closed`
- `n_parties_values`: `(300,)`
- `push_suppression`: `0.2`
- `seeds`: `(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29)`
- `task_duration`: `60.0`
- `tool_call_rates`: `(1.0, 10.0, 100.0)`
- `tool_name`: `repo-write`
- `ttl`: `60.0`

## Compatibility Aggregates

| n | calls/s/gateway | cell | runs | compat | schema | lifecycle | enforced | available | latency | allowed calls | prevented |
|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 300 | 1.00 | new-client-new-server | 30 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.3986 | 34.98 | 0.9981 |
| 300 | 1.00 | new-client-old-server | 30 | 1.0000 | 1.0000 | 0.0000 | 1.0000 | 0.0000 | 0.0500 | 0.00 | 1.0000 |
| 300 | 1.00 | old-client-new-server | 30 | 1.0000 | 1.0000 | 0.0000 | 1.0000 | 1.0000 | 0.3986 | 34.98 | 0.9981 |
| 300 | 1.00 | old-client-old-server | 30 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 1.0000 | 60.0000 | 18000.00 | 0.0000 |
| 300 | 10.00 | new-client-new-server | 30 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.3986 | 349.78 | 0.9981 |
| 300 | 10.00 | new-client-old-server | 30 | 1.0000 | 1.0000 | 0.0000 | 1.0000 | 0.0000 | 0.0500 | 0.00 | 1.0000 |
| 300 | 10.00 | old-client-new-server | 30 | 1.0000 | 1.0000 | 0.0000 | 1.0000 | 1.0000 | 0.3986 | 349.78 | 0.9981 |
| 300 | 10.00 | old-client-old-server | 30 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 1.0000 | 60.0000 | 180000.00 | 0.0000 |
| 300 | 100.00 | new-client-new-server | 30 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.3986 | 3497.78 | 0.9981 |
| 300 | 100.00 | new-client-old-server | 30 | 1.0000 | 1.0000 | 0.0000 | 1.0000 | 0.0000 | 0.0500 | 0.00 | 1.0000 |
| 300 | 100.00 | old-client-new-server | 30 | 1.0000 | 1.0000 | 0.0000 | 1.0000 | 1.0000 | 0.3986 | 3497.78 | 0.9981 |
| 300 | 100.00 | old-client-old-server | 30 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 1.0000 | 60.0000 | 1800000.00 | 0.0000 |

## Interpretation

E-B9 thickens the A2A deployability claim from payload shape to lifecycle binding. It evaluates Agent Card discovery plus TaskStatusUpdateEvent-like cancellation behavior across new/new, new/old, old/new, and old/old compatibility cells. The experiment is a local conformance and propagation model, not an interoperability test against third-party A2A servers.
