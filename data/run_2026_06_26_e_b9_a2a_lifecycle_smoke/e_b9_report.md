# E-B9 A2A Lifecycle Binding Report

Raw rows: 24
Aggregate rows: 8
Compatibility cells: ['new-client-new-server', 'new-client-old-server', 'old-client-new-server', 'old-client-old-server']
Compatibility pass rate: 1.0000
Schema conformance pass rate: 1.0000
Lifecycle binding success rate: 0.2500
Revocation enforced rate: 0.7500
New/new mean effective enforcement latency: 0.3865
Old/new mean server enforcement latency: 0.3865
New/old mean availability loss: 1.0000
Old/old mean revoked tool calls allowed: 13200.00
Max lifecycle event bytes: 569

## Run Config

- No run config recorded.

## Compatibility Aggregates

| n | calls/s/gateway | cell | runs | compat | schema | lifecycle | enforced | available | latency | allowed calls | prevented |
|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 40 | 1.00 | new-client-new-server | 3 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.3865 | 4.57 | 0.9981 |
| 40 | 1.00 | new-client-old-server | 3 | 1.0000 | 1.0000 | 0.0000 | 1.0000 | 0.0000 | 0.0500 | 0.00 | 1.0000 |
| 40 | 1.00 | old-client-new-server | 3 | 1.0000 | 1.0000 | 0.0000 | 1.0000 | 1.0000 | 0.3865 | 4.57 | 0.9981 |
| 40 | 1.00 | old-client-old-server | 3 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 1.0000 | 60.0000 | 2400.00 | 0.0000 |
| 40 | 10.00 | new-client-new-server | 3 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.3865 | 45.68 | 0.9981 |
| 40 | 10.00 | new-client-old-server | 3 | 1.0000 | 1.0000 | 0.0000 | 1.0000 | 0.0000 | 0.0500 | 0.00 | 1.0000 |
| 40 | 10.00 | old-client-new-server | 3 | 1.0000 | 1.0000 | 0.0000 | 1.0000 | 1.0000 | 0.3865 | 45.68 | 0.9981 |
| 40 | 10.00 | old-client-old-server | 3 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 1.0000 | 60.0000 | 24000.00 | 0.0000 |

## Interpretation

E-B9 thickens the A2A deployability claim from payload shape to lifecycle binding. It evaluates Agent Card discovery plus TaskStatusUpdateEvent-like cancellation behavior across new/new, new/old, old/new, and old/old compatibility cells. The experiment is a local conformance and propagation model, not an interoperability test against third-party A2A servers.
