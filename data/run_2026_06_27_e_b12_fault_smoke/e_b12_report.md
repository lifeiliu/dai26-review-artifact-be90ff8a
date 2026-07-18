# E-B12 Fault Injection Path Report

Raw rows: 16
Aggregate rows: 8
Protocol profiles: ['raw-http-json']
Fault scenarios: ['gateway-restart', 'log-delay', 'partition-heal', 'push-drop-log-repair']
Integration success rate: 1.0000
Protocol schema pass rate: 1.0000
Pre-revocation allowed rate: 1.0000
Post-repair reject rate: 1.0000
Mean prevented fraction: 0.9648
Max revoked tool calls allowed: 179.87
Max stale capability window: 3.6347
Max fault recovery latency: 1.6289
Transport error count: 0
Loopback service boundary rate: 1.0000
Separate OS process rate: 0.0000

## Run Config

- No run config recorded.

## Integration Aggregates

| n | calls/s/gateway | protocol | fault | runs | success | schema | stale p99 | recovery p99 | allowed calls | prevented | errors |
|---:|---:|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 5 | 1.00 | raw-http-json | gateway-restart | 2 | 1.0000 | 1.0000 | 1.6742 | 1.6186 | 8.26 | 0.9725 | 0.00 |
| 5 | 1.00 | raw-http-json | log-delay | 2 | 1.0000 | 1.0000 | 1.6186 | 1.6186 | 7.98 | 0.9734 | 0.00 |
| 5 | 1.00 | raw-http-json | partition-heal | 2 | 1.0000 | 1.0000 | 3.6186 | 1.6186 | 17.98 | 0.9401 | 0.00 |
| 5 | 1.00 | raw-http-json | push-drop-log-repair | 2 | 1.0000 | 1.0000 | 1.6186 | 1.6186 | 7.98 | 0.9734 | 0.00 |
| 5 | 10.00 | raw-http-json | gateway-restart | 2 | 1.0000 | 1.0000 | 1.6742 | 1.6186 | 82.60 | 0.9725 | 0.00 |
| 5 | 10.00 | raw-http-json | log-delay | 2 | 1.0000 | 1.0000 | 1.6186 | 1.6186 | 79.84 | 0.9734 | 0.00 |
| 5 | 10.00 | raw-http-json | partition-heal | 2 | 1.0000 | 1.0000 | 3.6186 | 1.6186 | 179.84 | 0.9401 | 0.00 |
| 5 | 10.00 | raw-http-json | push-drop-log-repair | 2 | 1.0000 | 1.0000 | 1.6186 | 1.6186 | 79.84 | 0.9734 | 0.00 |

## Interpretation

E-B12 injects concrete failure paths in the local prototype: dropped push delivery, delayed log repair, partition healing, and gateway restart with log recovery. The evidence supports bounded recovery-path behavior for the prototype fault model; it does not claim production-grade chaos testing or large-scale distributed fault tolerance.
