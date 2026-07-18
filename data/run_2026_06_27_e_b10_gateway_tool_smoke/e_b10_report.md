# E-B10 Real Gateway/Tool Path Report

Raw rows: 8
Aggregate rows: 4
Protocol profiles: ['raw-http-json']
Fault scenarios: ['none', 'push-drop-log-repair']
Integration success rate: 1.0000
Protocol schema pass rate: 1.0000
Pre-revocation allowed rate: 1.0000
Post-repair reject rate: 1.0000
Mean prevented fraction: 0.9946
Max revoked tool calls allowed: 29.87
Max stale capability window: 0.6347
Max fault recovery latency: 0.6289
Transport error count: 0
Loopback service boundary rate: 1.0000
Separate OS process rate: 0.0000

## Run Config

- No run config recorded.

## Integration Aggregates

| n | calls/s/gateway | protocol | fault | runs | success | schema | stale p99 | recovery p99 | allowed calls | prevented | errors |
|---:|---:|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 5 | 1.00 | raw-http-json | none | 2 | 1.0000 | 1.0000 | 0.0572 |  | 0.28 | 0.9991 | 0.00 |
| 5 | 1.00 | raw-http-json | push-drop-log-repair | 2 | 1.0000 | 1.0000 | 0.6186 | 0.6186 | 2.98 | 0.9901 | 0.00 |
| 5 | 10.00 | raw-http-json | none | 2 | 1.0000 | 1.0000 | 0.0572 |  | 2.76 | 0.9991 | 0.00 |
| 5 | 10.00 | raw-http-json | push-drop-log-repair | 2 | 1.0000 | 1.0000 | 0.6186 | 0.6186 | 29.84 | 0.9901 | 0.00 |

## Interpretation

E-B10 exercises the revocation decision across live loopback gateway, tool, and log services. Every agent call crosses a TCP JSONL gateway boundary and accepted calls are forwarded across a second TCP JSONL tool boundary. The evidence upgrades E-B8 from a pure simulator to a local prototype path, but it is still not a multi-process, multi-host, or production deployment.
