# E-B10 Real Gateway/Tool Path Report

Raw rows: 40
Aggregate rows: 4
Protocol profiles: ['raw-http-json']
Fault scenarios: ['none', 'push-drop-log-repair']
Integration success rate: 1.0000
Protocol schema pass rate: 1.0000
Pre-revocation allowed rate: 1.0000
Post-repair reject rate: 1.0000
Mean prevented fraction: 0.9945
Max revoked tool calls allowed: 182.49
Max stale capability window: 0.6499
Max fault recovery latency: 0.6495
Transport error count: 0
Loopback service boundary rate: 1.0000
Separate OS process rate: 0.0000

## Run Config

- `fault_scenarios`: `('none', 'push-drop-log-repair')`
- `n_parties_values`: `(30,)`
- `protocol_profiles`: `('raw-http-json',)`
- `seeds`: `(0, 1, 2, 3, 4, 5, 6, 7, 8, 9)`
- `task_duration`: `60.0`
- `tool_call_rates`: `(1.0, 10.0)`
- `tool_name`: `repo-write`
- `ttl`: `60.0`

## Integration Aggregates

| n | calls/s/gateway | protocol | fault | runs | success | schema | stale p99 | recovery p99 | allowed calls | prevented | errors |
|---:|---:|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 30 | 1.00 | raw-http-json | none | 10 | 1.0000 | 1.0000 | 0.0594 |  | 1.65 | 0.9991 | 0.00 |
| 30 | 1.00 | raw-http-json | push-drop-log-repair | 10 | 1.0000 | 1.0000 | 0.6430 | 0.6430 | 18.02 | 0.9900 | 0.00 |
| 30 | 10.00 | raw-http-json | none | 10 | 1.0000 | 1.0000 | 0.0594 |  | 16.51 | 0.9991 | 0.00 |
| 30 | 10.00 | raw-http-json | push-drop-log-repair | 10 | 1.0000 | 1.0000 | 0.6430 | 0.6430 | 180.16 | 0.9900 | 0.00 |

## Interpretation

E-B10 exercises the revocation decision across live loopback gateway, tool, and log services. Every agent call crosses a TCP JSONL gateway boundary and accepted calls are forwarded across a second TCP JSONL tool boundary. The evidence upgrades E-B8 from a pure simulator to a local prototype path, but it is still not a multi-process, multi-host, or production deployment.
