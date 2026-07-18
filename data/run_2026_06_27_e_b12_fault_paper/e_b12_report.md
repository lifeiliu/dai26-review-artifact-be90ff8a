# E-B12 Fault Injection Path Report

Raw rows: 80
Aggregate rows: 8
Protocol profiles: ['raw-http-json']
Fault scenarios: ['gateway-restart', 'log-delay', 'partition-heal', 'push-drop-log-repair']
Integration success rate: 1.0000
Protocol schema pass rate: 1.0000
Pre-revocation allowed rate: 1.0000
Post-repair reject rate: 1.0000
Mean prevented fraction: 0.9648
Max revoked tool calls allowed: 1082.49
Max stale capability window: 3.6499
Max fault recovery latency: 1.6495
Transport error count: 0
Loopback service boundary rate: 1.0000
Separate OS process rate: 0.0000

## Run Config

- `fault_scenarios`: `('push-drop-log-repair', 'log-delay', 'partition-heal', 'gateway-restart')`
- `gateway_restart_at`: `0.25`
- `log_delay`: `1.0`
- `n_parties_values`: `(30,)`
- `partition_duration`: `2.0`
- `protocol_profiles`: `('raw-http-json',)`
- `seeds`: `(0, 1, 2, 3, 4, 5, 6, 7, 8, 9)`
- `task_duration`: `60.0`
- `tool_call_rates`: `(1.0, 10.0)`
- `tool_name`: `repo-write`
- `ttl`: `60.0`

## Integration Aggregates

| n | calls/s/gateway | protocol | fault | runs | success | schema | stale p99 | recovery p99 | allowed calls | prevented | errors |
|---:|---:|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 30 | 1.00 | raw-http-json | gateway-restart | 10 | 1.0000 | 1.0000 | 1.6997 | 1.6430 | 49.67 | 0.9724 | 0.00 |
| 30 | 1.00 | raw-http-json | log-delay | 10 | 1.0000 | 1.0000 | 1.6430 | 1.6430 | 48.02 | 0.9733 | 0.00 |
| 30 | 1.00 | raw-http-json | partition-heal | 10 | 1.0000 | 1.0000 | 3.6430 | 1.6430 | 108.02 | 0.9400 | 0.00 |
| 30 | 1.00 | raw-http-json | push-drop-log-repair | 10 | 1.0000 | 1.0000 | 1.6430 | 1.6430 | 48.02 | 0.9733 | 0.00 |
| 30 | 10.00 | raw-http-json | gateway-restart | 10 | 1.0000 | 1.0000 | 1.6997 | 1.6430 | 496.67 | 0.9724 | 0.00 |
| 30 | 10.00 | raw-http-json | log-delay | 10 | 1.0000 | 1.0000 | 1.6430 | 1.6430 | 480.16 | 0.9733 | 0.00 |
| 30 | 10.00 | raw-http-json | partition-heal | 10 | 1.0000 | 1.0000 | 3.6430 | 1.6430 | 1080.16 | 0.9400 | 0.00 |
| 30 | 10.00 | raw-http-json | push-drop-log-repair | 10 | 1.0000 | 1.0000 | 1.6430 | 1.6430 | 480.16 | 0.9733 | 0.00 |

## Interpretation

E-B12 injects concrete failure paths in the local prototype: dropped push delivery, delayed log repair, partition healing, and gateway restart with log recovery. The evidence supports bounded recovery-path behavior for the prototype fault model; it does not claim production-grade chaos testing or large-scale distributed fault tolerance.
