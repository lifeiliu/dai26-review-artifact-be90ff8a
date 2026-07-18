# E-B14 Multi-Process Deployment Report

Raw rows: 20
Aggregate rows: 4
Protocol profiles: ['raw-http-json']
Fault scenarios: ['none', 'push-drop-log-repair']
Integration success rate: 1.0000
Protocol schema pass rate: 1.0000
Pre-revocation allowed rate: 1.0000
Post-repair reject rate: 1.0000
Mean prevented fraction: 0.9945
Max revoked tool calls allowed: 49.12
Max stale capability window: 0.6462
Max fault recovery latency: 0.6448
Transport error count: 0
Loopback service boundary rate: 1.0000
Separate OS process rate: 1.0000

## Run Config

- `fault_scenarios`: `('none', 'push-drop-log-repair')`
- `n_parties_values`: `(8,)`
- `output_dir`: `data/run_2026_06_27_e_b14_multiprocess_paper`
- `protocol_profiles`: `('raw-http-json',)`
- `seeds`: `(0, 1, 2, 3, 4)`
- `task_duration`: `60.0`
- `tool_call_rates`: `(1.0, 10.0)`
- `tool_name`: `repo-write`
- `ttl`: `60.0`

## Integration Aggregates

| n | calls/s/gateway | protocol | fault | runs | success | schema | stale p99 | recovery p99 | allowed calls | prevented | errors |
|---:|---:|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 8 | 1.00 | raw-http-json | none | 5 | 1.0000 | 1.0000 | 0.0574 |  | 0.44 | 0.9991 | 0.00 |
| 8 | 1.00 | raw-http-json | push-drop-log-repair | 5 | 1.0000 | 1.0000 | 0.6377 | 0.6377 | 4.86 | 0.9899 | 0.00 |
| 8 | 10.00 | raw-http-json | none | 5 | 1.0000 | 1.0000 | 0.0574 |  | 4.37 | 0.9991 | 0.00 |
| 8 | 10.00 | raw-http-json | push-drop-log-repair | 5 | 1.0000 | 1.0000 | 0.6377 | 0.6377 | 48.59 | 0.9899 | 0.00 |

## Interpretation

E-B14 runs gateway, tool, and log roles in separate OS processes with a persisted log file. The deployment upgrades E-B10--E-B12 from single-process loopback to multi-process service isolation, but it remains a local artifact deployment, not a production multi-host cluster.
