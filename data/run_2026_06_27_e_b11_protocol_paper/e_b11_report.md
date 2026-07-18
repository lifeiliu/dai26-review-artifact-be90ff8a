# E-B11 Protocol Boundary Path Report

Raw rows: 60
Aggregate rows: 6
Protocol profiles: ['a2a-task-lifecycle', 'mcp-style-jsonrpc', 'raw-http-json']
Fault scenarios: ['none']
Integration success rate: 1.0000
Protocol schema pass rate: 1.0000
Pre-revocation allowed rate: 1.0000
Post-repair reject rate: 1.0000
Mean prevented fraction: 0.9991
Max revoked tool calls allowed: 16.80
Max stale capability window: 0.0600
Max fault recovery latency: 
Transport error count: 0
Loopback service boundary rate: 1.0000
Separate OS process rate: 0.0000

## Run Config

- `fault_scenarios`: `('none',)`
- `n_parties_values`: `(30,)`
- `protocol_profiles`: `('raw-http-json', 'mcp-style-jsonrpc', 'a2a-task-lifecycle')`
- `seeds`: `(0, 1, 2, 3, 4, 5, 6, 7, 8, 9)`
- `task_duration`: `60.0`
- `tool_call_rates`: `(1.0, 10.0)`
- `tool_name`: `repo-write`
- `ttl`: `60.0`

## Integration Aggregates

| n | calls/s/gateway | protocol | fault | runs | success | schema | stale p99 | recovery p99 | allowed calls | prevented | errors |
|---:|---:|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 30 | 1.00 | a2a-task-lifecycle | none | 10 | 1.0000 | 1.0000 | 0.0594 |  | 1.65 | 0.9991 | 0.00 |
| 30 | 1.00 | mcp-style-jsonrpc | none | 10 | 1.0000 | 1.0000 | 0.0594 |  | 1.65 | 0.9991 | 0.00 |
| 30 | 1.00 | raw-http-json | none | 10 | 1.0000 | 1.0000 | 0.0594 |  | 1.65 | 0.9991 | 0.00 |
| 30 | 10.00 | a2a-task-lifecycle | none | 10 | 1.0000 | 1.0000 | 0.0594 |  | 16.51 | 0.9991 | 0.00 |
| 30 | 10.00 | mcp-style-jsonrpc | none | 10 | 1.0000 | 1.0000 | 0.0594 |  | 16.51 | 0.9991 | 0.00 |
| 30 | 10.00 | raw-http-json | none | 10 | 1.0000 | 1.0000 | 0.0594 |  | 16.51 | 0.9991 | 0.00 |

## Interpretation

E-B11 holds the gateway/tool enforcement logic fixed while changing the outer protocol envelope across raw JSON, MCP-style JSON-RPC, and A2A task-lifecycle shaped requests. The measured claim is protocol-envelope binding and schema handling on the local prototype, not third-party protocol interoperability certification.
