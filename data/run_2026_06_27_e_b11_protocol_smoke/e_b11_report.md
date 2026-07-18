# E-B11 Protocol Boundary Path Report

Raw rows: 12
Aggregate rows: 6
Protocol profiles: ['a2a-task-lifecycle', 'mcp-style-jsonrpc', 'raw-http-json']
Fault scenarios: ['none']
Integration success rate: 1.0000
Protocol schema pass rate: 1.0000
Pre-revocation allowed rate: 1.0000
Post-repair reject rate: 1.0000
Mean prevented fraction: 0.9991
Max revoked tool calls allowed: 2.80
Max stale capability window: 0.0584
Max fault recovery latency: 
Transport error count: 0
Loopback service boundary rate: 1.0000
Separate OS process rate: 0.0000

## Run Config

- No run config recorded.

## Integration Aggregates

| n | calls/s/gateway | protocol | fault | runs | success | schema | stale p99 | recovery p99 | allowed calls | prevented | errors |
|---:|---:|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 5 | 1.00 | a2a-task-lifecycle | none | 2 | 1.0000 | 1.0000 | 0.0572 |  | 0.28 | 0.9991 | 0.00 |
| 5 | 1.00 | mcp-style-jsonrpc | none | 2 | 1.0000 | 1.0000 | 0.0572 |  | 0.28 | 0.9991 | 0.00 |
| 5 | 1.00 | raw-http-json | none | 2 | 1.0000 | 1.0000 | 0.0572 |  | 0.28 | 0.9991 | 0.00 |
| 5 | 10.00 | a2a-task-lifecycle | none | 2 | 1.0000 | 1.0000 | 0.0572 |  | 2.76 | 0.9991 | 0.00 |
| 5 | 10.00 | mcp-style-jsonrpc | none | 2 | 1.0000 | 1.0000 | 0.0572 |  | 2.76 | 0.9991 | 0.00 |
| 5 | 10.00 | raw-http-json | none | 2 | 1.0000 | 1.0000 | 0.0572 |  | 2.76 | 0.9991 | 0.00 |

## Interpretation

E-B11 holds the gateway/tool enforcement logic fixed while changing the outer protocol envelope across raw JSON, MCP-style JSON-RPC, and A2A task-lifecycle shaped requests. The measured claim is protocol-envelope binding and schema handling on the local prototype, not third-party protocol interoperability certification.
