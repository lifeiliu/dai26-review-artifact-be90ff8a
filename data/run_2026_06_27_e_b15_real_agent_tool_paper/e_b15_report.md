# E-B15 Real Agent Tool Path Report

Raw rows: 80
Aggregate rows: 8
Path profiles: ['langgraph-stategraph-tool-call', 'mcp-python-tools-call']
Fault scenarios: ['none', 'push-drop-log-repair']
Integration success rate: 1.0000
MCP tools/call validation rate: 1.0000
LangGraph completion rate: 1.0000
Mean prevented fraction: 0.9948
Max stale capability window: 0.6499
Transport error count: 0

## Path Aggregates

| path | fault | n | rate | runs | success | stale p99 | prevented | errors |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| langgraph-stategraph-tool-call | none | 30 | 1.00 | 10 | 1.0000 | 0.0500 | 0.9992 | 0.00 |
| langgraph-stategraph-tool-call | none | 30 | 10.00 | 10 | 1.0000 | 0.0500 | 0.9992 | 0.00 |
| langgraph-stategraph-tool-call | push-drop-log-repair | 30 | 1.00 | 10 | 1.0000 | 0.5500 | 0.9908 | 0.00 |
| langgraph-stategraph-tool-call | push-drop-log-repair | 30 | 10.00 | 10 | 1.0000 | 0.5500 | 0.9908 | 0.00 |
| mcp-python-tools-call | none | 30 | 1.00 | 10 | 1.0000 | 0.0594 | 0.9991 | 0.00 |
| mcp-python-tools-call | none | 30 | 10.00 | 10 | 1.0000 | 0.0594 | 0.9991 | 0.00 |
| mcp-python-tools-call | push-drop-log-repair | 30 | 1.00 | 10 | 1.0000 | 0.6430 | 0.9900 | 0.00 |
| mcp-python-tools-call | push-drop-log-repair | 30 | 10.00 | 10 | 1.0000 | 0.6430 | 0.9900 | 0.00 |

## Interpretation

E-B15 exercises real agent-facing package/runtime surfaces: the MCP Python CallToolRequest type for tools/call and a compiled LangGraph StateGraph tool workflow. It strengthens the agent-system path evidence, while remaining a local artifact path rather than third-party MCP interoperability or a live LLM planner benchmark.
