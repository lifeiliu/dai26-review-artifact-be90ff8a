# E-B26 Protocol: Frozen Live Multi-Agent MCP Replay

## Material passport

- Version: `e-b26-live-agent-mcp-v1`
- Status: PRE-EXECUTION-FROZEN
- Agent model: `openai/gpt-4.1-mini` through OpenRouter
- Agent roles: one orchestrator and two tool workers
- Tool transport: MCP streamable HTTP using the Python MCP SDK
- Policy engine and fault injector: the pinned OPA/Toxiproxy stack from E-B25
- Effects: one fsync/rename filesystem write and one PostgreSQL transaction

## Objective

Determine whether the E-B25 completion boundary survives when tool arguments
come from a live multi-agent model execution and are then replayed through
networked MCP gateways, rather than from E-B20's argument hashes or E-B24's
effect-carrying identity mapper.

## Trace freeze

Call the model exactly three times at temperature zero: once for the
orchestrator assignment and once for each worker action. The orchestrator must
assign `worker-filesystem` to `g-filesystem` and `worker-postgres` to
`g-postgres`. Workers return one schema-validated MCP tool call each. Persist
the complete safe synthetic arguments and their canonical SHA-256 hashes before
any paired arm begins.

The full MCP tool name and argument object, including the same delegation ID,
must be byte-identical after canonical JSON serialization in `active`,
`normal`, `post_persist_fault`, and `recovery`. Agent inference is not rerun
between arms.

## Arms

1. `active`: both OPA instances start active; both calls must commit.
2. `normal`: receiver persistence precedes successful updates and receipts from
   both OPA gateways; both calls must be denied and the bounded monitor reach
   C5.
3. `post_persist_fault`: receiver persistence precedes Toxiproxy disabling only
   the Filesystem OPA update path. Its direct decision path remains live. The
   Filesystem call must commit, the Postgres call must be denied, and the
   monitor must report `VIOLATED` at C3.
4. `recovery`: re-enable the proxy, use a fresh receiver store but reset both
   OPA instances to active before applying the same event normally; both calls
   must be denied and the monitor reach C5.

No inference or experimental arm is retried. Readiness polling is not a task
retry. A failed run remains evidence of failure.

## Frozen inherited settings

E-B26 does not recalculate or change E-B20's risk index, target policy, 20%
membership, mutation labels, repair policy, or 30% gate. E-B26 is an execution
sanity check with two agent-generated actions and cannot rescue the failed
E-B20 outcome comparison.

## Claim boundary

Passing E-B26 establishes one real LLM-generated, networked MCP, real-effect
replication of the completion boundary. The prompts and gateway adapter are
self-authored; this is not an independent benchmark population, production
incidence estimate, or statistical generalization across agent models.
