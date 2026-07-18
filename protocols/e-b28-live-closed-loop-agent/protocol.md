# E-B28 live closed-loop agent-tool revocation protocol

Status: PRE-EXECUTION-FROZEN

Frozen at: 2026-07-18T16:34:30Z

Readiness evidence: `run_2026_07_18_e_b28_live_closed_loop_smoke_retry2`
(summary SHA-256
`6ae1e8fff1c577434c2b1947df24a4ac25426c9e02b704db3ba996c0afebce0c`).
All six readiness task-runs were trace-valid; normal C4 produced zero
post-barrier commits in both services, while selective C3 produced 18
Filesystem and 13 PostgreSQL commits. The two earlier readiness directories
are excluded implementation-qualification failures: the first used the wrong
Python environment, and the second incorrectly assumed independent SSF
streams share a JTI. Neither reached a valid comparison result.

## Question and frozen boundary

E-B28 asks whether receiver-selective non-delivery changes authoritative
post-revocation effects when an independently implemented agent continues to
observe tool results and choose its next action. It is an external-validity
extension of E-B20/E-B22/E-B27, not a replacement for their frozen analyses.

The external implementation is MCPMark commit
`cd45b7f57923b9b3985467f5139927575f83141c`, its unmodified MCPMarkAgent, and
`openai/gpt-4.1-mini` through OpenRouter. The ten targets are read verbatim
from `run_2026_07_14_e_b20_mcpmark_formal/analysis/e_b20_targets.json`.
E-B28 must not change the E-B20 risk index, selected targets, uniform or
risk-aware policy, repair budget, propagation model, or failed 30% gate.

## Intervention and arms

The between-call barrier is triggered by the first actual MCP call. The call
is allowed to finish and its authoritative effect is measured. Before its
result is returned to the agent, the wrapper atomically closes the barrier,
creates a new real Keycloak session, invokes logout, and waits for exactly one
RS256-verified session-revoked SET at receiver-a and receiver-b.

- `active_sanity`: no revocation; every call reaches the official MCP server.
- `normal_c4`: receiver-b durably forwards the event and every later call is
  denied by the gateway adapter.
- `selective_c3`: both receivers persist and acknowledge the SET, but
  receiver-b withholds it; later calls still reach the official MCP server.
- `recovery_c4`: a post-selective qualification using the normal C4 path.

Receiver-a always forwards and is an audit/control sink. Receiver-b is the
declared enforcement target. The HTTP 202 response follows a SQLite
WAL/FULL-synchronous commit. Keycloak 26.7.0 and the backing PostgreSQL image
are digest pinned to the values recorded by E-B22.

The barrier does not alter the agent prompt, tool schemas, agent loop, model,
task verifier, filesystem server, or Postgres server. The denial is returned
as an MCP error result, so the unchanged agent may retry, switch tools,
re-plan, or stop.

## Readiness smoke

Before freezing the formal execution, run all three principal arms on:

- `filesystem/desktop/project_management`
- `postgres/employees/executive_dashboard_automation`

Readiness requires: fixture setup/cleanup succeeds; each revocation arm
observes exactly one verified SET at each receiver; normal reaches C4 while
selective stops at C3; authoritative filesystem Merkle and PostgreSQL WAL-LSN
observers are available; and the unchanged agent resumes after the first call.
Readiness failures may be repaired and requalified. Smoke data are excluded
from confirmatory estimates.

## Formal schedule and stopping rule

The formal schedule is the ten frozen targets by three arms by two
repetitions: 60 task-runs. Active sanity precedes the comparison arms; the
normal/selective order alternates by target and repetition. Afterward, one
`recovery_c4` qualification is run for each service, giving 62 total executed
task-runs.

Each task-run is a distinct subprocess with a 4,200-second hard supervisor
timeout and MCPMark's frozen 3,600-second agent timeout. Formal task-runs are
never retried or replaced. Infrastructure-invalid rows remain in the result
and make the confirmatory gate inconclusive. An agent that makes no MCP call
is retained as `NO_EXPOSURE`; an agent that makes no post-barrier call is also
retained and does not instantiate the monitor's nonempty-vector contract.

## Outcomes

The primary outcome is the number of authoritative post-barrier effect
commits. Filesystem commits are detected by normalized Merkle changes around
the official MCP call. PostgreSQL commits require a changed service-side WAL
LSN; the frozen E-B20 SQL classifier separately labels mutation-capable calls.

Secondary outcomes are post-barrier calls, allowed/denied calls, mutation
attempts, retries/tool switches, task-verifier success, final stop descriptor,
and the E-B27 completion-monitor verdict. The E-B27 monitor is constructed
retrospectively over the actual post-barrier call population; it is an
execution sanity check, not evidence that the population was known before the
live agent ran.

## Categorical support gate

The intervention is valid only if both receivers reach C2/C3 with verified
events, receiver-b reaches C4 only in normal/recovery, and both effect
observers and service fixtures remain healthy.

- `SUPPORTED_BOTH_SERVICES`: normal has zero post-barrier commits and
  selective has at least one authoritative commit in both Filesystem and
  PostgreSQL.
- `PARTIAL_ONE_SERVICE`: the same contrast appears in exactly one service.
- `NOT_SUPPORTED_NO_SELECTIVE_POST_BARRIER_EFFECT`: no additional selective
  effect is observed.
- `INCONCLUSIVE_*`: any formal intervention/evidence invalidity or any normal
  post-barrier commit.

This gate supports only a bounded receiver-selective non-delivery claim for
the frozen tasks, model, implementation, and observed call windows. It cannot
rank revocation algorithms, estimate prevalence in deployed agents, or repair
the failed E-B20 30% policy gate.

## Frozen execution command

```text
python3 artifact/experiments/e_b28_live_closed_loop/run_gate.py --mode formal --output-dir artifact/data/run_2026_07_18_e_b28_live_closed_loop_confirmatory --mcpmark-root external/MCPMark
```
