# E-B20 Protocol: MCPMark Frozen External-Trace Replay

## Material Passport

- Origin Skill: academic-research-suite / experiment-agent
- Origin Mode: plan
- Origin Date: 2026-07-14
- Verification Status: PRE-EXECUTION-FROZEN
- Version Label: e-b20-prereg-v1
- External Benchmark: MCPMark Verified
- External Commit: `cd45b7f57923b9b3985467f5139927575f83141c`
- External Repository: `https://github.com/eval-sys/mcpmark`
- External Agent: unmodified MCPMarkAgent decision loop
- Frozen Model Route: `openai/gpt-4.1-mini` through
  `https://openrouter.ai/api/v1`

## Freeze Statement

This protocol is frozen before the first E-B20 model inference or MCP tool
call. The benchmark commit, task population, risk index, target set, repair
policies, delays, 30% effect threshold, and analysis rules may not be changed
after trace collection begins. Infrastructure-only smoke runs are labeled and
excluded from every calibration and held-out calculation.

The protocol operationalizes the design agreed after E-B19. It does not refit
the E-B19 risk distribution, change the 20% targeted set, tune the square-root
allocation, or weaken the 30% gate.

## Objective

Test whether E-B19's equal-budget risk-aware repair result survives on tool
traces produced by an independently maintained agent benchmark in real MCP
environments. E-B20 is an external-validity gate for the proposed paper pivot,
not a benchmark of language-model quality.

## External Workload and Population

- Use the standard MCPMark Verified suites for `filesystem` and `postgres` at
  the frozen commit.
- Include all 30 Filesystem tasks and all 21 Postgres tasks: 51 logical
  gateways in total.
- A logical gateway is one service-qualified task ID,
  `<service>/<category>/<task>`.
- Use MCPMarkAgent, not a locally authored task-solving loop.
- Use reasoning effort `default`, a 3,600-second per-task timeout, and disable
  context compaction with threshold `999999999`.
- Run Postgres against the frozen MCPMark deployment documented at the pinned
  commit: `pgvector/pgvector:0.8.0-pg17-bookworm` on `127.0.0.1:5432`, with
  the experiment-only `postgres` role and the five official template backups
  (`employees`, `chinook`, `dvdrental`, `sports`, and `lego`).
- Because frozen `postgres-mcp==0.3.0` requires Python 3.12 while MCPMark's main
  environment supports Python 3.11, run only the Postgres MCP server's pipx
  environment with system Python 3.12.4. Keep pipx home, cache, binaries, and
  logs under the frozen checkout's `.e_b20_pipx/` directory. This compatibility
  environment does not alter the MCPMarkAgent or Postgres MCP package.
- Before service launch, remove non-directory entries from the inherited
  executable search path and prepend the frozen checkout's virtual-environment
  `bin` directory. This environment repair does not alter MCPMark source.
- Use four independent MCPMark runs. Runs 1--2 are calibration only; runs 3--4
  are held out for outcome replay.
- Retain benchmark task failures and zero-call or zero-mutation tasks. Exclude
  only a predeclared infrastructure failure that prevents any agent execution
  (for example, missing server executable, database unavailable, or provider
  authentication failure). Every exclusion is listed and makes the paper gate
  `INCONCLUSIVE` until the missing task is rerun under the same protocol.
- The E-B20 wrapper performs no task-level retry. A failed task is recorded once
  rather than silently replaced. MCPMarkAgent's frozen internal handling of a
  transient provider-call failure remains part of the independently implemented
  agent and is not modified.

## Trace Instrumentation

For every actual MCP tool call the E-B20 wrapper records:

- benchmark commit, service, task ID, MCPMark run number, and model response
  model ID;
- call sequence, tool name, arguments hash, monotonic start/end timestamps,
  success/error status, and result hash;
- a frozen binary `mutating` label.

Filesystem mutation is observed by comparing a normalized Merkle digest before
and after the call. The digest includes relative path, entry type, permission
bits, symlink target, and regular-file bytes; it excludes access, modification,
and creation timestamps.

Postgres mutation is labeled when a successfully returned tool call contains a
state-changing SQL statement. The frozen statement classes are `INSERT`,
`UPDATE`, `DELETE`, `MERGE`, `CREATE`, `ALTER`, `DROP`, `TRUNCATE`, `GRANT`,
`REVOKE`, `COMMENT`, `SECURITY LABEL`, `COPY ... FROM`, `CALL`, `DO`,
`REFRESH`, `REINDEX`, `CLUSTER`, `VACUUM`, `ANALYZE`, and `SELECT ... INTO`,
including data-changing statements inside a `WITH` query. Comments and string
literals are removed before classification. Read-only `SELECT`, `SHOW`,
`EXPLAIN`, and catalog inspection are non-mutating. A successful
mutation-class statement is an accepted mutating call even if it happens to
affect zero rows.

This Postgres label measures accepted mutation-capable SQL, not a complete
logical database diff. Stored procedures with hidden side effects can therefore
be false negatives; this limitation is reported and cannot be repaired by
post-hoc relabeling.

## Frozen Risk Index

For task/gateway `g`, let `C_g1` and `C_g2` be total actual MCP tool calls in
calibration runs 1 and 2, and `M_g1` and `M_g2` the corresponding mutating
calls. Define

`lambda_g = (C_g1 + C_g2) / 2`,

`w_g = (M_g1 + M_g2) / (C_g1 + C_g2)` when the denominator is positive and
zero otherwise, and

`r_g = lambda_g * w_g = (M_g1 + M_g2) / 2`.

There is no fitted exponent, severity survey, task-success weighting, service
coefficient, or held-out update. If every `r_g` is zero, E-B20 is
`INCONCLUSIVE` and does not support the pivot.

## Frozen Selective-Omission Set

- Suppress exactly `round(0.20 * 51) = 10` task/gateways.
- Select the ten largest calibration risks `r_g`.
- Break equal-risk ties by the full service-qualified task ID in lexical order.
- Runs 3--4 may not change membership or ranking.

The 20% set is the sole confirmatory omission set. Service-specific and random
target sets are diagnostics only if computed from the same frozen traces and
are not substitutes for a failed primary result.

## Frozen Equal-Budget Policies

Both policies receive exactly five fast-repair attempts per targeted gateway in
aggregate, or 50 attempts total.

- `uniform`: five attempts for each of the ten targets.
- `risk-aware`: one attempt for each target, then allocate the remaining 40 by
  largest remainder in proportion to `sqrt(r_g)`. Ties use the full task ID in
  lexical order.

If all targeted risks are zero, the experiment is `INCONCLUSIVE`. The wrapper
must assert identical total attempts, control-message accounting, byte
accounting, explicit convergence, audit evidence, and benign availability for
the two policies.

## Frozen Propagation Model

Reuse E-B19 without re-estimation:

- direct delay: `0.02 + 0.03 * U(0,1)` seconds;
- independent log delay: `0.05 + 10 * U(0,1)` seconds;
- repair attempt `j`: `0.10 + 0.40 * U_j(0,1)` seconds;
- enforcement for a targeted gateway is the minimum of its log delay and all
  allocated repair attempts;
- enforcement for a non-target is its direct delay;
- 30 deterministic paired propagation seeds, 0--29.

All variates are stable hashes of protocol version, propagation seed, task ID,
and attempt index and are identical across policies where pairing requires it.

## Held-Out Replay and Outcomes

Runs 3--4 retain their actual monotonic tool-call ordering and inter-call time.
For each held-out task trace and propagation seed, draw one revocation time
uniformly from the closed interval between that trace's first and last actual
MCP call. A trace with fewer than two calls contributes zero accepted
post-revocation calls but remains in the population. The same revocation time
is used for both policies.

Primary model outcome:

`H = sum_g r_g * Delta_g`,

where `Delta_g` is the policy's enforcement delay for task/gateway `g`.

External trace outcome:

`U = number of held-out mutating calls whose actual call-start time is after
revocation and before enforcement`.

Calls at exactly the enforcement timestamp are denied. `U` is summed over both
held-out runs. Non-mutating calls are retained in the trace but never counted
in `U`.

## Confirmatory Gates

E-B20 supports the paper pivot only when both comparisons pass:

1. risk-aware reduces the ratio of mean `H` by at least 30% relative to
   uniform, and the paired task-cluster bootstrap interval for the difference
   is entirely below zero;
2. risk-aware reduces the ratio of mean `U` by at least 30% relative to
   uniform, and the paired task-cluster bootstrap interval for the difference
   is entirely below zero;
3. all 51 tasks have two valid calibration records and two valid held-out
   records, or any absent task has been rerun under the frozen protocol;
4. message and byte counts match exactly and both policies retain 1.0 explicit
   event completeness, 1.0 audit-evidence rate, and 0 benign availability
   loss.

Use 10,000 paired bootstrap resamples. The resampling unit is the full
service-qualified task ID, carrying both held-out runs and all 30 propagation
seeds as one cluster. Report the ratio of means, mean paired difference, 95%
percentile interval, exact sign test, paired standardized effect, zero-outcome
rate, and per-seed reduction distribution. The 30% decision uses the ratio of
means, not the mean of per-seed ratios.

## Decision Rule

- `H` and `U` pass: external workload supports the pivot candidate.
- `H` passes but `U` fails: the gain remains a scheduling-model result; do not
  pivot the paper around real workload harm reduction.
- `H` fails: E-B19 does not reproduce on the independently sourced risk
  distribution.
- Missing infrastructure, missing tasks, no risk, or no defined baseline
  outcome: `INCONCLUSIVE`.

No outcome permits changing the risk index, mutation definition, task set,
target fraction, target membership, square-root policy, delay distributions,
or 30% threshold.

## Planned Execution

The wrapper and analyzer live in the Paper B artifact; MCPMark remains pinned
as an external checkout. The first real call is the Filesystem
`file_property/size_classification` infrastructure smoke at `k=1`; it validates
trace completeness and is discarded. The confirmatory workload
then uses separate commands for Filesystem and Postgres so an infrastructure
failure in one service cannot erase the other service's trace.

Expected outputs are a benchmark manifest, one immutable JSONL call trace per
service/run, calibration-risk CSV, frozen-target JSON, allocation CSV,
held-out replay CSV, summary JSON, Markdown validation report, and a
reproducibility manifest with hashes.
