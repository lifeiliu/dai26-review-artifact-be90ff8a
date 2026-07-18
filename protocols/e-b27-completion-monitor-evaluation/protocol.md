# E-B27 Completion-Monitor Fault Matrix and Scaling Protocol

## Freeze record

- Protocol version: `e-b27-v1`
- Monitor version: `c0-c5-bounded-v2`
- Frozen: 2026-07-18 UTC, before the confirmatory run
- Evaluation type: deterministic fault classification plus descriptive
  single-host scaling; no production SLO is inferred
- Independence: this protocol does not change the E-B20 risk index, policy,
  workload, or 30% boundary.

## Research questions

RQ1 asks whether the persistent monitor returns the exact conservative verdict
for complete, partial, indeterminate, and violating executions. RQ2 asks
whether evidence and contract state remain immutable and recoverable across
duplicates and process restart. RQ3 measures the local monitor cost as declared
gateway and effect-vector cardinality increase.

## Frozen fault matrix

The confirmatory run uses fresh SQLite databases for every row and must match
all expected outcomes exactly:

1. persisted receiver, no receipts: `PARTIAL_ENFORCEMENT`, C3;
2. one of two receipts: `PARTIAL_ENFORCEMENT`, C3;
3. all receipts, open window: `IN_PROGRESS`, C4;
4. all receipts, closed window, missing effect evidence:
   `INDETERMINATE_MISSING_EFFECT_EVIDENCE`, C4;
5. all receipts, every frozen vector denied without a committed effect, closed
   window: `COMPLETE_FOR_BOUND`, C5;
6. one allowed vector without a committed effect: `VIOLATED`, C4;
7. one denied vector with a committed effect: `VIOLATED`, C4;
8. a violation observed before the final late receipt remains `VIOLATED` after
   that receipt; its highest evidenced stage advances from C3 to C4;
9. byte-equivalent receipt/effect duplicates are idempotent, while conflicting
   duplicates are rejected;
10. reopening both databases reproduces the complete verdict exactly;
11. changes to the registered vector/time contract or receiver target set are
    rejected;
12. closure before the frozen deadline and closure in the future are rejected;
13. out-of-set and out-of-window effect evidence is rejected; and
14. missing C0--C2 evidence identifiers are rejected.

The confirmatory correctness criterion is 14/14 rows passing. A failed row is
reported, not retried. Code/debug failures may be repaired using a separately
labelled smoke run before the single clean confirmatory run.

## Frozen scaling matrix

Each configuration uses a fresh receiver/monitor pair and three measured
trials. Ten warm-up assessments precede 100 timed assessments. Two one-factor
axes avoid a misleading full cross-product:

- gateway axis: 1, 8, 32, 128, 512, and 1,024 gateways with 225 vectors;
- vector axis: 1, 225, 1,000, 5,000, and 10,000 vectors with 8 gateways.

Recorded costs are receiver persistence, contract registration, total and
per-item receipt/effect insertion, window closure, steady-state assessment
p50/p95/p99, first assessment after monitor restart, and durable database
bytes. Aggregation reports the median across the three trials. Scaling is
descriptive: there is no post-hoc latency threshold and no inferential test.

## Evidence and validity boundary

The runner records protocol SHA-256, exact parameters, Python/OS class without
hostname or user identity, per-row assertions, all raw timing rows, and summary
statistics. The validator independently checks matrix coverage, exact verdicts,
trial counts, parameter freeze, and protocol hash, then writes a Material
Passport. The run tests one implementation on one local host; it does not
establish distributed consensus, Byzantine robustness, or a production SLO.
