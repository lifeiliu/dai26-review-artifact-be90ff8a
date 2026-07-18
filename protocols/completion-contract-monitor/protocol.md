# C0--C5 Executable Completion Contract

## Status and scope

- Version: `c0-c5-bounded-v2`
- Status: implementation contract; v2 was frozen before E-B27 after a
  pre-evaluation audit found two fail-open evidence mutations in v1
- Scope: one declared revocation event, its immutable physical-gateway target
  set, and a finite predeclared effect-observation window

## Contract

For an event `e`, the stages are C0 issuer commit, C1 transmitter durable
queueing, C2 transport acknowledgement, C3 receiver persistence, C4 a bound
enforcement receipt from every declared physical gateway, and C5 no allowed or
committed effect for every expected call in the closed observation window.

The executable monitor returns `COMPLETE_FOR_BOUND` only at C5. Missing gateway
receipts yield `PARTIAL_ENFORCEMENT`; a closed window with missing effect
observations yields `INDETERMINATE_MISSING_EFFECT_EVIDENCE`; an allowed or
committed effect yields `VIOLATED`. The target set, vector set, and time bound
are immutable after registration. A persisted gateway receipt and an effect
observation are idempotent only when their complete evidence records match;
conflicting duplicates are rejected. A window cannot close before its frozen
deadline or at a future timestamp.

Version v1, used to label the stored E-B25 and E-B26 runs, allowed a gateway
receipt to be overwritten and allowed explicit closure before the registered
deadline. The underlying receipts, decisions, and effect-oracle records remain
available, but those legacy C5 labels are not treated as v2 monitor-validation
evidence. E-B27 evaluates v2 directly.

## Lower-bound statement

Let a completion detector receive observations no later than C3. There exist
two executions with the same C0--C3 observation prefix: in one, every target
enforces and all bounded calls are denied; in the other, one target never
enforces and a bounded call commits. Because the detector's inputs are equal,
its verdict is equal on both executions. A positive verdict is therefore
unsound for the second execution, while a negative verdict cannot certify the
first. Consequently, C0--C3 evidence alone cannot soundly decide end-to-end
revocation completion under this outcome contract.

`lower_bound_indistinguishability_witness()` constructs these executions, and
the unit test asserts prefix equality and outcome inequality.

## Claim boundary

C5 is an empirical, bounded safety result. It does not establish that no
future call, undiscovered gateway, or out-of-model side channel can produce an
effect. Any paper claim must name the target set and observation window.
