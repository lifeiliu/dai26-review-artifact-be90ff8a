# E-B24 Operational Amendment: Confirmatory Run v2

## Status and ancestry

- Scientific protocol: `e-b24-prereg-v1` (unchanged)
- Superseded execution identity: `eb24-confirmatory-v1-20260717`
- New execution identity: `eb24-confirmatory-v2-20260717`
- Amendment time: 2026-07-17T22:58:10Z
- Amendment class: pre-outcome repair plus post-interruption non-replay continuation

The v1 execution is permanently retained as `ABORTED` and is not reused or
overwritten. Its assembled report is stored under
`confirmatory/assembled/eb24-confirmatory-v1-20260717/`; its raw transport
diagnostic is stored under
`confirmatory/raw/eb24-confirmatory-v1-20260717/block-01/normal/driver/`.

## Why v1 contains no scientific operation

The first phase container stopped with `PermissionError` while executing
`output_dir.mkdir(...)`. In the frozen driver, that statement precedes opening
any gateway session, Keycloak login, logout/revocation, workload replay, and
Filesystem/PostgreSQL effect request. The phase stdout is empty. Therefore the
aborted attempt supplied no arm outcome and could not be used to tune a
scientific setting or decision rule.

Evidence digests are:

- assembled v1 run report:
  `bd74cc914c14d4c16d4b809e49f7534afca65ae46c1a8c77b1e6f4675cfa57bb`;
- raw v1 phase stderr:
  `daa0a91b96350e3581259279c1c7fe5a2a53f52abe4d40f2f78a6ceeb44d2f14`;
- empty raw v1 phase stdout:
  `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

## Sole operational change

The host phase directory is now run-scoped and created with mode `0777`. The
run scope preserves the v1 directory instead of deleting or reusing it; the
mode permits the pinned runtime's non-root user to create its result
subdirectory in the bind mount. A preflight exercises only this filesystem
write path with the exact pinned runtime and mount type. It performs no
Keycloak, gateway, receiver, or effect-service operation. AWS SSM command
`10048d10-4405-436e-a432-6421f46e8105` passed this preflight.

No other experimental element changes. In particular, the inherited risk
index, target policy, membership, mutation labels, 20% target fraction, 30%
boundary, 225-vector workload, physical vector assignment, receiver split,
fault, 30 paired blocks, counterbalanced arm order, time bound, exact outcome
contracts, or analysis and claim boundary are unchanged. There is no adaptive
stop and no outcome retry. The v2 source hashes are frozen separately in
`freeze-manifest-v2.json` before execution or continuation.

## v2 interruption and non-replay continuation

The initial v2 process completed block 1 `normal` and
`receiver_gateway_fault`, including driver traces, point-in-time receiver
exports, and effect queries. It then stopped while parsing the treatment
effect oracle because AWS SSM appended an output-truncation marker to the
full vector-list JSON. The failure was in evidence transport, after the two
phase operations. The abort handler cleared the receiver-B fault. It did not
execute block 1 `recovery` or any phase in blocks 2--30.

The completed phases are immutable and will not be replayed. Their command
identities are frozen in `RESUME_BLOCK_1` in the continuation runner. A
read-only re-export archived the complete treatment oracle under
`confirmatory/raw/eb24-confirmatory-v2-20260717/oracles/` and returned only a
bounded count/digest summary; its SSM command is
`dda99e25-3a1c-4b91-868b-67025694be2c`. That reconstructed normal and treatment
evidence passed every preregistered categorical assertion. This observation
does not alter the required 30-block sample or any contract.

For subsequent oracle reads, complete vector JSON is uploaded directly to S3,
while SSM returns only counts, digests, and vector counts. The output-only
transport was validated on a nonexistent namespace by command
`5c88d787-e186-480d-8302-e3c47d57daba`. Read-only continuation barrier command
`a24b2ee7-2e95-47e2-9961-5cf8de46e625` confirmed that the two completed phase
directories exist and the recovery directory does not.

Continuation therefore reconstructs the two completed phase records, executes
only the previously unexecuted block 1 recovery, records the post-clock
snapshot, and then executes blocks 2--30 in their original frozen order. The
same run identity is retained because this is completion of an interrupted
run, not a new sample. The assembled record marks block 1 as
`continued_without_phase_replay`.

## block 2 interruption and timestamp reconstruction

The first continuation completed and verified block 1, then executed only the
first arm of block 2 (`receiver_gateway_fault`). Its delegation identifier
began with a hyphen. The subsequent read-only receiver exporter passed it as a
separate argv token, so argparse rejected it before reading receiver state.
The abort handler cleared the fault. Block 2 recovery and normal were not
executed. The driver trace and authoritative effects for the completed
treatment are retained; that phase is not replayed.

The operational correction passes delegation identifiers as
`--delegation-id=<value>` in receiver and recovery commands. Current receiver
records were exported read-only by commands
`48f6c351-66aa-4bdb-b6a8-dfe672166576` and
`2cf0fcdd-adc8-40c4-803d-ec31dcbc53e9`. The preregistered phase-finish cutoff
is taken directly from the immutable driver summary:
`1784330158669945565` ns. State at that cutoff is reconstructed only from
durable timestamps: ingress and receipts are included iff their recorded time
is at or before the cutoff, and `ENFORCED` applies iff `enforced_at_ns` is at
or before the cutoff. Receiver A had four pre-cutoff receipts; receiver B's
four receipts and enforcement timestamp were all after the cutoff, yielding
the frozen treatment state `PERSISTED` with zero receipts and HTTP 202 ingress.

Read-only oracle archive command `02e35ba9-b430-4e43-9001-1b1d98cf71b8`
records the completed block 2 treatment's full vector evidence. All twelve
categorical assertions pass under the timestamp projection. Barrier command
`38fb9b2d-bd8d-440c-b5bc-20f8eb9026e3` confirms that only the treatment phase
directory exists for block 2. The completed, verified block 1 JSON is pinned
by SHA-256
`4bcaca7a346aa65b40f275fd31e7efd3aca4b213cebc13719b85f48b9a2022a5`
and S3 VersionId `hHSC.4nDeAEz.ruAfoJZFG8.y4YjB1jY`.

The next continuation imports that exact block 1 record, reconstructs the
completed block 2 treatment without replay, and executes only block 2 recovery,
block 2 normal, and blocks 3--30. Sample size, order, contracts, thresholds,
and analysis remain unchanged.

## block 27 setup interruption and bounded SSM polling

The second continuation completed and verified blocks 1--26, then completed
block 27 normal. Before block 27 treatment, the independent fault controller
sent nested SSM apply command `f1f4b3d4-14cc-481b-968e-45554caf4ad8` but AWS
had not yet exposed an invocation record. The controller's immediate
`get-command-invocation` therefore returned `InvocationDoesNotExist` and the
outer command failed before the treatment phase was started. The pending
nested command was canceled and is recorded as `Cancelled`; read-only command
`7e24ce66-6203-4a87-ba33-0a2bb4e7ab9f` verified that the fault table was
absent.

The controller now treats only AWS exit 254 carrying
`InvocationDoesNotExist` as visibility lag and polls within the pre-existing
120-second timeout. All other errors still fail closed. Its repaired source
SHA-256 is
`58369dd3961eaec8c8132d4cd79be5daffcb618e2fada3cf8799f5f5b50ff7fd`.
Read-only controller preflight commands
`fe0b40b2-a76f-4319-9fd0-5006f4d67933` and
`1d540e16-9238-4d0d-84e1-845436c802a5` verified the repaired nested polling
path and an absent fault state.

The completed blocks 1--26 report is pinned by SHA-256
`3fb99189eadd305224948fcc0e535e1a7c47dc80e4c2e5603d0a03119e5ba0f9`
and S3 VersionId `CYK1iRHHRKF12QhaFr8NGwqW2oS5rC38`. Block 27 normal's
existing driver, receiver, oracle, and pre-clock command identities are frozen
in `RESUME_BLOCK_27`; its twelve normal assertions pass. Read-only barrier
command `bcd6ee34-6bae-446a-b772-2d99ac61831a` verifies that block 27 normal
exists while treatment, recovery, and all block 28 phases do not.

The next continuation imports the exact blocks 1--26 report, reconstructs
block 27 normal without replay, and executes only block 27 treatment/recovery
and blocks 28--30. No scientific input, ordering rule, sample-size rule,
contract, threshold, or analysis changes.
