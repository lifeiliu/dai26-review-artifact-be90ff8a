# E-B24 clean reproduction validation

Status: **VERIFIED**.

The reproduction used run ID `eb24-reproduction-v1-20260718`, a newly provisioned 16-host topology across three AWS availability zones, eight physical gateways, the pinned runtime image, and the pre-execution freeze manifest. It executed all 30 blocks once, without continuation, resume, retry, or parameter repair during measurement.

## Categorical result

- 30/30 blocks passed and all 30 clock checks were valid.
- 1,080/1,080 phase assertions passed.
- Normal delivery denied all 6,750 calls and committed no effects.
- Receiver-selective gateway handoff failure allowed and committed 3,360/6,750 calls (112/225 per block, 49.78%). Independent effect oracles observed 1,680 filesystem and 1,680 PostgreSQL commits.
- Recovery denied all 6,750 calls and committed no effects.
- For every treatment block, receiver B returned HTTP 202 and durably persisted the revocation event, but emitted zero gateway enforcement receipts.
- The normal-first and treatment-first orders were balanced 15/15.

These totals exactly match the original E-B24 confirmatory run. The clean reproduction therefore removes the original run's continuation history as a plausible explanation for the categorical finding.

## Frozen configuration

The risk index, target policy, target membership, and mutation labels were unchanged. The target fraction remained 20%, and the pre-existing 30% effect threshold was not retuned.

## Evidence integrity

The final report is stored locally as `confirmatory/run-report.json` and in the versioned evidence bucket. Its local and remote SHA-256 is `39c8c5033c3105d481d5a8e194a44860ab5d8a3041d71e0bab0d52dc807ac192`; the S3 version ID is `y80jJXU_YbTQBRfa.i7EGRntrt1mJchQ`. The run produced 630 raw evidence objects and 31 assembled objects.

## Cleanup audit

The saved destroy plan contained exactly 96 deletes, including 16 EC2 instances, with no create or change actions. It applied successfully. The strict Terraform state, non-terminated experiment instances, ALB, EIP, VPC, 48 temporary SSM parameters, and temporary ACM certificate are absent. The 19-resource bootstrap evidence stack and versioned S3 evidence were retained.

## Claim boundary

This reproduction establishes a deterministic implementation-level boundary for the frozen topology: acknowledgment and durable receiver persistence do not imply downstream enforcement or effect prevention under receiver-selective handoff non-delivery. It does not estimate population incidence, establish production safety, compare mechanism superiority, or rescue E-B20's failed 30% risk gate.
