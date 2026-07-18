# E-B25 Independent OPA Stack

- Verification: PASSED
- Generated: 2026-07-18T03:22:50.384135+00:00
- Policy engine: OPA 1.17.0
- Fault injector: Toxiproxy 2.12.0

| Condition | Allowed | Denied | Effects | Monitor |
|---|---:|---:|---:|---|
| `normal` | 0 | 225 | 0 | `COMPLETE_FOR_BOUND` |
| `post_persist_fault` | 112 | 113 | 112 | `VIOLATED` |
| `recovery` | 0 | 225 | 0 | `COMPLETE_FOR_BOUND` |

## Assertions

- [x] `frozen_225_vectors`
- [x] `frozen_configuration_unchanged`
- [x] `active_allows_and_commits_all`
- [x] `normal_has_two_receipts`
- [x] `normal_c5_zero_effects`
- [x] `fault_occurs_after_persistence`
- [x] `fault_missing_only_filesystem_receipt`
- [x] `fault_stale_opa_commits_112`
- [x] `fault_monitor_reports_violation`
- [x] `late_receipt_does_not_erase_violation`
- [x] `recovery_c5_zero_effects`

## Claim boundary

This one-host result independently replicates the persisted-but-not-enforced boundary in OPA under an externally injected control-path fault. It does not measure production incidence or establish multi-host independence.
