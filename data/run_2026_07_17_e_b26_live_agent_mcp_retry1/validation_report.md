# E-B26 Live Multi-Agent MCP Gate

- Verification: PASSED
- Model: `openai/gpt-4.1-mini`
- Agent trace: `4f2c94e31359d4ef440849c8d6d15d603908b4bd44cab017dd13031d233b00df`

| Arm | Allowed | Denied | Real effects | Monitor |
|---|---:|---:|---:|---|
| `active` | 2 | 0 | 2 | `n/a` |
| `normal` | 0 | 2 | 0 | `COMPLETE_FOR_BOUND` |
| `post_persist_fault` | 1 | 1 | 1 | `VIOLATED` |
| `recovery` | 0 | 2 | 0 | `COMPLETE_FOR_BOUND` |

## Assertions

- [x] `three_live_model_calls`
- [x] `two_agent_actions`
- [x] `bit_identical_paired_arguments`
- [x] `active_two_real_effects`
- [x] `normal_reaches_c5`
- [x] `fault_is_post_persistence`
- [x] `fault_missing_only_filesystem_receipt`
- [x] `fault_commits_only_filesystem`
- [x] `fault_monitor_violated_at_c3`
- [x] `recovery_reaches_c5`
- [x] `e_b20_settings_unchanged`

## Claim boundary

This run is a real three-role LLM workflow with two networked MCP tool calls and authoritative Filesystem/Postgres effects. Its prompts and adapter are self-authored, so it is an execution replication rather than an independent workload population.
