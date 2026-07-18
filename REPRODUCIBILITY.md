# Reproducibility Guide

## Environment

The recorded paper runs used Python 3.11. The direct dependencies are pinned in
`requirements.txt`; package metadata remains in `pyproject.toml`.

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 -m pip install -e .
make verify
```

## Saved evidence

`data/` contains the raw CSV rows, aggregate CSVs, summary JSON, Markdown
reports, and persistent JSONL evidence used by the manuscript. E-B1--E-B12 and
E-B14--E-B18 are self-contained. E-B13 is a bridge over separately generated
Paper A E16--E19 outputs; its saved sanitized result is included, while reruns
require `--paper-a-experiments-dir`.

## Smoke profile

The smoke profile exercises E-B1--E-B12 without external data:

```bash
python3 experiments/e_b_research_suite.py \
  --experiment all \
  --profile smoke \
  --output-dir _outputs/all_smoke
```

## Paper-scale examples

```bash
# Main propagation and mechanism-family baselines
python3 experiments/e_b_research_suite.py \
  --experiment e-b2 --profile paper \
  --output-dir _outputs/e_b2_paper

# Watcher-coverage sensitivity
python3 experiments/e_b_research_suite.py \
  --experiment e-b4 --profile paper \
  --output-dir _outputs/e_b4_paper

# Loopback gateway, protocol envelope, and fault paths
for exp in e-b10 e-b11 e-b12; do
  python3 experiments/e_b_research_suite.py \
    --experiment "$exp" --profile paper \
    --output-dir "_outputs/${exp}_paper"
done

# Multi-process, MCP/LangGraph, and status-outage paths
for exp in e-b14 e-b15 e-b16; do
  python3 experiments/e_b_research_suite.py \
    --experiment "$exp" --profile paper \
    --output-dir "_outputs/${exp}_paper"
done

# Preregistered strongest-mechanism comparison and deterministic validation
python3 experiments/e_b_research_suite.py \
  --experiment e-b17 --profile paper \
  --output-dir _outputs/e_b17_paper
python3 scripts/validate_e_b17.py \
  data/run_2026_07_14_e_b17_p0_matched
```

E-B18 additionally requires a local Ollama service with
`llama3.1:latest`. It uses no paid or remote model API:

```bash
python3 experiments/e_b18_real_llm_mcp.py \
  --profile paper --output-dir _outputs/e_b18_paper
python3 scripts/replay_e_b18.py \
  data/run_2026_07_14_e_b18_real_llm_mcp
```

The saved E-B18 traces can be replayed without Ollama or live MCP servers. To
recompute the frozen overall decision from saved evidence:

```bash
python3 scripts/decide_p0.py \
  --e-b17-dir data/run_2026_07_14_e_b17_p0_matched \
  --e-b18-dir data/run_2026_07_14_e_b18_real_llm_mcp \
  --output-dir _outputs/p0_verdict
```

## Completion-boundary studies

E-B24's portable release contains its frozen protocol, strict-topology
Terraform/source scripts under `infra/e_b24/`, original and clean-reproduction
reports, and validation summaries. Cloud state, plans, private SQLite stores,
and credentials are deliberately absent. Reprovisioning therefore requires a
separate AWS account/profile and new reviewer-owned resource names; the saved
reports are the submission evidence.

E-B25 requires Docker plus the pinned OPA, Toxiproxy, and PostgreSQL images. A
version-2 rerun waits for each registered observation deadline before closing:

```bash
python3 experiments/e_b25_opa_independent_stack/run_gate.py \
  --output-dir _outputs/e_b25_v2
```

E-B26 additionally requires an independently supplied `OPENROUTER_API_KEY`.
No API key is present in the artifact. It generates one live three-role trace,
freezes two actions, and replays active/normal/fault/recovery arms:

```bash
OPENROUTER_API_KEY=... \
python3 experiments/e_b26_live_multi_agent_mcp/run_gate.py \
  --output-dir _outputs/e_b26_v2
```

E-B27 has no network or cloud dependency. The saved clean run can be validated
directly, or a new confirmatory run can be created in a new directory:

```bash
python3 experiments/e_b27_completion_monitor/validate_run.py \
  data/run_2026_07_18_e_b27_completion_monitor_confirmatory

python3 experiments/e_b27_completion_monitor/run_evaluation.py \
  --mode confirmatory --output _outputs/e_b27_confirmatory
python3 experiments/e_b27_completion_monitor/validate_run.py \
  _outputs/e_b27_confirmatory
```

The confirmatory matrix is fixed at 14 fault rows, 11 scaling configurations,
three fresh databases per configuration, and 100 measured assessments after 10
warm-ups. Performance has no pass threshold.

E-B28 requires Docker, the clean external MCPMark checkout at commit
`cd45b7f57923b9b3985467f5139927575f83141c`, its local `.venv`, the frozen
MCPMark PostgreSQL fixture container, and an independently supplied
`OPENROUTER_API_KEY`. Keycloak and its database are started from the digest-
pinned images recorded in the pre-execution manifest. The 6-run readiness
smoke is separate from the frozen 60-run formal schedule and two recovery
qualifications:

```bash
OPENROUTER_API_KEY=... \
python3 experiments/e_b28_live_closed_loop/run_gate.py \
  --mode smoke \
  --output-dir _outputs/e_b28_smoke \
  --mcpmark-root ../external/MCPMark

OPENROUTER_API_KEY=... \
python3 experiments/e_b28_live_closed_loop/run_gate.py \
  --mode formal \
  --output-dir _outputs/e_b28_confirmatory \
  --mcpmark-root ../external/MCPMark
```

Formal rows are never retried or replaced. The saved post-execution audit is
`data/run_2026_07_18_e_b28_live_closed_loop_confirmatory/analysis/e_b28_validation.json`.
E-B28 freezes E-B20's ten target identities but does not change its risk index,
policies, or failed 30% threshold.

The full E-B1 adversarial sweep is the longest run; the recorded run took about
71 minutes on a local ARM64 workstation. Other run times depend on host load and
the selected matrix. Use saved results for manuscript verification and smoke
runs for artifact sanity checks.

## Claim boundaries

The artifact spans simulation, loopback/multi-process execution, two 16-host
cloud lifecycles, independently maintained OPA/Toxiproxy components, a live
remote-model/MCP workflow, and local monitor scaling. It does not establish
production incidence, mechanism superiority, multi-vendor MCP/A2A
interoperability, population-level LLM behavior, a distributed/Byzantine
monitor, or a production SLO. E-B17's 50% message-budget cell and E-B20's 30%
external-workload gates remain failures. E-B25/E-B26 stored C5 labels use
monitor v1 and are retained as legacy evidence; E-B27 validates v2. E-B28 uses
v2 retrospectively over each actual adaptive post-barrier call population, so
its monitor labels are execution checks rather than a pre-known call-set claim.
