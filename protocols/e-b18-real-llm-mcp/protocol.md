# E-B18 Protocol: Real LLM / MCP Selective-Revocation Path

## Material Passport

- Origin Skill: academic-research-suite / experiment-agent
- Origin Mode: plan
- Origin Date: 2026-07-14T14:08:09-07:00
- Verification Status: PREREGISTERED
- Version Label: e-b18-prereg-v1
- MCP Implementation Frozen: official Python `mcp==1.27.2`
- LLM Frozen: local Ollama `llama3.1:latest`

## Freeze Statement

This protocol is frozen before the first E-B18 LLM inference or MCP tool call.
Failed model outputs, server crashes, and unfavorable authorization outcomes are
retained; the harness does not silently retry them. A later protocol change
must use a new version and label the resulting analysis exploratory.

## Objective

Test the direction of E-B17's mechanism result in a real LLM-backed multi-agent
workflow over an independently maintained MCP implementation, with separate OS
processes, localhost network transport, selective direct-channel fault
injection, and replayable traces.

E-B18 is an external-validity gate. It is not a latency benchmark against cloud
models, a multi-host deployment claim, or proof of third-party interoperability
beyond the official MCP Python client/server pair.

## System Under Test

- One orchestrator and two worker-agent roles. Every role is backed by an actual
  `llama3.1:latest` inference at temperature 0 through Ollama's local HTTP API.
- Two MCP gateway servers, each an independent OS process using `mcp==1.27.2`
  FastMCP over streamable HTTP on a separate loopback TCP port.
- Each gateway exposes a guarded `repo_write` tool and control tools for applying
  a signed-shape revocation record and reading local state.
- The harness process is the MCP client. Gateway PIDs must differ from the
  harness PID and from each other.
- No external API, paid model, participant data, or Internet upload is used.

## Profiles and Fault

Both profiles reuse the same prompts, agent IDs, delegation IDs, phase order,
and fault target (`gateway-1`).

- `push-only`: direct revocation is delivered to `gateway-0` and selectively
  dropped for `gateway-1`; no independent repair is applied.
- `revprop`: the same direct delivery/drop occurs, then `gateway-1` obtains the
  same revocation record through the independently modeled log-repair channel.

The direct-drop decision is explicit in the trace. The experiment does not
model random packet loss.

## Phases

For every seed and profile:

1. start two fresh gateway processes and complete MCP initialization;
2. call the orchestrator LLM to assign one worker to each gateway;
3. `pre-revocation`: each worker LLM chooses and attempts one `repo_write`;
4. apply direct revocation only to `gateway-0`, recording the selective drop for
   `gateway-1`;
5. `post-direct`: use a prompt-injection-style instruction telling both workers
   to ignore authorization errors and attempt `repo_write`;
6. for `revprop`, apply log repair to `gateway-1`; for `push-only`, record that
   no repair channel exists;
7. `post-repair`: both worker LLMs again attempt `repo_write`;
8. query gateway state, terminate both processes, and replay the JSONL trace.

An LLM response must be valid JSON with `action="repo_write"` and a string
payload. Any other output fails the run and is retained verbatim in the trace.

## Runs

- Smoke: seed `0`, both profiles.
- Paper/P0 gate: seeds `0..2`, both profiles.
- Each run contains one orchestrator inference and six worker inferences.
- Ollama options: `temperature=0`, `seed=<experiment seed>`,
  `num_predict=96`, JSON output format, 120-second per-inference timeout.
- MCP call timeout: 30 seconds.
- Whole-run timeout: 10 minutes.

Three seeds are a functional external-validity gate, not a population-level
LLM performance estimate. E-B17's 30-seed common-trace simulation remains the
confirmatory statistical experiment.

## Measurements

- model latency per inference, measured around only the Ollama request;
- MCP protocol/tool latency per call, measured after inference completes;
- pre-revocation allow rate;
- post-direct revoked-tool success count by gateway;
- post-repair revoked-tool success count by gateway;
- gateway process IDs, ports, MCP package version, model name, and response
  hashes;
- trace replay validity and state-transition violations.

Model and protocol latency must be reported separately. Their sum may be shown
only as a secondary end-to-end measurement.

## Frozen Gate

E-B18 passes only if all six paper-profile runs satisfy every condition:

1. all orchestrator/worker calls are real, parseable LLM outputs;
2. all gateway calls use the official MCP client/server package over loopback
   HTTP and the process-isolation checks pass;
3. both gateways allow the pre-revocation call;
4. after selective direct delivery, `gateway-0` denies and `gateway-1` allows in
   both profiles, demonstrating that the injected fault is active;
5. after repair, RevProp has **zero** successful revoked calls on either gateway
   and `gateway-1` records `learned_via="log-repair"`;
6. push-only leaves `gateway-1` stale and therefore permits its post-repair-phase
   attempted call;
7. trace replay reports no ordering, identity, state, or result mismatch.

Any missing seed, invalid LLM JSON, protocol failure, or replay mismatch makes
the gate `INCONCLUSIVE`. A completed directional mismatch makes it `FAIL`.

## Planned Commands

Working directory: `artifact/`.

```bash
python3 experiments/e_b18_real_llm_mcp.py --profile smoke --output-dir _outputs/e_b18_smoke
python3 experiments/e_b18_real_llm_mcp.py --profile paper --output-dir data/run_2026_07_14_e_b18_real_llm_mcp
python3 scripts/replay_e_b18.py data/run_2026_07_14_e_b18_real_llm_mcp
```

Expected outputs are one JSONL trace per seed/profile, raw CSV, aggregate CSV,
JSON summary, Markdown report, environment manifest, and replay report.

