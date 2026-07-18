# E-B6 Protocol: Local End-to-End Transport Experiment

Status: paper-scale run complete on 2026-06-24.

## Research Question

RQ6: Does the propagation protocol still work when propagation crosses a real
local TCP and JSON serialization boundary instead of using only the in-process
simulator?

## Hypothesis

- H6: The loopback JSONL/TCP prototype preserves the core qualitative result:
  hybrid reaches full completeness under moderate push suppression, verifies
  signatures and root certificates at receivers, and completes without transport
  errors.

## Scope Lock

In scope:

- Local asyncio TCP services for relying parties and log.
- JSON-lines request/response transport.
- Receiver-side signed-event and root-certificate verification.
- Push, log, push-gossip, and hybrid strategy comparison.

Out of scope:

- Multi-process deployment.
- WAN or container network measurements.
- Production signature-aggregation and storage implementation.
- Multi-vendor A2A interoperability.

## Variables

- Number of relying parties: 10, 30, 100.
- Seeds: 0..9.
- Strategy: push, log, push-gossip, hybrid.
- Push suppression: 0.2.
- Gossip/log suppression: 0.0.
- Trial duration: 1.5s.
- Gossip fanout: 4.

## Metrics

- Completeness.
- p50/p95/p99/max `delta_prop`.
- Loopback request count and transport error count.
- Bytes sent/received.
- Receiver-side signature verification rate.
- Receiver-side root-certificate verification rate.

## Paper-Scale Run

- Output directory: `data/run_2026_06_24_e_b6_paper`
- Raw rows: 120
- Aggregate rows: 12
- Runtime: 191.47s
- Service model: `asyncio-tcp-jsonl`
- Command:

```bash
python3 experiments/e_b_research_suite.py \
  --experiment e-b6 \
  --profile paper \
  --seeds 0:10 \
  --n-parties 10,30,100 \
  --strategies push,log,push-gossip,hybrid \
  --duration 1.5 \
  --gossip-fanout 4 \
  --output-dir data/run_2026_06_24_e_b6_paper
```

## Result Summary

H6 is partially supported:

- Mean transport errors: 0.0.
- Mean signature verification rate: 1.0.
- Mean root-certificate verification rate: 1.0.
- Minimum completeness across all strategies: 0.8, caused by push-only under
  20 percent push suppression.
- n=100 hybrid completeness: 1.0.
- n=100 hybrid p99 `delta_prop`: 0.5778s.
- n=100 push-only completeness: 0.8.

This is local end-to-end evidence, not production deployment evidence. The paper
should describe it as a loopback prototype that exercises sockets,
serialization, and receiver-side verification in one asyncio process.
