# E-B5 Protocol: Thin A2A Deployability Experiment

Status: paper-scale run complete on 2026-06-23.

## Research Question

RQ5: Can the protocol be instantiated on A2A to obtain real `delta_prop` and completeness numbers, without turning Paper B into an A2A standardization paper?

## Hypothesis

- H5: A thin A2A implementation reproduces the harness ordering of strategies and yields real `delta_prop` within a small constant factor of harness predictions.

## Scope Lock

In scope:

- One Agent Card extension advertising revocation log URL, root threshold, and root IDs.
- One lifecycle/status binding for revocation-issued events.
- Small local deployment using pinned `a2a-sdk` and a fixed transport.

Out of scope:

- Full Agent Card schema proposal.
- Conformance suite.
- Multi-implementation interoperability matrix.
- Standardization claims.

## Variables

- SDK/spec version: pin before implementation.
- Transport: JSON-RPC, HTTP+JSON/REST, or gRPC, selected once for the first run.
- Number of local agents: 3, 10, 30.
- Strategy: push, log, hybrid.

## Metrics

- Real `delta_prop` p50/p95/p99.
- Completeness.
- Transport overhead.
- Serialization overhead for signed revocation event and STH/proof metadata.
- Failure/flakiness notes.

## Confirmatory Prediction

Hybrid should preserve the same qualitative ordering as the harness: faster than TTL/log-only for most parties and more complete than push-only under selective suppression.

## Paper-Scale Run

- Output directory: `data/run_2026_06_23_e_b5_paper`
- Raw rows: 270
- Aggregate rows: 9
- Runtime: 7.07s
- SDK probe: `a2a-sdk==1.1.0` importable in a temporary Python environment
- Transport mode: local A2A-shaped JSON payload/transport model
- Seeds: 0..29
- Agent counts: 3, 10, 30
- Strategies: push, log, hybrid

## Result Summary

H5 is partially supported:

- Qualitative ordering success rate: 1.0.
- Payload size: 485 bytes.
- Modeled transport delay: 0.001485s.
- n=30 hybrid completeness: 1.0.
- n=30 hybrid p99 `delta_prop`: 0.3574s.
- n=30 push completeness: 0.8.
- n=30 log p99 `delta_prop`: 0.5461s.

This is a deployability-substrate result, not a live SDK-server interoperability result. The paper should state this limitation explicitly.
