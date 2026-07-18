# E-B4 Protocol: M-of-N Equivocation Resistance

Status: paper-scale run complete on 2026-06-23.

## Research Question

RQ1/RQ3: Does M-of-N root federation plus STH anchoring detect equivocation that a weaker baseline misses?

## Hypothesis

- H3: M-of-N root approval plus STH cross-observation detects equivocation that a single-root or non-anchored log baseline can hide.

## Adversary Scenarios

- Single malicious root signs a conflicting event.
- Malicious minority of roots signs a conflicting event below threshold.
- Malicious threshold signs a conflicting event.
- Log presents split views with same size and different root hash.
- Log replays old STH to a subset of relying parties.
- Partition prevents cross-observation temporarily, then heals.

## Baselines

- Single root, no threshold.
- M-of-N without STH cross-observation.
- STH cross-observation without root threshold.
- Full design.

## Metrics

- Detection probability.
- Equivocation detection latency.
- False positive rate under benign reordering.
- Required number of honest cross-observers.
- Evidence size: approvals, STHs, inclusion proofs, consistency proofs.

## Confirmatory Prediction

Below-threshold root corruption should not produce an accepted revocation certificate. Split-view logs should be detected after honest parties exchange STHs, bounded by gossip/log observation assumptions.

## Paper-Scale Run

- Output directory: `data/run_2026_06_23_e_b4_paper`
- Raw rows: 360
- Aggregate rows: 7
- Runtime: 0.32s
- Root federation: 3-of-5
- Seeds: 0..29
- Cross-observation delays: 0.25s, 0.5s, 1.0s, 2.0s
- Partition-heal delays: 0.5s, 2.0s, 5.0s

## Result Summary

H3 is supported in the local model:

- Below-threshold rejection rate: 1.0.
- Split-view detection rate after STH cross-observation: 1.0.
- Benign STH reordering false-positive rate: 0.0.
- No-STH-cross-observation baseline miss rate: 1.0.
- Maximum detection latency: 5.3s under the largest partition-heal delay.
- Mean split-view evidence size: 821 bytes.

The result depends on eventual honest cross-observation. During partitions, the model delays evidence until observers exchange same-size STHs after healing.
