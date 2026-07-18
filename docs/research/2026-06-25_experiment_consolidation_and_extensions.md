# Paper B Experiment Consolidation and Extensions

Timestamp: 2026-06-25T22:23:29-0700

## Decision

The original E-B1..E-B7 experiments should not be discarded. The main paper
should present them as four evaluation questions rather than seven equally
weighted experiment lines:

1. Propagation completeness and latency under suppression and related-work
   delivery baselines.
2. Stale-authority damage under TTL, request velocity, and damage budgets.
3. Equivocation observability under root-threshold evidence and watcher
   coverage assumptions.
4. Implementation-boundary checks for A2A-shaped payloads, TCP/JSON transport,
   reproducibility, and sensitivity.

## Keep, Merge, Or Demote

| Existing track | Paper treatment | Rationale |
|---|---|---|
| E-B1 suppression boundary | Keep in main text | Defines the operating envelope and theorem-assumption boundary. |
| E-B2 strategy comparison | Keep and extend | This is where related-work delivery baselines belong. |
| E-B3 stale-authority damage | Keep in main text | Converts propagation delay into application-facing harm. |
| E-B4 equivocation evidence | Keep and extend | This is where watcher/monitor coverage sensitivity belongs. |
| E-B5 thin A2A binding | Merge/demote | Useful artifact/prototype sanity check, not a main claim by itself. |
| E-B6 local end-to-end transport | Merge/demote | Implementation-boundary evidence, not production network evidence. |
| E-B7 sensitivity | Merge/demote | Robustness/reproducibility support; can be appendix or paragraph. |

## New Experiment Additions

### E-B2 Delivery-Regime Baselines

Add delivery-regime rows that emulate mechanism families from related work
without claiming to reimplement their full cryptographic systems:

- `full-snapshot`: CRL or VC bitstring-style periodic full status snapshot.
- `request-time-check`: OCSP-style synchronous validation.
- `request-time-fail-open`: OCSP-like check that may fail open under status
  service suppression.
- `compact-delta`: compact delta or Clubcards-style status update.
- `dns-log-poll`: DNS/log-poll-style decentralized status polling.
- `hybrid`: this paper's push/gossip/log hybrid.

Metrics should include stale acceptance window, p99 propagation delay,
completeness, message count, approximate bytes, per-party state bytes,
suppression sensitivity, and expected/worst stale-authority damage.

### E-B4 Watcher Coverage Sensitivity

Extend the equivocation experiment with observer topology and observation-delay
sweeps:

- watcher count;
- watcher coverage fraction;
- observation interval;
- party reporting fraction;
- partition duration;
- adversarial selective disclosure fraction.

Metrics should include detection probability, detection latency, false-positive
rate, evidence bytes, and the minimum watcher coverage needed to bound detection
latency.

## Implementation Guidance

Keep the artifact code explicit and reproducible. It is acceptable for the code
to retain E-B1..E-B7 function names for compatibility, but new related-work
coverage should be implemented as E-B2/E-B4 extensions rather than standalone
paper sections. Reports should mark these baselines as mechanism-level
simulations, not faithful reimplementations of CRLite, Clubcards, RevDNS, OCSP,
or W3C VC status-list systems.
