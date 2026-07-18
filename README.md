# Anonymous Revocation-Completion Artifact

This artifact accompanies an anonymous paper on a C0--C5 outcome contract for
distributed agent-tool revocation. Its main claim is not a new propagation
mechanism: transport acknowledgment and receiver persistence do not certify
gateway enforcement or prevention of real tool effects.

The release contains implementation, frozen protocols, validators, and saved
evidence for the mechanism/workload boundaries (E-B17--E-B20), real Keycloak
PUSH/POLL paths (E-B22/E-B23), two 16-host AWS executions with real
Filesystem/PostgreSQL effects (E-B24), an OPA/Toxiproxy replication (E-B25), a
live model-to-MCP execution (E-B26), and the version-2 completion-monitor fault
and scaling evaluation (E-B27). Secondary E-B1--E-B16 material remains for
auditability but is not the paper's main evidence.

## Quick start

Requirements: Python 3.11 or newer.

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 -m pip install -e .
make verify
```

`make verify` runs the unit suite, validates saved JSON, checks claim-boundary
metadata and release checksums, and scans every released file for identity,
AWS account/role, email, home-path, and credential-shaped leakage.

Validate the highest-leverage monitor experiment directly:

```bash
python3 experiments/e_b27_completion_monitor/validate_run.py \
  data/run_2026_07_18_e_b27_completion_monitor_confirmatory
```

The validator checks the frozen protocol hash, 14 exact fault rows, all 33
scaling trials, all 11 configurations, and every reported median. Its
`validation_report.md` begins with the Material Passport.

## Layout

- `src/revocation_propagation/`: propagation, receiver, gateway, and C0--C5
  monitor implementations.
- `tests/unit/`: 98 unit and integration-boundary tests in the release state.
- `experiments/`: experiment runners, including E-B24--E-B27.
- `protocols/`: frozen study and completion-contract definitions.
- `data/`: saved portable evidence and validators' reports.
- `scripts/`: integrity, claim-boundary, release, and anonymization tools.

See `REPRODUCIBILITY.md` for study-specific commands and limits. The generated
`ANONYMOUS_RELEASE_NOTES.md`, `RELEASE_MANIFEST.json`, and
`CHECKSUMS.sha256` describe release transformations and exact released bytes.

This review bundle has no public-source license. It is supplied solely for
anonymous scholarly peer review; a publication license will be selected after
double-blind review.
