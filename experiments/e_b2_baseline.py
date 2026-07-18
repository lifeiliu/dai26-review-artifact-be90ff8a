"""Run the Paper B baseline matrix for delta_prop and damage accounting."""

from __future__ import annotations

import json
import sys
from dataclasses import asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from revocation_propagation.byzantine_harness import TrialParams, run_baseline_matrix


def main() -> None:
    params = TrialParams()
    metrics = run_baseline_matrix(params)
    print(json.dumps([asdict(metric) for metric in metrics], indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
