"""Run the Paper B research experiment suite."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from revocation_propagation.experiment_cli import main


if __name__ == "__main__":
    main()
