"""Run one frozen E-B19 risk-weighted selective-omission pilot round."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from revocation_propagation.risk_weighted_pilot import main


if __name__ == "__main__":
    main()
