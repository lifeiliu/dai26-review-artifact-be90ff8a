#!/usr/bin/env python3
"""Validate saved JSON/JSONL files and report primary raw-row counts."""

from __future__ import annotations

import csv
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"


def main() -> int:
    json_files = list(DATA.rglob("*.json"))
    jsonl_files = list(DATA.rglob("*.jsonl"))
    raw_csv_files = [path for path in DATA.rglob("*.csv") if not path.name.endswith("_aggregate.csv")]

    for path in json_files:
        json.loads(path.read_text())
    for path in jsonl_files:
        for line_number, line in enumerate(path.read_text().splitlines(), start=1):
            try:
                json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"{path}:{line_number}: {error}") from error

    rows = 0
    for path in raw_csv_files:
        with path.open(newline="") as handle:
            rows += sum(1 for _ in csv.DictReader(handle))

    print(
        f"Saved data valid: {len(json_files)} JSON, {len(jsonl_files)} JSONL, "
        f"{len(raw_csv_files)} raw CSV files, {rows} raw rows."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
