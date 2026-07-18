#!/usr/bin/env python3
"""Verify artifact files against CHECKSUMS.sha256."""

from __future__ import annotations

import hashlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "CHECKSUMS.sha256"


def main() -> int:
    failures: list[str] = []
    entries = 0
    for line in MANIFEST.read_text().splitlines():
        if not line.strip():
            continue
        expected, relative = line.split("  ", 1)
        path = ROOT / relative
        entries += 1
        if not path.is_file():
            failures.append(f"missing: {relative}")
            continue
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            failures.append(f"changed: {relative}")

    if failures:
        print("Checksum verification failed:")
        for failure in failures:
            print(f"- {failure}")
        return 1
    print(f"Checksum verification passed for {entries} files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
