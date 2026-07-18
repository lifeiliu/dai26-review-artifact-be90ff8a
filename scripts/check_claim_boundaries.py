#!/usr/bin/env python3
"""Fail if the anonymous artifact overstates the P0-3 evidence-plane boundary."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent
PAPER = REPO / "paper"

FORBIDDEN = (
    "threshold signature",
    "threshold-signature",
    "threshold signing",
    "threshold-signing",
    "threshold certificate",
    "threshold-signed",
    "production-grade transparency log",
    "production transparency log",
)


def iter_claim_files():
    roots = (
        ROOT / "README.md",
        ROOT / "REPRODUCIBILITY.md",
        ROOT / "protocols",
        ROOT / "src",
        ROOT / "data",
        PAPER / "manuscript" / "main.tex",
        PAPER / "scripts",
        PAPER / "figures" / "fig1_architecture.svg",
        PAPER / "tables" / "claim_notes.json",
    )
    for root in roots:
        if root.is_file():
            yield root
            continue
        for path in root.rglob("*"):
            # Raw CSV rows are immutable measurements, not current prose claims.
            # User-facing reports and summaries remain in scope through MD/JSON.
            if path.is_file() and path.suffix.lower() in {".md", ".py", ".tex", ".svg", ".json"}:
                yield path


def main() -> int:
    failures: list[str] = []
    checked = 0
    for path in iter_claim_files():
        checked += 1
        text = path.read_text(errors="replace").lower()
        for phrase in FORBIDDEN:
            if phrase in text:
                failures.append(f"{path.relative_to(REPO)}: forbidden phrase {phrase!r}")

    ledger = (ROOT / "src" / "revocation_propagation" / "ledger_client.py").read_text()
    root_authority = (ROOT / "src" / "revocation_propagation" / "root_authority.py").read_text()
    required = {
        "ledger stand-in disclosure": "in-process stand-in" in ledger and "bulky prefix-consistency proof" in ledger,
        "root quorum disclosure": "individual-signature quorum certificates" in root_authority,
    }
    manuscript_path = PAPER / "manuscript" / "main.tex"
    if manuscript_path.is_file():
        manuscript = manuscript_path.read_text()
        required.update({
            "manuscript quorum boundary": "M-of-N individual" in manuscript and "quorum certificate" in manuscript,
            "manuscript log boundary": "transparency-inspired log" in manuscript,
        })
    failures.extend(f"missing required boundary: {name}" for name, passed in required.items() if not passed)

    if failures:
        print("Claim-boundary check failed:")
        for failure in failures:
            print(f"- {failure}")
        return 1
    print(f"Claim-boundary check passed for {checked} files; P0-3 scope remains prototype quorum/log only.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
