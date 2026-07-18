#!/usr/bin/env python3
"""Replay E-B18 traces without calling the LLM or MCP servers."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from revocation_propagation.real_llm_mcp_harness import replay_e_b18_directory


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay an E-B18 output directory.")
    parser.add_argument("output_dir")
    args = parser.parse_args()
    result = replay_e_b18_directory(args.output_dir)
    print(f"E-B18 replay: {result['valid_traces']}/{result['trace_count']} valid")
    return 0 if result["all_valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
