"""Create the frozen E-B20 manifest or analyze collected MCPMark traces."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from revocation_propagation.mcpmark_external_trace import (  # noqa: E402
    analyze_e_b20,
    write_benchmark_manifest,
)
from revocation_propagation.mcpmark_instrumentation import verify_frozen_checkout  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    manifest_parser = subparsers.add_parser("manifest")
    manifest_parser.add_argument("--mcpmark-root", type=Path, required=True)
    manifest_parser.add_argument("--output", type=Path, required=True)

    analyze_parser = subparsers.add_parser("analyze")
    analyze_parser.add_argument("--manifest", type=Path, required=True)
    analyze_parser.add_argument("--trace-dir", type=Path, required=True)
    analyze_parser.add_argument("--output-dir", type=Path, required=True)
    analyze_parser.add_argument("--bootstrap-samples", type=int, default=10_000)

    args = parser.parse_args()
    if args.command == "manifest":
        verify_frozen_checkout(args.mcpmark_root)
        result = write_benchmark_manifest(args.mcpmark_root, args.output)
    else:
        result = analyze_e_b20(
            manifest_path=args.manifest,
            trace_dir=args.trace_dir,
            output_dir=args.output_dir,
            bootstrap_samples=args.bootstrap_samples,
        )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

