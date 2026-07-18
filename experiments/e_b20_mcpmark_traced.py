"""Run the frozen MCPMark checkout with E-B20 observation hooks."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


ARTIFACT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ARTIFACT_ROOT / "src"))

from revocation_propagation.mcpmark_instrumentation import (  # noqa: E402
    install_mcpmark_instrumentation,
    prepare_new_trace_dir,
    verify_frozen_checkout,
)


FROZEN_MODEL = "openai/gpt-4.1-mini"
FROZEN_BASE_URL = "https://openrouter.ai/api/v1"


def _argument_value(arguments: list[str], flag: str, default: str | None = None) -> str | None:
    if flag not in arguments:
        return default
    index = arguments.index(flag)
    if index + 1 >= len(arguments):
        raise ValueError(f"missing value after {flag}")
    return arguments[index + 1]


def _sanitized_path(mcpmark_root: Path, current_path: str) -> str:
    """Drop non-directory PATH entries that make macOS exec raise ENOTDIR."""

    candidates = [mcpmark_root / ".venv" / "bin"]
    candidates.extend(Path(item) for item in current_path.split(os.pathsep) if item)
    kept: list[str] = []
    for candidate in candidates:
        resolved = candidate.expanduser().resolve()
        text = str(resolved)
        if resolved.is_dir() and text not in kept:
            kept.append(text)
    return os.pathsep.join(kept)


def _validate_forwarded(arguments: list[str], *, infrastructure_smoke: bool) -> str:
    service = _argument_value(arguments, "--mcp", "filesystem")
    if service not in ("filesystem", "postgres"):
        raise ValueError("E-B20 permits only filesystem and postgres")
    frozen = {
        "--models": FROZEN_MODEL,
        "--agent": "mcpmark",
        "--tasks": "file_property/size_classification" if infrastructure_smoke else "all",
        "--task-suite": "standard",
        "--k": "1" if infrastructure_smoke else "4",
        "--reasoning-effort": "default",
        "--compaction-token": "999999999",
        "--timeout": "3600",
    }
    for flag, expected in frozen.items():
        actual = _argument_value(arguments, flag, expected)
        if actual != expected:
            raise ValueError(f"E-B20 freezes {flag}={expected}, received {actual}")
    if _argument_value(arguments, "--exp-name") is None:
        raise ValueError("E-B20 requires an explicit --exp-name")
    return str(service)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mcpmark-root", type=Path, required=True)
    parser.add_argument("--trace-dir", type=Path, required=True)
    parser.add_argument("--infrastructure-smoke", action="store_true")
    parser.add_argument("pipeline_args", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    forwarded = list(args.pipeline_args)
    if forwarded and forwarded[0] == "--":
        forwarded = forwarded[1:]
    service = _validate_forwarded(
        forwarded, infrastructure_smoke=args.infrastructure_smoke
    )
    if args.infrastructure_smoke and service != "filesystem":
        raise ValueError("the frozen infrastructure smoke is the Filesystem task")

    mcpmark_root = args.mcpmark_root.resolve()
    verify_frozen_checkout(mcpmark_root)
    trace_dir = prepare_new_trace_dir(args.trace_dir, service=service)

    openrouter_key = os.environ.get("OPENROUTER_API_KEY")
    if not openrouter_key:
        raise RuntimeError("E-B20 requires OPENROUTER_API_KEY in the process environment")
    os.environ["OPENAI_API_KEY"] = openrouter_key
    os.environ["OPENAI_BASE_URL"] = FROZEN_BASE_URL
    os.environ["PATH"] = _sanitized_path(mcpmark_root, os.environ.get("PATH", ""))
    if service == "postgres":
        os.environ["POSTGRES_HOST"] = "127.0.0.1"
        os.environ["POSTGRES_PORT"] = "5432"
        os.environ["POSTGRES_DATABASE"] = "postgres"
        os.environ["POSTGRES_USERNAME"] = "postgres"
        os.environ["POSTGRES_PASSWORD"] = "password"
        pipx_root = mcpmark_root / ".e_b20_pipx"
        os.environ["PIPX_HOME"] = str(pipx_root / "home")
        os.environ["PIPX_BIN_DIR"] = str(pipx_root / "bin")
        os.environ["PIPX_SHARED_LIBS"] = str(pipx_root / "shared")
        os.environ["PIPX_LOG_DIR"] = str(pipx_root / "logs")
        os.environ["PIPX_DEFAULT_PYTHON"] = (
            "/Library/Frameworks/Python.framework/Versions/3.12/bin/python3.12"
        )

    os.chdir(mcpmark_root)
    sys.path.insert(0, str(mcpmark_root))
    install_mcpmark_instrumentation(trace_dir)
    from pipeline import main as mcpmark_main

    sys.argv = ["pipeline.py", *forwarded]
    mcpmark_main()


if __name__ == "__main__":
    main()
