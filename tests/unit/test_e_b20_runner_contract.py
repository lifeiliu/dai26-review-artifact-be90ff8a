import importlib.util
from pathlib import Path

import pytest


RUNNER_PATH = Path(__file__).resolve().parents[2] / "experiments" / "e_b20_mcpmark_traced.py"
SPEC = importlib.util.spec_from_file_location("e_b20_runner", RUNNER_PATH)
assert SPEC and SPEC.loader
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


def _formal_args():
    return [
        "--mcp",
        "filesystem",
        "--models",
        "openai/gpt-4.1-mini",
        "--agent",
        "mcpmark",
        "--tasks",
        "all",
        "--task-suite",
        "standard",
        "--k",
        "4",
        "--reasoning-effort",
        "default",
        "--compaction-token",
        "999999999",
        "--timeout",
        "3600",
        "--exp-name",
        "e-b20-formal",
    ]


def test_formal_runner_contract_accepts_only_frozen_values() -> None:
    assert RUNNER._validate_forwarded(_formal_args(), infrastructure_smoke=False) == "filesystem"

    changed = _formal_args()
    changed[changed.index("--tasks") + 1] = "file_property/size_classification"
    with pytest.raises(ValueError, match="freezes --tasks=all"):
        RUNNER._validate_forwarded(changed, infrastructure_smoke=False)


def test_smoke_runner_contract_is_separate_from_formal_population() -> None:
    arguments = _formal_args()
    arguments[arguments.index("--tasks") + 1] = "file_property/size_classification"
    arguments[arguments.index("--k") + 1] = "1"

    assert RUNNER._validate_forwarded(arguments, infrastructure_smoke=True) == "filesystem"


def test_runner_drops_non_directory_path_entries(tmp_path) -> None:
    mcpmark = tmp_path / "mcpmark"
    venv_bin = mcpmark / ".venv" / "bin"
    venv_bin.mkdir(parents=True)
    good = tmp_path / "good"
    good.mkdir()
    file_component = tmp_path / "not-a-directory"
    file_component.write_text("x", encoding="utf-8")

    sanitized = RUNNER._sanitized_path(
        mcpmark, f"{file_component}:{good}:{good}"
    ).split(":")

    assert sanitized == [str(venv_bin.resolve()), str(good.resolve())]
