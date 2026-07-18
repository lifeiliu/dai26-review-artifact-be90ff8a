from __future__ import annotations

import importlib.util
from pathlib import Path


STRICT = Path(__file__).resolve().parents[1] / "strict"


def _load(name: str):
    path = STRICT / name
    spec = importlib.util.spec_from_file_location(name.replace(".py", ""), path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_fault_is_external_and_targets_only_control_port() -> None:
    module = _load("e_b24_fault_controller.py")
    commands = "\n".join(module._commands("apply"))
    assert "dport 9444" in commands
    assert "e_b24_rx_fault" in commands
    assert "8000" not in commands
    assert "9443" not in commands
    assert "docker" not in commands


def test_fault_clear_fails_closed_on_residual_table() -> None:
    module = _load("e_b24_fault_controller.py")
    commands = "\n".join(module._commands("clear"))
    assert "delete table" in commands
    assert "then exit 1" in commands


def test_fault_controller_tolerates_ssm_invocation_visibility_lag() -> None:
    source = (STRICT / "e_b24_fault_controller.py").read_text(encoding="utf-8")
    assert "InvocationDoesNotExist" in source
    assert "time.monotonic() + timeout" in source
    assert "time.sleep(2)" in source


def test_measurement_helpers_are_read_only() -> None:
    for name in ("e_b24_receiver_export.py", "e_b24_effect_oracle_export.py"):
        source = (STRICT / name).read_text(encoding="utf-8").lower()
        assert " delete " not in source
        assert " update " not in source
        assert " insert " not in source
        assert "method=\"post\"" in source or "urllib.request" not in source
