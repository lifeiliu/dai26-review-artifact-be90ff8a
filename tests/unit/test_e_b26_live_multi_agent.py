import importlib.util
import sys
from pathlib import Path

import pytest


RUNNER = (
    Path(__file__).resolve().parents[2]
    / "experiments"
    / "e_b26_live_multi_agent_mcp"
    / "run_gate.py"
)
SPEC = importlib.util.spec_from_file_location("e_b26_runner", RUNNER)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def test_validates_frozen_orchestrator_and_worker_schemas() -> None:
    assignments = MODULE.validate_orchestrator(
        {
            "assignments": [
                {"worker": "worker-postgres", "gateway": "g-postgres"},
                {"worker": "worker-filesystem", "gateway": "g-filesystem"},
            ]
        }
    )
    assert assignments[0]["worker"] == "worker-filesystem"
    action = MODULE.validate_worker_action(
        worker="worker-filesystem",
        gateway="g-filesystem",
        parsed={
            "tool": "write_file_effect",
            "arguments": {
                "relative_path": "live_agent_note.txt",
                "content": "safe content",
                "action_id": "fs-live-action",
            },
        },
    )
    assert action["arguments"]["delegation_id"] == MODULE.DELEGATION_ID
    assert len(action["canonical_sha256"]) == 64


def test_rejects_agent_path_or_schema_drift() -> None:
    with pytest.raises(ValueError):
        MODULE.validate_worker_action(
            worker="worker-filesystem",
            gateway="g-filesystem",
            parsed={
                "tool": "write_file_effect",
                "arguments": {
                    "relative_path": "../escape",
                    "content": "unsafe",
                    "action_id": "fs-live-action",
                },
            },
        )
