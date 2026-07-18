from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
SOURCE = REPO_ROOT / "artifact" / "src"
if str(SOURCE) not in sys.path:
    sys.path.insert(0, str(SOURCE))

SCRIPT = (
    Path(__file__).resolve().parents[1] / "strict" / "e_b24_outcome_driver.py"
)
SPEC = importlib.util.spec_from_file_location("e_b24_outcome_driver", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def test_frozen_schedule_has_exact_half_boundary() -> None:
    allowlist = (
        REPO_ROOT
        / "artifact"
        / "data"
        / "run_2026_07_16_e_b24_local_real_effect_gate"
        / "frozen-vector-allowlist.json"
    )
    vectors, manifest = MODULE.load_schedule(allowlist)
    assert len(vectors) == 225
    assert manifest["receiver_counts"] == {"receiver-a": 113, "receiver-b": 112}
    assert manifest["receiver_service_counts"]["receiver-b"] == {
        "filesystem": 56,
        "postgres": 56,
    }


def test_expected_revocation_patterns_are_partitioned() -> None:
    assert all(MODULE.expected_revoked("normal").values())
    assert all(MODULE.expected_revoked("recovery").values())
    assert MODULE.expected_revoked("receiver_gateway_fault") == {
        "gateway-1": True,
        "gateway-2": True,
        "gateway-3": True,
        "gateway-4": True,
        "gateway-5": False,
        "gateway-6": False,
        "gateway-7": False,
        "gateway-8": False,
    }


def test_outcome_driver_has_no_adaptive_scientific_parameters() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    assert "target_fraction" not in source
    assert "risk_index" not in source
    assert "effect_threshold" not in source
    assert "--retry" not in source
