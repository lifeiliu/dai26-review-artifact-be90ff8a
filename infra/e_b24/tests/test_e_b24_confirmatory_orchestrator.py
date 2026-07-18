from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "run_e_b24_confirmatory.py"
)
SPEC = importlib.util.spec_from_file_location("run_e_b24_confirmatory", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def test_frozen_run_has_thirty_counterbalanced_blocks() -> None:
    assert MODULE.BLOCK_COUNT == 30
    odd = ["normal", "receiver_gateway_fault"]
    even = ["receiver_gateway_fault", "normal"]
    assert odd != even


def test_reproduction_run_id_is_explicit_and_path_safe() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    assert 'parser.add_argument("--run-id", default=DEFAULT_RUN_ID)' in source
    assert "run ID must be a lowercase S3/path-safe identifier" in source


def test_primary_contract_is_exact_and_uses_authoritative_oracles() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    assert '"receiver_gateway_fault": (112, 112, 56, 56)' in source
    assert '"normal": (0, 0, 0, 0)' in source
    assert '"recovery": (0, 0, 0, 0)' in source
    assert 'oracle["filesystem"]["count"]' in source
    assert 'oracle["postgres"]["count"]' in source


def test_execution_has_no_outcome_retry_or_adaptive_stop() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    assert "--retry" not in source
    assert "early_stop" not in source
    assert "power_analysis" not in source
    assert "for block in range(1, BLOCK_COUNT + 1)" in source


def test_runtime_uses_the_image_python_entrypoint_once() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    assert '{runtime_image} /run/e-b24/outcome-driver.py' in source
    assert '{runtime_image} python3 /run/e-b24/outcome-driver.py' not in source


def test_phase_output_mount_is_writable_by_the_nonroot_runtime() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    assert 'install -d -m 0777 {phase_dir}' in source
    assert 'f"/var/lib/e-b24/confirmatory/{RUN_ID}/block-' in source
    assert "def validate_runtime_output_mount(" in source
    assert '"scientific_operations": 0' in source


def test_oracle_archives_full_json_before_emitting_bounded_summary() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    assert "confirmatory/raw/{RUN_ID}/oracles/{experiment_run}" in source
    assert "e-b24-effect-oracle=" in source
    assert "vector_count:(.filesystem.vector_ids|length)" in source


def test_block1_continuation_reuses_completed_phases_without_replay() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    assert "RESUME_BLOCK_1" in source
    assert "if resuming_block_1:" in source
    assert '"reconstructed_from_completed_phase": True' in source
    assert '"continued_without_phase_replay": (' in source
    assert "resuming_block_1 or resuming_block_2" in source


def test_delegation_ids_are_passed_with_equals_for_leading_hyphens() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    assert ' --delegation-id={delegation_id}' in source
    assert '--delegation-id={delegation_id}' in source


def test_block2_projection_uses_only_durable_pre_cutoff_timestamps() -> None:
    evidence = {
        "evidence": {
            "delegation_id": "-example",
            "found": True,
            "persisted_at_ns": 10,
            "enforced_at_ns": 30,
            "status": "ENFORCED",
            "ingress_records": [{"observed_at_ns": 11, "http_response": 202}],
            "receipts": [{"recorded_at_ns": 30}],
            "targets": [{"attempts": 1, "last_error": None}],
        }
    }
    projected = MODULE.project_receiver_evidence_as_of(evidence, 20)
    assert projected["evidence"]["status"] == "PERSISTED"
    assert projected["evidence"]["enforced_at_ns"] is None
    assert projected["evidence"]["receipts"] == []
    assert projected["evidence"]["ingress_records"][0]["http_response"] == 202


def test_block27_continuation_imports_1_to_26_and_reuses_normal() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    assert "COMPLETED_REPORT_26_SHA256" in source
    assert "RESUME_BLOCK_27" in source
    assert "if args.resume_v2_block27 and block <= 26:" in source
    assert "elif resuming_block_27:" in source
