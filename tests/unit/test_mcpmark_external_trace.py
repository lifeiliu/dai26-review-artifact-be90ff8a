import json
import os
from pathlib import Path

import pytest

from revocation_propagation.mcpmark_external_trace import (
    CalibrationRisk,
    PROPAGATION_SEEDS,
    ReplayContribution,
    analyze_replay,
    calibrate_risks,
    cost_contract,
    extract_sql,
    filesystem_merkle_digest,
    postgres_sql_is_mutating,
    repair_allocations,
    select_top_risk_targets,
)


def test_filesystem_digest_ignores_times_but_detects_persistent_changes(tmp_path) -> None:
    root = tmp_path / "tree"
    root.mkdir()
    file_path = root / "note.txt"
    file_path.write_text("one", encoding="utf-8")
    first = filesystem_merkle_digest(root)

    os.utime(file_path, (1_000_000, 2_000_000))
    assert filesystem_merkle_digest(root) == first

    file_path.write_text("two", encoding="utf-8")
    assert filesystem_merkle_digest(root) != first


@pytest.mark.parametrize(
    "sql",
    [
        "INSERT INTO audit VALUES (1)",
        "WITH changed AS (UPDATE t SET x=1 RETURNING *) SELECT * FROM changed",
        "CREATE INDEX idx ON t (x)",
        "SELECT * INTO archived FROM active",
        "COPY t FROM STDIN",
        "DO $$ BEGIN DELETE FROM t; END $$",
    ],
)
def test_postgres_classifier_detects_frozen_mutation_classes(sql) -> None:
    assert postgres_sql_is_mutating(sql) is True


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT * FROM t",
        "SELECT 'DELETE FROM t' AS example",
        "-- UPDATE t SET x=1\nSELECT 1",
        "/* CREATE TABLE nope(x int) */ SHOW search_path",
        "COPY (SELECT * FROM t) TO STDOUT",
        'SELECT "update" FROM t',
    ],
)
def test_postgres_classifier_keeps_read_only_sql_non_mutating(sql) -> None:
    assert postgres_sql_is_mutating(sql) is False


def test_extract_sql_uses_frozen_argument_keys_recursively() -> None:
    assert extract_sql({"params": {"query": "SELECT 1"}}) == "SELECT 1"
    assert extract_sql({"path": "/tmp/example"}) is None


def _risk(gateway_id: str, mutations: int) -> CalibrationRisk:
    return CalibrationRisk(
        gateway_id=gateway_id,
        service="filesystem",
        calls_run1=10,
        calls_run2=10,
        mutations_run1=mutations,
        mutations_run2=mutations,
    )


def test_calibration_risk_top20_and_equal_budget_are_frozen() -> None:
    risks = [_risk(f"filesystem/cat/task-{index:02d}", index) for index in range(51)]
    targets = select_top_risk_targets(risks)
    uniform = repair_allocations(risks, targets, "uniform")
    aware = repair_allocations(risks, targets, "risk-aware")

    assert len(targets) == 10
    assert "filesystem/cat/task-50" in targets
    assert "filesystem/cat/task-40" not in targets
    assert sum(uniform.values()) == sum(aware.values()) == 50
    assert min(aware.values()) >= 1
    assert cost_contract(51, 10)["control_messages_per_gateway"] == 8.0


def test_calibrate_risks_retains_zero_call_tasks() -> None:
    tasks = [
        {"gateway_id": "filesystem/cat/a", "service": "filesystem"},
        {"gateway_id": "postgres/cat/b", "service": "postgres"},
    ]
    events = []
    for task in tasks:
        for run in (1, 2):
            events.append(
                {
                    "event_type": "task_end",
                    "gateway_id": task["gateway_id"],
                    "run": run,
                    "trace_valid": True,
                }
            )
    events.extend(
        [
            {
                "event_type": "tool_call",
                "gateway_id": "filesystem/cat/a",
                "run": 1,
                "mutating": True,
            },
            {
                "event_type": "tool_call",
                "gateway_id": "filesystem/cat/a",
                "run": 2,
                "mutating": False,
            },
        ]
    )
    risks = calibrate_risks(events, tasks)

    assert risks[0].risk == 0.5
    assert risks[1].call_rate == risks[1].risk == 0.0


def test_replay_analysis_uses_ratio_of_means_and_paired_task_clusters() -> None:
    contributions = []
    for task_index in range(3):
        for seed in PROPAGATION_SEEDS:
            contributions.extend(
                [
                    ReplayContribution(
                        gateway_id=f"task-{task_index}",
                        seed=seed,
                        policy="uniform",
                        weighted_harm=10.0 + task_index,
                        accepted_mutating_calls=2,
                    ),
                    ReplayContribution(
                        gateway_id=f"task-{task_index}",
                        seed=seed,
                        policy="risk-aware",
                        weighted_harm=5.0 + task_index / 2,
                        accepted_mutating_calls=1,
                    ),
                ]
            )

    analysis = analyze_replay(contributions, bootstrap_samples=200)

    assert analysis["H"]["relative_reduction"] == pytest.approx(0.5)
    assert analysis["U"]["relative_reduction"] == pytest.approx(0.5)
    assert analysis["H"]["gate_pass"] is True
    assert analysis["U"]["gate_pass"] is True
    assert analysis["overall_gate_pass"] is True

