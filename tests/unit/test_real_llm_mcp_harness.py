import json

from revocation_propagation.real_llm_mcp_harness import (
    _validate_assignments,
    _validate_worker_action,
    replay_e_b18_trace,
)


def test_e_b18_validates_frozen_llm_json_contracts() -> None:
    assignments = _validate_assignments(
        {
            "assignments": [
                {"worker": "worker-1", "gateway": "gateway-1"},
                {"worker": "worker-0", "gateway": "gateway-0"},
            ]
        }
    )
    payload = _validate_worker_action({"action": "repo_write", "payload": "seed-0 harmless"})

    assert assignments[0] == {"worker": "worker-0", "gateway": "gateway-0"}
    assert payload == "seed-0 harmless"


def test_e_b18_replay_reconstructs_revocation_state(tmp_path) -> None:
    events = []

    def add(event_type, **fields):
        events.append({"run_id": "test", "seq": len(events), "event_type": event_type, **fields})

    add("run_started", profile="revprop")
    add("server_started", gateway_id="gateway-0", server_pid=101)
    add("server_started", gateway_id="gateway-1", server_pid=102)
    add("llm_call", role="orchestrator", phase="assignment", parsed_response={"assignments": []})
    for worker, gateway in (("worker-0", "gateway-0"), ("worker-1", "gateway-1")):
        add("llm_call", role=worker, phase="pre-revocation", parsed_response={"action": "repo_write"})
        add(
            "mcp_call",
            gateway_id=gateway,
            phase="pre-revocation",
            tool="repo_write",
            arguments={},
            result={"allowed": True},
        )
    add(
        "mcp_call",
        gateway_id="gateway-0",
        phase="direct-revocation",
        tool="apply_revocation",
        arguments={"channel": "direct-push"},
        result={"learned_via": "direct-push"},
    )
    for worker, gateway, allowed in (
        ("worker-0", "gateway-0", False),
        ("worker-1", "gateway-1", True),
    ):
        add("llm_call", role=worker, phase="post-direct", parsed_response={"action": "repo_write"})
        add(
            "mcp_call",
            gateway_id=gateway,
            phase="post-direct",
            tool="repo_write",
            arguments={},
            result={"allowed": allowed},
        )
    add(
        "mcp_call",
        gateway_id="gateway-1",
        phase="repair",
        tool="apply_revocation",
        arguments={"channel": "log-repair"},
        result={"learned_via": "log-repair"},
    )
    for worker, gateway in (("worker-0", "gateway-0"), ("worker-1", "gateway-1")):
        add("llm_call", role=worker, phase="post-repair", parsed_response={"action": "repo_write"})
        add(
            "mcp_call",
            gateway_id=gateway,
            phase="post-repair",
            tool="repo_write",
            arguments={},
            result={"allowed": False},
        )
    add(
        "mcp_call",
        gateway_id="gateway-0",
        phase="final-status",
        tool="gateway_status",
        arguments={},
        result={"revoked": True, "learned_via": "direct-push"},
    )
    add(
        "mcp_call",
        gateway_id="gateway-1",
        phase="final-status",
        tool="gateway_status",
        arguments={},
        result={"revoked": True, "learned_via": "log-repair"},
    )
    trace = tmp_path / "trace.jsonl"
    trace.write_text("".join(json.dumps(event) + "\n" for event in events))

    report = replay_e_b18_trace(trace)

    assert report["valid"] is True
    assert report["llm_calls"] == 7
    assert report["violations"] == []
