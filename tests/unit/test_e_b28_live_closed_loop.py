import base64
import importlib.util
import json
from pathlib import Path

import pytest


ARTIFACT = Path(__file__).resolve().parents[2]
RECEIVER_PATH = ARTIFACT / "experiments/e_b28_live_closed_loop/receiver.py"
GATE_PATH = ARTIFACT / "experiments/e_b28_live_closed_loop/run_gate.py"


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def compact_jws(payload: dict[str, object]) -> bytes:
    def encode(value: object) -> str:
        raw = json.dumps(value, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    return f"{encode({'alg': 'RS256', 'kid': 'test'})}.{encode(payload)}.signature".encode()


def test_durable_receiver_freezes_selective_action(tmp_path: Path) -> None:
    receiver = load(RECEIVER_PATH, "e_b28_receiver_test")
    store = receiver.DurableRelayStore(tmp_path / "receiver.sqlite3")
    store.register(run_id="run-selective", arm="selective_c3", receiver_b_action="withhold")
    payload = {
        "jti": "event-1",
        "sub_id": {"session": {"id": "session-1"}},
        "events": {receiver.SESSION_REVOKED: {"event_timestamp": 28}},
    }
    raw_a = compact_jws(payload)
    payload_b = {**payload, "jti": "event-2"}
    raw_b = compact_jws(payload_b)
    a = store.record(receiver="receiver-a", authorization_valid=True, content_type="application/secevent+jwt", raw=raw_a)
    b = store.record(receiver="receiver-b", authorization_valid=True, content_type="application/secevent+jwt", raw=raw_b)
    assert a["forwarded"] is True
    assert b["forwarded"] is False
    state = store.state("run-selective")
    assert state["attempt_count"] == 2
    assert {item["receiver"] for item in state["attempts"]} == {"receiver-a", "receiver-b"}
    assert {item["jti"] for item in state["attempts"]} == {"event-1", "event-2"}


def test_durable_receiver_rejects_arm_action_mismatch(tmp_path: Path) -> None:
    receiver = load(RECEIVER_PATH, "e_b28_receiver_mismatch_test")
    store = receiver.DurableRelayStore(tmp_path / "receiver.sqlite3")
    with pytest.raises(ValueError, match="requires receiver-b action"):
        store.register(run_id="bad", arm="normal_c4", receiver_b_action="withhold")


def test_formal_schedule_is_exact_and_balanced() -> None:
    gate = load(GATE_PATH, "e_b28_gate_test")
    rows = gate.formal_schedule()
    assert len(rows) == 60
    assert len({(row["target"], row["arm"], row["repetition"]) for row in rows}) == 60
    assert {arm: sum(row["arm"] == arm for row in rows) for arm in (
        "active_sanity", "normal_c4", "selective_c3"
    )} == {"active_sanity": 20, "normal_c4": 20, "selective_c3": 20}
    assert len(gate.recovery_schedule()) == 2
