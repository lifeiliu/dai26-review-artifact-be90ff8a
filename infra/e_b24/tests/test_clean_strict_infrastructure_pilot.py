from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "run_clean_strict_infrastructure_pilot.py"
)
SPEC = importlib.util.spec_from_file_location("clean_strict_pilot", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class CleanStrictInfrastructurePilotTests(unittest.TestCase):
    def test_bootstrap_version_gate_accepts_audited_successors_only(self) -> None:
        self.assertTrue(
            MODULE._is_sigpipe_safe_bootstrap(
                "strict-bootstrap-v5-bounded-package-retry"
            )
        )
        self.assertTrue(
            MODULE._is_sigpipe_safe_bootstrap("strict-bootstrap-v3-no-sigpipe")
        )
        self.assertFalse(
            MODULE._is_sigpipe_safe_bootstrap(
                "strict-bootstrap-v2-adjudicated-continuation"
            )
        )
        self.assertFalse(MODULE._is_sigpipe_safe_bootstrap(None))

    def test_role_commands_follow_strict_security_group_paths(self) -> None:
        urls = {
            "receiver-a": "https://public.example:443/events",
            "receiver-b": "https://public.example:8443/events",
        }
        commands = {
            role: "\n".join(lines)
            for role, lines in MODULE._role_commands(urls).items()
        }

        self.assertIn("infrastructure-pilot.py", commands["driver"])
        self.assertNotIn(":9444", commands["driver"])
        self.assertNotIn("public.example", commands["receiver"])
        self.assertIn("public.example", commands["keycloak"])
        self.assertIn(":9444/health", commands["receiver"])
        self.assertIn("filesystem-effects:9443/health", commands["gateway"])
        self.assertIn("postgres-effects:9443/health", commands["gateway"])

    def test_driver_report_parser_requires_one_sanitized_report(self) -> None:
        report = {"assertions": {"safe": True}}
        output = "e-b24-driver-report=" + json.dumps(report) + "\n"
        self.assertEqual(MODULE._driver_report(output), report)
        with self.assertRaises(MODULE.PilotGateError):
            MODULE._driver_report("missing\n")

    def test_target_readiness_gate_requires_both_target_groups(self) -> None:
        with mock.patch.object(
            MODULE, "_healthy_target_group", side_effect=[True, True]
        ):
            result = MODULE._wait_target_groups_healthy(
                profile="test", region="us-east-1", timeout=30
            )
        self.assertTrue(result["passed"])
        self.assertEqual(
            result["target_groups"],
            {"paper-b-eb24-recv-a": True, "paper-b-eb24-recv-b": True},
        )

    def test_runner_source_contains_no_outcome_operation(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        lowered = source.lower()
        self.assertNotIn("/logout", lowered)
        self.assertNotIn("pending-events", lowered)
        self.assertNotIn("filesystem/write", lowered)
        self.assertNotIn("postgres/insert", lowered)
        self.assertNotIn("method=\"post\"", lowered)

    def test_driver_persists_sanitized_diagnostics_before_failure(self) -> None:
        source = (
            SCRIPT.parents[1] / "strict" / "infrastructure_pilot.py"
        ).read_text(encoding="utf-8")
        self.assertLess(
            source.index('args.output.write_text('),
            source.index('if not report["passed"]:'),
        )

    def test_driver_accepts_keycloak_admin_stream_id_wire_name(self) -> None:
        pilot_path = SCRIPT.parents[1] / "strict" / "infrastructure_pilot.py"
        spec = importlib.util.spec_from_file_location("strict_driver_pilot", pilot_path)
        assert spec is not None and spec.loader is not None
        pilot = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(pilot)

        self.assertTrue(pilot._stream_id_present({"streamId": "admin-wire-id"}))
        self.assertTrue(pilot._stream_id_present({"stream_id": "receiver-wire-id"}))
        self.assertFalse(pilot._stream_id_present({"streamId": ""}))


if __name__ == "__main__":
    unittest.main()
