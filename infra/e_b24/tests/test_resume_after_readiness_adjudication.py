from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
SCRIPT = SCRIPTS / "resume_strict_services_after_readiness_adjudication.py"
SPEC = importlib.util.spec_from_file_location("readiness_adjudication", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def _fixture() -> tuple[dict[str, str], dict[str, object], dict[str, object]]:
    names = [
        "fault-controller",
        "filesystem-effects",
        *[f"gateway-{index}" for index in range(1, 9)],
        "keycloak",
        "keycloak-postgres",
        "postgres-effects",
        "receiver-a",
        "receiver-b",
        "workload-driver",
    ]
    by_name = {
        name: f"i-{index:016x}" for index, name in enumerate(names, start=1)
    }
    hosts = []
    for name, instance_id in by_name.items():
        failed = name == "gateway-4"
        hosts.append(
            {
                "host": name,
                "instance_id": instance_id,
                "status": "Failed" if failed else "Success",
                "response_code": 141 if failed else 0,
                "output": "status: done\n" if failed else "ready\n",
            }
        )
    source = {
        "failed": True,
        "waves": [],
        "host_readiness_gate": {
            "command_id": "readiness-1",
            "ready_host_count": 15,
            "hosts": hosts,
        },
    }
    diagnostic = {
        "CommandInvocations": [
            {
                "InstanceId": by_name["gateway-4"],
                "Status": "Success",
                "CommandPlugins": [
                    {
                        "ResponseCode": 0,
                        "Output": "\n".join(MODULE.REQUIRED_DIAGNOSTIC_SNIPPETS),
                    }
                ],
            }
        ]
    }
    return by_name, source, diagnostic


class AdjudicatedContinuationTests(unittest.TestCase):
    def test_valid_adjudication_runs_each_wave_once(self) -> None:
        by_name, source, diagnostic = _fixture()
        topology = {
            "protocol_stage": "strict-confirmatory-candidate-pilot",
            "hosts": {
                name: {"instance_id": instance_id}
                for name, instance_id in by_name.items()
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_path = root / "source.json"
            source_path.write_text(json.dumps(source), encoding="utf-8")
            argv = [
                str(SCRIPT),
                "--profile",
                "test",
                "--region",
                "us-east-1",
                "--source-report",
                str(source_path),
                "--diagnostic-command-id",
                "diagnostic-1",
                "--output-dir",
                str(root),
            ]
            with (
                mock.patch.object(MODULE, "_terraform_output", return_value=topology),
                mock.patch.object(MODULE, "_aws_json", return_value=diagnostic),
                mock.patch.object(
                    MODULE,
                    "_run_wave",
                    side_effect=lambda **kwargs: {
                        "wave": kwargs["name"],
                        "command_id": f"command-{kwargs['name']}",
                        "invocations": [],
                    },
                ) as run_wave,
                mock.patch.object(sys, "argv", argv),
            ):
                self.assertEqual(MODULE.main(), 0)
            report = json.loads(
                (root / "strict-service-bootstrap-adjudicated.json").read_text(
                    encoding="utf-8"
                )
            )
        self.assertFalse(report["failed"])
        self.assertTrue(report["readiness_adjudication"]["passed"])
        self.assertEqual(len(report["waves"]), 5)
        self.assertEqual(run_wave.call_count, 5)

    def test_incomplete_diagnostic_stops_before_service_waves(self) -> None:
        _, source, diagnostic = _fixture()
        diagnostic["CommandInvocations"][0]["CommandPlugins"][0]["Output"] = (
            "status: done\n"
        )
        with mock.patch.object(MODULE, "_aws_json", return_value=diagnostic):
            with self.assertRaises(RuntimeError):
                MODULE._adjudicate(
                    profile="test",
                    region="us-east-1",
                    source=source,
                    diagnostic_command_id="diagnostic-1",
                )


if __name__ == "__main__":
    unittest.main()
