from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "bootstrap_strict_services.py"
SERVICE_BOOTSTRAP = Path(__file__).resolve().parents[1] / "strict" / "service-bootstrap.sh"
CLOUD_INIT = Path(__file__).resolve().parents[1] / "strict" / "cloud-init.yaml.tftpl"
SPEC = importlib.util.spec_from_file_location("bootstrap_strict_services", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def _hosts() -> dict[str, str]:
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
    return {name: f"i-{index:016x}" for index, name in enumerate(names, start=1)}


class StrictReadinessBarrierTests(unittest.TestCase):
    def test_confirmatory_receivers_have_disjoint_four_gateway_targets(self) -> None:
        source = SERVICE_BOOTSTRAP.read_text(encoding="utf-8")
        self.assertIn('"${receiver_name}" == "receiver-a"', source)
        self.assertIn("first_gateway=1", source)
        self.assertIn("last_gateway=4", source)
        self.assertIn("first_gateway=5", source)
        self.assertIn("last_gateway=8", source)
        self.assertIn("range(first,last+1)", source)

    def test_cloud_init_uses_bounded_package_retry_before_services(self) -> None:
        source = CLOUD_INIT.read_text(encoding="utf-8")
        self.assertNotIn("\npackages:\n", source)
        self.assertIn("max_attempts=12", source)
        self.assertIn("dnf -y install docker jq chrony nftables", source)
        self.assertIn("sleep_seconds=$((attempt * 5))", source)
        self.assertIn("e-b24-package-bootstrap=failed", source)
        self.assertNotIn("dnf -y install docker jq chrony nftables || true", source)
        self.assertLess(
            source.index("- [/usr/local/sbin/e-b24-install-packages]"),
            source.index("- [systemctl, enable, --now, docker]"),
        )

    def test_keycloak_alone_has_a_360_second_https_readiness_budget(self) -> None:
        source = SERVICE_BOOTSTRAP.read_text(encoding="utf-8")
        self.assertIn('local attempts="${3:-90}"', source)
        self.assertIn('for _ in $(seq 1 "${attempts}")', source)

        calls = [
            line.strip()
            for line in source.splitlines()
            if line.strip().startswith("wait_https ")
        ]
        self.assertEqual(len(calls), 5)
        keycloak_calls = [line for line in calls if "e-b24-keycloak " in line]
        self.assertEqual(len(keycloak_calls), 1)
        self.assertTrue(keycloak_calls[0].endswith(" 180"))
        self.assertTrue(
            all(not line.endswith(" 180") for line in calls if line not in keycloak_calls)
        )

    def test_ssm_online_gate_requires_all_sixteen_hosts(self) -> None:
        by_name = _hosts()
        response = {
            "InstanceInformationList": [
                {"InstanceId": instance_id, "PingStatus": "Online"}
                for instance_id in by_name.values()
            ]
        }
        with mock.patch.object(MODULE, "_aws_json", return_value=response):
            result = MODULE._wait_ssm_online(
                profile="test",
                region="us-east-1",
                instance_ids=list(by_name.values()),
                timeout=30,
            )
        self.assertTrue(result["passed"])
        self.assertEqual(result["online_host_count"], 16)

    def test_host_readiness_gate_checks_cloud_init_docker_and_chrony(self) -> None:
        by_name = _hosts()
        captured: dict[str, object] = {}

        def send(*, profile: str, region: str, request: dict[str, object]) -> str:
            captured["request"] = request
            return "command-1"

        invocations = [
            {
                "InstanceId": instance_id,
                "Status": "Success",
                "StatusDetails": "Success",
                "CommandPlugins": [
                    {"ResponseCode": 0, "Output": "e-b24-readiness=passed\n"}
                ],
            }
            for instance_id in by_name.values()
        ]
        with (
            mock.patch.object(MODULE, "_send_command_request", side_effect=send),
            mock.patch.object(MODULE, "_wait_wave", return_value=invocations),
        ):
            result = MODULE._run_host_readiness_gate(
                profile="test", region="us-east-1", by_name=by_name, timeout=30
            )

        request = captured["request"]
        assert isinstance(request, dict)
        commands = "\n".join(request["Parameters"]["commands"])
        self.assertIn("cloud-init status --wait --long", commands)
        self.assertIn("systemctl is-active --quiet docker", commands)
        self.assertIn("docker info", commands)
        self.assertIn("chronyc tracking", commands)
        self.assertIn('case "$cloud_init_status"', commands)
        self.assertIn('case "$chrony_status"', commands)
        self.assertNotIn("| grep -q", commands)
        self.assertEqual(len(request["InstanceIds"]), 16)
        self.assertTrue(result["passed"])
        self.assertEqual(result["ready_host_count"], 16)

    def test_failed_readiness_gate_prevents_every_service_wave(self) -> None:
        by_name = _hosts()
        topology = {
            "protocol_stage": "strict-confirmatory-candidate-pilot",
            "hosts": {
                name: {"instance_id": instance_id}
                for name, instance_id in by_name.items()
            },
        }
        failed_result = {
            "passed": False,
            "expected_host_count": 16,
            "ready_host_count": 15,
            "hosts": [],
        }
        failure = MODULE.InfrastructureGateError(
            "host_readiness_gate", "15/16 passed", failed_result
        )
        with tempfile.TemporaryDirectory() as output_dir:
            argv = [
                str(SCRIPT),
                "--profile",
                "test",
                "--region",
                "us-east-1",
                "--output-dir",
                output_dir,
                "--timeout-seconds",
                "30",
            ]
            with (
                mock.patch.object(MODULE, "_terraform_output", return_value=topology),
                mock.patch.object(
                    MODULE,
                    "_wait_ssm_online",
                    return_value={"passed": True, "online_host_count": 16},
                ),
                mock.patch.object(
                    MODULE, "_run_host_readiness_gate", side_effect=failure
                ),
                mock.patch.object(MODULE, "_run_wave") as run_wave,
                mock.patch.object(sys, "argv", argv),
            ):
                with self.assertRaises(MODULE.InfrastructureGateError):
                    MODULE.main()

            run_wave.assert_not_called()
            report = json.loads(
                (Path(output_dir) / "strict-service-bootstrap.json").read_text(
                    encoding="utf-8"
                )
            )
        self.assertTrue(report["failed"])
        self.assertEqual(report["host_readiness_gate"]["ready_host_count"], 15)
        self.assertEqual(report["waves"], [])


if __name__ == "__main__":
    unittest.main()
