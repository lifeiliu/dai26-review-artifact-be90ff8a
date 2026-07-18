#!/usr/bin/env python3
"""Supervise E-B28 readiness or the frozen 60-run confirmatory gate."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable


HERE = Path(__file__).resolve().parent
ARTIFACT = HERE.parents[1]
REPO = ARTIFACT.parent
PROTOCOL = ARTIFACT / "protocols/e-b28-live-closed-loop-agent/protocol.md"
TARGETS_FILE = ARTIFACT / "data/run_2026_07_14_e_b20_mcpmark_formal/analysis/e_b20_targets.json"
REALM_FILE = ARTIFACT / "experiments/e_b22_keycloak_gateway_gate/realm-e-b22.json"
KEYCLOAK_IMAGE = "quay.io/keycloak/keycloak:26.7.0"
KEYCLOAK_DIGEST = "sha256:2eb3cd316835c990e69e26ade292ffa78f6fb0db7d5fc6377463c162e1979ac0"
POSTGRES_IMAGE = "pgvector/pgvector:0.8.0-pg17-bookworm"
POSTGRES_DIGEST = "sha256:40b404964359299eefdd5f8518facf1886c562848cf4de13b6eaf91cb70c2b87"
KEYCLOAK_CONTAINER = "revprop-keycloak-e-b22"
POSTGRES_CONTAINER = "revprop-keycloak-e-b22-postgres"
DOCKER_NETWORK = "revprop-keycloak-e-b22-network"
KEYCLOAK_BASE = "http://127.0.0.1:18082"
RECEIVER_BASE = "http://127.0.0.1:19002"
REALM = "ssf-smoke"
SESSION_REVOKED = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
TASK_TIMEOUT_SECONDS = 4200


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def http_request(
    url: str,
    *,
    method: str = "GET",
    json_body: dict[str, Any] | None = None,
    form: dict[str, str] | None = None,
    token: str | None = None,
    timeout: float = 20.0,
) -> tuple[int, Any]:
    headers: dict[str, str] = {"Accept": "application/json"}
    data: bytes | None = None
    if json_body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(json_body).encode("utf-8")
    elif form is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        data = urllib.parse.urlencode(form).encode("ascii")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as error:
        raw = error.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"{method} {url} -> {error.code}: {raw}") from error


def wait_for(predicate: Callable[[], bool], timeout: float, description: str) -> None:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            if predicate():
                return
        except Exception as error:
            last_error = error
        time.sleep(0.25)
    suffix = f"; last error: {last_error}" if last_error else ""
    raise TimeoutError(f"timed out waiting for {description}{suffix}")


def docker_cleanup() -> None:
    for container in (KEYCLOAK_CONTAINER, POSTGRES_CONTAINER):
        subprocess.run(["docker", "rm", "-f", container], check=False, capture_output=True)
    subprocess.run(["docker", "network", "rm", DOCKER_NETWORK], check=False, capture_output=True)


def start_postgres() -> str:
    subprocess.check_output(["docker", "network", "create", DOCKER_NETWORK], text=True)
    container = subprocess.check_output(
        [
            "docker", "run", "-d", "--rm", "--name", POSTGRES_CONTAINER,
            "--network", DOCKER_NETWORK,
            "-e", "POSTGRES_DB=keycloak",
            "-e", "POSTGRES_USER=keycloak",
            "-e", "POSTGRES_PASSWORD=keycloak-e-b22-password",
            f"{POSTGRES_IMAGE}@{POSTGRES_DIGEST}",
        ],
        text=True,
    ).strip()
    wait_for(
        lambda: subprocess.run(
            ["docker", "exec", POSTGRES_CONTAINER, "pg_isready", "-U", "keycloak", "-d", "keycloak"],
            capture_output=True,
        ).returncode == 0,
        30,
        "E-B28 Keycloak PostgreSQL readiness",
    )
    return container


def start_keycloak() -> str:
    return subprocess.check_output(
        [
            "docker", "run", "-d", "--rm", "--name", KEYCLOAK_CONTAINER,
            "--network", DOCKER_NETWORK, "-p", "18082:8080",
            "-e", "KC_BOOTSTRAP_ADMIN_USERNAME=admin",
            "-e", "KC_BOOTSTRAP_ADMIN_PASSWORD=admin-e-b22-password",
            "-e", "KC_DB=postgres",
            "-e", f"KC_DB_URL=jdbc:postgresql://{POSTGRES_CONTAINER}:5432/keycloak",
            "-e", "KC_DB_USERNAME=keycloak",
            "-e", "KC_DB_PASSWORD=keycloak-e-b22-password",
            "-v", f"{REALM_FILE}:/opt/keycloak/data/import/ssf-smoke-realm.json:ro",
            f"{KEYCLOAK_IMAGE}@{KEYCLOAK_DIGEST}",
            "start-dev", "--import-realm", "--features=ssf",
            "--spi-ssf-transmitter--default--allow-insecure-push-targets=true",
        ],
        text=True,
    ).strip()


def admin_token() -> str:
    return str(http_request(
        f"{KEYCLOAK_BASE}/realms/master/protocol/openid-connect/token",
        method="POST",
        form={
            "grant_type": "password", "client_id": "admin-cli",
            "username": "admin", "password": "admin-e-b22-password",
        },
    )[1]["access_token"])


def create_stream(receiver: str, token: str) -> dict[str, Any]:
    status, body = http_request(
        f"{KEYCLOAK_BASE}/admin/realms/{REALM}/ssf/clients/{receiver}/stream",
        method="POST",
        json_body={
            "description": f"E-B28 live closed-loop stream for {receiver}",
            "events_requested": [SESSION_REVOKED],
            "delivery": {
                "method": "urn:ietf:rfc:8935",
                "endpoint_url": f"http://host.docker.internal:19002/{receiver}",
                "authorization_header": f"Bearer {receiver}-e-b22",
            },
        },
        token=token,
    )
    if status != 201 or not isinstance(body, dict):
        raise RuntimeError(f"Keycloak stream creation failed for {receiver}: {status} {body}")
    return body


def frozen_targets() -> tuple[str, ...]:
    document = json.loads(TARGETS_FILE.read_text(encoding="utf-8"))
    targets = tuple(str(item) for item in document["targets"])
    if len(targets) != 10 or len(set(targets)) != 10:
        raise RuntimeError("E-B28 requires the exact ten unique E-B20 targets")
    if sum(target.startswith("filesystem/") for target in targets) != 4:
        raise RuntimeError("frozen E-B20 target set lost its four filesystem tasks")
    if sum(target.startswith("postgres/") for target in targets) != 6:
        raise RuntimeError("frozen E-B20 target set lost its six postgres tasks")
    return targets


def formal_schedule() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for repetition in (1, 2):
        for index, target in enumerate(frozen_targets()):
            comparison = (
                ("normal_c4", "selective_c3")
                if (index + repetition) % 2 == 1
                else ("selective_c3", "normal_c4")
            )
            for arm in ("active_sanity", *comparison):
                rows.append({"target": target, "arm": arm, "repetition": repetition, "qualification": False})
    if len(rows) != 60:
        raise AssertionError(f"formal schedule has {len(rows)} rows, expected 60")
    return rows


def smoke_schedule() -> list[dict[str, Any]]:
    targets = (
        "filesystem/desktop/project_management",
        "postgres/employees/executive_dashboard_automation",
    )
    return [
        {"target": target, "arm": arm, "repetition": 1, "qualification": False}
        for target in targets
        for arm in ("active_sanity", "normal_c4", "selective_c3")
    ]


def recovery_schedule() -> list[dict[str, Any]]:
    return [
        {
            "target": "filesystem/desktop/project_management",
            "arm": "recovery_c4", "repetition": 1, "qualification": True,
        },
        {
            "target": "postgres/employees/executive_dashboard_automation",
            "arm": "recovery_c4", "repetition": 1, "qualification": True,
        },
    ]


def run_id(index: int, row: dict[str, Any]) -> str:
    target_slug = str(row["target"]).replace("/", "-")
    prefix = "q" if row.get("qualification") else "t"
    return f"e-b28-{prefix}{index:03d}-r{row['repetition']}-{row['arm']}-{target_slug}"


def register_receiver(identifier: str, arm: str) -> None:
    action = "withhold" if arm == "selective_c3" else "forward"
    status, _ = http_request(
        f"{RECEIVER_BASE}/control/register",
        method="POST",
        json_body={"run_id": identifier, "arm": arm, "receiver_b_action": action},
    )
    if status != 201:
        raise RuntimeError(f"receiver registration returned {status}")


def append_jsonl(path: Path, value: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(canonical_json(value) + "\n")


def run_one(
    *, index: int, total: int, row: dict[str, Any], output_dir: Path, mcpmark_root: Path,
) -> dict[str, Any]:
    identifier = run_id(index, row)
    task_dir = output_dir / "tasks" / identifier
    stdout_path = output_dir / "logs" / f"{identifier}.stdout.log"
    stderr_path = output_dir / "logs" / f"{identifier}.stderr.log"
    interpreter = mcpmark_root / ".venv/bin/python"
    if not interpreter.is_file():
        raise FileNotFoundError(f"frozen MCPMark interpreter is unavailable: {interpreter}")
    command = [
        str(interpreter), str(HERE / "run_task.py"),
        "--mcpmark-root", str(mcpmark_root),
        "--output-dir", str(task_dir),
        "--target", str(row["target"]),
        "--arm", str(row["arm"]),
        "--repetition", str(row["repetition"]),
        "--run-id", identifier,
    ]
    started = time.time_ns()
    print(
        f"E-B28 START {index}/{total} {identifier} target={row['target']} arm={row['arm']}",
        flush=True,
    )
    if row["arm"] != "active_sanity":
        try:
            register_receiver(identifier, str(row["arm"]))
        except Exception as error:
            result = {
                **row,
                "index": index,
                "run_id": identifier,
                "command": command,
                "started_unix_ns": started,
                "finished_unix_ns": time.time_ns(),
                "returncode": None,
                "timed_out": False,
                "summary_present": False,
                "trace_valid": False,
                "summary": None,
                "pre_execution_error": f"{type(error).__name__}: {error}",
            }
            stderr_path.write_text(result["pre_execution_error"] + "\n", encoding="utf-8")
            stdout_path.write_text("", encoding="utf-8")
            print(
                f"E-B28 END   {index}/{total} {identifier} rc=NA valid=False "
                f"pre_execution_error={type(error).__name__}",
                flush=True,
            )
            return result
    timed_out = False
    with stdout_path.open("w", encoding="utf-8") as stdout, stderr_path.open("w", encoding="utf-8") as stderr:
        process = subprocess.Popen(command, cwd=REPO, stdout=stdout, stderr=stderr, env=os.environ.copy())
        try:
            returncode = process.wait(timeout=TASK_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
            returncode = 124
        except KeyboardInterrupt:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
            raise
    summary_path = task_dir / "task_summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8")) if summary_path.exists() else None
    result = {
        **row,
        "index": index,
        "run_id": identifier,
        "command": command,
        "started_unix_ns": started,
        "finished_unix_ns": time.time_ns(),
        "returncode": returncode,
        "timed_out": timed_out,
        "summary_present": summary is not None,
        "trace_valid": bool(summary and summary.get("trace_valid") and returncode == 0),
        "summary": summary,
    }
    print(
        f"E-B28 END   {index}/{total} {identifier} rc={returncode} "
        f"valid={result['trace_valid']} effects={summary.get('post_barrier_effect_commits') if summary else 'NA'}",
        flush=True,
    )
    return result


def analyze(rows: list[dict[str, Any]], *, mode: str) -> dict[str, Any]:
    formal = [row for row in rows if not row.get("qualification")]
    qualifications = [row for row in rows if row.get("qualification")]
    summaries = [row["summary"] for row in formal if row.get("summary")]
    invalid = [row["run_id"] for row in formal if not row.get("trace_valid")]
    no_exposure = [
        row["run_id"] for row in formal
        if row.get("summary") and row["summary"].get("exposure_status") == "NO_EXPOSURE"
    ]
    normal_effects = sum(
        int(summary["post_barrier_effect_commits"])
        for summary in summaries if summary["arm"] == "normal_c4"
    )
    selective_effects = {
        service: sum(
            int(summary["post_barrier_effect_commits"])
            for summary in summaries
            if summary["arm"] == "selective_c3" and summary["service"] == service
        )
        for service in ("filesystem", "postgres")
    }
    if invalid:
        support = "INCONCLUSIVE_INVALID_TASK_RUNS"
    elif normal_effects != 0:
        support = "INCONCLUSIVE_NORMAL_ARM_EFFECT"
    elif all(value >= 1 for value in selective_effects.values()):
        support = "SUPPORTED_BOTH_SERVICES"
    elif any(value >= 1 for value in selective_effects.values()):
        support = "PARTIAL_ONE_SERVICE"
    else:
        support = "NOT_SUPPORTED_NO_SELECTIVE_POST_BARRIER_EFFECT"
    return {
        "mode": mode,
        "formal_task_run_count": len(formal),
        "valid_formal_task_run_count": len(formal) - len(invalid),
        "invalid_formal_run_ids": invalid,
        "no_exposure_run_ids": no_exposure,
        "normal_post_barrier_effect_commits": normal_effects,
        "selective_post_barrier_effect_commits_by_service": selective_effects,
        "support_gate": support,
        "recovery_qualification_count": len(qualifications),
        "valid_recovery_qualification_count": sum(row.get("trace_valid") is True for row in qualifications),
        "clean_recovery_qualification": (
            len(qualifications) == 2 and all(row.get("trace_valid") is True for row in qualifications)
        ) if mode == "formal" else None,
    }


def save_container_logs(output_dir: Path) -> None:
    for container, name in ((KEYCLOAK_CONTAINER, "keycloak.log"), (POSTGRES_CONTAINER, "keycloak-postgres.log")):
        completed = subprocess.run(["docker", "logs", container], capture_output=True, text=True, check=False)
        (output_dir / "logs" / name).write_text(completed.stdout + completed.stderr, encoding="utf-8")


def freeze_manifest(*, output_dir: Path, mode: str, schedule: list[dict[str, Any]]) -> dict[str, Any]:
    source_files = [
        HERE / "run_gate.py",
        HERE / "run_task.py",
        HERE / "receiver.py",
        ARTIFACT / "src/revocation_propagation/e_b28_mcpmark_instrumentation.py",
        ARTIFACT / "src/revocation_propagation/completion_contract.py",
        ARTIFACT / "src/revocation_propagation/e_b24_receiver.py",
        PROTOCOL,
        TARGETS_FILE,
        REALM_FILE,
    ]
    manifest = {
        "experiment": "E-B28",
        "mode": mode,
        "status": "PRE-EXECUTION-FROZEN" if mode == "formal" else "READINESS_SMOKE",
        "created_unix_ns": time.time_ns(),
        "schedule": schedule,
        "schedule_sha256": hashlib.sha256(canonical_json(schedule).encode()).hexdigest(),
        "source_sha256": {str(path.relative_to(REPO)): sha256(path) for path in source_files},
        "external_mcpmark_commit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=REPO / "external/MCPMark", text=True
        ).strip(),
        "model": "openai/gpt-4.1-mini",
        "keycloak_image": KEYCLOAK_IMAGE,
        "keycloak_digest": KEYCLOAK_DIGEST,
        "postgres_image": POSTGRES_IMAGE,
        "postgres_digest": POSTGRES_DIGEST,
        "task_timeout_seconds": TASK_TIMEOUT_SECONDS,
        "platform": platform.platform(),
        "python": sys.version,
        "openrouter_key_present": bool(os.environ.get("OPENROUTER_API_KEY")),
    }
    path = output_dir / "pre_execution_manifest.json"
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (output_dir / "pre_execution_manifest.sha256").write_text(f"{sha256(path)}  {path.name}\n", encoding="utf-8")
    return manifest


def run(*, mode: str, output_dir: Path, mcpmark_root: Path, keep_infrastructure: bool) -> dict[str, Any]:
    if output_dir.exists():
        raise FileExistsError(f"E-B28 output already exists: {output_dir}")
    if mode == "formal" and "PRE-EXECUTION-FROZEN" not in PROTOCOL.read_text(encoding="utf-8"):
        raise RuntimeError("formal E-B28 requires a PRE-EXECUTION-FROZEN protocol")
    output_dir.mkdir(parents=True)
    (output_dir / "tasks").mkdir()
    (output_dir / "logs").mkdir()
    progress_path = output_dir / "progress.jsonl"
    progress_path.write_text("", encoding="utf-8")
    schedule = formal_schedule() + recovery_schedule() if mode == "formal" else smoke_schedule()
    (output_dir / "schedule.json").write_text(json.dumps(schedule, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    manifest = freeze_manifest(output_dir=output_dir, mode=mode, schedule=schedule)
    receiver_log = (output_dir / "logs/receiver.log").open("w", encoding="utf-8")
    receiver = subprocess.Popen(
        [sys.executable, str(HERE / "receiver.py"), "--sqlite", str(output_dir / "receiver.sqlite3")],
        cwd=REPO,
        stdout=receiver_log,
        stderr=subprocess.STDOUT,
    )
    rows: list[dict[str, Any]] = []
    infrastructure: dict[str, Any] = {}
    docker_cleanup()
    try:
        wait_for(lambda: http_request(f"{RECEIVER_BASE}/health")[0] == 200, 15, "E-B28 receiver")
        infrastructure["keycloak_postgres_container_id"] = start_postgres()
        infrastructure["keycloak_container_id"] = start_keycloak()
        wait_for(
            lambda: http_request(f"{KEYCLOAK_BASE}/realms/{REALM}/.well-known/ssf-configuration")[0] == 200,
            180,
            "E-B28 Keycloak SSF discovery",
        )
        token = admin_token()
        infrastructure["streams"] = {
            receiver_name: create_stream(receiver_name, token)
            for receiver_name in ("receiver-a", "receiver-b")
        }
        infrastructure["mcpmark_postgres_ready"] = subprocess.run(
            ["docker", "exec", "mcpmark-postgres", "pg_isready", "-U", "postgres", "-d", "postgres"],
            capture_output=True,
        ).returncode == 0
        if not infrastructure["mcpmark_postgres_ready"]:
            raise RuntimeError("existing MCPMark PostgreSQL service is not ready")
        total = len(schedule)
        for index, row in enumerate(schedule, 1):
            result = run_one(
                index=index, total=total, row=row, output_dir=output_dir,
                mcpmark_root=mcpmark_root,
            )
            rows.append(result)
            append_jsonl(progress_path, result)
        analysis = analyze(rows, mode=mode)
        summary = {
            "experiment": "E-B28",
            "mode": mode,
            "manifest_sha256": sha256(output_dir / "pre_execution_manifest.json"),
            "schedule_sha256": manifest["schedule_sha256"],
            "infrastructure": infrastructure,
            "analysis": analysis,
            "rows": rows,
            "finished_unix_ns": time.time_ns(),
        }
        (output_dir / "summary.json").write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return summary
    finally:
        try:
            save_container_logs(output_dir)
        finally:
            if not keep_infrastructure:
                docker_cleanup()
            receiver.terminate()
            try:
                receiver.wait(timeout=5)
            except subprocess.TimeoutExpired:
                receiver.kill()
                receiver.wait(timeout=5)
            receiver_log.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("smoke", "formal"), required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--mcpmark-root", type=Path, required=True)
    parser.add_argument("--keep-infrastructure", action="store_true")
    args = parser.parse_args()
    try:
        summary = run(
            mode=args.mode,
            output_dir=args.output_dir.resolve(),
            mcpmark_root=args.mcpmark_root.resolve(),
            keep_infrastructure=args.keep_infrastructure,
        )
    except Exception as error:
        print(f"E-B28 ERROR: {type(error).__name__}: {error}", file=sys.stderr, flush=True)
        return 1
    print(json.dumps(summary["analysis"], indent=2, sort_keys=True), flush=True)
    invalid = summary["analysis"]["invalid_formal_run_ids"]
    return 0 if not invalid else 2


if __name__ == "__main__":
    raise SystemExit(main())
