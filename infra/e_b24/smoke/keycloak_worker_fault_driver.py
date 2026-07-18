#!/usr/bin/env python3
"""Two-phase external receiver-worker fault smoke for E-B24."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import time
from contextlib import AsyncExitStack
from datetime import datetime, timedelta, timezone
from pathlib import Path

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

import keycloak_push_driver as common
from revocation_propagation.e_b24_cloud_effects import RemoteEffectStore


REALM = "ssf-smoke"


def _load_vectors(path: Path) -> tuple[str, dict[str, dict[str, object]]]:
    body_bytes = path.read_bytes()
    digest = hashlib.sha256(body_bytes).hexdigest()
    if digest != common.EXPECTED_ALLOWLIST_SHA256:
        raise ValueError("frozen allowlist hash mismatch")
    body = json.loads(body_bytes)
    if body.get("vector_count") != 225:
        raise ValueError("frozen allowlist vector count changed")
    vectors = body.get("vectors", [])
    return digest, {
        service: next(vector for vector in vectors if vector["service"] == service)
        for service in ("filesystem", "postgres")
    }


def _effect_clients(args: argparse.Namespace) -> dict[str, RemoteEffectStore]:
    token = common._secret(args.effect_token_file)
    return {
        service: RemoteEffectStore(
            service=service,
            base_url=args.effect_url,
            bearer_token=token,
            ca_file=str(args.ca_file),
        )
        for service in ("filesystem", "postgres")
    }


async def _open_session(stack: AsyncExitStack, endpoint: str) -> ClientSession:
    read_stream, write_stream, _ = await stack.enter_async_context(
        streamable_http_client(endpoint, terminate_on_close=True)
    )
    session = await stack.enter_async_context(
        ClientSession(
            read_stream,
            write_stream,
            read_timeout_seconds=timedelta(seconds=30),
        )
    )
    await session.initialize()
    return session


async def _execute_pair(
    session: ClientSession,
    *,
    delegation_id: str,
    experiment_run: str,
    arm: str,
    selected: dict[str, dict[str, object]],
) -> dict[str, dict[str, object]]:
    decisions: dict[str, dict[str, object]] = {}
    for service in ("filesystem", "postgres"):
        result = await common._tool(
            session,
            "execute_effect",
            {
                "delegation_id": delegation_id,
                "experiment_run": experiment_run,
                "arm": arm,
                "vector_payload": json.dumps(
                    selected[service], sort_keys=True, separators=(",", ":")
                ),
            },
        )
        decisions[service] = common._decision_summary(result)
    return decisions


async def fault_phase(args: argparse.Namespace) -> dict[str, object]:
    digest, selected = _load_vectors(args.allowlist)
    effects = _effect_clients(args)
    keycloak_base = args.keycloak_url.rstrip("/")
    admin_password = common._secret(args.keycloak_admin_password_file)
    _, token_body = common._http(
        f"{keycloak_base}/realms/master/protocol/openid-connect/token",
        ca_file=args.ca_file,
        method="POST",
        form={
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": "admin",
            "password": admin_password,
        },
    )
    admin_token = str(token_body["access_token"])
    stats_before = common._http(
        f"{keycloak_base}/admin/realms/{REALM}/ssf/events/stats",
        ca_file=args.ca_file,
        bearer_token=admin_token,
    )[1]
    _, login = common._http(
        f"{keycloak_base}/realms/{REALM}/protocol/openid-connect/token",
        ca_file=args.ca_file,
        method="POST",
        form={
            "grant_type": "password",
            "client_id": "workload-client",
            "username": "alice",
            "password": "alice-smoke-password",
        },
    )
    delegation_id = str(login["session_state"])
    experiment_run = f"{args.run_id}-worker-stopped"
    arm = "keycloak-202-receiver-worker-stopped"

    async with AsyncExitStack() as stack:
        session = await _open_session(stack, args.gateway_mcp_url)
        status_before = await common._tool(
            session, "gateway_status", {"delegation_id": delegation_id}
        )
        logout_status, _ = common._http(
            f"{keycloak_base}/realms/{REALM}/protocol/openid-connect/logout",
            ca_file=args.ca_file,
            method="POST",
            form={
                "client_id": "workload-client",
                "refresh_token": str(login["refresh_token"]),
            },
        )
        delivered_deadline = time.monotonic() + 30
        while True:
            stats_after = common._http(
                f"{keycloak_base}/admin/realms/{REALM}/ssf/events/stats",
                ca_file=args.ca_file,
                bearer_token=admin_token,
            )[1]
            if common._status_count(stats_after, "DELIVERED") > common._status_count(
                stats_before, "DELIVERED"
            ):
                break
            if time.monotonic() >= delivered_deadline:
                raise TimeoutError("Keycloak did not record delivery while worker was stopped")
            await asyncio.sleep(0.25)
        await asyncio.sleep(args.stale_observation_seconds)
        status_during_fault = await common._tool(
            session, "gateway_status", {"delegation_id": delegation_id}
        )
        decisions = await _execute_pair(
            session,
            delegation_id=delegation_id,
            experiment_run=experiment_run,
            arm=arm,
            selected=selected,
        )

    oracles = {
        service: effects[service].oracle(experiment_run=experiment_run, arm=arm)
        for service in ("filesystem", "postgres")
    }
    assertions = {
        "frozen_allowlist_unchanged": digest == common.EXPECTED_ALLOWLIST_SHA256,
        "status_started_active": status_before.get("revoked") is False,
        "keycloak_logout_succeeded": logout_status in {200, 204},
        "keycloak_transport_acknowledged": (
            common._status_count(stats_after, "DELIVERED")
            > common._status_count(stats_before, "DELIVERED")
        ),
        "gateway_still_active_with_worker_stopped": (
            status_during_fault.get("revoked") is False
        ),
        "stale_filesystem_effect_committed": (
            decisions["filesystem"]["allowed"] is True
            and decisions["filesystem"]["effect_committed"] is True
            and oracles["filesystem"].get("count") == 1
        ),
        "stale_postgres_effect_committed": (
            decisions["postgres"]["allowed"] is True
            and decisions["postgres"]["effect_committed"] is True
            and oracles["postgres"].get("count") == 1
        ),
    }
    if not all(assertions.values()):
        raise RuntimeError(f"one or more worker-fault assertions failed: {assertions}")
    return {
        "experiment": "E-B24 external receiver-worker stop smoke",
        "phase": "fault",
        "claim_boundary": (
            "Three-host smoke only; the worker was stopped externally after startup. "
            "This is not a selective-non-delivery incidence estimate or confirmatory run."
        ),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "run_id": args.run_id,
        "delegation_id": delegation_id,
        "frozen_allowlist_sha256": digest,
        "stale_observation_seconds": args.stale_observation_seconds,
        "logout_http_status": logout_status,
        "keycloak_outbox": {
            "delivered_before": common._status_count(stats_before, "DELIVERED"),
            "delivered_after": common._status_count(stats_after, "DELIVERED"),
            "pending_after": common._status_count(stats_after, "PENDING"),
        },
        "status_before": status_before,
        "status_during_fault": status_during_fault,
        "decisions": decisions,
        "oracles": oracles,
        "assertions": assertions,
    }


async def recovery_phase(args: argparse.Namespace) -> dict[str, object]:
    digest, selected = _load_vectors(args.allowlist)
    effects = _effect_clients(args)
    experiment_run = f"{args.run_id}-recovered"
    arm = "receiver-worker-recovered"
    async with AsyncExitStack() as stack:
        session = await _open_session(stack, args.gateway_mcp_url)
        deadline = time.monotonic() + 30
        while True:
            status = await common._tool(
                session, "gateway_status", {"delegation_id": args.delegation_id}
            )
            if status.get("revoked") is True:
                break
            if time.monotonic() >= deadline:
                raise TimeoutError("restarted receiver worker did not enforce within 30 seconds")
            await asyncio.sleep(0.25)
        decisions = await _execute_pair(
            session,
            delegation_id=args.delegation_id,
            experiment_run=experiment_run,
            arm=arm,
            selected=selected,
        )
    oracles = {
        service: effects[service].oracle(experiment_run=experiment_run, arm=arm)
        for service in ("filesystem", "postgres")
    }
    assertions = {
        "frozen_allowlist_unchanged": digest == common.EXPECTED_ALLOWLIST_SHA256,
        "gateway_enforced_after_worker_restart": (
            status.get("revoked") is True
            and status.get("learned_via") == "keycloak-push"
            and bool(status.get("event_id"))
        ),
        "recovered_filesystem_denied_without_effect": (
            decisions["filesystem"]["allowed"] is False
            and decisions["filesystem"]["effect_committed"] is None
            and oracles["filesystem"].get("count") == 0
        ),
        "recovered_postgres_denied_without_effect": (
            decisions["postgres"]["allowed"] is False
            and decisions["postgres"]["effect_committed"] is None
            and oracles["postgres"].get("count") == 0
        ),
    }
    if not all(assertions.values()):
        raise RuntimeError(f"one or more recovery assertions failed: {assertions}")
    return {
        "experiment": "E-B24 external receiver-worker recovery smoke",
        "phase": "recovery",
        "claim_boundary": "Three-host smoke recovery only; not a confirmatory run.",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "run_id": args.run_id,
        "delegation_id": args.delegation_id,
        "receiver_jti": status.get("event_id"),
        "frozen_allowlist_sha256": digest,
        "gateway_status": status,
        "decisions": decisions,
        "oracles": oracles,
        "assertions": assertions,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=("fault", "recovery"))
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--delegation-id")
    parser.add_argument("--keycloak-url")
    parser.add_argument("--gateway-mcp-url", required=True)
    parser.add_argument("--effect-url", required=True)
    parser.add_argument("--allowlist", type=Path, required=True)
    parser.add_argument("--ca-file", type=Path, required=True)
    parser.add_argument("--keycloak-admin-password-file", type=Path)
    parser.add_argument("--effect-token-file", type=Path, required=True)
    parser.add_argument("--stale-observation-seconds", type=float, default=3.0)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.phase == "fault":
        if not args.keycloak_url or not args.keycloak_admin_password_file:
            parser.error("fault phase requires Keycloak URL and admin password file")
        evidence = asyncio.run(fault_phase(args))
    else:
        if not args.delegation_id:
            parser.error("recovery phase requires a delegation ID")
        evidence = asyncio.run(recovery_phase(args))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"assertions": evidence["assertions"], "run_id": args.run_id}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
