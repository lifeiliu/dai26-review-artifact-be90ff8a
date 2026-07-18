"""OPA-backed enforcement adapter for the E-B25 independent-stack gate."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Mapping

from .keycloak_gateway_gate import ReplayVector
from .real_effect_gate import (
    EffectPlan,
    FilesystemEffectStore,
    canonical_json,
    parse_replay_vector,
    sha256_text,
)


E_B25_POLICY_VERSION = "e-b25-opa-policy-v1"
OPA_POLICY = """package revocation

import rego.v1

default allow := false

allow if {
    data.revocation.gateway_id == input.gateway_id
    not data.revocation.revocations[input.delegation_id]
}
"""


class OpaHttpClient:
    """Small client for OPA's documented policy and data REST APIs."""

    def __init__(self, base_url: str, *, timeout: float = 5.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _request(
        self,
        method: str,
        path: str,
        body: object | None = None,
        *,
        content_type: str = "application/json",
    ) -> object:
        data: bytes | None = None
        if body is not None:
            if content_type == "application/json":
                data = (canonical_json(body) + "\n").encode("utf-8")
            else:
                data = str(body).encode("utf-8")
        request = urllib.request.Request(
            f"{self.base_url}{path}",
            data=data,
            headers={"Content-Type": content_type, "Accept": "application/json"},
            method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                payload = response.read()
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"OPA returned HTTP {error.code}: {detail}") from error
        if not payload:
            return {}
        parsed = json.loads(payload)
        if not isinstance(parsed, (dict, list)):
            raise RuntimeError("OPA returned an invalid JSON payload")
        return parsed

    def health(self) -> bool:
        result = self._request("GET", "/health")
        return isinstance(result, dict)

    def install_policy(self, policy: str = OPA_POLICY) -> None:
        self._request(
            "PUT",
            "/v1/policies/e_b25_revocation",
            policy,
            content_type="text/plain",
        )

    def initialize_gateway(self, gateway_id: str) -> None:
        self._request(
            "PUT",
            "/v1/data/revocation",
            {"gateway_id": gateway_id, "revocations": {}},
        )

    def put_revocation(self, delegation_id: str, value: Mapping[str, object]) -> None:
        component = urllib.parse.quote(delegation_id, safe="")
        self._request(
            "PUT",
            f"/v1/data/revocation/revocations/{component}",
            dict(value),
        )

    def read_revocation(self, delegation_id: str) -> dict[str, object] | None:
        component = urllib.parse.quote(delegation_id, safe="")
        result = self._request(
            "GET", f"/v1/data/revocation/revocations/{component}"
        )
        if not isinstance(result, dict) or "result" not in result:
            return None
        value = result["result"]
        return dict(value) if isinstance(value, dict) else None

    def allowed(self, *, gateway_id: str, delegation_id: str) -> tuple[bool, object]:
        result = self._request(
            "POST",
            "/v1/data/revocation/allow",
            {"input": {"gateway_id": gateway_id, "delegation_id": delegation_id}},
        )
        if not isinstance(result, dict) or not isinstance(result.get("result"), bool):
            raise RuntimeError("OPA decision response does not contain a Boolean result")
        return bool(result["result"]), result


class OpaPolicyGateway:
    """Thin effect adapter; OPA, not this class, computes allow/deny."""

    def __init__(
        self,
        *,
        gateway_id: str,
        update_url: str,
        decision_url: str,
        allowlist: Mapping[str, ReplayVector],
        filesystem_store: FilesystemEffectStore | None,
        postgres_store: Any | None,
        timeout: float = 5.0,
    ) -> None:
        self.gateway_id = gateway_id
        self.update_client = OpaHttpClient(update_url, timeout=timeout)
        self.decision_client = OpaHttpClient(decision_url, timeout=timeout)
        self.allowlist = dict(allowlist)
        self.filesystem_store = filesystem_store
        self.postgres_store = postgres_store

    def _validated_plan(self, vector_payload: str) -> EffectPlan:
        vector = parse_replay_vector(vector_payload)
        expected = self.allowlist.get(vector.vector_id)
        if expected is None or expected != vector:
            raise ValueError("vector is not an exact member of the frozen E-B25 allowlist")
        return EffectPlan.from_vector(vector)

    def apply_revocation(
        self,
        *,
        delegation_id: str,
        event_id: str,
        channel: str,
        sequence: int,
    ) -> dict[str, object]:
        if sequence < 0:
            raise ValueError("revocation sequence must be non-negative")
        applied_at_ns = time.time_ns()
        value = {
            "event_id": event_id,
            "channel": channel,
            "sequence": sequence,
            "applied_at_ns": applied_at_ns,
            "policy_version": E_B25_POLICY_VERSION,
        }
        # The write uses the independently faulted control path. Readback and
        # decision use the direct data-plane path, so a receipt proves that the
        # policy engine itself installed and evaluated the new state.
        self.update_client.put_revocation(delegation_id, value)
        readback = self.decision_client.read_revocation(delegation_id)
        if readback != value:
            raise RuntimeError("OPA revocation readback did not match the applied value")
        allowed, decision = self.decision_client.allowed(
            gateway_id=self.gateway_id,
            delegation_id=delegation_id,
        )
        if allowed:
            raise RuntimeError("OPA still allowed the delegation after revocation write")
        receipt_material = {
            "gateway_id": self.gateway_id,
            "delegation_id": delegation_id,
            "event_id": event_id,
            "channel": channel,
            "sequence": sequence,
            "applied_at_ns": applied_at_ns,
            "policy_version": E_B25_POLICY_VERSION,
            "opa_readback": readback,
            "opa_decision": decision,
        }
        return {
            "applied": True,
            "receipt_id": sha256_text(canonical_json(receipt_material)),
            **receipt_material,
        }

    def status(self, delegation_id: str) -> dict[str, object]:
        value = self.decision_client.read_revocation(delegation_id)
        allowed, decision = self.decision_client.allowed(
            gateway_id=self.gateway_id,
            delegation_id=delegation_id,
        )
        return {
            "gateway_id": self.gateway_id,
            "delegation_id": delegation_id,
            "revoked": not allowed,
            "state": value,
            "opa_decision": decision,
            "policy_version": E_B25_POLICY_VERSION,
        }

    def execute_effect(
        self,
        *,
        delegation_id: str,
        experiment_run: str,
        arm: str,
        vector_payload: str,
    ) -> dict[str, object]:
        plan = self._validated_plan(vector_payload)
        decided_at_ns = time.time_ns()
        allowed, opa_response = self.decision_client.allowed(
            gateway_id=self.gateway_id,
            delegation_id=delegation_id,
        )
        effect: dict[str, object] | None = None
        if allowed:
            if plan.service == "filesystem" and self.filesystem_store is not None:
                effect = self.filesystem_store.commit(
                    plan,
                    experiment_run=experiment_run,
                    arm=arm,
                    delegation_id=delegation_id,
                )
            elif plan.service == "postgres" and self.postgres_store is not None:
                effect = self.postgres_store.commit(
                    plan,
                    experiment_run=experiment_run,
                    arm=arm,
                    delegation_id=delegation_id,
                )
            else:
                raise ValueError(f"no effect store for service {plan.service}")
        material = {
            "gateway_id": self.gateway_id,
            "delegation_id": delegation_id,
            "experiment_run": experiment_run,
            "arm": arm,
            "vector_id": plan.vector_id,
            "allowed": allowed,
            "opa_response": opa_response,
            "decided_at_ns": decided_at_ns,
        }
        return {
            "allowed": allowed,
            "reason": "opa-active-delegation" if allowed else "opa-revoked-delegation",
            "gateway_id": self.gateway_id,
            "delegation_id": delegation_id,
            "vector_id": plan.vector_id,
            "decision_id": sha256_text(canonical_json(material)),
            "decided_at_ns": decided_at_ns,
            "opa_response": opa_response,
            "effect": effect,
        }
