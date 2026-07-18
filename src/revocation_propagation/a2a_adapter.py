"""A2A-shaped bindings used as deployability substrates for the experiments."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from .events import RevocationEvent

REVPROP_A2A_EXTENSION_URI = "https://revprop.dev/a2a/extensions/revocation-lifecycle/v1"
REVPROP_A2A_PROTOCOL_VERSION = "revprop-a2a-lifecycle-v1"


def agent_card_extension(
    *,
    revocation_log_url: str,
    root_threshold: int,
    root_ids: list[str],
) -> dict[str, object]:
    """Return a minimal Agent Card extension for revocation propagation."""

    return {
        "x-revocation-propagation": {
            "eventTarget": "paper-a-edge",
            "logUrl": revocation_log_url,
            "rootThreshold": root_threshold,
            "rootIds": root_ids,
        }
    }


def revocation_protocol_extension(
    *,
    revocation_log_url: str,
    root_threshold: int,
    root_ids: Sequence[str],
    protocol_version: str = REVPROP_A2A_PROTOCOL_VERSION,
    required: bool = False,
    lifecycle_events: Sequence[str] = ("TaskStatusUpdateEvent",),
    freshness_policy: str = "deny-after-revocation-or-ttl",
) -> dict[str, object]:
    """Return an A2A Agent Card extension for lifecycle-bound revocation."""

    return {
        "extensions": [
            {
                "uri": REVPROP_A2A_EXTENSION_URI,
                "required": required,
                "params": {
                    "protocolVersion": protocol_version,
                    "eventTarget": "paper-a-edge",
                    "logUrl": revocation_log_url,
                    "rootThreshold": root_threshold,
                    "rootIds": list(root_ids),
                    "lifecycleEvents": list(lifecycle_events),
                    "freshnessPolicy": freshness_policy,
                },
            }
        ],
        "capabilities": {
            "revocationProtocol": {
                "version": protocol_version,
                "eventTarget": "paper-a-edge",
                "logUrl": revocation_log_url,
                "rootThreshold": root_threshold,
                "rootIds": list(root_ids),
                "lifecycleEvents": list(lifecycle_events),
                "freshnessPolicy": freshness_policy,
            }
        },
    }


def a2a_agent_card(
    *,
    agent_name: str,
    endpoint_url: str,
    revocation_log_url: str,
    root_threshold: int,
    root_ids: Sequence[str],
    supports_revocation: bool,
) -> dict[str, object]:
    """Build a minimal A2A Agent Card with optional RevProp support."""

    card: dict[str, object] = {
        "name": agent_name,
        "version": "0.1.0",
        "url": endpoint_url,
        "capabilities": {
            "streaming": True,
            "pushNotifications": True,
        },
        "skills": [
            {
                "id": "delegated-tool-use",
                "name": "Delegated Tool Use",
                "description": "Executes delegated tool tasks for the evaluation harness.",
            }
        ],
    }
    if supports_revocation:
        extension = revocation_protocol_extension(
            revocation_log_url=revocation_log_url,
            root_threshold=root_threshold,
            root_ids=root_ids,
        )
        capabilities = dict(card["capabilities"]) if isinstance(card["capabilities"], dict) else {}
        capabilities.update(extension["capabilities"])  # type: ignore[arg-type]
        card["capabilities"] = capabilities
        card["extensions"] = extension["extensions"]
    return card


def agent_card_supports_revocation(card: Mapping[str, object]) -> bool:
    """Return whether a card advertises the RevProp A2A lifecycle extension."""

    capabilities = card.get("capabilities")
    if isinstance(capabilities, Mapping) and "revocationProtocol" in capabilities:
        return True
    extensions = card.get("extensions")
    if isinstance(extensions, Sequence) and not isinstance(extensions, (str, bytes)):
        for extension in extensions:
            if isinstance(extension, Mapping) and extension.get("uri") == REVPROP_A2A_EXTENSION_URI:
                return True
    return "x-revocation-propagation" in card


def task_status_update_binding(event: RevocationEvent) -> dict[str, object]:
    """Represent a revocation event as a TaskStatusUpdateEvent-like payload."""

    return {
        "kind": "TaskStatusUpdateEvent",
        "status": {
            "state": "revocation-issued",
            "metadata": {
                "edgeId": event.edge_id,
                "epochId": event.epoch_id,
                "eventId": event.event_id,
                "issuerKeyId": event.issuer_key_id,
                "issuedAt": event.issued_at,
                "targetType": event.target_type,
            },
        },
    }


def task_lifecycle_revocation_binding(
    event: RevocationEvent,
    *,
    task_id: str,
    context_id: str | None = None,
    enforcement_action: str = "abort-task",
    protocol_version: str = REVPROP_A2A_PROTOCOL_VERSION,
    freshness_policy: str = "deny-after-revocation-or-ttl",
) -> dict[str, object]:
    """Represent revocation as a concrete A2A task lifecycle update."""

    status: dict[str, object] = {
        "state": "canceled",
        "metadata": {
            "edgeId": event.edge_id,
            "epochId": event.epoch_id,
            "eventId": event.event_id,
            "issuerKeyId": event.issuer_key_id,
            "issuedAt": event.issued_at,
            "targetType": event.target_type,
            "protocolVersion": protocol_version,
            "extensionUri": REVPROP_A2A_EXTENSION_URI,
            "freshnessPolicy": freshness_policy,
            "enforcementAction": enforcement_action,
        },
    }
    payload: dict[str, object] = {
        "kind": "TaskStatusUpdateEvent",
        "taskId": task_id,
        "status": status,
        "final": True,
    }
    if context_id is not None:
        payload["contextId"] = context_id
    return payload


def validate_task_lifecycle_revocation_binding(payload: Mapping[str, object]) -> bool:
    """Check the fields E-B9 relies on for A2A lifecycle binding."""

    if payload.get("kind") != "TaskStatusUpdateEvent" or not payload.get("taskId"):
        return False
    status = payload.get("status")
    if not isinstance(status, Mapping) or status.get("state") != "canceled":
        return False
    metadata = status.get("metadata")
    if not isinstance(metadata, Mapping):
        return False
    required = {
        "edgeId",
        "epochId",
        "eventId",
        "issuerKeyId",
        "issuedAt",
        "targetType",
        "protocolVersion",
        "extensionUri",
        "freshnessPolicy",
        "enforcementAction",
    }
    return required.issubset(metadata)
