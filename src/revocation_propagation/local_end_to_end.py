"""Local end-to-end revocation propagation over loopback JSONL transport."""

from __future__ import annotations

import asyncio
import json
import random
import time
from dataclasses import dataclass, field
from typing import Any, Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .crypto import KeyPair, canonical_json_bytes, generate_keypair
from .events import RevocationEvent, create_revocation_event, verify_revocation_event
from .ledger_client import SignedTreeHead, TransparencyLedger
from .propagator import PropagationStrategy
from .root_authority import RootApproval, RootCertificate, RootFederation, RootAuthority

HOST = "127.0.0.1"


@dataclass
class TransportCounters:
    requests: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    errors: int = 0
    push_attempts: int = 0
    push_delivered: int = 0
    push_suppressed: int = 0
    gossip_attempts: int = 0
    gossip_delivered: int = 0
    gossip_suppressed: int = 0
    log_polls: int = 0
    log_poll_suppressed: int = 0
    log_appends: int = 0


@dataclass
class LocalPartyState:
    party_id: str
    first_seen_at: float | None = None
    via: str | None = None
    event_payload: dict[str, Any] | None = None
    certificate_payload: dict[str, Any] | None = None
    accepted_events: int = 0
    rejected_events: int = 0
    signature_verified_events: int = 0
    certificate_verified_events: int = 0

    @property
    def has_event(self) -> bool:
        return self.event_payload is not None


@dataclass
class LocalEndToEndResult:
    strategy: PropagationStrategy
    seed: int
    n_parties: int
    issued_at: float
    first_seen: dict[str, float]
    via: dict[str, str]
    counters: TransportCounters
    wall_time_seconds: float
    root_threshold: int
    root_count: int
    event_payload_bytes: int
    certificate_payload_bytes: int
    signature_verified_events: int
    certificate_verified_events: int
    rejected_events: int
    log_port: int
    party_ports: dict[str, int]
    service_model: str = "asyncio-tcp-jsonl"

    @property
    def deltas(self) -> tuple[float, ...]:
        return tuple(seen - self.issued_at for seen in self.first_seen.values())

    @property
    def completeness(self) -> float:
        if self.n_parties <= 0:
            return 1.0
        return len(self.first_seen) / self.n_parties

    @property
    def undelivered_count(self) -> int:
        return self.n_parties - len(self.first_seen)

    def percentile_delta(self, quantile: float) -> float | None:
        if not self.deltas:
            return None
        ordered = sorted(self.deltas)
        idx = min(len(ordered) - 1, int(quantile * (len(ordered) - 1)))
        return ordered[idx]


@dataclass
class _LogService:
    ledger: TransparencyLedger
    counters: TransportCounters
    event_payload: dict[str, Any] | None = None
    certificate_payload: dict[str, Any] | None = None
    sth_payload: dict[str, Any] | None = None

    async def handle(self, request: dict[str, Any]) -> dict[str, Any]:
        request_type = request.get("type")
        if request_type == "append":
            event = event_from_payload(_expect_dict(request.get("event")))
            self.ledger.append(event, appended_at=float(request.get("appended_at", 0.0)))
            sth = self.ledger.latest_sth(timestamp=float(request.get("sth_timestamp", 0.0)))
            self.event_payload = event.to_payload()
            self.certificate_payload = _expect_dict(request.get("certificate"))
            self.sth_payload = sth_to_payload(sth)
            self.counters.log_appends += 1
            return {"ok": True, "sth": self.sth_payload}
        if request_type == "latest":
            return {
                "ok": True,
                "has_event": self.event_payload is not None,
                "event": self.event_payload,
                "certificate": self.certificate_payload,
                "sth": self.sth_payload,
            }
        return {"ok": False, "error": f"unknown log request: {request_type}"}


@dataclass
class _PartyService:
    state: LocalPartyState
    issuer_public_key: Ed25519PublicKey
    federation: RootFederation

    async def handle(self, request: dict[str, Any]) -> dict[str, Any]:
        request_type = request.get("type")
        if request_type in {"push_revocation", "gossip_revocation", "log_revocation"}:
            return self._accept_revocation(request, via=str(request.get("via", request_type)))
        if request_type == "metrics":
            return {
                "ok": True,
                "party_id": self.state.party_id,
                "has_event": self.state.has_event,
                "first_seen_at": self.state.first_seen_at,
                "via": self.state.via,
                "accepted_events": self.state.accepted_events,
                "rejected_events": self.state.rejected_events,
                "signature_verified_events": self.state.signature_verified_events,
                "certificate_verified_events": self.state.certificate_verified_events,
            }
        return {"ok": False, "error": f"unknown party request: {request_type}"}

    def _accept_revocation(self, request: dict[str, Any], *, via: str) -> dict[str, Any]:
        event_payload = _expect_dict(request.get("event"))
        certificate_payload = _expect_dict(request.get("certificate"))
        event = event_from_payload(event_payload)
        certificate = certificate_from_payload(certificate_payload)
        signature_ok = verify_revocation_event(event, self.issuer_public_key)
        certificate_ok = self.federation.verify_certificate(certificate)
        if not signature_ok or not certificate_ok:
            self.state.rejected_events += 1
            return {"ok": False, "accepted": False, "signature_ok": signature_ok, "certificate_ok": certificate_ok}
        now = float(request.get("delivered_at", 0.0))
        self.state.accepted_events += 1
        self.state.signature_verified_events += 1
        self.state.certificate_verified_events += 1
        if self.state.first_seen_at is None:
            self.state.first_seen_at = now
            self.state.via = via
            self.state.event_payload = event_payload
            self.state.certificate_payload = certificate_payload
        return {"ok": True, "accepted": True, "first_seen_at": self.state.first_seen_at, "via": self.state.via}


async def run_local_end_to_end_trial(
    *,
    seed: int,
    n_parties: int,
    strategy: PropagationStrategy = "hybrid",
    push_suppression: float = 0.2,
    gossip_suppression: float = 0.0,
    log_suppression: float = 0.0,
    duration: float = 1.5,
    push_delay: float = 0.02,
    gossip_interval: float = 0.10,
    poll_interval: float = 0.15,
    gossip_fanout: int = 4,
    root_count: int = 5,
    threshold: int = 3,
) -> LocalEndToEndResult:
    """Run a local loopback trial with real TCP JSONL services.

    This is intentionally lightweight: services run as asyncio TCP servers in
    one process, but every propagation step crosses a loopback socket and JSON
    serialization boundary.
    """

    if strategy not in {"push", "log", "push-gossip", "hybrid"}:
        raise ValueError("E-B6 local transport supports push, log, push-gossip, and hybrid")
    rng = random.Random(seed)
    counters = TransportCounters()
    wall_start = time.perf_counter()
    loop = asyncio.get_running_loop()
    issuer = generate_keypair()
    roots = [RootAuthority(f"root-{idx}", generate_keypair()) for idx in range(root_count)]
    federation = RootFederation({root.root_id: root.keypair.public for root in roots}, threshold=threshold)
    log_service = _LogService(TransparencyLedger(generate_keypair(), log_id=f"e-b6-log-{seed}"), counters)
    log_server = await _serve(log_service.handle)
    log_port = _server_port(log_server)

    party_ids = [f"rp-{idx}" for idx in range(n_parties)]
    suppressed_push = set(_select_fraction(party_ids, push_suppression, rng, exclude={"rp-0"}))
    suppressed_gossip = set(_select_fraction(party_ids, gossip_suppression, rng, exclude={"rp-0"}))
    suppressed_log = set(_select_fraction(party_ids, log_suppression, rng, exclude={"rp-0"}))
    party_services: dict[str, _PartyService] = {}
    party_servers: dict[str, asyncio.AbstractServer] = {}
    party_ports: dict[str, int] = {}
    tasks: list[asyncio.Task[None]] = []
    try:
        for party_id in party_ids:
            state = LocalPartyState(party_id)
            service = _PartyService(state, issuer.public, federation)
            server = await _serve(service.handle)
            party_services[party_id] = service
            party_servers[party_id] = server
            party_ports[party_id] = _server_port(server)

        issued_at = loop.time()
        event = create_revocation_event(f"edge-e-b6-{seed}-{strategy}", issuer, epoch_id="epoch-e-b6", issued_at=issued_at)
        approvals = [root.approve_event(event) for root in roots[:threshold]]
        certificate = federation.certificate_for(event, approvals)
        event_payload = event.to_payload()
        certificate_payload = certificate_to_payload(certificate)

        await _request(
            log_port,
            {
                "type": "append",
                "event": event_payload,
                "certificate": certificate_payload,
                "appended_at": issued_at,
                "sth_timestamp": issued_at,
            },
            counters,
        )

        uses_push = strategy in {"push", "push-gossip", "hybrid"}
        uses_gossip = strategy in {"push-gossip", "hybrid"}
        uses_log = strategy in {"log", "hybrid"}
        stop_at = issued_at + duration

        if uses_push:
            await asyncio.sleep(push_delay)
            for party_id in party_ids:
                counters.push_attempts += 1
                if party_id in suppressed_push:
                    counters.push_suppressed += 1
                    continue
                response = await _request(
                    party_ports[party_id],
                    {
                        "type": "push_revocation",
                        "via": "push",
                        "event": event_payload,
                        "certificate": certificate_payload,
                        "delivered_at": loop.time(),
                    },
                    counters,
                )
                if response.get("accepted"):
                    counters.push_delivered += 1

        if uses_gossip:
            tasks.append(
                asyncio.create_task(
                    _gossip_loop(
                        party_ids=party_ids,
                        party_services=party_services,
                        party_ports=party_ports,
                        suppressed_gossip=suppressed_gossip,
                        counters=counters,
                        rng=random.Random(seed + 10_000),
                        stop_at=stop_at,
                        interval=gossip_interval,
                        fanout=gossip_fanout,
                    )
                )
            )
        if uses_log:
            for party_id in party_ids:
                tasks.append(
                    asyncio.create_task(
                        _poll_loop(
                            party_id=party_id,
                            party_port=party_ports[party_id],
                            log_port=log_port,
                            suppressed_log=suppressed_log,
                            counters=counters,
                            stop_at=stop_at,
                            interval=poll_interval,
                        )
                    )
                )

        await asyncio.sleep(max(0.0, stop_at - loop.time()))
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

        first_seen = {
            party_id: service.state.first_seen_at
            for party_id, service in party_services.items()
            if service.state.first_seen_at is not None
        }
        via = {
            party_id: str(service.state.via)
            for party_id, service in party_services.items()
            if service.state.via is not None
        }
        return LocalEndToEndResult(
            strategy=strategy,
            seed=seed,
            n_parties=n_parties,
            issued_at=issued_at,
            first_seen=first_seen,
            via=via,
            counters=counters,
            wall_time_seconds=time.perf_counter() - wall_start,
            root_threshold=threshold,
            root_count=root_count,
            event_payload_bytes=len(canonical_json_bytes(event_payload)),
            certificate_payload_bytes=len(canonical_json_bytes(certificate_payload)),
            signature_verified_events=sum(service.state.signature_verified_events for service in party_services.values()),
            certificate_verified_events=sum(
                service.state.certificate_verified_events for service in party_services.values()
            ),
            rejected_events=sum(service.state.rejected_events for service in party_services.values()),
            log_port=log_port,
            party_ports=party_ports,
        )
    finally:
        for task in tasks:
            task.cancel()
        log_server.close()
        await log_server.wait_closed()
        for server in party_servers.values():
            server.close()
        for server in party_servers.values():
            await server.wait_closed()


async def _gossip_loop(
    *,
    party_ids: Sequence[str],
    party_services: dict[str, _PartyService],
    party_ports: dict[str, int],
    suppressed_gossip: set[str],
    counters: TransportCounters,
    rng: random.Random,
    stop_at: float,
    interval: float,
    fanout: int,
) -> None:
    loop = asyncio.get_running_loop()
    while loop.time() < stop_at:
        await asyncio.sleep(interval)
        informed = [party_id for party_id in party_ids if party_services[party_id].state.has_event]
        for source_id in informed:
            state = party_services[source_id].state
            if state.event_payload is None or state.certificate_payload is None:
                continue
            peers = [party_id for party_id in party_ids if party_id != source_id]
            if fanout < len(peers):
                peers = rng.sample(peers, max(0, fanout))
            for dest_id in peers:
                counters.gossip_attempts += 1
                if dest_id in suppressed_gossip:
                    counters.gossip_suppressed += 1
                    continue
                response = await _request(
                    party_ports[dest_id],
                    {
                        "type": "gossip_revocation",
                        "via": "gossip",
                        "event": state.event_payload,
                        "certificate": state.certificate_payload,
                        "delivered_at": loop.time(),
                    },
                    counters,
                )
                if response.get("accepted"):
                    counters.gossip_delivered += 1


async def _poll_loop(
    *,
    party_id: str,
    party_port: int,
    log_port: int,
    suppressed_log: set[str],
    counters: TransportCounters,
    stop_at: float,
    interval: float,
) -> None:
    loop = asyncio.get_running_loop()
    while loop.time() < stop_at:
        await asyncio.sleep(interval)
        counters.log_polls += 1
        if party_id in suppressed_log:
            counters.log_poll_suppressed += 1
            continue
        latest = await _request(log_port, {"type": "latest"}, counters)
        if latest.get("has_event"):
            await _request(
                party_port,
                {
                    "type": "log_revocation",
                    "via": "log",
                    "event": latest.get("event"),
                    "certificate": latest.get("certificate"),
                    "delivered_at": loop.time(),
                },
                counters,
            )


async def _serve(handler: Any) -> asyncio.AbstractServer:
    async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=2.0)
            if not line:
                response = {"ok": False, "error": "empty request"}
            else:
                response = await handler(json.loads(line.decode()))
            writer.write((json.dumps(response, sort_keys=True, separators=(",", ":")) + "\n").encode())
            await writer.drain()
        except Exception as exc:  # pragma: no cover - defensive service boundary
            writer.write((json.dumps({"ok": False, "error": str(exc)}, sort_keys=True) + "\n").encode())
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    return await asyncio.start_server(handle_client, HOST, 0)


async def _request(port: int, request: dict[str, Any], counters: TransportCounters) -> dict[str, Any]:
    payload = (json.dumps(request, sort_keys=True, separators=(",", ":")) + "\n").encode()
    counters.requests += 1
    counters.bytes_sent += len(payload)
    try:
        reader, writer = await asyncio.open_connection(HOST, port)
        writer.write(payload)
        await writer.drain()
        line = await asyncio.wait_for(reader.readline(), timeout=2.0)
        counters.bytes_received += len(line)
        writer.close()
        await writer.wait_closed()
        if not line:
            counters.errors += 1
            return {"ok": False, "error": "empty response"}
        return json.loads(line.decode())
    except Exception as exc:  # pragma: no cover - defensive service boundary
        counters.errors += 1
        return {"ok": False, "error": str(exc)}


def _server_port(server: asyncio.AbstractServer) -> int:
    sockets = server.sockets or []
    if not sockets:
        raise RuntimeError("server has no bound socket")
    return int(sockets[0].getsockname()[1])


def _select_fraction(
    party_ids: Sequence[str],
    fraction: float,
    rng: random.Random,
    *,
    exclude: set[str] | None = None,
) -> list[str]:
    if fraction <= 0.0:
        return []
    excluded = exclude or set()
    population = [party_id for party_id in party_ids if party_id not in excluded]
    count = min(len(population), int(round(len(party_ids) * fraction)))
    if count <= 0:
        return []
    return sorted(rng.sample(population, count))


def event_from_payload(payload: dict[str, Any]) -> RevocationEvent:
    return RevocationEvent(
        edge_id=str(payload["edge_id"]),
        epoch_id=str(payload["epoch_id"]),
        issuer_key_id=str(payload["issuer_key_id"]),
        issued_at=float(payload["issued_at"]),
        sequence=int(payload.get("sequence", 0)),
        target_type="edge",
        reason=str(payload.get("reason", "")),
        signature=str(payload["signature"]),
    )


def certificate_to_payload(certificate: RootCertificate) -> dict[str, Any]:
    return {
        "event_id": certificate.event_id,
        "threshold": certificate.threshold,
        "approvals": [
            {
                "root_id": approval.root_id,
                "root_key_id": approval.root_key_id,
                "event_id": approval.event_id,
                "signature": approval.signature,
            }
            for approval in certificate.approvals
        ],
    }


def certificate_from_payload(payload: dict[str, Any]) -> RootCertificate:
    approvals = tuple(
        RootApproval(
            root_id=str(approval["root_id"]),
            root_key_id=str(approval["root_key_id"]),
            event_id=str(approval["event_id"]),
            signature=str(approval["signature"]),
        )
        for approval in payload.get("approvals", [])
    )
    return RootCertificate(event_id=str(payload["event_id"]), threshold=int(payload["threshold"]), approvals=approvals)


def sth_to_payload(sth: SignedTreeHead) -> dict[str, Any]:
    payload = sth.signable_payload()
    payload["signature"] = sth.signature
    payload["sth_hash"] = sth.sth_hash
    return payload


def _expect_dict(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("expected object payload")
    return value
