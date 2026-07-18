#!/usr/bin/env python3
"""Extract a sanitized durable-receiver state summary for one E-B24 SET."""

from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-db", type=Path, required=True)
    parser.add_argument("--events-jsonl", type=Path, required=True)
    identity = parser.add_mutually_exclusive_group(required=True)
    identity.add_argument("--jti")
    identity.add_argument("--delegation-id")
    parser.add_argument("--source", choices=("synthetic", "keycloak"), required=True)
    parser.add_argument(
        "--expected-status", choices=("PERSISTED", "ENFORCED"), required=True
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    connection = sqlite3.connect(f"file:{args.state_db}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    selection = "jti=?" if args.jti else "delegation_id=?"
    identity_value = args.jti or args.delegation_id
    inbox = connection.execute(
        "SELECT jti, delegation_id, event_id, channel, sequence, set_sha256, "
        "metadata_json, status, persisted_at_ns, enforced_at_ns FROM inbox WHERE "
        f"{selection} ORDER BY persisted_at_ns DESC LIMIT 1",
        (identity_value,),
    ).fetchone()
    if inbox is None:
        raise KeyError(identity_value)
    jti = str(inbox["jti"])
    targets = connection.execute(
        "SELECT gateway_id, attempts, last_error FROM gateway_targets "
        "WHERE jti=? ORDER BY gateway_id",
        (jti,),
    ).fetchall()
    receipts = connection.execute(
        "SELECT gateway_id, receipt_json, recorded_at_ns FROM enforcement_receipts "
        "WHERE jti=? ORDER BY gateway_id",
        (jti,),
    ).fetchall()
    connection.close()

    event_records = [
        json.loads(line)
        for line in args.events_jsonl.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    matching_events = [record for record in event_records if record.get("jti") == jti]
    parsed_receipts = []
    for row in receipts:
        receipt = json.loads(row["receipt_json"])
        parsed_receipts.append(
            {
                "gateway_id": row["gateway_id"],
                "recorded_at_ns": row["recorded_at_ns"],
                "receipt_id": receipt.get("receipt_id"),
                "applied": receipt.get("applied"),
                "delegation_id": receipt.get("delegation_id"),
                "event_id": receipt.get("event_id"),
                "channel": receipt.get("channel"),
                "sequence": receipt.get("sequence"),
            }
        )
    body = dict(inbox)
    body["metadata"] = json.loads(body.pop("metadata_json"))
    summary = {
        "experiment": "E-B24 durable-receiver state summary",
        "source": args.source,
        "claim_boundary": (
            "Live Keycloak PUSH three-host service smoke; not a selective-fault, "
            "strict-topology, or confirmatory result."
            if args.source == "keycloak"
            else "Synthetic SET receiver-path smoke; not a Keycloak result."
        ),
        "inbox": body,
        "targets": [dict(row) for row in targets],
        "receipts": parsed_receipts,
        "accepted_event_records": matching_events,
    }
    summary["assertions"] = {
        "event_logged_once": len(matching_events) == 1,
        "expected_receiver_status": body["status"] == args.expected_status,
        "valid_state_timestamps": (
            body["enforced_at_ns"] is None
            if args.expected_status == "PERSISTED"
            else isinstance(body["enforced_at_ns"], int)
            and body["persisted_at_ns"] <= body["enforced_at_ns"]
        ),
        "expected_receipt_state": (
            len(parsed_receipts) == 0
            if args.expected_status == "PERSISTED"
            else len(targets) == len(parsed_receipts) > 0
        ),
        "no_handoff_error": all(row["last_error"] is None for row in targets),
        "receipts_bind_event": all(
            receipt["applied"] is True
            and receipt["delegation_id"] == body["delegation_id"]
            and receipt["event_id"] == body["event_id"]
            and receipt["channel"] == body["channel"]
            and receipt["sequence"] == body["sequence"]
            and bool(receipt["receipt_id"])
            for receipt in parsed_receipts
        )
        and (bool(parsed_receipts) or args.expected_status == "PERSISTED"),
    }
    if not all(summary["assertions"].values()):
        raise RuntimeError(f"receiver state assertions failed: {summary['assertions']}")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary["assertions"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
