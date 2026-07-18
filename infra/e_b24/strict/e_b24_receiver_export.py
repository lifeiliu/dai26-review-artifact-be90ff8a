#!/usr/bin/env python3
"""Read-only, sanitized receiver evidence export for one E-B24 delegation."""

from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path


def export_event(
    state_db: Path, evidence_jsonl: Path, delegation_id: str
) -> dict[str, object]:
    connection = sqlite3.connect(state_db)
    connection.row_factory = sqlite3.Row
    try:
        row = connection.execute(
            "SELECT * FROM inbox WHERE delegation_id=? ORDER BY persisted_at_ns DESC LIMIT 1",
            (delegation_id,),
        ).fetchone()
        if row is None:
            return {"delegation_id": delegation_id, "found": False}
        jti = str(row["jti"])
        targets = connection.execute(
            "SELECT gateway_id, attempts, last_error FROM gateway_targets "
            "WHERE jti=? ORDER BY gateway_id",
            (jti,),
        ).fetchall()
        receipts = connection.execute(
            "SELECT gateway_id, receipt_id, recorded_at_ns FROM enforcement_receipts "
            "WHERE jti=? ORDER BY gateway_id",
            (jti,),
        ).fetchall()
    finally:
        connection.close()
    ingress_records = []
    if evidence_jsonl.exists():
        for line in evidence_jsonl.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            item = json.loads(line)
            if item.get("delegation_id") == delegation_id:
                ingress_records.append(item)
    return {
        "delegation_id": delegation_id,
        "found": True,
        "jti": jti,
        "event_id": row["event_id"],
        "channel": row["channel"],
        "sequence": row["sequence"],
        "set_sha256": row["set_sha256"],
        "status": row["status"],
        "persisted_at_ns": row["persisted_at_ns"],
        "enforced_at_ns": row["enforced_at_ns"],
        "targets": [dict(item) for item in targets],
        "receipts": [dict(item) for item in receipts],
        "ingress_records": ingress_records,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-db", type=Path, required=True)
    parser.add_argument("--evidence-jsonl", type=Path, required=True)
    parser.add_argument("--delegation-id", required=True)
    args = parser.parse_args()
    print(
        json.dumps(
            export_event(args.state_db, args.evidence_jsonl, args.delegation_id),
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

