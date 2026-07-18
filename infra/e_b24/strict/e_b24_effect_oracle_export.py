#!/usr/bin/env python3
"""Read the authoritative remote Filesystem/PostgreSQL E-B24 effect oracles."""

from __future__ import annotations

import argparse
import json
import ssl
import urllib.request
from pathlib import Path


def _oracle(
    url: str,
    *,
    token: str,
    ca_file: Path,
    service: str,
    experiment_run: str,
    arm: str,
) -> dict[str, object]:
    body = json.dumps(
        {"service": service, "experiment_run": experiment_run, "arm": arm},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    request = urllib.request.Request(
        f"{url.rstrip('/')}/v1/oracle",
        data=body,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )
    context = ssl.create_default_context(cafile=str(ca_file))
    with urllib.request.urlopen(request, timeout=30, context=context) as response:
        parsed = json.loads(response.read())
    if not isinstance(parsed, dict):
        raise RuntimeError("effect oracle returned a non-object")
    return parsed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ca-file", type=Path, required=True)
    parser.add_argument("--token-file", type=Path, required=True)
    parser.add_argument("--experiment-run", required=True)
    parser.add_argument("--arm", required=True)
    args = parser.parse_args()
    token = args.token_file.read_text(encoding="utf-8").strip()
    if not token:
        raise ValueError("empty effect token")
    result = {
        "experiment_run": args.experiment_run,
        "arm": args.arm,
        "filesystem": _oracle(
            "https://filesystem-effects:9443",
            token=token,
            ca_file=args.ca_file,
            service="filesystem",
            experiment_run=args.experiment_run,
            arm=args.arm,
        ),
        "postgres": _oracle(
            "https://postgres-effects:9443",
            token=token,
            ca_file=args.ca_file,
            service="postgres",
            experiment_run=args.experiment_run,
            arm=args.arm,
        ),
    }
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

