#!/usr/bin/env python3
"""Verify that a generated anonymous-review release has no generic identity leaks.

This verifier is deliberately safe to distribute with the review artifact: it
contains no author-specific identifiers. The stricter private scanner and the
release builder run before this release is created and are intentionally not
shipped.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path


DEFAULT_ROOT = Path(__file__).resolve().parents[1]
SKIP_PARTS = {".git", ".venv", "__pycache__", "_outputs", ".pytest_cache", ".terraform"}
OPAQUE_ARCHIVE_SUFFIXES = {".gz", ".tgz", ".zip"}
ALLOWED_EMAIL_DOMAINS = {b"example.com", b"example.org", b"example.net", b"example.invalid"}

MAC_HOME_PATH = re.compile(rb"(?:^|[\s\"'=:(])/" + b"Users" + rb"/", re.I)
LINUX_HOME_PATH = re.compile(
    rb"(?:^|[\s\"'=:(])/" + b"home" + rb"/(?!anonymous(?:/|\b))", re.I
)
AWS_ARN_ACCOUNT = re.compile(rb"arn:aws(?:-[a-z]+)?:[^:\s]+:[^:\s]*:(\d{12}):", re.I)
AWS_ECR_ACCOUNT = re.compile(rb"\b(\d{12})\.dkr\.ecr\.", re.I)
AWS_ACCESS_KEY = re.compile(rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
EMAIL = re.compile(rb"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
PRIVATE_MATCHER = re.compile(
    rb"\b(?:LOCAL|KNOWN)_(?:USER|EMAIL|ACCOUNT|ROLE_PREFIX|SESSION)\b"
)
PRIVATE_SCRIPT_NAMES = {"build_anonymous_release.py", "check_anonymization.py"}
PRIVATE_KEY_MARKERS = (
    b"-----BEGIN " + b"PRIVATE KEY-----",
    b"-----BEGIN RSA " + b"PRIVATE KEY-----",
    b"sk-" + b"or-v1-",
)


def scan(root: Path) -> list[str]:
    findings: list[str] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if any(part in SKIP_PARTS for part in relative.parts):
            continue
        if path.suffix.lower() in OPAQUE_ARCHIVE_SUFFIXES:
            findings.append(f"{relative}: opaque archive embedded in release")
            continue
        if path.name in PRIVATE_SCRIPT_NAMES:
            findings.append(f"{relative}: private release tool included")
            continue

        content = path.read_bytes()
        relative_bytes = relative.as_posix().encode().lower()
        if MAC_HOME_PATH.search(content) or relative_bytes.startswith((b"users/", b"/" + b"users/")):
            findings.append(f"{relative}: macOS home-directory path")
        if LINUX_HOME_PATH.search(content):
            findings.append(f"{relative}: non-anonymous Linux home-directory path")
        if PRIVATE_MATCHER.search(content):
            findings.append(f"{relative}: private identity-matcher constant")
        if any(marker.lower() in content.lower() for marker in PRIVATE_KEY_MARKERS):
            findings.append(f"{relative}: credential-shaped material")
        if AWS_ACCESS_KEY.search(content):
            findings.append(f"{relative}: AWS access-key-shaped value")
        for expression, description in (
            (AWS_ARN_ACCOUNT, "non-placeholder AWS account in ARN"),
            (AWS_ECR_ACCOUNT, "non-placeholder AWS account in ECR URI"),
        ):
            for match in expression.finditer(content):
                if match.group(1) != b"000000000000":
                    findings.append(f"{relative}: {description}")
                    break
        for match in EMAIL.finditer(content):
            domain = match.group(0).rsplit(b"@", 1)[1].lower()
            if domain not in ALLOWED_EMAIL_DOMAINS:
                findings.append(f"{relative}: non-placeholder email address")
                break
    return sorted(set(findings))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    arguments = parser.parse_args()
    root = arguments.root.resolve()
    if not root.is_dir():
        raise SystemExit(f"scan root is not a directory: {root}")
    findings = scan(root)
    if findings:
        print("Anonymous-release surface audit failed:")
        for finding in findings:
            print(f"- {finding}")
        return 1
    print(f"Anonymous-release surface audit passed for {sum(1 for path in root.rglob('*') if path.is_file())} files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
