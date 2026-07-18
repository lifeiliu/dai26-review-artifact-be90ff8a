#!/usr/bin/env python3
"""Scan an anonymous-review release for identity and credential leakage."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


DEFAULT_ROOT = Path(__file__).resolve().parents[1]
SELF = Path(__file__).resolve()

# Literals are split so the scanner does not contain the values it rejects.
KNOWN_ACCOUNT = (b"498" + b"283" + b"327" + b"263").lower()
KNOWN_USER = (b"liu" + b"lifei").lower()
KNOWN_EMAIL = (b"lliu" + b".lifei" + b"@gmail.com").lower()
KNOWN_ROLE_PREFIX = (b"AWS" + b"Reserved" + b"SSO_").lower()
KNOWN_SESSION = (b"Paper2" + b"-EB24-manager").lower()
BYTE_MARKERS = {
    KNOWN_USER: "known local username",
    KNOWN_EMAIL: "known author email",
    KNOWN_ACCOUNT: "known AWS account ID",
    KNOWN_ROLE_PREFIX: "AWS identity-center role name",
    KNOWN_SESSION: "known AWS role session",
    (b"agent-id-" + b"experiment").lower(): "former working repository",
    (b"paper-a-" + b"revocation").lower(): "former external project path",
    (b"-----BEGIN " + b"PRIVATE KEY-----").lower(): "private key",
    (b"-----BEGIN RSA " + b"PRIVATE KEY-----").lower(): "RSA private key",
    (b"sk-" + b"or-v1-").lower(): "OpenRouter API key",
}
MAC_HOME_PATH = re.compile(rb"(?:^|[\s\"'=:(])/(?:" + b"Users" + rb")/", re.I)
AWS_ARN_ACCOUNT = re.compile(rb"arn:aws(?:-[a-z]+)?:[^:\s]+:[^:\s]*:(\d{12}):", re.I)
AWS_ECR_ACCOUNT = re.compile(rb"\b(\d{12})\.dkr\.ecr\.", re.I)
AWS_ACCESS_KEY = re.compile(rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
EMAIL = re.compile(rb"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
ALLOWED_EMAIL_DOMAINS = {b"example.com", b"example.org", b"example.net", b"example.invalid"}
SKIP_PARTS = {".git", ".venv", "__pycache__", "_outputs", ".pytest_cache", ".terraform"}
OPAQUE_ARCHIVE_SUFFIXES = {".gz", ".tgz", ".zip"}


def scan(root: Path) -> list[str]:
    findings: list[str] = []
    for path in sorted(root.rglob("*")):
        if (
            not path.is_file()
            or path.resolve() == SELF
            or path.relative_to(root).as_posix() == "scripts/check_anonymization.py"
            or path.suffix.lower() in OPAQUE_ARCHIVE_SUFFIXES
        ):
            continue
        relative = path.relative_to(root)
        if any(part in SKIP_PARTS for part in relative.parts):
            continue
        relative_bytes = relative.as_posix().encode().lower()
        content = path.read_bytes()
        lowered = content.lower()
        for marker, description in BYTE_MARKERS.items():
            if marker in relative_bytes or marker in lowered:
                findings.append(f"{relative}: {description}")
        if MAC_HOME_PATH.search(content) or relative_bytes.startswith((b"users/", b"/users/")):
            findings.append(f"{relative}: macOS home-directory path")
        for expression, description in (
            (AWS_ARN_ACCOUNT, "non-placeholder AWS account in ARN"),
            (AWS_ECR_ACCOUNT, "non-placeholder AWS account in ECR URI"),
        ):
            for match in expression.finditer(content):
                if match.group(1) != b"000000000000":
                    findings.append(f"{relative}: {description}")
                    break
        if AWS_ACCESS_KEY.search(content):
            findings.append(f"{relative}: AWS access-key-shaped value")
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
        print("Anonymization audit failed:")
        for finding in findings:
            print(f"- {finding}")
        return 1
    print(f"Anonymization audit passed for {sum(1 for path in root.rglob('*') if path.is_file())} files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
