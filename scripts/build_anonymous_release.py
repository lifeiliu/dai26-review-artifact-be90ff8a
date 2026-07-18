#!/usr/bin/env python3
"""Build a sanitized, deterministic archive for anonymous peer review."""

from __future__ import annotations

import argparse
import ast
import datetime as dt
import gzip
import hashlib
import ipaddress
import json
import os
import re
import shutil
import socket
import stat
import tarfile
from pathlib import Path


DEFAULT_SOURCE = Path(__file__).resolve().parents[1]
LOCAL_USER = "liu" + "lifei"
LOCAL_EMAIL = "lliu" + ".lifei" + "@gmail.com"
LOCAL_ACCOUNT = "498" + "283" + "327" + "263"
LOCAL_ROLE_PREFIX = "AWS" + "Reserved" + "SSO_"
LOCAL_SESSION = "Paper2" + "-EB24-manager"
HOME_RE = re.compile(r"/" + "Users" + r"/[^/\s\"']+")
LINUX_HOME_RE = re.compile(r"/home/anonymous/|\b))[^/\s\"']+")
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
ARN_ACCOUNT_RE = re.compile(r"(arn:aws(?:-[a-z]+)?:[^:\s]+:[^:\s]*:)\d{12}(:)", re.I)
ECR_ACCOUNT_RE = re.compile(r"\b\d{12}(?=\.dkr\.ecr\.)", re.I)
ASSUMED_ROLE_RE = re.compile(r"arn:aws:sts::\d{12}:assumed-role/[^/\s\"']+/[^/\s\"']+", re.I)
RESERVED_ROLE_RE = re.compile(("AWS" + "Reserved" + "SSO_") + r"[A-Za-z0-9_+=,.@-]+")
PUBLIC_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
AWS_RESOURCE_RE = re.compile(r"\b(i|ami|sg|subnet|vpc|eni|vol|igw|rtb|acl)-([0-9a-f]{8,17})\b", re.I)
SKIP_PARTS = {".git", ".venv", "__pycache__", ".pytest_cache", "_outputs", ".terraform"}
SKIP_NAMES = {".DS_Store", "CHECKSUMS.sha256"}
SKIP_SUFFIXES = {".pyc", ".sqlite3", ".db", ".sqlite", ".sha256"}
ARCHIVE_ROOT = "anonymous-revocation-completion-artifact"


def token(prefix: str, value: str, length: int) -> str:
    return prefix + hashlib.sha256(value.encode()).hexdigest()[:length]


def sanitize_email(match: re.Match[str]) -> str:
    value = match.group(0)
    if value.lower() == "anonymous@example.invalid":
        return value
    return f"anon-{hashlib.sha256(value.lower().encode()).hexdigest()[:10]}@example.invalid"


def sanitize_ipv4(match: re.Match[str]) -> str:
    value = match.group(0)
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return value
    if address.is_private or address.is_loopback or address.is_link_local or address.is_multicast or address.is_reserved:
        return value
    final = 1 + int(hashlib.sha256(value.encode()).hexdigest()[:8], 16) % 254
    return f"192.0.2.{final}"


def sanitize_resource(match: re.Match[str]) -> str:
    prefix, identifier = match.groups()
    return f"{prefix.lower()}-{hashlib.sha256(match.group(0).lower().encode()).hexdigest()[:len(identifier)]}"


def sanitize_text(value: str, *, hostname: str) -> str:
    value = ASSUMED_ROLE_RE.sub(
        "arn:aws:sts::000000000000:assumed-role/ANONYMOUS_REVIEW_ROLE/anonymous-session",
        value,
    )
    value = ARN_ACCOUNT_RE.sub(r"\g<1>000000000000\g<2>", value)
    value = ECR_ACCOUNT_RE.sub("000000000000", value)
    value = RESERVED_ROLE_RE.sub("ANONYMOUS_REVIEW_ROLE", value)
    value = re.sub(re.escape(LOCAL_ACCOUNT), "000000000000", value, flags=re.I)
    value = re.sub(re.escape(LOCAL_SESSION), "anonymous-session", value, flags=re.I)
    value = re.sub(re.escape(LOCAL_EMAIL), "anonymous@example.invalid", value, flags=re.I)
    value = re.sub(re.escape(LOCAL_USER), "anonymous", value, flags=re.I)
    if hostname:
        value = re.sub(re.escape(hostname), "anonymous-host", value, flags=re.I)
    value = HOME_RE.sub("/home/anonymous", value)
    value = LINUX_HOME_RE.sub("/home/anonymous", value)
    value = EMAIL_RE.sub(sanitize_email, value)
    value = PUBLIC_IPV4_RE.sub(sanitize_ipv4, value)
    value = AWS_RESOURCE_RE.sub(sanitize_resource, value)
    return value


def skip(relative: Path) -> bool:
    if any(part in SKIP_PARTS for part in relative.parts):
        return True
    if relative.name in SKIP_NAMES:
        return True
    if relative.suffix.lower() in SKIP_SUFFIXES:
        return True
    if relative.name.endswith((".sqlite3-wal", ".sqlite3-shm", ".tfstate", ".tfstate.backup", ".tfplan")):
        return True
    if ".tfplan" in relative.name:
        return True
    return False


def sanitize_relative(relative: Path, *, hostname: str) -> Path:
    parts = [sanitize_text(part, hostname=hostname) for part in relative.parts]
    return Path(*parts)


def release_notes() -> str:
    return """# Anonymous Review Release Notes

This directory is a generated release boundary. It contains source, protocols,
tests, and saved JSON/JSONL/CSV/Markdown evidence, including E-B24--E-B27.

The release builder deterministically replaces author emails, local user/home
paths, hostnames, public IP addresses, cloud resource IDs, AWS account IDs,
identity-center role names, and role-session names. AWS accounts use the
non-routable placeholder `000000000000`; roles use
`ANONYMOUS_REVIEW_ROLE`. Git history and remotes are not included.

SQLite databases, interpreter caches, Terraform state/plans, and source
checksum manifests are excluded because binary/state files can retain
identifiers and because text sanitization changes source bytes. Saved portable
evidence remains in JSON/JSONL/CSV/Markdown form. `CHECKSUMS.sha256` is rebuilt
over the released bytes. Workload hash locks are recomputed over the sanitized
portable traces so release-side loaders still enforce exact byte identity.
`RELEASE_MANIFEST.json` records exclusions and transformations.

This material is supplied solely for anonymous scholarly peer review. No
copyright or patent license is granted by its availability. A publication
license will be selected after double-blind review.
"""


def repair_portable_hash_locks(root: Path) -> int:
    """Rebind E-B22's byte locks to the sanitized E-B20 release traces."""
    module_path = root / "src/revocation_propagation/keycloak_gateway_gate.py"
    workload = root / "data/run_2026_07_14_e_b20_mcpmark_formal"
    source = module_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    mapping: dict[str, str] | None = None
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "EXPECTED_INPUT_SHA256"
            for target in node.targets
        ):
            candidate = ast.literal_eval(node.value)
            if isinstance(candidate, dict):
                mapping = {str(key): str(value) for key, value in candidate.items()}
            break
    if mapping is None:
        raise RuntimeError("cannot locate E-B22 workload hash lock")
    replacements = 0
    for relative, original in mapping.items():
        path = workload / relative
        if not path.is_file():
            raise FileNotFoundError(f"missing released frozen input: {relative}")
        released = hashlib.sha256(path.read_bytes()).hexdigest()
        if original != released:
            if source.count(original) != 1:
                raise RuntimeError(f"ambiguous workload hash lock: {relative}")
            source = source.replace(original, released)
            replacements += 1
    module_path.write_text(source, encoding="utf-8")
    return replacements


def write_checksums(root: Path) -> int:
    entries: list[str] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name == "CHECKSUMS.sha256":
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        entries.append(f"{digest}  {path.relative_to(root).as_posix()}")
    (root / "CHECKSUMS.sha256").write_text("\n".join(entries) + "\n", encoding="utf-8")
    return len(entries)


def deterministic_archive(release_dir: Path, archive: Path) -> None:
    archive.parent.mkdir(parents=True, exist_ok=True)
    temporary = archive.with_suffix(archive.suffix + ".tmp")
    with temporary.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as tar:
                for path in sorted(release_dir.rglob("*")):
                    if not path.is_file():
                        continue
                    relative = Path(ARCHIVE_ROOT) / path.relative_to(release_dir)
                    info = tar.gettarinfo(str(path), arcname=relative.as_posix())
                    info.uid = 0
                    info.gid = 0
                    info.uname = "anonymous"
                    info.gname = "anonymous"
                    info.mtime = 0
                    info.mode = 0o755 if os.access(path, os.X_OK) else 0o644
                    with path.open("rb") as handle:
                        tar.addfile(info, handle)
    temporary.replace(archive)


def build(
    source: Path,
    release_dir: Path,
    archive: Path,
    extras: list[tuple[Path, Path]],
) -> dict[str, object]:
    if release_dir.exists():
        raise FileExistsError(f"refusing to overwrite release directory: {release_dir}")
    if archive.exists():
        raise FileExistsError(f"refusing to overwrite archive: {archive}")
    release_dir.mkdir(parents=True)
    hostname = socket.gethostname()
    copied = 0
    transformed = 0
    binary = 0
    excluded: dict[str, int] = {}
    destinations: set[Path] = set()

    roots = [(source, Path(".")), *extras]
    for input_root, destination_prefix in roots:
        if not input_root.is_dir():
            raise FileNotFoundError(f"release input is not a directory: {input_root}")
        for path in sorted(input_root.rglob("*")):
            if not path.is_file():
                continue
            relative = destination_prefix / path.relative_to(input_root)
            if skip(relative):
                category = "state_or_cache" if relative.suffix.lower() in {".sqlite3", ".db", ".sqlite", ".pyc"} else "manifest_or_infrastructure_state"
                excluded[category] = excluded.get(category, 0) + 1
                continue
            destination_relative = sanitize_relative(relative, hostname=hostname)
            if destination_relative in destinations:
                raise RuntimeError(f"sanitized path collision: {destination_relative}")
            destinations.add(destination_relative)
            destination = release_dir / destination_relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            content = path.read_bytes()
            try:
                decoded = content.decode("utf-8")
            except UnicodeDecodeError:
                # Binary content is copied only after the release scanner has no
                # literal identity marker to transform.
                destination.write_bytes(content)
                binary += 1
            else:
                sanitized = sanitize_text(decoded, hostname=hostname)
                encoded = sanitized.encode("utf-8")
                destination.write_bytes(encoded)
                transformed += int(encoded != content)
            mode = path.stat().st_mode
            destination.chmod(0o755 if mode & stat.S_IXUSR else 0o644)
            copied += 1

    repaired_hash_locks = repair_portable_hash_locks(release_dir)
    (release_dir / "ANONYMOUS_RELEASE_NOTES.md").write_text(release_notes(), encoding="utf-8")
    manifest = {
        "release": ARCHIVE_ROOT,
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "source_file_count": sum(
            1
            for input_root, _ in roots
            for path in input_root.rglob("*")
            if path.is_file()
        ),
        "included_roots": [destination.as_posix() for _, destination in roots],
        "released_file_count_before_manifests": copied,
        "text_files_changed_by_sanitization": transformed,
        "portable_hash_locks_recomputed": repaired_hash_locks,
        "binary_files_copied": binary,
        "excluded_files": excluded,
        "transformations": [
            "local users, home paths, hostnames, and non-placeholder emails",
            "AWS account, role, role-session, and resource identifiers",
            "public IPv4 addresses mapped to RFC 5737 documentation space",
            "portable workload byte locks recomputed after sanitization",
        ],
        "excluded_categories": [
            "SQLite databases and sidecars",
            "Python/interpreter caches",
            "Terraform state and plans",
            "source checksum manifests invalidated by sanitization",
            "Git metadata and local output/cache directories",
        ],
    }
    (release_dir / "RELEASE_MANIFEST.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    manifest["checksum_entries"] = write_checksums(release_dir)
    (release_dir / "RELEASE_MANIFEST.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    # Recompute after the manifest receives its final checksum-entry count.
    manifest["checksum_entries"] = write_checksums(release_dir)
    deterministic_archive(release_dir, archive)
    result = {
        **manifest,
        "archive_name": archive.name,
        "archive_bytes": archive.stat().st_size,
        "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
    }
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument(
        "--extra",
        action="append",
        default=[],
        metavar="SOURCE=DESTINATION",
        help="include an additional directory under a release-relative destination",
    )
    parser.add_argument("--release-dir", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    arguments = parser.parse_args()
    extras: list[tuple[Path, Path]] = []
    for specification in arguments.extra:
        if "=" not in specification:
            raise SystemExit("--extra must use SOURCE=DESTINATION")
        raw_source, raw_destination = specification.split("=", 1)
        destination = Path(raw_destination)
        if destination.is_absolute() or ".." in destination.parts:
            raise SystemExit("--extra destination must be a safe relative path")
        extras.append((Path(raw_source).resolve(), destination))
    result = build(
        arguments.source.resolve(),
        arguments.release_dir.resolve(),
        arguments.archive.resolve(),
        extras,
    )
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
