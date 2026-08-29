#!/usr/bin/env python3
"""Reject credentials, deployment identity, and personal data in release trees."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


BLOCKED_SUFFIXES = {
    ".crt",
    ".cer",
    ".db",
    ".db3",
    ".der",
    ".jks",
    ".key",
    ".kdbx",
    ".keystore",
    ".ovpn",
    ".p12",
    ".pem",
    ".pfx",
    ".sqlite",
    ".sqlite3",
}

BLOCKED_NAMES = {
    ".env",
    ".npmrc",
    ".pypirc",
    "compose.override.yaml",
    "credentials",
    "id_ed25519",
    "id_rsa",
}

CONTENT_PATTERNS = (
    (
        "private key payload",
        re.compile(rb"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----"),
    ),
    ("certificate payload", re.compile(rb"-----BEGIN CERTIFICATE-----")),
    (
        "GitHub access token",
        re.compile(rb"(?:github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{20,})"),
    ),
    ("OpenAI API key", re.compile(rb"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("AWS access key", re.compile(rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    (
        "Windows user profile path",
        re.compile(rb"(?i)\b[A-Z]:\\Users\\[^\\/\r\n]+"),
    ),
    (
        "Unix user home path",
        re.compile(rb"(?<![A-Za-z0-9_.-])/home/[A-Za-z0-9_.-]+"),
    ),
    (
        "email address",
        re.compile(rb"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"),
    ),
)

CHUNK_BYTES = 1024 * 1024
PATTERN_OVERLAP_BYTES = 1024


def iter_files(roots: list[Path]):
    for root in roots:
        if not root.exists():
            raise FileNotFoundError(f"release hygiene path does not exist: {root}")
        if root.is_file():
            yield root, root.name
            continue
        for path in sorted(candidate for candidate in root.rglob("*") if candidate.is_file()):
            yield path, path.relative_to(root).as_posix()


def content_findings(path: Path) -> set[str]:
    findings: set[str] = set()
    carry = b""
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(CHUNK_BYTES)
            if not chunk:
                break
            sample = carry + chunk
            for label, pattern in CONTENT_PATTERNS:
                if label not in findings and pattern.search(sample):
                    findings.add(label)
            carry = sample[-PATTERN_OVERLAP_BYTES:]
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", type=Path, help="release trees to inspect")
    arguments = parser.parse_args()

    violations: list[str] = []
    scanned_count = 0
    for path, display_path in iter_files(arguments.paths):
        # The scanner contains the signatures it searches for and is not part
        # of release archives. Skip it when auditing a staged source tree.
        if path.name == Path(__file__).name:
            continue
        scanned_count += 1
        lower_name = path.name.lower()
        is_private_env = lower_name == ".env" or (
            lower_name.startswith(".env.") and lower_name != ".env.example"
        )
        if lower_name in BLOCKED_NAMES or is_private_env:
            violations.append(f"{display_path}: blocked deployment or credential filename")
        if path.suffix.lower() in BLOCKED_SUFFIXES:
            violations.append(f"{display_path}: blocked sensitive file type")
        for finding in sorted(content_findings(path)):
            violations.append(f"{display_path}: contains {finding}")

    if violations:
        print("Release hygiene check failed:", file=sys.stderr)
        for violation in violations:
            print(f"- {violation}", file=sys.stderr)
        return 1

    print(f"Release hygiene check passed: {scanned_count} files inspected.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
