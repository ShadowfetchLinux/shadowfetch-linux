#!/usr/bin/env python3
"""The releases/CURRENT.json contract: build it, and validate one before trusting it.

ADR-0009 makes one R2 key the answer to "which release is current": the
publisher writes releases/CURRENT.json LAST, and the artifact worker reads that
key instead of sorting an R2 listing by upload time. Two programs therefore have
to agree on the document's shape -- the worker (src/index.js, pointerProblem)
and this module, used by the prune tool so a destructive run cannot disagree
with the pointer about which release is live.

The document:

    {
      "schema": "shadowfetch.linux-current.v1",
      "version": "4.0.0",
      "published": "2026-09-06T00:00:00Z",
      "iso": {
        "filename": "shadowfetch-4.0.0-amd64.iso",
        "key": "releases/shadowfetch-4.0.0-amd64.iso",
        "size_bytes": 3400000000,
        "sha256": "<64 lowercase hex>"
      },
      "sidecars": {
        "sha256": "releases/shadowfetch-4.0.0-amd64.iso.sha256",
        "signature": "releases/shadowfetch-4.0.0-amd64.iso.asc"
      },
      "signing_key_fingerprint": "<40 uppercase hex>"
    }

This module validates SHAPE. It does not decide which key is the real signing
key: the worker holds that constant and refuses a pointer naming any other, and
the release TOML holds it for the build side. Adding a third copy here would be
the duplication ADR-0009 exists to remove.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re

SCHEMA = "shadowfetch.linux-current.v1"
KEY = "releases/CURRENT.json"
PREFIX = "releases/"
ISO_NAME = "shadowfetch-{version}-amd64.iso"

SEMVER = re.compile(r"^\d+\.\d+\.\d+$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")
FINGERPRINT = re.compile(r"^[0-9A-F]{40}$")


def iso_name(version: str) -> str:
    return ISO_NAME.format(version=version)


def iso_key(version: str) -> str:
    return PREFIX + iso_name(version)


def problems(document: object) -> list[str]:
    """Every reason this document must not be treated as the current release."""
    found: list[str] = []
    if not isinstance(document, dict):
        return ["pointer is not a JSON object"]
    if document.get("schema") != SCHEMA:
        found.append(f"schema is {document.get('schema')!r}, expected {SCHEMA!r}")

    version = document.get("version")
    if not isinstance(version, str) or not SEMVER.match(version):
        found.append(f"version {version!r} is not X.Y.Z")
        version = None

    iso = document.get("iso")
    if not isinstance(iso, dict):
        found.append("iso is missing or not an object")
    else:
        if version:
            if iso.get("filename") != iso_name(version):
                found.append("iso.filename does not match the version")
            if iso.get("key") != iso_key(version):
                found.append("iso.key is not releases/<filename>")
        size = iso.get("size_bytes")
        if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
            found.append("iso.size_bytes is not a positive integer")
        digest = iso.get("sha256")
        if not isinstance(digest, str) or not SHA256.match(digest):
            found.append("iso.sha256 is not 64 lowercase hex characters")

    fingerprint = document.get("signing_key_fingerprint")
    if not isinstance(fingerprint, str) or not FINGERPRINT.match(fingerprint):
        found.append("signing_key_fingerprint is not 40 uppercase hex characters")
    return found


def validate(document: object) -> dict:
    """Return the document, or raise ValueError listing everything wrong with it."""
    found = problems(document)
    if found:
        raise ValueError("; ".join(found))
    return document  # type: ignore[return-value]


def build(
    version: str,
    iso_path: Path,
    published: str,
    fingerprint: str,
    sha256: str | None = None,
) -> dict:
    """Build a pointer from the ISO that is actually on disk.

    Size and digest are read from the file rather than copied from a manifest,
    so a pointer can never describe bytes that were never published. A caller
    that has already digested the same file (the publisher does) may pass it in
    as `sha256` rather than reading multiple gigabytes twice.
    """
    if not SEMVER.match(version):
        raise ValueError(f"version {version!r} is not X.Y.Z")
    iso_path = Path(iso_path)
    if iso_path.name != iso_name(version):
        raise ValueError(f"{iso_path.name} is not the {version} release image")
    if sha256 is not None:
        if not SHA256.match(sha256):
            raise ValueError("sha256 is not 64 lowercase hex characters")
        digest = sha256
    else:
        with iso_path.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
    document = {
        "schema": SCHEMA,
        "version": version,
        "published": published,
        "iso": {
            "filename": iso_path.name,
            "key": iso_key(version),
            "size_bytes": iso_path.stat().st_size,
            "sha256": digest,
        },
        "sidecars": {
            "sha256": iso_key(version) + ".sha256",
            "signature": iso_key(version) + ".asc",
        },
        "signing_key_fingerprint": fingerprint,
    }
    return validate(document)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="validate an existing CURRENT.json")
    check.add_argument("path", type=Path)

    make = sub.add_parser("build", help="print a CURRENT.json for a local ISO")
    make.add_argument("--version", required=True)
    make.add_argument("--iso", type=Path, required=True)
    make.add_argument("--published", required=True, help="ISO-8601 timestamp")
    make.add_argument("--fingerprint", required=True)

    args = parser.parse_args(argv)
    if args.command == "check":
        found = problems(json.loads(args.path.read_text(encoding="utf-8")))
        for problem in found:
            print(f"{args.path}: {problem}")
        if found:
            return 1
        print(f"{args.path}: valid {SCHEMA}")
        return 0

    print(json.dumps(
        build(args.version, args.iso, args.published, args.fingerprint), indent=2,
    ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
