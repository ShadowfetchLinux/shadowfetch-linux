#!/usr/bin/env python3
"""Evidence collection, quality floors and receipt digests.

Two rules drive this module.

  A zero-byte artifact is not evidence. Neither is a blank screenshot or an
  all-zero log. The floors are not invented here: they are imported from
  tools/release/acceptance.py, so a file this harness accepts is a file the
  release gate will also accept. One source of truth, no drift.

  Evidence is bound to the artifact digest. A receipt names the ISO it was
  produced from, lists every evidence file with its SHA-256, and is itself
  hashed. Moving a receipt to a different artifact, or swapping a file under a
  receipt, breaks the digest.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import time
from typing import Any

from . import release_link


class EvidenceError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical(payload: Any) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def digest_of(payload: Any) -> str:
    return hashlib.sha256(canonical(payload)).hexdigest()


class EvidenceSet:
    """The evidence produced by one run, inside the release evidence root."""

    def __init__(self, repo_root: Path, directory: Path) -> None:
        self.repo_root = repo_root
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)
        # The live release recorder, imported not reimplemented: a file this
        # harness accepts is a file the release gate accepts.
        self.recorder = release_link.recorder()
        self.items: list[dict[str, Any]] = []

    def path(self, name: str) -> Path:
        return self.directory / name

    def write_text(self, name: str, text: str, kind: str = "log") -> Path:
        target = self.path(name)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        self.add(target, kind)
        return target

    def write_json(self, name: str, payload: Any, kind: str = "json") -> Path:
        return self.write_text(
            name, json.dumps(payload, indent=2, sort_keys=True) + "\n", kind
        )

    def add(self, path: Path, kind: str) -> dict[str, Any]:
        """Register a file as evidence, refusing anything that cannot be one."""
        path = path.resolve()
        if not path.is_file():
            raise EvidenceError(f"evidence file does not exist: {path}")
        try:
            path.relative_to(self.directory.resolve())
        except ValueError as error:
            raise EvidenceError(
                f"evidence must be written inside {self.directory}: {path}"
            ) from error
        if kind not in self.recorder.VALID_KINDS:
            raise EvidenceError(f"invalid evidence kind {kind!r}")
        problems = self.recorder.evidence_quality_errors(path, kind)
        if problems:
            raise EvidenceError(f"unusable evidence {path}: " + "; ".join(problems))
        if kind == "screenshot":
            width, height = self.recorder.png_size(path)
            if width < 1280 or height < 720:
                raise EvidenceError(
                    f"screenshot {path} is {width}x{height}, below the 1280x720 "
                    "floor the release gate enforces"
                )
        try:
            located = str(path.relative_to(self.repo_root))
        except ValueError:
            # Evidence normally lives under the release evidence root inside the
            # repository. A run driven at an arbitrary directory (tests, a
            # scratch tree) still records a resolvable path rather than failing:
            # "root / absolute" is the absolute path again, so verify() reads
            # the same file back.
            located = str(path)
        item = {
            "kind": kind,
            "name": path.name,
            "relative_path": located,
            "bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        }
        self.items.append(item)
        return item

    def try_add(self, path: Path, kind: str) -> dict[str, Any] | None:
        """Register evidence, returning None instead of raising.

        Used for supporting captures (a serial log that never got written, a
        console screenshot on a machine that is off). A missing supporting
        capture must not crash a run that otherwise produced a real result --
        but it must also never quietly become a recorded piece of evidence.
        """
        try:
            return self.add(path, kind)
        except (EvidenceError, ValueError, OSError):
            return None

    def relative_to_evidence_root(self, root: Path) -> list[str]:
        return [
            str((self.repo_root / item["relative_path"]).resolve().relative_to(root))
            for item in self.items
        ]


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def harness_fingerprint(package_dir: Path) -> dict[str, Any]:
    """Hash the harness itself.

    A verdict is only as good as the code that produced it. Recording which
    bytes of harness produced a receipt is what lets a reviewer tell a PASS
    from an older, weaker version of the same case apart.
    """
    files = {}
    for path in sorted(package_dir.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        files[str(path.relative_to(package_dir))] = sha256_file(path)
    return {"files": files, "digest": digest_of(files)}
