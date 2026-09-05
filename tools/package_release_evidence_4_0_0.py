#!/usr/bin/env python3
"""Package an explicit, hash-verified prepublication evidence snapshot.

This does not record acceptance or publish anything. All required prepublication
cases except EVIDENCE-01 must already pass. EVIDENCE-01 stays pending while this
bundle is produced, avoiding a bundle containing its own acceptance hash.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tarfile
import tempfile

import verify_acceptance_4_0_0 as acceptance


VERSION = "4.0.0"
PREFIX = f"shadowfetch-{VERSION}-evidence"
BUNDLE = f"evidence-bundle-{VERSION}.tar.gz"
CONTENTS = f"evidence-bundle-{VERSION}.contents"
GENERATED = tuple(f"{stem}-{VERSION}{suffix}" for stem, suffix in (
    ("dossier", ".md"), ("packages", ".manifest"), ("sbom", ".cdx.json"),
    ("sbom-sources", ".txt"), ("release-facts", ".json"),
))
CHECKSUMS = f"release-evidence-{VERSION}.sha256"
QA_SOURCES = (
    "tools/build_release_evidence_4_0_0.py",
    "tools/iso_gate_4_0_0.py",
    "tools/drkonqi_pickup_contract.py",
    "tools/package_release_evidence_4_0_0.py",
    "tools/verify_acceptance_4_0_0.py",
    "tools/publish_release_4_0_0.py",
    "tools/pre_release_check.sh",
    "tools/package_gate_4_0_0.py",
    "tools/build_drkonqi_pickup.sh",
    "tools/containers/drkonqi-build.Containerfile",
    "tools/qa_4_0_0/README.md",
    "tools/qa_4_0_0/vm_harness.sh",
    "tools/qa_4_0_0/qga_exec.py",
    "tools/qa_4_0_0/stress_45m.sh",
    "tools/qa_4_0_0/classify_service_journal.py",
    "tools/qa_4_0_0/mission_stress.py",
    "tools/qa_4_0_0/container_stress.py",
    "tools/qa_4_0_0/latency_probe.py",
    "tools/qa_4_0_0/engine_acceptance.py",
    "tools/qa_4_0_0/durable_worker_acceptance.py",
    "tools/qa_4_0_0/native_mission_acceptance.py",
    "tools/qa_4_0_0/upgrade_recovery_acceptance.py",
    "tools/qa_4_0_0/installed_audit.sh",
    "tools/qa_4_0_0/native_ui_probe.py",
    "tools/qa_4_0_0/native_atspi.py",
)
MAX_FILE = 256 * 1024**2
MAX_TOTAL = 1024**3
MAX_FILES = 512
HEX = re.compile(r"[0-9a-fA-F]{64}\Z")
RASTER = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp", ".ppm"}


def relative_name(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 512:
        raise ValueError("Expected a bounded relative file path")
    path = PurePosixPath(value)
    if (path.is_absolute() or "\\" in value or
            any(ord(c) < 32 or ord(c) == 127 for c in value) or
            any(part in ("", ".", "..") for part in value.split("/"))):
        raise ValueError(f"Unsafe or escaping relative path: {value!r}")
    return path.as_posix()


def checked_path(root: Path, value: str, *, directory: bool = False) -> Path:
    value = relative_name(value)
    current = root
    for part in value.split("/"):
        current = current / part
        if current.is_symlink():
            raise ValueError(f"Symbolic links are not evidence inputs: {value}")
    current.resolve().relative_to(root)
    mode = current.stat().st_mode
    if not (stat.S_ISDIR(mode) if directory else stat.S_ISREG(mode)):
        raise ValueError(f"Expected a regular {'directory' if directory else 'file'}: {value}")
    return current


def expected_hash(value: str) -> str:
    if not isinstance(value, str) or not HEX.fullmatch(value):
        raise ValueError("Expected a SHA256 digest with 64 hexadecimal characters")
    return value.lower()


def json_bytes(value) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


class Snapshot:
    def __init__(self, root: Path, staging: Path):
        self.root, self.staging = root, staging
        self.entries: dict[str, dict] = {}
        self.total = 0

    def _reserve(self, name: str, size: int):
        relative_name(name)
        if name in self.entries:
            raise ValueError(f"Duplicate archive destination: {name}")
        if size > MAX_FILE or self.total + size > MAX_TOTAL or len(self.entries) >= MAX_FILES:
            raise ValueError("Evidence bundle exceeds bounded file/count/total limits")

    def add_bytes(self, name: str, data: bytes):
        self._reserve(name, len(data))
        path = self.staging / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        self.entries[name] = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
        self.total += len(data)

    def add_file(self, name: str, source: str, digest: str | None = None):
        path = checked_path(self.root, source)
        if path.name in (BUNDLE, CONTENTS):
            raise ValueError("Circular evidence-bundle reference is forbidden")
        size = path.stat().st_size
        self._reserve(name, size)
        destination = self.staging / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        actual = hashlib.sha256()
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as stream, destination.open("wb") as out:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size != size:
                raise ValueError(f"Input changed while opening: {source}")
            for chunk in iter(lambda: stream.read(1024**2), b""):
                actual.update(chunk)
                out.write(chunk)
                if out.tell() > size:
                    raise ValueError(f"Input grew while copying: {source}")
            after = os.fstat(stream.fileno())
        if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
            raise ValueError(f"Input changed while copying: {source}")
        checked_path(self.root, source)
        if destination.stat().st_size != size:
            raise ValueError(f"Input truncated while copying: {source}")
        actual_hash = actual.hexdigest()
        if digest is not None and actual_hash != expected_hash(digest):
            raise ValueError(f"SHA256 mismatch: {source}")
        self.entries[name] = {"sha256": actual_hash, "size": size}
        self.total += size


def approve_inputs(root: Path, path: str) -> dict:
    approval_file = checked_path(root, path)
    if approval_file.stat().st_size > 1024**2:
        raise ValueError("Approved input manifest exceeds 1 MiB")
    data = json.loads(approval_file.read_text())
    if not isinstance(data, dict) or set(data) != {"schema_version", "screenshots", "documents"} or data["schema_version"] != 1:
        raise ValueError("Approval input requires schema_version=1, screenshots and documents")
    for category in ("screenshots", "documents"):
        if not isinstance(data[category], list) or len(data[category]) > MAX_FILES:
            raise ValueError(f"Invalid approved {category} array")
        seen = set()
        for item in data[category]:
            if not isinstance(item, dict) or set(item) != {"path", "sha256", "approved"} or item["approved"] is not True:
                raise ValueError(f"Every {category} input needs explicit approved:true, path and sha256")
            name = relative_name(item["path"])
            expected_hash(item["sha256"])
            if name in seen:
                raise ValueError(f"Duplicate approved input: {name}")
            seen.add(name)
            suffix = PurePosixPath(name).suffix.lower()
            if category == "screenshots" and suffix != ".png":
                raise ValueError("Approved screenshots must be actual PNG captures")
            if category == "documents" and suffix not in {".md", ".txt", ".pdf", ".docx", ".html", ".json"}:
                raise ValueError(f"Unsupported release document type: {name}")
    return data


def validate_prepublication(data: dict):
    errors = acceptance.validate_manifest(data)
    for case in data.get("cases", []):
        if not isinstance(case, dict):
            continue
        if case.get("phase") == "postpublish" and (case.get("status") != "pending" or case.get("evidence")):
            errors.append("Prepublication bundle cannot claim publication has passed")
        if case.get("id") == "EVIDENCE-01":
            if case.get("status") != "pending":
                errors.append("EVIDENCE-01 must remain pending until bundle verification")
        elif case.get("required") and case.get("phase") == "prepublish":
            if case.get("status") != "pass" or not case.get("evidence"):
                errors.append(f"{case.get('id')}: required prepublication evidence has not passed")
    if not any(c.get("id") == "EVIDENCE-01" for c in data.get("cases", []) if isinstance(c, dict)):
        errors.append("Missing EVIDENCE-01 packaging case")
    artifact = data.get("artifact", {})
    if artifact.get("evidence_bundle_sha256"):
        errors.append("Circular bundle digest: package before recording artifact.evidence_bundle_sha256")
    if errors:
        raise ValueError("; ".join(errors))


def package(root: Path, output_dir: str, approved_path: str) -> dict:
    if root.is_symlink():
        raise ValueError("Repository root cannot be a symbolic link")
    root = root.resolve(strict=True)
    output = checked_path(root, output_dir, directory=True)
    for name in (BUNDLE, CONTENTS):
        if (output / name).exists() or (output / name).is_symlink():
            raise ValueError(f"Preserve the prior snapshot before rebuilding: {output / name}")
    manifest_path = checked_path(root, "qa/4.0.0/acceptance.json")
    if manifest_path.stat().st_size > 8 * 1024**2:
        raise ValueError("Acceptance manifest exceeds 8 MiB")
    manifest_bytes = manifest_path.read_bytes()
    data = json.loads(manifest_bytes)
    validate_prepublication(data)
    approvals = approve_inputs(root, approved_path)
    evidence_root = relative_name(data["evidence_root"])
    checked_path(root, evidence_root, directory=True)
    artifact = data["artifact"]
    iso = checked_path(root, artifact["iso_path"])
    if iso.stat().st_size != artifact.get("iso_size_bytes") or acceptance.sha256_file(iso) != expected_hash(artifact.get("iso_sha256")):
        raise ValueError("ISO identity differs from prepublication acceptance")
    checked_path(root, artifact["signature_path"])
    if not re.fullmatch(r"[0-9A-Fa-f]{40}", artifact.get("signing_fingerprint", "")):
        raise ValueError("A full signing fingerprint is required")
    approved_shots = {item["path"]: expected_hash(item["sha256"]) for item in approvals["screenshots"]}
    with tempfile.TemporaryDirectory(prefix=".evidence-snapshot-", dir=output) as temp:
        staging = Path(temp) / "files"
        staging.mkdir()
        snapshot = Snapshot(root, staging)
        # Original statuses are retained; no output digest is inserted here.
        snapshot.add_bytes("acceptance.prepublication.json", json_bytes(data))
        snapshot.add_bytes("approved-inputs.json", json_bytes(approvals))
        references: dict[str, str] = {}
        for case in data["cases"]:
            for item in case["evidence"]:
                if not isinstance(item, dict) or item.get("kind") not in acceptance.VALID_KINDS:
                    raise ValueError(f"Invalid evidence entry in {case['id']}")
                name, digest = relative_name(item["path"]), expected_hash(item["sha256"])
                if name in references and references[name] != digest:
                    raise ValueError(f"Conflicting referenced hashes: {name}")
                if item["kind"] == "screenshot" or PurePosixPath(name).suffix.lower() in RASTER:
                    if approved_shots.get(name) != digest:
                        raise ValueError(f"Screenshot has not been explicitly approved at this hash: {name}")
                references[name] = digest
        for name, digest in approved_shots.items():
            if name in references and references[name] != digest:
                raise ValueError(f"Approved screenshot differs from acceptance: {name}")
            references[name] = digest
        for name, digest in sorted(references.items()):
            source = evidence_root + "/" + name
            if name in approved_shots:
                width, height = acceptance.png_size(checked_path(root, source))
                if width < 1280 or height < 720:
                    raise ValueError(f"Approved screenshot below 1280x720: {name}")
            snapshot.add_file("evidence/" + name, source, digest)
        # Generated release document hashes are a closed set, not a glob.
        release_dir = "work/release-4.0.0"
        checksum_file = checked_path(root, release_dir + "/" + CHECKSUMS)
        checksums = {}
        for line in checksum_file.read_text().splitlines():
            match = re.fullmatch(r"([a-fA-F0-9]{64})  ([^/\\]+)", line)
            if not match or match[2] in checksums:
                raise ValueError("Malformed or duplicate generated release checksum")
            checksums[match[2]] = match[1].lower()
        if set(checksums) != set(GENERATED):
            raise ValueError("Generated release checksum list differs from the five expected documents")
        for name in (*GENERATED, CHECKSUMS):
            snapshot.add_file("release/" + name, release_dir + "/" + name, checksums.get(name))
        facts_path = staging / "release" / f"release-facts-{VERSION}.json"
        if facts_path.stat().st_size > 8 * 1024**2:
            raise ValueError("Release facts exceed 8 MiB")
        facts = json.loads(facts_path.read_text())
        if facts.get("publicationStatus") != "prepublication" or facts.get("iso") != artifact:
            raise ValueError("Generated release facts are stale or not a prepublication snapshot")
        for item in approvals["documents"]:
            snapshot.add_file("documents/" + item["path"], item["path"], item["sha256"])
        for name in QA_SOURCES:
            snapshot.add_file("source/" + name, name)
        snapshot.add_file("release/" + PurePosixPath(artifact["signature_path"]).name, artifact["signature_path"])
        snapshot.add_bytes("bundle-metadata.json", json_bytes({
            "schema_version": 1, "release": VERSION, "publication_status": "prepublication",
            "iso_sha256": artifact["iso_sha256"], "iso_size_bytes": artifact["iso_size_bytes"],
            "snapshot_rule": "EVIDENCE-01 remains pending; record bundle hash only in the external acceptance manifest after inspection.",
            "scope": "Explicit acceptance evidence, approved captures/documents, generated release docs, signature and named QA sources. ISO bytes and unrelated work files excluded.",
            "source_acceptance_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "member_hashes": dict(sorted(snapshot.entries.items())),
        }))
        sums = "".join(f"{entry['sha256']}  {PREFIX}/{name}\n" for name, entry in sorted(snapshot.entries.items()))
        snapshot.add_bytes("SHA256SUMS", sums.encode())
        archive_path = Path(temp) / BUNDLE
        with archive_path.open("wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as tar:
                for name, entry in sorted(snapshot.entries.items()):
                    info = tarfile.TarInfo(PREFIX + "/" + name)
                    info.size, info.mode, info.mtime = entry["size"], 0o644, 0
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    with (staging / name).open("rb") as source:
                        tar.addfile(info, source)
        contents = "".join(f"{entry['sha256']}  {PREFIX}/{name}\n" for name, entry in sorted(snapshot.entries.items()))
        # Validate actual archive bytes before exposing the final output names.
        with tarfile.open(archive_path, "r:gz") as tar:
            if tar.getnames() != [PREFIX + "/" + name for name in sorted(snapshot.entries)]:
                raise ValueError("Archive member list differs from snapshot")
            for member in tar:
                if not member.isfile():
                    raise ValueError("Archive contains a non-file member")
                digest = hashlib.file_digest(tar.extractfile(member), "sha256").hexdigest()
                if digest != snapshot.entries[member.name[len(PREFIX) + 1:]]["sha256"]:
                    raise ValueError("Archive member hash/type mismatch")
        if manifest_path.read_bytes() != manifest_bytes:
            raise ValueError("Acceptance manifest changed during packaging")
        (Path(temp) / CONTENTS).write_text(contents)
        result = {"bundle": str(output / BUNDLE), "sha256": acceptance.sha256_file(archive_path),
                  "contents": str(output / CONTENTS), "members": len(snapshot.entries),
                  "uncompressed_bytes": snapshot.total, "acceptance_modified": False}
        os.replace(Path(temp) / CONTENTS, output / CONTENTS)
        os.replace(archive_path, output / BUNDLE)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output-dir", default="work/release-4.0.0", help="Existing repository-relative output directory")
    parser.add_argument("--approved-inputs", required=True, help="Repository-relative explicit screenshot/document approval JSON")
    args = parser.parse_args()
    try:
        print(json.dumps(package(args.root, args.output_dir, args.approved_inputs), indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print(f"EVIDENCE_BUNDLE_FAILED: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
