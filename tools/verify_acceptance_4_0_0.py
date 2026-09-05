#!/usr/bin/env python3
"""Record and verify Shadowfetch Linux 4.0.0 release evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
from typing import Any


VALID_STATUSES = {"pending", "pass", "fail", "blocked"}
VALID_PHASES = {"prepublish", "postpublish"}
VALID_KINDS = {"artifact", "json", "log", "report", "screenshot"}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_manifest(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("manifest root must be an object")
    return data


def save_manifest(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def png_size(path: Path) -> tuple[int, int]:
    with path.open("rb") as handle:
        header = handle.read(24)
    if len(header) != 24 or header[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("not a PNG file")
    if header[12:16] != b"IHDR":
        raise ValueError("PNG does not begin with IHDR")
    return struct.unpack(">II", header[16:24])


def repo_root_for(manifest: Path) -> Path:
    candidate = manifest.resolve()
    for parent in (candidate.parent, *candidate.parents):
        if (parent / "Makefile").is_file() and (parent / "packages").is_dir():
            return parent
    raise ValueError(f"could not locate repository root above {manifest}")


def evidence_root_for(manifest: Path, data: dict[str, Any]) -> Path:
    root = Path(str(data.get("evidence_root", "")))
    if not root.is_absolute():
        root = repo_root_for(manifest) / root
    return root.resolve()


def resolve_evidence(root: Path, value: str) -> Path:
    candidate = (root / value).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"evidence path escapes evidence root: {value}") from exc
    return candidate


def validate_manifest(data: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if data.get("schema_version") != 1:
        errors.append("schema_version must be 1")
    release = data.get("release")
    if not isinstance(release, dict):
        errors.append("release must be an object")
    else:
        expected = {
            "version": "4.0.0",
            "edition": "Fire and Ice",
            "codename": "Umbra",
        }
        for key, value in expected.items():
            if release.get(key) != value:
                errors.append(f"release.{key} must be {value!r}")

    cases = data.get("cases")
    if not isinstance(cases, list) or not cases:
        errors.append("cases must be a non-empty array")
        return errors

    seen: set[str] = set()
    for index, case in enumerate(cases):
        label = f"cases[{index}]"
        if not isinstance(case, dict):
            errors.append(f"{label} must be an object")
            continue
        case_id = case.get("id")
        if not isinstance(case_id, str) or not case_id:
            errors.append(f"{label}.id must be a non-empty string")
        elif case_id in seen:
            errors.append(f"duplicate case id: {case_id}")
        else:
            seen.add(case_id)
        if case.get("phase") not in VALID_PHASES:
            errors.append(f"{case_id or label}: invalid phase")
        if case.get("status") not in VALID_STATUSES:
            errors.append(f"{case_id or label}: invalid status")
        if not isinstance(case.get("required"), bool):
            errors.append(f"{case_id or label}: required must be boolean")
        if not isinstance(case.get("evidence"), list):
            errors.append(f"{case_id or label}: evidence must be an array")
    return errors


def verify(args: argparse.Namespace) -> int:
    manifest = args.manifest.resolve()
    data = load_manifest(manifest)
    errors = validate_manifest(data)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1

    evidence_root = evidence_root_for(manifest, data)
    selected_phases = {"prepublish"}
    if args.phase == "final":
        selected_phases.add("postpublish")

    selected = [
        case
        for case in data["cases"]
        if case["required"] and case["phase"] in selected_phases
    ]
    for case in selected:
        case_id = case["id"]
        status = case["status"]
        if status != "pass":
            if not args.allow_pending or status != "pending":
                errors.append(f"{case_id}: required status is {status}, not pass")
            continue
        evidence = case["evidence"]
        if not evidence:
            errors.append(f"{case_id}: passing case has no evidence")
            continue
        for index, item in enumerate(evidence):
            label = f"{case_id}.evidence[{index}]"
            if not isinstance(item, dict):
                errors.append(f"{label}: entry must be an object")
                continue
            kind = item.get("kind")
            path_value = item.get("path")
            expected_hash = item.get("sha256")
            if kind not in VALID_KINDS:
                errors.append(f"{label}: invalid kind {kind!r}")
                continue
            if not isinstance(path_value, str) or not path_value:
                errors.append(f"{label}: path must be a non-empty string")
                continue
            if not isinstance(expected_hash, str) or len(expected_hash) != 64:
                errors.append(f"{label}: sha256 must contain 64 hexadecimal characters")
                continue
            try:
                evidence_path = resolve_evidence(evidence_root, path_value)
            except ValueError as exc:
                errors.append(f"{label}: {exc}")
                continue
            if not evidence_path.is_file():
                errors.append(f"{label}: missing file {evidence_path}")
                continue
            actual_hash = sha256_file(evidence_path)
            if actual_hash != expected_hash.lower():
                errors.append(
                    f"{label}: SHA-256 mismatch, expected {expected_hash}, got {actual_hash}"
                )
            if kind == "screenshot":
                try:
                    width, height = png_size(evidence_path)
                except ValueError as exc:
                    errors.append(f"{label}: {exc}")
                else:
                    if width < 1280 or height < 720:
                        errors.append(
                            f"{label}: screenshot is {width}x{height}, below 1280x720"
                        )

    if not args.allow_pending:
        artifact = data.get("artifact")
        if not isinstance(artifact, dict):
            errors.append("artifact must be an object")
        else:
            required_artifact_fields = (
                "iso_path",
                "iso_sha256",
                "iso_size_bytes",
                "signature_path",
                "signing_fingerprint",
                "evidence_bundle_path",
                "evidence_bundle_sha256",
            )
            for field in required_artifact_fields:
                if artifact.get(field) in (None, "", 0):
                    errors.append(f"artifact.{field} is not recorded")

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        print(
            f"ACCEPTANCE_FAILED phase={args.phase} errors={len(errors)}",
            file=sys.stderr,
        )
        return 1

    passed = sum(1 for case in selected if case["status"] == "pass")
    pending = sum(1 for case in selected if case["status"] == "pending")
    print(
        f"ACCEPTANCE_PASSED phase={args.phase} required={len(selected)} "
        f"passed={passed} pending={pending} evidence_root={evidence_root}"
    )
    return 0


def record(args: argparse.Namespace) -> int:
    manifest = args.manifest.resolve()
    data = load_manifest(manifest)
    errors = validate_manifest(data)
    if errors:
        raise ValueError("; ".join(errors))
    matching = [case for case in data["cases"] if case["id"] == args.case_id]
    if not matching:
        raise ValueError(f"unknown case id: {args.case_id}")
    case = matching[0]
    case["status"] = args.status
    if args.notes is not None:
        case["notes"] = args.notes

    if args.clear_evidence:
        case["evidence"] = []
    if args.evidence:
        evidence_root = evidence_root_for(manifest, data)
        evidence_root.mkdir(parents=True, exist_ok=True)
        recorded = []
        for source in args.evidence:
            source = source.resolve()
            if not source.is_file():
                raise ValueError(f"evidence file does not exist: {source}")
            try:
                relative = source.relative_to(evidence_root)
            except ValueError as exc:
                raise ValueError(
                    f"evidence must be inside {evidence_root}: {source}"
                ) from exc
            kind = args.kind
            if kind is None:
                kind = "screenshot" if source.suffix.lower() == ".png" else "log"
            recorded.append(
                {
                    "kind": kind,
                    "path": relative.as_posix(),
                    "sha256": sha256_file(source),
                }
            )
        case["evidence"] = recorded

    if args.status == "pass" and not case["evidence"]:
        raise ValueError("a passing case must have at least one evidence file")
    save_manifest(manifest, data)
    print(
        f"RECORDED case={args.case_id} status={args.status} "
        f"evidence={len(case['evidence'])}"
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    default_manifest = (
        Path(__file__).resolve().parents[1] / "qa" / "4.0.0" / "acceptance.json"
    )
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=default_manifest)
    subparsers = parser.add_subparsers(dest="command", required=True)

    verify_parser = subparsers.add_parser("verify", help="verify recorded evidence")
    verify_parser.add_argument("--phase", choices=("prepublish", "final"), default="prepublish")
    verify_parser.add_argument(
        "--allow-pending",
        action="store_true",
        help="validate structure and recorded passes without failing pending cases",
    )
    verify_parser.set_defaults(func=verify)

    record_parser = subparsers.add_parser("record", help="record one case result")
    record_parser.add_argument("case_id")
    record_parser.add_argument("--status", choices=sorted(VALID_STATUSES), required=True)
    record_parser.add_argument("--evidence", action="append", type=Path)
    record_parser.add_argument("--kind", choices=sorted(VALID_KINDS))
    record_parser.add_argument("--notes")
    record_parser.add_argument("--clear-evidence", action="store_true")
    record_parser.set_defaults(func=record)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return args.func(args)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
