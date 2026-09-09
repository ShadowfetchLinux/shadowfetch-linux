"""Unit tests for the live acceptance verifier (tools/release/acceptance.py).

W-14: no junk evidence, hard gate. Before Stage Q these cases existed three
times over -- against verify_acceptance_2_1_4.py and _2_1_5.py as well -- and
the two archived copies do not have the waiver contract or the evidence-quality
floors at all, so passing there proved nothing about the release.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
import zlib


RELEASE_DIR = Path(__file__).resolve().parents[1] / "release"
if str(RELEASE_DIR) not in sys.path:
    sys.path.insert(0, str(RELEASE_DIR))

import gate  # noqa: E402

SCRIPT = RELEASE_DIR / "acceptance.py"
SPEC = importlib.util.spec_from_file_location("release_acceptance_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
qa = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(qa)

# The release identity a manifest must declare is version DATA now, so the
# tests read it from the same file the gate reads.
RELEASE = gate.load_release("4.0.0")


def full_artifact(iso_sha256: str = "a" * 64, iso_size_bytes: int = 1) -> dict:
    """The artifact block. The digest and size are parameters now, because the
    gate OPENS the file and compares -- a placeholder digest for a file that
    never existed is the state it exists to refuse."""
    return {
        "iso_path": "shadowfetch-4.0.0-amd64.iso",
        "iso_sha256": iso_sha256,
        "iso_size_bytes": iso_size_bytes,
        "signature_path": "shadowfetch-4.0.0-amd64.iso.asc",
        "signing_fingerprint": "8F13CE1535EE1F4A2916A1F73C5C900B7BE80CA1",
        "evidence_bundle_path": "evidence-bundle-4.0.0.tar.gz",
        "evidence_bundle_sha256": "b" * 64,
    }


def base_manifest(artifact: dict | None = None) -> dict:
    return {
        "schema_version": 1,
        "release": {
            "version": "4.0.0",
            "edition": "Fire and Ice",
            "codename": "Umbra",
        },
        "evidence_root": "work/qa-4.0.0/evidence",
        "artifact": artifact if artifact is not None else full_artifact(),
        "cases": [
            {
                "id": "SRC-01",
                "phase": "prepublish",
                "area": "test",
                "title": "Pre-publication test",
                "required": True,
                "status": "pending",
                "evidence": [],
                "notes": "",
            },
            {
                "id": "PUB-01",
                "phase": "postpublish",
                "area": "test",
                "title": "Post-publication test",
                "required": False,
                "status": "pending",
                "evidence": [],
                "notes": "",
            },
        ],
    }


def png_chunk(tag: bytes, payload: bytes) -> bytes:
    body = tag + payload
    return struct.pack(">I", len(payload)) + body + struct.pack(">I", zlib.crc32(body))


def solid_png(width: int, height: int) -> bytes:
    """A real, valid PNG of a single flat colour — the junk screenshot from the audit."""
    raw = b"".join(b"\x00" + b"\x00" * (width * 3) for _ in range(height))
    header = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + png_chunk(b"IHDR", header)
        + png_chunk(b"IDAT", zlib.compress(raw, 9))
        + png_chunk(b"IEND", b"")
    )


def detailed_png(width: int, height: int) -> bytes:
    """A PNG-headed file with real, high-entropy payload — stands in for a screenshot."""
    header = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + png_chunk(b"IHDR", header) + os.urandom(8192)


class AcceptanceVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "Makefile").write_text("test:\n\t@true\n", encoding="utf-8")
        (self.root / "packages").mkdir()
        self.manifest = self.root / "qa" / "4.0.0" / "acceptance.json"
        self.manifest.parent.mkdir(parents=True)
        self.evidence_root = self.root / "work" / "qa-4.0.0" / "evidence"
        self.evidence_root.mkdir(parents=True)
        # A REAL artifact on disk. The gate re-hashes it, so a manifest whose
        # digest names nothing is a manifest describing nothing -- which is
        # what these fixtures used to be, and what the audit found in the
        # shipped one.
        self.iso = self.root / "shadowfetch-4.0.0-amd64.iso"
        body = os.urandom(4096)
        self.iso.write_bytes(body)
        self.iso_sha256 = hashlib.sha256(body).hexdigest()
        self.artifact = full_artifact(self.iso_sha256, len(body))

    def bound_manifest(self) -> dict:
        """A manifest whose artifact really is the file on disk."""
        return base_manifest(dict(self.artifact))

    def bind(self, data: dict) -> dict:
        """Stamp every recorded evidence entry with the artifact digest, the
        way `record` does. A test that recorded evidence by hand and then
        expected `verify` to pass would be asserting the hole is still open."""
        for case in data["cases"]:
            for item in case.get("evidence") or []:
                if isinstance(item, dict) and "sha256" in item:
                    item.setdefault("artifact_sha256", self.iso_sha256)
        return data

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_manifest(self, data: dict) -> None:
        self.manifest.write_text(json.dumps(data), encoding="utf-8")

    def verify(self, phase: str = "prepublish", allow_pending: bool = True) -> int:
        return qa.verify(
            argparse.Namespace(
                manifest=self.manifest,
                phase=phase,
                allow_pending=allow_pending,
                release=RELEASE,
            )
        )

    def record(self, **kwargs) -> int:
        namespace = {
            "manifest": self.manifest,
            "release": RELEASE,
            "case_id": "SRC-01",
            "status": "pass",
            "evidence": None,
            "kind": None,
            "notes": None,
            "waiver_approver": None,
            "waiver_reason": None,
            "clear_evidence": False,
        }
        namespace.update(kwargs)
        return qa.record(argparse.Namespace(**namespace))

    def evidence_case(self, name: str, payload: bytes, kind: str,
                      bound: bool = True) -> dict:
        path = self.evidence_root / name
        path.write_bytes(payload)
        data = self.bound_manifest()
        data["cases"][0]["status"] = "pass"
        entry = {
            "kind": kind,
            "path": name,
            "sha256": hashlib.sha256(payload).hexdigest(),
        }
        if bound:
            entry["artifact_sha256"] = self.iso_sha256
        data["cases"][0]["evidence"] = [entry]
        return data

    # ---- the hard gate -----------------------------------------------------

    def test_audit_reports_pending_but_gate_rejects_it(self) -> None:
        self.write_manifest(base_manifest())
        self.assertEqual(self.verify(allow_pending=True), 0)
        self.assertEqual(self.verify(allow_pending=False), 1)

    def test_gate_subcommand_is_hard_and_audit_subcommand_is_soft(self) -> None:
        parser = qa.build_parser()
        gate = parser.parse_args(["acceptance-gate"])
        audit = parser.parse_args(["acceptance-audit"])
        self.assertFalse(gate.allow_pending)
        self.assertTrue(audit.allow_pending)
        self.assertIs(gate.func, qa.verify)
        self.assertIs(audit.func, qa.verify)
        self.assertFalse(parser.parse_args(["gate"]).allow_pending)
        self.assertTrue(parser.parse_args(["audit"]).allow_pending)

    # ---- waivers -----------------------------------------------------------

    def test_waived_case_without_reason_is_rejected(self) -> None:
        data = base_manifest()
        data["cases"][0]["status"] = "waived"
        self.assertIn("waiver object", " ".join(qa.validate_manifest(data, RELEASE)))
        data["cases"][0]["waiver"] = {"approver": "R. Corbin", "reason": "   "}
        self.assertIn("waiver.reason", " ".join(qa.validate_manifest(data, RELEASE)))

    def test_waived_case_with_written_reason_passes_the_gate(self) -> None:
        data = self.bound_manifest()
        data["cases"][0]["status"] = "waived"
        data["cases"][0]["waiver"] = {
            "approver": "R. Corbin",
            "reason": "no NVIDIA host available for this candidate; deferred to 4.0.1",
        }
        self.write_manifest(data)
        self.assertEqual(self.verify(allow_pending=False), 0)

    def test_record_waived_requires_approver_and_reason(self) -> None:
        self.write_manifest(base_manifest())
        with self.assertRaisesRegex(ValueError, "waiver"):
            self.record(status="waived")
        self.assertEqual(
            self.record(
                status="waived",
                waiver_approver="R. Corbin",
                waiver_reason="hardware unavailable",
            ),
            0,
        )
        recorded = json.loads(self.manifest.read_text(encoding="utf-8"))
        self.assertEqual(
            recorded["cases"][0]["waiver"],
            {"approver": "R. Corbin", "reason": "hardware unavailable"},
        )

    # ---- junk evidence -----------------------------------------------------

    def test_zero_byte_evidence_is_rejected(self) -> None:
        self.write_manifest(self.evidence_case("empty.log", b"", "log"))
        self.assertEqual(self.verify(), 1)

    def test_uniform_low_entropy_log_is_rejected(self) -> None:
        self.write_manifest(self.evidence_case("null.log", b"\x00" * 4096, "log"))
        self.assertEqual(self.verify(), 1)

    def test_solid_colour_screenshot_is_rejected(self) -> None:
        payload = solid_png(1280, 720)
        self.assertGreaterEqual(len(payload), qa.MIN_SCREENSHOT_BYTES)
        self.write_manifest(self.evidence_case("black.png", payload, "screenshot"))
        self.assertEqual(self.verify(), 1)

    def test_tiny_screenshot_is_rejected(self) -> None:
        payload = b"\x89PNG\r\n\x1a\n" + struct.pack(">I", 13) + b"IHDR" + struct.pack(
            ">II", 1920, 1080
        )
        self.write_manifest(self.evidence_case("stub.png", payload, "screenshot"))
        self.assertEqual(self.verify(), 1)

    def test_record_refuses_zero_byte_evidence(self) -> None:
        self.write_manifest(base_manifest())
        empty = self.evidence_root / "empty.log"
        empty.write_bytes(b"")
        with self.assertRaisesRegex(ValueError, "empty"):
            self.record(evidence=[empty], kind="log")

    # ---- invariants --------------------------------------------------------

    def test_real_shipped_evidence_still_passes(self) -> None:
        """The 12-byte ICE-01 identity log that 4.0.0 actually recorded must stay valid."""
        self.write_manifest(self.evidence_case("identity.txt", b"ice\noffline\n", "log"))
        self.assertEqual(self.verify(), 0)

    def test_real_screenshot_still_passes(self) -> None:
        self.write_manifest(
            self.evidence_case("desktop.png", detailed_png(1280, 720), "screenshot")
        )
        self.assertEqual(self.verify(), 0)

    def test_small_screenshot_dimensions_still_rejected(self) -> None:
        self.write_manifest(
            self.evidence_case("small.png", detailed_png(1024, 600), "screenshot")
        )
        self.assertEqual(self.verify(), 1)

    def test_sha256_binding_is_unchanged(self) -> None:
        data = self.evidence_case("result.log", b"97 tests passed\n", "log")
        data["cases"][0]["evidence"][0]["sha256"] = "0" * 64
        self.write_manifest(data)
        self.assertEqual(self.verify(), 1)

    def test_evidence_path_cannot_escape_root(self) -> None:
        with self.assertRaisesRegex(ValueError, "escapes evidence root"):
            qa.resolve_evidence(self.evidence_root, "../outside.log")

    # ---- the artifact the manifest claims to be about ----------------------

    def test_the_gate_opens_the_iso_it_accepts(self) -> None:
        """It never did. `verify` checked that artifact.iso_sha256 was a
        non-empty string and stopped, so a manifest could name the digest of
        an image that did not exist -- or of a different image -- and
        ACCEPTANCE_PASSED was printed against it. Two tools downstream already
        re-hashed the real file; the gate the release criteria point at did
        not."""
        data = self.bound_manifest()
        data["artifact"]["iso_sha256"] = "c" * 64
        data["cases"][0]["status"] = "waived"
        data["cases"][0]["waiver"] = {"approver": "A", "reason": "b"}
        self.write_manifest(data)
        self.assertEqual(self.verify(allow_pending=False), 1)

    def test_a_manifest_naming_no_artifact_file_is_refused(self) -> None:
        """Absence is an error, not a skip: a manifest describing an image
        nobody can produce is describing nothing."""
        data = self.bound_manifest()
        self.iso.unlink()
        data["cases"][0]["status"] = "waived"
        data["cases"][0]["waiver"] = {"approver": "A", "reason": "b"}
        self.write_manifest(data)
        self.assertEqual(self.verify(allow_pending=False), 1)

    def test_a_wrong_size_is_caught_even_when_the_digest_is_right(self) -> None:
        data = self.bound_manifest()
        data["artifact"]["iso_size_bytes"] = 999_999
        data["cases"][0]["status"] = "waived"
        data["cases"][0]["waiver"] = {"approver": "A", "reason": "b"}
        self.write_manifest(data)
        self.assertEqual(self.verify(allow_pending=False), 1)

    # ---- evidence bound to a particular image ------------------------------

    def test_unbound_evidence_is_refused(self) -> None:
        """The audit's finding, as a test. ICE-01 -- a REQUIRED case -- passed
        on twelve bytes reading b'ice\noffline\n': over the size floor, over
        the entropy floor, and about no particular image. The floors stop a
        0-byte file and a blank screenshot; they cannot tell a real result from
        a plausible-looking one, and nothing else was trying."""
        data = self.evidence_case("identity.txt", b"ice\noffline\n", "log",
                                  bound=False)
        self.write_manifest(data)
        self.assertEqual(self.verify(allow_pending=False), 1)

    def test_evidence_recorded_against_a_different_image_is_refused(self) -> None:
        data = self.evidence_case("result.log", b"97 tests passed\n" * 8, "log")
        data["cases"][0]["evidence"][0]["artifact_sha256"] = "d" * 64
        self.write_manifest(data)
        self.assertEqual(self.verify(allow_pending=False), 1)

    def test_bound_evidence_passes(self) -> None:
        data = self.evidence_case("result.log", b"97 tests passed\n" * 8, "log")
        self.write_manifest(data)
        self.assertEqual(self.verify(allow_pending=False), 0)

    def test_record_stamps_the_artifact_digest(self) -> None:
        """A person cannot forget it and cannot choose it."""
        self.write_manifest(self.bound_manifest())
        source = self.evidence_root / "gate.log"
        source.write_bytes(b"SOURCE_GATE_PASSED\n" * 64)
        self.assertEqual(self.record(status="pass", evidence=[source]), 0)
        recorded = json.loads(self.manifest.read_text(encoding="utf-8"))
        entry = recorded["cases"][0]["evidence"][0]
        self.assertEqual(entry["artifact_sha256"], self.iso_sha256)

    def test_recording_before_the_artifact_exists_is_unbound_and_says_so(self) -> None:
        """The source gate legitimately runs before an image is cut. That
        recording is allowed and it is UNBOUND -- so it will not satisfy a
        strict verify, and the case has to be re-recorded against the image it
        is meant to be about."""
        data = self.bound_manifest()
        data["artifact"]["iso_sha256"] = ""
        self.write_manifest(data)
        source = self.evidence_root / "early.log"
        source.write_bytes(b"SOURCE_GATE_PASSED\n" * 64)
        self.assertEqual(self.record(status="pass", evidence=[source]), 0)
        recorded = json.loads(self.manifest.read_text(encoding="utf-8"))
        self.assertNotIn("artifact_sha256", recorded["cases"][0]["evidence"][0])

    def test_record_pass_hashes_the_file(self) -> None:
        self.write_manifest(base_manifest())
        evidence = self.evidence_root / "suite.log"
        evidence.write_text("97 tests passed\n", encoding="utf-8")
        self.assertEqual(
            self.record(evidence=[evidence], kind="log", notes="fresh run"), 0
        )
        recorded = json.loads(self.manifest.read_text(encoding="utf-8"))
        case = recorded["cases"][0]
        self.assertEqual(case["status"], "pass")
        self.assertEqual(case["notes"], "fresh run")
        self.assertEqual(case["evidence"][0]["sha256"], qa.sha256_file(evidence))


if __name__ == "__main__":
    unittest.main()
