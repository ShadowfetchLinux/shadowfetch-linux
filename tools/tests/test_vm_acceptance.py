#!/usr/bin/env python3
"""Tests for the VM acceptance harness.

These run without a virtual machine. They cover the parts a VM run cannot
exercise honestly: that unusable evidence is refused, that the ledger notices
its own history being edited, and -- the point of the harness -- that there is
no path from "did not run" to "PASS".
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
import zlib

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tools"))

from acceptance import release_link  # noqa: E402
from acceptance import trusted  # noqa: E402
from acceptance import vm_acceptance  # noqa: E402
from acceptance.cases import CASES, Blocked, Context  # noqa: E402
from acceptance.evidence import EvidenceError, EvidenceSet, digest_of  # noqa: E402
from acceptance.ledger import (  # noqa: E402
    GENESIS,
    Ledger,
    receipt_problems,
    write_receipt,
)
from acceptance.vm import ppm_to_png  # noqa: E402

RELEASE = release_link.load_release()


def make_png(path: Path, width: int, height: int) -> None:
    def chunk(tag: bytes, payload: bytes) -> bytes:
        return (
            struct.pack(">I", len(payload))
            + tag
            + payload
            + struct.pack(">I", zlib.crc32(tag + payload) & 0xFFFFFFFF)
        )

    raw = bytearray()
    for row in range(height):
        raw.append(0)
        for column in range(width):
            raw += bytes(((row * 7 + column) % 251, (column * 13) % 251, 91))
    path.write_bytes(
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(bytes(raw), 1))
        + chunk(b"IEND", b"")
    )


class TrustedPathTests(unittest.TestCase):
    """The permanent invariant: no security-relevant binary via PATH.

    Resolution is delegated to tools/release/gate.py, so these tests assert the
    harness's contract with it -- every program declared, every one resolved to
    an absolute root-owned path, and PATH ignored -- rather than restating the
    resolver's own unit tests.
    """

    def test_every_declared_program_has_a_role(self) -> None:
        gate = release_link.gate()
        for name, role in trusted._requirements():
            self.assertIn(role, (gate.ROLE_SECURITY, gate.ROLE_QUALITY))
            self.assertEqual(trusted.classification(name), role)

    def test_every_declared_program_resolves_root_owned_and_absolute(self) -> None:
        gate = release_link.gate()
        for name, _ in trusted._requirements():
            found = trusted.program(name)
            self.assertTrue(found.path.is_absolute(), name)
            self.assertEqual(found.trust, gate.TRUST_SYSTEM, f"{name} at {found.path}")
            self.assertEqual(found.path.stat().st_uid, 0, name)

    def test_undeclared_program_is_refused(self) -> None:
        """journalctl is the defect this invariant was written for."""
        with self.assertRaises(trusted.TrustError):
            trusted.resolve("journalctl")

    def test_resolution_never_consults_the_environment(self) -> None:
        """A hostile PATH must not change what gets resolved.

        The impostor is executable, named exactly like the real program, and
        first on PATH. A which()-based lookup would run it.
        """
        with tempfile.TemporaryDirectory() as directory:
            impostor = Path(directory) / "qemu-img"
            impostor.write_text("#!/bin/sh\necho forged\n")
            impostor.chmod(0o755)
            original = os.environ.get("PATH")
            try:
                os.environ["PATH"] = f"{directory}:{original or ''}"
                self.assertEqual(trusted.resolve("qemu-img"), Path("/usr/bin/qemu-img"))
                self.assertNotEqual(trusted.resolve("qemu-img"), impostor)
            finally:
                if original is None:
                    os.environ.pop("PATH", None)
                else:
                    os.environ["PATH"] = original

    def test_argv_is_the_absolute_path(self) -> None:
        self.assertEqual(trusted.argv("qemu-img", ["--version"])[0], "/usr/bin/qemu-img")

    def test_trust_base_is_recordable(self) -> None:
        rows = trusted.describe()
        self.assertEqual({row["name"] for row in rows},
                         {name for name, _ in trusted._requirements()})
        for row in rows:
            self.assertTrue(row["path"].startswith("/"), row)

    def test_safe_env_carries_no_inherited_path(self) -> None:
        self.assertEqual(trusted.SAFE_ENV["PATH"], "/usr/sbin:/usr/bin:/sbin:/bin")

    def test_guest_output_is_classified_as_the_subject_not_a_verdict(self) -> None:
        self.assertEqual(trusted.GUEST_SUBJECT, "guest-subject")


class LedgerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.ledger = Ledger(Path(self.directory.name) / "ledger.jsonl")
        self.addCleanup(self.directory.cleanup)

    def append(self, case: str, verdict: str) -> dict:
        return self.ledger.append(
            {
                "run_id": f"{case}-{verdict}",
                "case": case,
                "verdict": verdict,
                "artifact_sha256": "a" * 64,
            }
        )

    def test_chain_starts_at_genesis_and_links(self) -> None:
        first = self.append("recovery", "FAIL")
        second = self.append("recovery", "PASS")
        self.assertEqual(first["prev"], GENESIS)
        self.assertEqual(second["prev"], first["entry_sha256"])
        self.assertEqual(self.ledger.verify(), [])

    def test_editing_an_entry_is_detected(self) -> None:
        self.append("recovery", "FAIL")
        rows = self.ledger.entries()
        rows[0]["verdict"] = "PASS"
        self.ledger.path.write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows)
        )
        self.assertTrue(
            any("digest does not match" in problem for problem in self.ledger.verify())
        )

    def test_deleting_a_failure_before_a_pass_is_detected(self) -> None:
        """The exact fraud a plain directory of receipts cannot notice."""
        self.append("recovery", "FAIL")
        self.append("recovery", "FAIL")
        self.append("recovery", "PASS")
        rows = self.ledger.entries()
        del rows[0:2]
        self.ledger.path.write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows)
        )
        problems = self.ledger.verify()
        self.assertTrue(any("prev does not chain" in problem for problem in problems))

    def test_find_filters_on_every_criterion(self) -> None:
        self.append("recovery", "PASS")
        self.append("live-boot", "PASS")
        self.assertEqual(
            [row["case"] for row in self.ledger.find(case="recovery", verdict="PASS")],
            ["recovery"],
        )
        self.assertEqual(self.ledger.find(case="recovery", verdict="FAIL"), [])


class ReceiptTests(unittest.TestCase):
    def test_receipt_digest_covers_the_whole_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            digest = write_receipt(path, {"case": "recovery", "verdict": "FAIL"})
            receipt = json.loads(path.read_text())
            self.assertEqual(receipt["receipt_sha256"], digest)
            self.assertEqual(receipt_problems(receipt), [])
            receipt["verdict"] = "PASS"
            self.assertEqual(
                receipt_problems(receipt),
                ["receipt digest does not match its content"],
            )

    def test_digest_is_order_independent(self) -> None:
        self.assertEqual(digest_of({"a": 1, "b": 2}), digest_of({"b": 2, "a": 1}))


class EvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.evidence = EvidenceSet(REPO_ROOT, self.root / "evidence" / "run")

    def test_empty_file_is_not_evidence(self) -> None:
        target = self.evidence.path("empty.log")
        target.write_bytes(b"")
        with self.assertRaises(EvidenceError) as caught:
            self.evidence.add(target, "log")
        self.assertIn("empty", str(caught.exception))

    def test_informationless_file_is_not_evidence(self) -> None:
        target = self.evidence.path("zeros.log")
        target.write_bytes(b"\x00" * 4096)
        with self.assertRaises(EvidenceError):
            self.evidence.add(target, "log")

    def test_undersized_screenshot_is_not_evidence(self) -> None:
        target = self.evidence.path("small.png")
        make_png(target, 640, 480)
        with self.assertRaises(EvidenceError) as caught:
            self.evidence.add(target, "screenshot")
        self.assertIn("640x480", str(caught.exception))

    def test_real_screenshot_is_accepted_and_hashed(self) -> None:
        target = self.evidence.path("desktop.png")
        make_png(target, 1920, 1080)
        item = self.evidence.add(target, "screenshot")
        self.assertEqual(item["kind"], "screenshot")
        self.assertEqual(len(item["sha256"]), 64)
        self.assertGreater(item["bytes"], 1024)

    def test_evidence_outside_the_run_directory_is_refused(self) -> None:
        outside = self.root / "elsewhere.log"
        outside.write_text("a plausible looking log from somewhere else\n")
        with self.assertRaises(EvidenceError) as caught:
            self.evidence.add(outside, "log")
        self.assertIn("must be written inside", str(caught.exception))

    def test_try_add_never_silently_registers_bad_evidence(self) -> None:
        target = self.evidence.path("empty2.log")
        target.write_bytes(b"")
        self.assertIsNone(self.evidence.try_add(target, "log"))
        self.assertEqual(self.evidence.items, [])

    def test_floors_come_from_the_release_recorder(self) -> None:
        """Imported, not reimplemented: the floors cannot drift apart."""
        self.assertEqual(self.evidence.recorder.MIN_SCREENSHOT_BYTES, 1024)
        self.assertIn("screenshot", self.evidence.recorder.VALID_KINDS)


class VerdictTests(unittest.TestCase):
    def context(self) -> Context:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        return Context(
            name="unit",
            repo_root=REPO_ROOT,
            run_dir=root / "run",
            evidence=EvidenceSet(REPO_ROOT, root / "evidence"),
            artifact={"path": "/dev/null", "sha256": "b" * 64},
            options={"version": "4.0.0"},
        )

    def test_a_case_that_checked_nothing_is_blocked_not_passed(self) -> None:
        verdict, reason = vm_acceptance.verdict_for(self.context())
        self.assertEqual(verdict, "BLOCKED")
        self.assertIn("nothing was proven", reason)

    def test_one_failing_check_fails_the_case(self) -> None:
        ctx = self.context()
        ctx.check("something true", True)
        ctx.check("the important one", False, "it did not hold")
        verdict, reason = vm_acceptance.verdict_for(ctx)
        self.assertEqual(verdict, "FAIL")
        self.assertIn("the important one", reason)

    def test_all_checks_passing_is_a_pass(self) -> None:
        ctx = self.context()
        ctx.check("a", True)
        ctx.check("b", True)
        self.assertEqual(vm_acceptance.verdict_for(ctx)[0], "PASS")

    def test_observations_are_not_checks(self) -> None:
        """Recording a fact must never move a case toward passing."""
        ctx = self.context()
        ctx.observe("version_marker", "4.0.0")
        ctx.observe("everything_looked_fine", True)
        self.assertEqual(ctx.checks, [])
        self.assertEqual(vm_acceptance.verdict_for(ctx)[0], "BLOCKED")


class NoPathToAnUnearnedPassTests(unittest.TestCase):
    """The harness's central claim, tested as an adversary would."""

    def test_there_is_no_subcommand_that_records_a_result(self) -> None:
        parser = vm_acceptance.build_parser()
        actions = [
            action
            for action in parser._actions
            if isinstance(action, argparse._SubParsersAction)
        ]
        self.assertEqual(len(actions), 1)
        self.assertEqual(
            sorted(actions[0].choices), ["list", "run", "status", "verify"]
        )

    def test_run_offers_no_way_to_supply_a_verdict(self) -> None:
        parser = vm_acceptance.build_parser()
        run = [
            action
            for action in parser._actions
            if isinstance(action, argparse._SubParsersAction)
        ][0].choices["run"]
        flags = {option for action in run._actions for option in action.option_strings}
        for forbidden in ("--status", "--verdict", "--pass", "--result", "--case-id"):
            self.assertNotIn(forbidden, flags)
        self.assertIn("--record", flags)

    def _gapless(self, name: str):
        """The same case with its coverage gap removed.

        The gap refusal fires first and would mask every other guard, so the
        guards below are tested against a case that is allowed to record.
        """
        case = CASES[name]
        return type(case)(
            case.name,
            case.run,
            summary=case.summary,
            manifest_case=case.manifest_case,
            companions=case.companions,
            consumes_artifact=case.consumes_artifact,
        )

    def _receipt(self, verdict: str, evidence: list | None = None) -> dict:
        return {
            "verdict": verdict,
            "run_id": "unit-run",
            "receipt_sha256": "c" * 64,
            "harness": {"digest": "d" * 64},
            "artifact": {"sha256": "e" * 64, "name": "unit.iso"},
            "checks": [{"name": "x", "state": "PASSED", "detail": ""}],
            "evidence": evidence if evidence is not None else [],
        }

    def test_recording_refuses_every_verdict_but_pass(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ledger = Ledger(Path(directory) / "ledger.jsonl")
            case = self._gapless("recovery")
            for verdict in ("FAIL", "BLOCKED", "ERROR"):
                code = vm_acceptance._record(
                    REPO_ROOT,
                    RELEASE,
                    case,
                    self._receipt(verdict),
                    Path(directory) / "receipt.json",
                    ledger,
                )
                self.assertEqual(code, 0, verdict)

    def test_recording_refuses_a_pass_with_no_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ledger = Ledger(Path(directory) / "ledger.jsonl")
            # live-boot has no companions, so evidence is the only thing missing.
            code = vm_acceptance._record(
                REPO_ROOT,
                RELEASE,
                self._gapless("install"),
                self._receipt("PASS", evidence=[]),
                Path(directory) / "receipt.json",
                ledger,
            )
            self.assertEqual(code, vm_acceptance.EXIT_ERROR)

    def test_recovery_will_not_record_without_its_power_loss_companion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ledger = Ledger(Path(directory) / "ledger.jsonl")
            code = vm_acceptance._record(
                REPO_ROOT,
                RELEASE,
                self._gapless("recovery"),
                self._receipt(
                    "PASS",
                    evidence=[{"relative_path": "Makefile", "sha256": "f" * 64}],
                ),
                Path(directory) / "receipt.json",
                ledger,
            )
            self.assertEqual(code, vm_acceptance.EXIT_BLOCKED)

    def test_recording_refuses_when_the_ledger_does_not_verify(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ledger = Ledger(Path(directory) / "ledger.jsonl")
            ledger.append(
                {
                    "run_id": "companion",
                    "case": "recovery-interrupted",
                    "verdict": "PASS",
                    "artifact_sha256": "e" * 64,
                }
            )
            rows = ledger.entries()
            # Leave the fields the companion lookup matches on intact, so the
            # entry still LOOKS like the required passing companion. Only the
            # chain notices that its history was edited.
            rows[0]["run_id"] = "companion-renamed"
            ledger.path.write_text(json.dumps(rows[0], sort_keys=True) + "\n")
            code = vm_acceptance._record(
                REPO_ROOT,
                RELEASE,
                self._gapless("recovery"),
                self._receipt(
                    "PASS",
                    evidence=[{"relative_path": "Makefile", "sha256": "f" * 64}],
                ),
                Path(directory) / "receipt.json",
                ledger,
            )
            self.assertEqual(code, vm_acceptance.EXIT_ERROR)


    def test_a_case_that_only_half_covers_a_release_case_cannot_record(self) -> None:
        """Contributing to a required case is not the same as proving it.

        RECOVERY-01 is "project diff/undo AND supported system rollback". The
        recovery cases prove the rollback half against a real injected failure.
        Recording the whole case from them would claim the half nobody ran.
        """
        manifest = RELEASE.acceptance_manifest()
        before = manifest.read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            ledger = Ledger(Path(directory) / "ledger.jsonl")
            for name in ("recovery", "upgrade", "install"):
                case = CASES[name]
                self.assertIsNotNone(case.manifest_case, name)
                self.assertTrue(case.manifest_gap, name)
                code = vm_acceptance._record(
                    REPO_ROOT,
                    RELEASE,
                    case,
                    self._receipt(
                        "PASS",
                        evidence=[{"relative_path": "Makefile", "sha256": "f" * 64}],
                    ),
                    Path(directory) / "receipt.json",
                    ledger,
                )
                self.assertEqual(code, 0, name)
        self.assertEqual(manifest.read_bytes(), before,
                         "the release manifest must not have been touched")

    def test_recording_writes_the_manifest_when_a_case_fully_covers_one(self) -> None:
        """The one workflow, proven end to end against a scratch manifest.

        Every guard above is a refusal. This is the other half: given a case
        that does prove its release case, a PASS with real evidence reaches the
        manifest -- through the release recorder, not through this harness
        writing JSON of its own.
        """
        scratch = REPO_ROOT / "work" / f"vm-acceptance-record-test-{os.getpid()}"
        evidence_dir = (
            REPO_ROOT / "work" / f"qa-{RELEASE.version}" / "evidence"
            / "vm-acceptance" / f"_record_test_{os.getpid()}"
        )
        try:
            scratch.mkdir(parents=True)
            evidence_dir.mkdir(parents=True)
            manifest = scratch / "acceptance.json"
            manifest.write_bytes(RELEASE.acceptance_manifest().read_bytes())
            proof = evidence_dir / "transcript.log"
            proof.write_text(
                "PASSED the restored Point is what boots\n"
                "PASSED root and /boot are the same generation\n"
            )

            class ScratchRelease:
                version = RELEASE.version

                @staticmethod
                def acceptance_manifest() -> Path:
                    return manifest

            case = CASES["recovery"]
            complete = vm_acceptance.CASES.__class__  # noqa: F841 - readability
            full = type(case)(
                "recovery-complete",
                case.run,
                summary=case.summary,
                manifest_case="RECOVERY-01",
                consumes_artifact=False,
            )
            receipt = self._receipt(
                "PASS",
                evidence=[
                    {
                        "relative_path": str(proof.relative_to(REPO_ROOT)),
                        "sha256": "0" * 64,
                    }
                ],
            )
            code = vm_acceptance._record(
                REPO_ROOT,
                ScratchRelease,
                full,
                receipt,
                scratch / "receipt.json",
                Ledger(scratch / "ledger.jsonl"),
            )
            self.assertEqual(code, 0)
            recorded = json.loads(manifest.read_text())
            case_row = next(
                row for row in recorded["cases"] if row["id"] == "RECOVERY-01"
            )
            self.assertEqual(case_row["status"], "pass")
            self.assertEqual(len(case_row["evidence"]), 1)
            self.assertIn("vm_acceptance.py run", case_row["notes"])
            self.assertIn(receipt["run_id"], case_row["notes"])
        finally:
            for path in (
                scratch / "acceptance.json",
                scratch / "ledger.jsonl",
                evidence_dir / "transcript.log",
            ):
                path.unlink(missing_ok=True)
            for directory in (scratch, evidence_dir):
                if directory.is_dir():
                    directory.rmdir()

    def test_blocked_does_not_exit_zero(self) -> None:
        self.assertNotEqual(vm_acceptance.EXIT_BLOCKED, vm_acceptance.EXIT_PASS)
        self.assertNotEqual(vm_acceptance.EXIT_FAIL, vm_acceptance.EXIT_PASS)
        self.assertNotEqual(vm_acceptance.EXIT_ERROR, vm_acceptance.EXIT_PASS)


class CaseRegistryTests(unittest.TestCase):
    def test_the_assigned_cases_exist(self) -> None:
        for name in ("live-boot", "install", "upgrade", "recovery",
                     "recovery-interrupted"):
            self.assertIn(name, CASES)

    def test_recovery_requires_the_power_loss_companion(self) -> None:
        self.assertIn("recovery-interrupted", CASES["recovery"].companions)

    def test_cases_without_a_base_image_block_rather_than_pass(self) -> None:
        for name in ("recovery", "recovery-interrupted"):
            ctx = Context(
                name=name,
                repo_root=REPO_ROOT,
                run_dir=Path("/nonexistent"),
                evidence=None,
                artifact={"path": "/dev/null", "sha256": "b" * 64},
                options={"version": "4.0.0"},
            )
            with self.assertRaises(Blocked):
                CASES[name].run(ctx)
            self.assertEqual(ctx.checks, [])

    def test_upgrade_blocks_without_a_previous_release_image(self) -> None:
        ctx = Context(
            name="upgrade",
            repo_root=REPO_ROOT,
            run_dir=Path("/nonexistent"),
            evidence=None,
            artifact={"path": "/dev/null", "sha256": "b" * 64},
            options={"version": "4.0.0"},
        )
        with self.assertRaises(Blocked) as caught:
            CASES["upgrade"].run(ctx)
        self.assertIn("previous-release installed image", str(caught.exception))


class FramebufferTests(unittest.TestCase):
    def test_ppm_is_converted_to_a_png_of_the_same_size(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ppm = Path(directory) / "frame.ppm"
            png = Path(directory) / "frame.png"
            width, height = 1920, 1080
            pixels = bytes(((index * 37) % 256) for index in range(width * height * 3))
            ppm.write_bytes(f"P6\n{width} {height}\n255\n".encode() + pixels)
            self.assertEqual(ppm_to_png(ppm, png), (width, height))
            header = png.read_bytes()[:24]
            self.assertEqual(header[:8], b"\x89PNG\r\n\x1a\n")
            self.assertEqual(struct.unpack(">II", header[16:24]), (width, height))

    def test_a_truncated_framebuffer_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ppm = Path(directory) / "frame.ppm"
            ppm.write_bytes(b"P6\n1920 1080\n255\n" + b"\x00" * 100)
            with self.assertRaises(Exception) as caught:
                ppm_to_png(ppm, Path(directory) / "frame.png")
            self.assertIn("truncated", str(caught.exception))


if __name__ == "__main__":
    unittest.main(verbosity=2)
