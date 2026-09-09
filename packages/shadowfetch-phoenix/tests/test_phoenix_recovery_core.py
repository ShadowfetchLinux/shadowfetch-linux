"""Unit proofs for the Phoenix recovery core (Stage T).

These run on any filesystem and take no privileges, so they cover the parts of
root recovery that are DECISIONS. The parts that are real subvolume operations
are proved separately, on a real loopback Btrfs, in
test_phoenix_btrfs_loopback.py - including the two power-cut scenarios.

Where a seam exists for testability it is named here and its default is
asserted, so the seam cannot quietly become the shipped behaviour:

  * Layout.probe(detector=...) - the DEFAULT is the kernel's st_ino == 256.
  * gc.apply_previous_roots(executor=...) - the shipped caller passes a
    TrustedExecutor, whose btrfs is resolved by absolute path.

Nothing here stubs a program onto PATH. That would be the very defect the
permanent invariant exists to prevent.
"""

import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from harness import PHOENIX, PHOENIX_LIB, import_phoenix

phoenix = import_phoenix()
from phoenix import gc as gcmod                    # noqa: E402
from phoenix import journal as journalmod          # noqa: E402
from phoenix import layout as layoutmod            # noqa: E402
from phoenix import transaction as txmod           # noqa: E402
from phoenix import trusted as trustedmod          # noqa: E402


SUBVOL_MARKER = ".fake-subvolume"


def fake_detector(path: Path) -> bool:
    """Model a subvolume on a tmpdir. Only ever passed in explicitly."""
    return (Path(path) / SUBVOL_MARKER).exists()


def make_subvolume(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    (path / SUBVOL_MARKER).write_text("")
    return path


class FakeExecutor:
    """Records what would be run. Never resolves anything through PATH."""

    def __init__(self, fail: set[str] | None = None):
        self.calls: list[list[str]] = []
        self.fail = fail or set()

    def run(self, name, *args, check=True):
        self.calls.append([name, *args])
        if name in self.fail:
            raise trustedmod.ExecutableError(f"{name} refused by the test")
        return subprocess.CompletedProcess([name, *args], 0, "", "")

    def available(self, name):
        return name not in self.fail


class Volume:
    """A fake Btrfs top-level in a temp dir."""

    def __init__(self, base: Path):
        self.base = base
        make_subvolume(base / "@")
        make_subvolume(base / "@snapshots")
        (base / "@/var/lib/shadowfetch").mkdir(parents=True)
        (base / "@/lib/modules").mkdir(parents=True)

    def point(self, number: int) -> Path:
        path = make_subvolume(self.base / f"@snapshots/{number}/snapshot")
        (path / "var/lib/shadowfetch").mkdir(parents=True, exist_ok=True)
        return path

    def previous(self, stamp: str, recovered: bool = False,
                 subvolume: bool = True) -> Path:
        name = f"@_prev_{stamp}" + ("_recovered" if recovered else "")
        path = self.base / name
        if subvolume:
            make_subvolume(path)
        else:
            path.mkdir()
        return path

    def staging(self) -> Path:
        path = make_subvolume(self.base / "@new")
        (path / "var/lib/shadowfetch").mkdir(parents=True, exist_ok=True)
        return path

    def flag(self, subvolume: str, **values) -> None:
        target = self.base / subvolume / txmod.FLAG_REL
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("".join(f"{k}={v}\n" for k, v in values.items()))

    def probe(self):
        return layoutmod.Layout.probe(self.base, detector=fake_detector,
                                      fstype="btrfs")


class TempCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="phoenix-core.")
        self.addCleanup(self._tmp.cleanup)
        self.base = Path(self._tmp.name)


# =========================================================================
# The permanent invariant: trusted absolute paths, never PATH.
# =========================================================================
class TrustedExecutablePaths(TempCase):

    def test_every_candidate_path_is_absolute(self):
        for name, candidates in trustedmod.TRUSTED_PATHS.items():
            self.assertTrue(candidates, name)
            for candidate in candidates:
                self.assertTrue(Path(candidate).is_absolute(),
                                f"{name}: {candidate} is not absolute")

    def test_the_package_never_resolves_a_program_through_PATH(self):
        """Adversarial: a PATH lookup anywhere in this package would let a
        user-writable directory decide which `btrfs` deletes a subvolume.

        Parsed, not grepped - the module docstrings talk ABOUT shutil.which,
        and a test that cannot tell prose from a call is a test that gets
        weakened the first time it fires."""
        import ast
        banned_calls = {("shutil", "which"), ("spawn", "find_executable")}
        banned_names = {"which", "find_executable", "system", "popen",
                        "execvp", "execlp", "spawnp"}
        banned_modules = {"shutil", "distutils"}
        offenders = []
        sources = list(PHOENIX_LIB.glob("phoenix/*.py"))
        sources.append(PHOENIX / "usr/libexec/phoenix-recover")
        self.assertGreaterEqual(len(sources), 7, sources)
        for source in sorted(sources):
            tree = ast.parse(source.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name.split(".")[0] in banned_modules:
                            offenders.append(f"{source.name}: import {alias.name}")
                elif isinstance(node, ast.ImportFrom):
                    if (node.module or "").split(".")[0] in banned_modules:
                        offenders.append(f"{source.name}: from {node.module}")
                elif isinstance(node, ast.Call):
                    func = node.func
                    if isinstance(func, ast.Attribute):
                        owner = getattr(func.value, "id", None)
                        if (owner, func.attr) in banned_calls:
                            offenders.append(f"{source.name}: {owner}.{func.attr}()")
                    elif isinstance(func, ast.Name) and func.id in banned_names:
                        offenders.append(f"{source.name}: {func.id}()")
                    for keyword in node.keywords:
                        if keyword.arg == "shell":
                            offenders.append(f"{source.name}: shell=")
        self.assertEqual(offenders, [])

    def test_only_trusted_py_launches_a_process(self):
        """Every exec in the package goes through TrustedExecutor.run."""
        offenders = []
        for source in sorted(PHOENIX_LIB.glob("phoenix/*.py")):
            if source.name == "trusted.py":
                continue
            text = source.read_text(encoding="utf-8")
            for needle in ("subprocess.run", "subprocess.Popen", "os.system",
                           "os.popen"):
                if needle in text:
                    offenders.append(f"{source.name}: {needle}")
        self.assertEqual(offenders, [])

    def test_a_binary_this_user_owns_is_untrusted(self):
        impostor = self.base / "btrfs"
        impostor.write_text("#!/bin/sh\nexit 0\n")
        impostor.chmod(0o755)
        self.assertEqual(trustedmod.classify(impostor),
                         trustedmod.ExecutableTrust.UNTRUSTED)
        executor = trustedmod.TrustedExecutor({"btrfs": (str(impostor),)})
        with self.assertRaises(trustedmod.ExecutableError):
            executor.resolve("btrfs")
        self.assertFalse(executor.available("btrfs"))

    def test_a_relative_path_is_untrusted_even_if_it_exists(self):
        self.assertEqual(trustedmod.classify("btrfs"),
                         trustedmod.ExecutableTrust.UNTRUSTED)

    def test_a_missing_path_is_absent_not_trusted(self):
        self.assertEqual(trustedmod.classify(self.base / "nothing-here"),
                         trustedmod.ExecutableTrust.ABSENT)

    def test_a_name_outside_the_table_cannot_be_run(self):
        executor = trustedmod.TrustedExecutor()
        with self.assertRaises(trustedmod.ExecutableError):
            executor.trust("journalctl")

    def test_children_get_a_fixed_PATH(self):
        self.assertEqual(trustedmod.SAFE_ENV["PATH"], trustedmod.SAFE_PATH)
        for element in trustedmod.SAFE_PATH.split(":"):
            self.assertTrue(element.startswith("/"), element)

    @unittest.skipUnless(os.path.exists("/usr/bin/btrfs"), "btrfs-progs absent")
    def test_the_packaged_btrfs_classifies_as_distro_managed(self):
        executor = trustedmod.TrustedExecutor()
        path, verdict = executor.trust("btrfs")
        self.assertEqual(verdict, trustedmod.ExecutableTrust.DISTRO_MANAGED, path)
        self.assertTrue(Path(path).is_absolute())


# =========================================================================
# The intent journal
# =========================================================================
class Journal(TempCase):

    def journal(self):
        return journalmod.IntentJournal(self.base / journalmod.JOURNAL_NAME)

    def test_records_round_trip_with_run_and_phase(self):
        entry = self.journal()
        entry.append("7", "20260909010203", "requested", "restore requested")
        entry.append("7", "20260909010203", "staging-created", "creating @new")
        records = entry.read()
        self.assertEqual([r.phase for r in records],
                         ["requested", "staging-created"])
        self.assertEqual(records[0].point, "7")
        self.assertEqual(records[0].run, "20260909010203")
        self.assertIn("restore requested", records[0].message)

    def test_the_4_0_0_key_less_format_still_parses(self):
        """An upgrade must not blind the resume path to a restore that was in
        flight across it."""
        path = self.base / journalmod.JOURNAL_NAME
        path.write_text("2026-09-08T00:00:00Z pid=42 point=3 restore requested\n")
        records = self.journal().read()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].phase, journalmod.LEGACY_PHASE)
        self.assertIsNone(records[0].run)
        self.assertFalse(records[0].structured)

    def test_garbage_lines_are_dropped_not_half_interpreted(self):
        path = self.base / journalmod.JOURNAL_NAME
        path.write_text("not a record at all\n\nalso not one\n")
        self.assertEqual(self.journal().read(), [])

    def test_in_flight_is_none_once_a_run_reaches_a_terminal_phase(self):
        entry = self.journal()
        entry.append("1", "20260101000000", "requested", "")
        self.assertEqual(entry.in_flight()[0], "20260101000000")
        entry.append("1", "20260101000000", "complete", "")
        self.assertIsNone(entry.in_flight()[0])

    def test_two_attempts_are_never_read_as_one(self):
        entry = self.journal()
        entry.append("1", "20260101000000", "requested", "")
        entry.append("1", "20260101000000", "aborted", "")
        entry.append("2", "20260101010000", "requested", "")
        entry.append("2", "20260101010000", "staging-created", "")
        self.assertEqual(entry.phase_of("20260101000000"), "aborted")
        self.assertEqual(entry.phase_of("20260101010000"), "staging-created")
        self.assertEqual(entry.in_flight(), ("20260101010000", "staging-created"))

    def test_an_unknown_phase_is_refused_at_the_call_site(self):
        with self.assertRaises(ValueError):
            self.journal().append("1", "20260101000000", "improvised", "")

    def test_reading_is_bounded_and_rotation_bounds_the_file(self):
        entry = self.journal()
        line = ("2026-09-09T00:00:00Z pid=1 point=1 run=20260909000000 "
                "phase=requested " + "x" * 200 + "\n")
        with open(entry.path, "w") as handle:
            handle.write(line * 4000)          # ~1 MiB, far over the read bound
        self.assertLess(len(entry.read()) * len(line), journalmod.MAX_READ_BYTES + 4096)
        self.assertTrue(entry.rotate())
        self.assertLessEqual(len(entry.read()), journalmod.KEEP_RECORDS)
        self.assertFalse(entry.rotate(), "a small journal must not be rewritten")

    def test_append_reports_failure_instead_of_raising(self):
        entry = journalmod.IntentJournal(self.base / "no-such-dir/journal")
        self.assertFalse(entry.append("1", "20260101000000", "requested", ""))


# =========================================================================
# Layout
# =========================================================================
class LayoutValidation(TempCase):

    def test_the_default_subvolume_detector_is_the_kernel_one(self):
        """The seam must not become the shipped behaviour."""
        import inspect
        signature = inspect.signature(layoutmod.Layout.probe)
        self.assertIs(signature.parameters["detector"].default,
                      layoutmod.btrfs_subvolume)

    def test_a_healthy_volume_validates(self):
        volume = Volume(self.base)
        volume.point(1)
        layout = volume.probe()
        self.assertTrue(layout.ok, layout.problems)
        self.assertIsNotNone(layout.root)
        self.assertIsNone(layout.staging)
        self.assertTrue(layout.has_point("1", detector=fake_detector))

    def test_a_volume_without_an_at_subvolume_is_refused(self):
        make_subvolume(self.base / "@snapshots")
        layout = layoutmod.Layout.probe(self.base, detector=fake_detector,
                                        fstype="btrfs")
        self.assertFalse(layout.ok)
        self.assertIn("no-root", [p.code for p in layout.failures])

    def test_an_at_that_is_only_a_directory_is_refused(self):
        (self.base / "@").mkdir()
        make_subvolume(self.base / "@snapshots")
        layout = layoutmod.Layout.probe(self.base, detector=fake_detector,
                                        fstype="btrfs")
        self.assertIn("root-not-subvolume", [p.code for p in layout.failures])

    def test_missing_snapshots_is_a_failure_not_a_warning(self):
        make_subvolume(self.base / "@")
        layout = layoutmod.Layout.probe(self.base, detector=fake_detector,
                                        fstype="btrfs")
        self.assertIn("no-snapshots", [p.code for p in layout.failures])

    def test_a_non_btrfs_volume_is_refused(self):
        volume = Volume(self.base)
        layout = layoutmod.Layout.probe(volume.base, detector=fake_detector,
                                        fstype="ext4")
        self.assertFalse(layout.ok)
        self.assertIn("not-btrfs", [p.code for p in layout.failures])

    def test_staging_is_reported_as_an_interrupted_restore(self):
        volume = Volume(self.base)
        volume.staging()
        layout = volume.probe()
        self.assertTrue(layout.ok)
        self.assertIn("staging-present", [p.code for p in layout.warnings])

    def test_previous_roots_order_by_timestamp_not_by_string(self):
        """The shell sorted names, so @_prev_<TS>_recovered outranked the real
        @_prev_<TS> of the same second and the wrong one was kept."""
        volume = Volume(self.base)
        volume.previous("20260101000000", recovered=True)
        volume.previous("20260101000000")
        volume.previous("20250101000000")
        layout = volume.probe()
        self.assertEqual([item.name for item in layout.previous], [
            "@_prev_20260101000000_recovered",   # provenance unknown: ranked last
            "@_prev_20250101000000",
            "@_prev_20260101000000",
        ])

    def test_an_unidentified_leftover_never_displaces_a_real_previous_root(self):
        """phoenix-restore parks a leftover @new under the CURRENT run's
        timestamp, so by recency alone the unidentified thing was the newest on
        the volume and a keep=1 collection deleted the genuine previous root."""
        volume = Volume(self.base)
        real = volume.previous("20250101000000")
        volume.previous("20260101000000", recovered=True)
        plan = gcmod.plan_previous_roots(volume.probe(), keep=1)
        self.assertEqual([d.path for d in plan.keeps], [real])
        self.assertEqual([d.path.name for d in plan.deletions],
                         ["@_prev_20260101000000_recovered"])

    def test_a_name_we_did_not_write_is_reported_and_not_collected(self):
        volume = Volume(self.base)
        make_subvolume(self.base / "@_prev_backup")
        make_subvolume(self.base / "@_prev_99999999999999")   # month 99
        layout = volume.probe()
        self.assertEqual(layout.previous, ())
        codes = [p.code for p in layout.warnings]
        self.assertEqual(codes.count("previous-unparsed"), 2)

    def test_a_previous_root_that_is_a_plain_directory_is_flagged(self):
        volume = Volume(self.base)
        volume.previous("20260101000000", subvolume=False)
        layout = volume.probe()
        self.assertIn("previous-not-subvolume", [p.code for p in layout.warnings])

    def test_point_numbers_are_validated_before_they_become_a_path(self):
        volume = Volume(self.base)
        layout = volume.probe()
        for bad in ("", "0", "01", "-1", "1 2", "../../etc", "1/../@", "abc",
                    "1234567890123", "٣"):
            with self.assertRaises(layoutmod.LayoutError, msg=bad):
                layout.point_source(bad)
        self.assertEqual(layout.point_source("12").name, "snapshot")
        self.assertEqual(layout.point_source("12").parent.name, "12")

    def test_probe_of_an_unreadable_directory_fails_closed(self):
        layout = layoutmod.Layout.probe(self.base / "not-there",
                                        detector=fake_detector, fstype="btrfs")
        self.assertFalse(layout.ok)
        self.assertIn("unreadable", [p.code for p in layout.failures])

    def test_mount_fstype_reads_the_kernel_not_a_program(self):
        self.assertEqual(layoutmod.mount_fstype("/proc"), "proc")
        self.assertIsNotNone(layoutmod.mount_fstype("/"))


# =========================================================================
# Bounded garbage collection
# =========================================================================
class BoundedCollection(TempCase):

    def test_the_newest_previous_root_survives_by_timestamp(self):
        volume = Volume(self.base)
        volume.previous("20260101000000", recovered=True)
        newest = volume.previous("20260101000000")
        volume.previous("20250101000000")
        plan = gcmod.plan_previous_roots(volume.probe(), keep=1)
        self.assertEqual([d.path for d in plan.keeps], [newest])
        self.assertEqual(
            sorted(d.path.name for d in plan.deletions),
            ["@_prev_20250101000000", "@_prev_20260101000000_recovered"])

    def test_keep_zero_deletes_them_all_and_keep_two_keeps_two(self):
        volume = Volume(self.base)
        for stamp in ("20240101000000", "20250101000000", "20260101000000"):
            volume.previous(stamp)
        self.assertEqual(len(gcmod.plan_previous_roots(volume.probe(), 0).deletions), 3)
        self.assertEqual(len(gcmod.plan_previous_roots(volume.probe(), 2).deletions), 1)

    def test_asking_to_keep_more_than_exist_keeps_them_all(self):
        """A negative slice start reads from the END: keep=3 of 2 kept one and
        deleted the other."""
        volume = Volume(self.base)
        volume.previous("20250101000000")
        volume.previous("20260101000000")
        plan = gcmod.plan_previous_roots(volume.probe(), keep=3)
        self.assertEqual(plan.deletions, ())
        self.assertEqual(len(plan.keeps), 2)

    def test_a_plain_directory_is_refused_not_deleted(self):
        volume = Volume(self.base)
        volume.previous("20260101000000")                       # survivor
        volume.previous("20250101000000", subvolume=False)
        plan = gcmod.plan_previous_roots(volume.probe(), keep=1)
        self.assertEqual([d.path.name for d in plan.deletions], [])
        self.assertIn("@_prev_20250101000000",
                      [d.path.name for d in plan.refusals])

    def test_deletion_is_bounded_for_one_pass(self):
        volume = Volume(self.base)
        for index in range(20):
            volume.previous("2026010100%04d" % index)
        plan = gcmod.plan_previous_roots(volume.probe(), keep=1)
        self.assertEqual(len(plan.deletions), gcmod.MAX_DELETES_PER_RUN)
        self.assertEqual(len(plan.deletions) + len(plan.keeps) + len(plan.refusals),
                         20)

    def test_a_broken_layout_is_collected_not_at_all(self):
        volume = Volume(self.base)
        volume.previous("20250101000000")
        volume.previous("20260101000000")
        import shutil as _shutil
        _shutil.rmtree(volume.base / "@")                       # no root subvolume
        plan = gcmod.plan_previous_roots(volume.probe(), keep=1)
        self.assertEqual(plan.deletions, ())
        self.assertEqual(len(plan.refusals), 2)

    def test_apply_deletes_through_the_injected_executor_only(self):
        volume = Volume(self.base)
        volume.previous("20260101000000")
        doomed = volume.previous("20250101000000")
        plan = gcmod.plan_previous_roots(volume.probe(), keep=1)
        executor = FakeExecutor()
        results = gcmod.apply_previous_roots(plan, executor)
        self.assertEqual(executor.calls,
                         [["btrfs", "subvolume", "delete", str(doomed)]])
        self.assertEqual([(p.name, ok) for p, ok, _ in results],
                         [(doomed.name, True)])

    def test_a_dry_run_deletes_nothing(self):
        volume = Volume(self.base)
        volume.previous("20260101000000")
        volume.previous("20250101000000")
        plan = gcmod.plan_previous_roots(volume.probe(), keep=1)
        executor = FakeExecutor()
        gcmod.apply_previous_roots(plan, executor, dry_run=True)
        self.assertEqual(executor.calls, [])

    def test_a_failing_delete_is_reported_not_swallowed(self):
        volume = Volume(self.base)
        volume.previous("20260101000000")
        volume.previous("20250101000000")
        plan = gcmod.plan_previous_roots(volume.probe(), keep=1)
        results = gcmod.apply_previous_roots(plan, FakeExecutor(fail={"btrfs"}))
        self.assertEqual([ok for _p, ok, _d in results], [False])


class KernelBackupCollection(TempCase):
    """Nothing collected /boot/phoenix-kernel-backup-* before Stage T, and
    archiving a kernel made restoring back to it impossible."""

    def setUp(self):
        super().setUp()
        self.boot = self.base / "boot"
        self.boot.mkdir()
        self.modules = self.base / "modules"
        self.modules.mkdir()

    def archive(self, stamp, kernels):
        path = self.boot / f"phoenix-kernel-backup-{stamp}"
        path.mkdir()
        for kernel in kernels:
            for prefix in gcmod.KERNEL_PREFIXES:
                (path / f"{prefix}{kernel}").write_text(prefix + kernel)
        return path

    def test_a_kernel_the_root_still_needs_is_rescued_before_collection(self):
        (self.modules / "6.9.0-new").mkdir()
        archive = self.archive("20260101000000", ["6.9.0-new"])
        plan = gcmod.plan_kernel_archives(self.boot, self.modules, keep=0)
        self.assertEqual(sorted(r.source.name for r in plan.rescues),
                         ["System.map-6.9.0-new", "config-6.9.0-new",
                          "initrd.img-6.9.0-new", "vmlinuz-6.9.0-new"])
        gcmod.apply_kernel_archives(plan)
        self.assertTrue((self.boot / "vmlinuz-6.9.0-new").is_file())
        self.assertFalse(archive.exists())

    def test_a_kernel_already_in_boot_is_not_rescued(self):
        (self.modules / "6.9.0-new").mkdir()
        (self.boot / "vmlinuz-6.9.0-new").write_text("live")
        self.archive("20260101000000", ["6.9.0-new"])
        plan = gcmod.plan_kernel_archives(self.boot, self.modules, keep=1)
        self.assertEqual(plan.rescues, ())

    def test_only_the_newest_archives_survive(self):
        old = self.archive("20250101000000", ["6.1.0-old"])
        new = self.archive("20260101000000", ["6.9.0-new"])
        plan = gcmod.plan_kernel_archives(self.boot, self.modules, keep=1)
        self.assertEqual([d.path for d in plan.deletions], [old])
        gcmod.apply_kernel_archives(plan)
        self.assertFalse(old.exists())
        self.assertTrue(new.is_dir())

    def test_an_archive_holding_a_foreign_file_is_left_alone(self):
        """A root tool must not recursively delete a directory on /boot that
        somebody else has put something in."""
        old = self.archive("20250101000000", ["6.1.0-old"])
        (old / "notes.txt").write_text("mine")
        self.archive("20260101000000", ["6.9.0-new"])
        plan = gcmod.plan_kernel_archives(self.boot, self.modules, keep=1)
        self.assertEqual(plan.deletions, ())
        self.assertIn(old, [d.path for d in plan.refusals])
        gcmod.apply_kernel_archives(plan)
        self.assertTrue((old / "notes.txt").exists())

    def test_asking_to_keep_more_archives_than_exist_keeps_them_all(self):
        first = self.archive("20250101000000", ["6.1.0-old"])
        second = self.archive("20260101000000", ["6.9.0-new"])
        plan = gcmod.plan_kernel_archives(self.boot, self.modules, keep=5)
        self.assertEqual(plan.deletions, ())
        gcmod.apply_kernel_archives(plan)
        self.assertTrue(first.is_dir())
        self.assertTrue(second.is_dir())

    def test_collection_is_bounded(self):
        for index in range(20):
            self.archive("2026010100%04d" % index, ["6.1.0-old"])
        plan = gcmod.plan_kernel_archives(self.boot, self.modules, keep=1)
        self.assertEqual(len(plan.deletions), gcmod.MAX_DELETES_PER_RUN)

    def test_a_dry_run_moves_and_deletes_nothing(self):
        (self.modules / "6.9.0-new").mkdir()
        archive = self.archive("20260101000000", ["6.9.0-new"])
        plan = gcmod.plan_kernel_archives(self.boot, self.modules, keep=0)
        gcmod.apply_kernel_archives(plan, dry_run=True)
        self.assertTrue(archive.is_dir())
        self.assertFalse((self.boot / "vmlinuz-6.9.0-new").exists())


# =========================================================================
# The resume decision
# =========================================================================
class ResumeDecision(TempCase):

    RUN = "20260909120000"

    def setUp(self):
        super().setUp()
        self.volume = Volume(self.base)
        self.volume.point(1)
        self.boot = self.base / "boot"
        self.boot.mkdir()
        self.journal = journalmod.IntentJournal(self.base / journalmod.JOURNAL_NAME)

    def transaction(self):
        return txmod.RestoreTransaction(self.volume.probe(), self.journal,
                                        boot=self.boot)

    def journal_up_to(self, *phases):
        for phase in phases:
            self.journal.append("1", self.RUN, phase, f"test {phase}")

    # -- crash AFTER the exchange -----------------------------------------
    def test_a_flag_in_at_proves_the_exchange_happened(self):
        self.volume.staging()
        self.volume.flag("@", restored="1", date=self.RUN,
                         previous=f"@_prev_{self.RUN}")
        self.journal_up_to("requested", "staging-created", "exchange-begin")
        state = self.transaction().inspect()
        self.assertIs(state.decision, txmod.Decision.FINISH_EXCHANGE)
        self.assertTrue(state.exchanged)
        self.assertEqual(state.previous_name, f"@_prev_{self.RUN}")
        self.assertFalse(state.boot_rollback,
                         "a completed exchange must never roll /boot back")

    def test_resume_parks_the_replaced_root_under_its_planned_name(self):
        self.volume.staging()
        self.volume.flag("@", restored="1", date=self.RUN,
                         previous=f"@_prev_{self.RUN}")
        self.journal_up_to("requested", "staging-created", "exchange-begin")
        transaction = self.transaction()
        state = transaction.inspect()
        transaction.resume(state, FakeExecutor())
        self.assertFalse((self.base / "@new").exists())
        self.assertTrue((self.base / f"@_prev_{self.RUN}").is_dir())
        self.assertEqual(self.journal.phase_of(self.RUN), "complete")

    def test_a_name_collision_parks_under_a_recovered_name(self):
        self.volume.staging()
        self.volume.previous(self.RUN)
        self.volume.flag("@", restored="1", date=self.RUN,
                         previous=f"@_prev_{self.RUN}")
        self.journal_up_to("requested", "exchange-complete")
        state = self.transaction().inspect()
        self.assertEqual(state.previous_name, f"@_prev_{self.RUN}_recovered")

    def test_the_journal_alone_proves_it_when_the_flag_was_consumed(self):
        """phoenix-postboot deletes the flag once the menu is rebuilt; the
        journal phase must still resolve the case."""
        self.volume.staging()
        self.journal_up_to("requested", "exchange-complete")
        state = self.transaction().inspect()
        self.assertIs(state.decision, txmod.Decision.FINISH_EXCHANGE)

    # -- crash BEFORE the exchange ----------------------------------------
    def test_a_flag_in_new_proves_the_exchange_did_not_happen(self):
        self.volume.staging()
        self.volume.flag("@new", restored="1", date=self.RUN,
                         previous=f"@_prev_{self.RUN}")
        self.journal_up_to("requested", "staging-created", "exchange-begin")
        state = self.transaction().inspect()
        self.assertIs(state.decision, txmod.Decision.DISCARD_STAGING)
        self.assertFalse(state.exchanged)

    def test_a_journal_that_stopped_early_proves_it_too(self):
        self.volume.staging()
        self.journal_up_to("requested", "staging-created")
        state = self.transaction().inspect()
        self.assertIs(state.decision, txmod.Decision.DISCARD_STAGING)

    def test_resume_discards_the_throwaway_copy_through_the_executor(self):
        staging = self.volume.staging()
        self.journal_up_to("requested", "staging-created")
        transaction = self.transaction()
        executor = FakeExecutor()
        transaction.resume(transaction.inspect(), executor)
        self.assertEqual(executor.calls,
                         [["btrfs", "subvolume", "delete", str(staging)]])

    def test_an_unexchanged_run_rolls_the_external_boot_back(self):
        """A power cut runs no shell trap. Before Stage T nothing undid the
        kernel staging, so the machine booted the OLD root against a /boot
        holding only the Point's kernel - the W-11 mismatch, by another route."""
        self.volume.staging()
        self.volume.flag("@new", restored="1", date=self.RUN)
        archive = self.boot / f"phoenix-kernel-backup-{self.RUN}"
        archive.mkdir()
        (archive / "vmlinuz-6.9.0-new").write_text("new kernel")
        (archive / "initrd.img-6.9.0-new").write_text("new initrd")
        (self.boot / "vmlinuz-6.1.0-old").write_text("point kernel")
        (self.boot / "grub").mkdir()
        (self.boot / "grub/grubenv").write_text("next_entry=x\n")
        self.journal_up_to("requested", "staging-created", "boot-staged")

        transaction = self.transaction()
        state = transaction.inspect()
        self.assertTrue(state.boot_rollback)
        executor = FakeExecutor()
        outcomes = transaction.resume(state, executor)

        self.assertTrue((self.boot / "vmlinuz-6.9.0-new").is_file())
        self.assertTrue((self.boot / "vmlinuz-6.1.0-old").is_file())
        self.assertFalse(archive.exists())
        # grub-editenv takes an explicit file, so it acts on the sandbox.
        self.assertIn(["grub-editenv", str(self.boot / "grub/grubenv"),
                       "unset", "next_entry"], executor.calls)
        # update-grub cannot be aimed anywhere but /boot, so on a sandbox it is
        # refused and SAID to be refused. That guard is also what keeps this
        # suite from rewriting the build host's own boot menu.
        self.assertNotIn(["update-grub"], executor.calls)
        self.assertTrue(any("NOT rebuilt" in line for line in outcomes), outcomes)
        phases = [r.phase for r in self.journal.records_for(self.RUN)]
        self.assertIn("resume", phases)
        self.assertEqual(phases[-1], "rolled-back",
                         "the attempt is undone in full, so nothing stays in flight")
        self.assertIsNone(self.journal.in_flight()[0])

    def test_only_the_systems_own_boot_menu_is_ever_rebuilt(self):
        """update-grub is grub-mkconfig hard-wired to /boot/grub/grub.cfg, so a
        rollback on any other /boot must not invoke it."""
        self.assertEqual(txmod.SYSTEM_BOOT, Path("/boot"))
        self.assertNotEqual(self.boot, txmod.SYSTEM_BOOT)

    def test_boot_rollback_leaves_a_file_it_did_not_put_there(self):
        self.volume.staging()
        self.volume.flag("@new", restored="1", date=self.RUN)
        archive = self.boot / f"phoenix-kernel-backup-{self.RUN}"
        archive.mkdir()
        (archive / "vmlinuz-6.9.0-new").write_text("new kernel")
        (archive / "somebody-elses-file").write_text("keep me")
        self.journal_up_to("requested", "boot-staged")
        transaction = self.transaction()
        transaction.resume(transaction.inspect(), FakeExecutor())
        self.assertTrue((archive / "somebody-elses-file").is_file())
        self.assertTrue((self.boot / "vmlinuz-6.9.0-new").is_file())

    # -- undecidable ------------------------------------------------------
    def test_no_evidence_means_park_not_guess(self):
        self.volume.staging()
        state = self.transaction().inspect()
        self.assertIs(state.decision, txmod.Decision.PARK_STAGING)
        self.assertIsNone(state.exchanged)

    def test_park_keeps_the_subvolume(self):
        self.volume.staging()
        transaction = self.transaction()
        state = transaction.inspect()
        transaction.resume(state, FakeExecutor())
        self.assertFalse((self.base / "@new").exists())
        parked = list(self.base.glob("@_prev_*_recovered"))
        self.assertEqual(len(parked), 1, parked)

    def test_without_a_journal_the_newer_flag_decides(self):
        self.volume.staging()
        self.volume.flag("@", restored="1", date="20260909120000")
        self.volume.flag("@new", restored="1", date="20250101000000")
        self.assertIs(self.transaction().inspect().decision,
                      txmod.Decision.FINISH_EXCHANGE)

    def test_without_a_journal_a_newer_flag_in_new_decides_the_other_way(self):
        self.volume.staging()
        self.volume.flag("@", restored="1", date="20250101000000")
        self.volume.flag("@new", restored="1", date="20260909120000")
        self.assertIs(self.transaction().inspect().decision,
                      txmod.Decision.DISCARD_STAGING)

    # -- nothing in flight / refusals -------------------------------------
    def test_a_clean_volume_needs_no_resume(self):
        state = self.transaction().inspect()
        self.assertIs(state.decision, txmod.Decision.NOTHING)
        self.assertEqual(self.transaction().resume(state, FakeExecutor()),
                         ["nothing to resume"])

    def test_a_broken_layout_blocks_every_action(self):
        import shutil as _shutil
        self.volume.staging()
        _shutil.rmtree(self.base / "@")
        transaction = self.transaction()
        state = transaction.inspect()
        self.assertIs(state.decision, txmod.Decision.BLOCKED)
        executor = FakeExecutor()
        outcomes = transaction.resume(state, executor)
        self.assertEqual(executor.calls, [])
        self.assertTrue((self.base / "@new").exists())
        self.assertTrue(outcomes[0].startswith("refused:"))

    def test_a_dry_run_changes_nothing(self):
        staging = self.volume.staging()
        self.journal_up_to("requested", "staging-created")
        transaction = self.transaction()
        executor = FakeExecutor()
        transaction.resume(transaction.inspect(), executor, dry_run=True)
        self.assertEqual(executor.calls, [])
        self.assertTrue(staging.exists())


# =========================================================================
# The shipped script wiring
# =========================================================================
class ShippedWiring(unittest.TestCase):

    def test_phoenix_restore_writes_the_flag_before_the_exchange(self):
        text = (PHOENIX / "usr/libexec/phoenix-restore").read_text(encoding="utf-8")
        flag_at = text.index('"$MNT/@new/var/lib/shadowfetch/phoenix-update-grub"')
        exchange_at = text.index("mv --exchange --no-target-directory")
        self.assertLess(flag_at, exchange_at,
                        "the flag must be inside @new before the swap, or a "
                        "power cut between them loses the boot-menu rebuild")
        self.assertNotIn('> "$MNT/@/var/lib/shadowfetch/phoenix-update-grub"', text,
                         "the post-exchange flag write should be gone")

    def test_every_journal_call_names_a_known_phase(self):
        text = (PHOENIX / "usr/libexec/phoenix-restore").read_text(encoding="utf-8")
        import re
        calls = re.findall(r"^\s*journal ([a-z][a-z-]*)", text, re.MULTILINE)
        self.assertGreaterEqual(len(calls), 8, calls)
        for phase in calls:
            self.assertIn(phase, journalmod.PHASES, phase)

    def test_postboot_resumes_before_it_consumes_the_flag(self):
        text = (PHOENIX / "usr/libexec/phoenix-postboot").read_text(encoding="utf-8")
        self.assertLess(text.index('"$RECOVER" resume'), text.index('rm -f "$FLAG"'),
                        "consuming the flag first would erase the evidence that "
                        "resume uses to prove the exchange completed")
        self.assertNotIn("sort | tail -n 1", text)
        self.assertNotIn("_recovered", text.split("SFHELP")[-1],
                         "postboot must no longer park @new by itself")

    def test_phoenix_recover_is_importable_and_prints_its_plan(self):
        result = subprocess.run(
            [sys.executable, str(PHOENIX / "usr/libexec/phoenix-recover"), "--help"],
            capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("inspect", result.stdout)
        self.assertIn("--dry-run", result.stdout)

    def test_phoenix_recover_refuses_to_run_as_a_normal_user(self):
        if os.geteuid() == 0:
            self.skipTest("running as root")
        result = subprocess.run(
            [sys.executable, str(PHOENIX / "usr/libexec/phoenix-recover"), "inspect"],
            capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 1)
        self.assertIn("must run as root", result.stderr)

    def test_the_package_is_in_the_debian_install_manifest(self):
        manifest = (PHOENIX / "debian/shadowfetch-phoenix.install").read_text(
            encoding="utf-8")
        self.assertIn("usr/libexec/phoenix-recover", manifest)
        self.assertIn("usr/lib/shadowfetch/phoenix/", manifest)


if __name__ == "__main__":
    unittest.main()
