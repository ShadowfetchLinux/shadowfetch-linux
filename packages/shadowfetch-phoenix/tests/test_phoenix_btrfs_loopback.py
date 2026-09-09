"""Root recovery against a REAL Btrfs filesystem, including power cuts.

Everything here runs on a loopback Btrfs made with mkfs.btrfs in a temp dir:
real subvolumes, a real `btrfs subvolume snapshot`, a real
renameat2(RENAME_EXCHANGE) between two subvolume roots, and the SHIPPED
phoenix-restore driving them. Only the things that must not touch this machine
are stubbed - id, findmnt, blkid, mount, umount, mountpoint, mktemp, grub-*
and update-grub - and /boot is rewritten to a sandbox directory in a copy of
the script, exactly as harness.py already does for the fake-volume tests.

The point of the whole file is the two power-cut cases. A signal-based test
can only ever prove that a shell trap runs; a power cut runs NO trap, and
before Stage T nothing recovered from one:

  * SIGKILL before the exchange left @new behind, and phoenix-postboot parked
    it as if it were the previous root, costing a generation.
  * SIGKILL after the exchange left the restored root with no update-grub flag
    (it was written after the swap), so the boot menu was never rebuilt, and
    left @new - the ACTUAL previous root - indistinguishable from the case
    above.

SIGKILL is used deliberately: it cannot be caught, so nothing in the script
gets a chance to tidy up, which is what a power cut looks like.

Root is needed only to mount the loop device. The tests skip, loudly, when
`sudo -n` is not available rather than pretending to have run.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from harness import (EXCHANGE_HELPER, FAKE_UUID, NEW_KERNEL, OLD_KERNEL,
                     PHOENIX, RECOVER, RESTORE, LoopbackBtrfs, import_phoenix,
                     real_mv_supports_exchange, run_root)

phoenix = import_phoenix()
from phoenix import gc as gcmod                    # noqa: E402
from phoenix import journal as journalmod          # noqa: E402
from phoenix import layout as layoutmod            # noqa: E402
from phoenix import transaction as txmod           # noqa: E402
from phoenix import trusted as trustedmod          # noqa: E402


class RealVolumeTestCase(unittest.TestCase):
    """A loopback Btrfs plus a sandboxed /boot and a stub PATH."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="phoenix-loop.")
        self.addCleanup(self._tmp.cleanup)
        self.base = Path(self._tmp.name)
        self.volume = LoopbackBtrfs(self.base)
        # LIFO: give the sandbox back to this user (the shipped script runs as
        # root and leaves root-owned files in it), then unmount, then remove.
        self.addCleanup(self.volume.__exit__, None, None, None)
        self.addCleanup(run_root, "chown", "-R",
                        "%d:%d" % (os.getuid(), os.getgid()), str(self.base),
                        check=False)
        self.volume.__enter__()
        self.mount = self.volume.mount
        self.bin = self.base / "bin"
        self.boot = self.base / "boot"
        self.state = self.base / "state"
        self.log = self.base / "calls.log"
        for directory in (self.bin, self.boot, self.state):
            directory.mkdir(parents=True, exist_ok=True)

    # -- the volume --------------------------------------------------------
    def build_volume(self):
        root = self.volume.subvolume("@")
        (root / "var/lib/shadowfetch").mkdir(parents=True)
        (root / f"lib/modules/{NEW_KERNEL}").mkdir(parents=True)
        (root / "generation").write_text("OLD-ROOT\n")

        self.volume.subvolume("@snapshots")
        (self.mount / "@snapshots/1").mkdir()
        point = self.volume.subvolume("@snapshots/1/snapshot")
        (point / "var/lib/shadowfetch").mkdir(parents=True)
        (point / f"lib/modules/{OLD_KERNEL}").mkdir(parents=True)
        (point / "generation").write_text("POINT-1\n")
        return root, point

    def build_boot(self):
        (self.boot / "grub").mkdir(parents=True, exist_ok=True)
        for kernel in (OLD_KERNEL, NEW_KERNEL):
            for prefix in ("vmlinuz", "initrd.img", "config", "System.map"):
                (self.boot / f"{prefix}-{kernel}").write_text(f"{prefix} {kernel}\n")
        (self.boot / "grub/grub.cfg").write_text(
            f"submenu 'Advanced' --id 'gnulinux-advanced-{FAKE_UUID}' {{\n"
            f"  menuentry 'old' --id 'gnulinux-{OLD_KERNEL}-advanced-{FAKE_UUID}' {{}}\n"
            f"  menuentry 'new' --id 'gnulinux-{NEW_KERNEL}-advanced-{FAKE_UUID}' {{}}\n"
            "}\n")
        (self.boot / "grub/grubenv").write_text("# GRUB Environment Block\n")

    # -- stubs (everything EXCEPT btrfs and mv) ---------------------------
    def stub(self, name, body):
        path = self.bin / name
        path.write_text("#!/bin/sh\n" + body)
        path.chmod(0o755)

    def build_stubs(self, kill_after_snapshot=False, kill_after_exchange=False):
        log = self.log
        device = self._a_block_device()
        self.stub("id", f'printf "id %s\\n" "$*" >> "{log}"\necho 0\n')
        self.stub("findmnt", f"""
printf 'findmnt %s\\n' "$*" >> "{log}"
what=
for a in "$@"; do case "$a" in FSTYPE|SOURCE) what=$a ;; esac; done
case "$what" in
  FSTYPE) echo btrfs ;;
  SOURCE) echo '{device}[/@]' ;;
esac
""")
        self.stub("blkid", f'printf "blkid %s\\n" "$*" >> "{log}"\necho {FAKE_UUID}\n')
        # The volume is ALREADY mounted at this path by the harness, so mktemp
        # hands the script the real top-level and mount/umount are no-ops.
        self.stub("mktemp", f'printf "mktemp %s\\n" "$*" >> "{log}"\necho "{self.mount}"\n')
        self.stub("mount", f'printf "mount %s\\n" "$*" >> "{log}"\n: > "{self.state}/mounted"\n')
        self.stub("umount", f'printf "umount %s\\n" "$*" >> "{log}"\nrm -f "{self.state}/mounted"\n')
        self.stub("mountpoint", f"""
printf 'mountpoint %s\\n' "$*" >> "{log}"
target=
for a in "$@"; do case "$a" in -*) ;; *) target=$a ;; esac; done
case "$target" in
  '{self.boot}') exit 0 ;;
  '{self.mount}') [ -f '{self.state}/mounted' ] ;;
  *) exit 1 ;;
esac
""")
        self.stub("grub-reboot", f'printf "grub-reboot %s\\n" "$*" >> "{log}"\n')
        self.stub("grub-editenv", f'printf "grub-editenv %s\\n" "$*" >> "{log}"\n')
        self.stub("update-grub", f'printf "update-grub %s\\n" "$*" >> "{log}"\n')

        # btrfs is REAL. The wrapper exists only to model a power cut at an
        # exact instant: it runs the genuine binary first, so the on-disk state
        # the resume path then sees is the state a real crash would leave.
        kill_snapshot = ""
        if kill_after_snapshot:
            kill_snapshot = (
                'if [ "$1 $2" = "subvolume snapshot" ]; then\n'
                f'  kill -KILL "$PPID" 2>/dev/null || true\n'
                '  sleep 2\n'
                'fi\n')
        self.stub("btrfs", f"""
printf 'btrfs %s\\n' "$*" >> "{log}"
/usr/bin/btrfs "$@"
status=$?
{kill_snapshot}exit $status
""")

        # mv: the real binary, except for --exchange. coreutils only grew
        # --exchange in 9.5, so on an older build host the exchange goes
        # through the same renameat2 syscall by hand rather than through an
        # imitation of it.
        helper = self.bin / "mv-exchange-helper.py"
        helper.write_text(EXCHANGE_HELPER)
        real_mv = shutil.which("mv", path="/usr/bin:/bin")
        exchange_impl = ('exec "%s" "$@"' % real_mv if real_mv_supports_exchange(self.base)
                         else 'exec python3 "%s" "$3" "$4"' % helper)
        kill_exchange = ""
        if kill_after_exchange:
            # The exchange really happens, and only then does the shell die -
            # the exact window in which @ is the restored Point and @new is
            # still the old root.
            exchange_impl = (
                ('"%s" "$@"' % real_mv) if real_mv_supports_exchange(self.base)
                else ('python3 "%s" "$3" "$4"' % helper))
            kill_exchange = (
                'status=$?\n'
                f'kill -KILL "$PPID" 2>/dev/null || true\n'
                'sleep 2\n'
                'exit $status\n')
        self.stub("mv", f"""
if [ "$1" = "--exchange" ] && [ "$2" = "--no-target-directory" ]; then
    printf 'mv --exchange %s %s\\n' "$3" "$4" >> "{log}"
    {exchange_impl}
{kill_exchange}fi
exec '{real_mv}' "$@"
""")

    @staticmethod
    def _a_block_device():
        import stat as statmod
        for entry in sorted(Path("/dev").iterdir()):
            try:
                if statmod.S_ISBLK(os.stat(entry).st_mode):
                    return str(entry)
            except OSError:
                continue
        raise unittest.SkipTest("no block device node available")

    # -- running the shipped script ---------------------------------------
    def script_copy(self):
        text = RESTORE.read_text()
        self.assertGreater(text.count("/boot"), 0, "no /boot path was sandboxed")
        text = text.replace("/boot", str(self.boot))
        self.assertEqual(text.count("/run/phoenix-restore.XXXXXX"), 1)
        text = text.replace("/run/phoenix-restore.XXXXXX",
                            str(self.base / "phoenix-restore.XXXXXX"))
        target = self.base / "phoenix-restore"
        target.write_text(text)
        target.chmod(0o755)
        return target

    def run_restore(self, *args, timeout=180):
        """The shipped script, as root, against the real loopback volume.

        Root because `btrfs subvolume show` searches the B-tree and needs
        CAP_SYS_ADMIN - which is also how the tool really runs (pkexec). The
        stub PATH is handed to the child explicitly through env(1) rather than
        inherited, so sudo's own secure_path cannot change what is on it."""
        path = f"{self.bin}:/usr/sbin:/usr/bin:/sbin:/bin"
        return run_root("/usr/bin/env", f"PATH={path}", "LC_ALL=C",
                        "/bin/sh", str(self.script_copy()), *args, check=False)

    def run_recover(self, *args, timeout=120):
        """phoenix-recover, as root, against the real volume and sandbox /boot."""
        # -B: this runs as root against the SOURCE tree, and a root-owned
        # __pycache__ left in packages/ would end up in a package build.
        return run_root(sys.executable, "-B", str(RECOVER), *args,
                        "--mount", str(self.mount), "--boot", str(self.boot),
                        check=False)

    # -- helpers -----------------------------------------------------------
    def is_subvolume(self, name):
        return layoutmod.btrfs_subvolume(self.mount / name)

    def generation(self, name="@"):
        return (self.mount / name / "generation").read_text()

    def journal(self):
        return journalmod.IntentJournal(self.mount / journalmod.JOURNAL_NAME)


# =========================================================================
# The layout model, against real subvolumes
# =========================================================================
class LayoutOnRealBtrfs(RealVolumeTestCase):

    def test_the_default_detector_finds_real_subvolumes_and_not_directories(self):
        self.build_volume()
        (self.mount / "just-a-directory").mkdir()
        layout = layoutmod.Layout.probe(self.mount)
        self.assertEqual(layout.fstype, "btrfs")
        self.assertTrue(layout.ok, layout.problems)
        self.assertTrue(layout.root.is_subvolume)
        self.assertTrue(layout.snapshots.is_subvolume)
        self.assertFalse(layout.entry("just-a-directory").is_subvolume)
        self.assertTrue(layout.has_point("1"))
        self.assertFalse(layout.has_point("2"))

    def test_a_plain_directory_named_like_a_previous_root_is_never_deleted(self):
        self.build_volume()
        self.volume.subvolume("@_prev_20260101000000")
        (self.mount / "@_prev_20250101000000").mkdir()
        layout = layoutmod.Layout.probe(self.mount)
        plan = gcmod.plan_previous_roots(layout, keep=1)
        self.assertEqual([d.path.name for d in plan.deletions], [])
        self.assertIn("@_prev_20250101000000",
                      [d.path.name for d in plan.refusals])

    def test_bounded_gc_really_deletes_a_real_subvolume(self):
        self.build_volume()
        newest = self.volume.subvolume("@_prev_20260101000000")
        doomed = self.volume.subvolume("@_prev_20250101000000")
        (doomed / "payload").write_text("bytes\n")
        executor = trustedmod.TrustedExecutor()
        if not executor.available("btrfs"):
            self.skipTest("no trusted btrfs on this host")
        plan = gcmod.plan_previous_roots(layoutmod.Layout.probe(self.mount), keep=1)
        results = gcmod.apply_previous_roots(plan, executor)
        self.assertEqual([(p.name, ok) for p, ok, _ in results],
                         [(doomed.name, True)], results)
        self.assertFalse(doomed.exists())
        self.assertTrue(newest.is_dir())
        self.assertTrue(self.is_subvolume("@"))

    def test_the_atomic_exchange_swaps_two_real_subvolumes(self):
        root, point = self.build_volume()
        copy = self.volume.snapshot(point, self.mount / "@new")
        self.assertTrue(self.is_subvolume("@new"))
        txmod.rename_exchange(self.mount / "@new", self.mount / "@")
        # Both names still exist, both are still subvolume roots, and their
        # contents have traded places. That is the whole safety argument.
        self.assertTrue(self.is_subvolume("@"))
        self.assertTrue(self.is_subvolume("@new"))
        self.assertEqual(self.generation("@"), "POINT-1\n")
        self.assertEqual(self.generation("@new"), "OLD-ROOT\n")
        del root, copy


# =========================================================================
# The shipped restore, end to end, on real Btrfs
# =========================================================================
class RestoreOnRealBtrfs(RealVolumeTestCase):

    def test_a_full_restore_exchanges_real_subvolumes(self):
        self.build_volume()
        self.build_boot()
        self.build_stubs()
        result = self.run_restore("1")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

        self.assertEqual(self.generation("@"), "POINT-1\n")
        self.assertTrue(self.is_subvolume("@"))
        previous = sorted(self.mount.glob("@_prev_*"))
        self.assertEqual(len(previous), 1, previous)
        self.assertEqual((previous[0] / "generation").read_text(), "OLD-ROOT\n")
        self.assertTrue(layoutmod.btrfs_subvolume(previous[0]))
        self.assertFalse((self.mount / "@new").exists())

        flag = txmod.read_flag(self.mount / "@")
        self.assertEqual(flag["restored"], "1")
        self.assertEqual(flag["kernel"], OLD_KERNEL)
        self.assertEqual(flag["previous"], previous[0].name)

        journal = self.journal()
        run = flag["date"]
        self.assertEqual(journal.phase_of(run), "complete")
        self.assertIsNone(journal.in_flight()[0])

    def test_a_restore_leaves_a_volume_the_recovery_tools_call_clean(self):
        self.build_volume()
        self.build_boot()
        self.build_stubs()
        self.assertEqual(self.run_restore("1").returncode, 0)
        result = self.run_recover("inspect")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("decision:    nothing", result.stdout)

    def test_a_dry_run_does_not_fold_the_kernel_archive_back_in(self):
        """The unarchive step is a real /boot mutation, so --dry-run has to
        describe it and not do it."""
        self.build_volume()
        self.build_boot()
        archive = self.boot / "phoenix-kernel-backup-20250101000000"
        archive.mkdir()
        (archive / f"vmlinuz-{NEW_KERNEL}-spare").write_text("spare\n")
        before_boot = sorted(str(p.relative_to(self.boot))
                             for p in self.boot.rglob("*"))
        before_volume = sorted(p.name for p in self.mount.iterdir())

        self.build_stubs()
        result = self.run_restore("--dry-run", "1")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        # (/boot reads as the sandbox path here: the harness rewrote it.)
        self.assertIn("folded back into", result.stdout)
        self.assertIn(archive.name, result.stdout)
        self.assertEqual(sorted(str(p.relative_to(self.boot))
                                for p in self.boot.rglob("*")), before_boot)
        self.assertEqual(sorted(p.name for p in self.mount.iterdir()),
                         before_volume)
        self.assertFalse((self.mount / journalmod.JOURNAL_NAME).exists())

    def test_an_archived_kernel_no_longer_blocks_restoring_back_to_it(self):
        """Before Stage T, archiving NEW_KERNEL made the return trip
        impossible: prepare_external_boot only looked in /boot, so the Point
        that needs it reported 'no kernel shared with the external /boot
        filesystem' and refused."""
        self.build_volume()
        self.build_boot()
        # A previous restore's archive, holding the kernel a second Point needs.
        archive = self.boot / "phoenix-kernel-backup-20250101000000"
        archive.mkdir()
        for prefix in ("vmlinuz", "initrd.img", "config", "System.map"):
            os.replace(self.boot / f"{prefix}-{NEW_KERNEL}",
                       archive / f"{prefix}-{NEW_KERNEL}")
        # Point 2 is the generation whose kernel is only in that archive.
        (self.mount / "@snapshots/2").mkdir()
        point2 = self.volume.subvolume("@snapshots/2/snapshot")
        (point2 / "var/lib/shadowfetch").mkdir(parents=True)
        (point2 / f"lib/modules/{NEW_KERNEL}").mkdir(parents=True)
        (point2 / "generation").write_text("POINT-2\n")

        self.build_stubs()
        result = self.run_restore("2")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.generation("@"), "POINT-2\n")
        self.assertTrue((self.boot / f"vmlinuz-{NEW_KERNEL}").is_file())
        self.assertEqual(sorted(p.name for p in self.boot.glob(
            "phoenix-kernel-backup-*")).__len__(), 1,
            "exactly one archive should remain: the old one was folded back in")


# =========================================================================
# Power cuts
# =========================================================================
class PowerCutBeforeTheExchange(RealVolumeTestCase):
    """SIGKILL immediately after `btrfs subvolume snapshot` created @new.

    On disk: @ is still the old root, @new is a writable copy of the Point,
    the Point itself is untouched. @new is therefore worth nothing, and
    phoenix-postboot's old behaviour - park it as @_prev_<now>_recovered -
    spent a generation of previous-root retention on a throwaway.
    """

    def setUp(self):
        super().setUp()
        self.build_volume()
        self.build_boot()
        self.build_stubs(kill_after_snapshot=True)
        self.result = self.run_restore("1")

    def test_the_crash_left_exactly_the_state_it_should_have(self):
        self.assertNotEqual(self.result.returncode, 0)
        self.assertEqual(self.generation("@"), "OLD-ROOT\n",
                         "the root must be untouched before the exchange")
        self.assertTrue(self.is_subvolume("@new"))
        self.assertEqual(self.generation("@new"), "POINT-1\n")
        # The flag was not written yet, so nothing in @ claims this run.
        self.assertEqual(txmod.read_flag(self.mount / "@").get("date"), None)

    def test_the_journal_names_the_phase_the_crash_interrupted(self):
        journal = self.journal()
        run, phase = journal.in_flight()
        self.assertIsNotNone(run, journal.read())
        self.assertIn(phase, ("staging-created", "requested"))

    def test_inspect_proves_the_exchange_did_not_happen(self):
        layout = layoutmod.Layout.probe(self.mount)
        transaction = txmod.RestoreTransaction(layout, self.journal(), boot=self.boot)
        state = transaction.inspect()
        self.assertIs(state.decision, txmod.Decision.DISCARD_STAGING)
        self.assertFalse(state.exchanged)

    def test_resume_discards_the_copy_and_keeps_the_real_root(self):
        result = self.run_recover("resume")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((self.mount / "@new").exists(), result.stdout)
        self.assertEqual(self.generation("@"), "OLD-ROOT\n")
        self.assertTrue(self.is_subvolume("@"))
        # Nothing was parked: the retention generation is intact.
        self.assertEqual(sorted(self.mount.glob("@_prev_*")), [])
        # And the Point is still restorable afterwards.
        self.assertTrue(layoutmod.Layout.probe(self.mount).has_point("1"))

    def test_a_dry_run_of_the_same_resume_changes_nothing(self):
        before = sorted(p.name for p in self.mount.iterdir())
        result = self.run_recover("resume", "--dry-run")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(sorted(p.name for p in self.mount.iterdir()), before)
        self.assertIn("dry run", result.stdout)


class PowerCutAfterTheExchange(RealVolumeTestCase):
    """SIGKILL in the window between the renameat2 and parking the old root.

    On disk: @ IS the restored Point, @new is the ACTUAL previous root. This is
    the case that was indistinguishable from the one above, and the case whose
    update-grub flag used to be lost (it was written after the swap).
    """

    def setUp(self):
        super().setUp()
        self.build_volume()
        self.build_boot()
        self.build_stubs(kill_after_exchange=True)
        self.result = self.run_restore("1")

    def test_the_crash_left_the_restored_point_as_the_root(self):
        self.assertNotEqual(self.result.returncode, 0)
        self.assertEqual(self.generation("@"), "POINT-1\n")
        self.assertTrue(self.is_subvolume("@"))
        self.assertEqual(self.generation("@new"), "OLD-ROOT\n")
        self.assertEqual(sorted(self.mount.glob("@_prev_*")), [])

    def test_the_boot_menu_rebuild_survived_the_crash(self):
        """The flag is written into @new BEFORE the exchange, so it travels
        with the swap. Written after it, as through 4.0.0, this window lost it
        and the restored root came up against a menu describing the old one."""
        flag = txmod.read_flag(self.mount / "@")
        self.assertEqual(flag.get("restored"), "1")
        self.assertEqual(flag.get("kernel"), OLD_KERNEL)
        self.assertTrue(flag.get("date"))

    def test_inspect_proves_the_exchange_completed(self):
        layout = layoutmod.Layout.probe(self.mount)
        transaction = txmod.RestoreTransaction(layout, self.journal(), boot=self.boot)
        state = transaction.inspect()
        self.assertIs(state.decision, txmod.Decision.FINISH_EXCHANGE)
        self.assertTrue(state.exchanged)
        self.assertFalse(state.boot_rollback,
                         "/boot matches the restored root and must be left alone")

    def test_resume_parks_the_previous_root_under_its_planned_name(self):
        run = txmod.read_flag(self.mount / "@")["date"]
        result = self.run_recover("resume")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((self.mount / "@new").exists())
        parked = self.mount / f"@_prev_{run}"
        self.assertTrue(parked.is_dir(), sorted(self.mount.iterdir()))
        self.assertEqual((parked / "generation").read_text(), "OLD-ROOT\n")
        self.assertTrue(layoutmod.btrfs_subvolume(parked))
        self.assertEqual(self.generation("@"), "POINT-1\n")
        self.assertEqual(self.journal().phase_of(run), "complete")

    def test_resume_is_idempotent(self):
        self.assertEqual(self.run_recover("resume").returncode, 0)
        before = sorted(p.name for p in self.mount.iterdir())
        second = self.run_recover("resume")
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assertEqual(sorted(p.name for p in self.mount.iterdir()), before)

    def test_the_two_power_cuts_are_told_apart_by_evidence_not_by_guessing(self):
        """The pair with PowerCutBeforeTheExchange IS the proof: the same
        leftover @new on the same real filesystem, and the opposite correct
        action, reached from evidence rather than from a default."""
        state = txmod.RestoreTransaction(
            layoutmod.Layout.probe(self.mount), self.journal(),
            boot=self.boot).inspect()
        self.assertTrue(state.exchanged)
        self.assertIs(state.decision, txmod.Decision.FINISH_EXCHANGE)
        self.assertNotEqual(state.evidence, "")
        self.assertIsNotNone(state.run)


class PowerCutAfterBootStaging(RealVolumeTestCase):
    """SIGKILL with the external /boot already staged and the root not swapped.

    A power cut runs no trap, so the shell's W-11 rollback never happens: the
    machine would boot the OLD root against a /boot holding only the Point's
    kernel. Nothing recovered from this before Stage T.
    """

    def setUp(self):
        super().setUp()
        self.build_volume()
        self.build_boot()
        self.build_stubs()
        # Model the post-crash disk directly: the restore reached boot-staged
        # and died. Killing the shell at exactly this instant needs a hook in
        # update-grub, which the signal-based suite already covers; what is
        # under test here is that the RESUME path repairs it on real Btrfs.
        run = "20260909121314"
        self.run = run
        self.volume.snapshot(self.mount / "@snapshots/1/snapshot",
                             self.mount / "@new")
        flag = self.mount / "@new/var/lib/shadowfetch/phoenix-update-grub"
        flag.parent.mkdir(parents=True, exist_ok=True)
        flag.write_text(f"restored=1\ndate={run}\nprevious=@_prev_{run}\n"
                        f"kernel={OLD_KERNEL}\n")
        archive = self.boot / f"phoenix-kernel-backup-{run}"
        archive.mkdir()
        for prefix in ("vmlinuz", "initrd.img", "config", "System.map"):
            os.replace(self.boot / f"{prefix}-{NEW_KERNEL}",
                       archive / f"{prefix}-{NEW_KERNEL}")
        journal = self.journal()
        for phase in ("requested", "staging-created", "boot-staged"):
            journal.append("1", run, phase, "modelled crash")

    def test_resume_puts_the_running_kernels_back_and_discards_the_copy(self):
        result = self.run_recover("resume")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((self.boot / f"vmlinuz-{NEW_KERNEL}").is_file(),
                        "the root that will actually boot got its kernel back")
        self.assertTrue((self.boot / f"vmlinuz-{OLD_KERNEL}").is_file())
        self.assertEqual(sorted(self.boot.glob("phoenix-kernel-backup-*")), [])
        self.assertFalse((self.mount / "@new").exists())
        self.assertEqual(self.generation("@"), "OLD-ROOT\n")
        # /boot repair is journalled first and is not terminal on its own; the
        # attempt is only closed once the staging decision has been carried out.
        journal = self.journal()
        phases = [r.phase for r in journal.records_for(self.run)]
        self.assertIn("resume", phases)
        self.assertEqual(phases[-1], "rolled-back")
        self.assertIsNone(journal.in_flight()[0],
                          "a finished attempt must not stay in flight")

    def test_the_plan_says_so_before_it_does_it(self):
        result = self.run_recover("inspect")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("discard-staging", result.stdout)
        self.assertIn("rollback-boot", result.stdout)


if __name__ == "__main__":
    unittest.main()
