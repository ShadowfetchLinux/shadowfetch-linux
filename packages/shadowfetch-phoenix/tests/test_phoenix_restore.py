"""W-11: phoenix-restore must never leave /boot from one generation next to a
root subvolume from another, and a successful restore must be unchanged.

Every test runs the SHIPPED script against a fake Btrfs volume and a fake
external /boot (see harness.py). The real machine's root, /boot and GRUB
environment are never touched: mount, umount, btrfs, grub-reboot, update-grub,
grub-editenv, blkid, findmnt, mktemp, sync and id are all stubs on PATH.
"""

import subprocess
import unittest
from pathlib import Path

from harness import (FAKE_UUID, NEW_KERNEL, OLD_KERNEL, RESTORE, ROOT,
                     SandboxTestCase, tree_state)


# The regression proofs below compare against the code as PUBLISHED, not
# against HEAD. Pinning to HEAD made these tests self-invalidating: once the
# fix was committed, HEAD held the fixed script and every "the old code did
# X" assertion failed against code that no longer does X.
SHIPPED_REVISION = "v4.0.0"


def assert_is_the_pre_fix_script(source: str, current: Path) -> None:
    """Guard: the revision really is the code before the fix."""
    if source == current.read_text():
        raise AssertionError(
            "%s resolves to the CURRENT script, so this regression proof would "
            "compare the fix against itself" % SHIPPED_REVISION)


def git_show(path: Path, revision: str = SHIPPED_REVISION) -> str:
    rel = path.relative_to(ROOT)
    return subprocess.run(["git", "-C", str(ROOT), "show", f"{revision}:{rel}"],
                          capture_output=True, text=True, check=True).stdout


class RestoreSucceedsUnchanged(SandboxTestCase):
    """Invariant: an uninterrupted restore does exactly what it did before."""

    def test_uninterrupted_restore_matches_the_shipped_behaviour(self):
        self.sb.build_stubs()
        script = self.sb.script_copy(RESTORE, "phoenix-restore.fixed")
        self.assertGreater(self.sb.rewrites[0], 0, "no /boot path was sandboxed")
        self.assertEqual(self.sb.rewrites[1], 1, "the /run mktemp template moved")

        result = self.sb.run(script, "1")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

        # The Point is now the root; the old root is kept once.
        self.assertEqual((self.sb.volume / "@/generation").read_text(), "POINT-1\n")
        prev = sorted(self.sb.volume.glob("@_prev_*"))
        self.assertEqual(len(prev), 1, prev)
        self.assertEqual((prev[0] / "generation").read_text(), "OLD-ROOT\n")
        self.assertFalse((self.sb.volume / "@new").exists())

        # /boot keeps the restored Point's kernel and archives the other one.
        self.assertTrue((self.sb.boot / f"vmlinuz-{OLD_KERNEL}").exists())
        archive = sorted(self.sb.boot.glob("phoenix-kernel-backup-*"))
        self.assertEqual(len(archive), 1, archive)
        self.assertTrue((archive[0] / f"vmlinuz-{NEW_KERNEL}").exists())
        self.assertFalse((self.sb.boot / f"vmlinuz-{NEW_KERNEL}").exists())

        # The next boot is pinned and postboot is told to rebuild the menu.
        calls = self.sb.log.read_text()
        self.assertIn(f"grub-reboot gnulinux-advanced-{FAKE_UUID}>"
                      f"gnulinux-{OLD_KERNEL}-advanced-{FAKE_UUID}", calls)
        flag = (self.sb.volume / "@/var/lib/shadowfetch/phoenix-update-grub").read_text()
        self.assertIn("restored=1", flag)
        self.assertIn(f"kernel={OLD_KERNEL}", flag)

    def test_result_is_identical_to_the_pre_fix_script(self):
        """The fix removes a failure mode, not a feature: on the happy path the
        old and the new script must produce the same volume and /boot."""
        def outcome(source_text: str, name: str) -> dict:
            self.setUp()                      # a fresh sandbox per run
            self.sb.build_stubs()
            script = self.sb.base / name
            script.write_text(source_text)
            script.chmod(0o755)
            # apply the same sandboxing rewrites as script_copy
            text = script.read_text().replace("/boot", str(self.sb.boot))
            text = text.replace("/run/phoenix-restore.XXXXXX",
                                str(self.sb.runtmp / "phoenix-restore.XXXXXX"))
            script.write_text(text)
            result = self.sb.run(script, "1")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            state = {}
            state["root"] = (self.sb.volume / "@/generation").read_text()
            state["prev"] = sorted(p.name.split("_prev_")[0]
                                   for p in self.sb.volume.glob("@_prev_*"))
            state["boot"] = sorted(p.name for p in self.sb.boot.iterdir()
                                   if not p.name.startswith("phoenix-kernel-backup"))
            archive = sorted(self.sb.boot.glob("phoenix-kernel-backup-*"))
            state["archived"] = sorted(p.name for p in archive[0].iterdir())
            flag = self.sb.volume / "@/var/lib/shadowfetch/phoenix-update-grub"
            state["flag"] = [line for line in flag.read_text().splitlines()
                             if not line.startswith(("date=", "previous=",
                                                     "boot_archive="))]
            return state

        after = outcome(RESTORE.read_text(), "phoenix-restore.fixed")
        before = outcome(git_show(RESTORE), "phoenix-restore.orig")
        self.assertEqual(before, after)


class InterruptedRestoreLeavesBootConsistent(SandboxTestCase):
    """The defect: an interrupt between the /boot staging and the subvolume
    exchange left the machine with a root from one generation and a /boot from
    another - less recoverable than before the restore was attempted."""

    def test_sigterm_after_boot_staging_rolls_boot_back(self):
        self.sb.build_stubs(kill_on_update_grub="TERM")
        script = self.sb.script_copy(RESTORE, "phoenix-restore.fixed")
        result = self.sb.run(script, "1")

        self.assertEqual(result.returncode, 143,
                         f"expected SIGTERM exit\n{result.stdout}\n{result.stderr}")
        # The root subvolume was never exchanged ...
        self.assertEqual((self.sb.volume / "@/generation").read_text(), "OLD-ROOT\n")
        # ... so /boot must be back exactly as the running system left it.
        for kernel in (OLD_KERNEL, NEW_KERNEL):
            self.assertTrue((self.sb.boot / f"vmlinuz-{kernel}").exists(),
                            f"vmlinuz-{kernel} was not put back")
            self.assertTrue((self.sb.boot / f"initrd.img-{kernel}").exists())
        self.assertEqual(sorted(self.sb.boot.glob("phoenix-kernel-backup-*")), [],
                         "the kernel archive was left behind")
        # ... and the pinned next boot was released.
        self.assertIn("grub-editenv", self.sb.log.read_text())

        # The intent journal explains what was in flight and what was undone.
        # (/boot reads as the sandbox path here: the harness rewrote it.)
        journal = (self.sb.volume / "phoenix-restore.journal").read_text()
        self.assertIn("restore requested for Point #1", journal)
        self.assertIn(f"staged for kernel {OLD_KERNEL}", journal)
        self.assertIn("interrupted before the atomic exchange", journal)
        self.assertIn("back", journal.splitlines()[-1])
        # The same journal is on the root that keeps booting.
        in_root = (self.sb.volume / "@/var/lib/shadowfetch/phoenix-restore.journal")
        self.assertIn("restore requested for Point #1", in_root.read_text())

    def test_the_pre_fix_script_did_not_roll_boot_back(self):
        """Same interrupt, the script as shipped in v4.0.0.

        Modelled with a mount that survives cleanup (a busy top-level mount -
        `umount` in the old cleanup is best-effort and ignores its own failure).
        The old trap cleaned up and then let the script CONTINUE, so the
        interrupt neither aborted the restore nor rolled /boot back."""
        self.sb.build_stubs(kill_on_update_grub="TERM")
        script = self.sb.base / "phoenix-restore.orig"
        text = git_show(RESTORE).replace("/boot", str(self.sb.boot))
        text = text.replace("/run/phoenix-restore.XXXXXX",
                            str(self.sb.runtmp / "phoenix-restore.XXXXXX"))
        script.write_text(text)
        script.chmod(0o755)

        result = self.sb.run(script, "1")
        root_generation = (self.sb.volume / "@/generation").read_text()
        archives = sorted(self.sb.boot.glob("phoenix-kernel-backup-*"))
        # The old script ran to completion through the signal: the exchange it
        # was interrupted before happened anyway, and nothing rolled back.
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(root_generation, "POINT-1\n",
                         "expected the pre-fix script to finish through SIGTERM")
        self.assertEqual(len(archives), 1)
        self.assertFalse((self.sb.volume / "phoenix-restore.journal").exists(),
                         "the pre-fix script wrote no intent journal")


class DryRun(SandboxTestCase):
    def test_dry_run_changes_nothing_and_prints_the_plan(self):
        self.sb.build_stubs()
        script = self.sb.script_copy(RESTORE, "phoenix-restore.fixed")
        before_volume = tree_state(self.sb.volume)
        before_boot = tree_state(self.sb.boot)

        result = self.sb.run(script, "--dry-run", "1")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

        self.assertEqual(before_volume, tree_state(self.sb.volume))
        self.assertEqual(before_boot, tree_state(self.sb.boot))
        self.assertFalse((self.sb.volume / "phoenix-restore.journal").exists())

        out = result.stdout
        self.assertIn("DRY RUN", out)
        self.assertIn("@new <-> @", out)
        self.assertIn(f"kernel kept in", out)
        self.assertIn(OLD_KERNEL, out)
        self.assertIn(f"vmlinuz-{NEW_KERNEL}", out)

        calls = self.sb.log.read_text()
        self.assertNotIn("grub-reboot", calls)
        self.assertNotIn("subvolume snapshot", calls)

    def test_dry_run_reports_a_point_that_cannot_be_restored(self):
        self.sb.build_stubs()
        script = self.sb.script_copy(RESTORE, "phoenix-restore.fixed")
        result = self.sb.run(script, "--dry-run", "7")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Point #7", result.stderr)


if __name__ == "__main__":
    unittest.main()
