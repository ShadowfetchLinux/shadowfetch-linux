"""W-10: exactly ONE first-boot job may establish the Btrfs snapshot layout.

Through 3.5 both shadowfetch-firstboot.service (firstboot.sh) and
phoenix-firstboot.service created and tuned the snapper root config. Nothing
ordered them, so whichever won decided the layout - and when firstboot.sh won,
snapper's nested /.snapshots subvolume survived instead of being replaced by the
top-level @snapshots mount, so Point history did not survive a restore.

These tests pin: the duplicate initialiser is gone, the surviving one is intact,
the ordering is declared, and phoenix-check-layout actually detects the
half-initialised layout the race produced.
"""

import os
import re
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PHOENIX = ROOT / "packages/shadowfetch-phoenix"
DEFAULTS = ROOT / "packages/shadowfetch-defaults"

FIRSTBOOT_SH = DEFAULTS / "data/usr/lib/shadowfetch/firstboot.sh"
FIRSTBOOT_UNIT = DEFAULTS / "data/usr/lib/systemd/system/shadowfetch-firstboot.service"
PHOENIX_FIRSTBOOT = PHOENIX / "usr/libexec/phoenix-firstboot"
PHOENIX_UNIT = PHOENIX / "usr/lib/systemd/system/phoenix-firstboot.service"
CHECK_LAYOUT = PHOENIX / "usr/libexec/phoenix-check-layout"
INSTALL = PHOENIX / "debian/shadowfetch-phoenix.install"


def code_of(path: Path) -> str:
    """The script without comment lines - what actually runs."""
    return "\n".join(line for line in path.read_text().splitlines()
                     if not line.lstrip().startswith("#"))


class OnlyPhoenixArmsSnapper(unittest.TestCase):
    def test_firstboot_sh_no_longer_initialises_snapshots(self):
        code = code_of(FIRSTBOOT_SH)
        for forbidden in ("snapper", "grub-btrfsd", "update-grub",
                          "snapper-timeline.timer", "create-config"):
            self.assertNotIn(forbidden, code,
                             f"firstboot.sh still races Phoenix over {forbidden}")

    def test_firstboot_sh_kept_everything_else_it_owns(self):
        code = code_of(FIRSTBOOT_SH)
        for kept in ("flatpak remote-add --if-not-exists flathub",
                     "timedatectl set-local-rtc 0 --adjust-system-clock",
                     "systemctl enable --now systemd-timesyncd.service",
                     "ufw limit OpenSSH",
                     "ufw --force enable",
                     "/usr/bin/batcat",
                     'touch "$STAMP"'):
            self.assertIn(kept, code, f"firstboot.sh lost {kept!r}")

    def test_phoenix_firstboot_is_still_the_full_initialiser(self):
        code = code_of(PHOENIX_FIRSTBOOT)
        for kept in ("snapper --no-dbus -c root create-config /",
                     "btrfs subvolume delete /.snapshots",
                     "mount /.snapshots",
                     "TIMELINE_CREATE=no",
                     "snapper-cleanup.timer",
                     "grub-btrfsd.service",
                     'create --description "Fresh install"'):
            self.assertIn(kept, code, f"phoenix-firstboot lost {kept!r}")

    def test_first_boot_setup_is_ordered_after_phoenix(self):
        unit = FIRSTBOOT_UNIT.read_text()
        self.assertIn("After=phoenix-firstboot.service", unit)
        # Ordering only: a Phoenix failure must not stop the firewall or the RTC.
        self.assertNotIn("Requires=phoenix-firstboot.service", unit)
        self.assertNotIn("BindsTo=phoenix-firstboot.service", unit)

    def test_layout_is_verified_after_arming(self):
        unit = PHOENIX_UNIT.read_text()
        self.assertIn("ExecStartPost=/usr/libexec/phoenix-check-layout", unit)
        self.assertIn("ExecStart=/usr/libexec/phoenix-firstboot", unit)

    def test_check_layout_is_shipped_and_executable(self):
        self.assertIn("usr/libexec/phoenix-check-layout", INSTALL.read_text())
        mode = CHECK_LAYOUT.stat().st_mode
        self.assertTrue(mode & stat.S_IXUSR, "phoenix-check-layout is not executable")
        self.assertTrue(CHECK_LAYOUT.read_text().startswith("#!/bin/sh"))

    def test_check_layout_only_reads(self):
        code = code_of(CHECK_LAYOUT)
        for mutation in (r"\bmkdir\b", r"\brmdir\b", r"\brm\s", r"\bmv\s",
                         r"\bsystemctl\s+(enable|start|disable)",
                         r"subvolume\s+(create|delete|snapshot)",
                         r"snapper[^\n]*(create|set-config)",
                         r"\bumount\b", r"\bmount\s+/",
                         r">\s*/(?!dev/null)"):
            self.assertIsNone(re.search(mutation, code),
                              f"phoenix-check-layout must not mutate: {mutation}")


class CheckLayoutDetectsTheRaceArtifact(unittest.TestCase):
    """phoenix-check-layout run against fake layouts. PHOENIX_CHECK_ROOT only
    changes which paths are READ; the tool writes nothing anywhere."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="phoenix-layout.")
        self.addCleanup(self._tmp.cleanup)
        self.base = Path(self._tmp.name)
        self.fake = self.base / "root"
        self.bin = self.base / "bin"
        self.bin.mkdir(parents=True)
        (self.fake / "etc/snapper/configs").mkdir(parents=True)

    def stub(self, name: str, body: str) -> None:
        path = self.bin / name
        path.write_text("#!/bin/sh\n" + body)
        path.chmod(0o755)

    def layout(self, *, config: bool, snapshots: str) -> None:
        """snapshots: 'mount' | 'nested-subvolume' | 'plain' | 'missing'"""
        if config:
            (self.fake / "etc/snapper/configs/root").write_text("SUBVOLUME=/\n")
        if snapshots != "missing":
            (self.fake / ".snapshots").mkdir()
        self.stub("mountpoint", "exit 0\n" if snapshots == "mount" else "exit 1\n")
        self.stub("btrfs", "exit 0\n" if snapshots == "nested-subvolume" else "exit 1\n")

    def run_check(self):
        env = dict(os.environ)
        env["PATH"] = f"{self.bin}:{env.get('PATH', '')}"
        env["PHOENIX_CHECK_ROOT"] = str(self.fake)
        env["LC_ALL"] = "C"
        return subprocess.run(["/bin/sh", str(CHECK_LAYOUT)],
                              capture_output=True, text=True, env=env,
                              timeout=30, check=False)

    def test_healthy_layout_passes(self):
        self.layout(config=True, snapshots="mount")
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("separate mount", result.stdout)

    def test_the_race_artifact_fails(self):
        """The exact half-initialised state the deleted firstboot.sh block
        produced: a snapper config plus snapper's own NESTED .snapshots
        subvolume, with @snapshots never mounted over it."""
        self.layout(config=True, snapshots="nested-subvolume")
        result = self.run_check()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("nested subvolume", result.stderr)
        self.assertIn("lost on the first restore", result.stderr)

    def test_missing_snapper_config_fails(self):
        self.layout(config=False, snapshots="plain")
        result = self.run_check()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("no snapper root config", result.stderr)

    def test_missing_snapshots_directory_fails(self):
        self.layout(config=True, snapshots="missing")
        result = self.run_check()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("/.snapshots is missing", result.stderr)

    def test_degraded_but_working_layout_only_warns(self):
        self.layout(config=True, snapshots="plain")
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("WARN", result.stderr)
        self.assertIn("does not survive", result.stderr)


if __name__ == "__main__":
    unittest.main()
