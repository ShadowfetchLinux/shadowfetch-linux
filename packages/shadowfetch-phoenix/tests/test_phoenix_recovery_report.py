"""W-18: phoenix-recovery-report runs as root through pkexec, so its argument
must not steer a root write, its output must not be world-readable, and it must
not carry hardware serials or raw dmesg - while staying good enough to diagnose
a failed boot.

The script's one hard-coded absolute path (its output directory) is rewritten to
a sandbox path in a COPY - deliberately, so the shipped tool keeps no
environment hook that could move a root-owned write. Every tool it shells out to
is a stub on PATH.
"""

import subprocess
import tarfile
import unittest
from pathlib import Path

from harness import REPORT, ROOT, SandboxTestCase

SERIAL = "S3Z8NB0K123456"
MAC = "a4:bb:6d:1f:9e:02"
OUTDIR_LINE = "OUTDIR=/var/lib/shadowfetch/recovery-reports"

DMESG = f"""[    0.000000] Linux version 6.9.0-new (builder@shadowfetch)
[    0.000000] Command line: BOOT_IMAGE=/@/boot/vmlinuz-6.9.0-new root=UUID=1234 ro quiet
[    1.101000] ata1.00: ATA-11: Samsung SSD 990, {SERIAL}, max UDMA/133
[    1.204000] usb 1-3: SerialNumber: {SERIAL}
[    2.310000] e1000e 0000:00:1f.6 eth0: MAC: {MAC}
[    3.000000] wlan0: authenticate psk=hunter2secretvalue
[   42.900000] BTRFS error (device nvme0n1p2): parent transid verify failed
"""

SMART_JSON = f"""{{
  "model_name": "Samsung SSD 990",
  "serial_number": "{SERIAL}",
  "wwn": {{ "naa": 5, "oui": 6478, "id": 123456789 }},
  "smart_status": {{ "passed": true }},
  "temperature": {{ "current": 41 }}
}}
"""


def git_show(path: Path, revision: str = "HEAD") -> str:
    rel = path.relative_to(ROOT)
    return subprocess.run(["git", "-C", str(ROOT), "show", f"{revision}:{rel}"],
                          capture_output=True, text=True, check=True).stdout


class ReportSandbox(SandboxTestCase):
    requires_exchange = False   # this tool never exchanges a subvolume

    def setUp(self):
        super().setUp()
        self.outdir = self.sb.base / "reports"
        self.sb.write_stub("id", 'echo 0\n')
        self.sb.write_stub("journalctl", 'echo "sfboot: something failed"\n')
        self.sb.write_stub("dmesg", "cat <<'EOF'\n" + DMESG + "EOF\n")
        self.sb.write_stub("systemctl", 'echo "nothing.service failed"\n')
        self.sb.write_stub("dpkg", 'echo ""\n')
        self.sb.write_stub("snapper", 'exit 1\n')
        self.sb.write_stub("btrfs", 'echo "Overall: 12 GiB"\n')
        self.sb.write_stub("lsblk", f"""
case "$*" in
  *SERIAL*) echo '{SERIAL}' ;;
  *NAME,TYPE*) echo 'sda disk' ;;
  *) echo 'sda 500G disk btrfs /' ;;
esac
""")
        self.sb.write_stub("smartctl", "cat <<'EOF'\n" + SMART_JSON + "EOF\n")
        self.sb.write_stub("inxi", f"echo 'Drive serial: {SERIAL}'\n")

    def prepare(self, text: str, name: str) -> Path:
        self.assertEqual(text.count(OUTDIR_LINE), 1,
                         "the report output directory is no longer a single "
                         "hard-coded assignment; update this test")
        script = self.sb.base / name
        script.write_text(text.replace(OUTDIR_LINE, f"OUTDIR={self.outdir}"))
        script.chmod(0o755)
        return script

    def fixed(self) -> Path:
        return self.prepare(REPORT.read_text(), "phoenix-recovery-report.fixed")

    def original(self) -> Path:
        return self.prepare(git_show(REPORT), "phoenix-recovery-report.orig")

    def extract(self, bundle: Path) -> dict:
        target = self.sb.base / ("x" + bundle.name)
        target.mkdir()
        with tarfile.open(bundle) as tar:
            try:
                tar.extractall(target, filter="data")
            except TypeError:       # Python < 3.12
                tar.extractall(target)
        return {p.name: p.read_text(errors="replace")
                for p in target.rglob("*") if p.is_file()}


class OutputIsConfinedAndPrivate(ReportSandbox):
    def test_default_report_is_0600_in_a_0700_directory(self):
        result = self.sb.run(self.fixed())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        bundles = list(self.outdir.glob("recovery-report-*.tar.gz"))
        self.assertEqual(len(bundles), 1, bundles)
        self.assertEqual(bundles[0].stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.outdir.stat().st_mode & 0o777, 0o700)

    def test_the_pre_fix_report_was_world_readable(self):
        result = self.sb.run(self.original())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        bundles = list(self.outdir.glob("recovery-report-*.tar.gz"))
        self.assertEqual(bundles[0].stat().st_mode & 0o777, 0o644)

    def test_traversal_argument_stays_inside_the_report_directory(self):
        escape = self.sb.base / "escaped.tar.gz"
        result = self.sb.run(self.fixed(), f"../../{escape.name}")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(escape.exists(), "the report escaped its directory")
        self.assertTrue((self.outdir / escape.name).exists())

    def test_absolute_path_argument_is_reduced_to_its_name(self):
        escape = self.sb.base / "pwned.tar.gz"
        result = self.sb.run(self.fixed(), str(escape))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(escape.exists())
        self.assertTrue((self.outdir / "pwned.tar.gz").exists())

    def test_the_pre_fix_script_wrote_wherever_it_was_told(self):
        escape = self.sb.base / "pwned.tar.gz"
        result = self.sb.run(self.original(), str(escape))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(escape.exists(),
                        "expected the pre-fix script to write the caller's path")

    def test_unusable_names_are_refused(self):
        for name in ("..", ".", "-rf", "/"):
            with self.subTest(name=name):
                result = self.sb.run(self.fixed(), name)
                self.assertEqual(result.returncode, 2, result.stderr)


class ReportIsRedactedButStillDiagnostic(ReportSandbox):
    def test_serials_and_secrets_are_gone_and_diagnosis_survives(self):
        result = self.sb.run(self.fixed())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        bundle = next(self.outdir.glob("*.tar.gz"))
        files = self.extract(bundle)

        joined = "\n".join(files.values())
        self.assertNotIn(SERIAL, joined, "a hardware serial number leaked")
        self.assertNotIn(MAC, joined, "a MAC address leaked")
        self.assertNotIn("hunter2secretvalue", joined, "a psk= value leaked")

        dmesg = files["dmesg.txt"]
        self.assertIn("redacted", dmesg)
        # ... and everything a failed boot is actually diagnosed from remains:
        self.assertIn("Command line: BOOT_IMAGE=", dmesg)
        self.assertIn("BTRFS error", dmesg)
        self.assertIn("parent transid verify failed", dmesg)
        self.assertIn("Linux version 6.9.0-new", dmesg)
        self.assertIn("smart_status", files["smart-sda.json"])
        self.assertIn("temperature", files["smart-sda.json"])
        self.assertIn("nothing.service failed", files["failed-units.txt"])

    def test_the_pre_fix_report_leaked_the_serial_and_raw_dmesg(self):
        result = self.sb.run(self.original())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        bundle = next(self.outdir.glob("*.tar.gz"))
        joined = "\n".join(self.extract(bundle).values())
        self.assertIn(SERIAL, joined)
        self.assertIn(MAC, joined)
        self.assertIn("hunter2secretvalue", joined)


if __name__ == "__main__":
    unittest.main()
