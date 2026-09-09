"""Stage V: the argv grammar of /usr/libexec/phoenix-apt-snapshot.

This helper exists because the Control Center's "Point before every software
change" switch used to run

    pkexec /bin/sh -c "<sed script>"

on every real install (the two helper names busutil probed for were never
shipped, so the shell fallback was the only path).  A generic root shell
authorised by org.freedesktop.policykit.exec is not a scoped authorization: it
grants "a shell, as root", and the constant script text was a property of the
caller's source file rather than of the grant.

These tests are adversarial: they assert what the helper REFUSES.  The
privileged verbs are exercised against a rewritten copy whose TARGET points
into a sandbox, the way the phoenix-restore harness does it -- the script is
adapted to the test, never the other way round, so /etc/default/snapper never
becomes an environment-controlled path in a tool that runs as root.
"""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
HELPER = ROOT / "packages/shadowfetch-phoenix/usr/libexec/phoenix-apt-snapshot"
POLICY = (ROOT / "packages/shadowfetch-phoenix/usr/share/polkit-1/actions"
                 "/org.shadowfetch.phoenix.policy")


class Sandbox:
    """A copy of the helper whose only write target is inside a temp dir,
    plus an `id` stub so the root-only paths can be exercised unprivileged."""

    def __init__(self, base: Path):
        self.base = base
        self.bin = base / "bin"
        self.bin.mkdir()
        self.target = base / "snapper"
        (self.bin / "id").write_text("#!/bin/sh\necho 0\n")
        (self.bin / "id").chmod(0o755)

        text = HELPER.read_text()
        hits = text.count("TARGET=/etc/default/snapper")
        assert hits == 1, (
            "phoenix-apt-snapshot no longer names its write target once at the "
            "top; this harness would silently escape the sandbox")
        self.script = base / "phoenix-apt-snapshot"
        self.script.write_text(
            text.replace("TARGET=/etc/default/snapper", f"TARGET={self.target}"))
        self.script.chmod(0o755)

    def run(self, *args, as_root=True, timeout=20):
        env = dict(os.environ)
        env["PATH"] = (f"{self.bin}:" if as_root else "") + "/usr/bin:/bin"
        env["LC_ALL"] = "C"
        return subprocess.run(["/bin/sh", str(self.script), *args],
                              capture_output=True, text=True, env=env,
                              timeout=timeout, check=False)


class AptSnapshotHelperTests(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="apt-snapshot.")
        self.addCleanup(self._tmp.cleanup)
        self.sb = Sandbox(Path(self._tmp.name))
        self.sb.target.write_text('# keep me\nDISABLE_APT_SNAPSHOT="no"\nOTHER=keep\n')

    # ---- the grammar is a closed set of one word --------------------------

    def test_rejects_zero_arguments(self):
        r = self.sb.run()
        self.assertNotEqual(r.returncode, 0)

    def test_rejects_more_than_one_argument(self):
        r = self.sb.run("enable", "disable")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('DISABLE_APT_SNAPSHOT="no"', self.sb.target.read_text())

    def test_rejects_every_argument_outside_the_verb_set(self):
        # Each of these is a shape a generic-escalation helper would have
        # accepted: a path, a flag, an option pair, shell metacharacters, a
        # verb with a rider.
        for bad in ("/bin/sh", "-c", "--enable", "enable;id", "enable disable",
                    "ENABLE", "on", "off", "yes", "no", "", "..",
                    "/etc/default/snapper", "$(id)", "`id`", "enable\nid"):
            with self.subTest(argument=bad):
                r = self.sb.run(bad)
                self.assertNotEqual(
                    r.returncode, 0,
                    "helper accepted %r; the verb set must stay closed" % bad)
                self.assertIn('DISABLE_APT_SNAPSHOT="no"',
                              self.sb.target.read_text())

    def test_help_and_version_need_no_authentication_and_change_nothing(self):
        for flag in ("-h", "--help", "--version"):
            with self.subTest(flag=flag):
                r = self.sb.run(flag, as_root=False)
                self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('DISABLE_APT_SNAPSHOT="no"', self.sb.target.read_text())

    # ---- root is required for the writes, and only for the writes ---------

    def test_write_verbs_require_root(self):
        for verb in ("enable", "disable"):
            with self.subTest(verb=verb):
                r = self.sb.run(verb, as_root=False)
                self.assertNotEqual(r.returncode, 0)
                self.assertIn("must run as root", r.stderr)

    def test_status_is_readable_without_root(self):
        r = self.sb.run("status", as_root=False)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), "enabled")

    # ---- the write target is not a root-write primitive -------------------

    def test_refuses_to_write_through_a_symlink(self):
        victim = self.sb.base / "victim"
        victim.write_text("untouched\n")
        self.sb.target.unlink()
        self.sb.target.symlink_to(victim)
        r = self.sb.run("disable")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("symlink", r.stderr)
        self.assertEqual(victim.read_text(), "untouched\n")

    def test_refuses_a_missing_target(self):
        self.sb.target.unlink()
        r = self.sb.run("disable")
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(self.sb.target.exists())

    # ---- the write itself -------------------------------------------------

    def test_disable_then_enable_round_trips_and_preserves_other_lines(self):
        self.assertEqual(self.sb.run("disable").returncode, 0)
        text = self.sb.target.read_text()
        self.assertIn('DISABLE_APT_SNAPSHOT="yes"', text)
        self.assertIn("# keep me", text)
        self.assertIn("OTHER=keep", text)
        self.assertEqual(self.sb.run("status").stdout.strip(), "disabled")

        self.assertEqual(self.sb.run("enable").returncode, 0)
        text = self.sb.target.read_text()
        self.assertIn('DISABLE_APT_SNAPSHOT="no"', text)
        self.assertIn("# keep me", text)
        self.assertEqual(self.sb.run("status").stdout.strip(), "enabled")

    def test_appends_the_key_when_the_file_does_not_carry_it(self):
        self.sb.target.write_text("OTHER=keep\n")
        self.assertEqual(self.sb.run("disable").returncode, 0)
        text = self.sb.target.read_text()
        self.assertIn("OTHER=keep", text)
        self.assertEqual(text.count("DISABLE_APT_SNAPSHOT="), 1)

    def test_writes_exactly_one_key_however_often_it_runs(self):
        for _ in range(3):
            self.sb.run("disable")
            self.sb.run("enable")
        self.assertEqual(
            self.sb.target.read_text().count("DISABLE_APT_SNAPSHOT="), 1)

    # ---- the helper's own privileged tools are not PATH-resolved ----------

    def test_privileged_path_names_its_tools_absolutely(self):
        """Permanent invariant: a root helper must not resolve the binaries
        it runs as root through PATH."""
        text = HELPER.read_text()
        for tool in ("MKTEMP=/usr/bin/mktemp", "CHMOD=/usr/bin/chmod",
                     "MV=/usr/bin/mv"):
            self.assertIn(tool, text)
        # A stub `mv` earlier on PATH must not be reachable: prove it by
        # putting a hostile one there and checking the write still lands.
        hostile = self.sb.bin / "mv"
        hostile.write_text("#!/bin/sh\nexit 0\n")   # swallow the replace
        hostile.chmod(0o755)
        self.assertEqual(self.sb.run("disable").returncode, 0)
        self.assertIn('DISABLE_APT_SNAPSHOT="yes"', self.sb.target.read_text())


class AptSnapshotPolicyTests(unittest.TestCase):
    """The action must be pinned to this one executable."""

    def test_action_exists_and_pins_the_exec_path(self):
        text = POLICY.read_text()
        self.assertIn('<action id="org.shadowfetch.phoenix.apt-snapshot">', text)
        self.assertIn(
            '<annotate key="org.freedesktop.policykit.exec.path">'
            '/usr/libexec/phoenix-apt-snapshot</annotate>', text)

    def test_action_is_not_passwordless(self):
        text = POLICY.read_text()
        block = text.split('id="org.shadowfetch.phoenix.apt-snapshot"', 1)[1]
        block = block.split("</action>", 1)[0]
        self.assertIn("<allow_active>auth_admin_keep</allow_active>", block)
        self.assertNotIn("<allow_active>yes</allow_active>", block)


if __name__ == "__main__":
    unittest.main()
