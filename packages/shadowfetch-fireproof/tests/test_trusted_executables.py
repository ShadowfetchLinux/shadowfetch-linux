"""Adversarial: a substitutable program must never decide an update fact.

PERMANENT INVARIANT under test. Any executable used to establish, verify,
enforce or attest a security fact is invoked through an explicit trusted
ABSOLUTE path with a defined trust classification - and the child's PATH is
pinned too, because resolving the program is not enough when the program is
a shell script that resolves its own helpers.

Every test here is written as the ATTACK, not as the happy path: each one
plants a program an unprivileged user can write and asserts the update
system refuses it, rather than asserting that the real program works.

The two live incidents this rule was written from are both reproduced:

  * the forged clean scan - a substituted scanner reporting "nothing wrong"
    on a machine that is in fact broken. Here: a forged `dpkg` printing an
    empty --audit, which is exactly what a healthy machine prints, must not
    yield a passing verify battery.
  * the forged fact that steers a destructive action - here a forged
    `snapper` inventing a snapshot number, which `fireproof rollback` would
    hand to `pkexec /usr/libexec/phoenix-restore`.
"""
import os
import pathlib
import re
import tempfile
import unittest

from stubs import FIREPROOFD, load_fireproofd

fp = load_fireproofd()

from sfupdate import snapshots as sfsnap          # noqa: E402
from sfupdate.trusted import (                    # noqa: E402
    SAFE_PATH, SECURITY_CRITICAL, TRUSTED_PATHS, ExecutableError,
    ExecutableTrust, UpdateExecutor, classify)


def write_program(path, body):
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(0o755)
    return str(path)


class TestClassification(unittest.TestCase):
    """The classifier is phoenix's; these prove we did not weaken it."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def test_user_writable_program_is_untrusted(self):
        forged = self.dir / "snapper"
        write_program(forged, "echo forged\n")
        self.assertIs(classify(str(forged)), ExecutableTrust.UNTRUSTED)

    def test_relative_path_is_untrusted_without_touching_the_filesystem(self):
        self.assertIs(classify("snapper"), ExecutableTrust.UNTRUSTED)
        self.assertIs(classify("./snapper"), ExecutableTrust.UNTRUSTED)

    def test_missing_path_is_absent_not_untrusted(self):
        # The distinction carries weight downstream: absent optional tools
        # are a legitimate skip, substitutable ones are a finding.
        self.assertIs(classify(str(self.dir / "nope")), ExecutableTrust.ABSENT)

    def test_a_real_distro_binary_classifies_as_distro_managed(self):
        # Anchors the negative tests: if EVERY path classified UNTRUSTED the
        # refusals below would pass for the wrong reason.
        for candidate in ("/usr/bin/env", "/bin/sh", "/usr/bin/sh"):
            if os.path.exists(candidate):
                self.assertIs(classify(candidate),
                              ExecutableTrust.DISTRO_MANAGED, candidate)
                break
        else:
            self.skipTest("no distro binary to anchor against")


class TestExecutorRefusal(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        self.forged = self.dir / "snapper"
        write_program(self.forged, "echo attacker\n")
        self.executor = UpdateExecutor(
            paths={"snapper": (str(self.forged),),
                   "findmnt": (str(self.dir / "findmnt"),)})

    def test_resolve_refuses_and_says_why(self):
        with self.assertRaises(ExecutableError) as caught:
            self.executor.resolve("snapper")
        self.assertIn("untrusted", str(caught.exception))
        self.assertIn(str(self.forged), str(caught.exception))

    def test_available_reports_a_substitutable_program_as_unavailable(self):
        # "present but substitutable" must never open a code path that a
        # trusted absence would have closed.
        self.assertFalse(self.executor.available("snapper"))

    def test_run_never_executes_the_substituted_program(self):
        marker = self.dir / "executed"
        write_program(self.forged, "touch %s\n" % marker)
        with self.assertRaises(ExecutableError):
            self.executor.run("snapper", "list")
        self.assertFalse(marker.exists(), "the forged program was executed")

    def test_a_name_outside_the_table_cannot_be_run_at_all(self):
        with self.assertRaises(ExecutableError):
            self.executor.run("curl", "https://example.invalid")

    def test_every_candidate_path_in_the_table_is_absolute(self):
        for name, candidates in TRUSTED_PATHS.items():
            for candidate in candidates:
                self.assertTrue(os.path.isabs(candidate),
                                "%s: %s" % (name, candidate))

    def test_security_critical_names_are_all_in_the_table(self):
        self.assertTrue(SECURITY_CRITICAL)
        for name in SECURITY_CRITICAL:
            self.assertIn(name, TRUSTED_PATHS)


class TestChildPathIsPinned(unittest.TestCase):
    """Resolving the PROGRAM is not enough - pin the child's PATH too."""

    def test_child_does_not_inherit_the_callers_path(self):
        env_bin = next((p for p in ("/usr/bin/env", "/bin/env")
                        if os.path.exists(p)), None)
        if env_bin is None:
            self.skipTest("no env(1) to inspect the child environment")
        if classify(env_bin) is not ExecutableTrust.DISTRO_MANAGED:
            self.skipTest("%s is not distro-managed on this host" % env_bin)
        executor = UpdateExecutor(paths={"env": (env_bin,)})
        poisoned = "/tmp/attacker-owned:/home/nobody/bin"
        saved = os.environ.get("PATH")
        os.environ["PATH"] = poisoned
        try:
            rc, out, _err = executor.run("env")
        finally:
            if saved is None:
                os.environ.pop("PATH", None)
            else:
                os.environ["PATH"] = saved
        self.assertEqual(0, rc)
        child_path = next((line.split("=", 1)[1] for line in out.splitlines()
                           if line.startswith("PATH=")), None)
        self.assertEqual(SAFE_PATH, child_path)
        self.assertNotIn("attacker-owned", out)


class TestForgedSnapperCannotNameARollbackPoint(unittest.TestCase):
    """The forged fact that steers a destructive action.

    sfupdate.snapshots' number is handed to phoenix-restore. A snapper an
    unprivileged user can replace must yield "no Point", never a number.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        forged = self.dir / "snapper"
        write_program(forged, (
            "echo '# | Type | Date | Description'\n"
            "echo '99999,pre,2026-09-09,attacker'\n"))
        write_program(self.dir / "findmnt", "echo btrfs\n")
        self.executor = UpdateExecutor(paths={
            "snapper": (str(forged),),
            "findmnt": (str(self.dir / "findmnt"),)})

    def test_rows_are_empty_rather_than_attacker_supplied(self):
        self.assertEqual([], sfsnap.snapshot_rows(executor=self.executor))

    def test_no_rollback_target_is_invented(self):
        self.assertIsNone(sfsnap.first_pre_after(0, executor=self.executor))
        self.assertEqual(0, sfsnap.max_number(executor=self.executor))

    def test_phoenix_is_not_claimed_available_on_a_forged_findmnt(self):
        # A forged findmnt printing "btrfs" would otherwise make the product
        # promise a rollback that does not exist.
        self.assertFalse(sfsnap.phoenix_available(executor=self.executor))

    def test_relabel_is_refused_rather_than_reported_as_done(self):
        self.assertFalse(sfsnap.label_point(1, "x", "txn",
                                            executor=self.executor))

    def test_zero_is_never_a_rollback_target(self):
        # snapper 0 is the "current" pseudo-snapshot. Returning it would
        # "restore" the machine to itself while claiming a rollback.
        rows = [sfsnap.Snapshot(0, "pre", "", "current")]
        self.assertIsNone(sfsnap.first_pre_after(0, rows=rows))


class TestForgedScannerCannotForgeACleanVerify(unittest.TestCase):
    """The forged clean scan, one layer down from the gitleaks incident.

    An empty `dpkg --audit` is EXACTLY what a healthy machine prints. If the
    daemon accepted a substitutable dpkg, an attacker (or a broken machine
    with a hijacked path) would get "Package database consistent: pass" and
    the user would never be told to restore.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        # Every forgery below prints what a HEALTHY machine prints.
        write_program(self.dir / "dpkg", "exit 0\n")
        write_program(self.dir / "apt-get",
                      "echo '0 upgraded, 0 newly installed, 0 to remove'\n")
        write_program(self.dir / "systemctl", "exit 0\n")
        write_program(self.dir / "ip", "echo 'default via 10.0.0.1'\n")
        forged_paths = {name: (str(self.dir / name),)
                        for name in ("dpkg", "apt-get", "systemctl", "ip",
                                     "getent", "ldd", "dkms", "needrestart",
                                     "snapper", "findmnt", "apt-listchanges")}
        self.executor = UpdateExecutor(paths=forged_paths)
        self._saved = fp.EXECUTOR
        fp.EXECUTOR = self.executor
        self.addCleanup(lambda: setattr(fp, "EXECUTOR", self._saved))

    def _by_id(self, verify, check_id):
        return next(c for c in verify["checks"] if c["id"] == check_id)

    def test_verify_refuses_rather_than_passing(self):
        verify = fp.run_verify({})
        audit = self._by_id(verify, "dpkg-audit")
        self.assertEqual("fail", audit["status"])
        self.assertIn("not established", audit["detail"])
        self.assertIn("untrusted", audit["detail"])
        consistency = self._by_id(verify, "apt-consistency")
        self.assertEqual("fail", consistency["status"])
        # A refusal must LEAD WITH RESTORE, not degrade to a warning.
        self.assertEqual("restore-recommended", verify["verdict"])

    def test_no_check_reports_pass_on_a_forged_toolchain(self):
        verify = fp.run_verify({})
        passed = [c["id"] for c in verify["checks"] if c["status"] == "pass"]
        self.assertEqual([], passed, "forged tools produced passing checks")

    def test_failed_units_is_unknown_not_empty(self):
        # [] means "nothing is failing". A substitutable systemctl must not
        # be able to say that.
        self.assertIsNone(fp.failed_units())
        units = self._by_id(fp.run_verify({}), "failed-units")
        self.assertEqual("fail", units["status"])
        self.assertIn("not established", units["detail"])

    def test_substitutable_is_distinguished_from_absent(self):
        self.assertTrue(fp.is_substitutable("dpkg"))
        self.assertFalse(fp.is_substitutable("getent"))   # nothing installed
        self.assertFalse(fp.EXECUTOR.available("dpkg"))


class TestDaemonHasNoPathLookupsLeft(unittest.TestCase):
    """Static sweep: the invariant is a property of the file, not a habit."""

    def setUp(self):
        with open(FIREPROOFD) as handle:
            self.source = handle.read()

    def test_no_shutil_which_anywhere_in_the_daemon(self):
        self.assertNotIn("shutil.which", self.source)
        self.assertNotIn("import shutil", self.source)

    def test_no_direct_subprocess_use_in_the_daemon(self):
        # All child processes go through sfupdate.trusted, which is the only
        # place that may call subprocess.
        self.assertNotIn("subprocess.run", self.source)
        self.assertNotIn("os.system", self.source)
        self.assertNotIn("import subprocess", self.source)

    def test_every_run_call_names_a_program_in_the_trusted_table(self):
        names = set(re.findall(r'run\(\["([a-z0-9.+-]+)"', self.source))
        self.assertTrue(names, "no run() call sites found - test is blind")
        for name in names:
            self.assertIn(name, TRUSTED_PATHS, name)


if __name__ == "__main__":
    unittest.main()
