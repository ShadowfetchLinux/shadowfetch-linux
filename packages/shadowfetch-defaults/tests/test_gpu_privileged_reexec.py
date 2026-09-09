"""Stage V: shadowfetch-gpu must never re-execute a PATH-resolved or
caller-writable program as root.

The defect this covers: `as_root "$0" --apply "$hybrid"` where as_root ran
`pkexec "$@"`.  argv[0] is what the shell was told, not where the script is --
invoked through PATH it is the bare word "shadowfetch-gpu", so the program
handed to the privileged runner was re-resolved through PATH *by that runner*,
and what it re-enters is the driver installer.  A PATH-resolved program that
then runs as root is a root escalation.

The two guard functions are extracted from the shipped script and exercised
directly, rather than being reimplemented here: the assertion on the extraction
means a rewrite that removes or renames them fails this file loudly instead of
testing nothing.
"""

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
GPU = ROOT / "packages/shadowfetch-defaults/data/usr/bin/shadowfetch-gpu"


def extract(name):
    """The body of one shell function, from the shipped script."""
    text = GPU.read_text()
    match = re.search(r"^%s\(\) \{\n(.*?)^\}\n" % re.escape(name),
                      text, re.MULTILINE | re.DOTALL)
    assert match, "shadowfetch-gpu no longer defines %s(); this test would " \
                  "silently stop covering the privileged re-exec" % name
    return "%s() {\n%s}\n" % (name, match.group(1))


PRELUDE = "\n".join((
    "PKEXEC=/usr/bin/pkexec",
    "SUDO=/usr/bin/sudo",
    "STAT=/usr/bin/stat",
    "INSTALLED_SELF=/usr/bin/shadowfetch-gpu",
    'warn() { printf "!! %s\\n" "$*" >&2; }',
))


def code(path=GPU):
    """The script with whole-line comments removed.

    House style is to name the defect a change removed, and this script's
    as_root() comment quotes `command -v pkexec` for exactly that reason.  A
    contract test that cannot tell code from prose would push the next author
    into deleting the explanation.
    """
    return "\n".join(line for line in path.read_text().splitlines()
                      if not line.strip().startswith("#"))


def run_shell(script):
    return subprocess.run(["bash", "-c", script], capture_output=True,
                          text=True, check=False)


class RootSafeProgramTests(unittest.TestCase):
    """Nothing group- or other-writable, and nothing the caller owns, may be
    handed to pkexec or sudo: whoever can write it chooses what runs as root."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="gpu-guard.")
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.guard = PRELUDE + "\n" + extract("root_safe_program")

    def verdict(self, target):
        r = run_shell('%s\nif root_safe_program %s; then echo ACCEPT; '
                      'else echo REFUSE; fi' % (self.guard, target))
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout.strip()

    def test_refuses_a_file_the_calling_user_owns(self):
        mine = self.tmp / "mine"
        mine.write_text("#!/bin/sh\nid\n")
        mine.chmod(0o755)
        self.assertEqual(self.verdict(str(mine)), "REFUSE")

    def test_refuses_a_missing_file(self):
        self.assertEqual(self.verdict(str(self.tmp / "nope")), "REFUSE")

    def test_refuses_a_directory(self):
        self.assertEqual(self.verdict(str(self.tmp)), "REFUSE")

    def test_accepts_a_root_owned_program_with_no_group_or_other_write_bit(self):
        # /usr/bin/id is root-owned 0755 on every supported host; skip rather
        # than pass vacuously if that is not true here.
        probe = "/usr/bin/id"
        st = os.stat(probe)
        if st.st_uid != 0 or st.st_mode & 0o022:
            self.skipTest("%s is not root-owned 0755 on this host" % probe)
        self.assertEqual(self.verdict(probe), "ACCEPT")


class SelfPathTests(unittest.TestCase):
    """The program re-executed as root must be an absolute path."""

    def setUp(self):
        self.guard = PRELUDE + "\n" + extract("self_path")

    def resolve(self, argv0, cwd=None):
        # bash -c '<guard>; self_path' NAME sets $0 to NAME.
        r = subprocess.run(["bash", "-c", self.guard + "\nself_path", argv0],
                           capture_output=True, text=True, cwd=cwd, check=False)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout.strip()

    def test_a_bare_name_off_path_becomes_the_installed_path(self):
        self.assertEqual(self.resolve("shadowfetch-gpu"),
                         "/usr/bin/shadowfetch-gpu")

    def test_a_relative_path_is_made_absolute(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(self.resolve("./shadowfetch-gpu", cwd=d),
                             "%s/./shadowfetch-gpu" % d)

    def test_an_absolute_path_is_kept(self):
        self.assertEqual(self.resolve("/opt/x/shadowfetch-gpu"),
                         "/opt/x/shadowfetch-gpu")

    def test_every_resolution_is_absolute(self):
        for argv0 in ("shadowfetch-gpu", "./shadowfetch-gpu",
                      "../bin/shadowfetch-gpu", "/usr/bin/shadowfetch-gpu"):
            with self.subTest(argv0=argv0):
                self.assertTrue(self.resolve(argv0).startswith("/"))


class ScriptContractTests(unittest.TestCase):

    def test_the_privileged_reexec_does_not_use_argv_zero(self):
        text = code()
        self.assertNotIn('as_root "$0"', text,
                         'the privileged re-exec must not pass $0: invoked '
                         'through PATH it is a bare name, which the '
                         'privileged runner then resolves through PATH')
        self.assertIn('as_root "$(self_path)" --apply "$hybrid"', text)

    def test_the_escalators_are_named_absolutely(self):
        text = code()
        self.assertIn("PKEXEC=/usr/bin/pkexec", text)
        self.assertIn("SUDO=/usr/bin/sudo", text)
        self.assertNotIn("command -v pkexec", text)
        self.assertNotIn("command -v sudo", text)

    def test_the_ownership_check_does_not_resolve_stat_through_path(self):
        """The check decides a security question, so its binary is pinned."""
        text = code()
        self.assertIn("STAT=/usr/bin/stat", text)
        self.assertNotIn("$(stat ", text)

    def test_as_root_refuses_rather_than_falling_back(self):
        """No escalator available must mean 'no', never 'run it anyway'."""
        # The overrides come AFTER the prelude, or the prelude would put the
        # real escalators back -- and this test would run pkexec for real.
        guard = PRELUDE + "\n" + extract("root_safe_program") + extract("as_root")
        r = run_shell(
            '%s\nPKEXEC=/nonexistent\nSUDO=/nonexistent\n'
            'if as_root /usr/bin/id; then echo RAN; else echo REFUSED; fi'
            % guard)
        self.assertNotIn("uid=", r.stdout,
                         "as_root ran the target with no escalator available")
        self.assertIn("REFUSED", r.stdout)

    def test_as_root_refuses_a_caller_writable_target_before_escalating(self):
        guard = PRELUDE + "\n" + extract("root_safe_program") + extract("as_root")
        with tempfile.TemporaryDirectory() as d:
            mine = Path(d) / "mine"
            mine.write_text("#!/bin/sh\necho PWNED\n")
            mine.chmod(0o755)
            r = run_shell(
                '%s\nPKEXEC=/bin/sh\nSUDO=/bin/sh\n'
                'if as_root %s; then echo RAN; else echo REFUSED; fi'
                % (guard, mine))
        self.assertNotIn("PWNED", r.stdout)
        self.assertIn("REFUSED", r.stdout)


if __name__ == "__main__":
    unittest.main()
