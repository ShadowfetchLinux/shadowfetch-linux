"""Stage U: exactly ONE system decides snapshot/update behaviour.

THE RULE: do not leave two systems independently deciding snapshot/update
behaviour. That is how a rollback and an update come to disagree about what
state the machine is in.

Before Stage U the tree shipped two updaters. `shadowfetch-update` (342
lines of bash) ran its own `apt-get update`, its own `apt-get -s
full-upgrade`, its own sha256 plan fingerprint and its own `apt-get
full-upgrade` under sudo; then it RELABELLED the same snapper Point that
Fireproof labels - different description, no `fireproof=pre` userdata - and
recorded it NOWHERE. /var/lib/shadowfetch/fireproof-state.json therefore
still described the previous Fireproof transaction, so the next `fireproof
rollback` would have restored the wrong system.

These tests are the regression fence around that. They are written against
the shipped source rather than against behaviour on this build host,
because the property is "the tree contains one implementation", and that is
a property of the files.
"""
import os
import pathlib
import re
import subprocess
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
FIREPROOF_PKG = HERE.parent
PACKAGES = FIREPROOF_PKG.parent
DEFAULTS = PACKAGES / "shadowfetch-defaults"

SHIM = DEFAULTS / "data/usr/bin/shadowfetch-update"
DAEMON = FIREPROOF_PKG / "data/usr/libexec/fireproofd"
CLI = FIREPROOF_PKG / "data/usr/bin/fireproof"
SFUPDATE = FIREPROOF_PKG / "data/usr/lib/shadowfetch/sfupdate"

#: Directories that are stale build copies, vendored trees or test code
#: rather than shipped payload. Scanning them would measure the wrong tree.
SKIP_PARTS = ("debian", "live-build", "work", "build", "vendor", "repo",
              ".git", "__pycache__", "chroot", "tests")

_DQ = '"' * 3
_SQ = "'" * 3
_TRIPLE = re.compile(_DQ + r"[\s\S]*?" + _DQ + "|" + _SQ + r"[\s\S]*?" + _SQ)
_HEREDOC = re.compile(r"<<'?([A-Z][A-Z0-9_]*)'?\n[\s\S]*?\n\1\n")


def code_only(text):
    """Strip prose so a test measures behaviour, not the comment about it.

    These files DOCUMENT the mechanism they replaced - the shim's header
    names apt-get and snapper precisely in order to say it no longer runs
    them - so a naive substring scan would fail on the explanation and
    tempt somebody to delete the explanation instead of the mechanism.
    """
    text = _TRIPLE.sub("", text)
    text = _HEREDOC.sub("", text)
    return "\n".join(line for line in text.splitlines()
                     if not line.lstrip().startswith("#"))


def product_files():
    """Every shipped payload file under packages/, build copies excluded."""
    for path in PACKAGES.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_PARTS for part in path.parts):
            continue
        yield path


#: OPEN FINDINGS, outside Stage U's file territory, recorded here rather
#: than hidden by a narrower test. Both parse snapper's machine-readable
#: list with their own code, so the tree still contains three snapper
#: readers even though only ONE of them - sfupdate.snapshots - may name a
#: rollback target:
#:
#:   welcome/.../shadowfetch-bundle-install  derives Phoenix Point numbers
#:       around its own apt transaction, exactly the shape Stage U deleted
#:       from shadowfetch-update. It should call sfupdate.snapshots.
#:   fireline/.../mcp/sf_mcp.py  lists restore points read-only for display
#:       and never names a target; lower severity, but it resolves snapper
#:       with shutil.which() (against a constrained PATH) rather than a
#:       trusted absolute path.
#:
#: The set is pinned: a THIRD reader fails this suite, and fixing either of
#: these forces the note above to be updated rather than quietly rotting.
KNOWN_OTHER_SNAPPER_READERS = {
    "shadowfetch-welcome/data/usr/libexec/shadowfetch-bundle-install",
    "shadowfetch-fireline/data/usr/lib/shadowfetch/mcp/sf_mcp.py",
}


def product_code():
    """(path, code) for every payload file that can be read as text."""
    for path in product_files():
        try:
            yield path, code_only(path.read_text())
        except (UnicodeDecodeError, OSError):
            continue


class TestOnlyOneUpdater(unittest.TestCase):
    def test_the_shim_contains_no_update_mechanism_of_its_own(self):
        body = code_only(SHIM.read_text())
        # Each of these was a real line in the old duplicate updater.
        for forbidden in ("apt-get", "apt-config", "dpkg-query", "dpkg --",
                          "snapper", "flatpak", "sudo ", "flock",
                          "sha256sum", "findmnt", "full-upgrade"):
            self.assertNotIn(forbidden, body,
                             "%s builds its own update mechanism: %s"
                             % (SHIM.name, forbidden))

    def test_the_shim_execs_fireproof_by_absolute_path(self):
        source = SHIM.read_text()
        code = code_only(source)
        self.assertIn("FIREPROOF=/usr/bin/fireproof", code)
        self.assertIn('exec "$FIREPROOF" "$verb"', code)
        # One exec, and no program lookup of any kind: $PATH belongs to the
        # caller, and this program chooses which binary performs a root
        # package transaction.
        self.assertEqual(1, len(re.findall(r"(?m)^\s*exec\s", code)))
        self.assertNotRegex(code, r"\bcommand -v\b")
        self.assertNotRegex(code, r"(?m)(^|[;|&(`$]\s*)which\b")
        self.assertNotIn("type -P", code)

    def test_the_shim_maps_every_legacy_form_onto_one_vocabulary(self):
        source = SHIM.read_text()
        for option, verb in (("--check", "check"), ("--verify", "verify"),
                             ("--rollback", "rollback")):
            self.assertRegex(source, re.escape(option) + r"\)\s*verb=" + verb)
        self.assertRegex(source, r'""\)\s*verb=update')

    def test_the_shim_is_short_enough_to_read_in_one_sitting(self):
        # The old file was 342 lines. A "thin compatibility surface" that
        # grows back past ~150 lines is growing a mechanism again.
        self.assertLess(len(SHIM.read_text().splitlines()), 150)

    def test_no_other_program_in_the_tree_commits_packages(self):
        offenders = []
        for path, text in product_code():
            if path == DAEMON:
                continue
            if path == SFUPDATE / "vocabulary.py":
                # The contract DESCRIBES each step's mechanism by name -
                # that is its whole job. It executes nothing.
                continue
            if re.search(r"apt-get[^\n]*\b(full-upgrade|dist-upgrade)\b", text):
                offenders.append(str(path.relative_to(PACKAGES)))
            if "cache.commit(" in text:
                offenders.append(str(path.relative_to(PACKAGES)))
        self.assertEqual([], sorted(set(offenders)),
                         "a second program installs packages")


class TestOnlyOneSnapshotAuthority(unittest.TestCase):
    def test_the_update_path_parses_snapper_in_exactly_one_place(self):
        readers = {str(path.relative_to(PACKAGES))
                   for path, text in product_code()
                   if path != SFUPDATE / "snapshots.py"
                   and "machine-readable" in text and "snapper" in text}
        # Not "no other readers" - that would be false today, and a test
        # must not assert something the tree does not do. The claim is the
        # narrower true one: no NEW reader, and none inside the update path.
        self.assertEqual(KNOWN_OTHER_SNAPPER_READERS, readers,
                         "the set of snapper readers changed")
        for path in readers:
            self.assertFalse(
                path.startswith("shadowfetch-fireproof/")
                or path.endswith("shadowfetch-update"),
                "the update path grew a second snapper reader: %s" % path)

    def test_only_sfupdate_relabels_a_point(self):
        offenders = [str(path.relative_to(PACKAGES))
                     for path, text in product_code()
                     if path != SFUPDATE / "snapshots.py"
                     and re.search(r"snapper[^\n]*\bmodify\b", text)]
        self.assertEqual([], sorted(set(offenders)))

    def test_the_daemon_delegates_instead_of_reimplementing(self):
        source = DAEMON.read_text()
        self.assertIn("sfsnap.max_number()", source)
        self.assertIn("sfsnap.first_pre_after(n)", source)
        self.assertIn("sfsnap.phoenix_available()", source)
        self.assertIn("sfsnap.label_point(", source)
        # The bodies must be gone, not shadowed by a delegating wrapper.
        self.assertNotIn("def snapper_list(", source)
        self.assertNotIn('"--machine-readable"', source)


class TestOnlyOneStateStore(unittest.TestCase):
    def test_only_sfupdate_state_writes_the_update_record(self):
        offenders = [
            str(path.relative_to(PACKAGES))
            for path, text in product_code()
            if path != SFUPDATE / "state.py"
            and re.search(r"(atomic_write|open)\([^\n]*fireproof-(state|pending)",
                          text)]
        self.assertEqual([], sorted(set(offenders)),
                         "a second program writes the update record")

    def test_the_rollback_target_comes_from_the_record_only(self):
        source = DAEMON.read_text()
        self.assertIn("sfstate.rollback_target(", source)
        self.assertIn("sfstate.write_pending(", source)
        self.assertIn("sfstate.record_failed_set(", source)


class TestNoConflictingAutomaticUpdates(unittest.TestCase):
    def test_apt_periodic_is_declared_in_exactly_one_file(self):
        declaring = sorted(str(path.relative_to(PACKAGES))
                           for path, text in product_code()
                           if "apt.conf.d" in str(path)
                           and "APT::Periodic" in text)
        self.assertEqual(
            ["shadowfetch-fireproof/data/etc/apt/apt.conf.d/85fireproof"],
            declaring,
            "two files decide whether this machine updates itself")

    def test_unattended_upgrades_stays_off(self):
        conf = (FIREPROOF_PKG
                / "data/etc/apt/apt.conf.d/85fireproof").read_text()
        self.assertIn('APT::Periodic::Unattended-Upgrade "0";', conf)
        self.assertIn('APT::Periodic::Download-Upgradeable-Packages "0";', conf)
        # Lists may refresh: the badge has to be honest without any daemon
        # of ours touching the network.
        self.assertIn('APT::Periodic::Update-Package-Lists "1";', conf)

    def test_the_deleted_conffile_is_removed_on_upgrade(self):
        # Deleting the file from the source tree is not enough: it is a
        # conffile, so an already-installed machine KEEPS it - still
        # enabling unattended-upgrades - unless dpkg is told to remove it.
        self.assertFalse(
            (DEFAULTS / "data/etc/apt/apt.conf.d/"
             "52shadowfetch-unattended.conf").exists())
        maintscript = (DEFAULTS
                       / "debian/shadowfetch-defaults.maintscript").read_text()
        self.assertIn(
            "rm_conffile /etc/apt/apt.conf.d/52shadowfetch-unattended.conf",
            maintscript)
        install = (DEFAULTS
                   / "debian/shadowfetch-defaults.install").read_text()
        self.assertNotIn("52shadowfetch-unattended.conf", install)


class TestSharedModuleIsShipped(unittest.TestCase):
    def test_every_sfupdate_module_is_in_the_package_manifest(self):
        install = (FIREPROOF_PKG
                   / "debian/shadowfetch-fireproof.install").read_text()
        self.assertIn("data/usr/lib/shadowfetch/sfupdate/*.py", install)
        self.assertIn("usr/lib/shadowfetch/sfupdate/", install)
        shipped = {path.name for path in SFUPDATE.glob("*.py")}
        self.assertEqual(
            {"__init__.py", "trusted.py", "snapshots.py", "state.py",
             "vocabulary.py"}, shipped)

    def test_the_daemon_finds_it_without_pythonpath(self):
        source = DAEMON.read_text()
        self.assertIn('_LIB = Path(__file__).resolve().parent.parent '
                      '/ "lib" / "shadowfetch"', source)
        self.assertIn("sys.path.insert(0, str(_LIB))", source)
        # The search path is derived from the daemon's own location, never
        # read from an environment the caller controls.
        self.assertNotRegex(code_only(source), r"environ[^\n]*PYTHONPATH")

    def test_phoenix_is_a_declared_dependency_because_we_import_it(self):
        control = (FIREPROOF_PKG / "debian/control").read_text()
        self.assertRegex(control, r"(?m)^ shadowfetch-phoenix$")


class TestShimBehaviour(unittest.TestCase):
    """Run the shim with a booby-trapped PATH: it must touch none of it."""

    def _trapped_path(self, directory):
        marker = directory / "ran"
        for name in ("apt", "apt-get", "dpkg", "dpkg-query", "snapper",
                     "sudo", "flatpak", "curl", "flock", "fuser", "df",
                     "upower", "sha256sum", "findmnt", "fireproof"):
            program = directory / name
            program.write_text("#!/bin/sh\necho %s >> %s\n" % (name, marker))
            program.chmod(0o755)
        return marker

    def _run(self, args, directory):
        env = dict(os.environ)
        env["PATH"] = "%s:/usr/bin:/bin" % directory
        return subprocess.run([str(SHIM), *args], env=env, timeout=20,
                              capture_output=True, text=True)

    def test_help_and_version_execute_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = pathlib.Path(tmp)
            marker = self._trapped_path(directory)
            for args in (["--help"], ["--version"]):
                result = self._run(args, directory)
                self.assertEqual(0, result.returncode, result.stderr)
            self.assertFalse(marker.exists(),
                             marker.read_text() if marker.exists() else "")

    def test_unknown_and_extra_arguments_are_refused_not_guessed(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = pathlib.Path(tmp)
            marker = self._trapped_path(directory)
            for args in (["--yolo"], ["--check", "--verify"]):
                result = self._run(args, directory)
                self.assertEqual(2, result.returncode, result.stdout)
            self.assertFalse(marker.exists())

    def test_a_fireproof_on_PATH_is_never_used(self):
        """The trap that matters: $PATH belongs to the caller.

        A `fireproof` planted earlier on PATH must not become the binary
        that performs a root package transaction.
        """
        if os.path.exists("/usr/bin/fireproof"):
            self.skipTest("fireproof is installed here; this asserts the "
                          "absent case, where a PATH hit would be visible")
        with tempfile.TemporaryDirectory() as tmp:
            directory = pathlib.Path(tmp)
            marker = self._trapped_path(directory)
            for args in ([], ["--check"], ["--verify"], ["--rollback"]):
                result = self._run(args, directory)
                self.assertEqual(1, result.returncode)
                self.assertIn("/usr/bin/fireproof is not installed",
                              result.stderr)
            self.assertFalse(marker.exists(),
                             "the shim ran a program found on PATH")

    def test_the_help_names_the_five_steps(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = pathlib.Path(tmp)
            self._trapped_path(directory)
            out = self._run(["--help"], directory).stdout
        for step in ("simulate", "approve", "commit", "verify", "rollback"):
            self.assertIn(step, out)
        self.assertNotIn("Safe Update", out)


class TestCliAndShimAgree(unittest.TestCase):
    def test_the_cli_offers_exactly_the_verbs_the_shim_dispatches(self):
        cli = CLI.read_text()
        for verb in ("check", "update", "verify", "rollback"):
            self.assertRegex(cli, r'cmd == "%s"' % verb)
        shim_verbs = set(re.findall(r"verb=([a-z]+)", SHIM.read_text()))
        self.assertEqual({"update", "check", "verify", "rollback"}, shim_verbs)


if __name__ == "__main__":
    unittest.main()
