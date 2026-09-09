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

Stage U's remainder found the same shape still live in a second place.
`shadowfetch-bundle-install` is not merely a third snapper reader: it is a
SECOND PROGRAM THAT COMMITS PACKAGES AS ROOT, it derived a Phoenix Point with
its own CSV parser, and it offered that number to the user as
`pkexec /usr/libexec/phoenix-restore <n>` while recording it nowhere.
Measured on the shipped code before the fix, with a previous Fireproof update
recorded at Point 41: the bundle install printed `SF-POINT 43` and
fireproof-state.json was byte-for-byte unchanged, so Fireproof1.RollbackTarget
still answered `pkexec /usr/libexec/phoenix-restore 41`. Two programs, two
different answers to "what does the one rollback button restore", differing by
two Points. It never relabelled - that is the one third of the original defect
it did not have.

It genuinely cannot delegate the transaction: it installs a NAMED CATALOG
BUNDLE and fireproofd's only verb is the full upgrade of everything
upgradable. So it stopped DECIDING instead: the Point now comes from
sfupdate.snapshots, the transaction is recorded through sfupdate.state before
the Point is offered to anybody, and a Point that cannot be recorded is not
named. TestBundleInstallIsNotASecondDecider holds all of that.

These tests are the regression fence around that. Most are written against the
shipped source rather than against behaviour on this build host, because the
property is "the tree contains one implementation", and that is a property of
the files. The bundle-install measurements are the exception: they run the
shipped program and read back the record and the rollback target, because
"the record moved" is a property of a run.
"""
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
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


#: The snapper readers outside sfupdate.snapshots. ONE is left, and it is a
#: reader rather than a decider:
#:
#:   fireline/.../mcp/sf_mcp.py  prints `snapper list` output verbatim for an
#:       agent to read. It never derives a number and never names a rollback
#:       target - the number that reaches phoenix-restore comes from
#:       Fireproof1.RollbackTarget - so there is no derived value here that
#:       could disagree with the authority's. It no longer resolves snapper
#:       through PATH: it names the same absolute candidate paths
#:       sfupdate.trusted names, refuses anything that is not a root-owned
#:       regular file, and pins its child's PATH. What remains, and is why it
#:       is still on this list, is that it reads snapper's machine-readable
#:       output with its own eyes instead of sfupdate.snapshots'.
#:
#: welcome/.../shadowfetch-bundle-install LEFT this set. It was the worse of
#: the two: a second program committing packages as root, deriving a Point
#: with its own parser and offering it as
#: `pkexec /usr/libexec/phoenix-restore <n>` while fireproof-state.json still
#: described the PREVIOUS transaction (measured: SF-POINT 43 against
#: RollbackTarget 41). It now has no snapper parser and no snapper
#: invocation at all; TestBundleInstallIsNotASecondDecider is its fence.
#:
#: The set is pinned: any NEW reader fails this suite, and removing the last
#: one forces this note to be rewritten rather than quietly rotting.
KNOWN_OTHER_SNAPPER_READERS = {
    "shadowfetch-fireline/data/usr/lib/shadowfetch/mcp/sf_mcp.py",
}

#: Every shipped file that names apt-get at all, pinned so a TWELFTH cannot
#: appear unnoticed.
#:
#: Stage U's `test_no_other_program_in_the_tree_commits_packages` looked only
#: for `full-upgrade`/`dist-upgrade`/`cache.commit(`, so its name claimed more
#: than it measured: shadowfetch-bundle-install ran `apt-get -y install` as
#: root the whole time and never tripped it. The predicate here is deliberately
#: the bluntest one that cannot be evaded by re-quoting - a bare word match on
#: the code with prose stripped - because the first attempt at this test used a
#: quote-anchored regex and silently missed every shell script in the tree.
#:
#: Four root package-changers besides the two intended ones fell out of it, and
#: they are recorded here rather than hidden by narrowing the regex until they
#: disappear:
#:
#:   fireproof/.../fireproofd            THE update authority.
#:   welcome/.../shadowfetch-bundle-install  the one other program that has to
#:       commit: fireproofd's only verb is the full upgrade of everything
#:       upgradable, and this installs a named catalog bundle. Routed through
#:       sfupdate.snapshots and sfupdate.state - see
#:       TestBundleInstallIsNotASecondDecider.
#:   defaults/.../shadowfetch-gpu        OPEN FINDING, the largest one left:
#:       `apt-get --no-remove install -y` of the NVIDIA driver stack as root,
#:       around a snapper pre/post pair it mints itself. See
#:       KNOWN_POINT_MINTERS below.
#:   defaults/.../shadowfetch-grok-bot   OPEN FINDING: installs a downloaded
#:       .deb with /usr/bin/apt-get install as root. The path is absolute, but
#:       it changes the installed package set and writes nothing to the update
#:       record, so a rollback after it restores a Point that predates it.
#:   defaults/.../shadowfetch-hardware   OPEN FINDING, and the sharpest:
#:       subprocess.call(["sudo", "apt-get", "install", "-y"] + need). BOTH
#:       names resolve through the invoking user's PATH, so PATH chooses which
#:       binary performs a root package transaction AND which binary receives
#:       the password.
#:   defaults/.../shadowfetch-migrate-2.1.3-ai  OPEN FINDING: simulates with
#:       `apt-get -s ... remove` and compares the plan against a sha256-checked
#:       manifest - a careful design - and then REMOVES those packages for real
#:       with a second, bare-name `apt-get`. Nothing is written to the update
#:       record.
#:   phoenix/.../phoenix-apt-repair      `apt-get update` only: it refreshes
#:       lists and changes no packages. PATH is pinned at the top of the script.
#:   control-center/.../sfcc/phoenix_page.py  a sentence shown to a person.
#:   fireproof/.../sfupdate/trusted.py   the table of absolute paths.
#:   fireproof/.../sfupdate/vocabulary.py  the contract that DESCRIBES each
#:       step's mechanism by name. Executes nothing; that is its whole job.
#:   welcome/.../welcome/catalog/README  documentation shipped as payload.
KNOWN_APT_GET_CALLERS = {
    "shadowfetch-control-center/data/usr/share/shadowfetch/control-center/"
    "sfcc/phoenix_page.py",
    "shadowfetch-defaults/data/usr/bin/shadowfetch-gpu",
    "shadowfetch-defaults/data/usr/bin/shadowfetch-grok-bot",
    "shadowfetch-defaults/data/usr/bin/shadowfetch-hardware",
    "shadowfetch-defaults/data/usr/libexec/shadowfetch-migrate-2.1.3-ai",
    "shadowfetch-fireproof/data/usr/lib/shadowfetch/sfupdate/trusted.py",
    "shadowfetch-fireproof/data/usr/lib/shadowfetch/sfupdate/vocabulary.py",
    "shadowfetch-fireproof/data/usr/libexec/fireproofd",
    "shadowfetch-phoenix/usr/libexec/phoenix-apt-repair",
    "shadowfetch-welcome/data/usr/libexec/shadowfetch-bundle-install",
    "shadowfetch-welcome/data/usr/share/shadowfetch/welcome/catalog/README",
}

#: Every shipped file that MINTS a Phoenix Point (`snapper ... create`).
#:
#: This set exists because KNOWN_OTHER_SNAPPER_READERS above is pinned against
#: a `--machine-readable` PARSE, and a program that mints a Point instead of
#: parsing one evades that predicate completely. One already had, for the whole
#: of Stage U:
#:
#:   phoenix/.../phoenix-firstboot   mints the "Fresh install" baseline Point
#:       once, at first boot, in the package that OWNS Phoenix Points. There is
#:       no transaction to record and it names no rollback target.
#:   defaults/.../shadowfetch-gpu    OPEN FINDING: mints a pre/post pair around
#:       a root NVIDIA driver install with `snapper -c root create --type pre
#:       --print-number`, tells the user "Phoenix Point N is available for
#:       recovery", resolves snapper with `command -v` - a PATH lookup deciding
#:       a Point number - and writes nothing to fireproof-state.json. It is
#:       shadowfetch-bundle-install's defect exactly, in a program Stage U's
#:       detector could not see.
KNOWN_POINT_MINTERS = {
    "shadowfetch-defaults/data/usr/bin/shadowfetch-gpu",
    "shadowfetch-phoenix/usr/libexec/phoenix-firstboot",
}

BUNDLE_INSTALL = (PACKAGES / "shadowfetch-welcome/data/usr/libexec"
                  / "shadowfetch-bundle-install")
SFUPDATE_LIB = FIREPROOF_PKG / "data/usr/lib/shadowfetch"
PHOENIX_LIB = PACKAGES / "shadowfetch-phoenix/usr/lib/shadowfetch"


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

    def test_every_program_that_names_apt_get_is_written_down(self):
        """The set of files that can reach apt-get at all, pinned.

        The test above measures `full-upgrade`/`dist-upgrade`/`cache.commit(`
        and nothing else, which is why shadowfetch-bundle-install - running
        `apt-get -y install` as root since 4.0.0 - passed it every time. This
        one is deliberately blunt: it names every shipped file that mentions
        apt-get at all, so a new one has to be classified in the note above
        before this suite goes green again. Two open findings are recorded
        there rather than hidden by narrowing the regex until they vanish.
        """
        callers = {str(path.relative_to(PACKAGES))
                   for path, text in product_code()
                   if re.search(r"\bapt-get\b", text)
                   or "cache.commit(" in text}
        self.assertEqual(KNOWN_APT_GET_CALLERS, callers,
                         "the set of programs that can reach apt-get changed")

    def test_every_program_that_mints_a_phoenix_point_is_written_down(self):
        """A `snapper create` mints a Point number; who may do that is pinned.

        KNOWN_OTHER_SNAPPER_READERS is pinned against a `--machine-readable`
        parse, and that is how shadowfetch-gpu stayed invisible through all of
        Stage U: it never parses snapper, it MINTS a pre/post pair around a
        root driver install and prints the number as a recovery Point. A
        detector that only sees parsers cannot see the deciders that matter
        most, so this one watches the mint.
        """
        minters = {str(path.relative_to(PACKAGES))
                   for path, text in product_code()
                   if re.search(r"snapper[^\n]*\bcreate\b(?!-)", text)}
        self.assertEqual(KNOWN_POINT_MINTERS, minters,
                         "a new program creates Phoenix Points")
        # Whatever mints one, sfupdate.snapshots stays the only thing that may
        # RELABEL one - see test_only_sfupdate_relabels_a_point.
        self.assertNotIn(str(SFUPDATE.relative_to(PACKAGES)) + "/snapshots.py",
                         minters)


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


#: The measurement harness. It loads the SHIPPED program, points its state
#: and catalog directories at a scratch tree, and supplies the snapper ROWS
#: the one authority would have read - sfupdate.snapshots still owns the parse
#: and the "first pre above the baseline" rule, so the Point below is the
#: number the shipped logic derives, not one the harness chose.
#:
#: It runs under `unshare -r`, which is not decoration: shadowfetch-bundle-
#: install refuses to install unless euid is 0 and refuses a catalog record
#: that is not root-owned, and neither refusal is what is being measured. In
#: that namespace the harness's own files are uid 0.
_HARNESS = r'''
import io, json, os, sys
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader

root, bundle, sflib, phxlib, scenario = sys.argv[1:6]
for lib in (sflib, phxlib):
    if lib not in sys.path:
        sys.path.insert(0, lib)
from sfupdate import snapshots as sfsnap
from sfupdate import state as sfstate

catalog = os.path.join(root, "catalog")
varlib = os.path.join(root, "var")
logdir = os.path.join(root, "log")
bindir = os.path.join(root, "bin")
state_file = os.path.join(varlib, "fireproof-state.json")
pending = os.path.join(varlib, "fireproof-pending")
for d in (catalog, varlib, logdir, bindir):
    os.makedirs(d, exist_ok=True)
    os.chmod(d, 0o755)
record = os.path.join(catalog, "test-bundle.json")
with open(record, "w") as fh:
    fh.write(json.dumps({"id": "test-bundle", "kind": "apt", "name": "T",
                         "packages": ["cowsay", "sl"]}))
os.chmod(record, 0o644)

def stub(name):
    path = os.path.join(bindir, name)
    with open(path, "w") as fh:
        fh.write("#!/bin/sh\nexit 0\n")
    os.chmod(path, 0o755)
    return path

# The machine has already had ONE Fireproof update, and its Point is 41.
PREVIOUS = {"schema": 1, "failed_sets": [],
            "last_txn": {"txn": "previous-transaction", "hash": "a" * 64,
                         "date": "2026-09-01T10:00:00+00:00",
                         "pre_point": 41, "verdict": "ok", "kernels": []}}
sfstate.save_state(dict(PREVIOUS), state_file)
if scenario == "pending-update":
    # That update committed and has not yet been judged by a good boot.
    sfstate.write_pending("previous-transaction", 41, [], pending)
before = sfstate.rollback_target(sfstate.load_state(state_file),
                                 sfstate.read_pending(pending))
raw_before = open(state_file).read()

S = sfsnap.Snapshot
ROWS_PRE = [S(0, "single"), S(41, "pre"), S(42, "post")]
ROWS_POST = ROWS_PRE + [S(43, "pre"), S(44, "post")]
seen = []
def rows(executor=None):
    seen.append(1)
    return list(ROWS_PRE if len(seen) == 1 else ROWS_POST)
sfsnap.snapshot_rows = rows
sfsnap.phoenix_available = lambda executor=None: True

loader = SourceFileLoader("bundle_install", bundle)
mod = module_from_spec(spec_from_loader("bundle_install", loader))
loader.exec_module(mod)
mod.CATALOG_DIR = catalog
mod.STATE_DIR = varlib
mod.LOG_DIR = logdir
mod.DONE_FILE = os.path.join(varlib, "ignition-done")
mod.CHOICE_FILE = os.path.join(varlib, "ignition-choice.json")
mod.STATE_FILE = state_file
mod.PENDING_FILE = pending
mod.root_is_btrfs = lambda: True
mod.wait_for_locks = lambda allow_cancel: True
mod.APT_GET_PATHS = (stub("apt-get"),)
mod.DPKG_PATHS = (stub("dpkg"),)
if scenario == "no-authority":
    # Exactly what _load_update_authority() returns on a machine that has
    # shadowfetch-welcome but not shadowfetch-fireproof.
    mod.sfsnap = mod.sfstate = mod.STATE_FILE = mod.PENDING_FILE = None
if scenario == "unrecordable":
    mod.STATE_FILE = "/proc/sf-nowhere/fireproof-state.json"
if scenario == "no-apt":
    mod.APT_GET_PATHS = ("/proc/sf-nowhere/apt-get",)
apt = []
def fake_apt(argv, stage, log_fh, allow_cancel):
    apt.append(list(argv))
    return (1 if (scenario == "failed" and stage == "commit") else 0), False
mod.run_apt = fake_apt
mod.subprocess.run = lambda *a, **k: type(
    "R", (), {"stdout": "", "stderr": "", "returncode": 0})()

out, real = io.StringIO(), sys.stdout
sys.stdout = out
code = 0
try:
    mod.verb_install("test-bundle")
except SystemExit as exc:
    code = exc.code
finally:
    sys.stdout = real
after_state = sfstate.load_state(state_file)
print(json.dumps({
    "exit": code,
    "events": [l for l in out.getvalue().splitlines() if l.strip()],
    "apt_argv0": [c[0] for c in apt],
    "state_unchanged": open(state_file).read() == raw_before,
    "last_txn": after_state.get("last_txn"),
    "before": before,
    "after": sfstate.rollback_target(after_state,
                                     sfstate.read_pending(pending)),
    "pending": os.path.exists(pending),
    "snapper_reads": len(seen),
}))
'''


def _userns_available():
    if not shutil.which("unshare"):
        return False
    probe = subprocess.run(["unshare", "-r", "true"], capture_output=True)
    return probe.returncode == 0


class TestBundleInstallIsNotASecondDecider(unittest.TestCase):
    """The second program that commits packages as root, held to one authority.

    It may commit - fireproofd has no verb for a named bundle - but it may not
    DECIDE. Every test here is about the seam between the two.
    """

    def setUp(self):
        self.code = code_only(BUNDLE_INSTALL.read_text())

    # -- source: the second parser is gone, not shadowed -------------------
    def test_it_has_no_snapper_parser_and_runs_no_snapper(self):
        # These were real lines here: its own --machine-readable CSV parse,
        # its own human-table fallback, and its own first-pre-after rule.
        for gone in ("--machine-readable", "def snapper_snapshots(",
                     "def snapper_max_number(", "def first_pre_after(",
                     '"snapper"', "'snapper'"):
            self.assertNotIn(gone, self.code,
                             "bundle-install still owns snapper: %s" % gone)

    def test_it_derives_the_point_through_the_one_authority(self):
        self.assertIn("sfsnap.phoenix_available()", self.code)
        self.assertIn("sfsnap.max_number()", self.code)
        self.assertIn("sfsnap.first_pre_after(baseline)", self.code)

    def test_it_relabels_nothing(self):
        # label_point is the only snapper mutation in the product and it
        # belongs to fireproofd. Relabelling the Point Fireproof labels, with
        # a different description and no userdata, is precisely what
        # shadowfetch-update did before Stage U deleted it.
        self.assertNotIn("label_point", self.code)
        self.assertNotRegex(self.code, r"snapper[^\n]*\bmodify\b")

    def test_it_records_through_the_one_store_and_not_a_second_one(self):
        self.assertIn("sfstate.load_state(STATE_FILE)", self.code)
        self.assertIn("sfstate.save_state(state, STATE_FILE)", self.code)
        # The record is the authority's file, named once, from the authority.
        self.assertIn("STATE_FILE = sfstate.STATE_FILE", self.code)
        self.assertNotIn("fireproof-state.json", self.code)

    def test_it_does_not_write_the_pending_flag(self):
        """fireproof-pending stays fireproofd's.

        The flag means "a commit is waiting on a good boot to be judged", and
        fireproof-postboot restores from it when the desktop does not come
        back. An update still under that assessment must keep priority: if the
        desktop breaks after an update AND a later bundle install, the Point
        that repairs it is the update's, not the bundle's.
        """
        self.assertNotIn("write_pending", self.code)
        self.assertNotIn("fireproof-pending", self.code)

    def test_every_program_it_runs_is_an_absolute_path(self):
        # apt-get performs the root transaction; dpkg --audit decides whether
        # the system is broken; gpasswd grants a group carrying realtime
        # priority and unlimited memory locking. None may be chosen by PATH.
        for table in ("APT_GET_PATHS", "DPKG_PATHS", "GPASSWD_PATHS"):
            self.assertIn(table + " = (", self.code)
            self.assertIn("trusted_program(%s)" % table, self.code)
        for bare in ('["apt-get"', '["dpkg"', '["gpasswd"'):
            self.assertNotIn(bare, self.code)
        self.assertNotIn("shutil.which", self.code)

    def test_the_authority_is_found_without_pythonpath(self):
        # Derived from this file's own installed location, never from an
        # environment the caller controls - this program runs as root.
        self.assertIn('installed = here.parent.parent / "lib" / "shadowfetch"',
                      self.code)
        self.assertNotRegex(self.code, r"environ[^\n]*PYTHONPATH")

    # -- behaviour: the record and the rollback target actually move --------
    def _run(self, scenario):
        if not _userns_available():
            self.skipTest("no user namespaces here: the program refuses to "
                          "install unless euid is 0, so this cannot be staged")
        with tempfile.TemporaryDirectory() as tmp:
            harness = pathlib.Path(tmp) / "harness.py"
            harness.write_text(_HARNESS)
            root = pathlib.Path(tmp) / "root"
            root.mkdir()
            result = subprocess.run(
                ["unshare", "-r", sys.executable, str(harness), str(root),
                 str(BUNDLE_INSTALL), str(SFUPDATE_LIB), str(PHOENIX_LIB),
                 scenario],
                capture_output=True, text=True, timeout=120)
        self.assertEqual(0, result.returncode, result.stderr[-2000:])
        return json.loads(result.stdout)

    def test_a_bundle_install_moves_the_rollback_target_to_its_own_point(self):
        """THE regression. Before the fix these two numbers were 43 and 41.

        The machine has a Fireproof update recorded at Point 41. A bundle
        install produces Points 43/44. What the Welcome failure card offers
        and what Fireproof1.RollbackTarget answers must be ONE number.
        """
        run = self._run("normal")
        self.assertIn("SF-POINT 43", run["events"])
        self.assertEqual(41, run["before"]["point"])
        self.assertEqual(43, run["after"]["point"])
        self.assertEqual("pkexec /usr/libexec/phoenix-restore 43",
                         run["after"]["command"])
        self.assertFalse(run["state_unchanged"],
                         "the update record did not move")

    def test_the_record_says_which_program_committed_and_claims_no_verdict(self):
        txn = self._run("normal")["last_txn"]
        self.assertEqual("shadowfetch-bundle-install", txn["source"])
        self.assertEqual("test-bundle", txn["bundle"])
        self.assertEqual(43, txn["pre_point"])
        self.assertEqual([], txn["kernels"])
        # No verify battery is run here, so "ok" would be a fabricated
        # verdict - the forged-clean-scan shape one layer down.
        self.assertEqual("not-verified", txn["verdict"])
        # Namespaced, so a rolled-back BUNDLE can never be read as a
        # rolled-back UPGRADE and suppress a legitimate update: fireproofd's
        # change_set_hash is a bare 64-character sha256 hexdigest.
        self.assertTrue(txn["hash"].startswith("bundle:"))
        self.assertNotRegex(txn["hash"], r"^[0-9a-f]{64}$")

    def test_a_failed_commit_still_names_the_point_and_says_so(self):
        run = self._run("failed")
        self.assertIn("SF-POINT 43", run["events"])
        self.assertEqual(43, run["after"]["point"])
        # Not a judgement of the machine - no battery ran - but the same
        # evidence fireproofd acts on: the commit did not complete.
        self.assertEqual("restore-recommended", run["last_txn"]["verdict"])

    def test_a_point_that_cannot_be_recorded_is_never_offered(self):
        """The defect, stated as the rule that replaces it.

        A Point only this program knows about is exactly what shipped: the
        failure card turned it into `pkexec /usr/libexec/phoenix-restore 43`
        while Fireproof went on naming 41. If the record cannot be written,
        the number is not printed.
        """
        run = self._run("unrecordable")
        self.assertIn("SF-NOPOINT not-recorded", run["events"])
        self.assertFalse([e for e in run["events"] if e.startswith("SF-POINT")])
        self.assertEqual(2, run["snapper_reads"],
                         "the Point was derived, so it was there to be leaked")
        self.assertTrue(run["state_unchanged"])
        self.assertEqual(41, run["after"]["point"])

    def test_without_the_update_authority_no_point_is_invented(self):
        """shadowfetch-welcome does not depend on shadowfetch-fireproof.

        On such a machine there is no store to record into, so no Point is
        offered at all. Printing one anyway would be keeping the defect for
        exactly the installs where nothing could ever act on it.
        """
        run = self._run("no-authority")
        self.assertIn("SF-NOPOINT no-authority", run["events"])
        self.assertFalse([e for e in run["events"] if e.startswith("SF-POINT")])
        self.assertEqual(0, run["snapper_reads"])
        self.assertTrue(run["state_unchanged"])

    def test_no_trusted_apt_get_means_nothing_is_installed(self):
        run = self._run("no-apt")
        self.assertEqual(6, run["exit"])
        self.assertEqual([], run["apt_argv0"])
        self.assertTrue(any("no-apt" in e for e in run["events"]))
        self.assertTrue(run["state_unchanged"])

    def test_the_pending_flag_is_not_written_by_a_bundle_install(self):
        self.assertFalse(self._run("normal")["pending"])

    def test_nothing_is_recorded_while_an_update_is_still_pending(self):
        """A defect introduced by the first version of this fix, and removed.

        sfupdate.state.rollback_target takes the POINT from fireproof-pending
        when one exists but the TXN ID from last_txn, always. That was
        consistent while fireproofd wrote both. A bundle install that
        overwrites last_txn between a commit and its first good boot splits
        them: the button would restore the UPDATE's Point and the
        RecordRollback that follows would file the BUNDLE's change-set hash in
        failed_sets - so the update that had just been rolled back would be
        offered again with no "Don't proceed". The whole point of failed_sets,
        defeated by a bundle install.

        In that window nothing is recorded and no Point is offered. The
        update's Point is the right target there anyway: a desktop that does
        not come back may be the update's doing.
        """
        run = self._run("pending-update")
        self.assertIn("SF-NOPOINT pending-update", run["events"])
        self.assertFalse([e for e in run["events"] if e.startswith("SF-POINT")])
        self.assertEqual(2, run["snapper_reads"],
                         "the Point was derived, so it was there to be leaked")
        self.assertTrue(run["state_unchanged"])
        # The one rollback target still describes ONE transaction: the Point
        # and the txn id that travels with it belong to the same update.
        self.assertEqual(41, run["after"]["point"])
        self.assertEqual("pending", run["after"]["source"])
        self.assertEqual("previous-transaction", run["after"]["txn"])
        self.assertEqual("previous-transaction", run["last_txn"]["txn"])


class TestCliAndShimAgree(unittest.TestCase):
    def test_the_cli_offers_exactly_the_verbs_the_shim_dispatches(self):
        cli = CLI.read_text()
        for verb in ("check", "update", "verify", "rollback"):
            self.assertRegex(cli, r'cmd == "%s"' % verb)
        shim_verbs = set(re.findall(r"verb=([a-z]+)", SHIM.read_text()))
        self.assertEqual({"update", "check", "verify", "rollback"}, shim_verbs)


if __name__ == "__main__":
    unittest.main()
