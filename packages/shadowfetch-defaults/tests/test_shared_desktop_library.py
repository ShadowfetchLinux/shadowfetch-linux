"""The shared desktop library this package ships, and the gate that keeps it
single (W-30, second half).

W-30 asks for one desktop library -- catalog, hwscan, net, launch,
bundle_install_argv -- imported by BOTH the Control Center and Welcome.  Stage
P landed the Control Center half as sfcc/desktop.py and said so plainly: there
was one implementation inside the Control Center and a second one still inside
Welcome, and tools/drift_gate.py reported the pair BLOCKED.

This half moved that module to shadowfetch-defaults, which both front-ends now
depend on, and pointed Welcome at it.  The Control Center's own suite
(packages/shadowfetch-control-center/tests/test_desktop_library.py) still
covers the library's behaviour, because sfcc.desktop IS the library object; the
tests here cover the things that suite structurally cannot:

  * that the library is SHIPPED, and that both front-ends can reach it on an
    installed system rather than only in this tree -- a shared module nobody
    packages is two ImportErrors and a green test run;
  * that Welcome really stopped implementing its own copies, including the
    privileged argv where its copy named pkexec by a bare word the session's
    PATH resolved;
  * that the rewritten drift-gate check FAILS on the ways the duplication has
    actually been made to come back -- including every one an adversarial
    verifier used, which the first version of this check reported clean.  A
    gate is worth landing only if it has been seen to go red on the thing it
    claims to catch.

The claim over these tests is DETECTED, not ENFORCED.  The check is a CI-time
scanner over source shape; it prevents nothing at runtime, and WhatThisBarrierStillMisses
records the honest edge of it, measured rather than guessed.  The enforced half is inside the
library -- every program it runs is resolved from PROGRAMS -- and it only
covers a front-end that CALLS the library, which is exactly what these tests
and that check are here to detect the loss of.
"""
import ast
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
DEFAULTS = ROOT / "packages/shadowfetch-defaults"
LIBRARY = DEFAULTS / "data/usr/lib/shadowfetch/desktop/sf_desktop.py"
LIBRARY_INSTALLED_DIR = "usr/lib/shadowfetch/desktop"
INSTALL_LIST = DEFAULTS / "debian/shadowfetch-defaults.install"
WELCOME = ROOT / "packages/shadowfetch-welcome/src/shadowfetch-welcome"
WELCOME_CONTROL = ROOT / "packages/shadowfetch-welcome/debian/control"
SFCC = (ROOT / "packages/shadowfetch-control-center/data/usr/share/shadowfetch/"
        "control-center/sfcc")
CC_CONTROL = ROOT / "packages/shadowfetch-control-center/debian/control"

sys.path.insert(0, str(ROOT / "tools"))
import drift_gate  # noqa: E402


def library_source() -> str:
    return LIBRARY.read_text(encoding="utf-8")


def welcome_source() -> str:
    return WELCOME.read_text(encoding="utf-8")


def load_library():
    """The library, loaded straight off this package's payload."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("sf_desktop_undertest", LIBRARY)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --------------------------------------------------------------------------- #
# it is shipped, and both front-ends can reach it
# --------------------------------------------------------------------------- #

class TheLibraryIsShippedAndReachable(unittest.TestCase):
    """"One module imported by both" is a claim about an installed system."""

    def test_the_payload_exists_and_is_this_packages_to_ship(self):
        self.assertTrue(LIBRARY.is_file(), LIBRARY)
        self.assertIn("packages/shadowfetch-defaults", str(LIBRARY))

    def test_the_install_list_ships_it_to_the_path_both_front_ends_import(self):
        lines = [line for line in INSTALL_LIST.read_text(encoding="utf-8").splitlines()
                 if "sf_desktop.py" in line]
        self.assertEqual(1, len(lines), lines)
        source, destination = lines[0].split()
        self.assertTrue((DEFAULTS / source).is_file(), source)
        self.assertEqual(LIBRARY_INSTALLED_DIR, destination.rstrip("/"))

    def test_both_front_ends_load_it_from_the_installed_path(self):
        """Both name the installed path and both really load the module.

        Asserted through drift_gate.library_resolution() rather than by
        grepping for "import sf_desktop": the Control Center no longer contains
        that statement ON PURPOSE (ATTACK B -- `import` consults sys.modules
        before sys.path, so the existence check the loader had just performed
        decided nothing), and a grep for it would now read the fix as a
        regression.
        """
        for name, path in (("Welcome", WELCOME), ("Control Center", SFCC / "desktop.py")):
            with self.subTest(front_end=name):
                source = path.read_text(encoding="utf-8")
                self.assertIn("/" + LIBRARY_INSTALLED_DIR, source)
                self.assertTrue(drift_gate.library_resolution(source),
                                f"{name} does not load the shared library at all")

    def test_the_control_centre_loads_the_file_it_checked(self):
        """ATTACK B, held from this side too. The Control Center's loader must
        execute the FILE; Welcome still resolves the module by name, which the
        gate reports BLOCKED with the exact replacement."""
        source = (SFCC / "desktop.py").read_text(encoding="utf-8")
        self.assertIn("file", drift_gate.library_resolution(source))
        self.assertNotIn("name", drift_gate.library_resolution(source))

    def test_both_front_end_packages_depend_on_the_package_that_ships_it(self):
        """Recommends is not enough. Both front-ends raise ImportError without
        the library, so an install that omits it is a broken install, not a
        degraded one."""
        for control, package in ((WELCOME_CONTROL, "shadowfetch-welcome"),
                                 (CC_CONTROL, "shadowfetch-control-center")):
            with self.subTest(package=package):
                depends = drift_gate.depends_field(
                    control.read_text(encoding="utf-8"), package)
                self.assertIn("shadowfetch-defaults", depends)

    def test_the_dependency_cycle_it_creates_is_written_down(self):
        """shadowfetch-defaults Depends on shadowfetch-welcome (Workbench reads
        Welcome's catalog and runs its bundle installer) and Welcome now
        Depends back. That is a real Depends cycle; the point of this test is
        that it cannot be there by accident."""
        defaults = (DEFAULTS / "debian/control").read_text(encoding="utf-8")
        self.assertIn("shadowfetch-welcome",
                      drift_gate.depends_field(defaults, "shadowfetch-defaults"))
        welcome = WELCOME_CONTROL.read_text(encoding="utf-8")
        self.assertIn("Depends CYCLE", welcome,
                      "the cycle is undocumented; say why it is the cheaper "
                      "evil or break it")


# --------------------------------------------------------------------------- #
# sfcc.desktop is the library, not a copy of its names
# --------------------------------------------------------------------------- #

class TheControlCentreNameIsTheSameObject(unittest.TestCase):
    """The loader replaces itself in sys.modules on purpose.

    A re-export list would be the obvious shape and is the wrong one: it makes
    a second set of bindings, and a name added to the library and forgotten in
    the list is an AttributeError nobody sees until a button is clicked. That
    happened during Stage P -- four pages called busutil.desktop.SYSTEMCTL
    after busutil stopped importing the module under that name, and every test
    still passed.
    """

    def setUp(self):
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        if str(SFCC.parent) not in sys.path:
            sys.path.insert(0, str(SFCC.parent))

    def test_importing_sfcc_desktop_yields_the_shipped_library(self):
        from sfcc import desktop
        self.assertEqual(str(LIBRARY), desktop.__file__,
                         "sfcc.desktop is not the module this package ships")

    def test_patching_the_name_patches_what_the_functions_read(self):
        """The property that distinguishes an alias from a re-export."""
        from sfcc import desktop
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "one.json").write_text(
                json.dumps({"id": "a", "kind": "preset"}), encoding="utf-8")
            with patch.object(desktop, "CATALOG_DIR", tmp):
                self.assertEqual(["a"], [r["id"] for r in desktop.load_catalog()])

    def test_the_loader_carries_no_implementation_of_its_own(self):
        source = (SFCC / "desktop.py").read_text(encoding="utf-8")
        for gone in ("PROGRAMS = {", "def bundle_install_argv(",
                     "def load_catalog("):
            self.assertNotIn(gone, source,
                             "the Control Center is implementing a desktop "
                             "fact again instead of loading the library")


# --------------------------------------------------------------------------- #
# Welcome stopped implementing its half
# --------------------------------------------------------------------------- #

class WelcomeHasNoSecondImplementation(unittest.TestCase):

    def code_lines(self):
        """Lines that can execute. Comments and docstrings are prose: the house
        style names the defect a change removed, and several comments in
        Welcome now quote the spellings this class asserts are gone."""
        text = welcome_source()
        prose = set()
        for node in ast.walk(ast.parse(text)):
            if (isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
                    and isinstance(node.value.value, str)):
                prose.update(range(node.lineno,
                                   (node.end_lineno or node.lineno) + 1))
        for number, line in enumerate(text.splitlines(), 1):
            if number in prose or line.lstrip().startswith("#"):
                continue
            yield number, line

    def test_the_five_helper_paths_are_not_spelled_here_any_more(self):
        for label, path in drift_gate.HELPER_PATHS.items():
            offenders = [n for n, line in self.code_lines() if path in line]
            with self.subTest(path=label):
                self.assertEqual([], offenders,
                                 f"{path} is written in Welcome again")

    def test_nor_assembled_out_of_fragments(self):
        """The line scan above is a substring search, and the verifier walked
        `"/usr/libexec/" "shadowfetch-bundle-install"` straight past it with a
        second bundle installer behind it. Same file, different spelling."""
        self.assertEqual([], drift_gate.assembled_path_hits(welcome_source()))

    def test_the_catalog_and_hwscan_readers_are_gone(self):
        """By shape. This test used to grep for `def load_catalog(` and
        `def hwscan_cached(`, and a verifier renamed its plant to
        `_read_bundle_records` and walked past with a complete second reader.
        A function that walks a directory and decodes JSON out of it IS a
        catalog reader; what it is called decides nothing."""
        source = welcome_source()
        readers = drift_gate.catalog_reader_functions(source)
        self.assertEqual([], readers,
                         "a second catalog reader in Welcome: " + str(readers))
        for gone in ("def load_catalog(", "def hwscan_cached("):
            self.assertNotIn(gone, source)
        self.assertIn("desktop.catalog_by_id(None)", source)
        self.assertIn("desktop.hwscan_cached()", source)
        self.assertIn("desktop.load_hwscan()", source)

    def test_no_privileged_argv_is_built_here_at_all(self):
        """The rule is structural, and it used to be a list of spellings.

        The check this replaces walked only an `ast.List` that was the FIRST
        POSITIONAL ARGUMENT of run/Popen/CommandWorker, so a builder that
        RETURNED the argv was invisible to it, `Popen(_install_argv(id))`
        passed an ast.Call, and `argv = [...]` bound one line earlier walked
        straight past. The honest rule is the one that has a single legal
        source: a front-end contains no privileged argv construction at all --
        every such argv comes from the library -- which is checkable over
        every list display in the file rather than over three call shapes.

        The defect underneath is still the one W-30 names: Welcome ran
        ["pkexec", HELPER, ...], and a same-user process that can prepend a
        directory to PATH becomes the program that button asks for an
        administrator password.
        """
        offenders = drift_gate.privileged_argv_displays(welcome_source())
        self.assertEqual([], offenders,
                         "a privileged or Shadowfetch argv is assembled in "
                         "Welcome: " + str(offenders))

    def test_the_installed_package_map_is_the_shared_one(self):
        """"Already on your system (3 of 7)" is a statement about the reader's
        machine, and Welcome produced it from a bare dpkg-query resolved
        through the session's PATH -- the same defect the library records for
        the Control Center's copy."""
        source = welcome_source()
        self.assertIn("desktop.installed_map(list(pkgs))", source)
        self.assertEqual([], [n for n, line in self.code_lines()
                              if "dpkg-query" in line])

    def test_the_create_workspace_button_resolves_its_tool_by_trusted_path(self):
        """W-30's other half. The button was dead (it started the interactive
        menu, which reads stdin and gets EOF from a desktop launch); the verb
        fix landed earlier, and this is the resolution half -- shutil.which
        asks the session's PATH which program the button runs."""
        source = welcome_source()
        self.assertIn('desktop.trusted_program("shadowfetch-agent-workspace")',
                      source)
        self.assertNotIn('shutil.which("shadowfetch-agent-workspace")', source)
        self.assertIn('[helper, "create", name.strip()]', source)


class WelcomeRunsAgainstTheLibrary(unittest.TestCase):
    """Source greps prove the copies are gone. This proves the replacement
    works: Welcome is imported for real, with Qt offscreen, and asked."""

    SCRIPT = r"""
import importlib.machinery, json, sys, types
loader = importlib.machinery.SourceFileLoader("sf_welcome_qa", sys.argv[1])
module = types.ModuleType(loader.name)
module.__file__ = sys.argv[1]
loader.exec_module(module)
# Point the LIBRARY at a scratch catalog and a known package answer. Welcome
# holds the module itself, not copies of its names, so this reaches every
# caller in the wizard -- which is the property under test.
library = module.desktop
library.CATALOG_DIR = sys.argv[2]
library.installed_map = lambda packages: {p: p == "a" for p in packages}
print(json.dumps({
    "library": library.__file__,
    "has_own_load_catalog": hasattr(module, "load_catalog"),
    "has_own_hwscan_cached": hasattr(module, "hwscan_cached"),
    "catalog": sorted(module.desktop.catalog_by_id(None)),
    "installed": sorted(module.dpkg_installed(["a", "b"])),
}))
"""

    def test_welcome_imports_and_reads_the_shared_library(self):
        with tempfile.TemporaryDirectory() as tmp:
            catalog = Path(tmp, "catalog")
            catalog.mkdir()
            # The array form Welcome's own copy rejected, plus a record with no
            # kind, which neither front-end can render.
            Path(catalog, "many.json").write_text(json.dumps(
                [{"id": "b", "kind": "apt"}, {"id": "c", "kind": "preset"}]),
                encoding="utf-8")
            Path(catalog, "one.json").write_text(json.dumps(
                {"id": "a", "kind": "template"}), encoding="utf-8")
            Path(catalog, "kindless.json").write_text(json.dumps(
                {"id": "z"}), encoding="utf-8")
            env = dict(os.environ, QT_QPA_PLATFORM="offscreen", HOME=tmp,
                       XDG_CONFIG_HOME=str(Path(tmp, "config")))
            done = subprocess.run(
                [sys.executable, "-c", self.SCRIPT, str(WELCOME), str(catalog)],
                capture_output=True, text=True, timeout=180, env=env)
            self.assertEqual(0, done.returncode, done.stderr[-3000:])
            result = json.loads(done.stdout.strip().splitlines()[-1])
        self.assertEqual(str(LIBRARY), result["library"],
                         "Welcome loaded something other than the payload this "
                         "package ships")
        self.assertFalse(result["has_own_load_catalog"])
        self.assertFalse(result["has_own_hwscan_cached"])
        self.assertEqual(["a", "b", "c"], result["catalog"],
                         "the array form or the kind rule regressed")
        self.assertEqual(["a"], result["installed"])


# --------------------------------------------------------------------------- #
# the library's own rules, where the Control Center suite does not reach
# --------------------------------------------------------------------------- #

class LibraryRules(unittest.TestCase):

    def setUp(self):
        self.lib = load_library()

    def test_hwscan_cached_never_execs_anything(self):
        """It is the reader for callers on the UI thread. load_hwscan() may run
        the scanner with an 8-second timeout, and a page constructor that can
        block for eight seconds is a frozen window."""
        with tempfile.TemporaryDirectory() as tmp:
            fact = Path(tmp, "hwscan.json")
            fact.write_text(json.dumps({"gpus": []}), encoding="utf-8")
            def explode(*a, **k):
                raise AssertionError("hwscan_cached executed a program")
            with patch.object(self.lib, "HWSCAN_JSON", str(fact)), \
                    patch.object(self.lib.subprocess, "run", explode), \
                    patch.object(self.lib.subprocess, "Popen", explode):
                self.assertEqual({"gpus": []}, self.lib.hwscan_cached())
                fact.unlink()
                self.assertEqual({}, self.lib.hwscan_cached())

    def test_a_record_with_no_kind_is_skipped_by_every_view(self):
        """Welcome's copy required a kind and the Control Center's did not.
        Keeping Welcome's rule is deliberate: a record with no kind has no
        action either front-end can offer, so showing it is a dead card."""
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "a.json").write_text(
                json.dumps({"id": "a", "kind": "preset"}), encoding="utf-8")
            Path(tmp, "z.json").write_text(
                json.dumps({"id": "z"}), encoding="utf-8")
            with patch.object(self.lib, "CATALOG_DIR", tmp):
                self.assertEqual(["a"], [r["id"] for r in self.lib.load_catalog(None)])
                self.assertEqual(["a"], sorted(self.lib.catalog_by_id(None)))

    def test_every_declared_program_is_absolute_and_classified(self):
        for name, (path, trust) in self.lib.PROGRAMS.items():
            with self.subTest(program=name):
                self.assertTrue(path.startswith("/"), path)
                self.assertIn(trust, ("system", "shadowfetch"))

    def test_the_element_tool_welcome_launches_is_in_the_table(self):
        """Welcome ran it as a bare name, so the session's PATH decided which
        program rewrote the user's Plasma configuration."""
        self.assertEqual("/usr/bin/shadowfetch-element",
                         self.lib.PROGRAMS["shadowfetch-element"][0])


# --------------------------------------------------------------------------- #
# the gate: it has to go red on each way the duplication comes back
# --------------------------------------------------------------------------- #

GATE_FILES = tuple(set(drift_gate.HELPER_CONSUMERS)
                   | set(drift_gate.BUNDLE_CALL_SITES))


class _GateSandbox:
    """A copy of the tree the gate reads, so a plant can be made in it.

    Extracted from GateCatchesTheDuplicationComingBack when the shape tests
    below were added: three classes plant into the same sandbox and the
    helpers are the same three methods.
    """

    def sandbox(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        fake = Path(tmp.name)
        for rel in GATE_FILES:
            target = fake / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / rel, target)
        saved = drift_gate.ROOT
        drift_gate.ROOT = fake
        self.addCleanup(setattr, drift_gate, "ROOT", saved)
        return fake

    @staticmethod
    def drifts():
        return [f for f in drift_gate.check_desktop_helpers({})
                if f.kind == "DRIFT"]

    @staticmethod
    def edit(path: Path, old: str, new: str):
        text = path.read_text(encoding="utf-8")
        assert text.count(old) == 1, f"{path}: expected exactly one {old!r}"
        path.write_text(text.replace(old, new), encoding="utf-8")

    LIB_REL = drift_gate.DESKTOP_LIBRARY
    WELCOME_REL = "packages/shadowfetch-welcome/src/shadowfetch-welcome"


class GateCatchesTheDuplicationComingBack(_GateSandbox, unittest.TestCase):
    """The check changed shape: it used to compare two copies and report the
    duplication BLOCKED, it now holds one implementation to a contract. A gate
    that has never been seen to fail is a claim, not a control."""

    def test_the_tree_as_it_stands_has_no_drift(self):
        self.sandbox()
        found = self.drifts()
        self.assertEqual([], found, "\n".join(str(f) for f in found))

    def test_the_old_blocked_finding_is_gone_and_the_rest_are_recorded(self):
        """The deliverable, and the honest scope of it.

        The old finding -- "load_catalog(), the hwscan freshness rule and the
        five helper paths are still implemented twice" -- is gone. What is
        left is recorded here by file and kind, so a new BLOCKED item cannot
        arrive unnoticed and a fixed one cannot quietly shrink the report.
        Recorded by KIND rather than by line, because these are other
        packages' files and an edit there must not fail this test.

          net        the one member of W-30's list this work did not move
          loader     Welcome resolves the module by name (ATTACK B), which is
                     reported with the exact replacement; the Control Center's
                     loader is fixed, so it is not in this list
          argv       workbench_page.py declares /usr/bin/shadowfetch-workbench
                     itself, a program the library's table does not carry
        """
        self.sandbox()
        blocked = [f for f in drift_gate.check_desktop_helpers({})
                   if f.kind == "BLOCKED"]
        for finding in blocked:
            self.assertNotIn("still implemented twice, in two divergent shapes",
                             finding.detail)

        def kind(finding):
            if "`net`" in finding.detail:
                return "net"
            if "resolves the module BY NAME" in finding.detail:
                return "loader"
            if "trusted-program table does not carry" in finding.detail:
                return "argv"
            return "UNRECORDED"

        found = sorted((finding.site.split(":")[0].rsplit("/", 1)[-1], kind(finding))
                       for finding in blocked)
        self.assertEqual(
            [("busutil.py", "net"),
             ("shadowfetch-welcome", "loader"),
             ("workbench_page.py", "argv"),
             ("workbench_page.py", "argv")],
            found,
            "the blocked inventory changed:\n"
            + "\n".join(str(f) for f in blocked))

    def test_a_front_end_spelling_a_helper_path_again_is_caught(self):
        fake = self.sandbox()
        self.edit(fake / self.WELCOME_REL,
                  'STATE_HELPER = "/usr/libexec/shadowfetch-ignition-state"',
                  'STATE_HELPER = "/usr/libexec/shadowfetch-ignition-state"\n'
                  'BUNDLE_HELPER = "/usr/libexec/shadowfetch-bundle-install"')
        found = self.drifts()
        self.assertTrue(any("spells the bundle-install path" in f.detail
                            for f in found), found)

    def test_a_front_end_that_stops_loading_the_library_is_caught(self):
        fake = self.sandbox()
        # The name still appears -- both front-ends print it in the
        # ImportError they raise without the library -- and the module bound
        # to it is something else entirely.
        self.edit(fake / self.WELCOME_REL,
                  "            import sf_desktop",
                  "            import json as sf_desktop")
        found = self.drifts()
        self.assertTrue(any("does not load the shared desktop library" in f.detail
                            for f in found), found)

    def test_an_unshipped_library_is_caught(self):
        fake = self.sandbox()
        install = fake / drift_gate.LIBRARY_INSTALL
        install.write_text(
            "\n".join(line for line in install.read_text().splitlines()
                      if "sf_desktop.py" not in line), encoding="utf-8")
        found = self.drifts()
        self.assertTrue(any("does not ship the shared library" in f.detail
                            for f in found), found)

    def test_a_front_end_package_that_does_not_depend_on_it_is_caught(self):
        fake = self.sandbox()
        control = fake / "packages/shadowfetch-welcome/debian/control"
        control.write_text(
            control.read_text(encoding="utf-8").replace(
                " shadowfetch-defaults (= ${binary:Version})",
                " flatpak"), encoding="utf-8")
        found = self.drifts()
        self.assertTrue(any("does not Depends on shadowfetch-defaults" in f.detail
                            for f in found), found)

    def test_the_builder_losing_its_install_verb_is_caught(self):
        """UI-ARGV-01: seven Install buttons exited 2 after the password
        prompt. The literal now exists in exactly one place, so this is where
        the plant goes."""
        fake = self.sandbox()
        self.edit(fake / self.LIB_REL,
                  'return [pkexec, helper, "install", bundle_id]',
                  'return [pkexec, helper, bundle_id]')
        found = self.drifts()
        self.assertTrue(any('without the "install" verb' in f.detail
                            for f in found), found)

    def test_the_builder_resolving_pkexec_through_path_is_caught(self):
        fake = self.sandbox()
        self.edit(fake / self.LIB_REL,
                  '    pkexec = trusted_program("pkexec")\n'
                  '    helper = trusted_program("shadowfetch-bundle-install")',
                  '    pkexec = "pkexec"\n'
                  '    helper = trusted_program("shadowfetch-bundle-install")')
        found = self.drifts()
        self.assertTrue(any("trusted program table" in f.detail for f in found),
                        found)

    def test_a_second_builder_outside_the_library_is_caught(self):
        fake = self.sandbox()
        target = fake / self.WELCOME_REL
        target.write_text(
            target.read_text(encoding="utf-8")
            + '\n\ndef bundle_install_argv(bundle_id):\n'
              '    return ["pkexec", BUNDLE_HELPER, "install", bundle_id]\n',
            encoding="utf-8")
        found = self.drifts()
        self.assertTrue(any("a second bundle_install_argv()" in f.detail
                            for f in found), found)

    def test_the_library_losing_one_of_its_facts_is_caught(self):
        fake = self.sandbox()
        self.edit(fake / self.LIB_REL, "def hwscan_is_fresh(", "def _hwscan_is_fresh(")
        found = self.drifts()
        self.assertTrue(any("def hwscan_is_fresh(" in f.detail for f in found),
                        found)

    def test_a_second_spelling_inside_the_library_is_caught(self):
        fake = self.sandbox()
        self.edit(fake / self.LIB_REL,
                  'HWSCAN_JSON = "/var/lib/shadowfetch/hwscan.json"',
                  'HWSCAN_JSON = "/var/lib/shadowfetch/hwscan.json"\n'
                  'HWSCAN_JSON_ALSO = "/var/lib/shadowfetch/hwscan.json"')
        found = self.drifts()
        self.assertTrue(any("is written 2 times in the library" in f.detail
                            for f in found), found)

    def test_prose_naming_a_path_is_not_a_second_copy(self):
        """The counts read code. This codebase's style is to name the file a
        constant points at; a gate that fired on the explanation would teach
        the next author to delete it."""
        fake = self.sandbox()
        target = fake / self.LIB_REL
        target.write_text(
            target.read_text(encoding="utf-8")
            + '\n\ndef _note():\n'
              '    """See /var/lib/shadowfetch/hwscan.json and '
              '/usr/libexec/shadowfetch-hwscan."""\n'
              '    return None\n',
            encoding="utf-8")
        self.assertEqual([], self.drifts())


# --------------------------------------------------------------------------- #
# ATTACK A: the barrier has to survive a rename and a new spelling
# --------------------------------------------------------------------------- #

# The plant an adversarial verifier put into a copy of this tree, immediately
# before `class NMWatcher`, and got `Ran 30 tests OK` and `desktop-helpers
# DRIFT findings: 0` out of the barrier that was supposed to hold W-30.  It is
# a complete second catalog reader and a complete second privileged argv
# builder, with two live call sites.
VERIFIER_PLANT = """
_BUNDLE_DIR = "/usr/share/shadowfetch/" + "bundles"
_BUNDLE_HELPER = "/usr/libexec/" "shadowfetch-bundle-install"


def _read_bundle_records(kinds=None):        # a second catalog reader
    records = []
    for name in sorted(os.listdir(_BUNDLE_DIR)):
        try:
            data = json.loads(Path(_BUNDLE_DIR, name).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        records.extend(data if isinstance(data, list) else [data])
    return records


def _install_argv(bundle_id):                # a second privileged argv builder
    return ["pkexec", _BUNDLE_HELPER, "install", bundle_id]


def _run_install(bundle_id):
    subprocess.Popen(_install_argv(bundle_id))          # live call site


def _run_install_direct(bundle_id):
    argv = ["pkexec", _BUNDLE_HELPER, "install", bundle_id]
    subprocess.Popen(argv)                              # live call site


"""


class GateCatchesASecondImplementationByShape(_GateSandbox, unittest.TestCase):
    """Attack A, reproduced plant by plant.

    Row 1 of this stage's report said the drift gate ENFORCED "one
    implementation of catalog/hwscan/launch/installed-map/privileged argv".  It
    did not.  `check_desktop_helpers` asked only whether a front-end (a) does
    not contain the five path LITERALS and (b) contains an `import sf_desktop`
    statement.  It never asked whether a front-end has a SECOND
    implementation, and three evasions composed to walk the whole plant past
    it:

      1.  the readers were held by grepping for `def load_catalog(` and
          `def hwscan_cached(`, which a rename defeats and nothing else;
      2.  the five reserved paths were checked with `path in code`, so
          `"/usr/libexec/" "shadowfetch-bundle-install"` and
          `os.path.join("/usr/libexec", "shadowfetch-bundle-install")` --
          different strings, same file -- walked past;
      3.  the privileged-argv check inspected only an `ast.List` that was the
          FIRST POSITIONAL ARGUMENT of run/Popen/CommandWorker, so a builder
          that RETURNS the argv was invisible, `Popen(_install_argv(id))`
          passes an `ast.Call`, and `argv = [...]` bound one line earlier was
          never looked at.

    Every test in this class failed against the barrier as it stood.  The
    replacement reads shape rather than spelling: what a folded string
    actually names, what a list display's head actually is, and what a
    function actually does.
    """

    WELCOME_REL = "packages/shadowfetch-welcome/src/shadowfetch-welcome"
    ANCHOR = "class NMWatcher(QObject):"

    def plant(self, code):
        """Put `code` where the verifier put it, and return the DRIFT
        findings the gate reports afterwards."""
        fake = self.sandbox()
        self.edit(fake / self.WELCOME_REL, self.ANCHOR, code + self.ANCHOR)
        return self.drifts()

    @staticmethod
    def details(found):
        return "\n".join(f.detail for f in found)

    def test_the_verifiers_whole_plant_is_caught(self):
        found = self.plant(VERIFIER_PLANT)
        self.assertTrue(found, "the verifier's plant produced 0 DRIFT findings")
        text = self.details(found)
        self.assertIn("second catalog reader", text)
        self.assertIn("privileged argv", text)
        self.assertIn("/usr/libexec/shadowfetch-bundle-install", text)

    def test_a_renamed_catalog_reader_is_caught_by_shape(self):
        """Evasion 1. The old barrier grepped for `def load_catalog(`."""
        found = self.plant(
            "def _records_for_cards(kinds=None):\n"
            "    out = []\n"
            "    for name in sorted(os.listdir(SOME_DIR)):\n"
            "        out.append(json.loads(Path(SOME_DIR, name).read_text()))\n"
            "    return out\n\n\n")
        self.assertIn("second catalog reader", self.details(found))

    def test_a_reserved_path_spelled_by_implicit_concatenation_is_caught(self):
        """Evasion 2, the form the verifier used. Python folds the two
        adjacent literals into one string; only a source grep sees two."""
        found = self.plant('_H = "/usr/libexec/" "shadowfetch-bundle-install"\n\n\n')
        self.assertIn("/usr/libexec/shadowfetch-bundle-install",
                      self.details(found))

    def test_a_reserved_path_spelled_by_os_path_join_is_caught(self):
        found = self.plant(
            '_H = os.path.join("/usr/libexec", "shadowfetch-bundle-install")\n\n\n')
        self.assertIn("/usr/libexec/shadowfetch-bundle-install",
                      self.details(found))

    def test_a_reserved_path_spelled_by_addition_is_caught(self):
        found = self.plant('_J = "/var/lib/shadowfetch/" + "hwscan.json"\n\n\n')
        self.assertIn("/var/lib/shadowfetch/hwscan.json", self.details(found))

    def test_a_reserved_path_assembled_through_a_named_fragment_is_caught(self):
        found = self.plant('_D = "/usr/libexec"\n'
                           '_H = _D + "/shadowfetch-hwscan"\n\n\n')
        self.assertIn("/usr/libexec/shadowfetch-hwscan", self.details(found))

    def test_a_privileged_argv_that_is_only_returned_is_caught(self):
        """Evasion 3. There is no run/Popen call anywhere near it."""
        found = self.plant(
            "def _argv(bundle_id):\n"
            '    return ["pkexec", "/usr/libexec/x", "install", bundle_id]\n\n\n')
        self.assertIn("privileged argv", self.details(found))

    def test_a_privileged_argv_bound_to_a_name_first_is_caught(self):
        """Evasion 3 again: `argv = [...]` one line above the call is not the
        first positional argument of anything."""
        found = self.plant(
            "def _go(bundle_id):\n"
            '    argv = ["pkexec", "/usr/libexec/x", "install", bundle_id]\n'
            "    subprocess.Popen(argv)\n\n\n")
        self.assertIn("privileged argv", self.details(found))

    def test_a_privileged_argv_whose_head_is_a_name_is_caught(self):
        found = self.plant(
            '_P = "/usr/bin/" "pkexec"\n'
            "def _go(bundle_id):\n"
            '    return [_P, "/usr/libexec/x", "install", bundle_id]\n\n\n')
        self.assertIn("privileged argv", self.details(found))

    def test_a_shadowfetch_helper_argv_is_caught_too(self):
        """The trusted-program invariant, not just pkexec: which binary named
        `shadowfetch-hwscan` runs is decided by the library's table, and a
        front-end that writes the argv itself has taken that decision back."""
        found = self.plant(
            "def _scan():\n"
            '    return subprocess.run(["shadowfetch-hwscan", "--json"])\n\n\n')
        self.assertIn("privileged argv", self.details(found))

    def test_delegating_to_the_library_is_not_a_finding(self):
        """The negative control. A barrier that fires on the correct shape
        teaches the next author to route around it."""
        found = self.plant(
            "def _go(bundle_id):\n"
            "    argv = desktop.bundle_install_argv(bundle_id)\n"
            "    records = desktop.load_catalog(None)\n"
            "    return argv, records\n\n\n")
        self.assertEqual([], found, self.details(found))


class GateCatchesADeadBranchImport(_GateSandbox, unittest.TestCase):
    """ATTACK C. `imports_module()` returned True for an import that cannot
    run, so a front-end could bind the name to anything at all and still
    satisfy the load check with `if False: import sf_desktop` elsewhere in the
    file."""

    WELCOME_REL = "packages/shadowfetch-welcome/src/shadowfetch-welcome"

    def test_an_unreachable_import_does_not_prove_the_library_is_loaded(self):
        fake = self.sandbox()
        target = fake / self.WELCOME_REL
        self.edit(target, "            import sf_desktop",
                  "            import json as sf_desktop")
        self.edit(target, "def _load_desktop():",
                  "if False:\n    import sf_desktop\n\n\ndef _load_desktop():")
        found = self.drifts()
        self.assertTrue(any("does not load the shared desktop library" in f.detail
                            for f in found),
                        "a dead branch satisfied the load check: "
                        + str([str(f) for f in found]))


# --------------------------------------------------------------------------- #
# the BLOCKED item ships with a fix that was run, not a suggestion
# --------------------------------------------------------------------------- #

# The exact anchor and replacement this stage reports for Welcome's loader
# (ATTACK B).  Welcome belongs to another package and is outside this
# territory, so the change is made HERE, in a copy, and executed -- a remedy
# nobody has run is a guess, and an anchor nobody has matched rots silently.
WELCOME_LOADER_ANCHOR = """    for location in locations:
        if (location / "sf_desktop.py").is_file():
            if str(location) not in sys.path:
                sys.path.insert(0, str(location))
            import sf_desktop
            return sf_desktop"""

WELCOME_LOADER_REPLACEMENT = """    for location in locations:
        path = location / "sf_desktop.py"
        if path.is_file():
            # Execute the file that was just checked. `import sf_desktop`
            # consults sys.modules BEFORE sys.path, so a module already
            # registered under that name is handed back and this existence
            # check decides nothing: a planted module was accepted with PKEXEC
            # back to the bare word and the install argv resolved through $PATH
            # again. spec_from_file_location never consults sys.modules.
            cached = sys.modules.get("sf_desktop")
            if cached is not None and getattr(cached, "__file__", None) == str(path):
                return cached
            spec = importlib.util.spec_from_file_location("sf_desktop", path)
            module = importlib.util.module_from_spec(spec)
            sys.modules["sf_desktop"] = module
            try:
                spec.loader.exec_module(module)
            except BaseException:
                sys.modules.pop("sf_desktop", None)
                raise
            return module"""

WELCOME_IMPORT_ANCHOR = "import json\nimport os\n"
WELCOME_IMPORT_REPLACEMENT = "import importlib.util\nimport json\nimport os\n"


class TheRemedyForWelcomesLoaderIsExact(unittest.TestCase):
    """ATTACK B in the front-end this stage may not edit.

    Welcome's `_load_desktop()` has the same defect the Control Center's
    loader had: it checks that the file exists, puts its directory on
    sys.path, and then resolves the module BY NAME. The gate reports it
    BLOCKED. These tests apply the reported replacement to a COPY and run it,
    so the report carries a fix that has been executed and an anchor that
    cannot rot without a test going red.
    """

    POISON = r'''
import importlib.machinery, sys, types
evil = types.ModuleType("sf_desktop")
evil.__file__ = "/tmp/evil.py"
evil.PKEXEC = "pkexec"
sys.modules["sf_desktop"] = evil
loader = importlib.machinery.SourceFileLoader("sf_welcome_qa", sys.argv[1])
module = types.ModuleType(loader.name)
module.__file__ = sys.argv[1]
loader.exec_module(module)
print(module.desktop.__file__)
print(module.desktop.PKEXEC)
'''

    WELCOME_REL = "packages/shadowfetch-welcome/src/shadowfetch-welcome"
    LIBRARY_REL = drift_gate.DESKTOP_LIBRARY

    def remedy_tree(self, tmp):
        """A copy of the tree with the reported replacement applied to Welcome.

        Shaped like the repo, because Welcome's own loader walks
        Path(__file__).resolve().parents looking for the library: a patched
        copy in a bare temp directory cannot find it and proves nothing.
        """
        fake = Path(tmp)
        for rel in GATE_FILES:
            copy = fake / rel
            copy.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / rel, copy)
        source = welcome_source()
        for anchor in (WELCOME_LOADER_ANCHOR, WELCOME_IMPORT_ANCHOR):
            self.assertEqual(1, source.count(anchor),
                             "the reported anchor no longer matches Welcome "
                             "exactly once; re-derive the remedy:\n" + anchor)
        source = source.replace(WELCOME_LOADER_ANCHOR, WELCOME_LOADER_REPLACEMENT)
        source = source.replace(WELCOME_IMPORT_ANCHOR, WELCOME_IMPORT_REPLACEMENT)
        (fake / self.WELCOME_REL).write_text(source, encoding="utf-8")
        return fake

    def test_the_remedy_makes_the_gate_stop_reporting_the_loader(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = self.remedy_tree(tmp)
            saved = drift_gate.ROOT
            drift_gate.ROOT = fake
            try:
                findings = drift_gate.check_desktop_helpers({})
            finally:
                drift_gate.ROOT = saved
        loaders = [f for f in findings if "resolves the module BY NAME" in f.detail]
        self.assertEqual([], loaders, [str(f) for f in loaders])
        self.assertEqual([], [f for f in findings if f.kind == "DRIFT"],
                         "the remedy introduced drift: "
                         + str([str(f) for f in findings if f.kind == "DRIFT"]))

    def test_the_patched_welcome_refuses_a_poisoned_sys_modules(self):
        """And it still loads the real library: the fix has to keep working,
        not just stop the finding."""
        with tempfile.TemporaryDirectory() as tmp:
            fake = self.remedy_tree(tmp)
            env = dict(os.environ, QT_QPA_PLATFORM="offscreen", HOME=tmp,
                       XDG_CONFIG_HOME=str(Path(tmp, "config")))
            done = subprocess.run(
                [sys.executable, "-c", self.POISON, str(fake / self.WELCOME_REL)],
                capture_output=True, text=True, timeout=180, env=env)
            self.assertEqual(0, done.returncode, done.stderr[-3000:])
            loaded, pkexec = done.stdout.split()
            self.assertEqual(str(fake / self.LIBRARY_REL), loaded,
                             "the patched loader accepted a module it never "
                             "checked")
        self.assertEqual("/usr/bin/pkexec", pkexec)


class WhatThisBarrierStillMisses(unittest.TestCase):
    """The edge of the detector, measured and recorded.

    NOT a wish list and not an accepted risk: it is the answer to "what could
    a rename or a new spelling still get past", written as something that goes
    RED the day one of these forms starts being caught -- at which point the
    line moves up into GateCatchesASecondImplementationByShape and this record
    shrinks by one. A barrier whose limits are only described in prose is a
    barrier whose limits nobody re-measures.

    Every entry below was run against the current check, not reasoned about.
    """

    WELCOME_REL = "packages/shadowfetch-welcome/src/shadowfetch-welcome"
    ANCHOR = "class NMWatcher(QObject):"

    # (label, plant) -- each one a second implementation the scanner cannot
    # fold or cannot recognise by shape.
    MISSED = (
        ("the argv head reached through a dict subscript",
         '_TABLE = {"p": "pkexec"}\n'
         "def _go(b):\n"
         '    return [_TABLE["p"], "/usr/libexec/x", "install", b]\n\n\n'),
        ("a catalog reader over a hard-coded list of filenames, which never "
         "enumerates the directory",
         '_FILES = ["a.json", "b.json"]\n'
         "def _read(d):\n"
         "    return [json.loads(Path(d, n).read_text()) for n in _FILES]\n\n\n"),
        ("a privileged helper under a name prefix nobody has added to "
         "PRIVILEGED_PREFIXES",
         "def _go():\n"
         '    return subprocess.run(["sf-bundle-install", "install", "x"])\n\n\n'),
        ("a reserved path built one character at a time",
         '_H = "".join(chr(c) for c in [47, 117, 115, 114])'
         ' + "/libexec/shadowfetch-hwscan"\n\n\n'),
    )

    def plant(self, code):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        fake = Path(tmp.name)
        for rel in GATE_FILES:
            copy = fake / rel
            copy.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / rel, copy)
        target = fake / self.WELCOME_REL
        source = target.read_text(encoding="utf-8")
        self.assertEqual(1, source.count(self.ANCHOR))
        target.write_text(source.replace(self.ANCHOR, code + self.ANCHOR),
                          encoding="utf-8")
        saved = drift_gate.ROOT
        drift_gate.ROOT = fake
        try:
            return [f for f in drift_gate.check_desktop_helpers({})
                    if f.kind == "DRIFT"]
        finally:
            drift_gate.ROOT = saved

    def test_the_recorded_misses_are_still_the_misses(self):
        improved = []
        for label, code in self.MISSED:
            if self.plant(code):
                improved.append(label)
        self.assertEqual([], improved,
                         "the barrier now catches these -- move each one into "
                         "GateCatchesASecondImplementationByShape as a test "
                         "that asserts the catch, and delete it here: "
                         + str(improved))

    def test_the_thing_that_makes_those_misses_survivable(self):
        """Each miss above is a front-end that stopped calling the library.
        None of them widens what the library itself will run: every program it
        executes is resolved from PROGRAMS by absolute path, which is the
        ENFORCED half of this seam and is tested in
        packages/shadowfetch-control-center/tests/test_desktop_library.py.
        """
        library = load_library()
        self.assertTrue(library.PROGRAMS)
        for name, (path, trust) in library.PROGRAMS.items():
            with self.subTest(program=name):
                self.assertTrue(path.startswith("/"), path)
        with self.assertRaises(library.UnknownProgram):
            library.trusted_program("sf-bundle-install")


if __name__ == "__main__":
    unittest.main(verbosity=2)
