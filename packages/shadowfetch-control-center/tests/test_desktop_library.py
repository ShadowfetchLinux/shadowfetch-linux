"""The shared desktop library and the trusted program table (W-30, invariant).

W-30 asks for one implementation of the desktop facts -- catalog, hwscan, net,
launch, bundle install argv -- shared by the Control Center and Welcome.
tools/drift_gate.py reports the divergence as BLOCKED:

    BLOCKED [desktop-helpers] sfcc/busutil.py + shadowfetch-welcome
      load_catalog(), the hwscan freshness rule and the five helper paths are
      still implemented twice, in two divergent shapes ...

Stage P landed the Control Center half: sfcc.desktop is that one
implementation, importable without Qt and without dbus so the other front-end
can adopt it.  Welcome is a different package and outside this stage's
territory, so THE SECOND COPY STILL EXISTS.  These tests hold the half that
shipped, and `SecondCopyIsStillThere` fails the day Welcome adopts the module,
so nobody has to remember to delete this note.

The permanent invariant is also tested here.  An executable whose output
establishes, verifies, enforces or attests a security fact must be invoked
through an explicit trusted absolute path with a defined trust classification:
no shutil.which, no PATH lookup, and the child's PATH pinned too.  It was live
twice in this package before Stage P -- `installed_map` decided which packages
a person is told they have from a bare `dpkg-query`, and `system_summary`
printed "System check passed" from a bare `systemctl`.
"""
import ast
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
CC = Path(__file__).resolve().parents[1]
SFCC = CC / "data/usr/share/shadowfetch/control-center/sfcc"
REPO = CC.parents[1]
WELCOME = REPO / "packages/shadowfetch-welcome/src/shadowfetch-welcome"
sys.path.insert(0, str(SFCC.parent))

from sfcc import desktop  # noqa: E402


class ImportableWithoutADisplay(unittest.TestCase):
    def test_the_shared_library_imports_no_qt_and_no_dbus(self):
        """A fact about the machine is not a widget. A helper that cannot be
        imported without PyQt cannot be shared with a front-end that does not
        use it the same way, cannot be unit tested cheaply, and cannot be
        reused by a CLI."""
        # Both files: the loader, and the library it loads. Reading only
        # sfcc/desktop.py stopped meaning anything the day the implementation
        # moved to shadowfetch-defaults -- the loader has no imports to speak
        # of, so the assertion passed while checking nothing.
        for path in (SFCC / "desktop.py", Path(desktop.__file__)):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            imported = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.update(alias.name.split(".")[0] for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imported.add(node.module.split(".")[0])
            for banned in ("PyQt6", "dbus", "sfcc"):
                with self.subTest(file=path.name, banned=banned):
                    self.assertNotIn(banned, imported)

    def test_it_can_be_imported_in_a_bare_interpreter(self):
        out = subprocess.run(
            [sys.executable, "-c",
             "import sys; sys.path.insert(0, sys.argv[1]); "
             "import importlib.util as u; "
             "spec = u.spec_from_file_location('d', sys.argv[2]); "
             "m = u.module_from_spec(spec); spec.loader.exec_module(m); "
             "print(m.TRUSTED_PATH)",
             str(SFCC.parent), str(SFCC / "desktop.py")],
            capture_output=True, text=True, timeout=60)
        self.assertEqual(0, out.returncode, out.stderr[-2000:])
        self.assertIn("/usr/bin", out.stdout)


class TrustedProgramTable(unittest.TestCase):
    """The invariant, as a property of this package's source and behaviour."""

    def test_every_declared_program_is_absolute_and_classified(self):
        self.assertTrue(desktop.PROGRAMS)
        for name, (path, trust) in desktop.PROGRAMS.items():
            with self.subTest(program=name):
                self.assertTrue(path.startswith("/"), path)
                self.assertIn(trust, ("system", "shadowfetch"))

    def test_an_undeclared_program_is_refused_not_guessed(self):
        with self.assertRaises(desktop.UnknownProgram):
            desktop.trusted_program("curl")

    def test_the_search_space_is_system_directories_only(self):
        for directory in desktop.TRUSTED_DIRS:
            with self.subTest(directory=directory):
                self.assertTrue(directory.startswith("/usr/")
                                or directory in ("/bin", "/sbin"))
        self.assertEqual(":".join(desktop.TRUSTED_DIRS), desktop.TRUSTED_PATH)

    def test_the_session_path_cannot_choose_the_binary(self):
        with tempfile.TemporaryDirectory() as attacker:
            forged = Path(attacker) / "systemctl"
            forged.write_text("#!/bin/sh\nexit 0\n")
            forged.chmod(0o755)
            with patch.dict(os.environ, {"PATH": attacker + ":" + os.environ.get("PATH", "")}):
                resolved = desktop.trusted_program("systemctl")
            if resolved is not None:
                self.assertNotIn(attacker, resolved)

    def test_no_module_in_this_package_resolves_a_program_through_path(self):
        """shutil.which, and subprocess/QProcess calls whose program is a bare
        name, are both PATH lookups. Neither may decide which binary runs."""
        offenders = []
        for path in sorted(SFCC.glob("*.py")):
            source = path.read_text(encoding="utf-8")
            for node in ast.walk(ast.parse(source)):
                if (isinstance(node, ast.Attribute) and node.attr == "which"
                        and getattr(node.value, "id", None) == "shutil"):
                    offenders.append(f"{path.name}:{node.lineno} shutil.which")
                if not isinstance(node, ast.Call):
                    continue
                target = getattr(node.func, "attr", None)
                if target not in ("run", "Popen", "start", "startDetached"):
                    continue
                if not node.args:
                    continue
                first = node.args[0]
                # A bare string program name, or a list whose first element is
                # one, is resolved by the loader against $PATH.
                if isinstance(first, ast.List) and first.elts:
                    first = first.elts[0]
                if (isinstance(first, ast.Constant) and isinstance(first.value, str)
                        and not first.value.startswith("/")):
                    offenders.append(f"{path.name}:{node.lineno} {first.value!r}")
        self.assertEqual([], offenders,
                         "a program is resolved through $PATH: " + str(offenders))

    def test_the_child_environment_pins_path_and_drops_loader_hooks(self):
        with patch.dict(os.environ, {"BASH_ENV": "/tmp/evil",
                                     "LD_PRELOAD": "/tmp/evil.so",
                                     "PYTHONPATH": "/tmp/evil"}):
            env = desktop.trusted_env()
        self.assertEqual(desktop.TRUSTED_PATH, env["PATH"])
        for hook in ("BASH_ENV", "LD_PRELOAD", "PYTHONPATH", "LD_AUDIT"):
            self.assertNotIn(hook, env)

    def test_a_cosmetic_lookup_is_a_different_function_from_a_trusted_one(self):
        """installed_command answers "is this tool on the machine" for names
        that come from the bundle catalog. It must never be the way a
        privileged launch resolves its binary, so the two are separate and
        only one of them refuses unknown names."""
        self.assertIsNone(desktop.installed_command("definitely-not-installed"))
        self.assertIsNone(desktop.installed_command("../../bin/sh"))
        # The library's own source. This test read sfcc/desktop.py, which has
        # been the LOADER since the module moved to shadowfetch-defaults, so it
        # was failing on a sentence that had moved with the function.
        source = Path(desktop.__file__).read_text(encoding="utf-8")
        self.assertIn("Never route a privileged launch through this function",
                      source)


class EveryReExportedNameExists(unittest.TestCase):
    """busutil re-exports sfcc.desktop; a name that moved and was not
    re-exported is an AttributeError nobody sees until a button is clicked.

    That is exactly what happened while Stage P was being written: four pages
    called `busutil.desktop.SYSTEMCTL` after busutil stopped importing the
    module under that name. Every page still constructed, every test passed,
    and Ignite's start button would have raised on the first click.
    """

    def test_every_busutil_attribute_the_pages_use_is_defined(self):
        from sfcc import busutil
        missing = []
        for path in sorted(SFCC.glob("*.py")):
            if path.name == "busutil.py":
                continue
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if (isinstance(node, ast.Attribute)
                        and getattr(node.value, "id", None) == "busutil"
                        and not hasattr(busutil, node.attr)):
                    missing.append(f"{path.name}:{node.lineno} busutil.{node.attr}")
        self.assertEqual([], missing, "undefined busutil names: " + str(missing))

    def test_every_re_export_names_the_same_object_as_the_source(self):
        """A re-export that drifts into a copy is the duplication coming back."""
        from sfcc import busutil
        for name in dir(desktop):
            if name.startswith("_") or not hasattr(busutil, name):
                continue
            with self.subTest(name=name):
                self.assertIs(getattr(desktop, name), getattr(busutil, name))


class TerminalCommandIsNotALoginShell(unittest.TestCase):
    def setUp(self):
        self.calls = []
        patcher = patch("subprocess.Popen",
                        side_effect=lambda argv, **kw: self.calls.append((argv, kw)))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_never_uses_a_login_shell(self):
        with patch.object(desktop, "trusted_program",
                          side_effect=lambda name: "/usr/bin/" + name):
            desktop.terminal_command("shadowfetch-gpu")
        argv, kwargs = self.calls[0]
        joined = " ".join(argv)
        self.assertNotIn("-lc", joined,
                         "a login shell sources user-writable ~/.profile before "
                         "running a tool that asks for an admin password")
        self.assertNotIn("bash", joined)
        self.assertEqual(desktop.TRUSTED_PATH, kwargs["env"]["PATH"])

    def test_arguments_are_quoted_not_concatenated_into_shell_syntax(self):
        with patch.object(desktop, "trusted_program",
                          side_effect=lambda name: "/usr/bin/" + name):
            desktop.terminal_command("fireproof", ["update; rm -rf /"])
        argv, _ = self.calls[0]
        script = argv[-1]
        self.assertIn("'update; rm -rf /'", script)

    def test_a_missing_tool_launches_nothing(self):
        with patch.object(desktop, "trusted_program", return_value=None):
            self.assertFalse(desktop.terminal_command("shadowfetch-gpu"))
            self.assertFalse(desktop.start_detached("shadowfetch-welcome"))
        self.assertEqual([], self.calls)


class BundleInstallArgv(unittest.TestCase):
    """One builder for the privileged argv both front-ends offer."""

    def test_pkexec_is_named_by_absolute_path(self):
        with patch.object(desktop, "trusted_program",
                          side_effect=lambda n: {"pkexec": "/usr/bin/pkexec",
                                                 "shadowfetch-bundle-install":
                                                 "/usr/libexec/shadowfetch-bundle-install"}[n]):
            argv = desktop.bundle_install_argv("ignition-creator")
        self.assertEqual(["/usr/bin/pkexec",
                          "/usr/libexec/shadowfetch-bundle-install",
                          "install", "ignition-creator"], argv)

    def test_the_helper_gets_a_verb_before_the_catalog_id(self):
        """W-08: the catalog id was passed where the helper wants a verb, so
        the action failed AFTER the user typed their administrator password."""
        helper = (REPO / "packages/shadowfetch-welcome/data/usr/libexec"
                  / "shadowfetch-bundle-install").read_text()
        self.assertIn("verb, rest = args[0], args[1:]", helper)
        self.assertIn('if verb == "install":', helper)
        with patch.object(desktop, "trusted_program",
                          side_effect=lambda n: "/x/" + n):
            argv = desktop.bundle_install_argv("ignition-creator")
        self.assertEqual("install", argv[2])

    def test_a_missing_helper_returns_nothing_rather_than_widening_the_grant(self):
        with patch.object(desktop, "trusted_program", return_value=None):
            self.assertIsNone(desktop.bundle_install_argv("ignition-creator"))
            self.assertIsNone(desktop.apt_snapshot_toggle_argv(True))

    def test_a_catalog_id_that_is_not_one_is_refused(self):
        with patch.object(desktop, "trusted_program",
                          side_effect=lambda n: "/x/" + n):
            for bad in ("", "../../etc/passwd", "--root=/", "a/b"):
                with self.subTest(bad=bad):
                    self.assertIsNone(desktop.bundle_install_argv(bad))

    def test_both_pages_build_it_here_rather_than_spelling_it_out(self):
        for page in ("software_page.py", "workbench_page.py"):
            source = (SFCC / page).read_text(encoding="utf-8")
            body = "\n".join(line for line in source.splitlines()
                             if not line.lstrip().startswith("#"))
            with self.subTest(page=page):
                self.assertIn("bundle_install_argv", body)
                self.assertNotIn('"pkexec"', body,
                                 "the argv is spelled out again, with pkexec as "
                                 "a bare name $PATH resolves")


class CatalogAndHwscan(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        patcher = patch.object(desktop, "CATALOG_DIR", str(self.dir))
        patcher.start()
        self.addCleanup(patcher.stop)

    def write(self, name, payload):
        (self.dir / name).write_text(json.dumps(payload), encoding="utf-8")

    def test_a_file_may_hold_one_record_or_an_array_of_them(self):
        """Welcome's copy accepted only the single-record form. Two readers of
        the same directory disagreeing about what is in it is the divergence
        W-30 names."""
        self.write("one.json", {"id": "a", "kind": "preset"})
        self.write("many.json", [{"id": "b", "kind": "preset"},
                                 {"id": "c", "kind": "preset"}])
        self.assertEqual(["a", "b", "c"],
                         sorted(r["id"] for r in desktop.load_catalog()))

    def test_an_unreadable_file_is_skipped_not_fatal(self):
        self.write("good.json", {"id": "a", "kind": "preset"})
        (self.dir / "bad.json").write_text("{not json", encoding="utf-8")
        self.assertEqual(["a"], [r["id"] for r in desktop.load_catalog()])

    def test_the_kind_filter_and_the_keyed_view_read_the_same_source(self):
        self.write("p.json", {"id": "a", "kind": "preset"})
        self.write("m.json", {"id": "b", "kind": "media"})
        self.assertEqual(["a"], [r["id"] for r in desktop.load_catalog(("preset",))])
        self.assertEqual({"a", "b"}, set(desktop.catalog_by_id(None)))

    def test_the_freshness_rule_lives_in_one_place(self):
        stale = self.dir / "hwscan.json"
        stale.write_text("{}", encoding="utf-8")
        os.utime(stale, (1, 1))
        with patch.object(desktop, "HWSCAN_JSON", str(stale)):
            self.assertFalse(desktop.hwscan_is_fresh(str(stale)))
            os.utime(stale, None)
            self.assertTrue(desktop.hwscan_is_fresh(str(stale)))


class SystemSummaryDoesNotInventGoodNews(unittest.TestCase):
    def test_an_unanswered_systemctl_is_not_a_passing_check(self):
        """It used to be. `systemctl --failed` failing to run fell through to a
        generic except and printed a reassuring header."""
        with patch.object(desktop, "failed_units", return_value=None):
            state, _detail = desktop.system_summary()
        self.assertEqual("Status unavailable", state)

    def test_no_failed_units_is_reported_as_such(self):
        with patch.object(desktop, "failed_units", return_value=[]):
            state, detail = desktop.system_summary()
        self.assertEqual("System check passed", state)
        self.assertIn("No failed system units", detail)

    def test_failed_units_are_reported_as_needing_attention(self):
        with patch.object(desktop, "failed_units", return_value=["a.service"]):
            state, detail = desktop.system_summary()
        self.assertEqual("Needs attention", state)
        self.assertIn("1 failed", detail)


# SecondCopyIsStillThere lived here. It asserted that Welcome STILL had its own
# load_catalog/HWSCAN_CLI and still spelled ["pkexec", BUNDLE_HELPER, "install"]
# out for itself, and its docstring said to delete it the day Welcome adopted
# the shared module. Welcome adopted it; the class was left behind and had been
# failing ever since -- a suite reporting the opposite of the truth. The claim
# it used to hold is now held from the other side, by
# packages/shadowfetch-defaults/tests/test_shared_desktop_library.py and by the
# desktop-helpers drift-gate check.


class TheLoaderExecutesTheFileItChecked(unittest.TestCase):
    """ATTACK B, as a test.

    `_load()` checked that <dir>/sf_desktop.py existed, inserted <dir> on
    sys.path and then ran `import sf_desktop` -- and `import` consults
    sys.modules BEFORE sys.path, so the existence check it had just performed
    decided nothing. An adversarial verifier registered a module under that
    name and got it back:

        sfcc.desktop.__file__ = /tmp/evil.py
        PKEXEC = pkexec
        argv   = ['pkexec', '/tmp/evil-helper', 'install', 'x']

    PKEXEC is a bare name again there, and the argv that asks for an
    administrator password is resolved through $PATH again. This needs code
    execution inside the Control Center process already, so it is defence in
    depth and not a privilege boundary -- but it is the PATH-shadowing shape
    this program has been bitten by before, and the loader's docstring rests
    its safety case on sfcc.desktop BEING the library.

    A subprocess, because sfcc.desktop is imported at module scope up here and
    the poisoning has to happen before the first import.
    """

    POISON = r'''
import sys, types
sys.path.insert(0, sys.argv[1])
evil = types.ModuleType("sf_desktop")
evil.__file__ = "/tmp/evil.py"
evil.PKEXEC = "pkexec"
evil.bundle_install_argv = lambda b: ["pkexec", "/tmp/evil-helper", "install", b]
sys.modules["sf_desktop"] = evil
from sfcc import desktop
print(desktop.__file__)
print(desktop.PKEXEC)
print(sys.modules["sf_desktop"].__file__)
'''

    IDENTITY = r'''
import sys
sys.path.insert(0, sys.argv[1])
from sfcc import desktop
import sfcc.desktop
print(sys.modules["sf_desktop"] is desktop)
print(sfcc.desktop is desktop)
print(desktop.__file__)
'''

    def run_child(self, script):
        done = subprocess.run([sys.executable, "-c", script, str(SFCC.parent)],
                              capture_output=True, text=True, timeout=120,
                              env=dict(os.environ, QT_QPA_PLATFORM="offscreen"))
        self.assertEqual(0, done.returncode, done.stderr[-2000:])
        return done.stdout.split()

    def test_a_module_planted_in_sys_modules_is_not_the_library(self):
        loaded, pkexec, registered = self.run_child(self.POISON)
        self.assertNotEqual("/tmp/evil.py", loaded,
                            "the loader accepted a module it never checked")
        self.assertTrue(loaded.endswith("sf_desktop.py"), loaded)
        self.assertEqual("/usr/bin/pkexec", pkexec,
                         "PKEXEC came from somewhere other than the library")
        self.assertNotEqual("/tmp/evil.py", registered,
                            "the poisoned entry was left in sys.modules for the "
                            "next importer to find")

    def test_the_module_is_still_one_object_under_both_names(self):
        """The property the loader exists for, and the one a fix to ATTACK B
        could easily break: loading by file must not make a SECOND module
        object for anything that imports sf_desktop by name."""
        same_entry, same_alias, loaded = self.run_child(self.IDENTITY)
        self.assertEqual("True", same_entry)
        self.assertEqual("True", same_alias)
        self.assertTrue(loaded.endswith("sf_desktop.py"), loaded)

    def test_the_loader_does_not_resolve_the_module_by_name(self):
        """The shape, not just the behaviour: a later edit that reintroduces
        `import sf_desktop` reintroduces the hole, because import consults
        sys.modules first however carefully the file was checked."""
        tree = ast.parse((SFCC / "desktop.py").read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertNotEqual("sf_desktop", alias.name)
            if isinstance(node, ast.ImportFrom):
                self.assertNotEqual("sf_desktop", node.module)
        self.assertIn("spec_from_file_location",
                      (SFCC / "desktop.py").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
