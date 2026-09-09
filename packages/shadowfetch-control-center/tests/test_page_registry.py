"""The Control Center's page registry and its plugin contract (W-31, W-32).

Phase 3 Step 24 deferred both findings and pinned the invariants they pointed
at in this file instead.  Stage P implemented them, so these tests changed from
recording a coupling to exercising the thing that replaced it:

  W-31  app.py held the registry as TWO lists joined by list index, plus a
        third alias table whose values had to name a key in the first.  There
        is now one `sfcc.pages.REGISTRY`; the alias map, the row lookup and the
        badge are DERIVED from it, so the classes of bug the old pin watched
        for -- a page in one list and not the other, an alias naming a section
        that does not exist, `next(...)` raising StopIteration when a hard-coded
        key leaves the list -- are not expressible.  What is still worth a test
        is the behaviour: routes land on the page they name, and the optional
        half of the protocol degrades honestly.

  W-32  the plugin seam is a cross-package import that EXECUTES another
        package's application script inside this process.  The tests below are
        adversarial: a plugin that exits at import, one that declares the wrong
        contract version, one that declares none, one whose entry point raises,
        and one that returns nothing.  Each must leave the Control Center
        standing and produce a reason a person can read.

Run with QT_QPA_PLATFORM=offscreen python3 -m unittest discover
-s packages/shadowfetch-control-center/tests
"""
import ast
import os
import sys
import textwrap
import unittest
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
CC = Path(__file__).resolve().parents[1]
SFCC = CC / "data/usr/share/shadowfetch/control-center/sfcc"
REPO = CC.parents[1]
FIREPROOF = REPO / "packages/shadowfetch-fireproof"
PLUGIN = FIREPROOF / "data/usr/share/shadowfetch/control-center/sfcc/fireproof_page.py"
FIREPROOF_APP = FIREPROOF / "data/usr/bin/shadowfetch-fireproof"
sys.path.insert(0, str(SFCC.parent))

from sfcc import pages, plugins  # noqa: E402
from sfcc.pages import PageContext  # noqa: E402

from PyQt6.QtCore import QObject, pyqtSignal  # noqa: E402


class StubFirewatch(QObject):
    """The sensor client the shell hands the pages, without a bus.

    A section that needs sensors must still be constructible in a test, and a
    None here would only prove that None is not a FirewatchClient.
    """

    updated = pyqtSignal(dict)

    def __init__(self):
        super().__init__()
        self.last = {"available": False}

    def acquire(self):
        pass

    def release(self):
        pass


CONTEXT = PageContext(open_route=lambda _route: None,
                      firewatch=StubFirewatch(), version="test")


class OneRegistry(unittest.TestCase):
    """One list, and everything else read out of it."""

    def test_app_no_longer_carries_a_second_list_of_pages(self):
        """The failure this replaces: two lists, joined by list index."""
        tree = ast.parse((SFCC / "app.py").read_text(encoding="utf-8"))
        literals = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.List)
            and isinstance(node.targets[0], ast.Attribute)
            and node.targets[0].attr == "pages"
            and any(isinstance(element, ast.Call) for element in node.value.elts)
        ]
        self.assertEqual([], literals,
                         "app.py builds self.pages from a list of constructor "
                         "calls again; the sidebar and the pages are two lists "
                         "once more")

    def test_every_section_names_a_page_that_can_be_built(self):
        # A QApplication FIRST. Constructing a QWidget without one is a Qt
        # fatal, not an exception: the interpreter aborts and the suite ends
        # with no verdict for this test or any test after it, which reads in a
        # log exactly like a pass. offscreen is set at import above, so this
        # needs no display.
        from PyQt6.QtWidgets import QApplication
        application = QApplication.instance() or QApplication([])
        self.addCleanup(application.processEvents)
        for section in pages.REGISTRY:
            with self.subTest(section=section.key):
                widget = section.build(CONTEXT)
                self.addCleanup(widget.deleteLater)
                self.assertIsNotNone(widget)

    def test_the_workspaces_row_is_served_by_the_class_named_for_it(self):
        """W-31 asks for this rename. It shipped as AgentsPage behind a row
        labelled Workspaces, which is the kind of mismatch that survives for
        years because nothing but a reader notices it."""
        section = next(s for s in pages.REGISTRY if s.key == "workspaces")
        self.assertEqual("WorkspacesPage", section.factory)
        self.assertEqual("sfcc.workspaces_page", section.module)
        self.assertFalse((SFCC / "agents_page.py").exists(),
                         "the old module is still shipped beside the new one")

    def test_agents_still_routes_to_workspaces(self):
        """The rename must not break a deep link, a .desktop file or the
        servicemenu, all of which are installed on machines already."""
        for word in ("agents", "local-ai", "ai", "buzz", "workspaces"):
            with self.subTest(word=word):
                resolved = pages.resolve(word)
                self.assertIsNotNone(resolved)
                self.assertEqual("workspaces", pages.REGISTRY[resolved[0]].key)

    def test_every_historic_route_word_still_resolves(self):
        """The alias table app.py used to carry, as an external expectation."""
        historic = {
            "missions": "missions", "mission-control": "missions",
            "home": "missions", "grok-bot": "grok-bot", "grokbot": "grok-bot",
            "guide": "guide", "passport": "guide", "system-passport": "guide",
            "workbench": "workbench", "forge": "workbench",
            "projects": "workbench", "ignite": "ignite", "ember": "ignite",
            "watch": "watch", "firewatch": "watch", "recover": "recover",
            "phoenix": "recover", "recovery": "recover",
            "workspaces": "workspaces", "local-ai": "workspaces",
            "agents": "workspaces", "ai": "workspaces", "buzz": "workspaces",
            "drivers": "drivers", "software": "software",
            "software-updates": "software", "updates": "software",
            "bundles": "software",
        }
        table = pages.aliases()
        for word, key in historic.items():
            with self.subTest(word=word):
                self.assertEqual(key, table.get(word))

    def test_two_sections_cannot_claim_the_same_route_word(self):
        clash = pages.Section("other", "Other", None, "sfcc.drivers_page",
                              "DriversPage", ("software",))
        original = pages.REGISTRY
        pages.REGISTRY = original + (clash,)
        try:
            with self.assertRaises(ValueError):
                pages.aliases()
        finally:
            pages.REGISTRY = original

    def test_an_unknown_route_is_ignored_rather_than_raising(self):
        self.assertIsNone(pages.resolve("no-such-section"))
        self.assertIsNone(pages.resolve(""))
        self.assertIsNone(pages.resolve("::"))

    def test_the_deep_link_tail_reaches_the_page(self):
        row, rest = pages.resolve("software:bundles")
        self.assertEqual("software", pages.REGISTRY[row].key)
        self.assertEqual(["bundles"], rest)


class TheOptionalHalfOfTheProtocol(unittest.TestCase):
    """badge_count and blocking_reason, and what a page that has neither does."""

    def test_a_page_with_no_badge_has_no_badge(self):
        self.assertIsNone(pages.section_badge(object()))

    def test_a_badge_that_raises_does_not_take_the_window_down(self):
        class Angry:
            def badge_count(self):
                raise RuntimeError("fireproofd is not answering")
        self.assertIsNone(pages.section_badge(Angry()))

    def test_zero_and_none_are_both_no_badge(self):
        class Zero:
            def badge_count(self):
                return 0

        class Absent:
            def badge_count(self):
                return None
        self.assertIsNone(pages.section_badge(Zero()))
        self.assertIsNone(pages.section_badge(Absent()))

    def test_a_count_is_shown(self):
        class Three:
            def badge_count(self):
                return 3
        self.assertEqual(3, pages.section_badge(Three()))

    def test_the_page_supplies_the_sentence_not_the_shell(self):
        class Busy:
            def blocking_reason(self):
                return "A restore is running."
        self.assertEqual("A restore is running.",
                         pages.section_blocking_reason(Busy()))
        self.assertIsNone(pages.section_blocking_reason(object()))

    def test_a_blocking_reason_that_raises_does_not_trap_the_window_shut(self):
        """Failing open matters more than failing closed here: a window a
        person cannot close is worse than one that closes during an operation
        the page could not describe."""
        class Angry:
            def blocking_reason(self):
                raise RuntimeError("boom")
        self.assertIsNone(pages.section_blocking_reason(Angry()))

    def test_the_shell_asks_every_page_for_both(self):
        source = (SFCC / "app.py").read_text(encoding="utf-8")
        self.assertNotIn('key == "software"', source,
                         "the shell hard-codes which section has a badge again")
        self.assertNotIn("review_pending", source,
                         "the shell reads one page's attribute again instead of "
                         "asking every page for its reason")
        self.assertIn("section_badge", source)
        self.assertIn("section_blocking_reason", source)


def write_plugin(directory: Path, name: str, body: str) -> Path:
    path = directory / (name + ".py")
    path.write_text(textwrap.dedent(body), encoding="utf-8")
    return path


class PluginContractIsEnforced(unittest.TestCase):
    """Adversarial: every one of these must leave the window standing."""

    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def load(self, name, body):
        return plugins.load_plugin(write_plugin(self.dir, name, body), CONTEXT)

    def test_a_plugin_that_exits_at_import_is_contained(self):
        """This is the shipped shape: importing the Fireproof page executes an
        application script that raises SystemExit at module scope."""
        result = self.load("exiter", """
            PAGE_API = 1
            raise SystemExit(2)
            """)
        self.assertFalse(result.ok)
        self.assertIn("SystemExit", result.error)

    def test_a_plugin_that_calls_sys_exit_is_contained(self):
        result = self.load("quitter", """
            import sys
            PAGE_API = 1
            sys.exit("usage: shadowfetch-fireproof [--help]")
            """)
        self.assertFalse(result.ok)
        self.assertIn("SystemExit", result.error)

    def test_a_plugin_declaring_no_contract_version_is_refused(self):
        result = self.load("undeclared", """
            def build_page(context):
                return object()
            """)
        self.assertFalse(result.ok)
        self.assertIn("PAGE_API", result.error)

    def test_a_plugin_declaring_the_wrong_version_is_refused_not_called(self):
        result = self.load("future", """
            PAGE_API = 99
            def build_page(context):
                raise AssertionError("build_page must not be called")
            """)
        self.assertFalse(result.ok)
        self.assertIn("99", result.error)

    def test_a_plugin_with_no_entry_point_is_refused(self):
        result = self.load("empty", """
            PAGE_API = 1
            """)
        self.assertFalse(result.ok)
        self.assertIn("build_page", result.error)

    def test_an_entry_point_that_raises_is_contained_with_its_reason(self):
        result = self.load("thrower", """
            PAGE_API = 1
            def build_page(context):
                raise ValueError("the daemon is not on the bus")
            """)
        self.assertFalse(result.ok)
        self.assertIn("the daemon is not on the bus", result.error)

    def test_an_entry_point_returning_nothing_is_a_failure_not_a_page(self):
        result = self.load("nothing", """
            PAGE_API = 1
            def build_page(context):
                return None
            """)
        self.assertFalse(result.ok)

    def test_a_conforming_plugin_is_built_with_the_context(self):
        result = self.load("good", """
            PAGE_API = 1
            SEEN = []
            def build_page(context):
                SEEN.append(context)
                return {"route": getattr(context, "open_route", None)}
            """)
        self.assertTrue(result.ok, result.error)
        self.assertIs(CONTEXT.open_route, result.widget["route"])

    def test_a_plugin_cannot_be_imported_under_an_sfcc_module_name(self):
        """A plugin loaded as `sfcc.theme` would be a third-party page
        replacing the host's palette, stylesheet and process dialog."""
        before = dict(sys.modules)
        self.load("theme", """
            PAGE_API = 1
            def build_page(context):
                return object()
            """)
        self.assertIs(before.get("sfcc.theme"), sys.modules.get("sfcc.theme"))
        for name in set(sys.modules) - set(before):
            with self.subTest(name=name):
                self.assertFalse(name.startswith("sfcc."), name)

    def test_a_failed_import_leaves_no_half_built_module_behind(self):
        self.load("halfbuilt", """
            PAGE_API = 1
            raise SystemExit(1)
            """)
        self.assertNotIn("sfcc_plugin_halfbuilt", sys.modules)

    def test_keyboard_interrupt_still_reaches_the_application(self):
        """Containment is for the plugin's failures, not for the person's."""
        path = write_plugin(self.dir, "interrupted", """
            PAGE_API = 1
            raise KeyboardInterrupt
            """)
        with self.assertRaises(KeyboardInterrupt):
            plugins.load_plugin(path, CONTEXT)


class TheUpdatesSeam(unittest.TestCase):
    """The one real plugin, and the mount that has to survive it."""

    def test_the_plugin_is_installed_into_the_control_centre_package_dir(self):
        """Still true, and still the finding: shadowfetch-fireproof writes a
        module into shadowfetch-control-center's own Python package. The
        contract in sfcc.plugins exists; this plugin has not adopted it, and
        that package is outside Stage P's file territory."""
        install = (FIREPROOF / "debian/shadowfetch-fireproof.install").read_text()
        self.assertIn(
            "data/usr/share/shadowfetch/control-center/sfcc/fireproof_page.py",
            install)

    def test_the_loader_and_the_plugin_agree_on_the_legacy_name(self):
        self.assertEqual("sfcc.fireproof_page", plugins.LEGACY_UPDATES_MODULE)
        self.assertEqual("FireproofPage", plugins.LEGACY_UPDATES_CLASS)
        self.assertIn("FireproofPage = _mod.FireproofPage",
                      PLUGIN.read_text(encoding="utf-8"))

    def test_the_plugin_loads_the_script_the_package_ships(self):
        plugin = PLUGIN.read_text(encoding="utf-8")
        self.assertIn('_SCRIPT = "/usr/bin/shadowfetch-fireproof"', plugin)
        install = (FIREPROOF / "debian/shadowfetch-fireproof.install").read_text()
        self.assertRegex(install, r"data/usr/bin/shadowfetch-fireproof\s+usr/bin/")
        self.assertTrue(FIREPROOF_APP.is_file())

    def test_the_script_exits_the_process_at_module_scope(self):
        """This is why containment cannot be `except Exception`. The import
        executes this script inside the Control Center's own process, and these
        statements run at module scope, not under __main__."""
        app = ast.parse(FIREPROOF_APP.read_text(encoding="utf-8"))
        guarded = {
            name.id
            for branch in app.body if isinstance(branch, ast.If)
            for name in ast.walk(branch.test) if isinstance(name, ast.Name)
        }
        self.assertIn("__name__", guarded, "the __main__ guard moved")
        top_level_exits = [
            node.lineno
            for branch in app.body
            if isinstance(branch, ast.If) and not any(
                isinstance(n, ast.Name) and n.id == "__name__"
                for n in ast.walk(branch.test))
            for node in ast.walk(branch)
            if isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call)
            and getattr(node.exc.func, "id", None) == "SystemExit"
        ]
        self.assertTrue(top_level_exits,
                        "if the script stopped exiting at module scope, this "
                        "seam got safer; relax the guard deliberately")

    def test_the_mount_survives_a_plugin_that_exits(self):
        source = (SFCC / "software_page.py").read_text(encoding="utf-8")
        self.assertIn("plugins.load_updates_page", source,
                      "Software & Updates mounts the plugin inline again "
                      "instead of through the contract's loader")
        loader = (SFCC / "plugins.py").read_text(encoding="utf-8")
        self.assertIn("except BaseException", loader)

    def test_an_absent_plugin_is_an_ordinary_missing_page_not_an_error(self):
        """shadowfetch-fireproof is a Recommends. On a system without it the
        built-in updates card is the intended screen."""
        if (SFCC / "fireproof_page.py").exists():  # pragma: no cover
            self.skipTest("the legacy plugin is present in this tree")
        result = plugins.load_updates_page(CONTEXT)
        self.assertFalse(result.ok)
        self.assertIn("ModuleNotFoundError", result.error)
        self.assertFalse(plugins.legacy_plugin_installed())


if __name__ == "__main__":
    unittest.main(verbosity=2)
