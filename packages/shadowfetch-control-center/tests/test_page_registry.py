"""The Control Center's page registry and its one out-of-tree plugin.

Phase 3 Step 24 re-examined W-31 (a Page protocol and a single registry) and
W-32 (an explicit plugin contract for fireproof_page.py) and left both
DEFERRED: neither is on the path of any Phase 3 UI work, and W-31 would change
the constructor of every page class including missions_page.py, which Phase 3
is editing.

What is NOT deferred is the invariant each finding was pointed at. app.py
carries the registry as two lists that are joined by nothing but list index,
and the plugin seam is a cross-package import with no declared relationship in
either direction and, until this file, no test anywhere in the tree. Both are
pinned here so a silent break is impossible while the refactors wait.
"""
import ast
import unittest
from pathlib import Path

CC = Path(__file__).resolve().parents[1]
SFCC = CC / "data/usr/share/shadowfetch/control-center/sfcc"
REPO = CC.parents[1]
FIREPROOF = REPO / "packages/shadowfetch-fireproof"
PLUGIN = FIREPROOF / "data/usr/share/shadowfetch/control-center/sfcc/fireproof_page.py"
FIREPROOF_APP = FIREPROOF / "data/usr/bin/shadowfetch-fireproof"

APP = SFCC / "app.py"
TREE = ast.parse(APP.read_text(encoding="utf-8"))

# The registry app.py encodes only positionally. Until W-31 replaces the two
# lists with one, this pairing lives here, where a change to either list that
# is not made to the other fails.
REGISTRY = [
    ("missions", "MissionsPage"),
    ("grok-bot", "GrokBotPage"),
    ("guide", "GuidePage"),
    ("workbench", "WorkbenchPage"),
    ("ignite", "EmberPage"),
    ("watch", "FirewatchPage"),
    ("recover", "PhoenixPage"),
    ("workspaces", "AgentsPage"),
    ("drivers", "DriversPage"),
    ("software", "SoftwarePage"),
]


def module_assign(name):
    for node in TREE.body:
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == name for t in node.targets):
            return node.value
    raise AssertionError(f"{name} is no longer a module-level assignment")


def section_keys():
    return [element.elts[0].value for element in module_assign("SECTIONS").elts]


def alias_targets():
    node = module_assign("ALIASES")
    return {key.value: value.value for key, value in zip(node.keys, node.values)}


def page_classes():
    for node in ast.walk(TREE):
        if not (isinstance(node, ast.Assign) and isinstance(node.value, ast.List)):
            continue
        target = node.targets[0]
        if (isinstance(target, ast.Attribute) and target.attr == "pages"
                and isinstance(target.value, ast.Name) and target.value.id == "self"):
            return [element.func.id for element in node.value.elts]
    raise AssertionError("self.pages is no longer a list literal")


class SidebarAndPagesAgree(unittest.TestCase):
    """`_section_changed` and `open_route` index self.pages with the sidebar
    row. A page inserted into one list and not the other silently shows the
    wrong screen; a section key removed from SECTIONS turns the `next(...)`
    in `_refresh_badge` and `open_route` into an uncaught StopIteration."""

    def test_the_two_lists_are_the_same_length(self):
        self.assertEqual(len(section_keys()), len(page_classes()))

    def test_every_row_shows_the_page_it_names(self):
        self.assertEqual(list(zip(section_keys(), page_classes())), REGISTRY)

    def test_the_workspaces_row_still_shows_the_class_named_for_agents(self):
        """W-31 also asks for this rename. It is deferred, so the mismatch is
        recorded rather than hidden: `workspaces` is served by `AgentsPage`."""
        pairing = dict(zip(section_keys(), page_classes()))
        self.assertEqual(pairing["workspaces"], "AgentsPage")

    def test_every_alias_resolves_to_a_real_section(self):
        keys = set(section_keys())
        for alias, target in alias_targets().items():
            with self.subTest(alias=alias):
                self.assertIn(target, keys)

    def test_the_only_badged_section_exists(self):
        source = APP.read_text(encoding="utf-8")
        self.assertIn('if key == "software"', source,
                      "the badge lookup moved; it raises StopIteration if the "
                      "key it searches for is not a section")
        self.assertIn("software", section_keys())


class FireproofPluginSeam(unittest.TestCase):
    """shadowfetch-fireproof writes a module into shadowfetch-control-center's
    Python package. Neither debian/control mentions the other, so nothing but
    this file couples the two halves."""

    def test_the_plugin_is_installed_into_the_control_centre_package_dir(self):
        install = (FIREPROOF / "debian/shadowfetch-fireproof.install").read_text()
        self.assertIn(
            "data/usr/share/shadowfetch/control-center/sfcc/fireproof_page.py",
            install)

    def test_the_importer_and_the_plugin_agree_on_the_name(self):
        mount = (SFCC / "software_page.py").read_text(encoding="utf-8")
        self.assertIn("from sfcc.fireproof_page import FireproofPage", mount)
        self.assertIn("FireproofPage = _mod.FireproofPage",
                      PLUGIN.read_text(encoding="utf-8"))

    def test_the_plugin_loads_the_script_the_package_ships(self):
        plugin = PLUGIN.read_text(encoding="utf-8")
        self.assertIn('_SCRIPT = "/usr/bin/shadowfetch-fireproof"', plugin)
        install = (FIREPROOF / "debian/shadowfetch-fireproof.install").read_text()
        self.assertRegex(install,
                         r"data/usr/bin/shadowfetch-fireproof\s+usr/bin/")
        self.assertTrue(FIREPROOF_APP.is_file())

    def test_the_script_exits_the_process_at_module_scope(self):
        """This is why the guard below cannot be `except Exception`. The
        import executes this script inside the Control Center's own process,
        and these statements run at module scope, not under __main__."""
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
        mount = (SFCC / "software_page.py").read_text(encoding="utf-8")
        block = mount[mount.index("from sfcc.fireproof_page import"):][:900]
        self.assertIn("except BaseException:", block)
        self.assertNotIn("except Exception:", block,
                         "SystemExit is not an Exception: this clause would "
                         "let the plugin take the Control Center down")


if __name__ == "__main__":
    unittest.main(verbosity=2)
