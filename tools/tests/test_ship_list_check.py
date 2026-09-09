"""The ship-list check, and proof that each of its four properties can fail.

A gate that has only ever been run against a tree it passes is not evidence of
anything. Every check here is run twice: once against the real tree, and once
against a tree mutated to reintroduce the exact defect the check exists for --

  * shadowfetch-fireproof dropping a Python module into the Control Center's
    package with neither debian/control naming the other;
  * shadowfetch-desktop losing a pillar, so installing the metapackage stops
    installing the product;
  * a live-build package list supplying a Shadowfetch package the graph does
    not reach, which is how Mission Control, Ember, Firewatch, Phoenix,
    Fireproof, hwscan and the launcher reached the ISO through 4.0.0;
  * a payload file in Git that no .install line ships and no
    debian/not-installed declares.
"""
import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import ship_list_check as ship  # noqa: E402


class TheRealTree(unittest.TestCase):
    def test_every_property_holds_on_this_tree(self):
        ship.check_all()


class PrivateNamespaceSharing(unittest.TestCase):
    """usr/share/shadowfetch/<name> is one package's directory and another
    package's plugin point. Sharing it without a declared relationship is the
    Fireproof/Control Center seam, reproduced here in miniature."""

    SHIP = {
        "owner": {"usr/share/shadowfetch/thing/core.py": Path("data/core.py")},
        "plugin": {"usr/share/shadowfetch/thing/extra.py": Path("data/extra.py")},
    }

    def test_an_undeclared_module_drop_fails(self):
        stanzas = {"owner": {"Package": "owner"}, "plugin": {"Package": "plugin"}}
        with self.assertRaises(ship.ShipListError) as caught:
            ship.check_private_namespaces(self.SHIP, stanzas)
        self.assertIn("usr/share/shadowfetch/thing", str(caught.exception))

    def test_enhances_from_the_plugin_is_enough(self):
        stanzas = {"owner": {"Package": "owner"},
                   "plugin": {"Package": "plugin", "Enhances": "owner"}}
        ship.check_private_namespaces(self.SHIP, stanzas)

    def test_a_relationship_naming_some_other_package_is_not_enough(self):
        stanzas = {"owner": {"Package": "owner"},
                   "plugin": {"Package": "plugin", "Enhances": "somebody-else"}}
        with self.assertRaises(ship.ShipListError):
            ship.check_private_namespaces(self.SHIP, stanzas)

    def test_a_shared_directory_outside_the_private_namespaces_is_not_a_seam(self):
        """/usr/bin belongs to the whole system; two packages in it prove
        nothing, and failing there would train people to ignore this."""
        shared = {"one": {"usr/bin/a": Path("a")}, "two": {"usr/bin/b": Path("b")}}
        ship.check_private_namespaces(shared, {"one": {}, "two": {}})


class CrossPackageResolution(unittest.TestCase):
    OWNERS = {
        "usr/lib/shadowfetch/engine/sf_thing.py": "engine",
        "usr/libexec/shadowfetch-helper": "helper-pkg",
        "usr/share/shadowfetch/control-center/sfcc/extra_page.py": "plugin",
    }

    def test_a_private_namespace_directory_resolves_to_its_one_filler(self):
        source = 'sys.path.insert(0, "/usr/lib/shadowfetch/engine")'
        self.assertEqual(ship.resolved_owners(source, self.OWNERS), {"engine"})

    def test_an_exact_installed_path_resolves_to_its_owner(self):
        source = 'HELPER = "/usr/libexec/shadowfetch-helper"'
        self.assertEqual(ship.resolved_owners(source, self.OWNERS), {"helper-pkg"})

    def test_an_sfcc_import_resolves_to_whoever_ships_that_module(self):
        source = "from sfcc.extra_page import ExtraPage"
        self.assertEqual(ship.resolved_owners(source, self.OWNERS), {"plugin"})

    def test_a_shared_system_directory_resolves_to_nobody(self):
        """/usr/bin/ is not a namespace anyone owns, so a program naming it
        raises no finding -- only the exact file inside it does."""
        source = 'BIN = "/usr/bin/shadowfetch-nothing-in-particular"'
        self.assertEqual(ship.resolved_owners(source, self.OWNERS), set())

    def test_the_version_string_is_the_one_documented_exemption(self):
        source = 'VERSION_FILE = "/usr/share/shadowfetch/version"'
        owners = {"usr/share/shadowfetch/version": "branding"}
        self.assertEqual(ship.resolved_owners(source, owners), set())
        self.assertEqual(ship.COSMETIC_PATHS, {"usr/share/shadowfetch/version"},
                         "the exemption set grew; each entry needs a reader that "
                         "degrades without failing and an edge with no behaviour")


class PillarClosure(unittest.TestCase):
    """Installing shadowfetch-desktop must install the architecture."""

    def stanzas(self):
        return copy.deepcopy(ship.binary_stanzas()[0])

    def test_the_real_graph_reaches_every_pillar_through_depends(self):
        ship.check_pillar_closure(self.stanzas(), named={})

    def test_dropping_a_pillar_from_the_metapackage_fails(self):
        for pillar in sorted(ship.REQUIRED_PILLARS):
            with self.subTest(pillar=pillar):
                stanzas = self.stanzas()
                stanzas[ship.DESKTOP]["Depends"] = ", ".join(
                    clause for clause in stanzas[ship.DESKTOP]["Depends"].split(",")
                    if clause.strip().split()[0] != pillar)
                # Removing it from the metapackage is not enough on its own:
                # several pillars are also reached through another pillar's
                # Depends, and the check is about reachability, not the literal
                # line. Cut every edge into it.
                for stanza in stanzas.values():
                    for field in ("Depends", "Pre-Depends"):
                        if field in stanza:
                            stanza[field] = ", ".join(
                                clause for clause in stanza[field].split(",")
                                if clause.strip().split()[0] != pillar)
                with self.assertRaises(ship.ShipListError) as caught:
                    ship.check_pillar_closure(stanzas, named={})
                self.assertIn(pillar, str(caught.exception))

    def test_a_recommends_does_not_satisfy_a_pillar(self):
        """--no-install-recommends is a supported way to install, and the
        container package gate uses it. A pillar behind Recommends is a pillar
        that can be absent."""
        stanzas = self.stanzas()
        depends = [clause for clause in stanzas[ship.DESKTOP]["Depends"].split(",")
                   if clause.strip().split()[0] != "shadowfetch-phoenix"]
        stanzas[ship.DESKTOP]["Depends"] = ", ".join(depends)
        stanzas[ship.DESKTOP]["Recommends"] = "shadowfetch-phoenix"
        for stanza in stanzas.values():
            if "Depends" in stanza:
                stanza["Depends"] = ", ".join(
                    clause for clause in stanza["Depends"].split(",")
                    if clause.strip().split()[0] != "shadowfetch-phoenix")
        with self.assertRaises(ship.ShipListError):
            ship.check_pillar_closure(stanzas, named={})

    def test_a_package_list_may_not_secretly_supply_a_pillar(self):
        """The 4.0.0 defect exactly: fire-edition.list.chroot named seven
        packages the metapackage did not."""
        stanzas = self.stanzas()
        for stanza in stanzas.values():
            for field in ("Depends", "Recommends"):
                if field in stanza:
                    stanza[field] = ", ".join(
                        clause for clause in stanza[field].split(",")
                        if clause.strip().split()[0] != "shadowfetch-menus")
        stanzas[ship.DESKTOP].setdefault("Depends", "")
        with self.assertRaises(ship.ShipListError) as caught:
            ship.check_pillar_closure(
                stanzas, named={"shadowfetch-menus": "fire-edition.list.chroot"})
        self.assertIn("shadowfetch-menus", str(caught.exception))

    def test_the_real_package_lists_name_nothing_the_graph_cannot_reach(self):
        ship.check_pillar_closure(self.stanzas())


class TheGateSolvesTheMetapackageAlone(unittest.TestCase):
    """The declaration is checked from source text; this is the enforcement.

    Every other solve in the container gate names every package explicitly, so
    none of them can notice a metapackage that does not install the product.
    One solve is given only shadowfetch-desktop, with --no-install-recommends,
    and apt decides.
    """

    def script(self):
        sys.path.insert(0, str(ROOT / "tools/release"))
        import gate
        import package_gate
        return package_gate.container_script(gate.load_release("4.0.0"))

    def test_the_container_solves_the_metapackage_on_its_own(self):
        script = self.script()
        self.assertIn(
            "apt-get --simulate --no-install-recommends install shadowfetch-desktop",
            script)

    def test_every_pillar_is_asserted_in_that_plan(self):
        script = self.script()
        for pillar in ship.REQUIRED_PILLARS:
            with self.subTest(pillar=pillar):
                self.assertIn(pillar, script)
        self.assertIn("does not install $pillar", script,
                      "the plan is read but nothing fails on it")


class ReverseManifest(unittest.TestCase):
    ROOTS = {Path("data")}

    def test_a_payload_file_nobody_ships_is_a_finding(self):
        findings, swept = ship.unshipped(
            tracked={Path("data/a"), Path("data/b")},
            consumed={Path("data/a")}, roots=self.ROOTS, exempt=[])
        self.assertEqual(findings, ["data/b"])
        self.assertEqual(swept, 2)

    def test_debian_not_installed_declares_it_instead_of_hiding_it(self):
        findings, _ = ship.unshipped(
            tracked={Path("data/a"), Path("data/b")},
            consumed={Path("data/a")}, roots=self.ROOTS, exempt=["data/b"])
        self.assertEqual(findings, [])

    def test_not_installed_wildcards_expand(self):
        findings, _ = ship.unshipped(
            tracked={Path("data/w/x/1.jpg"), Path("data/w/x/2.jpg")},
            consumed=set(), roots=self.ROOTS, exempt=["data/w/*/*"])
        self.assertEqual(findings, [])

    def test_files_outside_a_declared_payload_root_are_not_payload(self):
        """tests/ and docs/ are not shipped and are not meant to be."""
        findings, swept = ship.unshipped(
            tracked={Path("tests/test_thing.py"), Path("debian/control")},
            consumed=set(), roots=self.ROOTS, exempt=[])
        self.assertEqual((findings, swept), ([], 0))

    def test_the_two_declared_exclusions_are_still_the_only_ones(self):
        """If a package stops shipping something, the reverse manifest fails
        rather than letting a debian/not-installed grow quietly."""
        declared = {
            path.parent.parent.name: ship.not_installed(path.parent.parent)
            for path in ROOT.glob("packages/*/debian/not-installed")
        }
        self.assertEqual(sorted(declared), ["shadowfetch-branding", "shadowfetch-welcome"])
        self.assertEqual(declared["shadowfetch-welcome"],
                         ["data/usr/share/shadowfetch/welcome/catalog/README"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
