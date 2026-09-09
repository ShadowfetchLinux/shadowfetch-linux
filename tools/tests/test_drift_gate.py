#!/usr/bin/env python3
"""Adversarial tests for tools/drift_gate.py and tools/generate_theme_assets.py.

A gate is only worth landing if it FAILS on the thing it claims to catch.  Every
test here plants a divergence a careless edit would really make -- a bumped
version in one file, one wrong hex digit in a signing fingerprint, a hand-edited
generated colour, a new unnamed colour, a look-and-feel that names the other
package, a pkexec call missing its verb -- and asserts the gate reports DRIFT.

Two tests assert the CURRENT tree state (0 DRIFT, and the exact set of BLOCKED
findings).  They are snapshots on purpose: when somebody fixes one of the
blocked duplications, the snapshot test tells them to move it into the enforced
set instead of letting the report quietly shrink.

Run:  python3 -m unittest discover -s tools/tests -p 'test_drift_gate.py' -v
"""

from __future__ import annotations

import contextlib
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

TOOLS = Path(__file__).resolve().parents[1]
ROOT = TOOLS.parent
sys.path.insert(0, str(TOOLS))

import drift_gate  # noqa: E402
import generate_theme_assets  # noqa: E402

# Release identity comes from Stage Q's per-release gate data, not from a
# second copy under tools/truth/.
TRUTH = drift_gate.load_truth()
RELEASE_DATA = TRUTH["_data_file"]
POINTER = "tools/truth/release.json"


@contextlib.contextmanager
def sandbox(*rels: str):
    """A temporary ROOT holding copies of exactly these files.

    The gate reads the tree through module-level ROOT constants, so pointing
    those at a copy is what lets a test mutate a shipped file without touching
    the real one.  Any check reading a file that was not copied fails loudly
    rather than silently reading the real tree.
    """
    with tempfile.TemporaryDirectory() as tmp:
        fake = Path(tmp)
        for rel in rels:
            target = fake / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / rel, target)
        saved = (drift_gate.ROOT, generate_theme_assets.ROOT,
                 generate_theme_assets.PALETTE,
                 generate_theme_assets.COLOR_SCHEME_DIR,
                 generate_theme_assets.KONSOLE_DIR)
        drift_gate.ROOT = fake
        generate_theme_assets.ROOT = fake
        generate_theme_assets.PALETTE = fake / "tools/truth/palette.json"
        generate_theme_assets.COLOR_SCHEME_DIR = (
            fake / "packages/shadowfetch-themes/data/usr/share/color-schemes")
        generate_theme_assets.KONSOLE_DIR = (
            fake / "packages/shadowfetch-themes/data/usr/share/konsole")
        try:
            yield fake
        finally:
            (drift_gate.ROOT, generate_theme_assets.ROOT,
             generate_theme_assets.PALETTE,
             generate_theme_assets.COLOR_SCHEME_DIR,
             generate_theme_assets.KONSOLE_DIR) = saved


def drifts(findings):
    return [f for f in findings if f.kind == "DRIFT"]


def edit(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    assert text.count(old) == 1, f"{path}: expected exactly one {old!r}"
    path.write_text(text.replace(old, new), encoding="utf-8")


PALETTE_REL = "tools/truth/palette.json"
GENERATED = (
    "packages/shadowfetch-themes/data/usr/share/color-schemes/ShadowfetchDark.colors",
    "packages/shadowfetch-themes/data/usr/share/color-schemes/ShadowfetchIce.colors",
    "packages/shadowfetch-themes/data/usr/share/konsole/ShadowfetchUmbra.colorscheme",
    "packages/shadowfetch-themes/data/usr/share/konsole/ShadowfetchGlacier.colorscheme",
)
VERSION_RELS = tuple({rel for rel, _, _ in drift_gate.VERSION_SITES}) + (
    f"qa/{TRUTH['version']}/acceptance.json", RELEASE_DATA, POINTER)
FINGERPRINT_RELS = drift_gate.FINGERPRINT_REQUIRED + (
    f"qa/{TRUTH['version']}/acceptance.json", RELEASE_DATA, POINTER)
LNF_RELS = tuple(
    drift_gate.LNF_DEFAULTS.format(plugin=plugin)
    for plugin in ("org.shadowfetch.dark", "org.shadowfetch.ice"))
PALETTE_LITERAL_RELS = (
    tuple(drift_gate.SURFACE_OF)
    + tuple(drift_gate.SPLASH.format(plugin=p)
            for p in ("org.shadowfetch.dark", "org.shadowfetch.ice"))
    + (drift_gate.THEME_CONF, PALETTE_REL))
HELPER_RELS = tuple(set(drift_gate.HELPER_CONSUMERS) | set(drift_gate.BUNDLE_CALL_SITES))


class TestTreeIsClean(unittest.TestCase):
    """The state this stage is landing in. Not a claim that nothing is duplicated."""

    def test_no_drift_anywhere(self):
        found = drifts(drift_gate.run())
        self.assertEqual([], found, "\n".join(str(f) for f in found))

    def test_blocked_findings_are_the_recorded_set(self):
        blocked = [f for f in drift_gate.run() if f.kind == "BLOCKED"]
        by_check = {}
        for finding in blocked:
            by_check[finding.check] = by_check.get(finding.check, 0) + 1
        # Snapshot. A DIFFERENT number means a duplication was fixed (move it to
        # the enforced set and update this) or a new one appeared (fix it).
        self.assertEqual(
            {"palette": 1, "workspace-name": 13, "element-assets": 1,
             "desktop-helpers": 1, "release-pointer": 1},
            by_check,
            "the blocked-duplication inventory changed:\n"
            + "\n".join(str(f) for f in blocked))

    def test_generator_reproduces_the_shipped_assets(self):
        palette = generate_theme_assets.load_palette()
        self.assertEqual([], generate_theme_assets.check(palette))


class TestVersionDrift(unittest.TestCase):
    def test_a_single_bumped_copy_is_caught(self):
        rel = ("packages/shadowfetch-branding/data/usr/share/shadowfetch/"
               "os-release.shadowfetch")
        with sandbox(*VERSION_RELS) as fake:
            edit(fake / rel, 'VERSION_ID="4.0.0"', 'VERSION_ID="4.0.1"')
            found = drifts(drift_gate.check_version(TRUTH))
        self.assertTrue(found)
        self.assertIn("os-release VERSION_ID is '4.0.1'", found[0].detail)

    def test_a_deleted_assignment_is_caught(self):
        """A copy that stops existing is drift too -- silence is not agreement."""
        with sandbox(*VERSION_RELS) as fake:
            target = fake / ("packages/shadowfetch-defaults/data/usr/bin/"
                             "shadowfetch-element")
            edit(target, 'VERSION="4.0.0"', 'VERSION=$(cat /usr/share/shadowfetch/version)')
            found = drifts(drift_gate.check_version(TRUTH))
        self.assertTrue(any("could not be located" in f.detail for f in found))

    def test_acceptance_manifest_release_block_is_checked(self):
        with sandbox(*VERSION_RELS) as fake:
            manifest = fake / f"qa/{TRUTH['version']}/acceptance.json"
            edit(manifest, '"edition": "Fire and Ice"', '"edition": "Fire"')
            found = drifts(drift_gate.check_version(TRUTH))
        self.assertTrue(any("release.edition" in f.detail for f in found))

    def test_clean_copy_passes(self):
        with sandbox(*VERSION_RELS):
            self.assertEqual([], drifts(drift_gate.check_version(TRUTH)))


class TestFingerprintDrift(unittest.TestCase):
    """The signing key is a security fact; a retyped copy is a real exposure."""

    REAL = TRUTH["signing"]["fingerprint"]

    def test_one_wrong_hex_digit_is_caught(self):
        with sandbox(*FINGERPRINT_RELS) as fake:
            wrong = self.REAL[:-1] + ("2" if self.REAL[-1] != "2" else "3")
            edit(fake / "Makefile", self.REAL, wrong)
            found = drifts(drift_gate.check_fingerprint(TRUTH))
        self.assertTrue(found)
        self.assertTrue(any("Makefile" in f.site for f in found))

    def test_the_sweep_is_not_vacuous(self):
        """A wrong key in ANY swept file is caught, not just the listed ones."""
        with sandbox(*FINGERPRINT_RELS) as fake:
            planted = fake / "packages/anything/data/usr/bin/some-tool"
            planted.parent.mkdir(parents=True, exist_ok=True)
            fake_key = ("0123456789AB" * 4)[:40]
            planted.write_text(f'GPG_FINGERPRINT = "{fake_key}"\n', encoding="utf-8")
            found = drifts(drift_gate.check_fingerprint(TRUTH))
        self.assertTrue(any("some-tool" in f.site for f in found))

    def test_the_gpg_spaced_grouping_is_not_mistaken_for_a_different_key(self):
        """README and SECURITY.md group the hex in fours. Same key, not drift."""
        with sandbox(*FINGERPRINT_RELS):
            self.assertIn("8F13 CE15", (ROOT / "SECURITY.md").read_text())
            self.assertEqual([], drifts(drift_gate.check_fingerprint(TRUTH)))

    def test_a_required_file_that_stops_naming_the_key_is_caught(self):
        with sandbox(*FINGERPRINT_RELS) as fake:
            edit(fake / "repo/conf/distributions", self.REAL, "")
            found = drifts(drift_gate.check_fingerprint(TRUTH))
        self.assertTrue(any("no 40-hex fingerprint found" in f.detail for f in found))

    def test_a_commit_sha_is_not_mistaken_for_a_key(self):
        """qa/<v>/acceptance.json carries 40-hex Git SHAs next to the key."""
        manifest = ROOT / f"qa/{TRUTH['version']}/acceptance.json"
        text = manifest.read_text(encoding="utf-8")
        self.assertRegex(text, r'"source_commit":\s*"[0-9a-f]{40}"')
        with sandbox(*FINGERPRINT_RELS):
            self.assertEqual([], drifts(drift_gate.check_fingerprint(TRUTH)))

    def test_a_third_party_key_must_be_named(self):
        with sandbox(*FINGERPRINT_RELS) as fake:
            planted = fake / "packages/anything/vendor/provenance.json"
            planted.parent.mkdir(parents=True, exist_ok=True)
            other_key = ("ABCDEF9876" * 4)[:40]
            planted.write_text(
                '{"upstream_signing_fingerprint": "%s"}\n' % other_key,
                encoding="utf-8")
            found = drifts(drift_gate.check_fingerprint(TRUTH))
        self.assertTrue(found)
        self.assertIn("OTHER_KEYS", found[0].remedy)

    def test_the_named_third_party_keys_are_accepted(self):
        for value, why in drift_gate.OTHER_KEYS.items():
            self.assertEqual(40, len(value), value)
            self.assertTrue(why.strip(), f"{value} has no named owner")


class TestReleaseData(unittest.TestCase):
    """The release data file is the authority; the Makefile is a copy."""

    def test_a_makefile_that_disagrees_with_the_release_data_is_caught(self):
        with sandbox("Makefile", f"qa/{TRUTH['version']}/acceptance.json",
                     RELEASE_DATA, POINTER) as fake:
            edit(fake / "Makefile", "VERSION  ?= 4.0.0", "VERSION  ?= 4.0.1")
            found = drifts(drift_gate.check_release_data(TRUTH))
        self.assertTrue(found)
        self.assertIn("Makefile VERSION is '4.0.1'", found[0].detail)

    def test_exactly_one_release_is_live(self):
        """Two non-historical data files is an ambiguity, not a default."""
        truth = drift_gate.load_truth()
        self.assertEqual(TRUTH["version"], truth["version"])
        self.assertTrue(truth["_data_file"].startswith("tools/release/versions/"))

    def test_clean_copy_passes(self):
        with sandbox("Makefile", f"qa/{TRUTH['version']}/acceptance.json",
                     RELEASE_DATA, POINTER):
            self.assertEqual([], drifts(drift_gate.check_release_data(TRUTH)))


class TestGeneratedThemeAssets(unittest.TestCase):
    def test_a_hand_edited_generated_file_is_caught(self):
        with sandbox(PALETTE_REL, *GENERATED) as fake:
            target = fake / GENERATED[1]
            edit(target, "inactiveForeground=154,163,173", "inactiveForeground=0,0,0")
            found = drifts(drift_gate.check_theme_assets(TRUTH))
        self.assertTrue(found)
        self.assertIn("inactiveForeground=0,0,0", found[0].detail)

    def test_semantic_colours_do_not_mirror_by_element(self):
        """The defect this generator was written to end.

        The Ice assets had been produced by R/B-mirroring every value, so ANSI
        red rendered blue in Konsole and Plasma error text rendered blue --
        contradicting sfcc/theme.py:29-31, which promises semantic colours keep
        their meaning on a cold desktop.
        """
        palette = generate_theme_assets.load_palette()
        fire = generate_theme_assets.render_konsole(palette, "fire")
        ice = generate_theme_assets.render_konsole(palette, "ice")
        red = generate_theme_assets.rgb(palette["semantic"]["negative"])
        self.assertIn(f"[Color1]\nColor={red}", fire)
        self.assertIn(f"[Color1]\nColor={red}", ice)
        for element in ("fire", "ice"):
            colors = generate_theme_assets.render_colors(palette, element)
            self.assertIn(f"ForegroundNegative={red}", colors)
        # ...while the brand accent still does mirror.
        self.assertNotEqual(palette["elements"]["fire"]["accent"],
                            palette["elements"]["ice"]["accent"])

    def test_write_then_check_is_a_fixed_point(self):
        with sandbox(PALETTE_REL, *GENERATED):
            palette = generate_theme_assets.load_palette()
            for path, text in generate_theme_assets.generated(palette).items():
                path.write_text(text, encoding="utf-8")
            self.assertEqual([], generate_theme_assets.check(palette))


class TestPaletteLiterals(unittest.TestCase):
    APP = ("packages/shadowfetch-control-center/data/usr/share/shadowfetch/"
           "control-center/sfcc/app.py")

    def test_a_new_unnamed_colour_is_caught(self):
        with sandbox(*PALETTE_LITERAL_RELS) as fake:
            edit(fake / self.APP, 'side_wrap.setStyleSheet("background: #101114;")',
                 'side_wrap.setStyleSheet("background: #123456;")')
            found = drifts(drift_gate.check_palette_literals(TRUTH))
        self.assertTrue(found)
        self.assertIn("#123456", found[0].detail)

    def test_a_slack_ratchet_entry_is_caught(self):
        """Removing a stray colour must also remove its ratchet entry."""
        with sandbox(*PALETTE_LITERAL_RELS) as fake:
            edit(fake / self.APP, "#101114", "#151619")  # an app-chrome role
            found = drifts(drift_gate.check_palette_literals(TRUTH))
        self.assertTrue(any("ratchet has gone slack" in f.detail for f in found))

    def test_a_third_red_in_the_fireproof_window_is_caught(self):
        """The audit's named defect: a window inside another window, own red."""
        rel = "packages/shadowfetch-fireproof/data/usr/bin/shadowfetch-fireproof"
        with sandbox(*PALETTE_LITERAL_RELS) as fake:
            edit(fake / rel, 'RED = "#e2533b"', 'RED = "#e07a6a"')
            found = drifts(drift_gate.check_palette_literals(TRUTH))
        self.assertTrue(found)
        self.assertIn("#e07a6a", found[0].detail)

    def test_a_splash_that_uses_the_other_accent_is_caught(self):
        rel = drift_gate.SPLASH.format(plugin="org.shadowfetch.ice")
        with sandbox(*PALETTE_LITERAL_RELS) as fake:
            (fake / rel).write_text(
                (fake / rel).read_text(encoding="utf-8").replace("#4aa2d8", "#d8a24a"),
                encoding="utf-8")
            found = drifts(drift_gate.check_palette_literals(TRUTH))
        self.assertTrue(any("#d8a24a" in f.detail for f in found))


class TestLookAndFeelIdentity(unittest.TestCase):
    ICE = drift_gate.LNF_DEFAULTS.format(plugin="org.shadowfetch.ice")

    def test_a_package_naming_the_other_package_is_caught(self):
        """Exactly the regression this stage fixed: Ice declared itself Dark."""
        with sandbox(*LNF_RELS, PALETTE_REL) as fake:
            edit(fake / self.ICE, "LookAndFeelPackage=org.shadowfetch.ice",
                 "LookAndFeelPackage=org.shadowfetch.dark")
            found = drifts(drift_gate.check_lookandfeel(TRUTH))
        self.assertTrue(found)
        self.assertIn("LookAndFeelPackage", found[0].detail)

    def test_a_wrong_accent_colour_is_caught(self):
        with sandbox(*LNF_RELS, PALETTE_REL) as fake:
            edit(fake / self.ICE, "AccentColor=74,162,216", "AccentColor=216,162,74")
            found = drifts(drift_gate.check_lookandfeel(TRUTH))
        self.assertTrue(any("AccentColor" in f.detail for f in found))

    def test_clean_copy_passes(self):
        with sandbox(*LNF_RELS, PALETTE_REL):
            self.assertEqual([], drifts(drift_gate.check_lookandfeel(TRUTH)))


class TestDesktopHelpers(unittest.TestCase):
    SOFTWARE = ("packages/shadowfetch-control-center/data/usr/share/shadowfetch/"
                "control-center/sfcc/software_page.py")

    def test_a_bundle_install_call_missing_its_verb_is_caught(self):
        """UI-ARGV-01: seven Install buttons exited 2 after the password prompt."""
        with sandbox(*HELPER_RELS) as fake:
            edit(fake / self.SOFTWARE,
                 '["pkexec", busutil.BUNDLE_INSTALL, "install", bundle_id]',
                 '["pkexec", busutil.BUNDLE_INSTALL, bundle_id]')
            found = drifts(drift_gate.check_desktop_helpers(TRUTH))
        self.assertTrue(found)
        self.assertIn("without the \"install\" verb", found[0].detail)

    def test_the_two_front_ends_disagreeing_on_a_helper_path_is_caught(self):
        with sandbox(*HELPER_RELS) as fake:
            rel = "packages/shadowfetch-welcome/src/shadowfetch-welcome"
            (fake / rel).write_text(
                (fake / rel).read_text(encoding="utf-8").replace(
                    "/usr/libexec/shadowfetch-bundle-install",
                    "/usr/libexec/sf-bundle-install"),
                encoding="utf-8")
            found = drifts(drift_gate.check_desktop_helpers(TRUTH))
        self.assertTrue(any("bundle-install path" in f.detail for f in found))

    def test_clean_copy_passes(self):
        with sandbox(*HELPER_RELS):
            self.assertEqual([], drifts(drift_gate.check_desktop_helpers(TRUTH)))


class TestElementAssets(unittest.TestCase):
    RELS = (drift_gate.ELEMENT_APPLIER, drift_gate.FIRST_LOGIN,
            drift_gate.SKEL_KDEGLOBALS, PALETTE_REL)

    def test_a_bash_branch_that_forgets_an_asset_is_caught(self):
        with sandbox(*self.RELS) as fake:
            edit(fake / drift_gate.ELEMENT_APPLIER,
                 'konsole="ShadowfetchGlacier"', 'konsole="ShadowfetchUmbra"')
            found = drifts(drift_gate.check_element_assets(TRUTH))
        self.assertTrue(found)
        self.assertIn("ShadowfetchGlacier", found[0].detail)

    def test_an_unapplied_look_and_feel_package_is_reported(self):
        """Choosing Ice leaves the Fire splash installed; nothing applies it."""
        findings = drift_gate.check_element_assets(TRUTH)
        blocked = [f for f in findings if f.kind == "BLOCKED"]
        self.assertTrue(blocked)
        self.assertIn("ice", blocked[0].detail)

    def test_it_stops_reporting_once_the_package_is_applied(self):
        with sandbox(*self.RELS) as fake:
            edit(fake / drift_gate.FIRST_LOGIN,
                 "plasma-apply-lookandfeel -a org.shadowfetch.dark || true",
                 "plasma-apply-lookandfeel -a org.shadowfetch.dark || true\n"
                 "plasma-apply-lookandfeel -a org.shadowfetch.ice || true")
            findings = drift_gate.check_element_assets(TRUTH)
        self.assertEqual([], findings)


class TestWorkspaceNameRule(unittest.TestCase):
    def test_the_corpus_matches_the_rule_it_claims_to_encode(self):
        for name, valid, why in drift_gate.WORKSPACE_CORPUS:
            self.assertEqual(valid, drift_gate._rule_accepts(name),
                             f"{name!r} ({why})")

    def test_the_rule_is_the_firebreak_rule(self):
        """Firebreak is the authority: it decides what a sandbox may write to.

        If this fails, either Firebreak changed or the rule was weakened -- and
        a weakened rule here would silently widen every other implementation.
        """
        verdicts = drift_gate._firebreak_verdicts()
        for name, valid, why in drift_gate.WORKSPACE_CORPUS:
            if name == "":
                continue  # Firebreak reads "" as "derive from cwd", not a name
            self.assertEqual(valid, verdicts[name], f"{name!r} ({why})")

    def test_a_divergent_implementation_is_detected(self):
        """Plant an implementation that accepts a hidden name; expect a finding."""
        def permissive():
            return {name: True for name, _, _ in drift_gate.WORKSPACE_CORPUS}

        saved = drift_gate.IMPLEMENTATIONS
        drift_gate.IMPLEMENTATIONS = (("planted", permissive, "planted/module.py"),)
        try:
            findings = drift_gate.check_workspace_name(TRUTH)
        finally:
            drift_gate.IMPLEMENTATIONS = saved
        planted = [f for f in findings if f.site.startswith("planted/")]
        self.assertTrue(planted)
        self.assertTrue(any("'.ssh'" in f.detail for f in planted))
        self.assertTrue(any("'a/b'" in f.detail for f in planted))

    def test_an_unrunnable_implementation_is_drift_not_silence(self):
        def broken():
            raise ImportError("no module named anything")

        saved = drift_gate.IMPLEMENTATIONS
        drift_gate.IMPLEMENTATIONS = (("broken", broken, "broken/module.py"),)
        try:
            findings = drift_gate.check_workspace_name(TRUTH)
        finally:
            drift_gate.IMPLEMENTATIONS = saved
        self.assertTrue(any(f.kind == "DRIFT" and "could not be exercised" in f.detail
                            for f in findings))


if __name__ == "__main__":
    unittest.main(verbosity=2)
