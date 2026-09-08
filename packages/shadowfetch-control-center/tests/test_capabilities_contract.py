"""Cross-package contract: every key the Control Center reads, the engine emits.

These are two separately-built Debian packages. Nothing but a test can stop the
engine renaming a key the desktop depends on, and Phase 2's baseline caught a
live example: missions_page.py has always read capabilities["summary"], and the
4.0.0 engine never emitted it, so the Readiness row silently never rendered.

This test runs the REAL engine and asserts against the REAL UI source, so it
fails if either side drifts.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
ENGINE = ROOT / "packages/shadowfetch-missions/data/usr/lib/shadowfetch/missions/sf_missions.py"
UI = (ROOT / "packages/shadowfetch-control-center/data/usr/share/shadowfetch"
      / "control-center/sfcc/missions_page.py")


def engine_capabilities():
    with tempfile.TemporaryDirectory() as tmp:
        ws = Path(tmp) / "ws"
        ws.mkdir()
        env = dict(os.environ,
                   XDG_STATE_HOME=str(Path(tmp) / "state"),
                   SHADOWFETCH_AGENT_WORKSPACES=str(ws))
        out = subprocess.run([sys.executable, str(ENGINE), "capabilities"],
                             capture_output=True, text=True, env=env, timeout=120)
        if out.returncode != 0:
            raise AssertionError("engine capabilities failed: " + out.stderr[-2000:])
        return json.loads(out.stdout)


class CapabilitiesContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.caps = engine_capabilities()
        cls.ui = UI.read_text()

    # -- the keys the dialog reads directly --------------------------------
    def test_summary_is_emitted(self):
        """missions_page.py:106 reads capabilities.get("summary").

        4.0.0 read it and never got it. If this fails, the Readiness row has
        silently stopped rendering again."""
        self.assertIn('capabilities.get("summary")', self.ui,
                      "the UI stopped reading summary; update this contract")
        self.assertIn("summary", self.caps)
        self.assertIsInstance(self.caps["summary"], str)
        self.assertTrue(self.caps["summary"].strip())

    def test_capability_kinds_maps_every_kind_the_ui_offers(self):
        """The dialog turns its legacy kind selector into a capability."""
        self.assertIn("capability_kinds", self.caps)
        offered = set(self.caps["capability_kinds"].values())
        # KINDS in the UI is the selector the person sees.
        for kind in ("code", "report", "media"):
            self.assertIn(kind, offered, f"no capability maps to the UI kind {kind!r}")

    def test_providers_carry_every_field_the_dialog_uses(self):
        required = {"display_name", "capabilities", "requires_network_approval",
                    "available", "installed", "reason"}
        self.assertIn("providers", self.caps)
        self.assertTrue(self.caps["providers"], "no providers were described")
        for provider_id, info in self.caps["providers"].items():
            with self.subTest(provider=provider_id):
                missing = sorted(required - set(info))
                self.assertEqual(missing, [], f"{provider_id} is missing {missing}")

    def test_every_ui_read_of_providers_is_satisfied(self):
        """Scrape the UI for info.get("...") and check the engine emits each."""
        import re
        reads = set(re.findall(r'info\.get\("([a-z_]+)"', self.ui))
        self.assertTrue(reads, "expected the dialog to read provider fields")
        for provider_id, info in self.caps["providers"].items():
            for key in reads:
                with self.subTest(provider=provider_id, key=key):
                    self.assertIn(key, info)

    # -- the 4.0.0 keys that must not disappear ----------------------------
    def test_the_four_zero_key_set_survives(self):
        """Recorded in PHASE2_BASELINE.md before any Phase 2 change."""
        for path in ("version", "workspace_root", "tools", "kinds", "states",
                     "max_attempts", "max_parallel", "local_ai", "grok_bot",
                     "runtimes"):
            self.assertIn(path, self.caps)
        for runtime in ("codex", "offline"):
            with self.subTest(runtime=runtime):
                self.assertIn(runtime, self.caps["runtimes"],
                              "the legacy runtime view is what 4.0.0 desktops read")
                entry = self.caps["runtimes"][runtime]
                self.assertIn("kinds", entry)
                self.assertIn("requires_network_approval", entry)

    def test_legacy_runtime_kinds_are_unchanged(self):
        self.assertEqual(self.caps["runtimes"]["codex"]["kinds"], ["code", "report"])
        self.assertEqual(self.caps["runtimes"]["offline"]["kinds"], ["media"])
        self.assertIs(self.caps["runtimes"]["codex"]["requires_network_approval"], True)
        self.assertIs(self.caps["runtimes"]["offline"]["requires_network_approval"], False)

    # -- the UI must not have reacquired provider knowledge -----------------
    def test_the_ui_names_no_provider_in_its_logic(self):
        """A hard-coded provider name in the dialog is how a valid third
        provider silently fails to appear."""
        import re
        code = "\n".join(line for line in self.ui.splitlines()
                         if not line.lstrip().startswith("#"))
        for banned in ('"codex"', "'codex'", '"offline"', "'offline'"):
            with self.subTest(token=banned):
                self.assertNotIn(banned, code,
                                 f"missions_page.py names {banned} in its logic")


if __name__ == "__main__":
    unittest.main(verbosity=2)
