"""How the Control Center invokes privileged tools (Phase 1 W-08, W-09).

W-08  Two pkexec call sites built argv the helper does not accept, so the
      action failed *after* the user typed their administrator password:
        * software_page passed the catalog id where the helper wants a verb
        * ember_page passed --duration to a parser that rejects any flag it
          does not know, and the failure was reported as "Authorisation was
          cancelled", which is why it went unnoticed.

W-09  terminal_command ran those tools through `bash -lc`. A login shell
      sources ~/.profile / ~/.bash_profile, which the unprivileged user can
      write, and the tools then ask for an administrator password.

Stage P moved the bundle-install argv and terminal_command into sfcc.desktop,
so their tests moved to test_desktop_library.py with them. What stays here is
the part that is about the HELPERS' own argv grammar and the dialog that
reports their exit status.
"""
import os
import re
import sys
import unittest
from pathlib import Path

CC = Path(__file__).resolve().parents[1]
SFCC = CC / "data/usr/share/shadowfetch/control-center/sfcc"
REPO = CC.parents[1]
sys.path.insert(0, str(SFCC.parent))

BUNDLE_HELPER = (REPO / "packages/shadowfetch-welcome/data/usr/libexec"
                 / "shadowfetch-bundle-install")
EMBER_HELPER = REPO / "packages/shadowfetch-ember/usr/libexec/ember-duration"


def source(name):
    return (SFCC / name).read_text()


class EmberDurationArgv(unittest.TestCase):
    def test_helper_has_no_duration_flag(self):
        helper = EMBER_HELPER.read_text()
        self.assertNotIn("--duration)", helper,
                         "helper grew a --duration flag; revisit the caller")
        self.assertIn("*[!0-9]*)", helper,
                      "the helper no longer rejects unknown arguments")

    def test_caller_passes_seconds_positionally(self):
        src = source("ember_page.py")
        self.assertNotIn('"--duration"', src,
                         "--duration is rejected by ember-duration's parser")
        self.assertRegex(src, r"args \+= \[str\(duration\)\]")

    def test_helper_failure_is_not_reported_as_cancelled_authorisation(self):
        src = source("ember_page.py")
        block = src[src.index("def _helper_done"):][:900]
        self.assertIn("126", block)
        self.assertIn("127", block)
        self.assertIn("cancelled", block)
        # The generic branch must not claim the user cancelled.
        generic = block[block.index("else:"):]
        self.assertNotIn("cancelled", generic)


class ProcessDialogExitCodes(unittest.TestCase):
    def test_distinguishes_pkexec_126_and_127(self):
        src = source("theme.py")
        block = src[src.index("def _done"):][:1200]
        self.assertIn("elif code == 126:", block,
                      "a declined authorisation is not distinguished")
        self.assertIn("elif code == 127:", block,
                      "a helper that could not be executed is not distinguished")


class MissionCommandIsNotEnvironmentSelectable(unittest.TestCase):
    def test_the_engine_binary_is_absolute(self):
        """Which binary answers "what did the policy decide" and "does the
        audit chain verify" is itself a security fact, so it comes from the
        trusted program table, absolute, with no PATH lookup."""
        from sfcc import mission_client
        self.assertTrue(mission_client.MISSION_COMMAND.startswith("/"))
        self.assertTrue(mission_client.GROK_COMMAND.startswith("/"))

    def test_the_session_path_cannot_choose_the_binary(self):
        os.environ["PATH"] = "/tmp/attacker:" + os.environ.get("PATH", "")
        try:
            for name in list(sys.modules):
                if name.endswith("mission_client"):
                    del sys.modules[name]
            from sfcc import mission_client
            self.assertNotIn("/tmp/attacker", mission_client.MISSION_COMMAND)
            self.assertNotIn("/tmp/attacker", mission_client.GROK_COMMAND)
        finally:
            os.environ["PATH"] = os.environ["PATH"].replace("/tmp/attacker:", "")

    def test_environment_cannot_choose_the_binary(self):
        os.environ["SHADOWFETCH_MISSIONS_COMMAND"] = "/tmp/attacker-missions"
        os.environ["SHADOWFETCH_GROK_BOT_COMMAND"] = "/tmp/attacker-grok"
        try:
            for name in list(sys.modules):
                if name.endswith("mission_client"):
                    del sys.modules[name]
            from sfcc import mission_client
            self.assertNotIn("attacker", mission_client.MISSION_COMMAND)
            self.assertNotIn("attacker", mission_client.GROK_COMMAND)
        finally:
            os.environ.pop("SHADOWFETCH_MISSIONS_COMMAND", None)
            os.environ.pop("SHADOWFETCH_GROK_BOT_COMMAND", None)


if __name__ == "__main__":
    unittest.main(verbosity=2)
