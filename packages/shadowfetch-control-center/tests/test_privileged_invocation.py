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
"""
import os
import re
import subprocess
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


class BundleInstallArgv(unittest.TestCase):
    """The helper dispatches on a verb; the caller must send one."""

    def test_helper_requires_a_verb(self):
        helper = BUNDLE_HELPER.read_text()
        self.assertIn('verb, rest = args[0], args[1:]', helper)
        self.assertIn('if verb == "install":', helper)

    def test_software_page_sends_the_install_verb(self):
        call = re.search(r'\[\s*"pkexec",\s*busutil\.BUNDLE_INSTALL[^\]]*\]',
                         source("software_page.py"), re.S)
        self.assertIsNotNone(call, "the bundle install call site moved")
        self.assertIn('"install"', call.group(0),
                      "the catalog id is passed where the helper expects a verb, "
                      "so the helper prints usage and exits 2")

    def test_both_call_sites_agree(self):
        """workbench_page always had it right; software_page did not."""
        shape = re.compile(r'"pkexec",\s*busutil\.BUNDLE_INSTALL,\s*"install",')
        for page in ("software_page.py", "workbench_page.py"):
            with self.subTest(page=page):
                self.assertRegex(source(page), shape)


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


class TerminalCommandIsNotALoginShell(unittest.TestCase):
    def setUp(self):
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        from sfcc import busutil
        self.busutil = busutil
        self.calls = []
        self._popen = subprocess.Popen
        subprocess.Popen = lambda argv, **kw: self.calls.append((argv, kw))

    def tearDown(self):
        subprocess.Popen = self._popen

    def _run(self, command="shadowfetch-gpu"):
        self.busutil.terminal_command(command)
        self.assertEqual(len(self.calls), 1)
        return self.calls[0]

    def test_never_uses_a_login_shell(self):
        argv, _ = self._run()
        joined = " ".join(argv)
        self.assertNotIn("-lc", joined,
                         "a login shell sources user-writable ~/.profile before "
                         "running a tool that asks for an admin password")
        self.assertNotIn("bash", joined)

    def test_runs_with_a_fixed_system_path(self):
        _, kw = self._run()
        self.assertEqual(kw["env"]["PATH"], self.busutil.TRUSTED_PATH)

    def test_strips_shell_startup_and_loader_hooks(self):
        os.environ["BASH_ENV"] = "/tmp/evil"
        os.environ["LD_PRELOAD"] = "/tmp/evil.so"
        try:
            _, kw = self._run()
            self.assertNotIn("BASH_ENV", kw["env"])
            self.assertNotIn("LD_PRELOAD", kw["env"])
        finally:
            os.environ.pop("BASH_ENV", None)
            os.environ.pop("LD_PRELOAD", None)

    def test_resolves_the_tool_against_system_directories_only(self):
        """A user-writable directory earlier in PATH must not win."""
        resolved = self.busutil.resolve_tool("sh -c true")
        self.assertTrue(resolved.startswith("/"), resolved)
        os.environ["PATH"] = "/tmp/attacker:" + os.environ.get("PATH", "")
        try:
            self.assertEqual(self.busutil.resolve_tool("sh"),
                             self.busutil.resolve_tool("sh"))
            self.assertNotIn("/tmp/attacker", self.busutil.resolve_tool("sh"))
        finally:
            os.environ["PATH"] = os.environ["PATH"].replace("/tmp/attacker:", "")


class MissionCommandIsNotEnvironmentSelectable(unittest.TestCase):
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
