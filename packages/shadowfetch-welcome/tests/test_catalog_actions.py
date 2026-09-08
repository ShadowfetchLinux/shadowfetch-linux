"""Welcome's catalog actions (Phase 3 Step 24, W-30).

Welcome shipped 3,159 lines with no tests and no line in `make test`. This is
the first file; it covers the two things Welcome hands to a privileged or
system helper, because both are contracts owned by *other* packages:

  * the workspace tool's argv, which the "Create workspace..." button got
    wrong in a way that made the button do nothing at all;
  * the bundle installer's argv, the third copy of a shape whose two Control
    Center copies are already pinned by
    packages/shadowfetch-control-center/tests/test_privileged_invocation.py.
    That test exists because one of those two copies shipped broken.
"""
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
WELCOME = ROOT / "packages/shadowfetch-welcome/src/shadowfetch-welcome"
BUNDLE_HELPER = (ROOT / "packages/shadowfetch-welcome/data/usr/libexec"
                 / "shadowfetch-bundle-install")
WORKSPACE_HELPER = (ROOT / "packages/shadowfetch-defaults/data/usr/bin"
                    / "shadowfetch-agent-workspace")


def source():
    return WELCOME.read_text(encoding="utf-8")


def template_body():
    src = source()
    start = src.index("    def _template(self, rec: dict):")
    end = src.index("\nclass ", start)
    return src[start:end]


class WorkspaceHelperArgv(unittest.TestCase):
    """The behaviour that made the button dead, measured on the real helper.

    Both cases close stdin, which is what a process spawned from a desktop
    button actually gets. Each runs against its own mkdtemp workspace root so
    concurrent runs and other users cannot collide.
    """

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="sf-welcome-ws-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.env = dict(os.environ, SHADOWFETCH_AGENT_WORKSPACES=self.root)

    def _run(self, *args):
        return subprocess.run(
            ["bash", str(WORKSPACE_HELPER), *args],
            stdin=subprocess.DEVNULL, capture_output=True, text=True,
            timeout=30, check=False, env=self.env)

    def test_no_verb_creates_nothing(self):
        """The old call. It opens an interactive menu, the first read gets
        EOF, and the refusal must leave the workspace root exactly as it
        was - no directory, no half-written AGENTS.md."""
        before = sorted(os.listdir(self.root)) if os.path.isdir(self.root) else []
        done = self._run()
        self.assertNotEqual(done.returncode, 0,
                            "a menu with no terminal must not report success")
        after = sorted(os.listdir(self.root))
        self.assertEqual(after, before)
        self.assertEqual(after, [], f"the refusal created {after}")

    def test_create_verb_needs_no_terminal(self):
        done = self._run("create", "step24 demo")
        self.assertEqual(done.returncode, 0, done.stderr)
        made = Path(self.root) / "step24-demo"
        self.assertTrue(made.is_dir(), sorted(os.listdir(self.root)))
        for name in ("AGENTS.md", "TASKS.md", "MEMORY.md", "JOURNAL.md"):
            self.assertTrue((made / name).is_file(), name)
        self.assertTrue(done.stdout.strip(),
                        "the button reprints this output verbatim")

    def test_create_refuses_a_duplicate_without_touching_it(self):
        self.assertEqual(self._run("create", "twice").returncode, 0)
        made = Path(self.root) / "twice"
        marker = made / "AGENTS.md"
        stamp = marker.read_text(encoding="utf-8")
        again = self._run("create", "twice")
        self.assertNotEqual(again.returncode, 0)
        self.assertEqual(marker.read_text(encoding="utf-8"), stamp,
                         "the refused second create rewrote the first workspace")
        self.assertEqual(sorted(os.listdir(self.root)), ["twice"])


class CreateWorkspaceButton(unittest.TestCase):
    def test_sends_the_create_verb_with_a_name(self):
        body = template_body()
        self.assertRegex(
            body, r'\[helper,\s*"create",\s*name\.strip\(\)\]',
            "the button must name the workspace on the command line")

    def test_never_starts_the_interactive_menu(self):
        body = template_body()
        self.assertNotIn('subprocess.Popen(cmd)', body)
        self.assertNotIn('["shadowfetch-agent-workspace"]', body,
                         "a bare argv is the menu form, which cannot run "
                         "without a terminal")

    def test_cannot_block_the_ui_on_stdin(self):
        body = template_body()
        self.assertIn("stdin=subprocess.DEVNULL", body)
        self.assertIn("timeout=30", body)

    def test_reports_the_helper_s_own_words(self):
        """No second vocabulary for the outcome: the helper already names the
        path it created and the error it refused on."""
        body = template_body()
        self.assertIn("done.stdout.strip()", body)
        self.assertIn("(done.stderr or done.stdout).strip()", body)


class BundleInstallArgv(unittest.TestCase):
    """Welcome is the third caller of a helper that dispatches on a verb."""

    def test_helper_requires_a_verb(self):
        helper = BUNDLE_HELPER.read_text(encoding="utf-8")
        self.assertIn("verb, rest = args[0], args[1:]", helper)
        self.assertIn('if verb == "install":', helper)

    def test_welcome_sends_the_install_verb(self):
        call = re.search(r'\[\s*"pkexec",\s*BUNDLE_HELPER[^\]]*\]', source(), re.S)
        self.assertIsNotNone(call, "the bundle install call site moved")
        self.assertRegex(call.group(0), r'"pkexec",\s*BUNDLE_HELPER,\s*"install",')

    def test_welcome_points_at_the_packaged_helper(self):
        self.assertRegex(
            source(),
            r'BUNDLE_HELPER = "/usr/libexec/shadowfetch-bundle-install"')


if __name__ == "__main__":
    unittest.main(verbosity=2)
