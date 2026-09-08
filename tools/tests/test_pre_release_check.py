"""Unit tests for tools/pre_release_check.sh (W-03: no silent skip without git)."""

from __future__ import annotations

import datetime
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "pre_release_check.sh"


@unittest.skipUnless(shutil.which("git"), "git is required")
class PreReleaseCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        distribution = self.root / "repo" / "dists" / "umbra"
        (distribution / "main" / "binary-amd64").mkdir(parents=True)
        (distribution / "main" / "source").mkdir(parents=True)
        valid_until = datetime.datetime.now(
            datetime.timezone.utc
        ) + datetime.timedelta(days=30)
        (distribution / "InRelease").write_text(
            "Origin: Shadowfetch\n"
            f"Valid-Until: {valid_until.strftime('%a, %d %b %Y %H:%M:%S UTC')}\n",
            encoding="utf-8",
        )
        (distribution / "main" / "binary-amd64" / "Packages").write_text(
            "Package: shadowfetch-defaults\nVersion: 4.0.0-1\n\n", encoding="utf-8"
        )
        (distribution / "main" / "source" / "Sources").write_text(
            "Package: shadowfetch-defaults\nVersion: 4.0.0-1\n\n", encoding="utf-8"
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def check(self) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["bash", str(SCRIPT)],
            env={**os.environ, "ROOT": str(self.root)},
            capture_output=True,
            text=True,
        )

    def test_unusable_git_is_a_hard_failure(self) -> None:
        """The tree is not a repository: the credential-state check cannot run."""
        result = self.check()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("PRE_RELEASE_CHECK_FAILED", result.stderr)
        self.assertIn("tracked-credential-state check cannot run", result.stderr)
        self.assertNotIn("PRE_RELEASE_CHECK_PASSED", result.stdout)

    def test_missing_git_executable_is_a_hard_failure(self) -> None:
        empty_path = self.root / "no-tools"
        empty_path.mkdir()
        for name in ("bash", "grep", "date", "find", "awk", "comm", "sort", "paste"):
            source = shutil.which(name)
            if source:
                (empty_path / name).symlink_to(source)
        result = subprocess.run(
            ["bash", str(SCRIPT)],
            env={"ROOT": str(self.root), "PATH": str(empty_path)},
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("git is not installed", result.stderr)

    def test_healthy_git_tree_still_passes(self) -> None:
        """Invariant: with a working git and a clean tree the check passes as before."""
        subprocess.run(["git", "init", "-q"], cwd=self.root, check=True)
        result = self.check()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PRE_RELEASE_CHECK_PASSED", result.stdout)

    def test_tracked_wrangler_state_still_fails(self) -> None:
        subprocess.run(["git", "init", "-q"], cwd=self.root, check=True)
        cache = self.root / ".wrangler" / "state.json"
        cache.parent.mkdir()
        cache.write_text("{}\n", encoding="utf-8")
        subprocess.run(
            ["git", "add", "-f", ".wrangler/state.json"], cwd=self.root, check=True
        )
        result = self.check()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("tracked Wrangler cache/state files", result.stderr)


if __name__ == "__main__":
    unittest.main()
