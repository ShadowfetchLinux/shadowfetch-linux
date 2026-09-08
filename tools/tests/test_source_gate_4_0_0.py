"""Unit tests for the Shadowfetch 4.0.0 source gate (W-03: loud failure without git)."""

from __future__ import annotations

import contextlib
import importlib.machinery
import importlib.util
import io
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SRC = Path(__file__).resolve().parents[1] / "source_gate_4_0_0.py"
sys.path.insert(0, str(SRC.parent))
_loader = importlib.machinery.SourceFileLoader("source_gate_4_0_0_test", str(SRC))
_spec = importlib.util.spec_from_loader("source_gate_4_0_0_test", _loader)
source_gate = importlib.util.module_from_spec(_spec)
_loader.exec_module(source_gate)


def git_init(path: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)


@unittest.skipUnless(shutil.which("git"), "git is required")
class CandidateFileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write(self, relative: str, content: str = "x\n") -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def test_broken_git_raises_named_history_error(self) -> None:
        """The tree is not a repository: the gate must say so, not raise CalledProcessError."""
        self.write("packages/a.py")
        with mock.patch.object(source_gate, "ROOT", self.root):
            with self.assertRaises(source_gate.GitHistoryUnavailable) as caught:
                source_gate.candidate_files()
        message = str(caught.exception)
        self.assertIn("Git is unusable", message)
        self.assertIn("Git-history secret scan cannot run", message)
        self.assertIn("--no-git", message)

    def test_missing_git_executable_raises_named_history_error(self) -> None:
        self.write("packages/a.py")
        with mock.patch.object(source_gate, "ROOT", self.root), mock.patch.object(
            source_gate.shutil, "which", return_value=None
        ):
            with self.assertRaises(source_gate.GitHistoryUnavailable) as caught:
                source_gate.candidate_files()
        self.assertIn("git executable is not installed", str(caught.exception))

    def test_healthy_git_file_list_is_unchanged(self) -> None:
        """Invariant: with a working git the candidate set is git ls-files minus blocked prefixes."""
        git_init(self.root)
        self.write("packages/a.py")
        self.write("tools/b.sh")
        self.write("build/generated.txt")
        self.write("live-build/chroot/etc/passwd")
        with mock.patch.object(source_gate, "ROOT", self.root):
            candidates = source_gate.candidate_files()
        self.assertEqual(
            sorted(path.relative_to(self.root).as_posix() for path in candidates),
            ["packages/a.py", "tools/b.sh"],
        )

    def test_no_git_fallback_enumerates_the_working_tree(self) -> None:
        self.write(".gitleaks.toml", "title = 'x'\n")
        self.write("packages/a.py")
        self.write("build/generated.txt")
        self.write("live-build/cache/blob.bin")
        self.write("tools/__pycache__/a.cpython-312.pyc")
        # A debhelper staging tree: a rebuilt copy of files already enumerated.
        self.write("packages/pkg/debian/pkg/DEBIAN/control", "Package: pkg\n")
        self.write("packages/pkg/debian/pkg/usr/share/pkg/copied.conf", "GPGKey=AAA\n")
        # Real packaging source under debian/ must still be scanned.
        self.write("packages/pkg/debian/source/format", "3.0 (native)\n")
        (self.root / ".git").mkdir()
        self.write(".git/config", "[core]\n")
        with mock.patch.object(source_gate, "ROOT", self.root):
            candidates = source_gate.filesystem_candidate_files()
        self.assertEqual(
            sorted(path.relative_to(self.root).as_posix() for path in candidates),
            [".gitleaks.toml", "packages/a.py", "packages/pkg/debian/source/format"],
        )


class SecretGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.candidate = self.root / "packages" / "a.py"
        self.candidate.parent.mkdir(parents=True)
        self.candidate.write_text("print('hello')\n", encoding="utf-8")
        (self.root / ".gitleaks.toml").write_text("title = 'x'\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_secret_gates(self, *, scan_history: bool) -> tuple[list[str], str]:
        labels: list[str] = []
        stdout = io.StringIO()
        with mock.patch.object(source_gate, "ROOT", self.root), mock.patch.object(
            source_gate.shutil, "which", return_value="/usr/bin/gitleaks"
        ), mock.patch.object(
            source_gate, "run", side_effect=lambda label, *a, **k: labels.append(label)
        ), contextlib.redirect_stdout(stdout):
            source_gate.secret_gates(
                [self.candidate, self.root / ".gitleaks.toml"],
                scan_history=scan_history,
            )
        return labels, stdout.getvalue()

    def test_history_scan_runs_by_default(self) -> None:
        labels, _ = self.run_secret_gates(scan_history=True)
        self.assertEqual(len(labels), 2)
        self.assertIn("Gitleaks Git history", labels[1])

    def test_no_git_still_scans_the_tree_and_says_history_was_skipped(self) -> None:
        labels, output = self.run_secret_gates(scan_history=False)
        self.assertEqual(len(labels), 1)
        self.assertIn("Gitleaks candidate tree", labels[0])
        self.assertIn("Git history was NOT secret-scanned", output)


class ParserTests(unittest.TestCase):
    def test_no_git_flag_exists_and_defaults_off(self) -> None:
        parser = source_gate.build_parser()
        self.assertFalse(parser.parse_args([]).no_git)
        self.assertTrue(parser.parse_args(["--no-git"]).no_git)


class BuildTimeDownloaderTests(unittest.TestCase):
    def test_entry_parser_ignores_comments(self) -> None:
        content = """
        # libdvd-pkg is intentionally omitted
        bash
        libdvd-pkg # this active entry must fail
        """
        self.assertEqual(
            ["libdvd-pkg"],
            source_gate.forbidden_build_time_downloader_entries(content),
        )


if __name__ == "__main__":
    unittest.main()
