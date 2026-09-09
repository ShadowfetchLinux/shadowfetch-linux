"""Unit tests for the live source gate (tools/release/source_gate.py).

Before Stage Q these tests were split across test_source_gate_2_1_4.py,
test_source_gate_2_1_5.py and test_source_gate_4_0_0.py, two of which exercised
archived copies. They now run against the one implementation that actually
gates a release.
"""

from __future__ import annotations

import contextlib
import importlib.machinery
import importlib.util
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


TOOLS = Path(__file__).resolve().parents[1]
RELEASE_DIR = TOOLS / "release"
if str(RELEASE_DIR) not in sys.path:
    sys.path.insert(0, str(RELEASE_DIR))

import gate  # noqa: E402

SRC = RELEASE_DIR / "source_gate.py"
_loader = importlib.machinery.SourceFileLoader("release_source_gate_test", str(SRC))
_spec = importlib.util.spec_from_loader("release_source_gate_test", _loader)
source_gate = importlib.util.module_from_spec(_spec)
_loader.exec_module(source_gate)


def trusted(name: str, path: str = "/usr/bin/placeholder") -> gate.TrustedProgram:
    """A resolved-program stand-in, so a test need not have the tool installed."""
    return gate.TrustedProgram(
        name=name, path=Path(path), trust=gate.TRUST_SYSTEM, role=gate.ROLE_SECURITY
    )


def system_git() -> gate.TrustedProgram | None:
    try:
        return gate.ProgramResolver().resolve("git", gate.ROLE_SECURITY)
    except gate.UntrustedProgram:
        return None


GIT = system_git()


@unittest.skipUnless(GIT is not None, "a trusted git is required")
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
        """The tree is not a repository: say so, do not raise CalledProcessError."""
        self.write("packages/a.py")
        with mock.patch.object(source_gate, "ROOT", self.root):
            with self.assertRaises(source_gate.GitHistoryUnavailable) as caught:
                source_gate.candidate_files(GIT)
        message = str(caught.exception)
        self.assertIn("Git is unusable", message)
        self.assertIn("Git-history secret scan cannot run", message)
        self.assertIn("--no-git", message)

    def test_healthy_git_file_list_is_unchanged(self) -> None:
        """Invariant: candidates are git ls-files minus the blocked prefixes."""
        subprocess.run(GIT.argv("init", "-q"), cwd=self.root, check=True)
        self.write("packages/a.py")
        self.write("tools/b.sh")
        self.write("build/generated.txt")
        self.write("live-build/chroot/etc/passwd")
        with mock.patch.object(source_gate, "ROOT", self.root):
            candidates = source_gate.candidate_files(GIT)
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

    def run_secret_gates(self, *, scan_history: bool) -> tuple[list[str], str, list]:
        labels: list[str] = []
        commands: list[list[str]] = []

        def record(label, command, *args, **kwargs):
            labels.append(label)
            commands.append(command)

        stdout = io.StringIO()
        with mock.patch.object(source_gate, "ROOT", self.root), mock.patch.object(
            source_gate, "run", side_effect=record
        ), contextlib.redirect_stdout(stdout):
            source_gate.secret_gates(
                [self.candidate, self.root / ".gitleaks.toml"],
                trusted("gitleaks", "/usr/bin/gitleaks"),
                scan_history=scan_history,
            )
        return labels, stdout.getvalue(), commands

    def test_history_scan_runs_by_default(self) -> None:
        labels, _, _ = self.run_secret_gates(scan_history=True)
        self.assertEqual(len(labels), 2)
        self.assertIn("Gitleaks Git history", labels[1])

    def test_no_git_still_scans_the_tree_and_says_history_was_skipped(self) -> None:
        labels, output, _ = self.run_secret_gates(scan_history=False)
        self.assertEqual(len(labels), 1)
        self.assertIn("Gitleaks candidate tree", labels[0])
        self.assertIn("Git history was NOT secret-scanned", output)

    def test_gitleaks_is_invoked_by_absolute_path_not_by_name(self) -> None:
        """The invariant, at the call site that decides whether a secret shipped."""
        _, _, commands = self.run_secret_gates(scan_history=True)
        for command in commands:
            self.assertTrue(
                command[0].startswith("/"),
                f"secret scan invoked a bare program name: {command[0]!r}",
            )
            self.assertEqual("/usr/bin/gitleaks", command[0])


class ParserTests(unittest.TestCase):
    def test_no_git_flag_exists_and_defaults_off(self) -> None:
        parser = source_gate.build_parser()
        self.assertFalse(parser.parse_args([]).no_git)
        self.assertTrue(parser.parse_args(["--no-git"]).no_git)

    def test_the_gate_takes_its_release_from_a_version_data_file(self) -> None:
        parser = source_gate.build_parser()
        self.assertIsNone(parser.parse_args([]).version)
        self.assertEqual("4.0.0", parser.parse_args(["--version", "4.0.0"]).version)


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
