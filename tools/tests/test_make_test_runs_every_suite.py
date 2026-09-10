#!/usr/bin/env python3
"""`make test` must actually run every test suite in the tree.

packages/shadowfetch-fireline/tests/ is the one directory whose files the
Makefile names ONE BY ONE rather than handing to `unittest discover`, because
several of its suites are scripts rather than discoverable modules. That is a
list, and a list goes stale silently: test_checkpoint_hardening.py -- 38
passing tests over the checkpoint hardening -- was written, committed, and run
by nothing. Not `make test`, not the source gate, not CI. It passed the whole
time, which is the worst version of this: a suite everyone believes is
protecting them.

This test is the thing that would have caught that. It reads the `test:` recipe
out of the Makefile and asserts every test file in the tree is reached by it.
"""
from __future__ import annotations

import fnmatch
from pathlib import Path
import re
import shlex
import unittest

ROOT = Path(__file__).resolve().parents[2]
MAKEFILE = ROOT / "Makefile"

# Where suites live. A new directory here is a deliberate choice, and adding
# one without wiring it into `make test` is exactly the defect above.
SUITE_DIRS = tuple(sorted(
    [ROOT / "tools" / "tests"]
    + [p for p in ROOT.glob("packages/*/tests") if p.is_dir()]
))


def recipe(target: str) -> list[str]:
    """The recipe lines of one target, with backslash continuations joined."""
    text = MAKEFILE.read_text(encoding="utf-8")
    match = re.search(rf"(?m)^{re.escape(target)}:[^\n]*\n((?:\t[^\n]*\n|\n)*)", text)
    if match is None:
        raise AssertionError(f"no {target}: target in the Makefile")
    body = match.group(1).replace("\\\n", " ")
    return [line.strip() for line in body.splitlines() if line.strip()]


class MakeTestReachesEverySuite(unittest.TestCase):
    def setUp(self) -> None:
        self.lines = recipe("test")
        self.assertTrue(self.lines, "the test: target has no recipe")

    def covered(self, path: Path) -> bool:
        relative = path.relative_to(ROOT).as_posix()
        for line in self.lines:
            if relative in line:
                return True
            try:
                words = shlex.split(line)
            except ValueError:
                words = line.split()
            if "discover" not in words:
                continue
            if "-s" not in words:
                continue
            directory = (ROOT / words[words.index("-s") + 1]).resolve()
            if directory != path.parent.resolve():
                continue
            pattern = words[words.index("-p") + 1] if "-p" in words else "test*.py"
            if fnmatch.fnmatch(path.name, pattern):
                return True
        return False

    def test_the_suite_directories_are_all_still_there(self) -> None:
        """If this list empties, every assertion below passes vacuously."""
        self.assertGreaterEqual(len(SUITE_DIRS), 8, [str(d) for d in SUITE_DIRS])

    def test_every_test_file_is_reached_by_make_test(self) -> None:
        missed = []
        checked = 0
        for directory in SUITE_DIRS:
            for path in sorted(directory.rglob("test_*.py")):
                if "__pycache__" in path.parts:
                    continue
                checked += 1
                if not self.covered(path):
                    missed.append(path.relative_to(ROOT).as_posix())
        self.assertGreater(checked, 50, "the sweep found almost no test files")
        self.assertEqual([], missed,
                         "these suites exist and `make test` never runs them:\n  "
                         + "\n  ".join(missed))

    def test_every_shell_suite_is_reached_too(self) -> None:
        missed = [p.relative_to(ROOT).as_posix()
                  for directory in SUITE_DIRS
                  for p in sorted(directory.rglob("test_*.sh"))
                  if not any(p.relative_to(ROOT).as_posix() in line
                             for line in self.lines)]
        self.assertEqual([], missed, "\n  ".join(missed))

    def test_a_planted_orphan_is_caught(self) -> None:
        """The check above is only worth having if it fails on the real thing.

        Proven against a name that is NOT in the Makefile rather than by
        writing a file into the tree: covered() is the whole mechanism, and a
        test that creates files in packages/ to test itself is a worse trade.
        """
        orphan = ROOT / "packages/shadowfetch-fireline/tests/test_not_wired_up.py"
        self.assertFalse(orphan.exists(), "this fixture name is now a real file")
        self.assertFalse(self.covered(orphan))
        wired = ROOT / "packages/shadowfetch-fireline/tests/test_checkpoint_hardening.py"
        self.assertTrue(wired.exists())
        self.assertTrue(self.covered(wired))


if __name__ == "__main__":
    unittest.main()
