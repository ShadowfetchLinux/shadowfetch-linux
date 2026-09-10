#!/usr/bin/env python3
"""tools/release/README.md tells whoever cuts a release which version sites
they must edit by hand. It described the OLD stamper: it named four sites as
hand-maintained that the rewritten stamper had taken over -- the grok-bot
--version string, the drkonqi CMake project version, VERSION in
tools/drkonqi_pickup_contract.py and the README fact table -- so following it
meant editing four files the stamper was about to rewrite, and believing the
rest of the list was complete.

The list is prose and has to stay prose; what it must not do is contradict
VERSION_SITES, which is the thing that actually runs.
"""
from __future__ import annotations

from pathlib import Path
import sys
import unittest

TOOLS = Path(__file__).resolve().parents[1]
ROOT = TOOLS.parent
sys.path.insert(0, str(TOOLS))

import drift_gate  # noqa: E402

README = TOOLS / "release" / "README.md"
MARKER = "Genuinely hand-maintained:"


class HandMaintainedListTests(unittest.TestCase):
    def setUp(self) -> None:
        self.text = README.read_text(encoding="utf-8")
        self.sites = sorted({rel for rel, _, _ in drift_gate.VERSION_SITES})
        self.assertGreaterEqual(len(self.sites), 8, self.sites)

    def clause(self) -> str:
        """The sentence claiming which sites a human still has to edit."""
        self.assertIn(MARKER, self.text,
                      f"{README.name} no longer says what is hand-maintained")
        start = self.text.index(MARKER)
        rest = self.text[start:]
        stop = rest.find("\n\n")
        return rest if stop == -1 else rest[:stop]

    def test_nothing_the_stamper_owns_is_called_hand_maintained(self) -> None:
        clause = self.clause()
        wrong = [rel for rel in self.sites if rel in clause]
        self.assertEqual([], wrong,
                         "the README tells a release engineer to hand-edit "
                         "sites tools/stamp_version.py rewrites:\n  "
                         + "\n  ".join(wrong))

    def test_the_readme_points_at_the_list_that_runs(self) -> None:
        """Prose that restates a list goes stale; prose that names it does not."""
        self.assertIn("VERSION_SITES", self.text)
        self.assertIn("tools/drift_gate.py", self.text)

    def test_the_genuinely_hand_maintained_sites_really_are(self) -> None:
        """The two it still names must NOT be on the list, or this file is
        telling the truth about the wrong thing."""
        clause = self.clause()
        for hand in ("debian/changelog", "show.qml"):
            with self.subTest(site=hand):
                self.assertIn(hand, clause)
                self.assertEqual([], [rel for rel in self.sites if hand in rel])


if __name__ == "__main__":
    unittest.main()
