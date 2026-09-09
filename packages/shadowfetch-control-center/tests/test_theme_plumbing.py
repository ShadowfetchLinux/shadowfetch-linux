"""Theme plumbing: one palette source, and the element reaching every screen.

Stage P's brief names "theme plumbing" among the duplications to remove.  Two
were live in this package:

  * app.py painted the sidebar well from a bare `#101114`, one of the unnamed
    shipped colours tools/drift_gate.py reports.  It is `theme.SIDEBAR` now.
  * guide_page.py's System Passport document hard-coded `#d8a24a` -- Fire's
    gold -- and `#e2533b`, a second spelling of `theme.RED`.  So the System
    Passport stayed gold on an Ice desktop: the element did not reach the one
    page a person opens to read what their system is.

What is NOT fixed, and is not claimed to be: the rest of that document's web
palette is still unnamed literals, and so are the ones in grok_bot_page.py.
tools/drift_gate.py reports them as a single BLOCKED finding whose remedy is a
palette.json shipped from shadowfetch-branding and imported by sfcc, Welcome
and Fireproof -- three packages, none of them this one.
"""
import os
import sys
import unittest
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
CC = Path(__file__).resolve().parents[1]
SFCC = CC / "data/usr/share/shadowfetch/control-center/sfcc"
sys.path.insert(0, str(SFCC.parent))

from PyQt6.QtWidgets import QApplication  # noqa: E402

from sfcc import guide_page, theme  # noqa: E402

APP = QApplication.instance() or QApplication([])

DOCUMENT = {"release_version": "4.0.0", "generated_at": "now", "checks": [],
            "verdict": {"title": "T", "summary": "S"}}


class TheElementReachesTheGuide(unittest.TestCase):
    def test_the_passport_accent_is_the_themes_accent(self):
        self.assertIn(theme.GOLD, guide_page._report_html(DOCUMENT))

    def test_the_fire_accent_is_not_written_into_the_document(self):
        """On Ice the literal must be absent, which is the whole finding: a
        hard-coded accent looks right in exactly one element."""
        if theme.ELEMENT == "ice":
            self.assertNotIn("#d8a24a", guide_page._report_html(DOCUMENT))
        else:
            self.assertEqual("#d8a24a", theme.GOLD)

    def test_the_alarm_colour_has_one_spelling(self):
        source = (SFCC / "guide_page.py").read_text(encoding="utf-8")
        self.assertNotIn("#e2533b", source,
                         "theme.RED is spelled out again in the passport CSS")
        self.assertIn(theme.RED, guide_page._report_html(DOCUMENT))


class TheShellPaintsFromTheme(unittest.TestCase):
    def test_the_sidebar_well_is_a_named_colour(self):
        source = (SFCC / "app.py").read_text(encoding="utf-8")
        self.assertNotIn("#101114", source,
                         "the sidebar colour is a bare literal in app.py again")
        self.assertEqual("#101114", theme.SIDEBAR)


if __name__ == "__main__":
    unittest.main(verbosity=2)
