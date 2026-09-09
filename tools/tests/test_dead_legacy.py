"""The dead legacy stays dead (W-69).

Three files were tracked, read by nothing, and named by every audit that looked
at this tree. They survived because nothing pinned their presence OR their
absence: an audit finding is a sentence in a document, and a document does not
fail a build.

The one that mattered was `weekly_release.sh` -- an executable, cron-driven
release script that sourced credentials from `~/.hermes/profiles/elaine/.env`
(a crew erased in August), read a Discord bot token out of another profile,
held scoped passwordless sudo for `lb`, `grub-mkrescue`, `chown` and `chmod`,
built an ISO from `$HOME/projects/shadowfetch` (which does not exist) and
PUBLISHED it. Nothing invoked it. It would have taken one restored profile
directory to make it live again.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]

GONE = {
    "weekly_release.sh":
        "an unattended release script sourcing an erased crew's credentials, "
        "with passwordless sudo and a publish step",
    "packages.manifest":
        "a package list frozen at 2.1.1-1, read by nothing; the release "
        "evidence packager generates packages-<version>.manifest instead",
}


class TheDeadLegacyStaysDead(unittest.TestCase):
    def test_none_of_them_came_back(self):
        for name, why in GONE.items():
            with self.subTest(name=name):
                self.assertFalse((ROOT / name).exists(),
                                 f"{name} is back: {why}")

    def test_nothing_references_them(self):
        """Deleting a file that something still calls is a different defect."""
        skip = {".git", "live-build", "chroot", "work", "__pycache__", "build",
                "repo", "node_modules"}
        haystack = []
        # os.walk with the prune done on `dirs`, not rglob with the prune done
        # after: rglob descends into the live-build chroot, where a dangling
        # symlink makes is_file() raise before any filter can see it.
        import os
        for directory, dirs, files in os.walk(ROOT):
            dirs[:] = [d for d in dirs if d not in skip and not d.startswith(".")]
            for name in files:
                path = Path(directory) / name
                if path.suffix not in (".py", ".sh", ".md", ".yml"):
                    continue
                if path.name == Path(__file__).name:
                    continue
                try:
                    haystack.append((path, path.read_text(encoding="utf-8")))
                except (OSError, UnicodeDecodeError):
                    continue
        for name in GONE:
            with self.subTest(name=name):
                # ARCHITECTURE_AUDIT.md names them as findings; that is a
                # record of why they went, not a caller.
                callers = [str(p.relative_to(ROOT)) for p, text in haystack
                           if name in text
                           # A document that RECORDS the file -- an audit
                           # finding, a decision, a roadmap entry, a risk note
                           # -- is why it went, not something that calls it.
                           # Every other mention is a caller until proven
                           # otherwise, which is the point of this test.
                           and p.name not in ("ARCHITECTURE_AUDIT.md",
                                              "ARCHITECTURE_DECISIONS.md",
                                              "FIRE_ROADMAP.md",
                                              "FINAL_REMAINING_RISKS.md")]
                self.assertEqual(callers, [], f"{name} is still referenced")

    def test_the_ci_secrets_document_describes_the_pipeline_that_exists(self):
        """It used to instruct exporting the ISO and APT signing private key
        into GitHub Actions, for a release pipeline that does not exist.
        Writing down how to hand a signing key to a workflow with no use for it
        is an instruction to widen a CI account's blast radius for no gain."""
        secrets = (ROOT / ".github/CI-SECRETS.md").read_text(encoding="utf-8")
        workflow = (ROOT / ".github/workflows/build-iso.yml").read_text(encoding="utf-8")
        self.assertNotIn("secrets.", workflow,
                         "the workflow now uses a secret; this document must "
                         "describe it, and this test must be updated")
        self.assertIn("There are none", secrets)
        for forbidden in ("export the signing key", "RELEASE_GITHUB_TOKEN=",
                          "gpg --export-secret"):
            self.assertNotIn(forbidden, secrets)


if __name__ == "__main__":
    unittest.main(verbosity=2)
