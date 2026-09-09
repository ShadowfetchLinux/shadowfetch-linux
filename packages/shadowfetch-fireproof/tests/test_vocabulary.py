"""One vocabulary: simulate, approve, commit, verify, rollback.

Two updaters meant two sets of words for the same five things, and the
words were where the dishonesty could hide: "simulation passed" reads like
"the update is safe", "Phoenix Point recorded" reads like "you can roll
back", "verify" reads like "the desktop will come up". These tests pin the
five steps, pin the claim each one is NOT allowed to make, and fail if a
sixth word appears in a user-facing surface.
"""
import pathlib
import re
import unittest

from stubs import install_stubs

install_stubs()   # puts the shipped sfupdate/ and phoenix/ on sys.path

from sfupdate.vocabulary import (                            # noqa: E402
    ORDER, STEPS, Step, claims, describe, forbids)

HERE = pathlib.Path(__file__).resolve().parent
FIREPROOF_PKG = HERE.parent
CLI = FIREPROOF_PKG / "data/usr/bin/fireproof"
DAEMON = FIREPROOF_PKG / "data/usr/libexec/fireproofd"
SHIM = (FIREPROOF_PKG.parent / "shadowfetch-defaults"
        / "data/usr/bin/shadowfetch-update")


class TestTheVocabularyIsClosed(unittest.TestCase):
    def test_there_are_exactly_five_steps_in_a_fixed_order(self):
        self.assertEqual(
            ["simulate", "approve", "commit", "verify", "rollback"],
            [step.value for step in ORDER])
        self.assertEqual(set(ORDER), set(Step))
        self.assertEqual(set(ORDER), set(STEPS))

    def test_every_step_states_what_it_may_not_claim(self):
        for step in Step:
            entry = describe(step)
            for key in ("summary", "mechanism", "produces", "claims",
                        "forbids", "surfaces"):
                self.assertTrue(entry[key], "%s.%s is empty" % (step, key))
            self.assertNotEqual(claims(step), forbids(step))

    def test_the_steps_are_not_interchangeable(self):
        # The whole point of the vocabulary: no two steps make the same
        # claim, so reporting one when you did another is detectable.
        made = [claims(step) for step in Step]
        self.assertEqual(len(made), len(set(made)))

    def test_simulate_forbids_the_claims_that_belong_to_later_steps(self):
        text = forbids(Step.SIMULATE)
        for word in ("locked", "downloaded", "installed", "approved"):
            self.assertIn(word, text)

    def test_commit_does_not_claim_the_machine_works(self):
        self.assertIn("VERIFY", forbids(Step.COMMIT))

    def test_verify_never_claims_a_graphical_login(self):
        self.assertIn("graphical login", forbids(Step.VERIFY))

    def test_rollback_forbids_the_silent_zero(self):
        self.assertIn("unavailable", forbids(Step.ROLLBACK))


class TestSurfacesUseTheVocabulary(unittest.TestCase):
    def test_every_named_surface_exists_in_the_shipped_source(self):
        cli = CLI.read_text()
        daemon = DAEMON.read_text()
        shim = SHIM.read_text()
        haystack = cli + daemon + shim
        for step in Step:
            for surface in describe(step)["surfaces"]:
                token = surface.split(".")[-1].split("(")[0].strip()
                self.assertIn(token, haystack,
                              "%s names a surface nothing implements: %s"
                              % (step.value, surface))

    def test_the_shim_help_teaches_the_same_five_words(self):
        text = SHIM.read_text()
        block = text.split("THE FIVE STEPS", 1)[1]
        for step in Step:
            self.assertRegex(block, r"(?m)^  %s\s" % step.value)

    def test_no_surface_reintroduces_a_second_updater_vocabulary(self):
        # Words the deleted duplicate used for the same five things. Their
        # return means a second vocabulary - and, historically, a second
        # mechanism - is growing back.
        # Identifiers and proper nouns only. "safe updates" as ordinary
        # prose is not a second vocabulary; `plan_fingerprint` is.
        retired = ("Safe Update", "plan_fingerprint", "simulate_upgrade",
                   "validate_removals", "package_lock_busy",
                   "write_snapper_rows", "load_migration_plan")
        for path in (CLI, DAEMON, SHIM):
            text = path.read_text()
            for word in retired:
                self.assertNotIn(word, text, "%s: %s" % (path.name, word))


class TestTheDaemonStillSeparatesTheSteps(unittest.TestCase):
    """Named phases in fireproofd must map onto the vocabulary."""

    def test_the_commit_worker_keeps_its_phases_distinct(self):
        source = DAEMON.read_text()
        phases = set(re.findall(r'_set_phase\("([a-z-]+)"\)', source))
        self.assertEqual(
            {"locking", "revalidating", "downloading", "news", "committing",
             "verifying"},
            phases)

    def test_analyze_is_not_allowed_to_call_itself_a_commit(self):
        source = DAEMON.read_text()
        analyze = source.split("def Analyze(", 1)[1].split("def GetState", 1)[0]
        for forbidden in ("cache.commit", "fetch_archives", "get_lock"):
            self.assertNotIn(forbidden, analyze)

    def test_verify_has_exactly_three_verdicts(self):
        source = DAEMON.read_text()
        verdicts = set(re.findall(r'verdict = "([a-z-]+)"', source))
        self.assertEqual({"ok", "reboot-recommended", "restore-recommended"},
                         verdicts)


if __name__ == "__main__":
    unittest.main()
