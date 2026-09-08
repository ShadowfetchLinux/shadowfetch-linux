"""Phase 3 Steps 19, 20, 21: waking, locking, and reconciling.

The baseline measured what these cost: 60 wake-ups, 479 SQL statements and 3,240
POSIX record locks per minute at idle, 0.128% of a core, 225 MiB/hour of page
cache dirtied, and a 0.447s median wake latency -- all with an EMPTY queue. The
tests here pin the BEHAVIOUR that made those numbers possible; the numbers
themselves are in PHASE3_TEST_RESULTS.md, because a timing assertion in CI is a
flake generator.
"""
import os
import sys
import threading
import time
import unittest
from pathlib import Path

import mission_states
from test_schema_migration import MigrationHarness, Store

sys.path.insert(0, str(Path(__file__).resolve().parents[1]
                       / "data/usr/lib/shadowfetch/missions"))
import sf_missions as sf


class WakeupBehaviour(MigrationHarness):
    def setUp(self):
        super().setUp()
        self.store = Store(self.root)

    def test_a_write_wakes_the_waiter(self):
        wake = sf.Wakeup(self.store.root)
        self.addCleanup(wake.close)
        if not wake.event_driven:
            self.skipTest("inotify is unavailable here; the fallback path is "
                          "covered by test_without_inotify_it_still_returns")
        while wake.wait(timeout=0.05):
            pass                                   # drain
        started = threading.Event()

        def writer():
            started.wait()
            self.store.append_event("mission-x", "probe", "x")

        thread = threading.Thread(target=writer)
        thread.start()
        started.set()
        self.assertTrue(wake.wait(timeout=5),
                        "a database write did not wake the worker")
        thread.join()

    def test_an_idle_waiter_blocks_for_the_whole_timeout(self):
        """The baseline woke 60 times a minute with an empty queue. Blocking is
        the entire point; a wait that returns early is a poll."""
        wake = sf.Wakeup(self.store.root)
        self.addCleanup(wake.close)
        while wake.wait(timeout=0.05):
            pass
        start = time.monotonic()
        woke = wake.wait(timeout=1.0)
        elapsed = time.monotonic() - start
        self.assertFalse(woke, "something woke an idle waiter")
        self.assertGreaterEqual(elapsed, 0.9,
                                "an idle wait returned early, which is a poll")

    def test_without_inotify_it_still_returns_and_says_so(self):
        """Degrading is fine. Degrading silently is not: a fallback that looked
        event-driven would hide a stall behind an apparently healthy worker."""
        wake = sf.Wakeup("/nonexistent/directory/for/this/test")
        self.addCleanup(wake.close)
        self.assertFalse(wake.event_driven)
        self.assertTrue(wake.reason, "a degraded waiter must say why")
        start = time.monotonic()
        self.assertFalse(wake.wait(timeout=0.3))
        self.assertGreaterEqual(time.monotonic() - start, 0.25)

    def test_the_fallback_is_a_backstop_not_a_poll_interval(self):
        self.assertGreaterEqual(sf.WAKE_FALLBACK_SECONDS, 10,
                                "a short fallback is a poll wearing another name")


class WorkspaceLocking(MigrationHarness):
    def setUp(self):
        super().setUp()
        self.store = Store(self.root)

    def held(self, workspace, results, key, hold=0.0):
        try:
            with self.store.lock(workspace=workspace):
                results[key] = "acquired"
                time.sleep(hold)
        except sf.MissionError as exc:
            results[key] = "refused: " + str(exc)

    def test_two_workspaces_run_at_the_same_time(self):
        """The whole reason max_parallel was 1."""
        results = {}
        first = threading.Thread(target=self.held, args=("alpha", results, "alpha", 0.5))
        first.start()
        time.sleep(0.1)
        self.held("beta", results, "beta")
        first.join()
        self.assertEqual(results["alpha"], "acquired")
        self.assertEqual(results["beta"], "acquired")

    def test_one_workspace_is_still_serialized(self):
        """Two writers on one workspace make Undo meaningless: it is defined
        against a checkpoint, and 'restore to before' needs one before."""
        results = {}
        first = threading.Thread(target=self.held, args=("alpha", results, "first", 0.5))
        first.start()
        time.sleep(0.1)
        self.held("alpha", results, "second")
        first.join()
        self.assertEqual(results["first"], "acquired")
        self.assertTrue(results["second"].startswith("refused"))
        self.assertIn("alpha", results["second"],
                      "the refusal should name the contended workspace")

    def test_the_whole_system_lock_still_excludes_every_workspace(self):
        """The hierarchy. My first version gave each workspace its own file and
        nothing else, so a worker in recovery -- exactly when nothing may start
        -- stopped excluding anything."""
        results = {}

        def globally():
            with self.store.lock():
                results["global"] = "acquired"
                time.sleep(0.5)

        thread = threading.Thread(target=globally)
        thread.start()
        time.sleep(0.1)
        self.held("alpha", results, "during")
        thread.join()
        self.assertEqual(results["global"], "acquired")
        self.assertTrue(results["during"].startswith("refused"))

    def test_a_workspace_holder_excludes_the_whole_system_lock(self):
        """The other direction, or recovery could run while a mission executes."""
        results = {}
        thread = threading.Thread(target=self.held, args=("alpha", results, "ws", 0.5))
        thread.start()
        time.sleep(0.1)
        try:
            with self.store.lock():
                results["global"] = "acquired"
        except sf.MissionError as exc:
            results["global"] = "refused: " + str(exc)
        thread.join()
        self.assertTrue(results["global"].startswith("refused"))

    def test_the_lock_file_name_is_a_digest_not_the_workspace_name(self):
        """A workspace name is user-supplied and would otherwise choose a
        filename in the state directory."""
        path, label = self.store.lock_path("../../etc/passwd")
        self.assertEqual(path.parent, self.store.root)
        self.assertNotIn("..", path.name)
        self.assertNotIn("/", path.name)
        self.assertEqual(label, "../../etc/passwd",
                         "the human label still names the real workspace")


class Reconciliation(MigrationHarness):
    def setUp(self):
        super().setUp()
        self.store = Store(self.root)
        ws = Path(os.environ["SHADOWFETCH_AGENT_WORKSPACES"]) / "proj"
        ws.mkdir(parents=True, exist_ok=True)
        (ws / "a.mkv").write_bytes(b"x")

    def mission(self):
        return self.store.create(capability="media_export",
                                 provider_id="offline-media", workspace_value="proj",
                                 title="t", prompt="p", inputs=["a.mkv"])["id"]

    def test_a_stale_task_is_settled_not_left_running(self):
        """A row saying 'running' about a process that died is worse than no
        row, because a reader believes it."""
        mid = self.mission()
        self.store.transition(mid, "running")
        task = self.store.create_task(mid, kind="inference", seq=1)
        self.store.task_transition(task["id"], sf.TaskState.RUNNING)
        with self.store.lock():
            self.store.reconcile(reason="test")
        self.assertEqual(self.store.task(task["id"])["state"], sf.TaskState.FAILED)

    def test_a_stale_session_is_closed(self):
        mid = self.mission()
        self.store.transition(mid, "running")
        sid = self.store.open_session(
            mid, task_id=None, provider_id="offline-media", provider_version="4.0.0",
            provider_trust="distro-managed", attempt=1, requested_sandbox={},
            effective_sandbox={}, enforcement={})
        with self.store.lock():
            self.store.reconcile(reason="test")
        session = self.store.session(sid)
        self.assertIsNotNone(session["ended_at"])
        self.assertIn("interrupted", session["outcome"])

    def test_the_mission_itself_still_reaches_a_terminal_state(self):
        mid = self.mission()
        self.store.transition(mid, "running")
        with self.store.lock():
            self.store.reconcile(reason="test")
        self.assertEqual(self.store.get(mid)["state"], "failed")

    def test_a_cancelled_mission_reconciles_to_cancelled(self):
        mid = self.mission()
        self.store.transition(mid, "running")
        self.store.cancel(mid)
        with self.store.lock():
            self.store.reconcile(reason="test")
        self.assertEqual(self.store.get(mid)["state"], "cancelled")

    def test_waiting_work_is_reported_and_left_alone(self):
        """A mission awaiting a person is in a CORRECT state. 'Fixing' it would
        discard the wait."""
        mid = self.mission()
        mission_states.reach(self.store, mid, "waiting-review")
        before = self.store.get(mid)
        with self.store.lock():
            found = self.store.reconcile(reason="test")
        self.assertEqual(found["reviews"], 1)
        self.assertEqual(self.store.get(mid), before, "a waiting mission was altered")

    def test_reconciling_a_quiet_system_emits_nothing(self):
        """An event every startup would drown the log it is meant to serve."""
        self.mission()
        before = len(self.store.events("*")) if False else None
        with self.store.db() as db:
            before = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        with self.store.lock():
            self.store.reconcile(reason="test")
        with self.store.db() as db:
            after = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        self.assertEqual(before, after)

    def test_reconciliation_is_scoped_to_the_workspace_it_holds(self):
        """Recovering a mission on a workspace somebody else is executing would
        mark a LIVE mission failed."""
        other = Path(os.environ["SHADOWFETCH_AGENT_WORKSPACES"]) / "other"
        other.mkdir(exist_ok=True)
        (other / "a.mkv").write_bytes(b"x")
        mine = self.mission()
        theirs = self.store.create(capability="media_export",
                                   provider_id="offline-media", workspace_value="other",
                                   title="t", prompt="p", inputs=["a.mkv"])["id"]
        self.store.transition(mine, "running")
        self.store.transition(theirs, "running")
        with self.store.lock(workspace="proj"):
            self.store.reconcile(workspace="proj", reason="test")
        self.assertEqual(self.store.get(mine)["state"], "failed")
        self.assertEqual(self.store.get(theirs)["state"], "running",
                         "another workspace's live mission was settled")


if __name__ == "__main__":
    unittest.main(verbosity=2)
