"""Phase 3 Step 11: cancellation, measured rather than assumed.

The empirical class runs REAL sandboxed processes and asserts they are gone
afterwards, because "we send SIGTERM" is a description of our own code and the
question is what happens to somebody else's.
"""
import os
import shutil
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

import mission_approvals
import mission_states
from test_schema_migration import MigrationHarness, Store

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "packages/shadowfetch-missions/data/usr/lib/shadowfetch/missions"))
import sf_missions as sf

FIREBREAK = REPO / "packages/shadowfetch-fireline/data/usr/bin/shadowfetch-firebreak"


def sandbox_available():
    if not (shutil.which("bwrap") and shutil.which("systemd-run")):
        return False
    probe = subprocess.run(["systemctl", "--user", "is-system-running"],
                           capture_output=True, text=True)
    return probe.returncode == 0 or "running" in probe.stdout or "degraded" in probe.stdout


def sleeping_processes():
    count = 0
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            if os.readlink(entry / "exe") == "/usr/bin/sleep":
                count += 1
        except OSError:
            continue
    return count


class CancelStateMachine(MigrationHarness):
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

    def test_cancelling_a_queued_mission_is_immediate_and_recorded(self):
        mid = self.mission()
        self.store.cancel(mid)
        row = self.store.get(mid)
        self.assertEqual(row["state"], "cancelled")
        self.assertEqual(row["cancel_requested"], 1)
        self.assertEqual(self.store.events(mid)[-1]["event"], "cancelled")

    def test_cancelling_a_running_mission_asks_rather_than_tells(self):
        """The state must not move until execution actually stops, or the log
        claims something ended that is still running."""
        mid = self.mission()
        self.store.transition(mid, "running")
        self.store.cancel(mid)
        self.assertEqual(self.store.get(mid)["state"], "running")
        self.assertEqual(self.store.get(mid)["cancel_requested"], 1)

    def test_repeated_cancel_is_idempotent(self):
        mid = self.mission()
        self.store.transition(mid, "running")
        self.store.cancel(mid)
        before = len(self.store.events(mid))
        self.store.cancel(mid)
        self.store.cancel(mid)
        self.assertEqual(len(self.store.events(mid)), before,
                         "pressing Stop twice must not imply two decisions")

    def test_cancel_is_refused_once_a_mission_is_finished(self):
        mid = self.mission()
        mission_states.reach(self.store, mid, "completed")
        with self.assertRaises(sf.MissionError):
            self.store.cancel(mid)

    def test_a_restart_after_a_cancel_request_records_cancelled_not_failed(self):
        """The person asked to stop; the worker then died before saying so.
        Calling that a failure invites a retry of work somebody stopped."""
        mid = self.mission()
        self.store.transition(mid, "running")
        self.store.cancel(mid)
        self.store.recover()
        row = self.store.get(mid)
        self.assertEqual(row["state"], "cancelled")
        self.assertIn("Cancelled", row["error"])
        self.assertEqual(self.store.events(mid)[-1]["event"], "cancelled")

    def test_a_restart_with_no_cancel_request_still_records_failed(self):
        mid = self.mission()
        self.store.transition(mid, "running")
        self.store.recover()
        self.assertEqual(self.store.get(mid)["state"], "failed")

    def test_cancel_does_not_undo_the_workspace(self):
        """Cancel and Undo are different actions, and conflating them would
        destroy work the person may want to keep."""
        ws = Path(os.environ["SHADOWFETCH_AGENT_WORKSPACES"]) / "proj"
        (ws / "written-during-the-run.txt").write_text("keep me")
        mid = self.mission()
        self.store.transition(mid, "running")
        self.store.cancel(mid)
        self.assertTrue((ws / "written-during-the-run.txt").exists())

    def test_a_cancelled_mission_can_be_retried(self):
        mid = self.mission()
        mission_states.reach(self.store, mid, "cancelled")
        self.store.retry(mid)
        row = self.store.get(mid)
        self.assertEqual(row["state"], "queued")
        self.assertEqual(row["cancel_requested"], 0,
                         "a retry must clear the stale request or it cancels itself")


class CancelDuringExecution(MigrationHarness):
    def setUp(self):
        super().setUp()
        self.store = Store(self.root)
        ws = Path(os.environ["SHADOWFETCH_AGENT_WORKSPACES"]) / "proj"
        ws.mkdir(parents=True, exist_ok=True)
        (ws / "facts.md").write_text("The launch is Friday.\n")

    def test_a_cancel_mid_turn_stops_the_mission_and_preserves_evidence(self):
        mission = self.store.create(kind="report", workspace_value="proj", title="t",
                                    prompt="p", inputs=["facts.md"], network="allow")
        mission_approvals.approve(self.store, mission)
        mid = mission["id"]

        def slow_turn(executor, prompt, **kwargs):
            self.store.cancel(mid)
            executor.check()                      # the poll point cancellation uses
            return "never reached"

        with mock.patch.object(sf.Executor, "agent_turn", slow_turn):
            result = sf.run_mission(self.store, mid)
        self.assertEqual(result["state"], "cancelled")
        names = [e["event"] for e in self.store.events(mid)]
        self.assertIn("cancel-requested", names)
        self.assertIn("cancelled", names)
        # the mission directory survives: cancel is not undo
        self.assertTrue(self.store.directory(mid).exists())
        self.assertTrue(self.store.verify_chain()["ok"])

    def test_a_cancelled_run_closes_its_session_and_settles_its_task(self):
        """A session or task left RUNNING forever is exactly the shape the
        baseline had for missions."""
        mission = self.store.create(kind="report", workspace_value="proj", title="t",
                                    prompt="p", inputs=["facts.md"], network="allow")
        mission_approvals.approve(self.store, mission)
        mid = mission["id"]

        def cancel_mid_turn(executor, prompt, **kwargs):
            self.store.cancel(mid)
            executor.check()
            return "never reached"

        with mock.patch.object(sf.Executor, "agent_turn", cancel_mid_turn):
            sf.run_mission(self.store, mid)
        for task in self.store.tasks(mid):
            self.assertNotEqual(task["state"], sf.TaskState.RUNNING,
                                f"task {task['kind']} was left running")
        for session in self.store.sessions(mid):
            self.assertIsNotNone(session["ended_at"],
                                 "a session was left open after cancellation")

    def test_the_cancel_race_with_completion_does_not_lose_the_result(self):
        """A cancel arriving after the work finished must not discard evidence
        that already exists. The mission completes; the request is recorded."""
        mission = self.store.create(kind="report", workspace_value="proj", title="t",
                                    prompt="p", inputs=["facts.md"], network="allow")
        mission_approvals.approve(self.store, mission)
        mid = mission["id"]
        with mock.patch.object(sf.Executor, "agent_turn", return_value="Friday. [S1:L1]"):
            result = sf.run_mission(self.store, mid)
        self.assertEqual(result["state"], "waiting-review", result["error"])
        with self.assertRaises(sf.MissionError):
            self.store.cancel(mid)         # too late, and refused rather than silent
        self.assertEqual(self.store.get(mid)["state"], "waiting-review")


@unittest.skipUnless(sandbox_available(),
                     "bubblewrap, systemd-run and a user session are required to "
                     "prove a real sandbox is terminated")
class CancelReachesTheSandbox(unittest.TestCase):
    """The claim that matters: somebody else's process actually stops.

    'We send SIGTERM' describes our own code. These assert the sandboxed
    process and its systemd scope are gone afterwards.
    """

    def setUp(self):
        self.temp = Path(subprocess.run(["mktemp", "-d"], capture_output=True,
                                        text=True).stdout.strip())
        self.addCleanup(shutil.rmtree, self.temp, ignore_errors=True)
        (self.temp / "ws" / "probe").mkdir(parents=True)
        self.env = dict(os.environ,
                        SHADOWFETCH_AGENT_WORKSPACES=str(self.temp / "ws"),
                        XDG_STATE_HOME=str(self.temp / "xdg"),
                        PATH=str(FIREBREAK.parent) + os.pathsep + os.environ["PATH"])

    def start(self, unit):
        proc = subprocess.Popen(
            [sys.executable, str(FIREBREAK), "run", "--workspace", "probe",
             "--net", "none", "--no-checkpoint", "--session-id", unit,
             "--memory-mb", "512", "--cpu-seconds", "120", "--processes", "16",
             "--workspace-mode", "workspace-write", "--", "/usr/bin/sleep", "600"],
            env=self.env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True)
        self.addCleanup(self._cleanup, proc, unit)
        for _ in range(80):
            if sleeping_processes() > self.baseline:
                return proc
            time.sleep(0.1)
        self.skipTest("the sandboxed process never started on this host")

    def _cleanup(self, proc, unit):
        if proc.poll() is None:
            proc.kill()
        subprocess.run(["systemctl", "--user", "stop", unit + ".scope"],
                       capture_output=True)

    def scopes(self, unit):
        done = subprocess.run(["systemctl", "--user", "list-units", "--type=scope",
                               "--no-legend"], capture_output=True, text=True)
        return done.stdout.count(unit)

    def settle(self, predicate, timeout=10):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return True
            time.sleep(0.2)
        return predicate()

    def test_sigterm_removes_the_process_and_the_scope(self):
        self.baseline = sleeping_processes()
        proc = self.start("cancelprobeterm")
        self.assertGreater(sleeping_processes(), self.baseline)
        self.assertEqual(self.scopes("cancelprobeterm"), 1)
        proc.terminate()
        self.assertTrue(self.settle(lambda: sleeping_processes() == self.baseline),
                        "the sandboxed process outlived its wrapper")
        self.assertTrue(self.settle(lambda: self.scopes("cancelprobeterm") == 0),
                        "the systemd scope was left behind")

    def test_sigkill_with_no_chance_to_clean_up_still_removes_both(self):
        """The provider ignoring a graceful stop is the case that matters:
        nothing in our code runs, and bwrap --die-with-parent has to hold."""
        self.baseline = sleeping_processes()
        proc = self.start("cancelprobekill")
        proc.kill()
        self.assertTrue(self.settle(lambda: sleeping_processes() == self.baseline),
                        "a killed wrapper left its sandboxed process running")
        self.assertTrue(self.settle(lambda: self.scopes("cancelprobekill") == 0),
                        "a killed wrapper left its systemd scope behind")


if __name__ == "__main__":
    unittest.main(verbosity=2)
