"""Real flock/SQLite regressions; model text alone is a controlled fixture.

Synchronization gates hold observed locks/transactions, not invented busy
responses. SHADOWFETCH_REVIEW_TEST_SOURCE allows the same tests to demonstrate
the defect against a separately extracted prior source revision.
"""
import concurrent.futures
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import selectors
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

SOURCE = Path(os.environ.get("SHADOWFETCH_REVIEW_TEST_SOURCE", str(
    Path(__file__).resolve().parents[1] / "data/usr/lib/shadowfetch/missions/sf_missions.py")))
spec = importlib.util.spec_from_file_location("sf_review_tests", SOURCE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class ReviewLockTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.ws = self.base / "Workspaces" / "example"
        self.ws.mkdir(parents=True)
        (self.ws / "facts.md").write_text("The launch is Friday.\n")
        env = patch.dict(os.environ, {
            "SHADOWFETCH_AGENT_WORKSPACES": str(self.ws.parent),
            "SHADOWFETCH_MISSIONS_STATE": str(self.base / "state"),
        })
        env.start()
        self.addCleanup(env.stop)
        self.store = m.Store()
        self.mid = self.store.create(kind="report", workspace_value="example",
            title="Review contention", prompt="Summarize the launch",
            inputs=["facts.md"], model="controlled-test-fixture")["id"]

    def run_report(self):
        with patch.object(m.Executor, "infer", return_value="Friday. [S1:L1]"):
            result = m.run_mission(self.store, self.mid)
        self.assertEqual(result["state"], "waiting-review", result["error"])
        return result

    @contextlib.contextmanager
    def observe_contention(self):
        blocked = threading.Event()
        flock = m.fcntl.flock
        def observed(fd, operation):
            try:
                return flock(fd, operation)
            except BlockingIOError:
                blocked.set()
                raise
        with patch.object(m.fcntl, "flock", observed):
            yield blocked

    def test_review_waits_for_execution_to_release_published_result_then_undoes_once(self):
        published, release = threading.Event(), threading.Event()
        original_lock = self.store.lock
        execution_thread = None
        @contextlib.contextmanager
        def pause_before_unlock(*args, **kwargs):
            with original_lock(*args, **kwargs):
                yield
                if threading.get_ident() == execution_thread:
                    published.set()
                    if not release.wait(5):
                        raise AssertionError("test did not release the execution lock")
        def execute():
            nonlocal execution_thread
            execution_thread = threading.get_ident()
            return self.run_report()
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            with patch.object(self.store, "lock", pause_before_unlock), self.observe_contention() as blocked:
                run = pool.submit(execute)
                try:
                    self.assertTrue(published.wait(5))
                    self.assertEqual(self.store.get(self.mid)["state"], "waiting-review")
                    review = pool.submit(m.review, self.store, self.mid, "undo")
                    self.assertTrue(blocked.wait(2), "review must encounter the real held flock")
                    self.assertFalse(concurrent.futures.wait([review], timeout=.1)[0], "brief contention must not reject a ready result")
                finally:
                    release.set()
                run.result(timeout=5)
                self.assertEqual(review.result(timeout=5)["state"], "undone")
        self.assertEqual((self.ws / "facts.md").read_text(), "The launch is Friday.\n")
        self.assertFalse((self.ws / "mission-output").exists())
        self.assertEqual([e["detail"] for e in self.store.events(self.mid) if e["event"] == "reviewed"], ["undo"])
        self.assertEqual(self.store.get(self.mid)["config"]["timeout"], 900)

    def test_review_waits_for_actual_idle_worker_recovery(self):
        self.run_report()
        # Run the real worker in a separate process so its signal handlers and
        # kernel lock ownership match production. Pause only after real recovery.
        script = """
import importlib.util, sys
spec = importlib.util.spec_from_file_location('worker_test', sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
store = m.Store()
recover = store.recover
def gated_recovery():
    recover()
    print('RECOVERY_LOCK_HELD', flush=True)
    if sys.stdin.readline().strip() != 'release':
        raise RuntimeError('missing test release')
store.recover = gated_recovery
raise SystemExit(m.worker(store, once=True))
"""
        worker = subprocess.Popen([sys.executable, "-c", script, str(SOURCE)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        def stop_worker():
            if worker.poll() is None:
                worker.kill()
            worker.communicate(timeout=5)
        self.addCleanup(stop_worker)
        with selectors.DefaultSelector() as selector:
            selector.register(worker.stdout, selectors.EVENT_READ)
            self.assertTrue(selector.select(timeout=5), "worker did not reach the recovery gate")
        self.assertEqual(worker.stdout.readline().strip(), "RECOVERY_LOCK_HELD")
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            with self.observe_contention() as blocked:
                review = pool.submit(m.review, self.store, self.mid, "accept")
                try:
                    self.assertTrue(blocked.wait(2))
                    self.assertFalse(concurrent.futures.wait([review], timeout=.1)[0], "idle recovery must not reject a ready result")
                finally:
                    worker.stdin.write("release\n")
                    worker.stdin.flush()
                self.assertEqual(review.result(timeout=5)["state"], "completed")
        _, stderr = worker.communicate(timeout=5)
        self.assertEqual(worker.returncode, 0, stderr)
        self.assertEqual([e["detail"] for e in self.store.events(self.mid) if e["event"] == "reviewed"], ["accept"])

    def test_busy_refusal_is_bounded_explicit_and_does_not_mutate(self):
        self.run_report()
        before = self.store.get(self.mid), self.store.events(self.mid), m.recovery_index(self.ws)
        with self.store.lock(), patch.object(m, "REVIEW_LOCK_WAIT_SECONDS", .15, create=True):
            for _ in range(2):
                started = time.monotonic()
                with self.assertRaisesRegex(m.MissionError, "controller is busy; this review was not applied"):
                    m.review(self.store, self.mid, "accept")
                elapsed = time.monotonic() - started
                self.assertGreaterEqual(elapsed, .12)
                self.assertLess(elapsed, 1)
                self.assertEqual((self.store.get(self.mid), self.store.events(self.mid), m.recovery_index(self.ws)), before)
        # A new explicit request can succeed; the refused call was never queued.
        self.assertEqual(m.review(self.store, self.mid, "accept")["state"], "completed")
        self.assertEqual(sum(e["event"] == "reviewed" for e in self.store.events(self.mid)), 1)

    def test_state_is_revalidated_after_lock_acquisition(self):
        self.run_report()
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            with self.observe_contention() as blocked:
                with self.store.lock():
                    review = pool.submit(m.review, self.store, self.mid, "accept")
                    self.assertTrue(blocked.wait(2))
                    self.assertFalse(concurrent.futures.wait([review], timeout=.1)[0])
                    self.store.update(self.mid, state="completed")
                    before_events = self.store.events(self.mid)
                with self.assertRaisesRegex(m.MissionError, "Only successful missions awaiting review"):
                    review.result(timeout=5)
        self.assertEqual(self.store.get(self.mid)["state"], "completed")
        self.assertEqual(self.store.events(self.mid), before_events)

    def test_cli_busy_error_is_json_and_does_not_queue_a_review(self):
        self.run_report()
        stdout = io.StringIO()
        with self.store.lock(), patch.object(m, "REVIEW_LOCK_WAIT_SECONDS", .1, create=True), contextlib.redirect_stdout(stdout):
            code = m.main(["--json", "review", self.mid, "--decision", "accept"])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(stdout.getvalue()), {
            "error": "Mission controller is busy; this review was not applied. Try again shortly."})
        self.assertEqual(self.store.get(self.mid)["state"], "waiting-review")
        self.assertFalse(any(e["event"] == "reviewed" for e in self.store.events(self.mid)))

    def test_acquisition_budget_does_not_interrupt_an_undo_in_progress(self):
        self.run_report()
        checkpoint = m.checkpoint_call
        calls = []
        def slow_checkpoint(action, *args, **kwargs):
            calls.append(action)
            time.sleep(.06)
            return checkpoint(action, *args, **kwargs)
        with patch.object(m, "REVIEW_LOCK_WAIT_SECONDS", .02, create=True), patch.object(m, "checkpoint_call", slow_checkpoint):
            result = m.review(self.store, self.mid, "undo")
        self.assertEqual(calls, ["undo"])
        self.assertEqual(result["state"], "undone")
        self.assertFalse((self.ws / "mission-output").exists())

    def test_other_execution_lock_callers_remain_nonblocking(self):
        with self.store.lock():
            started = time.monotonic()
            with self.assertRaisesRegex(m.MissionError, "Another mission is executing"):
                with self.store.lock():
                    self.fail("exclusive execution lock was bypassed")
            self.assertLess(time.monotonic() - started, .5)

    def test_lock_budget_is_below_read_only_gui_observation_budget(self):
        self.assertGreater(m.REVIEW_LOCK_WAIT_SECONDS, 0)
        self.assertLessEqual(m.REVIEW_LOCK_WAIT_SECONDS, 10)

    def test_final_state_and_event_become_visible_in_one_transaction(self):
        inserting, release = threading.Event(), threading.Event()
        db_context = self.store.db
        def trace(sql):
            if sql.startswith("INSERT INTO events") and "'waiting-review'" in sql:
                inserting.set()
                if not release.wait(5):
                    raise AssertionError("test did not release final publication")
        @contextlib.contextmanager
        def traced_db():
            with db_context() as db:
                db.set_trace_callback(trace)
                yield db
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            with patch.object(self.store, "db", traced_db):
                run = pool.submit(self.run_report)
                try:
                    self.assertTrue(inserting.wait(5))
                    observed = self.store.get(self.mid)
                    self.assertEqual(observed["state"], "running", "readiness escaped before the final event transaction")
                    receipt = json.loads(Path(observed["receipt"]).read_text())
                    self.assertTrue(all(m.digest(a["path"]) == a["sha256"] for a in receipt["artifacts"]))
                    self.assertFalse(any(e["event"] == "waiting-review" for e in self.store.events(self.mid)))
                finally:
                    release.set()
                result = run.result(timeout=5)
        self.assertEqual(result["state"], "waiting-review")
        self.assertEqual(self.store.events(self.mid)[-1]["event"], "waiting-review")

    def test_failed_final_event_does_not_publish_ready_state(self):
        with self.store.db() as db:
            db.execute("""CREATE TRIGGER reject_final_event BEFORE INSERT ON events
                WHEN NEW.event = 'waiting-review'
                BEGIN SELECT RAISE(ABORT, 'injected final event failure'); END""")
        with self.assertRaisesRegex(sqlite3.IntegrityError, "injected final event failure"):
            self.run_report()
        result = self.store.get(self.mid)
        self.assertEqual(result["state"], "running")
        self.assertTrue(Path(result["receipt"]).is_file())
        self.assertFalse(any(e["event"] == "waiting-review" for e in self.store.events(self.mid)))
        # Normal recovery reports the interrupted publication; it does not replay.
        with self.store.lock():
            self.store.recover()
        self.assertEqual(self.store.get(self.mid)["state"], "failed")
        self.assertIn("no automatic replay", self.store.get(self.mid)["error"])

    def test_failed_final_state_rolls_back_its_inserted_event(self):
        with self.store.db() as db:
            db.execute("""CREATE TRIGGER reject_final_state BEFORE UPDATE OF state ON missions
                WHEN NEW.state = 'waiting-review'
                BEGIN SELECT RAISE(ABORT, 'injected final state failure'); END""")
        with self.assertRaisesRegex(sqlite3.IntegrityError, "injected final state failure"):
            self.run_report()
        self.assertEqual(self.store.get(self.mid)["state"], "running")
        self.assertFalse(any(e["event"] == "waiting-review" for e in self.store.events(self.mid)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
