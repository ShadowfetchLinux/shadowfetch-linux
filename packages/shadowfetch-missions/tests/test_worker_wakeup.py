"""Regression: the mission worker's Wakeup must not wake itself on its own reads.

Phase 3 introduced an inotify-driven worker loop that watches the state
DIRECTORY. In WAL mode the worker's OWN queue scan opens and closes the
database's -wal/-shm sidecars in that directory, and those are create/modify/
close-write events on the watched dir. Before the fix, wait() ran select()
first and found those self-generated events readable immediately, every
iteration, so the worker span a core at 100% on an idle queue. The fix drains
what accumulated up to the moment wait() is entered, then blocks for a change
that happens strictly AFTER that point. These tests pin both halves: a
pre-existing (self) event must NOT cause an immediate wake, and a genuinely new
external event MUST still wake it promptly.
"""
import importlib.util
import os
import threading
import time
import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / "data/usr/lib/shadowfetch/missions/sf_missions.py"
spec = importlib.util.spec_from_file_location("sf_missions", SOURCE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class WorkerWakeupRegression(unittest.TestCase):
    def _wakeup(self, directory):
        w = m.Wakeup(directory, fallback=30)
        if not w.event_driven:
            w.close()
            self.skipTest("inotify unavailable on this host; worker uses the poll fallback")
        return w

    def test_self_generated_events_before_wait_do_not_spin(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            w = self._wakeup(d)
            try:
                # Simulate the churn the worker's own WAL/-shm access leaves in
                # the watched directory just before it calls wait().
                for i in range(5):
                    (d / f"db-wal-{i}").write_text("x")
                    (d / f"db-wal-{i}").unlink()
                # With the pre-drain fix, these already-past events are consumed
                # and wait() blocks for the full (short) timeout: no immediate,
                # spurious wake. The old code returned True instantly here.
                start = time.monotonic()
                woke = w.wait(timeout=0.4)
                elapsed = time.monotonic() - start
                self.assertFalse(woke, "a self-generated event that predates wait() must not wake it")
                self.assertGreaterEqual(elapsed, 0.35, "wait() returned early -- it did not block after draining")
            finally:
                w.close()

    def test_external_event_during_wait_wakes_promptly(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            w = self._wakeup(d)
            try:
                def writer():
                    time.sleep(0.2)
                    (d / "new-mission.json").write_text("queued")
                t = threading.Thread(target=writer)
                t.start()
                start = time.monotonic()
                woke = w.wait(timeout=5)
                elapsed = time.monotonic() - start
                t.join()
                self.assertTrue(woke, "a genuinely new external write must wake the worker")
                self.assertLess(elapsed, 2.0, "event-driven wake was not prompt")
            finally:
                w.close()


if __name__ == "__main__":
    unittest.main()
