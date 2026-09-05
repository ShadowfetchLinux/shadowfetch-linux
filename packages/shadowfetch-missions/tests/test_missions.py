"""State, real process cancellation, scope, receipts and workflow regressions.

Model outputs are controlled fixtures in unit tests, clearly separate from the
release's required live Buzz/Codex inference smoke tests. No mocked result is
reported as a successful model integration.
"""
import concurrent.futures
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "data/usr/lib/shadowfetch/missions/sf_missions.py"
spec = importlib.util.spec_from_file_location("sf_missions", SOURCE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class MissionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name).resolve()
        self.ws = self.base / "Workspaces" / "example"
        self.ws.mkdir(parents=True)
        (self.ws / "facts.md").write_text("The launch is Friday.\nThe release contains three workflows.\n")
        self.env = patch.dict(os.environ, {"SHADOWFETCH_AGENT_WORKSPACES": str(self.ws.parent), "SHADOWFETCH_MISSIONS_STATE": str(self.base / "state")})
        self.env.start()
        self.store = m.Store()
    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()
    def create(self, **kwargs):
        values = dict(kind="report", workspace_value="example", title="Launch report", prompt="Summarize the launch", inputs=["facts.md"], model="fixture-model")
        values.update(kwargs)
        return self.store.create(**values)
    def test_durable_queue_across_connections(self):
        mission = self.create()
        self.assertEqual(m.Store().get(mission["id"])["state"], "queued")
        self.assertEqual(self.store.events(mission["id"])[0]["event"], "queued")
        self.assertEqual(self.store.db_path.stat().st_mode & 0o777, 0o600)
    def test_parallel_creates_have_no_lost_updates(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            items = list(pool.map(lambda i:self.create(title="Task " + str(i)), range(80)))
        self.assertEqual(len({item["id"] for item in items}), 80)
        self.assertEqual(len(self.store.list()), 80)
    def test_scope_rejects_symlink_workspace_and_inputs(self):
        outside = self.base / "outside"
        outside.mkdir()
        (self.ws.parent / "linked").symlink_to(outside)
        with self.assertRaises(m.MissionError):
            self.create(workspace_value="linked")
        (self.ws / "escape.md").symlink_to(self.base / "secret.md")
        (self.base / "secret.md").write_text("secret")
        for path in ("../secret.md", "/etc/passwd", "escape.md"):
            with self.subTest(path=path), self.assertRaises(m.MissionError):
                self.create(inputs=[path])
    def test_controller_cannot_live_in_workspace(self):
        with self.assertRaises(m.MissionError):
            m.Store(self.ws / "state")
    def test_code_requires_explicit_tests_and_cloud_network(self):
        with self.assertRaises(m.MissionError):
            self.create(kind="code", test=None)
        with self.assertRaises(m.MissionError):
            self.create(kind="code", runtime="codex", test=["python3", "tests.py"])
    def test_report_real_checkpoint_diff_receipt_and_undo(self):
        mission = self.create()
        with patch.object(m.Executor, "infer", return_value="The launch is Friday. [S1:L1]\nThe release contains three workflows. [S1:L2]"):
            result = m.run_mission(self.store, mission["id"])
        self.assertEqual(result["state"], "waiting-review", result["error"])
        self.assertTrue(result["checkpoint"])
        self.assertEqual(len(result["artifacts"]), 2)
        receipt = json.loads(Path(result["receipt"]).read_text())
        self.assertTrue(all(m.digest(a["path"]) == a["sha256"] for a in receipt["artifacts"]))
        self.assertIn("report.md", Path(receipt["diff"]).read_text())
        m.review(self.store, mission["id"], "undo")
        self.assertFalse((self.ws / "mission-output").exists())
        self.assertEqual((self.ws / "facts.md").read_text().splitlines()[0], "The launch is Friday.")
    def test_invalid_citation_does_not_publish_or_claim_success(self):
        mission = self.create()
        with patch.object(m.Executor, "infer", return_value="Invented fact. [S1:L99]"):
            result = m.run_mission(self.store, mission["id"])
        self.assertEqual(result["state"], "failed")
        self.assertFalse(result["artifacts"])
        self.assertIn("invalid source citation", result["error"])
        self.assertTrue(Path(result["receipt"]).is_file())
    def test_pending_review_prevents_other_workspace_mutation(self):
        first = self.create()
        with patch.object(m.Executor, "infer", return_value="Friday. [S1:L1]"):
            m.run_mission(self.store, first["id"])
        second = self.create()
        with self.assertRaisesRegex(m.MissionError, "Review the previous"):
            m.run_mission(self.store, second["id"])
        self.assertEqual(self.store.get(second["id"])["state"], "queued")
        m.review(self.store, first["id"], "accept")
        with patch.object(m.Executor, "infer", return_value="Friday. [S1:L1]"):
            m.run_mission(self.store, second["id"])
        with self.assertRaisesRegex(m.MissionError, "newer mission"):
            m.review(self.store, first["id"], "undo")
    def test_recovery_never_replays_interrupted_work(self):
        mission = self.create()
        self.store.update(mission["id"], state="running", attempt=1)
        with self.store.lock():
            self.store.recover()
        item = self.store.get(mission["id"])
        self.assertEqual(item["state"], "failed")
        self.assertIn("no automatic replay", item["error"])
        self.store.retry(item["id"])
        self.assertEqual(self.store.get(item["id"])["state"], "queued")
    def test_retry_budget_is_bounded(self):
        mission = self.create()
        self.store.update(mission["id"], state="failed", attempt=3)
        with self.assertRaisesRegex(m.MissionError, "exhausted"):
            self.store.retry(mission["id"])
    def test_queued_cancellation_is_durable(self):
        mission = self.create()
        self.store.cancel(mission["id"])
        self.assertEqual(m.Store().get(mission["id"])["state"], "cancelled")
        with self.assertRaises(m.MissionError):
            m.run_mission(self.store, mission["id"])
    def test_running_process_cancel_kills_child_group(self):
        mission = self.create()
        self.store.update(mission["id"], state="running")
        executor = m.Executor(self.store, self.store.get(mission["id"]))
        marker = self.base / "should-not-exist"
        script = "import time,pathlib;time.sleep(3);pathlib.Path(" + repr(str(marker)) + ").write_text('bad')"
        timer = threading.Timer(.4, lambda:self.store.cancel(mission["id"]))
        timer.start()
        start = time.monotonic()
        try:
            with self.assertRaises(m.Cancelled):
                executor.run_process([sys.executable, "-c", script], "cancellation", sandbox=False)
        finally:
            timer.join()
        self.assertLess(time.monotonic() - start, 2)
        self.assertFalse(marker.exists())
    def test_structured_edits_validate_all_paths_before_writing(self):
        mission = self.create()
        executor = m.Executor(self.store, mission)
        for path in ("../escape.txt", "/tmp/escape", ".env", ".git/config"):
            payload = json.dumps({"files": [{"path": "ok.py", "content": "ok"}, {"path": path, "content": "bad"}]})
            with self.subTest(path=path), self.assertRaises(m.MissionError):
                executor.apply_edits(payload)
            self.assertFalse((self.ws / "ok.py").exists())
    def test_local_code_real_test_and_repair_receipt(self):
        (self.ws / "app.py").write_text("def add(a, b): return a - b\n")
        mission = self.create(kind="code", inputs=["app.py"], test=[sys.executable, "-c", "from app import add; assert add(2,3)==5"])
        outputs = [json.dumps({"files":[{"path":"app.py","content":"def add(a,b): return a-b\n"}]}), json.dumps({"files":[{"path":"app.py","content":"def add(a,b): return a+b\n"}]})]
        original = m.Executor.run_process
        def host_test(self, command, label, **kwargs):
            return original(self, command, label, sandbox=False)
        with patch.object(m.Executor, "infer", side_effect=outputs), patch.object(m.Executor, "run_process", host_test):
            result = m.run_mission(self.store, mission["id"])
        self.assertEqual(result["state"], "waiting-review", result["error"])
        receipt = json.loads(Path(result["receipt"]).read_text())
        self.assertEqual([t["exit"] for t in receipt["tests"]], [1, 0])
        self.assertIn("return a+b", (self.ws / "app.py").read_text())
    def test_resume_only_after_published_hash_verification(self):
        mission = self.create()
        with patch.object(m.Executor, "infer", return_value="Friday. [S1:L1]"):
            result = m.run_mission(self.store, mission["id"])
        self.store.update(mission["id"], state="failed")
        self.store.retry(mission["id"])
        with patch.object(m.Executor, "infer", side_effect=AssertionError("must resume verified report")):
            result = m.run_mission(self.store, mission["id"])
        self.assertEqual(result["state"], "waiting-review", result["error"])
        self.assertTrue(any(e["event"] == "step-resumed" for e in self.store.events(mission["id"])))
    def test_changed_report_inputs_refuse_resume_and_preserve_manual_edits(self):
        mission = self.create()
        with patch.object(m.Executor, "infer", return_value="Friday. [S1:L1]"):
            first = m.run_mission(self.store, mission["id"])
        report_path = next(Path(path) for path in first["artifacts"] if path.endswith("report.md"))
        report_before = report_path.read_text()
        self.store.update(mission["id"], state="failed")
        (self.ws / "facts.md").write_text("Updated launch is Saturday.\n")
        self.store.retry(mission["id"])
        with patch.object(m.Executor, "infer", side_effect=AssertionError("must not replay inference")):
            result = m.run_mission(self.store, mission["id"])
        self.assertEqual(result["state"], "failed")
        self.assertIn("Source inputs changed", result["error"])
        self.assertEqual(report_path.read_text(), report_before)
        self.assertEqual((self.ws / "facts.md").read_text(), "Updated launch is Saturday.\n")
        with self.assertRaisesRegex(m.MissionError, "changed after"):
            m.review(self.store, mission["id"], "undo")
        self.assertTrue(json.loads(Path(result["receipt"]).read_text())["recovery_index_preserved"])
    def test_missing_execution_baseline_does_not_claim_added_files(self):
        mission = self.create()
        executor = m.Executor(self.store, mission)
        executor.receipt("cancelled", "Cancelled before execution")
        diff = (self.store.directory(mission["id"]) / "changes.diff").read_text()
        self.assertIn("No recorded execution baseline", diff)
        self.assertNotIn("+ facts.md", diff)
        self.assertNotIn("after/facts.md", diff)

    def test_undo_refuses_newer_manual_file_changes(self):
        mission = self.create()
        with patch.object(m.Executor, "infer", return_value="Friday. [S1:L1]"):
            m.run_mission(self.store, mission["id"])
        (self.ws / "newer-manual.txt").write_text("keep me")
        with self.assertRaisesRegex(m.MissionError, "changed after"):
            m.review(self.store, mission["id"], "undo")
        self.assertEqual((self.ws / "newer-manual.txt").read_text(), "keep me")
    def test_code_cannot_rewrite_validation_to_pass(self):
        (self.ws / "test_app.py").write_text("raise AssertionError('required behavior')\n")
        mission = self.create(kind="code", inputs=["test_app.py"], test=["python3", "test_app.py"])
        response = json.dumps({"files":[{"path":"test_app.py", "content":"pass\n"}]})
        with patch.object(m.Executor, "infer", return_value=response):
            result = m.run_mission(self.store, mission["id"])
        self.assertEqual(result["state"], "failed")
        self.assertIn("changed or removed a pre-existing test", result["error"])
    def test_report_offline_refuses_unverified_router_before_request(self):
        mission = self.create()
        executor = m.Executor(self.store, mission)
        with patch.object(m.local_compute, "local_models", return_value=[]), patch.object(m.local_compute, "request", side_effect=AssertionError("no prompt to router")):
            with self.assertRaisesRegex(ValueError, "Offline missions never"):
                executor.infer("system", "private prompt")

    def test_secrets_are_redacted(self):
        with patch.dict(os.environ, {"CODEX_API_KEY": "private-test-credential"}):
            self.assertNotIn("private-test-credential", m.clean("key private-test-credential"))

if __name__ == "__main__":
    unittest.main(verbosity=2)
