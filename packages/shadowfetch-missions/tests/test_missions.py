"""State, real process cancellation, scope, receipts and workflow regressions.

Model outputs are controlled fixtures in unit tests, clearly separate from the
release's required live Codex inference smoke tests. No mocked result is
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
        values = dict(kind="report", workspace_value="example", title="Launch report", prompt="Summarize the launch", inputs=["facts.md"], network="allow")
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
            self.create(kind="code", runtime="codex", network="none", test=["python3", "tests.py"])
    def test_report_real_checkpoint_diff_receipt_and_undo(self):
        mission = self.create()
        with patch.object(m.Executor, "codex", return_value="The launch is Friday. [S1:L1]\nThe release contains three workflows. [S1:L2]"):
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
        with patch.object(m.Executor, "codex", return_value="Invented fact. [S1:L99]"):
            result = m.run_mission(self.store, mission["id"])
        self.assertEqual(result["state"], "failed")
        self.assertFalse(result["artifacts"])
        self.assertIn("invalid source citation", result["error"])
        self.assertTrue(Path(result["receipt"]).is_file())
    def test_pending_review_prevents_other_workspace_mutation(self):
        first = self.create()
        with patch.object(m.Executor, "codex", return_value="Friday. [S1:L1]"):
            m.run_mission(self.store, first["id"])
        second = self.create()
        with self.assertRaisesRegex(m.MissionError, "Review the previous"):
            m.run_mission(self.store, second["id"])
        self.assertEqual(self.store.get(second["id"])["state"], "queued")
        m.review(self.store, first["id"], "accept")
        with patch.object(m.Executor, "codex", return_value="Friday. [S1:L1]"):
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
    def test_removed_provider_and_model_selection_are_refused(self):
        for options in ({"runtime": "local"}, {"runtime": "shared"}, {"model": "old-model"}, {"runtime": "offline"}):
            with self.subTest(options=options), self.assertRaises(m.MissionError):
                self.create(**options)

    def test_codex_code_runs_actual_required_test(self):
        (self.ws / "app.py").write_text("def add(a, b): return a - b\n")
        mission = self.create(kind="code", inputs=["app.py"], test=[sys.executable, "-c", "from app import add; assert add(2,3)==5"])
        original = m.Executor.run_process
        def fixture_codex(executor, prompt):
            (executor.ws / "app.py").write_text("def add(a,b): return a+b\n")
        def host_test(executor, command, label, **kwargs):
            return original(executor, command, label, sandbox=False)
        with patch.object(m.Executor, "codex", fixture_codex), patch.object(m.Executor, "run_process", host_test):
            result = m.run_mission(self.store, mission["id"])
        self.assertEqual(result["state"], "waiting-review", result["error"])
        receipt = json.loads(Path(result["receipt"]).read_text())
        self.assertEqual([t["exit"] for t in receipt["tests"]], [0])
        self.assertEqual(receipt["runtime"], "codex")
        self.assertIn("return a+b", (self.ws / "app.py").read_text())
    def test_resume_only_after_published_hash_verification(self):
        mission = self.create()
        with patch.object(m.Executor, "codex", return_value="Friday. [S1:L1]"):
            result = m.run_mission(self.store, mission["id"])
        self.store.update(mission["id"], state="failed")
        self.store.retry(mission["id"])
        with patch.object(m.Executor, "codex", side_effect=AssertionError("must resume verified report")):
            result = m.run_mission(self.store, mission["id"])
        self.assertEqual(result["state"], "waiting-review", result["error"])
        self.assertTrue(any(e["event"] == "step-resumed" for e in self.store.events(mission["id"])))
    def test_changed_report_inputs_refuse_resume_and_preserve_manual_edits(self):
        mission = self.create()
        with patch.object(m.Executor, "codex", return_value="Friday. [S1:L1]"):
            first = m.run_mission(self.store, mission["id"])
        report_path = next(Path(path) for path in first["artifacts"] if path.endswith("report.md"))
        report_before = report_path.read_text()
        self.store.update(mission["id"], state="failed")
        (self.ws / "facts.md").write_text("Updated launch is Saturday.\n")
        self.store.retry(mission["id"])
        with patch.object(m.Executor, "codex", side_effect=AssertionError("must not replay inference")):
            result = m.run_mission(self.store, mission["id"])
        self.assertEqual(result["state"], "failed")
        self.assertIn("Source inputs changed", result["error"])
        self.assertEqual(report_path.read_text(), report_before)
        self.assertEqual((self.ws / "facts.md").read_text(), "Updated launch is Saturday.\n")
        with self.assertRaisesRegex(m.MissionError, "changed after"):
            m.review(self.store, mission["id"], "undo")
        self.assertTrue(json.loads(Path(result["receipt"]).read_text())["recovery_index_preserved"])
    def test_report_resume_retains_historical_codex_inference_provenance(self):
        mission = self.create()
        # Controlled unit fixture; release integration uses a real native server.
        original = {"provider": "codex", "model": None, "usage": {"output_tokens": 11}, "observed_at": "2026-09-05T00:00:00Z", "attempt": 1, "response_sha256": "a" * 64, "reused": False}
        def inference(executor, *args, **kwargs):
            executor.inferences.append(original.copy())
            return "Friday. [S1:L1]"
        with patch.object(m.Executor, "codex", inference):
            first = m.run_mission(self.store, mission["id"])
        self.assertEqual(first["state"], "waiting-review")
        provenance = self.store.step(mission["id"], "report-provenance")
        for change_source in (False, True):
            self.store.update(mission["id"], state="failed")
            self.store.retry(mission["id"])
            if change_source:
                (self.ws / "facts.md").write_text("A newer personal source edit.\n")
            with patch.object(m.Executor, "codex", side_effect=AssertionError("must not replay inference")):
                result = m.run_mission(self.store, mission["id"])
            self.assertEqual(result["state"], "failed" if change_source else "waiting-review")
            receipt = json.loads(Path(result["receipt"]).read_text())
            reused = receipt["inferences"][0]
            for key in ("provider", "model", "usage", "observed_at", "attempt", "response_sha256"):
                self.assertEqual(reused[key], original[key])
            self.assertTrue(reused["reused"])
            self.assertEqual(reused["original_report_attempt"], 1)
            self.assertEqual(reused["original_report_published_at"], provenance["published_at"])
            self.assertIn("Historical", reused["verification_scope"])
            self.assertEqual(self.store.step(mission["id"], "report-provenance"), provenance)
    def test_report_resume_refuses_missing_inference_provenance(self):
        mission = self.create()
        with patch.object(m.Executor, "codex", return_value="Friday. [S1:L1]"):
            m.run_mission(self.store, mission["id"])
        self.store.step(mission["id"], "report-provenance", {})
        self.store.update(mission["id"], state="failed")
        self.store.retry(mission["id"])
        with patch.object(m.Executor, "codex", side_effect=AssertionError("no repeat inference")):
            result = m.run_mission(self.store, mission["id"])
        self.assertEqual(result["state"], "failed")
        self.assertIn("no retained inference provenance", result["error"])
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
        with patch.object(m.Executor, "codex", return_value="Friday. [S1:L1]"):
            m.run_mission(self.store, mission["id"])
        (self.ws / "newer-manual.txt").write_text("keep me")
        with self.assertRaisesRegex(m.MissionError, "changed after"):
            m.review(self.store, mission["id"], "undo")
        self.assertEqual((self.ws / "newer-manual.txt").read_text(), "keep me")
    def test_code_cannot_rewrite_validation_to_pass(self):
        (self.ws / "test_app.py").write_text("raise AssertionError('required behavior')\n")
        mission = self.create(kind="code", inputs=["test_app.py"], test=["python3", "test_app.py"])
        def tamper(executor, prompt):
            (executor.ws / "test_app.py").write_text("pass\n")
        with patch.object(m.Executor, "codex", tamper):
            result = m.run_mission(self.store, mission["id"])
        self.assertEqual(result["state"], "failed")
        self.assertIn("changed or removed a pre-existing test", result["error"])
    def test_report_requires_explicit_cloud_permission(self):
        with self.assertRaisesRegex(m.MissionError, "explicit network"):
            self.create(network="none")

    def test_codex_cli_report_uses_stdin_and_retains_completed_turn(self):
        mission = self.create()
        executor = m.Executor(self.store, mission)
        observed = {}
        def cli(command, label, **kwargs):
            observed.update(command=command, env=kwargs["env"], prompt=Path(kwargs["input_path"]).read_text(), request=Path(kwargs["input_path"]))
            log = executor.directory / "fixture-events.jsonl"
            log.write_text(json.dumps({"type": "item.completed", "item": {"type": "agent_message", "text": "Friday. [S1:L1]"}}) + "\n" + json.dumps({"type": "turn.completed", "usage": {"output_tokens": 9}}) + "\n")
            return 0, "", log
        with patch.dict(os.environ, {"CODEX_API_KEY": "unit-only-placeholder"}), patch.object(m, "executable", return_value="codex"), patch.object(executor, "run_process", cli):
            self.assertEqual(executor.codex("Selected source context", read_only=True), "Friday. [S1:L1]")
        self.assertEqual(observed["command"][-1], "-")
        self.assertEqual(observed["command"][observed["command"].index("--sandbox")+1], "read-only")
        self.assertNotIn("Selected source context", observed["command"])
        self.assertEqual(set(observed["env"]), {"CODEX_API_KEY"})
        self.assertFalse(observed["request"].exists())
        self.assertEqual(executor.inferences[0]["provider"], "codex")
        self.assertEqual(executor.inferences[0]["usage"], {"output_tokens": 9})

    def test_codex_incomplete_turn_and_missing_key_refuse_success(self):
        executor = m.Executor(self.store, self.create())
        with patch.dict(os.environ, {"CODEX_API_KEY": "", "OPENAI_API_KEY": ""}), patch.object(executor, "run_process", side_effect=AssertionError("No call without API key")):
            with self.assertRaisesRegex(m.MissionError, "not configured"):
                executor.codex("task")
        log = executor.directory / "failed.jsonl"
        log.write_text(json.dumps({"type": "turn.failed", "error": {"message": "fixture"}}))
        with patch.dict(os.environ, {"CODEX_API_KEY": "unit-only-placeholder"}), patch.object(m, "executable", return_value="codex"), patch.object(executor, "run_process", return_value=(0,"",log)):
            with self.assertRaisesRegex(m.MissionError, "complete successful turn"):
                executor.codex("task")

    def test_legacy_provider_is_not_silently_sent_to_cloud(self):
        item = self.create()
        config = dict(item["config"], runtime="local", network="none")
        with self.store.db() as db:
            db.execute("UPDATE missions SET config=? WHERE id=?", (json.dumps(config), item["id"]))
        with patch.object(m.Executor, "codex", side_effect=AssertionError("No provider migration")), patch.object(m, "checkpoint_call", side_effect=AssertionError("No workspace mutation")):
            result = m.run_mission(self.store, item["id"])
        self.assertEqual(result["state"], "failed")
        self.assertIn("retired provider", result["error"])
        self.assertIsNone(result["checkpoint"])

    def test_capabilities_defer_local_ai_and_do_not_claim_authentication(self):
        caps = m.capabilities()
        self.assertEqual(set(caps["runtimes"]), {"offline", "codex"})
        self.assertEqual(caps["runtimes"]["codex"]["kinds"], ["code", "report"])
        self.assertEqual(caps["runtimes"]["offline"]["kinds"], ["media"])
        self.assertNotIn("authenticated", caps["runtimes"]["codex"])
        self.assertEqual(caps["local_ai"], "deferred")

    def test_secrets_are_redacted(self):
        with patch.dict(os.environ, {"CODEX_API_KEY": "private-test-credential"}):
            self.assertNotIn("private-test-credential", m.clean("key private-test-credential"))

    # W-15: a page limit must be an explicit, reportable boundary, never a silent cut.
    def bulk_missions(self, count, *, state="queued", year=2000):
        config = json.dumps({"runtime": "codex", "model": "", "inputs": ["facts.md"], "test": None, "network": "allow", "timeout": 900})
        rows = [(f"mission-{year}{index:06d}", f"Bulk {index}", "report", state, str(self.ws), "prompt", config,
                 f"{year}-01-01T{index // 3600 % 24:02d}:{index // 60 % 60:02d}:{index % 60:02d}+00:00", m.now()) for index in range(count)]
        with self.store.db() as db:
            db.executemany("INSERT INTO missions(id,title,kind,state,workspace,prompt,config,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)", rows)
        return rows

    def test_records_past_the_page_limit_are_reported_not_dropped(self):
        self.bulk_missions(m.LIST_PAGE_LIMIT + 1)
        with self.store.db() as db:
            legacy = db.execute("SELECT * FROM missions ORDER BY created_at DESC,rowid DESC LIMIT 1000").fetchall()
        self.assertEqual(len(legacy), m.LIST_PAGE_LIMIT)
        self.assertEqual(len(self.store.list()), m.LIST_PAGE_LIMIT + 1)
        page = self.store.page()
        self.assertEqual(len(page["missions"]), m.LIST_PAGE_LIMIT)
        self.assertEqual((page["total"], page["truncated"], page["next_offset"]), (m.LIST_PAGE_LIMIT + 1, True, m.LIST_PAGE_LIMIT))
        rest = self.store.page(offset=page["next_offset"])
        self.assertEqual((len(rest["missions"]), rest["truncated"], rest["next_offset"]), (1, False, None))
        self.assertEqual([item["id"] for item in self.store.list()], [item["id"] for item in page["missions"] + rest["missions"]])
        self.assertEqual(self.store.page(states=("queued",))["total"], m.LIST_PAGE_LIMIT + 1)
        self.assertEqual(self.store.page(states=())["missions"], [])
        for invalid in ({"limit": 0}, {"limit": -5}, {"offset": -1}):
            with self.subTest(invalid=invalid), self.assertRaises(m.MissionError):
                self.store.page(**invalid)

    def test_pending_review_beyond_one_page_still_blocks_new_work(self):
        first = self.create()
        with patch.object(m.Executor, "codex", return_value="Friday. [S1:L1]"):
            self.assertEqual(m.run_mission(self.store, first["id"])["state"], "waiting-review")
        self.bulk_missions(m.LIST_PAGE_LIMIT, year=2099)
        second = self.create()
        with patch.object(m.Executor, "codex", side_effect=AssertionError("must not run beside an unreviewed result")):
            with self.assertRaisesRegex(m.MissionError, "Review the previous"):
                m.run_mission(self.store, second["id"])
        self.assertEqual(self.store.get(second["id"])["state"], "queued")

    def test_undo_finds_its_place_in_a_queue_larger_than_one_page(self):
        mission = self.create()
        with patch.object(m.Executor, "codex", return_value="Friday. [S1:L1]"):
            m.run_mission(self.store, mission["id"])
        self.bulk_missions(m.LIST_PAGE_LIMIT, year=2099)
        self.assertEqual(m.review(self.store, mission["id"], "undo")["state"], "undone")
        self.assertFalse((self.ws / "mission-output").exists())

    def test_undo_reports_a_missing_queue_row_instead_of_crashing(self):
        mission = self.create()
        with patch.object(m.Executor, "codex", return_value="Friday. [S1:L1]"):
            m.run_mission(self.store, mission["id"])
        with patch.object(m.Store, "list", return_value=[]):
            with self.assertRaisesRegex(m.MissionError, "no longer listed"):
                m.review(self.store, mission["id"], "undo")
        self.assertEqual(self.store.get(mission["id"])["state"], "waiting-review")

    def test_cli_reports_an_exhausted_iterator_as_json_not_a_traceback(self):
        mission = self.create()
        printed = []
        with patch.object(m.Store, "get", side_effect=StopIteration()), patch("builtins.print", lambda *values, **kwargs: printed.append(" ".join(map(str, values)))):
            code = m.main(["--json", "show", mission["id"]])
        self.assertEqual(code, 1)
        self.assertIn("Mission records were incomplete", json.loads(printed[-1])["error"])

    # W-16: the guard covers new validation files, measured against a pristine baseline.
    def test_code_refuses_newly_added_validation_files(self):
        (self.ws / "app.py").write_text("def add(a, b): return a - b\n")
        mission = self.create(kind="code", inputs=["app.py"], test=[sys.executable, "-c", "import app"])
        def sneak(executor, prompt):
            (executor.ws / "app.py").write_text("def add(a, b): return a + b\n")
            (executor.ws / "conftest.py").write_text("collect_ignore_glob = ['*']\n")
            (executor.ws / "test_added.py").write_text("def test_ok():\n    assert True\n")
        with patch.object(m.Executor, "codex", sneak), patch.object(m.Executor, "run_process", side_effect=AssertionError("validation must not run")):
            result = m.run_mission(self.store, mission["id"])
        self.assertEqual(result["state"], "failed")
        self.assertIn("added unreviewed test/validation files", result["error"])
        self.assertIn("conftest.py", result["error"])
        self.assertIn("test_added.py", result["error"])

    def test_validation_guard_baseline_stays_pristine_across_retries(self):
        (self.ws / "app.py").write_text("value = 1\n")
        (self.ws / "test_app.py").write_text("raise AssertionError('required behavior')\n")
        mission = self.create(kind="code", inputs=["app.py"], test=[sys.executable, "test_app.py"])
        with patch.object(m.Executor, "codex", lambda executor, prompt: (executor.ws / "test_app.py").write_text("pass\n")):
            first = m.run_mission(self.store, mission["id"])
        self.assertEqual(first["state"], "failed")
        self.assertIn("changed or removed a pre-existing test", first["error"])
        self.assertEqual((self.ws / "test_app.py").read_text(), "pass\n")
        self.store.retry(mission["id"])
        with patch.object(m.Executor, "codex", lambda executor, prompt: None), patch.object(m.Executor, "run_process", side_effect=AssertionError("validation must not run")):
            second = m.run_mission(self.store, mission["id"])
        self.assertEqual(second["state"], "failed")
        self.assertIn("changed or removed a pre-existing test", second["error"])

    def test_legitimate_code_mission_still_passes_the_guard(self):
        (self.ws / "app.py").write_text("def add(a, b): return a - b\n")
        (self.ws / "tests").mkdir()
        (self.ws / "tests" / "test_add.py").write_text("import app\nassert app.add(2, 3) == 5\n")
        mission = self.create(kind="code", inputs=["app.py"], test=[sys.executable, "tests/test_add.py"])
        original = m.Executor.run_process
        with patch.object(m.Executor, "codex", lambda executor, prompt: (executor.ws / "app.py").write_text("def add(a, b): return a + b\n")), \
             patch.object(m.Executor, "run_process", lambda executor, command, label, **kwargs: original(executor, command, label, sandbox=False, env={"PYTHONPATH": str(executor.ws)})):
            result = m.run_mission(self.store, mission["id"])
        self.assertEqual(result["state"], "waiting-review", result["error"])

    # W-17: structured change rows, escaped paths and an explicit truncation trailer.
    def test_change_rows_are_typed_and_paths_cannot_forge_diff_structure(self):
        forged = "evil\n+++ after/etc/shadow\n"
        before = {"kept.txt": {"sha256": "a" * 64, "bytes": 4, "text": "one\n"}}
        after = {"kept.txt": {"sha256": "b" * 64, "bytes": 4, "text": "two\n"}, forged: {"sha256": "c" * 64, "bytes": 1}}
        change = m.git_change(before, after)
        rows = {row["path"]: row for row in change.rows}
        self.assertEqual(set(rows), {"kept.txt", json.dumps(forged)})
        self.assertEqual((rows["kept.txt"]["change"], rows["kept.txt"]["kind"]), ("modified", "text"))
        self.assertEqual((rows[json.dumps(forged)]["change"], rows[json.dumps(forged)]["kind"]), ("added", "binary"))
        self.assertEqual(rows["kept.txt"]["before"], {"sha256": "a" * 64, "bytes": 4})
        rendered = m.difference(before, after)
        self.assertNotIn("\n+++ after/etc/shadow", rendered)
        self.assertEqual(sum(1 for line in rendered.splitlines() if line.startswith("+++ ")), 1)
        self.assertEqual(sum(1 for line in rendered.splitlines() if line.startswith("--- ")), 1)
        self.assertEqual(sum(1 for line in rendered.splitlines() if line.startswith("+ ")), 1)
        self.assertFalse(change.truncated)
        self.assertEqual(change.counts(), {"added": 1, "removed": 0, "modified": 1})

    def test_change_summary_ends_with_an_explicit_truncation_trailer(self):
        block = "".join(f"line {number:04d}\n" for number in range(200))
        after = {f"file-{index:04d}.txt": {"sha256": str(index).zfill(64), "bytes": len(block), "text": block} for index in range(1000)}
        change = m.git_change({}, after)
        self.assertTrue(change.truncated)
        self.assertGreater(change.omitted_rows, 0)
        self.assertEqual(len(change.rows), 1000)
        rendered = m.difference({}, after)
        self.assertTrue(rendered.endswith("The complete typed record is in changes.json.\n"), rendered[-200:])
        self.assertIn(f"{change.omitted_rows} of 1000 change rows omitted", rendered)
        body = rendered[:rendered.index("... change summary truncated")]
        self.assertTrue(body.endswith("\n"))
        self.assertLessEqual(len(body.encode()), m.MAX_OUTPUT)

    def test_receipt_records_a_structured_change_summary(self):
        mission = self.create()
        with patch.object(m.Executor, "codex", return_value="Friday. [S1:L1]"):
            result = m.run_mission(self.store, mission["id"])
        receipt = json.loads(Path(result["receipt"]).read_text())
        self.assertFalse(receipt["diff_truncated"])
        record = json.loads(Path(receipt["changes"]).read_text())
        self.assertEqual(record["schema"], 1)
        self.assertEqual(record["counts"], {"added": 2, "removed": 0, "modified": 0})
        self.assertTrue(any(row["path"].endswith("report.md") and row["change"] == "added" for row in record["rows"]))
        self.assertTrue(all(row["after"]["sha256"] for row in record["rows"]))

if __name__ == "__main__":
    unittest.main(verbosity=2)
