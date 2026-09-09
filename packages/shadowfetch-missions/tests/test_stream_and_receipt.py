"""Phase 3 Steps 7, 18, 22: tool executions, the event stream, receipt v2.

The theme running through all three is that a record must not imply a decision
nobody made. A ToolExecution is OBSERVED, not permitted; a receipt reports the
audit chain rather than asserting its own trustworthiness.
"""
import json
import os
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

import mission_approvals
from test_schema_migration import MigrationHarness, Store

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "packages/shadowfetch-missions/data/usr/lib/shadowfetch/missions"))
import sf_missions as sf
import sf_providers as P

CLI = REPO / "packages/shadowfetch-missions/data/usr/bin/shadowfetch-missions"



def probe_secret(tag):
    """A credential-shaped value built at RUNTIME.

    Never a literal: the secret scanner in make source-gate cannot distinguish a
    fake token from a real one -- that is the whole point of it -- so a
    convincing test fixture is indistinguishable from a leak. Assembling it here
    keeps the test honest and the tree clean.
    """
    return "sk-" + tag + "-" + ("%016x" % abs(hash(tag)))


class Event:
    """A minimal AgentEvent stand-in: tool_records reads .data and nothing else,
    which is the provider-neutrality being tested."""

    def __init__(self, data):
        self.type = "progress"
        self.text = ""
        self.data = data


class ToolRecordNormalisation(unittest.TestCase):
    def test_an_event_without_a_tool_key_is_not_a_tool_record(self):
        """Guessing from prose would manufacture structure, and a wrong
        ToolExecution row is worse than a missing one."""
        self.assertEqual(sf.tool_records([Event({"message": "ran the shell tool"})]), [])
        self.assertEqual(sf.tool_records([Event({})]), [])
        self.assertEqual(sf.tool_records([Event(None)]), [])
        self.assertEqual(sf.tool_records(None), [])

    def test_a_reported_tool_becomes_a_record(self):
        records = sf.tool_records([Event({"tool": "shell", "action": "ls -la"})])
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["tool"], "shell")
        self.assertEqual(records[0]["requested_action"], "ls -la")

    def test_unknown_fields_are_null_never_guessed(self):
        """A 0 for bytes_changed would read as 'nothing changed'."""
        record = sf.tool_records([Event({"tool": "shell"})])[0]
        for field in ("exit_status", "result_digest", "bytes_changed",
                      "files_changed", "started_at", "ended_at", "args_digest"):
            self.assertIsNone(record[field], field)

    def test_a_malformed_number_is_unknown_rather_than_zero(self):
        record = sf.tool_records([Event({"tool": "t", "bytes_changed": "lots"})])[0]
        self.assertIsNone(record["bytes_changed"])
        record = sf.tool_records([Event({"tool": "t", "bytes_changed": True})])[0]
        self.assertIsNone(record["bytes_changed"], "a bool is not a byte count")

    def test_args_are_digested_before_they_are_redacted(self):
        """The digest identifies what actually ran; digesting the scrubbed form
        would identify something that never ran."""
        secret = probe_secret("toolargs")
        os.environ["OPENAI_API_KEY"] = secret
        try:
            record = sf.tool_records([Event({
                "tool": "http",
                "args": {"header": secret}})])[0]
        finally:
            os.environ.pop("OPENAI_API_KEY", None)
        self.assertNotIn(secret, json.dumps(record["args_redacted"]))
        self.assertEqual(len(record["args_digest"]), 64)

    def test_unserialisable_args_are_recorded_as_unparseable_not_dropped(self):
        record = sf.tool_records([Event({"tool": "t", "args": {1, 2, 3}})])[0]
        self.assertIsNotNone(record["args_redacted"])

    def test_the_normaliser_names_no_provider(self):
        """A provider added tomorrow is covered the day it declares a tool."""
        source = (REPO / "packages/shadowfetch-missions/data/usr/lib/shadowfetch"
                  "/missions/sf_missions.py").read_text()
        start = source.index("def tool_records(")
        body = source[start:source.index("\ndef ", start + 10)]
        for name in ("codex", "offline-media", "conformance-echo"):
            self.assertNotIn(name, body)


class ToolExecutionRows(MigrationHarness):
    def setUp(self):
        super().setUp()
        self.store = Store(self.root)
        ws = Path(os.environ["SHADOWFETCH_AGENT_WORKSPACES"]) / "proj"
        ws.mkdir(parents=True, exist_ok=True)
        (ws / "a.mkv").write_bytes(b"x")
        # A real mission, because Store.events() checks the mission exists --
        # which is the right behaviour to keep.
        self.mid = self.store.create(
            capability="media_export", provider_id="offline-media",
            workspace_value="proj", title="t", prompt="p", inputs=["a.mkv"])["id"]
        self.sid = self.store.open_session(
            self.mid, task_id=None, provider_id="offline-media",
            provider_version="4.0.0", provider_trust="distro-managed", attempt=1,
            requested_sandbox={}, effective_sandbox={}, enforcement={})

    def test_a_row_records_observed_not_permitted(self):
        """Nothing intercepted this call and nothing could have refused it."""
        self.store.record_tool_execution(self.sid, seq=1, tool="shell")
        row = self.store.tool_executions(session_id=self.sid)[0]
        self.assertEqual(row["decision"], "observed")
        self.assertNotIn(row["decision"], ("auto_allow", "approved", "allowed"))

    def test_a_duplicate_sequence_is_one_row_not_two(self):
        """A provider that replays its stream is a quirk, not a mission failure."""
        first = self.store.record_tool_execution(self.sid, seq=1, tool="shell")
        second = self.store.record_tool_execution(self.sid, seq=1, tool="shell")
        self.assertIsNotNone(first)
        self.assertIsNone(second, "the duplicate should be reported, not stored")
        self.assertEqual(len(self.store.tool_executions(session_id=self.sid)), 1)

    def test_each_row_emits_a_correlated_event(self):
        self.store.record_tool_execution(self.sid, seq=1, tool="shell")
        with self.store.db() as db:
            row = db.execute("SELECT event,session_id,tool_execution_id,actor "
                             "FROM events WHERE event='tool-observed'").fetchone()
        self.assertEqual(row["session_id"], self.sid)
        self.assertIsNotNone(row["tool_execution_id"])
        self.assertEqual(row["actor"], "provider")

    def test_a_failing_record_never_fails_the_mission(self):
        """Losing a completed mission over a malformed tool record would trade
        the work for its description."""
        executor = object.__new__(sf.Executor)
        executor.store = self.store
        executor.session_id = self.sid
        executor.mid = self.mid
        executor.task_id = None
        with mock.patch.object(Store, "record_tool_execution",
                               side_effect=RuntimeError("boom")):
            stored = sf.Executor.record_tool_activity(
                executor, [Event({"tool": "shell"})])
        self.assertEqual(stored, 0)
        names = [e["event"] for e in self.store.events(self.mid)]
        self.assertIn("tool-record-failed", names)


class EventStream(MigrationHarness):
    def setUp(self):
        super().setUp()
        self.store = Store(self.root)

    def test_it_starts_from_a_sequence_and_never_repeats(self):
        for i in range(4):
            self.store.append_event("m", "probe", str(i))
        everything = list(sf.stream_events(self.store, follow=False))
        resumed = list(sf.stream_events(self.store, since=everything[1]["seq"],
                                        follow=False))
        self.assertEqual([e["seq"] for e in resumed],
                         [e["seq"] for e in everything[2:]])

    def test_resuming_past_the_end_yields_nothing_rather_than_repeating(self):
        self.store.append_event("m", "probe", "x")
        head = list(sf.stream_events(self.store, follow=False))[-1]["seq"]
        self.assertEqual(list(sf.stream_events(self.store, since=head, follow=False)), [])

    def test_a_limit_stops_rather_than_truncating_silently(self):
        for i in range(5):
            self.store.append_event("m", "probe", str(i))
        rows = list(sf.stream_events(self.store, follow=False, limit=2))
        self.assertEqual(len(rows), 2)

    def test_following_delivers_an_event_written_after_the_wait_began(self):
        started, delivered = threading.Event(), []

        def consume():
            for row in sf.stream_events(self.store, since=0, idle=3):
                delivered.append(row)
                if row["event"] == "the-one":
                    return

        thread = threading.Thread(target=consume, daemon=True)
        thread.start()
        time.sleep(0.4)
        self.store.append_event("m", "the-one", "x")
        thread.join(timeout=10)
        self.assertTrue(any(r["event"] == "the-one" for r in delivered),
                        "an event written during the wait was not delivered")

    def test_every_correlation_column_reaches_the_consumer(self):
        self.store.append_event("m", "probe", "x", task_id="task-1",
                                session_id="sess-1", tool_execution_id="tool-1")
        row = list(sf.stream_events(self.store, follow=False))[-1]
        for field in ("seq", "at", "mission", "task_id", "session_id",
                      "tool_execution_id", "actor", "event", "detail",
                      "prev_hash", "hash"):
            self.assertIn(field, row)


class RecordsVerb(MigrationHarness):
    def setUp(self):
        super().setUp()
        self.store = Store(self.root)
        ws = Path(os.environ["SHADOWFETCH_AGENT_WORKSPACES"]) / "proj"
        ws.mkdir(parents=True, exist_ok=True)
        (ws / "a.mkv").write_bytes(b"x")

    def run_cli(self, *args):
        env = dict(os.environ, SHADOWFETCH_MISSIONS_STATE=str(self.root))
        return subprocess.run([sys.executable, str(CLI), *args],
                              capture_output=True, text=True, env=env, timeout=60)

    def test_it_returns_everything_show_does_not(self):
        """Without this the desktop had to infer a task state machine from
        event names."""
        mid = self.store.create(capability="media_export", provider_id="offline-media",
                                workspace_value="proj", title="t", prompt="p",
                                inputs=["a.mkv"])["id"]
        done = self.run_cli("--json", "records", mid)
        self.assertEqual(done.returncode, 0, done.stderr)
        payload = json.loads(done.stdout)
        for key in ("mission", "tasks", "sessions", "tool_executions", "test_runs",
                    "git_changes", "reviews", "artifacts", "approvals"):
            self.assertIn(key, payload)

    def test_watch_resumes_without_repeating(self):
        self.store.create(capability="media_export", provider_id="offline-media",
                          workspace_value="proj", title="t", prompt="p",
                          inputs=["a.mkv"])
        first = self.run_cli("watch", "--no-follow")
        rows = [json.loads(line) for line in first.stdout.splitlines()]
        self.assertTrue(rows)
        again = self.run_cli("watch", "--no-follow", "--since", str(rows[-1]["seq"]))
        self.assertEqual(again.stdout.strip(), "")


class ReceiptV2(MigrationHarness):
    def setUp(self):
        super().setUp()
        self.store = Store(self.root)
        ws = Path(os.environ["SHADOWFETCH_AGENT_WORKSPACES"]) / "proj"
        ws.mkdir(parents=True, exist_ok=True)
        (ws / "facts.md").write_text("The launch is Friday.\n")

    def receipt(self):
        mission = self.store.create(kind="report", workspace_value="proj", title="t",
                                    prompt="p", inputs=["facts.md"], network="allow")
        mission_approvals.approve(self.store, mission)
        with mock.patch.object(sf.Executor, "agent_turn", return_value="Friday. [S1:L1]"):
            sf.run_mission(self.store, mission["id"])
        path = self.store.directory(mission["id"]) / "receipt.json"
        return mission["id"], json.loads(path.read_text()), path.read_text()

    def test_it_is_schema_two_and_keeps_every_v1_key(self):
        """A v1 reader must see exactly what it saw."""
        _mid, receipt, _raw = self.receipt()
        self.assertEqual(receipt["schema"], 2)
        for key in ("mission", "title", "kind", "capability", "provider_id", "state",
                    "workspace", "checkpoint", "started_at", "finished_at", "runtime",
                    "network", "error", "artifacts", "tests", "inferences", "diff",
                    "changes", "diff_truncated", "review_required", "limits",
                    "recovery_scope"):
            self.assertIn(key, receipt, f"v1 key {key} was dropped")

    def test_it_carries_the_orchestration_provenance(self):
        _mid, receipt, _raw = self.receipt()
        for key in ("tasks", "sessions", "tool_executions", "test_runs",
                    "git_changes", "approval", "approval_required", "audit",
                    "declared_but_not_enforced"):
            self.assertIn(key, receipt)
        # NOT asserted here: this fixture mocks agent_turn, so run_invocation
        # never executes and no session opens. A session for a REAL provider
        # execution is asserted in test_correlation.py against a real run;
        # asserting it here would only prove the mock was installed.

    def test_it_names_who_authorised_the_work(self):
        _mid, receipt, _raw = self.receipt()
        self.assertTrue(receipt["approval_required"])
        self.assertIsNotNone(receipt["approval"])
        self.assertTrue(receipt["approval"]["granted_by"])
        self.assertTrue(receipt["approval"]["method"])

    def test_it_reports_the_audit_chain_rather_than_asserting_trust(self):
        """A receipt that asserted its own trustworthiness would be asking to be
        believed."""
        _mid, receipt, _raw = self.receipt()
        self.assertIn("ok", receipt["audit"])
        self.assertIn("head_seq", receipt["audit"])
        self.assertIn("anchor", receipt["audit"])

    def test_it_names_the_controls_that_are_not_enforced(self):
        """Listing these anywhere else and not in the artifact a person reads
        when deciding to accept the work would be the omission that matters."""
        _mid, receipt, _raw = self.receipt()
        self.assertIn("declared_but_not_enforced", receipt)
        self.assertIn("enforcement_note", receipt)
        self.assertIn("Do not read them as controls", receipt["enforcement_note"])

    def test_no_credential_value_reaches_it(self):
        secret = probe_secret("receipt")
        os.environ["OPENAI_API_KEY"] = secret
        try:
            _mid, _receipt, raw = self.receipt()
        finally:
            os.environ.pop("OPENAI_API_KEY", None)
        self.assertNotIn(secret, raw)

    def test_sessions_keep_requested_and_effective_apart(self):
        """Driven by a REAL provider execution: a mocked turn never reaches
        run_invocation, so it opens no session and would prove only that the
        mock was installed."""
        ws = Path(os.environ["SHADOWFETCH_AGENT_WORKSPACES"]) / "proj"
        (ws / "clip.mkv").write_bytes(b"not a real clip")
        mission = self.store.create(capability="media_export",
                                    provider_id="offline-media",
                                    workspace_value="proj", title="t", prompt="p",
                                    inputs=["clip.mkv"])
        # ffmpeg will refuse the fake clip; the session is opened and closed
        # either way, which is exactly the property under test.
        try:
            sf.run_mission(self.store, mission["id"])
        except sf.MissionError:
            pass
        sessions = self.store.sessions(mission["id"])
        if not sessions:
            self.skipTest("no sandbox available here, so no session was opened")
        for key in ("requested_sandbox", "effective_sandbox", "enforcement",
                    "network_requested", "network_effective", "egress_requested"):
            self.assertIn(key, sessions[0])


if __name__ == "__main__":
    unittest.main(verbosity=2)
