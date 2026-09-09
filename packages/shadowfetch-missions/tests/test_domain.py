"""Stage A: the domain rows a receipt reprints as fact are integrity-bound.

Phase 3.1 made missions, events and approvals tamper-evident and left these
tables directly editable, so a forged receipt could rest on rewritten rows while
`audit verify` still reported the chain intact.
"""
import os
import sqlite3
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_schema_migration import MigrationHarness      # noqa: E402
import sf_missions as sf                                # noqa: E402
from sf_missions import Store                           # noqa: E402


class Harness(MigrationHarness):
    def setUp(self):
        super().setUp()
        self.store = Store(self.root)
        ws = Path(os.environ["SHADOWFETCH_AGENT_WORKSPACES"]) / "probe"
        ws.mkdir(parents=True, exist_ok=True)
        (ws / "a.mkv").write_bytes(b"clip")
        self.ws = ws
        self.mid = self.store.create(
            capability="media_export", provider_id="offline-media",
            workspace_value="probe", title="t", prompt="p", inputs=["a.mkv"])["id"]
        self.task = self.store.create_task(self.mid, kind="media", seq=1)["id"]

    def session(self):
        return self.store.open_session(
            self.mid, task_id=self.task, provider_id="offline-media",
            provider_version="4.0.0", provider_trust="distro-managed", attempt=1,
            requested_sandbox={"network": "none"}, effective_sandbox={"network": "none"},
            enforcement={"network": "enforced"}, executable="/usr/bin/ffprobe",
            executable_trust="distro-managed", network_requested="none",
            network_effective="none")

    def sql(self, statement, *params):
        db = sqlite3.connect(self.root / "missions.sqlite3")
        db.execute(statement, params)
        db.commit()
        db.close()

    def domain(self):
        return self.store.verify_chain()


class EveryRecordIsWitnessed(Harness):
    def test_the_witness_table_matches_the_schema(self):
        """A declared field that is not a column would silently hash as NULL,
        and the record would look witnessed while that fact was uncovered."""
        db = sqlite3.connect(self.root / "missions.sqlite3")
        for witness in sf.DOMAIN_WITNESSES:
            columns = {r[1] for r in db.execute("PRAGMA table_info(%s)" % witness.table)}
            with self.subTest(table=witness.table):
                self.assertTrue(set(witness.immutable) <= columns,
                                set(witness.immutable) - columns)
                self.assertTrue(set(witness.closed) <= columns,
                                set(witness.closed) - columns)
                if witness.closing:
                    self.assertIn(witness.closed_when, columns)

    def test_a_clean_mission_verifies(self):
        self.session()
        report = self.domain()
        self.assertTrue(report["ok"], report["problems"])
        self.assertEqual(report["domain"]["verdict"], "agrees")
        self.assertGreater(report["domain"]["verified"], 0)

    def test_a_session_edit_is_detected(self):
        self.session()
        self.sql("UPDATE agent_sessions SET executable='/tmp/evil'")
        report = self.domain()
        self.assertFalse(report["ok"])
        self.assertEqual(report["domain"]["verdict"], "disagrees")
        self.assertTrue(report["chain_ok"], "the LOG is intact; the ROW was edited")

    def test_the_close_facts_are_witnessed_separately(self):
        """How a session ended is a legitimate later mutation, so it has its own
        witness rather than being folded into a digest taken at creation."""
        sid = self.session()
        self.store.close_session(sid, exit_code=1, outcome="failed")
        self.assertTrue(self.domain()["ok"])
        self.sql("UPDATE agent_sessions SET exit_code=0, outcome='succeeded'")
        self.assertFalse(self.domain()["ok"])

    def test_an_invented_row_is_detected(self):
        self.store.record_artifact(self.mid, task_id=self.task, path=str(self.ws / "a.mkv"),
                                   sha256="e" * 64, size=4, kind="media")
        self.assertTrue(self.domain()["ok"])
        self.sql("INSERT INTO artifacts(id,mission_id,task_id,path,sha256,bytes,kind,"
                 "created_at) VALUES('art-planted',?,?,'/tmp/planted','f',1,'media',?)",
                 self.mid, self.task, sf.now())
        report = self.domain()
        self.assertFalse(report["ok"])
        self.assertTrue(any("art-planted" in p for p in report["problems"]))

    def test_an_artifact_commits_with_its_event(self):
        """record_artifact wrote a row and NO event, which AUDIT_EVENTS.md
        already listed as a gap."""
        before = len(self.store.events(self.mid))
        self.store.record_artifact(self.mid, task_id=self.task, path=str(self.ws / "a.mkv"),
                                   sha256="e" * 64, size=4, kind="media")
        events = self.store.events(self.mid)
        self.assertEqual(len(events), before + 1)
        self.assertEqual(events[-1]["event"], "artifact-recorded")

    def test_a_review_decision_commits_with_its_event(self):
        self.store.open_review(self.mid, summary="one file changed")
        self.store.decide_review(self.mid, "undo", decided_by="uid:1000")
        self.assertTrue(self.domain()["ok"])
        self.sql("UPDATE reviews SET decision='accept', decided_by='uid:0'")
        report = self.domain()
        self.assertFalse(report["ok"], "who decided a review was rewritten undetected")


class LateHashedField(Harness):
    def test_a_null_late_field_is_omitted_from_the_hash(self):
        """Adding record_sha256 to HASHED_FIELDS must not break the hash of a
        row written before the column existed."""
        row = {"seq": 1, "at": "t", "mission": "m", "task_id": None,
               "session_id": None, "tool_execution_id": None, "actor": "user",
               "event": "e", "detail": "d"}
        without = sf.event_hash("prev", row)
        with_null = sf.event_hash("prev", dict(row, record_sha256=None))
        self.assertEqual(without, with_null,
                         "a NULL late field changed an existing row's hash")
        with_value = sf.event_hash("prev", dict(row, record_sha256="x" * 64))
        self.assertNotEqual(without, with_value,
                            "the digest is not covered by the hash")

    def test_clearing_the_digest_on_a_new_row_is_detected(self):
        self.session()
        self.sql("UPDATE events SET record_sha256=NULL WHERE event='session-opened'")
        self.assertFalse(self.store.verify_chain()["chain_ok"])


if __name__ == "__main__":
    unittest.main()
