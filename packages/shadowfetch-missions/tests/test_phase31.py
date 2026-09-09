"""Unit tests for the Phase 3.1 hardening.

The adversarial suites prove these behaviours under attack. These prove them
under ordinary use, name each rule, and fail loudly if one is quietly removed --
which is the failure mode an attack suite is worst at, because an attack that
stops finding anything looks exactly like an attack that passes.
"""
import json
import os
import sqlite3
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_schema_migration import MigrationHarness      # noqa: E402
import sf_missions as sf                                # noqa: E402
import sf_policy                                        # noqa: E402
from sf_missions import Store                           # noqa: E402


class Harness(MigrationHarness):
    def setUp(self):
        super().setUp()
        self.store = Store(self.root)
        ws = Path(os.environ["SHADOWFETCH_AGENT_WORKSPACES"]) / "probe"
        ws.mkdir(parents=True, exist_ok=True)
        (ws / "a.mkv").write_bytes(b"clip")

    def mission(self):
        return self.store.create(capability="media_export", provider_id="offline-media",
                                 workspace_value="probe", title="t", prompt="p",
                                 inputs=["a.mkv"])["id"]

    def sql(self, statement, *params):
        db = sqlite3.connect(self.root / "missions.sqlite3")
        cur = db.execute(statement, params)
        db.commit()
        n = cur.rowcount
        db.close()
        return n


class AtomicCreation(Harness):
    def test_the_row_and_its_first_event_commit_together(self):
        mid = self.mission()
        events = [e["event"] for e in self.store.events(mid)]
        self.assertEqual(events[0], "queued")

    def test_a_failure_inside_create_leaves_no_row(self):
        """They were on two connections, so an interruption left a mission with
        no events -- the exact shape verify_states now treats as forged."""
        before = self.raw().execute("SELECT COUNT(*) FROM missions").fetchone()[0]
        real = Store._append

        def explode(self_, db, **kwargs):
            if kwargs.get("event") == "queued":
                raise RuntimeError("interrupted between the row and its event")
            return real(self_, db, **kwargs)

        Store._append = explode
        try:
            with self.assertRaises(RuntimeError):
                self.mission()
        finally:
            Store._append = real
        after = self.raw().execute("SELECT COUNT(*) FROM missions").fetchone()[0]
        self.assertEqual(after, before, "a mission row survived without its event")


class MissionClassification(Harness):
    def test_a_healthy_mission_is_valid_current(self):
        mid = self.mission()
        report = self.store.verify_chain()
        self.assertEqual(report["states"]["classes"][mid], sf.CLASS_VALID)
        self.assertEqual(report["states"]["verdict"], "agrees")

    def test_a_fabricated_row_is_missing_history(self):
        mid = self.mission()
        db = sqlite3.connect(self.root / "missions.sqlite3")
        cols = [r[1] for r in db.execute("PRAGMA table_info(missions)")]
        row = dict(zip(cols, db.execute("SELECT * FROM missions WHERE id=?", (mid,)).fetchone()))
        row["id"], row["state"] = "mission-invented", "completed"
        db.execute("INSERT INTO missions (%s) VALUES (%s)"
                   % (",".join(cols), ",".join("?" * len(cols))), [row[c] for c in cols])
        db.commit(); db.close()
        report = self.store.verify_chain()
        self.assertEqual(report["states"]["classes"]["mission-invented"], sf.CLASS_MISSING)
        self.assertFalse(report["ok"])
        self.assertTrue(report["chain_ok"], "the LOG is intact; the ROW was invented")

    def test_a_state_written_without_an_event_is_divergence(self):
        mid = self.mission()
        self.sql("UPDATE missions SET state='completed' WHERE id=?", mid)
        report = self.store.verify_chain()
        self.assertEqual(report["states"]["classes"][mid], sf.CLASS_DIVERGENT)
        self.assertFalse(report["ok"])

    def test_the_pin_is_written_even_when_it_names_nothing(self):
        """An empty pin grants no exemption. What it does is CLOSE THE SLOT, so
        a pin appended later is not the first one."""
        pins = self.raw().execute(
            "SELECT COUNT(*) FROM events WHERE event=?", (sf.LEGACY_PIN,)).fetchone()[0]
        self.assertEqual(pins, 1)

    def test_a_second_pin_is_reported_and_not_honoured(self):
        # One connection: self.raw() hands back a fresh one each call, so an
        # execute() on one and a commit() on another writes nothing.
        self.sql("INSERT INTO events(mission,at,event,detail) VALUES(?,?,?,?)",
                 "*", sf.now(), sf.LEGACY_PIN,
                 json.dumps({"missions": ["mission-invented"]}))
        report = self.store.verify_chain()
        self.assertTrue(any("pinned once" in p for p in report["problems"]),
                        report["problems"])

    def test_a_pin_from_a_broken_chain_is_not_evidence(self):
        mid = self.mission()
        self.sql("UPDATE events SET detail='x' WHERE seq=(SELECT MAX(seq) FROM events)")
        report = self.store.verify_chain()
        self.assertFalse(report["chain_ok"])
        self.assertIn(mid, report["states"]["classes"])


class RetryBudget(Harness):
    def test_the_edge_refuses_whichever_verb_asks(self):
        for verb in ("transition", "finish_execution"):
            with self.subTest(verb=verb):
                mid = self.mission()
                self.sql("UPDATE missions SET state='failed', attempt=? WHERE id=?",
                         sf.MAX_ATTEMPTS, mid)
                with self.assertRaises(sf.TransitionError) as caught:
                    if verb == "transition":
                        self.store.transition(mid, sf.MissionState.QUEUED)
                    else:
                        self.store.finish_execution(mid, sf.MissionState.QUEUED, None)
                self.assertIn("retry budget exhausted", str(caught.exception))
                self.assertEqual(self.store.get(mid)["state"], "failed")

    def test_the_refusal_is_recorded(self):
        mid = self.mission()
        self.sql("UPDATE missions SET state='failed', attempt=? WHERE id=?",
                 sf.MAX_ATTEMPTS, mid)
        with self.assertRaises(sf.TransitionError):
            self.store.transition(mid, sf.MissionState.QUEUED)
        self.assertIn("retry-budget-exhausted",
                      [e["event"] for e in self.store.events(mid)])

    def test_an_attempt_under_the_ceiling_is_allowed(self):
        mid = self.mission()
        self.sql("UPDATE missions SET state='failed', attempt=1 WHERE id=?", mid)
        self.store.transition(mid, sf.MissionState.QUEUED)
        self.assertEqual(self.store.get(mid)["state"], "queued")

    def test_requeue_refusal_only_speaks_about_requeue_edges(self):
        self.assertIsNone(sf.requeue_refusal("running", 99))
        self.assertIsNotNone(sf.requeue_refusal("retry-queued", sf.MAX_ATTEMPTS))


class ApprovalWitness(Harness):
    def grant(self):
        mid = self.mission()
        scope = {"provider": "offline-media", "capability": "media_export",
                 "workspace": self.store.get(mid)["workspace"], "network": "none"}
        aid = self.store.grant_approval(subject=mid, scope=scope, granted_by="owner",
                                        method="cli",
                                        expires_at="2099-01-01T00:00:00+00:00")
        return mid, aid, sf_policy.Scope.from_json(scope)

    def test_an_untouched_approval_is_accepted(self):
        mid, _aid, required = self.grant()
        row, why = self.store.find_approval(mid, required)
        self.assertIsNotNone(row, why)

    def test_every_provenance_field_is_witnessed(self):
        for column, value in (("granted_by", "somebody-else"), ("method", "forged"),
                              ("granted_at", "1999-01-01T00:00:00+00:00"),
                              ("expires_at", "2099-12-31T00:00:00+00:00"),
                              ("reason", "a different justification")):
            with self.subTest(column=column):
                mid, _aid, required = self.grant()
                self.sql("UPDATE approvals SET %s=?" % column, value)
                row, why = self.store.find_approval(mid, required)
                self.assertIsNone(row, "%s was rewritten undetected" % column)
                self.assertIn("does not match what was granted", why)

    def test_clearing_revoked_at_does_not_revive_an_approval(self):
        mid, aid, required = self.grant()
        self.store.revoke_approval(aid, reason="withdrawn")
        self.sql("UPDATE approvals SET revoked_at=NULL")
        row, why = self.store.find_approval(mid, required)
        self.assertIsNone(row)
        self.assertIn("revocation in the audit chain", why)

    def test_revoking_does_not_rewrite_the_grant_reason(self):
        """A revoke used to overwrite reason, which made an honest revocation
        look like a tampered grant."""
        mid, aid, _required = self.grant()
        before = self.raw().execute("SELECT reason FROM approvals WHERE id=?",
                                    (aid,)).fetchone()[0]
        self.store.revoke_approval(aid, reason="a different reason")
        after = self.raw().execute("SELECT reason FROM approvals WHERE id=?",
                                   (aid,)).fetchone()[0]
        self.assertEqual(before, after)


class ExitCodeContract(Harness):
    def test_the_ladder_is_derived_from_the_report_alone(self):
        self.assertEqual(sf.audit_exit_code({"ok": True, "anchor": {"verdict": "agrees"}}), 0)
        self.assertEqual(sf.audit_exit_code({"ok": False}), 1)
        self.assertEqual(sf.audit_exit_code({"ok": True, "anchor": {"verdict": "unverified"}}), 2)
        self.assertEqual(sf.audit_exit_code({"ok": True, "anchor": {"verdict": "degraded"}}), 2)

    def test_it_fails_closed(self):
        """The only way to be told a log is intact is for the verifier to have
        said so."""
        self.assertEqual(sf.audit_exit_code({}), 1)


if __name__ == "__main__":
    unittest.main()
