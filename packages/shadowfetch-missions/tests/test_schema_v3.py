"""Phase 3 schema v3 and the event hash chain.

Two things are being proven here, and they are different. The MIGRATION tests
prove that nothing a v0/v1/v2 database carried is lost or reinterpreted. The
CHAIN tests prove that the log is tamper-EVIDENT -- not tamper-proof, which no
table in a file the user owns can be. Every adversarial case below therefore
alters the database directly with sqlite3 and asks only that verify_chain()
notices.
"""
import copy
import json
import os
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from test_schema_migration import MigrationHarness, build_legacy_db, Store, SCHEMA_VERSION
import test_schema_migration as legacy_module

sf = legacy_module.sf_missions if hasattr(legacy_module, "sf_missions") else None
if sf is None:                                   # the module is loaded by path there
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]
                           / "data/usr/lib/shadowfetch/missions"))
    import sf_missions as sf


V3_TABLES = ("tasks", "agent_sessions", "tool_executions", "approvals",
             "reviews", "artifacts", "test_runs", "git_changes")


class SchemaShape(MigrationHarness):
    def test_every_v3_table_exists_and_none_was_invented(self):
        self.open_store()
        db = self.raw()
        names = {r[0] for r in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%'")}
        for table in V3_TABLES:
            self.assertIn(table, names)
        # The audit proposed three more. Their absence is a decision, recorded
        # in PHASE3_IMPLEMENTATION.md; if one appears, that decision changed and
        # the reasoning has to change with it.
        for absent in ("schema_version", "agent_providers", "workspaces"):
            self.assertNotIn(absent, names,
                             f"{absent} was created; update the Step 2 reasoning")

    def test_the_legacy_tables_are_still_there(self):
        self.open_store()
        db = self.raw()
        names = {r[0] for r in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        for kept in ("missions", "events", "steps"):
            self.assertIn(kept, names)

    def test_missions_and_events_gained_only_columns(self):
        self.open_store()
        db = self.raw()
        missions = {r[1] for r in db.execute("PRAGMA table_info(missions)")}
        events = {r[1] for r in db.execute("PRAGMA table_info(events)")}
        for column in ("id", "title", "kind", "state", "workspace", "prompt",
                       "config", "created_at", "updated_at", "attempt", "error",
                       "checkpoint", "artifacts", "receipt", "cancel_requested",
                       "capability", "provider_id"):
            self.assertIn(column, missions, "a v2 column was dropped")
        self.assertIn("approval_id", missions)
        for column in ("seq", "mission", "at", "event", "detail"):
            self.assertIn(column, events, "a v2 column was dropped")
        for column in ("task_id", "session_id", "tool_execution_id", "actor",
                       "prev_hash", "hash"):
            self.assertIn(column, events)


class LegacyDatabaseReachesV3(MigrationHarness):
    def setUp(self):
        super().setUp()
        build_legacy_db(self.db_path)

    def test_version_moves_to_three(self):
        self.open_store()
        self.assertEqual(
            self.raw().execute("PRAGMA user_version").fetchone()[0], SCHEMA_VERSION)

    def test_every_legacy_mission_survives_in_every_state(self):
        before = {r["id"]: dict(r) for r in
                  self.raw().execute("SELECT * FROM missions")}
        store = self.open_store()
        after = {m["id"]: m for m in store.list()}
        self.assertEqual(set(before), set(after), "a legacy mission disappeared")
        for mid, row in before.items():
            for field in ("title", "kind", "state", "workspace", "prompt",
                          "created_at", "attempt"):
                self.assertEqual(after[mid][field], row[field],
                                 f"{mid}.{field} was reinterpreted")

    def test_legacy_events_are_preserved_and_marked_unchained(self):
        before = self.raw().execute("SELECT COUNT(*) FROM events").fetchone()[0]
        store = self.open_store()
        report = store.verify_chain()
        self.assertTrue(report["ok"], report["problems"])
        # every pre-existing row, plus any v2 migration row, is unchained
        self.assertGreaterEqual(report["unchained"], before)
        self.assertEqual(report["chained"], 1, "only the genesis is chained yet")
        rows = self.raw().execute(
            "SELECT hash FROM events ORDER BY seq LIMIT ?", (before,)).fetchall()
        for row in rows:
            self.assertIsNone(row["hash"], "a pre-chain row was given a hash it never had")

    def test_the_genesis_pins_the_unchained_set(self):
        store = self.open_store()
        row = self.raw().execute(
            "SELECT detail FROM events WHERE event=? ", (sf.CHAIN_GENESIS,)).fetchone()
        detail = json.loads(row["detail"])
        self.assertIn("unchained_digest", detail)
        self.assertEqual(len(detail["unchained_digest"]), 64)
        self.assertEqual(detail["to_schema_version"], SCHEMA_VERSION)
        self.assertIn("not individually verifiable", detail["note"])

    def test_migrating_twice_adds_no_second_genesis(self):
        self.open_store()
        self.open_store()
        count = self.raw().execute(
            "SELECT COUNT(*) FROM events WHERE event=?", (sf.CHAIN_GENESIS,)).fetchone()[0]
        self.assertEqual(count, 1)

    def test_steps_rows_survive(self):
        before = self.raw().execute("SELECT COUNT(*) FROM steps").fetchone()[0]
        self.open_store()
        after = self.raw().execute("SELECT COUNT(*) FROM steps").fetchone()[0]
        self.assertEqual(before, after)


class MigrationInterruption(MigrationHarness):
    def setUp(self):
        super().setUp()
        build_legacy_db(self.db_path)

    def test_a_failure_midway_leaves_the_old_shape_intact(self):
        """migrate() runs inside the caller's transaction, so a crash rolls the
        whole step back rather than leaving a database at half a version."""
        original = sf.Store.start_chain

        def explode(self, db, **kw):
            raise RuntimeError("simulated crash during migration")

        sf.Store.start_chain = explode
        try:
            with self.assertRaises(RuntimeError):
                self.open_store()
        finally:
            sf.Store.start_chain = original
        db = self.raw()
        self.assertLess(db.execute("PRAGMA user_version").fetchone()[0], 3,
                        "the version was stamped despite the failure")
        names = {r[0] for r in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertNotIn("agent_sessions", names,
                         "a partial schema survived a failed migration")
        # and the retry succeeds
        store = self.open_store()
        self.assertTrue(store.verify_chain()["ok"])
        self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], SCHEMA_VERSION)


class ChainAppend(MigrationHarness):
    def setUp(self):
        super().setUp()
        self.store = self.open_store()

    def append(self, n=5):
        for i in range(n):
            self.store.append_event("mission-%d" % i, "probe", "detail %d" % i)

    def test_a_clean_chain_verifies(self):
        self.append()
        report = self.store.verify_chain()
        self.assertTrue(report["ok"], report["problems"])
        self.assertEqual(report["problems"], [])
        self.assertEqual(report["chained"], 6)          # genesis + 5
        self.assertEqual(report["head_seq"], 6)

    def test_the_first_row_chains_from_a_known_genesis_value(self):
        row = self.raw().execute("SELECT * FROM events ORDER BY seq LIMIT 1").fetchone()
        self.assertEqual(row["prev_hash"], sf.GENESIS_PREV)

    def test_every_appended_row_carries_its_actor(self):
        self.store.append_event("m", "did-a-thing", "x", actor=sf.ACTOR_USER)
        row = self.raw().execute(
            "SELECT actor FROM events ORDER BY seq DESC LIMIT 1").fetchone()
        self.assertEqual(row["actor"], sf.ACTOR_USER)

    def test_correlation_columns_round_trip(self):
        self.store.append_event("m", "tool", "x", task_id="task-1",
                                session_id="sess-1", tool_execution_id="tool-1")
        row = self.raw().execute(
            "SELECT * FROM events ORDER BY seq DESC LIMIT 1").fetchone()
        self.assertEqual((row["task_id"], row["session_id"], row["tool_execution_id"]),
                         ("task-1", "sess-1", "tool-1"))

    def test_a_detail_is_redacted_before_it_is_hashed(self):
        os.environ["OPENAI_API_KEY"] = "sk-conformance-not-a-real-key-000000"
        try:
            self.store.append_event("m", "leak", "token sk-conformance-not-a-real-key-000000")
        finally:
            os.environ.pop("OPENAI_API_KEY", None)
        row = self.raw().execute(
            "SELECT detail FROM events ORDER BY seq DESC LIMIT 1").fetchone()
        self.assertNotIn("sk-conformance", row["detail"])
        self.assertTrue(self.store.verify_chain()["ok"],
                        "redaction must happen before hashing, or the row cannot verify")


class ChainIsTamperEvident(MigrationHarness):
    """Every case alters the database directly. The claim is EVIDENCE, not
    prevention: a user who owns the file can always change it, and the only
    honest guarantee is that the change is visible afterwards."""

    def setUp(self):
        super().setUp()
        self.store = self.open_store()
        for i in range(6):
            self.store.append_event("mission-%d" % (i % 2), "probe", "detail %d" % i)
        self.assertTrue(self.store.verify_chain()["ok"])

    def broken(self):
        report = self.store.verify_chain()
        self.assertFalse(report["ok"], "the alteration was not detected")
        return " ".join(report["problems"])

    def raw_write(self, sql, params=()):
        db = sqlite3.connect(self.db_path)
        db.execute(sql, params)
        db.commit()
        db.close()

    def test_a_modified_detail_is_detected(self):
        self.raw_write("UPDATE events SET detail='rewritten' WHERE seq=4")
        self.assertIn("does not match its hash", self.broken())

    def test_a_modified_mission_id_is_detected(self):
        self.raw_write("UPDATE events SET mission='somebody-else' WHERE seq=3")
        self.assertIn("does not match its hash", self.broken())

    def test_a_modified_actor_is_detected(self):
        self.raw_write("UPDATE events SET actor='user' WHERE seq=5")
        self.assertIn("does not match its hash", self.broken())

    def test_a_deleted_row_is_detected(self):
        self.raw_write("DELETE FROM events WHERE seq=4")
        problems = self.broken()
        self.assertTrue("truncated or renumbered" in problems
                        or "does not match the previous row" in problems, problems)

    def test_a_truncated_chain_is_caught_only_by_the_external_anchor(self):
        """Deleting the TAIL is the case a per-row checksum cannot catch: every
        surviving row is individually valid.

        Both halves are asserted, because the interesting fact is WHERE the
        finding comes from. The chain's own verdict on the surviving rows is
        still "all agree" -- that is not a bug, it is what a chain is. The
        detection is entirely the journald high-water mark from Step 4, which
        the mission worker's uid cannot rewrite.
        """
        self.raw_write("DELETE FROM events WHERE seq >= 5")
        report = self.store.verify_chain()
        self.assertEqual(report["head_seq"], 4)

        # (a) the chain by itself finds nothing: no row was altered
        row_problems = [p for p in report["problems"] if "journal" not in p]
        self.assertEqual(row_problems, [],
                         "per-row hashes should still agree after a truncation")

        # (b) the anchor is the whole finding
        anchor = report["anchor"]
        if not anchor["readable"]:
            self.skipTest("journald is not readable here, so truncation is "
                          "genuinely undetectable on this host -- which is the "
                          "degraded state, reported rather than hidden")
        self.assertEqual(anchor["verdict"], "truncated")
        self.assertFalse(report["ok"])
        self.assertTrue(any("removed from the end" in p for p in report["problems"]))

    def test_an_inserted_row_is_detected(self):
        self.raw_write(
            "INSERT INTO events(seq,mission,at,event,detail,actor,prev_hash,hash) "
            "VALUES(99,'m','2026-01-01T00:00:00','forged','x','user','deadbeef','cafe')")
        self.assertIn("does not match the previous row", self.broken())

    def test_a_reordered_pair_is_detected(self):
        db = sqlite3.connect(self.db_path)
        a = db.execute("SELECT detail FROM events WHERE seq=3").fetchone()[0]
        b = db.execute("SELECT detail FROM events WHERE seq=4").fetchone()[0]
        db.execute("UPDATE events SET detail=? WHERE seq=3", (b,))
        db.execute("UPDATE events SET detail=? WHERE seq=4", (a,))
        db.commit(); db.close()
        self.assertIn("does not match its hash", self.broken())

    def test_a_corrupted_prev_hash_is_detected(self):
        # 'x' is not a hex digit, so this always differs from the real value.
        # The first version of this test used '0', which was a no-op whenever the
        # hash already began with '0' -- a flake that passed roughly fifteen runs
        # in sixteen and reported a corruption it had not made.
        self.raw_write("UPDATE events SET prev_hash='x'||substr(prev_hash,2) WHERE seq=4")
        self.assertIn("does not match the previous row", self.broken())

    def test_rewriting_a_row_AND_its_hash_still_breaks_the_successor(self):
        """The point of chaining. A forger who recomputes one row's own hash has
        not finished -- every later row's prev_hash still names the old value."""
        db = sqlite3.connect(self.db_path)
        db.row_factory = sqlite3.Row
        row = dict(db.execute("SELECT * FROM events WHERE seq=3").fetchone())
        row["detail"] = "rewritten"
        forged = sf.event_hash(row["prev_hash"], row)
        db.execute("UPDATE events SET detail=?, hash=? WHERE seq=3",
                   (row["detail"], forged))
        db.commit(); db.close()
        self.assertIn("does not match the previous row", self.broken())

    def test_a_hash_on_a_pre_chain_row_is_detected(self):
        self.raw_write(
            "INSERT INTO events(seq,mission,at,event,detail,hash) "
            "VALUES(0,'m','2026-01-01T00:00:00','sneaked','x','abc')")
        self.assertIn("carries a hash before the chain genesis", self.broken())


class Canonicalization(unittest.TestCase):
    def test_key_order_does_not_change_the_digest(self):
        a = {"b": 1, "a": 2, "c": [1, 2]}
        b = {"c": [1, 2], "a": 2, "b": 1}
        self.assertEqual(sf.canonical(a), sf.canonical(b))

    def test_whitespace_is_not_representable(self):
        self.assertNotIn(b" ", sf.canonical({"a": 1, "b": 2}))

    def test_non_ascii_hashes_as_text_not_as_an_escape(self):
        blob = sf.canonical({"detail": "café"})
        self.assertIn("café".encode("utf-8"), blob)
        self.assertNotIn(b"\\u00e9", blob)

    def test_only_the_named_fields_are_hashed(self):
        base = {k: "x" for k in sf.HASHED_FIELDS}
        extra = dict(base, something_else="ignored")
        self.assertEqual(sf.event_hash("p", base), sf.event_hash("p", extra))

    def test_every_hashed_field_actually_changes_the_hash(self):
        base = {k: "x" for k in sf.HASHED_FIELDS}
        reference = sf.event_hash("p", base)
        for field in sf.HASHED_FIELDS:
            with self.subTest(field=field):
                self.assertNotEqual(sf.event_hash("p", dict(base, **{field: "y"})),
                                    reference, f"{field} is not covered by the hash")

    def test_the_previous_hash_changes_the_hash(self):
        base = {k: "x" for k in sf.HASHED_FIELDS}
        self.assertNotEqual(sf.event_hash("a", base), sf.event_hash("b", base))


class ConcurrentAppend(MigrationHarness):
    def test_parallel_appends_produce_one_unforked_chain(self):
        """Two writers that both read the same chain head would fork it. The
        append path takes BEGIN IMMEDIATE so they cannot."""
        store = self.open_store()
        errors = []

        def worker(n):
            try:
                own = Store(self.root)
                for i in range(10):
                    own.append_event("mission-%d" % n, "concurrent", "%d-%d" % (n, i))
            except Exception as exc:                      # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        report = store.verify_chain()
        self.assertTrue(report["ok"], report["problems"])
        self.assertEqual(report["chained"], 41)           # genesis + 4*10
        seqs = [r[0] for r in self.raw().execute("SELECT seq FROM events ORDER BY seq")]
        self.assertEqual(seqs, list(range(1, 42)), "sequence numbers collided or skipped")


class InterruptedTransaction(MigrationHarness):
    def test_a_failed_state_change_leaves_no_event_behind(self):
        """A state change and its event share one transaction, so a crash
        between them is not representable. An event that describes something
        that did not happen is worse than a missing one."""
        store = self.open_store()
        ws = Path(os.environ["SHADOWFETCH_AGENT_WORKSPACES"]) / "probe"
        ws.mkdir(parents=True, exist_ok=True)
        (ws / "a.mkv").write_bytes(b"not really a clip")
        mission = store.create(capability="media_export", provider_id="offline-media",
                               workspace_value="probe", title="t", prompt="p",
                               inputs=["a.mkv"])
        before = self.raw().execute("SELECT COUNT(*) FROM events").fetchone()[0]
        with self.assertRaises(sqlite3.Error):
            with store.db() as db:
                db.execute("BEGIN IMMEDIATE")
                store._append(db, mission=mission["id"], event="about-to-fail")
                db.execute("UPDATE missions SET nonexistent_column=1 WHERE id=?",
                           (mission["id"],))
        after = self.raw().execute("SELECT COUNT(*) FROM events").fetchone()[0]
        self.assertEqual(before, after, "an event survived a rolled-back transaction")
        self.assertTrue(store.verify_chain()["ok"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
