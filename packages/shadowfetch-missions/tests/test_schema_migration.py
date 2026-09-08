"""Forward migration of the mission database (Phase 2 Step 5).

4.0.0 shipped with no schema versioning at all: PRAGMA user_version was 0, there
was no schema_version column and no migrations table. Provider identity lived
inside the JSON config blob as "runtime", and the mission "kind" was
simultaneously the capability, the provider selector and the name of the method
that implemented it.

v2 makes capability and provider_id first-class columns DERIVED from what each
row already carried. Nothing is dropped, renamed or reinterpreted -- these tests
exist to prove that, for a database containing a mission in every state.
"""
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE / "data/usr/lib/shadowfetch/missions"))

import sf_missions
from sf_missions import Store, SCHEMA_VERSION, LEGACY_RUNTIME_PROVIDER

# The 4.0.0 schema, verbatim, so this test does not drift with the current one.
LEGACY_SCHEMA = """
CREATE TABLE IF NOT EXISTS missions (
    id TEXT PRIMARY KEY, title TEXT NOT NULL, kind TEXT NOT NULL,
    state TEXT NOT NULL, workspace TEXT NOT NULL, prompt TEXT NOT NULL,
    config TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
    attempt INTEGER NOT NULL DEFAULT 0, error TEXT,
    checkpoint TEXT, artifacts TEXT NOT NULL DEFAULT '[]', receipt TEXT,
    cancel_requested INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT, mission TEXT NOT NULL,
    at TEXT NOT NULL, event TEXT NOT NULL, detail TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS steps (
    mission TEXT NOT NULL, name TEXT NOT NULL, result TEXT NOT NULL,
    PRIMARY KEY (mission, name));
CREATE INDEX IF NOT EXISTS missions_queue ON missions(state, created_at);
"""

# One mission in every state 4.0.0 could produce.
LEGACY_ROWS = [
    # id, title, kind, state, runtime, network, extra config, error, checkpoint
    ("mission-queued01", "Queued code", "code", "queued", "codex", "allow",
     {"test": ["true"]}, None, None),
    ("mission-running1", "Running report", "report", "running", "codex", "allow",
     {"inputs": ["a.txt"]}, None, "20260101-000001"),
    ("mission-review01", "Awaiting review", "code", "waiting-review", "codex", "allow",
     {"test": ["pytest"]}, None, "20260101-000002"),
    ("mission-done0001", "Completed media", "media", "completed", "offline", "none",
     {"inputs": ["clip.mp4"]}, None, "20260101-000003"),
    ("mission-failed01", "Failed code", "code", "failed", "codex", "allow",
     {"test": ["false"]}, "Required tests failed (exit 1)", "20260101-000004"),
    ("mission-cancel01", "Cancelled media", "media", "cancelled", "offline", "none",
     {"inputs": ["x.wav"]}, "Cancelled by the person who started it", None),
    ("mission-undone01", "Undone code", "code", "undone", "codex", "allow",
     {"test": ["true"]}, None, "20260101-000005"),
]


def build_legacy_db(path):
    """A database exactly as 4.0.0 would have left it."""
    db = sqlite3.connect(path)
    db.executescript(LEGACY_SCHEMA)
    for mid, title, kind, state, runtime, network, extra, error, checkpoint in LEGACY_ROWS:
        config = {"runtime": runtime, "model": "", "inputs": extra.get("inputs", []),
                  "test": extra.get("test"), "network": network, "timeout": 900}
        db.execute(
            "INSERT INTO missions(id,title,kind,state,workspace,prompt,config,"
            "created_at,updated_at,attempt,error,checkpoint,artifacts,receipt,"
            "cancel_requested) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (mid, title, kind, state, "/home/u/Workspaces/demo", "do the thing",
             json.dumps(config), "2026-09-01T00:00:00+00:00", "2026-09-01T00:05:00+00:00",
             1, error, checkpoint, json.dumps(["/tmp/a"]), None, 0))
        db.execute("INSERT INTO events(mission,at,event,detail) VALUES(?,?,?,?)",
                   (mid, "2026-09-01T00:00:00+00:00", "queued", f"{kind}; network={network}"))
        db.execute("INSERT INTO steps(mission,name,result) VALUES(?,?,?)",
                   (mid, "some-step", json.dumps({"ok": True})))
    db.commit()
    assert db.execute("PRAGMA user_version").fetchone()[0] == 0
    db.close()


class MigrationHarness(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "state"
        self.root.mkdir(parents=True)
        self.db_path = self.root / "missions.sqlite3"
        self._env = dict(os.environ)
        os.environ["SHADOWFETCH_AGENT_WORKSPACES"] = str(Path(self.tmp.name) / "ws")
        (Path(self.tmp.name) / "ws").mkdir(exist_ok=True)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._env)
        self.tmp.cleanup()

    def open_store(self):
        return Store(self.root)

    def raw(self):
        db = sqlite3.connect(self.db_path)
        db.row_factory = sqlite3.Row
        return db


class EmptyDatabase(MigrationHarness):
    def test_a_fresh_database_is_created_at_the_current_version(self):
        store = self.open_store()
        db = self.raw()
        self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], SCHEMA_VERSION)
        columns = {r[1] for r in db.execute("PRAGMA table_info(missions)")}
        self.assertIn("capability", columns)
        self.assertIn("provider_id", columns)
        self.assertIn("kind", columns, "the legacy column must survive")
        self.assertEqual(store.list(), [])

    def test_opening_twice_is_idempotent(self):
        self.open_store()
        self.open_store()
        db = self.raw()
        self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], SCHEMA_VERSION)


class ExistingFourZeroDatabase(MigrationHarness):
    def setUp(self):
        super().setUp()
        build_legacy_db(self.db_path)

    def test_version_moves_forward(self):
        self.open_store()
        db = self.raw()
        self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], SCHEMA_VERSION)

    def test_every_mission_survives_in_every_state(self):
        store = self.open_store()
        got = {m["id"]: m for m in store.list()}
        self.assertEqual(len(got), len(LEGACY_ROWS))
        for mid, title, kind, state, runtime, network, extra, error, checkpoint in LEGACY_ROWS:
            with self.subTest(state=state):
                row = got[mid]
                self.assertEqual(row["title"], title)
                self.assertEqual(row["kind"], kind, "the original kind must be untouched")
                self.assertEqual(row["state"], state)
                self.assertEqual(row["error"], error)
                self.assertEqual(row["checkpoint"], checkpoint)
                self.assertEqual(row["config"]["runtime"], runtime,
                                 "the original config blob must not be rewritten")
                self.assertEqual(row["config"]["network"], network)
                self.assertEqual(row["prompt"], "do the thing")

    def test_capability_and_provider_are_derived(self):
        self.open_store()
        db = self.raw()
        rows = {r["id"]: r for r in db.execute(
            "SELECT id, kind, capability, provider_id, config FROM missions")}
        expected_capability = {"code": "code_change", "report": "sourced_report",
                               "media": "media_export"}
        for mid, title, kind, state, runtime, network, extra, error, checkpoint in LEGACY_ROWS:
            with self.subTest(mission=mid):
                row = rows[mid]
                self.assertEqual(row["capability"], expected_capability[kind])
                self.assertEqual(row["provider_id"], LEGACY_RUNTIME_PROVIDER[runtime])

    def test_offline_runtime_becomes_the_offline_media_provider(self):
        """The one rename in the migration, stated explicitly."""
        self.open_store()
        db = self.raw()
        row = db.execute(
            "SELECT provider_id, config FROM missions WHERE id='mission-done0001'").fetchone()
        self.assertEqual(row["provider_id"], "offline-media")
        self.assertEqual(json.loads(row["config"])["runtime"], "offline",
                         "the legacy runtime string must remain readable in config")

    def test_events_and_steps_are_untouched(self):
        self.open_store()
        db = self.raw()
        self.assertEqual(
            db.execute("SELECT COUNT(*) FROM events WHERE mission != '*'").fetchone()[0],
            len(LEGACY_ROWS))
        self.assertEqual(db.execute("SELECT COUNT(*) FROM steps").fetchone()[0],
                         len(LEGACY_ROWS))

    def test_the_migration_is_recorded(self):
        self.open_store()
        db = self.raw()
        note = db.execute(
            "SELECT detail FROM events WHERE event='schema-migrated'").fetchone()
        self.assertIsNotNone(note, "a migration that leaves no trace cannot be audited")
        self.assertIn("v0 -> v2", note["detail"])

    def test_migrating_twice_changes_nothing(self):
        self.open_store()
        first = self.raw().execute(
            "SELECT id, capability, provider_id FROM missions ORDER BY id").fetchall()
        self.open_store()
        second = self.raw().execute(
            "SELECT id, capability, provider_id FROM missions ORDER BY id").fetchall()
        self.assertEqual([tuple(r) for r in first], [tuple(r) for r in second])
        count = self.raw().execute(
            "SELECT COUNT(*) FROM events WHERE event='schema-migrated'").fetchone()[0]
        self.assertEqual(count, 1, "a second open must not re-log a migration")

    def test_a_queued_mission_is_still_runnable_shaped(self):
        store = self.open_store()
        queued = [m for m in store.list() if m["state"] == "queued"]
        self.assertEqual(len(queued), 1)
        self.assertEqual(queued[0]["config"]["test"], ["true"])

    def test_review_and_undo_predicates_still_hold(self):
        store = self.open_store()
        by_state = {m["state"]: m for m in store.list()}
        self.assertTrue(by_state["waiting-review"]["checkpoint"],
                        "a mission awaiting review must keep its recovery point")
        self.assertTrue(by_state["completed"]["checkpoint"])
        self.assertTrue(by_state["failed"]["checkpoint"])


class UnknownLegacyRows(MigrationHarness):
    def test_an_unrecognised_row_is_left_alone_rather_than_guessed_at(self):
        build_legacy_db(self.db_path)
        db = sqlite3.connect(self.db_path)
        db.execute(
            "INSERT INTO missions(id,title,kind,state,workspace,prompt,config,"
            "created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
            ("mission-strange1", "From the future", "hologram", "completed",
             "/home/u/Workspaces/demo", "?", json.dumps({"runtime": "telepathy"}),
             "2026-09-01T00:00:00+00:00", "2026-09-01T00:00:00+00:00"))
        db.commit(); db.close()

        store = self.open_store()
        rows = {m["id"]: m for m in store.list()}
        self.assertIn("mission-strange1", rows, "it must still be readable and listable")
        self.assertEqual(rows["mission-strange1"]["kind"], "hologram")
        raw = self.raw().execute(
            "SELECT capability, provider_id FROM missions WHERE id='mission-strange1'").fetchone()
        self.assertIsNone(raw["capability"])
        self.assertIsNone(raw["provider_id"])


class NewerDatabaseIsRefused(MigrationHarness):
    def test_a_database_from_the_future_is_not_reinterpreted(self):
        build_legacy_db(self.db_path)
        db = sqlite3.connect(self.db_path)
        db.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 5}")
        db.commit(); db.close()
        with self.assertRaisesRegex(sf_missions.MissionError, "newer Shadowfetch"):
            self.open_store()


if __name__ == "__main__":
    unittest.main(verbosity=2)
