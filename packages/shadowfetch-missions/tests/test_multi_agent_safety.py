"""Stage O: what this engine does when more than one agent runs.

capabilities() reports max_parallel: 1, and the shipped worker consumes its
queue in a single-threaded loop holding worker.lock exclusively. Read on its
own, that reads as a system-wide guarantee. It is not one: it is a property of
ONE WORKER PROCESS on ONE state root, and the lock hierarchy is deliberately
built so that two workspaces proceed at the same time.

Every assertion here was measured first, by tools/probes/stage_o_multi_agent.py,
and the measurements are written down in docs/MULTI_AGENT_SAFETY.md with the
command that produced them. What these tests do is make each measured property
REGRESSION-VISIBLE: if the engine stops serializing one workspace, stops keying
approvals by subject, or starts forking its audit chain, one of these goes red.

ONE TEST IN HERE IS RED ON ARRIVAL, and it is the point of the stage:
ApprovalsUnderConcurrency.test_a_revoke_racing_the_check_never_produces_used_after_revoked
asserts the invariant require_approval()'s own comment claims, and the engine
does not hold it. 25 of 240 races against a separate revoking process consumed
an approval that had already been revoked and chained, and all 25 of those
missions took a workspace checkpoint and started work. The window is between the
re-read committing and 'approval-used' being appended. The fix belongs in
sf_missions.py, which this stage does not edit; the exact anchor and replacement
are in docs/MULTI_AGENT_SAFETY.md under BLOCKED. Do NOT relax this assertion to
match the current behaviour -- with the fix it is green deterministically.

THREE MORE TESTS PIN SOMETHING THAT IS NOT A CONTROL, and each says so in its
own docstring:

  * two callers with different SHADOWFETCH_MISSIONS_STATE roots are NOT
    serialized on a shared workspace -- the lock file lives under the state
    root and the workspace lives somewhere else entirely;
  * a worker that loses worker.lock exits 0 in silence, which is what a worker
    that did all its work also does;
  * a caller that loses the first-open race on a new database escapes as a bare
    sqlite3.OperationalError, which the CLI's own error handler does not catch.

Those three assert the behaviour AS MEASURED. If a later stage fixes one, the
test will go red, and the fix is to assert the NEW verified fact -- with a
docstring saying what changed and what was measured -- never to delete it.

WHAT IS DELIBERATELY NOT HERE. Nothing in this file asserts a line number, a
copied constant or the text of a comment. Concurrency claims are made by
running two real callers and comparing what each one observed.
"""
import contextlib
import fcntl
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path

import mission_approvals
from test_schema_migration import MigrationHarness, Store

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "packages/shadowfetch-missions/data/usr/lib/shadowfetch/missions"))
import sf_missions as sf

MISSIONS_CLI = REPO / "packages/shadowfetch-missions/data/usr/bin/shadowfetch-missions"
FIREBREAK_BIN = REPO / "packages/shadowfetch-fireline/data/usr/bin/shadowfetch-firebreak"
CHECKPOINT_BIN = REPO / "packages/shadowfetch-fireline/data/usr/bin/shadowfetch-checkpoint"

# Absolute, and never resolved through PATH. Whether a sandbox exists decides
# what these tests claim to have proved, so an inherited PATH must not be what
# answers it -- and a child of these programs resolves ITS helpers through what
# it inherits, which is why TRUSTED_PATH is handed down rather than the
# caller's.
BWRAP = "/usr/bin/bwrap"
SYSTEMD_RUN = "/usr/bin/systemd-run"
SYSTEMCTL = "/usr/bin/systemctl"
FFMPEG = "/usr/bin/ffmpeg"
TRUSTED_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


def sandbox_available():
    """Whether a REAL Firebreak session can run here.

    Every program is named by absolute path rather than found with which():
    the answer decides whether a test claims to have measured a sandbox, and a
    build tree or a shim earlier on PATH would let the environment decide that.
    """
    if not (Path(BWRAP).is_file() and Path(SYSTEMD_RUN).is_file()
            and Path(FFMPEG).is_file() and FIREBREAK_BIN.is_file()):
        return False
    probe = subprocess.run([SYSTEMCTL, "--user", "is-system-running"],
                           capture_output=True, text=True,
                           env={"PATH": TRUSTED_PATH,
                                "HOME": os.environ.get("HOME", "/tmp"),
                                "XDG_RUNTIME_DIR": os.environ.get(
                                    "XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")})
    return probe.returncode == 0 or "running" in probe.stdout or "degraded" in probe.stdout


class StageOHarness(MigrationHarness):
    """MigrationHarness plus the things a SECOND caller needs to exist.

    MigrationHarness redirects the workspace root and hands out a state
    directory, which is enough for a test that only ever holds one Store. Stage
    O runs subprocesses and second Stores, so the state root has to be in the
    environment too, and the Firebreak and checkpoint engines have to be the
    ones in this tree rather than whatever is installed.
    """

    def setUp(self):
        super().setUp()
        os.environ["SHADOWFETCH_MISSIONS_STATE"] = str(self.root)
        os.environ["SHADOWFETCH_FIREBREAK_STATE"] = str(Path(self.tmp.name) / "fb")
        os.environ["SHADOWFETCH_MCP_STATE"] = str(Path(self.tmp.name) / "mcp")
        os.environ["SHADOWFETCH_FIREBREAK_TEST_BIN"] = str(FIREBREAK_BIN)
        os.environ["SHADOWFETCH_CHECKPOINT_BIN"] = str(CHECKPOINT_BIN)
        os.environ["PATH"] = TRUSTED_PATH
        self.workspace_root = Path(os.environ["SHADOWFETCH_AGENT_WORKSPACES"])
        self.store = Store(self.root)

    # -- fixtures ---------------------------------------------------------
    def workspace(self, name):
        path = self.workspace_root / name
        path.mkdir(parents=True, exist_ok=True)
        (path / "facts.md").write_text("a fact this workspace already held\n")
        return path

    def media_mission(self, workspace="proj", title="media"):
        self.workspace(workspace)
        return self.store.create(capability="media_export",
                                 provider_id="offline-media",
                                 workspace_value=workspace, title=title,
                                 prompt="export", inputs=["facts.md"])

    def escalating_mission(self, workspace="proj", title="cloud"):
        """A mission whose policy decision needs a person.

        The cloud provider brings a credential identity and a network posture
        into the scope, which is what makes require_approval() actually decide
        something. It also fails as soon as it tries to run, with no sandbox
        involved -- so a test about APPROVAL does not silently become a test
        about whether bubblewrap is installed.
        """
        self.workspace(workspace)
        return self.store.create(kind="report", provider_id="codex",
                                 workspace_value=workspace, title=title,
                                 prompt="report", inputs=["facts.md"])

    def child_env(self, **overrides):
        env = {key: os.environ[key] for key in (
            "SHADOWFETCH_AGENT_WORKSPACES", "SHADOWFETCH_MISSIONS_STATE",
            "SHADOWFETCH_FIREBREAK_STATE", "SHADOWFETCH_MCP_STATE",
            "SHADOWFETCH_FIREBREAK_TEST_BIN", "SHADOWFETCH_CHECKPOINT_BIN",
            "PATH") if key in os.environ}
        env["HOME"] = os.environ.get("HOME", str(self.tmp.name))
        env.update(overrides)
        return env

    def cli(self, *args, timeout=300, env=None):
        return subprocess.run([sys.executable, str(MISSIONS_CLI), *args],
                              capture_output=True, text=True, timeout=timeout,
                              env=env or self.child_env())

    def event_rows(self, mid=None):
        """seq included. Store.events() returns at/event/detail, and the SEQUENCE
        is what says which of two records came first."""
        with self.store.db() as db:
            if mid is None:
                return [dict(r) for r in db.execute(
                    "SELECT seq, mission, event, prev_hash, hash FROM events "
                    "ORDER BY seq")]
            return [dict(r) for r in db.execute(
                "SELECT seq, mission, event FROM events WHERE mission=? "
                "ORDER BY seq", (mid,))]


# --------------------------------------------------------------------------- #
# O1 -- two workers
# --------------------------------------------------------------------------- #
class WorkerAdmission(StageOHarness):
    def test_a_second_worker_consumes_nothing_while_the_lock_is_held(self):
        """worker.lock is the whole of 'one consumer at a time'.

        Measured with two real worker processes: exactly one 'running' event,
        attempt 1, one set of agent sessions. Here the lock is held directly so
        the property can be asserted without a sandbox.
        """
        mission = self.media_mission(title="left alone")
        with (self.store.root / "worker.lock").open("a") as handle:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.addCleanup(lambda: None)
            code = sf.worker(self.store, once=True)
        self.assertEqual(code, 0)
        row = self.store.get(mission["id"])
        self.assertEqual(row["state"], "queued",
                         "a second worker consumed a mission it does not own")
        self.assertEqual([e["event"] for e in self.store.events(mission["id"])],
                         ["queued"],
                         "the refused worker appended something to the mission")

    def test_a_refused_worker_is_indistinguishable_from_an_idle_one(self):
        """MEASURED, AND A DEFECT: exit 0 is both answers.

        worker() returns 0 when it drained its queue and 0 when it was refused
        because another worker owns the state root. A supervisor, a systemd
        unit or an operator reading `shadowfetch-missions worker --once` cannot
        tell 'nothing to do' from 'somebody else has this'. The refusal is
        SAFE -- the queue is untouched, which the test above asserts -- and
        UNREPORTED, which is this one.

        If a later stage gives the refusal its own exit status or a message,
        this test goes red and must be rewritten to assert that new fact.
        """
        self.media_mission(title="still queued")
        with (self.store.root / "worker.lock").open("a") as handle:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            refused = sf.worker(self.store, once=True)
        drained = sf.worker(Store(Path(self.tmp.name) / "empty-state"), once=True)
        self.assertEqual(refused, 0)
        self.assertEqual(drained, 0)
        self.assertEqual(refused, drained,
                         "if these ever differ the refusal has become reportable; "
                         "assert the new distinction instead of this equality")

    def test_worker_lock_is_one_file_per_state_root(self):
        """The lock is scoped to a state root, not to the machine."""
        other = Store(Path(self.tmp.name) / "state-b")
        first = (self.store.root / "worker.lock").open("a")
        second = (other.root / "worker.lock").open("a")
        self.addCleanup(first.close)
        self.addCleanup(second.close)
        self.assertNotEqual(self.store.root, other.root)
        fcntl.flock(first, fcntl.LOCK_EX | fcntl.LOCK_NB)
        # No BlockingIOError: two state roots exclude nothing from each other.
        fcntl.flock(second, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(second, fcntl.LOCK_UN)
        fcntl.flock(first, fcntl.LOCK_UN)


# --------------------------------------------------------------------------- #
# O1/O2 -- workspace serialization
# --------------------------------------------------------------------------- #
class WorkspaceSerialization(StageOHarness):
    def test_one_workspace_admits_one_holder(self):
        self.workspace("alpha")
        with self.store.lock(workspace="alpha"):
            with self.assertRaises(sf.MissionError) as caught:
                with self.store.lock(workspace="alpha"):
                    pass
        self.assertIn("alpha", str(caught.exception),
                      "the refusal must name the contended workspace")

    def test_two_workspaces_do_not_exclude_each_other(self):
        self.workspace("alpha")
        self.workspace("beta")
        with self.store.lock(workspace="alpha"):
            with self.store.lock(workspace="beta"):
                pass

    def test_two_state_roots_do_not_serialize_on_one_workspace(self):
        """MEASURED, AND NOT A CONTROL.

        Store.lock_path() puts execution-<digest>.lock inside the STATE root,
        while the workspace it names lives under the workspace root. Two callers
        that differ only in SHADOWFETCH_MISSIONS_STATE therefore take two
        different files for one directory and both proceed. Measured with two
        real processes holding for 0.7s: 0.700030s of overlap.

        What still holds underneath: the checkpoint engine serializes snapshot
        and undo per workspace on its own lock, and review(undo) refuses a
        workspace whose recovery index moved. The agents' own writes are not
        serialized by anything.

        If a later stage moves the lock beside the workspace, this goes red;
        assert the new serialization then, and say what was measured.
        """
        self.workspace("alpha")
        other = Store(Path(self.tmp.name) / "state-b")
        with self.store.lock(workspace="alpha"):
            with other.lock(workspace="alpha"):
                pass
        self.assertNotEqual(self.store.lock_path("alpha")[0],
                            other.lock_path("alpha")[0])

    def test_every_spelling_of_a_workspace_maps_to_one_lock_file(self):
        real = self.workspace("alpha")
        spellings = ["alpha", str(real), str(real) + "/",
                     str(self.workspace_root / "alpha" / ".." / "alpha")]
        paths = {str(self.store.lock_path(value)[0]) for value in spellings}
        self.assertEqual(len(paths), 1,
                         f"{len(paths)} lock files for one workspace: {paths}")

    def test_a_workspace_cannot_be_a_symlink_or_a_subdirectory(self):
        real = self.workspace("alpha")
        alias = self.workspace_root / "alpha-alias"
        alias.symlink_to(real)
        nested = real / "inner"
        nested.mkdir()
        with self.assertRaises(sf.MissionError):
            sf.workspace("alpha-alias")
        with self.assertRaises(sf.MissionError):
            sf.workspace(str(nested))

    def test_the_workspace_column_is_not_settable_through_the_engine(self):
        mission = self.media_mission()
        self.workspace("beta")
        with self.assertRaises(sf.MissionError):
            self.store.update(mission["id"],
                              workspace=str(self.workspace_root / "beta"))


# --------------------------------------------------------------------------- #
# O2 -- starting a mission is exclusive
# --------------------------------------------------------------------------- #
class MissionStartIsExclusive(StageOHarness):
    def test_only_one_of_eight_racing_callers_moves_a_mission_to_running(self):
        """The layer UNDER the flock, and the one that still holds when two
        callers share no lock file: transition(expect=...) is a compare-and-swap
        inside BEGIN IMMEDIATE. Measured with eight processes and no execution
        lock at all: one winner, seven TransitionError.
        """
        mission = self.media_mission()
        mid = mission["id"]
        barrier = threading.Barrier(8)
        outcomes = []

        def contend():
            barrier.wait()
            try:
                self.store.transition(mid, "running", actor=sf.ACTOR_WORKER,
                                      expect="queued", detail="race")
                outcomes.append("won")
            except sf.TransitionError as exc:
                outcomes.append(f"refused: {exc}")

        threads = [threading.Thread(target=contend) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(60)
        self.assertEqual(outcomes.count("won"), 1, outcomes)
        self.assertEqual(len(outcomes), 8, outcomes)
        events = [row["event"] for row in self.event_rows(mid)]
        self.assertEqual(events.count("running"), 1,
                         "a refused start appended a state event anyway")
        self.assertTrue(self.store.verify_chain()["ok"])

    def test_the_cli_run_path_shares_the_workspace_lock(self):
        """Both entry points go through run_mission(), so a CLI run is refused
        by a worker's lock and leaves nothing behind."""
        mission = self.media_mission(title="refused by the lock")
        mid = mission["id"]
        before = (self.store.get(mid), self.store.events(mid),
                  self.store.verify_chain()["head"])
        with self.store.lock(workspace=mission["workspace"]):
            result = self.cli("--json", "run", mid, timeout=120)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        answer = json.loads(result.stdout or "{}")
        self.assertIn("Another mission is executing on", answer.get("error", ""))
        after = (self.store.get(mid), self.store.events(mid),
                 self.store.verify_chain()["head"])
        self.assertEqual(before, after, "the refusal was not inert")


# --------------------------------------------------------------------------- #
# O4 -- the audit chain
# --------------------------------------------------------------------------- #
class AuditChainUnderConcurrency(StageOHarness):
    def test_two_hundred_racing_appends_do_not_fork_the_chain(self):
        """A fork is two rows claiming one predecessor. Counted directly rather
        than read off verify()'s verdict, so the assertion is about the rows.
        Measured with 8 processes: 200 appends, 0 duplicate prev_hash,
        1.23 ms/append under contention.
        """
        writers, each = 8, 25
        barrier = threading.Barrier(writers)

        def append():
            barrier.wait()
            for index in range(each):
                self.store.append_event("mission-chainprobe", "stage-o-append",
                                        f"row {index}")

        threads = [threading.Thread(target=append) for _ in range(writers)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(300)
        rows = self.event_rows()
        mine = [r for r in rows if r["event"] == "stage-o-append"]
        self.assertEqual(len(mine), writers * each)
        self.assertEqual([r["seq"] for r in rows],
                         list(range(1, len(rows) + 1)),
                         "sequence numbers are not contiguous")
        prevs = [r["prev_hash"] for r in rows if r["prev_hash"]]
        self.assertEqual(len(prevs), len(set(prevs)),
                         "two rows share a prev_hash: the chain forked")
        report = self.store.verify_chain()
        self.assertTrue(report["ok"], report["problems"])
        self.assertEqual(report["unchained"], 0)

    def test_a_duplicated_prev_hash_is_reported_and_changes_the_exit_code(self):
        """The detector is what makes the zero above mean something. A count
        that can never be raised measures the query, not the chain."""
        for index in range(5):
            self.store.append_event("mission-chainprobe", "stage-o-row", str(index))
        self.assertTrue(self.store.verify_chain()["ok"])
        rows = self.event_rows()
        with self.store.db() as db:
            head = dict(db.execute(
                "SELECT * FROM events ORDER BY seq DESC LIMIT 1").fetchone())
        forged = dict(head)
        forged["seq"] = head["seq"] + 1
        forged["prev_hash"] = rows[-3]["prev_hash"]
        forged["event"] = "stage-o-forged"
        forged["detail"] = "a second row claiming an already-claimed predecessor"
        forged["hash"] = sf.event_hash(forged["prev_hash"], forged)
        with sqlite3.connect(self.db_path) as db:
            db.execute(
                "INSERT INTO events(seq,mission,at,event,detail,task_id,session_id,"
                "tool_execution_id,actor,prev_hash,hash,record_sha256) "
                "VALUES(:seq,:mission,:at,:event,:detail,:task_id,:session_id,"
                ":tool_execution_id,:actor,:prev_hash,:hash,:record_sha256)", forged)
        report = self.store.verify_chain()
        self.assertFalse(report["ok"])
        self.assertTrue(any("prev_hash does not match" in problem
                            for problem in report["problems"]), report["problems"])
        self.assertNotEqual(sf.audit_exit_code(report), sf.AUDIT_EXIT_OK)

    def test_two_concurrent_missions_share_one_interleaved_chain(self):
        """Not separated per caller, and deliberately so: a per-mission chain
        could be truncated one mission at a time. What has to hold is that the
        single chain survives being written by two callers at once."""
        self.workspace("alpha")
        self.workspace("beta")
        missions = [self.escalating_mission("alpha", "alpha work"),
                    self.escalating_mission("beta", "beta work")]
        for mission in missions:
            mission_approvals.approve(self.store, mission)
        barrier = threading.Barrier(len(missions))

        def run(mid):
            barrier.wait()
            with contextlib.suppress(Exception):
                sf.run_mission(self.store, mid)

        threads = [threading.Thread(target=run, args=(m["id"],)) for m in missions]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(300)
        rows = self.event_rows()
        ids = {m["id"] for m in missions}
        pair = [r for r in rows if r["mission"] in ids]
        switches = sum(1 for a, b in zip(pair, pair[1:])
                       if a["mission"] != b["mission"])
        genesis = [r for r in rows if r["event"] == sf.CHAIN_GENESIS]
        self.assertEqual(len(genesis), 1, "more than one chain genesis")
        self.assertGreater(switches, 0,
                           "the two missions did not interleave, so nothing about "
                           "concurrent appends was measured here")
        self.assertEqual([r["seq"] for r in rows], list(range(1, len(rows) + 1)))
        report = self.store.verify_chain()
        self.assertTrue(report["ok"], report["problems"])


# --------------------------------------------------------------------------- #
# O4 -- the first open of a database
# --------------------------------------------------------------------------- #
class FirstOpenRace(StageOHarness):
    """Store.__init__ creates the schema, migrates it and writes the chain
    genesis BEFORE any caller holds worker.lock or execution.lock. It is the one
    window in which two workers genuinely have no lock between them."""

    def race(self, root, callers=6):
        barrier = threading.Barrier(callers)
        errors = []

        def open_one():
            barrier.wait()
            try:
                Store(root)
            except BaseException as exc:                          # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=open_one) for _ in range(callers)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(120)
        return errors

    def test_racing_first_opens_leave_one_genesis_and_one_chain_id(self):
        """The INTEGRITY of the race, which does hold.

        A second genesis would give the database two chain ids; chain_id() takes
        the first, so every event mirrored to the journal under the other one
        would be unfindable and the external anchor would read degraded for the
        life of the installation.
        """
        for trial in range(4):
            root = Path(self.tmp.name) / f"race-{trial}"
            self.race(root)
            store = Store(root)
            with store.db() as db:
                genesis = db.execute(
                    "SELECT COUNT(*) FROM events WHERE event=?",
                    (sf.CHAIN_GENESIS,)).fetchone()[0]
                version = db.execute("PRAGMA user_version").fetchone()[0]
            with self.subTest(trial=trial):
                self.assertEqual(genesis, 1)
                self.assertEqual(version, sf.SCHEMA_VERSION)
                self.assertTrue(store.verify_chain()["ok"])
                self.assertIsNotNone(store.chain_id())

    def test_a_losing_first_open_is_serialized_rather_than_raising(self):
        """MEASURED AS A DEFECT, THEN FIXED. This asserts the fix.

        Store.db() ran `PRAGMA journal_mode=WAL` as its FIRST statement, before
        it set busy_timeout, and SQLite does not invoke the busy handler for a
        journal-mode conversion; Store.migrate() then ran its ALTER TABLEs
        outside any transaction, so two openers both saw a column missing and
        both added it. Measured: 4 of 6 concurrent processes raised, with
        'database is locked' and 'duplicate column name: provider_id'; through
        the CLI, 4 of 18 invocations produced an empty stdout and a traceback --
        to a desktop client that parses stdout as JSON.

        busy_timeout is set first now, the WAL conversion is retried inside a
        bounded deadline, and the migration holds BEGIN IMMEDIATE, so whoever
        loses the race waits and inherits the winner's work. This test was
        told, in its own previous docstring, what to become when that landed:
        assert that every caller now opens or is refused with a MissionError.
        """
        raised = []
        for trial in range(12):
            raised.extend(self.race(Path(self.tmp.name) / f"crash-{trial}"))
        # Not "no exception ever": a bounded wait can legitimately expire under
        # a load this test does not create. What must never happen again is a
        # BARE sqlite3.Error reaching a caller, because that is the one the CLI
        # could not report and the desktop could not parse.
        bare = [exc for exc in raised if isinstance(exc, sqlite3.Error)]
        self.assertEqual(bare, [],
                         "a raw SQLite error escaped a concurrent first open: "
                         + repr([str(exc) for exc in bare]))
        for exc in raised:
            self.assertIsInstance(exc, sf.MissionError, repr(exc))
            self.assertIn("busy", str(exc).lower())

    def test_the_cli_error_handler_does_not_cover_that_exception(self):
        """The half of the defect that turns a transient busy database into an
        operator-visible traceback.

        main() answers every refusal as JSON on stdout, and Mission Control's
        desktop client parses stdout as JSON. sqlite3.Error is not a
        MissionError, a ValueError or an OSError, so it escapes that handler
        entirely: empty stdout, a traceback on stderr, and a client with
        nothing to show.
        """
        self.assertFalse(issubclass(sqlite3.Error,
                                    (sf.MissionError, ValueError, OSError)),
                         "sqlite3.Error is now covered by the CLI's handler; "
                         "assert the JSON refusal it produces instead")


# --------------------------------------------------------------------------- #
# O5 -- approvals
# --------------------------------------------------------------------------- #
class ApprovalsUnderConcurrency(StageOHarness):
    def test_an_approval_does_not_cover_a_second_mission_with_the_same_scope(self):
        """Approvals are keyed by subject before any scope is compared, so two
        callers running two missions cannot share one human decision even when
        the decisions are byte-identical."""
        first = self.escalating_mission(title="approved")
        second = self.escalating_mission(title="not approved")
        first_decision, _ = sf.mission_decision(self.store, first)
        second_decision, _ = sf.mission_decision(self.store, second)
        self.assertEqual(first_decision.scope, second_decision.scope,
                         "the two scopes differ, so this proves nothing about "
                         "subject keying")
        mission_approvals.approve(self.store, first)
        with self.assertRaises(sf.ApprovalRequired) as caught:
            sf.require_approval(self.store, self.store.get(second["id"]))
        self.assertIn("no approval exists for mission:" + second["id"],
                      str(caught.exception))
        self.assertIsNone(self.store.get(second["id"])["approval_id"])

    def test_a_revoke_racing_the_check_never_produces_used_after_revoked(self):
        """RED ON ARRIVAL. Stage O found this, and it is not a logging quibble.

        require_approval() re-reads revoked_at under BEGIN IMMEDIATE -- the same
        write lock revoke_approval() takes -- and then RELEASES it. The
        'approval-used' append and the approval_id update happen afterwards, on
        two further connections. A revoke landing in that gap is chained BEFORE
        the use, the gate still returns the approval id, and run_mission() goes
        on to move the mission to running and execute it.

        The comment above that re-read says the opposite: "a revoke either lands
        before the mission starts or after it -- never in the window between the
        check and the start, which produced a log reading granted, revoked,
        used, in that order." That log is exactly what this produces.

        MEASURED (tools/probes/stage_o_multi_agent.py, probe
        O5-a-revoke-never-lands-between-the-check-and-the-use): 25 of 240 races
        against a separate revoking PROCESS inverted, and all 25 of those
        missions started -- they took a workspace checkpoint and began work on a
        withdrawn decision. Through require_approval() alone, 10 to 16 of 200.

        The sweep is 50 us steps, not a jitter across the whole call. The window
        is microseconds wide and a coarse spread walks straight over it: the
        first version of this race used 60 ms offsets, found nothing, and would
        have reported the invariant as holding.

        The invariant asserted here is the one the engine already claims, and
        the fix -- holding one BEGIN IMMEDIATE across the re-read, the
        'approval-used' append and the approval_id update -- makes it green
        deterministically. Do not relax it to match the current behaviour.
        """
        trials, step, points = 150, 0.00005, 120
        inverted, used, held = [], 0, 0
        for trial in range(trials):
            mission = self.escalating_mission(title=f"race {trial}")
            aid = mission_approvals.approve(self.store, mission)
            delay = (trial % points) * step
            revoked = []

            def revoke(pause=delay, approval=aid):
                time.sleep(pause)
                try:
                    self.store.revoke_approval(approval, reason="race")
                    revoked.append("revoked")
                except sf.MissionError as exc:
                    revoked.append(str(exc))

            thread = threading.Thread(target=revoke)
            thread.start()
            try:
                sf.require_approval(self.store, self.store.get(mission["id"]))
                used += 1
            except sf.ApprovalRequired:
                held += 1
            thread.join(60)
            self.assertEqual(revoked, ["revoked"], revoked)
            with self.store.db() as db:
                used_seq = db.execute(
                    "SELECT seq FROM events WHERE mission=? AND event='approval-used'"
                    " ORDER BY seq LIMIT 1", (mission["id"],)).fetchone()
                revoked_seq = db.execute(
                    "SELECT seq FROM events WHERE event='approval-revoked' AND "
                    "detail LIKE ? ORDER BY seq LIMIT 1", (f"%{aid}%",)).fetchone()
            if used_seq and revoked_seq and used_seq[0] > revoked_seq[0]:
                inverted.append({"trial": trial, "delay_ms": round(delay * 1000, 3),
                                 "revoked_seq": revoked_seq[0],
                                 "used_seq": used_seq[0],
                                 "approval_id": self.store.get(
                                     mission["id"])["approval_id"]})
        self.assertEqual(used + held, trials)
        self.assertTrue(self.store.verify_chain()["ok"])
        self.assertEqual(
            inverted, [],
            f"{len(inverted)} of {trials} races consumed an approval that had "
            f"already been revoked and chained. The log reads granted, revoked, "
            f"used, and the mission was allowed to start on a withdrawn "
            f"decision. First few: {json.dumps(inverted[:4], sort_keys=True)}")

    def test_the_approval_is_consulted_once_and_before_the_state_moves(self):
        mission = self.escalating_mission()
        mission_approvals.approve(self.store, mission)
        sf.require_approval(self.store, self.store.get(mission["id"]))
        self.store.transition(mission["id"], "running", actor=sf.ACTOR_WORKER,
                              expect="queued")
        events = [row["event"] for row in self.event_rows(mission["id"])]
        self.assertEqual(events.count("approval-used"), 1, events)
        self.assertLess(events.index("approval-used"), events.index("running"),
                        "the mission moved to running before the approval was used")

    def test_a_revoke_after_the_start_is_recorded_but_stops_nothing(self):
        """NOT ENFORCED, and this pins the honest version of it.

        There is no re-check and no kill switch. The withdrawal IS written to
        the mission's own event list, so a reader can see granted, used, ran,
        revoked in order -- but the mission's state does not move and nothing
        consults the approval again. cancel() is the live control; the sandbox
        class below measures that it actually stops a running process.
        """
        mission = self.escalating_mission()
        aid = mission_approvals.approve(self.store, mission)
        sf.require_approval(self.store, self.store.get(mission["id"]))
        self.store.transition(mission["id"], "running", actor=sf.ACTOR_WORKER,
                              expect="queued")
        self.store.revoke_approval(aid, reason="withdrawn mid-flight")
        row = self.store.get(mission["id"])
        events = [e["event"] for e in self.event_rows(mission["id"])]
        self.assertEqual(row["state"], "running",
                         "revocation moved a running mission; assert the new "
                         "behaviour and say what enforces it")
        self.assertEqual(events[-1], "approval-revoked")
        self.assertLess(events.index("approval-used"),
                        events.index("approval-revoked"))


# --------------------------------------------------------------------------- #
# O5/O3 -- undo cannot cross a workspace
# --------------------------------------------------------------------------- #
class UndoCannotCrossWorkspaces(StageOHarness):
    def setUp(self):
        super().setUp()
        self.alpha = self.workspace("alpha")
        self.beta = self.workspace("beta")

    def finished_mission(self, workspace, title):
        """A mission with a real checkpoint and a real recorded after-index.

        It fails on the provider, which is what makes it fast and sandbox-free;
        review() accepts a failed mission for undo, and the checkpoint and index
        are written either way.
        """
        mission = self.escalating_mission(workspace, title)
        mission_approvals.approve(self.store, mission)
        with contextlib.suppress(Exception):
            sf.run_mission(self.store, mission["id"])
        row = self.store.get(mission["id"])
        self.assertTrue(row["checkpoint"], "the fixture took no checkpoint")
        self.assertTrue((self.store.directory(row["id"]) / "after-index.json").exists())
        return row

    @staticmethod
    def tree(root):
        return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in sorted(Path(root).rglob("*")) if p.is_file()}

    def redirect(self, mid, target):
        with sqlite3.connect(self.db_path) as db:
            db.execute("UPDATE missions SET workspace=? WHERE id=?",
                       (str(target), mid))
        try:
            sf.review(self.store, mid, "undo")
            return None
        except sf.MissionError as exc:
            return str(exc)

    def test_a_repointed_mission_cannot_undo_into_a_written_workspace(self):
        older = self.finished_mission("alpha", "older")
        self.finished_mission("beta", "newer")
        before = self.tree(self.beta)
        refusal = self.redirect(older["id"], self.beta)
        self.assertIsNotNone(refusal, "an undo landed in another workspace")
        self.assertEqual(before, self.tree(self.beta))

    def test_a_repointed_mission_cannot_undo_into_an_untouched_workspace(self):
        self.finished_mission("alpha", "older")
        newest = self.finished_mission("beta", "newer")
        before = self.tree(self.alpha)
        refusal = self.redirect(newest["id"], self.alpha)
        self.assertIsNotNone(refusal, "an undo landed in another workspace")
        self.assertEqual(before, self.tree(self.alpha))

    def test_a_byte_identical_clone_does_not_make_the_checkpoint_addressable(self):
        """The sharpest version. The recorded after-index is satisfied by
        construction, so what is left is the checkpoint engine's own namespace:
        a recovery id lives under <workspace root>/.sf-checkpoints/<name>/ and
        is not addressable from anywhere else."""
        newest = self.finished_mission("beta", "newer")
        gamma = self.workspace_root / "gamma"
        shutil.copytree(self.beta, gamma)
        recorded = json.loads(
            (self.store.directory(newest["id"]) / "after-index.json").read_text())
        self.assertEqual(recorded, sf.recovery_index(gamma),
                         "the clone is not identical, so the index check would "
                         "refuse this for the wrong reason")
        before = self.tree(gamma)
        refusal = self.redirect(newest["id"], gamma)
        self.assertIsNotNone(refusal, "an undo landed in a cloned workspace")
        self.assertIn("checkpoint", refusal.lower())
        self.assertEqual(before, self.tree(gamma))

    def test_a_checkpoint_id_is_not_addressable_from_another_workspace(self):
        first = sf.checkpoint_call("snapshot", self.alpha, label="stage-o-alpha")
        second = sf.checkpoint_call("snapshot", self.beta, label="stage-o-beta")
        self.assertNotEqual(first["id"], second["id"])
        with self.assertRaises(sf.MissionError):
            sf.checkpoint_call("diff", self.beta, checkpoint=first["id"])


# --------------------------------------------------------------------------- #
# O6 -- credential identities
# --------------------------------------------------------------------------- #
class CredentialIdentitiesInOneProcess(StageOHarness):
    ANTHROPIC = "sk-ant-stage-o-not-a-real-key-0000"
    CODEX = "sk-codex-stage-o-not-a-real-key-1111"

    def setUp(self):
        super().setUp()
        for name, value in (("ANTHROPIC_API_KEY", self.ANTHROPIC),
                            ("CODEX_API_KEY", self.CODEX)):
            os.environ[name] = value
        self.workspace("proj")

    def resolved_for(self, provider_id):
        mission = self.store.create(kind="report", provider_id=provider_id,
                                    workspace_value="proj", title=provider_id,
                                    prompt="p", inputs=["facts.md"])
        executor = sf.Executor(self.store, mission)
        provider = sf.provider_for("sourced_report", provider_id)
        return provider, executor.credentials_for(provider)

    def test_each_provider_resolves_only_the_identity_it_declared(self):
        """One process holds every declared identity at once, because
        load_provider_credentials() reads the whole credential directory into
        os.environ. The separation is per INVOCATION, not per process."""
        for provider_id, expected in (("codex", "CODEX_API_KEY"),
                                      ("claude", "ANTHROPIC_API_KEY")):
            with self.subTest(provider=provider_id):
                provider, resolved = self.resolved_for(provider_id)
                self.assertEqual(sorted(resolved), [expected])
                self.assertEqual(resolved[expected], os.environ[expected])
                self.assertEqual(sorted(provider.manifest["credential_ids"]),
                                 [expected])

    def test_a_variable_no_provider_declared_is_never_resolved(self):
        os.environ["GITHUB_TOKEN"] = "stage-o-undeclared"
        for provider_id in ("codex", "claude"):
            with self.subTest(provider=provider_id):
                _provider, resolved = self.resolved_for(provider_id)
                self.assertNotIn("GITHUB_TOKEN", resolved)


# --------------------------------------------------------------------------- #
# What needs a real sandbox
# --------------------------------------------------------------------------- #
@unittest.skipUnless(sandbox_available(),
                     "a real Firebreak session needs bubblewrap, systemd-run, a "
                     "user manager and ffmpeg on this host")
class ConcurrentSandboxes(StageOHarness):
    def clip(self, name, seconds=6):
        path = self.workspace(name)
        target = path / "clip.mp4"
        result = subprocess.run(
            [FFMPEG, "-nostdin", "-v", "error", "-y",
             "-f", "lavfi", "-i", f"testsrc=size=320x240:rate=10:duration={seconds}",
             "-f", "lavfi", "-i", f"sine=frequency=440:duration={seconds}",
             "-c:v", "libx264", "-preset", "ultrafast", "-c:a", "aac",
             "-shortest", str(target)],
            capture_output=True, text=True, timeout=300,
            env={"PATH": TRUSTED_PATH, "HOME": os.environ.get("HOME", "/tmp")})
        self.assertEqual(result.returncode, 0, result.stderr[-400:])
        return path

    def test_two_concurrent_missions_get_disjoint_sessions_and_scopes(self):
        """Separation here is structural, not a consequence of the worker being
        single-threaded: the session id is minted per invocation, the systemd
        scope is named after it, and the bind mount is the mission's own
        workspace. Measured with two processes: 6 sessions, 6 scope units, no
        session attributed to the wrong workspace."""
        self.clip("alpha")
        self.clip("beta")
        missions = [
            self.store.create(capability="media_export", workspace_value=name,
                              title=name, prompt="export", inputs=["clip.mp4"])
            for name in ("alpha", "beta")]
        barrier = threading.Barrier(len(missions))

        def run(mid):
            barrier.wait()
            with contextlib.suppress(Exception):
                sf.run_mission(self.store, mid)

        threads = [threading.Thread(target=run, args=(m["id"],)) for m in missions]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(900)

        rows = {m["id"]: self.store.sessions(m["id"]) for m in missions}
        for mid, sessions in rows.items():
            with self.subTest(mission=mid):
                self.assertGreaterEqual(len(sessions), 1,
                                        "a mission opened no session at all")
        every = [s["id"] for sessions in rows.values() for s in sessions]
        self.assertEqual(len(every), len(set(every)), "a session id was reused")

        started = {}
        state = Path(os.environ["SHADOWFETCH_FIREBREAK_STATE"])
        for path in state.glob("*.session"):
            for line in path.read_text().splitlines():
                entry = json.loads(line)
                if entry.get("record") == "started":
                    started[entry["session"]] = entry
        scopes = {entry["scope_unit"] for entry in started.values()}
        self.assertEqual(len(scopes), len(started),
                         "two sandboxes shared a systemd scope, so they shared a "
                         "memory and task budget")
        for mid, sessions in rows.items():
            workspace = self.store.get(mid)["workspace"]
            for session in sessions:
                entry = started.get(session["id"])
                if entry is not None:
                    with self.subTest(session=session["id"]):
                        self.assertEqual(entry["workspace"], workspace)
                        self.assertEqual(entry["mission"], mid)

        checkpoints = {self.store.get(m["id"])["checkpoint"] for m in missions}
        self.assertEqual(len(checkpoints), len(missions),
                         "two concurrent missions shared a recovery point")
        self.assertTrue(self.store.verify_chain()["ok"])

    def test_a_granted_identity_does_not_reach_another_sandbox(self):
        """bwrap --clearenv, then one --setenv per granted identity: the sandbox
        does not inherit the orchestrator's environment and then have things
        removed from it."""
        self.workspace("alpha")
        env = dict(os.environ)
        env["ANTHROPIC_API_KEY"] = "sk-ant-stage-o-not-a-real-key-0000"
        env["CODEX_API_KEY"] = "sk-codex-stage-o-not-a-real-key-1111"
        payload = ("import os,json;"
                   "print(json.dumps(sorted(k for k in os.environ "
                   "if k.endswith('_API_KEY'))))")
        for granted in ("ANTHROPIC_API_KEY", "CODEX_API_KEY"):
            with self.subTest(granted=granted):
                result = subprocess.run(
                    [str(FIREBREAK_BIN), "run", "--workspace", "alpha",
                     "--net", "none", "--no-checkpoint",
                     "--credential-env", granted, "--",
                     "/usr/bin/python3", "-c", payload],
                    capture_output=True, text=True, timeout=300, env=env)
                self.assertEqual(result.returncode, 0, result.stderr[-400:])
                visible = [json.loads(line) for line in result.stdout.splitlines()
                           if line.startswith("[")]
                self.assertEqual(visible[-1] if visible else None, [granted],
                                 result.stdout)

    def test_an_undeclared_identity_cannot_be_granted(self):
        self.workspace("alpha")
        env = dict(os.environ)
        env["STAGE_O_SECRET"] = "not-a-declared-identity"
        refused = subprocess.run(
            [str(FIREBREAK_BIN), "run", "--workspace", "alpha", "--net", "none",
             "--no-checkpoint", "--credential-env", "STAGE_O_SECRET", "--",
             "/usr/bin/true"],
            capture_output=True, text=True, timeout=300, env=env)
        self.assertNotEqual(refused.returncode, 0, refused.stdout)
        leaked = subprocess.run(
            [str(FIREBREAK_BIN), "run", "--workspace", "alpha", "--net", "none",
             "--no-checkpoint", "--", "/usr/bin/python3", "-c",
             "import os;print('STAGE_O_SECRET' in os.environ)"],
            capture_output=True, text=True, timeout=300, env=env)
        self.assertEqual(leaked.returncode, 0, leaked.stderr[-400:])
        self.assertIn("False", leaked.stdout)
        self.assertNotIn("True", leaked.stdout)

    def test_cancellation_stops_a_running_mission(self):
        """The live control revocation is not. cancel() sets a flag that
        Executor.check() reads between steps and every 200 ms inside the process
        read loop. Measured: the runner returned 0.48s after cancel()."""
        self.clip("alpha", seconds=30)
        mission = self.store.create(capability="media_export",
                                    workspace_value="alpha", title="cancel me",
                                    prompt="export", inputs=["clip.mp4"])
        mid = mission["id"]
        finished = threading.Event()
        outcome = {}

        def run():
            try:
                outcome["result"] = sf.run_mission(self.store, mid)
            except BaseException as exc:                          # noqa: BLE001
                outcome["error"] = f"{type(exc).__name__}: {exc}"
            finished.set()

        thread = threading.Thread(target=run)
        thread.start()
        deadline = time.time() + 120
        while time.time() < deadline and not self.store.sessions(mid):
            time.sleep(0.02)
        self.assertTrue(self.store.sessions(mid),
                        "the mission never opened a sandbox, so there was nothing "
                        "live to cancel")
        requested = time.monotonic()
        self.store.cancel(mid)
        self.assertTrue(finished.wait(120), "the cancelled mission never returned")
        thread.join(60)
        stopped_after = time.monotonic() - requested
        self.assertEqual(self.store.get(mid)["state"], "cancelled",
                         outcome)
        self.assertLess(stopped_after, 30,
                        f"cancellation took {stopped_after:.1f}s; it is polled "
                        "between steps and inside the read loop, so a long delay "
                        "means the poll moved")


if __name__ == "__main__":
    unittest.main()
