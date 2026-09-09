#!/usr/bin/env python3
"""Attacks 7-11: the mission state machine and the event hash chain.

Re-runnable on purpose. The engine is still moving, so a one-off transcript
would be stale within the hour; this module re-derives every observation from
the tree it is run against and reports what it actually saw.

WHAT IS BEING ATTACKED
  7.  Force an invalid Mission state jump.
  8.  Corrupt an Event row.
  9.  Truncate the Event chain.
  10. Delete the last Event.
  11. Forge a Firebreak session ID.

The threat model for 8-10 is the one the chain already assumes and states: an
attacker who can write the SQLite file. That is the mission worker's own uid, so
it is not a hypothetical -- it is the uid the whole tamper-EVIDENCE design
exists for. Nothing here needs root.

PASS means the system refused the attack or contained it: it either stopped the
change, or it declined to claim anything the evidence did not support. An attack
the system cannot stop is a FINDING, not a failed attack, and the note says so
in the plainest words available.

WHY THE NOTES ARE ASSEMBLED RATHER THAN WRITTEN
  Every NOTE here used to be one hard-coded string. The observations underneath
  them were re-derived every run; the prose above them was not, so as Phase 3.1
  fixed defect after defect the notes went on describing behaviour the engine no
  longer had -- four of them contradicted, word for word, the OBSERVED block
  printed immediately above them, and every attack still said PASS. A note that
  can silently go stale is the same defect class as an enforcement table that
  can: a claim with nothing checking it.

  So a NOTE is now built by Note(): each clause carries the live value that makes
  it true, and a clause whose value does not hold is not printed as prose. It is
  printed as NO LONGER TRUE and it FAILS the attack. Note.either() is for the
  forks where both outcomes are worth describing -- it cannot go stale, because
  it reads the run and picks. Note.always() is for the few sentences that are
  about the design rather than about this run.

WHAT EACH ATTACK CHECKS AFTER A REFUSAL
  Not "it raised". Every refusal is followed by reading the mission row back
  column by column, counting the events, and re-verifying the chain head, because
  a guard that raises after writing is the defect this phase keeps finding.

SIDE EFFECTS
  Every attack runs against a throwaway store under a fresh tempfile.mkdtemp();
  the operator's ~/.local/state is never opened, and throwaway() asserts that
  before any attack touches a database. The one thing that does leave this
  process is the journald mirror: appending an event mirrors its head to the
  system journal, which is the anchor under test and cannot be faked away. Each
  throwaway store mints its own chain id, so those lines cannot be confused with
  the operator's chain -- read_head() filters by chain id.

HOW TO RUN IT
      python3 tools/attacks/attack_integrity.py      # table, exit 1 on any FAIL
  or  from attack_integrity import ATTACKS, run      # composed with the others
  `make attacks` runs it alongside the other three suites, and `make test` ends
  with `$(MAKE) attacks`, so it is in the gate. It was not when this module was
  written -- the docstring said so and said what the missing line was; that line
  now exists, which is why this paragraph reads differently from the one in the
  Phase 3 transcripts.
"""
from __future__ import annotations

import contextlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import textwrap
import uuid
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
MISSIONS_SRC = REPO / "packages/shadowfetch-missions/data/usr/lib/shadowfetch/missions"
MCP_SRC = REPO / "packages/shadowfetch-fireline/data/usr/lib/shadowfetch/mcp"
MISSIONS_CLI = REPO / "packages/shadowfetch-missions/data/usr/bin/shadowfetch-missions"

for _path in (MISSIONS_SRC, MCP_SRC):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

import sf_audit                      # noqa: E402
import sf_missions as sf             # noqa: E402
import sf_mcp                        # noqa: E402


# --------------------------------------------------------------------------- #
# Throwaway state
# --------------------------------------------------------------------------- #
@contextlib.contextmanager
def throwaway():
    """A store, a workspace root, a Firebreak state dir and an MCP audit dir
    that exist only for one attack.

    All four are overridden together. Overriding only the store leaves the MCP
    server writing its audit chain into the operator's real state tree, which a
    previous round did a hundred times.
    """
    base = Path(tempfile.mkdtemp(prefix="sf-attack-integrity-"))
    saved = dict(os.environ)
    try:
        (base / "ws" / "probe").mkdir(parents=True)
        (base / "ws" / "probe" / "a.mkv").write_bytes(b"clip")
        os.environ.update({
            "SHADOWFETCH_AGENT_WORKSPACES": str(base / "ws"),
            "SHADOWFETCH_MISSIONS_STATE": str(base / "state"),
            "SHADOWFETCH_FIREBREAK_STATE": str(base / "fb"),
            "SHADOWFETCH_MCP_STATE": str(base / "mcp"),
        })
        yield base
    finally:
        os.environ.clear()
        os.environ.update(saved)
        shutil.rmtree(base, ignore_errors=True)


def new_store(base):
    store = sf.Store()
    # Mechanical, not a comment: if a refactor ever makes Store ignore the
    # environment variable, this stops the module before it writes into the
    # operator's audit log rather than after.
    assert base in store.root.parents or store.root == base / "state", (
        f"refusing to attack a store outside the throwaway directory: {store.root}")
    return store


def new_mission(store):
    """A real queued mission. Returns (mission_id, how_it_was_created)."""
    try:
        mission = store.create(capability="media_export", provider_id="offline-media",
                               workspace_value="probe", title="attack", prompt="attack",
                               inputs=["a.mkv"])
        return mission["id"], "store.create()"
    except Exception as exc:                                       # noqa: BLE001
        # A host with no provider manifests must still be able to attack the
        # state machine, so the row is inserted the way create() would and the
        # creation edge's event is appended through the engine.
        mid = "mission-" + uuid.uuid4().hex[:16]
        stamp = sf.now()
        raw_sql(store.db_path,
                "INSERT INTO missions(id,title,kind,capability,provider_id,state,"
                "workspace,prompt,config,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (mid, "attack", "media", "media_export", "offline-media",
                 sf.MissionState.QUEUED, str(Path(os.environ["SHADOWFETCH_AGENT_WORKSPACES"]) / "probe"),
                 "attack", json.dumps({"runtime": "offline", "inputs": ["a.mkv"]}),
                 stamp, stamp))
        store.event(mid, sf.MISSION_TRANSITIONS[(None, sf.MissionState.QUEUED)][0],
                    "created by the attack module", actor=sf.ACTOR_USER)
        return mid, f"raw INSERT (store.create() refused: {type(exc).__name__}: {exc})"


# --------------------------------------------------------------------------- #
# Reading the store the way an attacker and an auditor both do
# --------------------------------------------------------------------------- #
def raw_sql(db_path, statement, params=()):
    """One statement against the database file, outside the engine entirely."""
    db = sqlite3.connect(db_path)
    try:
        cursor = db.execute(statement, params)
        db.commit()
        return cursor.rowcount
    finally:
        db.close()


def rows(db_path, query, params=()):
    db = sqlite3.connect(db_path)
    db.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in db.execute(query, params)]
    finally:
        db.close()


def columns(db_path, table):
    return [r["name"] for r in rows(db_path, f"PRAGMA table_info({table})")]


def fingerprint(store, mid=None):
    """Everything a refusal must leave untouched, in one comparable value."""
    events = rows(store.db_path, "SELECT seq,mission,at,event,detail,task_id,"
                                 "session_id,tool_execution_id,actor,prev_hash,hash "
                                 "FROM events ORDER BY seq")
    head = events[-1] if events else {}
    mission = rows(store.db_path, "SELECT * FROM missions WHERE id=?", (mid,)) if mid else []
    return {
        "mission_row": mission[0] if mission else None,
        "events": len(events),
        "head_seq": head.get("seq"),
        "head_hash": head.get("hash"),
        "mirror_state": store.mirror_state(),
    }


ANCHOR_BLINDED = False


def _cli_argv(args):
    """The command that runs the CLI, blinded if blind_anchor() is active.

    A subprocess resolves the real absolute journalctl, so an in-process patch
    of JOURNALCTL_PATHS never reached it and the child reported the anchor as
    readable. This carries the same patch into the child. Deliberately NOT an
    environment variable the engine honours: that would hand an attacker back
    the control that resolving by absolute path just removed.
    """
    if not ANCHOR_BLINDED:
        return [sys.executable, str(MISSIONS_CLI), *args]
    engine = str(Path(MISSIONS_CLI).resolve().parent.parent / "lib/shadowfetch/missions")
    code = ("import sys; sys.path.insert(0, %r);"
            "import sf_audit; sf_audit.JOURNALCTL_PATHS = ();"
            "import sf_missions; sys.exit(sf_missions.main())" % engine)
    return [sys.executable, "-c", code, *args]


def cli(*args):
    """Run the real CLI against the throwaway store. (exit, stdout, stderr)."""
    done = subprocess.run(_cli_argv(args),
                          capture_output=True, text=True, timeout=120,
                          env=dict(os.environ))
    return done.returncode, done.stdout, done.stderr


@contextlib.contextmanager
def blind_anchor():
    """Make the external anchor genuinely unreadable, without mocking it.

    PATH is emptied of journalctl, which is the real condition sf_audit already
    names ("journalctl is not installed, so the external anchor cannot be
    read") -- a container image, a minimal install. Patching read_head() would
    prove that the code branches; removing the binary proves that the branch is
    the one a host without a journal actually takes.
    """
    saved_path = os.environ.get("PATH", "")
    saved_paths = sf_audit.JOURNALCTL_PATHS
    empty = tempfile.mkdtemp(prefix="sf-attack-nopath-")
    # Emptying PATH is no longer enough, and that is deliberate: sf_audit
    # resolves journalctl by ABSOLUTE path, because a uid that controls PATH
    # controlled what the verifier believed the journal said. Point the absolute
    # candidates at a directory with no journalctl in it instead -- the real
    # lookup still runs and finds nothing, which is the branch a host without a
    # journal genuinely takes.
    global ANCHOR_BLINDED
    os.environ["PATH"] = empty
    sf_audit.JOURNALCTL_PATHS = (os.path.join(empty, "journalctl"),)
    ANCHOR_BLINDED = True
    try:
        yield
    finally:
        ANCHOR_BLINDED = False
        os.environ["PATH"] = saved_path
        sf_audit.JOURNALCTL_PATHS = saved_paths
        shutil.rmtree(empty, ignore_errors=True)


def journal_entries(chain):
    """Every mirrored head this uid can read for one chain, seq -> hash."""
    done = subprocess.run(["journalctl", "-t", sf_audit.AUDIT_IDENTIFIER, "-o", "cat",
                           "--no-pager", "-n", "5000"],
                          capture_output=True, text=True, timeout=60)
    found = {}
    for line in done.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if isinstance(entry, dict) and entry.get("chain") == chain:
            found[entry.get("seq")] = entry.get("hash")
    return found


def anchor_is_readable(store):
    return sf_audit.read_head(store.chain_id())["available"]


INCONCLUSIVE = ("INCONCLUSIVE: this host's journal is not readable by this uid, so "
                "the control under test never ran. Reported as not-passed because an "
                "unexercised control is not a passing one.")


def lines(*parts):
    return "\n".join(str(p) for p in parts if p is not None)


# --------------------------------------------------------------------------- #
# Notes that cannot outlive the behaviour they describe
# --------------------------------------------------------------------------- #
class Note:
    """A NOTE assembled from clauses, each checked against THIS run.

    The defect this exists for: `state-jump-forged-row` carried the sentence
    "nothing replays MISSION_TRANSITIONS ... Not prevented, not detected" for as
    long as it took Phase 3.1 to add verify_states(), and the OBSERVED block
    directly above it printed the detection. The attack still said PASS, because
    `passed` was computed from the engine and the note was a string literal.

    Three verbs, and the difference between them is the whole point:

      says(holds, text)     an assertion about this run. Printed when `holds`;
                            when it does not, the clause is reported as NO
                            LONGER TRUE and ok() goes false, which fails the
                            attack. Use it for anything a future fix could
                            falsify.
      either(cond, a, b)    a fork where both sides are worth describing. It
                            reads the run and picks, so it cannot go stale.
      always(text)          a sentence about the DESIGN, not about this run --
                            a threat model, a scope statement, a reference.
                            Nothing checks these, so keep them free of claims.

    A clause is a sentence, not a paragraph: the smaller the unit, the more
    precisely a change is reported.
    """

    STALE_HEADER = (
        "STALE NOTE -- this attack FAILS on that alone. The module carried "
        "claim(s) about the engine that this run contradicts. They are printed "
        "here instead of as prose because a note describing behaviour the "
        "system no longer has is exactly the defect this suite hunts:")

    def __init__(self):
        self._parts = []
        self._stale = []

    def says(self, holds, text):
        (self._parts if holds else self._stale).append(text)
        return self

    def either(self, cond, when_true, when_false):
        self._parts.append(when_true if cond else when_false)
        return self

    def always(self, text):
        self._parts.append(text)
        return self

    def ok(self):
        return not self._stale

    def text(self):
        body = " ".join(part.strip() for part in self._parts if part)
        if not self._stale:
            return body
        return lines(self.STALE_HEADER,
                     *("  NO LONGER TRUE: " + s for s in self._stale),
                     ("What this run actually saw: " + body) if body else None)

    def __str__(self):
        return self.text()


def _note_self_check():
    """The staleness guard needs a guard of its own, or it is one more claim.

    At import, so it holds however this module is reached -- `make attacks`, a
    person, or another suite importing ATTACKS -- rather than only on the path
    that happens to call main().
    """
    fresh = Note().says(True, "held").either(False, "no", "yes").always("design")
    assert fresh.ok(), "a Note whose clauses all hold must not report stale"
    assert fresh.text() == "held yes design", fresh.text()
    gone = Note().says(False, "the engine still does X").always("design")
    assert not gone.ok(), "a Note with a clause that no longer holds must fail"
    assert "NO LONGER TRUE: the engine still does X" in gone.text()
    assert "design" in gone.text(), "the surviving clauses are still shown"


_note_self_check()


def rechain(db_path, edits=None):
    """Recompute prev_hash/hash for every chained row, applying `edits` first.

    This is the attacker's tool, written the way an attacker would write it:
    straight out of the engine's own event_hash(), because the algorithm is in
    the shipped source and there is nothing secret in it.
    """
    edits = edits or {}
    db = sqlite3.connect(db_path)
    db.row_factory = sqlite3.Row
    try:
        prev = None
        for row in [dict(r) for r in db.execute("SELECT * FROM events ORDER BY seq")]:
            row.update(edits.get(row["seq"], {}))
            previous = sf.GENESIS_PREV if prev is None else prev
            row["prev_hash"] = previous
            row["hash"] = sf.event_hash(previous, row)
            db.execute("UPDATE events SET mission=?,at=?,event=?,detail=?,"
                       "prev_hash=?,hash=? WHERE seq=?",
                       (row["mission"], row["at"], row["event"], row["detail"],
                        row["prev_hash"], row["hash"], row["seq"]))
            prev = row["hash"]
        db.commit()
    finally:
        db.close()


# --------------------------------------------------------------------------- #
# 7. Force an invalid Mission state jump
# --------------------------------------------------------------------------- #
def state_jump_forged_row():
    """Write the state straight into SQLite, then ask the engine to act on it."""
    with throwaway() as base:
        store = new_store(base)
        mid, how = new_mission(store)
        raw_sql(store.db_path, "UPDATE missions SET state=? WHERE id=?", ("completed", mid))
        forged = store.get(mid)["state"]
        try:
            after = store.transition(mid, sf.MissionState.UNDONE)["state"]
            refused = None
        except Exception as exc:                                   # noqa: BLE001
            after, refused = store.get(mid)["state"], f"{type(exc).__name__}: {exc}"
        trail = [(e["event"], e["detail"][:64]) for e in store.events(mid)]
        report = store.verify_chain()
        exit_code, stdout, _ = cli("audit", "verify")
        verdict_line = next((l for l in stdout.splitlines() if l.startswith("chain")), "")
        states_line = next((l for l in stdout.splitlines()
                            if l.startswith("mission states")), "")

        states = report.get("states") or {}
        classification = (states.get("classes") or {}).get(mid)
        observed = lines(
            f"mission created by {how}, state {'queued'!r}",
            f"after UPDATE missions SET state='completed': store.get()['state'] == {forged!r}",
            f"store.transition(mid, 'undone') -> {refused or 'accepted, state is now ' + repr(after)}",
            f"event trail: {trail}",
            f"store.verify_chain(): ok={report['ok']} chain_ok={report.get('chain_ok')} "
            f"anchor={report['anchor']['verdict']!r}",
            f"  states verdict={states.get('verdict')!r}; this mission is classified "
            f"{classification!r}",
            f"  problems={report['problems']}",
            f"`audit verify` exit {exit_code}; {verdict_line.strip()!r}; "
            f"{states_line.strip()!r}")

        detected = (not report["ok"]) and states.get("verdict") == "disagrees"
        note = Note()
        note.says(forged == "completed",
                  "The WRITE is not prevented and cannot be: the missions table carries no "
                  "hash and sits in a database this uid owns, so the UPDATE lands and the "
                  "engine reads the forged state back as the mission's own.")
        note.either(refused is None,
                    "The engine then ACTS on it -- transition(mid, 'undone') is accepted, "
                    "and the event it writes carries the transition table's reason for the "
                    "completed -> undone edge, a sentence chosen from a state the mission "
                    "never reached.",
                    f"The engine refused to act on it: {refused}.")
        note.says(report.get("chain_ok"),
                  "The chain itself stays silent, correctly: no EVENT was altered, and "
                  "reporting one would be the chain claiming something outside its own "
                  "evidence.")
        note.says(detected,
                  "It is DETECTED all the same. verify_states() replays every mission's "
                  "event trail through MISSION_TRANSITIONS, and the replay is part of the "
                  f"same report: this mission is classified {classification!r}, the CLI "
                  f"prints {states_line.strip()!r} beside 'chain intact', and the exit "
                  f"status is {exit_code}.")
        note.says(exit_code == 1,
                  "Exit 1 is the tampered code, not the unverified one, so a caller that "
                  "gates on the exit status sees a finding rather than a caveat.")
        note.always(
            "Scope, stated plainly: this is detection at verify time, not prevention at "
            "write time, and it does not recover the state the mission actually had. "
            "Historical note: through Phase 3 nothing replayed the trail, so this attack "
            "was a FINDING -- 'not prevented, not detected' -- and verify reported a clean "
            "log over a mission that had never run.")
        passed = (refused is not None or not report["ok"]) and note.ok()
        return ("A mission state that no event records is not a state the engine reached: "
                "either the engine refuses to act on it, or verification reports the "
                "mismatch between the row and its event trail.",
                observed, passed, note.text())


def state_jump_illegal_target():
    """Targets that look like states, and one that is not hashable at all."""
    with throwaway() as base:
        store = new_store(base)
        mid, _ = new_mission(store)
        before = fingerprint(store, mid)
        attempts, changed_by = [], []

        candidates = [
            ("Queued", "capitalised"),
            ("running ", "trailing space"),
            ("waiting_review", "underscore for hyphen"),
            ("undone\n", "trailing newline"),
            (None, "no target at all"),
            (0, "an integer"),
            (["running"], "an unhashable target"),
            ("running'; DROP TABLE events;--", "SQL in the target"),
        ]
        for target, why in candidates:
            try:
                store.transition(mid, target)
                outcome = "ACCEPTED"
            except Exception as exc:                               # noqa: BLE001
                outcome = f"{type(exc).__name__}: {str(exc)[:96]}"
            attempts.append(f"  transition(mid, {target!r})  [{why}] -> {outcome}")
            if fingerprint(store, mid) != before:
                changed_by.append(f"transition(mid, {target!r})")

        # The two seams a caller reaches for when the target is refused.
        try:
            store.update(mid, state="running")
            attempts.append("  update(mid, state='running') -> ACCEPTED")
        except Exception as exc:                                   # noqa: BLE001
            attempts.append(f"  update(mid, state='running') -> {type(exc).__name__}: {str(exc)[:96]}")
        if fingerprint(store, mid) != before:
            changed_by.append("update(mid, state=...)")

        # NULL would make transition_allowed() see the (None -> queued) creation
        # edge, which is the one edge with no predecessor.
        try:
            raw_sql(store.db_path, "UPDATE missions SET state=NULL WHERE id=?", (mid,))
            attempts.append("  UPDATE missions SET state=NULL -> ACCEPTED BY SQLITE")
        except Exception as exc:                                   # noqa: BLE001
            attempts.append(f"  UPDATE missions SET state=NULL -> {type(exc).__name__}: {str(exc)[:96]}")
        after = fingerprint(store, mid)
        if after != before:
            changed_by.append("UPDATE missions SET state=NULL")

        report = store.verify_chain()
        tables = {r["name"] for r in rows(store.db_path,
                                          "SELECT name FROM sqlite_master WHERE type='table'")}
        observed = lines(
            *attempts,
            f"missions row after all of the above is byte-identical: {after['mission_row'] == before['mission_row']}",
            f"events {before['events']} -> {after['events']}; "
            f"head seq {before['head_seq']} -> {after['head_seq']}; "
            f"head hash {str(before['head_hash'])[:16]} -> {str(after['head_hash'])[:16]}",
            f"'events' table still exists after the SQL-shaped target: {'events' in tables}",
            f"verify_chain(): ok={report['ok']} problems={report['problems']}")
        unhashable = any("TypeError" in a and "unhashable" in a for a in attempts)
        note = Note()
        note.either(not changed_by,
                    "The near-miss spellings are refused by name, and the refusal text "
                    "names the reachable states rather than saying 'invalid' -- a person "
                    "can act on the first and not on the second.",
                    "FINDING: something on that list changed the row: "
                    + ", ".join(changed_by))
        note.says(after["mission_row"] == before["mission_row"],
                  "The mission row is byte-identical afterwards, which is the check that "
                  "matters: a guard that raises after writing is the defect this phase "
                  "keeps finding.")
        note.says(report["ok"],
                  "The chain is unchanged too -- no refusal appended an event describing a "
                  "change that did not happen.")
        note.says(unhashable,
                  "Worth the lead's eye: an unhashable target (a list) raises TypeError "
                  "from inside transition_allowed()'s dict lookup rather than "
                  "TransitionError. It is raised inside the BEGIN IMMEDIATE block, so the "
                  "transaction rolls back and nothing is written, but a caller catching "
                  "TransitionError will not catch it. That is an exception-class wart, not "
                  "a state change.")
        passed = (not changed_by) and report["ok"] and note.ok()
        return ("Every one of these is refused, and the mission row, the event count and "
                "the chain head are unchanged afterwards.",
                observed, passed, note.text())


def state_jump_retry_budget():
    """A legal-looking edge that should not compose: retry past the budget."""
    with throwaway() as base:
        store = new_store(base)
        mid, _ = new_mission(store)
        store.transition(mid, sf.MissionState.RUNNING, attempt=3)
        store.transition(mid, sf.MissionState.FAILED, error="attack")
        state_before = store.get(mid)
        try:
            store.retry(mid)
            verb = "ACCEPTED"
        except Exception as exc:                                   # noqa: BLE001
            verb = f"{type(exc).__name__}: {exc}"
        try:
            after = store.transition(mid, sf.MissionState.QUEUED, actor=sf.ACTOR_USER)
            edge = f"accepted; state {after['state']!r}, attempt {after['attempt']}"
            landed = after["state"] == sf.MissionState.QUEUED
        except Exception as exc:                                   # noqa: BLE001
            edge, landed = f"{type(exc).__name__}: {exc}", False
        # The THIRD verb that reaches the same edge. transition() and retry() were
        # the two the budget was moved between; finish_execution() is the one that
        # requeued a mission at the ceiling while both of those were being argued
        # about, which is why requeue_refusal() is keyed on the edge's event.
        try:
            store.finish_execution(mid, sf.MissionState.QUEUED, None)
            finish = "ACCEPTED"
            landed = landed or store.get(mid)["state"] == sf.MissionState.QUEUED
        except Exception as exc:                                   # noqa: BLE001
            finish = f"{type(exc).__name__}: {exc}"
        trail = [(e["event"], e["detail"][:52]) for e in store.events(mid)]
        published = sf.capabilities().get("max_attempts")
        final = store.get(mid)
        refusals = [e for e in store.events(mid) if e["event"] == "retry-budget-exhausted"]
        report = store.verify_chain()

        observed = lines(
            f"mission is {state_before['state']!r} with attempt={state_before['attempt']} "
            f"(capabilities() publishes max_attempts={published})",
            f"store.retry(mid)                    -> {verb}",
            f"store.transition(mid, 'queued')     -> {edge}",
            f"store.finish_execution(mid,'queued')-> {finish}",
            f"row afterwards: state={final['state']!r} attempt={final['attempt']} "
            f"error={final['error']!r}",
            f"event trail: {trail}",
            f"verify_chain(): ok={report['ok']} problems={report['problems']}")

        note = Note()
        note.says(not landed,
                  "The budget is a property of the failed -> queued EDGE, not of a verb: "
                  "requeue_refusal() is keyed on the edge's event name and every path to a "
                  "requeue asks it, so all three verbs refuse the fourth attempt.")
        note.says(len(refusals) >= 2,
                  "The refusal is RECORDED before it is raised. transition() and "
                  "finish_execution() each append a 'retry-budget-exhausted' event that "
                  "commits with their own transaction while the mission row is left "
                  "untouched, so the log gains a refusal and the state gains nothing -- "
                  "'no event' would read the same as 'nobody ever tried'.")
        note.says(final["state"] == sf.MissionState.FAILED
                  and final["attempt"] == state_before["attempt"],
                  "Nothing partial landed: the state and the attempt counter are exactly "
                  "what they were before the three attempts to get past the ceiling.")
        note.says(report["ok"],
                  "The chain still verifies afterwards, so the recorded refusals are "
                  "ordinary chained events and not a hole punched by the guard.")
        note.always(
            "Historical note: the budget once lived only in Store.retry(), so an in-process "
            "caller -- the worker, the desktop, any future orchestrator -- got a fourth "
            "attempt by calling transition() directly; moving it into transition() then "
            "left finish_execution() reaching the same edge on its own. Two verbs is why "
            "the question is now asked of the edge.")
        passed = (not landed) and note.ok()
        return ("The retry budget is a property of the failed -> queued edge, so the edge "
                "refuses a fourth attempt no matter which verb asks for it, and the "
                "refusal is recorded rather than silent.",
                observed, passed, note.text())


# --------------------------------------------------------------------------- #
# 8. Corrupt an Event row
# --------------------------------------------------------------------------- #
def event_field_coverage():
    """Is there any events column an attacker can rewrite that the hash misses?"""
    with throwaway() as base:
        store = new_store(base)
        for i in range(3):
            store.append_event("m", "probe", f"payload-{i}")
        present = columns(store.db_path, "events")
        chain_metadata = ("prev_hash", "hash")
        uncovered = [c for c in present
                     if c not in sf.HASHED_FIELDS and c not in chain_metadata]

        target_seq = rows(store.db_path, "SELECT MAX(seq) AS s FROM events")[0]["s"] - 1
        results = []
        for column in present:
            if column in chain_metadata:
                continue
            original = rows(store.db_path, f"SELECT {column} AS v FROM events WHERE seq=?",
                            (target_seq,))[0]["v"]
            forged = (original + 100) if column == "seq" else f"tampered-{column}"
            raw_sql(store.db_path, f"UPDATE events SET {column}=? WHERE seq=?",
                    (forged, target_seq))
            report = store.verify_chain()
            caught = not report["ok"]
            results.append(f"  {column:<18} {original!r} -> {forged!r}: "
                           f"{'DETECTED' if caught else 'NOT DETECTED'}"
                           + (f" ({report['problems'][0]})" if report["problems"] else ""))
            key = forged if column == "seq" else target_seq
            raw_sql(store.db_path, f"UPDATE events SET {column}=? WHERE seq=?",
                    (original, key))
            if not store.verify_chain()["ok"]:
                results.append(f"  {column:<18} !! restore failed; later rows in this "
                               "attack are unreliable")

        restored = store.verify_chain()
        observed = lines(
            f"events columns: {present}",
            f"HASHED_FIELDS:  {list(sf.HASHED_FIELDS)}",
            f"columns that are neither hashed nor chain metadata: {uncovered}",
            "one column at a time, rewritten with SQL and then restored:",
            *results,
            f"after restoring every column: verify_chain().ok={restored['ok']}")
        all_detected = all("NOT DETECTED" not in r for r in results)
        note = Note()
        note.either(not uncovered,
                    "Every column of `events` except prev_hash and hash is inside "
                    "HASHED_FIELDS, so there is no unprotected field to rewrite -- "
                    "including the three correlation columns (task_id, session_id, "
                    "tool_execution_id) that carry no data on most rows and would be the "
                    "quiet place to hide a reattribution.",
                    "FINDING: these columns are neither hashed nor chain metadata, so "
                    "rewriting them is invisible: " + ", ".join(uncovered))
        note.either(all_detected,
                    "Each one was rewritten with SQL and each rewrite was reported.",
                    "FINDING: at least one rewrite was NOT DETECTED; the lines above say "
                    "which column.")
        note.says(restored["ok"],
                  "The chain verifies again once every column is restored, so the walk did "
                  "not leave the store in a state that would flatter the next check.")
        note.always(
            "The existing unit tests cover detail, mission and actor. This walks the table, "
            "so a column ADDED later without being added to HASHED_FIELDS shows up here as "
            "NOT DETECTED rather than as nothing at all.")
        passed = not uncovered and all_detected and note.ok()
        return ("Every stored field of an event is covered by its hash, so rewriting any "
                "one of them is detected.",
                observed, passed, note.text())


def event_rechain_then_cover():
    """Rewrite a row, re-chain every successor, then let one honest event land."""
    with throwaway() as base:
        store = new_store(base)
        if not anchor_is_readable(store):
            return ("The journal catches a full re-chain, because the head hash it "
                    "recorded no longer matches the database's.",
                    "the journal is unreadable by this uid", False, INCONCLUSIVE)
        for i in range(4):
            store.append_event("m", "probe", f"payload-{i}")
        clean = store.verify_chain()
        victim = 3
        original_hash = rows(store.db_path, "SELECT hash FROM events WHERE seq=?",
                             (victim,))[0]["hash"]

        rechain(store.db_path, {victim: {"detail": "REWRITTEN BY THE ATTACKER"}})
        immediately = store.verify_chain()

        # The whole attack: one more event through the engine re-anchors the head.
        store.append_event("m", "probe", "cover")
        afterwards = store.verify_chain()
        exit_code, _, _ = cli("audit", "verify")

        mirrored = journal_entries(store.chain_id())
        now_stored = rows(store.db_path, "SELECT detail,hash FROM events WHERE seq=?",
                          (victim,))[0]

        observed = lines(
            f"before: ok={clean['ok']} anchor={clean['anchor']['verdict']!r}",
            f"seq {victim} rewritten to {now_stored['detail']!r} and every successor "
            "re-chained with the engine's own event_hash()",
            f"immediately after: ok={immediately['ok']} "
            f"anchor={immediately['anchor']['verdict']!r} problems={immediately['problems']}",
            "then ONE legitimate append_event() through the engine:",
            f"  ok={afterwards['ok']} anchor={afterwards['anchor']['verdict']!r} "
            f"problems={afterwards['problems']}",
            f"  `audit verify` exit {exit_code}",
            f"journal still holds seq {victim} hash {str(mirrored.get(victim))[:16]}, "
            f"database now holds {str(now_stored['hash'])[:16]} "
            f"(original was {str(original_hash)[:16]})",
            f"the two disagree at seq {victim}: {mirrored.get(victim) != now_stored['hash']}",
            f"anchor.rewritten_seqs after the cover append: "
            f"{afterwards['anchor'].get('rewritten_seqs')}")

        anchor = afterwards["anchor"]
        note = Note()
        note.says(clean["ok"] and not immediately["ok"],
                  "The rewrite is caught the moment it is made, which was never the "
                  "question here.")
        note.says(not afterwards["ok"],
                  "It is still caught AFTER the cover append. The anchor compares every "
                  "sequence number the journal can still see, not only the maximum, so the "
                  "honest event that re-aligned the two heads buys the attacker nothing.")
        note.says(victim in (anchor.get("rewritten_seqs") or []),
                  f"seq {victim} is named in anchor.rewritten_seqs, and the problem line "
                  "says which rows were rewritten after they were mirrored rather than "
                  "reporting a bare head mismatch.")
        note.says(anchor.get("verdict") == "conflict",
                  "The verdict is 'conflict' -- a finding, not a caveat -- and it is what "
                  "sets ok=False.")
        note.says(exit_code == 1,
                  "`audit verify` exits 1 over a log whose heads agree, which is the point: "
                  "the exit status follows the evidence, not the head.")
        note.always(
            "What this does NOT close: the journal is the only witness, so a row whose "
            "mirrored line has rotated out of the read window, or was never mirrored "
            "because the mirror was failing, has nothing to be compared against. That is "
            "the hole in the middle of the anchor, and it is a different gap from this one. "
            "Historical note: the anchor used to compare max(seq) alone, so a rewrite was "
            "detectable only until the next honest append -- a window the attacker chose "
            "the end of -- while the journal held the pre-tamper hash the whole time and "
            "nothing read it.")
        passed = (not afterwards["ok"]) and note.ok()
        return ("A rewritten row is detected however far back it is, because the journal "
                "recorded that row's hash and this uid cannot rewrite the journal.",
                observed, passed, note.text())


def event_detail_not_utf8():
    """A detail SQLite will store and canonical() cannot encode."""
    with throwaway() as base:
        store = new_store(base)
        store.append_event("m", "probe", "honest")
        victim = rows(store.db_path, "SELECT MAX(seq) AS s FROM events")[0]["s"]
        raw_sql(store.db_path, "UPDATE events SET detail=? WHERE seq=?",
                (sqlite3.Binary(b"\xff\xfe not utf-8"), victim))
        stored = rows(store.db_path, "SELECT typeof(detail) AS t FROM events WHERE seq=?",
                      (victim,))[0]["t"]
        report = None
        try:
            report = store.verify_chain()
            raised, verdict = None, f"ok={report['ok']} problems={report['problems']}"
        except Exception as exc:                                   # noqa: BLE001
            raised, verdict = f"{type(exc).__name__}: {exc}", None
        text_exit, _, text_err = cli("audit", "verify")
        json_exit, json_out, _ = cli("--json", "audit", "verify")
        parses = True
        try:
            json.loads(json_out)
        except ValueError as exc:
            parses = f"no: {exc}"

        observed = lines(
            f"detail of seq {victim} replaced with a BLOB; typeof(detail) is now {stored!r}",
            f"store.verify_chain() -> {raised or verdict}",
            f"`audit verify` exit {text_exit}; last line of stderr: "
            f"{(text_err.strip().splitlines() or ['(none)'])[-1]!r}",
            f"`--json audit verify` exit {json_exit}; stdout parses as JSON: {parses}")
        blob_problem = [p for p in ((report or {}).get("problems") or [])
                        if "not text" in p]
        note = Note()
        note.says(raised is None,
                  "verify_chain() returns a report rather than raising. The bytes SQLite "
                  "accepts into a TEXT-affinity column are not something json.dumps can "
                  "serialise, and canonical() used to take that TypeError all the way out "
                  "of verify.")
        note.says(bool(blob_problem),
                  "The row is reported as a PROBLEM in the ordinary way: "
                  + repr(blob_problem[0] if blob_problem else "") + " -- a non-text detail "
                  "is treated as evidence that something other than the engine wrote the "
                  "row, which is what it is, rather than being hashed.")
        note.says(text_exit != 0 and json_exit != 0,
                  "Both surfaces fail closed, and with the same code: nothing claims this "
                  "chain is intact.")
        note.says(parses is True,
                  "`--json audit verify` still emits parseable JSON, which is the half the "
                  "desktop reads. A traceback there is the difference between 'this log was "
                  "tampered with' and 'the audit view is broken again'.")
        note.always(
            "Historical note: this attack was a FINDING against the report rather than "
            "against the evidence -- it always failed closed, but an operator got a "
            "traceback with no PROBLEM line and no head, and --json produced nothing a "
            "caller could parse.")
        passed = (raised is None and verdict is not None
                  and "ok=False" in (verdict or "") and note.ok())
        return ("A row whose detail is not text is reported as a problem, like every other "
                "corrupt row, and verify still produces a verdict.",
                observed, passed, note.text())


def event_insert_bypassing_append():
    """Add rows to the log without going through _append()."""
    with throwaway() as base:
        store = new_store(base)
        for i in range(3):
            store.append_event("m", "probe", str(i))
        before = fingerprint(store)
        head = before["head_seq"]

        try:
            raw_sql(store.db_path,
                    "INSERT INTO events(seq,mission,at,event,detail) VALUES(?,?,?,?,?)",
                    (head, "m", sf.now(), "forged", "a second row claiming seq %d" % head))
            duplicate = "ACCEPTED"
        except Exception as exc:                                   # noqa: BLE001
            duplicate = f"{type(exc).__name__}: {exc}"
        after_duplicate = fingerprint(store)

        raw_sql(store.db_path,
                "INSERT INTO events(mission,at,event,detail) VALUES(?,?,?,?)",
                ("m", sf.now(), "forged", "appended with no hash"))
        report = store.verify_chain()
        exit_code, stdout, _ = cli("audit", "verify")
        chain_line = next((l for l in stdout.splitlines() if l.startswith("chain")), "")

        observed = lines(
            f"INSERT with a duplicate seq ({head}) -> {duplicate}",
            f"events {before['events']} -> {after_duplicate['events']}, "
            f"head hash unchanged: {before['head_hash'] == after_duplicate['head_hash']}",
            "INSERT letting AUTOINCREMENT pick the seq (so the row carries no hash):",
            f"  verify_chain(): ok={report['ok']} problems={report['problems']}",
            f"  `audit verify` exit {exit_code}; {chain_line.strip()!r}")
        unhashed = [p for p in report["problems"] if "no hash" in p]
        note = Note()
        note.says("IntegrityError" in duplicate,
                  "seq is the INTEGER PRIMARY KEY, so the storage engine itself refuses a "
                  "second row claiming a sequence number that is already taken. Forging "
                  "history IN PLACE is not available; only rewriting it is, which is the "
                  "attack two entries above this one.")
        note.says(before["head_hash"] == after_duplicate["head_hash"],
                  "The refused INSERT left the head hash untouched, so the failure was the "
                  "storage engine's and not a half-applied write.")
        note.says(bool(unhashed),
                  "A row appended around _append() carries no hash, and the chain reports "
                  + repr(unhashed[0]) + " rather than skipping it -- which is the "
                  "difference between a chain and a list of hashes.")
        note.always(
            "_append() is the only INSERT into events in the running engine. The one "
            "deliberate exception is historical rather than reachable: the v1 -> v2 "
            "migration writes its schema-migrated row with a raw INSERT, because it runs "
            "before the chain columns exist, and start_chain() pins it a moment later.")
        passed = "IntegrityError" in duplicate and not report["ok"] and note.ok()
        return ("A row inserted without going through _append() cannot take an existing "
                "sequence number, and one appended at the end is reported as unhashed "
                "rather than accepted.",
                observed, passed, note.text())


# --------------------------------------------------------------------------- #
# 9. Truncate the Event chain / 10. Delete the last Event
# --------------------------------------------------------------------------- #
def _delete_tail(store, count):
    head = rows(store.db_path, "SELECT MAX(seq) AS s FROM events")[0]["s"]
    deleted = raw_sql(store.db_path, "DELETE FROM events WHERE seq > ?", (head - count,))
    return head, deleted


def _truncation_attack(count, blind):
    """Shared body for attacks 9 and 10: the only variable is how many rows go."""
    with throwaway() as base:
        store = new_store(base)
        if not blind and not anchor_is_readable(store):
            return ("The journal reports the events the database no longer has.",
                    "the journal is unreadable by this uid", False, INCONCLUSIVE)
        for i in range(5):
            store.append_event("m", "probe", f"payload-{i}")
        before = store.verify_chain()
        head, deleted = _delete_tail(store, count)
        remaining = rows(store.db_path, "SELECT MAX(seq) AS s FROM events")[0]["s"]

        with contextlib.ExitStack() as stack:
            if blind:
                stack.enter_context(blind_anchor())
            report = store.verify_chain()
            exit_code, stdout, _ = cli("audit", "verify")
        chain_line = next((l for l in stdout.splitlines() if l.startswith("chain")), "")
        anchor_line = next((l for l in stdout.splitlines() if l.startswith("external")), "")
        hash_problems = [p for p in report["problems"] if "hash" in p and "journal" not in p]

        observed = lines(
            f"before: ok={before['ok']} head seq {before['head_seq']} "
            f"anchor={before['anchor']['verdict']!r}",
            f"DELETE FROM events WHERE seq > {head - count} removed {deleted} row(s); "
            f"database head is now seq {remaining}",
            f"anchor readable: {report['anchor']['readable']}"
            + (f" ({report['anchor']['reason']})" if report["anchor"]["reason"] else ""),
            f"verify_chain(): ok={report['ok']} verdict={report['anchor']['verdict']!r} "
            f"journal_head_seq={report['anchor']['journal_head_seq']} "
            f"database_head_seq={report['anchor']['database_head_seq']}",
            f"problems: {report['problems']}",
            f"problems the CHAIN alone raised (no journal): {hash_problems}",
            f"`audit verify` exit {exit_code}; {chain_line.strip()!r}; {anchor_line.strip()!r}")

        note = Note()
        if blind:
            note.says(not hash_problems,
                      "The deletion was NOT prevented and NOT detected. With no journal "
                      "there is nothing left that could detect it: every surviving row "
                      "still verifies against its predecessor, which is what a hash chain "
                      "is, and sf_audit's docstring says so in its first paragraph.")
            note.says(report["anchor"]["verdict"] == "unverified"
                      and bool(report["anchor"]["reason"]),
                      "This passes on the only claim available -- the system does not call "
                      "the log verified. The anchor reports 'unverified' with the reason "
                      "it could not be read: " + repr(report["anchor"]["reason"]) + ".")
            note.says(exit_code == 2,
                      "The CLI exits 2, not 0, so a caller that treats 0 as 'audited' is "
                      "not misled into treating an unexercised control as a passing one.")
            note.always("The removed events are gone and unrecoverable.")
            passed = (exit_code != 0
                      and report["anchor"]["verdict"] == "unverified"
                      and note.ok())
            expected = ("With no external anchor the truncation cannot be detected; the "
                        "system must therefore refuse to report the log as verified.")
        else:
            note.says(not hash_problems,
                      "The chain alone is perfectly happy -- the problems it raised on its "
                      "own are listed above as an empty list -- and the journal is the "
                      "entire reason this is caught.")
            note.says(report["anchor"]["verdict"] == "truncated"
                      and report["anchor"]["journal_head_seq"] == head,
                      f"The journal's high-water mark is seq {head}, the database's is "
                      f"{remaining}, and the count in the message is the real one.")
            note.says(exit_code == 1,
                      "The CLI exits 1: the removal is a finding, not a caveat.")
            note.always(
                "The journal entry this compares against was written by a process running "
                "as this uid, into a store this uid cannot edit. That asymmetry is the "
                "whole mechanism, and it ends at root.")
            passed = ((not report["ok"]) and report["anchor"]["verdict"] == "truncated"
                      and not hash_problems and exit_code == 1 and note.ok())
            expected = ("The journal's high-water mark exceeds the database's, so verify "
                        "reports the removal, names how many rows went, and the CLI exits "
                        "non-zero.")
        return (expected, observed, passed, note.text())


def chain_truncate_anchored():
    return _truncation_attack(3, blind=False)


def chain_truncate_unanchored():
    return _truncation_attack(3, blind=True)


def event_delete_last_anchored():
    return _truncation_attack(1, blind=False)


def event_delete_last_unanchored():
    return _truncation_attack(1, blind=True)


def chain_truncate_mirror_forged():
    """Truncate, then write the mirror bookkeeping the attacker also owns."""
    with throwaway() as base:
        store = new_store(base)
        if not anchor_is_readable(store):
            return ("Truncation is reported from the journal, whatever local state says.",
                    "the journal is unreadable by this uid", False, INCONCLUSIVE)
        for i in range(5):
            store.append_event("m", "probe", f"payload-{i}")
        _delete_tail(store, 2)
        plain = store.verify_chain()

        state_file = Path(store.root) / sf_audit.MirrorState.FILENAME
        state_file.unlink()
        deleted = store.verify_chain()

        # Same uid, same directory as the database it is meant to corroborate.
        state_file.write_text(json.dumps({
            "last_mirrored_seq": plain["head_seq"],
            "failures": 1,
            "last_error": "ConnectionResetError: [Errno 104] Connection reset by peer",
            "last_success_at": None}, sort_keys=True))
        forged = store.verify_chain()
        exit_code, stdout, _ = cli("audit", "verify")
        chain_line = next((l for l in stdout.splitlines() if l.startswith("chain")), "")
        journal_line = next((l for l in stdout.splitlines() if "journal head" in l), "")
        head_line = next((l for l in stdout.splitlines() if l.startswith("head ")), "")

        observed = lines(
            f"2 rows deleted from the end. verify_chain(): ok={plain['ok']} "
            f"verdict={plain['anchor']['verdict']!r}",
            f"  {plain['problems']}",
            f"after DELETING {state_file.name}: ok={deleted['ok']} "
            f"verdict={deleted['anchor']['verdict']!r} (deleting it does not help the attacker)",
            f"after WRITING {state_file.name} with failures=1: ok={forged['ok']} "
            f"verdict={forged['anchor']['verdict']!r}",
            f"  {forged['problems']}",
            f"`audit verify` exit {exit_code} (it was {1 if not plain['ok'] else 0} before the file was written)",
            f"  {chain_line.strip()!r}",
            f"  {head_line.strip()!r}",
            f"  {journal_line.strip()!r}")
        truncation_problems = [p for p in forged["problems"] if "a gap of" in p]
        degraded_problems = [p for p in forged["problems"] if "audit mirror has failed" in p]
        note = Note()
        note.says(not plain["ok"] and not deleted["ok"] and not forged["ok"],
                  "The truncation is reported in all three states of the local bookkeeping "
                  "file: present and honest, deleted, and written by the attacker with a "
                  "failure count in it.")
        note.says(forged["anchor"]["verdict"] == "truncated",
                  "The verdict stays 'truncated' with the forged file in place. The journal "
                  "comparison does not depend on the file, and a file the attacker owns "
                  "must not be able to silence the one check that does not.")
        note.says(bool(truncation_problems) and bool(degraded_problems),
                  "Both facts are reported, in that order of authority: the removal of the "
                  "rows is a FINDING and the mirror failure is a CAVEAT printed alongside "
                  "it. Degradation may add to a report and may never subtract from one.")
        note.says(forged["anchor"].get("degraded") is True,
                  "anchor['degraded'] stays separately readable, so a caller that wants to "
                  "know the mirror is unwell can still ask without the verdict having been "
                  "spent on saying so.")
        note.says(exit_code == 1,
                  "The exit status is 1, the tampered code -- not 2, which would say "
                  "'nothing could be concluded' about a log that had just been compared.")
        note.always(
            "Historical note: verify_chain() tested the failure count FIRST, as the head of "
            "an elif chain, and never reached the journal comparison while it was set. "
            "Truncating the log and then writing {\"failures\": 1} into a file the same uid "
            "already owns turned ok=False into ok=True, replaced '2 event(s) were removed "
            "from the end of the log' with 'the audit mirror has failed 1 time(s)', and "
            "turned exit 1 into exit 2 -- a suppression switch built out of local "
            "bookkeeping. Deleting the file never helped the attacker; only writing it did.")
        passed = (not forged["ok"] and forged["anchor"]["verdict"] == "truncated"
                  and note.ok())
        return ("Local mirror bookkeeping is attacker-writable, so it must not be able to "
                "suppress the journal comparison: the truncation is reported either way.",
                observed, passed, note.text())


def event_delete_genesis():
    """Remove the row the chain starts from, then forge a replacement."""
    with throwaway() as base:
        store = new_store(base)
        for i in range(3):
            store.append_event("m", "probe", f"payload-{i}")
        raw_sql(store.db_path, "DELETE FROM events WHERE event=?", (sf.CHAIN_GENESIS,))
        # A fresh Store, because an operator running `audit verify` gets a fresh
        # process and the chain id is cached per instance.
        first = new_store(base).verify_chain()
        first_exit, _, _ = cli("audit", "verify")

        forged_chain = uuid.uuid4().hex
        raw_sql(store.db_path,
                "INSERT INTO events(seq,mission,at,event,detail,actor) "
                "VALUES(1,'*',?,?,?,?)",
                (sf.now(), sf.CHAIN_GENESIS,
                 json.dumps({"chain_id": forged_chain, "from_schema_version": None,
                             "to_schema_version": sf.SCHEMA_VERSION,
                             "unchained_events": 0, "unchained_digest": "",
                             "note": "forged by the attack module"}, sort_keys=True),
                 sf.ACTOR_ORCHESTRATOR))
        rechain(store.db_path, {3: {"detail": "REWRITTEN UNDER A NEW GENESIS"}})
        second_store = new_store(base)
        second = second_store.verify_chain()
        second_exit, second_out, _ = cli("audit", "verify")
        chain_line = next((l for l in second_out.splitlines() if l.startswith("chain")), "")
        anchor_line = next((l for l in second_out.splitlines() if l.startswith("external")), "")

        observed = lines(
            "stage 1, genesis row deleted:",
            f"  ok={first['ok']} chained={first['chained']} problems={first['problems']}",
            f"  anchor={first['anchor']['verdict']!r} ({first['anchor']['reason']})",
            f"  `audit verify` exit {first_exit}",
            "stage 2, a replacement genesis with a new chain id, everything re-chained, "
            "one row rewritten:",
            f"  ok={second['ok']} problems={second['problems']}",
            f"  chain id is now {str(second_store.chain_id())[:8]} "
            f"(forged {forged_chain[:8]})",
            f"  anchor={second['anchor']['verdict']!r} ({second['anchor']['reason']})",
            f"  `audit verify` exit {second_exit}; {chain_line.strip()!r}; "
            f"{anchor_line.strip()!r}")
        others = second["anchor"].get("other_chains_for_this_store") or {}
        note = Note()
        note.says(not first["ok"] and first_exit != 0,
                  "Stage 1 is a clean catch: with the genesis gone every surviving row "
                  "'carries a hash before the chain genesis', verify says nothing is "
                  "verifiable, and the CLI exits non-zero.")
        note.says(bool(others),
                  "Stage 2 is now a MISMATCH rather than an absence. The journal is keyed by "
                  "a store identity derived from the database's absolute path -- the one "
                  "name in the record the database cannot restate about itself -- so the "
                  "entries this store mirrored under its original chain id are still "
                  "attributable to it: "
                  + ", ".join(f"{cid[:12]} ({n} event(s))" for cid, n in sorted(others.items()))
                  + ", against the id it now presents.")
        note.says(second["anchor"].get("verdict") == "conflict" and not second["ok"],
                  "That makes the verdict 'conflict' and sets ok=False: a chain id is minted "
                  "once at genesis, so a store presenting a second one re-minted its log.")
        note.says(second_exit == 1,
                  "The exit status is 1, the tampered code. An attacker who re-chains "
                  "everything under a new genesis no longer buys the softer 'unverified'.")
        note.always(
            "What remains true: the genesis lives in a row this uid can delete, so the "
            "chain id is still not a secret and still not outside the attacker's reach -- "
            "what changed is that moving it is now evidence rather than amnesia. A database "
            "genuinely copied to a new path is a different store with no journal history, "
            "which reports 'unverified' and is the honest answer to 'I have never seen this "
            "before'. Historical note: before the store identity existed, read_head() was "
            "keyed only by the id the database handed it, so re-minting detached the log "
            "from its own anchor and stage 2 reported a bare absence.")
        passed = (first_exit != 0 and second_exit != 0 and not first["ok"]
                  and note.ok())
        return ("Deleting the genesis row is reported as unverifiable, and a forged "
                "replacement is reported as a re-minted chain rather than as a log with no "
                "history.",
                observed, passed, note.text())


# --------------------------------------------------------------------------- #
# 11. Forge a Firebreak session ID
# --------------------------------------------------------------------------- #
def firebreak_session_forged():
    """Create a .session file under an id nobody issued, and use it."""
    with throwaway() as base:
        state = Path(os.environ["SHADOWFETCH_FIREBREAK_STATE"])
        state.mkdir(parents=True, exist_ok=True)
        os.environ["SHADOWFETCH_MCP_SESSION"] = "forged-session-01"
        os.environ["SHADOWFETCH_MCP_DESTRUCTIVE"] = sf_mcp.DESTRUCTIVE_ALLOW

        assert sf_mcp._firebreak_state() == state, (
            "the MCP server is not reading the throwaway Firebreak directory")
        before = sf_mcp.correlation()
        forged = state / "forged-session-01.session"
        forged.touch()
        after = sf_mcp.correlation()

        server = sf_mcp.build_checkpoint()
        assert base in server.audit.directory().parents, (
            "the MCP audit log is not inside the throwaway directory")
        undo = server.tools["undo"]
        allowed, reason = server._gate(undo, after)
        offered = [t.name for t in server.listed_tools()]
        result = server.call("undo", {"workspace": "probe", "checkpoint": "nope"})

        observed = lines(
            f"correlation() with the id set and no file: {before}",
            f"the file created is {forged.name}, {forged.stat().st_size} bytes, "
            f"mode {oct(forged.stat().st_mode & 0o777)}, written by uid {os.getuid()}",
            f"correlation() with the file present: {after}",
            f"_gate(undo, who) -> ({allowed}, {reason!r})",
            f"tools offered to the agent: {offered}",
            f"checkpoint.undo call -> {json.dumps(result)[:200]}")
        note = Note()
        note.says(before["status"] == sf_mcp.CORRELATION_UNKNOWN
                  and after["status"] == sf_mcp.CORRELATION_OBSERVED,
                  "NOT PREVENTED, and it is not meant to be. An empty file created by this "
                  "uid moves the correlation from 'unknown' to 'observed'.")
        note.says(allowed,
                  "That opens the DESTRUCTIVE gate, because _session_recorded() is one "
                  "is_file() call and nothing more.")
        note.always(
            "That is the documented design: the server runs with no more privilege than the "
            "agent it is gating, so it cannot hold evidence that agent cannot forge. What it "
            "buys is cost and a name -- the forged id is on the audit row, and the operator "
            "must also have set SHADOWFETCH_MCP_DESTRUCTIVE=allow, which the agent cannot do "
            "for itself. This is marked PASS for the next attack's reason, not this one's: "
            "the action succeeded, and the question that matters is what the system then "
            "CLAIMS about it.")
        passed = (after["status"] == sf_mcp.CORRELATION_OBSERVED and allowed
                  and note.ok())
        return ("Forging the file succeeds -- this uid owns that directory -- and the "
                "system's own documentation says so rather than claiming the session was "
                "verified.",
                observed, passed, note.text())


def firebreak_session_claim():
    """Does anything claim more than 'a file of that name exists'?"""
    with throwaway() as base:
        state = Path(os.environ["SHADOWFETCH_FIREBREAK_STATE"])
        state.mkdir(parents=True, exist_ok=True)
        os.environ["SHADOWFETCH_MCP_SESSION"] = "forged-session-02"
        os.environ["SHADOWFETCH_MCP_DESTRUCTIVE"] = sf_mcp.DESTRUCTIVE_ALLOW
        (state / "forged-session-02.session").touch()

        server = sf_mcp.build_checkpoint()
        server.call("undo", {"workspace": "probe", "checkpoint": "nope"})
        recorded = [json.loads(line) for line in
                    (server.audit.directory() / sf_mcp.AUDIT_FILENAME).read_text().splitlines()]
        gate_rows = [r for r in recorded if r.get("tool") == "undo"]
        statuses = {r["correlation"]["status"] for r in gate_rows}
        reasons = {r["reason"] for r in gate_rows}

        source = (MCP_SRC / "sf_mcp.py").read_text()
        recorded_fn = source.split("def _session_recorded")[1].split("\ndef ")[0]
        checks_is_file = "is_file()" in recorded_fn
        reads_content = any(token in recorded_fn for token in
                            ("read_text", "json.load", "open(", "st_uid", "read_records"))

        # A directory is not a file; a traversal id never reaches the filesystem.
        (state / "forged-session-03.session").mkdir()
        os.environ["SHADOWFETCH_MCP_SESSION"] = "forged-session-03"
        as_directory = sf_mcp.correlation()["status"]
        os.environ["SHADOWFETCH_MCP_SESSION"] = "../../../etc/passwd"
        traversal = sf_mcp.correlation()
        os.environ["SHADOWFETCH_MCP_SESSION"] = "nobody-issued-this"
        unknown = sf_mcp.correlation()
        _, refusal = server._gate(server.tools["undo"], unknown)

        observed = lines(
            f"audit rows for the forged call carry correlation status {statuses} "
            f"and reason {reasons}",
            f"the recorded session id on the row is "
            f"{ {r['correlation']['session'] for r in gate_rows} }",
            f"_session_recorded() calls is_file(): {checks_is_file}; "
            f"reads the record's contents in any way: {reads_content}",
            f"a DIRECTORY named <id>.session gives status {as_directory!r}",
            f"an id shaped like a path traversal: {traversal}",
            f"the refusal text for an unrecorded id: {refusal[:180]!r}")
        claims_verified = any(word in " ".join(reasons).lower()
                              for word in ("verified", "authenticated", "proven", "trusted"))
        note = Note()
        note.says(statuses == {sf_mcp.CORRELATION_OBSERVED} and not claims_verified,
                  "The claim matches the code. The word recorded is 'observed', never "
                  "'verified', 'authenticated', 'proven' or 'trusted', and the permitted "
                  "call's reason says what was permitted rather than anything about the "
                  "session.")
        note.says(checks_is_file and not reads_content,
                  "_session_recorded() is exactly one is_file() call. It reads nothing, so "
                  "the file's CONTENTS are not evidence and are not treated as evidence.")
        note.says(traversal["status"] == sf_mcp.CORRELATION_MALFORMED,
                  "A path-traversal id is MALFORMED before any path is built from it, which "
                  "falls out of the shape check rather than the file check.")
        note.says(as_directory == sf_mcp.CORRELATION_UNKNOWN,
                  "A directory of the right name reads as UNKNOWN for the same reason.")
        note.always(
            "What remains true and is not a defect to fix here: the correlation is worth "
            "what a file this uid can create is worth, which is the honest ceiling for a "
            "gate running with the agent's own privileges.")
        passed = (statuses == {sf_mcp.CORRELATION_OBSERVED} and checks_is_file
                  and not reads_content and not claims_verified
                  and traversal["status"] == sf_mcp.CORRELATION_MALFORMED
                  and as_directory == sf_mcp.CORRELATION_UNKNOWN
                  and note.ok())
        return ("The system records the forged correlation as 'observed' and nothing "
                "anywhere upgrades that into a claim that the session is real.",
                observed, passed, note.text())


# --------------------------------------------------------------------------- #
# The module's interface
# --------------------------------------------------------------------------- #
_TABLE = (
    ("state-jump-forged-row", state_jump_forged_row),
    ("state-jump-illegal-target", state_jump_illegal_target),
    ("state-jump-retry-budget", state_jump_retry_budget),
    ("event-field-coverage", event_field_coverage),
    ("event-rechain-then-cover", event_rechain_then_cover),
    ("event-detail-not-utf8", event_detail_not_utf8),
    ("event-insert-bypassing-append", event_insert_bypassing_append),
    ("chain-truncate-anchored", chain_truncate_anchored),
    ("chain-truncate-unanchored", chain_truncate_unanchored),
    ("chain-truncate-mirror-forged", chain_truncate_mirror_forged),
    ("event-delete-last-anchored", event_delete_last_anchored),
    ("event-delete-last-unanchored", event_delete_last_unanchored),
    ("event-delete-genesis", event_delete_genesis),
    ("firebreak-session-forged", firebreak_session_forged),
    ("firebreak-session-claim", firebreak_session_claim),
)

ATTACKS = tuple(name for name, _ in _TABLE)


def run(report):
    """Run every attack in order, handing each result to `report`.

    report(name, expected, observed, passed, note="")
    """
    for name, attack in _TABLE:
        try:
            expected, observed, passed, note = attack()
        except Exception as exc:                                   # noqa: BLE001
            import traceback
            report(name,
                   "the attack runs to completion and reports what it saw",
                   f"the attack module itself raised: {type(exc).__name__}: {exc}\n"
                   + textwrap.indent(traceback.format_exc().strip(), "  "),
                   False,
                   note=("This is a defect in the attack module or a change in the engine "
                         "it reads, NOT a result about the system. Nothing was proven "
                         "either way."))
            continue
        report(name, expected, observed, passed, note)


def main():
    results = []

    def collect(name, expected, observed, passed, note=""):
        results.append((name, expected, observed, passed, note))
        print(f"{'PASS' if passed else 'FAIL'}  {name}")
        for label, text in (("EXPECTED", expected), ("OBSERVED", observed),
                            ("NOTE", note)):
            if not text:
                continue
            body = str(text).splitlines() or [""]
            print(f"  {label:<9} {body[0]}")
            for extra in body[1:]:
                print(f"  {'':<9} {extra}")
        print()

    print(f"attack_integrity: {len(ATTACKS)} attacks against "
          f"{MISSIONS_SRC.relative_to(REPO)}\n")
    run(collect)
    failed = [name for name, _e, _o, passed, _n in results if not passed]
    print(f"{len(results) - len(failed)}/{len(results)} PASS")
    if failed:
        print("FAILED: " + ", ".join(failed))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
