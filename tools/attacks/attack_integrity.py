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

HOW TO RUN IT, AND WHERE IT IS NOT
      python3 tools/attacks/attack_integrity.py      # table, exit 1 on any FAIL
  or  from attack_integrity import ATTACKS, run      # composed with the others
  It is NOT in a gate. `make test` names each test directory explicitly and this
  file is in none of them, so nothing runs it but a person or another module.
  Wiring it in means one line in the Makefile's `test:` target --
  `python3 tools/attacks/attack_integrity.py` -- which the author of this file
  was not permitted to add. Until that line exists, saying this module "runs in
  CI" would be false; it runs when someone runs it.
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


def cli(*args):
    """Run the real CLI against the throwaway store. (exit, stdout, stderr)."""
    done = subprocess.run([sys.executable, str(MISSIONS_CLI), *args],
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
    saved = os.environ.get("PATH", "")
    empty = tempfile.mkdtemp(prefix="sf-attack-nopath-")
    os.environ["PATH"] = empty
    try:
        yield
    finally:
        os.environ["PATH"] = saved
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

        observed = lines(
            f"mission created by {how}, state {'queued'!r}",
            f"after UPDATE missions SET state='completed': store.get()['state'] == {forged!r}",
            f"store.transition(mid, 'undone') -> {refused or 'accepted, state is now ' + repr(after)}",
            f"event trail: {trail}",
            f"store.verify_chain(): ok={report['ok']} problems={report['problems']} "
            f"anchor={report['anchor']['verdict']!r}",
            f"`audit verify` exit {exit_code}; {verdict_line.strip()!r}")
        passed = refused is not None or not report["ok"]
        note = ("FINDING. The missions table is not covered by the hash chain and nothing "
                "replays MISSION_TRANSITIONS across the event trail, so a state written "
                "with SQL is indistinguishable from one the engine reached. The mission "
                "went queued -> undone without ever running, and the event the engine "
                "wrote for it says 'a human changed their mind about accepted work' -- a "
                "sentence chosen from the forged state, which makes the audit trail assert "
                "something that did not happen. verify_chain() is right to stay silent: it "
                "verifies events, not states. The gap is that nothing else checks. A replay "
                "of the event sequence against MISSION_TRANSITIONS would catch exactly this "
                "and needs no new storage. Not prevented, not detected.")
        return ("A mission state that no event records is not a state the engine reached: "
                "either the engine refuses to act on it, or verification reports the "
                "mismatch between the row and its event trail.",
                observed, passed, note)


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
        passed = not changed_by and report["ok"]
        note = ("The near-miss spellings are refused by name, and the refusal text names "
                "the reachable states rather than saying 'invalid'. Worth the lead's eye: "
                "an unhashable target (a list) raises TypeError from inside "
                "transition_allowed()'s dict lookup rather than TransitionError -- it is "
                "raised inside the BEGIN IMMEDIATE block, so the transaction rolls back "
                "and nothing is written, but a caller catching TransitionError will not "
                "catch it. That is an exception-class wart, not a state change."
                if not changed_by else
                "FINDING: something on that list changed the row: " + ", ".join(changed_by))
        return ("Every one of these is refused, and the mission row, the event count and "
                "the chain head are unchanged afterwards.",
                observed, passed, note)


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
        trail = [(e["event"], e["detail"][:52]) for e in store.events(mid)]
        published = sf.capabilities().get("max_attempts")

        observed = lines(
            f"mission is {state_before['state']!r} with attempt={state_before['attempt']} "
            f"(capabilities() publishes max_attempts={published})",
            f"store.retry(mid) -> {verb}",
            f"store.transition(mid, 'queued') -> {edge}",
            f"event trail: {trail}")
        passed = not landed
        note = ("FINDING. The three-attempt budget lives only in Store.retry(). "
                "Store.transition() owns the state machine and does not know about it, so "
                "the same failed -> queued edge goes through with attempt already at the "
                "published ceiling, and the event it writes carries the table's reason, "
                "'a human retried a failed mission'. Phase 3's own comment on Store.update "
                "says the defect it fixed was that 'every guard lived in a high-level verb "
                "that a caller could simply not use'; the retry budget is still exactly "
                "that. Scope, stated honestly: the CLI's `retry` goes through retry() and "
                "IS capped -- this is reachable by an in-process caller of the engine API, "
                "which is what the worker, the desktop and every future orchestrator are.")
        return ("The retry budget is a property of the failed -> queued edge, so the edge "
                "refuses a fourth attempt no matter which verb asks for it.",
                observed, passed, note)


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
        passed = not uncovered and all("NOT DETECTED" not in r for r in results)
        note = ("Every column of `events` except prev_hash and hash is inside "
                "HASHED_FIELDS, so there is no unprotected field to rewrite -- including "
                "the three correlation columns (task_id, session_id, tool_execution_id) "
                "that carry no data on most rows and would be the quiet place to hide a "
                "reattribution. The existing tests cover detail, mission and actor; this "
                "walks the table so a column ADDED later without being added to "
                "HASHED_FIELDS shows up here as NOT DETECTED."
                if passed else
                "FINDING: a column outside the hash, or a change the chain did not notice.")
        return ("Every stored field of an event is covered by its hash, so rewriting any "
                "one of them is detected.",
                observed, passed, note)


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
            f"the two disagree at seq {victim}: {mirrored.get(victim) != now_stored['hash']}")
        passed = not afterwards["ok"]
        note = ("FINDING. The anchor compares ONE row: read_head() returns max(seq) and "
                "verify_chain() compares only that head. So a rewrite is caught for "
                "exactly as long as the rewritten head is the newest event -- one honest "
                "append later, the journal's head and the database's head agree again and "
                "verify reports ok with verdict 'agrees', over a row that says REWRITTEN BY "
                "THE ATTACKER. The evidence is not missing: the journal still carries the "
                "pre-tamper hash for that seq, printed above, and this uid can read it. "
                "Nothing compares it. Comparing every mirrored seq the journal can still "
                "see, rather than only the maximum, closes this with no new storage and no "
                "new privilege -- and would also make the anchor useful for rows that have "
                "not rotated away. Not prevented; detectable only in a window the attacker "
                "chooses the end of.")
        return ("A rewritten row is detected however far back it is, because the journal "
                "recorded that row's hash and this uid cannot rewrite the journal.",
                observed, passed, note)


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
        passed = raised is None and verdict is not None and "ok=False" in (verdict or "")
        note = ("FINDING. verify_chain() raises TypeError out of canonical() instead of "
                "reporting the row as a problem: json.dumps cannot serialise the bytes "
                "SQLite happily stored in a TEXT-affinity column. It fails CLOSED -- the "
                "exit code is non-zero and nothing ever claims the chain is intact -- so "
                "this is not an evidence defeat. What it defeats is the report: an operator "
                "gets a traceback with no PROBLEM line and no head, and a caller reading "
                "`--json audit verify` gets no JSON at all, which for the desktop is the "
                "difference between 'this log was tampered with' and 'the audit view is "
                "broken again'. One row that treats a non-str detail as a problem, rather "
                "than hashing it, turns this back into a verdict.")
        return ("A row whose detail is not text is reported as a problem, like every other "
                "corrupt row, and verify still produces a verdict.",
                observed, passed, note)


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
        passed = "IntegrityError" in duplicate and not report["ok"]
        note = ("Two different mechanisms, both holding. seq is the INTEGER PRIMARY KEY, so "
                "the storage engine itself refuses a second row claiming a sequence number "
                "that is already taken -- forging history in place is not available, only "
                "rewriting it. A row appended around _append() has no hash, and the chain "
                "reports 'chained region has no hash' rather than skipping it, which is the "
                "difference between a chain and a list of hashes.")
        return ("A row inserted without going through _append() cannot take an existing "
                "sequence number, and one appended at the end is reported as unhashed "
                "rather than accepted.",
                observed, passed, note)


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

        if blind:
            passed = exit_code != 0 and report["anchor"]["verdict"] == "unverified"
            note = ("The deletion was NOT prevented and NOT detected -- with no journal "
                    "there is nothing left that could detect it, because every surviving "
                    "row still verifies against its predecessor. That is what a hash chain "
                    "is, and sf_audit's docstring says so in its first paragraph. This "
                    "passes on the only claim available: the system does not call the log "
                    "verified. verify reports the anchor as 'unverified' with the reason, "
                    "and the CLI exits 2 rather than 0, so a caller that treats 0 as "
                    "'audited' is not misled. The removed events are gone and "
                    "unrecoverable.")
            expected = ("With no external anchor the truncation cannot be detected; the "
                        "system must therefore refuse to report the log as verified.")
        else:
            passed = (not report["ok"]) and report["anchor"]["verdict"] == "truncated" \
                and not hash_problems and exit_code == 1
            note = ("The chain alone is perfectly happy -- no hash problem was raised, "
                    "listed above as an empty list -- and the journal is the entire reason "
                    "this is caught. The count in the message is the real one, and the "
                    "journal entry it compares against was written by a process running as "
                    "this uid but into a store this uid cannot edit.")
            expected = ("The journal's high-water mark exceeds the database's, so verify "
                        "reports the removal, names how many rows went, and the CLI exits "
                        "non-zero.")
        return (expected, observed, passed, note)


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
        passed = not forged["ok"] and forged["anchor"]["verdict"] == "truncated"
        note = ("FINDING, and the sharpest one here. audit-mirror.json sits beside the "
                "database, owned by the same uid that wrote the events, and verify_chain() "
                "branches on it FIRST: `if anchor['mirror_failures']` reports 'degraded' and "
                "never reaches the journal comparison at all. So an attacker who truncates "
                "the log and then writes failures=1 into a file they already control turns "
                "ok=False into ok=True, turns the message from '2 event(s) were removed "
                "from the end of the log' into 'the audit mirror has failed 1 time(s)', and "
                "turns exit 1 into exit 2. The CLI then prints 'chain intact', 'head seq N' "
                "and 'journal head seq N+2' on three consecutive lines without comparing "
                "them. Deleting the file does NOT help the attacker -- that path is clean -- "
                "which is what makes writing it worth reporting: the degraded branch is a "
                "suppression switch. Comparing the heads regardless of the local failure "
                "count, and reporting degraded ALONGSIDE the comparison rather than instead "
                "of it, fixes it; local bookkeeping should never be able to silence the one "
                "check that does not depend on local bookkeeping. Why this is a FAIL when "
                "chain-truncate-unanchored is a PASS, since both end at ok=True and exit 2: "
                "there no evidence existed and the system said so; here the evidence was in "
                "hand -- the CLI prints the journal head two lines below the database head "
                "-- and a file the attacker owns stopped the two being compared.")
        return ("Local mirror bookkeeping is attacker-writable, so it must not be able to "
                "suppress the journal comparison: the truncation is reported either way.",
                observed, passed, note)


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
        passed = first_exit != 0 and second_exit != 0 and not first["ok"]
        note = ("Stage 1 is a clean catch: every surviving row 'carries a hash before the "
                "chain genesis' and verify says nothing is verifiable, exit 1. Stage 2 is "
                "the honest boundary and the lead should read it as a finding rather than a "
                "pass: with a forged genesis the CHAIN reports itself intact over a "
                "rewritten row -- problems is empty and the CLI prints 'chain intact' -- and "
                "the only thing that stops a clean bill of health is that the new chain id "
                "was never mirrored, so the anchor is 'unverified' and the exit code is 2 "
                "rather than 0. The chain id living inside a row the attacker can delete is "
                "what makes that possible; an identifier kept outside the events table "
                "would turn stage 2 into a mismatch instead of an absence. The journal has "
                "not forgotten anything -- every mirrored head of the ORIGINAL chain is "
                "still there under the original id -- but read_head() is keyed by the id "
                "the database hands it, so re-minting the id detaches the log from its own "
                "anchor. Same root cause as event-rechain-then-cover: the comparison is by "
                "one identity and one row, and both are things the attacker can move.")
        return ("Deleting the genesis row is reported as unverifiable, and a forged "
                "replacement cannot buy a clean verification.",
                observed, passed, note)


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
        passed = after["status"] == sf_mcp.CORRELATION_OBSERVED and allowed
        note = ("NOT PREVENTED, and it is not meant to be. An empty file created by this "
                "uid moves the correlation from 'unknown' to 'observed' and opens the "
                "DESTRUCTIVE gate, because _session_recorded() is is_file() and nothing "
                "more. That is the documented design: the server runs with no more "
                "privilege than the agent it is gating, so it cannot hold evidence that "
                "agent cannot forge. What it buys is cost and a name -- the forged id is on "
                "the audit row, and the operator must also have set "
                "SHADOWFETCH_MCP_DESTRUCTIVE=allow, which the agent cannot do for itself. "
                "This is marked PASS for the next attack's reason, not this one's: the "
                "action succeeded, and the question that matters is what the system then "
                "CLAIMS about it.")
        return ("Forging the file succeeds -- this uid owns that directory -- and the "
                "system's own documentation says so rather than claiming the session was "
                "verified.",
                observed, passed, note)


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
        passed = (statuses == {sf_mcp.CORRELATION_OBSERVED} and checks_is_file
                  and not reads_content and not claims_verified
                  and traversal["status"] == sf_mcp.CORRELATION_MALFORMED
                  and as_directory == sf_mcp.CORRELATION_UNKNOWN)
        note = ("The claim matches the code. The word recorded is 'observed', the module's "
                "comment defines it as 'a Firebreak session record exists on disk under "
                "that id... weaker than the session is real', and _session_recorded() is "
                "exactly one is_file() call -- it reads nothing, so the file's CONTENTS are "
                "not evidence and are not treated as evidence. The permitted call's reason "
                "is 'DESTRUCTIVE call permitted', which says what was permitted and asserts "
                "nothing about the session. Two things fall out of the shape check rather "
                "than the file check: a path-traversal id is MALFORMED before any path is "
                "built from it, and a directory of the right name reads as UNKNOWN. What "
                "remains true and is not a defect to fix here: the correlation is worth "
                "what a file this uid can create is worth, which is the honest ceiling for "
                "a gate with the agent's own privileges.")
        return ("The system records the forged correlation as 'observed' and nothing "
                "anywhere upgrades that into a claim that the session is real.",
                observed, passed, note)


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
