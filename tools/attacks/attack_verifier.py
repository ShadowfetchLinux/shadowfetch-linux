#!/usr/bin/env python3
"""Attacks on the AUDIT VERIFIER itself.

The other suites attack the engine and read the verifier's answer as if it were
an oracle. This one treats the verifier as the target: every attack here is an
attempt to make `audit verify` say something that is not true -- to make it
report a tampered log intact, to make it excuse a fabricated row, to make it
accept an approval nobody granted, or to make its exit status disagree with its
own report.

WHAT IS BEING ATTACKED
   1. A mission row invented with SQL and no history at all.
   2. Deleting the chain genesis.
   3. Replacing the whole chain with a new, internally valid one.
   4. Altering one event and recomputing every hash after it.
   5. Truncating the tail.
   6. Appending a forged tail.
   7. Reordering events.
   8. Duplicating an event.
   9. Reattributing an event to another mission.
  10. Reattributing an event to another session.
  11. Forging approval provenance (granted_by / method / granted_at).
  12. Extending an approval's expiry.
  13. Deleting a revocation.
  14. Forging a journal head to cover a rewrite.
  15. Injecting journal messages as the mission uid.
  16. Removing the external anchor.
  17. Copying another chain's anchor.
  18. Restoring an old database against a newer anchor.
  19. Running a database past the anchor that witnessed it.
  20. Using --json to get a different exit status from the same report.
  21. Forging the v4 legacy pin. (Not on the assigned list: found while building
      attack 1, where the pin is the one thing standing between a fabricated
      mission row and a clean verification.)

THE THREAT MODEL
  A normal uid that can write the SQLite file and can write to /dev/log. That is
  the mission worker's own uid on a stock install, so nothing here needs root and
  nothing here is hypothetical. Root is explicitly out of scope: root can rewrite
  the journal, and sf_audit's docstring says so.

PASS AND FAIL
  PASS means the system detected the attack or refused it. FAIL means it did not,
  and a FAIL is reported as a finding about the system rather than quietly
  softened into an expectation the code happens to meet. The worst outcome an
  attack can reach is `audit verify` exiting 0 over a log that has been changed;
  where that happens the note says so in those words, and where it does not the
  note names the mechanism that stopped it. Neither sentence is written in
  advance -- see below.

WHY THERE IS NO FIXED PROSE IN THE NOTES
  attack_integrity.py hard-codes its notes, and several of them now describe
  defects Phase 3.1 has since fixed: prose written against one revision of a
  moving engine is stale the moment the engine moves, and a stale note in an
  adversarial report is worse than no note. Every sentence a note prints here is
  built from values measured in THAT run -- the verdict that came back, the
  problems list that came back, the exit code the CLI actually returned. Run it
  after a fix and the notes change with the system.

SIDE EFFECTS
  Every attack builds its own store under a fresh tempfile.mkdtemp() and
  new_store() refuses to touch anything outside it, so the operator's
  ~/.local/state is never opened. The one thing that leaves this process is the
  journald mirror: appending an event mirrors its head to the system journal,
  which is the anchor under test and cannot be faked away. Each store mints its
  own chain id and derives its own store identity from its own path, so those
  lines cannot be confused with the operator's. Attacks 14 and 15 deliberately
  write extra lines to the journal under their own throwaway chain ids.

  Attacks that need the anchor say so and report INCONCLUSIVE -- not PASS -- when
  this uid cannot read the journal, because a control that never ran has not
  passed.

HOW TO RUN IT
      python3 tools/attacks/attack_verifier.py     # table, exit 1 on any FAIL
  or  from attack_verifier import ATTACKS, run     # composed with the others
  It also runs from `make attacks`, which `make test` invokes.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import textwrap
import time
import uuid
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
MISSIONS_SRC = REPO / "packages/shadowfetch-missions/data/usr/lib/shadowfetch/missions"
MISSIONS_CLI = REPO / "packages/shadowfetch-missions/data/usr/bin/shadowfetch-missions"

if str(MISSIONS_SRC) not in sys.path:
    sys.path.insert(0, str(MISSIONS_SRC))

import sf_audit                      # noqa: E402
import sf_missions as sf             # noqa: E402
import sf_policy                     # noqa: E402


# --------------------------------------------------------------------------- #
# Throwaway state
# --------------------------------------------------------------------------- #
@contextlib.contextmanager
def throwaway():
    """A store root and a workspace root that exist only for one attack."""
    base = Path(tempfile.mkdtemp(prefix="sf-attack-verifier-"))
    saved = dict(os.environ)
    try:
        (base / "ws" / "probe").mkdir(parents=True)
        (base / "ws" / "probe" / "a.mkv").write_bytes(b"clip")
        os.environ.update({
            "SHADOWFETCH_AGENT_WORKSPACES": str(base / "ws"),
            "SHADOWFETCH_MISSIONS_STATE": str(base / "state"),
        })
        yield base
    finally:
        os.environ.clear()
        os.environ.update(saved)
        shutil.rmtree(base, ignore_errors=True)


def new_store(base, name="state"):
    """A Store under the throwaway base, and nowhere else.

    Mechanical, not a comment: if a refactor ever makes Store ignore the
    environment variable, this stops the module before it writes into the
    operator's audit log rather than after.
    """
    store = sf.Store(base / name) if name != "state" else sf.Store()
    assert base in store.root.parents, (
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
        # verifier, so the row is inserted the way create() would and the
        # creation edge's event is appended through the engine. Note that this
        # fallback writes the row and the event on two statements, which is the
        # shape create() was made atomic to avoid; it is a last resort and the
        # attacks that care say which path they got.
        mid = "mission-" + uuid.uuid4().hex[:16]
        stamp = sf.now()
        raw_sql(store.db_path,
                "INSERT INTO missions(id,title,kind,capability,provider_id,state,"
                "workspace,prompt,config,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (mid, "attack", "media", "media_export", "offline-media",
                 sf.MissionState.QUEUED,
                 str(Path(os.environ["SHADOWFETCH_AGENT_WORKSPACES"]) / "probe"),
                 "attack", json.dumps({"runtime": "offline", "inputs": ["a.mkv"]}),
                 stamp, stamp))
        store.event(mid, sf.MISSION_TRANSITIONS[(None, sf.MissionState.QUEUED)][0],
                    "created by the attack module", actor=sf.ACTOR_USER)
        return mid, f"raw INSERT (store.create() refused: {type(exc).__name__}: {exc})"


def reviewed_mission(store):
    """A mission the engine has driven to waiting-review, honestly.

    Four events: genesis, queued, running, waiting-review. Every attack that
    needs a plausible history starts here, so the story the attacker rewrites is
    one the engine really wrote.
    """
    mid, how = new_mission(store)
    store.transition(mid, sf.MissionState.RUNNING)
    store.transition(mid, sf.MissionState.WAITING_REVIEW)
    return mid, how


# --------------------------------------------------------------------------- #
# Reading and writing the store the way an attacker and an auditor both do
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


def event_rows(store):
    return rows(store.db_path, "SELECT * FROM events ORDER BY seq")


def rechain(db_path, edits=None):
    """Recompute prev_hash/hash for every chained row, applying `edits` first.

    The attacker's tool, written the way an attacker would write it: straight out
    of the engine's own event_hash(), because the algorithm ships in the source
    and there is nothing secret in it.
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
            db.execute("UPDATE events SET mission=?,at=?,event=?,detail=?,actor=?,"
                       "prev_hash=?,hash=? WHERE seq=?",
                       (row["mission"], row["at"], row["event"], row["detail"],
                        row["actor"], row["prev_hash"], row["hash"], row["seq"]))
            prev = row["hash"]
        db.commit()
    finally:
        db.close()


def append_raw(db_path, entries):
    """Append correctly chained rows straight into the events table.

    This is the whole of attack 6: _append() is not privileged, it is just code,
    and its hash input is public. Returns the sequence numbers written.
    """
    db = sqlite3.connect(db_path)
    db.row_factory = sqlite3.Row
    written = []
    try:
        head = db.execute("SELECT seq, hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()
        seq = head["seq"] if head else 0
        prev = head["hash"] if head and head["hash"] else sf.GENESIS_PREV
        for mission, event, detail, actor in entries:
            seq += 1
            row = {"seq": seq, "mission": mission, "at": sf.now(), "event": event,
                   "detail": detail, "task_id": None, "session_id": None,
                   "tool_execution_id": None, "actor": actor}
            row["hash"] = sf.event_hash(prev, row)
            db.execute(
                "INSERT INTO events(seq,mission,at,event,detail,task_id,session_id,"
                "tool_execution_id,actor,prev_hash,hash) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (seq, mission, row["at"], event, detail, None, None, None, actor,
                 prev, row["hash"]))
            prev = row["hash"]
            written.append(seq)
        db.commit()
    finally:
        db.close()
    return written


def copy_database(src_root, dst_dir):
    """Every file SQLite considers part of the database, not just the .sqlite3.

    A snapshot that leaves the -wal behind restores a database the attacker did
    not intend and would make attack 18 measure the wrong thing.
    """
    dst = Path(dst_dir)
    dst.mkdir(parents=True, exist_ok=True)
    for path in Path(src_root).glob("missions.sqlite3*"):
        shutil.copy2(path, dst / path.name)
    return sorted(p.name for p in dst.glob("missions.sqlite3*"))


def restore_database(snapshot_dir, dst_root):
    for path in Path(dst_root).glob("missions.sqlite3*"):
        path.unlink()
    for path in Path(snapshot_dir).glob("missions.sqlite3*"):
        shutil.copy2(path, Path(dst_root) / path.name)


# --------------------------------------------------------------------------- #
# The anchor
# --------------------------------------------------------------------------- #
def anchor(store):
    """What the journal can currently tell us about THIS store's chain."""
    return sf_audit.read_head(store.chain_id(), store=store.store_identity())


def anchor_is_readable(store):
    return anchor(store)["available"]


def settle(store, expect_seq, timeout=8.0):
    """Wait until the journal has caught up to `expect_seq`. Returns (seconds, head).

    Polled rather than slept: a fixed sleep is either too short on a loaded host
    -- which would report an honest lag as an attack -- or wasted time on an idle
    one. The wait is reported in the observation so a reader can see whether the
    anchor was current when the attack landed.
    """
    started = time.monotonic()
    head = None
    while time.monotonic() - started < timeout:
        head = anchor(store)["head_seq"]
        if head is not None and head >= expect_seq:
            break
        time.sleep(0.25)
    return round(time.monotonic() - started, 2), head


@contextlib.contextmanager
def blind_anchor():
    """Make the external anchor genuinely unreadable, without mocking it.

    PATH is emptied of journalctl, which is a real host condition sf_audit
    already names -- a container image, a minimal install. Patching read_head()
    would prove only that the code branches; removing the binary proves that the
    branch is the one such a host actually takes.
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


ANCHOR_BLINDED = False


def _cli_argv(args):
    """The command that runs the CLI, blinded if blind_anchor() is active.

    A subprocess resolves the real absolute journalctl, so an in-process patch
    of JOURNALCTL_PATHS never reached it and the child reported the anchor as
    readable. This carries the same patch into the child by importing the
    library and emptying the candidate list before main() runs. Deliberately NOT
    an environment variable the engine honours: that would hand an attacker back
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


# --------------------------------------------------------------------------- #
# Rendering what was measured
# --------------------------------------------------------------------------- #
INCONCLUSIVE = ("INCONCLUSIVE: this host's journal is not readable by this uid, so the "
                "control under test never ran. Reported as not-passed because an "
                "unexercised control is not a passing one.")

NEEDS_ANCHOR = "the journal is unreadable by this uid, so this attack was not run"


def lines(*parts):
    return "\n".join(str(p) for p in parts if p is not None)


def verdict(report):
    return (report.get("anchor") or {}).get("verdict")


def states_verdict(report):
    return (report.get("states") or {}).get("verdict")


def summary(label, report):
    """One line of everything the verifier claims, in the verifier's own words."""
    a = report.get("anchor") or {}
    return (f"{label}: ok={report['ok']} chain_ok={report.get('chain_ok')} "
            f"states={states_verdict(report)} anchor={verdict(report)!r} "
            f"journal_head={a.get('journal_head_seq')} db_head={a.get('database_head_seq')} "
            f"exit_code_for_this_report={sf.audit_exit_code(report)}")


def problems(report, limit=6):
    listed = report["problems"][:limit]
    if not listed:
        return "  problems: (none)"
    body = [f"  problem: {p}" for p in listed]
    if len(report["problems"]) > limit:
        body.append(f"  ... and {len(report['problems']) - limit} more")
    return "\n".join(body)


def chain_only_problems(report):
    """Problems the CHAIN raised on its own: nothing from the anchor, nothing
    from the state replay. What a host with no journal would still see."""
    return [p for p in report["problems"]
            if "journal" not in p and "mirror" not in p
            and not p.startswith("mission ")]


def objections(report):
    """Which of the three independent checks objected, as {name: problems}.

    Notes ask this rather than assuming it: the engine gains checks between
    runs, and a note that says "only the anchor caught this" is a claim about
    the code as it was the day the note was typed.
    """
    return {
        "the chain": chain_only_problems(report),
        "the state replay": [p for p in report["problems"] if p.startswith("mission ")],
        "the anchor": [p for p in report["problems"]
                       if "journal" in p or "mirror" in p],
    }


def who_objected(report):
    """'the anchor', or 'the chain and the state replay', or 'nothing'."""
    named = [name for name, found in objections(report).items() if found]
    if not named:
        return "nothing"
    if len(named) == 1:
        return named[0]
    return ", ".join(named[:-1]) + " and " + named[-1]


def undetected(report, exit_code):
    """The system said nothing was wrong. The only outcome worth its own word."""
    return report["ok"] and exit_code == 0


# --------------------------------------------------------------------------- #
# 1. A mission fabricated with SQL, with no history at all
# --------------------------------------------------------------------------- #
def mission_fabricated_no_history():
    with throwaway() as base:
        store = new_store(base)
        mid, how = reviewed_mission(store)
        fake = "mission-" + uuid.uuid4().hex[:16]
        raw_sql(store.db_path,
                "INSERT INTO missions(id,title,kind,capability,provider_id,state,"
                "workspace,prompt,config,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (fake, "work that never happened", "media", "media_export",
                 "offline-media", sf.MissionState.COMPLETED,
                 str(Path(os.environ["SHADOWFETCH_AGENT_WORKSPACES"]) / "probe"),
                 "attack", "{}", sf.now(), sf.now()))
        report = new_store(base).verify_chain()
        states = report["states"]
        klass = states["classes"].get(fake)
        exit_code, stdout, _ = cli("audit", "verify")
        state_line = next((l for l in stdout.splitlines()
                           if l.startswith("mission states")), "").strip()
        pinned = new_store(base).legacy_missions()

        observed = lines(
            f"an honest mission ({how}) was driven to waiting-review, then one row was "
            f"INSERTed straight into `missions` with state={sf.MissionState.COMPLETED!r} "
            "and no events at all",
            summary("verify_chain()", report),
            problems(report),
            f"  the fabricated mission is classified {klass!r}; "
            f"class counts {states.get('counts')}",
            f"  the chained legacy pin names {sorted(pinned) or 'nothing'}",
            f"`audit verify` exit {exit_code}; {state_line!r}")
        passed = (not report["ok"] and klass == sf.CLASS_MISSING and exit_code != 0)
        note = (
            f"Held. The row was classified {klass!r} rather than excused, and the "
            f"CLI exited {exit_code}. What makes that possible is that the exemption is now "
            f"a positive chained fact: legacy_missions() returned {sorted(pinned) or 'an empty set'} "
            "for this database, so 'no events' is not a story the row can tell about "
            "itself. Attack 21 asks what happens when the attacker writes that pin."
            if passed else
            f"FINDING. The fabricated row was classified {klass!r}, verify reported "
            f"ok={report['ok']}, and `audit verify` exited {exit_code}. A mission that "
            "never ran is being reported as work that did.")
        return ("A mission row with no history was written by something other than the "
                "engine -- creation and its first event commit in one transaction -- so "
                "verification must name it rather than excuse it.",
                observed, passed, note)


# --------------------------------------------------------------------------- #
# 2. Delete the chain genesis
# --------------------------------------------------------------------------- #
def chain_genesis_deleted():
    with throwaway() as base:
        store = new_store(base)
        reviewed_mission(store)
        before = store.verify_chain()
        deleted = raw_sql(store.db_path, "DELETE FROM events WHERE event=?",
                          (sf.CHAIN_GENESIS,))
        # A fresh Store: an operator running `audit verify` gets a fresh process,
        # and the chain id is cached per instance.
        after_store = new_store(base)
        report = after_store.verify_chain()
        exit_code, stdout, _ = cli("audit", "verify")
        chain_line = next((l for l in stdout.splitlines() if l.startswith("chain")), "").strip()

        observed = lines(
            summary("before", before),
            f"DELETE FROM events WHERE event='{sf.CHAIN_GENESIS}' removed {deleted} row(s)",
            f"chain_id() is now {after_store.chain_id()!r}",
            summary("after", report),
            problems(report),
            f"  problems the chain raised without the anchor: {len(chain_only_problems(report))}",
            f"`audit verify` exit {exit_code}; {chain_line!r}")
        passed = (not report["ok"] and exit_code != 0
                  and any("genesis" in p for p in report["problems"]))
        note = (
            f"Held, and held without the anchor: {len(chain_only_problems(report))} of the "
            f"{len(report['problems'])} problems came from the chain alone, so this is "
            f"caught on a host with no journal too. The anchor verdict is "
            f"{verdict(report)!r} because chain_id() is {after_store.chain_id()!r} -- "
            "the id lives in the row that was deleted, so the log can no longer say "
            "which journal history is its own. Exit "
            f"{exit_code}, and nothing anywhere claimed the log was intact."
            if passed else
            f"FINDING. Deleting the genesis left verify at ok={report['ok']} with exit "
            f"{exit_code}; problems: {report['problems']}")
        return ("Every surviving row carries a hash that starts from a genesis that is no "
                "longer there, so verification reports that nothing is verifiable.",
                observed, passed, note)


# --------------------------------------------------------------------------- #
# 3. Replace the chain with a new, internally valid one
# --------------------------------------------------------------------------- #
def chain_replaced_wholesale():
    with throwaway() as base:
        store = new_store(base)
        if not anchor_is_readable(store):
            return ("A re-minted chain is reported as a re-mint.", NEEDS_ANCHOR,
                    False, INCONCLUSIVE)
        mid, _ = reviewed_mission(store)
        honest = store.verify_chain()
        waited, journal_head = settle(store, honest["head_seq"])
        original_chain = store.chain_id()

        # The attack: throw the log away and write one that says the mission was
        # reviewed and accepted, under a chain id of the attacker's own minting.
        raw_sql(store.db_path, "UPDATE missions SET state=? WHERE id=?",
                (sf.MissionState.COMPLETED, mid))
        raw_sql(store.db_path, "DELETE FROM events")
        forged_chain = uuid.uuid4().hex
        append_raw(store.db_path, [
            ("*", sf.CHAIN_GENESIS, json.dumps(
                {"chain_id": forged_chain, "from_schema_version": None,
                 "to_schema_version": sf.SCHEMA_VERSION, "unchained_events": 0,
                 "unchained_digest": "0" * 64,
                 "note": "forged by the attack module"}, sort_keys=True),
             sf.ACTOR_ORCHESTRATOR),
            (mid, "queued", "media_export via offline-media", sf.ACTOR_USER),
            (mid, "running", "the worker claimed a queued mission", sf.ACTOR_ORCHESTRATOR),
            (mid, "waiting-review", "execution finished", sf.ACTOR_ORCHESTRATOR),
            (mid, "completed", "a human accepted the work", sf.ACTOR_USER),
        ])
        after_store = new_store(base)
        report = after_store.verify_chain()
        exit_code, stdout, _ = cli("audit", "verify")
        chain_line = next((l for l in stdout.splitlines() if l.startswith("chain")), "").strip()
        others = (report["anchor"] or {}).get("other_chains_for_this_store")

        observed = lines(
            f"honest log had {honest['events']} events under chain {original_chain[:12]} "
            f"(journal caught up to seq {journal_head} in {waited}s)",
            "the whole events table was deleted and rebuilt as five rows telling a "
            f"different story -- the mission now reads {sf.MissionState.COMPLETED!r} -- "
            f"under a new chain id {forged_chain[:12]}",
            summary("after", report),
            problems(report),
            f"  chain ids this store has mirrored before and no longer claims: {others}",
            f"  states verdict: {states_verdict(report)} "
            f"(the rebuilt log is internally consistent with the row it rewrote)",
            f"`audit verify` exit {exit_code}; {chain_line!r}")
        passed = not report["ok"] and exit_code != 0 and bool(others)
        note = (
            f"Held; {who_objected(report)} objected. The rebuilt log is internally "
            f"perfect on its own terms: states verdict is {states_verdict(report)!r} and "
            f"the rows chain cleanly (chain-level problems: "
            f"{objections(report)['the chain'] or 'none'}), so an auditor with the "
            "database alone sees nothing. What gives it "
            f"away is outside the database -- this store has mirrored {others} under its "
            "own path-derived identity, and a chain id is minted once at genesis, so a "
            f"second one is a re-mint. Exit {exit_code}."
            if passed else
            f"FINDING. A wholesale rebuild verified at ok={report['ok']} with exit "
            f"{exit_code}. other_chains_for_this_store={others}; problems={report['problems']}")
        return ("A chain id is minted once, so a database presenting a second one for the "
                "same store has been re-minted, and verification says so rather than "
                "reporting an absence of history.",
                observed, passed, note)


# --------------------------------------------------------------------------- #
# 4. Alter an event and recompute every hash after it
# --------------------------------------------------------------------------- #
def event_altered_and_rechained():
    with throwaway() as base:
        store = new_store(base)
        if not anchor_is_readable(store):
            return ("A rewritten row is caught by the hash the journal already holds.",
                    NEEDS_ANCHOR, False, INCONCLUSIVE)
        mid, _ = reviewed_mission(store)
        clean = store.verify_chain()
        waited, journal_head = settle(store, clean["head_seq"])
        victim = 3
        was = rows(store.db_path, "SELECT detail,hash FROM events WHERE seq=?", (victim,))[0]
        mirrored_before = anchor(store)["heads"].get(victim)

        rechain(store.db_path, {victim: {"detail": "REWRITTEN BY THE ATTACKER"}})
        report = new_store(base).verify_chain()
        now_stored = rows(store.db_path, "SELECT detail,hash FROM events WHERE seq=?",
                          (victim,))[0]
        exit_code, _, _ = cli("audit", "verify")
        rewritten = (report["anchor"] or {}).get("rewritten_seqs")

        observed = lines(
            summary("before", clean) + f" (journal caught up in {waited}s at seq {journal_head})",
            f"seq {victim} detail {was['detail'][:40]!r} -> {now_stored['detail']!r}, and "
            "every row from there on re-chained with the engine's own event_hash()",
            f"  hash of seq {victim}: {str(was['hash'])[:16]} -> {str(now_stored['hash'])[:16]}",
            f"  the journal still holds {str(mirrored_before)[:16]} for seq {victim}",
            summary("after", report),
            problems(report),
            f"  rewritten_seqs: {rewritten}",
            f"`audit verify` exit {exit_code}")
        passed = not report["ok"] and exit_code != 0 and victim in (rewritten or [])
        note = (
            f"Held; {who_objected(report)} objected. The re-chain leaves the chain itself "
            f"with {objections(report)['the chain'] or 'nothing to find'} -- the attacker "
            "used the shipped hash function and the rows agree with each other -- and the "
            f"catch is per-seq: the journal's line for seq {victim} still "
            f"carries {str(mirrored_before)[:16]} while the database now carries "
            f"{str(now_stored['hash'])[:16]}. rewritten_seqs={rewritten}, exit {exit_code}. "
            "Comparing only the head would have missed everything but the last row."
            if passed else
            f"FINDING. A rewritten row survived verification: ok={report['ok']}, exit "
            f"{exit_code}, rewritten_seqs={rewritten}, problems={report['problems']}")
        return ("The journal recorded that row's hash and this uid cannot rewrite the "
                "journal, so a rewrite is detected however far back in the log it is.",
                observed, passed, note)


# --------------------------------------------------------------------------- #
# 5. Truncate the tail
# --------------------------------------------------------------------------- #
def chain_tail_truncated():
    with throwaway() as base:
        store = new_store(base)
        if not anchor_is_readable(store):
            return ("Truncation is detected against the journal's high-water mark.",
                    NEEDS_ANCHOR, False, INCONCLUSIVE)
        mid, _ = reviewed_mission(store)
        for i in range(3):
            store.append_event(mid, "probe", f"payload-{i}")
        before = store.verify_chain()
        waited, journal_head = settle(store, before["head_seq"])
        head = before["head_seq"]
        removed = raw_sql(store.db_path, "DELETE FROM events WHERE seq > ?", (head - 3,))
        report = new_store(base).verify_chain()
        exit_code, stdout, _ = cli("audit", "verify")
        chain_line = next((l for l in stdout.splitlines() if l.startswith("chain")), "").strip()
        chain_only = chain_only_problems(report)

        observed = lines(
            summary("before", before) + f" (journal caught up in {waited}s at seq {journal_head})",
            f"DELETE FROM events WHERE seq > {head - 3} removed {removed} row(s)",
            summary("after", report),
            problems(report),
            f"  problems the chain raised on its own: {chain_only}",
            f"`audit verify` exit {exit_code}; {chain_line!r}")
        passed = (not report["ok"] and verdict(report) == "truncated" and exit_code == 1)
        note = (
            f"Held; {who_objected(report)} objected. The chain raised {len(chain_only)} "
            "problem(s) of its own, because every surviving row still verifies against its "
            "predecessor -- that is what a hash chain is. The journal's high-water mark "
            f"({journal_head}) exceeding the database's ({report['head_seq']}) is the whole "
            "detection, and the count in the message is the real one."
            + (f" Worth the lead's eye and not a fail: the CLI printed {chain_line!r} "
               f"while the chain's own problems were {chain_only} -- report['chain_ok'] is "
               "copied from report['ok'] after the anchor section has already set it, so "
               "an anchor finding is printed as a broken chain. The finding is right; the "
               "label on it points at the wrong half of the report."
               if "BROKEN" in chain_line and not chain_only else "")
            if passed else
            f"FINDING. {removed} rows were removed from the end and verify reported "
            f"ok={report['ok']} verdict={verdict(report)!r} exit {exit_code}.")
        return ("The journal's high-water mark exceeds the database's, so verification "
                "reports the removal, names how many rows went, and the CLI exits 1.",
                observed, passed, note)


# --------------------------------------------------------------------------- #
# 6. Append a forged tail
# --------------------------------------------------------------------------- #
def _unmirrored(store, report=None):
    """(seqs the database holds that the journal has no line for, with their
    event names). Computed from the journal's own per-seq map, so it says which
    rows nothing outside this database ever witnessed."""
    heads = set(anchor(store)["heads"])
    return [(row["seq"], row["event"]) for row in event_rows(store)
            if row["seq"] not in heads]


def chain_tail_forged():
    with throwaway() as base:
        store = new_store(base)
        if not anchor_is_readable(store):
            return ("A tail the anchor never witnessed is not accepted as history.",
                    NEEDS_ANCHOR, False, INCONCLUSIVE)
        mid, _ = reviewed_mission(store)
        before = store.verify_chain()
        waited, journal_head = settle(store, before["head_seq"])
        # The honest baseline FIRST: which rows does this engine append without
        # mirroring? Anything proposed as a coverage check has to survive these.
        baseline_unmirrored = _unmirrored(store)
        bookmark_before = store.mirror_state().get("last_mirrored_seq")

        # The forgery: the mission was never reviewed. Say a human accepted it,
        # in a row that chains correctly onto the honest head, and move the
        # mission row to match so the state replay agrees too.
        forged = append_raw(store.db_path, [
            (mid, "completed", "a human accepted the work", sf.ACTOR_USER)])[0]
        raw_sql(store.db_path, "UPDATE missions SET state=? WHERE id=?",
                (sf.MissionState.COMPLETED, mid))
        first = new_store(base).verify_chain()
        first_exit, _, _ = cli("audit", "verify")

        # Then one honest engine append. It changes nothing about the forged row
        # -- it just moves the mirror's high-water mark past it.
        cover_store = new_store(base)
        cover = cover_store.append_event(mid, "probe", "one honest event after the forgery")
        waited2, journal_head2 = settle(cover_store, cover["seq"])
        bookmark_after = cover_store.mirror_state().get("last_mirrored_seq")
        second = new_store(base).verify_chain()
        second_exit, second_out, _ = cli("audit", "verify")
        after_unmirrored = _unmirrored(cover_store)
        printed = [l.strip() for l in second_out.splitlines()
                   if l.startswith(("chain", "mission states", "external", "head", "PROBLEM"))]

        observed = lines(
            summary("before", before) + f" (journal caught up in {waited}s at seq {journal_head})",
            f"  rows this engine appended and did NOT mirror, before any attack: "
            f"{baseline_unmirrored or 'none'}",
            f"  the mirror's local bookmark (audit-mirror.json last_mirrored_seq): "
            f"{bookmark_before}",
            f"one row appended straight into `events` at seq {forged}, chained with the "
            f"engine's own event_hash(), claiming {mid} was accepted by a human; the "
            "missions row was moved to match",
            summary("after the forgery", first),
            problems(first),
            f"`audit verify` exit {first_exit}",
            f"then ONE honest append_event() through the engine (seq {cover['seq']}, "
            f"journal caught up in {waited2}s at seq {journal_head2}); the bookmark moves "
            f"{bookmark_before} -> {bookmark_after}:",
            summary("  after the cover", second),
            problems(second),
            f"  database seqs: {[r['seq'] for r in event_rows(cover_store)]}",
            f"  journal seqs:  {sorted(anchor(cover_store)['heads'])}",
            f"  rows with no journal line of their own, with their event names: "
            f"{after_unmirrored or 'none'}",
            f"`audit verify` exit {second_exit}; printed: {printed}")
        first_held = not undetected(first, first_exit)
        second_held = not undetected(second, second_exit)
        passed = first_held and second_held
        forged_row = [name for seq, name in after_unmirrored if seq == forged]
        note = (
            ("FINDING, and the worst outcome available: the log says a human accepted work "
             f"that was never reviewed and `audit verify` exits {second_exit} with "
             f"ok={second['ok']}, {printed}. " if not second_held else "")
            + ("The forgery IS caught at the moment it lands -- "
               f"{first['problems']} -- and the check that catches it is anchored to the "
               "mirror's local bookmark, which is a high-water mark: it asks what lies "
               f"AFTER seq {bookmark_before}, not which rows were witnessed. One honest "
               f"append moves that mark to {bookmark_after}, the forged row falls below "
               "it, and it is never looked at again. "
               if first_held and not second_held else "")
            + (f"The evidence is still in hand: the journal holds "
               f"{sorted(anchor(cover_store)['heads'])} while the database holds "
               f"{[r['seq'] for r in event_rows(cover_store)]}, so seq {forged} "
               f"({forged_row[0] if forged_row else 'the forged row'}) has no line of its "
               "own. Comparing COVERAGE rather than a high-water mark closes it with the "
               "same read_head() result already in hand -- but note what the honest "
               f"baseline above measured before anything was attacked: "
               f"{baseline_unmirrored or 'no unmirrored rows'}. "
               + ("Those rows were appended by the engine and never mirrored, so a "
                  "coverage check has to except them by name or the engine has to mirror "
                  "them; a naive 'every unwitnessed seq is a forgery' rule would fail on a "
                  "fresh install."
                  if baseline_unmirrored else
                  "Every row this engine appended was mirrored, so a coverage check would "
                  "have no false positives to except on a fresh install.")
               if not second_held else "")
            + (f"Held at both stages, and by two different questions. As it lands, the "
               f"forged row is past everything the mirror recorded writing (bookmark "
               f"{bookmark_before}) and the tail check names it: {first['problems']}. After "
               f"the cover the bookmark has moved to {bookmark_after} and that question no "
               "longer reaches the row -- what does is coverage: the journal holds "
               f"{sorted(anchor(cover_store)['heads'])} and the database holds "
               f"{[r['seq'] for r in event_rows(cover_store)]}, so "
               f"{after_unmirrored} was never witnessed although the journal has neighbours "
               f"on both sides of it. Exits {first_exit} then {second_exit}. The honest "
               f"baseline measured before the attack was {baseline_unmirrored or 'clean'}, "
               + ("so the coverage question has no false positive to except on a fresh "
                  "install."
                  if not baseline_unmirrored else
                  "so rows the engine itself does not mirror exist and a coverage check "
                  "has to account for them.")
               if first_held and second_held else "")
            + (f"Held, but only after the cover: as the forged row landed, verify reported "
               f"ok={first['ok']} at exit {first_exit} with {first['problems']}, and what "
               f"objected afterwards was {second['problems']}. A window in which a forged "
               "row verifies clean is a window an attacker can arrange to be inside."
               if second_held and not first_held else "")
        )
        return ("The engine mirrors every event it appends, so a row the journal never "
                "witnessed was not appended by the engine -- and one later honest append "
                "must not make that row unexaminable.",
                observed, passed, note)


# --------------------------------------------------------------------------- #
# 7. Reorder events
# --------------------------------------------------------------------------- #
def events_reordered():
    with throwaway() as base:
        store = new_store(base)
        mid, _ = reviewed_mission(store)
        a, b = 3, 4
        row_a = rows(store.db_path, "SELECT * FROM events WHERE seq=?", (a,))[0]
        row_b = rows(store.db_path, "SELECT * FROM events WHERE seq=?", (b,))[0]
        # Swap the CONTENT of two rows, leaving the hashes where they were: the
        # cheap reorder, which is what an attacker tries first.
        raw_sql(store.db_path, "UPDATE events SET event=?,detail=?,at=? WHERE seq=?",
                (row_b["event"], row_b["detail"], row_b["at"], a))
        raw_sql(store.db_path, "UPDATE events SET event=?,detail=?,at=? WHERE seq=?",
                (row_a["event"], row_a["detail"], row_a["at"], b))
        naive = new_store(base).verify_chain()
        naive_exit, _, _ = cli("audit", "verify")

        # And the expensive one: swap, then re-chain, so the rows agree again.
        rechain(store.db_path)
        rechained = new_store(base).verify_chain()
        rechained_exit, _, _ = cli("audit", "verify")

        observed = lines(
            f"seq {a} carried {row_a['event']!r} and seq {b} carried {row_b['event']!r}; "
            "their contents were swapped",
            summary("swapped, hashes untouched", naive),
            problems(naive),
            f"`audit verify` exit {naive_exit}",
            "then re-chained so every row agrees with its neighbour again:",
            summary("  swapped and re-chained", rechained),
            problems(rechained),
            f"  rewritten_seqs: {(rechained['anchor'] or {}).get('rewritten_seqs')}",
            f"  states verdict: {states_verdict(rechained)}",
            f"`audit verify` exit {rechained_exit}")
        passed = (not naive["ok"] and naive_exit != 0
                  and not rechained["ok"] and rechained_exit != 0)
        note = (
            "Held twice, by two independent mechanisms. Untouched hashes: the swapped rows "
            f"no longer hash to what they store ({len(chain_only_problems(naive))} chain-level "
            "problems). Re-chained: the rows agree with each other again, and the catch "
            f"moves to the replay -- states verdict {states_verdict(rechained)!r} -- because "
            "a reorder produces an edge the transition table forbids, and to the anchor, "
            f"which holds the pre-swap hashes for seq(s) "
            f"{(rechained['anchor'] or {}).get('rewritten_seqs')}. A reorder is the one "
            "tamper that cannot hide behind a correct re-chain: the ORDER is the content."
            if passed else
            f"FINDING. naive swap: ok={naive['ok']} exit {naive_exit}. re-chained swap: "
            f"ok={rechained['ok']} exit {rechained_exit}, problems={rechained['problems']}")
        return ("Reordering two events is detected whether or not the attacker re-chains "
                "afterwards, because the order is part of what each row commits to.",
                observed, passed, note)


# --------------------------------------------------------------------------- #
# 8. Duplicate an event
# --------------------------------------------------------------------------- #
def event_duplicated():
    with throwaway() as base:
        store = new_store(base)
        mid, _ = reviewed_mission(store)
        victim = rows(store.db_path, "SELECT * FROM events WHERE seq=3")[0]
        try:
            raw_sql(store.db_path,
                    "INSERT INTO events(seq,mission,at,event,detail,task_id,session_id,"
                    "tool_execution_id,actor,prev_hash,hash) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (victim["seq"], victim["mission"], victim["at"], victim["event"],
                     victim["detail"], None, None, None, victim["actor"],
                     victim["prev_hash"], victim["hash"]))
            in_place = "ACCEPTED"
        except Exception as exc:                                   # noqa: BLE001
            in_place = f"{type(exc).__name__}: {exc}"
        after_in_place = new_store(base).verify_chain()

        # The version that does not need a free sequence number: replay the same
        # event at the end, correctly chained.
        replayed = append_raw(store.db_path, [
            (victim["mission"], victim["event"], victim["detail"], victim["actor"])])[0]
        report = new_store(base).verify_chain()
        exit_code, _, _ = cli("audit", "verify")
        replay_said = [p for p in report["problems"] if p.startswith("mission ")]
        anchor_said = [p for p in report["problems"]
                       if "journal" in p or "mirror" in p]

        observed = lines(
            f"INSERT a second row claiming seq {victim['seq']} -> {in_place}",
            summary("  after that attempt", after_in_place),
            f"replaying event {victim['event']!r} at the tail (seq {replayed}), correctly "
            "chained onto the honest head:",
            summary("  after the replay", report),
            problems(report),
            f"  states classes: {report['states'].get('classes')}",
            f"  objections from the state replay: {replay_said}",
            f"  objections from the anchor: {anchor_said}",
            f"  objections from the chain alone: {chain_only_problems(report)}",
            f"`audit verify` exit {exit_code}")
        passed = ("IntegrityError" in in_place and not report["ok"] and exit_code != 0)
        note = (
            f"Held. In place: seq is the INTEGER PRIMARY KEY, so the storage engine itself "
            f"refuses a second row claiming it ({in_place.split(':')[0]}) -- forging history "
            "in place is not available, only rewriting it, which attack 4 covers. Replayed "
            "at the tail: the chain hashes fine, because the attacker can hash, and what "
            "objected in this run was "
            + (" and ".join(
                part for part in (
                    (f"the state replay ({report['states'].get('classes')})"
                     if replay_said else None),
                    (f"the anchor ({anchor_said[0][:110]}...)" if anchor_said else None),
                    (f"the chain ({chain_only_problems(report)})"
                     if chain_only_problems(report) else None)) if part) or "nothing")
            + ". Those are independent questions and it is worth keeping them apart: the "
            "replay objects to what the row SAYS, the anchor to the fact that nothing "
            "outside the database witnessed it. A duplicate of an event that records no "
            "state change says nothing the replay can object to, and would rest on the "
            "anchor alone -- which is attack 6's question."
            if passed else
            f"FINDING. duplicate in place -> {in_place}; replayed at the tail -> "
            f"ok={report['ok']} exit {exit_code} problems={report['problems']}")
        return ("A duplicated event cannot take a sequence number that is already used, "
                "and a replay appended at the end is reported rather than accepted.",
                observed, passed, note)


# --------------------------------------------------------------------------- #
# 9. Change the mission an event belongs to
# --------------------------------------------------------------------------- #
def event_mission_reattributed():
    with throwaway() as base:
        store = new_store(base)
        mid, _ = reviewed_mission(store)
        elsewhere = "mission-" + uuid.uuid4().hex[:16]
        raw_sql(store.db_path, "UPDATE events SET mission=? WHERE seq=?", (elsewhere, 3))
        naive = new_store(base).verify_chain()
        naive_exit, _, _ = cli("audit", "verify")
        rechain(store.db_path)
        rechained = new_store(base).verify_chain()
        rechained_exit, _, _ = cli("audit", "verify")

        observed = lines(
            f"UPDATE events SET mission='{elsewhere}' WHERE seq=3 "
            f"(the event belonged to {mid})",
            summary("hashes untouched", naive),
            problems(naive),
            f"`audit verify` exit {naive_exit}",
            "then re-chained:",
            summary("  re-chained", rechained),
            problems(rechained),
            f"  states classes: {rechained['states'].get('classes')}",
            f"  rewritten_seqs: {(rechained['anchor'] or {}).get('rewritten_seqs')}",
            f"`audit verify` exit {rechained_exit}")
        passed = (not naive["ok"] and naive_exit != 0
                  and not rechained["ok"] and rechained_exit != 0)
        note = (
            "Held. `mission` is inside HASHED_FIELDS, so moving an event to another "
            f"mission breaks its hash ({len(chain_only_problems(naive))} chain-level problem(s)). "
            "After a re-chain the hashes agree again and two other things object: the "
            f"replay of the mission the event was taken FROM ({states_verdict(rechained)}), "
            "because its trail now has a hole, and the anchor's per-seq hashes for "
            f"{(rechained['anchor'] or {}).get('rewritten_seqs')}. Reattribution is not a "
            "quiet edit: it damages two missions' histories at once."
            if passed else
            f"FINDING. naive: ok={naive['ok']} exit {naive_exit}; re-chained: "
            f"ok={rechained['ok']} exit {rechained_exit} problems={rechained['problems']}")
        return ("The mission an event belongs to is part of what the event's hash commits "
                "to, so moving it is detected -- and after a re-chain the state replay and "
                "the anchor still object.",
                observed, passed, note)


# --------------------------------------------------------------------------- #
# 10. Move an event between sessions
# --------------------------------------------------------------------------- #
def event_session_reattributed():
    with throwaway() as base:
        store = new_store(base)
        mid, _ = reviewed_mission(store)
        # A correlation column that is NULL on most rows: the quiet place to
        # hide a reattribution, if any column were outside the hash.
        tagged = store.append_event(mid, "probe", "work done in a session",
                                    session_id="sess-honest")
        columns = [r["name"] for r in rows(store.db_path, "PRAGMA table_info(events)")]
        outside = [c for c in columns
                   if c not in sf.HASHED_FIELDS and c not in ("prev_hash", "hash")]
        raw_sql(store.db_path, "UPDATE events SET session_id=? WHERE seq=?",
                ("sess-somebody-elses", tagged["seq"]))
        naive = new_store(base).verify_chain()
        naive_exit, _, _ = cli("audit", "verify")
        rechain(store.db_path)
        rechained = new_store(base).verify_chain()
        rechained_exit, _, _ = cli("audit", "verify")
        # Measured, not assumed: if every remaining objection came from the
        # anchor, then a host with no journal sees nothing here.
        left_to_the_anchor = not chain_only_problems(rechained) \
            and states_verdict(rechained) == "agrees"

        observed = lines(
            f"events columns: {columns}",
            f"columns that are neither hashed nor chain metadata: {outside}",
            f"seq {tagged['seq']} moved from session 'sess-honest' to 'sess-somebody-elses'",
            summary("hashes untouched", naive),
            problems(naive),
            f"`audit verify` exit {naive_exit}",
            "then re-chained (note: rechain() rewrites the hash but NOT session_id, so "
            "this measures whether the anchor still holds the pre-move hash):",
            summary("  re-chained", rechained),
            problems(rechained),
            f"  rewritten_seqs: {(rechained['anchor'] or {}).get('rewritten_seqs')}",
            f"  states verdict: {states_verdict(rechained)} "
            "(a session move changes no mission state, so the replay has nothing to say)",
            f"  problems the chain raised on its own: {chain_only_problems(rechained)}",
            f"`audit verify` exit {rechained_exit}")
        passed = (not outside and not naive["ok"] and naive_exit != 0
                  and not rechained["ok"] and rechained_exit != 0)
        note = (
            f"Held. There is no events column outside the hash ({outside or 'none'}), "
            "including the three correlation columns that are NULL on most rows and would "
            "be the quiet place to hide a reattribution, so the naive move breaks the hash "
            f"outright. After a re-chain the state replay says {states_verdict(rechained)!r} "
            "-- correctly, a session move is not a state change -- and the thing left "
            "objecting is the anchor's per-seq comparison at "
            f"{(rechained['anchor'] or {}).get('rewritten_seqs')}. "
            + ("Measured in this run: after the re-chain the chain raised no problem of "
               "its own and the replay agreed, so on a host with no readable journal this "
               "attack would land silently -- which is the anchor's job, and why attacks "
               "5, 6 and 16 measure the anchor separately."
               if left_to_the_anchor else
               "In this run the chain and the replay also objected after the re-chain, so "
               "the anchor was not the only thing standing here: "
               f"{chain_only_problems(rechained)}")
            if passed else
            f"FINDING. columns outside the hash: {outside}. naive: ok={naive['ok']} exit "
            f"{naive_exit}; re-chained: ok={rechained['ok']} exit {rechained_exit}")
        return ("Session attribution is part of the event's hash, so moving an event "
                "between sessions is detected rather than absorbed.",
                observed, passed, note)


# --------------------------------------------------------------------------- #
# Approvals: 11, 12, 13
# --------------------------------------------------------------------------- #
def _approved_mission(store, *, expires_at="2099-01-01T00:00:00+00:00"):
    """A mission with a real approval, and the scope a run of it would require.

    The scope is derived from THIS mission's workspace: an earlier probe reused
    one scope across fresh temp workspaces and refused everything for the wrong
    reason, which proves nothing.
    """
    mid, _ = new_mission(store)
    subject = "mission:" + mid
    scope = {"provider": "offline-media", "capability": "media_export",
             "workspace": store.get(mid)["workspace"], "network": "none"}
    aid = store.grant_approval(subject=subject, scope=scope, granted_by="the-owner",
                               method="cli", expires_at=expires_at,
                               reason="approved for this attack")
    return mid, subject, aid, sf_policy.Scope.from_json(scope)


def _approval_control(store, subject, required):
    row, why = store.find_approval(subject, required)
    return ("ACCEPTED, as it should be" if row else f"REFUSED -- broken probe: {why}"), row


def approval_provenance_forged():
    with throwaway() as base:
        store = new_store(base)
        mid, subject, aid, required = _approved_mission(store)
        control, row = _approval_control(store, subject, required)
        if row is None:
            return ("Forged provenance is refused.", f"control failed: {control}", False,
                    "INCONCLUSIVE: the untouched approval was refused, so nothing this "
                    "attack measured afterwards would mean anything.")
        edits = [
            ("granted_by", "UPDATE approvals SET granted_by='somebody-else' WHERE id=?"),
            ("method", "UPDATE approvals SET method='forged' WHERE id=?"),
            ("granted_at", "UPDATE approvals SET granted_at='1999-01-01T00:00:00+00:00' WHERE id=?"),
            ("reason", "UPDATE approvals SET reason='a different justification' WHERE id=?"),
        ]
        results, accepted = [], []
        for label, statement in edits:
            original = rows(store.db_path, "SELECT * FROM approvals WHERE id=?", (aid,))[0]
            raw_sql(store.db_path, statement, (aid,))
            found, why = store.find_approval(subject, required)
            results.append(f"  {label:<11} -> "
                           + ("ACCEPTED -- undetected" if found else f"REFUSED: {why}"))
            if found:
                accepted.append(label)
            raw_sql(store.db_path, f"UPDATE approvals SET {label}=? WHERE id=?",
                    (original[label], aid))

        # And the version that edits both sides: the row AND the chained witness
        # that is supposed to contradict it.
        witness_seq = rows(store.db_path,
                           "SELECT seq FROM events WHERE event='approval-granted' "
                           "ORDER BY seq LIMIT 1")[0]["seq"]
        raw_sql(store.db_path, "UPDATE approvals SET granted_by=? WHERE id=?",
                ("somebody-else", aid))
        forged_row = rows(store.db_path, "SELECT * FROM approvals WHERE id=?", (aid,))[0]
        witnessed = {"approval": aid, "subject": forged_row["subject"],
                     "granted_by": forged_row["granted_by"], "method": forged_row["method"],
                     "granted_at": forged_row["granted_at"],
                     "expires_at": forged_row["expires_at"], "reason": forged_row["reason"],
                     "scope_sha256": hashlib.sha256(
                         forged_row["scope"].encode("utf-8")).hexdigest()}
        forged_detail = json.dumps(
            dict(witnessed, record_sha256=store.approval_digest(witnessed)), sort_keys=True)
        rechain(store.db_path, {witness_seq: {"detail": forged_detail}})
        both, both_why = store.find_approval(subject, required)
        report = new_store(base).verify_chain()
        exit_code, _, _ = cli("audit", "verify")

        observed = lines(
            f"control (untouched approval {aid}): {control}",
            "one field of the approvals row at a time, then restored:",
            *results,
            f"then BOTH sides edited: granted_by forged in the row AND the chained "
            f"approval-granted event at seq {witness_seq} rewritten to match, everything "
            "re-chained:",
            f"  find_approval() -> "
            + ("ACCEPTED -- the approval check itself is defeated"
               if both else f"REFUSED: {both_why}"),
            summary("  verify_chain()", report),
            problems(report),
            f"  rewritten_seqs: {(report['anchor'] or {}).get('rewritten_seqs')}",
            f"`audit verify` exit {exit_code}")
        passed = not accepted and not report["ok"] and exit_code != 0
        note = (
            "Held on both levels, and they are different levels. Editing the row alone is "
            "refused at USE time, by one digest over every witnessed field rather than a "
            "field list at the comparison site -- so granted_by, method, granted_at and "
            "reason are covered by the same computation that wrote them. Editing the "
            f"chained witness to match does defeat that check ({'find_approval accepted it' if both else 'find_approval still refused it'}), "
            "which is the honest boundary: the witness is a row in the events table and "
            "the attacker can write that table. What stops it there is the audit chain, "
            f"not the approval logic -- rewritten_seqs="
            f"{(report['anchor'] or {}).get('rewritten_seqs')}, exit {exit_code}. Two "
            "independent controls, and the receipt of a mission run under this approval "
            "would print provenance the audit already contradicts."
            if passed else
            f"FINDING. fields accepted after being rewritten: {accepted or 'none'}; "
            f"both-sides forgery accepted: {bool(both)}; verify ok={report['ok']} "
            f"exit {exit_code}")
        return ("An approval's provenance is part of what was witnessed at grant time, so "
                "rewriting who granted it, how, when or why is refused when it is used -- "
                "and rewriting the witness too is caught by the chain.",
                observed, passed, note)


def approval_expiry_extended():
    with throwaway() as base:
        store = new_store(base)
        # An approval that has ALREADY run out: the interesting case, because
        # extending a live one only moves a limit that has not bitten yet.
        mid, subject, aid, required = _approved_mission(
            store, expires_at="2020-01-01T00:00:00+00:00")
        expired, expired_why = store.find_approval(subject, required)
        raw_sql(store.db_path,
                "UPDATE approvals SET expires_at='2099-12-31T00:00:00+00:00' WHERE id=?",
                (aid,))
        extended, extended_why = store.find_approval(subject, required)
        raw_sql(store.db_path, "UPDATE approvals SET expires_at=NULL WHERE id=?", (aid,))
        removed, removed_why = store.find_approval(subject, required)
        raw_sql(store.db_path, "UPDATE approvals SET expires_at=? WHERE id=?",
                ("not a date at all", aid))
        unreadable, unreadable_why = store.find_approval(subject, required)
        witness = store.approval_witness(aid)

        observed = lines(
            f"approval {aid} was granted with expires_at=2020-01-01T00:00:00+00:00",
            f"  before any edit: "
            + ("ACCEPTED -- broken probe" if expired else f"REFUSED: {expired_why}"),
            f"  expiry extended to 2099-12-31: "
            + ("ACCEPTED -- undetected" if extended else f"REFUSED: {extended_why}"),
            f"  expiry REMOVED (NULL, meaning never expires): "
            + ("ACCEPTED -- undetected" if removed else f"REFUSED: {removed_why}"),
            f"  expiry replaced with unparseable text: "
            + ("ACCEPTED -- undetected" if unreadable else f"REFUSED: {unreadable_why}"),
            f"the chained grant event still records expires_at="
            f"{(witness or {}).get('expires_at')!r}")
        passed = not any((expired, extended, removed, unreadable))
        note = (
            "Held, including the two shapes that are not 'a later date'. Removing the "
            "expiry entirely and making it unreadable both fail the same whole-record "
            f"digest as extending it, because the chained grant still says "
            f"{(witness or {}).get('expires_at')!r} and the digest is taken over the field "
            "list rather than over whatever the checker remembers to compare. The "
            "unreadable case has a second guard behind it: an expiry nobody can parse is "
            "treated as expired rather than as no expiry, so the two failure modes point "
            "the same way."
            if passed else
            f"FINDING. expired control accepted={bool(expired)}, extended={bool(extended)}, "
            f"removed={bool(removed)}, unreadable={bool(unreadable)}")
        return ("An expiry is part of what was witnessed at grant time, so moving it, "
                "removing it or corrupting it cannot revive an approval that has run out.",
                observed, passed, note)


def approval_revocation_deleted():
    with throwaway() as base:
        store = new_store(base)
        mid, subject, aid, required = _approved_mission(store)
        control, row = _approval_control(store, subject, required)
        store.revoke_approval(aid, reason="the owner changed their mind")
        after_revoke, after_why = store.find_approval(subject, required)
        # One honest event after the revoke, so deleting the revoke leaves a hole
        # in the MIDDLE of the log rather than shortening it. Truncation is
        # already attack 5's question; this one is about what the chain does when
        # a row is taken out from under its successors.
        store.append_event(mid, "probe", "work continued after the revocation")
        raw_sql(store.db_path, "UPDATE approvals SET revoked_at=NULL WHERE id=?", (aid,))
        cleared, cleared_why = store.find_approval(subject, required)
        chained = store.approval_revocation(aid, subject=subject)

        # And the deeper version: delete the revocation EVENT as well.
        revoke_seq = rows(store.db_path,
                          "SELECT seq FROM events WHERE event='approval-revoked'")[0]["seq"]
        raw_sql(store.db_path, "DELETE FROM events WHERE seq=?", (revoke_seq,))
        erased, erased_why = store.find_approval(subject, required)
        report = new_store(base).verify_chain()
        exit_code, _, _ = cli("audit", "verify")
        chain_only = chain_only_problems(report)

        observed = lines(
            f"control (before the revoke): {control}",
            f"after revoke_approval({aid}): "
            + ("ACCEPTED -- broken probe" if after_revoke else f"REFUSED: {after_why}"),
            "UPDATE approvals SET revoked_at=NULL:",
            f"  find_approval() -> "
            + ("ACCEPTED -- undetected" if cleared else f"REFUSED: {cleared_why}"),
            f"  the chain still carries the revocation: "
            f"{ {k: chained.get(k) for k in ('approval', 'revoked_at')} if chained else None}",
            f"then DELETE FROM events WHERE seq={revoke_seq} -- a row from the MIDDLE of "
            "the log, with an honest event after it:",
            f"  find_approval() -> "
            + ("ACCEPTED -- the approval is back in force" if erased
               else f"REFUSED: {erased_why}"),
            summary("  verify_chain()", report),
            problems(report),
            f"  problems the chain raised on its own: {chain_only}",
            f"`audit verify` exit {exit_code}")
        passed = (not after_revoke and not cleared
                  and (not erased or (not report["ok"] and exit_code != 0)))
        note = (
            "Held, and the two halves hold for different reasons. Clearing revoked_at does "
            "nothing because the check reads the CHAIN, not the column -- the revoke event "
            "names the approval, so the row's silence is contradicted by the log. Deleting "
            f"the revoke event as well does bring the approval back "
            f"({'find_approval accepted it' if erased else 'find_approval still refused it'}), "
            "and that is the point where the chain takes over: the row was removed from the "
            f"middle of the log and its successors no longer join up, which the chain "
            f"reports on its own -- {len(chain_only)} problem(s) with no help from the "
            f"anchor -- so verify reports ok={report['ok']} and the CLI exits {exit_code}. "
            "An attacker can have the approval or a clean audit, not both."
            if passed else
            f"FINDING. after revoke accepted={bool(after_revoke)}, revoked_at cleared "
            f"accepted={bool(cleared)}, revoke event deleted accepted={bool(erased)} with "
            f"verify ok={report['ok']} exit {exit_code}")
        return ("A revocation is witnessed by a chained event, so erasing it from the "
                "approvals table does not revive the approval, and erasing it from the "
                "chain does not go unreported.",
                observed, passed, note)


# --------------------------------------------------------------------------- #
# 14. Forge a journal head
# --------------------------------------------------------------------------- #
def journal_head_forged():
    with throwaway() as base:
        store = new_store(base)
        if not anchor_is_readable(store):
            return ("A forged mirror line cannot un-say the one the engine wrote.",
                    NEEDS_ANCHOR, False, INCONCLUSIVE)
        mid, _ = reviewed_mission(store)
        clean = store.verify_chain()
        waited, journal_head = settle(store, clean["head_seq"])
        victim = 3
        honest_hash = anchor(store)["heads"].get(victim)

        rechain(store.db_path, {victim: {"detail": "REWRITTEN BY THE ATTACKER"}})
        detected = new_store(base).verify_chain()
        new_hashes = {r["seq"]: r["hash"] for r in event_rows(store)}

        # THE ATTACK: the mission uid can write /dev/log, so mirror the new
        # hashes for every row it just rewrote, exactly as the engine would.
        sent = []
        for seq in sorted(new_hashes):
            if seq < victim:
                continue
            ok, why = sf_audit.mirror({"store": store.store_identity(),
                                       "chain": store.chain_id(), "seq": seq,
                                       "hash": new_hashes[seq], "mission": mid,
                                       "event": "forged-cover", "at": sf.now()})
            sent.append((seq, ok, why))
        time.sleep(1.0)
        covered_store = new_store(base)
        covered = covered_store.verify_chain()
        exit_code, _, _ = cli("audit", "verify")
        after = anchor(covered_store)

        observed = lines(
            summary("before", clean) + f" (journal caught up in {waited}s at seq {journal_head})",
            f"seq {victim} rewritten and the tail re-chained: "
            + summary("after the rewrite", detected),
            f"then {len(sent)} forged mirror line(s) written to /dev/log by this uid "
            f"({os.getuid()}) carrying the NEW hashes: "
            f"{[(s, ok) for s, ok, _ in sent]}",
            summary("after the forged cover", covered),
            problems(covered),
            f"  the journal's FIRST line for seq {victim} is still "
            f"{str(honest_hash)[:16]}; the database now holds "
            f"{str(new_hashes.get(victim))[:16]}",
            f"  mirror_conflicts: "
            f"{ {k: [h[:12] for h in v] for k, v in ((covered['anchor'] or {}).get('mirror_conflicts') or {}).items()} }",
            f"  journal entries for this chain after the forgery: {after['entries']}",
            f"  rewritten_seqs: {(covered['anchor'] or {}).get('rewritten_seqs')}",
            f"`audit verify` exit {exit_code}")
        passed = not covered["ok"] and exit_code != 0
        note = (
            "Held, and the reason is one line of policy in read_head(): the EARLIEST line "
            "for a sequence number wins, not the latest. journald is append-only to this "
            "uid -- the forged lines were accepted by /dev/log and are sitting there -- so "
            f"the attacker can add a claim about seq {victim} but cannot remove the one the "
            "engine wrote, and a second differing line for one sequence number is itself "
            "reported: mirror_conflicts names it, because the engine mirrors each event "
            f"exactly once. Exit {exit_code}. The forgery makes the evidence louder rather "
            "than quieter, which is the property an append-only anchor is bought for."
            if passed else
            f"FINDING. After forging {len(sent)} mirror lines the log verified at "
            f"ok={covered['ok']} with exit {exit_code}; problems={covered['problems']}")
        return ("The journal is append-only to this uid, so a forged line can only ADD a "
                "claim: the engine's original line still stands, and two hashes for one "
                "event are reported as the contradiction they are.",
                observed, passed, note)


# --------------------------------------------------------------------------- #
# 15. Inject a journal message as the mission user
# --------------------------------------------------------------------------- #
def journal_message_injected():
    with throwaway() as base:
        store = new_store(base)
        if not anchor_is_readable(store):
            return ("Injected anchor lines do not buy a clean verification.",
                    NEEDS_ANCHOR, False, INCONCLUSIVE)
        mid, _ = reviewed_mission(store)
        clean = store.verify_chain()
        waited, journal_head = settle(store, clean["head_seq"])
        honest_exit, _, _ = cli("audit", "verify")

        # Nothing was touched in the database. The attack is entirely in the
        # anchor: this uid writes /dev/log, so it can claim events that never
        # happened -- here, five sequence numbers past the real head.
        ahead = clean["head_seq"] + 5
        ok, why = sf_audit.mirror({"store": store.store_identity(),
                                   "chain": store.chain_id(), "seq": ahead,
                                   "hash": "f" * 64, "mission": mid,
                                   "event": "completed", "at": sf.now()})
        time.sleep(1.0)
        poisoned_store = new_store(base)
        report = poisoned_store.verify_chain()
        exit_code, stdout, _ = cli("audit", "verify")
        printed = [l.strip() for l in stdout.splitlines() if l.startswith("PROBLEM")]
        chain_only = chain_only_problems(report)
        db_rows = len(event_rows(poisoned_store))

        observed = lines(
            f"the database is untouched: {db_rows} events, "
            + summary("verify before the injection", clean)
            + f" (journal caught up in {waited}s at seq {journal_head}, `audit verify` "
            f"exit {honest_exit})",
            f"one line written to /dev/log by uid {os.getuid()} claiming seq {ahead} "
            f"with hash {'f' * 16}...: sent={ok}{'' if ok else ' (' + str(why) + ')'}",
            summary("after the injection", report),
            problems(report),
            f"  problems the chain raised on its own: {chain_only}",
            f"  rewritten_seqs: {(report['anchor'] or {}).get('rewritten_seqs')}",
            f"`audit verify` exit {exit_code}; printed: {printed}")
        passed = not report["ok"] and exit_code != 0
        note = (
            "Held in the sense that matters -- the verifier did not report a clean log "
            f"(exit {exit_code}) -- but read the wording, because it is the residual gap. "
            f"The database was never touched: {db_rows} rows, "
            f"{len(chain_only)} chain-level problems, rewritten_seqs "
            f"{(report['anchor'] or {}).get('rewritten_seqs')}. The report nevertheless "
            f"says {printed}, which accuses the database of a deletion that did not happen. "
            "Both sides of the comparison are writable by this uid -- the SQLite file and "
            "/dev/log -- so 'journal ahead of database' has two causes and the report names "
            "only one of them. An operator acting on this message goes looking for missing "
            "rows. Saying 'the journal claims events the database does not have; either "
            "rows were removed or lines were injected' costs nothing and is true in both "
            "cases. Also worth noting: this is a cheap way to make an honest install fail "
            "its own audit."
            if passed else
            f"FINDING. An injected anchor line left verify at ok={report['ok']} with exit "
            f"{exit_code}.")
        return ("An anchor line this uid can write must not be able to change the "
                "verifier's verdict to 'intact' -- and when it changes the verdict the "
                "other way, the report must not blame the side that was not touched.",
                observed, passed, note)


# --------------------------------------------------------------------------- #
# 16. Remove the external anchor
# --------------------------------------------------------------------------- #
def anchor_removed():
    with throwaway() as base:
        store = new_store(base)
        mid, _ = reviewed_mission(store)
        head = store.verify_chain()["head_seq"]

        # (a) the anchor cannot be READ: no journalctl on this host.
        with blind_anchor():
            blind = new_store(base).verify_chain()
            blind_exit, blind_out, _ = cli("audit", "verify")
            blind_json_exit, blind_json_out, _ = cli("--json", "audit", "verify")
        blind_line = next((l for l in blind_out.splitlines()
                           if l.startswith("external")), "").strip()

        # (b) the anchor cannot be ADDRESSED: the chain id lives in a row the
        #     attacker can delete, and read_head() is keyed by it.
        raw_sql(store.db_path, "DELETE FROM events WHERE event=?", (sf.CHAIN_GENESIS,))
        detached_store = new_store(base)
        detached = detached_store.verify_chain()
        detached_exit, _, _ = cli("audit", "verify")

        observed = lines(
            f"honest log: head seq {head}",
            "(a) journalctl removed from PATH -- the condition a container image or a "
            "minimal install is already in:",
            summary("  verify", blind),
            f"  anchor reason: {(blind['anchor'] or {}).get('reason')}",
            f"  `audit verify` exit {blind_exit}; {blind_line!r}",
            f"  `--json audit verify` exit {blind_json_exit}, parses: "
            f"{isinstance(json.loads(blind_json_out or '{}'), dict)}",
            "(b) the chain genesis deleted, so the log can no longer name its own anchor:",
            f"  chain_id() -> {detached_store.chain_id()!r}",
            summary("  verify", detached),
            problems(detached),
            f"  `audit verify` exit {detached_exit}")
        passed = (blind["anchor"]["verdict"] == "unverified" and blind_exit == 2
                  and blind_json_exit == 2 and detached_exit != 0)
        note = (
            "Held on the only claim available. With no anchor the log cannot be shown "
            "intact and cannot be shown tampered: every surviving row verifies against its "
            "predecessor, so a truncation would be undetectable. The system says so rather "
            f"than reporting success -- verdict {blind['anchor']['verdict']!r}, exit "
            f"{blind_exit} in text and {blind_json_exit} in JSON, which is neither 0 nor "
            "the 1 that would cry tampering. Removing the chain id instead is a different "
            f"failure and gets a different answer: exit {detached_exit}, with the chain "
            "itself objecting that nothing is verifiable. 'I cannot tell' and 'this is "
            "broken' stay separate words."
            if passed else
            f"FINDING. blind: verdict={blind['anchor']['verdict']!r} exit {blind_exit}/"
            f"{blind_json_exit}. detached: exit {detached_exit}, ok={detached['ok']}")
        return ("With no readable anchor the system must refuse to call the log verified, "
                "and must not call it tampered either: exit 2, in both output modes.",
                observed, passed, note)


# --------------------------------------------------------------------------- #
# 17. Copy an anchor from another chain
# --------------------------------------------------------------------------- #
def anchor_copied_from_another_chain():
    with throwaway() as base:
        victim_store = new_store(base)
        if not anchor_is_readable(victim_store):
            return ("Adopting another chain's anchor does not buy a clean verification.",
                    NEEDS_ANCHOR, False, INCONCLUSIVE)
        donor = new_store(base, "donor-state")
        # The donor is a healthy store with its own mirrored history; the victim
        # is the one being rewritten.
        donor_mid, _ = reviewed_mission(donor)
        victim_mid, _ = reviewed_mission(victim_store)
        settle(donor, donor.verify_chain()["head_seq"])
        waited, journal_head = settle(victim_store, victim_store.verify_chain()["head_seq"])
        own_chain = victim_store.chain_id()
        donor_chain = donor.chain_id()

        # The attack: rewrite this store's history, then relabel it with the
        # donor's chain id so it points at an anchor that has never seen it.
        genesis = rows(victim_store.db_path,
                       "SELECT * FROM events WHERE event=? ORDER BY seq LIMIT 1",
                       (sf.CHAIN_GENESIS,))[0]
        detail = json.loads(genesis["detail"])
        detail["chain_id"] = donor_chain
        rechain(victim_store.db_path, {
            genesis["seq"]: {"detail": json.dumps(detail, sort_keys=True)},
            3: {"detail": "REWRITTEN UNDER SOMEBODY ELSE'S ANCHOR"}})
        after_store = new_store(base)
        report = after_store.verify_chain()
        exit_code, _, _ = cli("audit", "verify")
        borrowed = sf_audit.read_head(donor_chain, store=after_store.store_identity())

        observed = lines(
            f"two stores under the same throwaway root: victim chain {own_chain[:12]} "
            f"(journal caught up in {waited}s at seq {journal_head}), donor chain "
            f"{donor_chain[:12]}",
            f"the victim's genesis was rewritten to claim chain id {donor_chain[:12]} and "
            "seq 3's detail was changed; everything re-chained",
            f"chain_id() now returns {str(after_store.chain_id())[:12]}",
            summary("after", report),
            problems(report),
            f"  other_chains_for_this_store: "
            f"{(report['anchor'] or {}).get('other_chains_for_this_store')}",
            f"  rewritten_seqs: {(report['anchor'] or {}).get('rewritten_seqs')}",
            f"  read_head() for the borrowed chain returns {borrowed['entries']} entries "
            f"at seqs {sorted(borrowed['heads'])}, mirrored by the DONOR's store identity, "
            f"not this one",
            f"`audit verify` exit {exit_code}")
        passed = (not report["ok"] and exit_code != 0
                  and bool((report["anchor"] or {}).get("other_chains_for_this_store")))
        note = (
            "Held, twice over. The borrowed anchor does not fit: its per-seq hashes belong "
            f"to another database, so rewritten_seqs is "
            f"{(report['anchor'] or {}).get('rewritten_seqs')}. And the store's own past "
            f"gives it away: this path has mirrored "
            f"{(report['anchor'] or {}).get('other_chains_for_this_store')} before, which "
            "is only possible if the chain was re-minted -- the identity that makes that "
            "comparison possible is derived from the path the operator opened, not from a "
            f"row the attacker can edit. Exit {exit_code}. One thing measured here that is "
            f"not a finding but is worth knowing: read_head() matched {borrowed['entries']} "
            "lines on the chain id alone, including lines whose `store` field is the "
            "donor's -- the chain id selects the history and the store id is used for the "
            "re-mint check, so a borrowed anchor is READ before it is disbelieved."
            if passed else
            f"FINDING. Adopting another chain's id left verify at ok={report['ok']} exit "
            f"{exit_code}; other_chains="
            f"{(report['anchor'] or {}).get('other_chains_for_this_store')}")
        return ("An anchor belongs to one database. Pointing a rewritten log at another "
                "chain's history must be reported as the re-mint it is, not as a fresh "
                "install with nothing to compare.",
                observed, passed, note)


# --------------------------------------------------------------------------- #
# 18. Restore an old database against a newer anchor
# --------------------------------------------------------------------------- #
def old_database_against_newer_anchor():
    with throwaway() as base:
        store = new_store(base)
        if not anchor_is_readable(store):
            return ("A rolled-back database is caught by the anchor that saw the newer rows.",
                    NEEDS_ANCHOR, False, INCONCLUSIVE)
        mid, _ = reviewed_mission(store)
        snapshot = base / "snapshot"
        copied = copy_database(store.root, snapshot)
        before = store.verify_chain()

        # Real work happens after the backup: a review, and its events.
        for i in range(3):
            store.append_event(mid, "probe", f"work the backup does not contain ({i})")
        newer = store.verify_chain()
        waited, journal_head = settle(store, newer["head_seq"])

        restore_database(snapshot, store.root)
        report = new_store(base).verify_chain()
        exit_code, stdout, _ = cli("audit", "verify")
        journal_line = next((l for l in stdout.splitlines() if "journal head" in l), "").strip()

        observed = lines(
            f"snapshot taken at head seq {before['head_seq']} "
            f"(files copied: {copied})",
            summary("after three more events", newer)
            + f" (journal caught up in {waited}s at seq {journal_head})",
            "the snapshot was copied back over the live database:",
            summary("  after the restore", report),
            problems(report),
            f"  {journal_line!r}",
            f"  problems the chain raised on its own: {chain_only_problems(report)}",
            f"`audit verify` exit {exit_code}")
        passed = (not report["ok"] and verdict(report) == "truncated" and exit_code != 0)
        note = (
            f"Held; {who_objected(report)} objected. A restored backup is a truncation "
            "with better manners: the file is internally consistent -- the chain found "
            f"{chain_only_problems(report) or 'nothing'} -- and the only thing that knows "
            "those three events ever existed is outside "
            f"the file. The journal's mark ({journal_head}) against the database's "
            f"({report['head_seq']}) names the gap and the count, and the CLI exits "
            f"{exit_code}. Note what this does NOT distinguish: a malicious rollback and a "
            "restore from backup after a disk failure produce the same report, which is "
            "correct -- both mean the log no longer contains events that were recorded, "
            "and only a person knows which happened."
            if passed else
            f"FINDING. Restoring an older database left verify at ok={report['ok']} "
            f"verdict={verdict(report)!r} exit {exit_code}")
        return ("The anchor witnessed the newer events, so restoring an older database is "
                "reported as the missing history it is.",
                observed, passed, note)


# --------------------------------------------------------------------------- #
# 19. Run a database past the anchor that witnessed it
# --------------------------------------------------------------------------- #
def old_anchor_against_newer_database():
    with throwaway() as base:
        store = new_store(base)
        if not anchor_is_readable(store):
            return ("A database ahead of its anchor is not reported as verified.",
                    NEEDS_ANCHOR, False, INCONCLUSIVE)
        mid, _ = reviewed_mission(store)
        clean = store.verify_chain()
        waited, journal_head = settle(store, clean["head_seq"])

        # First: what does HONEST lag look like on this host? Append through the
        # engine and verify immediately, before journalctl can catch up. If the
        # verifier ever reports lag the same way it reports an unwitnessed tail,
        # then the two are indistinguishable and the report is worth nothing.
        honest = []
        for i in range(3):
            store.append_event(mid, "probe", f"honest-{i}")
            immediate = store.verify_chain()
            honest.append((immediate["head_seq"],
                           (immediate["anchor"] or {}).get("journal_head_seq"),
                           verdict(immediate), sf.audit_exit_code(immediate)))
        settle(store, store.verify_chain()["head_seq"])

        # Then: rows the anchor never witnessed. This uid cannot delete journal
        # lines -- journald is append-only to it -- so the reachable way to put
        # the database ahead of its anchor is to add rows the mirror never saw,
        # which is also what a rotated-away or rolled-back anchor leaves behind.
        added = append_raw(store.db_path, [
            (mid, "probe", f"never mirrored ({i})", sf.ACTOR_ORCHESTRATOR)
            for i in range(3)])
        report = new_store(base).verify_chain()
        exit_code, stdout, _ = cli("audit", "verify")
        anchor_line = next((l for l in stdout.splitlines()
                            if l.startswith("external")), "").strip()
        honest_verdicts = sorted({v for _d, _j, v, _c in honest})

        # And then the second half of the same attack: the file that check reads
        # is audit-mirror.json, which sits beside the database and belongs to the
        # same uid that wrote the forged rows. Move its bookmark past them.
        state_file = Path(store.root) / sf_audit.MirrorState.FILENAME
        was = json.loads(state_file.read_text()) if state_file.exists() else {}
        state_file.write_text(json.dumps(
            dict(was, last_mirrored_seq=report["head_seq"], failures=0,
                 last_error=None), sort_keys=True))
        forged = new_store(base).verify_chain()
        forged_exit, forged_out, _ = cli("audit", "verify")
        forged_anchor_line = next((l for l in forged_out.splitlines()
                                   if l.startswith("external")), "").strip()

        observed = lines(
            summary("honest log", clean) + f" (journal caught up in {waited}s at seq {journal_head})",
            "three honest engine appends, each verified immediately, before journalctl "
            "could catch up -- (db head, journal head, verdict, exit):",
            *[f"  {row}" for row in honest],
            f"  verdicts honest lag produced on this host: {honest_verdicts}",
            f"then {len(added)} rows appended straight into `events` at seqs {added}, "
            "correctly chained, which the mirror never saw:",
            summary("  after", report),
            problems(report),
            f"  journal head {(report['anchor'] or {}).get('journal_head_seq')} vs database "
            f"head {report['head_seq']}; local bookmark "
            f"{(report['anchor'] or {}).get('last_mirrored_seq')}",
            f"  `audit verify` exit {exit_code}; {anchor_line!r}",
            f"then {state_file.name} -- same uid, same directory as the database -- was "
            f"rewritten with last_mirrored_seq={report['head_seq']}, failures=0:",
            summary("  after", forged),
            problems(forged),
            f"  `audit verify` exit {forged_exit}; {forged_anchor_line!r}")
        detected = not undetected(report, exit_code)
        survives = not undetected(forged, forged_exit)
        passed = detected and survives
        note = (
            ("Held. The unwitnessed tail is reported rather than filed under normal lag: "
             f"{report['problems']}, exit {exit_code}. Honest lag was measured in the same "
             f"run and produced {honest_verdicts}, so the two are not being confused. "
             if detected else
             f"FINDING. The database is {len(added)} events ahead of everything the anchor "
             f"witnessed and `audit verify` exits {exit_code} with ok={report['ok']} and "
             f"{anchor_line!r}. Honest lag produced {honest_verdicts} in the same run, so "
             "the verdict spent on the attack is not one honest operation was observed to "
             "produce. ")
            + ("And it survives the obvious follow-up: the check reads its high-water mark "
               f"from {state_file.name}, which this uid owns, and rewriting that file to "
               f"claim seq {report['head_seq']} was mirrored left exit {forged_exit} with "
               f"{forged['problems']}."
               if survives else
               f"FINDING, and the sharper half: the check reads its high-water mark from "
               f"{state_file.name}, a file beside the database owned by the same uid that "
               f"wrote the forged rows. Writing last_mirrored_seq={report['head_seq']} into "
               f"it turned exit {exit_code} into exit {forged_exit} and ok={report['ok']} "
               f"into ok={forged['ok']}, verdict {forged_anchor_line!r}. Local bookkeeping "
               "is being trusted to say what the external anchor witnessed, which is the "
               "one thing local bookkeeping cannot know. The journal answers it directly "
               f"and is not writable down by this uid: it reports head seq "
               f"{(forged['anchor'] or {}).get('journal_head_seq')} for this chain against "
               f"a database head of {forged['head_seq']}, and its per-seq map says which "
               "rows it witnessed. Prefer the journal when it is readable; fall back to "
               "the local mark only when it is not, and say which was used.")
        )
        return ("Events the anchor never witnessed cannot be reported as verified history, "
                "and the mark that decides this must not be a file the attacker owns.",
                observed, passed, note)


# --------------------------------------------------------------------------- #
# 20. Use JSON mode to get a different exit status
# --------------------------------------------------------------------------- #
def json_mode_exit_bypass():
    with throwaway() as base:
        store = new_store(base)
        mid, _ = reviewed_mission(store)
        cases, disagreements = [], []

        def compare(label):
            text_exit, text_out, _ = cli("audit", "verify")
            json_exit, json_out, _ = cli("--json", "audit", "verify")
            try:
                parsed = json.loads(json_out)
                parses = True
            except ValueError as exc:
                parsed, parses = {}, f"no: {exc}"
            derived = sf.audit_exit_code(parsed) if parses is True else None
            cases.append(f"  {label:<34} text exit {text_exit}   --json exit {json_exit}   "
                         f"JSON parses: {parses}   ok={parsed.get('ok')} "
                         f"anchor={(parsed.get('anchor') or {}).get('verdict')!r}   "
                         f"audit_exit_code(that JSON)={derived}")
            if text_exit != json_exit or (derived is not None and derived != json_exit):
                disagreements.append(label)
            return text_exit, json_exit

        compare("intact log")
        with blind_anchor():
            compare("no readable anchor")
        raw_sql(store.db_path, "UPDATE events SET detail=? WHERE seq=?",
                ("REWRITTEN BY THE ATTACKER", 3))
        compare("a row rewritten")
        raw_sql(store.db_path, "DELETE FROM events WHERE seq > ?", (2,))
        compare("the tail deleted")

        # The ladder itself, asked directly: a report that says nothing must not
        # be read as a report that says yes.
        ladder = [(json.dumps(report), sf.audit_exit_code(report)) for report in (
            {}, {"ok": True}, {"ok": False}, {"ok": None},
            {"ok": True, "anchor": {"verdict": "unverified"}},
            {"ok": True, "anchor": {"verdict": "degraded"}},
            {"ok": True, "anchor": {"verdict": "agrees"}})]
        fails_closed = sf.audit_exit_code({}) != 0 and sf.audit_exit_code({"ok": None}) != 0

        observed = lines(
            "the same store, verified both ways at four stages of damage:",
            *cases,
            "audit_exit_code() asked directly:",
            *[f"  {report:<50} -> {code}" for report, code in ladder],
            f"a report with no verdict in it fails closed: {fails_closed}")
        passed = not disagreements and fails_closed
        note = (
            "Held. The ladder is computed from the report before anything is rendered and "
            "the CLI returns it in both modes, so the caller most likely to pass --json -- "
            "a gate, a cron check, a LaunchAgent -- gets the same answer as the person "
            "reading the table. Two properties were checked rather than assumed: the exit "
            "status matches what audit_exit_code() derives from the JSON the same command "
            "printed, at every stage of damage above, so a caller can act on the document "
            "or on the status and cannot be told two different things; and a report with no "
            "'ok' in it exits non-zero, so a verifier that fell over is not mistaken for a "
            "verifier that approved."
            if passed else
            f"FINDING. The two output modes disagreed at: {disagreements}; "
            f"fails closed on an empty report: {fails_closed}")
        return ("Exit status is a property of the report, not of how it is printed: --json "
                "and text return the same code at every stage of damage, and a report that "
                "says nothing exits non-zero.",
                observed, passed, note)


# --------------------------------------------------------------------------- #
# 21. Forge the v4 legacy pin
# --------------------------------------------------------------------------- #
def legacy_pin_forged():
    """Not on the assigned list. Attack 1 is caught only because the pin is a
    chained fact, so the pin is worth attacking on its own -- in both shapes the
    attacker has: appending a pin, and rewriting the one already there."""
    with throwaway() as base:
        store = new_store(base)
        if not anchor_is_readable(store):
            return ("A forged legacy pin does not excuse a fabricated mission.",
                    NEEDS_ANCHOR, False, INCONCLUSIVE)
        mid, _ = reviewed_mission(store)
        settle(store, store.verify_chain()["head_seq"])
        existing = [r["seq"] for r in rows(store.db_path,
                                           "SELECT seq FROM events WHERE event=?",
                                           (sf.LEGACY_PIN,))]
        fake = "mission-" + uuid.uuid4().hex[:16]
        raw_sql(store.db_path,
                "INSERT INTO missions(id,title,kind,capability,provider_id,state,"
                "workspace,prompt,config,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (fake, "work that never happened", "media", "media_export",
                 "offline-media", sf.MissionState.COMPLETED,
                 str(Path(os.environ["SHADOWFETCH_AGENT_WORKSPACES"]) / "probe"),
                 "attack", "{}", sf.now(), sf.now()))
        caught = new_store(base).verify_chain()
        caught_exit, _, _ = cli("audit", "verify")

        def forged_pin(note):
            return json.dumps({"pinned_at_schema_version": sf.SCHEMA_VERSION,
                               "from_schema_version": 3, "missions": [fake],
                               "states": {fake: sf.MissionState.COMPLETED},
                               "count": 1, "note": note}, sort_keys=True)

        # (a) APPEND a pin: correctly chained, at the tail, long after the
        #     upgrade, naming the row the attacker just invented.
        appended_seq = append_raw(store.db_path, [
            ("*", sf.LEGACY_PIN, forged_pin("forged by the attack module, appended"),
             sf.ACTOR_ORCHESTRATOR)])[0]
        appended_store = new_store(base)
        appended = appended_store.verify_chain()
        appended_exit, appended_out, _ = cli("audit", "verify")
        appended_class = appended["states"]["classes"].get(fake)
        appended_pinned = sorted(appended_store.legacy_missions())
        appended_line = next((l for l in appended_out.splitlines()
                              if l.startswith("mission states")), "").strip()

        # (b) REWRITE the pin that is already there, so there is still exactly
        #     one -- the shape (a) cannot be caught by counting.
        if existing:
            raw_sql(store.db_path, "DELETE FROM events WHERE seq=?", (appended_seq,))
            rechain(store.db_path, {existing[0]: {
                "detail": forged_pin("forged by the attack module, rewritten in place")}})
            rewritten_store = new_store(base)
            rewritten = rewritten_store.verify_chain()
            rewritten_exit, rewritten_out, _ = cli("audit", "verify")
            rewritten_class = rewritten["states"]["classes"].get(fake)
            rewritten_pinned = sorted(rewritten_store.legacy_missions())
            stage_b = lines(
                f"then the appended pin was deleted and the FIRST pin (seq {existing[0]}, "
                "the one the migration wrote) was rewritten to name the fabricated "
                "mission instead; everything re-chained, so the database again holds "
                "exactly one pin:",
                f"  legacy_missions() now returns {rewritten_pinned}",
                f"  the fabricated mission is classified {rewritten_class!r}",
                summary("  verify", rewritten),
                problems(rewritten),
                f"  rewritten_seqs: {(rewritten['anchor'] or {}).get('rewritten_seqs')}",
                f"  problems the chain raised on its own: "
                f"{chain_only_problems(rewritten)}",
                f"`audit verify` exit {rewritten_exit}")
            b_held = not undetected(rewritten, rewritten_exit)
        else:
            rewritten, rewritten_exit, rewritten_class = None, None, None
            stage_b = ("this database carries no pin to rewrite, so stage (b) did not "
                       "run: with no first pin, appending one IS rewriting the only one "
                       "there will ever be, which is stage (a)")
            b_held = True

        observed = lines(
            f"pins in this database before the attack: {existing or 'none'}"
            + (f" -- the upgrade wrote one at seq {existing[0]} even though this database "
               "had no event-less missions to name" if existing else
               " -- the upgrade wrote none, so the first pin slot is unclaimed"),
            f"a mission row was invented with state={sf.MissionState.COMPLETED!r} and no events:",
            summary("  verify", caught),
            problems(caught),
            f"  classified {caught['states']['classes'].get(fake)!r}; "
            f"`audit verify` exit {caught_exit}",
            f"(a) one {sf.LEGACY_PIN!r} event appended at the tail (seq {appended_seq}), "
            "correctly chained, naming that mission:",
            f"  legacy_missions() now returns {appended_pinned}",
            f"  the fabricated mission is classified {appended_class!r}",
            summary("  verify", appended),
            problems(appended),
            f"`audit verify` exit {appended_exit}; {appended_line!r}",
            "(b) " + stage_b if not existing else stage_b)
        a_held = not undetected(appended, appended_exit)
        passed = a_held and b_held
        if rewritten is None:
            held = ("Held on the only shape this database allowed. There was no pin to "
                    "rewrite, so stage (b) did not run; appending one left the fabricated "
                    f"mission {appended_class!r} at exit {appended_exit}.")
        else:
            held = (
                "Held on both shapes. Appending a pin is refused by count: the fabricated "
                f"mission stayed {appended_class!r} and the log reports a pin after the "
                "first, because a database is pinned once at its upgrade -- which works "
                f"only because the upgrade wrote a pin here ({existing or 'no pin present'}) "
                "even though it had nothing to name, closing the slot rather than leaving "
                "it open. Rewriting that same pin keeps the count at one: the mission is "
                f"{rewritten_class!r} and legacy_missions() returned {rewritten_pinned}"
                + ((", so the pin was read and NOT honoured -- "
                    + "; ".join(p for p in rewritten["problems"] if "pin" in p))
                   if rewritten_class != sf.CLASS_LEGACY else
                   ", so the replay WAS defeated there and what caught it is the anchor's "
                   f"per-seq hashes at "
                   f"{(rewritten['anchor'] or {}).get('rewritten_seqs')}")
                + f". Exits {caught_exit} -> {appended_exit} -> {rewritten_exit}. What that "
                "leaves resting on the journal: the rewrite is refused because the chain "
                f"carrying the pin no longer verifies (rewritten_seqs "
                f"{(rewritten['anchor'] or {}).get('rewritten_seqs')}), and a re-chained "
                "log verifies clean on a host with no readable journal, where the pin "
                "would then be honoured.")
        note = (
            held
            if passed else
            "FINDING. "
            + (f"An appended pin moved the fabricated mission to {appended_class!r} and "
               f"`audit verify` to exit {appended_exit}, printing {appended_line!r} over a "
               "mission that never ran. " if not a_held else "")
            + (f"Rewriting the migration's pin moved it to {rewritten_class!r} with exit "
               f"{rewritten_exit} and problems {rewritten['problems'] if rewritten else []}. "
               if not b_held else "")
            + "The pin is what makes an event-less mission excusable, so a pin the "
              "attacker controls is an exemption the attacker controls.")
        return ("The legacy pin is what makes an event-less mission excusable, so neither "
                "a pin appended after the fact nor the migration's own pin rewritten to "
                "name invented rows may be honoured.",
                observed, passed, note)


# --------------------------------------------------------------------------- #
# The module's interface
# --------------------------------------------------------------------------- #
_TABLE = (
    ("mission-fabricated-no-history", mission_fabricated_no_history),
    ("chain-genesis-deleted", chain_genesis_deleted),
    ("chain-replaced-wholesale", chain_replaced_wholesale),
    ("event-altered-and-rechained", event_altered_and_rechained),
    ("chain-tail-truncated", chain_tail_truncated),
    ("chain-tail-forged", chain_tail_forged),
    ("events-reordered", events_reordered),
    ("event-duplicated", event_duplicated),
    ("event-mission-reattributed", event_mission_reattributed),
    ("event-session-reattributed", event_session_reattributed),
    ("approval-provenance-forged", approval_provenance_forged),
    ("approval-expiry-extended", approval_expiry_extended),
    ("approval-revocation-deleted", approval_revocation_deleted),
    ("journal-head-forged", journal_head_forged),
    ("journal-message-injected", journal_message_injected),
    ("anchor-removed", anchor_removed),
    ("anchor-copied-from-another-chain", anchor_copied_from_another_chain),
    ("old-database-against-newer-anchor", old_database_against_newer_anchor),
    ("old-anchor-against-newer-database", old_anchor_against_newer_database),
    ("json-mode-exit-bypass", json_mode_exit_bypass),
    ("legacy-pin-forged", legacy_pin_forged),
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

    print(f"attack_verifier: {len(ATTACKS)} attacks against the audit verifier in "
          f"{MISSIONS_SRC.relative_to(REPO)}\n")
    run(collect)
    failed = [name for name, _e, _o, passed, _n in results if not passed]
    print(f"{len(results) - len(failed)}/{len(results)} PASS")
    if failed:
        print("FAILED: " + ", ".join(failed))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
