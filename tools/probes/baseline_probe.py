#!/usr/bin/env python3
"""Phase 3.1 Step 1: what the verifier does TODAY, before any fix.

Import ONCE. An earlier draft re-imported the engine per case, which changed the
class objects behind the provider registry's isinstance check and produced a
fake 'OfflineMediaProvider is not an AgentProvider'. The probe must not
manufacture defects.
"""
import json, os, sqlite3, subprocess, sys, tempfile
from pathlib import Path

REPO = Path.home() / "projects/shadowfetch-4.0.0"
ENGINE = REPO / "packages/shadowfetch-missions/data/usr/lib/shadowfetch/missions"
sys.path.insert(0, str(ENGINE))
CLI = [sys.executable, str(ENGINE / "sf_missions.py")]

ROOT0 = tempfile.mkdtemp(prefix="p31-")
os.environ["SHADOWFETCH_MISSIONS_STATE"] = ROOT0
os.environ["SHADOWFETCH_AGENT_WORKSPACES"] = ROOT0 + "/ws"
import sf_missions as sf


def fresh():
    d = tempfile.mkdtemp(prefix="p31-")
    ws = Path(d) / "ws" / "probe"
    ws.mkdir(parents=True, exist_ok=True)
    (ws / "a.mkv").write_bytes(b"clip")
    os.environ["SHADOWFETCH_AGENT_WORKSPACES"] = str(Path(d) / "ws")
    s = sf.Store(d)
    m = s.create(capability="media_export", provider_id="offline-media",
                 workspace_value="probe", title="baseline probe", prompt="p",
                 inputs=["a.mkv"])
    mid = m["id"]
    s.transition(mid, sf.MissionState.RUNNING)
    s.transition(mid, sf.MissionState.WAITING_REVIEW)
    return d, s, mid


def cli(state, *args):
    env = dict(os.environ, SHADOWFETCH_MISSIONS_STATE=state,
               SHADOWFETCH_AGENT_WORKSPACES=state + "/ws")
    p = subprocess.run(CLI + list(args), capture_output=True, text=True, env=env)
    return p.returncode


def report(label, state, store, extra=None):
    try:
        r = store.verify_chain()
        line = "ok=%s chain_ok=%s states=%s anchor=%s" % (
            r.get("ok"), r.get("chain_ok"),
            (r.get("states") or {}).get("verdict"), (r.get("anchor") or {}).get("verdict"))
        probs = [p[:140] for p in (r.get("problems") or [])[:3]] or ["NONE"]
    except Exception as exc:
        line = "RAISED %s: %s" % (type(exc).__name__, exc)
        probs = []
    print("\n" + "=" * 72)
    print("CASE:", label)
    if extra: print("     ", extra)
    print("  verify_chain :", line)
    for p in probs: print("     problem:", p)
    print("  CLI text exit=%d   |   CLI --json exit=%d" % (
        cli(state, "audit", "verify"), cli(state, "--json", "audit", "verify")))


def sql(state, *stmts):
    db = sqlite3.connect(os.path.join(state, "missions.sqlite3"))
    n = 0
    for st in stmts:
        n = db.execute(st).rowcount
    db.commit(); db.close()
    return n


# 1 -----------------------------------------------------------------
st, s, mid = fresh()
report("valid database", st, s, "queued -> running -> waiting-review")

# 2 -----------------------------------------------------------------
st, s, mid = fresh()
sql(st, "UPDATE events SET detail='TAMPERED' WHERE seq=(SELECT MAX(seq) FROM events)")
report("modified event row", st, s, "newest event's detail rewritten")

# 3 -----------------------------------------------------------------
st, s, mid = fresh()
n = sql(st, "DELETE FROM events WHERE seq=(SELECT MAX(seq) FROM events)")
report("deleted event (tail truncation)", st, s, "%d row removed from the end" % n)

# 4 -----------------------------------------------------------------
st, s, mid = fresh()
db = sqlite3.connect(os.path.join(st, "missions.sqlite3"))
cols = [r[1] for r in db.execute("PRAGMA table_info(missions)")]
row = dict(zip(cols, db.execute("SELECT * FROM missions WHERE id=?", (mid,)).fetchone()))
row["id"] = "fabricated-0001"; row["state"] = "completed"; row["title"] = "never ran"
db.execute("INSERT INTO missions (%s) VALUES (%s)" % (",".join(cols), ",".join("?" * len(cols))),
           [row[c] for c in cols])
db.commit(); db.close()
report("FABRICATED mission row", st, s, "state='completed', ZERO events")

# 5 -----------------------------------------------------------------
st, s, mid = fresh()
extra = ""
try:
    aid = s.grant_approval(subject=mid, scope={"provider_id": "offline-media"},
                           granted_by="the-owner", method="cli",
                           expires_at="2026-09-09T00:00:00+00:00")
    sql(st, "UPDATE approvals SET granted_by='somebody-else', method='forged', "
            "expires_at='2099-01-01T00:00:00+00:00'")
    found = s.find_approval(mid)
    extra = ("granted_by/method/expires_at all rewritten -> find_approval() returned %s"
             % ("AN APPROVAL (accepted)" if found else "None (refused)"))
    if found:
        extra += " | granted_by now reads %r" % (found.get("granted_by"),)
except Exception as exc:
    extra = "%s: %s" % (type(exc).__name__, exc)
report("modified approval provenance", st, s, extra)

# 6 -----------------------------------------------------------------
st, s, mid = fresh()
sql(st, "UPDATE missions SET state='failed', attempt=3 WHERE id='%s'" % mid)
try:
    s.transition(mid, sf.MissionState.QUEUED)
    extra = "transition(failed -> queued) at attempt 3: ACCEPTED"
except Exception as exc:
    extra = "transition refused: %s" % str(exc)[:110]
try:
    s.finish_execution(mid, sf.MissionState.QUEUED, None)
    extra += " | finish_execution(-> queued): ACCEPTED"
except Exception as exc:
    extra += " | finish_execution refused: %s" % str(exc)[:70]
report("retry budget at the ceiling", st, s, extra)

print("\n" + "=" * 72)
print("baseline probe complete")
