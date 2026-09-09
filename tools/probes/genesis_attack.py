#!/usr/bin/env python3
"""Delete the genesis, mint a new chain id, re-chain everything.

Before Phase 3.1 this produced problems=[] and 'chain intact' over a rewritten
log; the only tell was an anchor verdict of 'unverified', which is what an
honest fresh install also looks like.
"""
import json, os, sqlite3, sys, tempfile, time, uuid
from pathlib import Path
ENGINE = Path.home() / "projects/shadowfetch-4.0.0/packages/shadowfetch-missions/data/usr/lib/shadowfetch/missions"
sys.path.insert(0, str(ENGINE))
R0 = tempfile.mkdtemp(prefix="p31g-")
os.environ["SHADOWFETCH_MISSIONS_STATE"] = R0
os.environ["SHADOWFETCH_AGENT_WORKSPACES"] = R0 + "/ws"
import sf_missions as sf

d = tempfile.mkdtemp(prefix="p31g-")
ws = Path(d) / "ws" / "probe"; ws.mkdir(parents=True, exist_ok=True)
(ws / "a.mkv").write_bytes(b"clip")
os.environ["SHADOWFETCH_AGENT_WORKSPACES"] = str(Path(d) / "ws")
s = sf.Store(d)
mid = s.create(capability="media_export", provider_id="offline-media",
               workspace_value="probe", title="honest work", prompt="p", inputs=["a.mkv"])["id"]
s.transition(mid, sf.MissionState.RUNNING)
s.transition(mid, sf.MissionState.WAITING_REVIEW)
time.sleep(1.5)
r = s.verify_chain()
print("HONEST DATABASE:  ok=%s anchor=%s chain=%s" % (r["ok"], r["anchor"]["verdict"], s.chain_id()[:12]))
old_chain = s.chain_id()

# ---- THE ATTACK -----------------------------------------------------------
db = sqlite3.connect(os.path.join(d, "missions.sqlite3"))
db.row_factory = sqlite3.Row
# 1. rewrite history: the mission was never reviewed, say it completed
db.execute("UPDATE missions SET state='completed' WHERE id=?", (mid,))
# 2. drop every event and rebuild a chain that tells the new story
db.execute("DELETE FROM events")
new_chain = uuid.uuid4().hex
rows = [
    ("*", sf.now(), sf.CHAIN_GENESIS, json.dumps({"chain_id": new_chain,
                                                  "from_schema_version": None,
                                                  "to_schema_version": sf.SCHEMA_VERSION,
                                                  "unchained_events": 0,
                                                  "unchained_digest": "0" * 64}, sort_keys=True)),
    (mid, sf.now(), "queued", "media_export via offline-media"),
    (mid, sf.now(), "running", "the worker claimed a queued mission"),
    (mid, sf.now(), "waiting-review", "execution finished"),
    (mid, sf.now(), "completed", "a human accepted the work"),
]
prev = sf.GENESIS_PREV
for i, (mission, at, event, detail) in enumerate(rows, 1):
    row = {"seq": i, "mission": mission, "at": at, "event": event, "detail": detail,
           "task_id": None, "session_id": None, "tool_execution_id": None,
           "actor": sf.ACTOR_ORCHESTRATOR}
    h = sf.event_hash(prev, row)
    db.execute("INSERT INTO events(seq,mission,at,event,detail,task_id,session_id,"
               "tool_execution_id,actor,prev_hash,hash) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
               (i, mission, at, event, detail, None, None, None, sf.ACTOR_ORCHESTRATOR, prev, h))
    prev = h
db.commit(); db.close()

s2 = sf.Store(d)
r = s2.verify_chain()
a = r["anchor"]
print()
print("AFTER DELETING THE GENESIS AND RE-CHAINING:")
print("  the log now claims the mission COMPLETED (it was waiting-review)")
print("  new chain id  =", str(s2.chain_id())[:12], "(was %s)" % old_chain[:12])
print("  ok            =", r["ok"])
print("  chain_ok      =", r.get("chain_ok"))
print("  states        =", (r.get("states") or {}).get("verdict"))
print("  anchor verdict=", a["verdict"])
print("  other chains for this store =", a.get("other_chains_for_this_store"))
for p in r["problems"][:4]:
    print("  problem:", p[:160])
print()
print("VERDICT:", "RE-MINT DETECTED" if not r["ok"] else "*** ATTACK SUCCEEDED -- verifies clean ***")
