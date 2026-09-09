#!/usr/bin/env python3
"""Rewrite an event, then forge the journal line that would cover it.

This is the attack the per-seq comparison was supposed to catch and did not:
the mission uid can write /dev/log, so it could simply append a newer line for
the same seq carrying the new hash.
"""
import json, os, sqlite3, sys, tempfile, time
from pathlib import Path
ENGINE = Path.home() / "projects/shadowfetch-4.0.0/packages/shadowfetch-missions/data/usr/lib/shadowfetch/missions"
sys.path.insert(0, str(ENGINE))
R0 = tempfile.mkdtemp(prefix="p31j-")
os.environ["SHADOWFETCH_MISSIONS_STATE"] = R0
os.environ["SHADOWFETCH_AGENT_WORKSPACES"] = R0 + "/ws"
import sf_missions as sf
import sf_audit

d = tempfile.mkdtemp(prefix="p31j-")
ws = Path(d) / "ws" / "probe"; ws.mkdir(parents=True, exist_ok=True)
(ws / "a.mkv").write_bytes(b"clip")
os.environ["SHADOWFETCH_AGENT_WORKSPACES"] = str(Path(d) / "ws")
s = sf.Store(d)
mid = s.create(capability="media_export", provider_id="offline-media",
               workspace_value="probe", title="t", prompt="p", inputs=["a.mkv"])["id"]
s.transition(mid, sf.MissionState.RUNNING)
s.transition(mid, sf.MissionState.WAITING_REVIEW)
time.sleep(1)

r = s.verify_chain()
print("before:      ok=%s anchor=%s" % (r["ok"], r["anchor"]["verdict"]))

# rewrite seq 3 and re-chain the tail with the engine's own hasher
db = sqlite3.connect(os.path.join(d, "missions.sqlite3"))
db.row_factory = sqlite3.Row
rows = [dict(x) for x in db.execute("SELECT * FROM events ORDER BY seq")]
target = 3
prev = rows[target - 2]["hash"] if target >= 2 else sf.GENESIS_PREV
for row in rows:
    if row["seq"] < target: continue
    if row["seq"] == target: row["detail"] = "REWRITTEN BY THE ATTACKER"
    row["prev_hash"] = prev
    row["hash"] = sf.event_hash(prev, row)
    db.execute("UPDATE events SET detail=?,prev_hash=?,hash=? WHERE seq=?",
               (row["detail"], row["prev_hash"], row["hash"], row["seq"]))
    prev = row["hash"]
db.commit()
newhash = db.execute("SELECT hash FROM events WHERE seq=?", (target,)).fetchone()[0]
db.close()

r = s.verify_chain()
print("after rewrite: ok=%s anchor=%s  problems=%d" % (r["ok"], r["anchor"]["verdict"], len(r["problems"])))

# THE ATTACK: forge one journal line for the same seq with the new hash
chain = s.chain_id()
payload = {"chain": chain, "seq": target, "hash": newhash,
           "mission": mid, "event": "running", "at": sf.now()}
ok, why = sf_audit.mirror(payload)
print("forged journal line sent: %s%s" % (ok, "" if ok else " (" + str(why) + ")"))
time.sleep(2)

r = s.verify_chain()
a = r["anchor"]
print()
print("AFTER THE FORGED APPEND:")
print("  ok            =", r["ok"])
print("  anchor verdict=", a["verdict"])
print("  rewritten_seqs=", a.get("rewritten_seqs"))
print("  mirror_conflicts=", a.get("mirror_conflicts"))
for p in r["problems"][:4]:
    print("  problem:", p[:150])
print()
print("VERDICT:", "ATTACK DETECTED" if not r["ok"] else "*** ATTACK SUCCEEDED -- covered up ***")
