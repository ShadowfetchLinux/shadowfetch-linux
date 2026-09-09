#!/usr/bin/env python3
"""Attack the legacy pin itself -- the mechanism added to close the fabricated-
mission finding. Two ways it was still a way through:

A. a pinned mission was exempt from replay forever, and the pin publishes the
   ids in plaintext, so an attacker reads one out of the log and edits it
B. a forged, unchained pin row reclassified a fabricated mission as legitimate
"""
import json, os, sqlite3, sys, tempfile
from pathlib import Path
ENGINE = Path.home() / "projects/shadowfetch-4.0.0/packages/shadowfetch-missions/data/usr/lib/shadowfetch/missions"
sys.path.insert(0, str(ENGINE))
R0 = tempfile.mkdtemp(prefix="p31p-")
os.environ["SHADOWFETCH_MISSIONS_STATE"] = R0
os.environ["SHADOWFETCH_AGENT_WORKSPACES"] = R0 + "/ws"
import sf_missions as sf

LEGACY_SQL = """
CREATE TABLE missions (id TEXT PRIMARY KEY, title TEXT NOT NULL, kind TEXT NOT NULL,
  state TEXT NOT NULL, workspace TEXT NOT NULL, prompt TEXT NOT NULL, config TEXT NOT NULL,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL, attempt INTEGER NOT NULL DEFAULT 0,
  error TEXT, checkpoint TEXT, artifacts TEXT NOT NULL DEFAULT '[]', receipt TEXT,
  cancel_requested INTEGER NOT NULL DEFAULT 0);
CREATE TABLE events (seq INTEGER PRIMARY KEY AUTOINCREMENT, mission TEXT NOT NULL,
  at TEXT NOT NULL, event TEXT NOT NULL, detail TEXT NOT NULL);
CREATE TABLE steps (mission TEXT NOT NULL, name TEXT NOT NULL, result TEXT NOT NULL,
  PRIMARY KEY (mission, name));
"""


def legacy_db():
    """A pre-chain database with one genuinely event-less mission."""
    d = tempfile.mkdtemp(prefix="p31p-")
    Path(d, "ws", "probe").mkdir(parents=True)
    db = sqlite3.connect(os.path.join(d, "missions.sqlite3"))
    db.executescript(LEGACY_SQL)
    db.execute("INSERT INTO missions(id,title,kind,state,workspace,prompt,config,"
               "created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
               ("mission-orphan", "old", "report", "waiting-review",
                str(Path(d, "ws", "probe")), "p", "{}", sf.now(), sf.now()))
    db.commit(); db.close()
    os.environ["SHADOWFETCH_AGENT_WORKSPACES"] = str(Path(d, "ws"))
    return d


print("=" * 74)
print("A. a PINNED mission is edited after the pin")
d = legacy_db()
s = sf.Store(d)                      # migrate -> v4 -> writes the pin
r = s.verify_chain()
print("  after upgrade:            ok=%s states=%s class=%s" % (
    r["ok"], r["states"]["verdict"], r["states"]["classes"].get("mission-orphan")))
print("  pin published these ids:  %s" % sorted(s.legacy_missions()))
db = sqlite3.connect(os.path.join(d, "missions.sqlite3"))
db.execute("UPDATE missions SET state='completed' WHERE id='mission-orphan'")
db.commit(); db.close()
r = sf.Store(d).verify_chain()
print("  after UPDATE -> completed: ok=%s states=%s class=%s" % (
    r["ok"], r["states"]["verdict"], r["states"]["classes"].get("mission-orphan")))
for p in r["problems"][:2]: print("    problem:", p[:150])
print("  VERDICT:", "DETECTED" if not r["ok"] else "*** STILL A WAY THROUGH ***")

print()
print("=" * 74)
print("B. a FORGED, UNCHAINED pin excuses a fabricated mission")
d2 = tempfile.mkdtemp(prefix="p31p-")
Path(d2, "ws", "probe").mkdir(parents=True)
Path(d2, "ws", "probe", "a.mkv").write_bytes(b"x")
os.environ["SHADOWFETCH_AGENT_WORKSPACES"] = str(Path(d2, "ws"))
s2 = sf.Store(d2)
mid = s2.create(capability="media_export", provider_id="offline-media",
                workspace_value="probe", title="real", prompt="p", inputs=["a.mkv"])["id"]
db = sqlite3.connect(os.path.join(d2, "missions.sqlite3"))
db.row_factory = sqlite3.Row
cols = [x[1] for x in db.execute("PRAGMA table_info(missions)")]
row = dict(zip(cols, db.execute("SELECT * FROM missions WHERE id=?", (mid,)).fetchone()))
row["id"] = "mission-forged"; row["state"] = "completed"
db.execute("INSERT INTO missions (%s) VALUES (%s)" % (",".join(cols), ",".join("?" * len(cols))),
           [row[c] for c in cols])
db.execute("INSERT INTO events(mission,at,event,detail) VALUES(?,?,?,?)",
           ("*", sf.now(), sf.LEGACY_PIN,
            json.dumps({"missions": ["mission-forged"],
                        "states": {"mission-forged": "completed"}})))
db.commit(); db.close()
r = sf.Store(d2).verify_chain()
print("  ok=%s chain_ok=%s states=%s class(forged)=%s" % (
    r["ok"], r.get("chain_ok"), r["states"]["verdict"],
    r["states"]["classes"].get("mission-forged")))
for p in r["problems"][:3]: print("    problem:", p[:150])
print("  VERDICT:", "DETECTED" if (not r["ok"] and r["states"]["verdict"] == "disagrees")
      else "*** the mission finding was suppressed ***")
