#!/usr/bin/env python3
"""Which approval fields can be rewritten without the engine noticing?

The grant EVENT already records subject, granted_by, method and expires_at.
find_approval() compares scope_sha256 and nothing else.

Every case builds its OWN mission and derives the required scope from THAT
mission, because an earlier draft reused one scope across fresh temp
workspaces and refused everything for the wrong reason. A probe whose control
does not pass proves nothing.
"""
import os, sqlite3, sys, tempfile
from pathlib import Path
ENGINE = Path.home() / "projects/shadowfetch-4.0.0/packages/shadowfetch-missions/data/usr/lib/shadowfetch/missions"
sys.path.insert(0, str(ENGINE))
R0 = tempfile.mkdtemp(prefix="p31a-")
os.environ["SHADOWFETCH_MISSIONS_STATE"] = R0
os.environ["SHADOWFETCH_AGENT_WORKSPACES"] = R0 + "/ws"
import sf_missions as sf
import sf_policy


def build():
    d = tempfile.mkdtemp(prefix="p31a-")
    ws = Path(d) / "ws" / "probe"; ws.mkdir(parents=True, exist_ok=True)
    (ws / "a.mkv").write_bytes(b"clip")
    os.environ["SHADOWFETCH_AGENT_WORKSPACES"] = str(Path(d) / "ws")
    s = sf.Store(d)
    mid = s.create(capability="media_export", provider_id="offline-media",
                   workspace_value="probe", title="t", prompt="p", inputs=["a.mkv"])["id"]
    scope = {"provider": "offline-media", "capability": "media_export",
             "workspace": s.get(mid)["workspace"], "network": "none"}
    aid = s.grant_approval(subject=mid, scope=scope, granted_by="the-owner",
                           method="cli", expires_at="2099-01-01T00:00:00+00:00")
    return d, s, mid, aid, sf_policy.Scope.from_json(scope)


CASES = [
    ("granted_by -> 'somebody-else'", "UPDATE approvals SET granted_by='somebody-else'"),
    ("method -> 'forged'", "UPDATE approvals SET method='forged'"),
    ("granted_at -> 1999", "UPDATE approvals SET granted_at='1999-01-01T00:00:00+00:00'"),
    ("expires_at extended to 2099-12", "UPDATE approvals SET expires_at='2099-12-31T00:00:00+00:00'"),
    ("expires_at REMOVED (never expires)", "UPDATE approvals SET expires_at=NULL"),
    ("EXPIRED approval revived", None),          # special: grant expired, then extend
    ("revoked_at cleared after revoke", "REVOKE"),
    ("reason rewritten", "UPDATE approvals SET reason='a different justification'"),
    ("approval id rewritten", "UPDATE approvals SET id='appr-attacker0000'"),
    ("scope -> another provider (control)", "UPDATE approvals SET scope=replace(scope,'offline-media','codex')"),
]

d, s, mid, aid, req = build()
row, why = s.find_approval(mid, req)
print("CONTROL (untouched approval): %s\n" % ("ACCEPTED, as it should be" if row
                                              else "REFUSED -- probe broken: " + str(why)[:70]))
if not row:
    raise SystemExit("control failed; measurements would be meaningless")

print("%-40s %s" % ("EDIT MADE DIRECTLY TO THE approvals TABLE", "RESULT"))
print("-" * 92)
undetected = 0
for label, stmt in CASES:
    d, s, mid, aid, req = build()
    if stmt == "REVOKE":
        s.revoke_approval(aid, reason="withdrawn")
        stmt = "UPDATE approvals SET revoked_at=NULL"
    elif stmt is None:
        db = sqlite3.connect(os.path.join(d, "missions.sqlite3"))
        db.execute("UPDATE approvals SET expires_at='2000-01-01T00:00:00+00:00'")
        db.commit(); db.close()
        stmt = "UPDATE approvals SET expires_at='2099-12-31T00:00:00+00:00'"
    db = sqlite3.connect(os.path.join(d, "missions.sqlite3"))
    db.execute(stmt); db.commit(); db.close()
    row, why = s.find_approval(mid, req)
    if row:
        undetected += 1
        print("%-40s *** ACCEPTED -- NOT DETECTED ***" % label)
    else:
        print("%-40s refused: %s" % (label, (why or "")[:44]))
print("-" * 92)
print("%d of %d edits went undetected" % (undetected, len(CASES)))
