#!/usr/bin/env python3
"""Stage A: can a forged receipt still rest on rewritten domain rows?

Run as an attack module: exits non-zero if any edit goes undetected.

Each edit below changes a fact the receipt reprints. Before Stage A every one
of them went undetected while `audit verify` reported the chain intact.
"""
import json, os, sqlite3, sys, tempfile, time
from pathlib import Path
ENGINE = Path.home() / "projects/shadowfetch-4.0.0/packages/shadowfetch-missions/data/usr/lib/shadowfetch/missions"
sys.path.insert(0, str(ENGINE))
R0 = tempfile.mkdtemp(prefix="stgA-")
os.environ["SHADOWFETCH_MISSIONS_STATE"] = R0
os.environ["SHADOWFETCH_AGENT_WORKSPACES"] = R0 + "/ws"
import sf_missions as sf


def build():
    """A mission with one of every domain record, written by the engine."""
    d = tempfile.mkdtemp(prefix="stgA-")
    ws = Path(d) / "ws" / "probe"; ws.mkdir(parents=True)
    (ws / "a.mkv").write_bytes(b"clip")
    os.environ["SHADOWFETCH_AGENT_WORKSPACES"] = str(Path(d) / "ws")
    s = sf.Store(d)
    mid = s.create(capability="media_export", provider_id="offline-media",
                   workspace_value="probe", title="t", prompt="p", inputs=["a.mkv"])["id"]
    task = s.create_task(mid, kind="media", seq=1)["id"]
    sid = s.open_session(mid, task_id=task, provider_id="offline-media",
                         provider_version="4.0.0", provider_trust="distro-managed",
                         attempt=1, requested_sandbox={"network": "none"},
                         effective_sandbox={"network": "none"},
                         enforcement={"network": "enforced"},
                         executable="/usr/bin/ffprobe",
                         executable_trust="distro-managed",
                         network_requested="none", network_effective="none")
    s.record_tool_execution(sid, seq=1, tool="shell", args_digest="d" * 64,
                            requested_action="ls", decision="observed",
                            exit_status="0")
    s.record_test_run(mid, task_id=task, command=["pytest"], executable="/usr/bin/pytest",
                      sandbox_mode="firebreak", network_requested="none",
                      network_effective="none", enforcement={"network": "enforced"},
                      guard_state="intact", started_at=sf.now(), duration_ms=12,
                      exit_code=0, log_path="/tmp/x.log", result="passed")
    s.record_git_change(mid, repo_path=str(ws),
                        delta={"head_before": "a", "head_after": "b",
                               "hooks_changed": [".git/hooks/pre-commit"],
                               "new_executables": ["build.sh"]})
    s.open_review(mid, summary="one file changed")
    s.record_artifact(mid, task_id=task, path=str(ws / "a.mkv"), sha256="e" * 64,
                      size=4, kind="media")
    s.close_session(sid, exit_code=0, outcome="succeeded")
    s.decide_review(mid, "undo", decided_by="uid:1000")
    return d, s


CASES = [
    ("session: which EXECUTABLE ran",
     "UPDATE agent_sessions SET executable='/tmp/evil'"),
    ("session: executable TRUST class",
     "UPDATE agent_sessions SET executable_trust='unknown'"),
    ("session: what the sandbox ENFORCED",
     """UPDATE agent_sessions SET enforcement='{"network": "enforced", "masked_paths": "enforced"}'"""),
    ("session: which CREDENTIALS were granted",
     """UPDATE agent_sessions SET credentials_granted='["OPENAI_API_KEY"]'"""),
    ("session: the NETWORK it actually got",
     "UPDATE agent_sessions SET network_effective='allow'"),
    ("session: how it ENDED",
     "UPDATE agent_sessions SET exit_code=0, outcome='succeeded and was clean'"),
    ("tool: the policy DECISION",
     "UPDATE tool_executions SET decision='auto_allow'"),
    ("tool: the APPROVAL it cites",
     "UPDATE tool_executions SET approval_id='appr-invented'"),
    ("tool: what the human READS",
     "UPDATE tool_executions SET requested_action='ls -l', args_redacted='[]'"),
    ("test run: RESULT passed -> failed",
     "UPDATE test_runs SET result='failed', exit_code=1"),
    ("test run: the COMMAND that ran",
     "UPDATE test_runs SET command='[\"true\"]'"),
    ("git change: hooks installed -> none",
     """UPDATE git_changes SET hooks_changed='[]', new_executables='[]'"""),
    ("review: the evidence presented",
     """UPDATE reviews SET summary='{"files": 0}'"""),
    ("review: WHO decided and WHAT",
     "UPDATE reviews SET decision='accept', decided_by='uid:0'"),
    ("artifact: its DIGEST",
     "UPDATE artifacts SET sha256='0000000000000000000000000000000000000000000000000000000000000000'"),
    ("artifact: a whole INVENTED row",
     "INSERT INTO artifacts(id,mission_id,task_id,path,sha256,bytes,kind,created_at) "
     "SELECT 'art-invented',mission_id,task_id,'/tmp/planted',sha256,bytes,kind,created_at FROM artifacts LIMIT 1"),
]

d, s = build()
r = s.verify_chain()
print("CONTROL (untouched): ok=%s chain_ok=%s domain=%s (%d of %d witnessed)\n" % (
    r["ok"], r["chain_ok"], r["domain"]["verdict"],
    r["domain"]["verified"], r["domain"]["records"]))
if not r["ok"]:
    print("  problems:", r["problems"][:3])
    raise SystemExit("control failed; measurements would be meaningless")

print("%-44s %s" % ("EDIT MADE DIRECTLY TO A DOMAIN TABLE", "RESULT"))
print("-" * 92)
undetected = 0
for label, stmt in CASES:
    d, s = build()
    db = sqlite3.connect(os.path.join(d, "missions.sqlite3"))
    db.execute(stmt); db.commit(); db.close()
    r = s.verify_chain()
    if r["ok"]:
        undetected += 1
        print("%-44s *** UNDETECTED ***" % label)
    else:
        why = (r["domain"]["problems"] or r["problems"])[0]
        print("%-44s detected: %s" % (label, why.split(":")[0][:36]))
print("-" * 92)
print("%d of %d edits went undetected" % (undetected, len(CASES)))


raise SystemExit(1 if undetected else 0)
