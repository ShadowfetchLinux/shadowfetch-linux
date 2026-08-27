import subprocess, json, os, shutil, sys
from pathlib import Path

FL = Path(__file__).resolve().parents[1]
MCP = ["python3", str(FL / "data/usr/lib/shadowfetch/mcp/sf_mcp.py")]

def session(server, calls, env=None):
    e = dict(os.environ); e.update(env or {})
    inp = "\n".join(json.dumps(c) for c in calls) + "\n"
    r = subprocess.run(MCP + [server], input=inp, capture_output=True, text=True, env=e, timeout=30)
    return [json.loads(l) for l in r.stdout.splitlines() if l.strip()]

init = {"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
def call(name, args): return {"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":name,"arguments":args}}

passed=failed=0
def check(desc, cond):
    global passed, failed
    cond=bool(cond); print(("  PASS " if cond else "  FAIL ")+desc)
    passed+=cond; failed+= (not cond)

# handshake protocolVersion
for srv in ("passport","phoenix","checkpoint","fs"):
    out=session(srv,[init])
    check(f"{srv}: initialize returns protocolVersion", out and out[0]["result"].get("protocolVersion"))

# checkpoint full: snapshot -> modify (same-size edit) -> diff shows M -> undo
root="/tmp/sf-full"; shutil.rmtree(root, ignore_errors=True)
Path(root+"/proj/src").mkdir(parents=True); Path(root+"/proj/src/app.py").write_text("aaaaaaaa\n")
env={"SHADOWFETCH_AGENT_WORKSPACES":root}
out=session("checkpoint",[init, call("snapshot",{"workspace":"proj"})],env)
cid=out[1]["result"]["content"][0]["text"].split()[1]
Path(root+"/proj/src/app.py").write_text("bbbbbbbb\n")  # SAME size, different content
out=session("checkpoint",[init, call("diff",{"workspace":"proj","checkpoint":cid})],env)
difftext=out[1]["result"]["content"][0]["text"]
check("diff detects equal-size content edit (M)", "M src/app.py" in difftext)
out=session("checkpoint",[init, call("undo",{"workspace":"proj","checkpoint":cid})],env)
check("undo restores equal-size edit", Path(root+"/proj/src/app.py").read_text()=="aaaaaaaa\n")
check("undo left a pre-undo safety checkpoint", len(list(Path(root+"/proj").parent.glob(".sf-checkpoints/proj/*.json")))>=2)

# invalid workspace name refused
out=session("checkpoint",[init, call("snapshot",{"workspace":"../etc"})],env)
check("checkpoint refuses path-traversal workspace name", out[1]["result"].get("isError"))

# fs read-only, scope
out=session("fs",[init, call("read_file",{"path":"src/app.py"})],{"SF_MCP_FS_ROOT":root+"/proj"})
check("fs read in-scope OK", not out[1]["result"].get("isError"))
out=session("fs",[init, call("read_file",{"path":"../../../etc/hostname"})],{"SF_MCP_FS_ROOT":root+"/proj"})
check("fs refuses scope escape", out[1]["result"].get("isError"))
out=session("fs",[init, {"jsonrpc":"2.0","id":9,"method":"tools/list"}],{"SF_MCP_FS_ROOT":root+"/proj"})
names=[t["name"] for t in out[1]["result"]["tools"]]
check("fs exposes no write tool", "write_file" not in names and set(names)=={"list_dir","read_file"})

# unknown method returns JSON-RPC error, not crash
out=session("passport",[{"jsonrpc":"2.0","id":5,"method":"bogus/method"}])
check("unknown method -> JSON-RPC error", out and "error" in out[0])

print(f"\n  {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
