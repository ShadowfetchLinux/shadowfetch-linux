"""Regression tests for the Fireline privilege boundary (Phase 1 W-04, W-05).

Both defects shipped in 4.0.0:
  W-04  a polkit action granted allow_active=yes for exec of
        /usr/bin/shadowfetch-firebreak, which runs an arbitrary command, so
        `pkexec shadowfetch-firebreak run -- sh` was a passwordless root shell.
  W-05  the fs MCP server defaulted its scope to the process CWD, so an agent
        started from $HOME could read the entire home directory.
"""
import importlib.machinery
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
MCP_PY = BASE / "data/usr/lib/shadowfetch/mcp/sf_mcp.py"
loader = importlib.machinery.SourceFileLoader("sf_mcp", str(MCP_PY))
spec = importlib.util.spec_from_loader("sf_mcp", loader)
sf_mcp = importlib.util.module_from_spec(spec)
loader.exec_module(sf_mcp)

passed = failed = 0


def check(desc, cond):
    global passed, failed
    cond = bool(cond)
    print(("  PASS " if cond else "  FAIL ") + desc)
    passed += cond
    failed += (not cond)


def scope_refused(value):
    """True when build_fs refuses the given SF_MCP_FS_ROOT."""
    previous = os.environ.get("SF_MCP_FS_ROOT")
    if value is None:
        os.environ.pop("SF_MCP_FS_ROOT", None)
    else:
        os.environ["SF_MCP_FS_ROOT"] = value
    try:
        sf_mcp.build_fs()
        return False
    except sf_mcp._ScopeError:
        return True
    finally:
        if previous is None:
            os.environ.pop("SF_MCP_FS_ROOT", None)
        else:
            os.environ["SF_MCP_FS_ROOT"] = previous


# -- W-04 -------------------------------------------------------------------
policies = list((BASE / "data").rglob("*.policy"))
check("no polkit action ships in the Fireline package", not policies)

install = (BASE / "debian/shadowfetch-fireline.install").read_text()
check("packaging installs no polkit action", "polkit-1/actions" not in install)

# The escalation the action enabled: firebreak runs an arbitrary command, so any
# polkit action naming it as exec.path is a root shell. Assert the property that
# made it dangerous still holds, so re-adding an action stays obviously wrong.
firebreak = (BASE / "data/usr/bin/shadowfetch-firebreak").read_text()
check("firebreak still takes an arbitrary command (so it must never be a pkexec target)",
      "argparse" in firebreak and "REMAINDER" in firebreak)

# -- W-05 -------------------------------------------------------------------
check("fs refuses to start with no scope set", scope_refused(None))
check("fs refuses an empty scope", scope_refused(""))
check("fs refuses the whole home directory", scope_refused(str(Path.home())))
check("fs refuses a filesystem root", scope_refused("/"))
check("fs refuses a top-level directory", scope_refused("/home"))
check("fs refuses /etc", scope_refused("/etc"))
check("fs refuses a credential store", scope_refused(str(Path.home() / ".ssh")))
check("fs refuses a relative scope", scope_refused("relative/path"))
check("fs refuses a scope that does not exist", scope_refused("/nonexistent-scope-xyz"))

with tempfile.TemporaryDirectory() as tmp:
    project = Path(tmp) / "project"
    (project / "src").mkdir(parents=True)
    (project / "src/app.py").write_text("print('hi')\n")
    check("fs accepts an explicit project scope", not scope_refused(str(project)))

    # Behaviour inside a legitimate scope must be unchanged.
    def session(calls, env):
        e = dict(os.environ)
        e.update(env)
        inp = "\n".join(json.dumps(c) for c in calls) + "\n"
        r = subprocess.run(["python3", str(MCP_PY), "fs"], input=inp,
                           capture_output=True, text=True, env=e, timeout=30)
        return r, [json.loads(l) for l in r.stdout.splitlines() if l.strip()]

    init = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}

    def call(name, args):
        return {"jsonrpc": "2.0", "id": 9, "method": "tools/call",
                "params": {"name": name, "arguments": args}}

    env = {"SF_MCP_FS_ROOT": str(project)}
    _, out = session([init, call("read_file", {"path": "src/app.py"})], env)
    check("in-scope read still works", not out[1]["result"].get("isError"))
    _, out = session([init, call("read_file", {"path": "../../../etc/hostname"})], env)
    check("relative scope escape still refused", out[1]["result"].get("isError"))
    _, out = session([init, call("read_file", {"path": "/etc/hostname"})], env)
    check("absolute path escape refused", out[1]["result"].get("isError"))

    # Unset scope must be a clean refusal on stderr with exit 2, not a traceback.
    e = dict(os.environ)
    e.pop("SF_MCP_FS_ROOT", None)
    r = subprocess.run(["python3", str(MCP_PY), "fs"], input="", capture_output=True,
                       text=True, env=e, timeout=30)
    check("unscoped launch exits 2", r.returncode == 2)
    check("unscoped launch explains itself without a traceback",
          "SF_MCP_FS_ROOT" in r.stderr and "Traceback" not in r.stderr)

    # The generated config must carry the scope, or it would start a dead server.
    wrapper = BASE / "data/usr/bin/shadowfetch-mcp"
    e = dict(os.environ)
    e["SF_MCP_FS_ROOT"] = str(project)
    r = subprocess.run(["bash", str(wrapper), "config", "--json"],
                       capture_output=True, text=True, env=e, timeout=30)
    check("generated JSON config is valid JSON", r.returncode == 0 and json.loads(r.stdout))
    cfg = json.loads(r.stdout)
    check("generated config scopes the fs server",
          cfg["mcpServers"]["shadowfetch-fs"]["env"]["SF_MCP_FS_ROOT"] == str(project))

print(f"\n  {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
