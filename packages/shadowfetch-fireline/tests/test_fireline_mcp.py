import subprocess, json, os, re, shutil, sys
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
Path("/tmp/sf-handshake").mkdir(exist_ok=True)
for srv in ("passport","phoenix","checkpoint","fs"):
    out=session(srv,[init], {"SF_MCP_FS_ROOT":"/tmp/sf-handshake"} if srv=="fs" else None)
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


# --------------------------------------------------------------------------- #
# W-28: the checkpoint id is DATA, not a word in a sentence.
#
# Mission Control used to recover it with re.search(r"checkpoint ([0-9-]+)")
# over the sentence the snapshot tool returns, and Firebreak split the same
# words. These checks hold both halves of the fix: the structured API hands the
# id back directly, and the sentences agents/scripts read did not move.
#
# GOLD is the wording shipped in 4.0.0, copied from the implementation as it
# stood before the structured engine landed. It is an interface, not a comment:
# if one of these strings has to change, every consumer changes with it.
# --------------------------------------------------------------------------- #
sys.path.insert(0, str(FL / "data/usr/lib/shadowfetch/mcp"))
import sf_mcp

CLI = [sys.executable, str(FL / "data/usr/bin/shadowfetch-checkpoint")]
GOLD = {
    "snapshot":   "checkpoint {id} taken ({method}) for workspace '{ws}'.",
    "list_empty": "no checkpoints for '{ws}'.",
    "list_head":  "checkpoints for '{ws}':",
    "list_row":   "  {id}  {method:6}  {label}",
    "diff_none":  "no changes since checkpoint.",
    "diff_head":  "changed since checkpoint:",
    "diff_row":   "  {mark} {path}",
    "undo":       ("workspace '{ws}' restored to checkpoint {id}. A safety "
                   "checkpoint of the pre-undo state was taken first."),
}

W = "/tmp/sf-w28"
shutil.rmtree(W, ignore_errors=True)
Path(W + "/proj/src").mkdir(parents=True)
Path(W + "/proj/src/app.py").write_text("one\n")
Path(W + "/proj/keep.md").write_text("keep\n")
Path(W + "/blank").mkdir()
os.environ["SHADOWFETCH_AGENT_WORKSPACES"] = W
env28 = {"SHADOWFETCH_AGENT_WORKSPACES": W}
store = Path(W) / ".sf-checkpoints/proj"

def mcp_text(tool, args):
    out = session("checkpoint", [init, call(tool, args)], env28)
    return out[1]["result"]["content"][0]["text"]

def cli(*argv):
    return subprocess.run(CLI + list(argv), capture_output=True, text=True,
                          env=dict(os.environ), timeout=120)

# -- 1. the structured API hands back the id, with nothing to parse ---------- #
snap = sf_mcp.checkpoint_call("snapshot", workspace="proj", label="mission:m-1")
check("structured snapshot returns a mapping, not a sentence", isinstance(snap, dict))
check("structured snapshot carries a non-empty id",
      isinstance(snap.get("id"), str) and snap["id"].strip())
check("structured snapshot names workspace and method",
      snap["workspace"] == "proj" and snap["method"] in ("btrfs", "tar"))
check("structured snapshot keeps the label and created stamp",
      snap["label"] == "mission:m-1" and snap["created"] == snap["id"])
check("structured id is the id the engine wrote to its metadata file",
      json.loads((store / f"{snap['id']}.json").read_text())["id"] == snap["id"])
check("structured snapshot keys are the documented set",
      set(snap) == {"action", "id", "workspace", "method", "label", "created", "archive"})

# -- 2. the human text is unchanged, and is rendered FROM that result -------- #
gold_snapshot = GOLD["snapshot"].format(id=snap["id"], method=snap["method"], ws="proj")
check("format_snapshot renders the shipped sentence",
      sf_mcp.format_snapshot(snap) == gold_snapshot)
mcp_snapshot = mcp_text("snapshot", {"workspace": "proj"})
mcp_cid = mcp_snapshot.split()[1]
check("MCP snapshot text is unchanged",
      mcp_snapshot == GOLD["snapshot"].format(id=mcp_cid, method=snap["method"], ws="proj"))

listing = sf_mcp.checkpoint_call("list", workspace="proj")
gold_list = GOLD["list_head"].format(ws="proj") + "\n" + "\n".join(
    GOLD["list_row"].format(**row) for row in listing["checkpoints"])
check("format_list renders the shipped table", sf_mcp.format_list(listing) == gold_list)
check("MCP list text is unchanged", mcp_text("list", {"workspace": "proj"}) == gold_list)
check("structured list counts what it returns",
      listing["count"] == len(listing["checkpoints"]) == 2)
check("MCP empty-list text is unchanged",
      mcp_text("list", {"workspace": "blank"}) == GOLD["list_empty"].format(ws="blank"))
check("structured empty list is an empty list, not a sentence",
      sf_mcp.checkpoint_call("list", workspace="blank")["checkpoints"] == [])

check("MCP no-change diff text is unchanged",
      mcp_text("diff", {"workspace": "proj", "checkpoint": snap["id"]}) == GOLD["diff_none"])
Path(W + "/proj/src/app.py").write_text("two\n")
Path(W + "/proj/added.txt").write_text("new\n")
Path(W + "/proj/keep.md").unlink()
d = sf_mcp.checkpoint_call("diff", workspace="proj", checkpoint=snap["id"])
check("structured diff reports statuses, not display strings",
      [(c["status"], c["path"]) for c in d["changes"]] ==
      [("added", "added.txt"), ("removed", "keep.md"), ("modified", "src/app.py")])
check("structured diff counts and flags truncation",
      d["count"] == 3 and d["truncated"] is False)
gold_diff = GOLD["diff_head"] + "\n" + "\n".join(
    GOLD["diff_row"].format(mark=m, path=p) for m, p in
    [("+", "added.txt"), ("-", "keep.md"), ("M", "src/app.py")])
check("format_diff renders the shipped listing", sf_mcp.format_diff(d) == gold_diff)
check("MCP diff text is unchanged",
      mcp_text("diff", {"workspace": "proj", "checkpoint": snap["id"]}) == gold_diff)

check("MCP undo text is unchanged",
      mcp_text("undo", {"workspace": "proj", "checkpoint": mcp_cid}) ==
      GOLD["undo"].format(ws="proj", id=mcp_cid))
u = sf_mcp.checkpoint_call("undo", workspace="proj", checkpoint=snap["id"])
check("format_undo renders the shipped sentence",
      sf_mcp.format_undo(u) == GOLD["undo"].format(ws="proj", id=snap["id"]))
check("structured undo names the safety checkpoint it took",
      u["safety"]["id"] != snap["id"] and (store / f"{u['safety']['id']}.json").exists())
check("undo actually restored the workspace",
      Path(W + "/proj/src/app.py").read_text() == "one\n"
      and not Path(W + "/proj/added.txt").exists())

# -- 3. the CLI: --json is structured, and without it nothing moved ---------- #
plain = cli("snapshot", "proj", "--label", "cli")
cli_cid = plain.stdout.strip().split()[1]
check("CLI snapshot output is unchanged",
      plain.returncode == 0 and plain.stdout ==
      GOLD["snapshot"].format(id=cli_cid, method=snap["method"], ws="proj") + "\n")
check("CLI list output is unchanged",
      cli("list", "proj").stdout ==
      sf_mcp.format_list(sf_mcp.checkpoint_call("list", workspace="proj")) + "\n")
check("CLI empty-list output is unchanged",
      cli("list", "blank").stdout == GOLD["list_empty"].format(ws="blank") + "\n")

j = cli("snapshot", "proj", "--json")
check("CLI --json exits 0", j.returncode == 0)
try:
    payload = json.loads(j.stdout)
except ValueError:
    payload = None
check("CLI --json emits valid JSON", isinstance(payload, dict))
check("CLI --json emits the documented snapshot keys",
      payload and set(payload) ==
      {"action", "id", "workspace", "method", "label", "created", "archive"}
      and payload["action"] == "snapshot" and payload["workspace"] == "proj")
check("CLI --json id is a real checkpoint on disk",
      payload and (store / f"{payload['id']}.json").exists())
check("CLI --json prints only JSON: no sentence to parse",
      payload and "taken (" not in j.stdout)
before_sub = cli("--json", "list", "proj")
check("CLI accepts --json before the subcommand too",
      before_sub.returncode == 0 and
      set(json.loads(before_sub.stdout)) == {"action", "workspace", "count", "checkpoints"})
dj = json.loads(cli("diff", "proj", payload["id"], "--json").stdout)
check("CLI --json diff emits the documented keys",
      set(dj) == {"action", "workspace", "checkpoint", "method", "count", "truncated", "changes"})
uj = json.loads(cli("undo", "proj", payload["id"], "--json").stdout)
check("CLI --json undo emits the documented keys",
      set(uj) == {"action", "workspace", "checkpoint", "method", "label", "safety"}
      and set(uj["safety"]) == {"id", "method"})
bad = cli("diff", "proj", "no-such-checkpoint", "--json")
check("CLI --json reports failure as JSON, not a traceback",
      bad.returncode == 1 and json.loads(bad.stdout) ==
      {"action": "diff", "error": "no such checkpoint: no-such-checkpoint"}
      and "Traceback" not in bad.stderr)
check("CLI --json also states the reason on stderr (Firebreak reads it)",
      bad.stderr == "no such checkpoint: no-such-checkpoint\n")

# -- 4. an id the retired regex would have mangled --------------------------- #
# The regex was [0-9-]+, so today's timestamp ids happen to survive it. Change
# the id format at all -- an ISO stamp, a ULID, a uuid4 -- and the old parser
# silently returns a PREFIX, which is not a checkpoint. The structured path
# cannot have that failure, because it never looks at the sentence.
hostile = "2026-09-08T12:13:14.500Z"
original_mint = sf_mcp._mint_id
try:
    sf_mcp._mint_id = lambda: hostile
    odd = sf_mcp.checkpoint_call("snapshot", workspace="proj", label="iso-8601 id")
finally:
    sf_mcp._mint_id = original_mint
check("structured path returns a non-[0-9-] id verbatim", odd["id"] == hostile)
sentence = sf_mcp.format_snapshot(odd)
scraped = re.search(r"checkpoint ([0-9-]+)", sentence)
mangled = scraped.group(1) if scraped else None
check("the retired regex silently mangles that id", mangled == "2026-09-08" != hostile)
check("structured id round-trips through diff",
      sf_mcp.checkpoint_call("diff", workspace="proj", checkpoint=odd["id"])["checkpoint"] == hostile)
check("structured id round-trips through undo",
      sf_mcp.checkpoint_call("undo", workspace="proj", checkpoint=odd["id"])["checkpoint"] == hostile)
mangled_worked = True
try:
    sf_mcp.checkpoint_call("diff", workspace="proj", checkpoint=mangled)
except (sf_mcp._ToolError, TypeError):
    mangled_worked = False
check("the scraped prefix is not a checkpoint (the bug was real)", not mangled_worked)
check("CLI --json returns such an id unparsed",
      any(c["id"] == hostile for c in
          json.loads(cli("list", "proj", "--json").stdout)["checkpoints"]))

# -- 5. Firebreak no longer splits the sentence either ----------------------- #
firebreak_src = (FL / "data/usr/bin/shadowfetch-firebreak").read_text()
check("firebreak asks the checkpoint CLI for JSON", '"--json"' in firebreak_src)
check("firebreak no longer splits the checkpoint sentence",
      "result.stdout.split()" not in firebreak_src)
check("firebreak still prints its own unchanged receipt line",
      'print("checkpoint " + checkpoint + " taken", flush=True)' in firebreak_src)

print(f"\n  {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
