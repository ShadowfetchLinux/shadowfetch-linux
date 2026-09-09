import subprocess, json, os, re, shutil, sys, tempfile, atexit
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

# Step 17: every MCP call is recorded. Give the run its own state directory so a
# test never appends to the operator's real audit log, and so a stale log from a
# previous run is never what a test reads back.
# A private directory per run. The fixed path this used to have was rmtree'd
# at import, so two concurrent runs -- or two users on one machine -- destroyed
# each other's fixture. This is the only suite covering the destructive-tool
# gate, and a collision there is a green that means nothing.
STATE=tempfile.mkdtemp(prefix="sf-mcp-test-state-")
atexit.register(shutil.rmtree, STATE, True)
# The two purpose-named variables, not XDG_STATE_HOME: that one is ambient and
# no longer moves either directory, so a fixture relying on it fabricates its
# session record where nothing reads it and the gate correctly refuses.
os.environ["XDG_STATE_HOME"]=STATE
os.environ["SHADOWFETCH_MCP_STATE"]=STATE
os.environ["SHADOWFETCH_FIREBREAK_STATE"]=str(Path(STATE)/"shadowfetch/firebreak")

def recorded_session(sid):
    """The Firebreak session record that makes a correlation OBSERVED."""
    d=Path(STATE)/"shadowfetch/firebreak"; d.mkdir(parents=True, exist_ok=True)
    (d/(sid+".session")).write_text("{}\n"); return sid

# What an operator sets to hand an agent a destructive tool: the posture AND a
# session id that names something real. Neither alone is enough.
OPERATOR={"SHADOWFETCH_MCP_DESTRUCTIVE":"allow",
          "SHADOWFETCH_MCP_SESSION":recorded_session("fb-20260908-wiretest")}

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
# undo is DESTRUCTIVE and the surface withholds it. Assert the refusal changed
# NOTHING before enabling it the way an operator would, so the behaviour below
# still proves the engine works rather than proving the gate is absent.
frozen=Path(root+"/proj/src/app.py").read_text()
store_before=sorted(p.name for p in Path(root+"/.sf-checkpoints/proj").glob("*"))
out=session("checkpoint",[init, call("undo",{"workspace":"proj","checkpoint":cid})],env)
check("undo is refused by default", out[1]["result"].get("isError"))
check("a refused undo restored nothing", Path(root+"/proj/src/app.py").read_text()==frozen)
check("a refused undo took no safety checkpoint",
      sorted(p.name for p in Path(root+"/.sf-checkpoints/proj").glob("*"))==store_before)
out=session("checkpoint",[init, {"jsonrpc":"2.0","id":9,"method":"tools/list"}],env)
check("undo is not advertised by default",
      "undo" not in [t["name"] for t in out[1]["result"]["tools"]])
out=session("checkpoint",[init, call("undo",{"workspace":"proj","checkpoint":cid})],{**env, **OPERATOR})
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

def mcp_text(tool, args, extra=None):
    out = session("checkpoint", [init, call(tool, args)], {**env28, **(extra or {})})
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

# The sentence is still the interface for the callers that read it; only WHO may
# reach it over the protocol changed.
check("MCP undo text is unchanged",
      mcp_text("undo", {"workspace": "proj", "checkpoint": mcp_cid}, OPERATOR) ==
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


# --------------------------------------------------------------------------- #
# The recovery and attestation surfaces resolve programs by ABSOLUTE PATH.
#
# PERMANENT INVARIANT: any executable used to establish, verify, enforce or
# attest a security fact is invoked through an explicit trusted ABSOLUTE path,
# and its own child PATH is pinned too, because a resolved program resolves its
# helpers through whatever it inherits.
#
# Two call sites in sf_mcp.py broke it in the SAME way, and the shape is worth
# naming because it survived a comment that described the correct behaviour:
# the directory that was CHECKED (shutil.which(name, path=TRUSTED_PATH)) and
# the directory that ANSWERED (the bare name handed to subprocess with the
# caller's own environment) were not the same directory. The constrained lookup
# approved "there is a snapper in /usr/bin" and then the exec ran whichever
# snapper the caller's PATH found first.
#
# These checks are written as the ATTACK: a forged program is planted EARLIER on
# PATH than the real one, and the surface must run the real one. The attack
# needs a root-owned /usr/sbin/snapper to exist, which this build host does not
# have -- without one every refusal would pass for the wrong reason ("nothing
# installed") -- so the run happens inside `unshare -rm`, a user namespace where
# our uid maps to 0, with a tmpfs over /usr/sbin. The script, _trusted_tool and
# the exec are the shipped ones; only the filesystem is borrowed.
# --------------------------------------------------------------------------- #
MCP_SRC = (FL / "data/usr/lib/shadowfetch/mcp/sf_mcp.py").read_text()
# Prose stripped: this file DOCUMENTS the defect by name, so a naive substring
# scan would fail on the explanation and tempt somebody to delete it.
MCP_CODE = "\n".join(line for line in MCP_SRC.splitlines()
                     if not line.lstrip().startswith("#"))

check("no PATH lookup survives in sf_mcp.py", "shutil.which" not in MCP_CODE)
check("snapper is resolved from an absolute-path table",
      '_TRUSTED_SNAPPER = ("/usr/bin/snapper"' in MCP_CODE
      and "_trusted_tool(_TRUSTED_SNAPPER)" in MCP_CODE)
check("the Passport is resolved from an absolute-path table",
      '_TRUSTED_PASSPORT = ("/usr/bin/shadowfetch-passport",)' in MCP_CODE
      and "_trusted_tool(_TRUSTED_PASSPORT)" in MCP_CODE)
check("the snapper table is the update authority's table, not a second one",
      '"/usr/bin/snapper", "/usr/sbin/snapper"' in MCP_CODE
      and '"/bin/snapper", "/sbin/snapper"' in MCP_CODE)
check("every child of sf_mcp.py gets a pinned PATH",
      "env=_trusted_env()" in MCP_CODE
      and 'TRUSTED_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"' in MCP_CODE)

FORGE = tempfile.mkdtemp(prefix="sf-mcp-forge-")
atexit.register(shutil.rmtree, FORGE, True)


def _stub(name, body):
    path = Path(FORGE) / name
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(0o755)
    return str(path)


# The honest program, and the attacker's. The honest one reports the PATH it
# was handed, which is how the child-environment half of the invariant is
# measured rather than asserted.
REAL_SNAPPER = _stub("real-snapper", 'echo "REAL-SNAPPER PATH=$PATH"\n')
_stub("snapper", "echo FORGED-SNAPPER\n")


def userns_ok():
    probe = subprocess.run(
        ["unshare", "-rm", "/bin/sh", "-c", "mount -t tmpfs tmpfs /usr/sbin"],
        capture_output=True, text=True)
    return probe.returncode == 0


def phoenix_under_attack(install_real=True, mode="755"):
    """list_restore_points with a forged `snapper` FIRST on PATH."""
    steps = ["mount -t tmpfs tmpfs /usr/sbin", "chmod 755 /usr/sbin"]
    if install_real:
        steps.append("cp %s /usr/sbin/snapper" % REAL_SNAPPER)
        steps.append("chmod %s /usr/sbin/snapper" % mode)
    steps.append("exec %s %s phoenix" % (sys.executable, MCP[1]))
    env = dict(os.environ)
    env["PATH"] = FORGE + ":" + env.get("PATH", "")
    payload = "\n".join(json.dumps(c) for c in
                        [init, call("list_restore_points", {})]) + "\n"
    result = subprocess.run(
        ["unshare", "-rm", "/bin/sh", "-c", " && ".join(steps)],
        input=payload, capture_output=True, text=True, env=env, timeout=60)
    lines = [json.loads(l) for l in result.stdout.splitlines() if l.strip()]
    if len(lines) < 2:
        return "NO-REPLY:" + result.stderr[-400:]
    return lines[1]["result"]["content"][0]["text"]


if not userns_ok():
    print("  SKIP  user namespaces unavailable: the PATH attack cannot be "
          "staged on this host (no root-owned /usr/sbin/snapper to defend)")
else:
    listing = phoenix_under_attack()
    check("a forged snapper earlier on PATH is never the one that runs",
          "REAL-SNAPPER" in listing and "FORGED-SNAPPER" not in listing)
    # The other half of the invariant: the child's own PATH. Without this the
    # real snapper -- a shell script on a real system too -- would resolve its
    # own helpers through the attacker's directory.
    check("the child snapper is handed the pinned PATH, not the caller's",
          "PATH=/usr/sbin:/usr/bin:/sbin:/bin" in listing
          and FORGE not in listing)
    substitutable = phoenix_under_attack(mode="775")
    check("a group-writable snapper is refused, not run",
          "REAL-SNAPPER" not in substitutable
          and "FORGED-SNAPPER" not in substitutable
          and "not a root-owned" in substitutable)
    absent = phoenix_under_attack(install_real=False)
    check("with no snapper installed the forged one still never runs",
          "FORGED-SNAPPER" not in absent and "not installed" in absent)

print(f"\n  {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
