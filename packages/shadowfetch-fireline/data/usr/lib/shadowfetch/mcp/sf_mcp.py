#!/usr/bin/env python3
"""Shadowfetch first-party MCP servers (dependency-free, stdio JSON-RPC 2.0).

One file, four servers, dispatched by argv[1]:

  passport    read-only system self-check (wraps `shadowfetch-passport --json`,
              privacy-scrubbed; never uploads, never changes the system)
  phoenix     read-only list of Btrfs/snapper restore points
  checkpoint  per-workspace snapshot / diff / undo under ~/Workspaces
              (Btrfs subvolume snapshot when available, tar fallback otherwise)
  fs          scoped, read-only file access under one root (SF_MCP_FS_ROOT)

Design rules (match the rest of Shadowfetch's tooling):
  * A server that only READS says so; the one server that writes (checkpoint)
    names its writes in every tool description and touches ONLY the workspace
    it was scoped to.
  * No third-party Python dependencies. Anything not in the standard library is
    an integration point that can rot or be supply-chain attacked; an MCP
    surface that an autonomous agent talks to is the last place that belongs.
  * Errors are returned as MCP tool errors (isError), never tracebacks to the
    agent.

Protocol: a minimal but correct subset of MCP over newline-delimited stdio
JSON-RPC: initialize, notifications/initialized, tools/list, tools/call, ping.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import time
from pathlib import Path

PROTOCOL_VERSION = "2025-06-18"
SERVER_VERSION = "4.0.0"


# --------------------------------------------------------------------------- #
# Tiny MCP server framework
# --------------------------------------------------------------------------- #
class Tool:
    def __init__(self, name, description, schema, handler):
        self.name = name
        self.description = description
        self.schema = schema
        self.handler = handler


class Server:
    def __init__(self, name, instructions=""):
        self.name = name
        self.instructions = instructions
        self.tools: dict[str, Tool] = {}

    def tool(self, name, description, schema):
        def deco(fn):
            self.tools[name] = Tool(name, description, schema, fn)
            return fn
        return deco

    # -- JSON-RPC plumbing -------------------------------------------------- #
    def _result(self, rid, result):
        return {"jsonrpc": "2.0", "id": rid, "result": result}

    def _error(self, rid, code, message):
        return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}

    def _text(self, text, is_error=False):
        return {"content": [{"type": "text", "text": text}], "isError": is_error}

    def handle(self, msg):
        method = msg.get("method")
        rid = msg.get("id")
        if method == "initialize":
            return self._result(rid, {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": f"shadowfetch-{self.name}", "version": SERVER_VERSION},
                "instructions": self.instructions,
            })
        if method in ("notifications/initialized", "notifications/cancelled"):
            return None  # notification, no reply
        if method == "ping":
            return self._result(rid, {})
        if method == "tools/list":
            return self._result(rid, {"tools": [
                {"name": t.name, "description": t.description, "inputSchema": t.schema}
                for t in self.tools.values()
            ]})
        if method == "tools/call":
            params = msg.get("params") or {}
            tname = params.get("name")
            args = params.get("arguments") or {}
            tool = self.tools.get(tname)
            if tool is None:
                return self._result(rid, self._text(f"Unknown tool: {tname}", is_error=True))
            try:
                out = tool.handler(args)
                if isinstance(out, dict) and "content" in out:
                    return self._result(rid, out)
                return self._result(rid, self._text(out if isinstance(out, str)
                                                    else json.dumps(out, indent=2)))
            except _ToolError as exc:
                return self._result(rid, self._text(str(exc), is_error=True))
            except Exception as exc:  # never leak a traceback to the agent
                return self._result(rid, self._text(f"internal error: {exc}", is_error=True))
        if rid is None:
            return None
        return self._error(rid, -32601, f"Method not found: {method}")

    def serve(self):
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            reply = self.handle(msg)
            if reply is not None:
                sys.stdout.write(json.dumps(reply) + "\n")
                sys.stdout.flush()


class _ToolError(Exception):
    pass


# --------------------------------------------------------------------------- #
# Shared helpers
# --------------------------------------------------------------------------- #
def _run(cmd, timeout=20):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _workspaces_root() -> Path:
    return Path(os.environ.get("SHADOWFETCH_AGENT_WORKSPACES",
                               str(Path.home() / "Workspaces"))).expanduser().resolve()


def _safe_name(name: str) -> str:
    if not isinstance(name, str) or not name.strip() or len(name) > 160 or name in (".", "..") or any(char in name for char in ("/", "\\")) or any(ord(char) < 32 or ord(char) == 127 for char in name):
        raise _ToolError(f"invalid workspace name: {name!r}")
    return name


def _workspace(name: str) -> Path:
    root = _workspaces_root()
    path = root / _safe_name(name)
    if path.is_symlink() or path.resolve().parent != root or not path.is_dir():
        raise _ToolError("workspace is missing or escapes the configured root")
    return path.resolve()


def _ckpt_store(ws: Path) -> Path:
    parent = ws.parent / ".sf-checkpoints"
    d = parent / ws.name
    if parent.is_symlink() or d.is_symlink():
        raise _ToolError("checkpoint storage cannot be a symbolic link")
    d.mkdir(parents=True, mode=0o700, exist_ok=True)
    parent.chmod(0o700)
    d.chmod(0o700)
    return d


# --------------------------------------------------------------------------- #
# Server: passport  (READ-ONLY)
# --------------------------------------------------------------------------- #
def build_passport() -> Server:
    s = Server("passport",
               "Read-only Shadowfetch System Passport. Reports what the machine "
               "can do (graphics, memory, storage, local-AI capacity) with host "
               "identity, serials and network identifiers removed. It never "
               "uploads and never changes the system.")

    @s.tool("system_passport",
            "Return the privacy-scrubbed System Passport for this machine "
            "(read-only; no identity, no upload, no changes).",
            {"type": "object", "properties": {}})
    def _passport(args):
        for cand in ("shadowfetch-passport", "/usr/bin/shadowfetch-passport"):
            if shutil.which(cand) or Path(cand).exists():
                r = _run([cand, "--json"])
                if r.returncode == 0 and r.stdout.strip():
                    try:
                        return json.dumps(json.loads(r.stdout), indent=2)
                    except json.JSONDecodeError:
                        return r.stdout
        # Degrade gracefully off a Shadowfetch system: a minimal, scrubbed view.
        vm = 0
        try:
            for ln in Path("/proc/meminfo").read_text().splitlines():
                if ln.startswith("MemTotal:"):
                    vm = int(ln.split()[1]) // 1024
        except OSError:
            pass
        return json.dumps({
            "note": "shadowfetch-passport not installed; minimal scrubbed view",
            "cpu_count": os.cpu_count(),
            "memory_mb": vm,
            "kernel": os.uname().release,
        }, indent=2)

    return s


# --------------------------------------------------------------------------- #
# Server: phoenix  (READ-ONLY)
# --------------------------------------------------------------------------- #
def build_phoenix() -> Server:
    s = Server("phoenix",
               "Read-only view of Phoenix / Btrfs restore points. Listing only: "
               "creating and restoring system snapshots stays in the Phoenix tool "
               "and the Control Center, behind polkit, on purpose.")

    @s.tool("list_restore_points",
            "List available Btrfs/snapper restore points (read-only).",
            {"type": "object", "properties": {}})
    def _list(args):
        if not shutil.which("snapper"):
            return "snapper is not installed; no restore points to list."
        r = _run(["snapper", "--machine-readable", "csv", "list"])
        if r.returncode != 0:
            r = _run(["snapper", "list"])
            return r.stdout or "no restore points found."
        return r.stdout or "no restore points found."

    return s


# --------------------------------------------------------------------------- #
# Checkpoint engine  (structured data; the MCP tools and the CLI render FROM it)
# --------------------------------------------------------------------------- #
# Recovery is the guarantee this distribution advertises, so a checkpoint id has
# to travel as DATA. Before this change every caller recovered it by running a
# regular expression over the English sentence the MCP tool returns --
# sf_missions.py did re.search(r"checkpoint ([0-9-]+)", ...) and Firebreak split
# the same words -- which made a human sentence the recovery ABI. Reword the
# sentence, or mint an id containing anything outside [0-9-], and recovery
# breaks silently.
#
# CheckpointEngine returns dictionaries. format_*() renders the same sentences
# those callers read today FROM those dictionaries, so the words and the data
# cannot drift apart. Every field below is something the engine actually knows:
# it comes from the metadata file the engine itself writes, or from the tree
# comparison it performs.
#
#   snapshot  {"action": "snapshot", "id": str, "workspace": str,
#              "method": "btrfs"|"tar", "label": str, "created": str,
#              "archive": str|None}            # archive: "tar" method only
#   list      {"action": "list", "workspace": str, "count": int,
#              "checkpoints": [{"id", "method", "label", "created", "archive"}]}
#   diff      {"action": "diff", "workspace": str, "checkpoint": str,
#              "method": str, "count": int, "truncated": bool,
#              "changes": [{"status": "added"|"removed"|"modified",
#                           "path": str}]}      # "truncated": text form elides
#   undo      {"action": "undo", "workspace": str, "checkpoint": str,
#              "method": str, "label": str,
#              "safety": {"id": str, "method": str}}
#
# The strings format_*() produces are an interface: agents read them and
# shadowfetch-checkpoint prints them. Changing one is an interface change, not a
# copy edit -- and a caller that needs the id should read result["id"] instead.

CHECKPOINT_ACTIONS = ("snapshot", "list", "diff", "undo")
DIFF_TEXT_LIMIT = 500
_CHANGE_MARK = {"added": "+", "removed": "-", "modified": "M"}


def _mint_id() -> str:
    # Second-precision ids collide when two snapshots land in the same second
    # (the pre-undo safety snapshot did exactly that and clobbered the target
    # checkpoint's archive). A nanosecond tail separates them.
    return time.strftime("%Y%m%d-%H%M%S") + f"-{time.monotonic_ns() % 1000000:06d}"


def _new_checkpoint_id(store: Path) -> str:
    cid = _mint_id()
    while (store / f"{cid}.json").exists() or (store / f"{cid}.tar.gz").exists():
        cid = _mint_id()
    return cid


def _no_ckpt_dir(ws):
    def f(ti: tarfile.TarInfo):
        return None if "/.sf-checkpoints/" in ("/" + ti.name + "/") else ti
    return f


class CheckpointEngine:
    """Snapshot / list / diff / undo one workspace, returning structured data.

    Nothing in this class formats or parses prose. A caller that needs the
    checkpoint id reads result["id"]; a caller that needs to show a person
    something passes the result to the matching format_*() function.
    """

    def snapshot(self, workspace: str, label: str = "manual") -> dict:
        ws = _workspace(workspace)
        if not ws.is_dir():
            raise _ToolError(f"workspace does not exist: {ws}")
        meta = self._snapshot(ws, label)
        return {"action": "snapshot", "id": meta["id"], "workspace": meta["workspace"],
                "method": meta["method"], "label": meta["label"],
                "created": meta["created"], "archive": meta.get("archive")}

    def list(self, workspace: str) -> dict:
        ws = _workspace(workspace)
        store = _ckpt_store(ws)
        rows = []
        for stem in sorted(p.stem for p in store.glob("*.json")):
            meta = json.loads((store / f"{stem}.json").read_text())
            rows.append({"id": meta["id"], "method": meta["method"],
                         "label": meta.get("label", ""),
                         "created": meta.get("created"),
                         "archive": meta.get("archive")})
        return {"action": "list", "workspace": ws.name,
                "count": len(rows), "checkpoints": rows}

    def diff(self, workspace: str, checkpoint: str) -> dict:
        ws = _workspace(workspace)
        store = _ckpt_store(ws)
        cid, meta = self._meta(store, checkpoint)
        base = _restore_tree(store, meta)
        changes = _tree_changes(base, ws)
        _cleanup_tmp(base, meta)
        return {"action": "diff", "workspace": ws.name, "checkpoint": cid,
                "method": meta["method"], "count": len(changes),
                "truncated": len(changes) > DIFF_TEXT_LIMIT,
                "changes": [{"status": status, "path": path} for status, path in changes]}

    def undo(self, workspace: str, checkpoint: str) -> dict:
        ws = _workspace(workspace)
        store = _ckpt_store(ws)
        cid, meta = self._meta(store, checkpoint)
        safety = self._snapshot(ws, f"pre-undo-of-{cid}")  # never lose current state silently
        base = _restore_tree(store, meta)
        # replace workspace contents (preserving the .sf-checkpoints store, which
        # lives OUTSIDE ws) with the checkpoint tree
        for child in ws.iterdir():
            if child.is_dir() and not child.is_symlink():
                shutil.rmtree(child)
            else:
                child.unlink()
        for child in base.iterdir():
            dst = ws / child.name
            if child.is_symlink():
                dst.symlink_to(os.readlink(child))
            elif child.is_dir():
                shutil.copytree(child, dst, symlinks=True)
            else:
                shutil.copy2(child, dst, follow_symlinks=False)
        _cleanup_tmp(base, meta)
        return {"action": "undo", "workspace": ws.name, "checkpoint": cid,
                "method": meta["method"], "label": meta.get("label", ""),
                "safety": {"id": safety["id"], "method": safety["method"]}}

    # -- internals ---------------------------------------------------------- #
    def _meta(self, store: Path, checkpoint: str) -> tuple[str, dict]:
        cid = _safe_name(checkpoint)
        meta_p = store / f"{cid}.json"
        if not meta_p.exists():
            raise _ToolError(f"no such checkpoint: {cid}")
        return cid, json.loads(meta_p.read_text())

    def _snapshot(self, ws: Path, label: str) -> dict:
        store = _ckpt_store(ws)
        cid = _new_checkpoint_id(store)
        meta = {"id": cid, "label": label, "workspace": ws.name,
                "created": cid, "method": None}
        is_btrfs = _run(["stat", "-f", "-c", "%T", str(ws)]).stdout.strip() == "btrfs"
        snapdir = store / cid
        if is_btrfs and _run(["btrfs", "subvolume", "show", str(ws)]).returncode == 0:
            r = _run(["btrfs", "subvolume", "snapshot", "-r", str(ws), str(snapdir)])
            if r.returncode == 0:
                meta["method"] = "btrfs"
        if meta["method"] is None:
            # portable fallback: a compressed archive of the workspace tree
            arc = store / f"{cid}.tar.gz"
            with tarfile.open(arc, "w:gz") as tf:
                tf.add(ws, arcname=ws.name, filter=_no_ckpt_dir(ws))
            meta["method"] = "tar"
            meta["archive"] = arc.name
        (store / f"{cid}.json").write_text(json.dumps(meta, indent=2))
        return meta


def checkpoint_call(action: str, **kwargs) -> dict:
    """Structured entry point for the rest of Shadowfetch.

    Mission Control and Firebreak use this (or `shadowfetch-checkpoint --json`)
    instead of scraping the human sentence:

        recovery = sf_mcp.checkpoint_call("snapshot", workspace=ws.name,
                                          label="mission:" + mid)["id"]

    Raises _ToolError on bad input, exactly as the MCP tool handlers do.
    """
    if action not in CHECKPOINT_ACTIONS:
        raise _ToolError(f"unknown checkpoint action: {action}")
    return getattr(CheckpointEngine(), action)(**kwargs)


# -- human rendering: the shipped sentences, built from the structured result - #
def format_snapshot(result: dict) -> str:
    return (f"checkpoint {result['id']} taken ({result['method']}) "
            f"for workspace '{result['workspace']}'.")


def format_list(result: dict) -> str:
    if not result["checkpoints"]:
        return f"no checkpoints for '{result['workspace']}'."
    rows = [f"  {c['id']}  {c['method']:6}  {c['label']}" for c in result["checkpoints"]]
    return f"checkpoints for '{result['workspace']}':\n" + "\n".join(rows)


def format_diff(result: dict) -> str:
    if not result["changes"]:
        return "no changes since checkpoint."
    rows = [f"  {_CHANGE_MARK[c['status']]} {c['path']}"
            for c in result["changes"][:DIFF_TEXT_LIMIT]]
    return "changed since checkpoint:\n" + "\n".join(rows)


def format_undo(result: dict) -> str:
    return (f"workspace '{result['workspace']}' restored to checkpoint "
            f"{result['checkpoint']}. A safety checkpoint of the pre-undo state "
            f"was taken first.")


CHECKPOINT_FORMATTERS = {"snapshot": format_snapshot, "list": format_list,
                         "diff": format_diff, "undo": format_undo}


# --------------------------------------------------------------------------- #
# Server: checkpoint  (WRITES — scoped to one workspace under ~/Workspaces)
# --------------------------------------------------------------------------- #
def build_checkpoint() -> Server:
    s = Server("checkpoint",
               "Snapshot, inspect and undo changes inside ONE agent workspace "
               "under ~/Workspaces. snapshot() and undo() WRITE (a snapshot copy, "
               "or a restore of the workspace); they touch only the named "
               "workspace. Use snapshot() before letting an agent run, then undo() "
               "to reverse everything it did.")
    engine = CheckpointEngine()

    @s.tool("snapshot",
            "WRITES: take a restore point of the named workspace before an agent "
            "runs. Returns a checkpoint id. Btrfs snapshot when possible, else a "
            "compressed archive. Touches only ~/Workspaces/<name>.",
            {"type": "object", "required": ["workspace"], "properties": {
                "workspace": {"type": "string", "description": "workspace name under ~/Workspaces"},
                "label": {"type": "string", "description": "optional human label"}}})
    def snapshot(args):
        return format_snapshot(engine.snapshot(args["workspace"], args.get("label", "manual")))

    @s.tool("list",
            "List checkpoints for a workspace (read-only).",
            {"type": "object", "required": ["workspace"], "properties": {
                "workspace": {"type": "string"}}})
    def _list(args):
        return format_list(engine.list(args["workspace"]))

    @s.tool("diff",
            "Show which files changed in the workspace since a checkpoint "
            "(read-only): what the agent touched.",
            {"type": "object", "required": ["workspace", "checkpoint"], "properties": {
                "workspace": {"type": "string"}, "checkpoint": {"type": "string"}}})
    def diff(args):
        return format_diff(engine.diff(args["workspace"], args["checkpoint"]))

    @s.tool("undo",
            "WRITES: restore the workspace to a checkpoint, reversing everything "
            "changed since (the agent's work is discarded). Touches only "
            "~/Workspaces/<name>. A safety snapshot of the current state is taken "
            "first.",
            {"type": "object", "required": ["workspace", "checkpoint"], "properties": {
                "workspace": {"type": "string"}, "checkpoint": {"type": "string"}}})
    def undo(args):
        return format_undo(engine.undo(args["workspace"], args["checkpoint"]))

    return s


def _restore_tree(store: Path, meta: dict) -> Path:
    """Materialize a checkpoint into a temp dir; return the workspace-root path."""
    if meta["method"] == "btrfs":
        return store / meta["id"]
    tmp = store / f".tmp-{meta['id']}"
    if tmp.exists():
        shutil.rmtree(tmp)
    tmp.mkdir(parents=True)
    # Restore archive members without following links or allowing traversal.
    # Links are created LAST, so no later member can write through them.
    if _safe_name(meta["workspace"]) != store.name:
        raise _ToolError("checkpoint workspace metadata mismatch")
    archive = _safe_name(meta["archive"])
    with tarfile.open(store / archive, "r:gz") as tf:
        members = tf.getmembers()
        links = []
        names = set()
        for item in members:
            relative = Path(item.name)
            if relative.is_absolute() or ".." in relative.parts or not relative.parts or relative.parts[0] != meta["workspace"]:
                raise _ToolError("unsafe checkpoint archive path")
            if item.name in names:
                raise _ToolError("duplicate checkpoint archive path")
            names.add(item.name)
            destination = tmp / relative
            if item.issym() or item.islnk():
                links.append(item)
                continue
            if not (item.isdir() or item.isfile()):
                raise _ToolError("special files cannot be restored from a checkpoint")
            destination.parent.mkdir(parents=True, exist_ok=True)
            if item.isdir():
                destination.mkdir(exist_ok=True)
            else:
                source = tf.extractfile(item)
                if source is None:
                    raise _ToolError("missing checkpoint file data")
                with source, destination.open("xb") as output:
                    shutil.copyfileobj(source, output)
            destination.chmod(item.mode & 0o777)
        for item in links:
            destination = tmp / item.name
            # Link directories cannot contain any archived child.
            if any(name.startswith(item.name.rstrip("/") + "/") for name in names):
                raise _ToolError("checkpoint contains children beneath a link")
            destination.parent.mkdir(parents=True, exist_ok=True)
            if item.issym():
                destination.symlink_to(item.linkname)
            else:
                target = Path(item.linkname)
                if target.is_absolute() or ".." in target.parts or not target.parts or target.parts[0] != meta["workspace"]:
                    raise _ToolError("unsafe checkpoint hard link")
                source = tmp / target
                if source.is_symlink() or not source.is_file():
                    raise _ToolError("invalid checkpoint hard link target")
                os.link(source, destination)
    return tmp / meta["workspace"]


def _cleanup_tmp(base: Path, meta: dict):
    if meta["method"] == "tar":
        root = base.parent
        if root.name.startswith(".tmp-"):
            shutil.rmtree(root, ignore_errors=True)


def _tree_changes(a: Path, b: Path) -> list[tuple[str, str]]:
    """Compare two trees; return (status, path) pairs, not display strings."""
    import hashlib

    def _digest(p: Path) -> str:
        h = hashlib.sha1()
        with p.open("rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    def index(root):
        out = {}
        for p in root.rglob("*"):
            if p.is_file() and not p.is_symlink():
                rel = p.relative_to(root)
                if rel.parts and rel.parts[0] == ".sf-checkpoints":
                    continue
                out[str(rel)] = _digest(p)
        return out
    ia, ib = index(a), index(b)
    changed = []
    for k in sorted(set(ia) | set(ib)):
        if k not in ia:
            changed.append(("added", k))
        elif k not in ib:
            changed.append(("removed", k))
        elif ia[k] != ib[k]:
            changed.append(("modified", k))
    return changed


def _tree_diff(a: Path, b: Path) -> list[str]:
    """Display form of _tree_changes ("+ path" / "- path" / "M path")."""
    return [f"{_CHANGE_MARK[status]} {path}" for status, path in _tree_changes(a, b)]


# --------------------------------------------------------------------------- #
# Server: fs  (READ-ONLY, scoped to SF_MCP_FS_ROOT -- required, no default)
# --------------------------------------------------------------------------- #
class _ScopeError(Exception):
    """The operator did not name a usable scope for the fs server."""


# Directories that can never be a meaningful "scope": pseudo-filesystems,
# system configuration, and the well-known credential stores. Mirrors the
# denylist shadowfetch-firebreak applies to --read grants.
_SCOPE_RESERVED = (Path("/proc"), Path("/sys"), Path("/dev"), Path("/run"),
                   Path("/boot"), Path("/etc"))
_SCOPE_RESERVED_HOME = (".ssh", ".gnupg", ".aws", ".codex", ".config/gcloud")


def _check_scope(root: Path) -> None:
    if len(root.parts) < 3:
        raise _ScopeError(
            f"SF_MCP_FS_ROOT={root} is a filesystem root or top-level directory; "
            "name the one project directory the agent may read")
    home = Path.home().resolve()
    if root == home:
        raise _ScopeError(
            "SF_MCP_FS_ROOT is the whole home directory, which exposes every "
            "credential and private file on the account; name a project directory")
    for item in _SCOPE_RESERVED:
        if root == item or item in root.parents:
            raise _ScopeError(f"SF_MCP_FS_ROOT={root} is inside {item}, which is never in scope")
    for leaf in _SCOPE_RESERVED_HOME:
        secret = home / leaf
        if root == secret or secret in root.parents:
            raise _ScopeError(f"SF_MCP_FS_ROOT={root} is a credential store and is never in scope")


def build_fs() -> Server:
    root_env = os.environ.get("SF_MCP_FS_ROOT", "").strip()
    if not root_env:
        raise _ScopeError(
            "SF_MCP_FS_ROOT is not set. The fs server refuses to start without an "
            "explicit scope -- it will not silently fall back to the working "
            "directory. Set SF_MCP_FS_ROOT to the one directory the agent may read.")
    candidate = Path(root_env).expanduser()
    if not candidate.is_absolute():
        raise _ScopeError(f"SF_MCP_FS_ROOT={root_env} must be an absolute path")
    root = candidate.resolve()
    if not root.is_dir():
        raise _ScopeError(f"SF_MCP_FS_ROOT={root} is not an existing directory")
    _check_scope(root)
    s = Server("fs",
               f"Read-only file access scoped to {root}. Every path is resolved "
               "and refused if it escapes the root. No writes, ever.")

    def _resolve(rel: str) -> Path:
        p = (root / rel).resolve()
        if p != root and root not in p.parents:
            raise _ToolError(f"path escapes scope: {rel}")
        return p

    @s.tool("list_dir", "List a directory within the scoped root (read-only).",
            {"type": "object", "properties": {"path": {"type": "string", "description": "relative path (default '.')"}}})
    def list_dir(args):
        p = _resolve(args.get("path", "."))
        if not p.is_dir():
            raise _ToolError("not a directory")
        rows = []
        for c in sorted(p.iterdir()):
            rows.append(("d " if c.is_dir() else "f ") + c.name)
        return "\n".join(rows) or "(empty)"

    @s.tool("read_file", "Read a UTF-8 text file within the scoped root (read-only, capped at 200 KB).",
            {"type": "object", "required": ["path"], "properties": {"path": {"type": "string"}}})
    def read_file(args):
        p = _resolve(args["path"])
        if not p.is_file():
            raise _ToolError("not a file")
        data = p.read_bytes()[:200 * 1024]
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            raise _ToolError("not a UTF-8 text file")

    return s


SERVERS = {
    "passport": build_passport,
    "phoenix": build_phoenix,
    "checkpoint": build_checkpoint,
    "fs": build_fs,
}


def main(argv):
    if len(argv) < 2 or argv[1] in ("-h", "--help"):
        sys.stderr.write(
            "usage: shadowfetch-mcp <passport|phoenix|checkpoint|fs>\n"
            "  Speak MCP (JSON-RPC 2.0) over stdio. Configure your agent to run\n"
            "  this as an MCP server. Servers: passport/phoenix/fs are read-only;\n"
            "  checkpoint writes only inside the named ~/Workspaces workspace.\n")
        return 0 if (len(argv) > 1 and argv[1] in ("-h", "--help")) else 2
    if argv[1] == "--version":
        print(f"shadowfetch-mcp (Shadowfetch Linux) {SERVER_VERSION}")
        return 0
    name = argv[1]
    if name not in SERVERS:
        sys.stderr.write(f"unknown server: {name}\n")
        return 2
    try:
        server = SERVERS[name]()
    except _ScopeError as exc:
        sys.stderr.write(f"{name}: {exc}\n")
        return 2
    server.serve()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
