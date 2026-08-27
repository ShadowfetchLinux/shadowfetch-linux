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
SERVER_VERSION = "3.5.0"


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
                               str(Path.home() / "Workspaces")))


def _safe_name(name: str) -> str:
    if not name or not re.fullmatch(r"[A-Za-z0-9._-]+", name) or name in (".", ".."):
        raise _ToolError(f"invalid workspace name: {name!r}")
    return name


def _ckpt_store(ws: Path) -> Path:
    d = ws.parent / ".sf-checkpoints" / ws.name
    d.mkdir(parents=True, exist_ok=True)
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
# Server: checkpoint  (WRITES — scoped to one workspace under ~/Workspaces)
# --------------------------------------------------------------------------- #
def build_checkpoint() -> Server:
    s = Server("checkpoint",
               "Snapshot, inspect and undo changes inside ONE agent workspace "
               "under ~/Workspaces. snapshot() and undo() WRITE (a snapshot copy, "
               "or a restore of the workspace); they touch only the named "
               "workspace. Use snapshot() before letting an agent run, then undo() "
               "to reverse everything it did.")

    def _snapshot(ws: Path, label: str) -> dict:
        store = _ckpt_store(ws)
        # Second-precision ids collide when two snapshots land in the same second
        # (the pre-undo safety snapshot did exactly that and clobbered the target
        # checkpoint's archive). Add a nanosecond tail and guard against reuse.
        cid = time.strftime("%Y%m%d-%H%M%S") + f"-{time.monotonic_ns() % 1000000:06d}"
        while (store / f"{cid}.json").exists() or (store / f"{cid}.tar.gz").exists():
            cid = time.strftime("%Y%m%d-%H%M%S") + f"-{time.monotonic_ns() % 1000000:06d}"
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

    def _no_ckpt_dir(ws):
        def f(ti: tarfile.TarInfo):
            return None if "/.sf-checkpoints/" in ("/" + ti.name + "/") else ti
        return f

    @s.tool("snapshot",
            "WRITES: take a restore point of the named workspace before an agent "
            "runs. Returns a checkpoint id. Btrfs snapshot when possible, else a "
            "compressed archive. Touches only ~/Workspaces/<name>.",
            {"type": "object", "required": ["workspace"], "properties": {
                "workspace": {"type": "string", "description": "workspace name under ~/Workspaces"},
                "label": {"type": "string", "description": "optional human label"}}})
    def snapshot(args):
        ws = _workspaces_root() / _safe_name(args["workspace"])
        if not ws.is_dir():
            raise _ToolError(f"workspace does not exist: {ws}")
        meta = _snapshot(ws, args.get("label", "manual"))
        return f"checkpoint {meta['id']} taken ({meta['method']}) for workspace '{ws.name}'."

    @s.tool("list",
            "List checkpoints for a workspace (read-only).",
            {"type": "object", "required": ["workspace"], "properties": {
                "workspace": {"type": "string"}}})
    def _list(args):
        ws = _workspaces_root() / _safe_name(args["workspace"])
        store = _ckpt_store(ws)
        pts = sorted(p.stem for p in store.glob("*.json"))
        if not pts:
            return f"no checkpoints for '{ws.name}'."
        rows = []
        for cid in pts:
            m = json.loads((store / f"{cid}.json").read_text())
            rows.append(f"  {m['id']}  {m['method']:6}  {m.get('label','')}")
        return f"checkpoints for '{ws.name}':\n" + "\n".join(rows)

    @s.tool("diff",
            "Show which files changed in the workspace since a checkpoint "
            "(read-only): what the agent touched.",
            {"type": "object", "required": ["workspace", "checkpoint"], "properties": {
                "workspace": {"type": "string"}, "checkpoint": {"type": "string"}}})
    def diff(args):
        ws = _workspaces_root() / _safe_name(args["workspace"])
        store = _ckpt_store(ws)
        cid = _safe_name(args["checkpoint"])
        meta_p = store / f"{cid}.json"
        if not meta_p.exists():
            raise _ToolError(f"no such checkpoint: {cid}")
        meta = json.loads(meta_p.read_text())
        base = _restore_tree(store, meta)
        changed = _tree_diff(base, ws)
        _cleanup_tmp(base, meta)
        if not changed:
            return "no changes since checkpoint."
        return "changed since checkpoint:\n" + "\n".join(f"  {c}" for c in changed[:500])

    @s.tool("undo",
            "WRITES: restore the workspace to a checkpoint, reversing everything "
            "changed since (the agent's work is discarded). Touches only "
            "~/Workspaces/<name>. A safety snapshot of the current state is taken "
            "first.",
            {"type": "object", "required": ["workspace", "checkpoint"], "properties": {
                "workspace": {"type": "string"}, "checkpoint": {"type": "string"}}})
    def undo(args):
        ws = _workspaces_root() / _safe_name(args["workspace"])
        store = _ckpt_store(ws)
        cid = _safe_name(args["checkpoint"])
        meta_p = store / f"{cid}.json"
        if not meta_p.exists():
            raise _ToolError(f"no such checkpoint: {cid}")
        meta = json.loads(meta_p.read_text())
        _snapshot(ws, f"pre-undo-of-{cid}")  # never lose current state silently
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
            if child.is_dir():
                shutil.copytree(child, dst, symlinks=True)
            else:
                shutil.copy2(child, dst)
        _cleanup_tmp(base, meta)
        return (f"workspace '{ws.name}' restored to checkpoint {cid}. "
                f"A safety checkpoint of the pre-undo state was taken first.")

    return s


def _restore_tree(store: Path, meta: dict) -> Path:
    """Materialize a checkpoint into a temp dir; return the workspace-root path."""
    if meta["method"] == "btrfs":
        return store / meta["id"]
    tmp = store / f".tmp-{meta['id']}"
    if tmp.exists():
        shutil.rmtree(tmp)
    tmp.mkdir(parents=True)
    with tarfile.open(store / meta["archive"], "r:gz") as tf:
        tf.extractall(tmp)
    return tmp / meta["workspace"]


def _cleanup_tmp(base: Path, meta: dict):
    if meta["method"] == "tar":
        root = base.parent
        if root.name.startswith(".tmp-"):
            shutil.rmtree(root, ignore_errors=True)


def _tree_diff(a: Path, b: Path) -> list[str]:
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
            changed.append(f"+ {k}")
        elif k not in ib:
            changed.append(f"- {k}")
        elif ia[k] != ib[k]:
            changed.append(f"M {k}")
    return changed


# --------------------------------------------------------------------------- #
# Server: fs  (READ-ONLY, scoped to SF_MCP_FS_ROOT)
# --------------------------------------------------------------------------- #
def build_fs() -> Server:
    root_env = os.environ.get("SF_MCP_FS_ROOT", str(Path.cwd()))
    root = Path(root_env).resolve()
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
    SERVERS[name]().serve()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
