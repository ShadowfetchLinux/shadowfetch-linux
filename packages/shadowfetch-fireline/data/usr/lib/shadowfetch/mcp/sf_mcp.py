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
  * Every tool DECLARES what it does -- READ_ONLY, MUTATING or DESTRUCTIVE --
    and the gate and the audit record read that declaration rather than the
    tool's name, so a tool added later is governed the moment it is registered.
  * Every call that CHANGES something is recorded, chained, in a log this
    package owns, or it is REFUSED. A read that cannot be recorded still
    returns unrecorded, and says on the
    server's stderr that it went unrecorded.
  * Destructive tools are not offered to agents. There is no tool-level
    approval path in this build, so `undo` -- which discards a person's work as
    readily as an agent's -- is hidden and refused unless an operator sets
    SHADOWFETCH_MCP_DESTRUCTIVE=allow AND the call carries a session id that
    names a Firebreak session record on this machine.
  * No third-party Python dependencies. Anything not in the standard library is
    an integration point that can rot or be supply-chain attacked; an MCP
    surface that an autonomous agent talks to is the last place that belongs.
  * Errors are returned as MCP tool errors (isError), never tracebacks to the
    agent.

Protocol: a minimal but correct subset of MCP over newline-delimited stdio
JSON-RPC: initialize, notifications/initialized, tools/list, tools/call, ping.
"""
from __future__ import annotations

import datetime
import fcntl
import hashlib
import json
import os
import pwd
import re
import shutil
import subprocess
import sys
import tarfile
import time
import uuid
from pathlib import Path

PROTOCOL_VERSION = "2025-06-18"
SERVER_VERSION = "4.1.0"


# --------------------------------------------------------------------------- #
# Trusted executables
# --------------------------------------------------------------------------- #
# PERMANENT INVARIANT: an executable whose output this file turns into a
# statement about the machine is named by an explicit ABSOLUTE path, never
# resolved through PATH -- and the child's PATH is pinned too, because
# resolving the program is not enough when that program resolves its own
# helpers through whatever it inherits.
#
# Two call sites in this file used shutil.which() and both were wrong in the
# same way -- the directory that was CHECKED and the directory that ANSWERED
# were not the same directory:
#
#   * `snapper` produces the restore-point listing an agent reads back. The
#     which() was constrained to a fixed TRUSTED_PATH, but the exec that
#     followed handed the bare name "snapper" to subprocess with the caller's
#     own environment, so the real PATH chose the binary that the constrained
#     lookup had approved. A `snapper` in ~/.local/bin answered a check that
#     had only ever looked at /usr/bin.
#   * the Passport is an attestation of this machine's security posture. Its
#     candidate loop tried the BARE NAME "shadowfetch-passport" BEFORE the
#     absolute path, so PATH won whenever it had an answer -- the exact
#     opposite of what the comment beside it claimed.
#
# The snapper candidate list is deliberately the same list the update
# authority uses (sfupdate.trusted.TRUSTED_PATHS): one set of places snapper
# may live, not two. It is spelled out here rather than imported because
# shadowfetch-fireline only Recommends the package that ships that module,
# and an MCP server that refused to start without it would be a worse
# failure than a listing that says it has no trusted snapper.
_TRUSTED_SNAPPER = ("/usr/bin/snapper", "/usr/sbin/snapper",
                    "/bin/snapper", "/sbin/snapper")
_TRUSTED_PASSPORT = ("/usr/bin/shadowfetch-passport",)

# The fixed PATH every child of this file gets. This is phoenix.trusted's
# SAFE_PATH spelled out: /usr/local is NOT in it, because on a stock install
# that is where unpackaged binaries are dropped and nothing this file runs is
# expected to live there.
TRUSTED_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"


# --------------------------------------------------------------------------- #
# What a tool DOES, declared as data
# --------------------------------------------------------------------------- #
# The gate and the audit record read a tool's category. Neither ever asks which
# tool it is looking at, so a tool added later is governed the moment it is
# registered -- and it cannot be registered without answering the question,
# because Tool refuses a category it does not recognise.
#
#   READ_ONLY    reports state and changes none
#   MUTATING     adds state; nothing that existed before the call is lost
#   DESTRUCTIVE  discards state that existed before the call
#
# snapshot() is MUTATING, not DESTRUCTIVE: it only adds a restore point. undo()
# is DESTRUCTIVE because everything in the workspace since the checkpoint goes,
# including work a person did rather than only an agent's.
READ_ONLY = "READ_ONLY"
MUTATING = "MUTATING"
DESTRUCTIVE = "DESTRUCTIVE"
CATEGORIES = (READ_ONLY, MUTATING, DESTRUCTIVE)

# How an operator hands agents the destructive tools this surface hides. Not a
# boolean-ish value on purpose: "allow" is a word somebody typed deliberately,
# and an inherited "1" from an unrelated variable cannot mean it.
DESTRUCTIVE_ENV = "SHADOWFETCH_MCP_DESTRUCTIVE"
DESTRUCTIVE_ALLOW = "allow"


def destructive_allowed() -> bool:
    return (os.environ.get(DESTRUCTIVE_ENV) or "").strip() == DESTRUCTIVE_ALLOW


# --------------------------------------------------------------------------- #
# Correlation: which session a call belongs to, and how much of that is checked
# --------------------------------------------------------------------------- #
# An MCP server is a separate process from whatever started the agent, so the
# identity has to be handed in. SHADOWFETCH_MCP_SESSION is the id an operator or
# an orchestrator issues; SHADOWFETCH_FIREBREAK is the one Firebreak already
# exports into a sandbox, so a server started inside one correlates with no
# extra configuration.
#
# The four states are kept apart because they are four different facts. "No id
# was given" is not "an id was given that names nothing on this machine", and
# only OBSERVED is evidence of anything beyond the caller's own say-so: a
# Firebreak session record exists on disk under that id. That is weaker than
# "the session is real" -- anything running as this uid can create such a file,
# so OBSERVED raises the cost of a forged correlation without making one
# impossible. A destructive call requires it because it is the strongest
# evidence available to a process with no more privilege than the agent it is
# gating, not because it is proof. The other three are DECLARED and nothing
# more.
CORRELATION_ABSENT = "absent"
CORRELATION_MALFORMED = "malformed"
CORRELATION_UNKNOWN = "unknown"
CORRELATION_OBSERVED = "observed"

CORRELATION_ENV = ("SHADOWFETCH_MCP_SESSION", "SHADOWFETCH_FIREBREAK")

# The shape Firebreak enforces on the same id, because it names a systemd unit,
# a session file there and a record here.
_SESSION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")


def _state_root() -> Path:
    """Where Firebreak writes its session records.

    This MUST match shadowfetch-firebreak's state(): the two are separate
    programs and a divergence means this gate looks in a directory nothing
    writes to, so every real session reads as unrecorded. That is exactly what
    happened when Firebreak moved off XDG_STATE_HOME and this copy did not, and
    test_mcp_audit.py now asserts the two agree rather than trusting a comment.

    From the passwd entry rather than $HOME, and relocatable only through one
    purpose-named variable, so an ambient desktop variable cannot move security
    audit state without anybody deciding to.
    """
    try:
        home = Path(pwd.getpwuid(os.geteuid()).pw_dir)
    except (KeyError, OSError):
        home = Path.home()
    return home / ".local/state"


MCP_STATE_ENV = "SHADOWFETCH_MCP_STATE"


def _audit_root() -> Path:
    """Where THIS server keeps its own audit log.

    A separate question from where Firebreak's records live, and separately
    overridable: relocating your own audit log is a different decision from
    reading somebody else's evidence. Purpose-named, so no ambient variable
    moves it by accident -- an agent that can redirect the log that records it
    has defeated the log.
    """
    override = os.environ.get(MCP_STATE_ENV, "").strip()
    if override:
        candidate = Path(override).expanduser()
        if candidate.is_absolute():
            return candidate
    return _state_root()


def _firebreak_state() -> Path:
    """The directory Firebreak writes its session records into.

    Mirrors shadowfetch-firebreak's state() EXACTLY, including that the override
    names the audit directory itself rather than a state root. The first version
    of this treated it as a root and appended shadowfetch/firebreak, so the two
    agreed only while the variable was unset -- the one case where agreement is
    free and proves nothing. A test now drives both with the variable set.
    """
    override = os.environ.get("SHADOWFETCH_FIREBREAK_STATE", "").strip()
    if override:
        candidate = Path(override).expanduser()
        if candidate.is_absolute():
            return candidate
    return _state_root() / "shadowfetch/firebreak"


def _session_recorded(session: str) -> bool:
    """True when Firebreak wrote a session record under this id."""
    return (_firebreak_state() / (session + ".session")).is_file()


def correlation() -> dict:
    for source in CORRELATION_ENV:
        value = (os.environ.get(source) or "").strip()
        if not value:
            continue
        if not _SESSION_ID.match(value):
            return {"session": value[:64], "source": source,
                    "status": CORRELATION_MALFORMED}
        return {"session": value, "source": source,
                "status": (CORRELATION_OBSERVED if _session_recorded(value)
                           else CORRELATION_UNKNOWN)}
    return {"session": None, "source": None, "status": CORRELATION_ABSENT}


# --------------------------------------------------------------------------- #
# The audit record this package owns
# --------------------------------------------------------------------------- #
# Mission Control keeps a chained event log with a journald mirror, and writing
# MCP calls into it would be the obvious move. This file cannot:
# shadowfetch-missions Depends on shadowfetch-fireline and not the reverse, so on
# a machine with only Fireline installed those modules are absent -- and handing
# the agent-facing process a write handle on Mission Control's chain would let an
# agent append to the record that describes it.
#
# So the record lives here, chained the same way (sha256 over the previous hash
# and the canonical row) so that the two can be merged later without either
# being reinterpreted. The journald anchor IS the shared one when
# shadowfetch-missions happens to be installed: an anchor outside this uid is
# the only part of this that an agent running as the same user cannot rewrite.
AUDIT_RECORD_VERSION = 1
AUDIT_DIRNAME = "shadowfetch/mcp"
AUDIT_FILENAME = "audit.jsonl"
AUDIT_STATE_FILENAME = "audit-state.json"
AUDIT_GENESIS = "audit-chain-started"
AUDIT_GENESIS_PREV = "0" * 64
AUDIT_ARG_LIMIT = 2000
AUDIT_TAIL_WINDOW = 65536

# Covered by the hash, in a fixed order. seq is in it, so renumbering rows is
# detectable and not merely implausible.
AUDIT_HASHED_FIELDS = ("seq", "at", "chain", "phase", "server", "tool",
                       "category", "decision", "reason", "correlation", "args",
                       "outcome", "pid")

_NOTED_FAILURE = None
_SHARED_ANCHOR = None


class AuditUnavailable(Exception):
    """The call could not be recorded.

    For a tool that changes something this is a refusal, not a warning: an
    unrecorded destructive call is the exact thing this surface exists to stop.
    """


def _stamp() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(
        timespec="milliseconds")


def _audit_canonical(payload: dict) -> bytes:
    """One byte string for one logical record.

    sort_keys so key order cannot change the digest, tight separators so
    pretty-printing cannot, ensure_ascii=False so non-ASCII text hashes as the
    text it is rather than as an escape a different json version may spell
    differently.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def audit_hash(prev_hash, row: dict) -> str:
    payload = {key: row.get(key) for key in AUDIT_HASHED_FIELDS}
    return hashlib.sha256((prev_hash or "").encode("utf-8")
                          + _audit_canonical(payload)).hexdigest()


def _audit_args(args) -> str:
    """The arguments as given, capped.

    Every argument any tool in this file declares is a workspace name, a
    checkpoint id or a path inside a scope, and naming them is the whole value
    of the record: "which workspace did it restore" is the question. The log is
    0600 inside a 0700 directory. A tool that ever declares a secret-bearing
    argument has to change this function, not only add a schema.
    """
    try:
        text = json.dumps(args, sort_keys=True, ensure_ascii=False)
    except (TypeError, ValueError):
        text = repr(args)
    if len(text) > AUDIT_ARG_LIMIT:
        text = text[:AUDIT_ARG_LIMIT] + f"...[truncated at {AUDIT_ARG_LIMIT} characters]"
    return text


def _tail_record(handle):
    """The last record in an open log, or None for an empty one."""
    handle.seek(0, os.SEEK_END)
    size = handle.tell()
    if not size:
        return None
    window = min(size, AUDIT_TAIL_WINDOW)
    handle.seek(size - window)
    data = handle.read(window)
    for line in reversed(data.splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except ValueError as exc:
            raise AuditUnavailable(
                "the last line of the audit log is not a record, so nothing can "
                "be chained onto it") from exc
        if not isinstance(row, dict) or not isinstance(row.get("seq"), int) \
                or not row.get("hash") or not row.get("chain"):
            raise AuditUnavailable(
                "the last audit record has no sequence, hash or chain id")
        return row
    return None


def _read_state(directory: Path) -> dict:
    try:
        with open(directory / AUDIT_STATE_FILENAME, "r", encoding="utf-8") as handle:
            state = json.load(handle)
        return state if isinstance(state, dict) else {}
    except (OSError, ValueError):
        return {}


def _write_state(directory: Path, state: dict) -> None:
    try:
        temporary = directory / (AUDIT_STATE_FILENAME + ".tmp")
        with open(temporary, "w", encoding="utf-8") as handle:
            json.dump(state, handle, sort_keys=True)
        os.replace(temporary, directory / AUDIT_STATE_FILENAME)
        os.chmod(directory / AUDIT_STATE_FILENAME, 0o600)
    except OSError:
        # Bookkeeping about a problem must never become a second problem for
        # the caller. The stderr notice below still fires.
        pass


def _shared_anchor():
    """sf_audit.mirror from shadowfetch-missions, when that package is present.

    The same one-directional-at-runtime borrow Firebreak makes for redact(): the
    package that owns the journald anchor Depends on this one, so it can never be
    a dependency in this direction and its absence must not be an error. It
    filters by chain id when it reads, so MCP rows and mission rows share the
    journal identifier without either being mistaken for the other.
    """
    global _SHARED_ANCHOR
    if _SHARED_ANCHOR is not None:
        return _SHARED_ANCHOR
    locations = [Path("/usr/lib/shadowfetch/missions")]
    locations += [parent / "packages/shadowfetch-missions/data/usr/lib/shadowfetch/missions"
                  for parent in Path(__file__).resolve().parents]
    for location in locations:
        if (location / "sf_audit.py").is_file():
            if str(location) not in sys.path:
                sys.path.insert(0, str(location))
            try:
                from sf_audit import mirror
            except ImportError:
                break
            _SHARED_ANCHOR = mirror
            return _SHARED_ANCHOR
    _SHARED_ANCHOR = False
    return _SHARED_ANCHOR


def _anchor(record: dict):
    """Mirror one record head outside this uid. Returns (ok, reason).

    Never raises and never gates: the local log is the record of truth, and
    losing it because the journal is unreachable would trade the record for its
    shadow. Whether it worked is reported, not assumed.
    """
    send = _shared_anchor()
    if not send:
        return False, ("shadowfetch-missions is not installed, so this log has no "
                       "external anchor and end-truncation is not detectable")
    return send({"chain": record.get("chain"), "seq": record.get("seq"),
                 "hash": record.get("hash"), "at": record.get("at"),
                 "mission": None,
                 "event": "mcp:%s.%s" % (record.get("server") or "-",
                                         record.get("tool") or "-")})


class AuditLog:
    """One chained line per MCP tool call, in a log this package owns."""

    def __init__(self, root=None):
        self._root = Path(root).expanduser() if root else None

    def directory(self) -> Path:
        directory = Path(self._root or (_audit_root() / AUDIT_DIRNAME))
        directory = directory.expanduser().resolve()
        workspaces = _workspaces_root()
        if directory == workspaces or workspaces in directory.parents:
            raise AuditUnavailable(
                "the audit log would sit inside the workspace root, where what "
                "it records could rewrite it")
        try:
            directory.mkdir(parents=True, mode=0o700, exist_ok=True)
            directory.chmod(0o700)
        except OSError as exc:
            raise AuditUnavailable(f"cannot prepare {directory}: {exc}") from exc
        return directory

    def path(self) -> Path:
        return self.directory() / AUDIT_FILENAME

    def append(self, row: dict, *, durable: bool) -> dict:
        """Chain one row on and return it, or raise AuditUnavailable.

        Reading the head and writing after it happen under one exclusive lock.
        Two servers appending at the same instant would otherwise read the same
        head and fork the chain into two branches that each verify on their own.
        """
        path = self.path()
        try:
            handle = open(path, "a+b")
        except OSError as exc:
            raise AuditUnavailable(f"cannot open {path}: {exc}") from exc
        try:
            with handle:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                # The file arrives with the process umask; the 0700 directory is
                # what actually keeps it private, and this narrows the file as
                # soon as we hold it.
                os.chmod(path, 0o600)
                head = _tail_record(handle)
                if head is None:
                    head = self._emit(handle, {
                        "phase": AUDIT_GENESIS, "server": None, "tool": None,
                        "category": None, "decision": None, "args": None,
                        "correlation": None, "outcome": None,
                        "reason": ("the MCP audit chain begins here; calls made "
                                   "before it were made by a build that kept no "
                                   "record and cannot be recovered")},
                        head=None, chain=uuid.uuid4().hex, durable=True)
                written = self._emit(handle, row, head=head, chain=head["chain"],
                                     durable=durable)
        except OSError as exc:
            raise AuditUnavailable(f"cannot write {path}: {exc}") from exc
        self._mirror(written)
        return written

    def note(self, kind: str, reason) -> None:
        """Make a failure findable. Never raises.

        Deduplicated per reason per process: a machine with no journald anchor
        would otherwise write a state file on every single call, and noise is
        how a real caveat comes to be ignored.
        """
        global _NOTED_FAILURE
        reason = str(reason)
        if _NOTED_FAILURE == (kind, reason):
            return
        _NOTED_FAILURE = (kind, reason)
        sys.stderr.write(f"shadowfetch-mcp: {kind} audit failure: {reason[:400]}\n")
        sys.stderr.flush()
        try:
            directory = self.directory()
        except AuditUnavailable:
            return          # nowhere to write it; stderr above is all there is
        state = _read_state(directory)
        state[kind + "_failures"] = int(state.get(kind + "_failures") or 0) + 1
        state["last_" + kind + "_error"] = reason[:500]
        state["last_failure_at"] = _stamp()
        _write_state(directory, state)

    # -- internals ---------------------------------------------------------- #
    def _emit(self, handle, row, *, head, chain, durable):
        record = dict(row)
        record["v"] = AUDIT_RECORD_VERSION
        record["chain"] = chain
        record["seq"] = (head["seq"] + 1) if head else 1
        record["at"] = _stamp()
        record["pid"] = os.getpid()
        previous = head["hash"] if head else AUDIT_GENESIS_PREV
        record["prev_hash"] = previous
        record["hash"] = audit_hash(previous, record)
        handle.write(_audit_canonical(record) + b"\n")
        handle.flush()
        if durable:
            # Ordering, not paranoia: a mutating call is refused unless its
            # intent is already on the platter, so the log cannot end up
            # describing less than actually happened.
            os.fsync(handle.fileno())
        return record

    def _mirror(self, record):
        ok, reason = _anchor(record)
        if not ok:
            self.note("mirror", reason)


def audit_state(root=None) -> dict:
    """What the audit has managed, so a degraded log is a state, not a silence."""
    log = AuditLog(root)
    try:
        directory = log.directory()
    except AuditUnavailable as exc:
        return {"available": False, "reason": str(exc), "path": None}
    state = _read_state(directory)
    state.update(available=True, reason=None,
                 path=str(directory / AUDIT_FILENAME))
    return state


def verify_audit(path=None) -> dict:
    """Recompute the chain and report what it proves.

    A report rather than a boolean: "there is no log", "a record was altered"
    and "the sequence jumps" are different facts and a caller acting on one of
    them needs to know which. Truncation at the END is not detectable here, by
    construction -- every surviving record still verifies. That is what the
    journald anchor exists for.
    """
    target = Path(path) if path else AuditLog().path()
    report = {"path": str(target), "records": 0, "chain": None, "head": None,
              "head_seq": None, "ok": True, "problems": []}
    try:
        lines = target.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        report["ok"] = False
        report["problems"].append("no audit log exists at this path")
        return report
    except OSError as exc:
        report["ok"] = False
        report["problems"].append(f"the audit log cannot be read: {exc}")
        return report
    previous_hash, previous_seq = None, None
    for number, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except ValueError:
            report["ok"] = False
            report["problems"].append(f"line {number} is not a record")
            continue
        report["records"] += 1
        if report["chain"] is None:
            report["chain"] = row.get("chain")
        elif row.get("chain") != report["chain"]:
            report["ok"] = False
            report["problems"].append(
                f"line {number}: belongs to chain {row.get('chain')!r}, not "
                f"{report['chain']!r}, so two logs were merged or the chain forked")
        expected = AUDIT_GENESIS_PREV if previous_hash is None else previous_hash
        if row.get("prev_hash") != expected:
            report["ok"] = False
            report["problems"].append(
                f"line {number}: prev_hash does not follow the record before it "
                "(one was inserted, removed or reordered here)")
        if previous_seq is not None and row.get("seq") != previous_seq + 1:
            report["ok"] = False
            report["problems"].append(
                f"line {number}: sequence {row.get('seq')} follows {previous_seq}, "
                "so the log was truncated or renumbered")
        if audit_hash(row.get("prev_hash"), row) != row.get("hash"):
            report["ok"] = False
            report["problems"].append(
                f"line {number}: content does not match its hash (this record was "
                "modified after it was written)")
        previous_hash, previous_seq = row.get("hash"), row.get("seq")
    report["head"], report["head_seq"] = previous_hash, previous_seq
    if not report["records"]:
        report["ok"] = False
        report["problems"].append("the audit log is empty; nothing is verifiable")
    return report


# --------------------------------------------------------------------------- #
# Tiny MCP server framework
# --------------------------------------------------------------------------- #
class Tool:
    def __init__(self, name, description, schema, handler, category):
        if category not in CATEGORIES:
            raise ValueError(
                f"tool {name!r} must declare one of "
                + ", ".join(CATEGORIES) + f"; got {category!r}")
        self.name = name
        self.description = description
        self.schema = schema
        # The engine, ungated and unrecorded. Server.call() is the audited path
        # an agent reaches over the protocol; shadowfetch-checkpoint and the
        # mission engine call the engine directly because they are a person at a
        # terminal and an orchestrator with its own chain, not the agent surface.
        self.handler = handler
        self.category = category


class Server:
    def __init__(self, name, instructions="", *, audit=None, allow_destructive=None):
        self.name = name
        self.instructions = instructions
        self.tools: dict[str, Tool] = {}
        self.audit = AuditLog() if audit is None else audit
        # Read once, at construction: the posture belongs to the process an
        # operator started, not to whatever the environment happens to say by
        # the time a particular call arrives.
        self.allow_destructive = (destructive_allowed() if allow_destructive is None
                                  else bool(allow_destructive))

    def tool(self, name, description, schema, category):
        def deco(fn):
            self.tools[name] = Tool(name, description, schema, fn, category)
            return fn
        return deco

    # -- JSON-RPC plumbing -------------------------------------------------- #
    def _result(self, rid, result):
        return {"jsonrpc": "2.0", "id": rid, "result": result}

    def _error(self, rid, code, message):
        return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}

    def _text(self, text, is_error=False):
        return {"content": [{"type": "text", "text": text}], "isError": is_error}

    # -- category, gate and record ------------------------------------------ #
    def _describe(self, tool):
        """The tool as the protocol sees it, carrying its category.

        annotations are the protocol's own vocabulary for this; _meta carries
        the category verbatim so a client that speaks Shadowfetch does not have
        to infer it back out of two booleans.
        """
        return {"name": tool.name, "description": tool.description,
                "inputSchema": tool.schema,
                "annotations": {"readOnlyHint": tool.category == READ_ONLY,
                                "destructiveHint": tool.category == DESTRUCTIVE},
                "_meta": {"shadowfetch/category": tool.category}}

    def listed_tools(self):
        """What this server offers an agent.

        A destructive tool it is not configured to allow is not advertised:
        offering a tool that will be refused teaches an agent to retry it.
        """
        return [tool for tool in self.tools.values()
                if tool.category != DESTRUCTIVE or self.allow_destructive]

    def _gate(self, tool, who):
        """(allowed, reason), decided from the category and the correlation.

        The tool's name is never consulted, so this is the rule for whatever is
        registered next as well as for what is registered today.
        """
        if tool.category == DESTRUCTIVE and not self.allow_destructive:
            return False, (
                f"{self.name}.{tool.name} is DESTRUCTIVE and is not offered to "
                "agents. This build has no tool-level approval path -- approval "
                "exists at the mission level only -- so rather than ask a "
                "question it could not enforce, the surface withholds the tool. "
                f"An operator enables it with {DESTRUCTIVE_ENV}={DESTRUCTIVE_ALLOW} "
                "and a recorded session id; a person can run "
                "`shadowfetch-checkpoint undo` at a terminal meanwhile. Nothing "
                "was changed.")
        if tool.category == DESTRUCTIVE and who["status"] != CORRELATION_OBSERVED:
            return False, (
                f"{self.name}.{tool.name} was refused: this call cannot be tied to "
                f"a session that exists (correlation {who['status']}). Set "
                f"{CORRELATION_ENV[0]} to the id of a recorded Firebreak session. "
                "A destructive call that cannot be attributed is not one this "
                "server will make. Nothing was changed.")
        return True, f"{tool.category} call permitted"

    def _record(self, *, phase, tool, category, decision, reason, who, args,
                outcome=None, durable=False, required=False):
        """Write one audit row. Raises only when the caller said it must."""
        try:
            return self.audit.append({
                "phase": phase, "server": self.name, "tool": tool,
                "category": category, "decision": decision, "reason": reason,
                "correlation": who, "args": _audit_args(args),
                "outcome": outcome}, durable=durable)
        except AuditUnavailable as exc:
            if required:
                raise
            self.audit.note("record", exc)
            return None

    def call(self, name, args):
        """The audited entry point for a tool call; handle() routes through it.

        Reaching tool.handler directly runs the engine with no record, which is
        why the in-process callers that keep their own audit chain use
        checkpoint_call() rather than a Server object.
        """
        who = correlation()
        tool = self.tools.get(name)
        if tool is None:
            self._record(phase="denied", tool=str(name)[:64], category=None,
                         decision="denied", reason="no such tool", who=who,
                         args=args)
            return self._text(f"Unknown tool: {name}", is_error=True)
        allowed, reason = self._gate(tool, who)
        if not allowed:
            # A refusal changes nothing, so a record that cannot be written
            # cannot let anything through: the refusal stands either way, and a
            # lost denial is counted rather than escalated into an outage.
            self._record(phase="denied", tool=tool.name, category=tool.category,
                         decision="denied", reason=reason, who=who, args=args,
                         durable=tool.category != READ_ONLY)
            return self._text(reason, is_error=True)
        effecting = tool.category in (MUTATING, DESTRUCTIVE)
        if effecting:
            # Fail closed. The intent is on the platter before the effect, or
            # there is no effect.
            try:
                self._record(phase="requested", tool=tool.name,
                             category=tool.category, decision="allowed",
                             reason=reason, who=who, args=args, durable=True,
                             required=True)
            except AuditUnavailable as exc:
                return self._text(
                    f"{self.name}.{tool.name} was refused because the call could "
                    f"not be recorded: {exc}. Nothing was changed.", is_error=True)
        try:
            out = tool.handler(args)
        except _ToolError as exc:
            outcome, result = f"refused: {exc}", self._text(str(exc), is_error=True)
        except Exception as exc:  # never leak a traceback to the agent
            outcome = f"internal error: {exc}"
            result = self._text(outcome, is_error=True)
        else:
            outcome = "ok"
            result = (out if isinstance(out, dict) and "content" in out
                      else self._text(out if isinstance(out, str)
                                      else json.dumps(out, indent=2)))
        self._record(phase="completed" if outcome == "ok" else "failed",
                     tool=tool.name, category=tool.category, decision="allowed",
                     reason=reason, who=who, args=args, outcome=outcome,
                     durable=effecting)
        return result

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
            return self._result(rid, {"tools": [self._describe(tool)
                                                for tool in self.listed_tools()]})
        if method == "tools/call":
            params = msg.get("params") or {}
            try:
                outcome = self.call(params.get("name"),
                                    params.get("arguments") or {})
            except Exception as exc:  # never leak a traceback to the agent
                outcome = self._text(f"internal error: {exc}", is_error=True)
            return self._result(rid, outcome)
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
def _trusted_env() -> dict:
    """The environment every child of this file gets.

    A fixed system PATH and no loader or shell-startup hooks. Resolving the
    PROGRAM is not enough: shadowfetch-passport is a Python program and
    `btrfs` is dynamically linked, so PYTHONPATH and LD_PRELOAD substitute
    the program just as effectively as replacing the file would.
    """
    env = dict(os.environ)
    env["PATH"] = TRUSTED_PATH
    for hook in ("BASH_ENV", "ENV", "SHELLOPTS", "LD_PRELOAD",
                 "LD_LIBRARY_PATH", "LD_AUDIT", "PYTHONPATH", "PYTHONSTARTUP"):
        env.pop(hook, None)
    return env


def _run(cmd, timeout=20):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                          env=_trusted_env())


def _workspaces_root() -> Path:
    return Path(os.environ.get("SHADOWFETCH_AGENT_WORKSPACES",
                               str(Path.home() / "Workspaces"))).expanduser().resolve()


def _safe_name(name: str) -> str:
    # A LEADING DOT IS REJECTED, like everywhere else that decides this. It was
    # accepted here and nowhere else, so this surface would hand an agent
    # ~/Workspaces/.ssh -- a name Firebreak, the security boundary, then
    # refuses to open. The rule is one decision set (tools/drift_gate.py
    # WORKSPACE_NAME_RULE) executed against a shared corpus, because four
    # regexes that look alike still disagreed on exactly this case.
    if (not isinstance(name, str) or not name.strip() or len(name) > 160
            or name in (".", "..") or name.startswith(".")
            or any(char in name for char in ("/", "\\"))
            or any(ord(char) < 32 or ord(char) == 127 for char in name)):
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
            {"type": "object", "properties": {}}, READ_ONLY)
    def _passport(args):
        # Absolute path or nothing: the Passport is an attestation of this
        # machine's security posture that an agent then reads back, so
        # anything able to set PATH for the MCP server could forge it. The
        # comment here used to say exactly that while the loop below it tried
        # the BARE NAME FIRST -- PATH answered before /usr/bin ever did, and
        # Path("shadowfetch-passport").exists() was a lookup in the current
        # working directory. Same defect as the journalctl one, in another
        # tool, hidden behind a correct comment.
        passport = _trusted_tool(_TRUSTED_PASSPORT)
        if passport is not None:
            r = _run([passport, "--json"])
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
            {"type": "object", "properties": {}}, READ_ONLY)
    def _list(args):
        # This listing is READ-ONLY and never names a restore target -- the
        # number that reaches phoenix-restore comes from
        # Fireproof1.RollbackTarget, not from here. It is still the recovery
        # surface an agent reads, so the program that produces it is named by
        # absolute path and classified, and the refusal says which it is:
        # "not installed" and "installed but substitutable" are different
        # facts, and reporting the second as the first would hide exactly the
        # thing worth knowing.
        snapper = _trusted_tool(_TRUSTED_SNAPPER)
        if snapper is None:
            if any(Path(cand).exists() for cand in _TRUSTED_SNAPPER):
                return ("snapper is installed but is not a root-owned "
                        "system binary, so this listing is not offered.")
            return "snapper is not installed; no restore points to list."
        r = _run([snapper, "--machine-readable", "csv", "list"])
        if r.returncode != 0:
            r = _run([snapper, "list"])
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


# --------------------------------------------------------------------------- #
# Stage H: durability -- space, retention, integrity, and an undo that cannot
# half-happen
# --------------------------------------------------------------------------- #
# The engine below used to answer "did the command exit 0?". That is a different
# question from "can this workspace be put back", and every defect Stage H fixes
# lived in the gap:
#
#   * undo DELETED the live workspace and then copied the checkpoint into the
#     hole it had just made. An ENOSPC, an EACCES on one read-only directory, or
#     a power cut anywhere in that copy left the person with neither their work
#     nor the checkpoint, and the call raised from a workspace it had already
#     destroyed. Undo now builds the tree in a SIBLING directory, verifies it,
#     and exchanges it with the workspace in one rename; the previous contents
#     are deleted only after the restored tree has been verified in place.
#   * nothing checked free space, so the first thing a full disk broke was the
#     recovery mechanism itself.
#   * nothing bounded the store. Every mission snapshot and every pre-undo
#     safety snapshot wrote a fresh full archive and kept it forever.
#   * "method": "btrfs" was recorded on the strength of an exit code from a
#     PATH-resolved `btrfs`, and a PATH-resolved `stat -f` decided whether to
#     try at all. A user-writable PATH could therefore mint a checkpoint that
#     claims to be a snapshot and restores nothing -- the same class of defect
#     as the forged journalctl. The filesystem type now comes from
#     /proc/self/mountinfo (no executable), the tool is an absolute
#     ownership-checked path, and the claim is verified against the filesystem
#     afterwards instead of believed.
#   * nothing compared the restored tree to the checkpoint, so "restored" was an
#     assertion rather than an observation. undo() now returns only after every
#     path, mode, symlink target and file digest in the workspace matches the
#     checkpoint manifest. A partial recovery raises; it is never reported as
#     success.
#
# Vocabulary used deliberately below:
#   VALIDATED  the request names a checkpoint this store holds
#   VERIFIED   a tree was compared, path by path and byte by byte, to a manifest
#   ENFORCED   the workspace cannot be left in a state that was not verified
#              (the exchange is atomic, and the failure paths delete only
#              staging directories)

CHECKPOINT_ACTIONS = ("snapshot", "list", "diff", "undo", "verify", "prune",
                      "recover")

# Retention. Defaults are deliberately generous -- the point is that the store
# is BOUNDED, not that it is small -- and both are operator-settable.
CKPT_KEEP_FLOOR = 2                       # never prune below this many
CKPT_KEEP_DEFAULT = 12
CKPT_BUDGET_DEFAULT = 5 * 1024 ** 3       # bytes of store per workspace
CKPT_SPACE_SLACK = 64 * 1024 ** 2         # headroom demanded beyond the estimate
CKPT_LOCK_SECONDS = 120
CKPT_DEBRIS_TTL = 3600.0                  # staging debris older than this is reaped
CKPT_VERIFY_REPORT = 20                   # mismatches listed before truncating

_CKPT_SIDE = ".sfh"                       # side-car dir; list() globs *.json only
_CKPT_STAGE_PREFIX = ".sf-restore-"
_CKPT_SKIP_DIR = ".sf-checkpoints"
_S_IFMT, _S_IFREG, _S_IFDIR, _S_IFLNK = 0o170000, 0o100000, 0o040000, 0o120000
# A btrfs subvolume root always has inode 256. That is the fact "method":
# "btrfs" asserts, and it is checked against the filesystem rather than taken
# from the exit code of a program the caller could have replaced.
_BTRFS_SUBVOL_INO = 256
_TRUSTED_BTRFS = ("/usr/bin/btrfs", "/bin/btrfs", "/usr/sbin/btrfs", "/sbin/btrfs")


def _ckpt_env_int(name: str, default: int, minimum: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise _ToolError(f"{name} must be a whole number of units, not {raw!r}")
    if value < minimum:
        raise _ToolError(f"{name} must be at least {minimum}")
    return value


def _trusted_tool(candidates: tuple[str, ...]) -> str | None:
    """First candidate that is a root-owned, non-group/other-writable file.

    PERMANENT INVARIANT: an executable whose output decides a security fact is
    named by absolute path and classified, never resolved through PATH. The
    snapshot METHOD recorded in a checkpoint is such a fact -- a forged `btrfs`
    that exits 0 would mint a checkpoint that restores nothing.
    """
    for candidate in candidates:
        try:
            st = os.lstat(candidate)
        except OSError:
            continue
        if (st.st_mode & _S_IFMT) != _S_IFREG or st.st_uid != 0 or st.st_mode & 0o022:
            continue
        return candidate
    return None


def _fstype(path: Path) -> str:
    """Filesystem type of `path`, read from the kernel with no subprocess.

    `stat -f -c %T` used to answer this through a PATH lookup, and its answer
    selects the snapshot method.
    """
    try:
        raw = Path("/proc/self/mountinfo").read_text()
    except OSError:
        return ""
    target = str(path.resolve())
    best_len, best_type = -1, ""
    for line in raw.splitlines():
        head, sep, tail = line.partition(" - ")
        fields = head.split()
        if not sep or len(fields) < 5 or not tail.split():
            continue
        mount = (fields[4].replace("\\040", " ").replace("\\011", "\t")
                 .replace("\\012", "\n").replace("\\134", "\\"))
        if target == mount or target.startswith(mount.rstrip("/") + "/"):
            if len(mount) > best_len:
                best_len, best_type = len(mount), tail.split()[0]
    return best_type


def _ckpt_side(store: Path) -> Path:
    """Side-car directory. Nothing here may match store.glob('*.json'): that
    glob is what makes a checkpoint EXIST for list()."""
    side = store / _CKPT_SIDE
    if side.is_symlink():
        raise _ToolError("checkpoint storage cannot be a symbolic link")
    side.mkdir(mode=0o700, exist_ok=True)
    return side


def _ckpt_fsync_dir(directory: Path) -> None:
    fd = os.open(str(directory), os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _ckpt_atomic_write(path: Path, payload: bytes) -> None:
    """Write-then-rename with fsync on both the file and its directory.

    A checkpoint exists when its metadata file exists, so a torn write there is
    a checkpoint that lists but cannot restore.
    """
    part = path.with_name(path.name + ".part")
    with part.open("wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(part, path)
    _ckpt_fsync_dir(path.parent)


def _ckpt_rmtree(path: Path) -> None:
    """Recursive delete that survives read-only directories.

    shutil.rmtree() cannot unlink a child of a 0o500 directory, and a workspace
    that contains one is ordinary. Before Stage H that failure landed AFTER the
    live workspace had already been deleted.
    """
    try:
        st = os.lstat(path)
    except OSError:
        return
    if (st.st_mode & _S_IFMT) != _S_IFDIR:
        try:
            path.unlink()
        except OSError:
            pass
        return
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass
    try:
        with os.scandir(path) as entries:
            children = [Path(entry.path) for entry in entries]
    except OSError:
        children = []
    for child in children:
        _ckpt_rmtree(child)
    try:
        path.rmdir()
    except OSError:
        pass


# -- the manifest: what a checkpoint must be able to put back ---------------- #
def _ckpt_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _ckpt_scan(root: Path) -> tuple[list[dict], int]:
    """Describe a tree exactly: sorted entries plus total file bytes.

    Refusals happen HERE, before anything is written, so an unreadable
    directory or a device node is a snapshot that did not happen rather than a
    checkpoint that cannot be restored.
    """
    entries: list[dict] = []
    total = 0

    def walk(directory: Path, prefix: str) -> None:
        nonlocal total
        try:
            with os.scandir(directory) as handle:
                children = sorted(handle, key=lambda item: item.name)
        except PermissionError:
            raise _ToolError(
                f"cannot read {prefix or '.'} in this workspace: permission "
                "denied. A checkpoint that cannot read the tree cannot put it "
                "back, so none was taken.")
        except OSError as exc:
            raise _ToolError(f"cannot read {prefix or '.'}: {exc.strerror}")
        for child in children:
            if child.name == _CKPT_SKIP_DIR:
                continue  # matches the tar filter: never archive a store
            rel = f"{prefix}{child.name}"
            st = child.stat(follow_symlinks=False)
            kind = st.st_mode & _S_IFMT
            if kind == _S_IFLNK:
                entries.append({"path": rel, "type": "link",
                                "target": os.readlink(child.path)})
            elif kind == _S_IFDIR:
                entries.append({"path": rel, "type": "dir",
                                "mode": st.st_mode & 0o777})
                walk(Path(child.path), rel + "/")
            elif kind == _S_IFREG:
                try:
                    digest = _ckpt_digest(Path(child.path))
                except PermissionError:
                    raise _ToolError(
                        f"cannot read {rel} in this workspace: permission "
                        "denied. No checkpoint was taken.")
                entries.append({"path": rel, "type": "file",
                                "mode": st.st_mode & 0o777,
                                "size": st.st_size, "sha256": digest})
                total += st.st_size
            else:
                raise _ToolError(
                    f"{rel} is a socket, fifo or device node; a checkpoint "
                    "cannot restore it, so none was taken.")

    walk(root, "")
    entries.sort(key=lambda item: item["path"])
    return entries, total


def _ckpt_usage(root: Path) -> int:
    """Bytes of regular-file content under `root`, without hashing any of it.

    The space precheck wants a size. _ckpt_scan() answers with a size AND a
    digest of every byte, which on a large workspace is a whole extra read to
    compute a number the caller then adds to another number.
    """
    total = 0
    stack = [root]
    while stack:
        try:
            with os.scandir(stack.pop()) as handle:
                children = list(handle)
        except OSError:
            continue
        for child in children:
            if child.name == _CKPT_SKIP_DIR:
                continue
            try:
                st = child.stat(follow_symlinks=False)
            except OSError:
                continue
            kind = st.st_mode & _S_IFMT
            if kind == _S_IFDIR:
                stack.append(Path(child.path))
            elif kind == _S_IFREG:
                total += st.st_size
    return total


def _ckpt_manifest_digest(entries: list[dict]) -> str:
    digest = hashlib.sha256()
    for entry in entries:
        digest.update(json.dumps(entry, sort_keys=True,
                                 separators=(",", ":")).encode() + b"\n")
    return digest.hexdigest()


def _ckpt_manifest_path(store: Path, cid: str) -> Path:
    return _ckpt_side(store) / f"{_safe_name(cid)}.manifest.json"


def _ckpt_manifest(store: Path, meta: dict) -> list[dict] | None:
    """The checkpoint's manifest, or None for a checkpoint written before
    Stage H. None is not an error and is never treated as 'verified'."""
    path = _ckpt_manifest_path(store, meta["id"])
    if not path.exists():
        return None
    try:
        entries = json.loads(path.read_text())
    except (OSError, ValueError):
        raise _ToolError(
            f"workspace unchanged: checkpoint {meta['id']} has an unreadable "
            "manifest and cannot be verified")
    if not isinstance(entries, list):
        raise _ToolError(
            f"workspace unchanged: checkpoint {meta['id']} has a malformed manifest")
    if meta.get("tree_digest") and _ckpt_manifest_digest(entries) != meta["tree_digest"]:
        raise _ToolError(
            f"workspace unchanged: checkpoint {meta['id']} manifest does not "
            "match the digest recorded when it was taken (corrupted store)")
    return entries


def _ckpt_verify(root: Path, entries: list[dict]) -> list[str]:
    """Compare a tree to a manifest. Empty list means VERIFIED, nothing else does."""
    try:
        observed, _ = _ckpt_scan(root)
    except _ToolError as exc:
        return [str(exc)]
    want = {item["path"]: item for item in entries}
    have = {item["path"]: item for item in observed}
    problems: list[str] = []
    for path in sorted(set(want) | set(have)):
        expected, actual = want.get(path), have.get(path)
        if expected is None:
            problems.append(f"unexpected {path}")
        elif actual is None:
            problems.append(f"missing {path}")
        elif expected != actual:
            problems.append(f"differs {path}")
        if len(problems) >= CKPT_VERIFY_REPORT:
            problems.append("... further mismatches not listed")
            break
    return problems


# -- space --------------------------------------------------------------- #
def _ckpt_free(path: Path) -> int:
    st = os.statvfs(str(path))
    return st.f_bavail * st.f_frsize


def _ckpt_require_space(where: Path, need: int, what: str) -> None:
    """Refuse BEFORE writing. A full disk must not be discovered halfway
    through the mechanism that exists to recover from mistakes."""
    free = _ckpt_free(where)
    want = int(need) + CKPT_SPACE_SLACK
    if free < want:
        raise _ToolError(
            f"workspace unchanged: not enough free space to {what} -- "
            f"{want} bytes wanted on {where}, {free} available")


# -- retention ------------------------------------------------------------ #
def _ckpt_rows(store: Path) -> list[tuple[str, dict, float]]:
    rows = []
    for meta_path in store.glob("*.json"):
        try:
            meta = json.loads(meta_path.read_text())
            age = meta_path.stat().st_mtime
        except (OSError, ValueError):
            continue
        if isinstance(meta, dict) and meta.get("id") == meta_path.stem:
            rows.append((meta_path.stem, meta, age))
    rows.sort(key=lambda row: (row[2], row[0]))
    return rows


def _ckpt_store_bytes(store: Path) -> int:
    """Bytes the store occupies, counting each inode once so a deduplicated
    (hardlinked) archive is not billed twice."""
    seen: set[tuple[int, int]] = set()
    total = 0
    for path in store.rglob("*"):
        try:
            st = path.lstat()
        except OSError:
            continue
        if (st.st_mode & _S_IFMT) != _S_IFREG:
            continue
        key = (st.st_dev, st.st_ino)
        if key in seen:
            continue
        seen.add(key)
        total += st.st_size
    return total


def _ckpt_drop(store: Path, cid: str, meta: dict) -> None:
    """Remove one checkpoint. The metadata file goes FIRST: a crash mid-drop
    then leaves debris the reaper collects, never a checkpoint that lists but
    has no data."""
    try:
        (store / f"{cid}.json").unlink()
    except OSError:
        pass
    archive = meta.get("archive")
    if archive:
        try:
            (store / _safe_name(archive)).unlink()
        except (OSError, _ToolError):
            pass
    try:
        _ckpt_manifest_path(store, cid).unlink()
    except (OSError, _ToolError):
        pass
    if meta.get("method") == "btrfs":
        subvolume = store / cid
        if subvolume.is_dir() and not subvolume.is_symlink():
            tool = _trusted_tool(_TRUSTED_BTRFS)
            if not (tool and _run([tool, "subvolume", "delete",
                                   str(subvolume)]).returncode == 0):
                _ckpt_rmtree(subvolume)


def _ckpt_prune(store: Path, protect: set[str]) -> list[str]:
    """Bound the store by count and by bytes. Never drops a protected
    checkpoint, and never takes the store below CKPT_KEEP_FLOOR."""
    keep = _ckpt_env_int("SHADOWFETCH_CKPT_KEEP", CKPT_KEEP_DEFAULT, CKPT_KEEP_FLOOR)
    budget = _ckpt_env_int("SHADOWFETCH_CKPT_MAX_BYTES", CKPT_BUDGET_DEFAULT, 1 << 20)
    rows = _ckpt_rows(store)
    removable = [row for row in rows if row[0] not in protect]
    dropped: list[str] = []
    while removable and len(rows) - len(dropped) > keep:
        cid, meta, _ = removable.pop(0)
        _ckpt_drop(store, cid, meta)
        dropped.append(cid)
    while (removable and len(rows) - len(dropped) > CKPT_KEEP_FLOOR
           and _ckpt_store_bytes(store) > budget):
        cid, meta, _ = removable.pop(0)
        _ckpt_drop(store, cid, meta)
        dropped.append(cid)
    return dropped


def _ckpt_reap(store: Path, ws: Path) -> None:
    """Collect debris a crashed or refused run left behind.

    Only things this engine creates and nothing references are removed. A
    restore directory is left alone while a journal claims it, and for a day
    afterwards, because it may hold the workspace as it was before an undo.
    """
    rows = _ckpt_rows(store)
    live_archives = {meta.get("archive") for _, meta, _ in rows}
    live_ids = {cid for cid, _, _ in rows}
    now = time.time()

    def stale(path: Path, ttl: float) -> bool:
        try:
            return now - path.lstat().st_mtime > ttl
        except OSError:
            return False

    for child in list(store.iterdir()):
        name = child.name
        if name == _CKPT_SIDE or name.endswith(".json"):
            continue
        if name.startswith(".tmp-") and child.is_dir():
            if stale(child, CKPT_DEBRIS_TTL):
                _ckpt_rmtree(child)
        elif name.endswith(".part"):
            if stale(child, CKPT_DEBRIS_TTL):
                child.unlink(missing_ok=True)
        elif name.endswith(".tar.gz") and name not in live_archives:
            if stale(child, CKPT_DEBRIS_TTL):
                child.unlink(missing_ok=True)
    side = _ckpt_side(store)
    for child in list(side.iterdir()):
        if child.name.endswith(".manifest.json"):
            cid = child.name[: -len(".manifest.json")]
            if cid not in live_ids and stale(child, CKPT_DEBRIS_TTL):
                child.unlink(missing_ok=True)
    if _ckpt_journal_read(store) is None:
        # No journal means no exchange was ever begun, so a restore directory
        # here is staging and nothing else. The pid suffix protects the one
        # this process may be holding: undo() builds its stage and THEN takes
        # the pre-undo safety snapshot, which reaps.
        mine = f".{os.getpid()}"
        for child in list(ws.parent.iterdir()):
            if (child.name.startswith(_CKPT_STAGE_PREFIX + ws.name + ".")
                    and not child.name.endswith(mine)
                    and child.is_dir() and not child.is_symlink()):
                _ckpt_rmtree(child)


# -- serialisation: one workspace, one operation at a time ------------------ #
class _CkptLock:
    """Two concurrent undos, or an undo racing a mission's snapshot, would
    interleave renames on the same workspace. Held for the whole operation."""

    def __init__(self, store: Path):
        self._path = _ckpt_side(store) / "lock"
        self._fd = -1

    def __enter__(self) -> "_CkptLock":
        self._fd = os.open(str(self._path), os.O_CREAT | os.O_RDWR, 0o600)
        deadline = time.monotonic() + CKPT_LOCK_SECONDS
        while True:
            try:
                fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except OSError:
                if time.monotonic() >= deadline:
                    os.close(self._fd)
                    self._fd = -1
                    raise _ToolError(
                        "another checkpoint operation is running on this "
                        "workspace; nothing was changed")
                time.sleep(0.05)

    def __exit__(self, *exc) -> None:
        if self._fd >= 0:
            fcntl.flock(self._fd, fcntl.LOCK_UN)
            os.close(self._fd)
            self._fd = -1


# -- the undo journal ------------------------------------------------------- #
def _ckpt_journal_path(store: Path) -> Path:
    return _ckpt_side(store) / "undo.journal"


def _ckpt_entries_path(store: Path) -> Path:
    """The tree description undo() verified against, kept beside the journal.

    recover() must compare the workspace to the SAME bytes undo() did. Reading
    the checkpoint's manifest again is not the same thing: a checkpoint taken
    before Stage H has none, and guessing there would mean reporting "the undo
    did not take effect" about an undo that did.
    """
    return _ckpt_side(store) / "undo.entries.json"


def _ckpt_entries_write(store: Path, entries: list[dict]) -> None:
    _ckpt_atomic_write(_ckpt_entries_path(store),
                       json.dumps(entries, separators=(",", ":")).encode())


def _ckpt_entries_read(store: Path) -> list[dict] | None:
    try:
        entries = json.loads(_ckpt_entries_path(store).read_text())
    except (OSError, ValueError):
        return None
    return entries if isinstance(entries, list) else None


def _ckpt_journal_read(store: Path) -> dict | None:
    path = _ckpt_journal_path(store)
    try:
        record = json.loads(path.read_text())
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        return {"phase": "unreadable"}
    return record if isinstance(record, dict) else {"phase": "unreadable"}


def _ckpt_journal_write(store: Path, record: dict) -> None:
    _ckpt_atomic_write(_ckpt_journal_path(store),
                       json.dumps(record, indent=2).encode())


def _ckpt_journal_clear(store: Path) -> None:
    path = _ckpt_journal_path(store)
    _ckpt_entries_path(store).unlink(missing_ok=True)
    try:
        path.unlink()
    except OSError:
        return
    _ckpt_fsync_dir(path.parent)


def _ckpt_require_settled(store: Path, ws: Path) -> None:
    """Refuse to operate on a workspace whose last undo did not finish.

    Snapshotting or diffing a half-restored tree would record the half state as
    if it were somebody's work.
    """
    record = _ckpt_journal_read(store)
    if record is not None:
        raise _ToolError(
            f"workspace unchanged: '{ws.name}' has an unfinished undo of "
            f"checkpoint {record.get('checkpoint', '?')} "
            f"(phase {record.get('phase', '?')}). Run "
            f"`shadowfetch-checkpoint recover {ws.name}` first.")


# -- the atomic step -------------------------------------------------------- #
_RENAME_EXCHANGE = 1 << 1
_AT_FDCWD = -100
# renameat2 numbers for the ports Shadowfetch builds; only reached on a glibc
# too old to export the wrapper.
_SYS_RENAMEAT2 = {"x86_64": 316, "aarch64": 276, "riscv64": 276, "i686": 353,
                  "armv7l": 382, "ppc64le": 357, "s390x": 347}


def _ckpt_exchange(first: Path, second: Path) -> bool:
    """RENAME_EXCHANGE: both directories change places in one atomic step.

    Returns False when the kernel or filesystem does not support it, so the
    caller can fall back to the journalled two-rename form. Never raises for
    'unsupported'; a real error (EXDEV, EACCES) is raised.
    """
    import ctypes
    import errno

    libc = ctypes.CDLL(None, use_errno=True)
    left, right = os.fsencode(str(first)), os.fsencode(str(second))
    wrapper = getattr(libc, "renameat2", None)
    ctypes.set_errno(0)
    if wrapper is not None:
        wrapper.restype = ctypes.c_int
        wrapper.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                            ctypes.c_char_p, ctypes.c_uint]
        rc = wrapper(_AT_FDCWD, left, _AT_FDCWD, right, _RENAME_EXCHANGE)
    else:
        number = _SYS_RENAMEAT2.get(os.uname().machine)
        if number is None:
            return False
        libc.syscall.restype = ctypes.c_long
        rc = libc.syscall(ctypes.c_long(number), ctypes.c_int(_AT_FDCWD), left,
                          ctypes.c_int(_AT_FDCWD), right,
                          ctypes.c_uint(_RENAME_EXCHANGE))
    if rc == 0:
        return True
    code = ctypes.get_errno()
    if code in (errno.ENOSYS, errno.EINVAL, errno.EOPNOTSUPP, errno.ENOTSUP,
                errno.EPERM):
        return False
    raise OSError(code, os.strerror(code), str(first))


def _ckpt_swap(ws: Path, stage: Path, store: Path, journal: dict) -> Path:
    """Put `stage` where the workspace is and return the displaced tree.

    Nothing is deleted here. Either form leaves the previous contents intact
    under a name the journal records, so an interruption is recoverable in both
    directions.
    """
    if _ckpt_exchange(ws, stage):
        journal.update(phase="exchanged", displaced=str(stage), atomic=True)
        _ckpt_journal_write(store, journal)
        return stage
    displaced = ws.parent / f"{_CKPT_STAGE_PREFIX}{ws.name}.displaced.{os.getpid()}"
    _ckpt_rmtree(displaced)
    # Written BEFORE the window opens: between the two renames the workspace
    # name does not exist, and this record is what tells recover() where both
    # halves went.
    journal.update(phase="exchanged", displaced=str(displaced), atomic=False)
    _ckpt_journal_write(store, journal)
    os.rename(ws, displaced)
    os.rename(stage, ws)
    return displaced


def _ckpt_materialize(store: Path, meta: dict, stage: Path) -> None:
    """Build the checkpoint's tree at `stage`, a sibling of the workspace.

    A sibling on the same filesystem is what makes the exchange possible; the
    tar path extracts through the existing hardened reader and then renames the
    result into place, which costs nothing extra.
    """
    if meta["method"] == "btrfs":
        source = store / meta["id"]
        if not source.is_dir() or source.is_symlink():
            raise _ToolError(
                f"workspace unchanged: checkpoint {meta['id']} records a btrfs "
                "snapshot that is not present")
        tool = _trusted_tool(_TRUSTED_BTRFS)
        made = False
        if tool:
            made = (_run([tool, "subvolume", "snapshot", str(source),
                          str(stage)]).returncode == 0 and stage.is_dir())
        if not made:
            _ckpt_rmtree(stage)
            shutil.copytree(source, stage, symlinks=True)
        return
    base = _restore_tree(store, meta)
    holder = base.parent
    try:
        if os.stat(holder).st_dev == os.stat(stage.parent).st_dev:
            os.rename(base, stage)
        else:
            shutil.copytree(base, stage, symlinks=True)
    finally:
        _ckpt_rmtree(holder)


def _ckpt_verify_archive(store: Path, meta: dict, entries: list[dict]) -> list[str]:
    """Check a tar checkpoint against its manifest without writing anything.

    This is what `verify` runs: corruption is reported from a read-only pass,
    with no staging directory and no space demand.
    """
    if meta["method"] != "tar":
        return []
    archive = store / _safe_name(meta["archive"])
    prefix = _safe_name(meta["workspace"]) + "/"
    observed: dict[str, dict] = {}
    try:
        with tarfile.open(archive, "r:gz") as handle:
            for item in handle:
                if item.name == meta["workspace"]:
                    continue
                if not item.name.startswith(prefix):
                    return [f"unexpected archive member {item.name}"]
                rel = item.name[len(prefix):].rstrip("/")
                if item.issym():
                    observed[rel] = {"path": rel, "type": "link",
                                     "target": item.linkname}
                elif item.isdir():
                    observed[rel] = {"path": rel, "type": "dir",
                                     "mode": item.mode & 0o777}
                elif item.isfile():
                    stream = handle.extractfile(item)
                    if stream is None:
                        return [f"missing data for {rel}"]
                    digest = hashlib.sha256()
                    with stream:
                        for chunk in iter(lambda: stream.read(1 << 20), b""):
                            digest.update(chunk)
                    observed[rel] = {"path": rel, "type": "file",
                                     "mode": item.mode & 0o777,
                                     "size": item.size,
                                     "sha256": digest.hexdigest()}
                elif item.islnk():
                    target = item.linkname[len(prefix):] if item.linkname.startswith(prefix) else None
                    source = observed.get(target or "")
                    if source is None:
                        return [f"invalid hard link {rel}"]
                    observed[rel] = dict(source, path=rel,
                                         mode=item.mode & 0o777)
                else:
                    return [f"{rel} is a special file and cannot be restored"]
    except (OSError, tarfile.TarError, EOFError) as exc:
        return [f"archive unreadable: {exc}"]
    want = {item["path"]: item for item in entries}
    problems: list[str] = []
    for path in sorted(set(want) | set(observed)):
        expected, actual = want.get(path), observed.get(path)
        if expected is None:
            problems.append(f"unexpected {path}")
        elif actual is None:
            problems.append(f"missing {path}")
        elif expected != actual:
            problems.append(f"differs {path}")
        if len(problems) >= CKPT_VERIFY_REPORT:
            problems.append("... further mismatches not listed")
            break
    return problems


def _ckpt_twin(store: Path, digest: str) -> tuple[str, dict] | None:
    """An existing tar checkpoint of a byte-identical tree, if the store holds
    one. Used to hardlink instead of writing a second archive: a mission
    snapshot followed by an untouched workspace's pre-undo safety snapshot used
    to cost two full copies of the same tree."""
    if not digest:
        return None
    for cid, meta, _ in _ckpt_rows(store):
        if meta.get("tree_digest") != digest or meta.get("method") != "tar":
            continue
        archive = meta.get("archive")
        if archive and (store / archive).is_file():
            return cid, meta
    return None


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
        store = _ckpt_store(ws)
        with _CkptLock(store):
            _ckpt_require_settled(store, ws)
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
        _ckpt_require_settled(store, ws)
        cid, meta = self._meta(store, checkpoint)
        # diff materializes a whole second copy of the tree; say so before
        # filling the disk rather than after.
        _ckpt_require_space(store, int(meta.get("payload_bytes") or 0),
                            f"read checkpoint {cid}")
        base = _restore_tree(store, meta)
        try:
            changes = _tree_changes(base, ws)
        finally:
            # try/finally: a comparison that raises used to leave the whole
            # materialized tree behind in the store.
            _cleanup_tmp(base, meta)
        return {"action": "diff", "workspace": ws.name, "checkpoint": cid,
                "method": meta["method"], "count": len(changes),
                "truncated": len(changes) > DIFF_TEXT_LIMIT,
                "changes": [{"status": status, "path": path} for status, path in changes]}

    def undo(self, workspace: str, checkpoint: str) -> dict:
        """Restore a workspace, transactionally.

        Order matters and is the whole fix. Everything that can fail happens
        while the workspace is still untouched: the checkpoint is VALIDATED,
        the restored tree is built in a SIBLING directory and VERIFIED against
        the manifest, and only then is it exchanged with the workspace in a
        single atomic rename. The previous contents are deleted only after the
        workspace has been verified AGAIN in place.

        The old implementation deleted the workspace first and copied into the
        hole. Any failure in that copy -- ENOSPC, a read-only directory, a
        power cut -- destroyed the person's work with nothing left to restore
        from, and the exception it raised said nothing about what survived.

        This method returns ONLY on a fully verified restore. Every other path
        raises a _ToolError, and the message says which side of the exchange it
        failed on: "workspace unchanged: ..." or "RECOVERY REQUIRED: ...".
        """
        ws = _workspace(workspace)
        store = _ckpt_store(ws)
        with _CkptLock(store):
            try:
                return self._undo(ws, store, checkpoint)
            except _ToolError:
                raise
            except (Exception, KeyboardInterrupt) as exc:
                # Uniform failure semantics for everything the layers below can
                # raise -- a corrupt archive, an ENOSPC, an EACCES, an operator
                # pressing Ctrl-C. The journal is the discriminator and it is
                # exact: it is written immediately before the workspace is
                # touched and cleared only after the restored tree has been
                # verified in place. SystemExit is deliberately not caught.
                detail = f"{type(exc).__name__}: {exc}"
                if _ckpt_journal_read(store) is None:
                    raise _ToolError(
                        f"workspace unchanged: checkpoint {checkpoint} could "
                        f"not be restored ({detail}). Nothing outside the "
                        "checkpoint store was written.") from exc
                raise _ToolError(
                    f"RECOVERY REQUIRED: the undo of checkpoint {checkpoint} "
                    f"failed after it had begun ({detail}). Run "
                    f"`shadowfetch-checkpoint recover {ws.name}`.") from exc

    def _undo(self, ws: Path, store: Path, checkpoint: str) -> dict:
        _ckpt_require_settled(store, ws)
        cid, meta = self._meta(store, checkpoint)
        entries = _ckpt_manifest(store, meta)
        _ckpt_reap(store, ws)
        # Staged tree + the safety archive of the current tree, both on the
        # workspace's filesystem.
        current_bytes = _ckpt_usage(ws)
        need = int(meta.get("payload_bytes") or current_bytes) + current_bytes
        _ckpt_require_space(ws.parent, need, f"restore workspace '{ws.name}'")
        stage = ws.parent / f"{_CKPT_STAGE_PREFIX}{ws.name}.{cid}.{os.getpid()}"
        _ckpt_rmtree(stage)
        settled = False
        try:
            _ckpt_materialize(store, meta, stage)
            if entries is None:
                # A checkpoint written before Stage H carries no manifest, so
                # the tree just materialized is the only description of it.
                # Deriving the manifest here still proves the exchange put
                # every byte in place -- the claim undo() makes -- but it
                # cannot prove the archive matched the original workspace, and
                # does not pretend to.
                entries, _ = _ckpt_scan(stage)
            problems = _ckpt_verify(stage, entries)
            if problems:
                raise _ToolError(
                    f"workspace unchanged: checkpoint {cid} did not restore "
                    "cleanly (" + "; ".join(problems[:5]) + ")")
            safety = self._snapshot(ws, f"pre-undo-of-{cid}", protect={cid})
            _ckpt_entries_write(store, entries)
            journal = {"phase": "exchange", "workspace": ws.name,
                       "checkpoint": cid, "stage": str(stage),
                       "displaced": None, "safety": safety["id"],
                       "started": time.time()}
            _ckpt_journal_write(store, journal)
            staged_id = (lambda st: (st.st_dev, st.st_ino))(os.stat(stage))
            displaced = _ckpt_swap(ws, stage, store, journal)
            # Two independent checks, deliberately not one. This one says the
            # directory now answering to the workspace's name IS the directory
            # that was verified; the content check says the bytes in it are the
            # checkpoint's.
            landed = (lambda st: (st.st_dev, st.st_ino))(os.stat(ws))
            problems = ([] if landed == staged_id else
                        ["the workspace is not the tree that was verified "
                         f"({landed} != {staged_id})"])
            problems += _ckpt_verify(ws, entries)
            if problems:
                raise _ToolError(
                    f"RECOVERY REQUIRED: workspace '{ws.name}' does not match "
                    f"checkpoint {cid} after the exchange "
                    "(" + "; ".join(problems[:5]) + "). The previous contents "
                    f"are at {displaced} and the pre-undo state is checkpoint "
                    f"{safety['id']}; run "
                    f"`shadowfetch-checkpoint recover {ws.name}`.")
            _ckpt_rmtree(displaced)
            _ckpt_journal_clear(store)
            settled = True
        finally:
            if not settled and _ckpt_journal_read(store) is None:
                # Nothing that could be a person's work is removed on a failure
                # path -- only the staging directory, and only while no journal
                # claims it.
                _ckpt_rmtree(stage)
        return {"action": "undo", "workspace": ws.name, "checkpoint": cid,
                "method": meta["method"], "label": meta.get("label", ""),
                "safety": {"id": safety["id"], "method": safety["method"]}}

    def verify(self, workspace: str, checkpoint: str) -> dict:
        """Read-only integrity check of one checkpoint. Writes nothing and
        needs no free space, so it is usable on the full disk that made the
        checkpoint matter."""
        ws = _workspace(workspace)
        store = _ckpt_store(ws)
        cid, meta = self._meta(store, checkpoint)
        entries = _ckpt_manifest(store, meta)
        if entries is None:
            return {"action": "verify", "workspace": ws.name, "checkpoint": cid,
                    "method": meta["method"], "entries": 0, "verified": False,
                    "problems": ["taken before Stage H: no manifest to verify against"]}
        if meta["method"] == "btrfs":
            subvolume = store / cid
            if not subvolume.is_dir() or subvolume.is_symlink():
                problems = ["btrfs snapshot is missing"]
            else:
                problems = _ckpt_verify(subvolume, entries)
        else:
            problems = _ckpt_verify_archive(store, meta, entries)
        return {"action": "verify", "workspace": ws.name, "checkpoint": cid,
                "method": meta["method"], "entries": len(entries),
                "verified": not problems, "problems": problems}

    def prune(self, workspace: str) -> dict:
        """Apply the retention policy now (snapshot() also applies it)."""
        ws = _workspace(workspace)
        store = _ckpt_store(ws)
        with _CkptLock(store):
            _ckpt_reap(store, ws)
            rows = _ckpt_rows(store)
            protect = {rows[-1][0]} if rows else set()
            dropped = _ckpt_prune(store, protect)
            remaining = _ckpt_rows(store)
        return {"action": "prune", "workspace": ws.name, "dropped": dropped,
                "kept": len(remaining), "bytes": _ckpt_store_bytes(store)}

    def recover(self, workspace: str) -> dict:
        """Finish or reverse an undo that was interrupted.

        The decision is made by OBSERVING the workspace against the
        checkpoint's manifest, not by trusting the phase the journal recorded:
        the journal says where the two trees went, the filesystem says which
        one is in place.

        An interrupted undo is never completed silently. If the workspace is
        still the pre-undo tree, recovery rolls the attempt back and says the
        undo did not take effect -- re-running it is the caller's decision.
        """
        ws_name = _safe_name(workspace)
        root = _workspaces_root()
        parent = root / ".sf-checkpoints"
        store = parent / ws_name
        # recover() cannot go through _ckpt_store(): the workspace may not
        # exist right now, which is exactly the state it is here to repair. The
        # symlink refusal that helper applies is repeated rather than skipped.
        if parent.is_symlink() or store.is_symlink():
            raise _ToolError("checkpoint storage cannot be a symbolic link")
        if not store.is_dir():
            raise _ToolError(f"no checkpoint store for workspace: {ws_name}")
        with _CkptLock(store):
            record = _ckpt_journal_read(store)
            if record is None:
                # Nothing to repair -- an undo that died before the exchange
                # never touched the workspace -- but its staging may still be
                # on disk, and this is where an operator asks about it.
                _ckpt_reap(store, root / ws_name)
                return {"action": "recover", "workspace": ws_name,
                        "result": "nothing-to-recover", "checkpoint": None,
                        "safety": None,
                        "detail": "no interrupted undo; the workspace was not "
                                  "changed by one"}
            if record.get("phase") == "unreadable":
                raise _ToolError(
                    f"RECOVERY REQUIRED: workspace '{ws_name}' has an "
                    "unreadable undo journal; inspect "
                    f"{_ckpt_journal_path(store)} by hand")
            ws = root / ws_name
            stage = Path(record["stage"]) if record.get("stage") else None
            displaced = Path(record["displaced"]) if record.get("displaced") else None
            # The journal is ours and lives in a 0700 directory, but its id
            # still reaches the filesystem, so it is validated like any other.
            cid = _safe_name(record.get("checkpoint") or "")
            entries = _ckpt_entries_read(store)
            if entries is None:
                raise _ToolError(
                    f"RECOVERY REQUIRED: workspace '{ws_name}' has an "
                    f"interrupted undo of checkpoint {cid} but no record of "
                    "what that checkpoint contains, so whether the undo took "
                    "effect cannot be established. Inspect "
                    f"{record.get('stage')} and {record.get('displaced')} by "
                    f"hand; the pre-undo state is checkpoint "
                    f"{record.get('safety')}.")
            if not ws.exists():
                # The two-rename window: the workspace name does not exist.
                # Whichever tree is present is put back under it.
                if stage is not None and stage.is_dir():
                    os.rename(stage, ws)
                elif displaced is not None and displaced.is_dir():
                    os.rename(displaced, ws)
                else:
                    raise _ToolError(
                        f"RECOVERY REQUIRED: workspace '{ws_name}' is absent "
                        "and neither half of the interrupted undo is on disk. "
                        f"The pre-undo state is checkpoint {record.get('safety')}.")
            if not _ckpt_verify(ws, entries):
                # The exchange happened: the workspace IS the checkpoint.
                for leftover in (stage, displaced):
                    if leftover is not None and leftover != ws and leftover.exists():
                        _ckpt_rmtree(leftover)
                _ckpt_journal_clear(store)
                return {"action": "recover", "workspace": ws_name,
                        "result": "completed", "checkpoint": cid,
                        "safety": record.get("safety"),
                        "detail": f"workspace matches checkpoint {cid}"}
            # The workspace is not the checkpoint, so the exchange did not
            # happen. Roll the attempt back rather than finishing an undo the
            # operator never saw succeed.
            if stage is not None and stage != ws and stage.exists():
                _ckpt_rmtree(stage)
            if displaced is not None and displaced != ws and displaced.exists():
                _ckpt_rmtree(displaced)
            _ckpt_journal_clear(store)
            return {"action": "recover", "workspace": ws_name,
                    "result": "rolled-back", "checkpoint": cid,
                    "safety": record.get("safety"),
                    "detail": ("the undo did not take effect; the workspace is "
                               "as it was before it was attempted")}

    # -- internals ---------------------------------------------------------- #
    def _meta(self, store: Path, checkpoint: str) -> tuple[str, dict]:
        cid = _safe_name(checkpoint)
        meta_p = store / f"{cid}.json"
        if not meta_p.exists():
            raise _ToolError(f"no such checkpoint: {cid}")
        return cid, json.loads(meta_p.read_text())

    def _snapshot(self, ws: Path, label: str, protect: set[str] | None = None) -> dict:
        store = _ckpt_store(ws)
        _ckpt_reap(store, ws)
        # Refusals (unreadable directory, device node) happen here, before
        # anything is written: a snapshot either exists and can restore the
        # tree, or it does not exist.
        entries, payload = _ckpt_scan(ws)
        digest = _ckpt_manifest_digest(entries)
        cid = _new_checkpoint_id(store)
        meta = {"id": cid, "label": label, "workspace": ws.name, "created": cid,
                "method": None, "tree_digest": digest, "payload_bytes": payload,
                "entries": len(entries)}
        manifest_path = _ckpt_manifest_path(store, cid)
        manifest_written = False
        snapdir = store / cid
        if _fstype(ws) == "btrfs":
            tool = _trusted_tool(_TRUSTED_BTRFS)
            if tool and _run([tool, "subvolume", "snapshot", "-r", str(ws),
                              str(snapdir)]).returncode == 0:
                # Believe the filesystem, not the exit code. A btrfs subvolume
                # root has inode 256; anything else means the "btrfs" method
                # would be a claim this checkpoint cannot honour.
                try:
                    st = os.lstat(snapdir)
                    real = ((st.st_mode & _S_IFMT) == _S_IFDIR
                            and st.st_ino == _BTRFS_SUBVOL_INO)
                except OSError:
                    real = False
                if real:
                    meta["method"] = "btrfs"
                else:
                    _ckpt_rmtree(snapdir)
        if meta["method"] is None:
            twin = _ckpt_twin(store, digest)
            archive = store / f"{cid}.tar.gz"
            if twin is not None:
                # Deduplication: the same tree, byte for byte, is already
                # archived. One inode, two names -- and unlinking either name
                # on prune leaves the other intact.
                os.link(store / _safe_name(twin[1]["archive"]), archive)
                meta["deduplicates"] = twin[0]
                try:
                    os.link(_ckpt_manifest_path(store, twin[0]), manifest_path)
                    manifest_written = True
                except OSError:
                    manifest_written = False
            else:
                _ckpt_require_space(store, payload, f"archive workspace '{ws.name}'")
                part = store / f"{cid}.tar.gz.part"
                try:
                    with tarfile.open(part, "w:gz") as archive_file:
                        archive_file.add(ws, arcname=ws.name, filter=_no_ckpt_dir(ws))
                    os.replace(part, archive)
                except BaseException:
                    # A half-written archive must never become a checkpoint.
                    part.unlink(missing_ok=True)
                    raise
            meta["method"] = "tar"
            meta["archive"] = archive.name
        if not manifest_written:
            _ckpt_atomic_write(manifest_path,
                               json.dumps(entries, separators=(",", ":")).encode())
        # The metadata file is what makes a checkpoint EXIST -- list() globs it
        # -- so it is written last, atomically, and fsynced. An interrupted
        # snapshot leaves debris the reaper collects, never a checkpoint that
        # lists but cannot restore.
        _ckpt_atomic_write(store / f"{cid}.json",
                           json.dumps(meta, indent=2).encode())
        _ckpt_prune(store, protect={cid} | set(protect or ()))
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
               "Snapshot and inspect changes inside ONE agent workspace under "
               "~/Workspaces. snapshot() WRITES a snapshot copy and touches only "
               "the named workspace. undo() restores a workspace and DISCARDS "
               "everything since the checkpoint, so it is not offered to agents "
               "unless an operator enabled destructive tools for this server; a "
               "person undoes with `shadowfetch-checkpoint undo`. Every call here "
               "is recorded.")
    engine = CheckpointEngine()

    @s.tool("snapshot",
            "WRITES: take a restore point of the named workspace before an agent "
            "runs. Returns a checkpoint id. Btrfs snapshot when possible, else a "
            "compressed archive. Touches only ~/Workspaces/<name>.",
            {"type": "object", "required": ["workspace"], "properties": {
                "workspace": {"type": "string", "description": "workspace name under ~/Workspaces"},
                "label": {"type": "string", "description": "optional human label"}}},
            MUTATING)
    def snapshot(args):
        return format_snapshot(engine.snapshot(args["workspace"], args.get("label", "manual")))

    @s.tool("list",
            "List checkpoints for a workspace (read-only).",
            {"type": "object", "required": ["workspace"], "properties": {
                "workspace": {"type": "string"}}}, READ_ONLY)
    def _list(args):
        return format_list(engine.list(args["workspace"]))

    @s.tool("diff",
            "Show which files changed in the workspace since a checkpoint "
            "(read-only): what the agent touched.",
            {"type": "object", "required": ["workspace", "checkpoint"], "properties": {
                "workspace": {"type": "string"}, "checkpoint": {"type": "string"}}},
            READ_ONLY)
    def diff(args):
        return format_diff(engine.diff(args["workspace"], args["checkpoint"]))

    @s.tool("undo",
            "WRITES: restore the workspace to a checkpoint, reversing everything "
            "changed since (the agent's work is discarded). Touches only "
            "~/Workspaces/<name>. A safety snapshot of the current state is taken "
            "first.",
            {"type": "object", "required": ["workspace", "checkpoint"], "properties": {
                "workspace": {"type": "string"}, "checkpoint": {"type": "string"}}},
            DESTRUCTIVE)
    def undo(args):
        return format_undo(engine.undo(args["workspace"], args["checkpoint"]))

    return s


def _restore_tree(store: Path, meta: dict) -> Path:
    """Materialize a checkpoint into a temp dir; return the workspace-root path."""
    if meta["method"] == "btrfs":
        return store / meta["id"]
    tmp = store / f".tmp-{meta['id']}"
    if tmp.exists():
        _ckpt_rmtree(tmp)
    tmp.mkdir(parents=True)
    try:
        return _extract_tree(tmp, store, meta)
    except BaseException:
        # The directory is created before anything can fail inside it, and the
        # callers' cleanup keys off a path this function never returned on the
        # failure path. So it cleans up after itself.
        _ckpt_rmtree(tmp)
        raise


def _extract_tree(tmp: Path, store: Path, meta: dict) -> Path:
    # Restore archive members without following links or allowing traversal.
    # Links are created LAST, so no later member can write through them.
    if _safe_name(meta["workspace"]) != store.name:
        raise _ToolError("checkpoint workspace metadata mismatch")
    archive = _safe_name(meta["archive"])
    with tarfile.open(store / archive, "r:gz") as tf:
        members = tf.getmembers()
        links = []
        names = set()
        # Directory modes are applied at the END, deepest first. Applying them
        # inline made a 0o500 directory in the checkpoint -- an ordinary thing
        # for a workspace to contain -- fail with EACCES on its own children,
        # and in undo() that failure landed after the live workspace had
        # already been deleted.
        modes = []
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
                modes.append((destination, item.mode & 0o777))
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
        for destination, mode in sorted(modes, key=lambda pair: len(pair[0].parts),
                                        reverse=True):
            destination.chmod(mode)
    return tmp / meta["workspace"]


def _cleanup_tmp(base: Path, meta: dict):
    if meta["method"] == "tar":
        root = base.parent
        if root.name.startswith(".tmp-"):
            # _ckpt_rmtree, not shutil: a 0o500 directory in the tree
            # made ignore_errors=True leave the whole copy behind.
            _ckpt_rmtree(root)


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
            {"type": "object", "properties": {"path": {"type": "string", "description": "relative path (default '.')"}}},
            READ_ONLY)
    def list_dir(args):
        p = _resolve(args.get("path", "."))
        if not p.is_dir():
            raise _ToolError("not a directory")
        rows = []
        for c in sorted(p.iterdir()):
            rows.append(("d " if c.is_dir() else "f ") + c.name)
        return "\n".join(rows) or "(empty)"

    @s.tool("read_file", "Read a UTF-8 text file within the scoped root (read-only, capped at 200 KB).",
            {"type": "object", "required": ["path"], "properties": {"path": {"type": "string"}}},
            READ_ONLY)
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
            "  checkpoint writes only inside the named ~/Workspaces workspace.\n"
            "  Calls that CHANGE something are recorded in the audit log, or\n"
            "  refused. Reads proceed even when the log is unwritable, and say\n"
            "  so on stderr.\n"
            "    log:      " + str(_audit_root() / AUDIT_DIRNAME / AUDIT_FILENAME) + "\n"
            "    relocate: $" + MCP_STATE_ENV + "\n"
            "    verify:   shadowfetch-mcp audit verify\n"
            "  Destructive tools are withheld unless "
            + DESTRUCTIVE_ENV + "=" + DESTRUCTIVE_ALLOW + "\n"
            "  and " + CORRELATION_ENV[0] + " names a recorded Firebreak session.\n")
        return 0 if (len(argv) > 1 and argv[1] in ("-h", "--help")) else 2
    if argv[1] == "--audit":
        # The chain is only an audit trail if a person can read it. Before this
        # verify_audit() and audit_state() had no caller outside their own
        # tests, which makes them a data structure with test coverage.
        state = audit_state()
        if len(argv) > 2 and argv[2] == "verify":
            report = verify_audit()
            print(json.dumps({"state": state, "verification": report},
                             indent=2, sort_keys=True))
            return 0 if report.get("ok") else 1
        print(json.dumps(state, indent=2, sort_keys=True))
        return 0 if state.get("available") else 2
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
