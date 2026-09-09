#!/usr/bin/env python3
"""Phase 3 attacks 12-18: a mission's lifecycle under interruption.

Seven attacks, each against a THROWAWAY store, run as a module the lead can
compose:

    12  malformed-tool-events            provider output carrying broken tool events
    13  duplicate-tool-events            the same tool event twice
    14  kill-mission-control             SIGKILL the orchestrator mid-execution
    15  kill-provider-mid-session        SIGKILL the provider process mid-session
    16  cancel-completion-race           Stop pressed as execution finishes
    17  worker-restart-stale-running     a worker starts on a RUNNING row nobody owns
    18  mcp-destructive-no-correlation   checkpoint.undo without a correlated session

14, 15 and 17 use real sandboxed processes and real signals: a mocked exception
proves the orchestrator's own except clause runs, which is not the question.
The question is what happens to somebody else's process, so the fixture is a
genuine ffmpeg encode that takes long enough to be interrupted in the middle.

VERDICTS.  PASS means the system refused the action or contained it -- and that
it CHANGED NOTHING it should not have, which is checked by reading rows back,
counting events and verifying the hash chain, not by observing that something
raised.  An action the system cannot prevent is recorded as a finding with
"the action itself was not prevented" said in those words.

WHAT THIS TOUCHES.  Every attack builds its own tempfile.mkdtemp() world and
points SHADOWFETCH_AGENT_WORKSPACES / _MISSIONS_STATE / _FIREBREAK_STATE /
_MCP_STATE at it, so the operator's ~/.local/state is never written.  Two
things do reach outside that world, because the engine works that way and
suppressing them would be measuring a different program:
  * Store.mirror() sends each event head to /dev/log, so the run leaves
    `shadowfetch-audit` lines in the system journal under throwaway chain ids.
  * Firebreak starts a transient systemd --user scope per sandboxed process.
Both are cleaned up by the kernel or by systemd --collect; the module also
kills anything still holding the lab root open before it deletes it.

TWO TRAPS THIS FILE WORKS AROUND, both of which silently test the WRONG code:
  * PATH: `shadowfetch-firebreak` resolves through PATH, so the source-tree
    bin directory is prepended for every child.  Without it the installed
    3.0.0 Firebreak answers and rejects 4.0.0's flags.
  * The source-tree `shadowfetch-mcp` wrapper prefers
    /usr/lib/shadowfetch/mcp/sf_mcp.py when that file exists, so on a host with
    fireline 3.0.0 installed it drives the 3.0.0 engine.  Attack 18 therefore
    executes the 4.0.0 implementation file directly.

Standalone:  python3 tools/attacks/attack_lifecycle.py [attack-name ...]
Exit status is non-zero if any attack FAILED (a SKIPPED attack does not fail
the run; a harness error does, and says so in its first words).
"""
from __future__ import annotations

import atexit
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from pathlib import Path

ATTACKS = (
    "malformed-tool-events",
    "duplicate-tool-events",
    "kill-mission-control",
    "kill-provider-mid-session",
    "cancel-completion-race",
    "worker-restart-stale-running",
    "mcp-destructive-no-correlation",
)

REPO = Path(__file__).resolve().parents[2]
MISSIONS_PKG = REPO / "packages/shadowfetch-missions"
FIRELINE_PKG = REPO / "packages/shadowfetch-fireline"
ENGINE = MISSIONS_PKG / "data/usr/lib/shadowfetch/missions"
MISSIONS_CLI = MISSIONS_PKG / "data/usr/bin/shadowfetch-missions"
PROVIDER_MANIFESTS = MISSIONS_PKG / "data/usr/share/shadowfetch/providers"
FIREBREAK_BIN = FIRELINE_PKG / "data/usr/bin"
CHECKPOINT_CLI = FIREBREAK_BIN / "shadowfetch-checkpoint"
# The implementation, not the wrapper: see the trap note in the docstring.
MCP_IMPL = FIRELINE_PKG / "data/usr/lib/shadowfetch/mcp/sf_mcp.py"

sys.path.insert(0, str(ENGINE))
import sf_missions as sf                      # noqa: E402
import sf_providers as sfp                    # noqa: E402
import sf_provider_codex as sfp_codex         # noqa: E402

KEEP = bool(os.environ.get("SHADOWFETCH_ATTACK_KEEP"))
SANDBOX_TOOLS = ("bwrap", "systemd-run", "ffmpeg", "ffprobe")


# --------------------------------------------------------------------------- #
# The throwaway world
# --------------------------------------------------------------------------- #
class Lab:
    """One attack's world: its own workspaces, state, Firebreak and MCP roots.

    The environment is applied to os.environ for the duration, not only handed
    to children, because the engine reads it in-process too -- Store.__init__,
    workspace(), and the checkpoint engine all consult it -- and a lab that
    only covered subprocesses would write half its state into the operator's
    real directories.
    """

    def __init__(self, name):
        self.root = Path(tempfile.mkdtemp(prefix="sf-attack-" + name + "-"))
        self.ws = self.root / "ws"
        self.state = self.root / "state"
        self.fb = self.root / "fb"
        self.mcp = self.root / "mcp"
        for directory in (self.ws, self.state, self.fb, self.mcp):
            directory.mkdir(parents=True)
        self.workspace = self.ws / "proj"
        self.workspace.mkdir()
        self.env = dict(os.environ)
        self.env.update(
            SHADOWFETCH_AGENT_WORKSPACES=str(self.ws),
            SHADOWFETCH_MISSIONS_STATE=str(self.state),
            SHADOWFETCH_FIREBREAK_STATE=str(self.fb),
            SHADOWFETCH_MCP_STATE=str(self.mcp),
        )
        self.env["PATH"] = str(FIREBREAK_BIN) + os.pathsep + self.env.get("PATH", "")
        self._saved = {}

    def __enter__(self):
        for key in ("SHADOWFETCH_AGENT_WORKSPACES", "SHADOWFETCH_MISSIONS_STATE",
                    "SHADOWFETCH_FIREBREAK_STATE", "SHADOWFETCH_MCP_STATE", "PATH"):
            self._saved[key] = os.environ.get(key)
            os.environ[key] = self.env[key]
        return self

    def __exit__(self, *exc):
        for key, value in self._saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        # Anything still holding the lab open would keep writing into a
        # directory about to be deleted, and an orphan encode outliving its
        # own attack would corrupt the NEXT one's process census.
        for pid, _cmd in processes_under(self.root):
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
        if not KEEP:
            shutil.rmtree(self.root, ignore_errors=True)
        return False

    def store(self):
        return sf.Store()

    def create(self, *, title, inputs):
        return self.store().create(capability="media_export",
                                   provider_id="offline-media",
                                   workspace_value=self.workspace.name,
                                   title=title, prompt="attack", inputs=list(inputs))["id"]

    def cli(self, *args, timeout=300):
        return subprocess.run([sys.executable, str(MISSIONS_CLI), *args],
                              env=self.env, capture_output=True, text=True,
                              timeout=timeout)

    def spawn_run(self, mid):
        """Mission Control, as its own process, so it can be killed for real."""
        return subprocess.Popen([sys.executable, str(MISSIONS_CLI), "run", mid],
                                env=self.env, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True)


_FIXTURES = {}
_FIXTURE_ROOT = None


def fixture_root():
    """One directory per process for the generated media, removed on the way out.

    The fixtures outlive every individual Lab -- they are what each Lab copies
    from -- so they cannot be cleaned up by a Lab's __exit__, and a 24 MB
    render left in /tmp on every run is a leak the module would be responsible
    for.
    """
    global _FIXTURE_ROOT
    if _FIXTURE_ROOT is None:
        _FIXTURE_ROOT = Path(tempfile.mkdtemp(prefix="sf-attack-fixtures-"))
        if not KEEP:
            atexit.register(shutil.rmtree, _FIXTURE_ROOT, True)
    return _FIXTURE_ROOT


def media_fixture(kind):
    """A real media file, generated once per process and copied per lab.

    'heavy' is a mandelbrot render: an ffmpeg encode of it takes long enough
    (tens of seconds at the provider's -threads 2) that a kill lands in the
    middle of real work rather than in start-up.  'light' finishes in about a
    second, which is what the completion race needs.
    """
    if kind in _FIXTURES:
        return _FIXTURES[kind]
    root = fixture_root()
    if kind == "heavy":
        path = root / "heavy.mp4"
        argv = ["ffmpeg", "-v", "error", "-y", "-f", "lavfi",
                "-i", "mandelbrot=size=800x600:rate=25", "-t", "24",
                "-c:v", "libx264", "-preset", "ultrafast", "-pix_fmt", "yuv420p",
                str(path)]
    else:
        path = root / "light.wav"
        argv = ["ffmpeg", "-v", "error", "-y", "-f", "lavfi",
                "-i", "sine=frequency=440:duration=2", "-c:a", "pcm_s16le", str(path)]
    subprocess.run(argv, check=True, capture_output=True, timeout=300)
    _FIXTURES[kind] = path
    return path


def place(lab, kind):
    source = media_fixture(kind)
    target = lab.workspace / source.name
    shutil.copyfile(source, target)
    return target.name


def processes_under(root):
    """Every live process whose argv still mentions this lab's root.

    The census is what distinguishes "the orchestrator stopped" from "the
    sandbox stopped": the provider runs in its own session and process group,
    so its survival is a fact about the system, not about our except clauses.
    """
    found = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            raw = (entry / "cmdline").read_bytes()
        except OSError:
            continue
        command = raw.decode("utf-8", "replace").replace("\x00", " ").strip()
        if command and str(root) in command:
            found.append((int(entry.name), command))
    return found


def wait_for(predicate, timeout, interval=0.02):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(interval)
    return None


def wait_for_event(store, mid, event, detail_prefix="", timeout=120):
    def seen():
        return [row for row in store.events(mid)
                if row["event"] == event and row["detail"].startswith(detail_prefix)]
    return wait_for(seen, timeout)


def chain_summary(store):
    report = store.verify_chain()
    return {"ok": report["ok"], "chained": report["chained"],
            "unchained": report["unchained"], "problems": report["problems"],
            "anchor": (report.get("anchor") or {}).get("verdict")}


def missing_sandbox_tools():
    return [name for name in SANDBOX_TOOLS if shutil.which(name) is None]


def lines(*parts):
    return "\n".join(str(part) for part in parts)


# --------------------------------------------------------------------------- #
# 12 and 13: the ToolExecution path
# --------------------------------------------------------------------------- #
def tool_execution_path():
    """What of the ToolExecution path exists RIGHT NOW, with the evidence.

    Step 7 is being written while this module runs, so the answer is looked up
    every time rather than baked in.  Three separate questions, because they
    have three different answers today:

      store      Store.record_tool_execution / Store.tool_executions
      producer   anything that CALLS record_tool_execution -- the ingestion
                 path from a provider stream into a row
      surface    an AgentEvent type or a CLI verb a person could reach it by
    """
    store_api = sorted(name for name in ("record_tool_execution", "tool_executions")
                       if hasattr(sf.Store, name))
    producers = []
    for path in sorted(ENGINE.glob("*.py")) + [MISSIONS_CLI]:
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        for number, line in enumerate(text.splitlines(), 1):
            if "record_tool_execution" not in line:
                continue
            stripped = line.strip()
            # The definition is not a caller. Everything else that names it is.
            if stripped.startswith("def record_tool_execution"):
                continue
            producers.append(f"{path.name}:{number}: {stripped[:110]}")
    event_types = sorted(value for key, value in vars(sfp.AgentEvent).items()
                         if isinstance(value, str) and key.isupper() and "tool" in value.lower())
    cli_verbs = re.findall(r'add_parser\("([^"]*tool[^"]*)"',
                           (ENGINE / "sf_missions.py").read_text(encoding="utf-8"))
    return {"store_api": store_api, "producers": producers,
            "agent_event_tool_types": event_types, "cli_verbs": cli_verbs}


def codex_provider():
    """The shipped Codex adapter, instantiated from its shipped manifest.

    Codex is unauthenticated on this host, so no turn can be run -- but
    parse_stream() is pure and is the only code in the tree that interprets a
    JSONL turn stream, which is where a malformed or duplicated tool event
    arrives.  Attacking it needs no credentials.
    """
    manifest = sfp.load_manifest(PROVIDER_MANIFESTS / "codex.json")
    return sfp_codex.CodexCliProvider(manifest, sfp.sandbox_from_manifest(manifest))


def probe_malformed_stream():
    """Feed the one existing stream interpreter malformed tool events."""
    provider = codex_provider()
    stream = "\n".join([
        json.dumps({"type": "item.completed",
                    "item": {"type": "command_execution", "command": "rm -rf /",
                             "status": "completed"}}),
        json.dumps({"type": "item.completed", "item": None}),
        json.dumps({"type": "item.completed", "item": "not-an-object"}),
        json.dumps({"type": "item.completed", "item": ["a", "b"]}),
        json.dumps({"type": "item.completed"}),
        '{"type": "item.completed", "item": {"type": "comm',      # truncated write
        "[1,2,3]",
        "null",
        json.dumps({"type": None}),
        json.dumps({"type": "item.completed",
                    "item": {"type": "file_change",
                             "changes": [{"path": "/etc/passwd"}]}}),
        "Firebreak session fb-1 ended (exit 0)",                  # sandbox trailer
        json.dumps({"type": "turn.completed", "usage": {"input_tokens": 1}}),
    ])
    result = {}
    try:
        events = provider.parse_stream(stream)
    except Exception as exc:                                      # noqa: BLE001
        result["raised"] = f"{type(exc).__name__}: {exc}"
        return result
    result["raised"] = None
    result["event_types"] = [event.type for event in events]
    result["fabricated_message"] = provider.final_message(events)
    result["turn_succeeded"] = provider.turn_succeeded(events)
    forged = provider.parse_stream(json.dumps({"type": "turn.completed", "usage": None}))
    result["forged_completion_alone_succeeds"] = provider.turn_succeeded(forged)
    both = provider.parse_stream(lines(json.dumps({"type": "turn.completed"}),
                                       json.dumps({"type": "turn.failed",
                                                   "message": "boom"})))
    result["completed_plus_failed_succeeds"] = provider.turn_succeeded(both)
    return result


def probe_duplicate_stream():
    provider = codex_provider()
    one = json.dumps({"type": "item.completed",
                      "item": {"id": "tool-1", "type": "command_execution",
                               "command": "echo one"}})
    stream = lines(one, one, one,
                   json.dumps({"type": "turn.completed",
                               "usage": {"input_tokens": 10, "output_tokens": 5}}),
                   json.dumps({"type": "turn.completed",
                               "usage": {"input_tokens": 999, "output_tokens": 999}}))
    events = provider.parse_stream(stream)
    return {"event_types": [event.type for event in events],
            "turn_succeeded": provider.turn_succeeded(events),
            "usage": provider.usage(events)}


class Unserialisable:
    """An argument value no JSON encoder can take, because a provider can send one."""

    def __repr__(self):
        return "<unserialisable>"


# Built at runtime, never written as a literal. A probe value that LOOKS like
# a real key is exactly what a secret scanner is built to stop, and a test
# suite is not a good reason to teach the repo to ignore that shape.
SECRET = "sk-" + "attack" + "A" * 4 + "".join(str(n % 10) for n in range(16))


def malformed_tool_events():
    """AgentEvents a hostile or broken adapter could hand the orchestrator.

    Built in the engine's OWN vocabulary (sf_providers.AgentEvent with a "tool"
    key in data), which is what tool_records() reads, so this is the shape the
    ingestion path consumes rather than a shape this module invented. Every
    field is wrong in a different way.
    """
    event = sfp.AgentEvent
    return [
        event(event.PROGRESS, "", {"tool": "shell", "action": "rm -rf /",
                                   "args": {"cmd": "rm -rf /"}}),
        event(event.PROGRESS, "", {"tool": 123}),                     # not a string
        event(event.PROGRESS, "", {"tool": ""}),                      # empty
        event(event.PROGRESS, "", {"tool": None}),
        event(event.PROGRESS, "", {"tool": "x" * 5000, "action": "y" * 5000}),
        event(event.PROGRESS, "", {"tool": "weird", "args": Unserialisable(),
                                   "exit_status": Unserialisable(),
                                   "bytes_changed": "abc", "files_changed": None,
                                   "started_at": Unserialisable(), "ended_at": {"a": 1}}),
        event(event.PROGRESS, "", {"tool": "nul\x00byte", "action": "a\x00b"}),
        event(event.PROGRESS, "", {"tool": "curl " + SECRET,
                                   "action": "POST with " + SECRET,
                                   "args": {"header": SECRET}}),
        event(event.LOG, "a log line with no tool key at all"),
        event(event.PROGRESS, "", {"item": {"type": "command_execution",
                                            "command": "rm -rf /"}}),
        event(event.TURN_COMPLETE, "", {"usage": None}),
    ]


def bound_executor(lab):
    """A real Executor on a real mission, with a real session in scope.

    Nothing is mocked: the mission ran, the session row is the one the engine
    wrote, and record_tool_activity() is the production ingestion. Only the
    events are supplied here -- which is exactly the boundary a provider
    adapter sits on.
    """
    name = place(lab, "light")
    mid = lab.create(title="tool-event ingestion", inputs=[name])
    store = lab.store()
    state = "not run"
    try:
        state = sf.run_mission(store, mid)["state"]
    except Exception as exc:                                      # noqa: BLE001
        state = f"run failed: {exc}"
    sessions = store.sessions(mid)
    executor = sf.Executor(store, store.get(mid))
    executor.session_id = sessions[-1]["id"] if sessions else None
    return store, mid, executor, state, [s["id"] for s in sessions]


def attack_malformed_tool_events(report):
    name = "malformed-tool-events"
    expected = ("Provider output carrying broken tool events -- a tool name that is not a "
                "string, arguments nothing can serialise, a NUL byte, a credential in the "
                "action text, a truncated JSON write -- reaches the ToolExecution path: "
                "nothing is fabricated from an event that reported no tool, nothing "
                "unredacted is stored, the mission is not lost over its own description, "
                "and the chain still verifies.")
    path = tool_execution_path()
    stream = probe_malformed_stream()
    if not path["producers"]:
        report(name, expected, lines(
            "DETECTION:",
            "  Store API present:   " + (", ".join(path["store_api"]) or "none"),
            "  producers (callers): NONE FOUND",
            "  AgentEvent tool types: " + (", ".join(path["agent_event_tool_types"]) or "NONE"),
            "  CLI verbs naming a tool: " + (", ".join(path["cli_verbs"]) or "NONE"),
            "",
            "parse_stream on 12 malformed tool-event lines: raised="
            + repr(stream["raised"]) + " fabricated_message="
            + repr(stream.get("fabricated_message"))), None,
            "SKIPPED, not passed: nothing calls record_tool_execution, so no provider "
            "stream can reach a tool_executions row and there is nothing to attack yet. "
            "Re-run after Step 7.")
        return

    events = malformed_tool_events()
    with Lab("tool12") as lab:
        store, mid, executor, mission_state, _sessions = bound_executor(lab)
        shipped_rows = len(store.tool_executions(mission_id=mid))
        extracted = sf.tool_records(events)
        before = len(store.events(mid))
        raised = None
        try:
            stored = executor.record_tool_activity(events)
        except Exception as exc:                                  # noqa: BLE001
            raised, stored = f"{type(exc).__name__}: {exc}", None
        rows = store.tool_executions(session_id=executor.session_id)
        new_events = store.events(mid)[before:]
        details = [entry["detail"] for entry in new_events]
        leaked_columns = [(row["seq"], field) for row in rows for field in
                          ("tool", "requested_action")
                          if isinstance(row[field], str) and SECRET in row[field]]
        leaked_chain = [detail for detail in details if SECRET in detail]
        control_characters = [(row["seq"], repr(row["tool"])) for row in rows
                              if isinstance(row["tool"], str)
                              and any(ord(ch) < 32 for ch in row["tool"])]
        after_state = store.get(mid)["state"]
        chain = chain_summary(store)

    observed = lines(
        "DETECTION (re-read every run; this path landed while the module was being written):",
        "  Store API:               " + ", ".join(path["store_api"]),
        "  producers (callers):     " + "; ".join(path["producers"]),
        "  AgentEvent tool types:   " + (", ".join(path["agent_event_tool_types"]) or "NONE"),
        "  CLI verbs naming a tool: " + (", ".join(path["cli_verbs"]) or "NONE"),
        f"  rows a real offline-media mission produced: {shipped_rows}",
        "",
        "parse_stream fed 12 malformed tool-event lines (the normalizer upstream):",
        "  raised:                       " + repr(stream["raised"]),
        "  normalized types:             " + ", ".join(stream.get("event_types", [])),
        "  message fabricated from junk: " + repr(stream.get("fabricated_message")),
        "  a lone forged turn.completed: turn_succeeded="
        + repr(stream.get("forged_completion_alone_succeeds")),
        "  completed + failed together:  turn_succeeded="
        + repr(stream.get("completed_plus_failed_succeeds")),
        "",
        f"{len(events)} malformed AgentEvents through tool_records() + "
        "Executor.record_tool_activity():",
        f"  tool_records extracted:  {len(extracted)} of {len(events)}",
        f"  record_tool_activity:    raised={raised!r} stored={stored!r}",
        f"  rows written:            {len(rows)}",
        *[f"    seq={row['seq']} tool={row['tool']!r:.70} action={row['requested_action']!r:.60} "
          f"digest={str(row['args_digest'])[:8]} bytes_changed={row['bytes_changed']!r} "
          f"exit_status={row['exit_status']!r}" for row in rows],
        f"  events appended:         {[entry['event'] for entry in new_events]}",
        f"  credential visible in a stored COLUMN: {leaked_columns}",
        f"  credential visible in the audit chain detail: {leaked_chain}",
        f"  NUL / control characters kept in a stored tool name: {control_characters}",
        f"  mission state after the malformed ingestion: {after_state!r} "
        f"(it was {mission_state!r})",
        f"  chain: {json.dumps(chain)}",
    )

    contained = (raised is None and stream["raised"] is None
                 and not stream.get("fabricated_message")
                 and stream.get("completed_plus_failed_succeeds") is False
                 and len(rows) == len(extracted)
                 and after_state == mission_state
                 and chain["ok"] and not chain["problems"]
                 and not leaked_columns and not leaked_chain)
    if contained:
        report(name, expected, observed, True,
               "Malformed tool events were contained: events reporting no tool produced no "
               "row, nothing raised, the mission was not lost over its own description and "
               "the chain verifies.")
        return
    report(name, expected, observed, False, lines(
        "Mostly contained, and one real leak. Held: tool_records() drops every event whose "
        "data carries no string 'tool' key (it refuses to guess structure out of prose), "
        "record_tool_activity() is non-fatal by construction, unserialisable arguments "
        "degrade to a digest of None rather than an exception, the mission finished, and "
        "the chain verifies.",
        "NOT CONTAINED: `tool` and `requested_action` are provider-controlled text stored "
        f"verbatim -- {leaked_columns} -- while the neighbouring `args_redacted` in the same "
        "record IS scrubbed, and its docstring gives the reason ('provider-supplied and go "
        "to a record that outlives the run'). The audit chain detail is redacted on the way "
        "through Store.event(), so the leak is in the tool_executions row rather than the "
        "chain, but that row is the durable description of what an agent did and a reviewer "
        "reads it. tool_records() should put the same clean() over tool and action that "
        "_redact_tool_args puts over args.",
        f"Also observed, smaller: a NUL byte survives into the stored tool name "
        f"{control_characters} and into the event detail, so provider-controlled control "
        "characters reach a terminal that prints either.",
        "Separately, and not a defect in this code: NO shipped provider emits data['tool'] "
        f"-- a real offline-media mission produced {shipped_rows} rows -- so the ingestion "
        "is DECLARED and provider-neutral but nothing that ships exercises it. The events "
        "above are the shape it consumes, supplied directly."))


def attack_duplicate_tool_events(report):
    name = "duplicate-tool-events"
    expected = ("A tool event delivered more than once -- the same stream ingested twice "
                "after an interruption, or a line repeated inside one stream -- does not "
                "produce a second record of the same execution, is not raised as an error, "
                "and leaves the chain intact.")
    path = tool_execution_path()
    stream = probe_duplicate_stream()
    if not path["producers"]:
        report(name, expected,
               "DETECTION: producers (callers of record_tool_execution): NONE FOUND", None,
               "SKIPPED, not passed: no ingestion path, so a duplicated provider event "
               "cannot reach a row. Re-run after Step 7.")
        return

    event = sfp.AgentEvent
    once = event(event.PROGRESS, "", {"tool": "shell", "action": "echo one",
                                      "args": {"cmd": "echo one"}})
    with Lab("tool13") as lab:
        store, mid, executor, _state, sessions = bound_executor(lab)
        first_session = executor.session_id
        # (a) the same stream ingested twice into the same session: the case a
        #     crash between recording and the next step would produce.
        first_pass = executor.record_tool_activity([once, once, once])
        rows_after_first = len(store.tool_executions(session_id=first_session))
        events_before = len(store.events(mid))
        second_pass = executor.record_tool_activity([once, once, once])
        rows_after_second = store.tool_executions(session_id=first_session)
        events_after = store.events(mid)[events_before:]
        # (b) the same event repeated inside ONE stream, into a session that
        #     has recorded nothing yet.
        if len(sessions) > 1:
            executor.session_id = sessions[0]
            in_stream = executor.record_tool_activity([once, once, once])
            in_stream_rows = store.tool_executions(session_id=sessions[0])
        else:
            in_stream, in_stream_rows = None, []
        chain = chain_summary(store)

    observed = lines(
        "DETECTION:",
        "  producers: " + "; ".join(path["producers"]),
        "",
        "upstream, in the normalizer: the same tool event three times plus two "
        "turn.completed lines through parse_stream:",
        "  events: " + ", ".join(stream["event_types"]),
        "  usage reported: " + json.dumps(stream["usage"])
        + "  (the LAST turn.completed wins, so a duplicated completion silently overrides "
          "the real figures)",
        "",
        "(a) the SAME stream ingested twice into the same session:",
        f"    first ingestion stored:  {first_pass}   rows: {rows_after_first}",
        f"    second ingestion stored: {second_pass}   rows now: {len(rows_after_second)}",
        f"    events appended by the replay: {[entry['event'] for entry in events_after]}",
        "",
        "(b) the same event repeated three times inside ONE stream:",
        f"    stored: {in_stream}",
        f"    rows: {[(row['seq'], row['tool'], row['requested_action'], (row['args_digest'] or '')[:8]) for row in in_stream_rows]}",
        "",
        f"chain: {json.dumps(chain)}",
    )

    suppressed = (second_pass == 0 and len(rows_after_second) == rows_after_first
                  and not events_after and chain["ok"] and not chain["problems"])
    report(name, expected, observed, bool(suppressed),
           "The replay was suppressed where it counts: record_tool_activity() numbers its "
           "records by position and UNIQUE(session_id, seq) turns the second pass over the "
           "same stream into zero rows and zero events, returned rather than raised, chain "
           "intact. The other half is a limit rather than a defect, and worth saying out "
           "loud: a record carries no provider-supplied identity, so a line repeated INSIDE "
           "one stream is indistinguishable from an agent running the same command twice "
           "and is recorded as two executions with an identical args_digest. A reviewer "
           "counting rows over-counts a provider that duplicates its own output; the "
           "matching digests are the only signal that they might be one action."
           if suppressed else
           "A replayed ingestion of the same stream produced additional rows or events: "
           "the (session_id, seq) suppression did not hold.")


# --------------------------------------------------------------------------- #
# 14: kill Mission Control during active execution
# --------------------------------------------------------------------------- #
def attack_kill_mission_control(report):
    name = "kill-mission-control"
    expected = ("SIGKILL to the orchestrator while a provider is running leaves nothing "
                "executing behind it, claims no success, loses no completed work, keeps the "
                "hash chain intact, and leaves a mission a later worker or run attempt can "
                "settle rather than a wedged lock.")
    absent = missing_sandbox_tools()
    if absent:
        report(name, expected, "not run: missing " + ", ".join(absent), None,
               "SKIPPED: this attack needs real sandboxed processes.")
        return

    with Lab("kill14") as lab:
        source = place(lab, "heavy")
        mid = lab.create(title="killed mid-encode", inputs=[source])
        store = lab.store()
        proc = lab.spawn_run(mid)
        started = wait_for_event(store, mid, "process-started", "export-", timeout=120)
        if not started:
            proc.kill()
            report(name, expected,
                   "the encode stage never started; events were "
                   + repr([row["event"] for row in store.events(mid)]), False,
                   "HARNESS ERROR (no verdict): the fixture mission did not reach its "
                   "encode, so nothing was interrupted.")
            return
        # Two seconds of real encoding, so the kill lands in the middle of the
        # provider's work rather than in its start-up.
        time.sleep(2.0)
        before = processes_under(lab.root)
        os.kill(proc.pid, signal.SIGKILL)
        returncode = proc.wait(timeout=30)
        survivors = wait_for(lambda: (processes_under(lab.root) == []) or None, 10)
        remaining = processes_under(lab.root)

        row = store.get(mid)
        tasks = [(task["kind"], task["state"]) for task in store.tasks(mid)]
        sessions = [(session["id"], session["ended_at"] is not None,
                     session["exit_code"], session["outcome"])
                    for session in store.sessions(mid)]
        chain = chain_summary(store)
        output = lab.workspace / "mission-output" / mid
        partial = sorted(f"{p.name} ({p.stat().st_size} bytes)"
                         for p in output.glob("*")) if output.is_dir() else []
        shown = lab.cli("show", mid)
        shown_state = json.loads(shown.stdout)["state"] if shown.returncode == 0 else shown.stdout
        # Does the crash leave a lock nobody can take, and can anything still
        # claim the mission is runnable?
        rerun = lab.cli("run", mid)
        settled = lab.store().get(mid)

    observed = lines(
        f"processes under the lab root while it ran ({len(before)}):",
        *("  " + command[:130] for _pid, command in before),
        f"SIGKILL -> orchestrator wait() returned {returncode}",
        f"processes under the lab root 1s after the kill: {len(remaining)} "
        + (repr([c[:80] for _p, c in remaining]) if remaining else "(none)"),
        "",
        f"mission row:  state={row['state']!r}  cancel_requested={row['cancel_requested']}  "
        f"attempt={row['attempt']}  error={row['error']!r}",
        f"checkpoint:   {row['checkpoint']!r}",
        f"tasks:        {tasks}",
        f"sessions:     {sessions}",
        f"partial work in the workspace: {partial or 'none'}",
        f"chain:        {json.dumps(chain)}",
        f"`shadowfetch-missions show` reports state: {shown_state!r}",
        "",
        f"`shadowfetch-missions run` on the stale row: rc={rerun.returncode} "
        f"stdout={rerun.stdout.strip()[:200]!r}",
        f"mission after that attempt: state={settled['state']!r} error={settled['error']!r}",
    )

    contained = (not remaining
                 and row["state"] == "running"
                 and row["checkpoint"]
                 and chain["ok"] and not chain["problems"]
                 and not any(state == "succeeded" for _kind, state in tasks[1:])
                 and rerun.returncode == 1
                 and settled["state"] == "failed")
    report(name, expected, observed, bool(contained),
           "Contained: the sandbox died with the orchestrator (bwrap --die-with-parent), no "
           "process outlived the kill, the completed checkpoint and the partial encode both "
           "survived, and the next `run` refused the mission after settling it honestly as "
           "interrupted. FINDING, not prevented: between the crash and the next worker start "
           "or run attempt the row still reads 'running' with no owner and no liveness "
           "marker, so Mission Control shows a mission that is not running for as long as "
           "nobody touches it. The tail of a killed run also leaves the *.partial encode in "
           "the workspace -- the unlink that removes it is in a finally clause SIGKILL never "
           "reaches -- so a person's Undo has to remove it.")


# --------------------------------------------------------------------------- #
# 15: kill the provider after launch
# --------------------------------------------------------------------------- #
def attack_kill_provider(report):
    name = "kill-provider-mid-session"
    expected = ("A provider process killed after launch cannot exist without a persisted "
                "AgentSession: the session row is written before the process starts, the "
                "kill is recorded as the exit status it was, the mission fails with a "
                "message naming the session, and the work stays reviewable and undoable.")
    absent = missing_sandbox_tools()
    if absent:
        report(name, expected, "not run: missing " + ", ".join(absent), None,
               "SKIPPED: this attack needs a real provider process to kill.")
        return

    with Lab("kill15") as lab:
        source = place(lab, "heavy")
        mid = lab.create(title="provider killed", inputs=[source])
        store = lab.store()
        proc = lab.spawn_run(mid)
        wait_for_event(store, mid, "process-started", "export-", timeout=120)
        encoders = wait_for(
            lambda: [(pid, cmd) for pid, cmd in processes_under(lab.root)
                     if cmd.startswith("/usr/bin/ffmpeg") and "libx264" in cmd], 60)
        if not encoders:
            proc.kill()
            report(name, expected, "no provider process became visible", False,
                   "HARNESS ERROR (no verdict): the encode process was never observed.")
            return
        # The persistence question, asked at the only moment it is meaningful:
        # the provider is running RIGHT NOW -- is its record already there?
        at_launch = [(session["id"], session["ended_at"]) for session in store.sessions(mid)]
        open_at_launch = [sid for sid, ended in at_launch if ended is None]
        for pid, _cmd in encoders:
            os.kill(pid, signal.SIGKILL)
        killed = [pid for pid, _cmd in encoders]
        returncode = proc.wait(timeout=180)
        stdout = proc.stdout.read()
        row = store.get(mid)
        sessions = [(session["id"], session["ended_at"] is not None,
                     session["exit_code"], session["outcome"])
                    for session in store.sessions(mid)]
        tasks = [(task["kind"], task["state"]) for task in store.tasks(mid)]
        chain = chain_summary(store)
        remaining = processes_under(lab.root)
        receipt = row["receipt"]
        artifacts = sorted(p.name for p in store.directory(mid).iterdir())
        try:
            accepted = sf.review(store, mid, "accept")["state"]
        except Exception as exc:                                  # noqa: BLE001
            accepted = f"REFUSED: {exc}"
        try:
            undone = sf.review(store, mid, "undo")["state"]
        except Exception as exc:                                  # noqa: BLE001
            undone = f"REFUSED: {exc}"
        workspace_after = sorted(str(p.relative_to(lab.workspace))
                                 for p in lab.workspace.rglob("*") if p.is_file())

    observed = lines(
        f"sessions persisted at the instant the provider process was visible: "
        f"{len(at_launch)} rows, open: {open_at_launch}",
        f"SIGKILL sent to provider pid(s) {killed}",
        f"orchestrator exit: {returncode}",
        f"mission row:  state={row['state']!r}",
        f"mission error: {(row['error'] or '')[:200]!r}",
        f"tasks:        {tasks}",
        f"sessions:     {sessions}",
        f"processes left under the lab root: {len(remaining)}",
        f"chain:        {json.dumps(chain)}",
        f"receipt written: {bool(receipt)}   mission dir: {artifacts}",
        f"review accept -> {accepted}",
        f"review undo   -> {undone}",
        f"workspace after undo: {workspace_after}",
        f"CLI stdout head: {stdout.strip()[:160]!r}",
    )

    recorded_kill = any(code == 137 for _sid, _ended, code, _outcome in sessions)
    all_closed = all(ended for _sid, ended, _code, _outcome in sessions)
    contained = (bool(open_at_launch) and recorded_kill and all_closed
                 and row["state"] == "failed" and not remaining
                 and chain["ok"] and not chain["problems"]
                 and undone == "undone" and str(accepted).startswith("REFUSED"))
    report(name, expected, observed, bool(contained),
           "The window the attack was aiming for does not exist: run_invocation() opens and "
           "PERSISTS the AgentSession before run_process() launches anything, which the "
           "census confirms -- the row was already there, still open, while the provider was "
           "running. The kill was then recorded as exit 137 on that row, the mission failed "
           "with the session id in its message, nothing survived, and because the receipt "
           "path still ran, review Undo restored the workspace.")


# --------------------------------------------------------------------------- #
# 16: cancel at the completion race
# --------------------------------------------------------------------------- #
def attack_cancel_completion_race(report):
    name = "cancel-completion-race"
    expected = ("A cancellation arriving as execution finishes either stops the mission or "
                "is refused, and in both cases the record matches what happened: nothing "
                "records a stop request against a mission that has already reached a "
                "terminal state.")
    absent = missing_sandbox_tools()
    if absent:
        report(name, expected, "not run: missing " + ", ".join(absent), None,
               "SKIPPED: the end-to-end half of this attack needs a real mission.")
        return

    with Lab("race16") as lab:
        # (a) a real mission, cancelled at the last possible instant: the moment
        #     its final export is verified and published.
        source = place(lab, "light")
        mid = lab.create(title="cancelled at the finish", inputs=[source])
        store = lab.store()
        proc = lab.spawn_run(mid)
        wait_for_event(store, mid, "export-verified", timeout=180)
        at_cancel = store.cancel(mid)
        proc.wait(timeout=180)
        final = store.get(mid)
        tail = [row["event"] for row in store.events(mid)][-6:]
        cancel_detail = next((row["detail"] for row in store.events(mid)
                              if row["event"] == "cancel-requested"), None)
        receipt = json.loads(Path(final["receipt"]).read_text()) if final["receipt"] else {}

        # (b) the same request one moment later, against the terminal row.
        events_before = len(store.events(mid))
        try:
            store.cancel(mid)
            late = "ACCEPTED"
        except Exception as exc:                                  # noqa: BLE001
            late = f"REFUSED: {exc}"
        events_after = len(store.events(mid))
        unchanged = (store.get(mid)["state"] == final["state"]
                     and events_before == events_after)

        # (c) the race itself. cancel() reads the state in one transaction and
        #     writes in another, with no expect= guard, so the two operations a
        #     person and the worker issue at the same instant are driven from a
        #     barrier and counted.
        trials, accepted_after_terminal, refused, reasons = 100, 0, 0, {}
        for index in range(trials):
            rid = lab.create(title=f"race {index}", inputs=[source])
            store.transition(rid, "running", expect="queued")
            gate = threading.Barrier(2)
            outcome = {}

            def canceller(target=rid, barrier=gate, box=outcome):
                barrier.wait()
                try:
                    box["cancel"] = store.cancel(target)
                except Exception as exc:                          # noqa: BLE001
                    box["cancel_error"] = str(exc)

            def finisher(target=rid, barrier=gate, box=outcome):
                barrier.wait()
                try:
                    box["finish"] = store.finish_execution(target, "waiting-review", None)
                except Exception as exc:                          # noqa: BLE001
                    box["finish_error"] = str(exc)

            first = threading.Thread(target=canceller)
            second = threading.Thread(target=finisher)
            first.start()
            second.start()
            first.join()
            second.join()
            if "cancel_error" in outcome:
                refused += 1
                key = outcome["cancel_error"][:60]
                reasons[key] = reasons.get(key, 0) + 1
                continue
            names = [row["event"] for row in store.events(rid)]
            if names and names[-1] == "cancel-requested" and "waiting-review" in names:
                accepted_after_terminal += 1
        race_chain = chain_summary(store)

    observed = lines(
        "(a) cancel issued the instant the last export was verified:",
        f"    mission state when cancel() was called: {at_cancel['state']!r}",
        f"    final state: {final['state']!r}   cancel_requested={final['cancel_requested']}   "
        f"error={final['error']!r}",
        f"    event tail: {tail}",
        f"    cancel-requested detail as written: {cancel_detail!r}",
        f"    receipt says state={receipt.get('state')!r} review_required="
        f"{receipt.get('review_required')} artifacts="
        f"{[Path(a['path']).name for a in receipt.get('artifacts', [])]}",
        "",
        "(b) the same cancel one moment later, against the terminal row:",
        f"    {late}",
        f"    row and event count unchanged: {unchanged} "
        f"({events_before} -> {events_after} events)",
        "",
        f"(c) cancel() and finish_execution() released from a barrier, {trials} trials:",
        f"    cancel refused because the mission was no longer active: {refused} {reasons}",
        f"    cancel ACCEPTED and its 'cancel-requested' event landed AFTER the terminal "
        f"'waiting-review' event: {accepted_after_terminal}",
        f"    chain after all trials: {json.dumps(race_chain)}",
    )

    passed = (accepted_after_terminal == 0 and unchanged and late.startswith("REFUSED")
              and race_chain["ok"])
    outcome_a = (
        f"(a) landed after the executor's last check: the mission finished as "
        f"{final['state']!r} carrying cancel_requested={final['cancel_requested']}, its "
        "export published and reviewable, and the 'cancel-requested' event it left behind "
        "says 'Running process is terminated' -- which is not what happened. Nothing was "
        "lost, and the desktop then prints 'Stop requested: yes' beside a mission awaiting "
        "review (missions_page.py:80), which is the only thing the person who pressed Stop "
        "is told."
        if final["state"] != "cancelled" else
        "(a) landed before the executor's last check and was honoured: the mission is "
        "cancelled with its completed export preserved and undoable.")
    report(name, expected, observed, bool(passed),
           lines(
               "FAILED on (c). Store.cancel() reads the mission state in one transaction and "
               "writes cancel_requested in another, with no expect= guard, so in "
               f"{accepted_after_terminal}/{trials} trials it ACCEPTED a stop request for a "
               "mission that had already reached waiting-review: the flag lands on a "
               "terminal row and the 'cancel-requested' event is appended AFTER the terminal "
               "event. Nothing is lost and the chain still verifies -- what is wrong is that "
               "the log records a decision that was never possible. transition() does "
               "exactly this correctly, in one transaction with expect=; cancel() is the "
               "verb that does not.",
               outcome_a,
               "(b) held: the same cancel one moment later was refused and changed nothing "
               f"({events_before} events before, {events_after} after).")
           if accepted_after_terminal else
           lines("No trial recorded a stop request against a terminal mission; the late "
                 "cancel was refused and changed nothing.", outcome_a))


# --------------------------------------------------------------------------- #
# 17: a worker restarts on a RUNNING row nobody owns
# --------------------------------------------------------------------------- #
def attack_worker_restart_stale_running(report):
    name = "worker-restart-stale-running"
    expected = ("A worker starting on a RUNNING row left by a crash settles it honestly "
                "rather than replaying it, settles its tasks and sessions, records what it "
                "found, keeps the chain intact, and leaves the person a route that actually "
                "works -- the regression to re-check is a crashed mission that can be "
                "NEITHER accepted NOR undone.")
    absent = missing_sandbox_tools()
    if absent:
        report(name, expected, "not run: missing " + ", ".join(absent), None,
               "SKIPPED: producing a genuine stale RUNNING row needs a real kill.")
        return

    with Lab("stale17") as lab:
        source = place(lab, "heavy")
        mid = lab.create(title="stale running row", inputs=[source])
        store = lab.store()
        proc = lab.spawn_run(mid)
        wait_for_event(store, mid, "process-started", "export-", timeout=120)
        time.sleep(2.0)
        os.kill(proc.pid, signal.SIGKILL)
        proc.wait(timeout=30)
        wait_for(lambda: (processes_under(lab.root) == []) or None, 10)
        stale = store.get(mid)["state"]
        sessions_before = len(store.sessions(mid))

        worker = lab.cli("worker", "--once")
        row = store.get(mid)
        tasks = [(task["kind"], task["state"], task["error"]) for task in store.tasks(mid)]
        sessions = [(session["ended_at"] is not None, session["exit_code"],
                     session["outcome"]) for session in store.sessions(mid)]
        # Store.events() takes a mission id and the reconciliation summary is
        # written against "*", which is not a mission, so it is read from the
        # events table directly rather than through that accessor.
        with store.db() as db:
            reconciled = [dict(record)["detail"] for record in
                          db.execute("SELECT detail FROM events WHERE event='reconciled'")]
        chain = chain_summary(store)

        try:
            accepted = sf.review(store, mid, "accept")["state"]
        except Exception as exc:                                  # noqa: BLE001
            accepted = f"REFUSED: {exc}"
        try:
            undone = sf.review(store, mid, "undo")["state"]
        except Exception as exc:                                  # noqa: BLE001
            undone = f"REFUSED: {exc}"
        # The refusal names shadowfetch-checkpoint. Does that route work?
        listed = subprocess.run([sys.executable, str(CHECKPOINT_CLI), "list",
                                 lab.workspace.name], env=lab.env,
                                capture_output=True, text=True, timeout=120)
        manual = subprocess.run([sys.executable, str(CHECKPOINT_CLI), "undo",
                                 lab.workspace.name, row["checkpoint"] or ""],
                                env=lab.env, capture_output=True, text=True, timeout=300)
        workspace_after = sorted(str(p.relative_to(lab.workspace))
                                 for p in lab.workspace.rglob("*") if p.is_file())
        retried = store.retry(mid)["state"]
        finished = lab.cli("worker", "--once", timeout=600)
        recovered = store.get(mid)
        recovered_sessions = len(store.sessions(mid))

    observed = lines(
        f"row left by the crash: state={stale!r} with {sessions_before} session row(s)",
        f"`shadowfetch-missions worker --once`: rc={worker.returncode} "
        f"stdout={worker.stdout.strip()[:120]!r} stderr={worker.stderr.strip()[:160]!r}",
        f"mission after the worker started: state={row['state']!r} attempt={row['attempt']} "
        f"error={row['error']!r}",
        f"tasks:    {tasks}",
        f"sessions: {sessions}",
        f"reconciliation events: {reconciled}",
        f"chain: {json.dumps(chain)}",
        "",
        "what the person can do with it:",
        f"  review accept -> {accepted}",
        f"  review undo   -> {undone}",
        f"  shadowfetch-checkpoint list -> rc={listed.returncode} "
        f"{listed.stdout.strip()[:160]!r}",
        f"  shadowfetch-checkpoint undo -> rc={manual.returncode} "
        f"{manual.stdout.strip()[:160]!r}",
        f"  workspace after the manual restore: {workspace_after}",
        f"  retry -> {retried!r}; second `worker --once` rc={finished.returncode} -> "
        f"state={recovered['state']!r} attempt={recovered['attempt']} "
        f"sessions={recovered_sessions}",
    )

    settled = (row["state"] == "failed" and row["attempt"] == 1
               and all(state != "running" for _kind, state, _error in tasks)
               and all(ended for ended, _code, _outcome in sessions)
               and reconciled and chain["ok"] and not chain["problems"])
    a_route_exists = manual.returncode == 0 and recovered["state"] == "waiting-review"
    report(name, expected, observed, bool(settled and a_route_exists),
           "The worker settled the row instead of replaying it: attempt stayed at 1, the "
           "RUNNING task became failed with 'The worker stopped while this step was "
           "running', the open session was closed as interrupted, and one 'reconciled' event "
           "records the counts. The chain verifies. THE REGRESSION IS HALF PRESENT: review "
           "Accept is refused (correctly -- nothing succeeded) and review Undo is ALSO "
           "refused, because receipt() never ran and so there is no after-index.json, which "
           "is the file review() compares against. The mission therefore cannot be undone "
           "through Mission Control. It is not a dead end: the refusal names "
           "shadowfetch-checkpoint, that route ran here and restored the workspace, and "
           "Retry then re-ran the mission to waiting-review. Worth knowing that after the "
           "manual restore the mission row still reads 'failed' and is not marked undone, so "
           "the record and the workspace disagree until the person retries.")


# --------------------------------------------------------------------------- #
# 18: a destructive MCP operation without correlation
# --------------------------------------------------------------------------- #
def mcp_call(lab, extra_env, arguments, checkpoint_id):
    """One stdio MCP conversation with the checkpoint server: list, then undo."""
    env = dict(lab.env)
    env.update(extra_env)
    request = [
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}),
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                    "params": {"name": "undo", "arguments": dict(
                        arguments, checkpoint=checkpoint_id)}}),
    ]
    done = subprocess.run([sys.executable, str(MCP_IMPL), "checkpoint"],
                          input="\n".join(request) + "\n", env=env,
                          capture_output=True, text=True, timeout=120)
    replies = {}
    for line in done.stdout.splitlines():
        try:
            message = json.loads(line)
        except ValueError:
            continue
        replies[message.get("id")] = message
    listed = sorted(tool["name"] for tool in
                    replies.get(1, {}).get("result", {}).get("tools", []))
    result = replies.get(2, {}).get("result", {})
    content = (result.get("content") or [{}])[0].get("text", "<no reply>")
    return {"tools": listed, "isError": result.get("isError"),
            "text": " ".join(content.split())[:260], "stderr": done.stderr.strip()[:160]}


def attack_mcp_destructive_without_correlation(report):
    name = "mcp-destructive-no-correlation"
    expected = ("checkpoint.undo -- the one DESTRUCTIVE tool on the agent-facing surface -- "
                "is not offered and not performed without both an operator's opt-in and a "
                "correlation the server can OBSERVE; every refusal leaves the workspace "
                "byte-for-byte as it was and is recorded in the audit chain.")
    with Lab("mcp18") as lab:
        (lab.workspace / "keep.txt").write_text("original\n")
        snapshot = subprocess.run([sys.executable, str(CHECKPOINT_CLI), "--json",
                                   "snapshot", lab.workspace.name],
                                  env=lab.env, capture_output=True, text=True, timeout=300)
        checkpoint_id = json.loads(snapshot.stdout)["id"]
        # Work an agent did AFTER the checkpoint. An undo destroys exactly this,
        # so its survival is the proof that nothing happened.
        (lab.workspace / "agent-made-this.txt").write_text("written after the checkpoint\n")

        def tree():
            return {str(p.relative_to(lab.workspace)): p.read_text()
                    for p in sorted(lab.workspace.rglob("*")) if p.is_file()}

        baseline = tree()
        arguments = {"workspace": lab.workspace.name}
        cases = []
        for label, env in (
            ("no correlation, destructive not enabled", {}),
            ("destructive=allow, correlation absent", {"SHADOWFETCH_MCP_DESTRUCTIVE": "allow"}),
            ("destructive=allow, forged session id (no record on disk)",
             {"SHADOWFETCH_MCP_DESTRUCTIVE": "allow",
              "SHADOWFETCH_MCP_SESSION": "sess-forged-000000"}),
            ("destructive=allow, malformed session id",
             {"SHADOWFETCH_MCP_DESTRUCTIVE": "allow",
              "SHADOWFETCH_MCP_SESSION": "../../etc/passwd"}),
        ):
            outcome = mcp_call(lab, env, arguments, checkpoint_id)
            cases.append((label, env, outcome, tree() == baseline))
        # Truthy-but-wrong values for the operator's opt-in.
        truthy = []
        for value in ("1", "true", "yes", "YES", "ALLOW", "Allow", "allowed", "0", " allow "):
            outcome = mcp_call(lab, {"SHADOWFETCH_MCP_DESTRUCTIVE": value,
                                     "SHADOWFETCH_MCP_SESSION": "sess-forged-000000"},
                               arguments, checkpoint_id)
            truthy.append((value, "undo" in outcome["tools"], outcome["isError"],
                           tree() == baseline))
        refusals_changed_nothing = all(unchanged for _l, _e, _o, unchanged in cases) and \
            all(unchanged for _v, _listed, _err, unchanged in truthy)
        refusals_refused = all(outcome["isError"] for _l, _e, outcome, _u in cases)

        # A destructive call an agent could reach out of band: /usr/bin is
        # read-only-bound into every Firebreak sandbox, and the human CLI
        # reaches the same engine WITHOUT the gate and without an audit row.
        outofband = subprocess.run(
            [sys.executable, str(FIREBREAK_BIN / "shadowfetch-firebreak"), "run",
             "--workspace", lab.workspace.name, "--net", "none", "--no-checkpoint",
             "--", "/usr/bin/shadowfetch-checkpoint", "undo", lab.workspace.name,
             checkpoint_id],
            env=lab.env, capture_output=True, text=True, timeout=300) \
            if Path("/usr/bin/shadowfetch-checkpoint").exists() else None
        sandbox_unchanged = tree() == baseline

        # Finally: a correlation the gate accepts, forged by this process. The
        # server itself says OBSERVED is not proof -- "anything running as this
        # uid can create such a file" -- so this measures whether the gate
        # CLAIMS more than it checks.
        (lab.fb / "sess-forged-observed.session").write_text(
            json.dumps({"session": "sess-forged-observed",
                        "note": "forged by tools/attacks/attack_lifecycle.py"}) + "\n")
        forged = mcp_call(lab, {"SHADOWFETCH_MCP_DESTRUCTIVE": "allow",
                                "SHADOWFETCH_MCP_SESSION": "sess-forged-observed"},
                          arguments, checkpoint_id)
        after_forged = tree()
        audit_path = lab.mcp / "shadowfetch/mcp/audit.jsonl"
        audit = []
        if audit_path.exists():
            for line in audit_path.read_text().splitlines():
                record = json.loads(line)
                audit.append((record.get("seq"), record.get("phase"), record.get("tool"),
                              record.get("decision"),
                              (record.get("correlation") or {}).get("status")))
        verify = subprocess.run([sys.executable, str(MCP_IMPL), "--audit", "verify"],
                                env=lab.env, capture_output=True, text=True, timeout=120)
        verified = json.loads(verify.stdout).get("verification", {}) if verify.stdout else {}

    observed = lines(
        f"workspace before any call: {sorted(baseline)}",
        *[lines(f"[{label}] env={env}",
                f"    tools offered: {outcome['tools']}",
                f"    isError={outcome['isError']}  {outcome['text']}",
                f"    workspace unchanged: {unchanged}")
          for label, env, outcome, unchanged in cases],
        "truthy-but-wrong values for SHADOWFETCH_MCP_DESTRUCTIVE "
        "(value, undo offered, refused, workspace unchanged):",
        *[f"    {value!r:12} {listed!r:6} {bool(err)!r:6} {unchanged!r}"
          for value, listed, err, unchanged in truthy],
        "",
        "out-of-band: the same undo attempted from inside a Firebreak sandbox via "
        "/usr/bin/shadowfetch-checkpoint (the human CLI, which reaches the engine with no "
        "gate and writes no audit row):",
        f"    {'not installed on this host' if outofband is None else 'rc=%d %s' % (outofband.returncode, (outofband.stderr.strip().splitlines() or ['']) [-2:])}",
        f"    workspace unchanged: {sandbox_unchanged}",
        "",
        "forged-but-OBSERVED correlation (a .session file this process wrote itself, plus "
        "the operator's opt-in):",
        f"    isError={forged['isError']}  {forged['text']}",
        f"    workspace after: {sorted(after_forged)}",
        f"audit rows (seq, phase, tool, decision, correlation status): {audit}",
        f"audit chain verification: ok={verified.get('ok')} head_seq={verified.get('head_seq')} "
        f"problems={verified.get('problems')}",
    )

    forged_status = [row for row in audit if row[4] == "observed"]
    passed = (refusals_refused and refusals_changed_nothing and sandbox_unchanged
              and all(not listed for value, listed, _e, _u in truthy if value.strip() != "allow")
              and bool(forged_status) and verified.get("ok"))
    report(name, expected, observed, bool(passed),
           "Every uncorrelated call was refused and changed nothing: the tool is not even "
           "advertised until the operator opts in, and no truthy-looking value other than "
           "'allow' (whitespace stripped, deliberately) enables it. From inside a Firebreak "
           "sandbox the same destructive engine is reachable as a program but not as an "
           "operation -- the checkpoint store lives outside the workspace bind, so the call "
           "failed with 'no such checkpoint' and nothing was restored. THE ACTION ITSELF WAS "
           "NOT PREVENTED in the last case: a file this process created under the Firebreak "
           "state directory made the correlation OBSERVED, and the undo then ran and deleted "
           "the post-checkpoint file. That is the documented limit rather than a broken "
           "control -- the server records the status as 'observed', never as verified or "
           "authenticated, and its own comment says the file is forgeable by anything "
           "running as this uid -- so the refusal to overclaim holds even though the "
           "destructive call went through. What is left standing between an agent and this "
           "tool is one environment variable the agent does not set. Separately worth the "
           "lead's attention: `shadowfetch-checkpoint undo` at a terminal performs the same "
           "DESTRUCTIVE operation through the tool handler directly, so it is gated by "
           "nothing and appears in no audit row -- intended for a person, but it is the one "
           "path to this engine that keeps no record.")


# --------------------------------------------------------------------------- #
# Composition
# --------------------------------------------------------------------------- #
RUNNERS = {
    "malformed-tool-events": attack_malformed_tool_events,
    "duplicate-tool-events": attack_duplicate_tool_events,
    "kill-mission-control": attack_kill_mission_control,
    "kill-provider-mid-session": attack_kill_provider,
    "cancel-completion-race": attack_cancel_completion_race,
    "worker-restart-stale-running": attack_worker_restart_stale_running,
    "mcp-destructive-no-correlation": attack_mcp_destructive_without_correlation,
}


def run(report, only=()):
    """Run the attacks in order, reporting each exactly once.

    A harness failure is reported as a FAILED attack whose first words say it
    is a harness error and not a verdict, because a module that swallowed its
    own exceptions would go green while measuring nothing.
    """
    for name in ATTACKS:
        if only and name not in only:
            continue
        try:
            RUNNERS[name](report)
        except Exception:                                          # noqa: BLE001
            report(name, "the attack to run at all",
                   "HARNESS ERROR (no verdict on the system):\n"
                   + traceback.format_exc()[-1200:], False,
                   "This module failed, not necessarily the system. Fix the module and "
                   "re-run before reading anything into this row.")


def main(argv):
    only = tuple(argv[1:])
    unknown = [name for name in only if name not in RUNNERS]
    if unknown:
        sys.stderr.write("unknown attack(s): " + ", ".join(unknown)
                         + "\nknown: " + ", ".join(ATTACKS) + "\n")
        return 2
    records = []

    def report(name, expected, observed, passed, note=""):
        records.append({"attack": name, "expected": expected, "observed": observed,
                        "passed": passed, "note": note})

    run(report, only)
    width = max((len(record["attack"]) for record in records), default=10)
    for record in records:
        verdict = {True: "PASS", False: "FAIL", None: "SKIPPED"}[record["passed"]]
        print("=" * 78)
        print(f"{record['attack']:<{width}}  {verdict}")
        print("-" * 78)
        print("EXPECTED  " + record["expected"])
        print("OBSERVED  " + record["observed"].replace("\n", "\n          "))
        if record["note"]:
            print("NOTE      " + record["note"].replace("\n", "\n          "))
    print("=" * 78)
    counts = {"PASS": 0, "FAIL": 0, "SKIPPED": 0}
    for record in records:
        counts[{True: "PASS", False: "FAIL", None: "SKIPPED"}[record["passed"]]] += 1
    print(f"{len(records)} attacks: {counts['PASS']} PASS, {counts['FAIL']} FAIL, "
          f"{counts['SKIPPED']} SKIPPED")
    return 1 if counts["FAIL"] else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
