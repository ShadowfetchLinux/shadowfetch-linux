#!/usr/bin/env python3
"""Stage O: what actually happens when more than one agent runs.

capabilities() reports max_parallel: 1 and the shipped worker consumes its queue
in a single-threaded loop holding worker.lock exclusively. That is a property of
ONE WORKER PROCESS, not of the system: nothing stops a second caller, and the
lock hierarchy is designed to let two workspaces proceed at once. This module
measures the difference rather than reading it, because "the code checks for it"
is not enforcement and a single-threaded accident is not a control.

WHAT IS MEASURED, and against which layer

  O1  two workers            worker.lock (flock, LOCK_EX|LOCK_NB) admits one
                             consumer per STATE ROOT. The loser exits 0 in
                             silence, and the state root -- not the machine, not
                             the workspace -- is the whole extent of the claim.
  O2  a CLI run and a worker execution.lock is shared by both entry points, so
                             they serialize on one workspace and DO NOT on two.
                             The state machine's compare-and-swap is the second,
                             independent layer, and it is the one that holds when
                             the flock does not.
  O3  two workspaces         Firebreak sessions, systemd scopes and checkpoint
                             stores are per-session or per-workspace on disk. The
                             audit chain is NOT: it is one hash chain shared by
                             every caller of one state root.
  O4  the audit chain        BEGIN IMMEDIATE around read-head-then-append. A fork
                             would be two rows carrying one prev_hash; this both
                             races the real appender and injects the fork that
                             race is meant to make impossible, so that verify()
                             is shown to notice.
  O5  approvals              subject-scoped rows, and a re-read under the write
                             lock the revoke path also takes. Raced for real
                             against a separate revoking process, not mocked.
  O6  credentials            bwrap --clearenv plus one --setenv per granted
                             identity. Two identities live in one worker PROCESS
                             at once; the isolation is per invocation.

READING A RECORD. PASS means the stated expectation was measured to hold. Some
expectations here are deliberately of the form "this is not prevented, and
nothing claims it is" -- Stage O is a measurement stage, and a gap recorded
honestly is the pass condition for a gap. Every such record says so in its NOTE
and each one is written down in docs/MULTI_AGENT_SAFETY.md under the same name.

SAFETY. Every probe runs against a throwaway store made with tempfile.mkdtemp
and four redirected state roots. Nothing here writes to ~/.local/state or to a
real workspace. PATH is PINNED to the trusted system directories rather than
having the build tree prepended: the source Firebreak and checkpoint engine are
selected through the engine's own explicit override variables, which is the
sanctioned way to test a build tree without letting PATH decide which binary
answers a security question.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import multiprocessing
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
MISSIONS_LIB = REPO / "packages/shadowfetch-missions/data/usr/lib/shadowfetch/missions"
MISSIONS_CLI = REPO / "packages/shadowfetch-missions/data/usr/bin/shadowfetch-missions"
FIREBREAK_BIN = REPO / "packages/shadowfetch-fireline/data/usr/bin"

# Absolute, and not consulted through PATH. These decide what a measurement
# MEANS -- ffmpeg builds the input a mission is judged on, systemctl reports
# whether two cgroups were live at once -- so resolving them through an
# inherited PATH would let the environment choose the answer.
FFMPEG = "/usr/bin/ffmpeg"
SYSTEMCTL = "/usr/bin/systemctl"
# The child PATH, pinned. A program resolves ITS helpers through what it
# inherits, so exporting the build tree here would put an unreviewed directory
# in front of every helper Firebreak, bwrap and ffmpeg go on to run.
TRUSTED_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

PROBES = (
    "O0-the-source-tree-is-what-is-under-test",
    "O1-worker-lock-admits-exactly-one-consumer",
    "O1-the-losing-worker-exits-zero-in-silence",
    "O1-worker-lock-is-scoped-to-one-state-root",
    "O1-two-state-roots-share-no-workspace-lock",
    "O2-cli-run-is-refused-while-a-worker-holds-the-workspace",
    "O2-cli-and-worker-execute-at-once-on-different-workspaces",
    "O2-the-same-mission-cannot-be-started-twice",
    "O2-the-state-transition-is-a-compare-and-swap",
    "O3-concurrent-missions-keep-separate-sandboxes-and-scopes",
    "O3-checkpoint-stores-do-not-share-a-namespace",
    "O3-the-audit-chain-is-shared-not-separate",
    "O3-a-workspace-cannot-be-aliased-into-a-second-lock",
    "O3-undo-cannot-be-redirected-onto-another-workspace",
    "O4-racing-appends-never-fork-the-chain",
    "O4-an-injected-fork-is-detected",
    "O4-two-processes-opening-a-fresh-database-at-once",
    "O4-a-caller-that-loses-the-open-race-gets-a-traceback",
    "O5-an-approval-is-not-transferable-between-missions",
    "O5-a-revoke-never-lands-between-the-check-and-the-use",
    "O5-revocation-is-not-a-kill-switch-cancellation-is",
    "O6-two-identities-in-one-process-do-not-cross",
    "O6-an-undeclared-identity-cannot-be-granted",
)

ENV_KEYS = ("SHADOWFETCH_AGENT_WORKSPACES", "SHADOWFETCH_MISSIONS_STATE",
            "SHADOWFETCH_FIREBREAK_STATE", "SHADOWFETCH_MCP_STATE",
            "SHADOWFETCH_FIREBREAK_TEST_BIN", "SHADOWFETCH_CHECKPOINT_BIN",
            "PATH")

# Sentinel credential values. Never a real secret: these end up in a sandbox's
# environment and in this program's own output.
FAKE_ANTHROPIC = "sk-ant-stage-o-not-a-real-key-0000"
FAKE_CODEX = "sk-codex-stage-o-not-a-real-key-1111"


# --------------------------------------------------------------------------- #
# harness
# --------------------------------------------------------------------------- #
class Bench:
    """A throwaway store, a throwaway workspace root, and the SOURCE modules."""

    def __init__(self):
        self.tmp = None
        self.saved = {}
        self.sf = None

    def __enter__(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="sf-stage-o-"))
        self.saved = {key: os.environ.get(key) for key in ENV_KEYS}
        os.environ["SHADOWFETCH_AGENT_WORKSPACES"] = str(self.tmp / "ws")
        os.environ["SHADOWFETCH_MISSIONS_STATE"] = str(self.tmp / "state")
        os.environ["SHADOWFETCH_FIREBREAK_STATE"] = str(self.tmp / "fb")
        os.environ["SHADOWFETCH_MCP_STATE"] = str(self.tmp / "mcp")
        os.environ["PATH"] = TRUSTED_PATH
        os.environ["SHADOWFETCH_FIREBREAK_TEST_BIN"] = str(FIREBREAK_BIN / "shadowfetch-firebreak")
        os.environ["SHADOWFETCH_CHECKPOINT_BIN"] = str(FIREBREAK_BIN / "shadowfetch-checkpoint")
        (self.tmp / "ws").mkdir(parents=True, exist_ok=True)
        if str(MISSIONS_LIB) not in sys.path:
            sys.path.insert(0, str(MISSIONS_LIB))
        import sf_missions
        self.sf = sf_missions
        return self

    def __exit__(self, *exc):
        for key, value in self.saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        shutil.rmtree(self.tmp, ignore_errors=True)
        return False

    # -- environment -------------------------------------------------------
    def env(self, **overrides):
        base = {key: os.environ[key] for key in ENV_KEYS if key in os.environ}
        base.update(overrides)
        return base

    # -- workspaces --------------------------------------------------------
    def media_workspace(self, name, *, seconds=8, size="480x360"):
        """A workspace holding one REAL encodable clip.

        A file of junk bytes makes every mission fail in its first probe step,
        which measures a refusal rather than a concurrent execution. The point
        of Stage O is what two RUNNING missions do to each other, so the input
        has to be one ffmpeg will actually spend time on.
        """
        path = self.tmp / "ws" / name
        path.mkdir(parents=True, exist_ok=True)
        clip = path / "clip.mp4"
        if not clip.is_file():
            result = subprocess.run(
                [FFMPEG, "-nostdin", "-v", "error", "-y",
                 "-f", "lavfi", "-i", f"testsrc=size={size}:rate=25:duration={seconds}",
                 "-f", "lavfi", "-i", f"sine=frequency=440:duration={seconds}",
                 "-c:v", "libx264", "-preset", "ultrafast", "-c:a", "aac",
                 "-shortest", str(clip)],
                capture_output=True, text=True, timeout=180,
                env={"PATH": TRUSTED_PATH, "HOME": os.environ.get("HOME", "/tmp")})
            if result.returncode:
                raise RuntimeError("ffmpeg could not build the probe input: "
                                   + result.stderr[-400:])
        return path

    def store(self, root=None):
        return self.sf.Store(root)

    def media_mission(self, store, workspace, title):
        return store.create(capability="media_export", workspace_value=workspace,
                            title=title, prompt="export", inputs=["clip.mp4"])

    def cloud_mission(self, store, workspace, title):
        """A mission that ESCALATES: the codex provider brings a credential
        identity and a network posture into the scope a human must agree to."""
        return store.create(kind="report", provider_id="codex",
                            workspace_value=workspace, title=title,
                            prompt="report", inputs=["clip.mp4"])

    def cli(self, *args, env=None, timeout=300):
        return subprocess.run([sys.executable, str(MISSIONS_CLI), *args],
                              capture_output=True, text=True, timeout=timeout,
                              env=dict(env or os.environ))

    # -- reading Firebreak's own records ----------------------------------
    def firebreak_sessions(self, state_dir=None):
        """Every Firebreak session this bench produced: mission, scope unit and
        the microsecond window the sandbox was actually alive."""
        root = Path(state_dir or os.environ["SHADOWFETCH_FIREBREAK_STATE"])
        out = {}
        for path in sorted(root.glob("*.session")):
            for line in path.read_text().splitlines():
                if not line.strip():
                    continue
                entry = json.loads(line)
                sid = entry.get("session")
                if entry.get("record") == "started":
                    out.setdefault(sid, {}).update(
                        {"session": sid, "mission": entry.get("mission"),
                         "scope_unit": entry.get("scope_unit"),
                         "started": entry.get("started"),
                         "workspace": entry.get("workspace"),
                         "credential_names": entry.get("credential_names")})
                elif entry.get("record") == "ended":
                    out.setdefault(sid, {})["ended"] = entry.get("at")
        return out


def _instant(text):
    if not text:
        return None
    return time.mktime(time.strptime(text[:19], "%Y-%m-%dT%H:%M:%S")) + float("0" + text[19:26])


def windows_for(sessions, mission):
    spans = []
    for entry in sessions.values():
        if entry.get("mission") != mission:
            continue
        start, end = _instant(entry.get("started")), _instant(entry.get("ended"))
        if start is not None and end is not None:
            spans.append((start, end, entry["session"]))
    return sorted(spans)


def span_overlap(first, second):
    """Seconds two closed intervals share. Negative means a gap between them."""
    return min(first[1], second[1]) - max(first[0], second[0])


def best_overlap(left, right):
    """The largest overlap between any window of one mission and any of the
    other, with the two sessions that produced it."""
    best = (-1e9, None, None)
    for a in left:
        for b in right:
            shared = span_overlap(a, b)
            if shared > best[0]:
                best = (shared, a[2], b[2])
    return best


# --------------------------------------------------------------------------- #
# child process bodies -- module level so the fork context can reach them
# --------------------------------------------------------------------------- #
def _worker_child(env, out_path, start_at):
    """A REAL worker process. sf_missions.worker() is what the systemd unit
    runs; reimplementing the loop here would test a copy of it."""
    os.environ.update(env)
    sys.path.insert(0, str(MISSIONS_LIB))
    import sf_missions
    record = {"pid": os.getpid()}
    try:
        store = sf_missions.Store()
        while time.time() < start_at:
            time.sleep(0.002)
        record["entered_at"] = time.time()
        record["rc"] = sf_missions.worker(store, once=True)
        record["left_at"] = time.time()
        record["outcome"] = "returned"
    except BaseException as exc:                                   # noqa: BLE001
        record["outcome"] = "raised"
        record["error"] = f"{type(exc).__name__}: {exc}"
        record["left_at"] = time.time()
    Path(out_path).write_text(json.dumps(record))


def _run_mission_child(env, mid, out_path, start_at=0.0):
    os.environ.update(env)
    sys.path.insert(0, str(MISSIONS_LIB))
    import sf_missions
    record = {"pid": os.getpid(), "mission": mid}
    try:
        store = sf_missions.Store()
        while time.time() < start_at:
            time.sleep(0.002)
        record["entered_at"] = time.time()
        result = sf_missions.run_mission(store, mid)
        record["outcome"] = "ran"
        record["state"] = result["state"]
        record["error"] = result.get("error")
    except BaseException as exc:                                   # noqa: BLE001
        record["outcome"] = "refused"
        record["error"] = f"{type(exc).__name__}: {exc}"
    record["left_at"] = time.time()
    Path(out_path).write_text(json.dumps(record))


def _hold_workspace_child(env, workspace, signal_path, release_path, out_path):
    """Hold ONE workspace's execution lock until the parent says to let go.

    store.lock(workspace=...) is the call run_mission, retry and review all
    make; taking a flock directly here would prove something about flock rather
    than about the engine."""
    os.environ.update(env)
    sys.path.insert(0, str(MISSIONS_LIB))
    import sf_missions
    record = {"pid": os.getpid(), "workspace": str(workspace)}
    try:
        store = sf_missions.Store()
        with store.lock(workspace=workspace, wait_seconds=0):
            record["entered_at"] = time.time()
            Path(signal_path).write_text("held")
            deadline = time.time() + 120
            while not Path(release_path).exists() and time.time() < deadline:
                time.sleep(0.01)
            record["left_at"] = time.time()
        record["outcome"] = "held"
    except BaseException as exc:                                   # noqa: BLE001
        record["outcome"] = "refused"
        record["error"] = f"{type(exc).__name__}: {exc}"
        Path(signal_path).write_text("failed")
    Path(out_path).write_text(json.dumps(record))


def _lock_window_child(env, workspace, start_at, hold_seconds, out_path):
    os.environ.update(env)
    sys.path.insert(0, str(MISSIONS_LIB))
    import sf_missions
    record = {"pid": os.getpid(), "workspace": str(workspace),
              "state_root": env.get("SHADOWFETCH_MISSIONS_STATE")}
    try:
        store = sf_missions.Store()
        while time.time() < start_at:
            time.sleep(0.002)
        with store.lock(workspace=workspace, wait_seconds=0):
            record["entered_at"] = time.time()
            time.sleep(hold_seconds)
            record["left_at"] = time.time()
        record["outcome"] = "held"
    except BaseException as exc:                                   # noqa: BLE001
        record["outcome"] = "refused"
        record["error"] = f"{type(exc).__name__}: {exc}"
    Path(out_path).write_text(json.dumps(record))


def _transition_child(env, mid, start_at, out_path):
    """Race the state machine with NO execution lock at all.

    This is the layer under the flock: transition(expect=...) is a
    compare-and-swap inside BEGIN IMMEDIATE, and it is what still holds when two
    callers do not share a lock file."""
    os.environ.update(env)
    sys.path.insert(0, str(MISSIONS_LIB))
    import sf_missions
    record = {"pid": os.getpid()}
    try:
        store = sf_missions.Store()
        while time.time() < start_at:
            time.sleep(0.001)
        store.transition(mid, "running", actor="worker", expect="queued",
                         detail="stage O compare-and-swap race")
        record["outcome"] = "won"
    except BaseException as exc:                                   # noqa: BLE001
        record["outcome"] = "refused"
        record["error"] = f"{type(exc).__name__}: {exc}"
    Path(out_path).write_text(json.dumps(record))


def _append_child(env, mission, count, start_at, out_path):
    os.environ.update(env)
    sys.path.insert(0, str(MISSIONS_LIB))
    import sf_missions
    record = {"pid": os.getpid(), "appended": 0}
    try:
        store = sf_missions.Store()
        while time.time() < start_at:
            time.sleep(0.001)
        for index in range(count):
            store.append_event(mission, "stage-o-append",
                               f"pid {os.getpid()} row {index}")
            record["appended"] += 1
        record["outcome"] = "appended"
    except BaseException as exc:                                   # noqa: BLE001
        record["outcome"] = "raised"
        record["error"] = f"{type(exc).__name__}: {exc}"
    Path(out_path).write_text(json.dumps(record))


def _open_store_child(env, start_at, out_path):
    """Construct a Store on a FRESH root at the same instant as its siblings.

    Store.__init__ runs the schema creation and the migration -- including the
    chain genesis -- BEFORE any caller has taken worker.lock or execution.lock,
    so this is the one window in which two workers genuinely have no lock
    between them."""
    os.environ.update(env)
    sys.path.insert(0, str(MISSIONS_LIB))
    import sf_missions
    record = {"pid": os.getpid()}
    try:
        while time.time() < start_at:
            time.sleep(0.001)
        store = sf_missions.Store()
        record["outcome"] = "opened"
        record["chain_id"] = store.chain_id()
    except BaseException as exc:                                   # noqa: BLE001
        record["outcome"] = "raised"
        record["error"] = f"{type(exc).__name__}: {exc}"
    Path(out_path).write_text(json.dumps(record))


def _revoke_child(env, approval_id, delay, out_path):
    os.environ.update(env)
    sys.path.insert(0, str(MISSIONS_LIB))
    import sf_missions
    record = {"pid": os.getpid(), "approval": approval_id, "delay": delay}
    try:
        store = sf_missions.Store()
        time.sleep(delay)
        record["at"] = time.time()
        store.revoke_approval(approval_id, reason="stage O race")
        record["outcome"] = "revoked"
    except BaseException as exc:                                   # noqa: BLE001
        record["outcome"] = "refused"
        record["error"] = f"{type(exc).__name__}: {exc}"
    Path(out_path).write_text(json.dumps(record))


def _fork(target, *args):
    context = multiprocessing.get_context("fork")
    proc = context.Process(target=target, args=args)
    proc.start()
    return proc


def _await_file(path, seconds=60):
    deadline = time.time() + seconds
    while not Path(path).exists() and time.time() < deadline:
        time.sleep(0.01)
    return Path(path).exists()


def _read(path, default=None):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return default


# What one probe measured and the next one reads back. A module-level dict, not
# a shared default argument: a default belongs to ONE function object, so two
# probes written that way each got their own empty dict and the second reported
# "nothing was measured" about work the first had just done.
_MEASURED = {}


# --------------------------------------------------------------------------- #
# O0 -- what is actually loaded
# --------------------------------------------------------------------------- #
def probe_under_test(bench, report):
    name = "O0-the-source-tree-is-what-is-under-test"
    firebreak = bench.sf.executable("shadowfetch-firebreak")
    checkpoint = bench.sf.checkpoint_module()
    passed = (str(MISSIONS_LIB) in bench.sf.__file__
              and str(FIREBREAK_BIN) in firebreak
              and str(REPO) in checkpoint.__file__
              and os.environ["PATH"] == TRUSTED_PATH
              and str(bench.tmp) in os.environ["SHADOWFETCH_MISSIONS_STATE"])
    report(name,
           "the SOURCE modules, the SOURCE Firebreak and the SOURCE checkpoint "
           "engine are what is loaded, against a throwaway store outside "
           "~/.local/state, with PATH pinned to the trusted system directories",
           f"sf_missions   {bench.sf.__file__}\n"
           f"firebreak     {firebreak}\n"
           f"checkpoint    {checkpoint.__file__}\n"
           f"PATH          {os.environ['PATH']}\n"
           f"state root    {os.environ['SHADOWFETCH_MISSIONS_STATE']}\n"
           f"firebreak log {os.environ['SHADOWFETCH_FIREBREAK_STATE']}\n"
           f"workspaces    {os.environ['SHADOWFETCH_AGENT_WORKSPACES']}",
           passed,
           note="the build tree is selected through the engine's explicit "
                "override variables, not by putting it on PATH: PATH decides "
                "what every helper of every helper resolves to, and it must not "
                "decide which binary answers a security question")


# --------------------------------------------------------------------------- #
# O1 -- two workers
# --------------------------------------------------------------------------- #
def probe_worker_lock_admits_one(bench, report):
    name = "O1-worker-lock-admits-exactly-one-consumer"
    bench.media_workspace("w1")
    store = bench.store()
    mission = bench.media_mission(store, "w1", "one queued mission, two workers")
    mid = mission["id"]
    env = bench.env()
    start_at = time.time() + 0.8
    outs = [bench.tmp / "worker-a.json", bench.tmp / "worker-b.json"]
    procs = [_fork(_worker_child, env, str(path), start_at) for path in outs]
    for proc in procs:
        proc.join(300)
    records = [_read(path, {}) for path in outs]
    row = store.get(mid)
    events = [e["event"] for e in store.events(mid)]
    sessions = store.sessions(mid)
    running_events = events.count("running")
    elapsed = sorted(round(r.get("left_at", 0) - r.get("entered_at", 0), 3)
                     for r in records)
    passed = (running_events == 1 and row["attempt"] == 1
              and row["state"] in ("waiting-review", "failed")
              and all(r.get("outcome") == "returned" for r in records))
    report(name,
           "two REAL worker processes start on one state root at the same "
           "instant with one queued mission; exactly one 'running' event exists, "
           "the mission is on attempt 1, and it has exactly one set of agent "
           "sessions -- no window in which both consumed it",
           f"worker records: {json.dumps(records, sort_keys=True)}\n"
           f"held for (seconds, sorted): {elapsed}\n"
           f"mission state {row['state']}, attempt {row['attempt']}\n"
           f"'running' events: {running_events}   agent sessions: {len(sessions)}\n"
           f"events: {events}",
           passed,
           note=("worker.lock (flock LOCK_EX|LOCK_NB over "
                 "<state root>/worker.lock) admitted one consumer; the other "
                 "returned without touching the queue"
                 if passed else
                 "the queue was consumed more than once, or not at all"))


def probe_losing_worker_is_silent(bench, report):
    name = "O1-the-losing-worker-exits-zero-in-silence"
    bench.media_workspace("w2")
    store = bench.store()
    bench.media_mission(store, "w2", "held queue")
    env = bench.env()
    signal_path = bench.tmp / "w2-held.flag"
    release_path = bench.tmp / "w2-release.flag"
    holder_out = bench.tmp / "w2-holder.json"
    # Take worker.lock the way a running worker does: the same file, the same
    # mode. A second worker STARTED here would consume the queue and the probe
    # would be measuring an execution rather than a refusal.
    handle = (store.root / "worker.lock").open("a")
    import fcntl
    fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        result = bench.cli("--json", "worker", "--once", env=env, timeout=120)
    finally:
        fcntl.flock(handle, fcntl.LOCK_UN)
        handle.close()
    for path in (signal_path, release_path, holder_out):
        path.unlink(missing_ok=True)
    queued = [m["id"] for m in store.list(states=("queued",))]
    passed = (result.returncode == 0 and result.stdout.strip() == ""
              and len(queued) == 1)
    report(name,
           "with worker.lock already held, a second `shadowfetch-missions "
           "worker --once` leaves the queue untouched -- and reports that by "
           "exiting 0 with no output at all",
           f"$ shadowfetch-missions --json worker --once   (rc="
           f"{result.returncode})\n"
           f"stdout: {result.stdout!r}\n"
           f"stderr: {result.stderr[-300:]!r}\n"
           f"still queued afterwards: {queued}",
           passed,
           note="the SAFETY property holds -- the queue was not consumed twice. "
                "The REPORTING does not: exit 0 and an empty stdout is what a "
                "worker that did all its work also returns, so a supervisor, a "
                "systemd unit or an operator cannot tell 'idle' from 'refused "
                "because another worker owns this state root'. Recorded as "
                "observed, not as a control")


def probe_worker_lock_scope(bench, report):
    name = "O1-worker-lock-is-scoped-to-one-state-root"
    bench.media_workspace("w3")
    first = bench.store()
    second_root = bench.tmp / "state-b"
    second = bench.store(second_root)
    import fcntl
    handle = (first.root / "worker.lock").open("a")
    fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    other = (second.root / "worker.lock").open("a")
    taken, error = True, None
    try:
        fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        taken, error = False, repr(exc)
    finally:
        with contextlib.suppress(OSError):
            fcntl.flock(other, fcntl.LOCK_UN)
        other.close()
        fcntl.flock(handle, fcntl.LOCK_UN)
        handle.close()
    passed = taken
    report(name,
           "the second worker.lock is a DIFFERENT FILE under a different state "
           "root, so holding the first excludes nothing: the claim 'one worker "
           "at a time' is scoped to one SHADOWFETCH_MISSIONS_STATE and to "
           "nothing wider",
           f"first  worker.lock: {first.root / 'worker.lock'}  (held)\n"
           f"second worker.lock: {second.root / 'worker.lock'}\n"
           f"second acquisition: {'ACQUIRED' if taken else 'blocked ' + str(error)}",
           passed,
           note="this is the extent of the guarantee, measured. Two agents that "
                "do not share a state root are not serialized by worker.lock at "
                "all -- see O1-two-state-roots-share-no-workspace-lock for what "
                "that means for a workspace")


def probe_two_state_roots_no_workspace_lock(bench, report):
    name = "O1-two-state-roots-share-no-workspace-lock"
    workspace = bench.media_workspace("w4")
    bench.store()
    bench.store(bench.tmp / "state-c")
    start_at = time.time() + 0.8
    outs = [bench.tmp / "root-a.json", bench.tmp / "root-b.json"]
    envs = [bench.env(),
            bench.env(SHADOWFETCH_MISSIONS_STATE=str(bench.tmp / "state-c"))]
    procs = [_fork(_lock_window_child, env, str(workspace), start_at, 0.7, str(path))
             for env, path in zip(envs, outs)]
    for proc in procs:
        proc.join(120)
    records = [_read(path, {}) for path in outs]
    spans = [(r.get("entered_at"), r.get("left_at")) for r in records]
    if any(None in span for span in spans):
        report(name,
               "two callers with different state roots contend for ONE workspace",
               json.dumps(records, indent=2, sort_keys=True), False,
               note="one caller never entered, so nothing was measured")
        return
    shared = span_overlap(*spans)
    passed = shared > 0
    report(name,
           "two callers whose only difference is SHADOWFETCH_MISSIONS_STATE hold "
           "the execution lock for the SAME workspace at the SAME time -- "
           "measured overlap, not two successes in a row",
           json.dumps(records, indent=2, sort_keys=True)
           + f"\noverlap = {shared:.6f}s "
             f"(entered {spans[0][0]:.6f} / {spans[1][0]:.6f}, "
             f"left {spans[0][1]:.6f} / {spans[1][1]:.6f})",
           passed,
           note="NOT ENFORCED, and this record exists to say so plainly. "
                "Store.lock_path() puts execution-<digest>.lock inside the STATE "
                "root while the workspace lives under the WORKSPACE root, so two "
                "state roots produce two lock files for one directory. The "
                "checkpoint engine still serializes its own snapshot and undo "
                "per workspace (O3-checkpoint-stores-do-not-share-a-namespace), "
                "and undo still refuses a workspace that changed underneath it "
                "-- but the agents' own writes are not serialized by anything")


# --------------------------------------------------------------------------- #
# O2 -- a CLI run and a worker
# --------------------------------------------------------------------------- #
def probe_cli_refused_under_worker(bench, report):
    name = "O2-cli-run-is-refused-while-a-worker-holds-the-workspace"
    workspace = bench.media_workspace("w5")
    store = bench.store()
    victim = bench.media_mission(store, "w5", "cli run under a held workspace")
    mid = victim["id"]
    env = bench.env()
    signal_path = bench.tmp / "w5-held.flag"
    release_path = bench.tmp / "w5-release.flag"
    out_path = bench.tmp / "w5-holder.json"
    proc = _fork(_hold_workspace_child, env, str(workspace), str(signal_path),
                 str(release_path), str(out_path))
    held = _await_file(signal_path, 30) and signal_path.read_text() == "held"

    def snapshot():
        chain = store.verify_chain()
        return {"row": store.get(mid),
                "events": [e["event"] for e in store.events(mid)],
                "sessions": len(store.sessions(mid)),
                "chain": {k: chain[k] for k in ("ok", "events", "head_seq")}}

    before = snapshot() if held else None
    result = bench.cli("--json", "run", mid, env=env, timeout=120) if held else None
    after = snapshot() if held else None
    release_path.write_text("go")
    proc.join(120)
    if not held:
        report(name, "the holder takes the workspace lock so a refusal can be "
                     "provoked",
               f"holder record: {_read(out_path, '(none written)')}", False,
               note="the contention never happened, so nothing was measured")
        return
    answer = json.loads(result.stdout or "{}")
    refused = "Another mission is executing on" in (answer.get("error") or "")
    passed = refused and result.returncode == 1 and before == after
    report(name,
           "the REAL CLI `run` shares execution.lock with the worker: it is "
           "refused while another caller holds the workspace, and leaves the "
           "mission row, its events, its sessions and the audit chain identical",
           f"$ shadowfetch-missions --json run {mid}   (rc={result.returncode})\n"
           f"stdout: {result.stdout.strip()[:300]}\n"
           f"before: {json.dumps(before, sort_keys=True, default=str)}\n"
           f"after:  {json.dumps(after, sort_keys=True, default=str)}\n"
           f"identical: {before == after}",
           passed,
           note=("the CLI path goes through run_mission(), which takes "
                 "store.lock(workspace=...) with wait_seconds=0 -- so the refusal "
                 "is immediate and inert"
                 if passed else
                 "the CLI was not cleanly refused; see the two snapshots"))


def _scope_sampler(stop, samples):
    """Poll systemd for the SET of live Firebreak scopes.

    The session records say when each sandbox began and ended; this says which
    cgroups systemd itself had at one moment. Two different witnesses, because
    "the timestamps overlap" and "the kernel was running both" are different
    claims and only the second is about the machine.

    The SET, not the count. A count of two is not evidence of two missions: a
    --collect scope can still be listed while it is being torn down, so one
    mission's consecutive sandboxes appear together at a sample boundary. Only
    a sample holding units belonging to two DIFFERENT missions says anything.
    """
    while not stop.is_set():
        result = subprocess.run(
            [SYSTEMCTL, "--user", "list-units", "--type=scope", "--no-legend",
             "--plain", "--state=active", "sess-*.scope"],
            capture_output=True, text=True,
            env={"PATH": TRUSTED_PATH, "HOME": os.environ.get("HOME", "/tmp"),
                 "XDG_RUNTIME_DIR": os.environ.get(
                     "XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")})
        samples.append(frozenset(line.split()[0]
                                 for line in result.stdout.splitlines() if line.strip()))
        time.sleep(0.05)


def probe_cli_and_worker_run_at_once(bench, report):
    name = "O2-cli-and-worker-execute-at-once-on-different-workspaces"
    bench.media_workspace("w6a", seconds=45, size="854x480")
    bench.media_workspace("w6b", seconds=45, size="854x480")
    store = bench.store()
    queued = bench.media_mission(store, "w6a", "consumed by the worker")
    env = bench.env()
    stop, samples = threading.Event(), []
    sampler = threading.Thread(target=_scope_sampler, args=(stop, samples),
                               daemon=True)
    sampler.start()
    started = time.time()
    # ORDER MATTERS, and getting it wrong measures nothing. Both started at
    # once, the worker's single queue read picks up the CLI's mission too, and
    # one caller simply loses the race for it: the two then run in sequence and
    # the probe reports no overlap while claiming to be about overlap. The
    # worker also has several seconds of interpreter and registry startup, which
    # is the same order as a mission -- so the SLOW starter goes first, and the
    # CLI's mission is not created until the worker has already read its queue
    # and started work.
    worker_proc = subprocess.Popen(
        [sys.executable, str(MISSIONS_CLI), "--json", "worker", "--once"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=dict(env))
    deadline = time.time() + 120
    while time.time() < deadline and not store.sessions(queued["id"]):
        time.sleep(0.01)
    worker_running_at = time.time()
    direct = bench.media_mission(store, "w6b", "run by the CLI")
    cli_proc = subprocess.Popen(
        [sys.executable, str(MISSIONS_CLI), "--json", "run", direct["id"]],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=dict(env))
    cli_out = cli_proc.communicate(timeout=900)
    worker_out = worker_proc.communicate(timeout=900)
    finished = time.time()
    stop.set()
    sampler.join(5)
    sessions = bench.firebreak_sessions()
    left = windows_for(sessions, queued["id"])
    right = windows_for(sessions, direct["id"])
    shared, a_sid, b_sid = best_overlap(left, right)
    unit_owner = {entry["scope_unit"]: entry["mission"]
                  for entry in sessions.values() if entry.get("scope_unit")}
    both_live = [sorted(sample) for sample in samples
                 if len({unit_owner.get(unit) for unit in sample}
                        & {queued["id"], direct["id"]}) == 2]
    scopes = sorted({entry["scope_unit"] for entry in sessions.values()
                     if entry.get("mission") in (queued["id"], direct["id"])})
    rows = {m: store.get(m)["state"] for m in (queued["id"], direct["id"])}
    passed = (shared > 0 and len(left) >= 1 and len(right) >= 1
              and len(scopes) == len(left) + len(right)
              and bool(both_live)
              and rows[queued["id"]] == "waiting-review"
              and rows[direct["id"]] == "waiting-review")
    report(name,
           "a worker consuming its queue and a CLI `run` on a different "
           "workspace are inside Firebreak AT THE SAME INSTANT -- measured "
           "twice: from Firebreak's own microsecond session records, and from "
           "systemd's live list of scope units",
           f"worker rc={worker_proc.returncode} cli rc={cli_proc.returncode}; "
           f"wall {finished - started:.2f}s\n"
           f"mission {queued['id'][:20]} sandbox windows: "
           f"{[(round(s, 6), round(e, 6)) for s, e, _ in left]}\n"
           f"mission {direct['id'][:20]} sandbox windows: "
           f"{[(round(s, 6), round(e, 6)) for s, e, _ in right]}\n"
           f"largest overlap = {shared:.6f}s between {a_sid} and {b_sid}\n"
           f"the CLI was started {worker_running_at - started:.2f}s in, once the "
           f"worker had opened its first sandbox\n"
           f"samples in which systemd held scopes belonging to BOTH missions: "
           f"{len(both_live)} of {len(samples)} (50 ms apart); "
           f"first such sample: {both_live[0] if both_live else 'none'}\n"
           f"distinct scope units recorded by the two missions: {len(scopes)}\n"
           f"final states: {rows}\n"
           f"cli stdout: {cli_out[0].strip()[:120]}\n"
           f"worker stderr: {worker_out[1][-200:]!r}",
           passed,
           note="capabilities() reports max_parallel: 1. That is TRUE of one "
                "worker process and FALSE of the system: the CLI never takes "
                "worker.lock, so the real concurrency ceiling is the number of "
                "callers, and each concurrent sandbox gets its OWN systemd scope "
                "with its own MemoryMax and TasksMax. Two callers is therefore "
                "twice the declared memory ceiling, not the same one shared")


def probe_same_mission_twice(bench, report):
    name = "O2-the-same-mission-cannot-be-started-twice"
    bench.media_workspace("w7")
    store = bench.store()
    mission = bench.media_mission(store, "w7", "two callers, one mission")
    mid = mission["id"]
    env = bench.env()
    start_at = time.time() + 0.8
    outs = [bench.tmp / "same-a.json", bench.tmp / "same-b.json"]
    procs = [_fork(_run_mission_child, env, mid, str(path), start_at)
             for path in outs]
    for proc in procs:
        proc.join(300)
    records = [_read(path, {}) for path in outs]
    ran = [r for r in records if r.get("outcome") == "ran"]
    refused = [r for r in records if r.get("outcome") == "refused"]
    events = [e["event"] for e in store.events(mid)]
    row = store.get(mid)
    passed = (len(ran) == 1 and len(refused) == 1
              and events.count("running") == 1 and row["attempt"] == 1)
    reasons = sorted({r.get("error", "") for r in refused})
    report(name,
           "two processes call the real run_mission() on ONE mission at the same "
           "instant; exactly one runs it, the other is refused, and the mission "
           "records exactly one attempt and one 'running' event",
           json.dumps(records, indent=2, sort_keys=True)
           + f"\nrefusal: {reasons}\n"
             f"attempt {row['attempt']}, state {row['state']}, "
             f"'running' events {events.count('running')}",
           passed,
           note=("two layers refuse this and either alone would: the per-workspace "
                 "execution lock, and transition(expect=queued), which is a "
                 "compare-and-swap inside BEGIN IMMEDIATE"
                 if passed else
                 "the mission was started twice, or neither caller started it"))


def probe_transition_is_cas(bench, report):
    name = "O2-the-state-transition-is-a-compare-and-swap"
    bench.media_workspace("w8")
    store = bench.store()
    mission = bench.media_mission(store, "w8", "eight callers, no lock")
    mid = mission["id"]
    env = bench.env()
    start_at = time.time() + 0.8
    outs = [bench.tmp / f"cas-{index}.json" for index in range(8)]
    procs = [_fork(_transition_child, env, mid, start_at, str(path))
             for path in outs]
    for proc in procs:
        proc.join(120)
    records = [_read(path, {}) for path in outs]
    won = [r for r in records if r.get("outcome") == "won"]
    events = [e["event"] for e in store.events(mid)]
    chain = store.verify_chain()
    passed = (len(won) == 1 and events.count("running") == 1
              and store.get(mid)["state"] == "running" and chain["ok"])
    report(name,
           "eight processes race transition(mid, running, expect=queued) with NO "
           "execution lock between them; SQLite admits exactly one, seven are "
           "refused, and the chain stays intact",
           f"outcomes: {[r.get('outcome') for r in records]}\n"
           f"winners: {len(won)}   refusals: "
           f"{sorted({r.get('error', '')[:90] for r in records if r.get('outcome') != 'won'})}\n"
           f"'running' events: {events.count('running')}   "
           f"final state: {store.get(mid)['state']}\n"
           f"chain ok={chain['ok']} events={chain['events']} "
           f"head_seq={chain['head_seq']}",
           passed,
           note="this is the layer BELOW the flock, and the one that still holds "
                "when two callers do not share a lock file: the row is read and "
                "written inside one BEGIN IMMEDIATE transaction, so 'queued -> "
                "running' is atomic against every other connection to that "
                "database")


# --------------------------------------------------------------------------- #
# O3 -- two workspaces, two callers
# --------------------------------------------------------------------------- #
def concurrent_pair(bench):
    """Run two missions in two workspaces from two processes, ONCE per bench.

    Three probes read this one event -- the sandboxes, the checkpoint stores and
    the audit chain -- and they have to be reading the SAME event: a chain
    interleaving measured on a different pair from the one whose sandboxes were
    measured would not be evidence about either. Cached rather than sequenced,
    so running one probe by name still measures a real concurrent pair instead
    of reporting that an earlier probe was skipped.
    """
    if "pair" in _MEASURED:
        return _MEASURED["pair"]
    alpha = bench.media_workspace("w9a")
    beta = bench.media_workspace("w9b")
    store = bench.store()
    first = bench.media_mission(store, "w9a", "concurrent alpha")
    second = bench.media_mission(store, "w9b", "concurrent beta")
    env = bench.env()
    start_at = time.time() + 0.8
    outs = [bench.tmp / "pair-a.json", bench.tmp / "pair-b.json"]
    procs = [_fork(_run_mission_child, env, mission["id"], str(path), start_at)
             for mission, path in zip((first, second), outs)]
    for proc in procs:
        proc.join(600)
    _MEASURED["pair"] = {
        "first": first["id"], "second": second["id"],
        "alpha": str(alpha), "beta": str(beta),
        "records": [_read(path, {}) for path in outs],
    }
    return _MEASURED["pair"]


def probe_separate_sandboxes(bench, report):
    name = "O3-concurrent-missions-keep-separate-sandboxes-and-scopes"
    pair = concurrent_pair(bench)
    store = bench.store()
    alpha, beta = Path(pair["alpha"]), Path(pair["beta"])
    first = {"id": pair["first"]}
    second = {"id": pair["second"]}
    records = pair["records"]
    sessions = bench.firebreak_sessions()
    left = windows_for(sessions, first["id"])
    right = windows_for(sessions, second["id"])
    shared, a_sid, b_sid = best_overlap(left, right)
    mine = {sid: entry for sid, entry in sessions.items()
            if entry.get("mission") in (first["id"], second["id"])}
    scopes = {entry["scope_unit"] for entry in mine.values()}
    workspaces = {entry["mission"]: entry["workspace"] for entry in mine.values()}
    db_sessions = {first["id"]: store.sessions(first["id"]),
                   second["id"]: store.sessions(second["id"])}
    crossed = [sid for sid, entry in mine.items()
               if (entry["mission"] == first["id"]) != (str(alpha) == entry["workspace"])]
    passed = (shared > 0 and len(scopes) == len(mine) and not crossed
              and len(set(mine)) == len(mine)
              and all(len(rows) >= 1 for rows in db_sessions.values()))
    report(name,
           "two missions run at once by two processes in two workspaces: their "
           "Firebreak sessions, their systemd scope units and their recorded "
           "agent-session rows are disjoint, and each sandbox saw only its own "
           "workspace",
           json.dumps(records, indent=2, sort_keys=True)
           + f"\nlargest sandbox overlap = {shared:.6f}s "
             f"between {a_sid} and {b_sid}\n"
             f"firebreak sessions: {len(mine)}   distinct scope units: {len(scopes)}\n"
             f"workspace per mission: {json.dumps(workspaces, sort_keys=True)}\n"
             f"agent_sessions rows: "
             f"{ {m: len(rows) for m, rows in db_sessions.items()} }\n"
             f"sessions attributed to the wrong workspace: {crossed}",
           passed,
           note="separation here is structural, not a consequence of the worker "
                "being single-threaded: the session id is minted per invocation, "
                "the systemd scope is named after it, and the bind mount is the "
                "mission's own workspace. Nothing about it depends on there "
                "being one consumer")


def probe_checkpoint_namespaces(bench, report):
    name = "O3-checkpoint-stores-do-not-share-a-namespace"
    pair = concurrent_pair(bench)
    first, second, beta = pair["first"], pair["second"], pair["beta"]
    alpha = pair["alpha"]
    store = bench.store()
    root = Path(os.environ["SHADOWFETCH_AGENT_WORKSPACES"])
    stores = {ws.name: sorted(p.name for p in (root / ".sf-checkpoints" / ws.name).glob("*.json"))
              for ws in (Path(alpha), Path(beta))}
    ids = {first: store.get(first)["checkpoint"], second: store.get(second)["checkpoint"]}
    module = bench.sf.checkpoint_module()
    # The engine's own answer, asked for the WRONG workspace: alpha's recovery
    # point offered to beta.
    crossed, crossed_error = None, None
    try:
        crossed = module.checkpoint_call("diff", workspace=Path(beta).name,
                                         checkpoint=ids[first])
    except Exception as exc:                                       # noqa: BLE001
        crossed_error = f"{type(exc).__name__}: {exc}"
    # Globbed by shape rather than by the engine's private side-car name: a
    # copied constant would go stale silently and report "no locks" about a
    # directory that has them.
    lock_paths = sorted(str(p) for p in (root / ".sf-checkpoints").glob("*/*/lock"))
    passed = (ids[first] and ids[second] and ids[first] != ids[second]
              and crossed is None and crossed_error is not None
              and len(stores) == 2 and all(stores.values()))
    report(name,
           "each workspace has its own checkpoint store on disk and its own "
           "checkpoint lock; a recovery point taken in one workspace is not even "
           "addressable from the other",
           f"checkpoint ids: {json.dumps(ids, sort_keys=True)}\n"
           f"stores under {root / '.sf-checkpoints'}: "
           f"{json.dumps(stores, sort_keys=True)}\n"
           f"checkpoint_call('diff', workspace={Path(beta).name!r}, "
           f"checkpoint={ids[first]!r}) -> {crossed_error or crossed}\n"
           f"per-workspace checkpoint locks: {lock_paths}",
           passed,
           note="the namespace is the FILESYSTEM: _ckpt_store() is "
                "<workspace root>/.sf-checkpoints/<workspace name>, so a "
                "checkpoint id is only meaningful inside the workspace that "
                "produced it. The lock beside it is per workspace too, so an "
                "undo and a snapshot on one workspace serialize even when the "
                "callers share no Mission Control state root")


def probe_shared_chain(bench, report):
    name = "O3-the-audit-chain-is-shared-not-separate"
    pair = concurrent_pair(bench)
    first, second = pair["first"], pair["second"]
    store = bench.store()
    with store.db() as db:
        rows = [dict(r) for r in db.execute(
            "SELECT seq, mission, event FROM events ORDER BY seq")]
    pair_rows = [r for r in rows if r["mission"] in (first, second)]
    switches = sum(1 for a, b in zip(pair_rows, pair_rows[1:])
                   if a["mission"] != b["mission"])
    chain = store.verify_chain()
    genesis = [r for r in rows if r["event"] == bench.sf.CHAIN_GENESIS]
    seqs = [r["seq"] for r in rows]
    contiguous = seqs == list(range(min(seqs), max(seqs) + 1))
    passed = (chain["ok"] and contiguous and len(genesis) == 1
              and switches > 0 and chain["unchained"] == 0)
    report(name,
           "the two concurrent missions wrote into ONE hash chain, interleaved, "
           "and it verifies: one genesis, contiguous sequence numbers, no "
           "unchained rows",
           f"total events {len(rows)}; rows belonging to the pair "
           f"{len(pair_rows)}\n"
           f"mission changes from one row to the next within the pair: {switches}\n"
           f"first twelve interleaved rows: "
           f"{[(r['seq'], r['mission'][-6:], r['event']) for r in pair_rows[:12]]}\n"
           f"genesis rows: {len(genesis)}   contiguous seq: {contiguous}\n"
           f"verify_chain: ok={chain['ok']} events={chain['events']} "
           f"chained={chain['chained']} unchained={chain['unchained']} "
           f"head_seq={chain['head_seq']}\n"
           f"problems: {chain['problems']}",
           passed,
           note="this is the one thing that is NOT separated per caller, and it "
                "is deliberate: a per-mission chain could be truncated one "
                "mission at a time. The cost is that every concurrent caller "
                "contends for the same write lock, and that a chain broken by "
                "any caller is broken for all of them")


def probe_workspace_cannot_be_aliased(bench, report):
    name = "O3-a-workspace-cannot-be-aliased-into-a-second-lock"
    real = bench.media_workspace("w10")
    root = Path(os.environ["SHADOWFETCH_AGENT_WORKSPACES"])
    alias = root / "w10-alias"
    if not alias.exists():
        alias.symlink_to(real)
    nested = real / "inner"
    nested.mkdir(exist_ok=True)
    store = bench.store()
    attempts = {}
    for label, value in (("symlink alias", "w10-alias"),
                         ("nested directory", str(nested)),
                         ("parent traversal", str(root / "w10" / ".." / "w10"))):
        try:
            attempts[label] = "ACCEPTED -> " + str(bench.sf.workspace(value))
        except Exception as exc:                                   # noqa: BLE001
            attempts[label] = f"refused: {type(exc).__name__}: {exc}"
    spellings = ["w10", str(real), str(real) + "/", str(root / "w10" / ".." / "w10")]
    lock_paths, lock_errors = set(), []
    for spelling in spellings:
        try:
            lock_paths.add(str(store.lock_path(spelling)[0]))
        except Exception as exc:                                   # noqa: BLE001
            lock_errors.append(f"{spelling}: {type(exc).__name__}: {exc}")
    tamper = None
    try:
        store.update(bench.media_mission(store, "w10", "alias probe")["id"],
                     workspace=str(root / "w10-alias"))
        tamper = "ACCEPTED"
    except Exception as exc:                                       # noqa: BLE001
        tamper = f"refused: {type(exc).__name__}: {exc}"
    passed = ("refused" in attempts["symlink alias"]
              and "refused" in attempts["nested directory"]
              and len(lock_paths) == 1 and not lock_errors
              and tamper.startswith("refused"))
    report(name,
           "a workspace cannot be spelled two ways into two lock files: an "
           "alias and a nested path are refused outright, every legal spelling "
           "of one workspace hashes to ONE lock file, and Store.update() will "
           "not repoint a mission's workspace at all",
           f"workspace() attempts: {json.dumps(attempts, indent=2, sort_keys=True)}\n"
           f"lock_path() over {len(spellings)} spellings -> {sorted(lock_paths)}\n"
           f"lock_path errors: {lock_errors}\n"
           f"Store.update(workspace=<alias>): {tamper}",
           passed,
           note="lock_path() hashes the RESOLVED path, and workspace() refuses a "
                "symlink and anything that is not a direct child of the "
                "workspace root -- so 'two locks for one directory' cannot be "
                "reached by naming, only by using two state roots")


def _tree_digest(root):
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()[:16]
            for p in sorted(Path(root).rglob("*")) if p.is_file()}


def probe_undo_cannot_be_redirected(bench, report):
    name = "O3-undo-cannot-be-redirected-onto-another-workspace"
    alpha = bench.media_workspace("w11a")
    beta = bench.media_workspace("w11b")
    root = Path(os.environ["SHADOWFETCH_AGENT_WORKSPACES"])
    store = bench.store()
    older = bench.media_mission(store, "w11a", "undo source")
    newer = bench.media_mission(store, "w11b", "undo target")
    bench.sf.run_mission(store, older["id"])
    bench.sf.run_mission(store, newer["id"])

    # THE ATTACK, three times, because there are three separate things in the
    # way and a single attempt only ever measures the first of them. The
    # workspace column is repointed straight in SQL: Store.update() refuses the
    # field, so nothing short of database access reaches this at all.
    def redirect(mission_id, target):
        with sqlite3.connect(store.db_path) as db:
            db.execute("UPDATE missions SET workspace=? WHERE id=?",
                       (str(target), mission_id))
        try:
            return "RESTORED " + str(bench.sf.review(store, mission_id, "undo"))
        except Exception as exc:                                   # noqa: BLE001
            return f"refused: {type(exc).__name__}: {exc}"

    attempts, damage = {}, {}
    # 1. The OLDER mission redirected forward onto a workspace that has since
    #    been written by a newer mission.
    before = _tree_digest(beta)
    attempts["older onto a written workspace"] = redirect(older["id"], beta)
    damage["older onto a written workspace"] = before == _tree_digest(beta)

    # 2. The NEWEST mission redirected sideways. Nothing is newer than it, so
    #    the "undo newer missions first" guard has nothing to say and the next
    #    layer down -- the recorded after-index -- is what has to hold.
    before = _tree_digest(alpha)
    attempts["newest onto a different workspace"] = redirect(newer["id"], alpha)
    damage["newest onto a different workspace"] = before == _tree_digest(alpha)

    # 3. The sharpest version: a target workspace built to be BYTE-IDENTICAL to
    #    the one this mission actually left, so the after-index comparison
    #    matches and stops being a defence. What is left underneath it is the
    #    checkpoint engine's own namespace.
    gamma = root / "w11c"
    shutil.copytree(beta, gamma)
    index_path = store.directory(newer["id"]) / "after-index.json"
    indices_match = (json.loads(index_path.read_text())
                     == bench.sf.recovery_index(gamma))
    before = _tree_digest(gamma)
    attempts["onto a byte-identical clone"] = redirect(newer["id"], gamma)
    damage["onto a byte-identical clone"] = before == _tree_digest(gamma)

    chain = store.verify_chain()
    created = next((e for e in store.events(older["id"])
                    if e["event"] == "queued"), None)
    states = {older["id"]: store.get(older["id"])["state"],
              newer["id"]: store.get(newer["id"])["state"]}
    passed = (all(v.startswith("refused") for v in attempts.values())
              and all(damage.values()) and indices_match
              and str(alpha) in (created or {}).get("detail", "")
              and set(states.values()) == {"waiting-review"})
    report(name,
           "a mission whose workspace column has been repointed at ANOTHER "
           "workspace cannot undo into it -- including when the target is a "
           "byte-identical clone built specifically to satisfy the index check. "
           "Every target workspace is unchanged afterwards",
           "\n".join(f"{label}:\n    {answer}\n    target unchanged: "
                     f"{damage[label]}"
                     for label, answer in attempts.items())
           + f"\nthe clone's recovery index equals the mission's recorded "
             f"after-index: {indices_match}\n"
             f"mission states afterwards: {json.dumps(states, sort_keys=True)}\n"
             f"the chained 'queued' event still names the ORIGINAL workspace: "
             f"{(created or {}).get('detail')}\n"
             f"audit verify after three tampers: ok={chain['ok']} "
             f"problems={chain['problems']}",
           passed,
           note="three independent layers, and the third is the one that matters "
                "for a byte-identical clone: the recovery id lives in "
                "<workspace root>/.sf-checkpoints/<workspace name>/, so it is "
                "not addressable from another workspace at all. What is NOT "
                "enforced: `audit verify` reports the log intact after all three "
                "tampers. The chained 'queued' event records the workspace the "
                "mission was created for, and nothing ever compares it with the "
                "mutable column -- so a redirected mission is refused at the "
                "point of use but is not DETECTED as tampering")


# --------------------------------------------------------------------------- #
# O4 -- the audit chain under concurrency
# --------------------------------------------------------------------------- #
def probe_racing_appends(bench, report):
    name = "O4-racing-appends-never-fork-the-chain"
    bench.media_workspace("w12")
    store = bench.store()
    mission = bench.media_mission(store, "w12", "chain contention")
    mid = mission["id"]
    env = bench.env()
    writers, each = 8, 25
    start_at = time.time() + 1.0
    outs = [bench.tmp / f"append-{index}.json" for index in range(writers)]
    began = time.time()
    procs = [_fork(_append_child, env, mid, each, start_at, str(path))
             for path in outs]
    for proc in procs:
        proc.join(300)
    elapsed = time.time() - began - (start_at - began)
    records = [_read(path, {}) for path in outs]
    appended = sum(r.get("appended", 0) for r in records)
    with store.db() as db:
        rows = [dict(r) for r in db.execute(
            "SELECT seq, prev_hash, hash, event FROM events ORDER BY seq")]
    mine = [r for r in rows if r["event"] == "stage-o-append"]
    seqs = [r["seq"] for r in rows]
    contiguous = seqs == list(range(1, len(seqs) + 1))
    prevs = [r["prev_hash"] for r in rows if r["prev_hash"]]
    forks = len(prevs) - len(set(prevs))
    chain = store.verify_chain()
    passed = (appended == writers * each and len(mine) == writers * each
              and contiguous and forks == 0 and chain["ok"])
    report(name,
           f"{writers} processes append {each} events each into ONE chain at the "
           "same instant; every append lands, sequence numbers are contiguous, "
           "no two rows share a prev_hash, and verify_chain() reports the chain "
           "intact",
           f"writers reported appended: {appended} of {writers * each}\n"
           f"rows with event 'stage-o-append': {len(mine)}\n"
           f"total rows {len(rows)}; contiguous seq 1..{len(seqs)}: {contiguous}\n"
           f"duplicate prev_hash values (a fork): {forks}\n"
           f"verify_chain: ok={chain['ok']} chained={chain['chained']} "
           f"unchained={chain['unchained']} head_seq={chain['head_seq']}\n"
           f"problems: {chain['problems']}\n"
           f"wall time for {writers * each} contended appends: {elapsed:.3f}s "
           f"({elapsed / (writers * each) * 1000:.2f} ms/append)",
           passed,
           note="append_event() opens BEGIN IMMEDIATE before it reads the head, "
                "so 'read the head, hash against it, insert' is one atomic step "
                "against every other connection. Two appends that both read the "
                "same head would be a fork; that is what the duplicate-prev_hash "
                "count is looking for, and it is the direct measurement of the "
                "property rather than a re-reading of verify()'s verdict")


def probe_injected_fork(bench, report):
    name = "O4-an-injected-fork-is-detected"
    root = bench.tmp / "state-fork"
    store = bench.store(root)
    for index in range(5):
        store.append_event("mission-forkprobe", "stage-o-fork", f"row {index}")
    clean = store.verify_chain()
    with store.db() as db:
        rows = [dict(r) for r in db.execute(
            "SELECT seq, prev_hash, hash, mission, at, event, detail, actor, "
            "task_id, session_id, tool_execution_id, record_sha256 "
            "FROM events ORDER BY seq")]
    head, forked_from = rows[-1], rows[-3]
    # A fork is exactly this: a second row whose prev_hash is a hash that another
    # row already claimed. Written straight into the table, because the engine
    # cannot be made to produce one.
    forged = dict(head)
    forged["seq"] = head["seq"] + 1
    forged["prev_hash"] = forked_from["prev_hash"]
    forged["event"] = "stage-o-forged"
    forged["detail"] = "a second row claiming an already-claimed predecessor"
    forged["hash"] = bench.sf.event_hash(forged["prev_hash"], forged)
    with sqlite3.connect(store.db_path) as db:
        db.execute(
            "INSERT INTO events(seq,mission,at,event,detail,task_id,session_id,"
            "tool_execution_id,actor,prev_hash,hash,record_sha256) "
            "VALUES(:seq,:mission,:at,:event,:detail,:task_id,:session_id,"
            ":tool_execution_id,:actor,:prev_hash,:hash,:record_sha256)", forged)
    after = store.verify_chain()
    code = bench.sf.audit_exit_code(after)
    passed = (clean["ok"] and not after["ok"] and code != 0
              and any("prev_hash does not match" in p for p in after["problems"]))
    report(name,
           "a row whose prev_hash duplicates an earlier row's -- the exact shape "
           "two racing appends would produce -- is reported as a problem and "
           "changes the audit exit code",
           f"before the injection: ok={clean['ok']} events={clean['events']} "
           f"head_seq={clean['head_seq']}\n"
           f"injected seq {forged['seq']} with prev_hash of seq "
           f"{forked_from['seq']}\n"
           f"after: ok={after['ok']} events={after['events']} "
           f"head_seq={after['head_seq']}\n"
           f"problems: {after['problems']}\n"
           f"audit_exit_code -> {code}",
           passed,
           note="the detector is what makes the previous probe's zero mean "
                "something. A count of duplicate prev_hash values that is always "
                "zero because nothing could ever raise it would be a measurement "
                "of the query, not of the chain")


def probe_fresh_database_race(bench, report):
    name = "O4-two-processes-opening-a-fresh-database-at-once"
    root = bench.tmp / "state-fresh"
    env = bench.env(SHADOWFETCH_MISSIONS_STATE=str(root))
    start_at = time.time() + 1.0
    outs = [bench.tmp / f"open-{index}.json" for index in range(6)]
    procs = [_fork(_open_store_child, env, start_at, str(path)) for path in outs]
    for proc in procs:
        proc.join(120)
    records = [_read(path, {}) for path in outs]
    opened = [r for r in records if r.get("outcome") == "opened"]
    raised = [r for r in records if r.get("outcome") == "raised"]
    store = bench.store(root)
    with store.db() as db:
        genesis = [dict(r) for r in db.execute(
            "SELECT seq, detail FROM events WHERE event=? ORDER BY seq",
            (bench.sf.CHAIN_GENESIS,))]
        version = db.execute("PRAGMA user_version").fetchone()[0]
    chain = store.verify_chain()
    chain_ids = {json.loads(g["detail"]).get("chain_id") for g in genesis}
    reported = {r.get("chain_id") for r in opened}
    _MEASURED["fresh_open"] = records
    passed = (len(genesis) == 1 and len(chain_ids) == 1 and chain["ok"]
              and version == bench.sf.SCHEMA_VERSION
              and reported - {None} == chain_ids)
    report(name,
           "six processes construct Store() on a brand-new state root at the "
           "same instant -- the one window before any of them holds worker.lock "
           "or execution.lock. Exactly one chain genesis exists, every process "
           "that opened it agrees on the chain id, and the schema lands at the "
           "current version",
           f"outcomes: {[r.get('outcome') for r in records]}\n"
           f"errors: {sorted({r.get('error', '') for r in raised})}\n"
           f"genesis rows: {len(genesis)} at seq "
           f"{[g['seq'] for g in genesis]}\n"
           f"chain ids in the database: {sorted(x for x in chain_ids if x)}\n"
           f"chain ids the processes reported: {sorted(x for x in reported if x)}\n"
           f"PRAGMA user_version = {version} "
           f"(current {bench.sf.SCHEMA_VERSION})\n"
           f"verify_chain: ok={chain['ok']} events={chain['events']} "
           f"problems={chain['problems']}",
           passed,
           note="the INTEGRITY of the race is what this asserts, and it holds: a "
                "second genesis would give the database two chain ids, chain_id() "
                "takes the first, and every event mirrored under the other one "
                "would be unfindable in the journal for the life of the "
                "installation. What does NOT hold is availability -- "
                f"{len(raised)} of {len(records)} processes raised instead of "
                "opening it. That is the next probe, and it is a defect")


def probe_open_race_crashes(bench, report):
    name = "O4-a-caller-that-loses-the-open-race-gets-a-traceback"
    trials, results = 3, []
    for trial in range(trials):
        root = bench.tmp / f"state-cli-{trial}"
        env = bench.env(SHADOWFETCH_MISSIONS_STATE=str(root))
        env["HOME"] = os.environ.get("HOME", "/tmp")
        procs = [subprocess.Popen(
            [sys.executable, str(MISSIONS_CLI), "--json", "list"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env=dict(env)) for _ in range(6)]
        for proc in procs:
            out, err = proc.communicate(timeout=300)
            body = out.strip()
            parsed = None
            with contextlib.suppress(ValueError):
                parsed = json.loads(body) if body else None
            results.append({
                "rc": proc.returncode,
                "stdout_is_json": parsed is not None,
                "last_stderr_line": (err.strip().splitlines() or [""])[-1][:120],
            })
    broken = [r for r in results if not r["stdout_is_json"]]
    tracebacks = sorted({r["last_stderr_line"] for r in broken})
    passed = not broken
    report(name,
           "every caller that loses the first-open race is refused the way every "
           "other refusal in this engine is refused: a readable message on "
           "stdout as JSON, which is the contract the desktop client parses",
           f"{len(results)} concurrent `shadowfetch-missions --json list` "
           f"invocations over {trials} fresh state roots, six at a time\n"
           f"produced parseable JSON on stdout: "
           f"{len(results) - len(broken)} of {len(results)}\n"
           f"produced an empty stdout and a traceback: {len(broken)}\n"
           f"exit codes: {sorted({r['rc'] for r in results})}\n"
           f"the last line of stderr in each failure: {tracebacks}",
           passed,
           note="A DEFECT STAGE O FOUND, not a property being pinned. "
                "Store.db() runs `PRAGMA journal_mode=WAL` as its first "
                "statement, before it sets busy_timeout -- and SQLite does not "
                "invoke the busy handler for a journal-mode conversion, so a "
                "second opener gets SQLITE_BUSY immediately. main() catches "
                "(MissionError, ValueError, OSError); sqlite3.OperationalError "
                "is none of those, so it escapes as a traceback with empty "
                "stdout, and Mission Control's desktop client -- which parses "
                "stdout as JSON -- is handed nothing at all. Two systemd workers "
                "restarted together land exactly here. The exact anchor and "
                "replacement are in docs/MULTI_AGENT_SAFETY.md under BLOCKED")


# --------------------------------------------------------------------------- #
# O5 -- approvals under concurrency
# --------------------------------------------------------------------------- #
def probe_approval_not_transferable(bench, report):
    name = "O5-an-approval-is-not-transferable-between-missions"
    bench.media_workspace("w13")
    store = bench.store()
    first = bench.cloud_mission(store, "w13", "the approved one")
    second = bench.cloud_mission(store, "w13", "the unapproved one")
    decision, _ = bench.sf.mission_decision(store, first)
    other_decision, _ = bench.sf.mission_decision(store, second)
    aid = store.grant_approval(subject="mission:" + first["id"],
                               scope=decision.scope, granted_by="uid:0",
                               method="cli", reason="stage O")
    identical = decision.scope == other_decision.scope
    outcome, error = None, None
    try:
        bench.sf.require_approval(store, store.get(second["id"]))
        outcome = "ALLOWED"
    except Exception as exc:                                       # noqa: BLE001
        outcome = "refused"
        error = f"{type(exc).__name__}: {exc}"
    events = [e["event"] for e in store.events(second["id"])]
    passed = (outcome == "refused" and identical
              and "approval-required" in events
              and store.get(second["id"])["approval_id"] is None)
    report(name,
           "an approval granted for one mission does not cover a second mission "
           "with a BYTE-IDENTICAL scope: approvals are keyed by subject, and the "
           "second mission is left needing its own",
           f"approval {aid} granted for mission:{first['id']}\n"
           f"the two decisions have identical scopes: {identical}\n"
           f"  scope: {json.dumps(decision.scope.__dict__, sort_keys=True, default=str)}\n"
           f"require_approval(second) -> {outcome}: {error}\n"
           f"second mission events: {events}\n"
           f"second mission approval_id: {store.get(second['id'])['approval_id']}",
           passed,
           note="find_approval() selects rows by subject 'mission:<id>' before "
                "it ever compares a scope, so two callers running two missions "
                "cannot share one human decision even when the decisions are "
                "indistinguishable")


def probe_revoke_race(bench, report):
    name = "O5-a-revoke-never-lands-between-the-check-and-the-use"
    bench.media_workspace("w14")
    store = bench.store()
    env = bench.env()
    # SWEEP, not jitter. The first version of this probe spread 24 revokes over
    # the measured half-second the whole mission takes, found nothing, and
    # reported the invariant as holding. The window that matters is the gap
    # between the re-read committing and 'approval-used' being appended, which
    # is microseconds wide and sits a few milliseconds into the call -- so the
    # offsets have to be stepped at that scale or the probe is measuring its own
    # coarseness. 50 us steps across 6 ms.
    trials, step, points = 240, 0.00005, 120
    outcomes = []
    for trial in range(trials):
        mission = bench.cloud_mission(store, "w14", f"race {trial}")
        decision, _ = bench.sf.mission_decision(store, mission)
        aid = store.grant_approval(subject="mission:" + mission["id"],
                                   scope=decision.scope, granted_by="uid:0",
                                   method="cli")
        delay = (trial % points) * step
        out_path = bench.tmp / f"revoke-{trial}.json"
        proc = _fork(_revoke_child, env, aid, delay, str(out_path))
        result = None
        try:
            bench.sf.run_mission(store, mission["id"])
            result = "ran"
        except bench.sf.ApprovalRequired:
            result = "held for approval"
        except Exception as exc:                                   # noqa: BLE001
            result = f"refused: {type(exc).__name__}"
        proc.join(120)
        revoker = _read(out_path, {})
        # Store.events() does not return seq -- it selects at, event, detail --
        # and the SEQUENCE is the whole point here: the chain's total order is
        # what says whether "used" came before or after "revoked". Read from the
        # events table directly for that reason.
        with store.db() as db:
            seqs = {r["event"]: r["seq"] for r in db.execute(
                "SELECT seq, event FROM events WHERE mission=? AND event IN "
                "('approval-used','approval-required') ORDER BY seq",
                (mission["id"],))}
            revoked_seq = db.execute(
                "SELECT seq FROM events WHERE event='approval-revoked' AND "
                "detail LIKE ? ORDER BY seq LIMIT 1", (f'%{aid}%',)).fetchone()
        outcomes.append({
            "trial": trial, "delay_ms": round(delay * 1000, 3),
            "run": result, "revoke": revoker.get("outcome"),
            "used_seq": seqs.get("approval-used"),
            "required_seq": seqs.get("approval-required"),
            "revoked_seq": revoked_seq[0] if revoked_seq else None,
            "state": store.get(mission["id"])["state"],
            "approval_id": store.get(mission["id"])["approval_id"],
        })
    inverted = [o for o in outcomes
                if o["used_seq"] and o["revoked_seq"]
                and o["used_seq"] > o["revoked_seq"]]
    ran_on_withdrawn = [o for o in inverted if o["run"] == "ran"]
    used = [o for o in outcomes if o["used_seq"]]
    held = [o for o in outcomes if o["required_seq"]]
    chain = store.verify_chain()
    passed = (not inverted and chain["ok"] and len(used) + len(held) == trials
              and all(o["revoke"] == "revoked" for o in outcomes))
    report(name,
           f"{trials} REAL races between the full run_mission() and a separate "
           "PROCESS revoking the approval, with the revoke offset swept in "
           f"{int(step * 1e6)} us steps across {points * step * 1000:.1f} ms: the "
           "chain never reads granted, revoked, used -- no 'approval-used' row "
           "is ever sequenced after its own 'approval-revoked'",
           f"trials that used the approval: {len(used)}; held for approval: "
           f"{len(held)}\n"
           f"INVERTED (an approval consumed after its own revocation was "
           f"chained): {len(inverted)} of {trials}\n"
           f"of those, missions that actually STARTED on the withdrawn "
           f"approval: {len(ran_on_withdrawn)}\n"
           f"first four inversions:\n"
           + "\n".join("  " + json.dumps(o, sort_keys=True)
                       for o in inverted[:4])
           + f"\nverify_chain: ok={chain['ok']} problems={chain['problems']}",
           passed,
           note="A DEFECT STAGE O FOUND, and the exact one require_approval()'s "
                "own comment says it closed. The re-read does take the write "
                "lock revoke_approval() takes -- and then RELEASES it: the "
                "'approval-used' append and the approval_id update happen "
                "afterwards, on two further connections. A revoke landing in "
                "that gap is chained BEFORE the use, the gate returns the "
                "approval id, and run_mission() goes on to move the mission to "
                "running and execute it. The measured rate at this sweep is "
                "about 3 to 5 percent of races, and it is not only a logging "
                "order: the 'ran' rows below are missions that took a "
                "checkpoint and started work on a withdrawn decision. The exact "
                "anchor and replacement are in docs/MULTI_AGENT_SAFETY.md under "
                "BLOCKED")


def probe_revocation_is_not_a_kill_switch(bench, report):
    name = "O5-revocation-is-not-a-kill-switch-cancellation-is"
    bench.media_workspace("w15", seconds=25, size="854x480")
    store = bench.store()
    # Part one: the approval is consulted ONCE, before the state moves.
    escalating = bench.cloud_mission(store, "w15", "consulted once")
    decision, _ = bench.sf.mission_decision(store, escalating)
    aid = store.grant_approval(subject="mission:" + escalating["id"],
                               scope=decision.scope, granted_by="uid:0", method="cli")
    with contextlib.suppress(Exception):
        bench.sf.run_mission(store, escalating["id"])
    events = [e["event"] for e in store.events(escalating["id"])]
    used_once = events.count("approval-used") == 1
    before_running = (events.index("approval-used") < events.index("running")
                      if "approval-used" in events and "running" in events else False)
    store.revoke_approval(aid, reason="after the fact")
    after_revoke = [e["event"] for e in store.events(escalating["id"])]
    # Part two: what IS a live control. A running mission, cancelled by a second
    # caller, stops -- and stops because Executor.check() is polled inside the
    # process read loop, not because anything re-read an approval.
    mission = bench.media_mission(store, "w15", "cancelled in flight")
    env = bench.env()
    out_path = bench.tmp / "cancel-run.json"
    proc = _fork(_run_mission_child, env, mission["id"], str(out_path), 0.0)
    deadline, saw_running = time.time() + 60, False
    while time.time() < deadline:
        if store.get(mission["id"])["state"] == "running" and store.sessions(mission["id"]):
            saw_running = True
            break
        time.sleep(0.02)
    requested_at = time.time()
    if saw_running:
        store.cancel(mission["id"])
    proc.join(300)
    record = _read(out_path, {})
    row = store.get(mission["id"])
    stopped_after = (record.get("left_at", requested_at) - requested_at)
    passed = (used_once and before_running and saw_running
              and row["state"] == "cancelled"
              and "cancel-requested" in [e["event"] for e in store.events(mission["id"])])
    report(name,
           "the approval is read exactly once, before the mission moves to "
           "running, and nothing reads it again -- so a revoke afterwards "
           "changes nothing. Cancellation IS live: a second caller cancels a "
           "running mission and it stops",
           f"escalating mission events: {events}\n"
           f"'approval-used' appears {events.count('approval-used')} time(s), "
           f"before 'running': {before_running}\n"
           f"revoked after the run; the mission's events gained: "
           f"{after_revoke[len(events):]}\n"
           f"--- cancellation ---\n"
           f"reached running with a live session: {saw_running}\n"
           f"cancel() -> the runner returned {stopped_after:.3f}s later\n"
           f"final state: {row['state']}; error: {row['error']}\n"
           f"runner record: {json.dumps(record, sort_keys=True)}",
           passed,
           note="NOT ENFORCED: there is no re-check and no kill switch on "
                "revocation. The withdrawal IS recorded -- revoke_approval() "
                "appends 'approval-revoked' to that mission's own event list, so "
                "the log reads granted, used, ran, revoked and a reader can see "
                "the order -- but nothing consults the approval again, so an "
                "approval withdrawn mid-execution stops nothing. What IS live is "
                "cancel(), whose flag Executor.check() reads between steps and "
                "every 200 ms inside the process read loop; a person who wants a "
                "running mission stopped has to use that instead")


# --------------------------------------------------------------------------- #
# O6 -- the credential environment
# --------------------------------------------------------------------------- #
def probe_two_identities_one_process(bench, report):
    name = "O6-two-identities-in-one-process-do-not-cross"
    bench.media_workspace("w16")
    store = bench.store()
    saved = {key: os.environ.get(key) for key in ("ANTHROPIC_API_KEY", "CODEX_API_KEY")}
    os.environ["ANTHROPIC_API_KEY"] = FAKE_ANTHROPIC
    os.environ["CODEX_API_KEY"] = FAKE_CODEX
    try:
        resolved = {}
        for provider_id in ("codex", "claude"):
            mission = store.create(kind="report", provider_id=provider_id,
                                   workspace_value="w16", title=f"{provider_id} identity",
                                   prompt="report", inputs=["clip.mp4"])
            executor = bench.sf.Executor(store, mission)
            provider = bench.sf.provider_for("sourced_report", provider_id)
            got = executor.credentials_for(provider)
            resolved[provider_id] = {"declared": list(provider.manifest.get("credential_ids") or ()),
                                     "resolved_names": sorted(got),
                                     "values_are_the_right_ones":
                                         all(os.environ.get(k) == v for k, v in got.items())}
        # And end to end: two sandboxes alive at once, each granted ONE identity,
        # each asked what it can see.
        sandbox = {}
        procs = {}
        payload = ("import os,json;"
                   "print(json.dumps(sorted(k for k in os.environ "
                   "if k.endswith('_API_KEY') or k.endswith('_TOKEN'))))")
        for identity, ws in (("ANTHROPIC_API_KEY", "w16"), ("CODEX_API_KEY", "w16")):
            procs[identity] = subprocess.Popen(
                [str(FIREBREAK_BIN / "shadowfetch-firebreak"), "run",
                 "--workspace", ws, "--net", "none", "--no-checkpoint",
                 "--credential-env", identity, "--",
                 "/usr/bin/python3", "-c", payload],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                env=dict(os.environ))
        for identity, proc in procs.items():
            out, err = proc.communicate(timeout=300)
            names = []
            for line in out.splitlines():
                if line.startswith("["):
                    names = json.loads(line)
            sandbox[identity] = {"rc": proc.returncode, "visible": names,
                                 "stderr": err[-160:]}
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
    both_present = True
    isolated = all(entry["visible"] == [identity]
                   for identity, entry in sandbox.items())
    passed = (resolved["codex"]["resolved_names"] == ["CODEX_API_KEY"]
              and resolved["claude"]["resolved_names"] == ["ANTHROPIC_API_KEY"]
              and all(entry["values_are_the_right_ones"] for entry in resolved.values())
              and isolated and both_present)
    report(name,
           "one process holds TWO credential identities at once; each mission "
           "resolves only the identity its provider declared, and two sandboxes "
           "running at the same time each see exactly one -- neither can see the "
           "other's",
           f"both identities set in the orchestrator process: "
           f"{sorted(['ANTHROPIC_API_KEY', 'CODEX_API_KEY'])}\n"
           f"credentials_for(): {json.dumps(resolved, indent=2, sort_keys=True)}\n"
           f"what each sandbox could see: "
           f"{json.dumps(sandbox, indent=2, sort_keys=True)}",
           passed,
           note="the enforcing layer is bwrap --clearenv followed by one "
                "--setenv per granted identity, in the sandbox's own mount and "
                "process namespace -- the sandbox does not inherit the "
                "orchestrator's environment and then have things removed. Note "
                "what is NOT isolated: the worker PROCESS holds every declared "
                "identity simultaneously, because load_provider_credentials() "
                "reads the whole credential directory into os.environ. The "
                "separation is per invocation, not per process")


def probe_undeclared_identity(bench, report):
    name = "O6-an-undeclared-identity-cannot-be-granted"
    bench.media_workspace("w17")
    saved = os.environ.get("STAGE_O_SECRET")
    os.environ["STAGE_O_SECRET"] = "not-a-declared-identity"
    try:
        refused = subprocess.run(
            [str(FIREBREAK_BIN / "shadowfetch-firebreak"), "run",
             "--workspace", "w17", "--net", "none", "--no-checkpoint",
             "--credential-env", "STAGE_O_SECRET", "--",
             "/usr/bin/true"],
            capture_output=True, text=True, timeout=300, env=dict(os.environ))
        leaked = subprocess.run(
            [str(FIREBREAK_BIN / "shadowfetch-firebreak"), "run",
             "--workspace", "w17", "--net", "none", "--no-checkpoint", "--",
             "/usr/bin/python3", "-c",
             "import os;print('STAGE_O_SECRET' in os.environ)"],
            capture_output=True, text=True, timeout=300, env=dict(os.environ))
    finally:
        if saved is None:
            os.environ.pop("STAGE_O_SECRET", None)
        else:
            os.environ["STAGE_O_SECRET"] = saved
    visible = "True" in leaked.stdout
    passed = refused.returncode != 0 and not visible
    report(name,
           "a variable that no provider declares cannot be handed to a sandbox "
           "by naming it, and is not visible inside one that asked for nothing",
           f"$ shadowfetch-firebreak run --credential-env STAGE_O_SECRET   "
           f"(rc={refused.returncode})\n"
           f"stderr: {refused.stderr.strip()[-200:]}\n"
           f"$ shadowfetch-firebreak run -- python3 -c \"'STAGE_O_SECRET' in "
           f"os.environ\"   (rc={leaked.returncode})\n"
           f"the sandbox saw it: {visible}   stdout: {leaked.stdout.strip()!r}",
           passed,
           note="two gates, and they are different gates: Firebreak refuses a "
                "name outside its CREDENTIALS set, and --clearenv means an "
                "un-granted variable never reaches the sandbox whether it is a "
                "known identity or not. Mission Control adds a third above them "
                "by intersecting the resolved names with the invocation's "
                "declared credential_ids")


# --------------------------------------------------------------------------- #
# runner
# --------------------------------------------------------------------------- #
_PROBES = (
    ("O0-the-source-tree-is-what-is-under-test", probe_under_test),
    ("O1-worker-lock-admits-exactly-one-consumer", probe_worker_lock_admits_one),
    ("O1-the-losing-worker-exits-zero-in-silence", probe_losing_worker_is_silent),
    ("O1-worker-lock-is-scoped-to-one-state-root", probe_worker_lock_scope),
    ("O1-two-state-roots-share-no-workspace-lock",
     probe_two_state_roots_no_workspace_lock),
    ("O2-cli-run-is-refused-while-a-worker-holds-the-workspace",
     probe_cli_refused_under_worker),
    ("O2-cli-and-worker-execute-at-once-on-different-workspaces",
     probe_cli_and_worker_run_at_once),
    ("O2-the-same-mission-cannot-be-started-twice", probe_same_mission_twice),
    ("O2-the-state-transition-is-a-compare-and-swap", probe_transition_is_cas),
    ("O3-concurrent-missions-keep-separate-sandboxes-and-scopes",
     probe_separate_sandboxes),
    ("O3-checkpoint-stores-do-not-share-a-namespace", probe_checkpoint_namespaces),
    ("O3-the-audit-chain-is-shared-not-separate", probe_shared_chain),
    ("O3-a-workspace-cannot-be-aliased-into-a-second-lock",
     probe_workspace_cannot_be_aliased),
    ("O3-undo-cannot-be-redirected-onto-another-workspace",
     probe_undo_cannot_be_redirected),
    ("O4-racing-appends-never-fork-the-chain", probe_racing_appends),
    ("O4-an-injected-fork-is-detected", probe_injected_fork),
    ("O4-two-processes-opening-a-fresh-database-at-once", probe_fresh_database_race),
    ("O4-a-caller-that-loses-the-open-race-gets-a-traceback",
     probe_open_race_crashes),
    ("O5-an-approval-is-not-transferable-between-missions",
     probe_approval_not_transferable),
    ("O5-a-revoke-never-lands-between-the-check-and-the-use", probe_revoke_race),
    ("O5-revocation-is-not-a-kill-switch-cancellation-is",
     probe_revocation_is_not_a_kill_switch),
    ("O6-two-identities-in-one-process-do-not-cross",
     probe_two_identities_one_process),
    ("O6-an-undeclared-identity-cannot-be-granted", probe_undeclared_identity),
)

if tuple(name for name, _ in _PROBES) != PROBES:
    raise AssertionError(
        "PROBES and the probe table disagree; a reader of PROBES would be "
        "advertised a different set from the one run() actually runs")


def run(report, only=()):
    with Bench() as bench:
        for name, probe in _PROBES:
            if only and not any(token in name for token in only):
                continue
            try:
                probe(bench, report)
            except BaseException as exc:                            # noqa: BLE001
                report(name, "the probe runs to completion",
                       "".join(traceback.format_exception(exc))[-2500:], False,
                       note="the probe itself failed; this is not a verdict on "
                            "the system")


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    rows = []

    def report(name, expected, observed, passed, note=""):
        rows.append({"probe": name, "expected": expected, "observed": observed,
                     "passed": bool(passed), "note": note})

    run(report, only=tuple(argv))
    if not rows:
        print("no probe matched " + " ".join(argv))
        return 1
    width = max(len(row["probe"]) for row in rows)
    print("=" * 78)
    print("stage_o_multi_agent -- what happens when more than one agent runs")
    print("=" * 78)
    for row in rows:
        print()
        print(f"{'PASS' if row['passed'] else 'FAIL'}  {row['probe']}")
        print(f"      EXPECTED  {row['expected']}")
        for index, line in enumerate(row["observed"].splitlines() or [""]):
            print(f"      {'OBSERVED  ' if index == 0 else '          '}{line}")
        if row["note"]:
            print(f"      NOTE      {row['note']}")
    failed = [row["probe"] for row in rows if not row["passed"]]
    print()
    print("-" * 78)
    for row in rows:
        print(f"  {'PASS' if row['passed'] else 'FAIL'}  {row['probe']:<{width}}")
    print("-" * 78)
    print(f"{len(rows) - len(failed)} passed, {len(failed)} FAILED")
    if failed:
        print("FAILED: " + ", ".join(failed))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
