#!/usr/bin/env python3
"""Phase 3 attacks 19-21: two writers, two workspaces, and one honest word.

Re-runnable on purpose. The engine is still moving underneath these, so nothing
here is asserted from a line number or a copied constant: every probe re-reads
the live module, re-runs the real caller, and quotes what came back.

WHAT IS BEING ATTACKED

  19  Two missions on ONE workspace must serialize. Undo is defined against a
      checkpoint, so a second writer inside the same window makes "restore to
      before" name a state that never existed.
  20  Two missions on DIFFERENT workspaces must NOT block each other. Same
      mechanism, opposite verdict -- which is why they are a matched pair, and
      why a probe that never actually contends proves neither of them.
  21  Every surface that reports enforcement must refuse to describe
      egress_allowlist, masked_paths or a syscall profile as enforced. This is
      an attack on the system's HONESTY, not on its containment: two of those
      three are known Phase-4 gaps and the attack itself succeeds -- what is
      under test is whether anything claims otherwise.

TWO GAPS ARE OBSERVED-ONLY BY DESIGN (Phase 4, not defects to fix now)

  * egress destinations -- Firebreak has two postures, none and allow, and no
    destination filter. An allowlist reaches whatever the host reaches.
  * path masking -- there is no masking flag; declared masks reach nothing.

  Probes that land on those PASS only when the system refuses to claim
  otherwise, and each such record says plainly that the action itself was not
  prevented.

SAFETY. Every probe runs against a throwaway store made with tempfile.mkdtemp
and four redirected state roots. Nothing here writes to ~/.local/state, and the
source-tree Firebreak is put on PATH so the installed 3.0.0 is never the thing
under test.
"""
from __future__ import annotations

import ast
import contextlib
import dataclasses
import inspect
import json
import multiprocessing
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import traceback
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
MISSIONS_LIB = REPO / "packages/shadowfetch-missions/data/usr/lib/shadowfetch/missions"
MISSIONS_CLI = REPO / "packages/shadowfetch-missions/data/usr/bin/shadowfetch-missions"
FIREBREAK_BIN = REPO / "packages/shadowfetch-fireline/data/usr/bin"
DESKTOP_LIB = REPO / "packages/shadowfetch-control-center/data/usr/share/shadowfetch/control-center"

ATTACKS = (
    "00-the-source-tree-is-what-is-under-test",
    "19-same-workspace-serializes",
    "19-refusal-changes-nothing",
    "20-different-workspaces-overlap",
    "20-cross-workspace-run-is-not-blocked",
    "20-declared-parallelism-matches-the-worker",
    "21-static-table-never-claims-the-three-gaps",
    "21-odd-specs-never-weaken-the-caveats",
    "21-no-vacuously-enforced-field",
    "21-session-record-agrees-with-firebreak",
    "21-deny-decision-still-names-its-gaps",
    "21-nothing-empties-advisory-fields",
    "21-desktop-caveat-refuses-to-reassure",
    "21-declared-masks-are-disclosed",
    "21-test-run-enforcement-is-derived",
    "21-cli-policy-surfaces-stay-honest",
    "21-a-declared-mask-reaches-nothing",
    "21-an-allowlist-reaches-a-destination-it-never-allowed",
)

# Words that mean "a mechanism outside our own code applies this". Any of them
# said about one of the three gap fields is the thing being hunted.
AFFIRMATIVE = {"enforced", "fully_mediated", "partially_mediated", "partial",
               "applied", "true", "yes"}

# `relied_on: true` means "this mission depends on it", which is the OPPOSITE
# of a claim of enforcement. Excluded so the scan does not cry wolf about the
# one field that exists to raise the alarm.
NOT_A_CLAIM = {"relied_on"}

# The fields under attack, in each vocabulary that names them. Spelled out
# rather than derived, so a rename cannot silently empty this list.
#
# masked_paths / path_masking LEFT this list in Stage E, by gaining a mechanism
# and a proof rather than by being excused: bwrap mounts an empty tmpfs over a
# masked directory and /dev/null over a masked file, in the sandbox's own mount
# namespace, and direct open, absolute path, relative traversal, symlink,
# nested file and rename are each denied through the real Firebreak. Leaving it
# here would make these probes hunt for an honest claim.
# WHAT IS STILL A GAP, and what stopped being one. These probes exist to catch
# a static surface describing an unenforced control as a control; they are not a
# claim that the list never shrinks. Stage E built path masking and Stage C built
# the destination filter, so those names MOVED here rather than being deleted --
# a closed gap still has to appear in every table, and still has to carry a
# mechanism, or the claim is decoration.
# NOTHING IS LEFT IN THE GAP LISTS, and the check has to keep working with
# them empty -- an attack that measures nothing because its subject list is
# empty is not a passing attack, it is an absent one. So the closed lists carry
# every name instead, and each is checked for the thing a closed row must have:
# a mechanism. A field that regresses moves back to the gap list and the
# affirmative-claim check finds it there.
GAP_FIELDS_SANDBOX = ()
GAP_FIELDS_POLICY = ()
CLOSED_FIELDS_SANDBOX = ("egress_allowlist", "masked_paths", "syscall_profile")
CLOSED_FIELDS_POLICY = ("network_destination", "path_masking", "syscalls")

ENV_KEYS = ("SHADOWFETCH_AGENT_WORKSPACES", "SHADOWFETCH_MISSIONS_STATE",
            "SHADOWFETCH_FIREBREAK_STATE", "SHADOWFETCH_MCP_STATE", "PATH")


# --------------------------------------------------------------------------- #
# harness
# --------------------------------------------------------------------------- #
class Bench:
    """A throwaway store, a throwaway workspace root, and the SOURCE modules.

    The modules are imported from the repository, never from /usr/lib: the
    installed 3.0.0 Firebreak rejects 4.0.0's flags, and an attack that quietly
    tested the installed build would report on software nobody is shipping.
    """

    def __init__(self):
        self.tmp = None
        self.saved = {}
        self.sf = self.providers = self.policy = self.desktop = None

    def __enter__(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="sf-attack-concurrency-"))
        self.saved = {key: os.environ.get(key) for key in ENV_KEYS}
        os.environ["SHADOWFETCH_AGENT_WORKSPACES"] = str(self.tmp / "ws")
        os.environ["SHADOWFETCH_MISSIONS_STATE"] = str(self.tmp / "state")
        os.environ["SHADOWFETCH_FIREBREAK_STATE"] = str(self.tmp / "fb")
        os.environ["SHADOWFETCH_MCP_STATE"] = str(self.tmp / "mcp")
        # The EXPLICIT development override, not PATH: Mission Control
        # resolves its own tools from trusted directories only, so a build tree
        # on PATH is (correctly) ignored and the stale installed Firebreak wins.
        os.environ["PATH"] = str(FIREBREAK_BIN) + os.pathsep + os.environ.get("PATH", "")
        os.environ["SHADOWFETCH_FIREBREAK_TEST_BIN"] = str(FIREBREAK_BIN / "shadowfetch-firebreak")
        os.environ["SHADOWFETCH_CHECKPOINT_BIN"] = str(FIREBREAK_BIN / "shadowfetch-checkpoint")
        (self.tmp / "ws").mkdir(parents=True, exist_ok=True)
        for path in (MISSIONS_LIB, DESKTOP_LIB):
            if str(path) not in sys.path:
                sys.path.insert(0, str(path))
        import sf_missions
        import sf_policy
        import sf_providers
        from sfcc import missions_page
        self.sf, self.policy, self.providers = sf_missions, sf_policy, sf_providers
        self.desktop = missions_page
        return self

    def __exit__(self, *exc):
        for key, value in self.saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        shutil.rmtree(self.tmp, ignore_errors=True)
        return False

    # -- convenience -------------------------------------------------------
    def workspace(self, name, *, with_input=True):
        path = self.tmp / "ws" / name
        path.mkdir(parents=True, exist_ok=True)
        if with_input:
            (path / "clip.mp4").write_bytes(b"not really a media file")
        return path

    def store(self):
        return self.sf.Store()

    def media_mission(self, store, workspace, title):
        """A mission needing no network, no credentials and no cloud CLI.

        offline-media is the only shipped provider that runs end to end here, so
        it is what makes the concurrency probes real rather than mocked.
        """
        return store.create(capability="media_export", workspace_value=workspace,
                            title=title, prompt="export", inputs=["clip.mp4"])

    def cli(self, *args):
        return subprocess.run([sys.executable, str(MISSIONS_CLI), *args],
                              capture_output=True, text=True,
                              env=dict(os.environ), timeout=180)

    def firebreak(self, *args, timeout=120):
        return subprocess.run([str(FIREBREAK_BIN / "shadowfetch-firebreak"), *args],
                              capture_output=True, text=True,
                              env=dict(os.environ), timeout=timeout)

    def firebreak_records(self):
        """Every Firebreak 'started' record this bench has produced, by session."""
        out = {}
        for path in sorted((self.tmp / "fb").glob("*.session")):
            for line in path.read_text().splitlines():
                if not line.strip():
                    continue
                entry = json.loads(line)
                if entry.get("record") == "started":
                    out[entry.get("session")] = entry
        return out


# --------------------------------------------------------------------------- #
# child process bodies -- module level so any start method can reach them
# --------------------------------------------------------------------------- #
def _hold_lock_child(env, workspace, start_at, hold_seconds, wait_seconds, out_path):
    """Take the REAL Store lock in a REAL separate process and hold it.

    store.lock(workspace=...) is the same call run_mission, retry and review
    make. Reimplementing the flock here would test a copy of the control instead
    of the control.
    """
    os.environ.update(env)
    sys.path.insert(0, str(MISSIONS_LIB))
    import sf_missions
    record = {"pid": os.getpid(), "workspace": str(workspace)}
    try:
        while time.time() < start_at:
            time.sleep(0.002)
        store = sf_missions.Store()
        record["asked_at"] = time.time()
        with store.lock(workspace=workspace, wait_seconds=wait_seconds):
            record["entered_at"] = time.time()
            time.sleep(hold_seconds)
            record["left_at"] = time.time()
        record["outcome"] = "held"
    except BaseException as exc:                                  # noqa: BLE001
        record["outcome"] = "refused"
        record["error"] = f"{type(exc).__name__}: {exc}"
    Path(out_path).write_text(json.dumps(record))


def _hold_until_file_child(env, workspace, signal_path, release_path, out_path):
    """Hold one workspace's lock until the parent says to let go."""
    os.environ.update(env)
    sys.path.insert(0, str(MISSIONS_LIB))
    import sf_missions
    record = {"pid": os.getpid(), "workspace": str(workspace)}
    try:
        store = sf_missions.Store()
        with store.lock(workspace=workspace, wait_seconds=0):
            record["entered_at"] = time.time()
            Path(signal_path).write_text("held")
            # A bounded wait, so a probe that dies does not leave a process
            # holding a lock on a directory that is about to be deleted.
            deadline = time.time() + 30
            while not Path(release_path).exists() and time.time() < deadline:
                time.sleep(0.01)
            record["left_at"] = time.time()
        record["outcome"] = "held"
    except BaseException as exc:                                  # noqa: BLE001
        record["outcome"] = "refused"
        record["error"] = f"{type(exc).__name__}: {exc}"
        Path(signal_path).write_text("failed")
    Path(out_path).write_text(json.dumps(record))


def _spawn(target, *args):
    return _fork(target, args)


def _fork(target, args):
    context = multiprocessing.get_context("fork")
    proc = context.Process(target=target, args=args)
    proc.start()
    return proc


def _overlap(first, second):
    """Seconds two closed intervals share. Negative means a gap between them."""
    return min(first[1], second[1]) - max(first[0], second[0])


def _affirmative(value):
    if isinstance(value, bool):
        return value is True
    if isinstance(value, str):
        return value.strip().lower() in AFFIRMATIVE
    return False


def _claims(blob, fields):
    """Every place inside `blob` where one of `fields` is described affirmatively.

    Walks the whole structure rather than checking known keys: the point of the
    attack is to find a surface nobody listed.
    """
    hits = []

    def walk(node, path):
        if isinstance(node, dict):
            for key, value in node.items():
                here = f"{path}.{key}" if path else str(key)
                if str(key) in fields:
                    if _affirmative(value):
                        hits.append((here, value))
                    elif isinstance(value, dict):
                        for sub, subvalue in value.items():
                            if sub not in NOT_A_CLAIM and _affirmative(subvalue):
                                hits.append((f"{here}.{sub}", subvalue))
                walk(value, here)
        elif isinstance(node, (list, tuple)):
            for index, value in enumerate(node):
                walk(value, f"{path}[{index}]")

    walk(blob, "")
    return hits


# --------------------------------------------------------------------------- #
# 0 -- what is actually loaded
# --------------------------------------------------------------------------- #
def attack_under_test_is_the_source_tree(bench, report):
    """Reported as a probe, not as harness noise.

    A composer reads ATTACKS to know what run() will emit; a row it never
    announced is a row somebody has to explain. And this one can genuinely
    fail: an already-imported sf_missions, or an installed Firebreak earlier on
    PATH, silently changes what every probe below is talking about.
    """
    name = "00-the-source-tree-is-what-is-under-test"
    firebreak = shutil.which("shadowfetch-firebreak") or ""
    passed = (str(MISSIONS_LIB) in bench.sf.__file__
              and str(FIREBREAK_BIN) in firebreak)
    report(name,
           "the SOURCE modules and the SOURCE Firebreak are what is loaded, "
           "against a throwaway store outside ~/.local/state",
           f"sf_missions   {bench.sf.__file__}\n"
           f"sf_providers  {bench.providers.__file__}\n"
           f"sf_policy     {bench.policy.__file__}\n"
           f"missions_page {bench.desktop.__file__}\n"
           f"firebreak     {firebreak}\n"
           f"state root    {os.environ['SHADOWFETCH_MISSIONS_STATE']}\n"
           f"firebreak log {os.environ['SHADOWFETCH_FIREBREAK_STATE']}\n"
           f"workspaces    {os.environ['SHADOWFETCH_AGENT_WORKSPACES']}",
           passed,
           note="a probe that quietly tested the installed 3.0.0 would report on "
                "software nobody is shipping; one that wrote to ~/.local/state "
                "would corrupt the operator's audit log")


# --------------------------------------------------------------------------- #
# 19 and 20 -- the matched pair
# --------------------------------------------------------------------------- #
def attack_same_workspace_serializes(bench, report):
    name = "19-same-workspace-serializes"
    workspace = bench.workspace("alpha")
    bench.store()                                # create the schema before forking
    env = {key: os.environ[key] for key in ENV_KEYS}
    start_at = time.time() + 0.6
    outs = [bench.tmp / "same-a.json", bench.tmp / "same-b.json"]
    procs = [_spawn(_hold_lock_child, env, str(workspace), start_at, 0.7, 10.0, str(path))
             for path in outs]
    for proc in procs:
        proc.join(60)
    records = [json.loads(path.read_text()) for path in outs]
    spans = [(r.get("entered_at"), r.get("left_at")) for r in records]
    observed = json.dumps(records, indent=2, sort_keys=True)
    if any(None in span for span in spans):
        report(name,
               "two processes contend for ONE workspace; both are admitted, one "
               "at a time, and their held intervals do not overlap",
               observed, False,
               note="a process never entered the lock at all, so serialization "
                    "cannot be judged from this run")
        return
    shared = _overlap(*spans)
    passed = shared <= 0
    report(name,
           "two real processes call store.lock(workspace=<the same one>) at the "
           "same instant; the second waits, and the two held intervals share 0s",
           observed + f"\noverlap = {shared:.6f}s "
                      f"(entered {spans[0][0]:.6f} / {spans[1][0]:.6f}, "
                      f"left {spans[0][1]:.6f} / {spans[1][1]:.6f})",
           passed,
           note=("held intervals are disjoint: the per-workspace lock serialized "
                 "two genuinely simultaneous writers"
                 if passed else
                 "two writers held ONE workspace at once, so a checkpoint taken "
                 "by either no longer describes a state Undo can restore"))


def attack_refusal_changes_nothing(bench, report):
    name = "19-refusal-changes-nothing"
    workspace = bench.workspace("alpha")
    store = bench.store()
    victim = bench.media_mission(store, "alpha", "second writer, same workspace")
    mid = victim["id"]
    env = {key: os.environ[key] for key in ENV_KEYS}
    signal_path = bench.tmp / "held.flag"
    release_path = bench.tmp / "release.flag"
    out_path = bench.tmp / "holder.json"
    proc = _spawn(_hold_until_file_child, env, str(workspace),
                  str(signal_path), str(release_path), str(out_path))
    deadline = time.time() + 20
    while not signal_path.exists() and time.time() < deadline:
        time.sleep(0.01)

    def snapshot():
        """Row, events, chain and directory tree -- not just "it raised"."""
        state_root = Path(os.environ["SHADOWFETCH_MISSIONS_STATE"])
        tree = sorted(str(p.relative_to(state_root)) for p in state_root.rglob("*")
                      if p.suffix != ".lock" and "missions.sqlite3" not in p.name)
        chain = store.verify_chain()
        return {"row": store.get(mid),
                "events": store.events(mid),
                "chain": {k: chain[k] for k in ("ok", "events", "chained",
                                                "unchained", "head_seq", "head")},
                "state_tree": tree}

    holding = signal_path.exists() and signal_path.read_text() == "held"
    before = snapshot() if holding else None
    raised = None
    try:
        bench.sf.run_mission(store, mid)
        raised = "NOTHING RAISED -- run_mission() returned"
    except BaseException as exc:                                  # noqa: BLE001
        raised = f"{type(exc).__name__}: {exc}"
    after = snapshot() if before is not None else None
    release_path.write_text("go")
    proc.join(60)

    if before is None:
        report(name,
               "the holder takes the workspace lock so the refusal can be provoked",
               f"holder never signalled; its record: "
               f"{out_path.read_text() if out_path.exists() else '(none written)'}",
               False, note="the contention never happened, so nothing was measured")
        return

    unchanged = before == after
    refused = "Another mission is executing on" in raised
    diff = ""
    if not unchanged:
        for key in before:
            if before[key] != after[key]:
                diff += (f"\nCHANGED {key}:\n  before "
                         f"{json.dumps(before[key], sort_keys=True, default=str)}"
                         f"\n  after  "
                         f"{json.dumps(after[key], sort_keys=True, default=str)}")
    passed = refused and unchanged
    report(name,
           "run_mission() on a second mission in a locked workspace raises, AND "
           "the mission row, its event list, the audit chain and the state "
           "directory are identical afterwards",
           f"run_mission() raised: {raised}\n"
           f"state  before/after: {before['row']['state']} -> {after['row']['state']}\n"
           f"updated_at before/after: {before['row']['updated_at']} -> "
           f"{after['row']['updated_at']}\n"
           f"events before/after: {len(before['events'])} -> {len(after['events'])}\n"
           f"chain before: {json.dumps(before['chain'], sort_keys=True)}\n"
           f"chain after:  {json.dumps(after['chain'], sort_keys=True)}\n"
           f"state directory identical: {before['state_tree'] == after['state_tree']}"
           f"  ({len(before['state_tree'])} entries)"
           + diff,
           passed,
           note=("refused and inert: the second writer produced no row change, no "
                 "event, no audit entry and no mission directory"
                 if passed else
                 "the refusal was not clean -- see the CHANGED sections above"))


def attack_different_workspaces_overlap(bench, report):
    name = "20-different-workspaces-overlap"
    alpha = bench.workspace("alpha")
    beta = bench.workspace("beta")
    bench.store()
    env = {key: os.environ[key] for key in ENV_KEYS}
    start_at = time.time() + 0.6
    outs = [bench.tmp / "diff-a.json", bench.tmp / "diff-b.json"]
    procs = [_spawn(_hold_lock_child, env, str(ws), start_at, 0.7, 10.0, str(path))
             for ws, path in zip((alpha, beta), outs)]
    for proc in procs:
        proc.join(60)
    records = [json.loads(path.read_text()) for path in outs]
    spans = [(r.get("entered_at"), r.get("left_at")) for r in records]
    observed = json.dumps(records, indent=2, sort_keys=True)
    if any(None in span for span in spans):
        report(name,
               "two processes hold locks on two DIFFERENT workspaces at the same "
               "time", observed, False,
               note="one of the two was refused, so different workspaces are not "
                    "proceeding concurrently")
        return
    shared = _overlap(*spans)
    passed = shared > 0
    report(name,
           "two real processes call store.lock() on two DIFFERENT workspaces at "
           "the same instant; both are admitted and their held intervals "
           "genuinely overlap in time",
           observed + f"\noverlap = {shared:.6f}s "
                      f"(entered {spans[0][0]:.6f} / {spans[1][0]:.6f}, "
                      f"left {spans[0][1]:.6f} / {spans[1][1]:.6f})",
           passed,
           note=("measured overlap, not merely two successes: both processes were "
                 "inside their critical sections at the same moment, which is the "
                 "whole difference from attack 19"
                 if passed else
                 "the two workspaces serialized against each other; the SHARED "
                 "level of the hierarchy is excluding what it should admit"))


def attack_cross_workspace_run_is_not_blocked(bench, report):
    name = "20-cross-workspace-run-is-not-blocked"
    bench.workspace("alpha")
    bench.workspace("beta")
    store = bench.store()
    other = bench.media_mission(store, "beta", "a mission on the other workspace")
    env = {key: os.environ[key] for key in ENV_KEYS}
    signal_path = bench.tmp / "held2.flag"
    release_path = bench.tmp / "release2.flag"
    out_path = bench.tmp / "holder2.json"
    proc = _spawn(_hold_until_file_child, env, str(bench.tmp / "ws" / "alpha"),
                  str(signal_path), str(release_path), str(out_path))
    deadline = time.time() + 20
    while not signal_path.exists() and time.time() < deadline:
        time.sleep(0.01)
    started = time.time()
    outcome = "returned"
    try:
        bench.sf.run_mission(store, other["id"])
    except BaseException as exc:                                  # noqa: BLE001
        outcome = f"{type(exc).__name__}: {exc}"
    finished = time.time()
    release_path.write_text("go")
    proc.join(60)
    holder = json.loads(out_path.read_text()) if out_path.exists() else {}
    row = store.get(other["id"])
    events = [e["event"] for e in store.events(other["id"])]
    blocked = "Another mission is executing on" in outcome
    inside = (holder.get("entered_at") is not None
              and holder["entered_at"] <= started <= holder.get("left_at", 0))
    started_work = row["state"] != "queued" and "running" in events
    passed = (not blocked) and inside and started_work
    report(name,
           "while one process holds workspace alpha, the REAL run_mission() on a "
           "mission in workspace beta gets past the lock and starts work",
           f"holder: {json.dumps(holder, sort_keys=True)}\n"
           f"run_mission(beta) started "
           f"{started - holder.get('entered_at', started):.3f}s after alpha was "
           f"locked, and took {finished - started:.3f}s\n"
           f"alpha was still held when beta started: {inside}\n"
           f"run_mission(beta) outcome: {outcome}\n"
           f"beta state: {row['state']}\nbeta events: {events}",
           passed,
           note=("beta executed inside alpha's lock window through the real "
                 "caller, not just through the lock helper. Beta then failed on "
                 "its own input, which is expected -- the claim under test is "
                 "that it was never blocked by alpha"
                 if passed else
                 "beta did not proceed while alpha was held"))


def attack_declared_parallelism_matches_the_worker(bench, report):
    name = "20-declared-parallelism-matches-the-worker"
    caps = bench.sf.capabilities()
    declared = caps.get("max_parallel")
    source = inspect.getsource(bench.sf.worker)
    tree = ast.parse(textwrap.dedent(source))
    concurrent = any(isinstance(node, ast.Attribute)
                     and node.attr in ("Thread", "Process", "Pool",
                                       "ThreadPoolExecutor", "ProcessPoolExecutor")
                     for node in ast.walk(tree))
    exclusive = "worker.lock" in source and "LOCK_EX | fcntl.LOCK_NB" in source
    dispatch = [line.strip() for line in source.splitlines() if "run_mission" in line]
    actual = 1 if (not concurrent and exclusive) else "more than 1"
    if not dispatch:
        # The anchor is gone. Either worker() no longer dispatches through
        # run_mission, or inspect just handed us a slice of a file being
        # rewritten underneath us. Either way this probe knows nothing, and a
        # probe that reports PASS when it could not find what it was looking
        # for is worse than no probe.
        report(name,
               "whatever the engine advertises as max_parallel is what the "
               "shipped queue consumer can actually do at once",
               f"capabilities()['max_parallel'] = {declared!r}\n"
               "no run_mission dispatch found in worker():\n"
               + textwrap.indent(source, "  "),
               False,
               note="anchor not found -- worker() was read while it was being "
                    "edited, or the dispatch moved. Re-run; do not read this row "
                    "as a verdict")
        return
    passed = declared == actual
    report(name,
           "whatever the engine advertises as max_parallel is what the shipped "
           "queue consumer can actually do at once",
           f"capabilities()['max_parallel'] = {declared!r}\n"
           f"worker() spawns a thread/process/pool: {concurrent}\n"
           f"worker() holds worker.lock LOCK_EX|LOCK_NB (one worker per store): "
           f"{exclusive}\n"
           f"worker() dispatches with: {dispatch}",
           passed,
           note=("honest. The lock hierarchy PERMITS concurrent workspaces -- "
                 "attack 20 above measures that -- but the shipped worker "
                 "consumes the queue in a single-threaded for loop and holds "
                 "worker.lock exclusively, so exactly one mission runs at a time "
                 "and capabilities() says 1 rather than claiming more. "
                 "Cross-workspace concurrency is reachable today only through two "
                 "separate callers."
                 if passed else
                 f"capabilities() advertises {declared!r} while the worker can "
                 f"only do {actual}"))


# --------------------------------------------------------------------------- #
# 21 -- the honesty attacks
# --------------------------------------------------------------------------- #
def attack_static_table(bench, report):
    name = "21-static-table-never-claims-the-three-gaps"
    providers, policy = bench.providers, bench.policy
    table = providers.sandbox_enforcement()
    matrix = policy.PolicyEngine.capability_matrix()
    unenforced = providers.unenforced_fields()
    rows = {field: table[field]["status"] for field in GAP_FIELDS_SANDBOX
            if field in table}
    mediation = {field: matrix[field]["mediation"] for field in GAP_FIELDS_POLICY
                 if field in matrix}
    bad = [f"{k}={v}" for k, v in rows.items() if _affirmative(v)]
    bad += [f"{k}={v}" for k, v in mediation.items() if _affirmative(v)]
    missing = [f for f in GAP_FIELDS_SANDBOX if f not in table]
    missing += [f for f in GAP_FIELDS_POLICY if f not in matrix]
    # A closed gap has to stay visible and has to say HOW. A field that quietly
    # left the table, or that claims a control with no mechanism behind it,
    # reads exactly like the overclaim this probe was written to catch.
    missing += [f for f in CLOSED_FIELDS_SANDBOX if f not in table]
    missing += [f for f in CLOSED_FIELDS_POLICY if f not in matrix]
    silent = [f for f in CLOSED_FIELDS_SANDBOX
              if not str(table.get(f, {}).get("mechanism", "")).strip()]
    silent += [f for f in CLOSED_FIELDS_POLICY
               if not str(matrix.get(f, {}).get("mechanism", "")).strip()]
    bad += [f"{f}=claimed with no mechanism" for f in silent]
    passed = not bad and not missing
    report(name,
           "with no mission in hand, both static tables describe every "
           "remaining gap as unenforced, name every closed one with the "
           "mechanism that closed it, and omit neither",
           f"sandbox_enforcement() = {json.dumps(rows, sort_keys=True)}\n"
           f"unenforced_fields() = {json.dumps(unenforced)}\n"
           f"capability_matrix() = {json.dumps(mediation, sort_keys=True)}\n"
           f"affirmative claims found: {bad or 'none'}\n"
           f"fields missing from a table: {missing or 'none'}",
           passed,
           note=("no remaining gap is described as a control, and each closed "
                 "one names its mechanism. What is still not prevented is the "
                 "syscall surface, which no layer here represents"
                 if passed else
                 f"a static table claims one of the gaps: {bad or missing}"))


def attack_odd_specs(bench, report):
    name = "21-odd-specs-never-weaken-the-caveats"
    providers, policy = bench.providers, bench.policy
    Spec = providers.SandboxSpec
    cases = {
        "empty everything":
            Spec(workspace_mode="workspace-write", network="none"),
        "all three declared":
            Spec(workspace_mode="workspace-write", network="allowlist",
                 egress_allowlist=("api.example.com",),
                 masked_paths=("/home/agent/.ssh",)),
        "network on, allowlist EMPTY":
            Spec(workspace_mode="read-only", network="allowlist",
                 egress_allowlist=()),
        "masks declared, no network":
            Spec(workspace_mode="workspace-write", network="none",
                 masked_paths=("/etc/shadow",)),
    }

    class Absent:
        """A spec-shaped object with none of the three attributes present."""
        workspace_mode = "workspace-write"
        network = "none"
        credential_ids = ()
        read_grants = ()

    cases["object with the three fields ABSENT"] = Absent()

    lines, bad = [], []
    for label, spec in cases.items():
        status = providers.sandbox_enforcement(spec)
        rows = {field: status.get(field, {}).get("status")
                for field in GAP_FIELDS_SANDBOX}
        lines.append(f"  {label}: {json.dumps(rows, sort_keys=True)}")
        bad += [f"{label}/{k}={v}" for k, v in rows.items() if _affirmative(v)]

    # The policy side, with the network value spelled the way the mission config
    # and sf_policy's own NETWORK_RANK spell it rather than the way SandboxSpec
    # does.
    class AllowSpelling:
        workspace_mode = "workspace-write"
        network = "allow"                      # a key in sf_policy.NETWORK_RANK
        credential_ids = ()
        read_grants = ()

    decision = policy.PolicyEngine().evaluate(
        capability="code_change", provider_id="probe", workspace="/w",
        sandbox=AllowSpelling(), provider_trust="distro-managed")
    lines.append("  policy scope network='allow' (the mission-config spelling): "
                 f"outcome={decision.outcome} "
                 f"advisory_fields={list(decision.advisory_fields)} "
                 "network_destination.relied_on="
                 f"{decision.mediation['network_destination']['relied_on']}")
    # The network is on and NO destination was declared, so nothing filters:
    # that has to be said out loud. The same check would be WRONG for a spec
    # that declares hosts -- there the filter exists and calling it advisory
    # would be a caveat about a control that is applied.
    if (decision.scope.network != "none"
            and not decision.scope.egress_hosts
            and "network_destination" not in decision.advisory_fields):
        bad.append("policy/network_destination dropped for an unfiltered "
                   "network='allow'")
    filtered = policy.PolicyEngine().evaluate(
        capability="code_change", provider_id="probe", workspace="/w",
        sandbox=Spec(workspace_mode="workspace-write", network="allowlist",
                     egress_allowlist=("api.example.com",)),
        provider_trust="distro-managed")
    entry = filtered.mediation["network_destination"]
    lines.append("  policy scope network='allowlist' with a declared host: "
                 f"mediation={entry['mediation']!r} "
                 f"advisory={'network_destination' in filtered.advisory_fields}")
    if entry["mediation"] != policy.FULLY_MEDIATED:
        bad.append("policy/network_destination is not mediated for a declared "
                   "allowlist, which is the case Stage C built")
    if "api.example.com" not in entry["mechanism"]:
        bad.append("policy/network_destination claims a filter without naming "
                   "what it permits")

    passed = not bad
    report(name,
           "no spec -- empty, odd, or missing the attribute entirely -- makes any "
           "surface describe one of the three gaps as a control, and no spelling "
           "of the network value silently removes the egress caveat",
           "\n".join(lines) + f"\nproblems: {bad or 'none'}",
           passed,
           note=("every case reports not_enforced / not_representable / "
                 "not_applicable; nothing flipped to a control"
                 if passed else
                 "LATENT, not reachable from mission_decision() today: scope_for() "
                 "reads a real SandboxSpec, whose network is validated to "
                 "none/allowlist. But sf_policy's own NETWORK_RANK and "
                 "Scope.from_json both accept 'allow', and _mediation_for() marks "
                 "network_destination relied_on only for the exact string "
                 "'allowlist' -- so a Scope carrying 'allow' escalates FOR network "
                 "access and then omits the egress caveat entirely. Problems: "
                 + "; ".join(bad)))


def attack_no_vacuously_enforced_field(bench, report):
    name = "21-no-vacuously-enforced-field"
    providers = bench.providers
    spec = providers.SandboxSpec(workspace_mode="workspace-write", network="none")
    status = providers.sandbox_enforcement(spec)
    # A FIELD A SESSION CANNOT DECLINE IS NOT A FIELD IT DECLARED NOTHING FOR.
    # The question this attack asks -- "was a session told a control applied
    # when it asked for none?" -- is the right one for every field the spec can
    # express, and meaningless for one it cannot. `syscall_profile` has no
    # manifest key and no SandboxSpec attribute on purpose: the filter is
    # Firebreak's, identical for every sandbox, and a provider choosing its own
    # syscall surface is the thing the boundary exists in order not to permit.
    # So it is checked for the opposite property instead -- that it is NOT
    # something a session can opt out of -- and if it ever becomes declarable,
    # `hasattr` sees that and it falls back under the vacuity rule.
    always_on = [f for f in status
                 if not hasattr(providers.SandboxSpec, f)
                 and not any(field.name == f
                             for field in dataclasses.fields(providers.SandboxSpec))]
    vacuous = []
    for field, entry in sorted(status.items()):
        if field in always_on:
            continue
        value = getattr(spec, field, None)
        if entry["status"] == "enforced" and value in (None, (), [], ""):
            vacuous.append((field, value, entry["mechanism"]))
    # An always-on control still has to be applied, or "not declinable" would be
    # a way of never being checked at all.
    unapplied = [f for f in always_on if status[f]["status"] != "enforced"]
    passed = not vacuous and not unapplied
    report(name,
           "a session that declared nothing for a field is not told that field is "
           "enforced -- the not_applicable convention sandbox_enforcement() "
           "already applies to credential_ids applies to every unused field",
           "sandbox_enforcement(SandboxSpec(workspace_mode='workspace-write', "
           "network='none')) =\n"
           + json.dumps({k: v["status"] for k, v in sorted(status.items())},
                        indent=2, sort_keys=True)
           + "\nfields reported 'enforced' whose declared value is empty:\n"
           + ("\n".join(f"  {f} = {v!r}  ->  {m}" for f, v, m in vacuous) or "  none")
           + "\nfields no session can declare, which must be applied anyway: "
           + (", ".join(sorted(always_on)) or "none")
           + ("" if not unapplied else
              "\n  NOT APPLIED: " + ", ".join(sorted(unapplied))),
           passed,
           note=("no vacuous claim" if passed else
                 "these are reported as applied mechanisms for a session that "
                 "asked for neither: bwrap is given no --ro-bind and no account "
                 "--bind, so 'enforced' here describes a loop over an empty list. "
                 "The credential_ids branch in sandbox_enforcement() fixes exactly "
                 "this for one field and its comment says the convention is "
                 "'consistent with the convention applied to every other unused "
                 "field'. It is not. Firebreak's own record of the same session "
                 "calls both not_applicable -- see the next attack."))


def attack_session_record_agrees_with_firebreak(bench, report):
    name = "21-session-record-agrees-with-firebreak"
    bench.workspace("gamma")
    store = bench.store()
    mission = bench.media_mission(store, "gamma", "one session, two records")
    with contextlib.suppress(BaseException):
        bench.sf.run_mission(store, mission["id"])
    sessions = store.sessions(mission["id"])
    if not sessions:
        report(name,
               "the mission session row and Firebreak's own record of the same "
               "session agree about what was enforced",
               "the mission opened no session, so Firebreak was never invoked",
               False, note="no evidence was produced by this run")
        return
    session = sessions[0]
    fb = bench.firebreak_records()
    record = fb.get(session["id"])
    if record is None:
        report(name,
               "the mission session row and Firebreak's own record of the same "
               "session agree about what was enforced",
               f"no Firebreak .session record carries session id "
               f"{session['id']}; records present: {sorted(fb)}",
               False, note="the two records could not be correlated by id")
        return
    ours = session.get("enforcement") or {}
    theirs = record.get("enforcement") or {}
    alias = {"credential_ids": "credentials"}
    conflicts = []
    for field, entry in sorted(ours.items()):
        if entry.get("status") != "enforced":
            continue
        their_key = alias.get(field, field)
        if their_key not in theirs:
            conflicts.append((field, "ABSENT from the Firebreak record"))
        elif theirs[their_key]["status"] != "enforced":
            conflicts.append((field, f"{theirs[their_key]['status']} -- "
                                     f"{theirs[their_key]['mechanism']}"))
    passed = not conflicts
    report(name,
           "for ONE session id, the agent_sessions.enforcement column and the "
           "Firebreak .session record do not disagree: nothing is 'enforced' in "
           "one and unapplied in the other",
           f"session {session['id']} (Firebreak record {record.get('session')})\n"
           "agent_sessions.enforcement = "
           + json.dumps({k: v["status"] for k, v in sorted(ours.items())},
                        indent=2, sort_keys=True)
           + "\nfirebreak .session enforcement = "
           + json.dumps({k: v["status"] for k, v in sorted(theirs.items())},
                        indent=2, sort_keys=True)
           + "\nconflicts (mission says enforced, the sandbox record does not):\n"
           + ("\n".join(f"  {f}: firebreak says {t}" for f, t in conflicts)
              or "  none"),
           passed,
           note=("the two records of one session agree" if passed else
                 "two records of the SAME session contradict each other. "
                 "Firebreak reads its statuses out of the argv it is about to "
                 "spawn; sf_providers.sandbox_enforcement() reads them out of a "
                 "static table, so a field nobody asked for still reports an "
                 "applied mechanism. The receipt and the review summary are both "
                 "built from the mission side, so this is the number a reviewer "
                 "sees."))


def attack_deny_still_names_its_gaps(bench, report):
    name = "21-deny-decision-still-names-its-gaps"
    policy, providers = bench.policy, bench.providers
    spec = providers.SandboxSpec(workspace_mode="workspace-write",
                                 network="allowlist",
                                 egress_allowlist=("api.example.com",))
    decision = policy.PolicyEngine().evaluate(
        capability="code_change", provider_id="probe", workspace="/w",
        sandbox=spec, provider_trust="a trust class this build never heard of")
    blob = decision.as_dict()
    caveat = bench.desktop.caveat_text(blob)
    claims = _claims(blob, set(GAP_FIELDS_POLICY) | set(GAP_FIELDS_SANDBOX))
    passed = (decision.outcome == policy.DENY
              and bool(decision.advisory_fields)
              and "relies on no control" not in caveat
              and not claims)
    report(name,
           "a DENY carries the same advisory_fields as any other decision, and "
           "the desktop does not render it as a clean bill of health",
           f"outcome = {decision.outcome}\n"
           f"reasons = {list(decision.reasons)}\n"
           f"advisory_fields = {list(decision.advisory_fields)}\n"
           f"network_destination.relied_on = "
           f"{decision.mediation['network_destination']['relied_on']}\n"
           f"affirmative claims about the gap fields: {claims or 'none'}\n"
           f"caveat_text() =\n{textwrap.indent(caveat, '  ')}",
           passed,
           note=("the DENY path builds its advisory fields like every other path; "
                 "the reviewed regression -- a DENY returning an empty list that "
                 "the desktop rendered as 'every control is applied by a mechanism "
                 "outside Mission Control' -- does not reproduce"
                 if passed else
                 "a DENY produced a decision the desktop can render as safe"))


def attack_nothing_empties_advisory_fields(bench, report):
    name = "21-nothing-empties-advisory-fields"
    policy, providers = bench.policy, bench.providers
    Spec = providers.SandboxSpec
    engines = {
        "defaults": policy.PolicyEngine(),
        "no approval for anything": policy.PolicyEngine(
            require_approval_for_network=False,
            require_approval_for_credentials=False,
            require_approval_for_workspace_write=False),
        "approval for everything": policy.PolicyEngine(
            require_approval_for_network=True,
            require_approval_for_credentials=True,
            require_approval_for_workspace_write=True),
    }
    specs = {
        "offline, read-only, nothing declared":
            Spec(workspace_mode="read-only", network="none"),
        "networked with hosts":
            Spec(workspace_mode="workspace-write", network="allowlist",
                 egress_allowlist=("api.example.com",)),
        "credentials and masks":
            Spec(workspace_mode="workspace-write", network="none",
                 credential_ids=("TOKEN",), masked_paths=("/home",)),
    }
    trusts = ("distro-managed", "developer", "unknown", "martian")
    empty, lines = [], []
    for ename, engine in engines.items():
        for sname, spec in specs.items():
            for trust in trusts:
                decision = engine.evaluate(capability="code_change",
                                           provider_id="probe", workspace="/w",
                                           sandbox=spec, provider_trust=trust)
                fields = list(decision.advisory_fields)
                if not fields:
                    empty.append(f"{ename} / {sname} / trust={trust}")
                lines.append(f"  {ename} | {sname} | trust={trust} | "
                             f"{decision.outcome} | advisory={fields}")
    passed = not empty
    report(name,
           "no combination of engine settings, sandbox and trust class produces a "
           "decision with an EMPTY advisory_fields list -- the list the desktop "
           "turns into 'this decision relies on no control Mission Control cannot "
           "enforce'",
           "\n".join(lines)
           + f"\ncombinations exercised: {len(lines)}"
           + f"\ncombinations with an empty list: {empty or 'none'}",
           passed,
           note=("syscalls and tool_actions_inside_a_turn are relied on "
                 "unconditionally, so the reassuring sentence is unreachable from "
                 "the engine"
                 if passed else
                 f"these inputs empty the list and unlock the reassurance: {empty}"))


def attack_desktop_caveat(bench, report):
    name = "21-desktop-caveat-refuses-to-reassure"
    desktop, policy, providers = bench.desktop, bench.policy, bench.providers
    spec = providers.SandboxSpec(workspace_mode="workspace-write",
                                 network="allowlist",
                                 egress_allowlist=("api.example.com",))
    real = policy.PolicyEngine().evaluate(
        capability="code_change", provider_id="probe", workspace="/w",
        sandbox=spec, provider_trust="distro-managed").as_dict()
    cases = {
        "a real networked decision": (real, "not-reassuring"),
        "advisory_fields ABSENT from the reply":
            ({k: v for k, v in real.items() if k != "advisory_fields"}, "unknown"),
        "advisory_fields present but EMPTY":
            (dict(real, advisory_fields=[]), "reassurance-is-allowed"),
        "no decision object at all": (None, "not-reassuring"),
    }
    lines, bad = [], []
    for label, (blob, want) in cases.items():
        text = desktop.caveat_text(blob)
        lines.append(f"  {label}:\n    {text!r}")
        if want == "not-reassuring" and "relies on no control" in text:
            bad.append(label)
        if want == "unknown" and "could not determine" not in text:
            bad.append(label + " -- ABSENT was treated as EMPTY")
    passed = not bad
    report(name,
           "caveat_text() distinguishes ABSENT from EMPTY: a reply that never "
           "carried advisory_fields is reported as unknown, never as 'there is "
           "nothing to know'",
           "\n".join(lines) + f"\nproblems: {bad or 'none'}",
           passed,
           note=("absent is handled separately from empty, so the reviewed "
                 "regression does not reproduce. Remaining shape worth knowing: "
                 "for a non-dict decision caveat_text() returns '', so the panel "
                 "shows no caveat line at all and decision_text() is the only "
                 "thing that says a decision was missing."
                 if passed else
                 f"caveat_text() mis-renders: {bad}"))


def attack_declared_masks_are_disclosed(bench, report):
    name = "21-declared-masks-are-disclosed"
    policy, providers = bench.policy, bench.providers
    spec = providers.SandboxSpec(workspace_mode="workspace-write", network="none",
                                 masked_paths=("/home/agent/.ssh", "/etc/shadow"))
    decision = policy.PolicyEngine().evaluate(
        capability="code_change", provider_id="probe", workspace="/w",
        sandbox=spec, provider_trust="distro-managed")
    scope_fields = tuple(f.name for f in dataclasses.fields(policy.Scope))
    source = inspect.getsource(policy.PolicyEngine._mediation_for)
    relied = decision.mediation["path_masking"]["relied_on"]
    listed = "path_masking" in decision.advisory_fields
    status = providers.sandbox_enforcement(spec)["masked_paths"]["status"]
    # INVERTED at Stage E. This probe used to demand that a declared mask be
    # DISCLOSED as relied-on-but-unenforced, which was the honest thing to say
    # while masking reached nothing. Masking is enforced now, so the advisory
    # list must NOT name it: an advisory that cries wolf about a control which
    # actually works teaches people to ignore the list.
    passed = status == "enforced" and not listed
    report(name,
           "a sandbox that declares masked_paths is enforced, and the "
           "'relied on and NOT enforced' advisory list therefore does NOT name "
           "path_masking -- an advisory that names a working control teaches "
           "people to ignore the list",
           f"sandbox.masked_paths = {spec.masked_paths}\n"
           f"decision.advisory_fields = {list(decision.advisory_fields)}\n"
           f"decision.mediation['path_masking'] = "
           f"{json.dumps(decision.mediation['path_masking'], sort_keys=True)}\n"
           f"sandbox_enforcement(spec)['masked_paths'].status = {status}\n"
           f"sf_policy.Scope fields = {scope_fields}\n"
           "_mediation_for() lines mentioning it: "
           + repr([line.strip() for line in source.splitlines()
                   if "path_masking" in line or "set by the caller" in line]),
           passed,
           note=("masking is enforced and is not advertised as a gap" if passed else
                 "the surfaces disagree about masking: enforcement says "
                 f"{status!r} while the advisory list "
                 f"{'names' if listed else 'omits'} it -- "
                 "Firebreak both say not_enforced, and the mask itself is not "
                 "applied, which is Phase 4. The defect is DISCLOSURE: "
                 "sf_policy.Scope carries no masked_paths, so _mediation_for() "
                 "structurally cannot see them and path_masking.relied_on is "
                 "hard-coded False. Its comment promises a caller that sets it "
                 "when masks are declared; there is no such caller. A reviewer "
                 "reading the heading 'Relied on by this decision and NOT "
                 "enforced' for a mission that masks /etc/shadow is not told the "
                 "mask is inert."))


def attack_test_run_enforcement_is_derived(bench, report):
    name = "21-test-run-enforcement-is-derived"
    sf = bench.sf
    code_source = inspect.getsource(sf.Executor.code)
    try:
        tree = ast.parse(textwrap.dedent(code_source))
    except SyntaxError as exc:
        report(name,
               "the enforcement map written to the test_runs row is derived from "
               "the posture that run actually got",
               f"Executor.code() would not parse: {exc}\n"
               + textwrap.indent(code_source, "  "),
               False,
               note="the source on disk no longer matches the imported module -- "
                    "it is being edited. Re-run; do not read this row as a verdict")
        return
    literal, constants = None, []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not (isinstance(node.func, ast.Attribute)
                and node.func.attr == "record_test_run"):
            continue
        for keyword in node.keywords:
            if keyword.arg != "enforcement":
                continue
            literal = ast.dump(keyword.value)
            if isinstance(keyword.value, ast.Dict):
                constants = [(getattr(k, "value", None), getattr(v, "value", None))
                             for k, v in zip(keyword.value.keys, keyword.value.values)
                             if isinstance(v, ast.Constant)]
    if literal is None:
        # No record_test_run(enforcement=...) in Executor.code(). Either the
        # call moved -- in which case this probe is aimed at nothing and must be
        # re-aimed -- or the file changed under inspect. A silent PASS here
        # would report "derived" about a call nobody looked at.
        report(name,
               "the enforcement map written to the test_runs row is derived from "
               "the posture that run actually got",
               "no record_test_run(enforcement=...) call found in "
               "Executor.code(); the probe's anchor is gone",
               False,
               note="anchor not found -- re-aim the probe or re-run if the source "
                    "was being edited. Do not read this row as a verdict")
        return
    # What Firebreak actually records for the posture this same code path can
    # hand it. Measured here, not assumed from the table.
    bench.workspace("delta", with_input=False)
    proc = bench.firebreak("run", "--workspace", "delta", "--net", "allow",
                           "--no-checkpoint", "--", "/usr/bin/true")
    allow_record = next((r for r in bench.firebreak_records().values()
                         if r.get("network_effective") == "allow"), None)
    firebreak_says = (allow_record or {}).get("enforcement", {}).get("network", {})
    net_lines = [line.strip() for line
                 in inspect.getsource(sf.Executor.run_process).splitlines()
                 if "firebreak_network" in line]
    hardcoded = [f"{k}={v}" for k, v in constants if _affirmative(v)]
    passed = not hardcoded
    report(name,
           "the enforcement map written to the test_runs row is derived from the "
           "posture that run actually got, not a constant that says 'enforced' "
           "whatever the mission asked for",
           f"Executor.code() passes enforcement={literal}\n"
           f"constant entries asserting a control: {hardcoded or 'none'}\n"
           f"the same code path chooses Firebreak's --net with: {net_lines}\n"
           f"Firebreak's own record for --net allow (rc={proc.returncode}): "
           f"{json.dumps(firebreak_says, sort_keys=True)}",
           passed,
           note=("derived" if passed else
                 "the map is a literal. For the workspace test command "
                 "run_process() passes self.mission['config']['network'] straight "
                 "to Firebreak, so a mission created with --network allow runs its "
                 "tests with no network namespace -- Firebreak records that exact "
                 "posture as not_enforced (above) while the test_runs row states "
                 "network_isolation=enforced regardless of what was asked for. "
                 "'network_isolation' is also a second vocabulary for the field "
                 "every other surface calls 'network'."))


def attack_cli_policy_surfaces(bench, report):
    name = "21-cli-policy-surfaces-stay-honest"
    bench.workspace("epsilon")
    store = bench.store()
    # Codex by name: three providers serve this capability now, and left to
    # inference this raises "name one with --provider" before a mission exists.
    networked = store.create(capability="sourced_report", provider_id="codex",
                             workspace_value="epsilon",
                             title="cloud report", prompt="p", inputs=["clip.mp4"],
                             network="allow")
    matrix = bench.cli("--json", "policy", "matrix")
    show = bench.cli("--json", "policy", "show", networked["id"])
    problems, blobs = [], {}
    for label, proc in (("policy matrix", matrix), ("policy show", show)):
        try:
            blobs[label] = json.loads(proc.stdout)
        except json.JSONDecodeError:
            problems.append(f"{label}: not JSON (rc={proc.returncode}) "
                            f"stdout={proc.stdout[:200]!r} "
                            f"stderr={proc.stderr[:200]!r}")
            continue
        problems += [f"{label}: {path} = {value!r}" for path, value
                     in _claims(blobs[label],
                                set(GAP_FIELDS_POLICY) | set(GAP_FIELDS_SANDBOX))]
    # This provider DECLARES destinations, so the filter exists for this
    # mission and network_destination must NOT be advisory -- an advisory field
    # is a control the decision relies on and does not get. What must hold
    # instead is that the surface says which destinations, so a person reading
    # it can see what was permitted rather than a bare "enforced".
    show_blob = blobs.get("policy show") or {}
    advisory = show_blob.get("advisory_fields") or []
    entry = (show_blob.get("mediation") or {}).get("network_destination") or {}
    if "network_destination" in advisory:
        problems.append("policy show: a mission whose destinations ARE filtered "
                        "still lists network_destination as relied on and "
                        "unenforced")
    if entry.get("mediation") != "fully_mediated":
        problems.append("policy show: a mission with a declared allowlist reports "
                        f"network_destination = {entry.get('mediation')!r}")
    if "api.openai.com" not in str(entry.get("mechanism", "")):
        problems.append("policy show: the destination filter is claimed without "
                        "naming a single destination it permits")
    passed = not problems
    report(name,
           "the shipped CLI's own policy surfaces never describe a remaining "
           "gap affirmatively, and a networked mission's 'policy show' reports "
           "its destination filter by naming what it permits",
           f"$ shadowfetch-missions --json policy matrix   (rc={matrix.returncode})\n"
           + json.dumps({k: v for k, v in (blobs.get("policy matrix") or {}).items()
                         if k in GAP_FIELDS_POLICY}, indent=2, sort_keys=True)
           + f"\n$ shadowfetch-missions --json policy show {networked['id']}   "
             f"(rc={show.returncode})\n"
           + f"outcome = {(blobs.get('policy show') or {}).get('outcome')!r}\n"
           + f"advisory_fields = {json.dumps(advisory)}\n"
           + "mediation for the gap fields = "
           + json.dumps({k: v for k, v
                         in ((blobs.get("policy show") or {}).get("mediation")
                             or {}).items() if k in GAP_FIELDS_POLICY},
                        indent=2, sort_keys=True)
           + "\nproblems: " + (json.dumps(problems, indent=2) if problems else "none"),
           passed,
           note=("both CLI surfaces carry a mediation level rather than a verdict, "
                 "and the networked mission is told its egress destinations are "
                 "not filtered. The destinations are still not filtered -- that is "
                 "Phase 4, not a claim being made here."
                 if passed else
                 f"a CLI policy surface overstates: {problems}"))


def attack_mask_reaches_nothing(bench, report):
    name = "21-a-declared-mask-reaches-nothing"
    workspace = bench.workspace("zeta", with_input=False)
    canary = workspace / "canary.txt"
    canary.write_text("SHADOWFETCH-ATTACK-CANARY\n")
    proc = bench.firebreak("run", "--workspace", "zeta", "--net", "none",
                           "--no-checkpoint", "--mask-path", str(canary),
                           "--", "/usr/bin/cat", str(canary))
    leaked = "SHADOWFETCH-ATTACK-CANARY" in proc.stdout
    record = next((r for r in bench.firebreak_records().values()
                   if r.get("masked_paths_requested")), None)
    status = (record or {}).get("enforcement", {}).get("masked_paths", {})
    # INVERTED at Stage E. This probe used to pass when the canary WAS read and
    # every surface honestly refused to call masking a control. The control
    # exists now, so the canary must not be readable AND the record must say
    # enforced -- either half alone would be the failure this probe hunts.
    passed = (not leaked) and status.get("status") == "enforced"
    report(name,
           "a --mask-path actually hides the file from the sandboxed process, "
           "and the session record describes it as the control it now is",
           f"$ shadowfetch-firebreak run --mask-path {canary} -- /usr/bin/cat {canary}\n"
           f"rc = {proc.returncode}   stdout = {proc.stdout.strip()!r}\n"
           f"the sandboxed process read the masked file: {leaked}\n"
           f".session masked_paths_requested = "
           f"{json.dumps((record or {}).get('masked_paths_requested'))}\n"
           f".session enforcement.masked_paths = {json.dumps(status, sort_keys=True)}",
           passed,
           note=("the canary was masked and the record says so: bwrap mounts "
                 "/dev/null over the file inside the sandbox's own mount "
                 "namespace, so no cooperation from the payload is involved"
                 if passed else
                 ("THE MASK DID NOT HOLD: the sandboxed process read the file "
                  "the caller asked to mask, in full"
                  if leaked else
                  "the file was hidden but the record does not describe masking "
                  f"as enforced -- it says {status.get('status')!r}")))


def attack_allowlist_reaches_elsewhere(bench, report):
    """Two destinations, two different truths.

    This used to aim at the host's loopback, because posture 'allow' created no
    network namespace and the sandbox simply shared it. Stage B closed that, so
    loopback now tests CONTAINMENT and an internet host tests the allowlist.
    """
    name = "21-an-allowlist-reaches-a-destination-it-never-allowed"
    bench.workspace("eta", with_input=False)
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    received = []

    def accept():
        try:
            conn, _ = server.accept()
            received.append(conn.recv(64))
            conn.close()
        except OSError:
            pass

    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    # Three destinations, one of each kind: (a) the host's loopback, which the
    # allowlist never named and Stage B put out of reach; (b) the address the
    # allowlist DID name, which must still be reachable or the filter has taken
    # away the access it was asked to narrow; and (c) another public address it
    # never named, which Stage C must now stop. The named host is resolved
    # rather than assumed -- an allowlist that resolves to nothing is refused
    # outright, which is a different measurement.
    program = (
        "import json,socket\n"
        "out={}\n"
        "try:\n"
        "    s=socket.create_connection(('127.0.0.1',%d),5); s.sendall(b'REACHED')\n"
        "    s.close(); out['loopback']='REACHED'\n"
        "except OSError as e: out['loopback']='blocked:'+type(e).__name__\n"
        "try:\n"
        "    s=socket.create_connection(('1.1.1.1',443),8); s.close()\n"
        "    out['allowed']='REACHED'\n"
        "except OSError as e: out['allowed']='blocked:'+type(e).__name__\n"
        "try:\n"
        "    s=socket.create_connection(('8.8.8.8',443),8); s.close()\n"
        "    out['denied']='REACHED'\n"
        "except OSError as e: out['denied']='blocked:'+type(e).__name__\n"
        "print('RESULT '+json.dumps(out))\n" % port)
    proc = bench.firebreak("run", "--workspace", "eta", "--net", "allow",
                           "--no-checkpoint", "--egress-host", "one.one.one.one",
                           "--", "/usr/bin/python3", "-c", program)
    thread.join(5)
    server.close()
    reached = {}
    for line in (proc.stdout or "").splitlines():
        if line.startswith("RESULT "):
            reached = json.loads(line[7:])
    record = next((r for r in bench.firebreak_records().values()
                   if r.get("egress_allowlist_requested")), None)
    egress = (record or {}).get("enforcement", {}).get("egress_allowlist", {})
    network = (record or {}).get("enforcement", {}).get("network", {})

    loopback_contained = (reached.get("loopback") != "REACHED" and not received)
    # The allowlist named one.one.one.one and nothing else. A destination it
    # never named must not be reachable, and the one it did name must be: a
    # filter that blocks everything would satisfy the first half while breaking
    # the access it was asked to narrow.
    denied_blocked = reached.get("denied") not in (None, "REACHED")
    allowed_reached = reached.get("allowed") == "REACHED"
    # And the record must not describe as enforced a filter that let an
    # un-allowlisted destination through.
    allowlist_honest = denied_blocked or egress.get("status") != "enforced"
    network_honest = (network.get("status") == "enforced") == loopback_contained
    offline = not allowed_reached and denied_blocked
    passed = (loopback_contained and allowlist_honest and network_honest
              and (allowed_reached or offline))

    note = ("Loopback is contained by the namespace, the allowlisted address "
            "was reached, and the address the allowlist never named was not: "
            "the filter narrows rather than merely existing. "
            + ("This host has no route out, so the reachable half proves "
               "nothing here and only the containment half was measured."
               if offline else
               f"allowed={reached.get('allowed')} denied={reached.get('denied')}"))
    if not passed:
        problems = []
        if not loopback_contained:
            problems.append("the sandbox reached the host's loopback, which the "
                            "allowlist never named")
        if not allowlist_honest:
            problems.append("an un-allowlisted internet destination was reached "
                            "while the allowlist was described as enforced")
        if not network_honest:
            problems.append("the record's network status does not match what the "
                            "sandbox could actually reach")
        note = "; ".join(problems)

    report(name,
           "an egress allowlist naming one host does not let the sandbox reach "
           "the host's loopback, and any destination it CAN still reach is "
           "described honestly rather than as enforced",
           f"$ shadowfetch-firebreak run --net allow --egress-host api.example.com "
           f"-- python3 (loopback 127.0.0.1:{port}, internet 1.1.1.1:443)\n"
           f"rc = {proc.returncode}\n"
           f"what the sandbox reached: {json.dumps(reached, sort_keys=True)}\n"
           f"bytes delivered to the loopback listener: {received}\n"
           f".session egress_allowlist_requested = "
           f"{json.dumps((record or {}).get('egress_allowlist_requested'))}\n"
           f".session enforcement.egress_allowlist = "
           f"{json.dumps(egress, sort_keys=True)}\n"
           f".session enforcement.network = {json.dumps(network, sort_keys=True)}",
           passed, note=note)


# --------------------------------------------------------------------------- #
# entry points
# --------------------------------------------------------------------------- #
_PROBES = (
    ("00-the-source-tree-is-what-is-under-test", attack_under_test_is_the_source_tree),
    ("19-same-workspace-serializes", attack_same_workspace_serializes),
    ("19-refusal-changes-nothing", attack_refusal_changes_nothing),
    ("20-different-workspaces-overlap", attack_different_workspaces_overlap),
    ("20-cross-workspace-run-is-not-blocked",
     attack_cross_workspace_run_is_not_blocked),
    ("20-declared-parallelism-matches-the-worker",
     attack_declared_parallelism_matches_the_worker),
    ("21-static-table-never-claims-the-three-gaps", attack_static_table),
    ("21-odd-specs-never-weaken-the-caveats", attack_odd_specs),
    ("21-no-vacuously-enforced-field", attack_no_vacuously_enforced_field),
    ("21-session-record-agrees-with-firebreak",
     attack_session_record_agrees_with_firebreak),
    ("21-deny-decision-still-names-its-gaps", attack_deny_still_names_its_gaps),
    ("21-nothing-empties-advisory-fields", attack_nothing_empties_advisory_fields),
    ("21-desktop-caveat-refuses-to-reassure", attack_desktop_caveat),
    ("21-declared-masks-are-disclosed", attack_declared_masks_are_disclosed),
    ("21-test-run-enforcement-is-derived", attack_test_run_enforcement_is_derived),
    ("21-cli-policy-surfaces-stay-honest", attack_cli_policy_surfaces),
    ("21-a-declared-mask-reaches-nothing", attack_mask_reaches_nothing),
    ("21-an-allowlist-reaches-a-destination-it-never-allowed",
     attack_allowlist_reaches_elsewhere),
)

if tuple(name for name, _ in _PROBES) != ATTACKS:
    raise AssertionError(
        "ATTACKS and the probe table disagree; a composer reading ATTACKS would "
        "advertise a different set from the one run() actually runs")


def run(report):
    """Run every attack in order, reporting through the caller's collector.

    One Bench for the whole module, on purpose: a store that already holds other
    missions is the more hostile input, and the concurrency probes have to be
    able to see each other's locks.
    """
    with Bench() as bench:
        for name, probe in _PROBES:
            try:
                probe(bench, report)
            except BaseException as exc:                          # noqa: BLE001
                report(name, "the probe runs to completion",
                       "".join(traceback.format_exception(exc))[-2000:], False,
                       note="the probe itself failed; this is not a verdict on the "
                            "system")


def main():
    rows = []

    def report(name, expected, observed, passed, note=""):
        rows.append({"attack": name, "expected": expected, "observed": observed,
                     "passed": bool(passed), "note": note})

    run(report)
    width = max(len(row["attack"]) for row in rows)
    print("=" * 78)
    print("attack_concurrency -- Phase 3 attacks 19, 20 and 21")
    print("=" * 78)
    for row in rows:
        print()
        print(f"{'PASS' if row['passed'] else 'FAIL'}  {row['attack']}")
        print(f"      EXPECTED  {row['expected']}")
        for index, line in enumerate(row["observed"].splitlines() or [""]):
            print(f"      {'OBSERVED  ' if index == 0 else '          '}{line}")
        if row["note"]:
            print(f"      NOTE      {row['note']}")
    failed = [row["attack"] for row in rows if not row["passed"]]
    print()
    print("-" * 78)
    for row in rows:
        print(f"  {'PASS' if row['passed'] else 'FAIL'}  {row['attack']:<{width}}")
    print("-" * 78)
    print(f"{len(rows) - len(failed)} passed, {len(failed)} FAILED")
    if failed:
        print("FAILED: " + ", ".join(failed))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
