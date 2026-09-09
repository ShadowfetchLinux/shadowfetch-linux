#!/usr/bin/env python3
"""Attacks on the approval gate: attacks 1-6 of the Phase 3 brief.

    1. Run a mission without an Approval.
    2. Reuse an expired Approval.
    3. Reuse an Approval granted for workspace A on workspace B.
    4. Reuse provider A's approval for provider B.
    5. Expand credentials after approval.
    6. Expand the network request after approval.

WHY THIS IS A MODULE AND NOT A RESULT
-------------------------------------
The engine is still being changed. A one-off transcript would be stale within
the hour, so every claim here is recomputed against whatever
packages/shadowfetch-missions/data/usr/lib/shadowfetch/missions currently holds.
Nothing is hard-coded from a previous run: an attack that starts failing because
the gap was closed is meant to flip to PASS on its own.

HOW IT DIFFERS FROM tests/test_approvals.py
-------------------------------------------
That suite already proves the straight cases: no approval, revoked, expired-in-
2000, wrong workspace, wrong provider, narrowed credentials, narrowed network,
another mission's approval, unreadable scope, and the three entry points. None of
those are repeated. These attacks go at what that suite assumed instead:

  * that the mission row names its provider the same way in every reader
  * that an approval row in the table was put there by grant_approval()
  * that the scope in the column is the scope the human agreed to
  * that expires_at is an instant (it is compared as a string)
  * that the approval checked is the approval used
  * that a scope field is a value (three of them are fnmatch patterns)

WHAT A PASS MEANS
-----------------
PASS means the system REFUSED OR CONTAINED the attempt AND the refusal changed
nothing: the mission is still queued, its approval_id is still what it was, the
workspace root digests identically, and the event chain still verifies. "It
raised" is not enough, so every case reads the row back.

Two things are known to be OBSERVED-ONLY and belong to Phase 4 rather than to
this gate -- egress destinations (Firebreak has none/allow and no destination
filter) and path masking (no masking flag exists). An attack landing on either
is a PASS only where the system refuses to CLAIM otherwise, and its record says
in plain words that the action itself was not prevented.

SAFETY
------
Nothing here executes a provider. Two attacks need a mission to actually start in
order to prove it started; for those, Executor.execute is replaced with a
sentinel that raises, so run_mission does everything it would normally do except
run the agent. No network call and no bwrap invocation is ever reached.

Every run builds its own throwaway state root with tempfile.mkdtemp() and points
all four SHADOWFETCH_* variables inside it, ignoring any it was handed. The
operator's audit log at ~/.local/state is never opened; a previous round left 100
stray files there and the cheapest way not to repeat that is to never be able to.
"""
from __future__ import annotations

# Importing the engine from the source tree writes .pyc files next to it. This
# module is read-only with respect to the repository, so byte-code writing is
# disabled BEFORE the first import rather than cleaned up afterwards.
import sys

sys.dont_write_bytecode = True

import contextlib
import dataclasses
import datetime as dt
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import traceback
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
ENGINE = REPO / "packages/shadowfetch-missions/data/usr/lib/shadowfetch/missions"
CLI = REPO / "packages/shadowfetch-missions/data/usr/bin/shadowfetch-missions"

# The state variables the engine reads. Listed once so the throwaway harness and
# the CLI subprocesses cannot drift apart about which store they are talking to.
STATE_VARS = ("SHADOWFETCH_AGENT_WORKSPACES", "SHADOWFETCH_MISSIONS_STATE",
              "SHADOWFETCH_FIREBREAK_STATE", "SHADOWFETCH_MCP_STATE")


# --------------------------------------------------------------------------- #
# Harness
# --------------------------------------------------------------------------- #
class Bench:
    """A throwaway store, two workspaces, and the readbacks every attack needs.

    Created and destroyed per run() call rather than per attack: the attacks are
    independent because each one creates its own mission, and a fresh SQLite file
    per attack would hide anything that leaks between missions in one store --
    which is exactly what a subject-confusion attack is looking for.
    """

    def __init__(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="sf-attack-approval-")).resolve()
        self._saved = {name: os.environ.get(name) for name in STATE_VARS}
        os.environ["SHADOWFETCH_AGENT_WORKSPACES"] = str(self.tmp / "ws")
        os.environ["SHADOWFETCH_MISSIONS_STATE"] = str(self.tmp / "state")
        os.environ["SHADOWFETCH_FIREBREAK_STATE"] = str(self.tmp / "fb")
        os.environ["SHADOWFETCH_MCP_STATE"] = str(self.tmp / "mcp")

        # Workspaces. "proj-secrets" exists so a prefix that is not a parent has
        # somewhere real to point, and "proj*" so a glob can be a directory name
        # rather than a hypothetical.
        for name in ("proj", "proj-secrets", "proj*"):
            (self.tmp / "ws" / name).mkdir(parents=True)
            (self.tmp / "ws" / name / "facts.md").write_text("x\n")
            (self.tmp / "ws" / name / "clip.mkv").write_bytes(b"x")

        if ENGINE not in [Path(p) for p in sys.path]:
            sys.path.insert(0, str(ENGINE))
        import sf_missions
        import sf_policy
        self.sf = sf_missions
        self.pol = sf_policy

        state_root = Path(os.environ["SHADOWFETCH_MISSIONS_STATE"]).resolve()
        # Belt and braces. mkdtemp already guarantees this; the assertion is here
        # so that a future edit which accepts an inherited path cannot silently
        # start writing into the operator's real audit log.
        assert self.tmp in state_root.parents or state_root.parent == self.tmp, state_root
        self.store = self.sf.Store()

    def close(self):
        for name, value in self._saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        shutil.rmtree(self.tmp, ignore_errors=True)

    # -- building missions -------------------------------------------------
    def cloud_mission(self, workspace="proj"):
        """A mission that escalates: the Codex provider, so credentials and
        network are both in the scope a human would have to agree to."""
        return self.store.create(kind="report", workspace_value=workspace,
                                 title="attack", prompt="p", inputs=["facts.md"])

    def offline_mission(self, workspace="proj"):
        """A mission that needs no approval at all -- the starting point for the
        'upgrade the provider afterwards' attack."""
        return self.store.create(kind="media", workspace_value=workspace,
                                 title="attack", prompt="p", inputs=["clip.mkv"])

    def approve(self, mission, **kw):
        """Grant exactly the scope this mission's decision asks for, the way the
        CLI does. Returns (approval id, decision)."""
        decision, _ceiling = self.sf.mission_decision(self.store, mission)
        aid = self.store.grant_approval(
            subject="mission:" + mission["id"], scope=kw.pop("scope", decision.scope),
            granted_by="uid:0", method="cli", **kw)
        return aid, decision

    # -- reading the world back -------------------------------------------
    def snapshot(self, mid):
        row = self.store.get(mid)
        chain = self.store.verify_chain()
        return {
            "state": row["state"],
            "approval_id": row["approval_id"],
            "attempt": row["attempt"],
            "events": [e["event"] for e in self.store.events(mid)],
            "chain_ok": chain["ok"],
            "chain_events": chain["events"],
            "chain_problems": list(chain["problems"]),
            "workspaces": self.workspace_digest(),
        }

    def workspace_digest(self):
        """Every file under the workspace ROOT, not just this mission's own
        workspace: an attack that reached a sibling workspace would otherwise
        look like it changed nothing."""
        root = Path(os.environ["SHADOWFETCH_AGENT_WORKSPACES"])
        out = {}
        for path in sorted(root.rglob("*")):
            if path.is_file():
                out[str(path.relative_to(root))] = hashlib.sha256(
                    path.read_bytes()).hexdigest()[:16]
        return out

    def diff(self, before, after, *, expect_events=()):
        """What the attempt changed, as a sentence for the OBSERVED field.

        Returns (clean, text). `clean` is the claim the brief asks for -- that a
        refusal left the mission where it was -- not merely that something
        raised. Events recorded BY the refusal are allowed and named.
        """
        new_events = after["events"][len(before["events"]):]
        parts = [f"state {before['state']}->{after['state']}",
                 f"approval_id {before['approval_id']}->{after['approval_id']}",
                 f"attempt {before['attempt']}->{after['attempt']}",
                 f"new events {new_events}",
                 f"workspace root {'identical' if before['workspaces'] == after['workspaces'] else 'CHANGED'}",
                 f"chain ok={after['chain_ok']} events={before['chain_events']}->{after['chain_events']}"]
        if after["chain_problems"]:
            parts.append(f"chain problems {after['chain_problems']}")
        clean = (before["state"] == after["state"] == "queued"
                 and before["approval_id"] == after["approval_id"]
                 and before["attempt"] == after["attempt"]
                 and before["workspaces"] == after["workspaces"]
                 and after["chain_ok"]
                 and list(new_events) == list(expect_events))
        return clean, "; ".join(parts)

    def sql(self, statement, params=()):
        """Direct SQLite writes. The user owns this file, so an attacker who has
        the account has this too; the engine's own tests say as much. What is
        under test is whether a row that was not written by grant_approval() is
        distinguishable from one that was."""
        with self.store.db() as db:
            db.execute(statement, params)

    def cli(self, *args):
        """The shipped CLI, in a subprocess, with this bench's state.

        Used where the finding must be operator-reachable rather than reachable
        only by editing the database -- a typo at a prompt is a different class
        of problem from a tampered row.
        """
        done = subprocess.run([sys.executable, str(CLI), "--json", *args],
                              capture_output=True, text=True, env=dict(os.environ),
                              timeout=120)
        return done

    @contextlib.contextmanager
    def no_provider_may_run(self):
        """Let run_mission do everything except run an agent.

        Two attacks are only proved by a mission actually reaching RUNNING. The
        provider turn is replaced by a raise, so the gate, the state machine and
        the receipt all execute for real while nothing is spawned, no credential
        is resolved and no packet leaves the host.
        """
        original = self.sf.Executor.execute

        def refuse(_self):
            raise RuntimeError("attack module: execution stopped before any provider ran")

        self.sf.Executor.execute = refuse
        try:
            yield
        finally:
            self.sf.Executor.execute = original

    @contextlib.contextmanager
    def manifest_says(self, **overrides):
        """Simulate a change to the root-owned provider manifest.

        Manifests are deliberately not environment-selectable
        (SHADOWFETCH_PROVIDER_MANIFESTS raises), so widening a provider's ceiling
        genuinely requires root. This wraps provider_for() to return the same
        provider with a doctored manifest dict, which is what the engine would
        see the moment someone with root edited the file. Nothing else about the
        provider is replaced.
        """
        original = self.sf.provider_for

        class Doctored:
            def __init__(self, inner, manifest):
                self._inner, self.manifest = inner, manifest

            def __getattr__(self, name):
                return getattr(self._inner, name)

        def doctored(capability, provider_id=None):
            provider = original(capability, provider_id)
            manifest = dict(provider.manifest)
            manifest.update(overrides)
            return Doctored(provider, manifest)

        self.sf.provider_for = doctored
        try:
            yield
        finally:
            self.sf.provider_for = original


def cli_answer(done):
    """The CLI's own answer, short enough to read and still literal.

    Its full stdout is one long JSON object; truncating it lands mid-string and
    hides the field the attack is about, so the keys that answer the question are
    picked out with their values unchanged.
    """
    try:
        payload = json.loads(done.stdout)
    except ValueError:
        return f"exit {done.returncode}: {(done.stdout + done.stderr).strip()[:300]}"
    picked = {key: payload[key] for key in ("approved", "approval", "reason",
                                            "not_enforced") if key in payload}
    return f"exit {done.returncode}: {json.dumps(picked)}"


def gate(bench, mission):
    """Call the gate the way every entry point does, and say what it said.

    require_approval() is what run_mission() calls before the state moves, so it
    is the honest place to ask "would this have been allowed to start" without
    starting anything. Returns (allowed, literal text).
    """
    try:
        approval = bench.sf.require_approval(bench.store, bench.store.get(mission["id"]))
    except bench.sf.ApprovalRequired as exc:
        return False, f"ApprovalRequired: {exc}"
    except bench.sf.MissionError as exc:
        return False, f"MissionError: {exc}"
    return True, f"require_approval returned {approval!r} -- the mission may start"


# --------------------------------------------------------------------------- #
# Attack 1: run a mission without an approval
# --------------------------------------------------------------------------- #
def unapproved_start_disguised_as_offline(bench, report):
    """Ask for the cloud provider with the network switched off, hoping the
    escalation is attached to the network rather than to the provider."""
    try:
        bench.store.create(kind="report", workspace_value="proj", title="attack",
                           prompt="p", inputs=["facts.md"], network="none")
        observed = "the mission was created; no refusal"
        passed = False
    except bench.sf.MissionError as exc:
        observed = f"MissionError: {exc}"
        passed = True
    report("unapproved-start-disguised-as-offline",
           "a cloud provider cannot be booked with network=none to dodge the escalation",
           observed, passed,
           note="the refusal comes from the provider's own accepts(), before a "
                "mission row exists, so there is nothing to approve or to leave queued")


def provider_id_laundering(bench, report):
    """Remove the provider id the GATE reads while leaving the one the EXECUTOR
    reads. mission_decision() resolves provider_id from the column then from
    config['provider_id']; Executor.provider falls back a third time, to
    config['runtime'], which the gate never consults."""
    mission = bench.cloud_mission()
    config = dict(bench.store.get(mission["id"])["config"])
    config.pop("provider_id", None)
    bench.sql("UPDATE missions SET provider_id=NULL, config=? WHERE id=?",
              (json.dumps(config), mission["id"]))
    row = bench.store.get(mission["id"])
    decision, _ = bench.sf.mission_decision(bench.store, row)
    allowed, said = gate(bench, mission)
    executor = bench.sf.Executor(bench.store, bench.store.get(mission["id"]))
    resolved = executor.provider.id

    before = bench.snapshot(mission["id"])
    with bench.no_provider_may_run():
        try:
            result = bench.sf.run_mission(bench.store, mission["id"])
            ran = f"run_mission returned state={result['state']!r} error={result['error']!r}"
        except Exception as exc:                                  # noqa: BLE001
            ran = f"run_mission raised {exc.__class__.__name__}: {exc}"
    after = bench.snapshot(mission["id"])
    _clean, changed = bench.diff(before, after)

    observed = (f"config left runtime={config.get('runtime')!r} and no provider_id; "
                f"mission_decision returned {decision!r}; {said}; "
                f"Executor.provider resolved to {resolved!r}; {ran}; {changed}")
    report("provider-id-laundering",
           "the gate resolves the provider the same way the executor does, so a "
           "mission that will run Codex is escalated for Codex",
           observed, after["state"] == "queued" and not allowed,
           note="mission_decision() reads mission['provider_id'] then "
                "config['provider_id']; Executor.provider adds a third fallback, "
                "LEGACY_RUNTIME_PROVIDER[config['runtime']]. One reader more than "
                "the other is the whole bug. The mission reached RUNNING with "
                "approval_id NULL and no approval event of any kind; only this "
                "module's sentinel stopped the provider turn")


def forged_approval_row(bench, report):
    """Insert an approval directly. The chain records grants as events, so the
    question is whether an approval with no grant event is distinguishable."""
    mission = bench.cloud_mission()
    decision, _ = bench.sf.mission_decision(bench.store, mission)
    before = bench.snapshot(mission["id"])
    bench.sql("INSERT INTO approvals(id,subject,scope,granted_by,method,granted_at,"
              "expires_at,reason) VALUES(?,?,?,?,?,?,?,?)",
              ("appr-forged000000000", "mission:" + mission["id"],
               decision.scope.to_json(), "uid:0", "cli", bench.sf.now(), None,
               "written straight into the table"))
    allowed, said = gate(bench, mission)
    after = bench.snapshot(mission["id"])
    _clean, changed = bench.diff(before, after, expect_events=["approval-used"])
    observed = (f"{said}; mission events {after['events']} -- there is no "
                f"'approval-granted' anywhere in the chain; verify_chain ok="
                f"{after['chain_ok']} problems={after['chain_problems']}; {changed}")
    report("forged-approval-row",
           "an approval the audit chain never recorded being granted is refused, "
           "or the chain reports the discrepancy",
           observed, not allowed,
           note="the events table is hash-chained; the approvals table is not, and "
                "nothing cross-checks one against the other. The mission's own log "
                "reads queued -> approval-used with no grant in between, and "
                "verify_chain() still says ok")


def approval_scope_widened_after_grant(bench, report):
    """Grant honestly, then widen the scope column.

    test_approvals.py already tampers with a scope, but sets it to
    {"capability": "*"} alone -- which fails because the OTHER fields become
    empty strings and _covers_value refuses an empty grant. Widen every field
    instead and the same tamper is honoured, because three of the fields are
    matched with fnmatch and '*' is treated as a deliberate human widening.
    """
    mission = bench.cloud_mission()
    aid, decision = bench.approve(mission)
    grant_event = [e for e in bench.store.events(mission["id"])
                   if e["event"] == "approval-granted"]
    before = bench.snapshot(mission["id"])
    wildcard = json.dumps({"capability": "*", "provider": "*", "workspace": "*",
                           "network": "allow", "paths": ["*"],
                           "credential_ids": list(decision.scope.credential_ids)},
                          sort_keys=True)
    bench.sql("UPDATE approvals SET scope=? WHERE id=?", (wildcard, aid))
    allowed, said = gate(bench, mission)
    after = bench.snapshot(mission["id"])
    _clean, changed = bench.diff(before, after, expect_events=["approval-used"])
    observed = (f"scope column rewritten to {wildcard}; {said}; the grant event "
                f"detail is {grant_event[0]['detail']!r}, which does not carry the "
                f"scope, so nothing in the chain contradicts the new one; "
                f"verify_chain ok={after['chain_ok']}; {changed}")
    report("approval-scope-widened-after-grant",
           "a scope rewritten after the grant is refused, or the chain shows the "
           "approval no longer matches what was recorded",
           observed, not allowed,
           note="what a human agreed to is stored only in the mutable approvals "
                "row; the chained approval-granted event records subject, granter "
                "and method but not the scope, so widening it afterwards leaves "
                "nothing to compare against")


def approval_for_an_unknown_mission(bench, report):
    """Approve a mission id that does not exist. If it is accepted, an approval
    can be planted before its subject, and the chain gains an event about a
    mission no reader can open."""
    ghost = "mission-" + "0" * 16
    scope = bench.pol.Scope(capability="sourced_report", provider="codex",
                            workspace="*", network="allow",
                            credential_ids=("CODEX_API_KEY",), paths=("*",))
    try:
        aid = bench.store.grant_approval(subject="mission:" + ghost, scope=scope,
                                         granted_by="uid:0", method="cli")
        accepted = f"grant_approval returned {aid!r}"
        passed = False
    except bench.sf.MissionError as exc:
        accepted = f"MissionError: {exc}"
        passed = True
    with bench.store.db() as db:
        planted = [dict(r) for r in db.execute(
            "SELECT seq,mission,event,actor,detail FROM events WHERE mission=?",
            (ghost,)).fetchall()]
    try:
        readable = str(bench.store.events(ghost))
    except bench.sf.MissionError as exc:
        readable = f"Store.events({ghost!r}) raises MissionError: {exc}"
    chain = bench.store.verify_chain()
    report("approval-for-an-unknown-mission",
           "an approval whose subject does not exist is refused when it is granted",
           f"{accepted}; events table now holds {planted}; {readable}; "
           f"verify_chain ok={chain['ok']}",
           passed,
           note="the row is inert until a mission with that id exists, so this is "
                "not a start. It is an approval that can be planted in advance and "
                "an audit entry about a mission that cannot be opened -- the "
                "normal reader raises rather than showing it")


# --------------------------------------------------------------------------- #
# Attack 2: reuse an expired approval
# --------------------------------------------------------------------------- #
def expiry_at_this_instant(bench, report):
    """Expiry exactly equal to the current instant. The comparison is
    `expires_at <= now`, so the boundary should be closed."""
    mission = bench.cloud_mission()
    stamp = bench.sf.now()
    bench.approve(mission, expires_at=stamp)
    before = bench.snapshot(mission["id"])
    allowed, said = gate(bench, mission)
    after = bench.snapshot(mission["id"])
    clean, changed = bench.diff(before, after, expect_events=["approval-required"])
    report("expiry-at-this-instant",
           "an approval whose expiry is the current instant is already expired",
           f"granted with expires_at={stamp!r}; {said}; {changed}",
           (not allowed) and clean)


def expiry_in_a_nonzero_offset(bench, report):
    """An approval that expired an hour ago, written in +10:00.

    find_approval compares expires_at to now() as TEXT. Both strings are valid
    ISO-8601 instants; only one of them is UTC. The clock reads later, so the
    string sorts later, so an expiry in the past reads as the future.
    """
    mission = bench.cloud_mission()
    past = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1)
    skewed = past.astimezone(dt.timezone(dt.timedelta(hours=10))).isoformat(timespec="seconds")
    done = bench.cli("approve", mission["id"], "--expires-at", skewed)
    stored = bench.store.approvals("mission:" + mission["id"])[0]
    stamp = bench.sf.now()
    really_expired = dt.datetime.fromisoformat(skewed) < dt.datetime.now(dt.timezone.utc)
    before = bench.snapshot(mission["id"])
    allowed, said = gate(bench, mission)
    after = bench.snapshot(mission["id"])
    clean, changed = bench.diff(before, after, expect_events=["approval-required"])
    report("expiry-in-a-nonzero-offset",
           "an approval that has expired as an INSTANT is refused whatever offset "
           "it was written in",
           f"CLI approve --expires-at {skewed!r} -> {cli_answer(done)}; stored "
           f"expires_at={stored['expires_at']!r}; that instant is in the past "
           f"({really_expired}); now()={stamp!r}; as text {skewed!r} > {stamp!r} is "
           f"{skewed > stamp}; {said}; {changed}",
           (not allowed) and clean,
           note="reachable with no database access at all: an operator in UTC+10 "
                "typing their own local time gets an approval that outlives its "
                "expiry by the size of the offset")


def expiry_that_is_not_a_date(bench, report):
    """The CLI takes --expires-at as an opaque string and stores it unparsed.
    A value that is not a date never sorts below a timestamp beginning with a
    digit, so it means 'never expires'."""
    mission = bench.cloud_mission()
    done = bench.cli("approve", mission["id"], "--expires-at", "yesterday")
    rows = bench.store.approvals("mission:" + mission["id"])
    # The approval may not exist at all now: an unreadable expiry is refused
    # while a person is watching, which is the stronger of the two acceptable
    # outcomes. Both are checked, because either one closes the finding.
    stored = rows[0]["expires_at"] if rows else "(no approval was created)"
    before = bench.snapshot(mission["id"])
    allowed, said = gate(bench, mission)
    after = bench.snapshot(mission["id"])
    clean, changed = bench.diff(before, after, expect_events=["approval-required"])
    report("expiry-that-is-not-a-date",
           "an expiry that cannot be read as an instant is rejected when it is "
           "typed, or treated as already expired",
           f"CLI approve --expires-at yesterday -> {cli_answer(done)}; stored "
           f"expires_at={stored!r}; "
           f"{said}; {changed}",
           (not allowed) and clean,
           note="an unreadable SCOPE is refused ('has an unreadable scope'); an "
                "unreadable EXPIRY is silently taken to mean no expiry, so the "
                "typo fails open in the one place a human was trying to add a limit")


def revoke_inside_the_check_window(bench, report):
    """Revoke between the check and the use.

    find_approval() reads the row and require_approval() then records and uses
    it; revoke_approval() takes no workspace lock, so the two can interleave.
    The revoke is fired from inside find_approval here to make the race
    deterministic rather than to widen it.
    """
    mission = bench.cloud_mission()
    aid, _ = bench.approve(mission)
    original = bench.sf.Store.find_approval

    def racing(store, subject, required):
        row, why = original(store, subject, required)
        if row is not None:
            store.revoke_approval(row["id"], reason="revoked while the mission was starting")
        return row, why

    bench.sf.Store.find_approval = racing
    try:
        allowed, said = gate(bench, mission)
    finally:
        bench.sf.Store.find_approval = original
    row = bench.store.approvals("mission:" + mission["id"])[0]
    after = bench.snapshot(mission["id"])
    report("revoke-inside-the-check-window",
           "an approval revoked before it is used is not used",
           f"{said}; approval row now revoked_at={row['revoked_at']!r}; mission "
           f"approval_id={after['approval_id']!r}; mission events {after['events']}",
           not allowed,
           note="the approval is read once, at the start, and never re-read; the "
                "mission's log therefore ends approval-revoked then approval-used, "
                "in that order, and the mission carries a revoked approval id")


# --------------------------------------------------------------------------- #
# Attack 3: an approval for workspace A used on workspace B
# --------------------------------------------------------------------------- #
def workspace_prefix_sibling(bench, report):
    """.../proj is a prefix of .../proj-secrets but not its parent. The paths
    field of a scope tests exactly this; the workspace field is matched
    differently, and is what an approval is actually bound by."""
    mission = bench.cloud_mission(workspace="proj-secrets")
    decision, _ = bench.sf.mission_decision(bench.store, mission)
    sibling = dataclasses.replace(
        decision.scope,
        workspace=str(Path(os.environ["SHADOWFETCH_AGENT_WORKSPACES"]) / "proj"))
    bench.approve(mission, scope=sibling)
    before = bench.snapshot(mission["id"])
    allowed, said = gate(bench, mission)
    after = bench.snapshot(mission["id"])
    clean, changed = bench.diff(before, after, expect_events=["approval-required"])
    report("workspace-prefix-sibling",
           "an approval naming a workspace that is a string prefix of this one "
           "does not cover it",
           f"approved workspace {sibling.workspace!r}, mission workspace "
           f"{decision.scope.workspace!r}; {said}; {changed}",
           (not allowed) and clean)


def workspace_glob_in_the_scope(bench, report):
    """A workspace whose directory NAME is a glob.

    approval_covers matches capability, provider and workspace with
    fnmatchcase, on the stated grounds that a wildcard is a widening a human
    typed. workspace() accepts '*' in a directory name, so an approval granted
    entirely through the CLI can hold a pattern nobody typed.
    """
    starred = bench.cloud_mission(workspace="proj*")
    star_decision, _ = bench.sf.mission_decision(bench.store, starred)
    other = bench.cloud_mission(workspace="proj-secrets")
    other_decision, _ = bench.sf.mission_decision(bench.store, other)
    covers, why = bench.pol.approval_covers(star_decision.scope, other_decision.scope)

    # Granted honestly, for the mission in the glob-named workspace. Nothing is
    # tampered with; the attack is to see whether the second workspace's mission
    # can reach it.
    aid, _ = bench.approve(starred)
    before = bench.snapshot(other["id"])
    allowed, said = gate(bench, other)
    after = bench.snapshot(other["id"])
    clean, changed = bench.diff(before, after, expect_events=["approval-required"])
    report("workspace-glob-in-the-scope",
           "an approval for one workspace cannot be made to cover another by the "
           "pattern matching in approval_covers",
           f"{aid} granted for workspace {star_decision.scope.workspace!r}; "
           f"approval_covers(that, {other_decision.scope.workspace!r}) = "
           f"({covers}, {why!r}); attacking the second mission with it: {said}; "
           f"{changed}",
           (not allowed) and clean and covers,
           note="PASS on containment, not on the scope: approval_covers DOES say "
                "the pattern covers the sibling workspace, and a directory named "
                "with a '*' is creatable, so a scope granted entirely through the "
                "CLI can hold a pattern nobody typed. Nothing carries it anywhere "
                "because the approval is bound to one mission id -- the subject "
                "binding is the only thing standing between a glob and a second "
                "workspace. Verified by asserting covers is True above")


def workspace_root_repointed(bench, report):
    """Keep the approval, move the world underneath it.

    The scope stores the workspace as an absolute path, so re-pointing
    SHADOWFETCH_AGENT_WORKSPACES at a different root holding a same-named
    workspace is the closest thing to running an approval for A inside B.
    """
    mission = bench.cloud_mission()
    bench.approve(mission)
    alternate = bench.tmp / "ws2"
    (alternate / "proj").mkdir(parents=True, exist_ok=True)
    (alternate / "proj" / "facts.md").write_text("z\n")
    before = bench.snapshot(mission["id"])
    os.environ["SHADOWFETCH_AGENT_WORKSPACES"] = str(alternate)
    try:
        with bench.no_provider_may_run():
            try:
                result = bench.sf.run_mission(bench.store, mission["id"])
                ran = f"run_mission returned state={result['state']!r}"
            except Exception as exc:                              # noqa: BLE001
                ran = f"run_mission raised {exc.__class__.__name__}: {exc}"
        landed = sorted(p.name for p in (alternate / "proj").iterdir())
        stranded = bench.store.get(mission["id"])["state"]
    finally:
        os.environ["SHADOWFETCH_AGENT_WORKSPACES"] = str(bench.tmp / "ws")
    with bench.store.lock(workspace=bench.store.get(mission["id"])["workspace"]):
        bench.store.recover(workspace=bench.store.get(mission["id"])["workspace"])
    recovered = bench.store.get(mission["id"])["state"]
    after = bench.snapshot(mission["id"])
    _clean, changed = bench.diff(before, after)
    report("workspace-root-repointed",
           "an approval naming workspace A never runs anything in workspace B, "
           "and refusing leaves the mission where it was",
           f"{ran}; the second root still holds {landed} (untouched); mission state "
           f"after the refusal was {stranded!r}, and store.recover() then made it "
           f"{recovered!r}; {changed}",
           stranded == "queued",
           note="the reuse itself was prevented -- workspace() refuses a path whose "
                "parent is not the current root, and nothing was written under the "
                "second root. The refusal is not clean: run_mission builds the "
                "Executor AFTER transitioning to RUNNING and OUTSIDE the try/finally "
                "that writes a receipt, so the mission is left running with no "
                "receipt until the next recover()")


# --------------------------------------------------------------------------- #
# Attack 4: provider A's approval used for provider B
# --------------------------------------------------------------------------- #
def approval_subject_is_not_a_mission(bench, report):
    """Approve the provider, the workspace, and everything, rather than the
    mission. grant_approval takes any subject string; find_approval only ever
    looks up 'mission:<id>'."""
    mission = bench.cloud_mission()
    decision, _ = bench.sf.mission_decision(bench.store, mission)
    broad = bench.pol.Scope(capability="*", provider="*", workspace="*",
                            network="allow",
                            credential_ids=decision.scope.credential_ids, paths=("*",))
    subjects = ("*", "mission:*", "provider:codex",
                "workspace:" + decision.scope.workspace, mission["id"])
    for subject in subjects:
        bench.store.grant_approval(subject=subject, scope=broad, granted_by="uid:0",
                                   method="cli")
    before = bench.snapshot(mission["id"])
    allowed, said = gate(bench, mission)
    after = bench.snapshot(mission["id"])
    clean, changed = bench.diff(before, after, expect_events=["approval-required"])
    report("approval-subject-is-not-a-mission",
           "an approval that names anything other than this mission does not "
           "cover it, however broad its scope",
           f"granted wildcard scopes under subjects {list(subjects)}; {said}; {changed}",
           (not allowed) and clean,
           note="grant_approval accepts any subject string and files the event "
                "under mission '*' when it is not a mission; none of them are "
                "reachable from the lookup, which asks only for mission:<id>")


def provider_swapped_after_approval(bench, report):
    """Approve for the cloud provider, then point the row at the offline one."""
    mission = bench.cloud_mission()
    bench.approve(mission)
    before = bench.snapshot(mission["id"])
    bench.sql("UPDATE missions SET provider_id='offline-media' WHERE id=?",
              (mission["id"],))
    allowed, said = gate(bench, mission)
    after = bench.snapshot(mission["id"])
    clean, changed = bench.diff(before, after, expect_events=[])
    report("provider-swapped-after-approval",
           "an approval granted for one provider does not carry to another",
           f"{said}; {changed}",
           (not allowed) and clean,
           note="refused before the scope is even compared: the swapped provider "
                "does not perform this capability, so mission_decision raises")


def provider_upgraded_after_approval(bench, report):
    """Start from a mission that needs no approval at all -- the offline media
    provider auto-allows -- and swap in the cloud provider afterwards. The
    decision is recomputed at run time, so the upgrade should be caught."""
    mission = bench.offline_mission()
    decision, _ = bench.sf.mission_decision(bench.store, mission)
    started_as = decision.outcome
    before = bench.snapshot(mission["id"])
    bench.sql("UPDATE missions SET provider_id='codex', capability='sourced_report',"
              "kind='report' WHERE id=?", (mission["id"],))
    allowed, said = gate(bench, mission)
    after = bench.snapshot(mission["id"])
    clean, changed = bench.diff(before, after, expect_events=["approval-required"])
    report("provider-upgraded-after-approval",
           "a mission that needed no approval cannot acquire a credentialled "
           "provider and keep its approval-free status",
           f"created as {started_as!r} (offline-media, no approval needed); after "
           f"the swap to codex: {said}; {changed}",
           (not allowed) and clean)


def capability_swapped_after_approval(bench, report):
    """Same provider, different capability. Codex performs both code_change and
    sourced_report, so the scope differs in one field and nothing else."""
    mission = bench.cloud_mission()
    bench.approve(mission)
    before = bench.snapshot(mission["id"])
    bench.sql("UPDATE missions SET capability='code_change', kind='code' WHERE id=?",
              (mission["id"],))
    allowed, said = gate(bench, mission)
    after = bench.snapshot(mission["id"])
    clean, changed = bench.diff(before, after, expect_events=["approval-required"])
    report("capability-swapped-after-approval",
           "an approval for one capability does not cover another performed by "
           "the same provider",
           f"{said}; {changed}",
           (not allowed) and clean)


# --------------------------------------------------------------------------- #
# Attack 5: expand credentials after approval
# --------------------------------------------------------------------------- #
def credential_ceiling_widened(bench, report):
    """Approve, then widen the credential identities the provider may be given.

    A mission cannot widen this itself -- the set comes from the root-owned
    manifest and the mission's config can only narrow -- so the attack is the
    root-level edit, and the question is whether the previously valid approval
    survives it.
    """
    mission = bench.cloud_mission()
    bench.approve(mission)
    before = bench.snapshot(mission["id"])
    with bench.manifest_says(credential_ids=["CODEX_API_KEY", "ANTHROPIC_API_KEY"]):
        widened, _ = bench.sf.mission_decision(bench.store, bench.store.get(mission["id"]))
        allowed, said = gate(bench, mission)
    after = bench.snapshot(mission["id"])
    clean, changed = bench.diff(before, after, expect_events=["approval-required"])
    report("credential-ceiling-widened",
           "an approval stops covering the mission the moment the identity set "
           "grows, whoever grew it",
           f"scope after the manifest gained a second identity: "
           f"{widened.scope.to_json()}; {said}; {changed}",
           (not allowed) and clean,
           note="the decision is recomputed from the manifest at every start, so "
                "the approval is matched against what the mission will be allowed "
                "to do rather than what it declared when it was approved")


def credential_alias_substitution(bench, report):
    """The approval names an IDENTITY. Ask which environment variable's value is
    injected under that name when the identity's own variable is unset."""
    mission = bench.cloud_mission()
    decision, _ = bench.sf.mission_decision(bench.store, mission)
    row = bench.store.get(mission["id"])
    provider = bench.sf.provider_for(row["capability"], row["provider_id"])
    saved = {name: os.environ.get(name) for name in ("CODEX_API_KEY", "OPENAI_API_KEY")}
    marker = "not-a-real-key-planted-by-the-attack-module"
    try:
        os.environ.pop("CODEX_API_KEY", None)
        os.environ["OPENAI_API_KEY"] = marker
        # credentials_for() uses no instance state; calling it unbound resolves
        # identities without constructing an Executor or running anything.
        resolved = bench.sf.Executor.credentials_for(None, provider)
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
    injected = sorted(resolved)
    approved = sorted(decision.scope.credential_ids)
    from_alias = {name: (value == marker) for name, value in resolved.items()}
    report("credential-alias-substitution",
           "only identities named in the approved scope are injected",
           f"approved identities {approved}; injected identities {injected}; "
           f"value taken from the OPENAI_API_KEY alias: {from_alias}",
           injected == approved,
           note="no undeclared identity appears, so the scope holds. Worth saying "
                "plainly anyway: the manifest declares OPENAI_API_KEY as an alias "
                "for CODEX_API_KEY, so a person approving 'CODEX_API_KEY' with only "
                "OPENAI_API_KEY set in their environment is handing over that "
                "variable's value. The approval names the identity, not the source")


# --------------------------------------------------------------------------- #
# Attack 6: expand the network request after approval
# --------------------------------------------------------------------------- #
def network_value_forged_in_config(bench, report):
    """Write a network posture into the config that create() would never accept,
    and see whether the ceiling moves."""
    mission = bench.cloud_mission()
    _aid, decision = bench.approve(mission)
    before = bench.snapshot(mission["id"])
    config = dict(bench.store.get(mission["id"])["config"])
    config["network"] = "unrestricted"
    bench.sql("UPDATE missions SET config=? WHERE id=?",
              (json.dumps(config), mission["id"]))
    forged, ceiling = bench.sf.mission_decision(bench.store, bench.store.get(mission["id"]))
    allowed, said = gate(bench, mission)
    after = bench.snapshot(mission["id"])
    _clean, changed = bench.diff(before, after, expect_events=["approval-used"])
    report("network-value-forged-in-config",
           "a network posture the mission never legitimately had does not widen "
           "what it is allowed to reach",
           f"config network set to 'unrestricted'; recomputed scope network="
           f"{forged.scope.network!r} (was {decision.scope.network!r}); sandbox "
           f"ceiling network={ceiling.network!r} egress={list(ceiling.egress_allowlist)}; "
           f"{said}; {changed}",
           forged.scope.network == decision.scope.network and after["state"] == "queued",
           note="the ceiling is the manifest's, and the mission's own choice can "
                "only narrow it, so nothing widens. The engine does not reject the "
                "unknown value either -- anything that is not 'none' is read as "
                "'the provider's declared posture' -- which is safe here only "
                "because the manifest is the ceiling")


def egress_widened_after_approval(bench, report):
    """Add a destination after the approval was granted.

    Scope carries capability, provider, workspace, network, credential_ids and
    paths. It does not carry egress hosts, so this asks whether the approval can
    tell that the destination list changed -- and, since Firebreak has no
    destination filter, whether the system says so instead of pretending.
    """
    mission = bench.cloud_mission()
    bench.approve(mission)
    before = bench.snapshot(mission["id"])
    with bench.manifest_says(egress_allowlist=["api.openai.com", "attacker.example"]):
        widened, ceiling = bench.sf.mission_decision(bench.store, bench.store.get(mission["id"]))
        allowed, said = gate(bench, mission)
    after = bench.snapshot(mission["id"])
    _clean, changed = bench.diff(before, after, expect_events=["approval-used"])
    matrix = bench.pol.PolicyEngine.capability_matrix()["network_destination"]
    stored = bench.store.approvals("mission:" + mission["id"])[0]
    honest = (matrix["mediation"] == bench.pol.OBSERVABLE_ONLY
              and "network_destination" in widened.advisory_fields)
    report("egress-widened-after-approval",
           "either the approval stops covering a mission whose destinations "
           "changed, or the system states that destinations are not something it "
           "enforces or records agreement to",
           f"ceiling egress is now {list(ceiling.egress_allowlist)}; the approval "
           f"granted at {stored['granted_at']} still covers it ({said}); its stored "
           f"scope is {stored['scope']} -- no host appears in it; capability matrix "
           f"says network_destination = {matrix['mediation']!r} ({matrix['mechanism']}); "
           f"decision.advisory_fields = {list(widened.advisory_fields)}; {changed}",
           honest,
           note="THE DESTINATION CHANGE WAS NOT PREVENTED AND WAS NOT DETECTED. "
                "PASS is only for the claim: the engine marks network_destination "
                "observable_only, lists it in advisory_fields, and the CLI prints "
                "it under 'not_enforced' when the approval is granted, so nobody is "
                "told the hosts are enforced. What a human agrees to is the posture "
                "'this reaches the internet', never a host list -- Firebreak has "
                "none/allow and no destination filter (Phase 4)")


# --------------------------------------------------------------------------- #
# Composition
# --------------------------------------------------------------------------- #
# One list. ATTACKS is derived from it so the published order and the executed
# order cannot drift apart.
_CASES = (
    # 1. run a mission without an approval
    ("unapproved-start-disguised-as-offline", unapproved_start_disguised_as_offline),
    ("provider-id-laundering", provider_id_laundering),
    ("forged-approval-row", forged_approval_row),
    ("approval-scope-widened-after-grant", approval_scope_widened_after_grant),
    ("approval-for-an-unknown-mission", approval_for_an_unknown_mission),
    # 2. reuse an expired approval
    ("expiry-at-this-instant", expiry_at_this_instant),
    ("expiry-in-a-nonzero-offset", expiry_in_a_nonzero_offset),
    ("expiry-that-is-not-a-date", expiry_that_is_not_a_date),
    ("revoke-inside-the-check-window", revoke_inside_the_check_window),
    # 3. an approval for workspace A used on workspace B
    ("workspace-prefix-sibling", workspace_prefix_sibling),
    ("workspace-glob-in-the-scope", workspace_glob_in_the_scope),
    ("workspace-root-repointed", workspace_root_repointed),
    # 4. provider A's approval used for provider B
    ("approval-subject-is-not-a-mission", approval_subject_is_not_a_mission),
    ("provider-swapped-after-approval", provider_swapped_after_approval),
    ("provider-upgraded-after-approval", provider_upgraded_after_approval),
    ("capability-swapped-after-approval", capability_swapped_after_approval),
    # 5. expand credentials after approval
    ("credential-ceiling-widened", credential_ceiling_widened),
    ("credential-alias-substitution", credential_alias_substitution),
    # 6. expand the network request after approval
    ("network-value-forged-in-config", network_value_forged_in_config),
    ("egress-widened-after-approval", egress_widened_after_approval),
)

ATTACKS = tuple(name for name, _ in _CASES)


def run(report):
    """Run every attack, calling report(name, expected, observed, passed, note='').

    An attack that raises is reported as a FAILED attack carrying its traceback
    rather than taking the run down: this module is pointed at an engine that is
    still being edited, and one broken case must not hide the other nineteen.
    """
    bench = Bench()
    try:
        for name, case in _CASES:
            try:
                case(bench, report)
            except Exception:                                     # noqa: BLE001
                report(name, "the attack runs to a verdict",
                       "the attack itself raised:\n" + traceback.format_exc(),
                       False, note="not a result about the engine; this module or "
                                   "the interface it calls has moved")
    finally:
        bench.close()


def main():
    results = []

    def report(name, expected, observed, passed, note=""):
        results.append({"attack": name, "expected": expected, "observed": observed,
                        "passed": bool(passed), "note": note})

    run(report)

    width = max(len(r["attack"]) for r in results)
    print("=" * (width + 8))
    print("attack_approval.py -- approvals, attacks 1-6")
    print("=" * (width + 8))
    for result in results:
        print(f"{result['attack']:<{width}}  {'PASS' if result['passed'] else 'FAIL'}")
    print()
    for result in results:
        print("-" * 78)
        print(f"ATTACK    {result['attack']}")
        print(f"EXPECTED  {result['expected']}")
        print(f"OBSERVED  {result['observed']}")
        if result["note"]:
            print(f"NOTE      {result['note']}")
        print(f"VERDICT   {'PASS' if result['passed'] else 'FAIL'}")
    print("-" * 78)
    failed = [r["attack"] for r in results if not r["passed"]]
    print(f"{len(results) - len(failed)}/{len(results)} PASS. "
          + ("FAILED: " + ", ".join(failed) if failed else "no findings."))
    print("A FAILED attack is a finding: the system could not refuse or contain it.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
