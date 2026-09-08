"""The Phase 3 control plane as the desktop exposes it, and the line it must hold.

Phase 3 put mission state, approvals, the policy decision and the audit chain
behind one CLI. The desktop's whole job here is to ASK and RENDER. Two failures
are worth a test rather than a review comment, because both are invisible in a
screenshot:

  * a decision reproduced in Qt, which makes the desktop a second policy owner
    that can disagree with the engine and be right-looking while doing it
  * a declared control drawn as though it were enforced -- an egress allowlist
    presented as a firewall rule is the exact claim this phase removes

The source assertions are in the style of test_capabilities_contract.py's
test_the_ui_names_no_provider_in_its_logic: read the REAL desktop source, ask the
REAL engine for the words it owns, and fail when they have met.

Run with QT_QPA_PLATFORM=offscreen python3 -m unittest discover
-s packages/shadowfetch-control-center/tests
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
ROOT = Path(__file__).resolve().parents[3]
SFCC = (ROOT / "packages/shadowfetch-control-center/data/usr/share/shadowfetch"
        / "control-center/sfcc")
ENGINE_LIB = ROOT / "packages/shadowfetch-missions/data/usr/lib/shadowfetch/missions"
ENGINE_BIN = ROOT / "packages/shadowfetch-missions/data/usr/bin/shadowfetch-missions"
sys.path.insert(0, str(SFCC.parent))

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QApplication
from sfcc import missions_page
from sfcc.missions_page import (MissionsPage, approval_line, audit_text,
                                caveat_text, decision_text, mission_text,
                                records_text)

APP = QApplication.instance() or QApplication([])

VOCABULARY_PROBE = """
import json, sys
sys.path.insert(0, sys.argv[1])
import sf_missions, sf_policy
print(json.dumps({
    "policy_outcomes": [sf_policy.AUTO_ALLOW, sf_policy.ESCALATE, sf_policy.DENY],
    "mediation_levels": [sf_policy.FULLY_MEDIATED, sf_policy.PARTIALLY_MEDIATED,
                         sf_policy.OBSERVABLE_ONLY, sf_policy.NOT_OBSERVABLE],
    "policy_controls": sorted(sf_policy.POLICY_MEDIATION),
    "mission_states": list(sf_missions.MISSION_STATES),
    "mission_transitions": [[a, b] for (a, b) in sf_missions.MISSION_TRANSITIONS if a],
    "task_states": list(sf_missions.TASK_STATES),
    "task_events": sorted(event for event, _ in sf_missions.TASK_TRANSITIONS.values()),
    "mission_events": sorted({event for event, _ in
                              sf_missions.MISSION_TRANSITIONS.values()}),
}))
"""


def engine_vocabulary():
    """Ask the engine package, in its own process, for the words it owns.

    Importing it into the desktop's test process would be the very coupling
    these tests exist to forbid, and would prove nothing about the shipped
    desktop, which has no access to it at all.
    """
    out = subprocess.run([sys.executable, "-c", VOCABULARY_PROBE, str(ENGINE_LIB)],
                         capture_output=True, text=True, timeout=120)
    if out.returncode != 0:
        raise AssertionError("engine vocabulary probe failed: " + out.stderr[-2000:])
    return json.loads(out.stdout)


def uncommented(path):
    return "\n".join(line for line in path.read_text().splitlines()
                     if not line.lstrip().startswith("#"))


class StubClient:
    """Answers in the engine's shapes and records every argv the desktop sends.

    Class attributes rather than constructor arguments because the page builds
    its own client, which is the coupling the real page has.
    """
    missions = []
    detail = {}
    decision = {}
    approvals = []
    audit = {}
    errors = {}

    def __init__(self, *_):
        self.calls = []

    def call(self, arguments, callback):
        self.calls.append(list(arguments))
        verb = arguments[0]
        if verb in self.errors:
            callback(None, self.errors[verb])
        elif verb == "list":
            callback([dict(m) for m in self.missions], None)
        elif verb == "capabilities":
            callback({}, None)
        elif verb == "show":
            callback(dict(self.detail), None)
        elif verb == "events":
            callback([], None)
        elif verb == "diff":
            callback({"diff": ""}, None)
        elif verb == "policy":
            callback(dict(self.decision), None)
        elif verb == "approvals":
            callback([dict(row) for row in self.approvals], None)
        elif verb == "audit":
            callback(dict(self.audit), None)
        elif verb in ("approve", "revoke"):
            callback({"granted": True}, None)
        else:
            callback(None, "This test did not describe an answer for " + verb)

    def review(self, arguments, callback, on_waiting):
        self.calls.append(list(arguments))

    def grok_status(self, callback):
        callback({"installed": False, "verified": False, "launchable": False}, None)


DECISION = {
    "outcome": "escalate",
    "reasons": ["this mission requests network access (allowlist)"],
    "scope": {"capability": "code_change", "provider": "an-agent",
              "workspace": "/w", "network": "allowlist",
              "credential_ids": ["A_KEY"], "paths": []},
    "mediation": {
        "network_on_off": {"mediation": "fully_mediated",
                           "mechanism": "a namespace with no route",
                           "relied_on": False},
        "network_destination": {"mediation": "observable_only",
                                "mechanism": "declared hosts are recorded and "
                                             "nothing filters packets",
                                "relied_on": True},
    },
    "advisory_fields": ["network_destination"],
}

MISSION = {"id": "m1", "state": "waiting-review", "title": "T", "checkpoint": "ck",
           "workspace": "/w", "receipt": "/r", "attempt": 1, "cancel_requested": 0,
           "approval_id": None, "provider_id": "an-agent", "capability": "code_change",
           "config": {"network": "allow", "provider_id": "an-agent"}, "artifacts": []}

APPROVALS = [
    {"id": "appr-one", "granted_at": "2026-09-08T00:00:00+00:00",
     "granted_by": "uid:1000", "method": "cli", "expires_at": None, "revoked_at": None},
    {"id": "appr-two", "granted_at": "2026-09-08T01:00:00+00:00",
     "granted_by": "uid:1000", "method": "cli", "expires_at": None,
     "revoked_at": "2026-09-08T02:00:00+00:00"},
]


def build_page():
    page = MissionsPage(lambda _: None)
    APP.processEvents()
    page.timer.stop()
    return page


def close_page(page):
    page.timer.stop()
    page.deleteLater()
    APP.processEvents()


class DesktopKeepsNoEngineKnowledge(unittest.TestCase):
    """Nothing the engine decides may have a second copy in Qt."""

    @classmethod
    def setUpClass(cls):
        cls.words = engine_vocabulary()
        cls.mission_surface = {
            name: uncommented(SFCC / name)
            for name in ("missions_page.py", "mission_client.py")}
        cls.desktop = {path.name: uncommented(path) for path in sorted(SFCC.glob("*.py"))}

    def assert_absent(self, tokens, why):
        for name, code in self.mission_surface.items():
            for token in tokens:
                for quoted in ('"%s"' % token, "'%s'" % token):
                    with self.subTest(file=name, token=quoted):
                        self.assertNotIn(quoted, code, why)

    def test_no_policy_outcome_is_named_in_the_desktop(self):
        """A button that compares against an outcome has re-decided it."""
        self.assert_absent(self.words["policy_outcomes"],
                           "the desktop names a policy outcome; ask the engine and "
                           "render its answer instead of branching on it")

    def test_no_mediation_level_is_named_in_the_desktop(self):
        """Deciding locally which levels count as enforced is how a declared
        control gets drawn as a firewall rule."""
        self.assert_absent(self.words["mediation_levels"],
                           "the desktop names a mediation level; print the level the "
                           "engine reported, do not classify it")

    def test_no_policy_control_name_is_hardcoded_in_the_desktop(self):
        """Special-casing one control is how the others stop being shown."""
        self.assert_absent(self.words["policy_controls"],
                           "the desktop hardcodes a policy control name; render the "
                           "rows the engine sends")

    def test_no_task_state_or_task_transition_event_is_named_in_the_desktop(self):
        """Task states the desktop cannot reach except by reimplementing the
        task machine. The three mission states share names with task states, so
        only the task-only words are checked."""
        task_only = sorted(set(self.words["task_states"])
                           - set(self.words["mission_states"]))
        self.assertTrue(task_only, "expected task states the missions do not share")
        self.assert_absent(task_only + self.words["task_events"],
                           "the desktop names a task state or task event; task "
                           "records are the engine's to publish")

    def test_the_desktop_never_assigns_a_mission_state(self):
        """Reading a state is rendering. Writing one is owning the machine."""
        for name, code in self.mission_surface.items():
            with self.subTest(file=name):
                self.assertIsNone(re.search(r"""\bstate\s*=\s*["']""", code),
                                  "the desktop sets a mission state; it may only "
                                  "send a verb and re-read")
                self.assertNotIn('"state":', code,
                                 "the desktop writes a state field")

    def test_the_desktop_labels_exactly_the_engine_states(self):
        """An engine state with no label renders as a raw token, and a label for
        a state that no longer exists is dead copy nobody notices."""
        self.assertEqual(sorted(missions_page.STATES), sorted(self.words["mission_states"]))
        overlap = set(missions_page.STATES.values()) & set(self.words["mission_states"])
        self.assertEqual(set(), overlap,
                         "a display label is spelled the same as an engine state, so "
                         "the two vocabularies can no longer be told apart")

    def test_the_desktop_never_imports_the_engine_or_opens_its_database(self):
        """The CLI is the desktop IPC boundary. The one exception is the shared
        secret redactor, which decides nothing."""
        for name, code in self.desktop.items():
            with self.subTest(file=name):
                self.assertNotIn("sqlite", code)
                for module in ("sf_missions", "sf_policy", "sf_providers", "sf_audit"):
                    self.assertNotIn(module, code,
                                     "the desktop imports engine internals")


class ActionAvailabilityMatchesTheEngine(unittest.TestCase):
    """The one action table still living in Qt, pinned to the engine's edges.

    _buttons() maps a mission state to the actions it offers, which is the same
    knowledge as MISSION_TRANSITIONS. It agrees today and this is what stops the
    two drifting apart in silence. It becomes deletable the moment `show`
    publishes the actions the engine will accept.
    """

    @classmethod
    def setUpClass(cls):
        cls.words = engine_vocabulary()

    def test_every_action_button_follows_the_engines_transition_table(self):
        edges = {(frm, to) for frm, to in self.words["mission_transitions"]}
        with patch("sfcc.missions_page.MissionClient", StubClient):
            page = build_page()
            for state in self.words["mission_states"]:
                # A checkpoint and a receipt are present so the comparison is
                # against the state edge alone, not against missing evidence.
                page.selected = dict(MISSION, state=state)
                page._buttons()
                for action, target in (("accept", "completed"), ("undo", "undone"),
                                       ("cancel", "cancelled"), ("retry", "queued")):
                    with self.subTest(state=state, action=action):
                        self.assertEqual(page.actions[action].isEnabled(),
                                         (state, target) in edges)
            close_page(page)


class RenderingIsFaithful(unittest.TestCase):
    def test_a_declared_control_is_reported_as_not_enforced(self):
        text = caveat_text(DECISION)
        self.assertIn(missions_page.NOT_ENFORCED_HEADING, text)
        self.assertIn("network_destination", text)
        self.assertIn("observable_only", text)
        self.assertIn("nothing filters packets", text)

    def test_the_scope_and_its_caveats_name_the_same_posture(self):
        """The scope says allowlist; on its own that reads as a filter."""
        self.assertIn("allowlist", decision_text(DECISION))
        self.assertIn("network_destination", caveat_text(DECISION))

    def test_an_empty_advisory_list_and_an_absent_one_read_differently(self):
        """The first version of this enshrined a false claim: both cases printed
        "every control is applied by a mechanism outside Mission Control", so a
        reply that never carried the field reassured the reader. The DENY path
        emitted exactly that reply."""
        empty = caveat_text(dict(DECISION, advisory_fields=[]))
        absent = caveat_text({k: v for k, v in DECISION.items()
                              if k != "advisory_fields"})
        self.assertNotEqual(empty, absent)
        self.assertIn("could not determine", absent)
        self.assertIn("Treat nothing here as enforced", absent)
        self.assertIn("relies on no control", empty)
        for text in (empty, absent):
            self.assertNotIn(missions_page.NOT_ENFORCED_HEADING, text)

    def test_the_unenforced_heading_says_what_it_means(self):
        """S1: the heading carrying the whole honesty guarantee was only ever
        compared against itself, so inverting it to "Controls enforced for this
        decision:" passed every test."""
        heading = missions_page.NOT_ENFORCED_HEADING.lower()
        self.assertIn("not", heading)
        self.assertNotRegex(heading, r"^controls enforced")

    def test_the_caveat_block_is_actually_on_screen_and_below_the_decision(self):
        """S2 and S3: deleting the caveat widget entirely, or moving it above
        the decision, passed all 97 tests -- they read .text() on the label
        object and never asked whether it was in the layout."""
        page = build_page()
        self.addCleanup(close_page, page)
        layout = page.caveat_view.parentWidget().layout()
        positions = {}
        for index in range(layout.count()):
            item = layout.itemAt(index).widget()
            if item is page.caveat_view:
                positions["caveat"] = index
            if item is page.decision_view:
                positions["decision"] = index
        self.assertIn("caveat", positions, "the caveat block is not in any layout")
        self.assertIn("decision", positions)
        self.assertGreater(positions["caveat"], positions["decision"],
                           "the caveats must sit below the decision they qualify")

    def test_a_missing_decision_is_not_rendered_as_an_allowance(self):
        self.assertIn("No policy decision", decision_text(None))
        self.assertEqual("", caveat_text(None))

    def test_absent_record_sets_are_not_rendered_as_empty_ones(self):
        text = records_text({})
        for heading in ("Steps", "Agent sessions", "Test runs", "Review"):
            with self.subTest(heading=heading):
                self.assertIn(heading + ": not reported.", text)
        self.assertIn("Steps: none recorded.", records_text({"tasks": []}))

    def test_present_record_sets_render_the_engines_own_fields(self):
        text = records_text({
            "tasks": [{"seq": 1, "kind": "inference", "state": "succeeded",
                       "exit_code": 0}],
            "sessions": [{"id": "sess-1", "provider_id": "an-agent",
                          "network_requested": "allowlist",
                          "network_effective": "allow", "ended_at": None}],
            "test_runs": [{"command": ["true"], "exit_code": 0, "result": "pass"}],
            "reviews": [{"requested_at": "t0", "decision": "accept",
                         "decided_by": "uid:1000"}],
        })
        self.assertIn("seq: 1", text)
        self.assertIn("state: succeeded", text)
        self.assertIn("network_requested: allowlist", text)
        self.assertIn("network_effective: allow", text)
        self.assertIn("ended_at: not recorded", text)
        self.assertIn("result: pass", text)
        self.assertIn("decision: accept", text)

    def test_audit_reports_a_broken_chain_as_broken(self):
        text = audit_text({"ok": False, "events": 9, "chained": 9, "unchained": 0,
                           "head_seq": 9, "head": "abc", "problems": ["seq 4 digest"],
                           "anchor": {"verdict": "agrees", "identifier": "x"}})
        self.assertIn("Chain: BROKEN", text)
        self.assertNotIn("intact", text)
        self.assertIn("PROBLEM: seq 4 digest", text)

    def test_an_unreadable_anchor_is_not_folded_into_the_chains_verdict(self):
        """An intact chain proves the rows agree with each other. Only the
        anchor speaks to truncation, so an unreadable one has to stay visible."""
        text = audit_text({"ok": True, "events": 3, "chained": 3, "unchained": 0,
                           "head_seq": 3, "head": "abc", "problems": [],
                           "anchor": {"verdict": "unverified", "identifier": "x",
                                      "reason": "the journal could not be read"}})
        self.assertIn("Chain: intact", text)
        self.assertIn("External anchor: unverified", text)
        self.assertIn("the journal could not be read", text)

    def test_rows_written_before_the_chain_are_reported_as_such(self):
        text = audit_text({"ok": True, "events": 10, "chained": 4, "unchained": 6,
                           "head_seq": 10, "head": "abc", "problems": [],
                           "anchor": {"verdict": "agrees", "identifier": "x"}})
        self.assertIn("unchained: 6", text)
        self.assertIn("not individually verifiable", text)

    def test_a_failed_verification_is_not_an_answer(self):
        self.assertIn("could not be verified", audit_text(None, "the tool did not answer"))
        self.assertIn("has not been verified", audit_text(None))

    def test_the_mission_line_separates_what_was_asked_from_what_happened(self):
        text = mission_text(dict(MISSION, cancel_requested=1))
        self.assertIn("Connection requested: allow", text)
        self.assertIn("Stop requested: yes", text)
        self.assertIn("Approval recorded against this mission: not recorded", text)
        self.assertIn("Performed by: an-agent", text)

    def test_an_approval_line_shows_expiry_and_revocation_without_judging_them(self):
        line = approval_line(APPROVALS[1])
        self.assertIn("appr-two", line)
        self.assertIn("expires: not recorded", line)
        self.assertIn("revoked: 2026-09-08T02:00:00+00:00", line)


class ControlPanelAsksTheEngine(unittest.TestCase):
    def setUp(self):
        StubClient.missions = [MISSION]
        StubClient.detail = MISSION
        StubClient.decision = DECISION
        StubClient.approvals = APPROVALS
        StubClient.audit = {"ok": True, "events": 3, "chained": 3, "unchained": 0,
                            "head_seq": 3, "head": "abcdef", "problems": [],
                            "anchor": {"verdict": "agrees", "identifier": "x"}}
        StubClient.errors = {}
        self.patcher = patch("sfcc.missions_page.MissionClient", StubClient)
        self.patcher.start()
        self.page = build_page()
        self.page.selected_id = "m1"
        self.page._shown("m1", dict(MISSION), None)

    def tearDown(self):
        close_page(self.page)
        self.patcher.stop()
        StubClient.errors = {}

    def argv_for(self, verb):
        return [call for call in self.page.client.calls if call[0] == verb]

    def test_the_control_plane_has_its_own_tab(self):
        titles = [self.page.tabs.tabText(i) for i in range(self.page.tabs.count())]
        self.assertIn("Control", titles)

    def test_selecting_a_mission_asks_for_its_decision_and_approvals(self):
        self.assertIn(["policy", "show", "m1"], self.page.client.calls)
        self.assertIn(["approvals", "m1"], self.page.client.calls)
        self.assertIn("Decision: escalate", self.page.decision_view.text())
        self.assertIn("network_destination", self.page.caveat_view.text())
        self.assertEqual(2, self.page.approvals.count())

    def test_the_audit_chain_is_verified_by_asking_the_engine(self):
        self.assertIn(["audit", "verify"], self.page.client.calls)
        self.assertIn("Chain: intact", self.page.audit_view.text())

    def test_the_audit_chain_is_not_reverified_on_every_queue_poll(self):
        """Verification recomputes the whole chain; the queue polls every three
        seconds. Attaching one to the other would make the desktop the heaviest
        reader of its own audit log."""
        before = len(self.argv_for("audit"))
        self.page.refresh()
        self.page._shown("m1", dict(MISSION), None)
        self.assertEqual(before, len(self.argv_for("audit")))

    def test_approve_sends_the_mission_id_and_nothing_else(self):
        self.page._approve()
        self.assertEqual([["approve", "m1"]], self.argv_for("approve"))

    def test_a_refused_approval_changes_nothing(self):
        StubClient.errors = {"approve": "Approval was already revoked"}
        before_selected = dict(self.page.selected or {})
        before_rows = [self.page.approvals.item(i).text()
                       for i in range(self.page.approvals.count())]
        before_decision = self.page.decision_view.text()
        self.page._approve()
        self.assertEqual([["approve", "m1"]], self.argv_for("approve"))
        self.assertEqual("Approval was already revoked", self.page.approval_notice.text())
        self.assertEqual(before_selected, dict(self.page.selected or {}))
        self.assertEqual(before_rows, [self.page.approvals.item(i).text()
                                       for i in range(self.page.approvals.count())])
        self.assertEqual(before_decision, self.page.decision_view.text())
        self.assertEqual([], self.argv_for("revoke"))
        self.assertEqual([], self.argv_for("review"))
        self.assertEqual([], self.argv_for("cancel"))
        self.assertFalse(self.page._mutation_pending)

    def test_revoke_names_the_approval_the_person_selected(self):
        self.page.approvals.setCurrentRow(1)
        self.page._revoke()
        self.assertEqual([["revoke", "appr-two"]], self.argv_for("revoke"))

    def test_revoke_is_unavailable_until_an_approval_is_selected(self):
        self.page.approvals.setCurrentItem(None)
        self.page._approval_buttons()
        self.assertFalse(self.page.revoke_button.isEnabled())
        self.page._revoke()
        self.assertEqual([], self.argv_for("revoke"))

    def test_a_mission_with_no_approval_offers_nothing_to_revoke(self):
        StubClient.approvals = []
        try:
            self.page._shown("m1", dict(MISSION), None)
            self.assertEqual(1, self.page.approvals.count())
            self.assertIn("No approval has been granted", self.page.approvals.item(0).text())
            self.page.approvals.setCurrentRow(0)
            self.page._approval_buttons()
            self.assertFalse(self.page.revoke_button.isEnabled())
        finally:
            StubClient.approvals = APPROVALS

    def test_an_engine_refusal_to_decide_is_shown_not_swallowed(self):
        StubClient.errors = {"policy": "This mission uses a retired provider"}
        self.page._shown("m1", dict(MISSION), None)
        self.assertIn("retired provider", self.page.decision_view.text())
        self.assertEqual("", self.page.caveat_view.text())

    def test_a_late_answer_cannot_paint_another_missions_control_plane(self):
        self.page.selected_id = "m2"
        self.page._policy_ready("m1", dict(DECISION, outcome="auto"), None)
        self.assertNotIn("Decision: auto", self.page.decision_view.text())

    def test_records_the_engine_does_not_publish_are_shown_as_unreported(self):
        self.assertIn("Steps: not reported.", self.page.records_view.text())


class RealEngineControlContract(unittest.TestCase):
    """Every key the panel renders, taken from the real CLI on a real database."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        root = Path(cls.tmp.name)
        (root / "Workspaces/demo").mkdir(parents=True)
        cls.env = dict(os.environ,
                       SHADOWFETCH_AGENT_WORKSPACES=str(root / "Workspaces"),
                       SHADOWFETCH_MISSIONS_STATE=str(root / "state"),
                       XDG_STATE_HOME=str(root / "xdg"))
        cls.mission = cls.run_cli(["create", "--kind", "code", "--workspace", "demo",
                                   "--title", "T", "--prompt", "p",
                                   "--network", "allow", "--test-json", '["true"]'])

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    @classmethod
    def run_cli(cls, arguments, expect_success=True):
        out = subprocess.run([sys.executable, str(ENGINE_BIN), "--json", *arguments],
                             capture_output=True, text=True, env=cls.env, timeout=180)
        if expect_success and out.returncode != 0:
            raise AssertionError("engine %s failed: %s %s"
                                 % (arguments, out.stdout[-2000:], out.stderr[-2000:]))
        return json.loads(out.stdout)

    def test_policy_show_carries_every_field_the_panel_renders(self):
        decision = self.run_cli(["policy", "show", self.mission["id"]])
        for key in ("outcome", "reasons", "scope", "mediation", "advisory_fields"):
            self.assertIn(key, decision)
        self.assertIn(decision["outcome"], decision_text(decision))
        self.assertTrue(decision["advisory_fields"],
                        "a networked mission that relies on nothing unenforced would "
                        "mean the caveat block has no live example")
        rendered = caveat_text(decision)
        for name in decision["advisory_fields"]:
            self.assertIn(name, decision["mediation"])
            self.assertIn(name, rendered)
            self.assertIn(decision["mediation"][name]["mediation"], rendered)
            self.assertIn(decision["mediation"][name]["mechanism"][:40], rendered)

    def test_the_engine_refuses_an_unapproved_run_and_the_mission_is_unchanged(self):
        before = self.run_cli(["show", self.mission["id"]])
        refused = self.run_cli(["run", self.mission["id"]], expect_success=False)
        self.assertIn("needs approval", refused.get("error", ""))
        after = self.run_cli(["show", self.mission["id"]])
        self.assertEqual(before["state"], after["state"])
        self.assertEqual(before, after)
        self.assertEqual([], self.run_cli(["approvals", self.mission["id"]]))

    def test_an_approval_round_trip_carries_every_field_the_panel_renders(self):
        mission = self.run_cli(["create", "--kind", "code", "--workspace", "demo",
                                "--title", "T2", "--prompt", "p", "--network", "allow",
                                "--test-json", '["true"]'])
        granted = self.run_cli(["approve", mission["id"]])
        self.assertTrue(granted["approved"])
        rows = self.run_cli(["approvals", mission["id"]])
        self.assertEqual(1, len(rows))
        for key in ("id", "granted_at", "granted_by", "method", "expires_at",
                    "revoked_at"):
            self.assertIn(key, rows[0])
        self.assertIn(rows[0]["id"], approval_line(rows[0]))
        self.run_cli(["revoke", rows[0]["id"]])
        revoked = self.run_cli(["approvals", mission["id"]])[0]
        self.assertTrue(revoked["revoked_at"])
        self.assertIn(revoked["revoked_at"], approval_line(revoked))
        # A second revocation is refused and leaves the record it named alone.
        again = self.run_cli(["revoke", rows[0]["id"]], expect_success=False)
        self.assertIn("already revoked", again.get("error", ""))
        self.assertEqual(revoked, self.run_cli(["approvals", mission["id"]])[0])

    def test_audit_verify_carries_every_field_the_panel_renders(self):
        report = self.run_cli(["audit", "verify"])
        for key in ("ok", "events", "chained", "unchained", "head", "head_seq",
                    "problems", "anchor"):
            self.assertIn(key, report)
        for key in ("verdict", "identifier"):
            self.assertIn(key, report["anchor"])
        rendered = audit_text(report)
        self.assertIn(str(report["events"]), rendered)
        self.assertIn(report["anchor"]["verdict"], rendered)

    def test_a_real_mission_record_renders_without_inventing_records(self):
        mission = self.run_cli(["show", self.mission["id"]])
        self.assertIn(mission["config"]["network"], mission_text(mission))
        self.assertIn("Steps: not reported.", records_text(mission))


if __name__ == "__main__":
    unittest.main(verbosity=2)
