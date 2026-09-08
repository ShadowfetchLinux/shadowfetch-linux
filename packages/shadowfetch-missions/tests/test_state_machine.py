"""Phase 3 Step 3: the mission state machine.

An invalid transition must fail closed and leave storage UNCHANGED -- not
partially applied, not applied-then-logged. Every test here therefore checks the
row, the event count and the chain after the refusal, because "it raised" is a
weaker claim than "nothing happened".
"""
import os
import sqlite3
import unittest
from pathlib import Path

import mission_states
from test_schema_migration import MigrationHarness, Store
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]
                       / "data/usr/lib/shadowfetch/missions"))
import sf_missions as sf


class StateMachineShape(unittest.TestCase):
    def test_every_transition_names_a_known_state(self):
        for (frm, to), (event, reason) in sf.MISSION_TRANSITIONS.items():
            with self.subTest(edge=(frm, to)):
                if frm is not None:
                    self.assertIn(frm, sf.MISSION_STATES)
                self.assertIn(to, sf.MISSION_STATES)
                self.assertTrue(event, "every edge emits a named event")
                self.assertTrue(reason, "every edge states why it exists")

    def test_every_state_is_reachable(self):
        reachable = {to for (_frm, to) in sf.MISSION_TRANSITIONS}
        for state in sf.MISSION_STATES:
            self.assertIn(state, reachable, f"{state} can never be entered")

    def test_no_state_is_a_dead_end_except_the_reviewed_ends(self):
        for state in sf.MISSION_STATES:
            outgoing = {to for (frm, to) in sf.MISSION_TRANSITIONS if frm == state}
            if state == sf.MissionState.UNDONE:
                self.assertEqual(outgoing, set(), "undone is final")
            elif state == sf.MissionState.COMPLETED:
                self.assertEqual(outgoing, {sf.MissionState.UNDONE})
            else:
                self.assertTrue(outgoing, f"{state} has no way out")

    def test_final_is_used_and_not_dead_code(self):
        """The audit's W-27 said 'delete or use FINAL'. It is used."""
        self.assertEqual(set(sf.FINAL),
                         {sf.MissionState.COMPLETED, sf.MissionState.UNDONE})

    def test_the_route_table_the_tests_use_agrees_with_the_machine(self):
        """mission_states.ROUTES spells the states literally. If the engine's
        spelling ever changes, this catches the drift rather than the fixtures
        silently addressing a state that no longer exists."""
        for target, route in mission_states.ROUTES.items():
            with self.subTest(target=target):
                self.assertIn(target, sf.MISSION_STATES)
                current = sf.MissionState.QUEUED
                for step in route:
                    allowed, _event, reason = sf.transition_allowed(current, step)
                    self.assertTrue(allowed, f"{current} -> {step}: {reason}")
                    current = step
                self.assertEqual(current, target)


class Harness(MigrationHarness):
    def setUp(self):
        super().setUp()
        self.store = Store(self.root)
        ws = Path(os.environ["SHADOWFETCH_AGENT_WORKSPACES"]) / "probe"
        ws.mkdir(parents=True, exist_ok=True)
        (ws / "a.mkv").write_bytes(b"clip")

    def new_mission(self):
        return self.store.create(capability="media_export", provider_id="offline-media",
                                 workspace_value="probe", title="t", prompt="p",
                                 inputs=["a.mkv"])["id"]

    def snapshot(self, mid):
        db = self.raw()
        row = dict(db.execute("SELECT * FROM missions WHERE id=?", (mid,)).fetchone())
        events = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        return row, events


class EveryLegalTransition(Harness):
    def test_each_edge_moves_the_state_and_emits_its_event(self):
        for (frm, to), (event, _reason) in sorted(
                sf.MISSION_TRANSITIONS.items(), key=lambda kv: (kv[0][0] or "", kv[0][1])):
            if frm is None:
                continue
            with self.subTest(edge=f"{frm} -> {to}"):
                mid = self.new_mission()
                mission_states.reach(self.store, mid, frm)
                before = self.store.events(mid)
                result = self.store.transition(mid, to)
                self.assertEqual(result["state"], to)
                after = self.store.events(mid)
                self.assertEqual(len(after), len(before) + 1,
                                 "a transition must emit exactly one event")
                self.assertEqual(after[-1]["event"], event)
                self.assertTrue(self.store.verify_chain()["ok"])

    def test_create_emits_the_queued_edge(self):
        mid = self.new_mission()
        events = self.store.events(mid)
        self.assertEqual([e["event"] for e in events], ["queued"])


class IllegalTransitionsFailClosed(Harness):
    """The five the brief names, plus the unknown-state case the baseline
    proved was accepted and persisted."""

    CASES = (
        ("completed", "running"),
        ("failed", "completed"),
        ("cancelled", "running"),
        ("undone", "running"),
        ("waiting-review", "queued"),
    )

    def refuse(self, frm, to):
        mid = self.new_mission()
        mission_states.reach(self.store, mid, frm)
        before_row, before_events = self.snapshot(mid)
        with self.assertRaises(sf.TransitionError) as caught:
            self.store.transition(mid, to)
        after_row, after_events = self.snapshot(mid)
        self.assertEqual(before_row, after_row, "storage changed despite the refusal")
        self.assertEqual(before_events, after_events, "a refusal emitted an event")
        self.assertTrue(self.store.verify_chain()["ok"])
        return str(caught.exception)

    def test_the_named_illegal_transitions_are_refused_and_change_nothing(self):
        for frm, to in self.CASES:
            with self.subTest(edge=f"{frm} -> {to}"):
                message = self.refuse(frm, to)
                self.assertIn(frm, message)
                self.assertIn(to, message)
                self.assertIn("may become", message,
                              "a refusal should say what IS possible")

    def test_an_unknown_state_string_is_refused(self):
        """The baseline executed store.update(mid, state='banana') and it was
        accepted and persisted."""
        message = self.refuse("queued", "banana")
        self.assertIn("is not a mission state", message)

    def test_a_repeat_of_the_current_state_is_refused(self):
        message = self.refuse("running", "running")
        self.assertIn("already running", message)

    def test_update_can_no_longer_set_the_state_at_all(self):
        mid = self.new_mission()
        before_row, before_events = self.snapshot(mid)
        with self.assertRaises(sf.TransitionError) as caught:
            self.store.update(mid, state="running")
        self.assertIn("cannot be set directly", str(caught.exception))
        self.assertEqual(self.snapshot(mid), (before_row, before_events))

    def test_update_still_refuses_columns_outside_its_allow_list(self):
        mid = self.new_mission()
        with self.assertRaises(sf.MissionError):
            self.store.update(mid, workspace="/etc")

    def test_a_transition_on_a_missing_mission_is_refused(self):
        with self.assertRaises(sf.MissionError):
            self.store.transition("mission-does-not-exist", "running")

    def test_an_undone_mission_can_never_run_again(self):
        """The baseline's damaging case: forcing undone -> queued let
        run_mission execute a finished mission again, overwrite its receipt and
        emit no event."""
        mid = self.new_mission()
        mission_states.reach(self.store, mid, "undone")
        for target in ("queued", "running"):
            with self.subTest(target=target):
                self.refuse("undone", target)


class OptimisticConcurrency(Harness):
    def test_expect_refuses_when_the_state_moved_underneath(self):
        mid = self.new_mission()
        self.store.transition(mid, "running")
        before_row, before_events = self.snapshot(mid)
        with self.assertRaises(sf.TransitionError) as caught:
            self.store.transition(mid, "waiting-review", expect="queued")
        self.assertIn("changed while you were looking at it", str(caught.exception))
        self.assertEqual(self.snapshot(mid), (before_row, before_events))

    def test_expect_allows_the_matching_case(self):
        mid = self.new_mission()
        self.store.transition(mid, "running", expect="queued")
        self.assertEqual(self.store.get(mid)["state"], "running")


class TransitionAtomicity(Harness):
    def test_extra_fields_land_with_the_state_not_beside_it(self):
        mid = self.new_mission()
        self.store.transition(mid, "running", attempt=7, error=None)
        row = self.store.get(mid)
        self.assertEqual((row["state"], row["attempt"]), ("running", 7))

    def test_an_invalid_extra_field_is_refused_before_anything_is_written(self):
        mid = self.new_mission()
        before = self.snapshot(mid)
        with self.assertRaises(sf.MissionError):
            self.store.transition(mid, "running", workspace="/etc")
        self.assertEqual(self.snapshot(mid), before)

    def test_the_event_and_the_state_share_one_transaction(self):
        """A state change with no event is invisible; an event describing a
        change that rolled back is a lie. Neither is representable."""
        mid = self.new_mission()
        original = sf.Store._append

        def explode(self, db, **kwargs):
            raise sqlite3.OperationalError("simulated failure after the UPDATE")

        sf.Store._append = explode
        try:
            with self.assertRaises(sqlite3.OperationalError):
                self.store.transition(mid, "running")
        finally:
            sf.Store._append = original
        self.assertEqual(self.store.get(mid)["state"], "queued",
                         "the state change survived a failed event write")


class EngineVerbsUseTheMachine(Harness):
    def test_cancel_of_a_queued_mission_is_a_real_transition(self):
        mid = self.new_mission()
        self.store.cancel(mid)
        row = self.store.get(mid)
        self.assertEqual(row["state"], "cancelled")
        self.assertEqual(row["cancel_requested"], 1)
        self.assertEqual(self.store.events(mid)[-1]["event"], "cancelled")

    def test_cancel_of_a_running_mission_only_asks(self):
        mid = self.new_mission()
        self.store.transition(mid, "running")
        self.store.cancel(mid)
        row = self.store.get(mid)
        self.assertEqual(row["state"], "running", "a running mission is asked, not told")
        self.assertEqual(row["cancel_requested"], 1)

    def test_cancel_is_refused_for_anything_not_active(self):
        mid = self.new_mission()
        mission_states.reach(self.store, mid, "completed")
        with self.assertRaises(sf.MissionError):
            self.store.cancel(mid)

    def test_retry_transitions_and_records(self):
        mid = self.new_mission()
        mission_states.reach(self.store, mid, "failed")
        self.store.retry(mid)
        self.assertEqual(self.store.get(mid)["state"], "queued")
        self.assertEqual(self.store.events(mid)[-1]["event"], "retry-queued")

    def test_recover_transitions_running_to_failed_with_an_event(self):
        mid = self.new_mission()
        self.store.transition(mid, "running")
        self.store.recover()
        row = self.store.get(mid)
        self.assertEqual(row["state"], "failed")
        self.assertIn("interrupted", row["error"].lower())
        self.assertEqual(self.store.events(mid)[-1]["event"], "failed")
        self.assertTrue(self.store.verify_chain()["ok"])

    def test_recover_leaves_non_running_missions_alone(self):
        mid = self.new_mission()
        before = self.snapshot(mid)
        self.store.recover()
        self.assertEqual(self.snapshot(mid), before)


if __name__ == "__main__":
    unittest.main(verbosity=2)
