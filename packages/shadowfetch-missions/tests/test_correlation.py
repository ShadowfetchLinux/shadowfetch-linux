"""Phase 3 Steps 5, 6 and 12: one correlation identity, sessions, tasks.

The claim being tested is navigational: starting from a mission id a person can
reach every task, session, process and event it produced -- and starting from a
Firebreak session id they can get back to the mission. Both directions, because
an audit trail that only reads forwards is no use to somebody holding a systemd
scope name.
"""
import importlib.machinery
import importlib.util
import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

from test_schema_migration import MigrationHarness, Store

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "packages/shadowfetch-missions/data/usr/lib/shadowfetch/missions"))
import sf_missions as sf
import sf_providers as P

FIREBREAK = REPO / "packages/shadowfetch-fireline/data/usr/bin/shadowfetch-firebreak"


def load_firebreak():
    loader = importlib.machinery.SourceFileLoader("fb_under_test", str(FIREBREAK))
    spec = importlib.util.spec_from_loader("fb_under_test", loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class FirebreakAcceptsOurIdentity(unittest.TestCase):
    def setUp(self):
        self.fb = load_firebreak()

    def test_an_orchestrator_id_is_adopted(self):
        self.assertEqual(self.fb.session_id("sess-abc123"), "sess-abc123")

    def test_no_id_still_mints_one(self):
        self.assertTrue(self.fb.session_id(None).startswith("fb-"))
        self.assertTrue(self.fb.session_id("").startswith("fb-"))

    def test_a_hostile_id_is_refused(self):
        """The id becomes a systemd unit name, a filename and an environment
        variable inside the sandbox. All three are injection surfaces."""
        for bad in ("../../etc/passwd", "a b", "unit;rm -rf /", "--property=Foo=bar",
                    "x" * 65, "-leading-dash", "semi;colon", "new\nline"):
            with self.subTest(value=bad):
                with self.assertRaises(self.fb.Error):
                    self.fb.session_id(bad)

    def test_the_manifest_records_where_the_id_came_from(self):
        """A reader must be able to tell an adopted id from a minted one:
        only the first proves the orchestrator was involved."""
        source = FIREBREAK.read_text()
        self.assertIn("session_id_source", source)


class SessionRecords(MigrationHarness):
    def setUp(self):
        super().setUp()
        self.store = Store(self.root)
        self.mid = self.real_mission()

    def real_mission(self):
        ws = Path(os.environ["SHADOWFETCH_AGENT_WORKSPACES"]) / "probe"
        ws.mkdir(parents=True, exist_ok=True)
        (ws / "a.mkv").write_bytes(b"clip")
        return self.store.create(capability="media_export",
                                 provider_id="offline-media",
                                 workspace_value="probe", title="t", prompt="p",
                                 inputs=["a.mkv"])["id"]

    def open_one(self, **overrides):
        spec = P.SandboxSpec(workspace_mode="workspace-write", network="none",
                             memory_mb=512, cpu_seconds=60, processes=16)
        kwargs = dict(
            task_id=None, provider_id="offline-media", provider_version="4.0.0",
            provider_trust="distro-managed", attempt=1,
            requested_sandbox={"network": "none"},
            effective_sandbox={"network": "none"},
            enforcement=P.sandbox_enforcement(spec),
            credentials_requested=("CODEX_API_KEY",),
            credentials_granted=("CODEX_API_KEY",),
            read_grants=("/usr/share",), network_requested="none",
            egress_requested=("api.example",), network_effective="none",
            executable="/usr/bin/ffmpeg", executable_trust="distro-managed",
            command="/usr/bin/ffmpeg -version")
        kwargs.update(overrides)
        return self.store.open_session(self.mid, **kwargs)

    def test_a_session_exists_before_anything_runs(self):
        sid = self.open_one()
        row = self.store.session(sid)
        self.assertEqual(row["outcome"], None)
        self.assertEqual(row["exit_code"], None)
        self.assertIsNotNone(row["started_at"])

    def test_opening_and_closing_each_emit_a_correlated_event(self):
        sid = self.open_one()
        self.store.close_session(sid, exit_code=0, outcome="completed")
        events = [e for e in self.store.events(self.mid)]
        names = [e["event"] for e in events]
        self.assertIn("session-opened", names)
        self.assertIn("session-closed", names)
        with self.store.db() as db:
            rows = db.execute(
                "SELECT event,session_id FROM events WHERE session_id=?", (sid,)).fetchall()
        self.assertEqual({r["event"] for r in rows}, {"session-opened", "session-closed"})

    def test_requested_and_effective_are_recorded_separately(self):
        """One 'sandbox' column would make a declared control indistinguishable
        from an enforced one."""
        sid = self.open_one(requested_sandbox={"network": "allowlist"},
                            effective_sandbox={"network": "none"})
        row = self.store.session(sid)
        self.assertNotEqual(row["requested_sandbox"], row["effective_sandbox"])

    def test_the_enforcement_map_is_stored_per_field(self):
        row = self.store.session(self.open_one())
        self.assertEqual(row["enforcement"]["network"]["status"], "enforced")
        # This session declares no egress hosts, so the honest answer is
        # not_applicable rather than a warning about a control it never asked
        # for. What must never appear is "enforced".
        self.assertEqual(row["enforcement"]["egress_allowlist"]["status"],
                         "not_applicable")
        self.assertEqual(row["enforcement"]["masked_paths"]["status"],
                         "not_applicable")

    def test_an_egress_allowlist_is_recorded_as_requested_never_as_enforced(self):
        row = self.store.session(self.open_one())
        self.assertEqual(list(row["egress_requested"]), ["api.example"])
        self.assertIn(row["enforcement"]["egress_allowlist"]["status"],
                      ("not_enforced", "not_applicable"))

    def test_only_credential_identities_are_stored(self):
        """A value has never reached this row and must not."""
        row = self.store.session(self.open_one())
        blob = json.dumps(row)
        self.assertIn("CODEX_API_KEY", blob)
        for column in ("credentials_requested", "credentials_granted"):
            for entry in row[column]:
                self.assertRegex(entry, r"^[A-Z0-9_]+$",
                                 "this looks like a value, not an identity")

    def test_a_firebreak_id_resolves_back_to_the_mission(self):
        sid = self.open_one()
        self.store.close_session(sid, exit_code=0, outcome="completed",
                                 firebreak_session=sid)
        found = self.store.session_for_firebreak(sid)
        self.assertIsNotNone(found)
        self.assertEqual(found["mission_id"], self.mid)

    def test_an_unknown_firebreak_id_resolves_to_nothing_rather_than_guessing(self):
        self.assertIsNone(self.store.session_for_firebreak("fb-not-ours"))


class TaskRecords(MigrationHarness):
    def setUp(self):
        super().setUp()
        self.store = Store(self.root)
        self.mid = self.real_mission()

    def real_mission(self):
        ws = Path(os.environ["SHADOWFETCH_AGENT_WORKSPACES"]) / "probe"
        ws.mkdir(parents=True, exist_ok=True)
        (ws / "a.mkv").write_bytes(b"clip")
        return self.store.create(capability="media_export",
                                 provider_id="offline-media",
                                 workspace_value="probe", title="t", prompt="p",
                                 inputs=["a.mkv"])["id"]

    def test_a_task_is_created_pending_and_emits_an_event(self):
        row = self.store.create_task(self.mid, kind=sf.TaskKind.CHECKPOINT, seq=1)
        self.assertEqual(row["state"], sf.TaskState.PENDING)
        self.assertEqual(self.store.events(self.mid)[-1]["event"], "task-created")

    def test_every_legal_task_edge_works_and_emits_once(self):
        for (frm, to), (event, _reason) in sf.TASK_TRANSITIONS.items():
            if frm is None:
                continue
            with self.subTest(edge=f"{frm} -> {to}"):
                seq = len(self.store.tasks(self.mid)) + 1
                row = self.store.create_task(self.mid, kind="probe", seq=seq)
                tid = row["id"]
                if frm != sf.TaskState.PENDING:
                    self.store.task_transition(tid, sf.TaskState.RUNNING)
                before = len(self.store.events(self.mid))
                self.store.task_transition(tid, to)
                after = self.store.events(self.mid)
                self.assertEqual(len(after), before + 1)
                self.assertEqual(after[-1]["event"], event)

    def test_an_illegal_task_edge_is_refused_and_changes_nothing(self):
        row = self.store.create_task(self.mid, kind="probe", seq=1)
        tid = row["id"]
        self.store.task_transition(tid, sf.TaskState.RUNNING)
        self.store.task_transition(tid, sf.TaskState.SUCCEEDED)
        before = self.store.task(tid)
        before_events = len(self.store.events(self.mid))
        with self.assertRaises(sf.TransitionError):
            self.store.task_transition(tid, sf.TaskState.RUNNING)
        self.assertEqual(self.store.task(tid), before)
        self.assertEqual(len(self.store.events(self.mid)), before_events)

    def test_timestamps_are_set_by_the_transition_not_the_caller(self):
        tid = self.store.create_task(self.mid, kind="probe", seq=1)["id"]
        self.store.task_transition(tid, sf.TaskState.RUNNING)
        self.assertIsNotNone(self.store.task(tid)["started_at"])
        self.store.task_transition(tid, sf.TaskState.SUCCEEDED)
        self.assertIsNotNone(self.store.task(tid)["finished_at"])

    def test_depends_on_is_stored_so_a_dag_stays_possible(self):
        first = self.store.create_task(self.mid, kind="a", seq=1)["id"]
        second = self.store.create_task(self.mid, kind="b", seq=2, depends_on=[first])
        self.assertEqual(second["depends_on"], [first])


class EnforcementTableIsHonest(unittest.TestCase):
    def test_the_production_table_matches_the_audited_one(self):
        """The audit table lives in a test and fails a build if a field drifts.
        The production table is what a session record and a receipt read. If
        they disagree, one of them is lying to somebody."""
        from test_sandbox_spec_audit import AUDIT
        audited = {row["field"]: row for row in AUDIT}
        for field, entry in P.SANDBOX_ENFORCEMENT.items():
            if field == "syscall_profile":
                continue                     # tracked in the audit as SECCOMP_PROFILE
            with self.subTest(field=field):
                self.assertIn(field, audited, "production names a field the audit does not")
                expected = audited[field]["enforced"]
                status = entry[0]
                if expected == "yes":
                    self.assertEqual(status, P.ENFORCED)
                elif expected == "partial":
                    self.assertEqual(status, P.PARTIAL)
                else:
                    self.assertEqual(status, P.NOT_ENFORCED)

    def test_the_unenforced_list_is_exactly_the_known_gaps(self):
        """masked_paths left in Stage E, egress_allowlist in Stage C. Only the
        syscall profile remains, and it is not even representable."""
        self.assertEqual(P.unenforced_fields(), ["syscall_profile"])

    def test_a_field_with_nothing_declared_is_not_applicable_rather_than_a_warning(self):
        spec = P.SandboxSpec(workspace_mode="workspace-write", network="none",
                             egress_allowlist=(), masked_paths=())
        status = P.sandbox_enforcement(spec)
        self.assertEqual(status["egress_allowlist"]["status"], "not_applicable")

    def test_a_field_with_something_declared_keeps_its_honest_status(self):
        """It used to be 'not_enforced' here, honestly. Stage C gave it a
        mechanism, so the honest status is now 'enforced'."""
        spec = P.SandboxSpec(workspace_mode="workspace-write", network="allowlist",
                             egress_allowlist=("api.example",))
        status = P.sandbox_enforcement(spec)
        self.assertEqual(status["egress_allowlist"]["status"], "enforced")
        self.assertIn("nftables", status["egress_allowlist"]["mechanism"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
