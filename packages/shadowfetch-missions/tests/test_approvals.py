"""Phase 3 Steps 8, 9 and 10: approvals, the PolicyEngine, and bypass attempts.

The exit criterion is not "the UI asks". It is that a mission requiring approval
CANNOT START without a valid persisted one, enforced where every caller has to
pass. So the bypass tests below deliberately avoid the UI entirely: they call the
engine, the CLI and the worker directly, which is what an attacker or a script
would do.
"""
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

import mission_approvals
from test_schema_migration import MigrationHarness, Store

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "packages/shadowfetch-missions/data/usr/lib/shadowfetch/missions"))
import sf_missions as sf
import sf_policy as pol
import sf_providers as P

CLI = REPO / "packages/shadowfetch-missions/data/usr/bin/shadowfetch-missions"


def spec(**kw):
    base = dict(workspace_mode="workspace-write", network="none")
    base.update(kw)
    return P.SandboxSpec(**base)


class PolicyDecisions(unittest.TestCase):
    def setUp(self):
        self.engine = pol.PolicyEngine()

    def decide(self, sandbox, **kw):
        return self.engine.evaluate(capability="code_change", provider_id="p",
                                    workspace="w", sandbox=sandbox,
                                    provider_trust=kw.get("trust", "distro-managed"))

    def test_offline_and_credential_free_work_is_auto_allowed(self):
        self.assertEqual(self.decide(spec()).outcome, pol.AUTO_ALLOW)

    def test_network_escalates(self):
        d = self.decide(spec(network="allowlist", egress_allowlist=("a.example",)))
        self.assertEqual(d.outcome, pol.ESCALATE)
        self.assertTrue(any("network access" in r for r in d.reasons))

    def test_credentials_escalate(self):
        d = self.decide(spec(credential_ids=("CODEX_API_KEY",)))
        self.assertEqual(d.outcome, pol.ESCALATE)
        self.assertTrue(any("credential identities" in r for r in d.reasons))

    def test_an_unknown_provider_trust_class_is_denied(self):
        d = self.decide(spec(), trust="downloaded-from-a-forum")
        self.assertEqual(d.outcome, pol.DENY)

    def test_policy_does_not_decide_availability(self):
        """Readiness is a different question with a different, actionable
        answer. A policy DENY there would replace 'run mission-account login'
        with 'policy refuses this mission'."""
        source = (REPO / "packages/shadowfetch-missions/data/usr/lib/shadowfetch"
                  "/missions/sf_policy.py").read_text()
        self.assertNotIn("provider_available", source.split('"""')[0] + source)

    def test_a_decision_does_not_warn_about_a_control_that_works(self):
        """This asserted the opposite until Stage C, and it was right to: a
        mission relying on an unenforced allowlist had to be told. The allowlist
        is enforced now, and an advisory that names a working control is how
        real caveats come to be ignored."""
        d = self.decide(spec(network="allowlist", egress_allowlist=("a.example",)))
        self.assertEqual(d.mediation["network_destination"]["mediation"],
                         pol.FULLY_MEDIATED)
        self.assertNotIn("network_destination", d.advisory_fields)

    def test_a_mission_not_relying_on_a_gap_is_not_warned_about_it(self):
        """Noise is how real caveats come to be ignored."""
        d = self.decide(spec())
        self.assertNotIn("network_destination", d.advisory_fields)

    def test_the_matrix_covers_every_mediation_level_honestly(self):
        """OBSERVABLE_ONLY is no longer required to appear: Stage C and Stage E
        emptied that level. The matrix must still never claim a level it cannot
        justify, which is what the per-row mechanism check below enforces."""
        matrix = pol.PolicyEngine.capability_matrix()
        levels = {entry["mediation"] for entry in matrix.values()}
        self.assertIn(pol.FULLY_MEDIATED, levels)
        self.assertIn(pol.NOT_OBSERVABLE, levels)
        for name, entry in matrix.items():
            with self.subTest(name=name):
                self.assertTrue(entry["mechanism"],
                                "every row must say HOW, or it is an assertion")

    def test_the_remaining_gaps_are_not_claimed_as_mediated(self):
        """path_masking left this list in Stage E, having gained a real
        mechanism. The other two have not, and must keep saying so."""
        matrix = pol.PolicyEngine.capability_matrix()
        # path_masking left in Stage E and network_destination in Stage C, each
        # by gaining a mechanism. Only the syscall profile remains, and it is
        # not observable at all.
        self.assertEqual(matrix["syscalls"]["mediation"], pol.NOT_OBSERVABLE)
        self.assertEqual(matrix["path_masking"]["mediation"], pol.FULLY_MEDIATED)
        # PARTIAL, and not a hedge. A declared allowlist becomes a default-DROP
        # ruleset and IS full mediation; the same posture with no hosts declared
        # gets a NAT and no ruleset and mediates nothing. The static table is
        # asked with no mission in hand, so it cannot know which of the two a
        # mission will be -- and answering with the better one is exactly the
        # overclaim this test exists to prevent. The decision knows, and says.
        self.assertEqual(matrix["network_destination"]["mediation"],
                         pol.PARTIALLY_MEDIATED)
        filtered = self.decide(spec(network="allowlist",
                                    egress_allowlist=("api.example.com",)))
        self.assertEqual(
            filtered.mediation["network_destination"]["mediation"],
            pol.FULLY_MEDIATED)
        self.assertIn("api.example.com",
                      filtered.mediation["network_destination"]["mechanism"],
                      "a filter claimed without naming what it permits")
        self.assertNotIn("network_destination", filtered.advisory_fields)

        unfiltered = self.decide(spec(network="allowlist", egress_allowlist=()))
        self.assertEqual(
            unfiltered.mediation["network_destination"]["mediation"],
            pol.OBSERVABLE_ONLY)
        self.assertIn("network_destination", unfiltered.advisory_fields,
                      "the network is on, nothing filters it, and the decision "
                      "does not say so")

        closed = self.decide(spec(network="none"))
        self.assertEqual(
            closed.mediation["network_destination"]["mediation"],
            pol.FULLY_MEDIATED)
        self.assertFalse(closed.mediation["network_destination"]["relied_on"])


class ScopeContainment(unittest.TestCase):
    BASE = pol.Scope(capability="code_change", provider="codex", workspace="proj",
                     network="allowlist", credential_ids=("CODEX_API_KEY",),
                     paths=("/usr/share/data",))

    def covers(self, **overrides):
        wanted = pol.Scope(**{**self.BASE.__dict__, **overrides})
        return pol.approval_covers(self.BASE, wanted)

    def test_an_identical_scope_is_covered(self):
        self.assertEqual(self.covers()[0], True)

    def test_a_narrower_request_is_covered(self):
        self.assertTrue(self.covers(network="none")[0])
        self.assertTrue(self.covers(credential_ids=())[0])
        self.assertTrue(self.covers(paths=())[0])

    def test_a_broader_network_is_refused(self):
        covered, why = self.covers(network="allow")
        self.assertFalse(covered)
        self.assertIn("network", why)

    def test_an_extra_credential_is_refused(self):
        covered, why = self.covers(credential_ids=("CODEX_API_KEY", "ANTHROPIC_API_KEY"))
        self.assertFalse(covered)
        self.assertIn("ANTHROPIC_API_KEY", why)

    def test_a_different_workspace_is_refused(self):
        covered, why = self.covers(workspace="somebody-elses")
        self.assertFalse(covered)
        self.assertIn("workspace", why)

    def test_a_different_provider_is_refused(self):
        covered, why = self.covers(provider="some-other-agent")
        self.assertFalse(covered)
        self.assertIn("provider", why)

    def test_a_different_capability_is_refused(self):
        self.assertFalse(self.covers(capability="media_export")[0])

    def test_a_path_outside_the_grant_is_refused(self):
        covered, why = self.covers(paths=("/etc",))
        self.assertFalse(covered)
        self.assertIn("/etc", why)

    def test_a_path_below_a_granted_directory_is_covered(self):
        self.assertTrue(self.covers(paths=("/usr/share/data/sub",))[0])

    def test_a_path_that_merely_shares_a_prefix_is_refused(self):
        """/usr/share/database is not inside /usr/share/data."""
        self.assertFalse(self.covers(paths=("/usr/share/database",))[0])

    def test_an_empty_approval_field_covers_nothing(self):
        empty = pol.Scope()
        covered, why = pol.approval_covers(empty, self.BASE)
        self.assertFalse(covered)


class EngineEnforcesApproval(MigrationHarness):
    def setUp(self):
        super().setUp()
        self.store = Store(self.root)
        ws = Path(os.environ["SHADOWFETCH_AGENT_WORKSPACES"]) / "proj"
        ws.mkdir(parents=True, exist_ok=True)
        (ws / "facts.md").write_text("x\n")

    def cloud_mission(self):
        return self.store.create(kind="report", provider_id="codex", workspace_value="proj",
                                 title="t", prompt="p", inputs=["facts.md"],
                                 network="allow")

    def offline_mission(self):
        (Path(os.environ["SHADOWFETCH_AGENT_WORKSPACES"]) / "proj" / "a.mkv").write_bytes(b"x")
        return self.store.create(capability="media_export",
                                 provider_id="offline-media",
                                 workspace_value="proj", title="t", prompt="p",
                                 inputs=["a.mkv"])

    # -- the headline ------------------------------------------------------
    def test_a_mission_needing_approval_cannot_run_without_one(self):
        mission = self.cloud_mission()
        with self.assertRaises(sf.ApprovalRequired) as caught:
            sf.run_mission(self.store, mission["id"])
        self.assertIn("needs approval", str(caught.exception))
        self.assertEqual(self.store.get(mission["id"])["state"], "queued",
                         "the mission must not have started")

    def test_the_refusal_happens_before_the_state_moves(self):
        """There must be no window in which an unapproved mission is running."""
        mission = self.cloud_mission()
        with self.assertRaises(sf.ApprovalRequired):
            sf.run_mission(self.store, mission["id"])
        names = [e["event"] for e in self.store.events(mission["id"])]
        self.assertNotIn("running", names)
        self.assertIn("approval-required", names)

    def test_an_offline_mission_needs_no_approval(self):
        mission = self.offline_mission()
        decision, _ = sf.mission_decision(self.store, mission)
        self.assertEqual(decision.outcome, pol.AUTO_ALLOW)

    def test_a_valid_approval_lets_it_run_and_is_recorded(self):
        mission = self.cloud_mission()
        aid = mission_approvals.approve(self.store, mission)
        self.assertIsNotNone(aid)
        with mock.patch.object(sf.Executor, "agent_turn", return_value="Friday. [S1:L1]"):
            result = sf.run_mission(self.store, mission["id"])
        self.assertEqual(result["state"], "waiting-review", result["error"])
        self.assertEqual(self.store.get(mission["id"])["approval_id"], aid)
        names = [e["event"] for e in self.store.events(mission["id"])]
        self.assertIn("approval-used", names)

    # -- bypass attempts, none of them through the UI ----------------------
    def test_bypass_expired_approval(self):
        mission = self.cloud_mission()
        decision, _ = sf.mission_decision(self.store, mission)
        self.store.grant_approval(subject="mission:" + mission["id"],
                                  scope=decision.scope, granted_by="uid:0",
                                  method="test", expires_at="2000-01-01T00:00:00")
        with self.assertRaises(sf.ApprovalRequired) as caught:
            sf.run_mission(self.store, mission["id"])
        self.assertIn("expired", str(caught.exception))

    def test_bypass_revoked_approval(self):
        mission = self.cloud_mission()
        aid = mission_approvals.approve(self.store, mission)
        self.store.revoke_approval(aid, reason="changed my mind")
        with self.assertRaises(sf.ApprovalRequired) as caught:
            sf.run_mission(self.store, mission["id"])
        self.assertIn("revoked", str(caught.exception))

    def test_bypass_approval_for_a_different_workspace(self):
        mission = self.cloud_mission()
        decision, _ = sf.mission_decision(self.store, mission)
        elsewhere = pol.Scope(**{**decision.scope.__dict__, "workspace": "elsewhere"})
        self.store.grant_approval(subject="mission:" + mission["id"], scope=elsewhere,
                                  granted_by="uid:0", method="test")
        with self.assertRaises(sf.ApprovalRequired) as caught:
            sf.run_mission(self.store, mission["id"])
        self.assertIn("workspace", str(caught.exception))

    def test_bypass_approval_for_a_different_provider(self):
        mission = self.cloud_mission()
        decision, _ = sf.mission_decision(self.store, mission)
        other = pol.Scope(**{**decision.scope.__dict__, "provider": "some-other"})
        self.store.grant_approval(subject="mission:" + mission["id"], scope=other,
                                  granted_by="uid:0", method="test")
        with self.assertRaises(sf.ApprovalRequired):
            sf.run_mission(self.store, mission["id"])

    def test_bypass_by_widening_credentials_after_approval(self):
        """The approval is matched against what the mission WILL be allowed to
        do, recomputed at run time -- not against what it claimed at approval."""
        mission = self.cloud_mission()
        decision, _ = sf.mission_decision(self.store, mission)
        narrow = pol.Scope(**{**decision.scope.__dict__, "credential_ids": ()})
        self.store.grant_approval(subject="mission:" + mission["id"], scope=narrow,
                                  granted_by="uid:0", method="test")
        with self.assertRaises(sf.ApprovalRequired) as caught:
            sf.run_mission(self.store, mission["id"])
        self.assertIn("credential", str(caught.exception))

    def test_bypass_by_widening_network_after_approval(self):
        mission = self.cloud_mission()
        decision, _ = sf.mission_decision(self.store, mission)
        narrow = pol.Scope(**{**decision.scope.__dict__, "network": "none"})
        self.store.grant_approval(subject="mission:" + mission["id"], scope=narrow,
                                  granted_by="uid:0", method="test")
        with self.assertRaises(sf.ApprovalRequired) as caught:
            sf.run_mission(self.store, mission["id"])
        self.assertIn("network", str(caught.exception))

    def test_bypass_approval_belonging_to_another_mission(self):
        first, second = self.cloud_mission(), self.cloud_mission()
        mission_approvals.approve(self.store, first)
        with self.assertRaises(sf.ApprovalRequired):
            sf.run_mission(self.store, second["id"])

    def test_bypass_a_tampered_approval_row(self):
        """Editing the row is possible -- the user owns the file. What must not
        happen is the tampered scope being honoured without notice."""
        mission = self.cloud_mission()
        aid = mission_approvals.approve(self.store, mission)
        with self.store.db() as db:
            db.execute("UPDATE approvals SET scope=? WHERE id=?",
                       (json.dumps({"capability": "*"}), aid))
        with self.assertRaises(sf.ApprovalRequired):
            sf.run_mission(self.store, mission["id"])

    def test_bypass_an_unreadable_scope_is_refused_not_ignored(self):
        mission = self.cloud_mission()
        aid = mission_approvals.approve(self.store, mission)
        with self.store.db() as db:
            db.execute("UPDATE approvals SET scope='not json' WHERE id=?", (aid,))
        with self.assertRaises(sf.ApprovalRequired) as caught:
            sf.run_mission(self.store, mission["id"])
        self.assertIn("unreadable", str(caught.exception))

    def test_bypass_via_the_worker_rather_than_the_cli(self):
        """The worker is a separate entry point; it must be gated too."""
        mission = self.cloud_mission()
        sf.worker(self.store, once=True)
        self.assertEqual(self.store.get(mission["id"])["state"], "queued")
        names = [e["event"] for e in self.store.events(mission["id"])]
        self.assertIn("approval-required", names)

    def test_bypass_via_the_cli_subprocess(self):
        env = dict(os.environ)
        env["SHADOWFETCH_MISSIONS_STATE"] = str(self.root)
        mission = self.cloud_mission()
        done = subprocess.run(
            [sys.executable, str(CLI), "--json", "run", mission["id"]],
            capture_output=True, text=True, env=env, timeout=120)
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("approval", (done.stdout + done.stderr).lower())
        self.assertEqual(self.store.get(mission["id"])["state"], "queued")

    def test_an_approval_must_say_who_granted_it(self):
        mission = self.cloud_mission()
        decision, _ = sf.mission_decision(self.store, mission)
        for bad in ({"granted_by": "", "method": "cli"},
                    {"granted_by": "uid:0", "method": ""}):
            with self.subTest(**bad):
                with self.assertRaises(sf.MissionError):
                    self.store.grant_approval(subject="mission:x",
                                              scope=decision.scope, **bad)

    def test_granting_and_revoking_are_both_audited(self):
        mission = self.cloud_mission()
        aid = mission_approvals.approve(self.store, mission)
        self.store.revoke_approval(aid, reason="no longer needed")
        names = [e["event"] for e in self.store.events(mission["id"])]
        self.assertIn("approval-granted", names)
        self.assertIn("approval-revoked", names)
        self.assertTrue(self.store.verify_chain()["ok"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
