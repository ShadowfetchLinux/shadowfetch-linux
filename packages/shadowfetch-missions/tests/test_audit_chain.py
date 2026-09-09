"""Phase 3 Step 4: the external anchor.

The chain proves no row was ALTERED. Only the journal can show that rows were
REMOVED FROM THE END, because every surviving row still verifies after a
truncation. These tests are about that second claim, and about being honest when
it cannot be made.

Most are hermetic -- they patch sf_audit rather than writing to the machine's
journal -- because a test that depends on journald being readable proves nothing
on a host where it is not. Two integration tests do use the real journal and skip
with a reason when it is unavailable.
"""
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

from test_schema_migration import MigrationHarness, Store

sys.path.insert(0, str(Path(__file__).resolve().parents[1]
                       / "data/usr/lib/shadowfetch/missions"))
import sf_audit
import sf_missions as sf

REPO = Path(__file__).resolve().parents[3]
CLI = REPO / "packages/shadowfetch-missions/data/usr/bin/shadowfetch-missions"


def journal_readable():
    probe = sf_audit.read_head("does-not-exist")
    return probe["available"]


class MirrorMechanics(unittest.TestCase):
    def test_an_unreachable_socket_is_reported_not_raised(self):
        ok, reason = sf_audit.mirror({"seq": 1}, socket_path="/nonexistent/sock")
        self.assertFalse(ok)
        self.assertIn("FileNotFoundError", reason)

    def test_only_the_head_fields_are_mirrored(self):
        """The detail is deliberately NOT copied: it can be large, and it is
        already redacted-but-sensitive where it lives."""
        sent = {}

        class FakeSocket:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def settimeout(self, _): pass
            def connect(self, _): pass
            def send(self, data): sent["line"] = data.decode()

        with mock.patch("socket.socket", lambda *a, **k: FakeSocket()):
            sf_audit.mirror({"seq": 3, "hash": "h", "mission": "m", "event": "e",
                             "at": "t", "chain": "c", "detail": "SENSITIVE"})
        self.assertIn('"seq":3', sent["line"])
        self.assertNotIn("SENSITIVE", sent["line"])
        self.assertNotIn("detail", sent["line"])

    def test_the_line_is_addressed_to_the_agreed_identifier(self):
        self.assertEqual(sf_audit.AUDIT_IDENTIFIER, "shadowfetch-audit")


class DegradedAudit(MigrationHarness):
    def test_a_mirror_failure_never_loses_the_event(self):
        with mock.patch.object(sf_audit, "mirror",
                               return_value=(False, "simulated outage")):
            store = Store(self.root)
            before = self.raw().execute("SELECT COUNT(*) FROM events").fetchone()[0]
            store.append_event("mission-x", "probe", "this must survive")
        count = self.raw().execute("SELECT COUNT(*) FROM events").fetchone()[0]
        # Derived, not pinned. What this test is about is that the row survives
        # a mirror outage; the number of events the migration happens to write
        # is not, and hardcoding it made this fail when an honest one was added.
        self.assertEqual(count, before + 1, "the database row is the record of truth")
        self.assertTrue(self.raw().execute(
            "SELECT 1 FROM events WHERE detail='this must survive'").fetchone())

    def test_a_mirror_failure_is_reported_as_degraded(self):
        with mock.patch.object(sf_audit, "mirror",
                               return_value=(False, "simulated outage")):
            store = Store(self.root)
            store.append_event("mission-x", "probe", "x")
            report = store.verify_chain()
        self.assertEqual(report["anchor"]["verdict"], "degraded")
        self.assertGreaterEqual(report["anchor"]["mirror_failures"], 1)
        self.assertIn("simulated outage", report["anchor"]["last_mirror_error"])
        self.assertTrue(any("not externally anchored" in p
                            for p in report["problems"]))
        # The degraded branch used to be the HEAD of an elif chain, which made
        # a file this uid owns able to suppress the journal comparison. It
        # reports alongside that comparison now.
        self.assertIn("journal_head_seq", report["anchor"])

    def test_a_degraded_mirror_does_not_claim_the_chain_is_broken(self):
        """Two different facts. The chain is fine; the anchor is not."""
        with mock.patch.object(sf_audit, "mirror", return_value=(False, "outage")):
            store = Store(self.root)
            store.append_event("m", "probe", "x")
            report = store.verify_chain()
        self.assertTrue(report["ok"], "a mirror outage is not chain corruption")

    def test_recovery_clears_the_degraded_state(self):
        with mock.patch.object(sf_audit, "mirror", return_value=(False, "outage")):
            store = Store(self.root)
            store.append_event("m", "probe", "x")
        with mock.patch.object(sf_audit, "mirror", return_value=(True, None)):
            store.append_event("m", "probe", "y")
            state = store.mirror_state()
        self.assertEqual(state["failures"], 0)
        self.assertIsNone(state["last_error"])


class ExternalAnchorVerdicts(MigrationHarness):
    def setUp(self):
        super().setUp()
        with mock.patch.object(sf_audit, "mirror", return_value=(True, None)):
            self.store = Store(self.root)
            for i in range(4):
                self.store.append_event("m", "probe", str(i))

    def anchor_with(self, **journal):
        base = {"available": True, "reason": None, "head_seq": None,
                "head_hash": None, "entries": 0,
                "identifier": sf_audit.AUDIT_IDENTIFIER, "chain": "c"}
        base.update(journal)
        with mock.patch.object(sf_audit, "read_head", return_value=base):
            return self.store.verify_chain()

    def test_matching_heads_agree(self):
        real = self.store.verify_chain()
        report = self.anchor_with(head_seq=real["head_seq"], head_hash=real["head"],
                                  entries=real["head_seq"])
        self.assertEqual(report["anchor"]["verdict"], "agrees")
        self.assertTrue(report["ok"])

    def test_a_journal_ahead_of_the_database_is_truncation(self):
        ahead = self.store.verify_chain()["head_seq"] + 4
        report = self.anchor_with(head_seq=ahead, entries=ahead)
        self.assertEqual(report["anchor"]["verdict"], "truncated")
        self.assertFalse(report["ok"])
        self.assertTrue(any("removed from the end" in p for p in report["problems"]))

    def test_a_journal_behind_the_database_is_a_finding(self):
        """A journal behind the database is UNWITNESSED HISTORY, not lag.

        This test used to assert the opposite, on the premise that "the mirror
        is asynchronous". It is not: Store.mirror() is a blocking socket write
        that happens as the event is appended. The only honest lag is journald's
        own flush, which is sub-second on every host measured, and verify_chain()
        now waits JOURNAL_SETTLE_SECONDS and re-reads before deciding.

        That premise was load-bearing for an attack: three rows inserted
        straight into the events table produced verdict 'behind', and 'behind'
        was documented as normal, so the log reported clean over history nobody
        had ever witnessed.
        """
        behind = max(1, self.store.verify_chain()["head_seq"] - 3)
        report = self.anchor_with(head_seq=behind, entries=behind)
        self.assertEqual(report["anchor"]["verdict"], "conflict")
        self.assertFalse(report["ok"])
        self.assertTrue(any("without passing through it" in p
                            for p in report["problems"]),
                        report["problems"])

    def test_a_hash_disagreement_at_the_same_seq_is_a_conflict(self):
        head = self.store.verify_chain()["head_seq"]
        report = self.anchor_with(head_seq=head, head_hash="0" * 64, entries=head)
        self.assertEqual(report["anchor"]["verdict"], "conflict")
        self.assertFalse(report["ok"])
        self.assertTrue(any("rewritten after it was mirrored" in p
                            for p in report["problems"]))

    def test_an_unreadable_journal_is_unverified_not_ok(self):
        report = self.anchor_with(available=False,
                                  reason="this user cannot read the journal")
        self.assertEqual(report["anchor"]["verdict"], "unverified")
        self.assertIn("cannot read", report["anchor"]["reason"])

    def test_an_empty_journal_is_unverified_not_a_pass(self):
        """Absence of evidence. A user outside the systemd-journal group sees an
        empty journal, and calling that verified would be the exact false claim
        this phase exists to remove."""
        report = self.anchor_with(head_seq=None, entries=0,
                                  reason="no entries for this chain are readable")
        self.assertEqual(report["anchor"]["verdict"], "unverified")


class ChainIdentity(MigrationHarness):
    def test_each_database_gets_its_own_chain_id(self):
        with mock.patch.object(sf_audit, "mirror", return_value=(True, None)):
            first = Store(self.root)
            other_root = self.root.parent / "second"
            other_root.mkdir()
            second = Store(other_root)
        self.assertIsNotNone(first.chain_id())
        self.assertIsNotNone(second.chain_id())
        self.assertNotEqual(first.chain_id(), second.chain_id())

    def test_the_chain_id_is_stable_across_opens(self):
        with mock.patch.object(sf_audit, "mirror", return_value=(True, None)):
            first = Store(self.root).chain_id()
            second = Store(self.root).chain_id()
        self.assertEqual(first, second)

    def test_read_head_ignores_another_databases_entries(self):
        entries = [json.dumps({"chain": "theirs", "seq": 99, "hash": "x"}),
                   json.dumps({"chain": "mine", "seq": 3, "hash": "y"})]
        done = subprocess.CompletedProcess([], 0, stdout="\n".join(entries), stderr="")
        with mock.patch("subprocess.run", return_value=done):
            result = sf_audit.read_head("mine")
        self.assertEqual(result["head_seq"], 3, "another chain's head leaked in")
        self.assertEqual(result["entries"], 1)

    def test_a_chain_with_no_id_refuses_to_compare(self):
        """Rather than comparing against somebody else's entries."""
        result = sf_audit.read_head(None)
        self.assertFalse(result["available"])
        self.assertIn("cannot be told apart", result["reason"])


@unittest.skipUnless(journal_readable(),
                     "journald is not readable by this user, so the external "
                     "anchor cannot be exercised end to end")
class RealJournalIntegration(MigrationHarness):
    """The only tests here that touch the machine's journal."""

    def test_an_event_round_trips_through_journald(self):
        store = Store(self.root)
        store.append_event("mission-round-trip", "probe", "x")
        report = store.verify_chain()
        self.assertTrue(report["anchor"]["readable"])
        self.assertIn(report["anchor"]["verdict"], ("agrees", "behind"))
        self.assertEqual(report["anchor"]["chain"], store.chain_id())

    def test_deleting_the_tail_is_caught_by_the_journal_alone(self):
        """The case the chain provably cannot catch: after truncation every
        surviving row still verifies against its predecessor."""
        store = Store(self.root)
        for i in range(4):
            store.append_event("m", "probe", str(i))
        before = store.verify_chain()
        self.assertTrue(before["ok"])
        db = self.raw()
        db.execute("DELETE FROM events WHERE seq >= 4")
        db.commit()
        after = store.verify_chain()
        self.assertEqual(after["anchor"]["verdict"], "truncated")
        self.assertFalse(after["ok"])
        # and the chain by itself is still perfectly happy
        self.assertFalse([p for p in after["problems"] if "hash" in p and "journal" not in p])


class AuditVerifyCommand(MigrationHarness):
    def run_cli(self, *args):
        env = dict(os.environ)
        env["SHADOWFETCH_MISSIONS_STATE"] = str(self.root)
        return subprocess.run([sys.executable, str(CLI), *args],
                              capture_output=True, text=True, env=env, timeout=60)

    def test_verify_reports_the_chain_and_the_anchor_separately(self):
        Store(self.root)
        done = self.run_cli("audit", "verify")
        self.assertIn("chain", done.stdout)
        self.assertIn("external anchor", done.stdout)
        self.assertIn("unchained", done.stdout)

    def test_a_broken_chain_exits_nonzero(self):
        store = Store(self.root)
        store.append_event("m", "probe", "x")
        db = self.raw()
        db.execute("UPDATE events SET detail='rewritten' WHERE seq=2")
        db.commit()
        done = self.run_cli("audit", "verify")
        self.assertEqual(done.returncode, 1)
        self.assertIn("BROKEN", done.stdout)

    def test_json_mode_returns_the_whole_report(self):
        Store(self.root)
        done = self.run_cli("--json", "audit", "verify")
        report = json.loads(done.stdout)
        for key in ("ok", "events", "chained", "unchained", "head", "anchor"):
            self.assertIn(key, report)
        self.assertIn("verdict", report["anchor"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
