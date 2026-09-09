"""Stage D: what the credential broker REFUSES, and what it still cannot stop.

The unit-test half of this file is not the interesting half. A broker is a thing
that says no, so the assertions that matter are the ones that try to make it say
yes: an identity the mission was not granted, a ticket from another session, the
same ticket twice, a ticket after the mission ended, and an audit record edited
after the fact.

Three of these are measured through a real AF_UNIX socket rather than by calling
decide() -- because the socket is the attack surface and a decision function that
is correct behind a broken reader is a decision function nobody reaches. Two are
measured from inside a real bwrap sandbox with no network at all, which is where
the claim "a sandbox with no interfaces can still reach the broker" either holds
on this kernel or does not.

WHAT THIS FILE DELIBERATELY DOES NOT ASSERT
-------------------------------------------
That the credential is unreachable from the sandbox. It is not. The sandbox that
is allowed to ask receives the value, and there is a test below that DEMONSTRATES
the theft rather than hiding it -- ValueIsStillReachable. If that test ever
starts failing because someone "fixed" it, the claims matrix row is wrong, not
the test.

That the orchestrator uses any of this. It does not yet; Firebreak still passes
--setenv and nothing constructs a CredentialBroker. Those are other packages'
files and are reported as blocked.
"""
from __future__ import annotations

import contextlib
import hashlib
import importlib.machinery
import importlib.util
import json
import os
import pwd
import resource
import shutil
import socket
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

TESTS_DIR = Path(__file__).resolve().parent
MISSION_MODULES = TESTS_DIR.parent / "data/usr/lib/shadowfetch/missions"
if str(MISSION_MODULES) not in sys.path:
    sys.path.insert(0, str(MISSION_MODULES))

import sf_audit                                                    # noqa: E402
import sf_broker                                                   # noqa: E402
import sf_providers                                                # noqa: E402
from sf_broker import (BrokerError, CredentialBroker, Peer,        # noqa: E402
                       REFUSAL_CODES, Refusal, redeem)

# Absolute, because a program that decides a security question is never found
# through PATH -- including in a test, where a forged bwrap earlier on PATH
# would let every assertion below pass while proving nothing.
BWRAP = "/usr/bin/bwrap"

# The interpreter that runs INSIDE the sandbox. Deliberately the packaged
# absolute path rather than sys.executable: a venv or pyenv interpreter is not
# under the /usr that gets bound in, so the probe would die with ENOENT and the
# measurement would silently become "the sandbox could not run anything".
PYTHON = "/usr/bin/python3"

# Child environment for every subprocess this file starts. Pinned, not
# inherited: these processes are how the containment claims are measured, and a
# measurement whose environment the caller chose is a measurement the caller
# chose. bwrap resolves nothing through PATH -- every path handed to it here is
# absolute -- and the payload's own PATH is set by --setenv inside the sandbox.
CHILD_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}

SECRET = "sk-ant-THIS-IS-THE-SECRET-VALUE-0123456789"
IDENTITY = "ANTHROPIC_API_KEY"

# The SHIPPED Firebreak, by absolute path inside this working tree. The claim
# "the endpoint is bindable" is a claim about THAT program's read_grants() and
# about nothing else, so the tests below call the real function rather than
# restating its rules -- which is precisely how the first version of this stage
# shipped an endpoint no --read grant would ever have accepted.
FIREBREAK = (TESTS_DIR.parents[1]
             / "shadowfetch-fireline/data/usr/bin/shadowfetch-firebreak")


def firebreak_module():
    """Load shadowfetch-firebreak as a module, by absolute path.

    It has no extension, so it cannot simply be imported; and it must not be
    found by searching, for the same reason no executable in this codebase is
    found through PATH. Its module body only defines things -- the entry point
    is guarded by __name__ == "__main__" -- so loading it runs nothing.
    """
    loader = importlib.machinery.SourceFileLoader("sf_firebreak_under_test",
                                                  str(FIREBREAK))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def have_bwrap() -> bool:
    return os.access(BWRAP, os.X_OK) and os.access(PYTHON, os.X_OK)


def journal_readable() -> bool:
    return bool(sf_audit.read_head("stage-d-does-not-exist").get("available"))


# The fields sf_audit.read_head() can come back with. Derived from the real
# function rather than typed out here, so a field added there shows up as a
# failing test in this file instead of as a stub that quietly lacks it.
# Underscore-prefixed keys are that function's own working state and are popped
# before it returns a completed answer.
JOURNAL_FIELDS = frozenset(name for name in sf_audit.read_head("")
                           if not name.startswith("_"))

# Every field a stub must state OUT LOUD because a wrong value in it is how the
# anchor gets fooled. There is no default: the reason the re-chain attack
# survived 67 tests is that every one of them wrote "other_chains": {} without
# deciding to, so an empty journal for a forged chain looked like agreement.
CONTRADICTION_FIELDS = ("entries", "heads", "conflicts", "other_chains",
                        "foreign_store_entries", "uids")


def journal_head(*, available, head_seq, entries, heads, conflicts,
                 other_chains, foreign_store_entries, uids, reason=None,
                 head_hash=None, store=None, chain=None,
                 identifier="shadowfetch-audit"):
    """A stubbed sf_audit.read_head() answer, with no silent defaults.

    Keyword-only and, for every field that can carry a contradiction,
    mandatory. A test that does not say what journald holds for OTHER chains at
    this store, or for THIS chain at another store, does not run at all -- which
    is the only durable fix for a suite that stubbed the one field that would
    have fired.
    """
    stub = {"available": available, "reason": reason, "head_seq": head_seq,
            "head_hash": head_hash, "entries": entries, "identifier": identifier,
            "heads": dict(heads), "conflicts": dict(conflicts),
            "other_chains": dict(other_chains),
            "foreign_store_entries": foreign_store_entries, "uids": list(uids),
            "store": store, "chain": chain}
    missing = JOURNAL_FIELDS - set(stub)
    if missing:
        raise AssertionError(
            "sf_audit.read_head() now returns %s, which this stub does not "
            "carry. Decide what the anchor does with it before stubbing it "
            "away." % ", ".join(sorted(missing)))
    return stub


class BrokerCase(unittest.TestCase):
    """One broker, in a private tree, with journald mirroring OFF by default.

    Mirroring is a side effect on a machine-wide log, so the tests that are
    about the chain do not write to it; the two that are about the anchor turn
    it on deliberately and say so.
    """

    mirror = False

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="sf-broker-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.endpoints = self.tmp / "run"
        self.state = self.tmp / "state"
        self.broker = CredentialBroker(root=self.endpoints, audit_root=self.state,
                                       mirror=self.mirror)
        self.addCleanup(self.broker.close)

    def grant(self, *, mission="mission-1", session="session-1",
              provider="cloud-agent", identity=IDENTITY, value=SECRET, **kw):
        return self.broker.open_grant(mission=mission, session=session,
                                      provider=provider, identity=identity,
                                      value=value, **kw)

    def ask(self, session, ticket, identity=IDENTITY):
        """Over the real socket, the way an attacker would."""
        return redeem(self.broker.socket_path(session), ticket, identity)

    def records(self, event=None):
        rows = [r for r in self.broker.audit.rows() if "_unparseable" not in r]
        if event is not None:
            rows = [r for r in rows if r.get("event") == event]
        return rows


# --------------------------------------------------------------------------- #
# The five attacks the stage was asked to answer
# --------------------------------------------------------------------------- #

class IdentityNotGranted(BrokerCase):
    def test_an_identity_the_mission_was_not_granted_is_refused(self):
        """A grant is for ONE identity. Holding a valid ticket is not holding a
        key to the whole credential set."""
        ticket = self.grant(identity="ANTHROPIC_API_KEY")
        answer = self.ask("session-1", ticket, identity="GITHUB_TOKEN")
        self.assertFalse(answer["ok"])
        self.assertEqual(answer["code"], Refusal.IDENTITY_NOT_GRANTED)
        self.assertNotIn("value", answer)

    def test_the_refusal_records_what_was_asked_for_not_what_the_grant_carries(self):
        """This caught a real defect: the record was written with the GRANT's
        identity, so a caller with a valid ticket reaching for a different
        credential -- the lateral move this refusal exists to catch -- appeared
        in the log as an ordinary request for the identity it already had. The
        attempt was invisible in the one place it needed to be visible."""
        ticket = self.grant()
        self.ask("session-1", ticket, identity="AWS_SECRET_ACCESS_KEY")
        row = self.records("credential-refused")[-1]
        self.assertEqual(row["identity"], "AWS_SECRET_ACCESS_KEY",
                         "the record must say what was asked for")
        self.assertEqual(row["grant_identity"], IDENTITY,
                         "and separately what the grant carried")
        self.assertEqual(row["code"], Refusal.IDENTITY_NOT_GRANTED)

    def test_a_grant_for_a_second_identity_does_not_widen_the_first(self):
        first = self.grant(identity="ANTHROPIC_API_KEY", value=SECRET)
        self.grant(identity="GITHUB_TOKEN", value="ghp_other")
        answer = self.ask("session-1", first, identity="GITHUB_TOKEN")
        self.assertEqual(answer["code"], Refusal.IDENTITY_NOT_GRANTED)


class OutsideTheSession(BrokerCase):
    def test_a_valid_ticket_on_another_missions_endpoint_is_refused(self):
        """Two missions run under the same worker uid. Without this check the
        endpoint mounted into mission B would answer mission A's ticket, and the
        per-session directory would be decoration."""
        mine = self.broker.open_grant(mission="m-a", session="session-a",
                                      provider="p", identity=IDENTITY, value=SECRET)
        self.broker.open_grant(mission="m-b", session="session-b",
                               provider="p", identity=IDENTITY, value="other-secret")
        answer = self.ask("session-b", mine)
        self.assertFalse(answer["ok"])
        self.assertEqual(answer["code"], Refusal.WRONG_SESSION)
        self.assertNotIn("value", answer)

    def test_the_ticket_still_works_on_its_own_endpoint_afterwards(self):
        """A refusal must not spend the grant: an attacker who can burn a
        ticket by presenting it on the wrong socket has a denial of service
        against every mission."""
        mine = self.broker.open_grant(mission="m-a", session="session-a",
                                      provider="p", identity=IDENTITY, value=SECRET)
        self.broker.open_grant(mission="m-b", session="session-b",
                               provider="p", identity=IDENTITY, value="other")
        self.assertEqual(self.ask("session-b", mine)["code"], Refusal.WRONG_SESSION)
        good = self.ask("session-a", mine)
        self.assertTrue(good["ok"], good)
        self.assertEqual(good["value"], SECRET)

    def test_each_session_gets_its_own_endpoint_directory(self):
        self.broker.open_grant(mission="m-a", session="session-a", provider="p",
                               identity=IDENTITY, value=SECRET)
        self.broker.open_grant(mission="m-b", session="session-b", provider="p",
                               identity=IDENTITY, value=SECRET)
        self.assertNotEqual(self.broker.endpoint("session-a"),
                            self.broker.endpoint("session-b"))
        self.assertTrue(self.broker.socket_path("session-a").is_socket())
        self.assertTrue(self.broker.socket_path("session-b").is_socket())

    def test_a_ticket_that_never_existed_is_refused_the_same_way_as_a_closed_one(self):
        """The refusal must not be an oracle. 'Never existed' and 'was closed'
        get the same code and the same words, or a caller can map grant
        lifetimes by probing."""
        ticket = self.grant()
        self.broker.close_grant(session="session-1")
        self.broker.open_grant(mission="m2", session="session-1", provider="p",
                               identity=IDENTITY, value=SECRET)
        closed = self.broker.decide(
            json.dumps({"v": 1, "op": "issue", "ticket": ticket,
                        "identity": IDENTITY}).encode(), session="session-1")
        never = self.broker.decide(
            json.dumps({"v": 1, "op": "issue", "ticket": "0" * 64,
                        "identity": IDENTITY}).encode(), session="session-1")
        self.assertEqual(closed["code"], Refusal.UNKNOWN_TICKET)
        self.assertEqual(never["code"], Refusal.UNKNOWN_TICKET)
        self.assertEqual(closed["error"], never["error"])


class ReplayAndRace(BrokerCase):
    def test_the_same_ticket_twice_is_refused_the_second_time(self):
        ticket = self.grant()
        first = self.ask("session-1", ticket)
        second = self.ask("session-1", ticket)
        self.assertTrue(first["ok"], first)
        self.assertEqual(first["value"], SECRET)
        self.assertFalse(second["ok"])
        self.assertEqual(second["code"], Refusal.REPLAYED)
        self.assertNotIn("value", second)

    def test_a_replay_is_recorded_as_a_refusal_not_dropped(self):
        ticket = self.grant()
        self.ask("session-1", ticket)
        self.ask("session-1", ticket)
        issued = self.records("credential-issued")
        refused = [r for r in self.records("credential-refused")
                   if r["code"] == Refusal.REPLAYED]
        self.assertEqual(len(issued), 1)
        self.assertEqual(len(refused), 1)

    def test_twenty_four_simultaneous_redemptions_yield_exactly_one_issue(self):
        """The single-issue rule is only a control if it survives a race.

        The counter is incremented inside the same lock that made the decision;
        an implementation that bumped it after replying would let every thread
        read issues == 0 and every thread be issued, which is the failure this
        asserts against and the reason the increment is where it is.

        It also asserts that every caller got an ANSWER. The first version of
        this test found four callers failing with EAGAIN out of connect()
        because the listen backlog had been set to the handler cap: those four
        never reached accept(), so they were neither served nor audited, and a
        payload flooding the endpoint could have shut the real consumer out
        silently. Both halves of that are fixed and both are asserted here.
        """
        ticket = self.grant()
        answers = []
        barrier = threading.Barrier(24)
        lock = threading.Lock()

        def attempt():
            barrier.wait(timeout=10)
            try:
                answer = self.ask("session-1", ticket)
            except Exception as exc:                               # noqa: BLE001
                answer = {"ok": False, "code": "client-error", "error": str(exc)}
            with lock:
                answers.append(answer)

        threads = [threading.Thread(target=attempt) for _ in range(24)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        issued = [a for a in answers if a.get("ok")]
        stranded = [a for a in answers if a.get("code") == "client-error"]
        self.assertEqual(len(answers), 24)
        self.assertEqual(len(issued), 1,
                         f"exactly one issue expected, got {len(issued)}")
        self.assertEqual(stranded, [],
                         "callers that never reached accept() are neither "
                         "served nor audited")
        self.assertTrue(all(a.get("code") in (Refusal.REPLAYED, Refusal.OVERLOADED)
                            for a in answers if not a.get("ok")),
                        [a.get("code") for a in answers if not a.get("ok")])
        # Everything that got an answer is on the chain: 24 decisions, one of
        # them an issue. An audit that lost the losers would hide the flood.
        decisions = [r for r in self.records()
                     if r.get("event") in ("credential-issued", "credential-refused")]
        self.assertEqual(len(decisions), 24, [r.get("code") for r in decisions])
        self.assertTrue(self.broker.audit.verify(anchor=False)["ok"])

    def test_a_grant_may_be_issued_more_than_once_only_when_it_says_so(self):
        ticket = self.grant(max_issues=2)
        self.assertTrue(self.ask("session-1", ticket)["ok"])
        self.assertTrue(self.ask("session-1", ticket)["ok"])
        self.assertEqual(self.ask("session-1", ticket)["code"], Refusal.REPLAYED)

    def test_a_grant_that_can_never_be_issued_is_refused_at_creation(self):
        with self.assertRaises(BrokerError):
            self.grant(max_issues=0)


class AfterTheMissionEnded(BrokerCase):
    def test_a_ticket_after_close_grant_is_refused(self):
        ticket = self.grant()
        self.broker.close_grant(session="session-1")
        answer = self.broker.decide(
            json.dumps({"v": 1, "op": "issue", "ticket": ticket,
                        "identity": IDENTITY}).encode(), session="session-1")
        self.assertFalse(answer["ok"])
        self.assertEqual(answer["code"], Refusal.UNKNOWN_TICKET)

    def test_the_post_mission_attempt_is_audited_as_revoked_though_the_caller_is_told_nothing(self):
        """The record and the answer differ here, on purpose.

        The first version of this forgot the grant on close, so a payload still
        trying to spend a credential after its mission ended was written down as
        `unknown_ticket` -- identical to someone typing hex at the socket. That
        is the single most interesting event this file can record and it was
        being thrown away. The CALLER still learns nothing, in the same words as
        a true miss, because telling it apart would make the broker an oracle
        for grant lifetimes.
        """
        ticket = self.grant()
        self.broker.close_grant(session="session-1")
        self.broker.open_grant(mission="m2", session="session-1", provider="p",
                               identity=IDENTITY, value=SECRET)
        answer = self.ask("session-1", ticket)
        self.assertEqual(answer["code"], Refusal.UNKNOWN_TICKET)
        row = self.records("credential-refused")[-1]
        self.assertEqual(row["code"], Refusal.REVOKED)
        self.assertEqual(row["mission"], "mission-1")
        self.assertIn("after", row["reason"])

    def test_the_tombstone_table_is_bounded(self):
        """A worker that runs for weeks must not accumulate one entry per
        mission forever."""
        for index in range(sf_broker.MAX_TOMBSTONES + 10):
            session = f"s-{index}"
            self.broker.open_grant(mission="m", session=session, provider="p",
                                   identity=IDENTITY, value=SECRET)
            self.broker.close_grant(session=session)
        self.assertLessEqual(len(self.broker._tombstones), sf_broker.MAX_TOMBSTONES)

    def test_closing_takes_the_endpoint_away_entirely(self):
        """Not merely refusing: the socket is unlinked, so a payload that kept
        the path cannot even connect."""
        ticket = self.grant()
        path = self.broker.socket_path("session-1")
        self.assertTrue(path.is_socket())
        self.broker.close_grant(session="session-1")
        self.assertFalse(path.exists())
        with self.assertRaises(OSError):
            redeem(path, ticket, IDENTITY)

    def test_closing_wipes_the_brokers_own_copy_of_the_value(self):
        """Zeroing the bytearray does not erase the copy os.environ already
        holds in the worker -- nothing here claims it does. It bounds how long
        the broker retains one, which is the copy this module owns."""
        ticket = self.grant()
        sha = hashlib.sha256(ticket.encode()).hexdigest()
        grant = self.broker._grants[sha]
        self.assertEqual(bytes(grant._value), SECRET.encode())
        self.broker.close_grant(session="session-1")
        self.assertIsNone(grant._value)

    def test_an_expired_grant_is_refused_on_the_monotonic_clock(self):
        """Expiry is checked against time.monotonic(), so moving the wall clock
        backwards cannot revive a grant. The fake clock here IS the assertion:
        it only advances forward."""
        fake = {"now": 1000.0}
        broker = CredentialBroker(root=self.tmp / "run2", audit_root=self.tmp / "st2",
                                  mirror=False, monotonic=lambda: fake["now"])
        self.addCleanup(broker.close)
        ticket = broker.open_grant(mission="m", session="s", provider="p",
                                   identity=IDENTITY, value=SECRET, ttl_seconds=30)
        fake["now"] = 1029.0
        self.assertTrue(redeem(broker.socket_path("s"), ticket, IDENTITY)["ok"])
        second = broker.open_grant(mission="m", session="s", provider="p",
                                   identity=IDENTITY, value=SECRET, ttl_seconds=30)
        fake["now"] = 1100.0
        answer = redeem(broker.socket_path("s"), second, IDENTITY)
        self.assertFalse(answer["ok"])
        self.assertEqual(answer["code"], Refusal.EXPIRED)

    def test_close_reports_how_many_grants_it_revoked(self):
        self.grant(identity="ANTHROPIC_API_KEY")
        self.grant(identity="GITHUB_TOKEN", value="ghp_x")
        self.assertEqual(self.broker.close_grant(session="session-1"), 2)
        self.assertEqual(self.broker.close_grant(session="session-1"), 0)


class ForgingTheAudit(BrokerCase):
    def test_every_answer_is_recorded_with_who_when_and_what(self):
        ticket = self.grant()
        self.ask("session-1", ticket)
        row = self.records("credential-issued")[-1]
        for field in ("at", "seq", "prev", "hash", "chain", "store", "session",
                      "identity", "peer", "decision", "mission", "provider",
                      "grant", "issues", "max_issues"):
            self.assertIn(field, row, field)
        self.assertEqual(row["decision"], "issued")
        self.assertEqual(row["identity"], IDENTITY)
        self.assertEqual(row["peer"]["uid"], os.getuid())
        self.assertIsInstance(row["peer"]["pid"], int)

    def test_no_record_anywhere_contains_the_value(self):
        """Not the value, and not a fingerprint of it either: a digest of a
        secret sitting in a file is a guessing oracle, and the audit exists to
        be readable by someone who is not trusted with the secret."""
        ticket = self.grant()
        self.ask("session-1", ticket)
        self.ask("session-1", ticket)
        text = (self.state / "credential-broker-audit.jsonl").read_text()
        self.assertNotIn(SECRET, text)
        for chunk in (SECRET[:16], hashlib.sha256(SECRET.encode()).hexdigest()[:16]):
            self.assertNotIn(chunk, text)

    def test_an_altered_record_breaks_the_chain_and_names_the_row(self):
        ticket = self.grant()
        self.ask("session-1", ticket)
        self.assertTrue(self.broker.audit.verify(anchor=False)["ok"])
        path = self.state / "credential-broker-audit.jsonl"
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        target = next(i for i, r in enumerate(rows) if r["event"] == "credential-issued")
        rows[target]["identity"] = "GITHUB_TOKEN"          # rewrite what was asked for
        path.write_text("".join(json.dumps(r, sort_keys=True,
                                           separators=(",", ":")) + "\n" for r in rows))
        report = self.broker.audit.verify(anchor=False)
        self.assertFalse(report["ok"])
        self.assertEqual(report["first_bad_seq"], rows[target]["seq"])
        self.assertIn("hash", report["reason"])

    def test_rehashing_the_edited_row_still_breaks_the_rows_after_it(self):
        """The obvious forgery. Recomputing one row's own hash is not enough,
        because the next row committed to the old one."""
        ticket = self.grant()
        self.ask("session-1", ticket)
        self.ask("session-1", ticket)
        path = self.state / "credential-broker-audit.jsonl"
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        target = next(i for i, r in enumerate(rows) if r["event"] == "credential-issued")
        rows[target]["decision"] = "refused"
        rows[target]["hash"] = self.broker.audit.digest(rows[target], rows[target]["prev"])
        path.write_text("".join(json.dumps(r, sort_keys=True,
                                           separators=(",", ":")) + "\n" for r in rows))
        report = self.broker.audit.verify(anchor=False)
        self.assertFalse(report["ok"])
        self.assertEqual(report["first_bad_seq"], rows[target]["seq"] + 1)

    def test_re_chaining_the_whole_file_is_the_attack_the_chain_cannot_see(self):
        """Stated as a fact about hash chains, not hidden.

        Rewriting EVERY row and recomputing the whole chain produces a file that
        verifies. That is what a chain is; only the external anchor can see it,
        which is why the anchor exists and why verify() reports it separately.
        """
        ticket = self.grant()
        self.ask("session-1", ticket)
        path = self.state / "credential-broker-audit.jsonl"
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        previous = sf_broker.GENESIS
        for row in rows:
            row["decision"] = "refused"
            row["prev"] = previous
            row["hash"] = self.broker.audit.digest(row, previous)
            previous = row["hash"]
        path.write_text("".join(json.dumps(r, sort_keys=True,
                                           separators=(",", ":")) + "\n" for r in rows))
        self.assertTrue(self.broker.audit.verify(anchor=False)["ok"],
                        "a fully re-chained file verifies; the anchor is the "
                        "only thing that can contradict it")

    def test_truncation_verifies_locally_and_is_caught_by_the_anchor(self):
        """Deleting the last records leaves every survivor verifying. The
        journal head is what contradicts it, and this proves the comparison with
        a stubbed anchor so it holds on a host where journald is unreadable."""
        ticket = self.grant()
        self.ask("session-1", ticket)
        self.ask("session-1", ticket)
        path = self.state / "credential-broker-audit.jsonl"
        lines = path.read_text().splitlines()
        head_before = json.loads(lines[-1])["seq"]
        path.write_text("".join(line + "\n" for line in lines[:-2]))
        self.assertTrue(self.broker.audit.verify(anchor=False)["ok"],
                        "the chain cannot see a truncation; that is not a bug")
        stub = journal_head(available=True, head_seq=head_before, head_hash="x",
                            entries=head_before, heads={}, conflicts={},
                            other_chains={},
                            foreign_store_entries=0, uids=[os.getuid()])
        with mock.patch.object(sf_audit, "read_head", return_value=stub):
            report = self.broker.audit.verify()
        self.assertFalse(report["ok"])
        self.assertTrue(report["anchor"]["truncated"])
        self.assertIn("removed from the end", report["reason"])

    def test_a_rewritten_row_is_caught_by_the_anchor_even_when_re_chained(self):
        ticket = self.grant()
        self.ask("session-1", ticket)
        path = self.state / "credential-broker-audit.jsonl"
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        mirrored = {row["seq"]: row["hash"] for row in rows}
        previous = sf_broker.GENESIS
        for row in rows:
            row["decision"] = "refused"
            row["prev"] = previous
            row["hash"] = self.broker.audit.digest(row, previous)
            previous = row["hash"]
        path.write_text("".join(json.dumps(r, sort_keys=True,
                                           separators=(",", ":")) + "\n" for r in rows))
        stub = journal_head(available=True, head_seq=rows[-1]["seq"],
                            head_hash=mirrored[rows[-1]["seq"]],
                            entries=len(rows), heads=mirrored, conflicts={},
                            other_chains={},
                            foreign_store_entries=0, uids=[os.getuid()])
        with mock.patch.object(sf_audit, "read_head", return_value=stub):
            report = self.broker.audit.verify()
        self.assertTrue(report["anchor"]["rewritten"])
        self.assertFalse(report["anchor"]["agrees"])
        # The boolean, not only the detail. verify() used to return ok=True over
        # exactly this file with the disagreement sitting unread inside
        # report["anchor"], and a caller reads the boolean.
        self.assertFalse(report["ok"])
        self.assertIn("journald", report["reason"])

    def test_a_forged_mirror_line_is_reported_as_a_conflict_not_resolved(self):
        """/dev/log is a local datagram socket, so the mission uid can write to
        the same identifier. Two different hashes mirrored for one sequence
        means somebody other than the engine wrote one of them. The broker
        reports it and does not pick a winner: choosing would mean deciding
        which forgery to believe."""
        ticket = self.grant()
        self.ask("session-1", ticket)
        rows = [json.loads(line) for line in
                (self.state / "credential-broker-audit.jsonl").read_text().splitlines()]
        stub = journal_head(
            available=True, head_seq=rows[-1]["seq"], head_hash=rows[-1]["hash"],
            entries=len(rows), heads={row["seq"]: row["hash"] for row in rows},
            conflicts={rows[-1]["seq"]: [rows[-1]["hash"], "f" * 64]},
            other_chains={},
                            foreign_store_entries=0, uids=[os.getuid()])
        with mock.patch.object(sf_audit, "read_head", return_value=stub):
            report = self.broker.audit.verify()
        self.assertFalse(report["ok"])
        self.assertTrue(report["anchor"]["conflicts"])
        self.assertFalse(report["anchor"]["agrees"])

    def test_a_forged_higher_journal_head_raises_an_alarm_rather_than_a_pass(self):
        """The same uid that can forge a mirror line can claim a sequence the
        file never had, which produces a truncation alarm over an intact file.
        That direction is the acceptable one and is asserted so nobody 'fixes'
        it by trusting the file instead: a forgeable input may raise a false
        alarm, and may never silence a real one."""
        self.grant()
        stub = journal_head(available=True, head_seq=9999, head_hash="f" * 64,
                            entries=9999, heads={}, conflicts={},
                            other_chains={},
                            foreign_store_entries=0, uids=[os.getuid()])
        with mock.patch.object(sf_audit, "read_head", return_value=stub):
            report = self.broker.audit.verify()
        self.assertFalse(report["ok"])
        self.assertTrue(report["anchor"]["truncated"])

    def test_an_unreadable_journal_is_reported_as_unknown_not_as_agreement(self):
        """The failure mode this codebase has been bitten by: a check that
        cannot run reporting a pass."""
        self.grant()
        stub = journal_head(available=False,
                            reason="this user cannot read the journal",
                            head_seq=None, entries=0, heads={}, conflicts={},
                            other_chains={},
                            foreign_store_entries=0, uids=[os.getuid()])
        with mock.patch.object(sf_audit, "read_head", return_value=stub):
            report = self.broker.audit.verify()
        self.assertIsNone(report["anchor"]["agrees"])
        self.assertFalse(report["anchor"]["available"])
        self.assertIn("cannot", report["anchor"]["reason"])
        # Unknown is not a contradiction. An anchor that cannot be read must
        # not fail the verification either -- a check that reports a FAILURE
        # everywhere it cannot run gets switched off just as fast as one that
        # reports a pass.
        self.assertEqual(report["anchor"]["contradictions"], [])

    def test_a_line_that_is_not_json_is_a_break_not_a_skip(self):
        self.grant()
        path = self.state / "credential-broker-audit.jsonl"
        path.write_text(path.read_text() + "not json at all\n")
        report = self.broker.audit.verify(anchor=False)
        self.assertFalse(report["ok"])
        self.assertIn("not readable JSON", report["reason"])

    def test_a_restart_adopts_the_existing_chain_rather_than_minting_one(self):
        """Re-minting on every restart would produce exactly the signature
        sf_audit reports as a forged chain, and an alarm that fires on every
        restart is an alarm nobody reads."""
        self.grant()
        chain = self.broker.audit.chain
        head = self.broker.audit.verify(anchor=False)["head_seq"]
        self.broker.close()
        second = CredentialBroker(root=self.tmp / "run3", audit_root=self.state,
                                  mirror=False)
        self.addCleanup(second.close)
        self.assertEqual(second.audit.chain, chain)
        second.open_grant(mission="m", session="s", provider="p",
                          identity=IDENTITY, value=SECRET)
        report = second.audit.verify(anchor=False)
        self.assertTrue(report["ok"], report)
        self.assertGreater(report["head_seq"], head)


class RechainingUnderAFreshId(BrokerCase):
    """The bypass the three enumerated anchor checks did not cover.

    verify() used to fail on anchor.truncated, anchor.rewritten or
    anchor.conflicts -- and anchor() returned BEFORE setting any of the three
    when the journal had no entries FOR THIS CHAIN. Writing the file out again
    under a chain id journald has never seen therefore produced ok=True over a
    file with every issued row removed, while journald still held the real
    chain's entries for the same store. That is the same "a caller reads the
    boolean" defect the rewritten check already fixed, one field over.
    """

    def forge_under_a_fresh_chain(self, fresh):
        """Rewrite the whole file as if nothing but the chain-opening happened."""
        path = self.broker.audit.path
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        kept = [row for row in rows if row.get("event") == "chain-opened"]
        previous = sf_broker.GENESIS
        lines = []
        for index, row in enumerate(kept, start=1):
            row["seq"] = index
            row["chain"] = fresh
            row["prev"] = previous
            row["hash"] = self.broker.audit.digest(row, previous)
            previous = row["hash"]
            lines.append(json.dumps(row, sort_keys=True, separators=(",", ":")))
        path.write_text("".join(line + "\n" for line in lines))
        self.broker.audit._chain = fresh
        return len(rows)

    def test_a_file_re_chained_under_a_new_id_is_not_reported_as_intact(self):
        ticket = self.grant()
        self.assertTrue(self.ask("session-1", ticket)["ok"])
        real_chain = self.broker.audit.chain
        real_rows = self.forge_under_a_fresh_chain("d" * 32)
        self.assertEqual(
            [r for r in self.broker.audit.rows()
             if r.get("event") == "credential-issued"], [],
            "the forgery must actually have removed the issue")
        self.assertTrue(self.broker.audit.verify(anchor=False)["ok"],
                        "a fully re-chained file verifies locally; the anchor "
                        "is the only thing that can contradict it")
        stub = journal_head(available=True, head_seq=None, entries=0, heads={},
                            conflicts={}, other_chains={real_chain: real_rows},
                            store=self.broker.audit.store, chain="d" * 32,
                            foreign_store_entries=0, uids=[os.getuid()])
        with mock.patch.object(sf_audit, "read_head", return_value=stub):
            report = self.broker.audit.verify()
        self.assertFalse(report["ok"],
                         "journald holds entries for another chain at this very "
                         "store, and the file claims a chain it has never seen")
        self.assertTrue(report["anchor"]["rechained"])
        self.assertFalse(report["anchor"]["agrees"])
        self.assertTrue(report["anchor"]["contradictions"])
        self.assertIn(real_chain, report["reason"])

    def test_a_conflict_is_seen_even_when_this_chain_has_no_entries(self):
        """The same short circuit swallowed a forged mirror line whenever the
        forger also removed this chain's own entries from the journal's reach."""
        self.grant()
        stub = journal_head(available=True, head_seq=None, entries=0, heads={},
                            conflicts={7: ["a" * 64, "b" * 64]},
                            other_chains={},
                            store=self.broker.audit.store,
                            foreign_store_entries=0, uids=[os.getuid()])
        with mock.patch.object(sf_audit, "read_head", return_value=stub):
            report = self.broker.audit.verify()
        self.assertFalse(report["ok"])
        self.assertTrue(report["anchor"]["contradictions"])

    def test_an_empty_journal_for_a_chain_nobody_else_claims_is_still_unknown(self):
        """The honest half of the same rule. No entries and no other chains is
        'cannot tell', which must not become a failure -- otherwise every
        first-run broker on a host with no readable journal reports a forgery."""
        self.grant()
        stub = journal_head(available=True, head_seq=None, entries=0, heads={},
                            conflicts={}, other_chains={},
                            store=self.broker.audit.store,
                            foreign_store_entries=0, uids=[os.getuid()])
        with mock.patch.object(sf_audit, "read_head", return_value=stub):
            report = self.broker.audit.verify()
        self.assertTrue(report["ok"])
        self.assertIsNone(report["anchor"]["agrees"])
        self.assertEqual(report["anchor"]["contradictions"], [])

    def test_every_field_the_journal_can_disagree_with_reaches_the_boolean(self):
        """The index that stops the next one of these.

        For each field of a read_head() answer that can carry a disagreement,
        a stub that carries it must make verify() return ok=False. Adding a
        detection that sets a new field on the anchor without teaching verify()
        to read it fails here rather than shipping."""
        self.grant()
        self.ask("session-1", self.grant(session="session-1",
                                         identity="GITHUB_TOKEN", value="ghp_x"),
                 "GITHUB_TOKEN")
        rows = [json.loads(line) for line in
                self.broker.audit.path.read_text().splitlines()]
        base = dict(available=True, head_seq=rows[-1]["seq"],
                    head_hash=rows[-1]["hash"], entries=len(rows),
                    heads={row["seq"]: row["hash"] for row in rows},
                    conflicts={}, other_chains={}, foreign_store_entries=0,
                    uids=[os.getuid()], store=self.broker.audit.store)
        disagreements = {
            # journald has sequences this file does not: rows were cut.
            "head_seq": dict(base, head_seq=rows[-1]["seq"] + 5),
            # journald remembers a different hash for a sequence this file has.
            "heads": dict(base, heads={rows[-1]["seq"]: "f" * 64}),
            # two hashes mirrored for one sequence: somebody else wrote one.
            "conflicts": dict(base, conflicts={rows[-1]["seq"]: ["a" * 64,
                                                                 "b" * 64]}),
            # journald holds another chain for this very store: a re-mint.
            "other_chains": dict(base, other_chains={"e" * 32: 4}),
            # this chain's entries were mirrored by a store at another path,
            # which is what a copied or relocated database looks like.
            "foreign_store_entries": dict(base, foreign_store_entries=3),
            # somebody who is not this uid has been mirroring this chain.
            "uids": dict(base, uids=[os.getuid(), os.getuid() + 7]),
        }
        # 'entries' is a precondition rather than a disagreement of its own:
        # having none is what the bypass hid behind, and the case for that is
        # test_a_file_re_chained_under_a_new_id_is_not_reported_as_intact.
        self.assertEqual(
            set(disagreements),
            (set(CONTRADICTION_FIELDS) - {"entries"}) | {"head_seq"},
            "every field the journal can disagree through needs a case here")
        for field, kwargs in disagreements.items():
            with self.subTest(field=field):
                with mock.patch.object(sf_audit, "read_head",
                                       return_value=journal_head(**kwargs)):
                    report = self.broker.audit.verify()
                self.assertFalse(
                    report["ok"],
                    f"journald disagreeing through {field!r} left ok=True")
                self.assertTrue(report["anchor"]["contradictions"])

    def test_the_stub_carries_every_field_the_real_read_head_returns(self):
        """A stub that has drifted from the function it stands in for is a test
        that proves something about a shape nothing produces."""
        real = {name: value for name, value in sf_audit.read_head("").items()
                if not name.startswith("_")}
        stub = journal_head(available=False, head_seq=None, entries=0, heads={},
                            conflicts={}, other_chains={},
                            foreign_store_entries=0, uids=[os.getuid()])
        self.assertEqual(set(stub), set(real))
        for field in CONTRADICTION_FIELDS:
            self.assertIn(field, real)


class JournalAnchor(unittest.TestCase):
    """The two assertions that use the machine's real journal.

    They skip loudly rather than passing quietly, because a test that depends on
    journald being readable proves nothing on a host where it is not -- and
    silently reporting a pass there is the exact failure this anchor exists to
    detect.
    """

    def setUp(self):
        if not journal_readable():
            self.skipTest("journald is not readable by this user, so the external "
                          "anchor cannot be measured here")
        self.tmp = Path(tempfile.mkdtemp(prefix="sf-broker-journal-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.broker = CredentialBroker(root=self.tmp / "run",
                                       audit_root=self.tmp / "state", mirror=True)
        self.addCleanup(self.broker.close)

    def test_a_real_request_reaches_the_real_journal(self):
        ticket = self.broker.open_grant(mission="m", session="s", provider="p",
                                        identity=IDENTITY, value=SECRET)
        redeem(self.broker.socket_path("s"), ticket, IDENTITY)
        self.assertEqual(self.broker.audit.mirror_failures, 0,
                         self.broker.audit.last_mirror_error)
        deadline = time.monotonic() + 15
        seen = {}
        while time.monotonic() < deadline:
            seen = sf_audit.read_head(self.broker.audit.chain,
                                      store=self.broker.audit.store)
            if seen.get("entries"):
                break
            time.sleep(0.5)
        self.assertTrue(seen.get("available"), seen.get("reason"))
        self.assertGreaterEqual(seen.get("entries") or 0, 1,
                                "the broker's heads did not reach journald")
        report = self.broker.audit.verify()
        self.assertTrue(report["ok"], report)

    def test_the_mirror_never_carries_the_value(self):
        ticket = self.broker.open_grant(mission="m", session="s2", provider="p",
                                        identity=IDENTITY, value=SECRET)
        redeem(self.broker.socket_path("s2"), ticket, IDENTITY)
        binary = sf_audit.journalctl_binary()
        self.assertIsNotNone(binary, "no journalctl at a trusted absolute path")
        done = subprocess.run(
            [binary, "-t", sf_audit.AUDIT_IDENTIFIER, "-o", "json", "--no-pager",
             "-n", "200"],
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            capture_output=True, text=True, timeout=30)
        self.assertNotIn(SECRET, done.stdout)


# --------------------------------------------------------------------------- #
# The wire
# --------------------------------------------------------------------------- #

class TheWireIsUntrusted(BrokerCase):
    def test_garbage_is_refused_and_the_broker_survives_it(self):
        self.grant()
        path = self.broker.socket_path("session-1")
        for payload in (b"\n", b"{\n", b"[]\n", b"null\n", b"not json\n",
                        b'{"v":2,"op":"issue","ticket":"x","identity":"Y"}\n',
                        b'{"v":1,"op":"drop-table","ticket":"x","identity":"Y"}\n',
                        b'{"v":1,"op":"issue","ticket":1,"identity":2}\n'):
            with self.subTest(payload=payload[:40]):
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect(str(path))
                sock.sendall(payload)
                answer = json.loads(sock.recv(4096).decode().splitlines()[0])
                sock.close()
                self.assertFalse(answer["ok"])
                self.assertEqual(answer["code"], Refusal.MALFORMED)
        ticket = self.grant(identity="GITHUB_TOKEN", value="ghp_still_working")
        self.assertTrue(self.ask("session-1", ticket, "GITHUB_TOKEN")["ok"],
                        "the broker stopped answering after malformed input")

    def test_an_oversized_request_is_refused_before_it_is_parsed(self):
        self.grant()
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect(str(self.broker.socket_path("session-1")))
        try:
            sock.sendall(b"{" + b"A" * (sf_broker.MAX_REQUEST_BYTES + 4096))
            answer = json.loads(sock.recv(4096).decode().splitlines()[0])
        finally:
            sock.close()
        self.assertEqual(answer["code"], Refusal.MALFORMED)
        self.assertIn("exceeds", answer["error"])

    def test_a_caller_that_never_sends_a_newline_is_dropped_on_the_deadline(self):
        """Otherwise one connection holds a handler slot forever and the
        legitimate consumer is starved by a caller that sends nothing."""
        self.grant()
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect(str(self.broker.socket_path("session-1")))
        started = time.monotonic()
        try:
            sock.sendall(b'{"v":1,"op":"issue"')          # no newline, ever
            data = sock.recv(4096)
        finally:
            sock.close()
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, sf_broker.REQUEST_DEADLINE + 5)
        answer = json.loads(data.decode().splitlines()[0])
        self.assertEqual(answer["code"], Refusal.MALFORMED)

    def test_every_refusal_code_has_a_name_and_is_reachable(self):
        """A code with no path is a refusal nobody has proved exists. Every
        member of REFUSAL_CODES is asserted somewhere in this file; this test
        is the index that stops one being added without one."""
        source = Path(__file__).read_text(encoding="utf-8")
        for code in REFUSAL_CODES:
            with self.subTest(code=code):
                constant = "Refusal." + code.upper()
                self.assertIn(constant, source,
                              f"{code} is declared but no test in this file asserts it")


class TheFloodMustNotEvictTheConsumer(BrokerCase):
    """The attack that does not need to win the race, because it removes the
    other runner.

    Measured against the first version of this module: 24 connections that
    connect, send a JSON prefix and never send a newline held every one of the
    16 handler slots for the full 2.0s deadline each. The legitimate consumer's
    single call came back 'overloaded' -- a hard answer, not a retry -- the
    flood was then released, the attacker redeemed, and the consumer's next
    attempt was told 'replayed'. The credential was gone and the consumer never
    had it, which is strictly worse than the environment delivery this stage
    exists to improve on.

    The property asserted here is therefore not 'the flood is refused'. It is
    that the CONSUMER IS ANSWERED while the flood is still running.
    """

    def room_for_descriptors(self, connections):
        """Raise this process's own fd ceiling, or skip loudly.

        Every connection here costs TWO descriptors in one process -- the
        client's and the one the broker accepted -- so the shell's default soft
        limit of 1024 can stop the flood before the broker's cap does, and the
        test would then quietly measure a smaller flood than it claims. The soft
        limit is ours to raise up to the hard limit; if it cannot be raised far
        enough, this skips rather than proving less than it says.
        """
        need = connections * 2 + 256
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        if soft < need:
            if hard != resource.RLIM_INFINITY and hard < need:
                self.skipTest(
                    f"this process may open {hard} descriptors and the flood "
                    f"needs about {need}")
            resource.setrlimit(resource.RLIMIT_NOFILE, (need, hard))
            self.addCleanup(resource.setrlimit, resource.RLIMIT_NOFILE,
                            (soft, hard))

    def slow_loris(self, count):
        """Connections that will never finish a request. Closed on cleanup."""
        self.room_for_descriptors(count)
        path = str(self.broker.socket_path("session-1"))
        opened = []
        for _ in range(count):
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(5)
            try:
                sock.connect(path)
                sock.sendall(b'{"v":1,"op":"issue"')          # no newline, ever
            except OSError:
                sock.close()
                continue
            opened.append(sock)
        self.addCleanup(self.close_all, opened)
        return opened

    @staticmethod
    def close_all(socks):
        for sock in socks:
            with contextlib.suppress(OSError):
                sock.close()

    def test_a_slow_loris_flood_does_not_take_the_consumers_answer_away(self):
        ticket = self.grant()
        held = self.slow_loris(sf_broker.MAX_CONCURRENT_REQUESTS + 8)
        self.assertGreaterEqual(len(held), sf_broker.MAX_CONCURRENT_REQUESTS + 8,
                                "the flood did not even connect; nothing is proved")
        answer = self.ask("session-1", ticket)
        self.assertTrue(answer.get("ok"),
                        f"the consumer was evicted by the flood: {answer}")
        self.assertEqual(answer["value"], SECRET)

    def test_a_flood_larger_than_every_bound_still_leaves_the_consumer_served(self):
        """Above the pending-connection cap the broker has to drop somebody.
        It must be the stalest connection in the flood and never the caller
        that just arrived, or the eviction is the attack with extra steps."""
        ticket = self.grant()
        held = self.slow_loris(sf_broker.MAX_PENDING_CONNECTIONS + 32)
        self.assertGreater(len(held), sf_broker.MAX_PENDING_CONNECTIONS)
        answer = self.ask("session-1", ticket)
        self.assertTrue(answer.get("ok"),
                        f"the consumer was evicted by the flood: {answer}")
        self.assertEqual(answer["value"], SECRET)

    def test_the_flood_cannot_spend_the_grant(self):
        """A refusal must never count as an issue, or a flood becomes a way to
        burn a credential nobody ever received."""
        ticket = self.grant()
        self.slow_loris(sf_broker.MAX_CONCURRENT_REQUESTS + 8)
        self.assertTrue(self.ask("session-1", ticket)["ok"])
        self.assertEqual(self.ask("session-1", ticket)["code"], Refusal.REPLAYED)

    def test_a_stalled_connection_still_gets_its_refusal_on_the_deadline(self):
        """Not starving the consumer must not become never answering anyone."""
        self.grant()
        held = self.slow_loris(4)
        started = time.monotonic()
        held[0].settimeout(sf_broker.REQUEST_DEADLINE + 10)
        data = held[0].recv(4096)
        elapsed = time.monotonic() - started
        answer = json.loads(data.decode().splitlines()[0])
        self.assertFalse(answer["ok"])
        self.assertIn(answer["code"], (Refusal.MALFORMED, Refusal.OVERLOADED))
        self.assertLess(elapsed, sf_broker.REQUEST_DEADLINE + 5)

    def test_the_flood_is_on_the_record_without_one_fsync_per_connection(self):
        """A record per connection would hand the flood a second target: the
        recorder. Bursts of one refusal code are recorded as the first event in
        full and then a counted summary, so the record survives and so does the
        broker. Coalescing is a claim, so it is asserted."""
        self.grant()
        self.slow_loris(sf_broker.MAX_CONCURRENT_REQUESTS + 8)
        deadline = time.monotonic() + sf_broker.REQUEST_DEADLINE + 8
        summary = []
        while time.monotonic() < deadline:
            summary = [r for r in self.records()
                       if r.get("event") == "credential-refused-burst"]
            if summary:
                break
            time.sleep(0.2)
        self.assertTrue(summary, "the flood left no summary record")
        self.assertGreater(summary[-1]["count"], 0)
        self.assertTrue(summary[-1]["code"])
        self.assertTrue(self.broker.audit.verify(anchor=False)["ok"])

    def test_a_full_decision_queue_refuses_the_arrival_not_the_next_in_line(self):
        """The eviction, checked for in the other queue too.

        Dropping the STALEST connection is right when every entry is a
        connection that has failed to finish a request -- that is the flood.
        It is exactly wrong for the queue of COMPLETE requests, where the oldest
        entry is the one about to be served, and where the legitimate consumer
        is the oldest entry precisely because it arrived before the burst. This
        drives _promote() directly, because filling that queue for real needs a
        blocking approver and a valid ticket."""
        pairs = []

        def pending(deadline):
            left, right = socket.socketpair()
            self.addCleanup(left.close)
            self.addCleanup(right.close)
            pairs.append(right)
            return sf_broker._Pending(conn=left, session="session-1", peer=None,
                                      buffer=bytearray(b'{"v":1}\n'),
                                      deadline=deadline)

        first_in_line = pending(time.monotonic() + 100)
        self.broker._ready.append(first_in_line)
        for index in range(sf_broker.MAX_PENDING_CONNECTIONS):
            self.broker._ready.append(pending(time.monotonic() + 200 + index))
        arrival = pending(time.monotonic() + 500)
        self.broker._promote(arrival)
        self.assertIs(self.broker._ready[0], first_in_line,
                      "the request next to be served was thrown away to make "
                      "room for the one that overflowed the queue")
        self.assertNotIn(arrival, list(self.broker._ready))
        answer = json.loads(pairs[-1].recv(4096).decode().splitlines()[0])
        self.assertEqual(answer["code"], Refusal.OVERLOADED)
        self.broker._ready.clear()

    def test_redeem_retries_an_overload_inside_its_own_deadline(self):
        """The shipped client is half of the property. An 'overloaded' answer
        is a 'not now', and a client that returns it as a hard failure hands the
        credential to whoever is still trying."""
        calls = {"n": 0}
        real = sf_broker.CredentialBroker.decide

        def flaky(broker, raw, *, session, peer=None):
            calls["n"] += 1
            if calls["n"] == 1:
                return {"ok": False, "op": "issue", "code": Refusal.OVERLOADED,
                        "error": "the broker is busy"}
            return real(broker, raw, session=session, peer=peer)

        ticket = self.grant()
        with mock.patch.object(sf_broker.CredentialBroker, "decide", flaky):
            answer = redeem(self.broker.socket_path("session-1"), ticket,
                            IDENTITY, timeout=5.0)
        self.assertTrue(answer.get("ok"), answer)
        self.assertGreaterEqual(calls["n"], 2)

    def test_a_client_that_runs_out_of_time_is_told_so_rather_than_hanging(self):
        """The retry has to end. A consumer that blocks forever on a wedged
        broker is its own outage."""
        with mock.patch.object(
                sf_broker.CredentialBroker, "decide",
                lambda *a, **k: {"ok": False, "op": "issue",
                                 "code": Refusal.OVERLOADED, "error": "busy"}):
            ticket = self.grant()
            started = time.monotonic()
            answer = redeem(self.broker.socket_path("session-1"), ticket,
                            IDENTITY, timeout=1.0)
        self.assertEqual(answer["code"], Refusal.OVERLOADED)
        self.assertLess(time.monotonic() - started, 10)


class PeerIdentity(BrokerCase):
    def test_the_peer_recorded_is_the_kernels_answer_not_the_callers(self):
        ticket = self.grant()
        self.ask("session-1", ticket)
        row = self.records("credential-issued")[-1]
        self.assertEqual(row["peer"]["uid"], os.getuid())
        self.assertEqual(row["peer"]["gid"], os.getgid())

    def test_a_foreign_uid_is_refused_before_the_ticket_is_even_looked_up(self):
        """Cannot be staged with a real second uid in a unit test, so the peer
        is injected. Checking it FIRST is the property: a foreign uid must not
        be able to use the broker as an oracle for whether a ticket exists."""
        ticket = self.grant()
        foreign = Peer(pid=4242, uid=os.getuid() + 4242, gid=os.getgid())
        answer = self.broker.decide(
            json.dumps({"v": 1, "op": "issue", "ticket": ticket,
                        "identity": IDENTITY}).encode(),
            session="session-1", peer=foreign)
        self.assertEqual(answer["code"], Refusal.PEER_REFUSED)
        self.assertTrue(self.ask("session-1", ticket)["ok"],
                        "the foreign attempt must not have spent the grant")

    def test_the_sandboxs_uid_is_the_mission_uid_and_is_not_a_discriminator(self):
        """Recorded here because a reader will otherwise assume SO_PEERCRED
        separates the agent from the orchestrator. It does not: bwrap maps the
        payload's uid 0 back to the invoking uid, so both sides of the boundary
        connect as the same uid. The docstring on Peer says so; this asserts the
        code does not quietly start relying on it."""
        source = (MISSION_MODULES / "sf_broker.py").read_text(encoding="utf-8")
        self.assertIn("AS THE MISSION UID", source)
        self.assertIn("does not tell the agent apart", " ".join(source.split()))


class ApprovalAndMinting(BrokerCase):
    def test_an_approver_that_refuses_is_a_recorded_refusal(self):
        seen = []

        def approver(grant):
            seen.append(grant)
            return False, "no person approved this"

        ticket = self.grant(approver=approver)
        answer = self.ask("session-1", ticket)
        self.assertEqual(answer["code"], Refusal.NOT_APPROVED)
        self.assertEqual(answer["error"], "no person approved this")
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0]["identity"], IDENTITY)
        self.assertEqual(self.records("credential-refused")[-1]["code"],
                         Refusal.NOT_APPROVED)

    def test_a_refused_request_does_not_spend_the_grant(self):
        state = {"allow": False}
        ticket = self.grant(approver=lambda g: state["allow"])
        self.assertEqual(self.ask("session-1", ticket)["code"], Refusal.NOT_APPROVED)
        state["allow"] = True
        self.assertTrue(self.ask("session-1", ticket)["ok"])

    def test_a_short_lived_credential_is_minted_per_issue(self):
        """The seam a short-lived credential needs, and the whole of what that
        alternative costs on this side of the boundary."""
        minted = []

        def factory(grant):
            minted.append(grant["grant"])
            return f"token-{len(minted)}"

        ticket = self.broker.open_grant(mission="m", session="s", provider="p",
                                        identity=IDENTITY, value_factory=factory,
                                        max_issues=2)
        first = redeem(self.broker.socket_path("s"), ticket, IDENTITY)
        second = redeem(self.broker.socket_path("s"), ticket, IDENTITY)
        self.assertEqual(first["value"], "token-1")
        self.assertEqual(second["value"], "token-2")

    def test_a_factory_that_fails_is_refused_and_redacted(self):
        def factory(grant):
            raise RuntimeError("upstream said no for " + SECRET)

        ticket = self.broker.open_grant(mission="m", session="s", provider="p",
                                        identity=IDENTITY, value_factory=factory)
        answer = redeem(self.broker.socket_path("s"), ticket, IDENTITY)
        self.assertEqual(answer["code"], Refusal.MINT_FAILED)
        self.assertNotIn(SECRET, answer["error"])
        self.assertNotIn(SECRET,
                         (self.tmp / "state/credential-broker-audit.jsonl").read_text())

    def test_a_grant_needs_exactly_one_of_value_and_factory(self):
        with self.assertRaises(BrokerError):
            self.broker.open_grant(mission="m", session="s", provider="p",
                                   identity=IDENTITY)
        with self.assertRaises(BrokerError):
            self.broker.open_grant(mission="m", session="s", provider="p",
                                   identity=IDENTITY, value=SECRET,
                                   value_factory=lambda g: "x")


class WhereThingsLive(BrokerCase):
    def test_the_granted_directory_holds_the_socket_and_nothing_else(self):
        """Firebreak grants a DIRECTORY, so everything in it is bind-mounted
        into the sandbox. Anything else in there is a file the agent gets."""
        self.grant()
        directory = self.broker.endpoint("session-1")
        self.assertEqual(sorted(p.name for p in directory.iterdir()),
                         [sf_broker.SOCKET_NAME])

    def test_the_audit_log_is_not_inside_the_granted_directory(self):
        self.grant()
        audit = self.broker.audit.path.resolve()
        with self.assertRaises(ValueError):
            audit.relative_to(self.broker.endpoint("session-1").resolve())
        with self.assertRaises(ValueError):
            audit.relative_to(self.broker.root.resolve())

    def test_a_broker_whose_audit_is_inside_the_endpoint_root_refuses_to_start(self):
        root = self.tmp / "overlapping"
        with self.assertRaises(BrokerError) as caught:
            CredentialBroker(root=root, audit_root=root / "inner", mirror=False)
        self.assertIn("reach of whoever made it", str(caught.exception))

    def test_the_endpoint_directory_and_socket_are_private_to_this_user(self):
        self.grant()
        directory = self.broker.endpoint("session-1")
        self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.broker.socket_path("session-1").stat().st_mode & 0o777,
                         0o600)

    def test_an_endpoint_path_too_long_for_af_unix_is_refused_not_truncated(self):
        """sun_path is a fixed 108 bytes. A silently truncated bind creates a
        socket at an address nobody handed to Firebreak."""
        deep = self.tmp / ("d" * 90) / ("e" * 90)
        broker = CredentialBroker.__new__(CredentialBroker)
        broker.root = deep
        broker._listeners = {}
        with self.assertRaises(BrokerError) as caught:
            CredentialBroker._ensure_listener(broker, "session-x")
        self.assertIn("AF_UNIX allows", str(caught.exception))

    def test_the_endpoint_root_is_constructed_not_read_from_the_environment(self):
        """XDG_RUNTIME_DIR and HOME are settable by anything in the session.
        Letting either choose where a credential socket is created is the same
        defect class as letting PATH choose which journalctl answers."""
        with mock.patch.dict(os.environ,
                             {"XDG_RUNTIME_DIR": "/tmp/attacker-owned",
                              "HOME": "/tmp/attacker-owned-home",
                              "XDG_STATE_HOME": "/tmp/attacker-owned-state"}):
            root = sf_broker.default_endpoint_root()
            audit = sf_broker.default_audit_root()
        self.assertNotIn("attacker-owned", str(root))
        self.assertNotIn("attacker-owned", str(audit))
        home = Path(pwd.getpwuid(os.geteuid()).pw_dir)
        self.assertTrue(str(root).startswith(str(home) + "/"), root)
        self.assertTrue(str(audit).startswith(str(home) + "/"), audit)

    def test_the_default_audit_root_is_durable_and_is_not_beside_the_socket(self):
        """An audit log inside the endpoint tree is the record of the theft,
        bind-mounted for the thief; one on a tmpfs disappears at logout, and the
        question it answers is asked afterwards."""
        audit = sf_broker.default_audit_root()
        self.assertNotIn("/run/user", str(audit))
        with self.assertRaises(ValueError):
            audit.resolve().relative_to(sf_broker.default_endpoint_root().resolve())

    def test_an_endpoint_left_by_a_dead_broker_is_swept(self):
        """The endpoint root is durable storage rather than a tmpfs wiped at
        logout, so a crash leaves a directory holding a socket nothing answers
        on. Liveness is decided by connecting, not by a timestamp."""
        root = self.tmp / "sweep"
        stale = root / "0123456789abcdef"
        stale.mkdir(parents=True)
        dead = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        dead.bind(str(stale / sf_broker.SOCKET_NAME))
        dead.listen(1)
        dead.close()                       # the file survives; nothing listens
        self.assertTrue((stale / sf_broker.SOCKET_NAME).exists())
        broker = CredentialBroker(root=root, audit_root=self.tmp / "sweep-state",
                                  mirror=False)
        self.addCleanup(broker.close)
        self.assertEqual(broker.stale_endpoints_removed, 1)
        self.assertFalse(stale.exists())

    def test_a_live_endpoint_belonging_to_another_broker_is_left_alone(self):
        """Two missions can be running. Sweeping somebody else's live endpoint
        would be this module cancelling another mission's credential."""
        root = self.tmp / "shared"
        first = CredentialBroker(root=root, audit_root=self.tmp / "s1",
                                 mirror=False)
        self.addCleanup(first.close)
        ticket = first.open_grant(mission="m", session="live", provider="p",
                                  identity=IDENTITY, value=SECRET)
        second = CredentialBroker(root=root, audit_root=self.tmp / "s2",
                                  mirror=False)
        self.addCleanup(second.close)
        self.assertEqual(second.stale_endpoints_removed, 0)
        self.assertTrue(first.socket_path("live").is_socket())
        self.assertTrue(redeem(first.socket_path("live"), ticket, IDENTITY)["ok"],
                        "the other broker's endpoint stopped answering")

    def test_relocating_the_audit_is_recorded_in_the_audit(self):
        """The caller may pass its own state root -- the orchestrator should.
        What it may not do is move the record silently, so a chain that is not
        at the canonical location says so in its own first row."""
        audit = sf_broker.BrokerAudit(self.tmp / "elsewhere", mirror=False)
        opened = [r for r in audit.rows() if r.get("event") == "chain-opened"]
        self.assertEqual(len(opened), 1)
        self.assertTrue(opened[0]["relocated"])
        self.assertEqual(opened[0]["audit_path"], str(audit.path))
        self.assertEqual(opened[0]["canonical_audit_root"],
                         str(sf_broker.default_audit_root()))
        self.assertTrue(audit.relocated)

    def test_a_resumed_chain_at_a_relocated_root_records_the_relocation_again(self):
        """A restart adopts the chain rather than re-minting it, so the
        chain-opened row is not written a second time -- and a relocation that
        is only recorded the very first time is a relocation the next reader
        cannot see."""
        first = sf_broker.BrokerAudit(self.tmp / "elsewhere2", mirror=False)
        second = sf_broker.BrokerAudit(self.tmp / "elsewhere2", mirror=False)
        self.assertEqual(second.chain, first.chain)
        moved = [r for r in second.rows() if r.get("event") == "audit-relocated"]
        self.assertTrue(moved)
        self.assertEqual(moved[-1]["audit_path"], str(second.path))
        self.assertTrue(second.verify(anchor=False)["ok"])


class TheEndpointMustBeBindable(unittest.TestCase):
    """F1: the claim that the existing --read grant IS the binding mechanism.

    The module says the socket lives in a directory containing that socket and
    nothing else, so that Firebreak's `--read` grant is the whole mechanism and
    no new one is needed. That is a claim about read_grants() in
    packages/shadowfetch-fireline/data/usr/bin/shadowfetch-firebreak, and it was
    FALSE on the shipped path: read_grants() lists /run among its reserved
    trees, and the endpoint root was /run/user/<uid>/shadowfetch-broker, so
    every endpoint the broker created by default was unbindable.

    The probe missed it by passing a /tmp root and hand-rolling its own
    --ro-bind. These tests call the real function, on the real default path, so
    the same miss cannot happen twice.
    """

    def setUp(self):
        if not FIREBREAK.is_file():
            self.skipTest(f"no Firebreak at {FIREBREAK}")
        self.firebreak = firebreak_module()
        self.tmp = Path(tempfile.mkdtemp(prefix="sf-broker-grant-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.ws = self.tmp / "workspace"
        self.ws.mkdir()

    @staticmethod
    def remove_quietly(path):
        with contextlib.suppress(OSError):
            os.rmdir(path)

    def grant_for(self, path):
        """The real read_grants(), or the real Error it raised."""
        try:
            return self.firebreak.read_grants([str(path)], self.ws), None
        except Exception as exc:                                    # noqa: BLE001
            return None, exc

    def test_the_default_endpoint_is_accepted_by_the_real_read_grants(self):
        broker = CredentialBroker(root=sf_broker.default_endpoint_root(),
                                  audit_root=self.tmp / "state", mirror=False)
        self.addCleanup(broker.close)
        broker.open_grant(mission="m", session="s", provider="p",
                          identity=IDENTITY, value=SECRET)
        endpoint = broker.endpoint("s")
        self.assertTrue(broker.socket_path("s").is_socket())
        grants, error = self.grant_for(endpoint)
        self.assertIsNone(error, f"read_grants refused the endpoint: {error}")
        self.assertEqual(grants, [endpoint.resolve()])

    def test_the_directory_that_is_granted_holds_the_socket_and_nothing_else(self):
        broker = CredentialBroker(root=sf_broker.default_endpoint_root(),
                                  audit_root=self.tmp / "state", mirror=False)
        self.addCleanup(broker.close)
        broker.open_grant(mission="m", session="s", provider="p",
                          identity=IDENTITY, value=SECRET)
        endpoint = broker.endpoint("s")
        self.assertEqual(sorted(p.name for p in endpoint.iterdir()),
                         [sf_broker.SOCKET_NAME])
        audit = broker.audit.path.resolve()
        with self.assertRaises(ValueError):
            audit.relative_to(endpoint.resolve())

    @unittest.skipUnless(have_bwrap(), f"no bubblewrap at {BWRAP}")
    def test_a_sandbox_built_from_that_grant_alone_reaches_the_broker(self):
        """End to end, with nothing hand-rolled.

        read_grants() decides what may be bound, the bind argument is built from
        WHAT IT RETURNED, and the mounts Firebreak lays down before its grants
        -- a fresh tmpfs over /run and the private /home/agent tree -- are laid
        down here first and in that order. A grant that a later mount covers is
        as useless as one that was refused, and the endpoint used to live under
        the very path Firebreak covers with a tmpfs.
        """
        broker = CredentialBroker(root=sf_broker.default_endpoint_root(),
                                  audit_root=self.tmp / "state3", mirror=False)
        self.addCleanup(broker.close)
        ticket = broker.open_grant(mission="m", session="s", provider="p",
                                   identity=IDENTITY, value=SECRET)
        grants, error = self.grant_for(broker.endpoint("s"))
        self.assertIsNone(error, f"read_grants refused the endpoint: {error}")
        script = self.tmp / "redeem.py"
        script.write_text(REDEEM_PROBE, encoding="utf-8")
        command = [BWRAP, "--ro-bind", "/usr", "/usr",
                   "--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib",
                   "--symlink", "usr/lib64", "/lib64",
                   "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
                   # Firebreak's own order: these come BEFORE the grants.
                   "--tmpfs", "/run", "--dir", "/home", "--dir", "/home/agent",
                   "--clearenv", "--setenv", "PATH", "/usr/bin:/bin",
                   "--unshare-net", "--unshare-pid", "--unshare-user",
                   "--die-with-parent"]
        for grant in grants:
            command += ["--ro-bind", str(grant), str(grant)]
        command += ["--ro-bind", str(script), str(script), "--",
                    PYTHON, str(script), str(broker.socket_path("s")), ticket,
                    IDENTITY]
        done = subprocess.run(command, capture_output=True, text=True,
                              timeout=60, env=dict(CHILD_ENV))
        self.assertEqual(done.returncode, 0, done.stderr)
        answer = json.loads(done.stdout.splitlines()[-1])
        self.assertTrue(answer["connected"], answer)
        self.assertEqual(answer["answer"]["value"], SECRET)
        self.assertFalse(answer["identity_in_env"],
                         "the value must not also be in the environment")

    def test_the_per_user_runtime_directory_is_still_refused_by_read_grants(self):
        """Why the endpoint is not under /run/user any more, asserted rather
        than remembered. If Firebreak ever stops reserving /run this fails, and
        the note explaining the move has to be revisited on purpose."""
        runtime = Path("/run/user") / str(os.getuid()) / "shadowfetch-broker-check"
        try:
            runtime.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            self.skipTest(f"no writable per-user runtime directory here: {exc}")
        self.addCleanup(self.remove_quietly, runtime)
        grants, error = self.grant_for(runtime)
        self.assertIsNone(grants)
        self.assertIn("protected", str(error))

    def test_the_broker_refuses_to_put_an_endpoint_where_it_could_not_be_granted(self):
        """Fail at construction, loudly, rather than serve a socket no sandbox
        can ever be given."""
        with self.assertRaises(BrokerError) as caught:
            CredentialBroker(root=Path("/run/user") / str(os.getuid()) / "sf-nope",
                             audit_root=self.tmp / "state2", mirror=False)
        self.assertIn("read_grants", str(caught.exception))
        self.assertIn("/run", str(caught.exception))

    def test_every_reserved_prefix_the_broker_refuses_is_one_read_grants_reserves(self):
        """The broker's own list must not drift away from the one that decides.
        Each prefix it refuses is checked against the real function."""
        for prefix in sf_broker.UNGRANTABLE_PREFIXES:
            with self.subTest(prefix=str(prefix)):
                probe = Path(prefix) / "shadowfetch-broker-drift-check"
                if not Path(prefix).is_dir():
                    continue
                grants, error = self.grant_for(probe if probe.exists() else prefix)
                self.assertIsNone(
                    grants,
                    f"{prefix} is on the broker's refuse list but read_grants "
                    f"accepts it; the list has drifted")


# --------------------------------------------------------------------------- #
# The measurement: a real sandbox, no network
# --------------------------------------------------------------------------- #

REDEEM_PROBE = textwrap.dedent("""
    import json, socket, sys
    path, ticket, identity = sys.argv[1], sys.argv[2], sys.argv[3]
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect(path)
    except OSError as exc:
        print(json.dumps({"connected": False, "errno": exc.errno,
                          "error": str(exc)}))
        raise SystemExit(0)
    s.sendall((json.dumps({"v": 1, "op": "issue", "ticket": ticket,
                           "identity": identity}) + "\\n").encode())
    buf = b""
    while b"\\n" not in buf:
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk
    answer = json.loads(buf.split(b"\\n", 1)[0].decode())
    print(json.dumps({"connected": True, "answer": answer,
                      "identity_in_env": identity in __import__("os").environ}))
""")


@unittest.skipUnless(have_bwrap(), f"no bubblewrap at {BWRAP}")
class InsideARealSandbox(BrokerCase):
    """Measured on this kernel, in a namespace with no interfaces at all."""

    def sandbox(self, *args, binds=()):
        command = [BWRAP,
                   "--ro-bind", "/usr", "/usr",
                   "--symlink", "usr/bin", "/bin",
                   "--symlink", "usr/lib", "/lib",
                   "--symlink", "usr/lib64", "/lib64",
                   "--proc", "/proc", "--dev", "/dev",
                   "--clearenv",
                   "--setenv", "PATH", "/usr/bin:/bin",
                   "--unshare-net", "--unshare-pid", "--unshare-user",
                   "--die-with-parent"]
        for path in binds:
            command += ["--ro-bind", str(path), str(path)]
        return [*command, "--", *args]

    def run_probe(self, session, ticket, identity=IDENTITY, bind=True):
        binds = [self.broker.endpoint(session)] if bind else []
        done = subprocess.run(
            self.sandbox(PYTHON, "-c", REDEEM_PROBE,
                         str(self.broker.socket_path(session)), ticket, identity,
                         binds=binds),
            capture_output=True, text=True, timeout=60,
            env=dict(CHILD_ENV))
        self.assertEqual(done.returncode, 0, done.stderr)
        return json.loads(done.stdout.strip().splitlines()[-1])

    def test_a_sandbox_with_no_network_reaches_the_broker_over_the_bound_socket(self):
        """The transport claim, on this kernel, against THIS socket. AF_UNIX is
        addressed by filesystem path, so an empty network namespace is no
        obstacle -- and a read-only bind is enough, because a socket inode is
        not a regular file."""
        ticket = self.grant(session="sandbox-a")
        result = self.run_probe("sandbox-a", ticket)
        self.assertTrue(result["connected"], result)
        self.assertTrue(result["answer"]["ok"], result)
        self.assertEqual(result["answer"]["value"], SECRET)

    def test_without_the_bind_the_endpoint_does_not_exist_in_the_sandbox(self):
        """The grant is what makes the broker reachable. Nothing else does."""
        ticket = self.grant(session="sandbox-b")
        result = self.run_probe("sandbox-b", ticket, bind=False)
        self.assertFalse(result["connected"], result)
        self.assertIn(result["errno"], (2, 111))          # ENOENT / ECONNREFUSED

    def test_the_replay_refusal_holds_across_the_boundary(self):
        """The single-issue rule is enforced by a process the sandbox cannot
        see, so the second attempt from inside is refused exactly as the second
        attempt from outside is."""
        ticket = self.grant(session="sandbox-c")
        first = self.run_probe("sandbox-c", ticket)
        second = self.run_probe("sandbox-c", ticket)
        self.assertTrue(first["answer"]["ok"], first)
        self.assertFalse(second["answer"]["ok"])
        self.assertEqual(second["answer"]["code"], Refusal.REPLAYED)
        peers = [r["peer"]["pid"] for r in self.records("credential-issued")]
        self.assertTrue(all(isinstance(p, int) for p in peers))

    def test_the_value_is_not_in_the_sandboxs_environment(self):
        """The property the broker actually buys, measured: with delivery over
        the broker there is nothing for `env` to print. Compare with the
        environment delivery that ships today, which is the next test."""
        ticket = self.grant(session="sandbox-d")
        done = subprocess.run(
            self.sandbox("/usr/bin/env", binds=[self.broker.endpoint("sandbox-d")]),
            capture_output=True, text=True, timeout=60,
            env=dict(CHILD_ENV))
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertNotIn(SECRET, done.stdout)
        self.assertNotIn(IDENTITY, done.stdout)

    def test_the_environment_delivery_that_ships_today_is_readable_by_env(self):
        """The residual, demonstrated rather than described. This is what
        Firebreak does now: --setenv on the init process, inherited by
        everything, printable by one command."""
        command = self.sandbox("/usr/bin/env")
        command.insert(command.index("--"), "--setenv")
        command.insert(command.index("--"), IDENTITY)
        command.insert(command.index("--"), SECRET)
        done = subprocess.run(command, capture_output=True, text=True, timeout=60,
            env=dict(CHILD_ENV))
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn(SECRET, done.stdout,
                      "if this ever stops being true, the residual is gone and "
                      "the claims matrix row must be rewritten")

    def test_the_broker_process_is_not_visible_in_the_sandboxs_pid_namespace(self):
        """Why the broker's memory is out of reach: with --unshare-pid the
        sandbox's /proc does not contain the broker at all, so there is no
        /proc/<pid>/mem to read and nothing to ptrace."""
        self.grant(session="sandbox-e")
        listing = subprocess.run(
            self.sandbox("/usr/bin/ls", "/proc",
                         binds=[self.broker.endpoint("sandbox-e")]),
            capture_output=True, text=True, timeout=60,
            env=dict(CHILD_ENV))
        self.assertEqual(listing.returncode, 0, listing.stderr)
        pids = {int(n) for n in listing.stdout.split() if n.isdigit()}
        self.assertNotIn(os.getpid(), pids,
                         "the broker's own pid is visible inside the sandbox")
        self.assertLess(len(pids), 8, f"too many host pids visible: {sorted(pids)}")

    def test_the_audit_log_is_not_reachable_from_inside_the_sandbox(self):
        ticket = self.grant(session="sandbox-f")
        self.ask("sandbox-f", ticket)
        done = subprocess.run(
            self.sandbox("/usr/bin/cat", str(self.broker.audit.path),
                         binds=[self.broker.endpoint("sandbox-f")]),
            capture_output=True, text=True, timeout=60,
            env=dict(CHILD_ENV))
        self.assertNotEqual(done.returncode, 0,
                            "the sandbox read the broker's audit log")


@unittest.skipUnless(have_bwrap(), f"no bubblewrap at {BWRAP}")
class ValueIsStillReachable(BrokerCase):
    """The honest half. Do not delete this class to make a claim look better.

    A value broker hands the value to whoever is allowed to ask. Everything
    above bounds WHO may ask, HOW OFTEN, FOR WHICH identity, FOR HOW LONG and
    WITH WHAT RECORD. None of it makes the value unreachable from a sandbox that
    holds a live ticket, and the claims matrix row says exactly that.
    """

    def test_a_shell_in_the_sandbox_with_a_live_ticket_gets_the_secret(self):
        ticket = self.grant(session="theft")
        # The probe goes in via a bound file rather than -c: a script passed
        # through `sh -c` as a quoted literal loses its newlines and the shell
        # hands Python a syntax error, which would have made this test pass by
        # failing to run the theft. A shell IS what runs it, which is the point.
        probe = self.tmp / "steal.py"
        probe.write_text(REDEEM_PROBE, encoding="utf-8")
        endpoint = self.broker.endpoint("theft")
        script = (f'{PYTHON} {probe} {self.broker.socket_path("theft")} '
                  f'{ticket} {IDENTITY}')
        done = subprocess.run(
            [BWRAP, "--ro-bind", "/usr", "/usr",
             "--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib",
             "--symlink", "usr/lib64", "/lib64", "--proc", "/proc", "--dev", "/dev",
             "--ro-bind", str(endpoint), str(endpoint),
             "--ro-bind", str(probe), str(probe),
             "--clearenv", "--setenv", "PATH", "/usr/bin:/bin",
             "--unshare-net", "--unshare-pid", "--unshare-user", "--die-with-parent",
             "--", "/bin/sh", "-c", script],
            capture_output=True, text=True, timeout=60,
            env=dict(CHILD_ENV))
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn(SECRET, done.stdout,
                      "if the value stopped coming back here, this is no longer "
                      "a value broker and the matrix row must be rewritten")

    def test_the_theft_left_a_record_which_is_the_entire_difference(self):
        ticket = self.grant(session="theft2")
        self.ask("theft2", ticket)
        row = self.records("credential-issued")[-1]
        self.assertEqual(row["identity"], IDENTITY)
        self.assertEqual(row["session"], "theft2")
        self.assertIsInstance(row["peer"]["pid"], int)
        self.assertTrue(row["at"])
        self.assertTrue(self.broker.audit.verify(anchor=False)["ok"])


# --------------------------------------------------------------------------- #
# The claim, in the codebase's own vocabulary
# --------------------------------------------------------------------------- #

class TheClaimsAreDefensible(unittest.TestCase):
    def test_the_delivery_every_shipped_manifest_gets_today_is_the_environment(self):
        """Nothing is wired. Any other answer here would be a manifest claiming
        a broker that no code constructs."""
        root = TESTS_DIR.parent / "data/usr/share/shadowfetch/providers"
        manifests = [p for p in sorted(root.glob("*.json"))
                     if p.name != "provider-manifest.schema.json"]
        self.assertTrue(manifests, f"no shipped manifests under {root}")
        for path in manifests:
            with self.subTest(manifest=path.name):
                manifest = json.loads(path.read_text())
                self.assertEqual(sf_providers.credential_delivery(manifest),
                                 sf_providers.CREDENTIAL_DELIVERY_ENVIRONMENT)

    def test_an_unknown_delivery_declaration_falls_back_to_the_weakest_claim(self):
        """Fail-safe has a direction here. Not understanding a declaration must
        report the WEAKEST delivery, never the strongest: the alternative is a
        typo in a manifest producing a receipt that says the credential never
        entered the sandbox."""
        self.assertEqual(
            sf_providers.credential_delivery({"credential_delivery": "magic"}),
            sf_providers.CREDENTIAL_DELIVERY_ENVIRONMENT)
        self.assertEqual(
            sf_providers.credential_delivery({"credential_delivery": 7}),
            sf_providers.CREDENTIAL_DELIVERY_ENVIRONMENT)

    def test_no_delivery_mode_claims_more_than_it_does(self):
        claims = sf_providers.CREDENTIAL_DELIVERY_CLAIMS
        self.assertFalse(claims["environment"]["value_enters_sandbox"] is False)
        self.assertTrue(claims["broker-value"]["value_enters_sandbox"],
                        "a value broker hands over the value; saying otherwise "
                        "is the one claim this stage must never make")
        self.assertFalse(claims["broker-proxy"]["value_enters_sandbox"])

    def test_the_broker_claims_row_does_not_say_enforced_about_the_shipped_path(self):
        row = sf_broker.BROKER_CLAIMS["credential_delivery"]
        self.assertEqual(row["status"], "not_enforced")
        self.assertEqual(
            sf_broker.BROKER_CLAIMS["value_unreachable_in_sandbox"]["status"],
            "not_enforced")

    def test_the_availability_cost_is_stated_and_not_left_implied(self):
        """The verifier's judgement was that a broker the consumer can be
        evicted from is strictly worse than an environment variable, because
        with an environment variable the consumer always gets its key. The
        eviction is fixed. The weaker half of that sentence is still true -- a
        broker is a live dependency and an environment variable is not -- so it
        has to be in the claims text rather than in somebody's head."""
        row = sf_broker.BROKER_CLAIMS["broker_availability"]
        self.assertEqual(row["status"], "partial")
        note = " ".join(row["note"].split())
        self.assertIn("CANNOT fail to deliver", note)
        self.assertIn("denial and never", note)
        self.assertIn("also_costs",
                      sf_broker.DELIVERY_ALTERNATIVES["broker-value"])
        text = " ".join(
            sf_broker.DELIVERY_ALTERNATIVES["broker-value"]["also_costs"].split())
        self.assertIn("availability dependency the environment does not have",
                      text)

    def test_the_threat_model_no_longer_claims_a_race_the_attacker_must_win(self):
        """The headline sentence said an attacker must 'win the race against the
        legitimate consumer'. It was falsifiable in about a second: the attacker
        evicted the consumer instead. The docstring now says what is actually
        excluded, and says the attacker inside the sandbox holds the same ticket
        and can simply ask first."""
        source = " ".join(
            (MISSION_MODULES / "sf_broker.py").read_text(encoding="utf-8").split())
        self.assertNotIn("WIN THE RACE against the legitimate consumer", source)
        self.assertIn("What it now excludes", source)
        self.assertIn("can simply ask before the consumer", source)
        self.assertIn("strictly worse than the environment delivery", source)

    def test_the_endpoint_grantability_claim_names_the_program_that_decides(self):
        row = sf_broker.BROKER_CLAIMS["broker_endpoint_is_grantable"]
        self.assertEqual(row["status"], "enforced")
        self.assertIn("read_grants", row["mechanism"])
        self.assertIn("read_grants", row["measured"])
        # It says the endpoint CAN be granted, never that anything grants it.
        self.assertEqual(
            sf_broker.BROKER_CLAIMS["credential_delivery"]["status"],
            "not_enforced")

    def test_the_alternatives_were_written_down_with_their_costs(self):
        for name in ("environment", "broker-value", "broker-proxy", "short-lived",
                     "per-request-approval"):
            with self.subTest(alternative=name):
                entry = sf_broker.DELIVERY_ALTERNATIVES[name]
                self.assertIn("cost", entry)
                self.assertIn("value_enters_sandbox", entry)
        self.assertTrue(sf_broker.DELIVERY_ALTERNATIVES["broker-proxy"]["removes_residual"])
        self.assertFalse(sf_broker.DELIVERY_ALTERNATIVES["broker-value"]["removes_residual"])

    def test_the_shipped_enforcement_table_was_not_quietly_extended(self):
        """sf_providers.SANDBOX_ENFORCEMENT is cross-checked field-by-field
        against the audited table in test_sandbox_spec_audit.py, which this
        stage does not own. Adding a row on one side alone breaks that check
        instead of recording anything, so the broker's claims live in
        sf_broker.BROKER_CLAIMS and this asserts they stayed there."""
        self.assertNotIn("credential_delivery", sf_providers.SANDBOX_ENFORCEMENT)
        # Emptied by Stage F, which filtered syscalls. The claim this test
        # cares about is that the BROKER did not add a field to the list, not
        # what else happens to be in it.
        self.assertEqual(sf_providers.unenforced_fields(), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
