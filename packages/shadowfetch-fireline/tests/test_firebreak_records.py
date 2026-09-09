"""Firebreak session records: append-safe, and honest about enforcement (W-37).

Two properties carry the weight here.

A record has to survive the end of the session it describes. The previous
implementation wrote one object and rewrote it at exit, so a running session
could not be inspected at all and a crash in between left neither the start nor
the end.

And every field has to separate what a caller ASKED FOR from what the kernel is
actually told. When these tests were written an egress allowlist and a masked
path reached nothing whatsoever, and they asserted exactly that: a record that
claimed otherwise would have been describing protection that did not exist.
Stages C and E built both controls, so the same tests now hold the argv to the
mechanism that is really applied -- read out of what is about to be spawned,
never echoed back from the request.
"""
import argparse
import importlib.machinery
import importlib.util
import io
import json
import os
import pwd
import shutil
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

BASE = Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader(
    "firebreak_records", str(BASE / "data/usr/bin/shadowfetch-firebreak"))
spec = importlib.util.spec_from_loader("firebreak_records", loader)
fb = importlib.util.module_from_spec(spec)
loader.exec_module(fb)

REAL_WHICH = shutil.which


def fake_which(name, mode=os.F_OK | os.X_OK, path=None):
    """bwrap and systemd-run always resolve; no test here executes either."""
    if name in ("bwrap", "systemd-run"):
        return "/usr/bin/" + name
    return REAL_WHICH(name, mode, path)


class FakeSandbox:
    """A sandbox that never runs. What is under test is the record, not bwrap.

    A networked session does not create its namespace inside bwrap any more.
    Stage C moved it out: an `unshare --user --net` helper makes the namespace,
    reports its own pid through a file, waits on a FIFO while the NAT is
    attached from outside, installs the egress allowlist itself and only then
    execs bwrap. The launcher polls for that pid file and REFUSES the run if it
    never appears -- correctly, since a sandbox that started before the NAT and
    the filter existed would have run unfiltered. So the stub writes the pid
    file the way the real helper does; the NAT is stubbed separately.
    """

    def __init__(self, rc=0, before=None):
        self.rc = rc
        self.before = before
        self.spawned = None
        self.argv = []
        # What bwrap would have READ. The resolver file is temporary and the
        # launcher deletes it on the way out, so a test that opened it
        # afterwards would be reading a file the sandbox no longer has either.
        self.resolv = None

    def __call__(self, cmd, **kwargs):
        if self.before is not None:
            self.before()
        self.spawned = list(cmd)
        self.argv = list(cmd)
        for index, value in enumerate(cmd[:-2]):
            if value == "--ro-bind" and cmd[index + 2] == "/etc/resolv.conf":
                self.resolv = Path(cmd[index + 1]).read_text(encoding="utf-8")
        if fb.EGRESS_HELPER in cmd:
            # Arguments 1 and 2 of the helper are the path it reports the
            # namespace pid through and the FIFO it waits on. Nothing here
            # unshares anything: the launcher only needs a pid to hand
            # slirp4netns, and slirp is stubbed too. But the FIFO has to be
            # drained by SOMEONE -- the launcher opens it for writing to release
            # the payload, and that open blocks until a reader arrives. A stub
            # that skipped it would hang the launcher, which is the real
            # helper's ordering guarantee working exactly as intended.
            index = cmd.index(fb.EGRESS_HELPER)
            with open(cmd[index + 1], "w") as handle:
                handle.write(str(os.getpid()))
            def drain(path=cmd[index + 2]):
                with open(path) as handle:
                    handle.read(1)

            reader = threading.Thread(target=drain, daemon=True)
            reader.start()
        return self

    def wait(self, timeout=None):
        return self.rc

    def poll(self):
        return self.rc

    def terminate(self):
        pass

    def kill(self):
        pass


def unshares_network(argv):
    """Whether this argv creates a network namespace. Two mechanisms count.

    bwrap's own --unshare-net makes one for posture 'none'. Posture 'allow'
    needs the namespace to exist BEFORE bwrap, so that the NAT and the egress
    filter can be installed into the same namespace the sandbox will run in; an
    `unshare --net` helper makes it there and bwrap inherits it. bwrap must NOT
    also be given --unshare-net in that case or it would make a second, empty
    one and leave the filtered namespace behind. Asserting only on bwrap's flag
    would therefore read a correctly contained session as an uncontained one.
    """
    if "--unshare-net" in argv:
        return True
    for index, value in enumerate(argv):
        if os.path.basename(value) == "unshare" and "--net" in argv[index:]:
            return True
    return False


def bwrap_argv(argv):
    """The bwrap invocation alone, without whatever wraps it."""
    for index, value in enumerate(argv):
        if os.path.basename(value) == "bwrap":
            return argv[index:]
    return []


class RecordTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.ws = self.base / "Workspaces" / "project"
        self.ws.mkdir(parents=True)
        self.audit = self.base / "audit"
        self.env = patch.dict(os.environ, {
            "SHADOWFETCH_AGENT_WORKSPACES": str(self.ws.parent),
            fb.STATE_ENV: str(self.audit),
            "SHADOWFETCH_ELEMENT": "ice"})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.which = patch.object(fb.shutil, "which", fake_which)
        self.which.start()
        self.addCleanup(self.which.stop)

    # -- helpers ------------------------------------------------------------ #
    def execute(self, *extra, sid="s-record", rc=0, before=None, popen=None):
        sandbox = popen or FakeSandbox(rc, before)

        def attach(child_pid, ready_w):
            """Stand in for slirp4netns: say the interface is up, run nothing."""
            os.write(ready_w, b"1")
            return FakeSandbox(0)

        with patch.object(fb.subprocess, "Popen", sandbox), \
                patch.object(fb, "attach_network", attach):
            code = fb.main(["run", "--workspace", "project", "--no-checkpoint",
                            "--session-id", sid, *extra, "--", "true"])
        return code, sandbox

    def path(self, sid="s-record"):
        return self.audit / (sid + ".session")

    def records(self, sid="s-record"):
        return fb.read_records(self.path(sid))

    def spec(self, **values):
        defaults = dict(workspace_mode="workspace-write", memory_mb=4096,
                        cpu_seconds=900, processes=128, egress_host=[],
                        mask_path=[], codex_account=False)
        defaults.update(values)
        return argparse.Namespace(**defaults)

    # -- append safety ------------------------------------------------------ #
    def test_the_start_record_is_on_disk_before_the_sandbox_is_spawned(self):
        """A record written after the fact cannot describe a session that hung,
        and a session Firebreak crashed before recording never existed."""
        seen = {}

        def snapshot():
            seen["at_spawn"] = self.path().read_bytes()

        code, _ = self.execute(before=snapshot)
        self.assertEqual(code, 0)
        started = json.loads(seen["at_spawn"].decode())
        self.assertEqual(started["record"], "started")
        self.assertEqual(started["session"], "s-record")

    def test_the_end_is_appended_and_the_start_is_left_byte_for_byte(self):
        seen = {}

        def snapshot():
            seen["at_spawn"] = self.path().read_bytes()

        self.execute(before=snapshot)
        after = self.path().read_bytes()
        self.assertTrue(after.startswith(seen["at_spawn"]),
                        "the start record was rewritten rather than appended to")
        self.assertGreater(len(after), len(seen["at_spawn"]))
        start, end = self.records()
        self.assertEqual((start["record"], end["record"]), ("started", "ended"))
        self.assertEqual(start["run"], end["run"])
        self.assertEqual(end["exit"], 0)
        self.assertEqual(end["exit_reason"], "completed")

    def test_a_session_that_never_reached_the_sandbox_keeps_its_start_record(self):
        def explode(cmd, **kwargs):
            raise OSError(13, "the scope could not be created")

        with patch.object(fb.subprocess, "Popen", explode):
            code = fb.main(["run", "--workspace", "project", "--no-checkpoint",
                            "--session-id", "s-record", "--", "true"])
        self.assertEqual(code, 1)
        start, end = self.records()
        self.assertEqual(start["record"], "started")
        self.assertIsNone(end["exit"])
        self.assertEqual(end["exit_reason"], "not-started")

    def test_a_truncated_tail_is_reported_and_costs_only_the_last_record(self):
        """What a crash mid-append looks like. The start must still read."""
        self.execute()
        first = self.path().read_text().splitlines()[0]
        self.path().write_text(first + "\n" + '{"record": "ended", "ru')
        start, tail = fb.read_records(self.path())
        self.assertEqual(start["record"], "started")
        self.assertEqual(tail["record"], "unreadable")
        self.assertEqual(tail["line"], 2)

    def test_a_reused_session_id_appends_and_pairs_by_run(self):
        """The id belongs to the caller, so it can come back; neither run may
        overwrite the other's evidence."""
        self.execute()
        self.execute(rc=3)
        entries = self.records()
        self.assertEqual([entry["record"] for entry in entries],
                         ["started", "ended", "started", "ended"])
        self.assertNotEqual(entries[0]["run"], entries[2]["run"])
        self.assertEqual(entries[0]["run"], entries[1]["run"])
        self.assertEqual(entries[3]["exit_reason"], "nonzero-exit")

    def test_a_cancelled_session_records_that_it_was_cancelled(self):
        """SIGTERM to Firebreak, or Ctrl-C. The reason has to survive: an exit
        of 130 alone does not distinguish a cancel from a program that chose
        that status."""
        class Interrupted(FakeSandbox):
            def wait(self, timeout=None):
                raise KeyboardInterrupt

        code, _ = self.execute(popen=Interrupted(0))
        self.assertEqual(code, 130)
        start, end = self.records()
        self.assertEqual(start["record"], "started")
        self.assertEqual(end["exit_reason"], "cancelled")
        self.assertEqual(end["exit"], 130)

    def test_a_killed_sandbox_records_the_signal_that_killed_it(self):
        code, _ = self.execute(rc=-9)
        self.assertEqual(code, 137)
        self.assertEqual(self.records()[1]["exit_reason"], "signal:SIGKILL")

    def test_a_record_that_cannot_be_written_refuses_the_run_and_spawns_nothing(self):
        self.audit.mkdir(parents=True)
        blocked = self.path()
        blocked.mkdir()
        code, sandbox = self.execute()
        self.assertEqual(code, 1)
        self.assertIsNone(sandbox.spawned, "a session that cannot be recorded ran anyway")
        self.assertEqual(list(blocked.iterdir()), [])

    def test_the_record_file_is_private(self):
        self.execute()
        self.assertEqual(self.path().stat().st_mode & 0o777, 0o600)

    # -- credentials -------------------------------------------------------- #
    def test_the_recorded_argv_never_contains_a_credential_value(self):
        """Struck out by position, so a value too short for the text redactor
        to recognise is still removed."""
        with patch.dict(os.environ, {"CODEX_API_KEY": "s3cr3t",
                                     "ANTHROPIC_API_KEY": "sk-ant-longer-value"}):
            self.execute("--credential-env", "CODEX_API_KEY",
                         "--credential-env", "ANTHROPIC_API_KEY")
        text = self.path().read_text()
        self.assertNotIn("s3cr3t", text)
        self.assertNotIn("sk-ant-longer-value", text)
        self.assertIn("[REDACTED]", text)
        start = self.records()[0]
        self.assertEqual(start["credential_names"],
                         ["ANTHROPIC_API_KEY", "CODEX_API_KEY"])
        self.assertEqual(start["credentials_requested"],
                         ["ANTHROPIC_API_KEY", "CODEX_API_KEY"])
        self.assertEqual(start["enforcement"]["credentials"]["status"], "enforced")

    def test_a_credential_identity_is_recorded_even_though_its_value_is_not(self):
        with patch.dict(os.environ, {"CODEX_API_KEY": "s3cr3t"}):
            self.execute("--credential-env", "CODEX_API_KEY")
        argv = self.records()[0]["sandbox_argv"]
        self.assertIn("CODEX_API_KEY", argv)
        self.assertEqual(argv[argv.index("CODEX_API_KEY") + 1], "[REDACTED]")

    # -- enforcement, read from the argv ------------------------------------ #
    def test_enforcement_is_read_from_the_argv_not_from_the_request(self):
        """The whole point of the field. A request for a read-only workspace
        that reached bwrap as a writable bind must not report itself enforced."""
        asked = self.spec(workspace_mode="read-only")
        writable = ["--bind", str(self.ws), str(self.ws)]
        readonly = ["--ro-bind", str(self.ws), str(self.ws)]
        self.assertEqual(
            fb.enforcement(writable, asked, self.ws, [], [], "none")["workspace_mode"]["status"],
            "not_enforced")
        self.assertEqual(
            fb.enforcement(readonly, asked, self.ws, [], [], "none")["workspace_mode"]["status"],
            "enforced")

    def test_a_network_posture_of_none_without_the_namespace_is_not_enforced(self):
        report = fb.enforcement(["--bind", str(self.ws), str(self.ws)],
                                self.spec(), self.ws, [], [], "none")
        self.assertEqual(report["network"]["status"], "not_enforced")
        report = fb.enforcement(["--unshare-net"], self.spec(), self.ws, [], [], "none")
        self.assertEqual(report["network"]["status"], "enforced")

    def test_a_resource_cap_missing_from_the_scope_is_not_enforced(self):
        report = fb.enforcement([], self.spec(), self.ws, [], [], "none")
        self.assertEqual(report["memory_mb"]["status"], "not_enforced")
        self.assertEqual(report["processes"]["status"], "not_enforced")

    def test_a_read_grant_that_was_not_bound_is_not_enforced(self):
        grant = self.base / "document.txt"
        grant.write_text("selected")
        self.assertEqual(
            fb.enforcement([], self.spec(), self.ws, [grant], [], "none")["read_grants"]["status"],
            "not_enforced")
        bound = ["--ro-bind", str(grant), str(grant)]
        self.assertEqual(
            fb.enforcement(bound, self.spec(), self.ws, [grant], [], "none")["read_grants"]["status"],
            "enforced")

    def test_a_real_run_records_the_controls_it_actually_applied(self):
        grant = self.base / "document.txt"
        grant.write_text("selected")
        self.execute("--workspace-mode", "read-only", "--read", str(grant))
        start = self.records()[0]
        status = start["enforcement"]
        self.assertEqual(start["workspace_mode_requested"], "read-only")
        self.assertEqual(status["workspace_mode"]["status"], "enforced")
        self.assertEqual(status["network"]["status"], "enforced")
        self.assertEqual(status["read_grants"]["status"], "enforced")
        self.assertEqual(status["memory_mb"]["status"], "enforced")
        self.assertEqual(status["processes"]["status"], "enforced")
        self.assertEqual(status["private_home"]["status"], "enforced")
        # Per-process, so a task that forks gets a fresh budget for each child.
        self.assertEqual(status["cpu_seconds"]["status"], "partial")
        self.assertEqual(status["executable_path"]["status"], "observed")
        self.assertEqual(start["read_grants"], [str(grant)])

    def test_network_allow_is_enforced_as_a_namespace(self):
        """This asserted the opposite until Stage B, and it was right to.

        Posture 'allow' created NO network namespace, so a sandbox that only
        wanted the internet also kept the host's loopback services and abstract
        AF_UNIX namespace. It unshares the network in both postures now and
        reaches the outside through a user-space NAT attached to its own
        namespace, measured against real listeners rather than argv:

            before  host_loopback REACHED   abstract REACHED   internet REACHED
            after   host_loopback blocked   abstract blocked   internet REACHED

        Stage C then moved the namespace out of bwrap so that an egress filter
        could be installed into it before the payload runs. The containment
        above was re-measured after that move and is unchanged; what moved is
        WHO makes the namespace, so this reads it from the helper.
        """
        code, spawned = self.execute("--net", "allow")
        self.assertEqual(code, 0)
        start = self.records()[0]
        self.assertEqual(start["network_requested"], "allow")
        self.assertEqual(start["network_effective"], "allow")
        self.assertEqual(start["enforcement"]["network"]["status"], "enforced")
        self.assertTrue(unshares_network(spawned.argv),
                        "posture 'allow' did not create a network namespace")
        self.assertNotIn("--unshare-net", bwrap_argv(spawned.argv),
                         "bwrap made a SECOND namespace, which the NAT and the "
                         "egress filter were never installed into")
        self.assertIn("disable-host-loopback",
                      start["enforcement"]["network"]["mechanism"])

    def test_every_posture_unshares_the_network(self):
        for posture in ("none", "allow"):
            with self.subTest(net=posture):
                _, spawned = self.execute("--net", posture)
                self.assertTrue(unshares_network(spawned.argv),
                                "posture " + posture + " ran on the host network")

    def test_a_networked_sandbox_gets_a_resolver_it_can_actually_reach(self):
        """The host's /etc/resolv.conf is useless inside a network namespace.

        It names 127.0.0.53, the host's stub listener, which inside the
        sandbox's own namespace is the sandbox's own empty loopback. Binding it
        gave a networked sandbox a resolver that answers nothing, and since
        every cloud provider addresses its API by name, every turn failed at
        getaddrinfo while an IP address was reachable the whole time. The NAT
        runs its own forwarder; the argv has to point at that one.
        """
        _, spawned = self.execute("--net", "allow")
        argv = spawned.argv
        bound = [index for index, value in enumerate(argv)
                 if value == "--ro-bind" and argv[index + 2] == "/etc/resolv.conf"]
        self.assertEqual(len(bound), 1,
                         "a networked sandbox got no resolver, or two of them")
        self.assertIsNotNone(spawned.resolv)
        self.assertEqual(spawned.resolv.count("nameserver"), 1)
        self.assertIn("nameserver " + fb.SLIRP_RESOLVER, spawned.resolv)
        self.assertNotIn("127.0.0.53", spawned.resolv,
                         "the sandbox was pointed at the host's stub resolver")

    def test_an_unnetworked_sandbox_is_not_handed_a_nat_resolver(self):
        """Posture 'none' has no NAT, so 10.0.2.3 answers nothing there either.
        It keeps the host's file, which is equally unreachable and equally
        honest -- what must not happen is a resolver that implies a route."""
        _, spawned = self.execute("--net", "none")
        self.assertNotIn(fb.SLIRP_RESOLVER, spawned.resolv or "")

    def test_a_refusal_before_the_sandbox_starts_is_still_recorded(self):
        """The audit directory has to show that somebody asked.

        An egress host that resolves to no address is refused rather than run
        unfiltered, and that refusal happens while the launch argv is being
        built -- before the started record exists. For a while it therefore
        left nothing behind at all: no session file, no reason, no trace that a
        run had been attempted with an allowlist nobody could satisfy.
        """
        code, _ = self.execute("--net", "allow",
                               "--egress-host", "nothing.here.invalid")
        self.assertNotEqual(code, 0, "an unsatisfiable allowlist started anyway")
        records = self.records()
        kinds = [r["record"] for r in records]
        self.assertEqual(kinds, ["refused"],
                         "a refused run left a started or ended record instead")
        refusal = records[0]
        self.assertEqual(refusal["session"], "s-record")
        self.assertEqual(refusal["refused_before"], "sandbox-launch")
        self.assertEqual(refusal["egress_allowlist_requested"],
                         ["nothing.here.invalid"])
        self.assertEqual(refusal["network_requested"], "allow")
        self.assertIn("nothing.here.invalid", refusal["reason"])

    def test_the_default_posture_records_that_the_caller_asked_for_nothing(self):
        self.execute()
        start = self.records()[0]
        self.assertIsNone(start["network_requested"])
        self.assertEqual(start["network_effective"], "none")

    # -- asked for, and now applied ----------------------------------------- #
    def test_an_egress_allowlist_on_an_unrouted_namespace_is_enforced_by_absence(self):
        """Posture 'none' attaches no NAT, so there is no route to filter.

        The argv is identical with and without the allowlist and that is
        correct -- nothing was installed. What must not happen is the record
        claiming an nftables ruleset that was never written: the control holds
        here because the namespace has no way out at all, and the mechanism has
        to say which of the two facts is the one that ran.
        """
        _, plain = self.execute()
        _, listed = self.execute("--egress-host", "api.example.com",
                                 "--egress-host", "cdn.example.com")
        self.assertEqual(plain.spawned, listed.spawned,
                         "an allowlist altered a sandbox that has no route")
        start = self.records()[2]
        self.assertEqual(start["egress_allowlist_requested"],
                         ["api.example.com", "cdn.example.com"])
        entry = start["enforcement"]["egress_allowlist"]
        self.assertEqual(entry["status"], "enforced")
        self.assertIn("no route exists", entry["mechanism"])
        self.assertNotIn("nftables", entry["mechanism"],
                         "the record claims a ruleset that was never installed")

    def test_an_egress_allowlist_reaches_a_real_filter_and_says_so(self):
        """This asserted the opposite until Stage C, and it was right to.

        --egress-host was accepted and applied by nothing: a provider could
        declare two permitted hosts, the receipt printed them, and the agent
        reached the whole internet. The hosts are resolved on the host at
        launch and become an nftables ruleset with a default DROP, installed
        into the sandbox's own namespace by the process that created it,
        before the payload runs. Measured through the real Firebreak:

            with allowlist   allowed REACHED   denied blocked:TimeoutError
            no allowlist     allowed REACHED   denied REACHED
            net=none         allowed blocked   denied blocked
        """
        # Resolution is stubbed: what is under test is the ruleset built from
        # an answer, not the answer. A test that asked real DNS for a real name
        # would be measuring the network it is supposed to be filtering.
        resolve = patch.object(fb, "egress_addresses",
                               lambda hosts: {h: ["203.0.113.7"] for h in hosts})
        _, plain = self.execute("--net", "allow")
        with resolve:
            _, listed = self.execute("--net", "allow",
                                     "--egress-host", "api.example.com")
        self.assertNotEqual(plain.spawned, listed.spawned,
                            "an egress allowlist did not alter the sandbox")
        joined = " ".join(listed.spawned)
        self.assertIn("ip daddr 203.0.113.7 counter accept", joined,
                      "the resolved address reaches no ruleset")
        self.assertIn("policy drop", joined,
                      "the ruleset does not default to DROP, so an allowlist "
                      "that matched nothing would permit everything")
        self.assertNotIn("203.0.113.7", " ".join(plain.spawned),
                         "a session that declared no host got a filter anyway")
        start = self.records()[2]
        self.assertEqual(start["egress_allowlist_requested"], ["api.example.com"])
        entry = start["enforcement"]["egress_allowlist"]
        self.assertEqual(entry["status"], "enforced")
        self.assertIn("nftables", entry["mechanism"])

    def test_the_recorded_argv_is_the_argv_that_was_spawned(self):
        """A record of a DIFFERENT command line than the one that ran describes
        a containment nobody applied. Posture 'allow' is where these could
        drift: the namespace helper and the egress filter are spliced in around
        bwrap, and for a while the record held only the bwrap half -- so its own
        enforcement row read the missing --unshare-net as a namespace that was
        never created, on a session that was fully contained."""
        for posture in ("none", "allow"):
            with self.subTest(net=posture):
                _, spawned = self.execute("--net", posture)
                # The LAST start record: both postures append to one session
                # file here, and index 0 would compare the second run's argv
                # against the first run's record.
                started = [r for r in self.records() if r["record"] == "started"]
                self.assertEqual(started[-1]["sandbox_argv"], spawned.argv)

    def test_a_masked_path_changes_the_sandbox_and_says_so(self):
        """This asserted the opposite until Stage E, and it was right to.

        --mask-path was accepted and applied by nothing -- its own help text
        said RECORDED ONLY -- so a provider could declare .env masked, the
        receipt printed the declaration, and the agent read the file. A file is
        masked with /dev/null over it and a directory with an empty tmpfs, both
        in the sandbox's own mount namespace. Measured through the real
        Firebreak: direct open, absolute path, relative traversal, symlink,
        nested file and renaming the target are each denied.
        """
        secret = self.base / "private.txt"
        secret.write_text("private")
        _, plain = self.execute()
        _, masked = self.execute("--mask-path", str(secret))
        self.assertNotEqual(plain.spawned, masked.spawned,
                            "a masked path did not alter the sandbox at all")
        self.assertIn("--ro-bind", masked.spawned)
        joined = " ".join(masked.spawned)
        self.assertIn("/dev/null " + str(secret), joined,
                      "the mask does not reach bwrap")
        start = self.records()[2]
        self.assertEqual(start["masked_paths_requested"], [str(secret)])
        self.assertEqual(start["enforcement"]["masked_paths"]["status"], "enforced")

    def test_a_masked_directory_becomes_an_empty_tmpfs(self):
        secret = self.base / "secrets"
        secret.mkdir()
        (secret / "token").write_text("token")
        _, masked = self.execute("--mask-path", str(secret))
        self.assertIn("--tmpfs", masked.spawned)
        self.assertIn("--tmpfs " + str(secret), " ".join(masked.spawned))

    def test_no_field_names_a_restriction_firebreak_does_not_apply(self):
        """Only the REQUESTED list may be recorded. A bare `egress_allowlist`
        or `masked_paths` key would read as the applied set, and the applied
        set is not the asked-for set: a name that resolves to nothing today
        contributes no address to the ruleset."""
        self.execute("--egress-host", "api.example.com", "--mask-path", "/etc/hosts")
        start = self.records()[0]
        for field in ("egress_allowlist", "masked_paths", "network", "limits"):
            self.assertNotIn(field, start)
        for field, entry in start["enforcement"].items():
            with self.subTest(field=field):
                self.assertIn(entry["status"], ("enforced", "partial", "not_enforced",
                                                "observed", "not_applicable"))
                self.assertTrue(entry["mechanism"].strip(),
                                "a status with no mechanism explains nothing")

    def test_an_unused_field_is_not_applicable_rather_than_unenforced(self):
        """A session that asked for no egress hosts is not a session whose
        allowlist failed."""
        self.execute()
        status = self.records()[0]["enforcement"]
        self.assertEqual(status["egress_allowlist"]["status"], "not_applicable")
        self.assertEqual(status["masked_paths"]["status"], "not_applicable")
        self.assertEqual(status["read_grants"]["status"], "not_applicable")

    # -- correlation and the command ---------------------------------------- #
    def test_the_record_correlates_the_session_mission_task_and_scope(self):
        self.execute("--mission", "m-0001", "--task", "t-0001")
        start = self.records()[0]
        self.assertEqual(start["session"], "s-record")
        self.assertEqual(start["session_id_source"], "orchestrator")
        self.assertEqual(start["mission"], "m-0001")
        self.assertEqual(start["task"], "t-0001")
        self.assertEqual(start["scope_unit"], "s-record.scope")
        self.assertIn("--unit=s-record", start["sandbox_argv"])
        end = self.records()[1]
        self.assertEqual((end["mission"], end["task"]), ("m-0001", "t-0001"))

    def test_a_minted_id_says_so_and_still_records(self):
        sandbox = FakeSandbox(0)
        with patch.object(fb.subprocess, "Popen", sandbox):
            fb.main(["run", "--workspace", "project", "--no-checkpoint", "--", "true"])
        files = sorted(self.audit.glob("*.session"))
        self.assertEqual(len(files), 1)
        start = fb.read_records(files[0])[0]
        self.assertEqual(start["session_id_source"], "firebreak")
        self.assertTrue(start["session"].startswith("fb-"))

    def test_the_agent_command_and_the_resolved_argv_are_both_recorded(self):
        self.execute()
        start = self.records()[0]
        self.assertEqual(start["agent_command"], ["true"])
        self.assertEqual(start["sandbox_argv"][0], "systemd-run")
        # An ABSOLUTE bwrap, not a name for PATH to answer: the argv is the
        # record of what confined this session, and a bare name would record a
        # question rather than an answer.
        self.assertIn("/usr/bin/bwrap", start["sandbox_argv"])
        self.assertEqual(start["sandbox_argv"][-1], "true")

    def test_the_resolved_executable_uses_the_sandbox_path(self):
        """The host's PATH would answer a different question: these directories
        are bound into the sandbox at the same paths, the host's PATH is not."""
        found, how = fb.resolved_executable("sh", self.ws)
        self.assertEqual(how, "sandbox-path-lookup")
        self.assertTrue(found.startswith(("/usr/", "/bin/")))
        self.assertEqual(fb.resolved_executable("no-such-program-anywhere", self.ws),
                         (None, "unresolved"))

    def test_a_relative_program_resolves_against_the_workspace(self):
        """The sandbox chdirs to the workspace; Firebreak's own cwd is not it."""
        tool = self.ws / "tool.sh"
        tool.write_text("#!/bin/sh\n")
        self.assertEqual(fb.resolved_executable("./tool.sh", self.ws),
                         (str(tool), "literal-path"))

    def test_the_record_says_where_it_was_written(self):
        self.execute()
        start = self.records()[0]
        self.assertEqual(start["audit_directory"], str(self.audit))
        self.assertTrue(start["audit_directory_relocated"],
                        "a record written outside the canonical directory must say so")

    # -- log ---------------------------------------------------------------- #
    def test_log_prints_every_record_of_a_session(self):
        self.execute()
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            fb.main(["log", "5"])
        printed = buffer.getvalue()
        self.assertIn('"record": "started"', printed)
        self.assertIn('"record": "ended"', printed)

    def test_log_still_reads_a_manifest_written_before_this_change(self):
        """The canonical directory already holds pretty-printed single objects."""
        self.audit.mkdir(parents=True)
        (self.audit / "old.session").write_text(
            json.dumps({"session": "old", "workspace": "/w"}, indent=2) + "\n")
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            fb.main(["log"])
        printed = buffer.getvalue()
        self.assertIn('"session": "old"', printed)
        self.assertIn('"record": "legacy"', printed)


class AuditStateLocationTests(unittest.TestCase):
    """Where the audit trail lives is not an ambient decision."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        (self.base / "Workspaces").mkdir()
        self.env = patch.dict(os.environ, {
            "SHADOWFETCH_AGENT_WORKSPACES": str(self.base / "Workspaces")})
        self.env.start()
        self.addCleanup(self.env.stop)
        os.environ.pop(fb.STATE_ENV, None)

    def test_the_canonical_home_comes_from_passwd_not_from_the_environment(self):
        with patch.dict(os.environ, {"HOME": str(self.base / "not-really-home")}):
            self.assertEqual(fb.passwd_home(),
                             Path(pwd.getpwuid(os.geteuid()).pw_dir))

    def test_xdg_state_home_no_longer_moves_the_audit_directory(self):
        """It is ambient: a desktop session, a user unit or a container image
        sets it for unrelated reasons and Firebreak inherits it, so it could
        move the audit trail with nobody having decided to."""
        home = self.base / "home"
        stray = self.base / "xdg"
        with patch.dict(os.environ, {"XDG_STATE_HOME": str(stray)}), \
                patch.object(fb, "passwd_home", return_value=home):
            resolved = fb.state()
        self.assertEqual(resolved, (home / ".local/state/shadowfetch/firebreak").resolve())
        self.assertFalse(stray.exists(), "the ambient variable created a directory")
        self.assertFalse(fb.state_relocated())

    def test_the_purpose_named_variable_relocates_and_the_relocation_is_visible(self):
        target = self.base / "elsewhere"
        with patch.dict(os.environ, {fb.STATE_ENV: str(target)}):
            self.assertEqual(fb.state(), target.resolve())
            self.assertTrue(fb.state_relocated())
        self.assertEqual(target.stat().st_mode & 0o777, 0o700)

    def test_a_relative_override_is_refused_and_creates_nothing(self):
        with patch.dict(os.environ, {fb.STATE_ENV: "relative/audit"}):
            with self.assertRaises(fb.Error):
                fb.state()
        self.assertFalse((Path.cwd() / "relative").exists())

    def test_an_audit_directory_belonging_to_someone_else_is_refused(self):
        target = self.base / "someone-elses"
        target.mkdir()
        other = os.geteuid() + 1
        with patch.dict(os.environ, {fb.STATE_ENV: str(target)}), \
                patch.object(fb.os, "geteuid", return_value=other):
            with self.assertRaises(fb.Error):
                fb.state()
        self.assertEqual(list(target.iterdir()), [],
                         "the refusal still wrote into the directory")

    def test_an_override_inside_the_workspace_root_is_refused(self):
        """An agent that can read its own workspace could otherwise read, or
        rewrite, the record of what it was allowed to do."""
        inside = self.base / "Workspaces" / "project" / "audit"
        with patch.dict(os.environ, {fb.STATE_ENV: str(inside)}):
            with self.assertRaises(fb.Error):
                fb.state()
        self.assertFalse(inside.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
