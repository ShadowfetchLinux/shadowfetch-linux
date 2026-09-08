"""Firebreak session records: append-safe, and honest about enforcement (W-37).

Two properties carry the weight here.

A record has to survive the end of the session it describes. The previous
implementation wrote one object and rewrote it at exit, so a running session
could not be inspected at all and a crash in between left neither the start nor
the end.

And every field has to separate what a caller ASKED FOR from what the kernel is
actually told. Firebreak has two network postures and no masking flag, so an
egress allowlist and a masked path reach nothing whatsoever; a record that did
not say so would be describing protection that does not exist.
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
    """A sandbox that never runs. What is under test is the record, not bwrap."""

    def __init__(self, rc=0, before=None):
        self.rc = rc
        self.before = before
        self.spawned = None

    def __call__(self, cmd, **kwargs):
        if self.before is not None:
            self.before()
        self.spawned = list(cmd)
        return self

    def wait(self, timeout=None):
        return self.rc

    def poll(self):
        return self.rc

    def terminate(self):
        pass

    def kill(self):
        pass


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
        with patch.object(fb.subprocess, "Popen", sandbox):
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

    def test_network_allow_is_never_recorded_as_enforced(self):
        code, _ = self.execute("--net", "allow")
        self.assertEqual(code, 0)
        start = self.records()[0]
        self.assertEqual(start["network_requested"], "allow")
        self.assertEqual(start["network_effective"], "allow")
        self.assertEqual(start["enforcement"]["network"]["status"], "not_enforced")

    def test_the_default_posture_records_that_the_caller_asked_for_nothing(self):
        self.execute()
        start = self.records()[0]
        self.assertIsNone(start["network_requested"])
        self.assertEqual(start["network_effective"], "none")

    # -- recorded, and applied by nothing ----------------------------------- #
    def test_an_egress_allowlist_changes_nothing_and_says_it_changes_nothing(self):
        _, plain = self.execute()
        _, listed = self.execute("--egress-host", "api.example.com",
                                 "--egress-host", "cdn.example.com")
        self.assertEqual(plain.spawned, listed.spawned,
                         "an egress allowlist appeared to alter the sandbox")
        start = self.records()[2]
        self.assertEqual(start["egress_allowlist_requested"],
                         ["api.example.com", "cdn.example.com"])
        self.assertEqual(start["enforcement"]["egress_allowlist"]["status"], "not_enforced")

    def test_a_masked_path_changes_nothing_and_says_it_changes_nothing(self):
        secret = self.base / "private.txt"
        secret.write_text("private")
        _, plain = self.execute()
        _, masked = self.execute("--mask-path", str(secret))
        self.assertEqual(plain.spawned, masked.spawned,
                         "a masked path appeared to alter the sandbox")
        start = self.records()[2]
        self.assertEqual(start["masked_paths_requested"], [str(secret)])
        self.assertEqual(start["enforcement"]["masked_paths"]["status"], "not_enforced")

    def test_no_field_names_a_restriction_firebreak_does_not_apply(self):
        """Only the REQUESTED list may be recorded. A bare `egress_allowlist`
        or `masked_paths` key reads as a control that was applied."""
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
        self.assertIn("bwrap", start["sandbox_argv"])
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
