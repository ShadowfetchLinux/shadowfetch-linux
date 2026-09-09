"""The Claude Code provider: the shared conformance suite, plus what it cannot see.

Two halves.

The first half runs the SAME assertions every other provider runs, against this
provider, inside a registry that also holds every other shipped provider. It
lives here rather than in the shared file so that adding a provider needs no
edit to a file six other people are editing; the shared file's own
"every registered provider has a profile" assertion still has to be satisfied,
and the profile it needs is importable as claude_conformance.CLAUDE_PROFILE.

The second half is adversarial, and is aimed at the things conformance is not
allowed to know: that this CLI refuses stream-json without --verbose, that a
model name becomes an argv element and therefore has to be an allowlist, that
an interactive sign-in on the host is NOT mission authentication, and that a
hostile stream cannot manufacture a durable tool record.

Nothing here contacts a network, and nothing here runs the real agent.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

from provider_conformance import (
    MISSION_MODULES, PROTECTED_FILES, ProviderCase, ProviderRegistry, REPO_ROOT,
    SHIPPED_MANIFESTS, conformance_class, fixture_registry, path_resolution_hits,
)

import sf_missions
import sf_providers
import sf_provider_claude
from sf_providers import (AgentEvent, ProviderError, sandbox_from_manifest,
                          verify_invocation)

from claude_conformance import CLAUDE_PROFILE, PROVIDER_ID

MANIFEST_PATH = SHIPPED_MANIFESTS / f"{PROVIDER_ID}.json"
POLICY_DIR = (REPO_ROOT
              / "packages/shadowfetch-missions/data/usr/share/shadowfetch/provider-policy")
APPROVED_ENTRY = POLICY_DIR / f"{PROVIDER_ID}.approved-entry.json"

REGISTRY = fixture_registry(SHIPPED_MANIFESTS, MISSION_MODULES)

# The identical suite, with this provider's profile. The id is spelled out
# rather than referenced, because the shared conformance file's
# PROFILES_ELSEWHERE check reads this source and requires the provider it
# delegates here to be named in it -- a map entry that pointed at a module
# testing something else would otherwise be a way to opt out of conformance by
# writing a filename down.
_CASE = ProviderCase(REGISTRY, "claude", CLAUDE_PROFILE, "claude")
assert PROVIDER_ID == "claude"
_KLASS = conformance_class(_CASE, module=__name__)
globals()[_KLASS.__name__] = _KLASS
# Bound under its generated name only. Leaving the loop variable bound as well
# made discovery collect the same suite twice under two names, which doubles
# the run and makes a count of passing assertions meaningless.
del _CASE, _KLASS


def provider():
    return REGISTRY.get(PROVIDER_ID)


def manifest():
    return REGISTRY.manifest(PROVIDER_ID)


def build(capability, request):
    with CLAUDE_PROFILE.invocation_context():
        return provider().build_invocation(capability, request)


def a_request(tmp, **extra):
    prompt = Path(tmp) / "agent-request.txt"
    prompt.write_text("Summarize the launch\n", encoding="utf-8")
    request = {"prompt_path": str(prompt), "config": {"network": "allow"}}
    request.update(extra)
    return request


class ArgvTests(unittest.TestCase):
    """What the command line has to say, because the CLI was asked."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="sf-claude-argv-")
        self.addCleanup(self.tmp.cleanup)
        self.request = a_request(self.tmp.name)

    def argv(self, capability="code_change", **extra):
        return list(build(capability, dict(self.request, **extra)).argv)

    def test_stream_json_is_always_accompanied_by_verbose(self):
        """Measured, not assumed: claude 2.1.178 refuses the combination.

            $ claude --bare --print --output-format stream-json
            Error: When using --print, --output-format=stream-json requires --verbose

        An adapter that drops --verbose therefore produces a provider that
        cannot complete a single mission, and every other assertion in this
        file would still pass.
        """
        for capability in ("code_change", "sourced_report"):
            argv = self.argv(capability)
            with self.subTest(capability=capability):
                self.assertIn("--output-format", argv)
                self.assertEqual(argv[argv.index("--output-format") + 1], "stream-json")
                self.assertIn("--verbose", argv)
                self.assertIn("--print", argv)

    def test_the_run_is_isolated_from_the_host_configuration(self):
        """--bare is what makes the run reproducible and the credential the
        only way in: no hooks, no plugins, no auto-discovered memory, no
        keychain, and Anthropic authentication strictly from the declared
        identity."""
        self.assertIn("--bare", self.argv())

    def test_a_read_only_mission_loses_the_writing_tool_and_the_writable_workspace(self):
        invocation = build("sourced_report", self.request)
        argv = list(invocation.argv)
        self.assertEqual(invocation.sandbox.workspace_mode, "read-only")
        self.assertIn("--tools", argv)
        tools = argv[argv.index("--tools") + 1].split(",")
        self.assertNotIn("Edit", tools)
        self.assertIn("Read", tools)
        # ... and a writing mission keeps it, so the narrowing is a decision
        # rather than a constant.
        writable = build("code_change", self.request)
        self.assertEqual(writable.sandbox.workspace_mode, "workspace-write")
        self.assertIn("Edit", list(writable.argv)[list(writable.argv).index("--tools") + 1])

    def test_read_only_is_requested_explicitly_as_well_as_by_capability(self):
        invocation = build("code_change", dict(self.request, read_only=True))
        self.assertEqual(invocation.sandbox.workspace_mode, "read-only")

    def test_the_settings_argument_is_one_stable_serialisation(self):
        """argv must be byte-identical for identical input; a dict re-serialised
        per call is not."""
        first, second = self.argv(), self.argv()
        self.assertEqual(first, second)
        settings = first[first.index("--settings") + 1]
        self.assertEqual(json.loads(settings),
                         {"env": {"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
                                  "IS_SANDBOX": "1"}})

    def test_the_run_declares_itself_sandboxed_so_the_agent_will_start(self):
        """A regression guard on a defect a fixture could not have found.

        Firebreak runs the payload as uid 0 in an unshared user namespace, and
        the CLI refuses the permission mode this adapter asks for under root:

            --dangerously-skip-permissions cannot be used with root/sudo
            privileges for security reasons

        It printed that and exited BEFORE writing a single stream record, so
        every mission would have failed with a log no parser could read.
        Removing this pair -- the declaration or the mode it unblocks -- breaks
        every mission, and nothing else in this suite would notice.
        """
        argv = self.argv()
        settings = json.loads(argv[argv.index("--settings") + 1])
        self.assertEqual(settings["env"]["IS_SANDBOX"], "1")
        self.assertEqual(argv[argv.index("--permission-mode") + 1],
                         "bypassPermissions")

    def test_the_egress_reducing_switch_is_requested(self):
        """Measured, and the reason the declared allowlist is one host: with the
        switch off, every run reached a second destination as well."""
        argv = self.argv()
        settings = json.loads(argv[argv.index("--settings") + 1])
        self.assertEqual(
            settings["env"]["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"], "1")

    def test_a_prompt_is_delivered_as_a_file_on_stdin_not_on_the_command_line(self):
        invocation = build("code_change", self.request)
        self.assertEqual(invocation.stdin_path, self.request["prompt_path"])
        self.assertNotIn("Summarize the launch", " ".join(map(str, invocation.argv)))

    def test_a_missing_prompt_is_a_refusal_a_person_can_act_on(self):
        with self.assertRaises(ProviderError) as caught:
            build("code_change", {"config": {"network": "allow"}})
        self.assertIn("prompt", str(caught.exception).lower())

    def test_a_missing_program_is_a_refusal_rather_than_a_crash(self):
        with CLAUDE_PROFILE.binary_absent(), self.assertRaises(ProviderError) as caught:
            provider().build_invocation("code_change", self.request)
        self.assertIn("not found", str(caught.exception).lower())


class ModelSelectionTests(unittest.TestCase):
    """A model name becomes an argv element, so it is an allowlist."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="sf-claude-model-")
        self.addCleanup(self.tmp.cleanup)
        self.request = a_request(self.tmp.name)

    def test_a_supported_model_reaches_the_command_line(self):
        for model in ("sonnet", "opus", "haiku", "fable", "claude-sonnet-4-6"):
            with self.subTest(model=model):
                request = dict(self.request,
                               config={"network": "allow", "model": model})
                argv = list(build("code_change", request).argv)
                self.assertIn("--model", argv)
                self.assertEqual(argv[argv.index("--model") + 1], model)
                self.assertTrue(provider().accepts("code_change", request["config"]).ok)

    def test_no_model_means_no_model_flag(self):
        argv = list(build("code_change", self.request).argv)
        self.assertNotIn("--model", argv)

    def test_a_hostile_model_value_is_refused_by_both_gates(self):
        """accepts() is advice; build_invocation() is the gate.

        A caller that skips acceptance -- and Mission Control's own retry path
        builds an invocation without re-asking -- must not be able to put an
        arbitrary string on this command line.
        """
        hostile = ("--dangerously-skip-permissions", "-p", "sonnet --add-dir /",
                   "sonnet;rm -rf /", "../../etc/passwd", "", " ", "claude-" + "x" * 80,
                   "SONNET", "opus\nsonnet", 5, None, ["sonnet"], {"model": "sonnet"})
        for model in hostile:
            with self.subTest(model=model):
                config = {"network": "allow", "model": model}
                if model:                       # falsy values mean "no selection"
                    self.assertFalse(provider().accepts("code_change", config).ok)
                    with self.assertRaises(ProviderError):
                        build("code_change", dict(self.request, config=config))
                else:
                    argv = list(build("code_change",
                                      dict(self.request, config=config)).argv)
                    self.assertNotIn("--model", argv)

    def test_the_refusal_names_what_is_acceptable(self):
        answer = provider().accepts("code_change",
                                    {"network": "allow", "model": "gpt-4o"})
        self.assertFalse(answer.ok)
        self.assertIn("sonnet", answer.reason)
        self.assertGreaterEqual(len(answer.reason.split()), 6)


class SessionCorrelationTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="sf-claude-session-")
        self.addCleanup(self.tmp.cleanup)

    def session_of(self, invocation):
        argv = list(invocation.argv)
        return argv[argv.index("--session-id") + 1]

    def test_the_session_id_is_a_uuid_derived_from_the_request(self):
        request = a_request(self.tmp.name)
        first = self.session_of(build("code_change", request))
        second = self.session_of(build("code_change", request))
        self.assertEqual(first, second, "argv is not deterministic")
        self.assertEqual(str(uuid.UUID(first)), first)

    def test_two_missions_do_not_share_a_session_identifier(self):
        one = tempfile.TemporaryDirectory(prefix="sf-claude-a-")
        two = tempfile.TemporaryDirectory(prefix="sf-claude-b-")
        self.addCleanup(one.cleanup)
        self.addCleanup(two.cleanup)
        self.assertNotEqual(
            self.session_of(build("code_change", a_request(one.name))),
            self.session_of(build("code_change", a_request(two.name))))

    def test_the_identifier_the_stream_reports_is_read_back_not_asserted(self):
        events = provider().parse_stream(CLAUDE_PROFILE.streams[0].text)
        correlation = provider().session_correlation(events)
        self.assertEqual(correlation["reported_session_ids"],
                         ["3c9f1f8e-2a1d-5f6b-8c7d-9e0a1b2c3d4e"])
        # Two different identifiers in one stream are BOTH reported. Choosing
        # one would hide the only evidence that something re-used the log.
        mixed = (CLAUDE_PROFILE.streams[0].text
                 + CLAUDE_PROFILE.streams[3].text)
        self.assertEqual(
            len(provider().session_correlation(
                provider().parse_stream(mixed))["reported_session_ids"]), 2)


class ReadinessHonestyTests(unittest.TestCase):
    """Installed, signed in, and able to run a mission are three facts."""

    @staticmethod
    def readiness_with(home, **environment):
        with mock.patch.dict(os.environ, dict(environment, HOME=str(home))):
            os.environ.pop("ANTHROPIC_API_KEY", None)
            for name, value in environment.items():
                os.environ[name] = value
            with CLAUDE_PROFILE.binary_present():
                return provider().readiness()

    def test_an_interactive_sign_in_on_the_host_is_not_mission_authentication(self):
        """The trap this provider is most likely to fall into.

        A person signs in with the CLI, the host grows an OAuth credential
        file, and every naive readiness check reports the provider ready. It is
        not: the sandbox is given its own home, and the CLI is run in a mode
        that reads no stored session, so the mission authenticates only through
        the declared identity. Counting the file would produce a provider that
        looks available and fails on first use.
        """
        home = tempfile.TemporaryDirectory(prefix="sf-claude-signedin-")
        self.addCleanup(home.cleanup)
        credentials = Path(home.name) / ".claude/.credentials.json"
        credentials.parent.mkdir(parents=True)
        credentials.write_text('{"claudeAiOauth":{"accessToken":"x"}}', encoding="utf-8")
        readiness = self.readiness_with(home.name)
        self.assertTrue(readiness.installed)
        self.assertFalse(readiness.authenticated)
        self.assertFalse(readiness.available)
        self.assertTrue(readiness.facts["interactive_sign_in_present"])
        self.assertFalse(readiness.facts["interactive_sign_in_usable_for_missions"])
        self.assertIn("does not carry into a mission", readiness.reason)

    def test_the_declared_identity_authenticates(self):
        home = tempfile.TemporaryDirectory(prefix="sf-claude-key-")
        self.addCleanup(home.cleanup)
        readiness = self.readiness_with(home.name,
                                        ANTHROPIC_API_KEY="fixture-identity")
        self.assertTrue(readiness.authenticated)
        self.assertTrue(readiness.available)
        self.assertEqual(readiness.missing, ())
        self.assertNotIn("fixture-identity", json.dumps(readiness.as_dict()),
                         "a credential VALUE reached a readiness report")

    def test_an_operator_credential_file_counts_only_when_it_is_private(self):
        for mode, expected in ((0o600, True), (0o640, False), (0o666, False)):
            home = tempfile.TemporaryDirectory(prefix="sf-claude-file-")
            self.addCleanup(home.cleanup)
            path = Path(home.name) / sf_provider_claude.CREDENTIAL_FILE
            path.parent.mkdir(parents=True)
            path.write_text("ANTHROPIC_API_KEY=fixture\n", encoding="utf-8")
            path.chmod(mode)
            with self.subTest(mode=oct(mode)):
                self.assertEqual(self.readiness_with(home.name).authenticated, expected)

    def test_a_symlinked_credential_file_does_not_count(self):
        home = tempfile.TemporaryDirectory(prefix="sf-claude-link-")
        self.addCleanup(home.cleanup)
        target = Path(home.name) / "elsewhere.env"
        target.write_text("ANTHROPIC_API_KEY=fixture\n", encoding="utf-8")
        target.chmod(0o600)
        path = Path(home.name) / sf_provider_claude.CREDENTIAL_FILE
        path.parent.mkdir(parents=True)
        path.symlink_to(target)
        self.assertFalse(self.readiness_with(home.name).authenticated)

    def test_readiness_runs_no_subprocess(self):
        """A readiness probe that executes the agent would spawn one process per
        UI refresh, and would still be answering a question about the HOST
        rather than about the sandbox."""
        home = tempfile.TemporaryDirectory(prefix="sf-claude-noproc-")
        self.addCleanup(home.cleanup)
        with mock.patch("subprocess.Popen") as popen, \
                mock.patch("subprocess.run") as run:
            self.readiness_with(home.name)
        self.assertEqual(popen.call_count, 0)
        self.assertEqual(run.call_count, 0)


class ToolRecordTests(unittest.TestCase):
    """Tool activity has to survive into the durable record, and nothing else may."""

    def records(self, stream_name):
        case = next(c for c in CLAUDE_PROFILE.streams if c.name == stream_name)
        return sf_missions.tool_records(provider().parse_stream(case.text))

    def test_one_row_per_tool_call_with_its_outcome(self):
        rows = self.records("claude_success.jsonl")
        self.assertEqual(len(rows), 1, "a call and its result must not become two rows")
        row = rows[0]
        self.assertEqual(row["tool"], "Read")
        self.assertEqual(row["exit_status"], "ok")
        self.assertEqual(row["requested_action"], "file_path=/workspace/RELEASE.md")
        self.assertTrue(row["args_digest"])
        self.assertEqual(row["args_redacted"], {"file_path": "/workspace/RELEASE.md"})

    def test_a_failed_tool_call_is_recorded_as_failed(self):
        rows = self.records("claude_tool_denied.jsonl")
        self.assertEqual([r["exit_status"] for r in rows], ["error"])
        self.assertEqual(len(rows[0]["result_digest"]), 64)

    def test_a_call_with_no_result_still_produces_a_row(self):
        """Cancellation is exactly when a person wants to know what ran."""
        rows = self.records("claude_cancelled.jsonl")
        self.assertEqual([r["tool"] for r in rows], ["Bash"])
        self.assertIsNone(rows[0]["exit_status"])

    def test_prose_and_unknown_events_produce_no_rows(self):
        for name in ("claude_interleaved.jsonl", "claude_unauthenticated.jsonl"):
            with self.subTest(stream=name):
                self.assertEqual(self.records(name), [])

    def test_a_hostile_stream_cannot_forge_a_tool_record(self):
        hostile = "\n".join([
            json.dumps({"type": "assistant", "message": {"content": [
                {"type": "tool_use", "id": "t1", "name": None, "input": {}}]}}),
            json.dumps({"type": "assistant", "message": {"content": [
                {"type": "tool_use", "id": "t2", "name": "", "input": {}}]}}),
            json.dumps({"type": "assistant", "message": {"content": [
                {"type": "tool_use", "id": "t3", "name": "A" * 5000,
                 "input": {"command": "B" * 5000}}]}}),
            json.dumps({"type": "assistant", "message": {"content": [
                {"type": "tool_use", "id": "t4", "name": "Ba\x00sh", "input": None}]}}),
            json.dumps({"type": "user", "message": {"content": [
                {"type": "tool_result", "tool_use_id": "unknown", "is_error": True}]}}),
            json.dumps({"type": "progress", "tool": "Bash",
                        "args": {"command": "rm -rf /"}}),
        ])
        rows = sf_missions.tool_records(provider().parse_stream(hostile))
        self.assertEqual([r["tool"] for r in rows],
                         ["A" * 200, "Bash"],
                         "a nameless tool_use, or a top-level key that merely looks "
                         "like one, became a durable record")
        for row in rows:
            self.assertLessEqual(len(row["tool"]), 200)
            self.assertIsNone(row["exit_status"],
                              "a result for a different call was attached to this one")


class StreamRobustnessTests(unittest.TestCase):
    """The stream is untrusted input. Shapes conformance's generic battery misses."""

    HOSTILE = (
        '{"type":"assistant"}',
        '{"type":"assistant","message":null}',
        '{"type":"assistant","message":{"content":"not a list"}}',
        '{"type":"assistant","message":{"content":[null,3,"x",[]]}}',
        '{"type":"assistant","message":{"content":[{"type":"text","text":null}]}}',
        '{"type":"assistant","message":{"content":[{"type":"text"}]},"error":123}',
        '{"type":"assistant","message":{"usage":"not a dict"}}',
        '{"type":"user","message":{"content":[{"type":"tool_result"}]}}',
        '{"type":"result"}',
        '{"type":"result","is_error":true}',
        '{"type":"result","is_error":"yes","result":null}',
        '{"type":"result","is_error":false,"usage":"not a dict","result":42}',
        '{"type":"result","is_error":false,"total_cost_usd":"free"}',
        '{"type":"system","subtype":null}',
        '{"type":"system","subtype":"init","tools":"Bash","session_id":9}',
        '{"type":"system","subtype":"api_retry","attempt":"many"}',
        '{"type":null}',
        '{"type":["assistant"]}',
        '{"type":"assistant","message":{"content":[{"type":"tool_use","id":{},"name":"X"}]}}',
    )

    def test_no_shape_raises_and_every_event_is_well_formed(self):
        allowed = {AgentEvent.MESSAGE, AgentEvent.PROGRESS, AgentEvent.USAGE,
                   AgentEvent.LOG, AgentEvent.ERROR, AgentEvent.TURN_COMPLETE}
        for line in self.HOSTILE:
            with self.subTest(line=line[:60]):
                events = provider().parse_stream(line)
                for event in events:
                    self.assertIn(event.type, allowed)
                    self.assertIsInstance(event.text, str)
                    self.assertIsInstance(event.data, dict)
                provider().final_message(events)
                provider().usage(events)
                provider().turn_succeeded(events)

    def test_all_of_them_at_once_in_any_order(self):
        joined = "\n".join(self.HOSTILE)
        self.assertIsInstance(provider().parse_stream(joined), list)
        self.assertIsInstance(provider().parse_stream("\n".join(reversed(self.HOSTILE))),
                              list)

    def test_a_truthy_is_error_of_any_type_fails_the_turn(self):
        """is_error is the fact; subtype has been observed saying 'success' on a
        turn that failed."""
        for value in ("yes", 1, [0], {"a": 1}):
            with self.subTest(is_error=value):
                events = provider().parse_stream(json.dumps(
                    {"type": "result", "subtype": "success", "is_error": value,
                     "result": "done"}))
                self.assertFalse(provider().turn_succeeded(events))
                self.assertIn(AgentEvent.ERROR, [e.type for e in events])

    def test_a_stream_with_no_records_at_all_says_the_agent_did_not_start(self):
        """The shape a refused flag or a broken sandbox produces.

        It cannot be a success under any reading -- there is no terminal record
        -- so naming it costs nothing and turns "did not record a complete turn"
        into the sentence the program actually printed.
        """
        prose = ("--dangerously-skip-permissions cannot be used with root/sudo "
                 "privileges for security reasons\nFirebreak session ended (exit 1)")
        events = provider().parse_stream(prose)
        self.assertEqual([e.type for e in events], ["log", "log", "error"])
        self.assertIn("did not start", events[-1].text)
        self.assertIn("root/sudo", events[-1].text)
        self.assertFalse(provider().turn_succeeded(events))

    def test_prose_beside_a_completed_turn_stays_a_log(self):
        """The inverse, and the reason this is not a rule about error-looking
        lines: a stray warning must not be able to fail a turn that finished."""
        case = next(c for c in CLAUDE_PROFILE.streams
                    if c.name == "claude_success.jsonl")
        noisy = "Error: a warning nobody asked for\n" + case.text
        events = provider().parse_stream(noisy)
        self.assertTrue(provider().turn_succeeded(events))
        self.assertEqual([e.type for e in events].count("error"), 0)

    def test_a_turn_with_no_terminal_line_is_never_a_success(self):
        for case in CLAUDE_PROFILE.streams:
            text = case.text.replace('"type":"result"', '"type":"result_removed"')
            with self.subTest(stream=case.name):
                self.assertFalse(provider().turn_succeeded(
                    provider().parse_stream(text)))

    def test_usage_survives_a_turn_that_failed(self):
        """The base rule reads usage only from a completed turn, which is
        exactly when nobody needs it."""
        case = next(c for c in CLAUDE_PROFILE.streams
                    if c.name == "claude_cancelled.jsonl")
        usage = provider().usage(provider().parse_stream(case.text))
        self.assertEqual(usage["output_tokens"], 30)

    def test_an_enormous_line_is_bounded_in_every_field(self):
        events = provider().parse_stream(json.dumps(
            {"type": "assistant", "message": {"content": [
                {"type": "text", "text": "x" * 500000}]}}))
        for event in events:
            self.assertLessEqual(len(event.text), sf_provider_claude.MAX_MESSAGE)


class SandboxAndCredentialTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="sf-claude-sandbox-")
        self.addCleanup(self.tmp.cleanup)
        self.request = a_request(self.tmp.name)

    def test_the_invocation_carries_identities_and_never_a_value(self):
        sentinel = "SENTINEL-ANTHROPIC-MUST-NOT-LEAK-0f1e2d"
        with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": sentinel}):
            invocation = build("code_change", self.request)
        self.assertEqual(invocation.env_allowlist, ("ANTHROPIC_API_KEY",))
        haystack = " ".join([invocation.executable, *map(str, invocation.argv),
                             *invocation.env_allowlist, str(invocation.stdin_path)])
        self.assertNotIn(sentinel, haystack)

    def test_the_network_posture_is_exactly_what_the_manifest_declares(self):
        invocation = build("code_change", self.request)
        self.assertEqual(invocation.sandbox.network, "allowlist")
        self.assertEqual(invocation.sandbox.egress_allowlist, ("api.anthropic.com",))
        self.assertEqual(invocation.sandbox.firebreak_network, "allow")
        # A read-only mission keeps the network: it is a cloud agent either way.
        self.assertEqual(build("sourced_report", self.request).sandbox.network,
                         "allowlist")

    def test_the_adapter_cannot_widen_what_it_was_given(self):
        ceiling = sandbox_from_manifest(manifest())
        for change in ({"credential_ids": ("ANTHROPIC_API_KEY", "STOLEN")},
                       {"egress_allowlist": ("api.anthropic.com", "exfil.example.com")},
                       {"read_grants": ("/etc",)},
                       {"memory_mb": ceiling.memory_mb + 1},
                       {"account_mount": "codex-account"}):
            with self.subTest(change=sorted(change)), self.assertRaises(ProviderError):
                ceiling.narrow(**change)

    def test_every_built_invocation_survives_the_orchestrator_check(self):
        for capability in ("code_change", "sourced_report"):
            for extra in ({}, {"read_only": True},
                          {"config": {"network": "allow", "model": "opus"}}):
                with self.subTest(capability=capability, extra=sorted(extra)):
                    invocation = build(capability, dict(self.request, **extra))
                    effective = json.loads(json.dumps(manifest()))
                    effective["executable"] = {
                        "kind": "absolute", "path": invocation.executable,
                        "trust": "user-runtime"}
                    verify_invocation(invocation, effective)

    def test_a_substituted_program_is_refused_by_the_orchestrator(self):
        substitute = "/usr/bin/true" if Path("/usr/bin/true").is_file() else "/bin/true"
        invocation = sf_providers.Invocation(
            executable=substitute, argv=("-x",),
            sandbox=sandbox_from_manifest(manifest()),
            manifest_executable=manifest().get("executable"))
        with self.assertRaises(ProviderError) as caught:
            verify_invocation(invocation, manifest())
        self.assertIn("not a program this manifest declares", str(caught.exception))


class ManifestAndPolicyTests(unittest.TestCase):
    """The data half of the provider, checked against the code half."""

    def setUp(self):
        self.manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

    def test_the_approved_entry_pins_the_manifest_that_actually_ships(self):
        """The handoff file, checked rather than trusted.

        approved.json is shared, so this provider's entry is delivered beside
        it for the release owner to merge. A digest that has drifted from the
        manifest would be found at merge time by the runtime refusing the
        provider; found here it is a one-line fix.
        """
        self.assertTrue(APPROVED_ENTRY.is_file(),
                        f"{APPROVED_ENTRY} is the merge handoff and must ship")
        document = json.loads(APPROVED_ENTRY.read_text(encoding="utf-8"))
        entry = document["providers"][PROVIDER_ID]
        self.assertEqual(document["schema_version"], 1)
        self.assertEqual(
            entry["manifest_sha256"],
            hashlib.sha256(MANIFEST_PATH.read_bytes()).hexdigest(),
            "the approved digest no longer matches the manifest bytes")
        for field in ("capabilities", "credential_ids", "egress_allowlist",
                      "network_policy", "package", "interface_version"):
            self.assertEqual(entry[field], self.manifest[field], field)
        self.assertEqual(entry["executable_trust"], self.manifest["executable"]["trust"])

    def test_the_entry_approves_the_manifest_through_the_real_policy_code(self):
        policy = sf_providers.ApprovedPolicy(
            json.loads(APPROVED_ENTRY.read_text(encoding="utf-8")),
            source="<claude.approved-entry.json>")
        effective = policy.approve(
            self.manifest, hashlib.sha256(MANIFEST_PATH.read_bytes()).hexdigest())
        self.assertEqual(effective["capabilities"], self.manifest["capabilities"])
        self.assertEqual(effective["_policy"]["executable_trust"], "user-runtime")

    def test_a_manifest_edited_after_approval_is_refused(self):
        policy = sf_providers.ApprovedPolicy(
            json.loads(APPROVED_ENTRY.read_text(encoding="utf-8")),
            source="<claude.approved-entry.json>")
        with self.assertRaises(sf_providers.PolicyError):
            policy.approve(self.manifest, "0" * 64)

    def test_the_declared_capabilities_and_the_class_agree(self):
        self.assertEqual(tuple(self.manifest["capabilities"]),
                         sf_provider_claude.ClaudeCodeProvider.CAPABILITIES)

    def test_the_program_is_never_located_through_the_environment(self):
        hits = path_resolution_hits(
            MISSION_MODULES / "sf_provider_claude.py")
        self.assertEqual(hits, [], f"the adapter resolves a program from PATH: {hits}")
        for candidate in self.manifest["executable"]["candidates"]:
            self.assertTrue(candidate.startswith(("/", "~/")), candidate)

    def test_an_allowlist_policy_carries_hosts(self):
        self.assertEqual(self.manifest["network_policy"], "allowlist")
        self.assertTrue(self.manifest["egress_allowlist"])

    def test_the_manifest_declares_no_credential_store_it_cannot_have(self):
        """There is no account mount for this provider, and the manifest must
        not imply one: the schema's account_mount vocabulary has no entry for
        it, so the only channel is the declared environment identity."""
        self.assertNotIn("account_mount", self.manifest["sandbox_profile"])
        self.assertEqual(
            sandbox_from_manifest(self.manifest).account_mount, "")


class SeamTests(unittest.TestCase):
    """The architectural claim: nothing outside this provider knows it exists."""

    def test_mission_control_never_learns_this_provider_name(self):
        for relative in PROTECTED_FILES:
            path = REPO_ROOT / relative
            with self.subTest(file=relative):
                self.assertNotIn(PROVIDER_ID,
                                 path.read_text(encoding="utf-8").lower(),
                                 "the orchestrator, the CLI, the desktop UI or the "
                                 "release gate names this provider, which is the "
                                 "coupling the provider seam exists to remove")

    def test_the_adapter_is_reachable_only_because_a_manifest_names_it(self):
        empty = ProviderRegistry(
            root=Path(tempfile.mkdtemp(prefix="sf-claude-empty-")),
            module_root=MISSION_MODULES,
            policy=sf_providers.ApprovedPolicy(
                json.loads(APPROVED_ENTRY.read_text(encoding="utf-8")),
                source="<seam>"))
        self.assertNotIn(PROVIDER_ID, empty.ids())

    def test_removing_the_approval_removes_the_provider(self):
        stripped = json.loads(json.dumps(REGISTRY.policy.document))
        del stripped["providers"][PROVIDER_ID]
        without = ProviderRegistry(
            root=REGISTRY.root, module_root=REGISTRY.module_root,
            policy=sf_providers.ApprovedPolicy(stripped, source="<seam>"))
        self.assertNotIn(PROVIDER_ID, without.ids())
        self.assertIn("approved-provider policy", " ".join(without.errors))


if __name__ == "__main__":       # pragma: no cover
    unittest.main()
