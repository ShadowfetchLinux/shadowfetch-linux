"""Stage J: the SHIPPED local model provider.

Not to be confused with test_provider_localmodel.py, which exercises the Phase
2.5 conformance FIXTURE of the same shape. This file is about the provider that
actually ships: data/usr/share/shadowfetch/providers/localmodel.json and
data/usr/lib/shadowfetch/missions/sf_provider_localmodel.py.

What is real here and what is not
---------------------------------
REAL. There is no mocked transport anywhere in this file. Where a local
inference service is needed, an actual AF_UNIX server is bound in a temporary
directory and actually answers HTTP; where the bridge is needed, the real
program is executed as a child process. The captured streams under
fixtures/providers/localmodel/streams were produced by running that bridge
against that service, except three that are marked hand-authored because a
well-behaved bridge cannot produce them (a mid-record disconnect, a Firebreak
trailer sharing the pipe, and an end-of-stream with no terminal event).

MOCKED. Exactly two seams, both of them about WHERE things are rather than what
they do: `resolve_executable` is pointed at the bridge in the source tree when
the packaged one is absent, and the manifest's read grant is pointed at the
temporary directory the test's own service is listening in. Both are restored.

NOT PROVEN HERE. That a sandbox with no network can reach the service at all --
that is a property of bwrap and the kernel, it is measured rather than assumed,
and it is measured in test_localmodel_transport.py.
"""
from __future__ import annotations

import contextlib
import copy
import hashlib
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

TESTS_DIR = Path(__file__).resolve().parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

from provider_conformance import (  # noqa: E402
    CAPABILITIES, Capability, MISSION_MODULES, ProviderCase, ProviderProfile,
    ProviderRegistry, SHIPPED_MANIFESTS, StreamCase, AgentEvent, ProviderError,
    conformance_class, failure_text, fixture_registry, manifest_root,
    run_conformance, shipped_manifest_files)

import sf_providers  # noqa: E402
import sf_provider_localmodel  # noqa: E402
from sf_providers import (  # noqa: E402
    Invocation, SandboxSpec, resolve_executable, sandbox_from_manifest,
    verify_invocation)

FIXTURES = TESTS_DIR / "fixtures/providers/localmodel"
STREAMS = FIXTURES / "streams"
# The PACKAGED bridge, not a copy under fixtures: a test that ran its own
# copy would prove the copy works and say nothing about what ships.
SOURCE_BRIDGE = (TESTS_DIR.parent
                 / "data/usr/libexec/shadowfetch/local-model-bridge")
if str(FIXTURES) not in sys.path:
    sys.path.insert(0, str(FIXTURES))
from localmodel_service import FakeModelService  # noqa: E402

PROVIDER_ID = "localmodel"
MANIFEST_PATH = SHIPPED_MANIFESTS / f"{PROVIDER_ID}.json"
APPROVED_ENTRY = (TESTS_DIR.parent
                  / "data/usr/share/shadowfetch/provider-policy"
                  / f"{PROVIDER_ID}.approved-entry.json")

# The whole shipped provider set, with a policy sealed over exactly those
# manifests. The local model provider is therefore exercised beside the two it
# ships with rather than alone, which is the only way the "one capability, more
# than one provider" assertions mean anything.
REGISTRY = fixture_registry(manifest_root(*shipped_manifest_files()), MISSION_MODULES)


def stream(name):
    return (STREAMS / name).read_text(encoding="utf-8")


def bridge_program():
    """The bridge to point readiness at: the packaged one if it is installed,
    otherwise the identical file in the source tree."""
    packaged = (sf_provider_localmodel.BRIDGE
                if os.access(sf_provider_localmodel.BRIDGE, os.X_OK) else None)
    return packaged or str(SOURCE_BRIDGE)


@contextlib.contextmanager
def endpoint_at(directory):
    """Point the provider's single declared read grant at `directory`.

    The socket path is DERIVED from the grant, on purpose: an endpoint outside
    a declared grant would be one the sandbox cannot see, so there is no way to
    express one. Moving the grant is therefore the only way to move the
    endpoint, in a test or anywhere else.
    """
    provider = REGISTRY.get(PROVIDER_ID)
    profile = provider.manifest["sandbox_profile"]
    before = profile["read_grants"]
    profile["read_grants"] = [str(directory)]
    try:
        yield str(Path(directory) / sf_provider_localmodel.ENDPOINT_NAME)
    finally:
        profile["read_grants"] = before


@contextlib.contextmanager
def service_running(**kwargs):
    """A real inference service on a real socket, with the grant pointed at it."""
    with tempfile.TemporaryDirectory(prefix="sf-localmodel-ep-") as directory:
        with FakeModelService(directory, **kwargs) as service, endpoint_at(directory):
            yield service


# --------------------------------------------------------------------------- #
# The conformance profile
# --------------------------------------------------------------------------- #

@contextlib.contextmanager
def localmodel_binary_present():
    """Bridge resolvable AND a service answering: the state readiness calls
    installed. Both halves are required, so both are supplied."""
    with service_running(), mock.patch.object(
            sf_provider_localmodel, "resolve_executable", lambda manifest: bridge_program()):
        yield


@contextlib.contextmanager
def localmodel_binary_absent():
    with mock.patch.object(sf_provider_localmodel, "resolve_executable",
                           lambda manifest: None):
        yield


def localmodel_requests(tmp):
    prompt = tmp / "prompt.md"
    prompt.write_text("Summarize the launch\n", encoding="utf-8")
    base = {"prompt_path": str(prompt), "config": {"network": "none"}}
    return {
        Capability.CODE_CHANGE: [
            dict(base),
            dict(base, read_only=True),
            {"prompt_path": str(prompt), "label": "resume",
             "config": {"network": "none", "session": "chat-1",
                        "model": "test-model:1b", "timeout_seconds": 60}},
        ],
        Capability.SOURCED_REPORT: [dict(base)],
    }


LOCALMODEL_PROFILE = ProviderProfile(
    provider_id=PROVIDER_ID,
    build_requests=localmodel_requests,
    accept_configs={Capability.CODE_CHANGE: {"network": "none"},
                    Capability.SOURCED_REPORT: {"network": "none"}},
    refusals=(
        (Capability.CODE_CHANGE, {"network": "allow"}, "network connection"),
        (Capability.SOURCED_REPORT, {"network": "none", "session": "chat-1"},
         "read-only mission"),
        (Capability.CODE_CHANGE, {"network": "none", "session": "not a session name"},
         "session name"),
        (Capability.CODE_CHANGE, {"network": "none", "timeout_seconds": 0},
         "greater than zero"),
        (Capability.CODE_CHANGE, {"network": "none", "model": "definitely-not-loaded"},
         "local model"),
        (Capability.MEDIA_EXPORT, {"network": "none"}, "does not perform"),
    ),
    streams=(
        StreamCase(
            name="success.ndjson", text=stream("success.ndjson"),
            expect_types=("progress", "progress", "progress", "message", "usage",
                          "turn-complete"),
            expect_final="The launch is Friday.", expect_success=True, exit_code=0),
        StreamCase(
            name="eos-without-terminal.ndjson", text=stream("eos-without-terminal.ndjson"),
            expect_types=("progress", "progress", "message", "turn-complete"),
            expect_final="The bridge closed its pipe on end of stream.",
            expect_success=True, exit_code=0),
        StreamCase(
            name="trailer.ndjson", text=stream("trailer.ndjson"),
            expect_types=("log", "progress", "message", "turn-complete", "log"),
            expect_final="Partial answer.", expect_success=True, exit_code=0),
        StreamCase(
            name="service-error.ndjson", text=stream("service-error.ndjson"),
            expect_types=("progress", "error"),
            expect_final="", expect_success=False, exit_code=1),
        StreamCase(
            name="idle-timeout.ndjson", text=stream("idle-timeout.ndjson"),
            expect_types=("progress", "progress", "message", "error"),
            expect_final="Partial", expect_success=False, exit_code=1),
        StreamCase(
            name="cancelled.ndjson", text=stream("cancelled.ndjson"),
            expect_types=("progress", "progress", "message", "error"),
            expect_final="Partial", expect_success=False, exit_code=143),
        StreamCase(
            name="disconnected.ndjson", text=stream("disconnected.ndjson"),
            expect_types=("progress", "progress", "log", "message", "error"),
            expect_final="Half an ", expect_success=False, exit_code=1),
    ),
    binary_absent=localmodel_binary_absent,
    binary_present=localmodel_binary_present,
    # No account and no credential, so there is nothing to authenticate. The
    # suite then asserts the provider says so rather than leaving the UI to
    # invent a sign-in prompt.
    auth_absent=None,
    auth_present=None,
    notes=("Cancellation and both timeouts are carried in the stream AND in the exit "
           "status: the bridge exits 143 on SIGTERM and 1 on a timeout, and a stream "
           "alone cannot tell 'finished' from 'killed'."),
)

CASE = ProviderCase(REGISTRY, PROVIDER_ID, LOCALMODEL_PROFILE, "localmodel_shipped")
Conformance_localmodel_shipped = conformance_class(CASE, module=__name__)


class ConformanceSuiteTests(unittest.TestCase):
    """The whole conformance suite, run as one assertion.

    The generated class above is what unittest discovery reports method by
    method. This runs the identical suite and fails with the collected output,
    so a regression names every broken assertion at once.
    """

    def test_the_shipped_local_model_provider_passes_provider_conformance(self):
        if resolve_executable(REGISTRY.manifest(PROVIDER_ID)) is None:
            # Not a soft pass: provider_conformance.py hands
            # classify_executable() the None that resolve_executable() returns
            # for an uninstalled program, and Path(None) raises TypeError. That
            # is a latent defect in the suite rather than in this provider --
            # any provider whose program is absent hits it, offline-media
            # included on a host with no ffmpeg. Reported to the lead with the
            # two-line fix; skipping here rather than asserting a green suite
            # that did not run.
            self.skipTest(
                f"{sf_provider_localmodel.BRIDGE} is not installed, so provider "
                "conformance cannot run for this provider on this host")
        result, output = run_conformance(CASE)
        self.assertTrue(result.wasSuccessful(), failure_text(result) or output)
        self.assertGreater(result.testsRun, 15)


# --------------------------------------------------------------------------- #
# Manifest, policy and registry
# --------------------------------------------------------------------------- #

class ManifestAndPolicyTests(unittest.TestCase):

    def setUp(self):
        self.manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

    def test_the_manifest_ships_and_the_registry_activates_it(self):
        self.assertIn(PROVIDER_ID, REGISTRY.ids())
        self.assertEqual(REGISTRY.errors, [])
        provider = REGISTRY.get(PROVIDER_ID)
        self.assertEqual(provider.id, PROVIDER_ID)
        self.assertEqual(tuple(provider.capabilities()),
                         (Capability.CODE_CHANGE, Capability.SOURCED_REPORT))

    def test_the_declared_posture_is_no_network_and_no_credential(self):
        """The containment claim, read off the manifest rather than the prose."""
        self.assertEqual(self.manifest["network_policy"], "none")
        self.assertEqual(self.manifest["egress_allowlist"], [])
        self.assertEqual(self.manifest["credential_ids"], [])
        spec = sandbox_from_manifest(self.manifest)
        self.assertEqual(spec.network, "none")
        self.assertEqual(spec.firebreak_network, "none")
        self.assertEqual(spec.credential_ids, ())
        self.assertEqual(spec.egress_allowlist, ())
        # And the sandbox cannot be talked into a network afterwards.
        with self.assertRaises(ProviderError):
            spec.narrow(network="allowlist", egress_allowlist=("example.com",))

    def test_exactly_one_read_grant_and_it_is_the_endpoint_directory(self):
        grants = self.manifest["sandbox_profile"]["read_grants"]
        self.assertEqual(len(grants), 1, "a second grant is a directory the sandbox "
                                         "can read for no reason this provider can give")
        provider = REGISTRY.get(PROVIDER_ID)
        self.assertEqual(provider.endpoint_directory(), grants[0])
        self.assertEqual(provider.endpoint(),
                         str(Path(grants[0]) / sf_provider_localmodel.ENDPOINT_NAME))
        self.assertTrue(grants[0].startswith("/"))
        # Firebreak's own read_grants() refuses a path with fewer than three
        # components, and refuses the reserved trees. Checked here so a future
        # edit to the manifest cannot silently produce a grant Firebreak will
        # reject at run time, which is a mission that fails at the last moment.
        self.assertGreaterEqual(len(Path(grants[0]).parts), 3)
        for reserved in ("/proc", "/dev", "/run", "/sys", "/home/agent"):
            self.assertFalse(grants[0] == reserved or grants[0].startswith(reserved + "/"))

    def test_the_approval_entry_matches_the_manifest_that_ships(self):
        """The policy pin is on BYTES. An entry that does not match them is an
        approval for a manifest nobody has."""
        self.assertTrue(APPROVED_ENTRY.is_file(),
                        f"{APPROVED_ENTRY.name} is the entry the lead merges into "
                        "approved.json; it must ship beside it")
        document = json.loads(APPROVED_ENTRY.read_text(encoding="utf-8"))
        self.assertEqual(sorted(document), [PROVIDER_ID])
        entry = document[PROVIDER_ID]
        self.assertEqual(entry["manifest_sha256"],
                         hashlib.sha256(MANIFEST_PATH.read_bytes()).hexdigest(),
                         "the approval entry pins a different manifest than the one "
                         "that ships; recompute it")
        for field in ("capabilities", "credential_ids", "egress_allowlist",
                      "network_policy", "interface_version", "package"):
            self.assertEqual(entry[field], self.manifest[field], field)
        self.assertEqual(entry["executable_trust"], self.manifest["executable"]["trust"])

    def test_removing_the_approval_removes_the_provider(self):
        policy = REGISTRY.policy
        stripped = copy.deepcopy(policy.document)
        del stripped["providers"][PROVIDER_ID]
        without = ProviderRegistry(root=REGISTRY.root, module_root=REGISTRY.module_root,
                                   policy=sf_providers.ApprovedPolicy(stripped, "<test>"))
        self.assertNotIn(PROVIDER_ID, without.ids())
        self.assertIn("approved-provider policy", " ".join(without.errors))

    def test_the_capability_is_now_served_by_more_than_one_provider(self):
        """The point of shipping this at all: code_change stops being a synonym
        for one particular runtime."""
        serving = sorted(p.id for p in REGISTRY.for_capability(Capability.CODE_CHANGE))
        self.assertIn(PROVIDER_ID, serving)
        self.assertGreaterEqual(len(serving), 2)
        self.assertNotIn(Capability.CODE_CHANGE, set(REGISTRY.ids()))


# --------------------------------------------------------------------------- #
# Readiness, against a real service on a real socket
# --------------------------------------------------------------------------- #

class ReadinessTests(unittest.TestCase):

    def setUp(self):
        self.provider = REGISTRY.get(PROVIDER_ID)

    def test_ready_when_the_bridge_is_installed_and_a_model_is_loaded(self):
        with mock.patch.object(sf_provider_localmodel, "resolve_executable",
                               lambda manifest: bridge_program()), \
                service_running(models=("qwen-test:1b", "other-test:3b")):
            readiness = self.provider.readiness()
        self.assertTrue(readiness.available, readiness.reason)
        self.assertTrue(readiness.authenticated,
                        "a provider with no account must not make the UI ask for a login")
        self.assertEqual(readiness.missing, ())
        self.assertEqual(readiness.facts["models"], ["qwen-test:1b", "other-test:3b"])
        self.assertEqual(readiness.facts["default_model"], "qwen-test:1b")
        self.assertIs(readiness.facts["requires_network"], False)
        self.assertIs(readiness.facts["requires_credentials"], False)

    def test_a_service_with_no_model_loaded_is_not_ready(self):
        with mock.patch.object(sf_provider_localmodel, "resolve_executable",
                               lambda manifest: bridge_program()), \
                service_running(models=()):
            readiness = self.provider.readiness()
        self.assertFalse(readiness.available)
        self.assertIn("a loaded model", readiness.missing)
        self.assertTrue(readiness.reason.strip())

    def test_no_service_is_reported_with_the_endpoint_named(self):
        with mock.patch.object(sf_provider_localmodel, "resolve_executable",
                               lambda manifest: bridge_program()), \
                tempfile.TemporaryDirectory() as empty, endpoint_at(empty) as endpoint:
            readiness = self.provider.readiness()
        self.assertFalse(readiness.available)
        self.assertIn("local model service", readiness.missing)
        self.assertIn(endpoint, readiness.reason)
        self.assertIn("endpoint_error", readiness.facts)

    def test_a_plain_file_where_the_socket_should_be_is_not_a_service(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / sf_provider_localmodel.ENDPOINT_NAME).write_text("not a socket")
            with endpoint_at(directory):
                readiness = self.provider.readiness()
        self.assertFalse(readiness.available)
        self.assertIn("not a socket", readiness.facts["endpoint_error"])

    def test_a_wedged_service_does_not_hang_mission_control(self):
        """A socket that accepts and never answers is the failure a UI thread
        cannot survive. The probe is bounded, and this measures the bound."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / sf_provider_localmodel.ENDPOINT_NAME
            import socket as _socket
            server = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
            server.bind(str(path))
            server.listen(4)
            try:
                with endpoint_at(directory):
                    started = time.monotonic()
                    readiness = self.provider.readiness()
                    elapsed = time.monotonic() - started
            finally:
                server.close()
        self.assertFalse(readiness.available)
        self.assertLess(elapsed, 10.0, "readiness blocked on a wedged endpoint")
        self.assertIn("local model service", readiness.missing)

    def test_a_service_that_dribbles_bytes_forever_is_still_bounded(self):
        """A per-read timeout cannot see this failure: every recv succeeds, so
        the socket timeout is reset for as long as the service likes. The
        wall-clock bound is what ends it, and this is the test that would go
        red if that bound were removed."""
        with service_running(dribble=True):
            started = time.monotonic()
            readiness = self.provider.readiness()
            elapsed = time.monotonic() - started
        self.assertFalse(readiness.available)
        self.assertLess(elapsed, 20.0,
                        "readiness never returned from a service answering one byte "
                        "at a time")
        self.assertIn("local model service", readiness.missing)

    def test_readiness_never_raises_however_the_endpoint_misbehaves(self):
        for grants in ([], ["relative/path"], ["/a", "/b"]):
            with self.subTest(grants=grants):
                profile = self.provider.manifest["sandbox_profile"]
                before = profile["read_grants"]
                profile["read_grants"] = grants
                try:
                    readiness = self.provider.readiness()
                finally:
                    profile["read_grants"] = before
                self.assertFalse(readiness.available)
                self.assertTrue(readiness.reason.strip())


# --------------------------------------------------------------------------- #
# Acceptance and invocation
# --------------------------------------------------------------------------- #

class InvocationTests(unittest.TestCase):

    def setUp(self):
        self.provider = REGISTRY.get(PROVIDER_ID)
        self.manifest = REGISTRY.manifest(PROVIDER_ID)
        temporary = tempfile.TemporaryDirectory(prefix="sf-localmodel-req-")
        self.addCleanup(temporary.cleanup)
        self.tmp = Path(temporary.name)
        self.prompt = self.tmp / "prompt.md"
        self.prompt.write_text("Summarize the launch\n", encoding="utf-8")

    def build(self, capability=Capability.CODE_CHANGE, **config):
        return self.provider.build_invocation(
            capability, {"prompt_path": str(self.prompt), "config": config})

    def test_the_endpoint_in_the_argv_is_inside_a_declared_read_grant(self):
        """The invariant that makes the transport reviewable: there is no way
        to point the bridge at a socket the sandbox was not granted."""
        invocation = self.build()
        argv = list(invocation.argv)
        endpoint = argv[argv.index("--endpoint") + 1]
        grants = invocation.sandbox.read_grants
        self.assertEqual(len(grants), 1)
        self.assertEqual(str(Path(endpoint).parent), grants[0])
        self.assertIn(grants[0], self.manifest["sandbox_profile"]["read_grants"])

    def test_the_invocation_carries_no_network_and_no_credential(self):
        for capability in (Capability.CODE_CHANGE, Capability.SOURCED_REPORT):
            with self.subTest(capability=capability):
                invocation = self.build(capability)
                self.assertEqual(invocation.sandbox.network, "none")
                self.assertEqual(invocation.sandbox.firebreak_network, "none")
                self.assertEqual(invocation.sandbox.egress_allowlist, ())
                self.assertEqual(invocation.sandbox.credential_ids, ())
                self.assertEqual(invocation.env_allowlist, ())

    def test_a_report_runs_in_a_read_only_workspace(self):
        self.assertEqual(
            self.build(Capability.SOURCED_REPORT).sandbox.workspace_mode, "read-only")
        self.assertEqual(self.build(Capability.CODE_CHANGE).sandbox.workspace_mode,
                         "workspace-write")
        invocation = self.provider.build_invocation(
            Capability.CODE_CHANGE,
            {"prompt_path": str(self.prompt), "read_only": True, "config": {}})
        self.assertEqual(invocation.sandbox.workspace_mode, "read-only")
        self.assertIn("--read-only", invocation.argv)

    def test_a_request_may_lower_a_bound_and_may_never_raise_one(self):
        ceiling = self.manifest["sandbox_profile"]["cpu_seconds"]
        argv = list(self.build(timeout_seconds=30).argv)
        self.assertEqual(argv[argv.index("--deadline") + 1], "30")
        self.assertEqual(argv[argv.index("--idle-timeout") + 1], "30",
                         "the idle bound must never exceed the whole-turn bound")
        raised = list(self.build(timeout_seconds=ceiling * 10).argv)
        self.assertEqual(raised[raised.index("--deadline") + 1], str(ceiling),
                         "a request raised its deadline above the declared cpu ceiling")
        for bad in (0, -1, "60", 1.5, True):
            with self.subTest(value=bad), self.assertRaises(ProviderError):
                self.build(timeout_seconds=bad)

    def test_a_hostile_model_or_session_name_never_reaches_the_argv(self):
        for bad in ("../../etc/passwd", "model; rm -rf /", "-x", "", "a" * 200,
                    "model name", 17, ["list"]):
            with self.subTest(model=bad):
                if bad == "":
                    self.assertNotIn("--model", self.build(model=bad).argv)
                    continue
                with self.assertRaises(ProviderError):
                    self.build(model=bad)
        for bad in ("../escape", "with space", "-flag", "!", "b" * 100):
            with self.subTest(session=bad), self.assertRaises(ProviderError):
                self.build(session=bad)

    def test_a_session_is_refused_for_a_read_only_mission(self):
        answer = self.provider.accepts(Capability.SOURCED_REPORT,
                                       {"network": "none", "session": "chat-1"})
        self.assertFalse(answer.ok)
        self.assertIn("read-only", answer.reason)
        with self.assertRaises(ProviderError):
            self.provider.build_invocation(
                Capability.SOURCED_REPORT,
                {"prompt_path": str(self.prompt), "config": {"session": "chat-1"}})

    def test_a_model_is_accepted_only_when_the_service_actually_has_it(self):
        with service_running(models=("present-test:1b",)):
            self.assertTrue(self.provider.accepts(
                Capability.CODE_CHANGE, {"model": "present-test:1b"}).ok)
            answer = self.provider.accepts(
                Capability.CODE_CHANGE, {"model": "absent-test:9b"})
            self.assertFalse(answer.ok)
            self.assertIn("present-test:1b", answer.reason)

    def test_the_built_invocation_survives_the_orchestrator_verification(self):
        """run_process() verifies every invocation before executing it. A
        provider whose own output is refused there cannot run one mission, and
        every other assertion would still pass."""
        resolved = resolve_executable(self.manifest)
        effective = copy.deepcopy(self.manifest)
        if resolved is None:
            # The packaged bridge is not installed on this host. Verify against
            # the identical file in the source tree instead, and say so: the
            # ONLY field that differs is where the program lives.
            standin = str(SOURCE_BRIDGE)
            effective["executable"] = {"kind": "absolute", "path": standin,
                                       "trust": "user-runtime"}
        else:
            standin = resolved
        for capability in (Capability.CODE_CHANGE, Capability.SOURCED_REPORT):
            with self.subTest(capability=capability):
                invocation = self.build(capability)
                if resolved is None:
                    invocation = Invocation(
                        executable=standin, argv=invocation.argv,
                        stdin_path=invocation.stdin_path,
                        env_allowlist=invocation.env_allowlist,
                        sandbox=invocation.sandbox, label=invocation.label,
                        manifest_executable=effective["executable"])
                verify_invocation(invocation, effective)

    def test_a_substituted_program_is_refused_by_verification(self):
        invocation = self.build()
        substitute = Invocation(
            executable="/usr/bin/true", argv=invocation.argv,
            stdin_path=invocation.stdin_path, sandbox=invocation.sandbox,
            manifest_executable=self.manifest.get("executable"))
        with self.assertRaises(ProviderError) as caught:
            verify_invocation(substitute, self.manifest)
        self.assertIn("not a program this manifest declares", str(caught.exception))

    def test_an_adapter_cannot_widen_what_the_manifest_declared(self):
        sandbox = self.build().sandbox
        for change in ({"network": "allowlist", "egress_allowlist": ("example.com",)},
                       {"credential_ids": ("STOLEN_TOKEN",)},
                       {"read_grants": (*sandbox.read_grants, "/etc")},
                       {"cpu_seconds": sandbox.cpu_seconds + 1},
                       {"memory_mb": sandbox.memory_mb + 1},
                       {"processes": sandbox.processes + 1}):
            with self.subTest(change=sorted(change)), self.assertRaises(ProviderError):
                sandbox.narrow(**change)


# --------------------------------------------------------------------------- #
# Stream normalisation
# --------------------------------------------------------------------------- #

class StreamTests(unittest.TestCase):

    def setUp(self):
        self.provider = REGISTRY.get(PROVIDER_ID)

    def test_the_answer_is_the_sum_of_the_deltas_and_exists_in_no_event(self):
        text = stream("success.ndjson")
        self.assertNotIn("The launch is Friday.", text,
                         "the fixture is not testing what it claims: the whole answer "
                         "appears in a single native event")
        events = self.provider.parse_stream(text)
        self.assertEqual(self.provider.final_message(events), "The launch is Friday.")

    def test_the_terminal_event_says_whether_it_was_native_or_synthesised(self):
        native = [e for e in self.provider.parse_stream(stream("success.ndjson"))
                  if e.type == AgentEvent.TURN_COMPLETE]
        synthetic = [e for e in self.provider.parse_stream(stream("eos-without-terminal.ndjson"))
                     if e.type == AgentEvent.TURN_COMPLETE]
        self.assertEqual(native[0].data["terminal"], "native")
        self.assertEqual(synthetic[0].data["terminal"], "synthesized")
        self.assertIsNone(synthetic[0].data["usage"])

    def test_a_disconnect_keeps_the_text_and_never_completes_the_turn(self):
        events = self.provider.parse_stream(stream("disconnected.ndjson"))
        self.assertEqual(self.provider.final_message(events), "Half an ")
        self.assertFalse(any(e.type == AgentEvent.TURN_COMPLETE for e in events))
        self.assertFalse(self.provider.turn_succeeded(events))
        error = [e for e in events if e.type == AgentEvent.ERROR][-1]
        self.assertEqual(error.data["reason"], "disconnected")

    def test_cancellation_is_a_failure_however_much_text_arrived(self):
        events = self.provider.parse_stream(stream("cancelled.ndjson"))
        self.assertEqual(self.provider.final_message(events), "Partial")
        self.assertFalse(self.provider.turn_succeeded(events))
        self.assertEqual([e for e in events if e.type == AgentEvent.ERROR][0].data["native"],
                         "cancelled")

    def test_the_session_identity_is_recovered_from_the_stream_not_from_the_adapter(self):
        events = self.provider.parse_stream(stream("success.ndjson"))
        self.assertEqual(
            sf_provider_localmodel.LocalModelProvider.session_from_events(events), "cap-1")
        self.assertIsNone(
            sf_provider_localmodel.LocalModelProvider.session_from_events([]))

    def test_a_forged_session_identity_is_dropped_rather_than_carried(self):
        forged = ('{"event":"session.started","session":"../../etc/passwd",'
                  '"model":"a b; rm -rf /"}\n')
        events = self.provider.parse_stream(forged)
        self.assertIsNone(events[0].data["session"])
        self.assertIsNone(events[0].data["model"])
        self.assertIsNone(
            sf_provider_localmodel.LocalModelProvider.session_from_events(events))

    def test_parsing_a_stream_leaves_no_trace_on_the_adapter(self):
        """One adapter instance serves every mission for the worker's life, so
        state stored here is one person's turn leaking into the next."""
        before = dict(vars(self.provider))
        for name in sorted(p.name for p in STREAMS.glob("*.ndjson")):
            self.provider.parse_stream(stream(name))
        self.assertEqual(dict(vars(self.provider)), before)

    def test_an_enormous_delta_is_bounded_before_it_becomes_a_message(self):
        huge = json.dumps({"event": "token", "delta": "x" * 900_000}) + "\n"
        huge += '{"event":"generation.done","stop":"length"}\n'
        events = self.provider.parse_stream(huge)
        message = [e for e in events if e.type == AgentEvent.MESSAGE][0]
        self.assertLessEqual(len(message.text), sf_provider_localmodel.MAX_MESSAGE_CHARS)

    def test_no_stream_can_make_parsing_raise(self):
        battery = [stream(p.name) for p in STREAMS.glob("*.ndjson")]
        battery += [None, "", "\n\n", "{", "null", "[1,2]", '"x"', "\x00\x01",
                    '{"event":123}', '{"event":"token","delta":null}',
                    '{"event":"generation.done","usage":"not-a-dict"}',
                    "x" * 300_000, "\r\n".join(['{"event":"heartbeat"}'] * 500)]
        for index, text in enumerate(battery):
            with self.subTest(index=index):
                events = self.provider.parse_stream(text)
                self.assertIsInstance(events, list)
                self.provider.final_message(events)


# --------------------------------------------------------------------------- #
# The bridge, executed for real against a real service
# --------------------------------------------------------------------------- #

BRIDGE_BASE = ("serve-turn", "--protocol", "localmodel-ndjson-v1", "--stream", "tokens")


def run_bridge(endpoint, workspace, *extra, prompt=b"Summarize the launch\n", timeout=60):
    return subprocess.run(
        [str(SOURCE_BRIDGE), *BRIDGE_BASE, "--endpoint", str(endpoint), *extra],
        input=prompt, capture_output=True, cwd=str(workspace), timeout=timeout)


class BridgeIntegrationTests(unittest.TestCase):
    """The real program, a real socket, a real HTTP conversation.

    These are integration tests of the bridge the manifest declares. They do
    NOT run inside a sandbox; that is test_localmodel_transport.py.
    """

    def setUp(self):
        self.endpoint_dir = tempfile.TemporaryDirectory(prefix="sf-localmodel-ep-")
        self.workspace = tempfile.TemporaryDirectory(prefix="sf-localmodel-ws-")
        self.addCleanup(self.endpoint_dir.cleanup)
        self.addCleanup(self.workspace.cleanup)
        self.provider = REGISTRY.get(PROVIDER_ID)

    def parsed(self, completed):
        return self.provider.parse_stream(completed.stdout.decode("utf-8", "replace"))

    def test_a_turn_streams_deltas_and_the_adapter_reassembles_the_answer(self):
        with FakeModelService(self.endpoint_dir.name,
                              tokens=("Ship ", "on ", "Friday.")) as service:
            done = run_bridge(service.path, self.workspace.name,
                              "--connect-timeout", "5", "--idle-timeout", "10",
                              "--deadline", "30")
        self.assertEqual(done.returncode, 0, done.stdout)
        self.assertEqual(done.stderr, b"", "the bridge must keep stderr empty")
        events = self.parsed(done)
        self.assertTrue(self.provider.turn_succeeded(events))
        self.assertEqual(self.provider.final_message(events), "Ship on Friday.")
        self.assertEqual(service.chat_requests[0]["model"], "test-model:1b")
        self.assertTrue(service.chat_requests[0]["stream"])

    def test_the_bridge_picks_a_loaded_model_and_reports_which(self):
        with FakeModelService(self.endpoint_dir.name,
                              models=("first-test:1b", "second-test:3b")) as service:
            done = run_bridge(service.path, self.workspace.name)
        events = self.parsed(done)
        started = [e for e in events if e.data.get("native") == "session.started"][0]
        self.assertEqual(started.data["model"], "first-test:1b")
        self.assertEqual(service.chat_requests[0]["model"], "first-test:1b")

    def test_a_named_model_is_the_one_asked_for(self):
        with FakeModelService(self.endpoint_dir.name,
                              models=("a-test:1b", "b-test:3b")) as service:
            run_bridge(service.path, self.workspace.name, "--model", "b-test:3b")
        self.assertEqual(service.chat_requests[0]["model"], "b-test:3b")

    def test_a_service_error_is_a_failed_turn_with_a_reason(self):
        with FakeModelService(self.endpoint_dir.name, status=503) as service:
            done = run_bridge(service.path, self.workspace.name)
        self.assertEqual(done.returncode, 1)
        events = self.parsed(done)
        self.assertFalse(self.provider.turn_succeeded(events))
        self.assertIn("503", [e.text for e in events if e.type == AgentEvent.ERROR][0])

    def test_a_missing_endpoint_fails_the_turn_and_says_what_is_missing(self):
        done = run_bridge(Path(self.endpoint_dir.name) / "absent.sock", self.workspace.name)
        self.assertEqual(done.returncode, 1)
        events = self.parsed(done)
        self.assertFalse(self.provider.turn_succeeded(events))
        self.assertIn("no local model endpoint",
                      [e.text for e in events if e.type == AgentEvent.ERROR][0])

    def test_an_idle_service_is_cut_off_at_the_idle_bound(self):
        with FakeModelService(self.endpoint_dir.name, tokens=("Partial", "never"),
                              stall_after=1) as service:
            started = time.monotonic()
            done = run_bridge(service.path, self.workspace.name,
                              "--connect-timeout", "5", "--idle-timeout", "2",
                              "--deadline", "300", timeout=60)
            elapsed = time.monotonic() - started
        self.assertEqual(done.returncode, 1)
        self.assertLess(elapsed, 30.0, "the idle bound did not bound anything")
        events = self.parsed(done)
        self.assertFalse(self.provider.turn_succeeded(events))
        self.assertEqual(self.provider.final_message(events), "Partial",
                         "text that did arrive must survive the timeout")

    def test_a_dribbling_service_is_cut_off_at_the_whole_turn_deadline(self):
        with FakeModelService(self.endpoint_dir.name, tokens=tuple("abcdefghij"),
                              delay=0.3) as service:
            started = time.monotonic()
            done = run_bridge(service.path, self.workspace.name,
                              "--connect-timeout", "5", "--idle-timeout", "30",
                              "--deadline", "1", timeout=60)
            elapsed = time.monotonic() - started
        self.assertEqual(done.returncode, 1)
        self.assertLess(elapsed, 20.0)
        errors = [e for e in self.parsed(done) if e.type == AgentEvent.ERROR]
        self.assertIn("deadline", errors[0].text)

    def test_terminating_the_process_group_ends_the_turn_and_says_it_was_cancelled(self):
        """COVERED: SIGTERM to the bridge's process group produces a terminal
        `cancelled` event, exit 143, and a turn the adapter calls failed --
        within a bounded period.

        NOT COVERED: that pressing cancel in Mission Control reaches this
        signal. That is the orchestrator's property and it is tested there
        (test_missions.py::test_running_process_cancel_kills_child_group).
        """
        with FakeModelService(self.endpoint_dir.name, tokens=("Partial", "never"),
                              stall_after=1) as service:
            child = subprocess.Popen(
                [str(SOURCE_BRIDGE), *BRIDGE_BASE, "--endpoint", service.path,
                 "--connect-timeout", "5", "--idle-timeout", "60", "--deadline", "300"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                cwd=self.workspace.name, start_new_session=True)
            try:
                child.stdin.write(b"hello\n")
                child.stdin.close()
                collected = ""
                while '"token"' not in collected:
                    line = child.stdout.readline()
                    if not line:
                        self.fail("the bridge produced no token to cancel")
                    collected += line.decode()
                started = time.monotonic()
                os.killpg(os.getpgid(child.pid), signal.SIGTERM)
                collected += child.stdout.read().decode()
                code = child.wait(timeout=10)
                elapsed = time.monotonic() - started
            finally:
                if child.poll() is None:  # pragma: no cover
                    child.kill()
                    child.wait(timeout=5)
                child.stdout.close()
        self.assertEqual(code, 143)
        self.assertLess(elapsed, 10.0)
        events = self.provider.parse_stream(collected)
        self.assertFalse(self.provider.turn_succeeded(events))
        self.assertEqual(self.provider.final_message(events), "Partial")
        self.assertEqual([e for e in events if e.type == AgentEvent.ERROR][0].data["native"],
                         "cancelled")

    def test_a_session_continues_the_conversation_and_lives_in_the_workspace(self):
        with FakeModelService(self.endpoint_dir.name, tokens=("noted",)) as service:
            first = run_bridge(service.path, self.workspace.name, "--session", "chat-1",
                               prompt=b"remember the number four\n")
            second = run_bridge(service.path, self.workspace.name, "--session", "chat-1",
                                prompt=b"what number?\n")
        self.assertEqual((first.returncode, second.returncode), (0, 0))
        opening = [e for e in self.parsed(first)
                   if e.data.get("native") == "session.started"][0]
        resumed = [e for e in self.parsed(second)
                   if e.data.get("native") == "session.started"][0]
        self.assertIs(opening.data["resumed"], False)
        self.assertIs(resumed.data["resumed"], True)
        self.assertEqual(resumed.data["session"], "chat-1")
        # The second turn carried the first one's exchange, and the history is
        # in the mission workspace -- not on the host and not in the adapter.
        self.assertEqual([m["content"] for m in service.chat_requests[1]["messages"]],
                         ["remember the number four\n", "noted", "what number?\n"])
        history = Path(self.workspace.name) / ".shadowfetch-localmodel/chat-1.json"
        self.assertTrue(history.is_file())
        self.assertEqual(len(json.loads(history.read_text())["messages"]), 4)

    def test_a_read_only_turn_refuses_a_session_rather_than_losing_it(self):
        with FakeModelService(self.endpoint_dir.name) as service:
            done = run_bridge(service.path, self.workspace.name,
                              "--session", "chat-1", "--read-only")
        self.assertEqual(done.returncode, 1)
        self.assertIn("read-only", self.parsed(done)[0].text)

    def test_the_bridge_refuses_a_protocol_it_does_not_speak(self):
        done = subprocess.run(
            [str(SOURCE_BRIDGE), "serve-turn", "--protocol", "some-other-protocol-v9",
             "--endpoint", "/nonexistent/model.sock", "--stream", "tokens"],
            input=b"hi\n", capture_output=True, timeout=30)
        self.assertEqual(done.returncode, 1)
        events = self.provider.parse_stream(done.stdout.decode())
        self.assertEqual(events[0].data["code"], "protocol")

    def test_an_oversized_line_from_the_service_is_refused_not_swallowed(self):
        """The bridge reads a line from a socket the sandbox does not control.
        Unbounded, that is an out-of-memory the sandbox MemoryMax would have to
        catch; bounded, it is a reported failure."""
        with FakeModelService(self.endpoint_dir.name, oversized=True) as service:
            done = run_bridge(service.path, self.workspace.name, timeout=90)
        self.assertEqual(done.returncode, 1)
        events = self.parsed(done)
        self.assertFalse(self.provider.turn_succeeded(events))
        self.assertIn(
            [e for e in events if e.type == AgentEvent.ERROR][0].data["code"],
            ("oversized-chunk", "malformed-chunk"))

    def test_a_service_speaking_nonsense_fails_the_turn_rather_than_the_parser(self):
        with FakeModelService(self.endpoint_dir.name, malformed=True) as service:
            done = run_bridge(service.path, self.workspace.name)
        self.assertEqual(done.returncode, 1)
        self.assertFalse(self.provider.turn_succeeded(self.parsed(done)))


if __name__ == "__main__":  # pragma: no cover
    unittest.main(verbosity=2)
