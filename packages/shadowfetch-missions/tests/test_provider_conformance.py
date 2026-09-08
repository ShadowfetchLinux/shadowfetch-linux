"""Every provider must pass the same suite (Phase 2 Step 7).

This file supplies the profiles -- what a valid request looks like, which
configurations must be refused, a captured native stream and what it must
normalise to -- and then runs the assertions in provider_conformance.py against
every registered provider. Adding a provider means adding a manifest, an
adapter and a profile; it means editing nothing else, and that claim is itself
asserted here.

Three registries are built, all from fixtures, none from a live system:

  SHIPPED     the manifests and adapters that actually ship
  COMBINED    those plus a deliberately VALID third provider that lives only in
              tests/ -- the architectural proof of the phase
  BROKEN      deliberately broken manifests and contract-violating adapters,
              which the suite must reject

No live cloud credential, no network, no real Codex binary and no real ffmpeg
process is used anywhere in this file.
"""
from __future__ import annotations

import contextlib
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

from provider_conformance import (
    CAPABILITIES, Capability, FIXTURE_ADAPTERS, FIXTURE_BROKEN, FIXTURE_MANIFESTS,
    MISSION_MODULES, PROTECTED_FILES, ProviderCase, ProviderProfile, ProviderRegistry,
    REPO_ROOT, SHIPPED_MANIFESTS, StreamCase, AgentEvent, ProviderError,
    conformance_class, failed_method_names, manifest_root, module_root, path_resolution_hits,
    protected_digests, run_conformance, shipped_adapter_files, shipped_manifest_files,
    stream,
    fixture_registry, policy_root_for)

sys.path.insert(0, str(REPO_ROOT / "tools/providers"))
import validate_manifest  # noqa: E402  the release gate, imported not edited

import sf_providers  # noqa: E402
import sf_provider_codex  # noqa: E402
import sf_provider_offline_media  # noqa: E402

MANIFEST_DIR = validate_manifest.MANIFEST_DIR
POLICY_PATH = validate_manifest.POLICY_PATH
ADAPTER_DIR = validate_manifest.ADAPTER_DIR
SHIPPED_DATA = REPO_ROOT / "packages/shadowfetch-missions/data"

# --------------------------------------------------------------------------- #
# Registries. Fixture manifest roots always link the REAL schema, so a fixture
# that passes was validated by the document that ships.
# --------------------------------------------------------------------------- #
FIXTURE_ADAPTER_FILES = sorted(FIXTURE_ADAPTERS.glob("sf_provider_*.py"))
ECHO_MANIFEST = FIXTURE_MANIFESTS / "conformance-echo.json"

SHIPPED_REGISTRY = fixture_registry(SHIPPED_MANIFESTS, MISSION_MODULES)

COMBINED_MANIFEST_ROOT = manifest_root(*shipped_manifest_files(), ECHO_MANIFEST)
COMBINED_MODULE_ROOT = module_root(*shipped_adapter_files(), *FIXTURE_ADAPTER_FILES)
COMBINED_REGISTRY = fixture_registry(COMBINED_MANIFEST_ROOT, COMBINED_MODULE_ROOT)

FIXTURE_MODULE_ROOT = module_root(*FIXTURE_ADAPTER_FILES)
BROKEN_MANIFEST_ROOT = manifest_root(*sorted(FIXTURE_BROKEN.glob("*.json")))
BROKEN_REGISTRY = fixture_registry(BROKEN_MANIFEST_ROOT, FIXTURE_MODULE_ROOT)

# A registry whose adapter directory contains an orphan module no manifest names.
_ECHO_ONLY_ROOT = manifest_root(ECHO_MANIFEST)
ECHO_ONLY_REGISTRY = fixture_registry(_ECHO_ONLY_ROOT, FIXTURE_MODULE_ROOT)

_SCRATCH = tempfile.TemporaryDirectory(prefix="sf-conformance-bin-")
FAKE_CODEX = Path(_SCRATCH.name) / "codex"
FAKE_CODEX.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
FAKE_FFMPEG = Path(_SCRATCH.name) / "ffmpeg"
FAKE_FFMPEG.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
FAKE_FFPROBE = Path(_SCRATCH.name) / "ffprobe"
FAKE_FFPROBE.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
# readiness asks whether the program is EXECUTABLE, not merely present;
# a non-executable file is not an installed binary.
for _fake in (FAKE_CODEX, FAKE_FFMPEG, FAKE_FFPROBE):
    _fake.chmod(0o755)


# --------------------------------------------------------------------------- #
# Codex profile
# --------------------------------------------------------------------------- #

def _codex_binary(path):
    return mock.patch.object(sf_provider_codex, "resolve_executable", lambda *a, **k: path)


def codex_binary_present():
    return _codex_binary(str(FAKE_CODEX))


def codex_binary_absent():
    return _codex_binary(None)


def codex_auth_present():
    return mock.patch.dict(os.environ, {"CODEX_API_KEY": "fixture-identity-not-a-real-key"})


@contextlib.contextmanager
def codex_auth_absent():
    """No dedicated account, no environment key, no worker credential file."""
    home = tempfile.TemporaryDirectory(prefix="sf-conformance-home-")
    with mock.patch.dict(os.environ, {"HOME": home.name}):
        os.environ.pop("CODEX_API_KEY", None)
        os.environ.pop("OPENAI_API_KEY", None)
        try:
            yield
        finally:
            home.cleanup()


def codex_requests(tmp):
    prompt = tmp / "prompt.md"
    prompt.write_text("Summarize the launch\n", encoding="utf-8")
    base = {"prompt_path": str(prompt), "config": {"network": "allow"}}
    return {
        Capability.CODE_CHANGE: [dict(base), dict(base, read_only=True)],
        Capability.SOURCED_REPORT: [dict(base)],
    }


CODEX_PROFILE = ProviderProfile(
    provider_id="codex",
    build_requests=codex_requests,
    accept_configs={Capability.CODE_CHANGE: {"network": "allow"},
                    Capability.SOURCED_REPORT: {"network": "allow"}},
    refusals=(
        (Capability.CODE_CHANGE, {}, "connection"),
        (Capability.CODE_CHANGE, {"network": "none"}, "connection"),
        (Capability.SOURCED_REPORT, {"network": "allow", "model": "some-model"},
         "model selection is unavailable"),
        (Capability.MEDIA_EXPORT, {"network": "allow"}, "does not perform"),
    ),
    streams=(
        StreamCase(
            name="codex_success.jsonl",
            text=stream("codex_success.jsonl"),
            expect_types=("progress", "progress", "progress", "progress", "message",
                          "turn-complete"),
            expect_final="The launch is Friday and the release contains three workflows.",
            expect_success=True, exit_code=0),
        StreamCase(
            name="codex_failed.jsonl",
            text=stream("codex_failed.jsonl"),
            expect_types=("progress", "progress", "error"),
            expect_final="", expect_success=False, exit_code=1),
        StreamCase(
            name="codex_interleaved.jsonl",
            text=stream("codex_interleaved.jsonl"),
            expect_types=("log", "message", "log", "log", "log", "turn-complete", "log"),
            expect_final="Partial answer.", expect_success=True, exit_code=0),
    ),
    binary_absent=codex_binary_absent,
    binary_present=codex_binary_present,
    auth_absent=codex_auth_absent,
    auth_present=codex_auth_present,
    invocation_context=codex_binary_present,
)


# --------------------------------------------------------------------------- #
# Offline media profile
# --------------------------------------------------------------------------- #

@contextlib.contextmanager
def _media_patch(ffmpeg, ffprobe):
    with mock.patch.object(sf_provider_offline_media, "FFMPEG", ffmpeg), \
            mock.patch.object(sf_provider_offline_media, "FFPROBE", ffprobe):
        yield


def media_binary_present():
    return _media_patch(str(FAKE_FFMPEG), str(FAKE_FFPROBE))


def media_binary_absent():
    return _media_patch("/nonexistent/bin/ffmpeg", "/nonexistent/bin/ffprobe")


def media_requests(tmp):
    source = tmp / "clip.mp4"
    source.write_bytes(b"\x00\x00\x00\x18ftypmp42")
    target = tmp / "export.mp4"
    return {Capability.MEDIA_EXPORT: [
        {"stage": "probe", "source": str(source), "report_path": str(tmp / "probe.json")},
        {"stage": "encode", "source": str(source), "target": str(target), "video": True},
        {"stage": "encode", "source": str(source), "target": str(tmp / "export.wav")},
        {"stage": "verify", "source": str(target)},
    ]}


MEDIA_PROFILE = ProviderProfile(
    provider_id="offline-media",
    build_requests=media_requests,
    accept_configs={Capability.MEDIA_EXPORT: {"network": "none", "inputs": ["clip.mp4"]}},
    refusals=(
        (Capability.MEDIA_EXPORT, {"network": "allow", "inputs": ["clip.mp4"]}, "offline"),
        (Capability.MEDIA_EXPORT, {"network": "none"}, "at least one media file"),
        (Capability.CODE_CHANGE, {"network": "none", "inputs": ["a"]}, "does not perform"),
        (Capability.SOURCED_REPORT, {"network": "none", "inputs": ["a"]}, "does not perform"),
    ),
    streams=(
        StreamCase(
            name="ffmpeg_export.log",
            text=stream("ffmpeg_export.log"),
            expect_types=("progress", "progress", "turn-complete"),
            expect_final="", expect_success=True, exit_code=0),
        StreamCase(
            name="ffmpeg_error.log",
            text=stream("ffmpeg_error.log"),
            expect_types=("log", "log", "turn-complete"),
            expect_final="", expect_success=False, exit_code=1),
    ),
    binary_absent=media_binary_absent,
    binary_present=media_binary_present,
    notes=("ffmpeg carries failure in its exit status, not in its stream: the adapter always "
           "appends turn-complete and never emits an error event. The failure fixture is "
           "therefore distinguished by exit_code, which is what the executor has."),
)


# --------------------------------------------------------------------------- #
# The third provider's profile -- and the profile the broken variants reuse
# --------------------------------------------------------------------------- #

def echo_requests(tmp):
    prompt = tmp / "report-prompt.md"
    prompt.write_text("Summarize the approved sources\n", encoding="utf-8")
    return {Capability.SOURCED_REPORT: [
        {"prompt_path": str(prompt),
         "config": {"network": "allow", "inputs": ["facts.md"]}},
        {"prompt_path": str(prompt), "label": "second",
         "config": {"network": "allow", "inputs": ["b.md", "a.md"]}},
    ]}


def _echo_program(path):
    import sf_provider_conformance_echo
    return mock.patch.object(sf_provider_conformance_echo, "PROGRAM", path)


def echo_binary_present():
    return _echo_program("/usr/bin/true" if Path("/usr/bin/true").is_file()
                         else str(FAKE_CODEX))


def echo_binary_absent():
    return _echo_program("/nonexistent/bin/conformance-echo")


def echo_auth_present():
    return mock.patch.dict(os.environ, {"CONFORMANCE_ECHO_TOKEN": "fixture-identity"})


@contextlib.contextmanager
def echo_auth_absent():
    with mock.patch.dict(os.environ, {}):
        os.environ.pop("CONFORMANCE_ECHO_TOKEN", None)
        yield


def echo_profile(provider_id="conformance-echo"):
    return ProviderProfile(
        provider_id=provider_id,
        build_requests=echo_requests,
        accept_configs={Capability.SOURCED_REPORT:
                        {"network": "allow", "inputs": ["facts.md"]}},
        refusals=(
            (Capability.SOURCED_REPORT, {"inputs": ["facts.md"]}, "approved for this mission"),
            (Capability.SOURCED_REPORT, {"network": "allow"}, "at least one approved source"),
            (Capability.CODE_CHANGE, {"network": "allow", "inputs": ["a"]}, "does not perform"),
            (Capability.MEDIA_EXPORT, {"network": "allow", "inputs": ["a"]}, "does not perform"),
        ),
        streams=(
            StreamCase(
                name="echo_report.txt",
                text=stream("echo_report.txt"),
                expect_types=("log", "progress", "progress", "usage", "message",
                              "turn-complete"),
                expect_final="The launch is Friday and the release contains three workflows.",
                expect_success=True, exit_code=0),
            StreamCase(
                name="echo_failed.txt",
                text=stream("echo_failed.txt"),
                expect_types=("log", "progress", "error", "error", "turn-complete"),
                expect_final="", expect_success=False, exit_code=1),
            StreamCase(
                name="echo_interleaved.txt",
                text=stream("echo_interleaved.txt"),
                expect_types=("log", "log", "progress", "message", "turn-complete", "log"),
                expect_final="Partial answer.", expect_success=True, exit_code=0),
        ),
        binary_absent=echo_binary_absent,
        binary_present=echo_binary_present,
        auth_absent=echo_auth_absent,
        auth_present=echo_auth_present,
    )


ECHO_PROFILE = echo_profile()

PROFILES = {"codex": CODEX_PROFILE, "offline-media": MEDIA_PROFILE,
            "conformance-echo": ECHO_PROFILE}


# --------------------------------------------------------------------------- #
# One generated TestCase per provider under test
# --------------------------------------------------------------------------- #

CASES = [
    ProviderCase(SHIPPED_REGISTRY, "codex", CODEX_PROFILE, "codex"),
    ProviderCase(SHIPPED_REGISTRY, "offline-media", MEDIA_PROFILE, "offline_media"),
    # The third provider runs the identical assertions, inside a registry that
    # also holds both shipped providers.
    ProviderCase(COMBINED_REGISTRY, "conformance-echo", ECHO_PROFILE, "conformance_echo"),
]

for _case in CASES:
    _klass = conformance_class(_case, module=__name__)
    globals()[_klass.__name__] = _klass
del _case, _klass


# --------------------------------------------------------------------------- #
# Registry-level behaviour
# --------------------------------------------------------------------------- #

class RegistryTests(unittest.TestCase):
    """Discovery, filtering, and the refusal to register anything unnamed."""

    def test_every_shipped_provider_loads_without_error(self):
        self.assertEqual(SHIPPED_REGISTRY.errors, [])
        self.assertEqual(SHIPPED_REGISTRY.ids(), ["codex", "offline-media"])

    def test_every_registered_provider_has_a_conformance_profile(self):
        """Adding a provider without a profile is a loud failure, not a silent gap."""
        registered = set(COMBINED_REGISTRY.ids())
        self.assertEqual(registered - set(PROFILES), set(),
                         "a registered provider has no conformance profile; add one to "
                         "PROFILES/CASES in this file so it is actually tested")

    def test_for_capability_returns_exactly_the_providers_that_declare_it(self):
        expected = {
            Capability.CODE_CHANGE: {"codex"},
            Capability.SOURCED_REPORT: {"codex", "conformance-echo"},
            Capability.MEDIA_EXPORT: {"offline-media"},
        }
        for capability in CAPABILITIES:
            with self.subTest(capability=capability):
                got = {p.id for p in COMBINED_REGISTRY.for_capability(capability)}
                self.assertEqual(got, expected[capability])
                for provider in COMBINED_REGISTRY.for_capability(capability):
                    self.assertIn(capability, COMBINED_REGISTRY.manifest(provider.id)["capabilities"])
        for capability in CAPABILITIES:
            declaring = {pid for pid in COMBINED_REGISTRY.ids()
                         if capability in COMBINED_REGISTRY.manifest(pid)["capabilities"]}
            self.assertEqual({p.id for p in COMBINED_REGISTRY.for_capability(capability)}, declaring)

    def test_an_unknown_capability_matches_nothing(self):
        self.assertEqual(COMBINED_REGISTRY.for_capability("world_domination"), [])
        self.assertIsNone(COMBINED_REGISTRY.default_for("world_domination"))

    def test_an_unknown_provider_id_is_a_readable_refusal(self):
        with self.assertRaises(ProviderError) as caught:
            COMBINED_REGISTRY.get("no-such-provider")
        self.assertIn("Installed providers", str(caught.exception))

    def test_describe_reports_every_provider_from_its_manifest(self):
        described = COMBINED_REGISTRY.describe()
        self.assertEqual(sorted(described), sorted(COMBINED_REGISTRY.ids()))
        for pid, entry in described.items():
            manifest = COMBINED_REGISTRY.manifest(pid)
            self.assertEqual(entry["capabilities"], list(manifest["capabilities"]))
            self.assertEqual(entry["network_policy"], manifest["network_policy"])
            self.assertEqual(entry["credential_ids"], list(manifest.get("credential_ids") or []))
            self.assertEqual(entry["requires_network_approval"],
                             manifest["network_policy"] != "none")
            self.assertIn("available", entry)

    def test_a_module_dropped_in_the_adapter_directory_is_not_a_provider(self):
        """Arbitrary provider registration is impossible.

        sf_provider_conformance_orphan.py is a complete, valid-looking adapter
        sitting in the same directory as the ones that do load. No manifest
        names it, so the registry never sees it.
        """
        self.assertTrue((FIXTURE_ADAPTERS / "sf_provider_conformance_orphan.py").is_file())
        self.assertIn("sf_provider_conformance_orphan.py",
                      {p.name for p in Path(ECHO_ONLY_REGISTRY.module_root).iterdir()})
        self.assertEqual(ECHO_ONLY_REGISTRY.ids(), ["conformance-echo"])
        self.assertEqual(ECHO_ONLY_REGISTRY.errors, [])
        for provider in ECHO_ONLY_REGISTRY.list():
            self.assertNotIn("orphan", type(provider).__module__)
        with self.assertRaises(ProviderError):
            ECHO_ONLY_REGISTRY.get("conformance-orphan")

    def test_a_missing_manifest_directory_fails_closed(self):
        # A real policy, so this fails for the missing DIRECTORY rather than
        # for the missing approval -- the test is about the former.
        registry = ProviderRegistry(root=Path("/nonexistent/providers"),
                                    module_root=MISSION_MODULES,
                                    policy_root=policy_root_for(SHIPPED_MANIFESTS))
        self.assertEqual(registry.ids(), [])
        self.assertEqual(registry.list(), [])
        self.assertTrue(registry.errors)


# --------------------------------------------------------------------------- #
# Security properties that are not per-provider
# --------------------------------------------------------------------------- #

class SecurityTests(unittest.TestCase):

    def test_invocation_refuses_a_relative_executable(self):
        for bad in ("codex", "./codex", "bin/codex", "", None):
            with self.subTest(executable=bad), self.assertRaises(ProviderError):
                sf_providers.Invocation(executable=bad)

    def test_invocation_refuses_a_credential_value_in_the_environment_allowlist(self):
        Invocation = sf_providers.Invocation
        for bad in ("sk-live-9f2b", "CODEX_API_KEY=secret", "codex_api_key", "1TOKEN"):
            with self.subTest(entry=bad), self.assertRaises(ProviderError):
                Invocation(executable="/usr/bin/true", env_allowlist=(bad,))
        # A declared identity is fine.
        self.assertEqual(
            Invocation(executable="/usr/bin/true", env_allowlist=("CODEX_API_KEY",)).env_allowlist,
            ("CODEX_API_KEY",))

    def test_a_sandbox_with_no_network_cannot_carry_an_egress_allowlist(self):
        SandboxSpec = sf_providers.SandboxSpec
        with self.assertRaises(ProviderError):
            SandboxSpec(workspace_mode="workspace-write", network="none",
                        egress_allowlist=("exfil.example.com",))
        with self.assertRaises(ProviderError):
            SandboxSpec(workspace_mode="workspace-write", network="wide-open")
        with self.assertRaises(ProviderError):
            SandboxSpec(workspace_mode="anything-goes", network="none")
        with self.assertRaises(ProviderError):
            SandboxSpec(workspace_mode="read-only", network="none", read_grants=("relative",))

    def test_no_shipped_adapter_resolves_its_program_through_path(self):
        offenders = {}
        for adapter in shipped_adapter_files():
            hits = path_resolution_hits(adapter)
            if hits:
                offenders[adapter.name] = hits
        self.assertEqual(offenders, {},
                         "a shipped provider adapter picks its executable out of the environment")

    def test_no_shipped_executable_resolver_reaches_path_through_a_helper(self):
        """The promise in sf_providers is "no code path", not "no adapter line".

        A manifest whose executable.kind is "resolver" names a function in the
        adapter. If that function delegates the lookup to a shipped sibling
        module, the sibling is part of the resolution chain and inherits the
        promise. This test follows that one hop.
        """
        from provider_conformance import sibling_modules_imported
        offenders = []
        for manifest_path in shipped_manifest_files():
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            executable = manifest.get("executable") or {"kind": "none"}
            if executable.get("kind") != "resolver":
                continue
            adapter = MISSION_MODULES / f"{manifest['adapter_module']}.py"
            for sibling in sibling_modules_imported(adapter):
                for line, what in path_resolution_hits(sibling):
                    offenders.append(f"{manifest['id']} -> {sibling.name}:{line}: {what}")
        self.assertEqual(offenders, [], "; ".join(offenders))


# --------------------------------------------------------------------------- #
# Cancellation
# --------------------------------------------------------------------------- #

class CancellationContractTests(unittest.TestCase):
    """What is and is not proven about cancellation from here.

    COVERED
      * Every invocation any provider can build carries finite cpu, memory and
        process bounds no larger than its manifest declared (asserted per
        provider in the conformance class, and across the registry here).
      * Terminating a provider's process GROUP does end it within a bounded
        period: a real child in its own session is signalled and reaped here.
      * The orchestrator still owns a generic kill path -- asserted at source
        level, because importing the executor is out of scope for this suite.

    NOT COVERED
      * That pressing cancel in Mission Control reaches that kill path. That is
        an orchestrator test and it exists:
        test_missions.py::MissionTests::test_running_process_cancel_kills_child_group
        starts a real process and cancels it.
      * ffmpeg's own runtime bound. cpu_seconds is a sandbox ceiling, not a
        watchdog inside the provider.
    """

    def test_every_provider_declares_finite_bounds(self):
        for pid in COMBINED_REGISTRY.ids():
            manifest = COMBINED_REGISTRY.manifest(pid)
            profile = manifest["sandbox_profile"]
            with self.subTest(provider=pid):
                self.assertGreater(profile["cpu_seconds"], 0)
                self.assertLessEqual(profile["cpu_seconds"], 7200)
                self.assertGreater(profile["processes"], 0)
                self.assertLessEqual(profile["processes"], 512)
                self.assertGreater(profile["memory_mb"], 0)
                self.assertLessEqual(profile["memory_mb"], 32768)

    def test_terminating_a_process_group_ends_it_within_a_bounded_period(self):
        script = "import time, sys\nsys.stdout.write('up\\n'); sys.stdout.flush()\ntime.sleep(120)\n"
        child = subprocess.Popen([sys.executable, "-c", script],
                                 stdout=subprocess.PIPE, start_new_session=True)
        try:
            self.assertEqual(child.stdout.readline(), b"up\n")
            started = time.monotonic()
            os.killpg(os.getpgid(child.pid), signal.SIGTERM)
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(os.getpgid(child.pid), signal.SIGKILL)
                child.wait(timeout=5)
            elapsed = time.monotonic() - started
        finally:
            if child.poll() is None:  # pragma: no cover
                child.kill()
                child.wait(timeout=5)
            child.stdout.close()
        self.assertIsNotNone(child.poll())
        self.assertLess(elapsed, 10.0, "a provider process outlived its cancellation bound")

    def test_the_orchestrator_retains_a_generic_kill_path(self):
        """Source-level presence check, deliberately.

        This asserts only that sf_missions.py still contains a cancellation
        request path and a process-group termination call. It does not execute
        either, and it is not a substitute for the orchestrator's own real
        cancellation test.
        """
        source_path = MISSION_MODULES / "sf_missions.py"
        if not source_path.is_file():  # pragma: no cover
            self.skipTest("sf_missions.py is not present in this tree")
        source = source_path.read_text(encoding="utf-8")
        self.assertIn("cancel_requested", source)
        self.assertTrue(any(token in source for token in ("killpg", "SIGKILL", "terminate(")),
                        "no process termination call remains in the orchestrator")


# --------------------------------------------------------------------------- #
# The broken fixtures must be rejected
# --------------------------------------------------------------------------- #

# Manifests so malformed the registry never creates an entry for them.
LOAD_REJECTED = {
    "broken-not-json": "is not valid JSON",
    "broken-missing-field": "network_policy",
    "broken-unknown-capability": "capabilities",
    "broken-network-lie": "egress_allowlist",
    "broken-empty-allowlist": "egress_allowlist",
    "broken-credential-value": "credential_ids",
    "broken-id-mismatch": "filename must match its id",
    "broken-adapter-traversal": "adapter_module",
    "broken-extra-key": "allow_everything",
    "broken-unbounded-cpu": "cpu_seconds",
}

# Manifests that parse but whose provider must never become usable.
LOADED_BUT_UNUSABLE = {
    "broken-interface-version": "interface v99",
    "broken-missing-adapter": "is not installed",
    "broken-not-provider": "is not an AgentProvider",
}

# Valid manifests whose ADAPTER violates the contract. The conformance suite is
# the only thing that can catch these, and it must.
CONTRACT_VIOLATORS = {
    "conformance-widen": {
        "test_the_sandbox_it_carries_never_exceeds_the_manifest",
        "test_no_provider_obtains_an_implicit_network_grant",
        "test_credential_identities_are_a_subset_of_the_manifest",
        "test_environment_allowlist_holds_no_undeclared_name_and_no_value",
    },
    "conformance-relative": {"test_every_invocation_uses_an_absolute_executable"},
    "conformance-secret": {"test_environment_allowlist_holds_no_undeclared_name_and_no_value"},
    "conformance-which": {"test_the_adapter_does_not_resolve_its_program_through_path"},
    "conformance-crash": {
        "test_readiness_reports_a_missing_binary_with_a_reason",
        "test_readiness_reports_an_available_binary",
        "test_a_captured_native_stream_normalises_to_the_expected_events",
        "test_malformed_partial_and_interleaved_output_is_tolerated",
    },
    "conformance-undeclared": {
        "test_rejects_a_capability_it_does_not_declare_with_a_reason",
        "test_accepts_a_valid_request_and_refuses_the_documented_ones",
    },
}


class BrokenProviderRejectionTests(unittest.TestCase):

    def test_malformed_manifests_never_become_providers(self):
        errors = " || ".join(BROKEN_REGISTRY.errors)
        for stem, expected in LOAD_REJECTED.items():
            with self.subTest(manifest=stem):
                self.assertNotIn(stem, BROKEN_REGISTRY.ids(),
                                 f"{stem}.json was accepted as a provider")
                self.assertIn(f"{stem}.json", errors)
                self.assertIn(expected, errors)

    def test_unusable_providers_are_reported_with_a_reason_and_never_returned(self):
        for pid, expected in LOADED_BUT_UNUSABLE.items():
            with self.subTest(provider=pid):
                self.assertIn(pid, BROKEN_REGISTRY.ids())
                self.assertNotIn(pid, [p.id for p in BROKEN_REGISTRY.list()])
                with self.assertRaises(ProviderError) as caught:
                    BROKEN_REGISTRY.get(pid)
                self.assertIn(expected, str(caught.exception))
                readiness = BROKEN_REGISTRY.readiness(pid)
                self.assertFalse(readiness.available)
                self.assertIn(expected, readiness.reason)
                for capability in CAPABILITIES:
                    self.assertNotIn(pid, [p.id for p in
                                           BROKEN_REGISTRY.for_capability(capability)])

    def test_a_broken_registry_still_serves_the_providers_that_are_fine(self):
        """One bad manifest must not take the others down."""
        self.assertTrue(BROKEN_REGISTRY.errors)
        usable = {p.id for p in BROKEN_REGISTRY.list()}
        self.assertIn("conformance-widen", usable)
        self.assertIn("conformance-crash", usable)

    def test_contract_violating_adapters_fail_the_conformance_suite(self):
        for pid, expected_failures in CONTRACT_VIOLATORS.items():
            with self.subTest(provider=pid):
                case = ProviderCase(BROKEN_REGISTRY, pid, echo_profile(pid), f"broken_{pid}")
                result, output = run_conformance(case)
                self.assertFalse(result.wasSuccessful(),
                                 f"{pid} passed conformance but must not:\n{output}")
                broke = failed_method_names(result)
                self.assertLessEqual(expected_failures, broke,
                                     f"{pid} did not fail where it should:\n{output}")

    def test_the_valid_third_provider_passes_the_same_suite(self):
        """The control for the test above: the suite is not simply always red."""
        case = ProviderCase(COMBINED_REGISTRY, "conformance-echo", ECHO_PROFILE, "control")
        result, output = run_conformance(case)
        self.assertTrue(result.wasSuccessful(), output)
        self.assertGreater(result.testsRun, 15)


# --------------------------------------------------------------------------- #
# The release gate agrees with the runtime
# --------------------------------------------------------------------------- #

def shipped_inventory():
    return sorted(str(p.relative_to(SHIPPED_DATA)) for p in SHIPPED_DATA.rglob("*")
                  if p.is_file())


class ReleaseGateTests(unittest.TestCase):
    """The gate validates DATA. A valid new provider needs no edit to it."""

    def setUp(self):
        self.inventory = shipped_inventory()
        self.mission_source = (MISSION_MODULES / "sf_missions.py").read_text(encoding="utf-8")

    def test_the_shipped_payload_passes_the_gate(self):
        result = validate_manifest.validate_provider_payload(self.inventory, self.mission_source)
        self.assertTrue(result["checked"])
        self.assertEqual(result["providers"], ["codex", "offline-media"])

    def test_a_valid_third_provider_passes_the_gate_with_no_gate_edit(self):
        gate_before = (REPO_ROOT / "tools/providers/validate_manifest.py").read_bytes()
        manifest_rel = f"{MANIFEST_DIR}/conformance-echo.json"
        adapter_rel = f"{ADAPTER_DIR}/sf_provider_conformance_echo.py"
        manifest_text = ECHO_MANIFEST.read_text(encoding="utf-8")
        echo = json.loads(manifest_text)
        # Three pieces of DATA: a manifest, an adapter, and an approval entry.
        # The approval is the Phase 2.5 addition -- a provider nobody approved
        # is not a provider -- and it is still data. No gate source changes.
        approved = json.loads((SHIPPED_DATA / POLICY_PATH).read_text(encoding="utf-8"))
        approved["providers"][echo["id"]] = {
            "package": echo["package"],
            "interface_version": echo["interface_version"],
            "capabilities": echo["capabilities"],
            "credential_ids": echo["credential_ids"],
            "network_policy": echo["network_policy"],
            "egress_allowlist": echo["egress_allowlist"],
            "manifest_sha256":
                hashlib.sha256(manifest_text.encode("utf-8")).hexdigest(),
            "trust": "developer",
        }
        extra = {
            POLICY_PATH: json.dumps(approved, indent=2),
            manifest_rel: manifest_text,
            adapter_rel: (FIXTURE_ADAPTERS / "sf_provider_conformance_echo.py")
                         .read_text(encoding="utf-8"),
        }

        def read(relative):
            if relative in extra:
                return extra[relative]
            path = SHIPPED_DATA / relative
            return path.read_text(encoding="utf-8") if path.is_file() else None

        result = validate_manifest.validate_provider_payload(
            [*self.inventory, manifest_rel, adapter_rel], self.mission_source, read=read)
        self.assertEqual(result["providers"],
                         ["codex", "conformance-echo", "offline-media"])
        self.assertEqual((REPO_ROOT / "tools/providers/validate_manifest.py").read_bytes(),
                         gate_before)

    def test_every_broken_manifest_is_refused_by_the_gate(self):
        for path in sorted(FIXTURE_BROKEN.glob("broken-*.json")):
            manifest_rel = f"{MANIFEST_DIR}/{path.name}"
            adapter_rel = f"{ADAPTER_DIR}/sf_provider_conformance_echo.py"
            extra = {manifest_rel: path.read_text(encoding="utf-8"),
                     adapter_rel: (FIXTURE_ADAPTERS / "sf_provider_conformance_echo.py")
                                  .read_text(encoding="utf-8")}

            def read(relative, extra=extra):
                if relative in extra:
                    return extra[relative]
                candidate = SHIPPED_DATA / relative
                return candidate.read_text(encoding="utf-8") if candidate.is_file() else None

            with self.subTest(manifest=path.name):
                with self.assertRaises(validate_manifest.ProviderPolicyError):
                    validate_manifest.validate_provider_payload(
                        [*self.inventory, manifest_rel, adapter_rel],
                        self.mission_source, read=read)

    def test_adapter_code_with_no_manifest_is_refused_by_the_gate(self):
        orphan_rel = f"{ADAPTER_DIR}/sf_provider_conformance_orphan.py"

        def read(relative):
            if relative == orphan_rel:
                return (FIXTURE_ADAPTERS / "sf_provider_conformance_orphan.py").read_text(
                    encoding="utf-8")
            path = SHIPPED_DATA / relative
            return path.read_text(encoding="utf-8") if path.is_file() else None

        with self.assertRaises(validate_manifest.ProviderPolicyError) as caught:
            validate_manifest.validate_provider_payload(
                [*self.inventory, orphan_rel], self.mission_source, read=read)
        self.assertIn("no validated manifest names", str(caught.exception))


# --------------------------------------------------------------------------- #
# The architectural claim of Phase 2
# --------------------------------------------------------------------------- #

class ThirdProviderProofTests(unittest.TestCase):
    """A new provider is reachable from its manifest and nothing else."""

    def test_the_third_provider_is_discovered_without_touching_protected_files(self):
        before = protected_digests()
        registry = fixture_registry(COMBINED_MANIFEST_ROOT, COMBINED_MODULE_ROOT)
        self.assertEqual(registry.errors, [])
        self.assertIn("conformance-echo", registry.ids())
        provider = registry.get("conformance-echo")
        self.assertEqual(provider.display_name, "Conformance echo (test fixture)")
        self.assertIn(provider, registry.for_capability(Capability.SOURCED_REPORT))

        case = ProviderCase(registry, "conformance-echo", ECHO_PROFILE, "proof")
        result, output = run_conformance(case)
        self.assertTrue(result.wasSuccessful(), output)

        after = protected_digests()
        self.assertEqual(before, after,
                         "a protected file changed while the third provider was exercised")
        self.assertEqual(sorted(before), sorted(PROTECTED_FILES))

    def test_no_protected_file_mentions_the_third_provider(self):
        for relative in PROTECTED_FILES:
            text = (REPO_ROOT / relative).read_text(encoding="utf-8")
            with self.subTest(file=relative):
                for token in ("conformance-echo", "conformance_echo", "ConformanceEcho"):
                    self.assertNotIn(token, text)

    def test_the_third_provider_does_not_ship(self):
        self.assertFalse((SHIPPED_MANIFESTS / "conformance-echo.json").exists())
        self.assertEqual(
            [p.name for p in SHIPPED_MANIFESTS.glob("*.json")
             if "conformance" in p.name], [])
        self.assertFalse((MISSION_MODULES / "sf_provider_conformance_echo.py").exists())
        self.assertEqual(
            [p.name for p in MISSION_MODULES.glob("sf_provider_conformance*.py")], [])

    def test_the_third_provider_is_discovered_purely_from_its_manifest(self):
        """Remove the manifest and the adapter is just a file again."""
        _root = manifest_root(*shipped_manifest_files())
        without = fixture_registry(_root, COMBINED_MODULE_ROOT)
        self.assertEqual(without.ids(), ["codex", "offline-media"])
        self.assertIn("sf_provider_conformance_echo.py",
                      {p.name for p in Path(COMBINED_MODULE_ROOT).iterdir()})
        with self.assertRaises(ProviderError):
            without.get("conformance-echo")


if __name__ == "__main__":  # pragma: no cover
    unittest.main(verbosity=2)
