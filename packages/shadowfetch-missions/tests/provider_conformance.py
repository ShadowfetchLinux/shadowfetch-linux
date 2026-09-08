"""The provider conformance suite: one set of assertions every provider must pass.

Phase 2 Step 7. This module is deliberately NOT named test*.py -- unittest
discovery must not run it directly, because the assertions here are
parameterised by a provider and mean nothing without one. test_provider_
conformance.py imports this, builds one concrete TestCase subclass per
registered provider, and puts those in its own namespace so discovery finds
them with useful names.

The point of the shape
----------------------
Adding the next provider should be boring. You write a manifest, you write an
adapter, you write a ProviderProfile that says what a valid request looks like
and hands over a captured native stream, and this suite tells you what is
wrong. Nothing in here knows the word "codex" or the word "ffmpeg"; every
assertion is derived from the provider's own manifest.

Fixture transports only
-----------------------
No live cloud credential, no network, no real Codex binary, no real ffmpeg run.
Where a provider's output is needed it comes from a captured/synthetic native
stream under tests/fixtures/providers/streams. Where a provider's environment
is needed (binary present/absent, auth present/absent) the profile supplies a
context manager that patches that provider's own seam.

What "reject" means here
------------------------
A provider fails conformance in one of three places and all three are covered:
  * the registry refuses to load it at all (bad manifest, missing adapter,
    wrong interface version, class that is not an AgentProvider);
  * the value types refuse what it built (relative executable, credential
    value in the environment allowlist, a narrow() that widens);
  * these assertions catch a behaviour the types cannot see (a sandbox that
    does not match the manifest, an undeclared capability accepted, a stream
    that raises).
"""
from __future__ import annotations

import ast
import atexit
import contextlib
import dataclasses
import hashlib
import io
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
PACKAGE_DIR = TESTS_DIR.parent                      # packages/shadowfetch-missions
REPO_ROOT = PACKAGE_DIR.parent.parent               # repository root
MISSION_MODULES = PACKAGE_DIR / "data/usr/lib/shadowfetch/missions"
SHIPPED_MANIFESTS = PACKAGE_DIR / "data/usr/share/shadowfetch/providers"
FIXTURES = TESTS_DIR / "fixtures/providers"
FIXTURE_ADAPTERS = FIXTURES / "adapters"
FIXTURE_MANIFESTS = FIXTURES / "manifests"
FIXTURE_BROKEN = FIXTURES / "broken"
FIXTURE_STREAMS = FIXTURES / "streams"

if str(MISSION_MODULES) not in sys.path:
    sys.path.insert(0, str(MISSION_MODULES))

import sf_providers  # noqa: E402
from sf_providers import (  # noqa: E402
    Acceptance, AgentEvent, AgentProvider, CAPABILITIES, Capability, Invocation,
    ProviderError, ProviderRegistry, Readiness, SandboxSpec, sandbox_from_manifest,
)

SCHEMA_NAME = "provider-manifest.schema.json"

# The files whose immutability is the architectural claim of this phase: a new
# provider must be reachable without touching the orchestrator, the CLI entry
# point, the desktop UI, or the release gate.
PROTECTED_FILES = (
    "packages/shadowfetch-missions/data/usr/lib/shadowfetch/missions/sf_missions.py",
    "packages/shadowfetch-missions/data/usr/bin/shadowfetch-missions",
    "packages/shadowfetch-control-center/data/usr/share/shadowfetch/control-center/sfcc/missions_page.py",
    "tools/providers/validate_manifest.py",
)


def protected_digests() -> dict:
    """sha256 of each protected file, right now."""
    out = {}
    for relative in PROTECTED_FILES:
        path = REPO_ROOT / relative
        out[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    return out


# --------------------------------------------------------------------------- #
# Temporary provider roots
# --------------------------------------------------------------------------- #

def _tempdir(prefix: str) -> Path:
    path = Path(tempfile.mkdtemp(prefix=prefix))
    atexit.register(shutil.rmtree, path, True)
    return path


def _link(source: Path, destination: Path) -> None:
    try:
        destination.symlink_to(source)
    except OSError:
        shutil.copy2(source, destination)


def manifest_root(*manifests: Path) -> Path:
    """A manifest directory holding the given manifests and the REAL schema.

    The schema is linked rather than copied so a fixture provider is validated
    by exactly the document that ships; a fixture that only passes a stale copy
    of the schema would prove nothing.
    """
    root = _tempdir("sf-conformance-manifests-")
    _link(SHIPPED_MANIFESTS / SCHEMA_NAME, root / SCHEMA_NAME)
    for manifest in manifests:
        _link(Path(manifest), root / Path(manifest).name)
    return root


def module_root(*modules: Path) -> Path:
    """An adapter module directory holding links to the given modules."""
    root = _tempdir("sf-conformance-modules-")
    for module in modules:
        _link(Path(module), root / Path(module).name)
    return root


def shipped_manifest_files() -> list:
    return sorted(p for p in SHIPPED_MANIFESTS.glob("*.json") if p.name != SCHEMA_NAME)


def shipped_adapter_files() -> list:
    return sorted(MISSION_MODULES.glob("sf_provider_*.py"))


def stream(name: str) -> str:
    return (FIXTURE_STREAMS / name).read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
# What a provider must tell the suite about itself
# --------------------------------------------------------------------------- #

@dataclasses.dataclass(frozen=True)
class StreamCase:
    """One captured/synthetic native stream and what it must normalise to."""

    name: str
    text: str
    expect_types: tuple
    expect_final: str = ""
    expect_success: bool = True
    exit_code: int = 0


def default_turn_succeeded(events, exit_code) -> bool:
    """The generic rule: a turn ended, nothing errored, the process agreed."""
    complete = any(e.type == AgentEvent.TURN_COMPLETE for e in events)
    failed = any(e.type == AgentEvent.ERROR for e in events)
    return complete and not failed and exit_code == 0


@dataclasses.dataclass
class ProviderProfile:
    """Everything the suite needs that cannot be read out of a manifest.

    build_requests(tmp) -> {capability: [request, ...]}
        At least one valid request per DECLARED capability. Paths must be real
        and inside tmp.
    accept_configs  {capability: config}    a config the provider must accept
    refusals        ((capability, config, reason_substring), ...)
    streams         (StreamCase, ...)       at least one success and one failure
    binary_absent / binary_present          context managers over this
                                            provider's own executable seam
    auth_absent / auth_present              same for authentication, or None
                                            when the provider has no account
    invocation_context                      context manager making
                                            build_invocation possible without
                                            a real binary on this machine
    """

    provider_id: str
    build_requests: object
    accept_configs: dict
    refusals: tuple
    streams: tuple
    binary_absent: object
    binary_present: object
    auth_absent: object = None
    auth_present: object = None
    invocation_context: object = contextlib.nullcontext
    turn_succeeded: object = default_turn_succeeded
    notes: str = ""

    @property
    def has_auth(self) -> bool:
        return self.auth_absent is not None and self.auth_present is not None


@dataclasses.dataclass(frozen=True)
class ProviderCase:
    """One provider, in one registry, with its profile."""

    registry: ProviderRegistry
    provider_id: str
    profile: ProviderProfile
    label: str = ""

    @property
    def name(self) -> str:
        return (self.label or self.provider_id).replace("-", "_").replace(".", "_")


# --------------------------------------------------------------------------- #
# Static source analysis: no provider program may come from PATH
# --------------------------------------------------------------------------- #

def path_resolution_hits(source_path) -> list:
    """Lines in a module that pick an executable out of the environment.

    Detects shutil.which()/which(), os.get_exec_path(), and reads of the PATH
    environment variable. This is a source assertion on purpose: the defect it
    guards against ("a provider program chosen by whatever PATH happens to say")
    is invisible at runtime on a machine where PATH is benign.
    """
    source = Path(source_path).read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(source_path))
    hits = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr in ("which", "get_exec_path"):
                hits.append((node.lineno, f"{ast.unparse(func)}()"))
            elif isinstance(func, ast.Name) and func.id in ("which", "get_exec_path"):
                hits.append((node.lineno, f"{func.id}()"))
            elif (isinstance(func, ast.Attribute) and func.attr == "get"
                  and isinstance(func.value, ast.Attribute) and func.value.attr == "environ"
                  and node.args and isinstance(node.args[0], ast.Constant)
                  and node.args[0].value == "PATH"):
                hits.append((node.lineno, "os.environ.get('PATH')"))
        elif isinstance(node, ast.Subscript):
            value = node.value
            if (isinstance(value, ast.Attribute) and value.attr == "environ"
                    and isinstance(node.slice, ast.Constant) and node.slice.value == "PATH"):
                hits.append((node.lineno, "os.environ['PATH']"))
    return hits


def sibling_modules_imported(source_path) -> list:
    """Shipped modules in the same directory that this module imports.

    Used to follow a manifest-declared executable RESOLVER one hop: an adapter
    that delegates its lookup to a helper has not stopped resolving, it has
    only moved where it resolves.
    """
    source_path = Path(source_path).resolve()
    directory = source_path.parent
    tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
    found = {}
    for node in ast.walk(tree):
        names = []
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names = [node.module]
        for name in names:
            head = name.split(".")[0]
            candidate = directory / f"{head}.py"
            if candidate.is_file() and candidate != source_path:
                found[head] = candidate
    return [found[key] for key in sorted(found)]


# --------------------------------------------------------------------------- #
# Hostile stream battery: identical for every provider
# --------------------------------------------------------------------------- #

HOSTILE_STREAMS = (
    ("empty", ""),
    ("none", None),
    ("blank-lines", "\n\n   \n\t\n"),
    ("open-brace", "{"),
    ("truncated-json", '{"type":"turn.completed","usage":{"input_tokens":'),
    ("prose", "codex: warning: could not read config, continuing"),
    ("nul-bytes", "\x00\x01\x02\x03"),
    ("single-quotes", "{'type': 'turn.completed'}"),
    ("json-null", "null"),
    ("json-array", "[1, 2, 3]"),
    ("json-scalar", '"just a string"'),
    ("null-item", '{"type":"item.completed","item":null}'),
    ("string-item", '{"type":"item.completed","item":"not an object"}'),
    ("numeric-type", '{"type":123}'),
    ("missing-type", '{"payload":"no type key"}'),
    ("very-long-line", "x" * 200000),
    ("many-lines", "\n".join('{"type":"turn.completed"}' for _ in range(3000))),
    ("unicode", "日本語のテキスト\nemoji 🐛\nsize=1kB"),
    ("crlf", '{"type":"turn.completed"}\r\n{"type":"error","message":"boom"}\r\n'),
    ("interleaved-binary", "frame=1\n\udcff\udcfe binary garbage\nsize=2kB"),
    ("deep-nesting", '{"type":"item.completed","item":' + '{"a":' * 200 + "1" + "}" * 200 + "}"),
)


# --------------------------------------------------------------------------- #
# The assertions
# --------------------------------------------------------------------------- #

class ProviderConformanceTests(unittest.TestCase):
    """Every assertion every provider must satisfy. Parameterised by `case`."""

    case: ProviderCase = None

    def setUp(self):
        if self.case is None:  # pragma: no cover - the unbound base class
            self.skipTest("ProviderConformanceTests is parameterised; see conformance_class()")
        self.registry = self.case.registry
        self.profile = self.case.profile
        self.provider = self.registry.get(self.case.provider_id)
        self.manifest = self.registry.manifest(self.case.provider_id)
        self.declared = sandbox_from_manifest(self.manifest)
        self.declared_capabilities = tuple(self.manifest["capabilities"])
        temp = tempfile.TemporaryDirectory(prefix="sf-conformance-req-")
        self.addCleanup(temp.cleanup)
        self.tmp = Path(temp.name)
        self.requests = self.profile.build_requests(self.tmp)

    # -- helpers -----------------------------------------------------------
    def each_request(self):
        for capability in self.declared_capabilities:
            for index, request in enumerate(self.requests.get(capability) or ()):
                yield capability, index, request

    def build(self, capability, request):
        with self.profile.invocation_context():
            return self.provider.build_invocation(capability, request)

    # ================= CAPABILITIES ======================================
    def test_capabilities_are_internally_consistent_with_the_manifest(self):
        """capabilities() is the manifest, not a second opinion."""
        self.assertEqual(tuple(self.provider.capabilities()), self.declared_capabilities)
        self.assertTrue(self.declared_capabilities, "a provider must declare at least one capability")
        self.assertEqual(len(set(self.declared_capabilities)), len(self.declared_capabilities))
        for capability in self.declared_capabilities:
            self.assertIn(capability, CAPABILITIES,
                          f"{capability!r} is not a capability this system knows")
            self.assertTrue(self.provider.supports(capability))
        declared_in_code = getattr(type(self.provider), "CAPABILITIES", None)
        if declared_in_code is not None:
            self.assertEqual(tuple(declared_in_code), self.declared_capabilities,
                             "the adapter's CAPABILITIES constant disagrees with its manifest, so "
                             "the manifest is no longer the single source of truth")

    def test_rejects_a_capability_it_does_not_declare_with_a_reason(self):
        """A refusal a person can act on, for everything not declared."""
        undeclared = [c for c in CAPABILITIES if c not in self.declared_capabilities]
        if not undeclared:
            self.skipTest("this provider declares every capability")
        for capability in undeclared:
            with self.subTest(capability=capability):
                self.assertFalse(self.provider.supports(capability))
                answer = self.provider.accepts(capability, {})
                self.assertIsInstance(answer, Acceptance)
                self.assertFalse(answer.ok,
                                 f"{self.provider.id} accepted undeclared capability {capability}")
                self.assertTrue(answer.reason.strip(), "a refusal must carry a reason")
                self.assertGreaterEqual(len(answer.reason.split()), 4,
                                        f"refusal is not human-readable: {answer.reason!r}")

    def test_registry_offers_this_provider_only_for_declared_capabilities(self):
        """for_capability() filtering is exactly the declaration, both ways."""
        for capability in CAPABILITIES:
            offered = [p.id for p in self.registry.for_capability(capability)]
            with self.subTest(capability=capability):
                if capability in self.declared_capabilities:
                    self.assertIn(self.provider.id, offered)
                else:
                    self.assertNotIn(self.provider.id, offered)

    def test_accepts_a_valid_request_and_refuses_the_documented_ones(self):
        for capability, config in self.profile.accept_configs.items():
            with self.subTest(accept=capability):
                answer = self.provider.accepts(capability, config)
                self.assertTrue(answer.ok, f"refused a valid request: {answer.reason}")
        for capability, config, expected in self.profile.refusals:
            with self.subTest(refuse=capability, expect=expected):
                answer = self.provider.accepts(capability, config)
                self.assertFalse(answer.ok, "this configuration should have been refused")
                self.assertIn(expected.lower(), answer.reason.lower())

    # ================= READINESS =========================================
    def test_readiness_reports_a_missing_binary_with_a_reason(self):
        with self.profile.binary_absent():
            readiness = self.provider.readiness()
        self.assertIsInstance(readiness, Readiness)
        self.assertFalse(readiness.installed)
        self.assertFalse(readiness.available)
        self.assertTrue(readiness.missing, "a missing binary must be named in `missing`")
        self.assertTrue(readiness.reason.strip(), "unavailable must always come with a reason")
        self.assertEqual(readiness.as_dict()["available"], False)

    def test_readiness_reports_an_available_binary(self):
        with self.profile.binary_present():
            readiness = self.provider.readiness()
        self.assertTrue(readiness.installed,
                        f"binary reported missing while present: {readiness.reason}")
        self.assertIsInstance(readiness.facts, dict)

    def test_readiness_reports_missing_authentication(self):
        if not self.profile.has_auth:
            self.skipTest("provider has no account to authenticate against")
        with self.profile.binary_present(), self.profile.auth_absent():
            readiness = self.provider.readiness()
        self.assertFalse(readiness.authenticated)
        self.assertFalse(readiness.available)
        self.assertTrue(readiness.reason.strip())

    def test_readiness_reports_available_authentication(self):
        if not self.profile.has_auth:
            with self.profile.binary_present():
                readiness = self.provider.readiness()
            self.assertTrue(readiness.authenticated,
                            "a provider with no account must report itself authenticated rather "
                            "than making the UI invent a sign-in prompt")
            self.assertNotIn("authentication", readiness.missing)
            return
        with self.profile.binary_present(), self.profile.auth_present():
            readiness = self.provider.readiness()
        self.assertTrue(readiness.authenticated, readiness.reason)
        self.assertTrue(readiness.available, readiness.reason)
        self.assertEqual(readiness.missing, ())

    def test_a_readiness_call_that_raises_is_reported_not_propagated(self):
        """A broken adapter must not be able to take Mission Control down."""
        original = self.provider.readiness

        def explode():
            raise RuntimeError("readiness probe exploded")

        self.provider.readiness = explode
        try:
            readiness = self.registry.readiness(self.provider.id)
        finally:
            self.provider.readiness = original
        self.assertFalse(readiness.available)
        self.assertIn("readiness", " ".join(readiness.missing))
        self.assertIn("exploded", readiness.reason)
        # ... and the rest of the registry keeps working.
        self.assertIn(self.provider.id, self.registry.ids())

    # ================= INVOCATION ========================================
    def test_every_invocation_uses_an_absolute_executable(self):
        seen = 0
        for capability, index, request in self.each_request():
            with self.subTest(capability=capability, request=index):
                invocation = self.build(capability, request)
                self.assertIsInstance(invocation, Invocation)
                self.assertTrue(invocation.executable.startswith("/"),
                                f"{invocation.executable!r} is not absolute")
                self.assertTrue(Path(invocation.executable).is_absolute())
                self.assertEqual(invocation.command[0], invocation.executable)
                if invocation.stdin_path is not None:
                    self.assertTrue(str(invocation.stdin_path).startswith("/"))
                seen += 1
        self.assertGreater(seen, 0, "the profile supplied no requests to build")

    def test_the_manifest_executable_declaration_is_honoured(self):
        """kind=absolute must actually be used; kind=resolver must exist and be absolute."""
        executable = self.manifest.get("executable") or {"kind": "none"}
        kind = executable.get("kind")
        built = set()
        for capability, _index, request in self.each_request():
            built.add(self.build(capability, request).executable)
        if kind == "absolute":
            declared = executable["path"]
            self.assertTrue(declared.startswith("/"))
            self.assertIn(declared, built,
                          f"manifest declares {declared} but no invocation used it: {sorted(built)}")
        elif kind == "resolver":
            module = sys.modules[self.manifest["adapter_module"]]
            resolver = getattr(module, executable["resolver"], None)
            self.assertTrue(callable(resolver),
                            f"manifest names resolver {executable['resolver']}() which the adapter "
                            "does not define")
            found = resolver()
            if found is not None:
                self.assertTrue(str(found).startswith("/"),
                                "a resolver must return an absolute path or nothing")

    def test_argv_is_deterministic(self):
        for capability, index, request in self.each_request():
            with self.subTest(capability=capability, request=index):
                first = self.build(capability, request)
                second = self.build(capability, request)
                self.assertEqual(first.executable, second.executable)
                self.assertEqual(first.argv, second.argv)
                self.assertEqual(first.env_allowlist, second.env_allowlist)
                self.assertEqual(first.stdin_path, second.stdin_path)
                self.assertEqual(first.sandbox, second.sandbox)
                self.assertEqual(first.label, second.label)

    def test_environment_allowlist_holds_no_undeclared_name_and_no_value(self):
        """Identities only, and only declared ones. Values never travel here."""
        declared = set(self.manifest.get("credential_ids") or ())
        sentinels = {name: f"SENTINEL-{name}-MUST-NOT-LEAK-0f1e2d" for name in declared}
        sentinels.setdefault("CODEX_API_KEY", "SENTINEL-CODEX-MUST-NOT-LEAK-0f1e2d")
        sentinels.setdefault("OPENAI_API_KEY", "SENTINEL-OPENAI-MUST-NOT-LEAK-0f1e2d")
        previous = {k: os.environ.get(k) for k in sentinels}
        os.environ.update(sentinels)
        try:
            for capability, index, request in self.each_request():
                with self.subTest(capability=capability, request=index):
                    invocation = self.build(capability, request)
                    for name in invocation.env_allowlist:
                        self.assertIn(name, declared,
                                      f"{name!r} is not a declared credential identity")
                    haystack = " ".join([invocation.executable, *map(str, invocation.argv),
                                         *map(str, invocation.env_allowlist),
                                         str(invocation.stdin_path), invocation.label,
                                         *map(str, (invocation.sandbox.credential_ids
                                                    if invocation.sandbox else ()))])
                    for value in sentinels.values():
                        self.assertNotIn(value, haystack,
                                         "a credential VALUE reached the invocation")
        finally:
            for name, value in previous.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value

    def test_the_sandbox_it_carries_never_exceeds_the_manifest(self):
        for capability, index, request in self.each_request():
            with self.subTest(capability=capability, request=index):
                sandbox = self.build(capability, request).sandbox
                self.assertIsInstance(sandbox, SandboxSpec,
                                      "an invocation must carry the sandbox it will run in")
                if self.declared.network == "none":
                    self.assertEqual(sandbox.network, "none")
                else:
                    self.assertIn(sandbox.network, ("none", self.declared.network))
                self.assertLessEqual(set(sandbox.egress_allowlist),
                                     set(self.declared.egress_allowlist))
                self.assertLessEqual(set(sandbox.read_grants), set(self.declared.read_grants))
                self.assertLessEqual(set(sandbox.credential_ids),
                                     set(self.declared.credential_ids))
                self.assertLessEqual(sandbox.memory_mb, self.declared.memory_mb)
                self.assertLessEqual(sandbox.cpu_seconds, self.declared.cpu_seconds)
                self.assertLessEqual(sandbox.processes, self.declared.processes)
                if self.declared.workspace_mode == "read-only":
                    self.assertEqual(sandbox.workspace_mode, "read-only")

    def test_credential_identities_are_a_subset_of_the_manifest(self):
        declared = set(self.manifest.get("credential_ids") or ())
        for capability, index, request in self.each_request():
            with self.subTest(capability=capability, request=index):
                invocation = self.build(capability, request)
                self.assertLessEqual(set(invocation.env_allowlist), declared)
                self.assertLessEqual(set(invocation.sandbox.credential_ids), declared)
                if not declared:
                    self.assertEqual(invocation.env_allowlist, ())
                    self.assertEqual(invocation.sandbox.credential_ids, ())

    # ================= STREAM PARSING ====================================
    def test_a_captured_native_stream_normalises_to_the_expected_events(self):
        self.assertTrue(self.profile.streams, "a profile must supply captured streams")
        for case in self.profile.streams:
            with self.subTest(stream=case.name):
                events = self.provider.parse_stream(case.text)
                self.assertEqual([e.type for e in events], list(case.expect_types))
                self.assertEqual(self.provider.final_message(events), case.expect_final)

    def test_malformed_partial_and_interleaved_output_is_tolerated(self):
        """The provider stream is untrusted input; it may never raise."""
        for name, text in HOSTILE_STREAMS:
            with self.subTest(stream=name):
                try:
                    events = self.provider.parse_stream(text)
                except Exception as exc:  # noqa: BLE001 - that is the assertion
                    self.fail(f"parse_stream raised {exc.__class__.__name__}: {exc}")
                self.assertIsInstance(events, list)
                for event in events:
                    self.assertIsInstance(event, AgentEvent)
                    self.assertIn(event.type, {AgentEvent.MESSAGE, AgentEvent.PROGRESS,
                                               AgentEvent.USAGE, AgentEvent.LOG,
                                               AgentEvent.ERROR, AgentEvent.TURN_COMPLETE})
                    self.assertIsInstance(event.text, str)
                try:
                    self.provider.final_message(events)
                except Exception as exc:  # noqa: BLE001
                    self.fail(f"final_message raised {exc.__class__.__name__}: {exc}")

    def test_end_of_turn_is_detected_and_failure_is_distinguishable(self):
        succeeded = [c for c in self.profile.streams if c.expect_success]
        failed = [c for c in self.profile.streams if not c.expect_success]
        self.assertTrue(succeeded, "a profile must include a successful turn")
        self.assertTrue(failed, "a profile must include a failed turn")
        rule = self.profile.turn_succeeded
        for case in self.profile.streams:
            with self.subTest(stream=case.name):
                events = self.provider.parse_stream(case.text)
                self.assertEqual(bool(rule(events, case.exit_code)), case.expect_success)
                if case.expect_success:
                    self.assertTrue(
                        any(e.type == AgentEvent.TURN_COMPLETE for e in events),
                        "a successful turn must end with an explicit turn-complete event")
        self.assertNotEqual({c.text for c in succeeded}, {c.text for c in failed},
                            "success and failure fixtures must not be the same bytes")

    # ================= CANCELLATION ======================================
    def test_a_long_running_invocation_is_built_with_bounded_limits(self):
        """COVERED: every invocation a provider can build carries finite cpu,
        memory and process limits no larger than its manifest declared, so a
        provider cannot construct a job that runs forever or that outlives the
        bound a reviewer approved.

        NOT COVERED HERE: that the orchestrator actually kills the process
        group when a person presses cancel. That needs the executor, which this
        suite deliberately does not import -- it is exercised for real in
        test_missions.py::test_running_process_cancel_kills_child_group, and
        the reachable half of the contract is asserted in
        test_provider_conformance.py::CancellationContractTests.
        """
        schema_ceilings = {"cpu_seconds": 7200, "memory_mb": 32768, "processes": 512}
        for capability, index, request in self.each_request():
            with self.subTest(capability=capability, request=index):
                sandbox = self.build(capability, request).sandbox
                for field, ceiling in schema_ceilings.items():
                    value = getattr(sandbox, field)
                    self.assertIsInstance(value, int)
                    self.assertGreater(value, 0, f"{field} must be a real bound")
                    self.assertLessEqual(value, ceiling,
                                         f"{field}={value} exceeds the manifest schema ceiling")
                    self.assertLessEqual(value, getattr(self.declared, field))

    # ================= SECURITY ==========================================
    def test_no_provider_obtains_an_implicit_network_grant(self):
        if self.manifest["network_policy"] == "none":
            self.assertEqual(self.declared.network, "none")
            self.assertEqual(self.declared.egress_allowlist, ())
            self.assertEqual(self.declared.firebreak_network, "none")
            for capability, index, request in self.each_request():
                with self.subTest(capability=capability, request=index):
                    sandbox = self.build(capability, request).sandbox
                    self.assertEqual(sandbox.network, "none")
                    self.assertEqual(sandbox.egress_allowlist, ())
                    self.assertEqual(sandbox.firebreak_network, "none")
        else:
            self.assertTrue(self.manifest.get("egress_allowlist"),
                            "an allowlist policy with no hosts is an unbounded grant")
            self.assertEqual(set(self.declared.egress_allowlist),
                             set(self.manifest["egress_allowlist"]))

    def test_narrow_refuses_to_add_anything_the_manifest_did_not_declare(self):
        base = self.declared
        with self.assertRaises(ProviderError):
            base.narrow(credential_ids=(*base.credential_ids, "STOLEN_TOKEN"))
        with self.assertRaises(ProviderError):
            base.narrow(egress_allowlist=(*base.egress_allowlist, "exfil.example.com"))
        with self.assertRaises(ProviderError):
            base.narrow(read_grants=(*base.read_grants, "/etc"))
        with self.assertRaises(ProviderError):
            base.narrow(cpu_seconds=base.cpu_seconds + 1)
        with self.assertRaises(ProviderError):
            base.narrow(memory_mb=base.memory_mb + 1)
        with self.assertRaises(ProviderError):
            base.narrow(processes=base.processes + 1)
        if base.network == "none":
            with self.assertRaises(ProviderError):
                base.narrow(network="allowlist", egress_allowlist=("exfil.example.com",))
        if base.workspace_mode == "read-only":
            with self.assertRaises(ProviderError):
                base.narrow(workspace_mode="workspace-write")
        # Narrowing in the safe direction still works.
        self.assertEqual(base.narrow(credential_ids=()).credential_ids, ())

    def test_the_adapter_does_not_resolve_its_program_through_path(self):
        module = sys.modules[self.manifest["adapter_module"]]
        source = Path(module.__file__).resolve()
        hits = path_resolution_hits(source)
        self.assertEqual(hits, [], f"{source.name} resolves an executable from the environment: "
                                   + ", ".join(f"line {line}: {what}" for line, what in hits))

    def test_the_declared_resolver_chain_does_not_reach_path_resolution(self):
        """A resolver that delegates has not stopped resolving.

        sf_providers promises "There is no code path that resolves a provider
        program through PATH". A manifest whose executable.kind is "resolver"
        names a function in the adapter; if that function hands the lookup to a
        shipped sibling module, the sibling is part of the chain and the promise
        covers it too.
        """
        executable = self.manifest.get("executable") or {"kind": "none"}
        if executable.get("kind") != "resolver":
            self.skipTest("this provider does not declare an executable resolver")
        module = sys.modules[self.manifest["adapter_module"]]
        adapter_source = Path(module.__file__).resolve()
        offenders = []
        for sibling in sibling_modules_imported(adapter_source):
            for line, what in path_resolution_hits(sibling):
                offenders.append(f"{sibling.name}:{line}: {what}")
        self.assertEqual(offenders, [], (
            f"{self.provider.id}'s executable resolver reaches PATH resolution through a shipped "
            "helper, so the provider program is still chosen by the environment: "
            + "; ".join(offenders)))


def conformance_class(case: ProviderCase, module: str = __name__):
    """One concrete TestCase subclass for one provider."""
    name = f"Conformance_{case.name}"
    klass = type(name, (ProviderConformanceTests,), {"case": case, "__module__": module})
    klass.__doc__ = f"Provider conformance: {case.provider_id}"
    return klass


def run_conformance(case: ProviderCase):
    """Run the whole suite against one provider; return (result, literal output)."""
    klass = conformance_class(case, module=__name__)
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(klass)
    buffer = io.StringIO()
    result = unittest.TextTestRunner(stream=buffer, verbosity=2).run(suite)
    return result, buffer.getvalue()


def failed_method_names(result) -> set:
    """Which conformance assertions broke.

    A failure raised inside subTest arrives wrapped in a _SubTest whose own
    _testMethodName is "runTest"; the real name lives on its test_case.
    """
    names = set()
    for test, _text in list(result.failures) + list(result.errors):
        inner = getattr(test, "test_case", None) or test
        names.add(getattr(inner, "_testMethodName", str(inner)))
    return names


def failure_text(result) -> str:
    return "\n".join(text for _test, text in list(result.failures) + list(result.errors))
