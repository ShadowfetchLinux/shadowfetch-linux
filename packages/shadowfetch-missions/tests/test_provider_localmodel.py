"""Phase 2.5: does AgentProvider carry a STREAMING, STATEFUL provider?

PHASE2_REMAINING_RISKS.md section 6 predicted this gap:

    "The interface has not yet met a long-running local model that streams
     tokens continuously and holds state between turns -- the case that most
     often breaks a turn-shaped abstraction. AgentEvent has a PROGRESS type and
     the executor reads incrementally, so the shape is plausible, but it is
     untested."

This file tests it. It adds no product code. Every assertion here is either the
existing conformance suite run against a new fixture provider, or a probe of a
behaviour the conformance suite does not reach: the real executor's incremental
reader, real cancellation of a real streaming child, the output cap, and the
lifetime of provider instance state.

Nothing here contacts a network, a model server or a cloud service. The fixture
provider declares network_policy "none" and the transport it would need is
injected; see the adapter docstring for why a real localhost transport must not
be built against today's Firebreak.

Read the verdicts as: PASSES = the current interface copes. DEFECT = it does
not, and the docstring says exactly where.
"""
from __future__ import annotations

import contextlib
import importlib.util
import json
import os
import sys
import tempfile
import threading
import time
import unittest

import mission_approvals

import mission_states
from pathlib import Path
from unittest import mock

from provider_conformance import (
    AgentEvent, Capability, FIXTURE_ADAPTERS, MISSION_MODULES, PROTECTED_FILES,
    ProviderCase, ProviderProfile, ProviderRegistry, REPO_ROOT, SHIPPED_MANIFESTS,
    StreamCase, conformance_class, manifest_root, module_root, protected_digests,
    run_conformance, shipped_adapter_files, shipped_manifest_files, stream,
)
import sf_providers
import sf_redact
from sf_providers import AgentProvider, ProviderError

FIXTURE_MANIFEST = (Path(__file__).resolve().parent
                    / "fixtures/providers/manifests/conformance-localmodel.json")
FIXTURE_ADAPTER = FIXTURE_ADAPTERS / "sf_provider_conformance_localmodel.py"
PROVIDER_ID = "conformance-localmodel"

try:                                   # Phase 3 approved-provider policy
    from provider_conformance import fixture_registry
except ImportError:                    # a tree without one
    def fixture_registry(manifests_dir, modules_dir):
        return ProviderRegistry(root=manifests_dir, module_root=modules_dir)


def build_registry():
    """A registry holding both shipped providers plus this fixture."""
    return fixture_registry(
        manifest_root(*shipped_manifest_files(), FIXTURE_MANIFEST),
        module_root(*shipped_adapter_files(),
                    *sorted(FIXTURE_ADAPTERS.glob("sf_provider_*.py"))))


# Imported by FILE, before any registry runs, so that this module object and the
# one the registry loads are the same object -- patching PROGRAM/TRANSPORT here
# must affect the provider the registry hands out.
if "sf_provider_conformance_localmodel" in sys.modules:
    adapter = sys.modules["sf_provider_conformance_localmodel"]
else:
    _aspec = importlib.util.spec_from_file_location(
        "sf_provider_conformance_localmodel", FIXTURE_ADAPTER)
    adapter = importlib.util.module_from_spec(_aspec)
    sys.modules["sf_provider_conformance_localmodel"] = adapter
    _aspec.loader.exec_module(adapter)

LOCAL_MODEL_REGISTRY = build_registry()

ANSWER = "The launch is Friday and the release contains three workflows."


# --------------------------------------------------------------------------- #
# The injected transport (Option A). Not a socket, not a broker.
# --------------------------------------------------------------------------- #

class FakeTransport:
    """Stands in for a broker-bound local model channel that does not exist."""

    def __init__(self, *, available=True, models=("phi-3-mini-q4", "qwen2.5-7b")):
        self.available = available
        self._models = tuple(models)

    def models(self):
        return self._models

    def default_model(self):
        return self._models[0] if self._models else ""


def with_transport(transport):
    return mock.patch.object(adapter, "TRANSPORT", transport)


def local_binary_present():
    """The bridge program exists AND a model server answers with a model."""
    return _both(mock.patch.object(adapter, "PROGRAM", "/usr/bin/true"),
                 with_transport(FakeTransport()))


def local_binary_absent():
    return _both(mock.patch.object(adapter, "PROGRAM", "/nonexistent/bin/bridge"),
                 with_transport(FakeTransport()))


@contextlib.contextmanager
def _both(*managers):
    with contextlib.ExitStack() as stack:
        for manager in managers:
            stack.enter_context(manager)
        yield


def local_requests(tmp):
    prompt = tmp / "turn-prompt.md"
    prompt.write_text("Summarize the launch\n", encoding="utf-8")
    base = {"prompt_path": str(prompt), "config": {"network": "none"}}
    return {
        Capability.CODE_CHANGE: [dict(base), dict(base, read_only=True)],
        Capability.SOURCED_REPORT: [dict(base)],
    }


LOCAL_PROFILE = ProviderProfile(
    provider_id=PROVIDER_ID,
    build_requests=local_requests,
    accept_configs={Capability.CODE_CHANGE: {"network": "none"},
                    Capability.SOURCED_REPORT: {"network": "none"}},
    refusals=(
        (Capability.CODE_CHANGE, {"network": "allow"}, "entirely on this machine"),
        (Capability.SOURCED_REPORT, {"network": "allow"}, "entirely on this machine"),
        (Capability.SOURCED_REPORT, {"network": "none", "model": "llama-3.1-70b"},
         "not running"),
        (Capability.MEDIA_EXPORT, {"network": "none"}, "does not perform"),
    ),
    streams=(
        StreamCase(
            name="localmodel_tokens.jsonl",
            text=stream("localmodel_tokens.jsonl"),
            expect_types=("progress", "progress", "message", "usage",
                          "turn-complete", "progress"),
            expect_final=ANSWER, expect_success=True, exit_code=0),
        StreamCase(
            name="localmodel_no_terminal.jsonl",
            text=stream("localmodel_no_terminal.jsonl"),
            expect_types=("progress", "message", "turn-complete"),
            expect_final=ANSWER, expect_success=True, exit_code=0),
        StreamCase(
            name="localmodel_disconnect.jsonl",
            text=stream("localmodel_disconnect.jsonl"),
            expect_types=("progress", "log", "message", "error"),
            expect_final="The launch is Fri", expect_success=False, exit_code=1),
        StreamCase(
            name="localmodel_model_unavailable.jsonl",
            text=stream("localmodel_model_unavailable.jsonl"),
            expect_types=("error",),
            expect_final="", expect_success=False, exit_code=1),
    ),
    binary_absent=local_binary_absent,
    binary_present=local_binary_present,
    notes=("A local model has no account, so authenticated is always True and the "
           "server's absence is reported through installed/missing instead. The "
           "message a person reads exists in no single native event: it is the "
           "concatenation of every token delta."),
)

# The whole existing conformance suite, run against this provider.
Conformance_conformance_localmodel = conformance_class(
    ProviderCase(LOCAL_MODEL_REGISTRY, PROVIDER_ID, LOCAL_PROFILE, "localmodel"),
    module=__name__)


def provider():
    """A FRESH provider instance, because several probes are about state."""
    return build_registry().get(PROVIDER_ID)


def types_of(events):
    return [e.type for e in events]


class RegistryAdmissionTests(unittest.TestCase):
    """This fixture must actually be admitted, or every verdict below is void."""

    def test_the_fixture_provider_loads_with_no_registry_error(self):
        self.assertEqual(LOCAL_MODEL_REGISTRY.errors, [],
                         "the fixture provider was refused; the probe results "
                         "below would be meaningless")
        self.assertIn(PROVIDER_ID, LOCAL_MODEL_REGISTRY.ids())
        self.assertIn(PROVIDER_ID, [p.id for p in LOCAL_MODEL_REGISTRY.list()])


# --------------------------------------------------------------------------- #
# 1. The stream battery
# --------------------------------------------------------------------------- #

class StreamShapeTests(unittest.TestCase):
    """Each named characteristic from the Phase 2.5 brief, one test each."""

    def setUp(self):
        self.provider = provider()

    def parse(self, name):
        return self.provider.parse_stream(stream(name))

    # -- incremental token chunks -----------------------------------------
    def test_incremental_token_deltas_become_one_message(self):
        """VERDICT PASSES. The answer exists in no single native event; the
        adapter accumulates and the interface never notices."""
        events = self.parse("localmodel_tokens.jsonl")
        self.assertEqual(types_of(events),
                         ["progress", "progress", "message", "usage",
                          "turn-complete", "progress"])
        self.assertEqual(self.provider.final_message(events), ANSWER)
        self.assertEqual(self.provider.usage(events)["completion_tokens"], 11)

    # -- long-running generation ------------------------------------------
    def test_a_long_lived_stream_with_heartbeats_and_tool_rounds(self):
        """VERDICT PASSES at the parsing layer. 600 deltas, 5 heartbeats and a
        tool request/result round reduce to progress events plus one message.
        The transport layer is a separate matter -- see OutputCapTests."""
        events = self.parse("localmodel_long_stream.jsonl")
        kinds = types_of(events)
        self.assertEqual(kinds.count("message"), 1)
        self.assertEqual(kinds.count("turn-complete"), 1)
        self.assertEqual(kinds.count("error"), 0)
        heartbeats = [e for e in events if e.data.get("native") == "heartbeat"]
        self.assertEqual(len(heartbeats), 5)
        tools = [e for e in events if (e.data.get("native") or "").startswith("tool.")]
        self.assertEqual([e.data["native"] for e in tools],
                         ["tool.request", "tool.result"])
        self.assertTrue(all(e.type == AgentEvent.PROGRESS for e in heartbeats + tools))
        message = [e for e in events if e.type == AgentEvent.MESSAGE][0]
        self.assertEqual(message.text.split()[0], "word0000")
        self.assertEqual(message.text.split()[-1], "word0599")
        self.assertTrue(self.provider.turn_succeeded(events))

    # -- no explicit turn.completed ---------------------------------------
    def test_a_stream_with_no_terminal_event_still_completes_a_turn(self):
        """VERDICT PASSES, exactly the way offline-media already does it: the
        adapter synthesises the terminal event. Note the cost, recorded in
        AgentEventVocabularyTests: the orchestrator cannot tell a synthesised
        terminal from a native one without reading a provider-private data key."""
        events = self.parse("localmodel_no_terminal.jsonl")
        self.assertEqual(types_of(events), ["progress", "message", "turn-complete"])
        self.assertEqual(self.provider.final_message(events), ANSWER)
        self.assertTrue(self.provider.turn_succeeded(events))
        self.assertEqual(events[-1].data["terminal"], "synthesized")

    # -- split / partial chunks -------------------------------------------
    def test_a_record_split_in_half_is_carried_not_raised(self):
        """VERDICT PASSES. The half record becomes a log line and the turn is
        not called complete."""
        events = self.parse("localmodel_split_chunks.jsonl")
        self.assertEqual(types_of(events), ["progress", "log", "message", "error"])
        self.assertEqual(self.provider.final_message(events), "The launch ")
        self.assertFalse(self.provider.turn_succeeded(events))
        self.assertEqual(events[1].data["unterminated"], True)

    def test_the_same_bytes_arriving_in_any_chunking_parse_identically(self):
        """VERDICT PASSES, but only because parse_stream is handed the whole
        stream. Chunk-independence is a property of buffering, not of the
        interface; an incremental parse_stream would have to prove it itself."""
        text = stream("localmodel_tokens.jsonl")
        whole = types_of(self.provider.parse_stream(text))
        for size in (1, 3, 7, 64, 997):
            with self.subTest(chunk=size):
                rejoined = "".join(text[i:i + size]
                                   for i in range(0, len(text), size))
                self.assertEqual(rejoined, text)
                self.assertEqual(types_of(provider().parse_stream(rejoined)), whole)

    # -- empty chunks ------------------------------------------------------
    def test_empty_deltas_and_blank_lines_produce_no_message(self):
        """VERDICT PASSES. Keep-alive deltas that carry nothing do not fabricate
        an empty answer, and agent_turn's own 'returned no final report message'
        check is what catches it."""
        events = self.parse("localmodel_empty_chunks.jsonl")
        self.assertEqual(types_of(events), ["progress", "usage", "turn-complete"])
        self.assertEqual(self.provider.final_message(events), "")
        self.assertTrue(self.provider.turn_succeeded(events))

    # -- unicode -----------------------------------------------------------
    def test_unicode_deltas_reassemble_exactly(self):
        """VERDICT PASSES at the provider layer. A grapheme cluster split across
        two deltas is rejoined byte-for-byte. The TRANSPORT layer is where this
        actually breaks: see ExecutorTransportTests."""
        raw = stream("localmodel_unicode.jsonl")
        deltas = [json.loads(l)["delta"] for l in raw.splitlines()
                  if l and json.loads(l).get("event") == "token"]
        events = self.provider.parse_stream(raw)
        message = [e for e in events if e.type == AgentEvent.MESSAGE][0]
        self.assertEqual(message.text, "".join(deltas))
        # A grapheme cluster split across two deltas is rejoined, not mangled.
        self.assertIn("e\u0301cole", message.text)              # e + combining acute
        self.assertIn("\U0001f41b\u200d\U0001f525", message.text)   # ZWJ emoji sequence
        self.assertIn("\u65e5\u672c\u8a9e\u306e\u30c6\u30ad\u30b9\u30c8", message.text)
        self.assertIn("\U0001d54ahadowfetch", message.text)      # astral plane
        self.assertTrue(self.provider.turn_succeeded(events))

    # -- a very large message ---------------------------------------------
    def test_a_very_large_message_is_capped_not_dropped(self):
        events = self.parse("localmodel_large_message.jsonl")
        message = [e for e in events if e.type == AgentEvent.MESSAGE][0]
        self.assertEqual(len(message.text), adapter.MAX_MESSAGE_CHARS)
        self.assertTrue(message.text.startswith("0000 xxx"))
        self.assertTrue(self.provider.turn_succeeded(events))

    # -- repeated events ---------------------------------------------------
    def test_repeated_sessions_and_terminals_keep_the_last_answer(self):
        """VERDICT PASSES. Two generations in one stream give two messages and
        two terminals; final_message() and usage() both read the last."""
        events = self.parse("localmodel_repeated_events.jsonl")
        self.assertEqual(types_of(events).count("message"), 2)
        self.assertEqual(types_of(events).count("turn-complete"), 3)
        self.assertEqual(self.provider.final_message(events), "Second answer.")
        self.assertTrue(self.provider.turn_succeeded(events))
        self.assertEqual(self.provider.session, "s-rep-2")

    # -- cancellation mid-stream (as reported BY the provider) -------------
    def test_a_server_side_cancellation_keeps_partial_output_and_fails_the_turn(self):
        events = self.parse("localmodel_cancelled.jsonl")
        self.assertEqual(types_of(events),
                         ["progress", "progress", "message", "error"])
        self.assertEqual(self.provider.final_message(events), "The launch is ")
        self.assertFalse(self.provider.turn_succeeded(events))

    # -- mid-stream disconnect / server crash ------------------------------
    def test_a_mid_record_disconnect_never_reports_a_complete_turn(self):
        events = self.parse("localmodel_disconnect.jsonl")
        self.assertFalse(self.provider.turn_succeeded(events))
        self.assertEqual(self.provider.final_message(events), "The launch is Fri")
        self.assertEqual(events[-1].data["reason"], "disconnected")

    # -- stalled stream ----------------------------------------------------
    def test_a_stalled_stream_that_only_heartbeats_is_a_failure_not_a_success(self):
        """VERDICT PASSES at the provider layer -- but only AFTER the stream
        ends. Nothing in the interface detects a stall WHILE it is happening;
        see ExecutorTransportTests.test_a_stalled_stream_is_bounded_only_by."""
        events = self.parse("localmodel_stalled.jsonl")
        self.assertEqual(types_of(events)[-1], "error")
        self.assertEqual(types_of(events).count("turn-complete"), 0)
        self.assertFalse(self.provider.turn_succeeded(events))

    # -- server unavailable ------------------------------------------------
    def test_a_bridge_that_could_not_connect_produces_a_readable_failure(self):
        events = self.parse("localmodel_server_unavailable.txt")
        self.assertEqual(types_of(events), ["log", "log", "error"])
        self.assertIn("connection refused", events[0].text)
        self.assertFalse(self.provider.turn_succeeded(events))

    # -- PHASE2 risk 8, confirmed for a streaming provider -----------------
    def test_a_non_dict_usage_reaches_the_inference_record_unchecked(self):
        """DEFECT (already known, PHASE2_REMAINING_RISKS section 8): usage is
        not type-checked, so a provider that reports a string ends up with a
        string in the receipt. Recorded here because a token-streaming server
        reports usage far more often than either shipped provider does."""
        events = self.parse("localmodel_bad_usage.jsonl")
        self.assertEqual(self.provider.usage(events), "not-a-dict")
        self.assertNotIsInstance(self.provider.usage(events), dict)


# --------------------------------------------------------------------------- #
# 2. Readiness: model discovery, model unavailable, server unavailable
# --------------------------------------------------------------------------- #

class ReadinessTests(unittest.TestCase):

    def setUp(self):
        self.provider = provider()

    def test_model_discovery_is_reported_as_facts(self):
        with local_binary_present():
            readiness = self.provider.readiness()
        self.assertTrue(readiness.available, readiness.reason)
        self.assertEqual(readiness.facts["models"], ["phi-3-mini-q4", "qwen2.5-7b"])
        self.assertEqual(readiness.facts["default_model"], "phi-3-mini-q4")
        self.assertFalse(readiness.facts["requires_credentials"])
        self.assertFalse(readiness.facts["requires_network"])

    def test_the_server_being_down_is_unavailable_with_a_reason(self):
        with mock.patch.object(adapter, "PROGRAM", "/usr/bin/true"), \
                with_transport(FakeTransport(available=False)):
            readiness = self.provider.readiness()
        self.assertFalse(readiness.available)
        self.assertIn("local model server", readiness.missing)
        self.assertIn("Start the local model service", readiness.reason)

    def test_no_transport_at_all_is_unavailable_rather_than_an_exception(self):
        with mock.patch.object(adapter, "PROGRAM", "/usr/bin/true"), \
                with_transport(None):
            readiness = self.provider.readiness()
        self.assertFalse(readiness.available)
        self.assertEqual(readiness.facts["transport"], "none")

    def test_a_server_with_no_model_loaded_is_unavailable(self):
        with mock.patch.object(adapter, "PROGRAM", "/usr/bin/true"), \
                with_transport(FakeTransport(models=())):
            readiness = self.provider.readiness()
        self.assertFalse(readiness.available)
        self.assertIn("a loaded model", readiness.missing)

    def test_naming_an_unloaded_model_is_refused_with_the_loaded_list(self):
        with local_binary_present():
            answer = self.provider.accepts(
                Capability.SOURCED_REPORT,
                {"network": "none", "model": "llama-3.1-70b"})
        self.assertFalse(answer.ok)
        self.assertIn("phi-3-mini-q4", answer.reason)

    def test_a_named_loaded_model_is_accepted_and_reaches_the_argv(self):
        with local_binary_present(), tempfile.TemporaryDirectory() as tmp:
            prompt = Path(tmp) / "p.md"
            prompt.write_text("x", encoding="utf-8")
            config = {"network": "none", "model": "qwen2.5-7b"}
            self.assertTrue(self.provider.accepts(Capability.SOURCED_REPORT, config).ok)
            invocation = self.provider.build_invocation(
                Capability.SOURCED_REPORT,
                {"prompt_path": str(prompt), "config": config})
        self.assertIn("--model", invocation.argv)
        self.assertIn("qwen2.5-7b", invocation.argv)


# --------------------------------------------------------------------------- #
# 3. Session state: start, reuse, and the lifetime problem
# --------------------------------------------------------------------------- #

class SessionStateTests(unittest.TestCase):
    """Explicit session start, session reuse, and what has no owner."""

    def setUp(self):
        self.provider = provider()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.prompt = Path(self.tmp.name) / "p.md"
        self.prompt.write_text("Summarize\n", encoding="utf-8")

    def build(self, **config):
        return self.provider.build_invocation(
            Capability.SOURCED_REPORT,
            {"prompt_path": str(self.prompt),
             "config": {"network": "none", **config}})

    def test_a_session_id_is_recovered_from_the_stream(self):
        """VERDICT PASSES. An explicit session start is expressible: it is a
        native event the adapter maps to PROGRESS and remembers."""
        self.assertIsNone(self.provider.session)
        events = self.provider.parse_stream(stream("localmodel_tokens.jsonl"))
        self.assertEqual(self.provider.session, "s-1a2b3c")
        self.assertEqual(events[0].data["session"], "s-1a2b3c")
        self.assertEqual(events[0].type, AgentEvent.PROGRESS)

    def test_session_reuse_across_two_submissions_is_expressible(self):
        """VERDICT PASSES, with a caveat the next test names. The provider
        object outlives one turn, so turn 2 can resume turn 1's session."""
        self.assertNotIn("--session", self.build(session_reuse=True).argv)
        self.provider.parse_stream(stream("localmodel_tokens.jsonl"))
        second = self.build(session_reuse=True)
        self.assertIn("--session", second.argv)
        self.assertIn("s-1a2b3c", second.argv)

    def test_a_session_id_from_a_hostile_stream_never_reaches_the_argv(self):
        for bad in ('{"event":"session.started","session":"../../etc/passwd"}',
                    '{"event":"session.started","session":"a b; rm -rf /"}',
                    '{"event":"session.started","session":123}',
                    '{"event":"session.started","session":{"a":1}}',
                    '{"event":"session.started","session":"' + "x" * 500 + '"}'):
            with self.subTest(session=bad[:60]):
                fresh = provider()
                fresh.parse_stream(bad + "\n")
                self.assertIsNone(fresh.session)
                self.assertNotIn("--session", fresh.build_invocation(
                    Capability.SOURCED_REPORT,
                    {"prompt_path": str(self.prompt),
                     "config": {"network": "none", "session_reuse": True}}).argv)

    def test_the_registry_hands_every_mission_the_same_provider_object(self):
        """DEFECT for a stateful provider. ProviderRegistry builds ONE adapter
        instance per manifest and returns it forever, and sf_missions.registry()
        caches the registry for the life of the worker process. So session state
        set during mission A is visible to mission B, and there is no interface
        point at which it is cleared -- AgentProvider has no close_session(),
        no reset(), and no per-mission scope of any kind.

        Neither shipped provider is stateful, so nothing catches this today.
        """
        registry = LOCAL_MODEL_REGISTRY
        first = registry.get(PROVIDER_ID)
        second = registry.get(PROVIDER_ID)
        self.assertIs(first, second,
                      "the registry is expected to memoise; this test documents "
                      "the consequence, not a wish for it to change")
        first.parse_stream(stream("localmodel_tokens.jsonl"))
        try:
            # "mission B" asks the registry for a provider and gets mission A's
            # session, with no way to have known.
            leaked = registry.get(PROVIDER_ID).session
            self.assertEqual(leaked, "s-1a2b3c")
        finally:
            first.forget_session()

    def test_the_interface_offers_no_place_to_end_a_session(self):
        """DEFECT, stated precisely. forget_session() exists on this fixture and
        nothing calls it, because it is not part of AgentProvider."""
        surface = {name for name in dir(AgentProvider) if not name.startswith("_")}
        for absent in ("close_session", "open_session", "reset", "cancel",
                       "stream_events", "submit", "end_turn"):
            self.assertNotIn(absent, surface)
        self.assertIn("forget_session", dir(type(self.provider)))
        self.assertNotIn("forget_session", surface)


# --------------------------------------------------------------------------- #
# 4. AgentEvent vocabulary
# --------------------------------------------------------------------------- #

class AgentEventVocabularyTests(unittest.TestCase):
    """Which of SESSION_STARTED / TEXT_DELTA / TOOL_REQUEST / TOOL_RESULT /
    STATUS / SESSION_END are genuinely needed, tested rather than asserted."""

    def setUp(self):
        self.provider = provider()

    def test_the_six_existing_types_carry_every_native_event_this_provider_has(self):
        """EVIDENCE that no new type is required. Ten distinct native event
        names reduce to the existing six with nothing dropped and nothing
        mislabelled -- the native name survives in data['native']."""
        events = self.provider.parse_stream(stream("localmodel_long_stream.jsonl")
                                            + stream("localmodel_unknown_events.jsonl"))
        self.assertLessEqual(set(types_of(events)),
                             {AgentEvent.MESSAGE, AgentEvent.PROGRESS,
                              AgentEvent.USAGE, AgentEvent.LOG,
                              AgentEvent.ERROR, AgentEvent.TURN_COMPLETE})
        natives = {e.data.get("native") for e in events} - {None}
        self.assertIn("session.started", natives)
        self.assertIn("session.ended", natives)
        self.assertIn("model.status", natives)
        self.assertIn("heartbeat", natives)
        self.assertIn("tool.request", natives)
        self.assertIn("tool.result", natives)
        self.assertIn("speculative.draft", natives)

    def test_an_unknown_native_event_becomes_a_log_and_never_raises(self):
        """The direct answer to 'can an unknown native provider event crash the
        orchestrator?' -- no, at the adapter layer."""
        events = self.provider.parse_stream(stream("localmodel_unknown_events.jsonl"))
        unknown = [e for e in events
                   if e.type == AgentEvent.LOG and "unrecognised" in e.text]
        self.assertEqual([e.data["native"] for e in unknown],
                         ["speculative.draft", "kv_cache.evict",
                          "grammar.constraint", "telemetry"])
        self.assertTrue(self.provider.turn_succeeded(events))
        self.assertEqual(self.provider.final_message(events), ANSWER)

    def test_an_unknown_agentevent_type_is_refused_by_the_value_type(self):
        """The type system already forbids inventing a type at runtime, which is
        why 'add TEXT_DELTA' is an interface change and not an adapter change."""
        for invented in ("text-delta", "session-started", "tool-request",
                         "status", "session-end", ""):
            with self.subTest(type=invented), self.assertRaises(ProviderError):
                AgentEvent(invented)

    def test_a_provider_whose_parse_stream_raises_fails_the_mission_not_the_worker(self):
        """An adapter that DOES try to invent a type raises out of parse_stream.
        The orchestrator's own boundary catches it: run_mission turns any
        exception into a failed mission with a receipt. Proven for real in
        OrchestratorSurvivalTests."""
        class Rogue(type(self.provider)):
            def parse_stream(self, text):
                return [AgentEvent("text-delta", "hi")]

        rogue = Rogue(self.provider.manifest, self.provider._sandbox)
        with self.assertRaises(ProviderError):
            rogue.parse_stream("anything")

    def test_progress_can_carry_status_but_not_distinguish_it(self):
        """The one honest gap in the vocabulary, measured. A consumer that wants
        to show 'loading model, 40%' separately from 'generated a token' has to
        read data['native'], which is a provider-private key the orchestrator
        does not define. PROGRESS is a bag."""
        events = self.provider.parse_stream(stream("localmodel_long_stream.jsonl"))
        progress = [e for e in events if e.type == AgentEvent.PROGRESS]
        self.assertGreater(len(progress), 5)
        self.assertEqual({e.type for e in progress}, {AgentEvent.PROGRESS})
        distinct = {e.data.get("native") for e in progress}
        self.assertEqual(distinct, {"session.started", "model.status", "heartbeat",
                                    "tool.request", "tool.result", "session.ended"})
        # Six different meanings, one type, and the only thing separating them
        # is a key no other provider is obliged to set.
        self.assertEqual(len({e.type for e in progress}), 1)

    def test_a_synthesised_terminal_is_indistinguishable_without_provider_keys(self):
        native = self.provider.parse_stream(stream("localmodel_tokens.jsonl"))
        synthetic = provider().parse_stream(stream("localmodel_no_terminal.jsonl"))
        native_end = [e for e in native if e.type == AgentEvent.TURN_COMPLETE][-1]
        synth_end = [e for e in synthetic if e.type == AgentEvent.TURN_COMPLETE][-1]
        self.assertEqual(native_end.type, synth_end.type)
        self.assertEqual(native_end.text, synth_end.text)
        self.assertNotEqual(native_end.data["terminal"], synth_end.data["terminal"])


# --------------------------------------------------------------------------- #
# 5. The real executor: transport-level behaviour
# --------------------------------------------------------------------------- #

SF_MISSIONS = MISSION_MODULES / "sf_missions.py"
_spec = importlib.util.spec_from_file_location("sf_missions", SF_MISSIONS)
sfm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sfm)


def bridge_script(body: str) -> list:
    return [sys.executable, "-c", body]


def ast_imports(path):
    import ast as _ast
    tree = _ast.parse(Path(path).read_text(encoding="utf-8"))
    names = set()
    for node in _ast.walk(tree):
        if isinstance(node, _ast.Import):
            names.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, _ast.ImportFrom) and node.module:
            names.add(node.module.split(".")[0])
    return names


DELTAS = ["The ", "launch ", "is ", "Friday ", "and ", "the ", "release ",
          "contains ", "three ", "workflows."]

SCRIPT_SLOW_TOKENS = f"""
import json, sys, time
w = sys.stdout.write
w(json.dumps({{"event":"session.started","session":"s-live","model":"m"}}) + "\\n")
sys.stdout.flush()
for delta in {DELTAS!r}:
    w(json.dumps({{"event":"token","delta":delta}}) + "\\n")
    sys.stdout.flush()
    time.sleep(0.03)
w(json.dumps({{"event":"generation.done","stop":"eos","usage":{{"completion_tokens":10}}}}) + "\\n")
"""

SCRIPT_FOREVER = """
import json, sys, time
w = sys.stdout.write
w(json.dumps({"event":"session.started","session":"s-forever","model":"m"}) + "\\n")
sys.stdout.flush()
n = 0
while True:
    w(json.dumps({"event":"token","delta":"tok%d " % n}) + "\\n")
    sys.stdout.flush()
    n += 1
    time.sleep(0.02)
"""

SCRIPT_BURST_THEN_HANG = """
import sys, time
w = sys.stdout.write
for i in range(int(sys.argv[1])):
    w('{"event":"token","delta":"tok%06d "}\\n' % i)
sys.stdout.flush()
time.sleep(60)
"""

SCRIPT_HEARTBEAT_ONLY = """
import json, sys, time
w = sys.stdout.write
w(json.dumps({"event":"session.started","session":"s-stall","model":"m"}) + "\\n")
sys.stdout.flush()
n = 0
while True:
    w(json.dumps({"event":"heartbeat","elapsed_ms":n*100}) + "\\n")
    sys.stdout.flush()
    n += 1
    time.sleep(0.05)
"""

SCRIPT_CRASH_MIDSTREAM = """
import json, os, sys
w = sys.stdout.write
w(json.dumps({"event":"session.started","session":"s-crash","model":"m"}) + "\\n")
w(json.dumps({"event":"token","delta":"The launch is Fri"}) + "\\n")
w('{"event":"tok')
sys.stdout.flush()
os._exit(1)
"""

# ~4.5 MB of token records, then the terminal event. MAX_OUTPUT is 2 000 000.
SCRIPT_HUGE = """
import sys
w = sys.stdout.write
for i in range(120000):
    w('{"event":"token","delta":"tok%06d "}\\n' % i)
w('{"event":"generation.done","stop":"eos","usage":{"completion_tokens":120000}}\\n')
sys.stdout.flush()
"""

# One multi-byte character placed so that it straddles the executor's 65536-byte
# read boundary.
SCRIPT_BOUNDARY = """
import sys
head = b'{"event":"token","delta":"'
pad = 65536 - 1 - len(head)
payload = head + b'a' * pad + '\\u20ac'.encode('utf-8') + b'b"}\\n'
payload += b'{"event":"generation.done","stop":"eos","usage":{}}\\n'
sys.stdout.buffer.write(payload)
sys.stdout.buffer.flush()
"""


class _ExecutorHarness:
    """A real Store, a real workspace and a real Executor.

    Streaming children are run through Executor.run_process with sandbox=False,
    the same technique test_missions.py uses for its real cancellation test, and
    the retained log is then handed to the fixture provider.
    """

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sf-localmodel-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.ws = self.base / "Workspaces" / "probe"
        self.ws.mkdir(parents=True)
        (self.ws / "facts.md").write_text("The launch is Friday.\n", encoding="utf-8")
        self.env = mock.patch.dict(os.environ, {
            "SHADOWFETCH_AGENT_WORKSPACES": str(self.ws.parent),
            "SHADOWFETCH_MISSIONS_STATE": str(self.base / "state")})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.store = sfm.Store()
        self.mission = self.store.create(
            kind="report", workspace_value="probe", title="Local model probe",
            prompt="Summarize the launch", inputs=["facts.md"], network="allow")
        mission_states.reach(self.store, self.mission["id"], "running")
        self.executor = sfm.Executor(self.store, self.store.get(self.mission["id"]))
        self.provider = provider()

    def log_path(self, label):
        return self.executor.directory / (label + ".log")

class ExecutorTransportTests(_ExecutorHarness, unittest.TestCase):
    """The half of streaming the provider interface does NOT own."""

    def test_incremental_deltas_survive_the_transport_intact(self):
        """VERDICT PASSES. Ten deltas written 30 ms apart across many reads
        reassemble into exactly one message."""
        code, _tail, log = self.executor.run_process(
            bridge_script(SCRIPT_SLOW_TOKENS), "slow", sandbox=False)
        self.assertEqual(code, 0)
        events = self.provider.parse_stream(log.read_text(encoding="utf-8"))
        self.assertEqual(self.provider.final_message(events), ANSWER)
        self.assertTrue(self.provider.turn_succeeded(events))

    def test_no_event_reaches_the_store_while_the_generation_runs(self):
        """DEFECT for a long-running provider, precisely stated: parse_stream is
        called ONCE, after the process exits, on the whole retained log. Every
        PROGRESS, heartbeat and partial message is therefore post-hoc. A model
        that streams for ten minutes shows a person nothing for ten minutes.

        The interface is not what blocks this -- AgentEvent already has the
        vocabulary. The call site does: Executor.agent_turn does
        provider.parse_stream(log.read_text()) after run_process returns.
        """
        seen = []
        done = threading.Event()

        def run():
            try:
                self.executor.run_process(bridge_script(SCRIPT_SLOW_TOKENS),
                                          "watch", sandbox=False)
            finally:
                done.set()

        worker = threading.Thread(target=run)
        worker.start()
        try:
            deadline = time.monotonic() + 3
            while not done.is_set() and time.monotonic() < deadline:
                seen.append(tuple(e["event"] for e in
                                  self.store.events(self.mission["id"])))
                time.sleep(0.03)
        finally:
            worker.join(timeout=10)
        during = set()
        for snapshot in seen:
            if "process-finished" in snapshot:
                break
            during.update(snapshot)
        self.assertIn("process-started", during)
        self.assertEqual(during - {"queued", "running", "process-started"}, set(),
                         "an event reached the store mid-generation; if this ever "
                         "fires, incremental reporting has been added and this "
                         "verdict should be revisited")

    def test_cancellation_during_an_active_generation_kills_the_stream(self):
        """VERDICT PASSES. A child streaming forever is signalled and reaped
        well inside the bound, and the mission ends as Cancelled."""
        timer = threading.Timer(.4, lambda: self.store.cancel(self.mission["id"]))
        timer.start()
        started = time.monotonic()
        try:
            with self.assertRaises(sfm.Cancelled):
                self.executor.run_process(bridge_script(SCRIPT_FOREVER),
                                          "cancel", sandbox=False)
        finally:
            timer.join()
        self.assertLess(time.monotonic() - started, 3)

    def test_a_cancelled_short_generation_keeps_its_partial_output(self):
        """FIXED. Everything the model had generated used to be thrown away.

        run_process feeds the retained log through sf_redact.StreamRedactor,
        which deliberately HOLDS BACK a tail (DEFAULT_CARRY, 20 608 bytes on
        this build) so a credential cannot straddle a block boundary. Its own
        docstring says "Always flush. Whatever is not flushed is never
        returned". run_process used to flush on the normal path only -- the flush sat
        after proc.wait() INSIDE the try, and the finally: did selector.close()
        / kill_tree() / stdout.close() and nothing else.

        So on the cancel path, and equally on the deadline path, the last
        ~20 KB never reached the file. A generation shorter than that left a
        ZERO-BYTE log: the person who pressed cancel was shown nothing at all of
        what the model had already produced. The flush now sits in a finally: of
        its own inside the open file, so every exit path writes the carry.

        Neither shipped provider makes this visible. ffmpeg at loglevel=error
        emits almost nothing worth keeping, and a cancelled Codex turn has no
        partial answer to lose because Codex only emits completed items.
        """
        timer = threading.Timer(.4, lambda: self.store.cancel(self.mission["id"]))
        timer.start()
        try:
            with self.assertRaises(sfm.Cancelled):
                self.executor.run_process(bridge_script(SCRIPT_FOREVER),
                                          "short-cancel", sandbox=False)
        finally:
            timer.join()
        log = self.log_path("short-cancel")
        self.assertTrue(log.is_file())
        self.assertGreater(log.stat().st_size, 0,
                           "a cancelled generation shorter than the redactor carry "
                           "window wrote a zero-byte log again")
        events = self.provider.parse_stream(log.read_text(encoding="utf-8"))
        self.assertTrue(self.provider.final_message(events).startswith("tok0 "),
                        "the partial answer did not survive cancellation")
        # A stream carries no terminal event here, so the adapter SYNTHESISES
        # one -- and nothing in a byte stream distinguishes "the process was
        # killed" from "the process finished". Only the orchestrator knows, and
        # it knows by raising Cancelled above, before parse_stream is ever
        # consulted on the real path. Asserted rather than hidden because a
        # future feature that showed a person their partial output WOULD have to
        # consult it, and would have to supply that fact itself.
        self.assertTrue(self.provider.turn_succeeded(events),
                        "a synthesised terminal cannot see the kill; if this now "
                        "fails, something learned to tell the two apart")

    def test_a_cancelled_long_generation_keeps_all_of_its_output(self):
        """The same fix, measured on the other side of the carry threshold.

        The burst completes long before the cancel timer fires, so the byte
        count is exact: it used to come up short by exactly DEFAULT_CARRY --
        the newest text on screen, for a token stream -- and now matches what
        the child emitted.
        """
        records = 3000
        timer = threading.Timer(.6, lambda: self.store.cancel(self.mission["id"]))
        timer.start()
        try:
            with self.assertRaises(sfm.Cancelled):
                self.executor.run_process(
                    bridge_script(SCRIPT_BURST_THEN_HANG) + ["3000"],
                    "long-cancel", sandbox=False)
        finally:
            timer.join()
        text = self.log_path("long-cancel").read_text(encoding="utf-8")
        self.assertGreater(len(text), 0)
        self.assertEqual(len(text.splitlines()), records,
                         f"{records - len(text.splitlines())} of {records} generated "
                         f"records were held back and never flushed (the carry window "
                         f"is {sf_redact.DEFAULT_CARRY} bytes, about "
                         f"{sf_redact.DEFAULT_CARRY // 39} records)")
        self.assertTrue(text.endswith("\n"),
                        "the log ends mid-record, so the flush cut the carry short")
        events = self.provider.parse_stream(text)
        self.assertTrue(self.provider.final_message(events).startswith("tok000000 "))
        # A stream carries no terminal event here, so the adapter SYNTHESISES
        # one -- and nothing in a byte stream distinguishes "the process was
        # killed" from "the process finished". Only the orchestrator knows, and
        # it knows by raising Cancelled above, before parse_stream is ever
        # consulted on the real path. Asserted rather than hidden because a
        # future feature that showed a person their partial output WOULD have to
        # consult it, and would have to supply that fact itself.
        self.assertTrue(self.provider.turn_succeeded(events),
                        "a synthesised terminal cannot see the kill; if this now "
                        "fails, something learned to tell the two apart")

    def test_a_stalled_stream_is_bounded_only_by_the_mission_deadline(self):
        """VERDICT: copes, with a named limitation. There is no idle timeout
        anywhere. A model server that heartbeats but never generates runs until
        the whole mission budget is spent -- up to two hours."""
        self.executor.deadline = time.monotonic() + 1.2
        started = time.monotonic()
        with self.assertRaises(sfm.MissionError) as caught:
            self.executor.run_process(bridge_script(SCRIPT_HEARTBEAT_ONLY),
                                      "stall", sandbox=False)
        elapsed = time.monotonic() - started
        self.assertIn("execution time budget", str(caught.exception))
        self.assertLess(elapsed, 4)
        self.assertGreater(elapsed, 1)
        events = self.provider.parse_stream(
            self.log_path("stall").read_text(encoding="utf-8"))
        self.assertFalse(self.provider.turn_succeeded(events))
        # The deadline path used to lose the log for the same unflushed-redactor
        # reason as cancellation; both exits are covered here so neither can
        # regress alone. What the model produced before the deadline survives.
        self.assertGreater(self.log_path("stall").stat().st_size, 0,
                           "the deadline path threw away the held-back output")

    def test_a_server_crash_mid_record_is_reported_by_both_layers(self):
        code, _tail, log = self.executor.run_process(
            bridge_script(SCRIPT_CRASH_MIDSTREAM), "crash", sandbox=False)
        self.assertEqual(code, 1)
        events = self.provider.parse_stream(log.read_text(encoding="utf-8"))
        self.assertFalse(self.provider.turn_succeeded(events))
        self.assertEqual(events[-1].data["reason"], "disconnected")

    def test_a_long_generation_keeps_its_terminal_event_past_the_output_cap(self):
        """FIXED, and it was the most consequential defect found.

        run_process stops writing the retained log at MAX_OUTPUT (2 000 000
        bytes). It used to keep only the FIRST two megabytes -- and a provider's
        terminal event is by definition at the END. So a local model generating
        more than about 2 MB of stream exited 0, having succeeded, and
        Executor.agent_turn raised 'did not record a complete successful turn'
        because the turn-complete event had been truncated away. The mission
        failed and the receipt blamed the provider.

        A marked tail window is now kept as well, begun at the first record
        boundary so no adapter is handed a spliced half-record.

        Neither shipped provider can hit this: Codex emits one record per
        completed item and ffmpeg at loglevel=error emits almost nothing.
        """
        code, _tail, log = self.executor.run_process(
            bridge_script(SCRIPT_HUGE), "huge", sandbox=False)
        self.assertEqual(code, 0, "the provider itself succeeded")
        size = log.stat().st_size
        self.assertGreaterEqual(size, sfm.MAX_OUTPUT - 131072)
        text = log.read_text(encoding="utf-8")
        self.assertIn(sfm.TRUNCATION_NOTE.decode(), text,
                      "the truncation is not disclosed in the log the person reads")
        self.assertIn("generation.done", text,
                      "the terminal event was truncated away again")
        events = self.provider.parse_stream(text)
        self.assertTrue(
            self.provider.turn_succeeded(events),
            "exit 0 with a real answer still did not record a successful turn")
        # The answer itself is still truncated -- the head is what survives --
        # but the turn is no longer misreported as a provider failure.
        self.assertTrue(self.provider.final_message(events).startswith("tok000000 "))

    def test_a_multibyte_character_on_the_read_boundary(self):
        """Recorded behaviour of the transport, whichever way it lands.

        run_process used to decode EACH 65536-byte read independently
        (block.decode('utf-8', 'replace')), so a character straddling a read
        boundary became replacement characters -- and the turn still succeeded,
        so the person was shown corrupt text with nothing indicating it. One
        incremental decoder now spans the life of the process.
        """
        code, _tail, log = self.executor.run_process(
            bridge_script(SCRIPT_BOUNDARY), "boundary", sandbox=False)
        self.assertEqual(code, 0)
        text = log.read_text(encoding="utf-8")
        events = self.provider.parse_stream(text)
        answer = self.provider.final_message(events)
        self.assertEqual(len(text.splitlines()), 2)
        # ASSERTED OUTCOME -- see the module docstring. If this flips back, the
        # per-block decode returned and the text is being silently corrupted.
        self.assertNotIn("�", text,
                         "a character on the read boundary became replacement chars")
        self.assertIn("€", text,
                      "the euro sign did not survive the read boundary")
        # It is still absent from the final MESSAGE, and that is the provider's
        # own doing: this adapter caps a message at MAX_MESSAGE_CHARS (64 000)
        # and the delta is longer, so its last characters -- including this one
        # -- are cut by the adapter after the transport delivered them intact.
        # Distinguishing the two is the whole point of asserting on both.
        self.assertNotIn("€", answer)
        self.assertEqual(len(answer), adapter.MAX_MESSAGE_CHARS)


class AgentTurnEndToEndTests(_ExecutorHarness, unittest.TestCase):
    """The whole of Executor.agent_turn, driven by the streaming provider.

    run_invocation is replaced by a stub that returns a captured stream, so no
    sandbox, no Firebreak and no model server is needed. Everything else --
    accepts(), build_invocation(), the prompt file, verify at the boundary,
    parse_stream, turn_succeeded, final_message, usage, the inference record --
    is the real orchestrator code path.
    """

    def setUp(self):
        super().setUp()
        self.executor._provider = self.provider
        # This provider refuses a network; the mission was created with one
        # because only Codex offers sourced_report in this tree.
        self.executor.mission["config"]["network"] = "none"
        self.calls = []

    def stub(self, fixture, code=0):
        log = self.executor.directory / "local-model.log"
        log.write_text(stream(fixture), encoding="utf-8")

        def run_invocation(invocation, secrets=None):
            self.calls.append(invocation)
            return code, "", log

        return mock.patch.object(self.executor, "run_invocation", run_invocation)

    def test_a_token_stream_with_no_native_terminal_completes_a_real_turn(self):
        """VERDICT PASSES end to end. A provider whose answer exists only as
        accumulated deltas, and whose stream carries no turn.completed at all,
        goes through agent_turn unchanged and records an inference."""
        with self.stub("localmodel_no_terminal.jsonl"):
            answer = self.executor.agent_turn("Summarize", read_only=True)
        self.assertEqual(answer, ANSWER)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.calls[0].executable, "/usr/bin/true")
        self.assertEqual(self.calls[0].sandbox.network, "none")
        self.assertEqual(len(self.executor.inferences), 1)
        self.assertEqual(self.executor.inferences[0]["provider"], PROVIDER_ID)
        self.assertFalse((self.executor.directory / "agent-request.txt").exists(),
                         "the prompt must not outlive the turn")

    def test_a_full_token_stream_records_its_usage_on_the_inference(self):
        with self.stub("localmodel_tokens.jsonl"):
            answer = self.executor.agent_turn("Summarize", read_only=True)
        self.assertEqual(answer, ANSWER)
        self.assertEqual(self.executor.inferences[0]["usage"],
                         {"prompt_tokens": 812, "completion_tokens": 11,
                          "tokens_per_second": 38.4})

    def test_a_truncated_stream_fails_the_turn_and_is_never_retried(self):
        """VERDICT: the orchestrator has no reconnect and no resume, and that is
        deliberate. One turn is one process; a disconnect fails the mission and
        recovery is a whole-mission retry that starts over."""
        with self.stub("localmodel_disconnect.jsonl"):
            with self.assertRaises(sfm.MissionError) as caught:
                self.executor.agent_turn("Summarize", read_only=True)
        self.assertIn("did not record a complete successful turn", str(caught.exception))
        self.assertEqual(len(self.calls), 1, "no reconnect, no second attempt")
        self.assertEqual(self.executor.inferences, [])

    def test_a_nonzero_exit_fails_before_the_stream_is_even_parsed(self):
        with self.stub("localmodel_tokens.jsonl", code=3):
            with self.assertRaises(sfm.MissionError) as caught:
                self.executor.agent_turn("Summarize", read_only=True)
        self.assertIn("exit 3", str(caught.exception))
        self.assertEqual(self.executor.inferences, [])

    def test_a_generation_that_produced_only_empty_deltas_is_refused(self):
        with self.stub("localmodel_empty_chunks.jsonl"):
            with self.assertRaises(sfm.MissionError) as caught:
                self.executor.agent_turn("Summarize", read_only=True)
        self.assertIn("returned no final report message", str(caught.exception))

    def test_a_non_dict_usage_is_written_into_the_inference_record_unchecked(self):
        """PHASE2_REMAINING_RISKS section 8, reproduced on the real path."""
        with self.stub("localmodel_bad_usage.jsonl"):
            self.executor.agent_turn("Summarize", read_only=True)
        self.assertEqual(self.executor.inferences[0]["usage"], "not-a-dict")

    def test_session_reuse_reaches_the_argv_of_the_second_real_turn(self):
        """VERDICT PASSES. Two consecutive agent_turns on one Executor: the
        second resumes the session the first opened."""
        self.executor.mission["config"]["session_reuse"] = True
        with self.stub("localmodel_tokens.jsonl"):
            self.executor.agent_turn("First", read_only=True)
        self.assertNotIn("--session", self.calls[0].argv)
        with self.stub("localmodel_tokens.jsonl"):
            self.executor.agent_turn("Second", read_only=True)
        self.assertIn("--session", self.calls[1].argv)
        self.assertIn("s-1a2b3c", self.calls[1].argv)


class OrchestratorSurvivalTests(unittest.TestCase):
    """A provider cannot take Mission Control down, whatever it emits."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sf-localmodel-survive-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.ws = self.base / "Workspaces" / "probe"
        self.ws.mkdir(parents=True)
        (self.ws / "facts.md").write_text("The launch is Friday.\n", encoding="utf-8")
        self.env = mock.patch.dict(os.environ, {
            "SHADOWFETCH_AGENT_WORKSPACES": str(self.ws.parent),
            "SHADOWFETCH_MISSIONS_STATE": str(self.base / "state")})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.store = sfm.Store()

    def create(self):
        return self.store.create(kind="report", workspace_value="probe",
                                 title="Survival", prompt="Summarize the launch",
                                 inputs=["facts.md"], network="allow")

    def test_a_provider_error_during_a_turn_fails_the_mission_with_a_receipt(self):
        mission = self.create()
        mission_approvals.approve(self.store, mission)

        def explode(executor, prompt, **kwargs):
            raise ProviderError("Unknown agent event type: 'text-delta'")

        with mock.patch.object(sfm.Executor, "agent_turn", explode):
            result = sfm.run_mission(self.store, mission["id"])
        self.assertEqual(result["state"], "failed")
        self.assertIn("text-delta", result["error"])
        self.assertTrue(Path(result["receipt"]).is_file())
        # ... and the worker is still usable afterwards.
        again = self.create()
        self.assertEqual(self.store.get(again["id"])["state"], "queued")

    def test_the_registry_is_a_process_wide_singleton(self):
        """The mechanism behind SessionStateTests' leak, asserted on the real
        orchestrator rather than on a fixture registry."""
        self.assertIs(sfm.registry(), sfm.registry())
        usable = [p.id for p in sfm.registry().list()]
        if not usable:
            self.skipTest("no usable providers registered in this environment")
        self.assertIs(sfm.registry().get(usable[0]), sfm.registry().get(usable[0]),
                      "one adapter instance serves every mission in this process")


# --------------------------------------------------------------------------- #
# 6. The fixture must stay a fixture
# --------------------------------------------------------------------------- #

class FixtureHygieneTests(unittest.TestCase):

    def test_the_local_model_provider_does_not_ship(self):
        self.assertFalse((SHIPPED_MANIFESTS / "conformance-localmodel.json").exists())
        self.assertFalse(
            (MISSION_MODULES / "sf_provider_conformance_localmodel.py").exists())
        self.assertEqual(sorted(p.name for p in SHIPPED_MANIFESTS.glob("*.json")
                                if "conformance" in p.name), [])

    def test_no_protected_file_mentions_it(self):
        for relative in PROTECTED_FILES:
            text = (REPO_ROOT / relative).read_text(encoding="utf-8")
            with self.subTest(file=relative):
                for token in ("conformance-localmodel", "conformance_localmodel",
                              "ConformanceLocalModel", "local_model_bridge"):
                    self.assertNotIn(token, text)

    def test_exercising_it_changes_no_protected_file(self):
        before = protected_digests()
        case = ProviderCase(LOCAL_MODEL_REGISTRY, PROVIDER_ID, LOCAL_PROFILE, "proof")
        result, output = run_conformance(case)
        self.assertTrue(result.wasSuccessful(), output)
        self.assertGreater(result.testsRun, 15)
        self.assertEqual(before, protected_digests())

    def test_it_declares_no_network_and_no_credential(self):
        """The safety constraint, asserted rather than promised: this fixture
        cannot be used to reach a host loopback service even by accident."""
        manifest = LOCAL_MODEL_REGISTRY.manifest(PROVIDER_ID)
        self.assertEqual(manifest["network_policy"], "none")
        self.assertEqual(manifest.get("egress_allowlist"), [])
        self.assertEqual(manifest["credential_ids"], [])
        sandbox = sf_providers.sandbox_from_manifest(manifest)
        self.assertEqual(sandbox.firebreak_network, "none")
        imported = ast_imports(FIXTURE_ADAPTER)
        self.assertEqual(imported,
                         {"__future__", "json", "re", "sys", "pathlib", "sf_providers"},
                         "the fixture adapter imports something it should not")
        for banned in ("socket", "ssl", "http", "urllib", "requests", "asyncio",
                       "subprocess", "selectors"):
            self.assertNotIn(banned, imported,
                             f"the fixture adapter must contain no transport code: {banned}")


if __name__ == "__main__":  # pragma: no cover
    unittest.main(verbosity=2)
