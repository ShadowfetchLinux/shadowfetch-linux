"""A local-model-shaped provider, used only by the provider probe suite.

PHASE 2.5 ARCHITECTURAL STRESS TEST. This is a TEST FIXTURE. It does not ship,
no shipped manifest names it, and it is not registered on any real system. It
exists to answer one question with executed tests rather than opinion:

    does AgentProvider genuinely carry a streaming, stateful, long-lived
    provider, or does it quietly assume "request -> stream -> turn.completed"?

It is deliberately unlike BOTH shipped providers in every way that matters:

  Codex          one JSONL object per line, one object per completed item,
                 an explicit turn.completed, cloud credential, network allowed.
  offline-media  a fixed number of short deterministic ffmpeg runs, no turn
                 protocol at all, failure carried in the exit status.
  this           a long-lived NDJSON stream of INCREMENTAL TOKEN DELTAS, where
                 the answer a person reads exists in no single event and must
                 be accumulated; an explicit session that can outlive one
                 submission and be resumed; a terminal event that is sometimes
                 absent; heartbeats; tool call/result rounds; and no credential
                 and no network at all.

TRANSPORT: OPTION A -- fake/injected, conformance only
------------------------------------------------------
The real thing this fixture models is a model server on the host's loopback
interface. It is NOT wired to one, and must not be.

Firebreak has exactly two network postures (`shadowfetch-firebreak --net`
accepts only "none" and "allow"). "none" is `bwrap --unshare-net`, so the
sandbox has its own empty network namespace and cannot see the host's
127.0.0.1 at all. "allow" shares the HOST network namespace with no filtering
whatsoever -- PHASE2_REMAINING_RISKS.md sections 1 and 2 record that
`egress_allowlist` and `masked_paths` are declared and enforced nowhere. So the
only way to make the sandbox reach a host-loopback model server today is to
give it the entire host network, including the whole internet, unfiltered.
That is precisely the host-loopback bypass this work was told not to build.

Therefore:

  * the manifest declares `network_policy: "none"` -- the posture the intended
    future broker-mediated local-model channel is supposed to run under;
  * the provider never opens a socket, and there is no socket code here;
  * everything that would need the server -- model discovery, readiness,
    "model unavailable", "server unavailable" -- goes through TRANSPORT, a
    module-level seam that is None by default and is INJECTED by tests;
  * the generation stream itself arrives the way every provider's stream
    arrives today: as the standard output of the invoked program. Captured
    NDJSON fixtures under tests/fixtures/providers/streams stand in for it.

That last point is itself a finding and it is recorded here rather than in a
comment nobody reads: the current seam has no concept of a transport, because
a provider IS a process and its stream IS that process's stdout. A local model
reached over a socket must therefore be fronted by a bridge program that the
sandbox executes. The interface is transport-agnostic because it never sees the
transport -- which is a genuine strength, and it is why no transport
abstraction is proposed.

NOT-YET-ENFORCED, stated plainly: TRANSPORT below is a test seam. It is not a
security boundary, it is not a broker, and nothing in Firebreak knows about it.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

try:
    from sf_providers import (Acceptance, AgentEvent, AgentProvider, Capability,
                              Invocation, ProviderError, Readiness)
except ImportError:  # source tree
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from sf_providers import (Acceptance, AgentEvent, AgentProvider, Capability,
                              Invocation, ProviderError, Readiness)

# Stands in for /usr/libexec/shadowfetch/local-model-bridge. The manifest
# declares this exact path with executable.kind "absolute" and the conformance
# suite checks the two agree. The program is never executed by the suite.
PROGRAM = "/usr/bin/true"

MODEL_ROOT = "/usr/share/shadowfetch/models"

TRANSPORT = None
"""NOT-YET-ENFORCED test seam. None means 'no local model server is reachable'.

A test injects an object with:
    .available          -> bool     the server answered at all
    .models()           -> tuple    model ids it has loaded or can load
    .default_model()    -> str      what it would use when none is named

It is deliberately NOT a socket, NOT a broker and NOT a security control. See
the module docstring for why a real localhost transport cannot exist yet.
"""

# A session identity recovered from an untrusted stream is used to build an
# argv, so it is constrained here rather than trusted.
SESSION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

MAX_MESSAGE_CHARS = 64_000
MAX_TEXT = 2_000


class ConformanceLocalModelProvider(AgentProvider):
    """Local model bridge: incremental token deltas over a long-lived stream."""

    CAPABILITIES = (Capability.CODE_CHANGE, Capability.SOURCED_REPORT)

    def __init__(self, manifest, sandbox):
        super().__init__(manifest, sandbox)
        # Session state that survives a submission. This is the "stateful"
        # half of the stress test, and it is exactly where the current seam
        # turns out to be uncomfortable: see test_provider_localmodel.py,
        # SessionStateTests.
        self._session = None
        self._last_terminal = None

    # -- session ------------------------------------------------------------
    @property
    def session(self):
        return self._session

    def forget_session(self):
        """There is no close_session() on AgentProvider, so this is the only
        way to drop session state -- and nothing in the orchestrator calls it,
        because the orchestrator does not know it exists."""
        self._session = None

    # -- readiness ----------------------------------------------------------
    def readiness(self) -> Readiness:
        bridge = Path(PROGRAM)
        installed_program = bridge.is_file()
        transport = TRANSPORT
        missing = []
        facts = {
            "bridge": PROGRAM,
            "model_root": MODEL_ROOT,
            "requires_credentials": False,
            "requires_network": False,
            "transport": "injected fixture" if transport is not None else "none",
        }
        if not installed_program:
            missing.append("local model bridge")
        models = ()
        if transport is None or not getattr(transport, "available", False):
            missing.append("local model server")
        else:
            models = tuple(transport.models() or ())
            facts["models"] = list(models)
            facts["default_model"] = transport.default_model()
            if not models:
                missing.append("a loaded model")
        installed = installed_program and bool(models)
        return Readiness(
            installed=installed,
            # Nothing to authenticate against: this provider has no account and
            # no credential. Saying so keeps the UI from inventing a sign-in
            # prompt, the same choice offline-media makes.
            authenticated=True,
            missing=tuple(missing),
            facts=facts,
            reason="" if installed else (
                "Start the local model service and load a model. This provider "
                "runs entirely on this machine and needs no account."),
        )

    # -- acceptance ---------------------------------------------------------
    def accepts(self, capability: str, config: dict) -> Acceptance:
        base = super().accepts(capability, config)
        if not base.ok:
            return base
        config = config or {}
        if config.get("network") not in (None, "none"):
            return Acceptance.no(
                "The local model runs entirely on this machine and will not be "
                "given a network connection.")
        wanted = config.get("model")
        if wanted:
            transport = TRANSPORT
            if transport is None or not getattr(transport, "available", False):
                return Acceptance.no(
                    "The local model service is not running, so a model cannot "
                    "be chosen for this mission.")
            if wanted not in (transport.models() or ()):
                return Acceptance.no(
                    f"No local model named {wanted} is loaded. Loaded models: "
                    + (", ".join(transport.models()) or "none"))
        return Acceptance.yes()

    # -- invocation ---------------------------------------------------------
    def build_invocation(self, capability: str, request: dict) -> Invocation:
        if not self.supports(capability):
            raise ProviderError(
                f"The local model bridge does not perform {capability}")
        request = request or {}
        prompt = request.get("prompt_path")
        if not prompt:
            raise ProviderError("The local model bridge requires a prompt file")
        config = request.get("config") or {}
        read_only = (capability == Capability.SOURCED_REPORT
                     or bool(request.get("read_only")))
        sandbox = self.sandbox_for(capability, config)
        if read_only:
            sandbox = sandbox.narrow(workspace_mode="read-only")
        argv = ["serve-turn", "--protocol", "ndjson-v1", "--stream", "tokens",
                "--model-root", MODEL_ROOT]
        if config.get("model"):
            argv += ["--model", str(config["model"])]
        # Session REUSE is opt-in per mission. When it is on, the id recovered
        # from a previous turn's stream is handed back to the bridge, which is
        # how a stateful provider keeps a warm KV cache between submissions.
        # The state lives on this provider object, and see the note in
        # forget_session(): nothing ever clears it.
        if config.get("session_reuse") and self._session:
            argv += ["--session", self._session]
        return Invocation(
            executable=PROGRAM,
            argv=tuple(argv),
            env_allowlist=tuple(self.manifest.get("credential_ids") or ()),
            sandbox=sandbox,
            stdin_path=str(prompt),
            label=request.get("label", "local-model"),
        )

    # -- stream -------------------------------------------------------------
    def parse_stream(self, text: str):
        """Normalise an NDJSON token stream into AgentEvents.

        The interesting property: the answer a person reads exists in NO single
        native event. It is the concatenation of every `token` delta, flushed
        as one MESSAGE at each generation boundary. That is only expressible
        because parse_stream is handed the WHOLE stream at once.

        Untrusted input. It must never raise, whatever arrives.
        """
        text = text or ""
        events = []
        buffer = []
        emitted_terminal = False
        saw_error = False
        truncated = False

        lines = text.split("\n")
        # NDJSON: a final fragment with no trailing newline is an unterminated
        # record, which is what a mid-stream disconnect looks like from here.
        tail = lines[-1] if lines else ""
        body = lines[:-1] if lines else []

        def flush():
            nonlocal buffer
            joined = "".join(buffer)
            buffer = []
            if joined:
                events.append(AgentEvent(AgentEvent.MESSAGE,
                                         joined[:MAX_MESSAGE_CHARS]))

        def handle(raw, *, partial=False):
            nonlocal emitted_terminal, saw_error
            kind = raw.get("event")
            if kind == "token":
                delta = raw.get("delta")
                if isinstance(delta, str):
                    buffer.append(delta)
                else:
                    events.append(AgentEvent(AgentEvent.LOG,
                                             f"token event with no text delta: {delta!r}"[:MAX_TEXT]))
                return
            if kind == "session.started":
                sid = raw.get("session")
                if isinstance(sid, str) and SESSION_ID.match(sid):
                    self._session = sid
                events.append(AgentEvent(AgentEvent.PROGRESS, "", {
                    "session": raw.get("session") if isinstance(raw.get("session"), str) else None,
                    "model": raw.get("model") if isinstance(raw.get("model"), str) else None,
                    "native": "session.started"}))
                return
            if kind == "session.ended":
                events.append(AgentEvent(AgentEvent.PROGRESS, "",
                                         {"native": "session.ended"}))
                return
            if kind in ("model.status", "heartbeat", "tool.request", "tool.result"):
                data = {"native": kind}
                for key in ("state", "progress", "elapsed_ms", "name", "id", "ok"):
                    if key in raw:
                        value = raw[key]
                        if isinstance(value, (str, int, float, bool)) or value is None:
                            data[key] = value
                events.append(AgentEvent(AgentEvent.PROGRESS, "", data))
                return
            if kind == "generation.done":
                flush()
                usage = raw.get("usage")
                if usage is not None:
                    events.append(AgentEvent(AgentEvent.USAGE, "", {"usage": usage}))
                events.append(AgentEvent(AgentEvent.TURN_COMPLETE, "", {
                    "usage": usage,
                    "stop": raw.get("stop") if isinstance(raw.get("stop"), str) else None,
                    "terminal": "native"}))
                emitted_terminal = True
                self._last_terminal = "native"
                return
            if kind == "cancelled":
                flush()
                saw_error = True
                events.append(AgentEvent(
                    AgentEvent.ERROR,
                    f"generation was cancelled ({raw.get('reason') or 'no reason given'})"[:MAX_TEXT],
                    {"native": "cancelled"}))
                return
            if kind == "error":
                flush()
                saw_error = True
                events.append(AgentEvent(
                    AgentEvent.ERROR,
                    str(raw.get("message") or raw.get("code") or "error")[:MAX_TEXT],
                    {"native": "error",
                     "code": raw.get("code") if isinstance(raw.get("code"), str) else None}))
                return
            # An event name this adapter has never seen. Carried, never dropped
            # and never raised: a future model server that adds an event must
            # not be able to fail a mission by mentioning it.
            events.append(AgentEvent(
                AgentEvent.LOG,
                f"unrecognised local model event {kind!r}"[:MAX_TEXT],
                {"native": kind if isinstance(kind, str) else None,
                 "partial": partial}))

        for line in body:
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except ValueError:
                events.append(AgentEvent(AgentEvent.LOG, line[:MAX_TEXT]))
                continue
            if not isinstance(raw, dict):
                events.append(AgentEvent(AgentEvent.LOG, line[:MAX_TEXT]))
                continue
            handle(raw)

        stripped_tail = tail.strip()
        if stripped_tail:
            # Bytes after the last newline. A complete object here still means
            # the stream stopped without terminating its record separator.
            truncated = True
            try:
                raw = json.loads(stripped_tail)
            except ValueError:
                events.append(AgentEvent(AgentEvent.LOG, stripped_tail[:MAX_TEXT],
                                         {"unterminated": True}))
            else:
                if isinstance(raw, dict):
                    handle(raw, partial=True)
                else:
                    events.append(AgentEvent(AgentEvent.LOG, stripped_tail[:MAX_TEXT],
                                             {"unterminated": True}))

        if emitted_terminal and not buffer:
            return events

        if truncated and not emitted_terminal:
            # A disconnect. Keep whatever was generated -- it is real output a
            # person may still want -- but never call the turn complete.
            flush()
            events.append(AgentEvent(
                AgentEvent.ERROR,
                "the local model stream ended mid-record; the generation did not "
                "finish", {"native": None, "reason": "disconnected"}))
            return events

        if saw_error and not buffer:
            return events

        pending = "".join(buffer)
        flush()
        if pending:
            # Tokens arrived, the stream ended cleanly, and the server never
            # said generation.done. This is a real local-model case (a bridge
            # that closes its pipe on EOS). The turn is treated as complete and
            # the fact that the terminal event was SYNTHESISED is recorded in
            # data, because AgentEvent has no other way to say it.
            events.append(AgentEvent(AgentEvent.TURN_COMPLETE, "",
                                     {"usage": None, "terminal": "synthesized"}))
            self._last_terminal = "synthesized"
            return events

        if not emitted_terminal and not saw_error:
            events.append(AgentEvent(
                AgentEvent.ERROR,
                "the local model produced no output before the stream ended",
                {"reason": "no-output"}))
        return events
