"""Local model provider: on-device inference, no network, no credentials.

WHAT THIS PROVIDER IS
---------------------
A model that runs on this machine, reached from inside a Firebreak sandbox that
has NO network at all, over ONE named AF_UNIX socket the operator granted. The
sandbox never gets the host's loopback, never gets the LAN and never gets the
internet -- the containment milestone Stage B established is not reopened here.

THE TRANSPORT, AND WHY IT IS THIS ONE
-------------------------------------
Firebreak has exactly two network postures: "none" is `bwrap --unshare-net`,
"allow" adds a slirp4netns NAT with --disable-host-loopback. Neither of them
can reach a TCP service on the host's 127.0.0.1, and "allow" would hand this
provider the whole internet to buy a loopback connection it still would not
get. So a TCP local model server is not reachable, and asking for one would be
asking for the wrong thing.

What IS reachable is a unix domain socket, because AF_UNIX is addressed by a
filesystem path rather than by a network namespace. A socket bind-mounted into
the sandbox is connectable from inside a namespace with no interfaces at all.
That is measured, not assumed -- see tests/test_localmodel_transport.py, which
proves all three halves on this kernel:

    A  --unshare-net + --ro-bind <socket dir>   connect() succeeds, bytes flow
    B  --unshare-net, socket NOT bound          the path does not exist
    C  --unshare-net, TCP to host 127.0.0.1     connection refused

and note that a READ-ONLY bind is enough: sb_permission() denies MAY_WRITE on a
read-only superblock only for regular files, directories and symlinks, so
connect() to a socket inode over a --ro-bind works.

The grant is expressed with machinery that already exists and is already
enforced: `sandbox_profile.read_grants` -> Firebreak `--read` -> bwrap
`--ro-bind`. Firebreak's read_grants() accepts a directory (it refuses a socket
path itself, because it requires is_file() or is_dir()), so the DIRECTORY that
contains the socket is what is granted, and that directory must contain nothing
else. No change to Firebreak is needed and none is asked for.

WHAT RUNS INSIDE
----------------
`/usr/libexec/shadowfetch/local-model-bridge`, a packaged program that connects
to the granted socket, speaks the inference service's HTTP API over it, and
writes ONE normalised NDJSON protocol on stdout. The adapter is coupled to that
protocol and to nothing else, so swapping the service behind the socket changes
the bridge and leaves this file alone.

  SHIPPED, from data/usr/libexec/shadowfetch/local-model-bridge in this same
  package. Where it is not installed -- an older package, a partial install --
  readiness() reports this provider unavailable with a reason, which is the
  honest state and not a failure mode.

STATE
-----
The registry memoises ONE adapter instance per manifest for the life of the
worker, so anything stored on `self` is visible to the next person's mission.
This adapter therefore stores nothing. A session identity is carried in the
REQUEST and re-emitted in the stream; session_from_events() recovers it as a
pure function. (The Phase 2.5 localmodel conformance fixture keeps its session
on the adapter and says in its own docstring that the seam is uncomfortable
there; this is what that finding is worth once it is applied.)

WHAT IS NOT CLAIMED
-------------------
  * The bridge is not a broker. Nothing here mediates a credential, because
    this provider has no credential to mediate.
  * `egress_allowlist` is empty and network_policy is "none", so the
    unenforced-destination-filter gap (Stage C) does not apply to this
    provider at all -- there is no egress to filter.
  * Cancellation: every invocation carries finite cpu/memory/process bounds,
    and the bridge turns SIGTERM into a terminal `cancelled` event and a
    non-zero exit. That the Mission Control cancel button reaches the process
    group is the ORCHESTRATOR's property and is tested there, not here.
"""
from __future__ import annotations

import json
import os
import re
import socket
import stat
import sys
import time
from pathlib import Path

try:
    from sf_providers import (Acceptance, AgentEvent, AgentProvider, Capability,
                              Invocation, ProviderError, Readiness,
                              resolve_executable)
except ImportError:  # source tree
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from sf_providers import (Acceptance, AgentEvent, AgentProvider, Capability,
                              Invocation, ProviderError, Readiness,
                              resolve_executable)


# The program is DECLARED by the manifest (executable.kind "absolute") and this
# constant exists only so readiness and the invocation builder agree with it.
# There is no lookup: no PATH, no which(), no environment. The manifest is the
# single place the path is written down, and build_invocation() reads it from
# there rather than from here.
BRIDGE = "/usr/libexec/shadowfetch/local-model-bridge"

# The socket's file name inside the granted directory. The DIRECTORY comes from
# the manifest's read_grants, so the endpoint the bridge is told to use is by
# construction inside a grant the sandbox actually receives; there is no way to
# point it somewhere the sandbox cannot see, or somewhere it was not granted.
ENDPOINT_NAME = "model.sock"

# The bridge's stdout protocol. Bumped only when the event vocabulary changes
# incompatibly; the adapter refuses to guess at an unknown protocol and instead
# carries unknown events through as logs.
PROTOCOL = "localmodel-ndjson-v1"

# Host-side probe bounds. readiness() is called to paint a UI, so it must fail
# fast and can never hang Mission Control on a wedged socket.
PROBE_CONNECT_TIMEOUT = 1.5
PROBE_READ_TIMEOUT = 2.5
PROBE_MAX_BYTES = 1_048_576
# A per-read timeout alone does not bound a probe: a service that dribbles one
# byte per second resets it on every recv and the loop never ends. The wall
# clock is what actually bounds it, so the wall clock is what is checked.
PROBE_DEADLINE = 6.0

# Default turn bounds, in seconds. Clamped against the manifest's declared
# cpu_seconds in build_invocation(), so a request can lower them and never
# raise them.
DEFAULT_CONNECT_TIMEOUT = 5
DEFAULT_IDLE_TIMEOUT = 120
DEFAULT_DEADLINE = 1800

# Values recovered from an untrusted stream or from a mission config are used to
# build an argv, so their shape is checked rather than trusted.
SESSION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
MODEL_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")

MAX_MESSAGE_CHARS = 200_000
MAX_TEXT = 2_000
MAX_MODELS = 200


# --------------------------------------------------------------------------- #
# Host-side probe of the local inference service
# --------------------------------------------------------------------------- #

def _read_http_response(sock, *, max_bytes=PROBE_MAX_BYTES, deadline=None):
    """Read one HTTP/1.1 response off a connected socket. Bounded, tolerant.

    Deliberately minimal rather than http.client: the only request this adapter
    ever makes host-side is a model listing, and a hand-rolled reader with an
    explicit byte ceiling and an explicit wall-clock bound is easier to reason
    about than a library configured to talk over a socket it did not open.

    BOTH bounds are load-bearing. The byte ceiling stops a service that answers
    with a gigabyte; the deadline stops one that answers with a byte at a time,
    which resets the socket timeout for as long as it likes and is the shape a
    per-read timeout cannot see.
    """
    def out_of_time():
        return deadline is not None and time.monotonic() >= deadline

    chunks = bytearray()
    while b"\r\n\r\n" not in chunks:
        if out_of_time():
            raise ProviderError("the local model service answered too slowly to be usable")
        block = sock.recv(65536)
        if not block:
            break
        chunks += block
        if len(chunks) > max_bytes:
            raise ProviderError("the local model service sent an oversized response header")
    head, _, rest = bytes(chunks).partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    if not lines or not lines[0].startswith(b"HTTP/"):
        raise ProviderError("the local model endpoint did not answer with HTTP")
    try:
        status = int(lines[0].split(b" ")[1])
    except (IndexError, ValueError) as exc:
        raise ProviderError("the local model service sent an unreadable status line") from exc
    length = None
    for line in lines[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            try:
                length = int(value.strip())
            except ValueError:
                length = None
    body = bytearray(rest)
    while length is None or len(body) < length:
        if out_of_time():
            raise ProviderError("the local model service answered too slowly to be usable")
        block = sock.recv(65536)
        if not block:
            break
        body += block
        if len(body) > max_bytes:
            raise ProviderError("the local model service sent an oversized response body")
    if length is not None:
        body = body[:length]
    return status, bytes(body)


def probe_models(endpoint, *, connect_timeout=PROBE_CONNECT_TIMEOUT,
                 read_timeout=PROBE_READ_TIMEOUT):
    """Model ids the local service currently offers, over the granted socket.

    Runs on the HOST, where Mission Control lives; the sandbox is not involved
    and no mission is running. Raises ProviderError with a sentence a person can
    act on. Never raises anything else, so readiness() can report rather than
    crash.
    """
    endpoint = str(endpoint)
    try:
        info = os.stat(endpoint)
    except OSError as exc:
        raise ProviderError(
            f"no local model endpoint at {endpoint}: {exc.strerror or exc}") from exc
    if not stat.S_ISSOCK(info.st_mode):
        raise ProviderError(
            f"{endpoint} exists but is not a socket, so it is not a local model endpoint")
    deadline = time.monotonic() + PROBE_DEADLINE
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.settimeout(connect_timeout)
        try:
            sock.connect(endpoint)
        except OSError as exc:
            raise ProviderError(
                f"the local model service is not answering on {endpoint}: "
                f"{exc.strerror or exc}") from exc
        sock.settimeout(read_timeout)
        request = (b"GET /api/tags HTTP/1.1\r\nHost: localmodel\r\n"
                   b"Accept: application/json\r\nConnection: close\r\n\r\n")
        try:
            sock.sendall(request)
            status, body = _read_http_response(sock, deadline=deadline)
        except socket.timeout as exc:
            raise ProviderError(
                "the local model service did not answer a model listing in time") from exc
        except OSError as exc:
            raise ProviderError(
                f"the local model service dropped the connection: {exc.strerror or exc}") from exc
    finally:
        try:
            sock.close()
        except OSError:
            pass
    if status != 200:
        raise ProviderError(
            f"the local model service refused a model listing (HTTP {status})")
    try:
        document = json.loads(body.decode("utf-8", "replace"))
    except ValueError as exc:
        raise ProviderError("the local model service sent a model listing that is not JSON") from exc
    if not isinstance(document, dict):
        raise ProviderError("the local model service sent a model listing of the wrong shape")
    models = []
    for entry in (document.get("models") or [])[:MAX_MODELS]:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name") or entry.get("model")
        # The listing is untrusted input that ends up in an argv, so the shape
        # is enforced here rather than at the point of use.
        if isinstance(name, str) and MODEL_ID.match(name) and name not in models:
            models.append(name)
    return tuple(models)


# --------------------------------------------------------------------------- #
# The provider
# --------------------------------------------------------------------------- #

class LocalModelProvider(AgentProvider):
    """On-device inference over one explicitly granted unix socket."""

    CAPABILITIES = (Capability.CODE_CHANGE, Capability.SOURCED_REPORT)

    # -- the granted endpoint ---------------------------------------------
    def endpoint_directory(self) -> str:
        """The one directory this provider's manifest grants it.

        Exactly one, deliberately. The socket lives inside a directory that is
        bind-mounted whole, so a second grant would mean a second directory the
        sandbox can read for no reason this provider can justify.
        """
        grants = tuple((self.manifest.get("sandbox_profile") or {}).get("read_grants") or ())
        if len(grants) != 1:
            raise ProviderError(
                "The local model provider expects its manifest to grant exactly one "
                f"directory -- the one holding its endpoint socket -- but it declares "
                f"{len(grants)}. Refusing to guess which one carries the model service.")
        grant = str(grants[0])
        if not grant.startswith("/"):
            raise ProviderError("The local model endpoint grant must be an absolute path")
        return grant

    def endpoint(self) -> str:
        return str(Path(self.endpoint_directory()) / ENDPOINT_NAME)

    def program(self) -> str:
        """The path the MANIFEST declares. Not a lookup, and not this module's
        constant: executable.kind is "absolute", so there is exactly one answer
        and the manifest is where it is written down."""
        block = self.manifest.get("executable") or {}
        path = block.get("path")
        if block.get("kind") != "absolute" or not path or not str(path).startswith("/"):
            raise ProviderError(
                "The local model provider requires a manifest that declares one absolute "
                "bridge program")
        return str(path)

    # -- readiness ---------------------------------------------------------
    def readiness(self) -> Readiness:
        missing = []
        facts = {
            "protocol": PROTOCOL,
            "requires_credentials": False,
            "requires_network": False,
            "transport": "unix socket bind-mounted into a sandbox with no network",
        }

        # resolve_executable() applies the manifest's declared trust tier, so a
        # bridge somebody else could substitute reports as NOT installed rather
        # than as an installed program that will be refused later.
        try:
            bridge = resolve_executable(self.manifest)
        except ProviderError as exc:
            bridge, facts["bridge_error"] = None, str(exc)
        if bridge:
            facts["bridge"] = bridge
        else:
            facts["bridge_declared"] = (self.manifest.get("executable") or {}).get("path", BRIDGE)
            missing.append("local model bridge")

        try:
            endpoint = self.endpoint()
        except ProviderError as exc:
            return Readiness(installed=False, authenticated=True,
                             missing=("endpoint grant",), facts=facts, reason=str(exc))
        facts["endpoint"] = endpoint
        facts["endpoint_directory"] = self.endpoint_directory()

        models = ()
        try:
            models = probe_models(endpoint)
        except ProviderError as exc:
            facts["endpoint_error"] = str(exc)
            missing.append("local model service")
        else:
            facts["models"] = list(models)
            if models:
                facts["default_model"] = models[0]
            else:
                missing.append("a loaded model")

        installed = bool(bridge) and bool(models)
        if installed:
            reason = ""
        elif "local model bridge" in missing:
            reason = (
                "Install the local model bridge, then start a local inference service "
                f"on {endpoint}. This provider runs entirely on this machine and needs "
                "no account and no network connection.")
        else:
            reason = (
                f"Start a local inference service on {endpoint} and load a model. "
                "The sandbox has no network at all, so the model is reached over that "
                "socket and nowhere else.")
        return Readiness(
            installed=installed,
            # Nothing to authenticate against: no account, no credential, no
            # network. Saying so keeps the UI from inventing a sign-in prompt,
            # the same choice the offline exporter makes.
            authenticated=True,
            missing=tuple(missing),
            facts=facts,
            reason=reason,
        )

    # -- acceptance --------------------------------------------------------
    def accepts(self, capability: str, config: dict) -> Acceptance:
        base = super().accepts(capability, config)
        if not base.ok:
            return base
        config = config or {}

        if config.get("network") not in (None, "none"):
            return Acceptance.no(
                "The local model runs entirely on this machine and will not be given a "
                "network connection. Choose a provider that works online, or run this "
                "mission offline.")

        session = config.get("session")
        if session is not None:
            if not isinstance(session, str) or not SESSION_ID.match(session):
                return Acceptance.no(
                    "A local model session name must be 1-64 characters of letters, "
                    "digits, dot, dash or underscore, starting with a letter or digit.")
            if capability == Capability.SOURCED_REPORT or config.get("read_only"):
                return Acceptance.no(
                    "A local model session keeps its conversation in the mission "
                    "workspace, so it cannot be continued by a read-only mission. Run "
                    "this as a code change, or start a fresh turn without a session.")

        for name, value in (("timeout_seconds", config.get("timeout_seconds")),
                            ("idle_timeout_seconds", config.get("idle_timeout_seconds"))):
            if value is None:
                continue
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                return Acceptance.no(
                    f"The local model {name.replace('_', ' ')} must be a whole number of "
                    "seconds greater than zero.")

        wanted = config.get("model")
        if wanted:
            if not isinstance(wanted, str) or not MODEL_ID.match(wanted):
                return Acceptance.no(
                    "A local model name may hold letters, digits and the characters "
                    ". _ : / - and must start with a letter or digit.")
            try:
                available = probe_models(self.endpoint())
            except ProviderError as exc:
                return Acceptance.no(
                    "A model cannot be chosen for this mission because the local model "
                    f"service is not reachable: {exc}")
            if wanted not in available:
                return Acceptance.no(
                    f"No local model named {wanted} is loaded. Loaded models: "
                    + (", ".join(available) or "none"))
        return Acceptance.yes()

    # -- invocation --------------------------------------------------------
    def build_invocation(self, capability: str, request: dict) -> Invocation:
        if not self.supports(capability):
            raise ProviderError(
                f"The local model provider does not perform {capability.replace('_', ' ')}")
        request = request or {}
        prompt = request.get("prompt_path")
        if not prompt:
            raise ProviderError("The local model provider requires a prompt file")
        config = request.get("config") or {}

        read_only = (capability == Capability.SOURCED_REPORT
                     or bool(request.get("read_only")) or bool(config.get("read_only")))
        sandbox = self.sandbox_for(capability, config)
        if read_only:
            sandbox = sandbox.narrow(workspace_mode="read-only")

        # Every bound handed to the bridge is <= the bound the manifest declared
        # and the sandbox will enforce. A request may lower them; nothing can
        # raise them, here or anywhere downstream.
        deadline = _bounded(config.get("timeout_seconds"), DEFAULT_DEADLINE,
                            sandbox.cpu_seconds, "timeout_seconds")
        idle = _bounded(config.get("idle_timeout_seconds"), DEFAULT_IDLE_TIMEOUT,
                        deadline, "idle_timeout_seconds")
        connect = min(DEFAULT_CONNECT_TIMEOUT, deadline)

        argv = ["serve-turn",
                "--protocol", PROTOCOL,
                "--endpoint", self.endpoint(),
                "--stream", "tokens",
                "--connect-timeout", str(connect),
                "--idle-timeout", str(idle),
                "--deadline", str(deadline)]

        model = config.get("model")
        if model:
            if not isinstance(model, str) or not MODEL_ID.match(model):
                raise ProviderError(
                    "A local model name may hold letters, digits and the characters "
                    ". _ : / - and must start with a letter or digit")
            argv += ["--model", model]

        # SESSION LIFECYCLE. The identity travels in the REQUEST and the
        # conversation it names lives in the mission workspace, inside the
        # sandbox. Nothing is stored on this adapter: the registry keeps one
        # instance for the worker's life, so adapter state would be one
        # person's session leaking into the next person's mission.
        session = config.get("session")
        if session:
            if not isinstance(session, str) or not SESSION_ID.match(session):
                raise ProviderError(
                    "A local model session name must be 1-64 characters of letters, "
                    "digits, dot, dash or underscore, starting with a letter or digit")
            if read_only:
                raise ProviderError(
                    "A local model session keeps its conversation in the mission "
                    "workspace, which a read-only mission cannot write")
            argv += ["--session", session]

        if read_only:
            argv.append("--read-only")

        return Invocation(
            executable=self.program(),
            manifest_executable=self.manifest.get("executable"),
            argv=tuple(argv),
            # No credentials at all. The manifest declares none, so this is the
            # empty tuple by construction rather than by intention.
            env_allowlist=tuple(self.manifest.get("credential_ids") or ()),
            sandbox=sandbox,
            stdin_path=str(prompt),
            label=str(request.get("label") or "local-model"),
        )

    # -- stream ------------------------------------------------------------
    def parse_stream(self, text: str):
        """Normalise the bridge's NDJSON into AgentEvents.

        The interesting property, and the reason this provider is worth having
        in the suite: the answer a person reads exists in NO single native
        event. It is the concatenation of every `token` delta, flushed as one
        MESSAGE at each generation boundary. parse_stream is handed the whole
        stream, so that is expressible; a line-at-a-time interface could not
        express it.

        Untrusted input. It must never raise, whatever arrives, and it must
        never store anything on self: see the module docstring.
        """
        text = text or ""
        events = []
        buffer = []
        emitted_terminal = False
        saw_error = False

        lines = text.split("\n")
        # NDJSON: bytes after the final newline are an unterminated record,
        # which is what a mid-stream disconnect looks like from here.
        body, tail = lines[:-1], lines[-1] if lines else ""

        def flush():
            joined = "".join(buffer)
            del buffer[:]
            if joined:
                events.append(AgentEvent(AgentEvent.MESSAGE, joined[:MAX_MESSAGE_CHARS]))

        def carry(raw, key, *, want=str):
            value = raw.get(key)
            return value if isinstance(value, want) else None

        def handle(raw, *, partial=False):
            nonlocal emitted_terminal, saw_error
            kind = raw.get("event")

            if kind == "token":
                delta = raw.get("delta")
                if isinstance(delta, str):
                    buffer.append(delta)
                else:
                    events.append(AgentEvent(
                        AgentEvent.LOG,
                        f"token event carried no text delta: {delta!r}"[:MAX_TEXT]))
                return

            if kind == "session.started":
                events.append(AgentEvent(AgentEvent.PROGRESS, "", {
                    "native": "session.started",
                    # Validated here so a caller recovering the identity from
                    # the stream is never handed a shape that could not have
                    # come from this system.
                    "session": (carry(raw, "session")
                                if SESSION_ID.match(str(raw.get("session") or "")) else None),
                    "model": (carry(raw, "model")
                              if MODEL_ID.match(str(raw.get("model") or "")) else None),
                    "resumed": raw.get("resumed") if isinstance(raw.get("resumed"), bool) else None,
                }))
                return

            if kind in ("session.ended", "model.status", "heartbeat",
                        "tool.request", "tool.result"):
                data = {"native": kind}
                for key in ("state", "progress", "elapsed_ms", "name", "id", "ok", "turns"):
                    if key in raw:
                        value = raw[key]
                        if value is None or isinstance(value, (str, int, float, bool)):
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
                    "stop": carry(raw, "stop"),
                    "model": carry(raw, "model"),
                    "terminal": "native",
                }))
                emitted_terminal = True
                return

            if kind == "cancelled":
                flush()
                saw_error = True
                events.append(AgentEvent(
                    AgentEvent.ERROR,
                    ("the local model turn was cancelled ("
                     + str(raw.get("reason") or "no reason given") + ")")[:MAX_TEXT],
                    {"native": "cancelled", "reason": carry(raw, "reason")}))
                return

            if kind == "error":
                flush()
                saw_error = True
                events.append(AgentEvent(
                    AgentEvent.ERROR,
                    str(raw.get("message") or raw.get("code") or "error")[:MAX_TEXT],
                    {"native": "error", "code": carry(raw, "code")}))
                return

            # An event name this adapter has never seen. Carried, never dropped
            # and never raised: a bridge that grows an event must not be able to
            # fail somebody's mission by mentioning it.
            events.append(AgentEvent(
                AgentEvent.LOG,
                f"unrecognised local model event {kind!r}"[:MAX_TEXT],
                {"native": kind if isinstance(kind, str) else None, "partial": partial}))

        for line in body:
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except ValueError:
                # Firebreak's session trailer and anything else sharing the
                # pipe land here. Carried as a log; never allowed to break the
                # turn either way.
                events.append(AgentEvent(AgentEvent.LOG, line[:MAX_TEXT]))
                continue
            if isinstance(raw, dict):
                handle(raw)
            else:
                events.append(AgentEvent(AgentEvent.LOG, line[:MAX_TEXT]))

        stripped = tail.strip()
        truncated = bool(stripped)
        if truncated:
            try:
                raw = json.loads(stripped)
            except ValueError:
                events.append(AgentEvent(AgentEvent.LOG, stripped[:MAX_TEXT],
                                         {"unterminated": True}))
            else:
                if isinstance(raw, dict):
                    handle(raw, partial=True)
                else:
                    events.append(AgentEvent(AgentEvent.LOG, stripped[:MAX_TEXT],
                                             {"unterminated": True}))

        if emitted_terminal and not buffer:
            return events

        if truncated and not emitted_terminal:
            # A disconnect. Keep whatever was generated -- it is real output a
            # person may still want -- but never call the turn complete.
            flush()
            events.append(AgentEvent(
                AgentEvent.ERROR,
                "the local model stream ended mid-record; the generation did not finish",
                {"native": None, "reason": "disconnected"}))
            return events

        if saw_error and not buffer:
            return events

        pending = "".join(buffer)
        flush()
        if pending:
            # Tokens arrived, the stream ended cleanly, and the bridge never
            # said generation.done -- a real case for a bridge that closes its
            # pipe on end-of-stream. The turn is treated as complete and the
            # fact that the terminal event was SYNTHESISED is recorded in data,
            # because AgentEvent has no other way to say it.
            events.append(AgentEvent(AgentEvent.TURN_COMPLETE, "",
                                     {"usage": None, "terminal": "synthesized"}))
            return events

        if not saw_error:
            events.append(AgentEvent(
                AgentEvent.ERROR,
                "the local model produced no output before the stream ended",
                {"reason": "no-output"}))
        return events

    # -- session recovery --------------------------------------------------
    @staticmethod
    def session_from_events(events):
        """The session identity a turn reported, or None.

        A pure function of the events the orchestrator already persists. It
        exists so a caller can continue a conversation WITHOUT this adapter
        holding state between missions -- which is the whole point.
        """
        for event in events or ():
            if event.type == AgentEvent.PROGRESS and event.data.get("native") == "session.started":
                session = event.data.get("session")
                if isinstance(session, str) and SESSION_ID.match(session):
                    return session
        return None


def _bounded(value, default, ceiling, name):
    """A whole number of seconds in 1..ceiling, defaulting sensibly.

    A request may lower a bound and may never raise one: the ceiling comes from
    the sandbox the registry built from the manifest.
    """
    ceiling = max(1, int(ceiling))
    if value is None:
        return min(int(default), ceiling)
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ProviderError(
            f"The local model {name.replace('_', ' ')} must be a whole number of seconds "
            "greater than zero")
    return min(value, ceiling)
