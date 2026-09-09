"""Claude Code CLI provider adapter.

Everything specific to this agent lives in this file and in the manifest that
names it. Mission Control does not learn the word for it: it asks the registry
for a provider that performs a capability, asks that provider for an
Invocation, runs it with generic plumbing, and reads back normalized
AgentEvents. Nothing in this module is imported by the orchestrator; it becomes
reachable only because a validated, policy-approved manifest names it.

What was VERIFIED about the CLI rather than assumed (2.1.178, on the build
host, by running it):

  * ``--print`` is the non-interactive mode. ``--output-format stream-json``
    REQUIRES ``--verbose``; without it the CLI refuses with
    "When using --print, --output-format=stream-json requires --verbose".
  * The stream is JSON Lines. Line types actually observed:
    ``system``/``init`` (carries session_id, model, tools, permissionMode,
    apiKeySource), ``system``/``api_retry`` (attempt, error_status),
    ``assistant`` (message.content blocks: text, tool_use; message.usage),
    ``user`` (tool_result blocks), and a terminal ``result`` carrying
    ``is_error``, ``usage``, ``total_cost_usd``, ``num_turns``,
    ``permission_denials``.
  * ``result.subtype`` was "success" on a run whose ``is_error`` was true, so
    IS_ERROR is the fact and subtype is not. The parser treats it that way.
  * ``--bare`` reads no user configuration, no hooks, no plugins, no keychain,
    and takes Anthropic authentication STRICTLY from ANTHROPIC_API_KEY. That
    is exactly the posture a sandboxed provider needs, and it is why an
    interactive sign-in on the host does not authenticate a mission (see
    readiness()).
  * ``--permission-mode``, ``--tools``, ``--model`` and ``--session-id`` are
    accepted and are echoed back in the init line, so their effect is
    observable rather than hoped for.
  * ``--settings`` with an inline env block measurably reduces egress: with the
    non-essential-traffic switch OFF the process connected to two distinct
    destinations (the API, and one Google-hosted endpoint), and with it ON,
    across repeated runs, only the API. That is the reason the flag is here.
  * Running this adapter's OWN invocation inside the real sandbox found what no
    fixture could: the payload is uid 0 in an unshared user namespace, and the
    CLI refuses its permission-bypass mode under root, before emitting a single
    JSON line. Every mission would have failed with an unparseable log. See
    SANDBOX_SETTINGS.

One thing deliberately NOT asked for: --include-partial-messages. The
orchestrator reads the retained log after the process ends and hands the whole
text to parse_stream, so token-level chunks would multiply the size of that log
and reach no consumer. Turn-level records are what the receipt, the tool
recorder and the reader all actually use. If incremental reading arrives, that
flag is the one line this file needs.

What is NOT claimed: the credential still reaches the sandbox as an
environment VALUE, because the credential broker does not exist yet. A
provider cannot fix that from inside an adapter, and this file does not
pretend to.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import uuid
from pathlib import Path

try:
    from sf_providers import (AgentEvent, AgentProvider, Acceptance, Invocation,
                              ProviderError, Readiness, Capability, resolve_executable)
except ImportError:  # source tree
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from sf_providers import (AgentEvent, AgentProvider, Acceptance, Invocation,
                              ProviderError, Readiness, Capability, resolve_executable)


# The program is located from the candidate list the MANIFEST declares. There
# is deliberately no lookup helper in this module and nothing it imports
# resolves a program from the environment: an executable whose identity decides
# a security question is never chosen by PATH.

# The settings this run is given, as one compact, stable serialisation computed
# once. argv must be deterministic -- the conformance suite builds the same
# request twice and compares -- so this cannot be re-serialised per call from an
# unordered dict.
#
# CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC was measured: with it off, a real run
# connected to the API and to one further, non-Anthropic destination on every
# attempt; with it on, only the API, three runs out of three.
#
# IS_SANDBOX is not a preference. Firebreak runs the payload in an unshared user
# namespace where it is uid 0, and the CLI refuses the permission mode below
# under root:
#
#     --dangerously-skip-permissions cannot be used with root/sudo privileges
#     for security reasons
#
# That refusal was reached by running this adapter's own invocation inside the
# real sandbox, and it failed before emitting a single JSON line -- so every
# mission would have failed with an unparseable log. The variable states the
# fact the check is really asking about, and it is TRUE here: an unshared
# network namespace, a bound workspace, no host loopback and a fresh home. With
# it set, the same invocation starts and reports the mode it was given.
SANDBOX_SETTINGS = json.dumps(
    {"env": {"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1", "IS_SANDBOX": "1"}},
    sort_keys=True, separators=(",", ":"))

# Where an operator may leave the worker's credential for the idle worker to
# load. Presence is a readiness HINT and nothing more: the value must be in the
# worker's environment for the boundary to inject it, and a file being present
# has never proved a credential is valid.
CREDENTIAL_FILE = ".config/shadowfetch/missions/claude.env"

# The interactive sign-in state. Present on a host where a person signed in --
# and deliberately NOT counted as authentication, because the sandbox is given
# a fresh home and --bare never reads OAuth. Reporting it as authenticated
# would produce a provider that looks ready and fails every mission.
OAUTH_CREDENTIALS = ".claude/.credentials.json"

# Model selection. The aliases are the ones the CLI documents; the pattern
# accepts a full model name. Anything else is refused rather than passed
# through, because this value becomes an argv element.
MODEL_ALIASES = ("fable", "opus", "sonnet", "haiku")
MODEL_NAME = re.compile(r"^claude-[a-z0-9][a-z0-9.-]{1,48}$")

# A tool call's most descriptive argument, for the human-readable "requested
# action" on the durable record. Best effort and explicitly labelled as such:
# the whole input is carried separately as args, so nothing is lost if this
# picks nothing.
ACTION_KEYS = ("command", "file_path", "path", "pattern", "url", "query", "prompt")

# The correlation namespace. A session identifier derived from the mission's
# own request path is deterministic (so argv is), unique per mission
# directory, and can be checked against what the CLI reports back.
SESSION_NAMESPACE = uuid.uuid5(
    uuid.NAMESPACE_URL, "https://www.shadowfetch.com/missions/agent-session")

MAX_MESSAGE = 20000
MAX_TEXT = 2000
MAX_FIELD = 200


def _text(value, limit=MAX_FIELD):
    """A provider-supplied scalar, made safe for a durable record."""
    if value is None:
        return None
    if not isinstance(value, str):
        value = str(value)
    value = value.replace("\x00", "")
    return value[:limit]


def _scalar(value, limit=MAX_FIELD):
    """Like _text, but a number stays a number.

    Coercing 401 to "401" would make an audit reader compare a status code
    against a string, and every consumer would have to know which fields this
    adapter happened to stringify.
    """
    if isinstance(value, bool) or isinstance(value, (int, float)):
        return value
    return _text(value, limit)


class ClaudeCodeProvider(AgentProvider):
    """The Claude Code CLI, run inside Firebreak with explicit network consent."""

    CAPABILITIES = (Capability.CODE_CHANGE, Capability.SOURCED_REPORT)

    # -- readiness ---------------------------------------------------------
    def readiness(self) -> Readiness:
        """Installed and authenticated are separate questions, and neither is
        answered by running the program.

        A subprocess here would make a UI listing providers spawn an agent
        binary per refresh, and its answer would still be about the HOST. What
        decides a mission is whether the identity this manifest declares has a
        value in the worker's environment, because that is the only channel
        that survives into the sandbox.
        """
        binary = resolve_executable(self.manifest)
        missing = []
        facts = {}
        if binary:
            facts["executable"] = binary
        else:
            missing.append("claude executable")

        identity = (self.manifest.get("credential_ids") or [None])[0]
        env_key = bool(identity and os.environ.get(identity))
        facts["credential_identity"] = identity
        facts["api_key_configured"] = env_key

        credential_file = Path.home() / CREDENTIAL_FILE
        present = False
        try:
            st = credential_file.stat()
            present = (credential_file.is_file() and not credential_file.is_symlink()
                       and st.st_uid == os.getuid() and not st.st_mode & 0o077)
        except OSError:
            present = False
        facts["worker_environment_file"] = str(credential_file)
        facts["worker_environment_file_present"] = present

        # Recorded, and deliberately not counted. This is the difference
        # between "this machine has an agent signed in" and "a mission can
        # authenticate", and conflating them is how a provider comes to look
        # available and fail on first use.
        try:
            interactive = (Path.home() / OAUTH_CREDENTIALS).is_file()
        except OSError:
            interactive = False
        facts["interactive_sign_in_present"] = interactive
        facts["interactive_sign_in_usable_for_missions"] = False

        authenticated = bool(env_key or present)
        if not authenticated:
            missing.append("authentication")
        reason = ""
        if not binary or not authenticated:
            reason = (
                "Missions authenticate only through the declared credential "
                f"identity {identity}: save a user-owned 0600 environment file at "
                f"{credential_file} and restart the idle worker. A sign-in on this "
                "machine does not carry into a mission, because the sandbox is "
                "given its own home and the CLI is run in a mode that reads no "
                "stored session. Credential presence does not verify "
                "authentication.")
        return Readiness(installed=bool(binary), authenticated=authenticated,
                         missing=tuple(missing), facts=facts, reason=reason)

    # -- acceptance --------------------------------------------------------
    def accepts(self, capability: str, config: dict) -> Acceptance:
        base = super().accepts(capability, config)
        if not base.ok:
            return base
        config = config or {}
        if config.get("network") != "allow":
            return Acceptance.no(
                "This is a cloud agent and requires explicit network approval for "
                "this mission. Allow a connection for it, or choose a provider "
                "that works offline.")
        model = config.get("model")
        if model:
            if not isinstance(model, str) or not self.model_supported(model):
                return Acceptance.no(
                    "Unrecognised model selection. Choose one of "
                    + ", ".join(MODEL_ALIASES)
                    + ", or a full model name of the form claude-<name>.")
        return Acceptance.yes()

    @staticmethod
    def model_supported(model) -> bool:
        """Whether a model may be placed on the command line.

        An allowlist rather than a filter: this value becomes an argv element,
        and a name the CLI does not know is a mission that fails after the
        person waited for it.
        """
        if not isinstance(model, str):
            return False
        model = model.strip()
        return model in MODEL_ALIASES or bool(MODEL_NAME.fullmatch(model))

    # -- invocation --------------------------------------------------------
    def build_invocation(self, capability: str, request: dict) -> Invocation:
        binary = resolve_executable(self.manifest)
        if not binary:
            raise ProviderError(
                "The Claude Code CLI was not found in any location its manifest "
                "declares")
        request = request or {}
        prompt_path = request.get("prompt_path")
        if not prompt_path:
            raise ProviderError("This provider requires a prompt file")
        config = request.get("config") or {}
        read_only = (capability == Capability.SOURCED_REPORT
                     or bool(request.get("read_only")))

        sandbox = self.sandbox_for(capability, config)
        if read_only:
            sandbox = sandbox.narrow(workspace_mode="read-only")

        argv = [
            # No user configuration, no hooks, no plugins, no auto-discovered
            # project memory, no keychain: what runs is decided by this argv
            # and nothing that happens to be on the host.
            "--bare",
            "--print",
            "--output-format", "stream-json",
            # Not optional. The CLI refuses stream-json in print mode without it.
            "--verbose",
            # Measured to remove one non-API destination. The allowlist is
            # declared and filtered elsewhere; this reduces what is attempted.
            "--settings", SANDBOX_SETTINGS,
            # Nothing persists anyway -- the sandbox home is fresh every run --
            # so say so rather than leaving a resume file the next session
            # cannot see.
            "--no-session-persistence",
            # Correlation: a deterministic identifier the CLI echoes back, so a
            # retained log can be tied to the mission that produced it.
            "--session-id", self.session_identifier(prompt_path),
        ]
        # A read-only mission is denied the editing tool as well as a read-only
        # workspace. The mount is the enforcement; this makes the agent stop
        # before it tries, which is a better experience and not a control.
        argv += ["--tools", "Bash,Read" if read_only else "Bash,Edit,Read"]
        # There is no person to approve a tool call inside a batch sandbox. The
        # containment is the sandbox: an unshared network namespace, a bound
        # workspace and nothing else writable.
        argv += ["--permission-mode", "bypassPermissions"]
        model = config.get("model")
        if model:
            if not self.model_supported(model):
                raise ProviderError(f"Unsupported model selection: {model!r}")
            argv += ["--model", model.strip()]

        return Invocation(
            executable=binary,
            manifest_executable=self.manifest.get("executable"),
            argv=tuple(argv),
            stdin_path=str(prompt_path),
            # Identities only. The value is injected at the Firebreak boundary
            # by code that did not come from a provider, and never travels here.
            env_allowlist=tuple(self.manifest.get("credential_ids") or ()),
            sandbox=sandbox,
            label="claude",
        )

    @staticmethod
    def session_identifier(prompt_path) -> str:
        """A stable session id for one mission request.

        Derived, not random: argv must be identical for identical input, and a
        fresh identifier per build would make an invocation impossible to
        reproduce or to verify.
        """
        return str(uuid.uuid5(SESSION_NAMESPACE, str(prompt_path)))

    # -- stream ------------------------------------------------------------
    def parse_stream(self, text: str):
        """Normalize the CLI's JSON Lines into AgentEvents.

        The stream is untrusted input. It arrives mixed with whatever else
        reached the same file descriptor -- the sandbox's own trailer, a
        truncation marker, a plain-text CLI error before any JSON at all -- so
        every line that is not a JSON object becomes a log event and nothing
        here may raise.

        Two passes, because a tool call and its result are on different lines
        and one ToolExecution row per call is worth more to a reviewer than two
        halves. Pass one indexes results by tool_use id; pass two emits events
        in stream order with the result folded into the call.
        """
        records = []
        for line in (text or "").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except ValueError:
                records.append((False, line))
                continue
            if not isinstance(raw, dict):
                records.append((False, line))
                continue
            records.append((True, raw))

        results = self._tool_results(records)
        events = []
        for structured, payload in records:
            if not structured:
                events.append(AgentEvent(AgentEvent.LOG, payload[:MAX_TEXT]))
                continue
            events.extend(self._events_for(payload, results))
        if records and not any(structured for structured, _ in records):
            # The process wrote something and none of it was a stream record, so
            # it never began a turn -- a refused flag, a missing runtime file, a
            # sandbox that would not let it start. That cannot be a success under
            # any reading, so naming it here costs nothing and turns "did not
            # record a complete turn" into the sentence the CLI actually printed.
            #
            # Deliberately NOT a rule about lines that merely look like errors:
            # prose alongside a completed turn stays a log, because a stray
            # warning must not be able to fail a mission that finished.
            events.append(AgentEvent(
                AgentEvent.ERROR,
                ("The agent produced no stream records at all; it did not start. "
                 "First line: " + records[0][1])[:MAX_TEXT],
                {"raw_type": "no-stream"}))
        return events

    # -- stream helpers ----------------------------------------------------
    @staticmethod
    def _blocks(raw):
        """The content blocks of a message line, or an empty list."""
        message = raw.get("message")
        if not isinstance(message, dict):
            return []
        content = message.get("content")
        if not isinstance(content, list):
            return []
        return [b for b in content if isinstance(b, dict)]

    @classmethod
    def _tool_results(cls, records) -> dict:
        """tool_use id -> what came back, indexed from the whole stream."""
        found = {}
        for structured, raw in records:
            if not structured or raw.get("type") != "user":
                continue
            for block in cls._blocks(raw):
                if block.get("type") != "tool_result":
                    continue
                key = block.get("tool_use_id")
                if not isinstance(key, str) or not key:
                    continue
                content = block.get("content")
                try:
                    serialised = json.dumps(content, sort_keys=True, default=repr)
                except (TypeError, ValueError):       # pragma: no cover - default=repr
                    serialised = repr(content)
                found[key] = {
                    "exit_status": "error" if block.get("is_error") else "ok",
                    "result_digest": hashlib.sha256(
                        serialised.encode("utf-8", "replace")).hexdigest(),
                }
        return found

    @classmethod
    def _tool_event(cls, block, results) -> AgentEvent:
        """One observed tool call, in the vocabulary the recorder reads.

        A record is created only when the provider actually said a tool ran.
        Nothing here guesses a tool out of prose: a wrong row in a durable
        record is worse than a missing one, because a reviewer believes it.
        """
        name = block.get("name")
        arguments = block.get("input") if isinstance(block.get("input"), dict) else None
        action = None
        for key in ACTION_KEYS:
            if arguments and isinstance(arguments.get(key), (str, int, float)):
                action = f"{key}={arguments[key]}"
                break
        data = {"tool": _text(name), "action": action, "args": arguments,
                "raw_type": "tool_use"}
        # A tool_use block carries its identifier as "id"; the tool_result that
        # answers it refers back to that value as "tool_use_id". Matching the
        # wrong key silently produced a record with no outcome at all, which
        # reads as "the call never returned" rather than "the adapter looked in
        # the wrong place" -- so the fixtures assert the outcome is present.
        identifier = block.get("id")
        outcome = results.get(identifier) if isinstance(identifier, str) else None
        if outcome:
            data.update(outcome)
        return AgentEvent(AgentEvent.PROGRESS, "", data)

    @classmethod
    def _assistant_events(cls, raw, results) -> list:
        events = []
        failure = raw.get("error")
        texts = []
        for block in cls._blocks(raw):
            kind = block.get("type")
            if kind == "text":
                value = block.get("text")
                if isinstance(value, str) and value.strip():
                    texts.append(value)
            elif kind == "tool_use":
                name = block.get("name")
                if isinstance(name, str) and name.strip():
                    events.append(cls._tool_event(block, results))
                else:
                    events.append(AgentEvent(AgentEvent.PROGRESS, "",
                                             {"raw_type": "tool_use"}))
        if isinstance(failure, str) and failure.strip():
            # An assistant line that carries an error is not an answer, and
            # presenting its text as one would hand a person a failure notice
            # as though the agent had replied.
            detail = " ".join(t.strip() for t in texts if t.strip())
            return events + [AgentEvent(
                AgentEvent.ERROR,
                (f"{failure}: {detail}" if detail else failure)[:MAX_TEXT],
                {"raw_type": "assistant"})]
        events.extend(AgentEvent(AgentEvent.MESSAGE, value[:MAX_MESSAGE])
                      for value in texts)
        message = raw.get("message")
        usage = message.get("usage") if isinstance(message, dict) else None
        if isinstance(usage, dict):
            events.append(AgentEvent(AgentEvent.USAGE, "", {"usage": usage}))
        return events

    @classmethod
    def _events_for(cls, raw, results) -> list:
        kind = raw.get("type")
        if kind == "system":
            subtype = raw.get("subtype")
            data = {"raw_type": "system", "subtype": _text(subtype)}
            if subtype == "init":
                for key, name in (("session_id", "session_id"), ("model", "model"),
                                  ("permissionMode", "permission_mode"),
                                  ("apiKeySource", "api_key_source"),
                                  ("cwd", "cwd")):
                    if key in raw:
                        data[name] = _text(raw.get(key))
                tools = raw.get("tools")
                if isinstance(tools, list):
                    data["tools"] = [_text(t, 60) for t in tools if isinstance(t, str)]
            elif subtype == "api_retry":
                # Operability: the CLI retries an authentication failure up to
                # ten times with backoff, so a mission that appears to hang on
                # a bad credential is explained by these lines rather than by
                # guesswork.
                for key, name in (("attempt", "attempt"), ("max_retries", "max_retries"),
                                  ("error_status", "error_status"), ("error", "error")):
                    if key in raw:
                        data[name] = _scalar(raw.get(key))
            return [AgentEvent(AgentEvent.PROGRESS, "", data)]

        if kind == "assistant":
            return cls._assistant_events(raw, results)

        if kind == "user":
            # Its content was folded into the call it answers. Recorded as
            # progress so the stream still shows the round trip, and without a
            # tool key so it cannot create a second row for one tool call.
            return [AgentEvent(AgentEvent.PROGRESS, "", {"raw_type": "tool_result"})]

        if kind == "result":
            data = {"raw_type": "result", "subtype": _text(raw.get("subtype"))}
            usage = raw.get("usage")
            data["usage"] = cls._usage_summary(raw) if isinstance(usage, dict) else None
            for key, name in (("session_id", "session_id"), ("num_turns", "num_turns"),
                              ("duration_ms", "duration_ms")):
                if key in raw:
                    data[name] = _scalar(raw.get(key))
            denials = raw.get("permission_denials")
            if isinstance(denials, list) and denials:
                data["permission_denials"] = len(denials)
            if raw.get("is_error"):
                # subtype has been observed as "success" on a run whose
                # is_error was true, so is_error is the fact.
                detail = raw.get("result")
                if not isinstance(detail, str) or not detail.strip():
                    detail = _text(raw.get("subtype")) or "the turn reported an error"
                return [AgentEvent(AgentEvent.ERROR, detail[:MAX_TEXT], data)]
            events = []
            answer = raw.get("result")
            if isinstance(answer, str) and answer.strip():
                events.append(AgentEvent(AgentEvent.MESSAGE, answer[:MAX_MESSAGE]))
            events.append(AgentEvent(AgentEvent.TURN_COMPLETE, "", data))
            return events

        return [AgentEvent(AgentEvent.PROGRESS, "", {"raw_type": _text(kind)})]

    @staticmethod
    def _usage_summary(raw) -> dict:
        """Usage as the CLI reports it, plus the cost it computed.

        Copied, not recomputed: a token count this adapter derived would be a
        number nobody could reconcile with a bill.
        """
        usage = dict(raw.get("usage") or {})
        summary = {key: usage.get(key) for key in
                   ("input_tokens", "output_tokens", "cache_creation_input_tokens",
                    "cache_read_input_tokens") if key in usage}
        if isinstance(raw.get("total_cost_usd"), (int, float)):
            summary["total_cost_usd"] = raw["total_cost_usd"]
        if isinstance(raw.get("num_turns"), int):
            summary["num_turns"] = raw["num_turns"]
        summary["reported_by"] = "provider"
        return summary

    # -- turn outcome ------------------------------------------------------
    # The base rule -- a terminal event and no error -- is exactly this CLI's
    # protocol after parsing, so it is not overridden. A stream that stops
    # before its result line (a cancel, a deadline, a kill) carries no
    # turn-complete event and is therefore not a success.

    def usage(self, events):
        """The last usage figure anywhere in the turn.

        The base implementation reads only a completed turn, so a mission that
        failed or was cancelled reported no usage at all -- which is exactly
        when a person wants to know what it spent.
        """
        for event in reversed(list(events)):
            if event.type in (AgentEvent.TURN_COMPLETE, AgentEvent.USAGE, AgentEvent.ERROR):
                usage = event.data.get("usage")
                if usage:
                    return usage
        return None

    def session_correlation(self, events) -> dict:
        """What the CLI said its session was, for a caller that wants to tie a
        retained log to a mission. Reported, never asserted: if the stream
        names two different sessions, both are returned rather than one being
        chosen."""
        found = []
        for event in events or ():
            data = getattr(event, "data", None)
            if isinstance(data, dict) and isinstance(data.get("session_id"), str):
                if data["session_id"] not in found:
                    found.append(data["session_id"])
        return {"reported_session_ids": found}
