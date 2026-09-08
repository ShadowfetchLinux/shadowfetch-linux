"""A deliberately VALID third provider, used only by the conformance suite.

This fixture is the architectural proof of Phase 2. It is a complete, honest
provider that nothing in the product knows about: it does not ship, it is not
named in sf_missions.py, not in the CLI, not in the desktop UI, not in the
release gate. It becomes a provider purely because a validated manifest names
it, and it passes the same conformance suite the shipped providers pass.

It is intentionally unlike both shipped providers so that "the interface fits"
means something:

  * read-only workspace with an explicit read grant and a masked path, where
    Codex is workspace-write and ffmpeg has neither;
  * much smaller resource ceilings (512 MB / 60 s / 8 processes);
  * an allowlist network posture WITH a credential, but only one host;
  * a native stream that is neither JSONL nor ffmpeg diagnostics -- prefixed
    plain text with an explicit terminator line;
  * its prompt travels in argv rather than on stdin.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

try:
    from sf_providers import (Acceptance, AgentEvent, AgentProvider, Capability,
                              Invocation, ProviderError, Readiness)
except ImportError:  # source tree
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from sf_providers import (Acceptance, AgentEvent, AgentProvider, Capability,
                              Invocation, ProviderError, Readiness)

# The manifest declares executable.kind "absolute" with this exact path, and the
# conformance suite checks the two agree. The program is never executed by the
# suite; only the invocation is built.
PROGRAM = "/usr/bin/true"

TOKEN_ENV = "CONFORMANCE_ECHO_TOKEN"
TERMINATOR_OK = "== turn ok =="
TERMINATOR_FAILED = "== turn failed =="


class ConformanceEchoProvider(AgentProvider):
    """A sourced-report provider with a plain-text native stream."""

    CAPABILITIES = (Capability.SOURCED_REPORT,)

    # -- readiness ---------------------------------------------------------
    def readiness(self) -> Readiness:
        installed = Path(PROGRAM).is_file()
        token = bool(os.environ.get(TOKEN_ENV))
        missing = []
        if not installed:
            missing.append("conformance-echo program")
        if not token:
            missing.append("authentication")
        return Readiness(
            installed=installed,
            authenticated=token,
            missing=tuple(missing),
            facts={"executable": PROGRAM, "token_configured": token},
            reason="" if (installed and token) else (
                "Install the conformance echo program and export a "
                f"{TOKEN_ENV} identity for the mission worker."),
        )

    # -- acceptance --------------------------------------------------------
    def accepts(self, capability: str, config: dict) -> Acceptance:
        base = super().accepts(capability, config)
        if not base.ok:
            return base
        config = config or {}
        if config.get("network") != "allow":
            return Acceptance.no(
                "Conformance echo reads approved sources over a connection and needs one "
                "approved for this mission.")
        if not config.get("inputs"):
            return Acceptance.no("Select at least one approved source document.")
        return Acceptance.yes()

    # -- invocation --------------------------------------------------------
    def build_invocation(self, capability: str, request: dict) -> Invocation:
        if not self.supports(capability):
            raise ProviderError(f"Conformance echo does not perform {capability}")
        request = request or {}
        prompt = request.get("prompt_path")
        if not prompt:
            raise ProviderError("Conformance echo requires a prompt file")
        config = request.get("config") or {}
        sandbox = self.sandbox_for(capability, config)
        # Narrowing in the safe direction: this provider never needs more than
        # four processes even though its manifest allows eight.
        sandbox = sandbox.narrow(processes=min(4, sandbox.processes))
        argv = ["--mode", "report", "--format", "conformance-v1", "--prompt", str(prompt)]
        for name in sorted(config.get("inputs") or ()):
            argv += ["--source", str(name)]
        return Invocation(
            executable=PROGRAM,
            argv=tuple(argv),
            env_allowlist=tuple(self.manifest.get("credential_ids") or ()),
            sandbox=sandbox,
            label=request.get("label", "conformance-echo"),
        )

    # -- stream ------------------------------------------------------------
    def parse_stream(self, text: str):
        """Prefixed plain text. Anything unrecognised is a log line, never an
        exception: a provider's own output must not be able to break a turn."""
        events = []
        for raw in (text or "").splitlines():
            line = raw.strip()
            if not line:
                continue
            if line == TERMINATOR_OK:
                events.append(AgentEvent(AgentEvent.TURN_COMPLETE, "", {"ok": True}))
            elif line == TERMINATOR_FAILED:
                events.append(AgentEvent(AgentEvent.ERROR, "turn failed"))
                events.append(AgentEvent(AgentEvent.TURN_COMPLETE, "", {"ok": False}))
            elif line.startswith("!!"):
                events.append(AgentEvent(AgentEvent.ERROR, line[2:].strip()[:2000]))
            elif line.startswith("say>"):
                events.append(AgentEvent(AgentEvent.MESSAGE, line[4:].strip()))
            elif line.startswith("usage "):
                events.append(AgentEvent(AgentEvent.USAGE, "", {"raw": line[6:][:500]}))
            elif line.startswith("step="):
                events.append(AgentEvent(AgentEvent.PROGRESS, line[:500]))
            else:
                events.append(AgentEvent(AgentEvent.LOG, line[:2000]))
        return events
