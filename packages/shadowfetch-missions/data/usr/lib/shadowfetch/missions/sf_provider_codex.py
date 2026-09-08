"""Codex CLI provider adapter.

This is a behaviour-preserving move of the code that used to live in
Executor.codex(). The argv, the sandbox posture and the stream interpretation
are the same bytes they were before; what changed is that Mission Control no
longer knows any of it. Mission Control asks the registry for a provider that
performs a capability, asks that provider for an Invocation, runs it with
generic plumbing, and reads back normalized AgentEvents.

Nothing in this file is imported by the orchestrator. It becomes reachable only
because codex.json, a validated manifest, names it.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

try:
    from sf_providers import (AgentEvent, AgentProvider, Acceptance, Invocation,
                              ProviderError, Readiness, Capability)
except ImportError:  # source tree
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from sf_providers import (AgentEvent, AgentProvider, Acceptance, Invocation,
                              ProviderError, Readiness, Capability)


def codex_executable():
    """Absolute path to the Codex CLI, or None.

    Delegates to sf_mission_account, which locates the binary in the explicit
    runtime distribution. It is never resolved through PATH: a provider program
    chosen by the environment is the defect class Phase 1 removed twice.
    """
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    try:
        from sf_mission_account import codex_executable as locate
    except ImportError:
        return None
    try:
        found = locate()
    except Exception:
        return None
    if not found:
        return None
    resolved = Path(found).resolve()
    return str(resolved) if resolved.is_absolute() else None


class CodexCliProvider(AgentProvider):
    """The OpenAI Codex CLI, run inside Firebreak with explicit network consent."""

    CAPABILITIES = (Capability.CODE_CHANGE, Capability.SOURCED_REPORT)

    # -- readiness ---------------------------------------------------------
    def readiness(self) -> Readiness:
        binary = codex_executable()
        missing = []
        facts = {}
        if binary:
            facts["executable"] = binary
        else:
            missing.append("codex executable")

        account = False
        try:
            sys.path.insert(0, str(Path(__file__).resolve().parent))
            from sf_mission_account import account_home
            account = (account_home() / "auth.json").is_file()
        except Exception:
            account = False
        facts["dedicated_account_present"] = account

        env_key = bool(os.environ.get("CODEX_API_KEY") or os.environ.get("OPENAI_API_KEY"))
        facts["api_key_configured"] = env_key

        credential_file = Path.home() / ".config/shadowfetch/missions/codex.env"
        present = False
        try:
            st = credential_file.stat()
            present = (credential_file.is_file() and not credential_file.is_symlink()
                       and st.st_uid == os.getuid() and not st.st_mode & 0o077)
        except OSError:
            present = False
        facts["worker_environment_file"] = str(credential_file)
        facts["worker_environment_file_present"] = present

        authenticated = bool(account or env_key or present)
        if not authenticated:
            missing.append("authentication")
        return Readiness(
            installed=bool(binary),
            authenticated=authenticated,
            missing=tuple(missing),
            facts=facts,
            reason="" if (binary and authenticated) else (
                "Run shadowfetch-mission-account login for a dedicated account, or save a "
                "user-owned 0600 CODEX_API_KEY environment file and restart the idle worker. "
                "Credential presence does not verify authentication."),
        )

    # -- acceptance --------------------------------------------------------
    def accepts(self, capability: str, config: dict) -> Acceptance:
        base = super().accepts(capability, config)
        if not base.ok:
            return base
        if (config or {}).get("network") != "allow":
            return Acceptance.no(
                "Codex is a cloud agent and needs an explicitly approved connection "
                "for this mission.")
        if (config or {}).get("model"):
            return Acceptance.no(
                "Mission model selection is unavailable; the Codex CLI default is used.")
        return Acceptance.yes()

    # -- invocation --------------------------------------------------------
    def build_invocation(self, capability: str, request: dict) -> Invocation:
        binary = codex_executable()
        if not binary:
            raise ProviderError("The Codex CLI is not installed")
        prompt_path = request.get("prompt_path")
        if not prompt_path:
            raise ProviderError("Codex requires a prompt file")
        read_only = capability == Capability.SOURCED_REPORT or bool(request.get("read_only"))
        sandbox = self.sandbox_for(capability, request.get("config") or {})
        if read_only:
            sandbox = sandbox.narrow(workspace_mode="read-only")
        argv = (
            "exec",
            "--ignore-user-config",
            "--ignore-rules",
            "--ephemeral",
            "-c", 'cli_auth_credentials_store="file"',
            "-c", 'shell_environment_policy.exclude=["CODEX_API_KEY","OPENAI_API_KEY"]',
            "-c", 'approval_policy="never"',
            "--skip-git-repo-check",
            "--sandbox", "read-only" if read_only else "workspace-write",
            "--json",
            "-",
        )
        return Invocation(
            executable=binary,
            argv=argv,
            stdin_path=str(prompt_path),
            # Identities only. The value is injected at the Firebreak boundary by
            # code that did not come from a provider, and never travels here.
            env_allowlist=tuple(self.manifest.get("credential_ids") or ()),
            sandbox=sandbox,
            label="codex",
        )

    # -- stream ------------------------------------------------------------
    def parse_stream(self, text: str):
        """Codex emits one JSON object per line. Anything else on the stream --
        Firebreak's session trailer, a partial write, an interleaved warning --
        is carried through as a log event rather than being allowed to break
        the turn. A provider's output is untrusted input."""
        events = []
        for line in (text or "").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except ValueError:
                events.append(AgentEvent(AgentEvent.LOG, line[:2000]))
                continue
            if not isinstance(raw, dict):
                events.append(AgentEvent(AgentEvent.LOG, line[:2000]))
                continue
            kind = raw.get("type")
            if kind == "turn.completed":
                events.append(AgentEvent(AgentEvent.TURN_COMPLETE, "",
                                         {"usage": raw.get("usage")}))
            elif kind in ("turn.failed", "error"):
                events.append(AgentEvent(AgentEvent.ERROR, str(raw.get("message") or kind)[:2000],
                                         {"raw_type": kind}))
            elif kind == "item.completed":
                item = raw.get("item")
                if isinstance(item, dict) and item.get("type") == "agent_message":
                    events.append(AgentEvent(AgentEvent.MESSAGE, item.get("text") or ""))
                else:
                    events.append(AgentEvent(AgentEvent.PROGRESS, "",
                                             {"item": item if isinstance(item, dict) else {}}))
            else:
                events.append(AgentEvent(AgentEvent.PROGRESS, "", {"raw_type": kind}))
        return events

    # -- turn outcome ------------------------------------------------------
    @staticmethod
    def turn_succeeded(events) -> bool:
        completed = [e for e in events if e.type == AgentEvent.TURN_COMPLETE]
        failed = [e for e in events if e.type == AgentEvent.ERROR]
        return bool(completed) and not failed

    @staticmethod
    def usage(events):
        for event in reversed(events):
            if event.type == AgentEvent.TURN_COMPLETE:
                return event.data.get("usage")
        return None
