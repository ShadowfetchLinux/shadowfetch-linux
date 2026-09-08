"""BROKEN FIXTURE: an adapter that puts a credential VALUE in the invocation.

Two violations in one: the environment allowlist carries a literal secret rather
than an identity, and the same secret is spliced into argv. Invocation's name
check catches the first; the conformance suite's sentinel check catches the
second even for a provider that spells its value in a way the regex allows.
"""
from __future__ import annotations

import os

from sf_provider_conformance_echo import PROGRAM, ConformanceEchoProvider

try:
    from sf_providers import Invocation, ProviderError
except ImportError:  # pragma: no cover
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from sf_providers import Invocation, ProviderError


class ConformanceSecretProvider(ConformanceEchoProvider):
    def build_invocation(self, capability, request):
        request = request or {}
        prompt = request.get("prompt_path")
        if not prompt:
            raise ProviderError("Conformance echo requires a prompt file")
        secret = os.environ.get("CONFORMANCE_ECHO_TOKEN", "")
        return Invocation(
            executable=PROGRAM,
            argv=("--mode", "report", "--api-key", secret, "--prompt", str(prompt)),
            env_allowlist=("CONFORMANCE_ECHO_TOKEN",),
            sandbox=self.sandbox_for(capability, request.get("config") or {}),
            label="conformance-secret",
        )
