"""BROKEN FIXTURE: an adapter that resolves its program by bare name.

Invocation refuses a relative executable, so this one cannot even be built. The
conformance suite must surface that as a failure rather than a crash somewhere
downstream.
"""
from __future__ import annotations

from sf_provider_conformance_echo import ConformanceEchoProvider

try:
    from sf_providers import Invocation, ProviderError
except ImportError:  # pragma: no cover
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from sf_providers import Invocation, ProviderError


class ConformanceRelativeProvider(ConformanceEchoProvider):
    def build_invocation(self, capability, request):
        request = request or {}
        prompt = request.get("prompt_path")
        if not prompt:
            raise ProviderError("Conformance echo requires a prompt file")
        return Invocation(
            executable="conformance-echo",           # <- relative, on purpose
            argv=("--mode", "report", "--prompt", str(prompt)),
            sandbox=self.sandbox_for(capability, request.get("config") or {}),
            label="conformance-relative",
        )
