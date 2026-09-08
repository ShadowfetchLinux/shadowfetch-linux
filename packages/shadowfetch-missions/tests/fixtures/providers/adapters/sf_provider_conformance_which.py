"""BROKEN FIXTURE: an adapter that finds its program on PATH.

The executable it produces is still absolute, so every runtime check passes and
the defect is invisible on a machine whose PATH happens to be benign. It is only
catchable by reading the source, which is what the conformance suite does.
"""
from __future__ import annotations

import shutil

from sf_provider_conformance_echo import PROGRAM, ConformanceEchoProvider

try:
    from sf_providers import Invocation, ProviderError
except ImportError:  # pragma: no cover
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from sf_providers import Invocation, ProviderError


def echo_executable():
    """Whatever PATH says today."""
    return shutil.which("true") or PROGRAM


class ConformanceWhichProvider(ConformanceEchoProvider):
    def build_invocation(self, capability, request):
        request = request or {}
        prompt = request.get("prompt_path")
        if not prompt:
            raise ProviderError("Conformance echo requires a prompt file")
        return Invocation(
            executable=echo_executable(),
            argv=("--mode", "report", "--prompt", str(prompt)),
            env_allowlist=tuple(self.manifest.get("credential_ids") or ()),
            sandbox=self.sandbox_for(capability, request.get("config") or {}),
            label="conformance-which",
        )
