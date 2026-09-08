"""BROKEN FIXTURE: an adapter that accepts work it never declared.

Its manifest declares sourced_report only. This accepts() says yes to anything,
so a mission could be routed to a provider that cannot perform it and the
refusal a person needs to read never appears.
"""
from __future__ import annotations

from sf_provider_conformance_echo import ConformanceEchoProvider

try:
    from sf_providers import Acceptance
except ImportError:  # pragma: no cover
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from sf_providers import Acceptance


class ConformanceUndeclaredProvider(ConformanceEchoProvider):
    def accepts(self, capability, config):
        return Acceptance.yes()
