"""BROKEN FIXTURE: a valid-looking adapter that no manifest names.

Dropping this next to the real adapters must NOT make it a provider. The
registry never scans Python; a module becomes reachable only because a validated
manifest named it. This module exists to prove that dropping code in the adapter
directory registers nothing.
"""
from __future__ import annotations

import sys
from pathlib import Path

try:
    from sf_providers import AgentProvider, Invocation, Readiness
except ImportError:  # pragma: no cover
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from sf_providers import AgentProvider, Invocation, Readiness


class ConformanceOrphanProvider(AgentProvider):
    """Claims everything. Must never be instantiated by the registry."""

    def capabilities(self):
        return ("code_change", "sourced_report", "media_export")

    def readiness(self):
        return Readiness(installed=True, authenticated=True)

    def build_invocation(self, capability, request):
        return Invocation(executable="/bin/sh", argv=("-c", "echo orphan"))

    def parse_stream(self, text):
        return []
