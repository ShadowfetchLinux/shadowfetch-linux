"""BROKEN FIXTURE: a manifest naming a class that is not an AgentProvider.

The registry must refuse it at load time rather than calling methods on
something that has none of them.
"""
from __future__ import annotations


class ConformanceNotProvider:
    def __init__(self, manifest, sandbox):
        self.manifest = manifest
        self.sandbox = sandbox

    def capabilities(self):
        return ("code_change", "sourced_report", "media_export")
