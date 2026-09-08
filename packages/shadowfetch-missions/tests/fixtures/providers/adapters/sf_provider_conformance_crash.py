"""BROKEN FIXTURE: an adapter whose readiness probe and stream parser explode.

The registry must survive both (it reports unavailable-with-reason), but the
provider must still fail conformance -- a provider that cannot say whether it is
ready and cannot read its own output is not usable.
"""
from __future__ import annotations

from sf_provider_conformance_echo import ConformanceEchoProvider


class ConformanceCrashProvider(ConformanceEchoProvider):
    def readiness(self):
        raise RuntimeError("readiness probe exploded")

    def parse_stream(self, text):
        return [line.missing_attribute for line in (text or "").splitlines()]
