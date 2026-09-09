"""Offline media export provider (ffmpeg/ffprobe).

This provider earns its place by being nothing like a chat model. It has no
credentials, no network, and no turn: its native stream is ffmpeg progress
output. If the AgentProvider interface can carry both this and the Codex CLI
without the orchestrator branching on which one it holds, then the interface is
about *doing work in a sandbox*, not about *talking to a language model*, and a
future local model or a different cloud agent will fit it too.

It is also where one Phase 1-class defect gets fixed rather than moved: the old
media path recovered ffprobe's JSON by searching a mixed log for the literal
'{"streams"', because Firebreak appends a session trailer to the same stream.
Here ffprobe writes to a file with -o, so there is no prose to parse.
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

try:
    from sf_providers import (AgentEvent, AgentProvider, Acceptance, Invocation,
                              ProviderError, Readiness, Capability)
except ImportError:  # source tree
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from sf_providers import (AgentEvent, AgentProvider, Acceptance, Invocation,
                              ProviderError, Readiness, Capability)

FFMPEG = "/usr/bin/ffmpeg"
FFPROBE = "/usr/bin/ffprobe"


class OfflineMediaProvider(AgentProvider):
    """Deterministic local media export. No model, no network, no credentials."""

    CAPABILITIES = (Capability.MEDIA_EXPORT,)

    # -- readiness ---------------------------------------------------------
    def readiness(self) -> Readiness:
        missing = [name for name, path in (("ffmpeg", FFMPEG), ("ffprobe", FFPROBE))
                   if not (Path(path).is_file() and os.access(path, os.X_OK))]
        installed = not missing
        return Readiness(
            installed=installed,
            # Nothing to authenticate against: an offline tool is authenticated
            # by definition. Saying so explicitly keeps the UI from inventing a
            # sign-in prompt for a provider that has no account.
            authenticated=True,
            missing=tuple(missing),
            facts={"ffmpeg": FFMPEG, "ffprobe": FFPROBE, "requires_credentials": False},
            reason="" if installed else f"Install ffmpeg: missing {', '.join(missing)}",
        )

    # -- acceptance --------------------------------------------------------
    def accepts(self, capability: str, config: dict) -> Acceptance:
        base = super().accepts(capability, config)
        if not base.ok:
            return base
        config = config or {}
        if config.get("network") not in (None, "none"):
            return Acceptance.no(
                "Media export runs offline; it will not be given a network connection.")
        if not config.get("inputs"):
            return Acceptance.no("Select at least one media file to export.")
        if config.get("model"):
            # Said rather than ignored. The engine used to refuse every model
            # for everyone, so this provider never had to answer for itself;
            # now that it does, silently dropping the field would let a person
            # believe a model had been chosen for a job that has none.
            return Acceptance.no(
                "Media export runs no model at all, so there is no model to "
                "choose. Leave the model unset.")
        return Acceptance.yes()

    # -- invocation --------------------------------------------------------
    def build_invocation(self, capability: str, request: dict) -> Invocation:
        """Three stages, each a separate Invocation the generic executor runs.

        stage=probe    inspect one input, JSON to a file
        stage=encode   transcode to a temporary output
        stage=verify   decode the result to prove it is playable
        """
        stage = (request or {}).get("stage")
        sandbox = self.sandbox_for(capability, (request or {}).get("config") or {})
        source = request.get("source")
        if not source:
            raise ProviderError("Media invocation requires a source path")

        if stage == "probe":
            report = request.get("report_path")
            if not report:
                raise ProviderError("Probe requires an output path for its JSON report")
            return Invocation(
                executable=FFPROBE,
                argv=("-v", "error", "-show_streams", "-show_format",
                      "-of", "json", "-o", str(report), str(source)),
                sandbox=sandbox,
                label=request.get("label", "probe"),
            )

        if stage == "encode":
            target = request.get("target")
            if not target:
                raise ProviderError("Encode requires a target path")
            argv = ["-nostdin", "-hide_banner", "-loglevel", "error", "-y",
                    "-i", str(source), "-map_metadata", "-1", "-map_chapters", "-1",
                    "-threads", "2"]
            if request.get("video"):
                argv += ["-map", "0:v:0", "-map", "0:a:0?", "-c:v", "libx264",
                         "-preset", "medium", "-crf", "20", "-pix_fmt", "yuv420p",
                         "-vf", "scale=trunc(iw/2)*2:trunc(ih/2)*2",
                         "-c:a", "aac", "-b:a", "160k", "-movflags", "+faststart"]
            else:
                argv += ["-map", "0:a:0", "-c:a", "pcm_s16le", "-ar", "48000"]
            argv.append(str(target))
            return Invocation(executable=FFMPEG, argv=tuple(argv), sandbox=sandbox,
                              label=request.get("label", "export"))

        if stage == "verify":
            return Invocation(
                executable=FFMPEG,
                argv=("-nostdin", "-v", "error", "-i", str(source), "-f", "null", "-"),
                sandbox=sandbox,
                label=request.get("label", "verify-export"),
            )

        raise ProviderError(f"Unknown media stage: {stage!r}")

    # -- stream ------------------------------------------------------------
    _PROGRESS = re.compile(r"^(frame|size|time)=", re.IGNORECASE)

    def parse_stream(self, text: str):
        """ffmpeg writes diagnostics, not turn events. Normalize conservatively:
        loglevel=error means most lines that appear at all are problems, but a
        provider stream is untrusted and must never be able to fail a mission by
        itself -- the exit status decides that."""
        events = []
        for line in (text or "").splitlines():
            line = line.strip()
            if not line:
                continue
            if self._PROGRESS.match(line):
                events.append(AgentEvent(AgentEvent.PROGRESS, line[:500]))
            else:
                events.append(AgentEvent(AgentEvent.LOG, line[:2000]))
        events.append(AgentEvent(AgentEvent.TURN_COMPLETE, "", {"usage": None}))
        return events

    # -- probe helper ------------------------------------------------------
    @staticmethod
    def read_probe(report_path) -> dict:
        """Read the JSON ffprobe wrote. No log scraping: -o gave us a file whose
        entire content is the report."""
        path = Path(report_path)
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise ProviderError(f"Media inspection produced no report: {exc}") from exc
        except ValueError as exc:
            raise ProviderError(f"Media inspection report is not valid JSON: {exc}") from exc
        if not isinstance(document, dict) or "streams" not in document:
            raise ProviderError("Media inspection report has no stream list")
        return document

    @staticmethod
    def classify(probe: dict):
        """(has_video, has_audio) for a probe report."""
        streams = probe.get("streams") or []
        video = any(s.get("codec_type") == "video"
                    and not (s.get("disposition") or {}).get("attached_pic")
                    for s in streams)
        audio = any(s.get("codec_type") == "audio" for s in streams)
        return video, audio
