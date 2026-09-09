"""The conformance profile for the Claude Code provider.

Kept in its own module, importable by name, so the shared suite can pick it up
with three lines rather than a merge. It supplies what a manifest cannot say:
what a valid request looks like, which configurations must be refused, and a
native stream with the events it must normalise to.

Fixture transports only. No credential, no network, no real agent process:
binary presence and authentication are patched at this provider's own seams,
and the streams are files.

Provenance of the streams, because it decides what they prove:

  claude_unauthenticated.jsonl   REAL. Captured from claude 2.1.178 on the
                                 build host, running the argv this adapter
                                 builds, with no credential available. It is
                                 the reason the parser trusts is_error rather
                                 than result.subtype: that recording says
                                 subtype "success" on a failed turn.
  every other claude_*.jsonl     SYNTHETIC, written to the schema of that
                                 recording and of the init/assistant/result
                                 lines observed on the same host. No recording
                                 of a successful authenticated turn exists in
                                 this tree, because no credential was available
                                 to produce one, and inventing one and calling
                                 it captured would be a lie a reviewer could
                                 not detect.
"""
from __future__ import annotations

import contextlib
import os
import tempfile
from pathlib import Path
from unittest import mock

from provider_conformance import (Capability, ProviderProfile, StreamCase, stream)

import sf_provider_claude

PROVIDER_ID = "claude"
ANSWER = "The launch is Friday and the release contains three workflows."

_SCRATCH = tempfile.TemporaryDirectory(prefix="sf-claude-bin-")
FAKE_BINARY = Path(_SCRATCH.name) / "claude"
FAKE_BINARY.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
# Readiness asks whether the program is EXECUTABLE, not merely present.
FAKE_BINARY.chmod(0o755)


def _binary(path):
    return mock.patch.object(sf_provider_claude, "resolve_executable",
                             lambda *a, **k: path)


def binary_present():
    return _binary(str(FAKE_BINARY))


def binary_absent():
    return _binary(None)


def auth_present():
    return mock.patch.dict(os.environ,
                           {"ANTHROPIC_API_KEY": "fixture-identity-not-a-real-key"})


@contextlib.contextmanager
def auth_absent():
    """No environment identity and no worker credential file.

    HOME is redirected as well as the variable cleared, because readiness also
    looks for an operator-installed environment file under the invoking user's
    home, and a developer machine that happens to have one would otherwise make
    this assertion pass for the wrong reason.
    """
    home = tempfile.TemporaryDirectory(prefix="sf-claude-home-")
    with mock.patch.dict(os.environ, {"HOME": home.name}):
        os.environ.pop("ANTHROPIC_API_KEY", None)
        try:
            yield
        finally:
            home.cleanup()


def requests(tmp):
    prompt = tmp / "agent-request.txt"
    prompt.write_text("Summarize the launch\n", encoding="utf-8")
    base = {"prompt_path": str(prompt), "config": {"network": "allow"}}
    with_model = {"prompt_path": str(prompt),
                  "config": {"network": "allow", "model": "sonnet"}}
    return {
        Capability.CODE_CHANGE: [dict(base), dict(base, read_only=True), with_model],
        Capability.SOURCED_REPORT: [dict(base)],
    }


PROFILE = ProviderProfile(
    provider_id=PROVIDER_ID,
    build_requests=requests,
    accept_configs={Capability.CODE_CHANGE: {"network": "allow"},
                    Capability.SOURCED_REPORT: {"network": "allow", "model": "opus"}},
    refusals=(
        (Capability.CODE_CHANGE, {}, "network approval"),
        (Capability.CODE_CHANGE, {"network": "none"}, "network approval"),
        (Capability.SOURCED_REPORT, {"network": "allow", "model": "gpt-4o"},
         "unrecognised model"),
        (Capability.SOURCED_REPORT, {"network": "allow",
                                     "model": "--dangerously-skip-permissions"},
         "unrecognised model"),
        (Capability.MEDIA_EXPORT, {"network": "allow"}, "does not perform"),
    ),
    streams=(
        StreamCase(
            name="claude_success.jsonl",
            text=stream("claude_success.jsonl"),
            expect_types=("progress", "message", "usage", "progress", "usage",
                          "progress", "message", "usage", "message", "turn-complete"),
            expect_final=ANSWER, expect_success=True, exit_code=0),
        StreamCase(
            name="claude_tool_denied.jsonl",
            text=stream("claude_tool_denied.jsonl"),
            expect_types=("progress", "progress", "usage", "progress", "message",
                          "usage", "message", "turn-complete"),
            expect_final="That host is unreachable from here.",
            expect_success=True, exit_code=0),
        StreamCase(
            name="claude_interleaved.jsonl",
            text=stream("claude_interleaved.jsonl"),
            expect_types=("log", "progress", "message", "log", "log",
                          "turn-complete", "log"),
            expect_final="Partial answer.", expect_success=True, exit_code=0),
        StreamCase(
            name="claude_unauthenticated.jsonl",
            text=stream("claude_unauthenticated.jsonl"),
            expect_types=("progress", "error", "error"),
            expect_final="", expect_success=False, exit_code=1),
        StreamCase(
            name="claude_cancelled.jsonl",
            text=stream("claude_cancelled.jsonl"),
            expect_types=("progress", "message", "usage", "progress", "usage"),
            expect_final="I'll start by listing the workspace.",
            expect_success=False, exit_code=143),
    ),
    binary_absent=binary_absent,
    binary_present=binary_present,
    auth_absent=auth_absent,
    auth_present=auth_present,
    invocation_context=binary_present,
    notes=("A cancelled turn keeps its partial text and its last usage figure but "
           "carries no terminal event, so it can never be read as a success -- "
           "the adapter does not synthesise one. An unauthenticated turn is the "
           "opposite trap: the CLI labels it subtype 'success' and sets "
           "is_error, and the recorded stream is what proves that."),
)

CLAUDE_PROFILE = PROFILE
