"""Nonblocking, bounded JSON transport for the local mission engine.

No shell, network, credentials or privileged operations live in the UI.
"""
import json
import os
import shutil
from pathlib import Path

from PyQt6.QtCore import QObject, QProcess, QTimer

MISSION_COMMAND = os.environ.get("SHADOWFETCH_MISSIONS_COMMAND", "shadowfetch-missions")
GROK_COMMAND = os.environ.get("SHADOWFETCH_GROK_BOT_COMMAND", "shadowfetch-grok-bot")


def workspaces_root() -> Path:
    return Path(os.environ.get("SHADOWFETCH_AGENT_WORKSPACES", str(Path.home() / "Workspaces"))).expanduser().resolve()


def workspace_path(value: str) -> Path:
    root = workspaces_root()
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = root / path
    if path.is_symlink():
        raise ValueError("Choose the project folder itself, not a symbolic link.")
    path = path.resolve()
    if path.parent != root or path == root or path.name.startswith("."):
        raise ValueError(f"Choose a project directly inside {root}. Create one in Workbench first, then select it here.")
    if not path.is_dir():
        raise ValueError("This project does not exist yet. Create it in Workbench, then return to New mission.")
    return path


def command_error(data, fallback: str) -> str:
    if isinstance(data, dict) and data.get("error"):
        return str(data["error"])
    return fallback


class JsonCommand(QObject):
    """Keeps stdout bounded and reports completion exactly once, including ENOENT."""
    MAX_BYTES = 4 * 1024 * 1024

    def __init__(self, parent, command, arguments, callback, timeout_ms=30_000,
                 preserve_operation=False, on_waiting=None):
        super().__init__(parent)
        self._callback = callback
        self._stdout = bytearray()
        self._stderr = bytearray()
        self._done = False
        self._failure = None
        self._preserve_operation = preserve_operation
        self._on_waiting = on_waiting
        self.process = QProcess(self)
        self.timer = QTimer(self)
        self.timer.setSingleShot(True)
        self.timer.timeout.connect(self._timeout)
        self.process.readyReadStandardOutput.connect(self._read_stdout)
        self.process.readyReadStandardError.connect(self._read_stderr)
        self.process.finished.connect(self._finished)
        self.process.errorOccurred.connect(self._error)
        self._command, self._arguments = command, arguments
        self._timeout_ms = timeout_ms

    def start(self):
        self.timer.start(self._timeout_ms)
        self.process.start(self._command, self._arguments)
        return self

    def _read_stdout(self):
        chunk = bytes(self.process.readAllStandardOutput())
        if len(self._stdout) + len(chunk) > self.MAX_BYTES:
            self._failure = "The local tool returned too much data. Open its receipt from the terminal."
            # A restore may already be changing files. Drain excess output,
            # but never kill a mutating review because its response is large.
            if not self._preserve_operation:
                self.process.kill()
            return
        self._stdout.extend(chunk)

    def _read_stderr(self):
        self._stderr.extend(bytes(self.process.readAllStandardError()))
        del self._stderr[:-16_384]

    def _timeout(self):
        if self._preserve_operation:
            if self._on_waiting:
                self._on_waiting("Review is still running. Mission Control will keep waiting for its result. Keep this window open; you can minimize it.")
            return
        self._failure = "The local tool did not answer in time. Refresh to check its current state."
        self.process.kill()

    def _error(self, error):
        if error == QProcess.ProcessError.FailedToStart:
            self._complete(None, f"Could not start {self._command}. Repair its Shadowfetch package and retry.")

    def _finished(self, code, _status):
        self._read_stdout()
        self._read_stderr()
        if self._failure:
            self._complete(None, self._failure)
            return
        try:
            data = json.loads(self._stdout.decode("utf-8"))
        except (ValueError, UnicodeError):
            self._complete(None, "The local tool returned an invalid response. " + self._stderr.decode("utf-8", "replace").strip()[-1000:])
            return
        if code:
            self._complete(None, command_error(data, f"The local tool exited with status {code}."))
        else:
            self._complete(data, None)

    def _complete(self, data, error):
        if self._done:
            return
        self._done = True
        self.timer.stop()
        self._callback(data, error)
        self.deleteLater()


class MissionClient(QObject):
    def call(self, arguments, callback):
        return JsonCommand(self, MISSION_COMMAND, ["--json", *arguments], callback).start()

    def review(self, arguments, callback, on_waiting):
        # The observation deadline is a status update, not permission to
        # interrupt checkpoint restoration. Keep the QProcess until it exits.
        return JsonCommand(self, MISSION_COMMAND, ["--json", *arguments], callback,
                           preserve_operation=True, on_waiting=on_waiting).start()

    def grok_status(self, callback):
        return JsonCommand(self, GROK_COMMAND, ["status", "--json"], callback).start()
