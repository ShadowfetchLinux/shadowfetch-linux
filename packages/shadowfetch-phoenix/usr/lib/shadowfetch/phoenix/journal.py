"""The Phoenix restore intent journal.

phoenix-restore writes one line before every mutation it performs, to two
durable places (the volume top-level, which survives the root exchange, and
/var/lib/shadowfetch inside the root being replaced, which survives NOT
exchanging). Through 4.0.0 those lines were free text: good for a human
reading them after the fact, useless to a program deciding what an interrupted
restore left behind.

This module gives the journal a grammar:

    <iso8601Z> pid=<pid> point=<N> run=<TS> phase=<phase> <free text>

`run` is the restore's own timestamp - the same TS that names @_prev_<TS> and
appears as date= in the update-grub flag - so every record of one attempt can
be gathered without guessing, and two interleaved attempts cannot be confused
for one. `phase` is a closed vocabulary; the phase reached is what the resume
decision is built from.

Free text is preserved verbatim after the keys, so the operator-facing lines
the shell already wrote are unchanged and older, key-less lines still parse
(as phase "legacy") instead of aborting the reader.

BOUNDED. The journal is append-only and is read on every boot. Reading takes
the last MAX_READ_BYTES only, and rotate() truncates it to KEEP_RECORDS lines
- a recovery subsystem must not be the thing that fills the disk it recovers.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

__all__ = [
    "PHASES", "PRE_EXCHANGE_PHASES", "POST_EXCHANGE_PHASES", "TERMINAL_PHASES",
    "LEGACY_PHASE", "Record", "IntentJournal", "JOURNAL_NAME",
]

JOURNAL_NAME = "phoenix-restore.journal"

# The closed phase vocabulary, in the order phoenix-restore reaches them.
PHASES = (
    "requested",         # arguments validated, layout accepted, nothing touched
    "leftover-parked",   # an @new from an earlier interrupted run was renamed
    "staging-created",   # @new exists: a writable copy of the Point
    "boot-unarchived",   # earlier kernel backups were folded back into /boot
    "boot-staged",       # external /boot now holds the Point's kernel only
    "exchange-begin",    # about to renameat2(RENAME_EXCHANGE) @new <-> @
    "exchange-complete", # @ IS the restored Point; the old root sits in @new
    "previous-parked",   # the old root was renamed to @_prev_<run>
    "complete",          # nothing is in flight
    "rolled-back",       # the attempt was undone; the system is as it was
    "aborted",           # the attempt stopped before it changed anything
    "resume",            # a later phoenix-recover pass acted on this run
    "gc",                # bounded garbage collection acted on this volume
)

# Phases that prove the atomic exchange had not yet been attempted. Note that
# "exchange-begin" is deliberately NOT here: it is written before the
# renameat2, so on its own it says nothing about whether the swap happened.
PRE_EXCHANGE_PHASES = frozenset({
    "requested", "leftover-parked", "staging-created",
    "boot-unarchived", "boot-staged", "rolled-back", "aborted",
})
# Phases that prove it did.
POST_EXCHANGE_PHASES = frozenset({
    "exchange-complete", "previous-parked", "complete",
})
TERMINAL_PHASES = frozenset({"complete", "rolled-back", "aborted"})

LEGACY_PHASE = "legacy"

MAX_READ_BYTES = 256 * 1024
KEEP_RECORDS = 400

_RECORD_RE = re.compile(
    r"^(?P<time>\S+) pid=(?P<pid>\d+) point=(?P<point>\S+) "
    r"run=(?P<run>\S+) phase=(?P<phase>[a-z][a-z-]*)(?: (?P<message>.*))?$")
# The 4.0.0 shape, kept readable so an upgrade does not blind the resume path
# to a restore that was in flight across the upgrade.
_LEGACY_RE = re.compile(
    r"^(?P<time>\S+) pid=(?P<pid>\d+) point=(?P<point>\S+)(?: (?P<message>.*))?$")

RUN_RE = re.compile(r"^\d{14}$")


@dataclass(frozen=True)
class Record:
    time: str
    pid: int
    point: str
    run: str | None
    phase: str
    message: str
    raw: str

    @property
    def structured(self) -> bool:
        return self.phase != LEGACY_PHASE


def _parse(line: str) -> Record | None:
    line = line.rstrip("\n")
    if not line.strip():
        return None
    match = _RECORD_RE.match(line)
    if match:
        return Record(time=match["time"], pid=int(match["pid"]),
                      point=match["point"], run=match["run"],
                      phase=match["phase"], message=match["message"] or "",
                      raw=line)
    match = _LEGACY_RE.match(line)
    if match:
        return Record(time=match["time"], pid=int(match["pid"]),
                      point=match["point"], run=None, phase=LEGACY_PHASE,
                      message=match["message"] or "", raw=line)
    return None


class IntentJournal:
    """Append-only intent log for one volume, read and written by absolute path."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)

    # -- reading -----------------------------------------------------------
    def read(self) -> list[Record]:
        """Every parseable record in the journal's last MAX_READ_BYTES.

        A truncated first line (the tail read landing mid-record) is dropped by
        _parse returning None rather than being half-interpreted.
        """
        try:
            with open(self.path, "rb") as handle:
                handle.seek(0, os.SEEK_END)
                size = handle.tell()
                handle.seek(max(0, size - MAX_READ_BYTES))
                blob = handle.read()
        except OSError:
            return []
        text = blob.decode("utf-8", "replace")
        return [record for record in map(_parse, text.splitlines()) if record]

    def last_run(self) -> str | None:
        """The run id of the newest structured record, or None."""
        for record in reversed(self.read()):
            if record.run:
                return record.run
        return None

    def records_for(self, run: str) -> list[Record]:
        return [record for record in self.read() if record.run == run]

    def phase_of(self, run: str) -> str | None:
        """The last phase reached by `run`, or None when it is not journalled."""
        records = self.records_for(run)
        return records[-1].phase if records else None

    def point_of(self, run: str) -> str | None:
        records = self.records_for(run)
        return records[-1].point if records else None

    def in_flight(self) -> tuple[str | None, str | None]:
        """(run, phase) of the newest run that never reached a terminal phase."""
        run = self.last_run()
        if run is None:
            return (None, None)
        phase = self.phase_of(run)
        if phase in TERMINAL_PHASES:
            return (None, phase)
        return (run, phase)

    # -- writing -----------------------------------------------------------
    def append(self, point: str, run: str, phase: str, message: str = "") -> bool:
        """Append one record. Never raises: a journal that cannot be written
        must not be what stops a recovery from happening."""
        if phase not in PHASES:
            raise ValueError(f"unknown journal phase {phase!r}")
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        line = "%s pid=%d point=%s run=%s phase=%s %s\n" % (
            stamp, os.getpid(), point, run, phase, message)
        try:
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        except OSError:
            return False
        try:
            os.write(fd, line.encode("utf-8"))
            os.fsync(fd)
        except OSError:
            return False
        finally:
            os.close(fd)
        return True

    def rotate(self, keep: int = KEEP_RECORDS) -> bool:
        """Bounded cleanup: keep the newest `keep` lines, atomically.

        Returns True when the journal was rewritten. Called from the boot-time
        pass, so the cost is one read and (rarely) one rename per boot.
        """
        try:
            size = self.path.stat().st_size
        except OSError:
            return False
        if size <= MAX_READ_BYTES:
            return False
        lines = [record.raw for record in self.read()][-keep:]
        tmp = self.path.with_name(self.path.name + ".rotate")
        try:
            with open(tmp, "w", encoding="utf-8") as handle:
                handle.write("\n".join(lines) + ("\n" if lines else ""))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, self.path)
        except OSError:
            try:
                tmp.unlink()
            except OSError:
                pass
            return False
        return True
