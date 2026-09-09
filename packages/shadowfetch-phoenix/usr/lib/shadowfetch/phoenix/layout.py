"""The Phoenix volume layout: what is on the Btrfs top-level, and is it sane.

phoenix-restore's whole safety argument is a statement about the top-level of
the volume ("an @ subvolume exists at every instant"), yet through 4.0.0 the
only thing that checked the top-level was two lines of shell: `test -d @` and
`btrfs subvolume show` on the Point. Everything else - which @_prev_* are
real subvolumes, which are safe to delete, whether @snapshots is where Point
history actually lives, whether a leftover @new is a discarded copy or the
previous root - was decided by ad-hoc globbing at the moment of deletion.

Layout makes that a value that can be printed, asserted on and refused.

TWO DELIBERATE NON-USES OF EXTERNAL PROGRAMS (see trusted.py):

  * Subvolume detection is `st_ino == 256`, which is how the kernel numbers a
    subvolume root, not `btrfs subvolume show`. Nothing to substitute.
  * The filesystem type of the mount comes from /proc/self/mountinfo, not from
    findmnt. Same reason: this decides whether GC may run at all.

The `detector` seam exists because unit tests must be able to model subvolumes
on a tmpdir. The DEFAULT is always the kernel one, an integration test on a
real loopback Btrfs exercises the default, and a unit test asserts the default
has not been swapped.
"""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable

__all__ = [
    "ROOT_NAME", "STAGING_NAME", "SNAPSHOTS_NAME", "PROTECTED_NAMES",
    "PREVIOUS_RE", "POINT_RE", "SUBVOLUME_INODE",
    "LayoutError", "Problem", "Entry", "PreviousRoot", "Layout",
    "btrfs_subvolume", "mount_fstype",
]

ROOT_NAME = "@"
STAGING_NAME = "@new"
SNAPSHOTS_NAME = "@snapshots"

# Never a garbage-collection candidate, whatever else is true of it. The
# Calamares layout creates @, @home, @log, @cache and @snapshots; the rest are
# spellings other Btrfs installers use and are listed so that a hand-rolled
# install cannot lose a subvolume to a Shadowfetch cleanup pass.
PROTECTED_NAMES = frozenset({
    ROOT_NAME, STAGING_NAME, SNAPSHOTS_NAME,
    "@home", "@log", "@cache", "@var", "@varlog", "@tmp", "@opt", "@srv",
    "@root", "@swap", "@images", "@.snapshots", "@boot",
})

# The exact shape phoenix-restore gives a swapped-out root. Anything else that
# merely starts with @_prev is reported and refused, never deleted: a name we
# did not write is a name we cannot reason about.
PREVIOUS_RE = re.compile(r"^@_prev_(?P<stamp>\d{14})(?P<recovered>_recovered)?$")
# A snapper Point number as it may appear in argv. No leading zeros, no signs,
# no path separators, bounded length - this string is concatenated into a path
# that is then handed to a root-run subvolume operation.
POINT_RE = re.compile(r"^[1-9][0-9]{0,8}$")

# The inode number the kernel gives every Btrfs subvolume root.
SUBVOLUME_INODE = 256

FAIL = "FAIL"
WARN = "WARN"


class LayoutError(ValueError):
    """The caller asked for something the layout cannot express."""


def btrfs_subvolume(path: Path) -> bool:
    """True when `path` is a Btrfs subvolume root. Kernel truth, no exec."""
    try:
        st = os.lstat(path)
    except OSError:
        return False
    return stat.S_ISDIR(st.st_mode) and st.st_ino == SUBVOLUME_INODE


def mount_fstype(path: str | os.PathLike[str]) -> str | None:
    """Filesystem type of the mount `path` lives on, from /proc/self/mountinfo.

    Returns None when the mountinfo cannot be read or no mount point matches
    (a caller must treat that as "unknown", never as "btrfs").
    """
    try:
        target = os.path.realpath(path)
        with open("/proc/self/mountinfo", "r", encoding="utf-8") as handle:
            entries = handle.read().splitlines()
    except OSError:
        return None
    best: tuple[int, str] | None = None
    for line in entries:
        # <id> <parent> <maj:min> <root> <mountpoint> <opts> [tags] - <fstype> ...
        head, sep, tail = line.partition(" - ")
        if not sep:
            continue
        head_fields = head.split(" ")
        tail_fields = tail.split(" ")
        if len(head_fields) < 5 or not tail_fields:
            continue
        mountpoint = head_fields[4].replace("\\040", " ").replace("\\011", "\t")
        fstype = tail_fields[0]
        if target == mountpoint or target.startswith(
                mountpoint.rstrip("/") + "/") or mountpoint == "/":
            # >= so a later mountinfo line (which shadows an earlier one at
            # the same mountpoint) wins.
            if best is None or len(mountpoint) >= best[0]:
                best = (len(mountpoint), fstype)
    return best[1] if best else None


@dataclass(frozen=True)
class Problem:
    level: str          # FAIL or WARN
    code: str
    detail: str

    def __str__(self) -> str:
        return f"{self.level} {self.code}: {self.detail}"


@dataclass(frozen=True)
class Entry:
    name: str
    path: Path
    is_subvolume: bool


@dataclass(frozen=True)
class PreviousRoot:
    """A swapped-out root kept for one generation, as @_prev_<TS>[_recovered]."""

    name: str
    path: Path
    stamp: datetime
    recovered: bool
    is_subvolume: bool

    @property
    def sort_key(self) -> tuple:
        """Retention rank, lowest collected first.

        Two corrections to `ls -d @_prev_* | sort | tail -1`:

        * the PARSED timestamp, not the string. Lexicographically
          @_prev_<TS>_recovered sorts after @_prev_<TS>, so the shell could
          keep a parked leftover and delete the real previous root of the
          same second.
        * provenance outranks recency. `_recovered` means "this subvolume was
          parked because nothing could prove what it was" - phoenix-restore
          parks a leftover @new under the CURRENT run's timestamp, which made
          an unidentified leftover the newest thing on the volume and pushed
          the genuine previous root out of a keep=1 retention. A root we know
          the provenance of is worth more than a newer one we do not.
        """
        return (1 if self.recovered else 2, self.stamp, self.name)


@dataclass(frozen=True)
class Layout:
    """Everything Phoenix recovery knows about one mounted Btrfs top-level."""

    mount: Path
    fstype: str | None
    entries: tuple[Entry, ...]
    previous: tuple[PreviousRoot, ...]
    problems: tuple[Problem, ...] = field(default=())

    # -- construction ------------------------------------------------------
    @classmethod
    def probe(cls, mount: str | os.PathLike[str], *,
              detector: Callable[[Path], bool] = btrfs_subvolume,
              fstype: str | None | object = None) -> "Layout":
        """Read the top-level of an already-mounted volume.

        `mount` must be the volume top-level (mount -o subvolid=5), not /.
        """
        base = Path(mount)
        resolved_fstype = mount_fstype(base) if fstype is None else fstype
        entries: list[Entry] = []
        try:
            names = sorted(child.name for child in base.iterdir())
        except OSError as exc:
            return cls(mount=base, fstype=resolved_fstype, entries=(),
                       previous=(),
                       problems=(Problem(FAIL, "unreadable",
                                         f"cannot read {base}: {exc}"),))
        for name in names:
            path = base / name
            entries.append(Entry(name=name, path=path,
                                 is_subvolume=bool(detector(path))))

        previous: list[PreviousRoot] = []
        problems: list[Problem] = []
        by_name = {entry.name: entry for entry in entries}

        for entry in entries:
            match = PREVIOUS_RE.match(entry.name)
            if match:
                try:
                    stamp = datetime.strptime(match["stamp"], "%Y%m%d%H%M%S")
                except ValueError:
                    problems.append(Problem(
                        WARN, "previous-unparsed",
                        f"{entry.name} has an impossible timestamp - left alone"))
                    continue
                previous.append(PreviousRoot(
                    name=entry.name, path=entry.path, stamp=stamp,
                    recovered=bool(match["recovered"]),
                    is_subvolume=entry.is_subvolume))
                if not entry.is_subvolume:
                    problems.append(Problem(
                        WARN, "previous-not-subvolume",
                        f"{entry.name} is not a subvolume - left alone"))
            elif entry.name.startswith("@_prev"):
                problems.append(Problem(
                    WARN, "previous-unparsed",
                    f"{entry.name} does not match @_prev_<timestamp> - left alone"))

        root = by_name.get(ROOT_NAME)
        if root is None:
            problems.append(Problem(
                FAIL, "no-root",
                f"no {ROOT_NAME} subvolume on {base} - refusing to touch this volume"))
        elif not root.is_subvolume:
            problems.append(Problem(
                FAIL, "root-not-subvolume",
                f"{ROOT_NAME} exists but is not a subvolume - unexpected layout"))

        snapshots = by_name.get(SNAPSHOTS_NAME)
        if snapshots is None:
            problems.append(Problem(
                FAIL, "no-snapshots",
                f"no {SNAPSHOTS_NAME} subvolume - Phoenix Points have nowhere to live"))
        elif not snapshots.is_subvolume:
            problems.append(Problem(
                WARN, "snapshots-not-subvolume",
                f"{SNAPSHOTS_NAME} is a plain directory: Points work, but the"
                " history does not survive a root-subvolume swap"))

        if STAGING_NAME in by_name:
            problems.append(Problem(
                WARN, "staging-present",
                f"{STAGING_NAME} exists - a restore was interrupted"))

        if resolved_fstype not in (None, "btrfs"):
            problems.append(Problem(
                FAIL, "not-btrfs",
                f"{base} is {resolved_fstype}, not btrfs"))

        previous.sort(key=lambda item: item.sort_key)
        return cls(mount=base, fstype=resolved_fstype, entries=tuple(entries),
                   previous=tuple(previous), problems=tuple(problems))

    # -- accessors ---------------------------------------------------------
    def entry(self, name: str) -> Entry | None:
        for item in self.entries:
            if item.name == name:
                return item
        return None

    @property
    def root(self) -> Entry | None:
        return self.entry(ROOT_NAME)

    @property
    def staging(self) -> Entry | None:
        return self.entry(STAGING_NAME)

    @property
    def snapshots(self) -> Entry | None:
        return self.entry(SNAPSHOTS_NAME)

    @property
    def failures(self) -> tuple[Problem, ...]:
        return tuple(p for p in self.problems if p.level == FAIL)

    @property
    def warnings(self) -> tuple[Problem, ...]:
        return tuple(p for p in self.problems if p.level == WARN)

    @property
    def ok(self) -> bool:
        """True when the layout is one this package is willing to MUTATE.

        Warnings are degraded-but-working states; a FAIL means the volume is
        not the layout phoenix-restore built, and the only correct action on a
        layout we do not recognise is none.
        """
        return not self.failures

    def point_source(self, point: str) -> Path:
        """Path of Point `point`'s snapshot. Raises on anything unparseable."""
        if not POINT_RE.match(str(point)):
            raise LayoutError(
                f"{point!r} is not a Phoenix Point number")
        return self.mount / SNAPSHOTS_NAME / str(point) / "snapshot"

    def has_point(self, point: str,
                  detector: Callable[[Path], bool] = btrfs_subvolume) -> bool:
        try:
            source = self.point_source(point)
        except LayoutError:
            return False
        return detector(source)

    def describe(self) -> list[str]:
        lines = [f"volume:      {self.mount} ({self.fstype or 'unknown fs'})"]
        root = self.root
        lines.append("root:        %s" % (
            "@ (subvolume)" if root and root.is_subvolume else "MISSING"))
        staging = self.staging
        lines.append("staging:     %s" % (
            "@new present - interrupted restore" if staging else "none"))
        if self.previous:
            lines.append("previous:    " + ", ".join(
                item.name for item in reversed(self.previous)))
        else:
            lines.append("previous:    none")
        for problem in self.problems:
            lines.append(str(problem))
        return lines
