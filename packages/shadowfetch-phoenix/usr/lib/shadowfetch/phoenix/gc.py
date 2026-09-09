"""Bounded garbage collection for Phoenix restore leftovers.

Two kinds of leftover accumulate, and through 4.0.0 exactly one of them was
collected:

  * @_prev_<TS> on the volume top-level - the swapped-out root, kept for one
    generation. phoenix-postboot collected these with
    `ls -d @_prev_* | sort | tail -1` and `btrfs subvolume delete` on the rest.
    That is unbounded in the number of deletions it will attempt, orders by
    string rather than by timestamp (so @_prev_<TS>_recovered outranks the real
    @_prev_<TS> of the same second), and deletes anything whose name merely
    starts with @_prev_.
  * /boot/phoenix-kernel-backup-<TS> - the running system's kernels, moved
    aside when /boot is its own filesystem. NOTHING ever collected these. One
    per successful restore accumulates on the smallest filesystem on the
    machine, and each holds a full vmlinuz+initrd set.

The second one also hides a correctness defect: once a kernel has been
archived it is no longer in /boot, so a later phoenix-restore that needs it
reports "no kernel shared with the external /boot filesystem" and refuses -
the restore you most want (back to where you were) is the one archiving made
impossible. Collection therefore RESCUES before it deletes.

Every plan here is a value. Nothing in this module deletes as a side effect of
being asked what it would delete, and `apply_*` walks a plan that a caller has
already been able to print. Both planners are bounded by MAX_DELETES_PER_RUN:
a recovery pass that finds a volume it does not understand must stop, not
grind through it.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

from .layout import PREVIOUS_RE, PROTECTED_NAMES, Layout
from .trusted import ExecutableError, TrustedExecutor

__all__ = [
    "DEFAULT_KEEP", "MAX_DELETES_PER_RUN", "ARCHIVE_RE", "KERNEL_PREFIXES",
    "Decision", "GcPlan", "Rescue", "KernelArchivePlan",
    "plan_previous_roots", "apply_previous_roots",
    "plan_kernel_archives", "apply_kernel_archives",
]

DEFAULT_KEEP = 1
# One pass may destroy at most this many things. Chosen well above any healthy
# volume (a healthy one has 0 or 1 of each) and well below "walked into a
# directory that is not what we think it is".
MAX_DELETES_PER_RUN = 8

ARCHIVE_RE = re.compile(r"^phoenix-kernel-backup-(?P<stamp>\d{14})$")
# The only file names phoenix-restore ever moves into an archive. A file in an
# archive directory that is not one of these was put there by something else,
# and its presence blocks the directory's removal.
KERNEL_PREFIXES = ("vmlinuz-", "initrd.img-", "config-", "System.map-")


@dataclass(frozen=True)
class Decision:
    path: Path
    action: str          # "keep" | "delete" | "refuse"
    reason: str

    def __str__(self) -> str:
        return f"{self.action:6} {self.path.name}: {self.reason}"


@dataclass(frozen=True)
class GcPlan:
    decisions: tuple[Decision, ...]

    def _of(self, action: str) -> tuple[Decision, ...]:
        return tuple(d for d in self.decisions if d.action == action)

    @property
    def deletions(self) -> tuple[Decision, ...]:
        return self._of("delete")

    @property
    def keeps(self) -> tuple[Decision, ...]:
        return self._of("keep")

    @property
    def refusals(self) -> tuple[Decision, ...]:
        return self._of("refuse")


def plan_previous_roots(layout: Layout, keep: int = DEFAULT_KEEP) -> GcPlan:
    """Which @_prev_* to delete, keeping the `keep` newest by real timestamp.

    A layout with a FAIL is not collected at all: on a volume whose shape we do
    not recognise, "delete nothing" is the only safe plan.
    """
    if not layout.ok:
        return GcPlan(tuple(
            Decision(item.path, "refuse", "the volume layout is not usable")
            for item in layout.previous))
    if keep < 0:
        raise ValueError("keep must not be negative")

    decisions: list[Decision] = []
    ordered = list(layout.previous)                 # oldest -> newest
    # max(0, ...) because a negative start index slices from the END: asking to
    # keep 3 of 2 would have kept one and DELETED the other.
    survivors = set(ordered[max(0, len(ordered) - keep):]) if keep else set()
    budget = MAX_DELETES_PER_RUN

    for item in ordered:
        if item in survivors:
            decisions.append(Decision(
                item.path, "keep",
                "one of the %d retained previous root(s)"
                " (known provenance before recency)" % keep))
            continue
        if item.name in PROTECTED_NAMES:
            decisions.append(Decision(item.path, "refuse", "protected subvolume name"))
            continue
        if not PREVIOUS_RE.match(item.name):
            decisions.append(Decision(item.path, "refuse",
                                      "not a name phoenix-restore writes"))
            continue
        if not item.is_subvolume:
            decisions.append(Decision(
                item.path, "refuse",
                "not a subvolume - phoenix-restore never creates a plain"
                " directory here, so something else owns it"))
            continue
        if budget <= 0:
            decisions.append(Decision(
                item.path, "refuse",
                "over the %d-deletion bound for one pass" % MAX_DELETES_PER_RUN))
            continue
        budget -= 1
        decisions.append(Decision(item.path, "delete",
                                  "superseded by a newer previous root"))

    # Names that looked like previous roots but did not parse never reach
    # layout.previous; surface them so a plan explains the whole directory.
    for problem in layout.warnings:
        if problem.code == "previous-unparsed":
            decisions.append(Decision(layout.mount, "refuse", problem.detail))
    return GcPlan(tuple(decisions))


def apply_previous_roots(plan: GcPlan, executor: TrustedExecutor,
                         dry_run: bool = False) -> list[tuple[Path, bool, str]]:
    """Delete what the plan says to delete. Returns (path, deleted, detail)."""
    results: list[tuple[Path, bool, str]] = []
    for decision in plan.deletions:
        if dry_run:
            results.append((decision.path, False, "dry run"))
            continue
        try:
            executor.run("btrfs", "subvolume", "delete", str(decision.path))
        except ExecutableError as exc:
            results.append((decision.path, False, str(exc)))
            continue
        results.append((decision.path, True, "deleted"))
    return results


# --- external /boot kernel archives ---------------------------------------

@dataclass(frozen=True)
class Rescue:
    kernel: str
    source: Path
    target: Path


@dataclass(frozen=True)
class KernelArchivePlan:
    rescues: tuple[Rescue, ...]
    decisions: tuple[Decision, ...]

    @property
    def deletions(self) -> tuple[Decision, ...]:
        return tuple(d for d in self.decisions if d.action == "delete")

    @property
    def refusals(self) -> tuple[Decision, ...]:
        return tuple(d for d in self.decisions if d.action == "refuse")


def _archives(boot: Path) -> list[tuple[str, Path]]:
    found: list[tuple[str, Path]] = []
    try:
        children = sorted(boot.iterdir())
    except OSError:
        return found
    for child in children:
        match = ARCHIVE_RE.match(child.name)
        if match and child.is_dir():
            found.append((match["stamp"], child))
    found.sort(key=lambda item: item[0])            # oldest -> newest
    return found


def _archive_contents(archive: Path) -> tuple[dict[str, list[Path]], list[Path]]:
    """(kernel -> files, foreign files). Only KERNEL_PREFIXES names are ours."""
    kernels: dict[str, list[Path]] = {}
    foreign: list[Path] = []
    try:
        children = sorted(archive.iterdir())
    except OSError:
        return kernels, foreign
    for child in children:
        if not child.is_file() or child.is_symlink():
            foreign.append(child)
            continue
        for prefix in KERNEL_PREFIXES:
            if child.name.startswith(prefix):
                kernels.setdefault(child.name[len(prefix):], []).append(child)
                break
        else:
            foreign.append(child)
    return kernels, foreign


def plan_kernel_archives(boot: Path, modules_dir: Path,
                         keep: int = DEFAULT_KEEP) -> KernelArchivePlan:
    """Rescue kernels the CURRENT root still needs, then bound the archives.

    `modules_dir` is the running root's /lib/modules. A kernel with a modules
    directory but no vmlinuz in /boot is a kernel this machine cannot boot;
    if an archive holds it, moving it back is strictly a repair.
    """
    if keep < 0:
        raise ValueError("keep must not be negative")

    archives = _archives(boot)
    try:
        needed = {child.name for child in modules_dir.iterdir() if child.is_dir()}
    except OSError:
        needed = set()

    rescues: list[Rescue] = []
    rescued_from: set[Path] = set()
    for kernel in sorted(needed):
        if (boot / f"vmlinuz-{kernel}").exists():
            continue
        for _stamp, archive in reversed(archives):   # newest archive first
            kernels, _foreign = _archive_contents(archive)
            if kernel not in kernels:
                continue
            for source in kernels[kernel]:
                target = boot / source.name
                if target.exists():
                    continue
                rescues.append(Rescue(kernel=kernel, source=source, target=target))
            rescued_from.add(archive)
            break

    decisions: list[Decision] = []
    # max(0, ...): see plan_previous_roots - a negative start would slice from
    # the end and delete archives the caller asked to keep.
    survivors = ({path for _stamp, path in archives[max(0, len(archives) - keep):]}
                 if keep else set())
    budget = MAX_DELETES_PER_RUN
    for _stamp, archive in archives:
        if archive in survivors:
            decisions.append(Decision(archive, "keep",
                                      "one of the %d newest kernel backup(s)" % keep))
            continue
        _kernels, foreign = _archive_contents(archive)
        if foreign:
            decisions.append(Decision(
                archive, "refuse",
                "holds %d file(s) phoenix-restore did not put there" % len(foreign)))
            continue
        if budget <= 0:
            decisions.append(Decision(
                archive, "refuse",
                "over the %d-deletion bound for one pass" % MAX_DELETES_PER_RUN))
            continue
        budget -= 1
        decisions.append(Decision(archive, "delete",
                                  "superseded kernel backup"))
    return KernelArchivePlan(rescues=tuple(rescues), decisions=tuple(decisions))


def apply_kernel_archives(plan: KernelArchivePlan, dry_run: bool = False,
                          ) -> list[tuple[Path, bool, str]]:
    """Move rescued kernels back, then remove superseded archives.

    Removal unlinks only KERNEL_PREFIXES files and then rmdir()s: an archive
    that still holds anything else is left in place, so a stray file can never
    be swept up by a recursive delete running as root on /boot.
    """
    results: list[tuple[Path, bool, str]] = []
    for rescue in plan.rescues:
        if dry_run:
            results.append((rescue.source, False, f"dry run: rescue {rescue.kernel}"))
            continue
        try:
            os.replace(rescue.source, rescue.target)
        except OSError as exc:
            results.append((rescue.source, False, f"rescue failed: {exc}"))
            continue
        results.append((rescue.target, True, f"rescued kernel {rescue.kernel}"))

    for decision in plan.deletions:
        if dry_run:
            results.append((decision.path, False, "dry run"))
            continue
        kernels, foreign = _archive_contents(decision.path)
        if foreign:
            results.append((decision.path, False,
                            "left in place: it gained a foreign file"))
            continue
        failed = ""
        for files in kernels.values():
            for path in files:
                try:
                    path.unlink()
                except OSError as exc:
                    failed = str(exc)
        if failed:
            results.append((decision.path, False, failed))
            continue
        try:
            decision.path.rmdir()
        except OSError as exc:
            results.append((decision.path, False, str(exc)))
            continue
        results.append((decision.path, True, "removed"))
    return results
