"""RestoreTransaction: what an interrupted phoenix-restore left, and what to do.

phoenix-restore is crash-atomic in the sense that matters most - an @ subvolume
exists at every instant - but "the machine still boots" is not the same as "the
restore finished". Three things can be left in flight by a power cut, and
through 4.0.0 only the first was handled, by guesswork:

  1. @new exists. phoenix-postboot renamed it to @_prev_<now>_recovered with
     the comment "never delete blind (if the crash was after the exchange, @new
     IS the previous root)". That comment is exactly right about the ambiguity
     and does not resolve it: after a crash BEFORE the exchange, @new is a
     throwaway copy of a Point that still exists, and parking it costs a
     generation of the real previous root at the next collection.

  2. The update-grub flag. phoenix-restore wrote it into @ AFTER the exchange,
     so a crash in the window between the two lost it and the restored root
     came up with a GRUB menu still describing the old one.

  3. The external /boot. The shell's cleanup trap rolls the kernel staging back
     on SIGINT/SIGTERM, but a power cut runs no trap. The machine then boots
     the OLD root against a /boot whose only kernel belongs to the Point -
     precisely the mismatch W-11 set out to make impossible.

The fix to (2) is also the evidence that resolves (1). phoenix-restore now
writes the flag into @new BEFORE the exchange, carrying date=<run>. The flag is
therefore inside the subvolume that becomes @ if and only if the exchange
happened, and comparing it against the journal's in-flight run decides the
question from the filesystem itself:

    flag date in @      == run   ->  the exchange COMPLETED   (@new is the old root)
    flag date in @new   == run   ->  it did NOT               (@new is a copy)

The journal's phase is used as a second, independent witness, and when the two
disagree - or when neither is present - the decision is PARK: keep everything,
change nothing, say so. An honest "I cannot tell" is the only correct answer
when the alternative is deleting somebody's root filesystem.
"""

from __future__ import annotations

import enum
import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from . import gc as gcmod
from .journal import (POST_EXCHANGE_PHASES, PRE_EXCHANGE_PHASES, IntentJournal)
from .layout import Layout, STAGING_NAME
from .trusted import ExecutableError, TrustedExecutor

__all__ = [
    "FLAG_REL", "SYSTEM_BOOT", "Decision", "Step", "RestoreState",
    "RestoreTransaction", "read_flag", "rename_exchange",
]

# The only /boot this system's update-grub can write. `update-grub` is
# grub-mkconfig hard-wired to /boot/grub/grub.cfg; there is no way to aim it at
# another directory, so a caller working on some OTHER /boot gets the file
# moves and the grubenv edit (which does take a path) and is told the menu was
# not rebuilt, rather than having this machine's menu rewritten behind its back.
SYSTEM_BOOT = Path("/boot")

# Written by phoenix-restore into the subvolume that is about to become @, and
# consumed by phoenix-postboot to rebuild the boot menu once.
FLAG_REL = "var/lib/shadowfetch/phoenix-update-grub"


class Decision(str, enum.Enum):
    NOTHING = "nothing"                 # no restore is in flight
    FINISH_EXCHANGE = "finish-exchange" # the swap happened: park the old root
    DISCARD_STAGING = "discard-staging" # the swap did not: @new is a throwaway
    PARK_STAGING = "park-staging"       # cannot prove either way: keep it
    BLOCKED = "blocked"                 # the layout is not one we may mutate


@dataclass(frozen=True)
class Step:
    kind: str
    detail: str


@dataclass(frozen=True)
class RestoreState:
    decision: Decision
    run: str | None
    point: str | None
    phase: str | None
    exchanged: bool | None              # None = undecidable
    evidence: str
    boot_rollback: bool
    previous_name: str | None
    steps: tuple[Step, ...] = field(default=())

    def describe(self) -> list[str]:
        lines = [f"decision:    {self.decision.value}",
                 f"run:         {self.run or 'none in flight'}",
                 f"point:       {self.point or '-'}",
                 f"phase:       {self.phase or '-'}",
                 f"exchanged:   {'unknown' if self.exchanged is None else self.exchanged}",
                 f"evidence:    {self.evidence}"]
        if self.boot_rollback:
            lines.append("boot:        external /boot staging must be rolled back")
        for step in self.steps:
            lines.append(f"step:        {step.kind} - {step.detail}")
        return lines


def read_flag(subvolume: Path) -> dict[str, str]:
    """Parse a phoenix-update-grub flag out of a subvolume. Missing = empty."""
    values: dict[str, str] = {}
    try:
        text = (subvolume / FLAG_REL).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return values
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            values[key.strip()] = value.strip()
    return values


def rename_exchange(first: Path, second: Path) -> None:
    """renameat2(RENAME_EXCHANGE) - the atomic swap, as one syscall.

    Used by the resume path's tests and by nothing that ships in the restore
    hot path (phoenix-restore does its own exchange with coreutils >= 9.5's
    `mv --exchange`). It lives here so a test can exercise the real syscall on
    a real Btrfs rather than an imitation of it.
    """
    import ctypes

    at_fdcwd, rename_exchange_flag = -100, 2
    libc = ctypes.CDLL(None, use_errno=True)
    func = getattr(libc, "renameat2", None)
    old, new = str(first).encode(), str(second).encode()
    if func is not None:
        func.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                         ctypes.c_char_p, ctypes.c_uint]
        rc = func(at_fdcwd, old, at_fdcwd, new, rename_exchange_flag)
    else:                                            # x86_64 SYS_renameat2
        rc = libc.syscall(316, at_fdcwd, old, at_fdcwd, new, rename_exchange_flag)
    if rc != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err), str(first), None, str(second))


class RestoreTransaction:
    """Reads the volume and the journal; decides; and, if asked, finishes."""

    def __init__(self, layout: Layout, journal: IntentJournal,
                 boot: Path | None = None) -> None:
        self.layout = layout
        self.journal = journal
        self.boot = Path(boot) if boot is not None else None

    # -- deciding ----------------------------------------------------------
    def inspect(self) -> RestoreState:
        run, phase = self.journal.in_flight()
        point = self.journal.point_of(run) if run else None
        staging = self.layout.staging

        if not self.layout.ok:
            return RestoreState(
                decision=Decision.BLOCKED, run=run, point=point, phase=phase,
                exchanged=None, boot_rollback=False, previous_name=None,
                evidence="; ".join(str(p) for p in self.layout.failures))

        root = self.layout.root
        assert root is not None                      # implied by layout.ok
        root_flag = read_flag(root.path)
        staging_flag = read_flag(staging.path) if staging else {}

        exchanged: bool | None = None
        evidence = "no restore is in flight"
        if run:
            if phase in POST_EXCHANGE_PHASES:
                exchanged, evidence = True, f"journal reached phase {phase}"
            elif root_flag.get("date") == run:
                exchanged, evidence = True, "@ carries the flag written for this run"
            elif staging_flag.get("date") == run:
                exchanged, evidence = False, "@new still carries this run's flag"
            elif phase in PRE_EXCHANGE_PHASES:
                exchanged, evidence = False, f"journal stopped at phase {phase}"
            else:
                evidence = f"phase {phase} with no flag on either subvolume"
        elif staging is not None:
            # No journal (an older restore, or the top-level copy was lost).
            # The two flags still carry timestamps, and the newer one names the
            # subvolume that was prepared last.
            root_date = root_flag.get("date", "")
            staging_date = staging_flag.get("date", "")
            if root_date and root_date > staging_date:
                exchanged, evidence = True, "@ carries the newer restore flag"
            elif staging_date and staging_date > root_date:
                exchanged, evidence = False, "@new carries the newer restore flag"
            else:
                evidence = "no journal and no flag distinguishes @ from @new"

        steps: list[Step] = []
        boot_rollback = False
        previous_name: str | None = None

        if staging is None:
            decision = Decision.NOTHING
            if run and exchanged:
                # The swap and the parking both happened; only the journal's
                # closing record is missing.
                decision = Decision.NOTHING
                evidence += "; nothing is left staged"
        elif exchanged is True:
            decision = Decision.FINISH_EXCHANGE
            previous_name = root_flag.get("previous") or f"@_prev_{run or 'unknown'}"
            if not previous_name.startswith("@_prev_"):
                previous_name = f"@_prev_{run or 'unknown'}"
            if (self.layout.mount / previous_name).exists():
                previous_name = f"{previous_name}_recovered"
            steps.append(Step("park-previous",
                              f"rename {STAGING_NAME} to {previous_name}"
                              " (it is the root that was replaced)"))
        elif exchanged is False:
            decision = Decision.DISCARD_STAGING
            steps.append(Step("delete-staging",
                              f"delete {STAGING_NAME}: a writable copy of Point"
                              f" {point or '?'}, which still exists"))
        else:
            decision = Decision.PARK_STAGING
            previous_name = f"@_prev_{datetime.now().strftime('%Y%m%d%H%M%S')}_recovered"
            steps.append(Step("park-staging",
                              f"rename {STAGING_NAME} to {previous_name}:"
                              " it cannot be proved to be a discardable copy"))

        # The external /boot. Only ever rolled back when the root was NOT
        # exchanged: after a completed exchange the staged /boot is the correct
        # one, and putting the old kernels back would recreate W-11 in reverse.
        if run and exchanged is False and self.boot is not None:
            archive = self.boot / f"phoenix-kernel-backup-{run}"
            if archive.is_dir():
                boot_rollback = True
                steps.append(Step(
                    "rollback-boot",
                    f"move {archive.name} back into {self.boot} and rebuild the"
                    " boot menu: the root was never exchanged, so this /boot"
                    " belongs to a generation that is not on disk"))

        return RestoreState(decision=decision, run=run, point=point, phase=phase,
                            exchanged=exchanged, evidence=evidence,
                            boot_rollback=boot_rollback,
                            previous_name=previous_name, steps=tuple(steps))

    # -- acting ------------------------------------------------------------
    def resume(self, state: RestoreState, executor: TrustedExecutor,
               dry_run: bool = False) -> list[str]:
        """Carry out `state`'s steps. Returns human-readable outcomes.

        Ordering is deliberate: /boot is repaired FIRST. If the pass dies
        halfway, a machine whose kernels are back in /boot and whose top-level
        still holds an unparked @new is in a strictly better place than the
        reverse, and the next pass reaches the same decision again because
        nothing it depends on has changed.
        """
        outcomes: list[str] = []
        if state.decision is Decision.BLOCKED:
            return ["refused: " + state.evidence]

        if state.boot_rollback and state.run and self.boot is not None:
            outcomes.extend(self._rollback_boot(state.run, executor, dry_run))

        staging = self.layout.staging
        if staging is None:
            if state.boot_rollback and state.run and not dry_run:
                # /boot was the only thing left in flight, and it is repaired.
                self._journal(state, "rolled-back",
                              "phoenix-recover undid an interrupted restore")
            return outcomes or ["nothing to resume"]

        if state.decision is Decision.DISCARD_STAGING:
            if dry_run:
                outcomes.append(f"dry run: would delete {staging.name}")
            else:
                try:
                    executor.run("btrfs", "subvolume", "delete", str(staging.path))
                    outcomes.append(f"deleted {staging.name} (a discarded copy)")
                    # Terminal: the attempt is undone in full, so a later pass
                    # sees no run in flight rather than re-deciding it.
                    self._journal(state, "rolled-back",
                                  "deleted @new: the exchange never happened")
                except ExecutableError as exc:
                    outcomes.append(f"could not delete {staging.name}: {exc}")
        elif state.decision in (Decision.FINISH_EXCHANGE, Decision.PARK_STAGING):
            target = self.layout.mount / (state.previous_name or "@_prev_unknown")
            if dry_run:
                outcomes.append(f"dry run: would rename {staging.name} to {target.name}")
            else:
                try:
                    os.rename(staging.path, target)
                    outcomes.append(f"renamed {staging.name} to {target.name}")
                    phase = ("previous-parked"
                             if state.decision is Decision.FINISH_EXCHANGE else "resume")
                    self._journal(state, phase,
                                  f"resume parked {STAGING_NAME} as {target.name}")
                    if state.decision is Decision.FINISH_EXCHANGE:
                        self._journal(state, "complete",
                                      "restore completed by phoenix-recover")
                except OSError as exc:
                    outcomes.append(f"could not rename {staging.name}: {exc}")
        return outcomes

    # -- pieces ------------------------------------------------------------
    def _rollback_boot(self, run: str, executor: TrustedExecutor,
                       dry_run: bool) -> list[str]:
        assert self.boot is not None
        archive = self.boot / f"phoenix-kernel-backup-{run}"
        outcomes: list[str] = []
        if dry_run:
            return [f"dry run: would restore {archive.name} into {self.boot}"]

        moved = 0
        for source in sorted(archive.iterdir()):
            if not source.is_file() or source.is_symlink():
                outcomes.append(f"left {source.name}: not a plain kernel file")
                continue
            if not source.name.startswith(gcmod.KERNEL_PREFIXES):
                outcomes.append(f"left {source.name}: not a kernel file")
                continue
            target = self.boot / source.name
            if target.exists():
                continue
            try:
                os.replace(source, target)
                moved += 1
            except OSError as exc:
                outcomes.append(f"could not restore {source.name}: {exc}")
        try:
            archive.rmdir()
        except OSError:
            outcomes.append(f"{archive.name} still holds files - left in place")
        outcomes.append(f"restored {moved} kernel file(s) into {self.boot}")

        # Release the pinned next boot before rebuilding the menu, so a failure
        # of either one cannot leave GRUB pointing at an entry that no longer
        # exists. Both are best-effort: neither is what makes the system
        # bootable, and refusing to finish the rollback because a boot-menu
        # tool is missing would be worse than a stale menu.
        grubenv = self.boot / "grub/grubenv"
        if grubenv.exists() and executor.available("grub-editenv"):
            try:
                executor.run("grub-editenv", str(grubenv), "unset", "next_entry")
                outcomes.append("released the pinned next boot")
            except ExecutableError as exc:
                outcomes.append(f"could not release the pinned next boot: {exc}")
        if self.boot != SYSTEM_BOOT:
            outcomes.append(
                f"boot menu NOT rebuilt: {self.boot} is not {SYSTEM_BOOT}, and"
                " update-grub only ever writes this system's own menu")
        elif executor.available("update-grub"):
            try:
                executor.run("update-grub")
                outcomes.append("rebuilt the boot menu")
            except ExecutableError as exc:
                outcomes.append(f"could not rebuild the boot menu: {exc}")
        # Not terminal on its own: the staging decision below still has to be
        # carried out before this attempt is finished with.
        self._journal_run(run, "resume",
                          "phoenix-recover rolled the external /boot back")
        return outcomes

    def _journal(self, state: RestoreState, phase: str, message: str) -> None:
        self._journal_run(state.run or "unknown", phase, message,
                          point=state.point or "unknown")

    def _journal_run(self, run: str, phase: str, message: str,
                     point: str = "unknown") -> None:
        self.journal.append(point=point, run=run, phase=phase, message=message)
