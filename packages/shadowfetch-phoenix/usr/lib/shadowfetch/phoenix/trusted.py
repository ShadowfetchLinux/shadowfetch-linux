"""Trusted executable resolution for Phoenix root recovery.

PERMANENT INVARIANT. Any executable used to establish, verify, enforce or
attest a security fact is invoked through an explicit trusted ABSOLUTE path
and has a defined trust classification. No shutil.which(), no PATH lookup,
anywhere its output decides a question. The rule was written after a real
CRITICAL defect elsewhere in the tree: a journalctl resolved through a
user-writable PATH could forge a clean audit.

The fact this module protects is "which subvolume may be destroyed", and the
consequence of forging it is `btrfs subvolume delete` aimed at the user's
root filesystem. So resolution REFUSES anything that is not DISTRO_MANAGED
rather than degrading to a warning, and the recovery tools treat that refusal
as "do nothing" rather than "guess".

Two further consequences of the same reasoning:

  * Layout facts are read from the kernel, not from a program. Whether a
    directory is a subvolume is `st_ino == 256`; the filesystem type of a
    mount comes from /proc/self/mountinfo. Neither can be substituted by
    anything short of the kernel itself, so neither appears here.
  * Every child process gets a fixed PATH. `update-grub` is a shell script
    that resolves its own helpers through PATH; inheriting the caller's PATH
    into a root-run update-grub would reintroduce the defect one level down.
"""

from __future__ import annotations

import enum
import os
import stat
import subprocess
from pathlib import Path

__all__ = [
    "ExecutableTrust", "TRUSTED_PATHS", "SAFE_PATH", "SAFE_ENV",
    "ExecutableError", "classify", "TrustedExecutor",
]


class ExecutableTrust(str, enum.Enum):
    """What a candidate path turned out to be - never what it claims."""

    DISTRO_MANAGED = "distro-managed"   # packaged path, root-owned all the way up
    UNTRUSTED = "untrusted"             # somebody other than root can substitute it
    ABSENT = "absent"                   # nothing is installed at that path


# Candidate ABSOLUTE paths per tool, in preference order. Both the merged-/usr
# and the split spellings are listed because a non-merged host really does
# install to /sbin; the classification, never the spelling, is what grants
# trust, so listing an extra path cannot widen the trust boundary.
TRUSTED_PATHS: dict[str, tuple[str, ...]] = {
    # The only tool that MUTATES: subvolume deletion during bounded GC.
    "btrfs": ("/usr/bin/btrfs", "/usr/sbin/btrfs", "/bin/btrfs", "/sbin/btrfs"),
    "mount": ("/usr/bin/mount", "/bin/mount"),
    "umount": ("/usr/bin/umount", "/bin/umount"),
    "update-grub": ("/usr/sbin/update-grub", "/sbin/update-grub"),
    "grub-editenv": ("/usr/bin/grub-editenv", "/usr/sbin/grub-editenv",
                     "/bin/grub-editenv", "/sbin/grub-editenv"),
}

# A fixed PATH for children. See the module docstring: update-grub is a shell
# script and would otherwise resolve its helpers through the caller's PATH.
SAFE_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
SAFE_ENV = {"PATH": SAFE_PATH, "LC_ALL": "C", "LANG": "C"}


class ExecutableError(RuntimeError):
    """No sufficiently trusted executable, or one that failed."""


def _node_is_root_owned(st: os.stat_result) -> bool:
    """Root-owned and not writable by group or other.

    Group-writability is disqualifying without exception here. sf_providers
    can afford to reason about a user's private group because it is judging a
    user's own runtime; this module is judging a binary that will be handed a
    subvolume path to delete as root.
    """
    if st.st_uid != 0:
        return False
    return not (st.st_mode & (stat.S_IWGRP | stat.S_IWOTH))


def classify(path: str | os.PathLike[str]) -> ExecutableTrust:
    """Classify one absolute candidate path.

    DISTRO_MANAGED requires all of: the path is absolute; the node and every
    parent directory up to / are root-owned and not group/other writable; the
    final target is a regular, executable file. A symlink is checked as the
    link node AND as its target, because replacing either one substitutes the
    program.
    """
    p = Path(path)
    if not p.is_absolute():
        return ExecutableTrust.UNTRUSTED
    try:
        link_st = os.lstat(p)
    except OSError:
        return ExecutableTrust.ABSENT
    if not _node_is_root_owned(link_st):
        return ExecutableTrust.UNTRUSTED
    try:
        target_st = os.stat(p)
    except OSError:
        return ExecutableTrust.ABSENT
    if not stat.S_ISREG(target_st.st_mode):
        return ExecutableTrust.UNTRUSTED
    if not (target_st.st_mode & stat.S_IXUSR):
        return ExecutableTrust.UNTRUSTED
    if not _node_is_root_owned(target_st):
        return ExecutableTrust.UNTRUSTED
    # Every directory on the way down: a writable parent means the file can be
    # replaced wholesale even when the file itself is 0755 root:root.
    for parent in p.resolve().parents:
        try:
            parent_st = os.stat(parent)
        except OSError:
            return ExecutableTrust.UNTRUSTED
        if not _node_is_root_owned(parent_st):
            return ExecutableTrust.UNTRUSTED
    return ExecutableTrust.DISTRO_MANAGED


class TrustedExecutor:
    """Runs the small set of programs Phoenix recovery genuinely needs.

    Resolution is cached per name so that a path cannot be swapped between the
    check and the call within one recovery pass, and so that the classification
    reported by `inspect` is the one the subsequent `resume` actually used.
    """

    def __init__(self, paths: dict[str, tuple[str, ...]] | None = None,
                 timeout: float = 300.0) -> None:
        self._paths = dict(TRUSTED_PATHS if paths is None else paths)
        self._timeout = timeout
        self._resolved: dict[str, tuple[str | None, ExecutableTrust]] = {}

    # -- resolution --------------------------------------------------------
    def trust(self, name: str) -> tuple[str | None, ExecutableTrust]:
        """(path, classification) for `name`; path is None when nothing qualifies."""
        if name in self._resolved:
            return self._resolved[name]
        candidates = self._paths.get(name)
        if not candidates:
            raise ExecutableError(
                f"{name!r} is not in the Phoenix trusted-executable table")
        best = (None, ExecutableTrust.ABSENT)
        for candidate in candidates:
            verdict = classify(candidate)
            if verdict is ExecutableTrust.DISTRO_MANAGED:
                best = (candidate, verdict)
                break
            if verdict is ExecutableTrust.UNTRUSTED and best[1] is ExecutableTrust.ABSENT:
                # Remembered only so the refusal can say WHY, never used.
                best = (candidate, verdict)
        self._resolved[name] = best
        return best

    def resolve(self, name: str) -> str:
        path, verdict = self.trust(name)
        if verdict is not ExecutableTrust.DISTRO_MANAGED:
            raise ExecutableError(
                f"no trusted {name}: {path or 'not installed'} is {verdict.value}")
        assert path is not None
        return path

    def available(self, name: str) -> bool:
        try:
            self.resolve(name)
        except ExecutableError:
            return False
        return True

    # -- running -----------------------------------------------------------
    def run(self, name: str, *args: str, check: bool = True) -> subprocess.CompletedProcess:
        argv = [self.resolve(name), *args]
        result = subprocess.run(argv, capture_output=True, text=True,
                                env=dict(SAFE_ENV), timeout=self._timeout,
                                check=False)
        if check and result.returncode != 0:
            raise ExecutableError(
                "%s failed (%d): %s" % (" ".join(argv), result.returncode,
                                        (result.stderr or result.stdout).strip()))
        return result
