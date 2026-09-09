"""The single implementation of "which Phoenix Point precedes this update".

THE RULE STAGE U EXISTS TO ENFORCE: two systems must not independently
decide snapshot/update behaviour, because that is how a rollback and an
update come to disagree about what state the machine is in.

Before Stage U this file's contents existed twice, in two languages, with
two different answers:

  * fireproofd (python) named the FIRST type=pre snapshot above the
    pre-commit maximum, relabelled it "Fireproof: before update <date>
    (<n> pkgs)" and attached `fireproof=pre,txn=<uuid>` userdata, then
    recorded the number in fireproof-state.json AND fireproof-pending, so
    `fireproof rollback`, the postboot check and the Phoenix panel all
    resolved the same Point.
  * shadowfetch-update (bash) computed the same number with its own awk,
    relabelled the SAME Point "Shadowfetch: before safe update <date>"
    with NO userdata, and recorded it NOWHERE. So after a
    `shadowfetch-update` run the recorded rollback target still pointed at
    the previous Fireproof transaction, and a rollback would have restored
    the wrong system state - silently, and only on the machines where it
    mattered most.

Both are now this module. Nothing else in the tree may derive a Point.

Every snapper invocation goes through sfupdate.trusted: the number this
module returns is handed to `pkexec /usr/libexec/phoenix-restore`, so a
substitutable snapper is an attacker choosing the user's root subvolume.
An untrusted or absent snapper yields "unavailable", never a fabricated
number and never Point 0 - 0 is snapper's "current" pseudo-snapshot, not a
restore target.

Fireproof CREATES no snapshots. snapper's shipped 80snapper
DPkg::Pre/Post-Invoke hooks (plus Phoenix's 79phoenix-space) wrap the
commit; this module only READS them and RELABELS the one it named.
"""

from __future__ import annotations

import os

from .trusted import EXECUTOR, ExecutableError

__all__ = [
    "SNAPPER_CONFIG", "Snapshot", "snapshot_rows", "max_number",
    "first_pre_after", "phoenix_available", "label_point",
    "point_userdata",
]

SNAPPER_CONFIG = "root"

#: The userdata every Fireproof pre-Point carries. `fireproof=pre` is what
#: makes a Point identifiable as an update Point by anything that reads
#: snapper directly (the Phoenix panel, grub-btrfs submenus).
USERDATA_KEY = "fireproof"
USERDATA_PRE = "pre"


def _executor(executor):
    """Resolve the executor at CALL time.

    Never `executor=EXECUTOR` in a signature: that binds the process-wide
    executor into the default at import, so a caller with its own trust
    table - or a test proving a forged binary is refused - would silently
    keep using the original one.
    """
    return EXECUTOR if executor is None else executor


class Snapshot(tuple):
    """(number, type, date, description) with names, and nothing else."""

    __slots__ = ()

    def __new__(cls, number, type_, date="", description=""):
        return super().__new__(cls, (int(number), type_, date, description))

    number = property(lambda self: self[0])
    type = property(lambda self: self[1])
    date = property(lambda self: self[2])
    description = property(lambda self: self[3])


def parse_snapper_csv(text: str) -> list[Snapshot]:
    """Parse `snapper --machine-readable csv list` output.

    Split on the first three commas only: a description legitimately
    contains commas ("Fireproof: before update ..., 42 pkgs") and splitting
    it further used to shift the columns.
    """
    rows: list[Snapshot] = []
    for line in text.splitlines()[1:]:
        parts = line.split(",", 3)
        if len(parts) < 2 or not parts[0].strip().isdigit():
            continue
        rows.append(Snapshot(
            parts[0].strip(),
            parts[1].strip(),
            parts[2].strip() if len(parts) > 2 else "",
            parts[3].strip() if len(parts) > 3 else "",
        ))
    return rows


def snapshot_rows(executor=None) -> list[Snapshot]:
    """Every snapper snapshot, or [] when snapper cannot be TRUSTED.

    [] is the honest answer to "I cannot establish this fact". Callers turn
    it into "rollback unavailable"; none of them may turn it into a Point.
    """
    executor = _executor(executor)
    try:
        rc, out, _err = executor.run(
            "snapper", "-c", SNAPPER_CONFIG, "--machine-readable", "csv",
            "list", "--columns", "number,type,date,description", timeout=20)
    except ExecutableError:
        return []
    if rc != 0:
        return []
    return parse_snapper_csv(out)


def max_number(rows=None, executor=None) -> int:
    """Highest existing snapshot number; 0 when there are none."""
    rows = snapshot_rows(executor) if rows is None else rows
    return max((row.number for row in rows), default=0)


def first_pre_after(number: int, rows=None, executor=None):
    """THE rollback target: the FIRST type=pre snapshot above `number`.

    One apt transaction can invoke dpkg several times, so it produces
    several pre/post pairs; the first pre is the only one that precedes
    the whole change set. Returns None when there is none - never 0.
    """
    rows = snapshot_rows(executor) if rows is None else rows
    pres = sorted(row.number for row in rows
                  if row.type == "pre" and row.number > number)
    return pres[0] if pres else None


def _apt_snapshots_disabled() -> bool:
    try:
        with open("/etc/default/snapper") as handle:
            for line in handle:
                line = line.strip()
                if not line.startswith("DISABLE_APT_SNAPSHOT"):
                    continue
                value = line.split("=", 1)[1].strip().strip('"').strip("'")
                if value.lower() in ("yes", "true", "1"):
                    return True
    except (OSError, IndexError):
        pass
    return False


def phoenix_available(executor=None) -> bool:
    """Can this install produce a Point at all?

    Btrfs root + a snapper root config + apt snapshots not disabled + a
    TRUSTED snapper. False is a product claim ("rollback unavailable on
    this filesystem"), so it must never be answered by a substitutable
    findmnt: an attacker who can force `btrfs` here makes Fireproof
    promise a rollback that does not exist.
    """
    executor = _executor(executor)
    try:
        rc, out, _err = executor.run("findmnt", "-n", "-o", "FSTYPE", "/",
                                     timeout=5)
    except ExecutableError:
        return False
    if rc != 0 or out.strip() != "btrfs":
        return False
    if not os.path.exists("/etc/snapper/configs/%s" % SNAPPER_CONFIG):
        return False
    if _apt_snapshots_disabled():
        return False
    return executor.available("snapper")


def point_userdata(txn: str) -> str:
    return "%s=%s,txn=%s" % (USERDATA_KEY, USERDATA_PRE, txn)


def label_point(point: int, description: str, txn: str,
                executor=None) -> bool:
    """Relabel the named Point. The ONLY snapper mutation in the product.

    Returns False when snapper is not trusted or the modify failed; the
    caller keeps the recorded number either way, because the Point exists
    whether or not its label took.
    """
    executor = _executor(executor)
    try:
        rc, _out, _err = executor.run(
            "snapper", "-c", SNAPPER_CONFIG, "modify",
            "-d", description,
            "-u", point_userdata(txn),
            str(int(point)), timeout=20)
    except ExecutableError:
        return False
    return rc == 0
