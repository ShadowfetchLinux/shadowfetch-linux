"""The single store of "what did the last update do to this machine".

Two files under /var/lib/shadowfetch, and no third place:

  fireproof-state.json  the durable record. last_txn (uuid, change-set
                        hash, date, pre_point, verdict, kernels) and a
                        bounded failed_sets history, which is what makes a
                        rolled-back change set re-simulate as "Don't
                        proceed" instead of being offered again as if
                        nothing had happened.
  fireproof-pending     the first-boot-after-update flag, written BEFORE
                        any reboot offer reaches the user and cleared by
                        fireproof-postboot on a good boot. GRUB has no boot
                        assessment on this platform, so this flag is the
                        whole "recovery opens at the right Point" claim.

Why one store matters here more than anywhere else: ROLLBACK reads
pre_point from this record and hands it to phoenix-restore. An updater
that mutates packages without writing here leaves the record describing an
OLDER transaction, and the next rollback restores the wrong system - which
is exactly what `shadowfetch-update` did before Stage U. Any future code
that commits packages MUST record here, in the same shape, or it is a
second system deciding update state.

Writes are atomic (tmp + fsync + rename) and the containing directory is
fsynced too, so a power cut during the commit cannot leave a rename that
the directory entry has not committed - the flag this protects is read on
the very next boot, which may be the boot after that power cut.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

__all__ = [
    "STATE_DIR", "STATE_FILE", "PENDING_FILE", "SCHEMA",
    "FAILED_SET_HISTORY", "now_iso", "atomic_write",
    "load_state", "save_state", "record_failed_set",
    "read_pending", "write_pending", "clear_pending",
    "rollback_target",
]

STATE_DIR = "/var/lib/shadowfetch"
STATE_FILE = os.path.join(STATE_DIR, "fireproof-state.json")
PENDING_FILE = os.path.join(STATE_DIR, "fireproof-pending")
SCHEMA = 1
FAILED_SET_HISTORY = 16


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def atomic_write(path: str, text: str) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)
    # The rename itself needs the directory entry on disk: this record is
    # read on the next boot, which may be the boot after the crash.
    dirfd = os.open(os.path.dirname(path) or ".", os.O_DIRECTORY)
    try:
        os.fsync(dirfd)
    finally:
        os.close(dirfd)


def _empty():
    return {"schema": SCHEMA, "failed_sets": [], "last_txn": None}


def load_state(path: str = STATE_FILE) -> dict:
    try:
        with open(path) as handle:
            state = json.load(handle)
        if isinstance(state, dict):
            state.setdefault("schema", SCHEMA)
            state.setdefault("failed_sets", [])
            state.setdefault("last_txn", None)
            return state
    except (OSError, ValueError):
        pass
    return _empty()


def save_state(state: dict, path: str = STATE_FILE) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    atomic_write(path, json.dumps(state, indent=1, sort_keys=True) + "\n")


def record_failed_set(state: dict, change_set_hash: str, reason: str) -> dict:
    """Remember that this exact change set failed or was rolled back.

    Keyed by the change_set_hash, so it is the SET that is remembered, not
    the day: the same packages offered again next week still analyze as
    "Don't proceed". Bounded history - a machine that fails an update every
    day must not grow this file without limit.
    """
    sets = [entry for entry in state.get("failed_sets", [])
            if entry.get("hash") != change_set_hash]
    sets.append({"hash": change_set_hash, "date": now_iso(), "reason": reason})
    state["failed_sets"] = sets[-FAILED_SET_HISTORY:]
    return state


def read_pending(path: str = PENDING_FILE):
    try:
        with open(path) as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return None


def write_pending(txn: str, pre_point, kernels, path: str = PENDING_FILE) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    atomic_write(path, json.dumps({
        "txn": txn,
        "pre_point": pre_point,
        "written": now_iso(),
        "kernels": list(kernels or []),
    }) + "\n")


def clear_pending(path: str = PENDING_FILE) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


def rollback_target(state: dict, pending=None) -> dict:
    """The Point the ONE rollback button restores.

    Pending (this boot follows a commit) wins over the durable record, so a
    machine that just updated offers the Point of the update it just did.
    A missing Point is reported as None with phoenix_available answered
    separately - never as 0, which is snapper's "current" pseudo-snapshot
    and would restore the machine to itself while claiming a rollback.
    """
    last = state.get("last_txn") or {}
    point = None
    source = None
    if pending and pending.get("pre_point") is not None:
        point, source = pending["pre_point"], "pending"
    elif last.get("pre_point") is not None:
        point, source = last["pre_point"], "state"
    return {
        "point": point,
        "source": source,
        "txn": last.get("txn"),
        "command": ("pkexec /usr/libexec/phoenix-restore %s" % point
                    if point is not None else None),
    }
