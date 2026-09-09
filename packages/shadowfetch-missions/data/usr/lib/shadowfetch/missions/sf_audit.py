"""External anchoring for the Mission Control audit chain.

A hash chain proves that no row was ALTERED. It cannot prove that no row was
REMOVED FROM THE END: delete the last three events and every surviving row still
verifies, because each one's hash was only ever computed over itself and its
predecessor. That is not a flaw in the chain, it is what a chain is.

Detecting truncation needs a record the agent's uid cannot rewrite. journald is
that record: it is root-owned, the mission worker runs unprivileged, and an
append to it survives anything done to the SQLite file afterwards. So each
appended event's HEAD -- its sequence number and hash -- is mirrored there, and
`audit verify` compares the journal's high-water mark against the database's.

What this does NOT claim:
  * It is not tamper PROOF. Root can rewrite the journal.
  * It does not protect the mirror in transit; /dev/log is a local socket.
  * A journal that has rotated away old entries reports the horizon it can
    see, not a failure.
Each of those is reported as what it is rather than folded into a boolean.
"""
from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess

AUDIT_IDENTIFIER = "shadowfetch-audit"

# journalctl is resolved by ABSOLUTE PATH and never through PATH. The verifier
# asks this program what the journal says, and a normal desktop uid controls
# PATH -- on a stock install ~/.local/bin is writable and precedes /usr/bin. A
# shadowed journalctl turned a truncated log into "chain intact, external anchor
# agrees", exit 0. That is not a denial of service, it is a forged clean bill of
# health through the one mechanism the anchor exists to provide.
#
# Ordered by how a Debian system actually ships it. If none exists the anchor
# reports itself unreadable, which is the honest answer and is not a pass.
JOURNALCTL_PATHS = ("/usr/bin/journalctl", "/bin/journalctl", "/usr/sbin/journalctl")


def journalctl_binary():
    """The absolute path of a real journalctl, or None."""
    for candidate in JOURNALCTL_PATHS:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None
SYSLOG_SOCKET = "/dev/log"

# authpriv.notice. authpriv because an audit trail is security-relevant and
# most distributions route it away from the general message stream; notice
# because these are not errors and must not page anyone.
_FACILITY = 10
_SEVERITY = 5
_PRIORITY = _FACILITY * 8 + _SEVERITY

# A mirrored line is small on purpose: the sequence number and the hash are what
# make truncation detectable, and copying the detail would duplicate content
# that may be large and is already redacted-but-sensitive in the database.
MIRRORED_FIELDS = ("store", "chain", "seq", "hash", "mission", "event", "at")


def store_identity(db_path) -> str:
    """A stable name for THIS database, derived from where it lives.

    The chain id is minted into an events row, so a uid that can write the
    events table can also mint a new one -- which is how deleting the genesis
    and re-chaining produced a log that verified clean. This identifier is
    derived from the absolute path the OPERATOR opened, so it is the one name in
    the record that the database cannot restate about itself.

    A database copied to a different path is a different store and will have no
    journal history: that reports as unverified, which is the honest answer to
    "I have never seen this before", and is not a pass.
    """
    return hashlib.sha256(str(db_path).encode("utf-8")).hexdigest()[:16]


class MirrorState:
    """What the mirror has managed, so a degraded audit can be reported rather
    than discovered. Persisted beside the database, not inside it: a mirror
    failure has to survive the transaction that provoked it."""

    FILENAME = "audit-mirror.json"

    def __init__(self, root):
        self.path = os.path.join(str(root), self.FILENAME)

    def read(self) -> dict:
        try:
            with open(self.path, "r", encoding="utf-8") as handle:
                return json.load(handle)
        except (OSError, ValueError):
            return {"last_mirrored_seq": None, "failures": 0, "last_error": None,
                    "last_success_at": None}

    def write(self, state: dict) -> None:
        try:
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as handle:
                json.dump(state, handle, sort_keys=True)
            os.replace(tmp, self.path)
            os.chmod(self.path, 0o600)
        except OSError:
            # A mirror bookkeeping failure must never take down the caller: the
            # DATABASE event is the record of truth and it is already written.
            pass

    def record_success(self, seq: int) -> None:
        state = self.read()
        state["last_mirrored_seq"] = seq
        state["last_error"] = None
        state["failures"] = 0
        self.write(state)

    def record_failure(self, reason: str) -> None:
        state = self.read()
        state["failures"] = int(state.get("failures") or 0) + 1
        state["last_error"] = reason[:500]
        self.write(state)


def mirror(row: dict, *, socket_path: str = SYSLOG_SOCKET) -> tuple:
    """Send one event head to journald. Returns (ok, reason).

    Never raises. The caller has already committed the database row, and losing
    that row because the journal is unavailable would trade the record of truth
    for its shadow.
    """
    payload = {key: row.get(key) for key in MIRRORED_FIELDS}
    line = "<%d>%s[%d]: %s" % (
        _PRIORITY, AUDIT_IDENTIFIER, os.getpid(),
        json.dumps(payload, sort_keys=True, separators=(",", ":")))
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.settimeout(2)
            sock.connect(socket_path)
            sock.send(line.encode("utf-8"))
        return True, None
    except OSError as exc:
        return False, f"{type(exc).__name__}: {exc}"


def read_head(chain: str, *, identifier: str = AUDIT_IDENTIFIER,
              limit: int = 5000, store: str = None) -> dict:
    """The highest sequence number journald has for us, or why we cannot tell.

    'Cannot tell' and 'nothing there' are different answers and are reported
    differently: a user who is not in the systemd-journal group sees an empty
    journal, and calling that a verified absence would be exactly the kind of
    false claim this phase exists to remove.
    """
    result = {"available": False, "reason": None, "head_seq": None,
              "head_hash": None, "entries": 0, "identifier": identifier,
              # Every seq the journal can still see, not only the newest. The
              # head alone made a rewrite detectable for exactly as long as the
              # rewritten row stayed newest: one honest append later the two
              # heads agreed again over a row that had been rewritten. The
              # evidence was never missing, only unread.
              "heads": {},
              # Sequence numbers mirrored more than once with DIFFERENT hashes.
              # The engine mirrors each seq exactly once, so a second, differing
              # line for one seq was written by something else -- and since
              # /dev/log is a local datagram socket, "something else" is within
              # reach of the mission uid. This is reported rather than resolved:
              # picking a winner would mean deciding which forgery to believe.
              "conflicts": {}, "_when": {},
              # Chain ids the journal has seen for THIS store other than the one
              # the database claims. A database whose chain id is absent here
              # while other ids are present did not merely lose its history --
              # its history is attributed to a chain it is no longer claiming.
              "other_chains": {},
              # Every uid that has written to this identifier for this chain.
              # More than one means somebody other than the mission user has
              # been mirroring, which is worth seeing even though the common
              # case -- the attacker holding the mission uid -- looks identical
              # to the engine here.
              "uids": set(), "foreign_store_entries": 0,
              "store": store, "chain": chain}
    if not chain:
        result["reason"] = (
            "this database has no chain id, so its entries cannot be told apart "
            "from another database mirroring to the same identifier")
        return result
    try:
        binary = journalctl_binary()
        if binary is None:
            result["reason"] = (
                "no journalctl exists at any of " + ", ".join(JOURNALCTL_PATHS)
                + ", so the external anchor cannot be read. It is deliberately NOT "
                "looked up on PATH: this user controls PATH and would then control "
                "what the verifier believes the journal said")
            return result
        done = subprocess.run(
            # -o json, not -o cat. `cat` returns MESSAGE alone and discards
            # everything journald knows about the writer, which left the
            # ordering that "earliest wins" depends on resting on output order,
            # and left the sender-supplied fields inside MESSAGE as the only
            # thing to reason about.
            [binary, "-t", identifier, "-o", "json", "--no-pager",
             "-n", str(limit)],
            # A clean environment: PATH is not consulted for the binary above,
            # and is not inherited into it either.
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            capture_output=True, text=True, timeout=30)
    except FileNotFoundError:
        result["reason"] = "journalctl is not installed, so the external anchor cannot be read"
        return result
    except (OSError, subprocess.SubprocessError) as exc:
        result["reason"] = f"journalctl could not be run: {exc}"
        return result
    if done.returncode != 0:
        result["reason"] = (
            "journalctl exited %d: %s" % (done.returncode, (done.stderr or "").strip()[:200])
            or "journalctl refused the read; this user may not be able to read the journal")
        return result
    result["available"] = True
    best = None
    for raw in done.stdout.splitlines():
        raw = raw.strip()
        if not raw.startswith("{"):
            continue
        try:
            record = json.loads(raw)
        except ValueError:
            continue
        message = record.get("MESSAGE")
        if isinstance(message, list):        # journald returns bytes as a list
            try:
                message = bytes(message).decode("utf-8", "replace")
            except (TypeError, ValueError):
                continue
        if not isinstance(message, str) or not message.strip().startswith("{"):
            continue
        try:
            entry = json.loads(message)
        except ValueError:
            continue
        # Trusted fields: journald sets these, the sender cannot. They cannot
        # tell the engine from an attacker who holds the same uid -- the mirror
        # runs as the mission user, so both write with _UID 1000 -- but they DO
        # give an ordering the sender cannot forge, and they make a write from a
        # different user visible.
        entry["_uid"] = record.get("_UID")
        entry["_boot"] = record.get("_BOOT_ID")
        try:
            entry["_mono"] = int(record.get("__MONOTONIC_TIMESTAMP") or 0)
        except (TypeError, ValueError):
            entry["_mono"] = 0
        if entry.get("_uid") is not None:
            result["uids"].add(entry["_uid"])
        if not isinstance(entry, dict) or not isinstance(entry.get("seq"), int):
            continue
        # A line for OUR chain that was mirrored by a different store. A
        # database copied to a new path keeps its chain id but changes store, and
        # read_head used to accept those lines as its own -- so a copy verified
        # clean and a re-mint was defeated by relocating the database, both of
        # which store_identity()'s own docstring said would be reported.
        if store and entry.get("chain") == chain and entry.get("store") \
                and entry.get("store") != store:
            result["foreign_store_entries"] = result.get("foreign_store_entries", 0) + 1
            continue
        if entry.get("chain") != chain:
            # Another chain id. If it was mirrored by THIS store, that is the
            # signature of a re-minted chain and is recorded rather than
            # skipped; if the store does not match it is simply a different
            # database sharing the identifier, which is expected.
            if store and entry.get("store") == store and entry.get("chain"):
                seen = result["other_chains"].setdefault(entry["chain"], 0)
                result["other_chains"][entry["chain"]] = seen + 1
            continue
        result["entries"] += 1
        if entry.get("hash"):
            seen = result["heads"].get(entry["seq"])
            if seen is None:
                # EARLIEST wins, and "earliest" is now journald's own monotonic
                # timestamp rather than the order journalctl happened to print.
                # The sender cannot set that clock.
                result["heads"][entry["seq"]] = entry["hash"]
                result["_when"][entry["seq"]] = (entry.get("_boot"), entry["_mono"])
            elif seen != entry["hash"]:
                previous = result["_when"].get(entry["seq"])
                current = (entry.get("_boot"), entry["_mono"])
                result["conflicts"].setdefault(entry["seq"], [seen]).append(entry["hash"])
                if previous and previous[0] == current[0] and current[1] < previous[1]:
                    # This line is genuinely older; it is the one to believe.
                    result["heads"][entry["seq"]] = entry["hash"]
                    result["_when"][entry["seq"]] = current
        if best is None or entry["seq"] > best["seq"]:
            best = entry
    result["uids"] = sorted(result["uids"])
    result.pop("_when", None)
    if best is not None:
        result["head_seq"] = best["seq"]
        result["head_hash"] = best.get("hash")
    elif result["entries"] == 0:
        result["reason"] = (
            "no entries for this chain are readable; either none were written, "
            "they have rotated away, or this user cannot read the journal")
    return result
