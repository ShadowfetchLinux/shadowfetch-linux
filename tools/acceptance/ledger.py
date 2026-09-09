#!/usr/bin/env python3
"""The append-only, hash-chained run ledger.

Every run of the harness -- pass, fail or blocked -- appends exactly one entry
here, written by the same process that ran the case, before that process is
allowed to record anything into the release acceptance manifest.

Why a chain and not a directory of receipts: a directory can be pruned. If a
case is run five times and passes once, deleting the four failures leaves a
perfectly plausible-looking single PASS. The chain makes the deletion visible,
because entry N+1 carries the digest of entry N.

The chain is tamper-EVIDENT, not tamper-PROOF. Anyone who can write the file
can rewrite the whole chain; there is no key on this host to sign it with. What
it enforces is that a rewrite is a rewrite of everything, and that a receipt
lifted from another run does not verify against it. Do not describe it as more
than that.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
from typing import Any

from .evidence import digest_of, utc_now

GENESIS = "0" * 64


class LedgerError(RuntimeError):
    pass


class Ledger:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def entries(self) -> list[dict[str, Any]]:
        if not self.path.is_file():
            return []
        rows = []
        for number, line in enumerate(
            self.path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as error:
                raise LedgerError(f"{self.path}:{number}: not valid JSON") from error
        return rows

    def head(self) -> str:
        rows = self.entries()
        return rows[-1]["entry_sha256"] if rows else GENESIS

    def append(self, payload: dict[str, Any]) -> dict[str, Any]:
        rows = self.entries()
        entry = dict(payload)
        entry["seq"] = len(rows) + 1
        entry["prev"] = rows[-1]["entry_sha256"] if rows else GENESIS
        entry["appended_utc"] = utc_now()
        entry["entry_sha256"] = digest_of(entry)
        line = json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n"
        # O_APPEND on a single write of one line: concurrent harness runs
        # interleave whole entries rather than corrupting one.
        descriptor = os.open(
            self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644
        )
        try:
            os.write(descriptor, line.encode())
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return entry

    def verify(self) -> list[str]:
        """Return the problems found in the chain. Empty means intact."""
        problems: list[str] = []
        previous = GENESIS
        for row in self.entries():
            sequence = row.get("seq")
            recorded = row.get("entry_sha256")
            body = {key: value for key, value in row.items() if key != "entry_sha256"}
            if digest_of(body) != recorded:
                problems.append(f"entry {sequence}: digest does not match its content")
            if row.get("prev") != previous:
                problems.append(
                    f"entry {sequence}: prev does not chain to the entry before it "
                    "(an earlier entry was changed or removed)"
                )
            previous = recorded or GENESIS
        return problems

    def find(self, **criteria: Any) -> list[dict[str, Any]]:
        return [
            row
            for row in self.entries()
            if all(row.get(key) == value for key, value in criteria.items())
        ]


def write_receipt(path: Path, receipt: dict[str, Any]) -> str:
    """Write a receipt with its own digest over everything else in it.

    The digest is stamped into the CALLER'S receipt as well as the file. It was
    computed over a private copy and returned, so the caller went on holding a
    receipt with no digest in it -- and `_record()` reads
    `receipt["receipt_sha256"]` to name the run in the manifest, so a case that
    PASSED with sixteen checks against two running machines raised KeyError on
    the way to being recorded. A receipt read back from disk carries the field;
    one still in hand did not, and only the promotion path noticed.

    Excluding the key from the body keeps it idempotent: stamping the caller's
    dict cannot change the digest a second call computes.
    """
    body = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    digest = digest_of(body)
    receipt["receipt_sha256"] = digest
    receipt = dict(body)
    receipt["receipt_sha256"] = digest
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(receipt, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise
    return receipt["receipt_sha256"]


def receipt_problems(receipt: dict[str, Any]) -> list[str]:
    recorded = receipt.get("receipt_sha256")
    body = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    if digest_of(body) != recorded:
        return ["receipt digest does not match its content"]
    return []
