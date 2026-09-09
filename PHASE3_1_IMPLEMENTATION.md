# Phase 3.1 — control-plane integrity hardening

Phase 3 built the control plane and claimed trustworthy provenance. A broad
adversarial audit then measured that claim and found it did not hold: a person
holding the ordinary mission uid could invent missions, rewrite who approved
them, revive expired approvals, exceed the retry budget, and have all of it pass
`audit verify --json` with exit 0.

Phase 3.1 is the narrow phase that closes that list. No new providers, no
Firebreak rewrite, no product scope.

Everything below was measured before and after, against the running engine.
The before-numbers are in PHASE3_1_BASELINE.md and the probes that produced them
are committed under `tools/probes/`, because a number in a document cannot be
re-run.

## The seven claims, and what each one cost

### 1. Mission state is reconstructable from history

`verify_states()` excused every mission with no events as `predates_chain`. That
exemption existed for a good reason — migrated pre-v3 rows have no events and
accusing them would be false — but it was an inference drawn from ABSENCE, and
an attacker obtains absence by writing nothing.

> before: `INSERT INTO missions(... state='completed')` with zero events →
> `ok=True`, verdict `agrees`, no problems, exit 0.

The fix replaces the inference with a chained positive fact. Schema **v4**
appends `legacy-missions-pinned`, a hash-chained event naming exactly which
missions existed without history at upgrade time. Afterwards an event-less
mission is either *named there* or it was invented.

That dichotomy is only real because of change 6 below — creation and its first
event now commit together, so the engine can no longer produce an event-less
mission honestly. The two changes are one idea and were made together.

The boolean became a classification, because "this row is fine", "this row was
edited" and "this row was invented" call for different actions:
`LEGACY_PRECHAIN`, `VALID_CURRENT`, `MISSING_HISTORY`, `STATE_DIVERGENCE`,
`CORRUPTED_HISTORY`. A legacy row now reports *why* it is believed legacy.

An empty pin is not written: it would grant no exemption, and it would add an
event to every fresh database to record that there was nothing to record.

> after: `ok=False`, states `disagrees`, exit 1 — with `chain_ok` still True,
> because the log really is intact. It is the row that was invented.

### 2. The event chain is tamper-evident, including its own identity

`chain_id()` read the chain's identity out of a row inside the events table —
the table it anchors. Delete the genesis, mint a new id, re-chain everything,
and the verifier reported `problems=[]`. The only tell was an anchor verdict of
`unverified`, which is also what an honest fresh install looks like. An absence
of evidence was standing in for a mismatch.

Every mirrored line now carries a **store identity**: `sha256` of the absolute
database path. That is the one name in the record the database cannot restate
about itself, because `audit verify` runs against a path the *operator* chose.
journald therefore holds the fact that this store has used that chain id before,
and `read_head()` records — rather than skips — entries for this store under a
chain the database is no longer claiming.

> after: `ok=False`, anchor `conflict`, "this store has previously mirrored
> chain id de13e4d8ba8e (4 events), and now presents 4d7701a8df95."

**What this is not:** it does not make the chain tamper-proof against the owning
uid. It converts one silent success into a detected conflict. Root still owns
journald. A database copied to another path is a different store with no
history, which reports `unverified` — the honest answer to "I have never seen
this before", and still not a pass.

### 3. The journal anchor stopped trusting the newest line

`read_head()` built its per-seq map with plain assignment while walking
journalctl oldest-first, so a *later* line for a sequence number overwrote the
earlier one. Since `/dev/log` is a local datagram socket the mission uid can
already write, rewriting event 5 and then sending one forged line for seq 5
emptied the detection again.

Two changes. The earliest line per seq wins. And a second, *different* hash for
a seq already seen is reported as its own alarm rather than resolved — because
two hashes for one sequence number means one of them was not written by the
engine, whichever one the database happens to agree with. The second part is
what keeps the fix from resting on the ordering claim.

> proven with a real forged append (`tools/probes/journal_attack.py`): the
> cover-up became the evidence.

### 4. Approval provenance is tamper-evident

The grant event already recorded `subject`, `granted_by`, `method` and
`expires_at`. `find_approval()` compared `scope_sha256` and nothing else, so the
evidence sat in the chain unread.

> before: **8 of 10** direct edits to the `approvals` table went undetected,
> including reviving an already-expired approval and clearing a revocation.

There is now one `APPROVAL_WITNESSED_FIELDS` list that both the writer and the
checker compute from — because enumerating the fields at the *comparison* site
is precisely how this went wrong, and a field added later must be covered by
both sides or by neither.

Revocation is read from the **chain**, not the column, so clearing `revoked_at`
no longer restores an approval. `revoked_at` is deliberately outside the
creation digest: revocation is legitimately mutable, and folding it in would
make every honest revoke look like tampering. `revoke_approval()` also stopped
overwriting `reason`, which had made an honest revocation look like a tampered
grant.

> after: **0 of 10**, each refused for its own correct reason.

### 5. Audit verification fails correctly

The exit ladder lived inside `if not args.json:`, so the caller most likely to
pass `--json` — a CI gate, a cron check, the LaunchAgent pattern this project
already uses — was told a tampered log had passed.

`audit_exit_code(report)` computes the ladder once, from the report and nothing
else, before either printer exists, and fails closed: a report with no `ok` at
all is a failure, because the only way to be told a log is intact is for the
verifier to have said so.

The contract: **0** clean, **1** tampered or the mission rows disagree with the
log, **2** unverified or degraded. Two is not a pass.

### 6. Retry budgets are enforced

The budget began inside `Store.retry()`. Phase 3 moved it into `transition()`.
Both are *verbs*, and `finish_execution()` was a third one: it called
`transition_allowed()`, got the legitimate `failed -> queued` edge, and requeued
a mission already at the ceiling.

`requeue_refusal(event, attempt)` is now keyed on the **edge's event** rather
than on who is asking, and both callers ask it. A path that reaches a requeue
without calling it is the only way back to the old defect, and there is now
exactly one place to look.

The refusal is **recorded**, not merely raised: a `retry-budget-exhausted` event
commits with the transaction that refuses it while the mission row is left
untouched. Raising from inside would have rolled back the only evidence that a
fourth attempt was asked for.

### 7. Mission creation and its first event are atomic

They were written on two different connections. An interruption between them
left a mission with no events — the exact shape claim 1 now treats as forged.
One `BEGIN IMMEDIATE` transaction covers both.

## Vocabulary

Unchanged from Phase 3 and still distinct: `enforced` / `partial` /
`not_enforced` / `not_representable` / `not_applicable` / `observed`. Phase 3.1
adds the mission classification above, and the audit report keeps `ok`,
`chain_ok` and `states` as three separate verdicts, because "the log verifies",
"the log is externally anchored" and "the mission rows agree with the log" are
three different claims.

## What Phase 3.1 deliberately did not do

* No Claude Code, Grok, Cursor, or additional providers.
* No Firebreak or credential-broker rewrite.
* No egress enforcement. `egress_allowlist` still reaches no filter.
* No masking. Firebreak's `--mask-path` exists and is **record-only** — the
  earlier claim that "Firebreak has no masking flag" was false in its reason,
  though right in its conclusion.
* No privileged audit sink. The mirror still runs as the mission uid, which is
  stated plainly in docs/TRUST_BOUNDARIES.md rather than implied away.
