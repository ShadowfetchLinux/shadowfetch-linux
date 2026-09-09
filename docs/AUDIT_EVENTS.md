# The audit event spine

One append-only, hash-chained table, an external anchor that can see what the chain cannot,
and an event vocabulary with exactly one definition per name.

**Version.** Written against `7978259` ("Phase 3 Steps 19, 20, 21, 23, 24, 25") plus the
uncommitted Step 18 work in the working tree. The chain lives in
`packages/shadowfetch-missions/data/usr/lib/shadowfetch/missions/sf_missions.py`; the
external anchor in `sf_audit.py` beside it. Proofs are in
`packages/shadowfetch-missions/tests/test_audit_chain.py` and `test_schema_v3.py`.

Every command output below was run on the build host against a throwaway store. Nothing is
paraphrased.

---

## 1. Read this first: what this chain does and does not prove

It **proves** that no row in the chained region was altered, inserted, removed from the
middle, reordered or renumbered without detection — including by a forger who recomputes
the altered row's own hash, because every successor's `prev_hash` then fails.

It **cannot** prove:

- that no row was removed **from the end**. Delete the last three events and every surviving
  row still verifies, because each one's hash was only ever computed over itself and its
  predecessor. That is not a flaw in the chain; it is what a chain is. Detecting it needs a
  record outside the database — §5.
- that events written **before** the chain existed are intact. They are left unchained and
  reported as such — §7.
- that the log is **complete**. Nothing forces a caller to emit an event; the chain protects
  what was written, not what should have been.
- anything against **root**. Root can rewrite both the database and the journal.
- anything about the **content's truth**. A correctly chained event can say something false
  about the world; the chain says only that this text is what was written at that sequence
  number.

---

## 2. The record

One table, `events`, one writer.

| Column | Notes |
|---|---|
| `seq` | chosen explicitly, not by AUTOINCREMENT — the hash covers it |
| `at` | UTC ISO-8601, `timespec="seconds"` |
| `mission` | a mission id, or `"*"` for a system-level event |
| `task_id`, `session_id`, `tool_execution_id` | correlation; NULL when not in scope |
| `actor` | `user` / `orchestrator` / `worker` / `provider` |
| `event` | a name from §8 |
| `detail` | `clean(detail)[:10000]` — redacted, then truncated, then hashed |
| `prev_hash` | the previous row's `hash`, or 64 zeros for the first chained row |
| `hash` | `sha256(prev_hash || canonical(hashed fields))` |

**`Store._append()` is the only INSERT into `events`.** It takes the caller's connection, so
a state change and its event land in **one transaction** — a state change with no event, and
an event describing a change that rolled back, are both unrepresentable. Callers with no
transaction of their own use `append_event()`, which opens `BEGIN IMMEDIATE`: reading the
chain head and appending after it must be atomic, or two concurrent appends that read the
same head fork the chain.

`seq` is chosen rather than left to SQLite because the hash covers it: the row has to know
its own sequence number *before* it is written, and reading it back afterwards to UPDATE the
hash would need an UPDATE on an append-only table. Covering `seq` is what makes renumbering
detectable, and it is also what makes `watch --since <seq>` resumable exactly once with no
gaps.

**One deliberate exception.** The v1→v2 migration writes its `schema-migrated` row with a
raw INSERT, because it runs before the chain columns exist. `start_chain()` runs a moment
later in the same migration and pins it along with every other pre-chain row (§7).

Two raw rows, as stored:

```json
{"actor":"orchestrator","at":"2026-09-08T23:54:22+00:00","detail":"{\"chain_id\": \"0b1c831aad114b0c94a89ecbee92450d\", \"from_schema_version\": 0, \"note\": \"events before this row predate the chain and are not individually verifiable; this digest pins the set as it stood when the chain began\", \"to_schema_version\": 3, \"unchained_digest\": \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\", \"unchained_events\": 0}","event":"audit-chain-started","hash":"84bc54a74df52bfdcc72363bd54a0291e48193e2eb0300db889120ad2a77d12c","mission":"*","prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","seq":1,"session_id":null,"task_id":null,"tool_execution_id":null}
{"actor":"orchestrator","at":"2026-09-08T23:54:30+00:00","detail":"the step began","event":"task-started","hash":"4106f4e5368a961b0650ee939dfde2654bab03f227c60d4987dc9dbc8f195895","mission":"mission-f7bb1831dcfa469d","prev_hash":"86e054823ec1f83bb0f27de2a83cc5748a0d5313055241fe33fcde1713850ff7","seq":10,"session_id":null,"task_id":"task-ba1795b7ad994506","tool_execution_id":null}
```

---

## 3. Canonical serialisation and exactly what the hash covers

```python
HASHED_FIELDS = ("seq", "at", "mission", "task_id", "session_id",
                 "tool_execution_id", "actor", "event", "detail")

def canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")

def event_hash(prev_hash: str, row: dict) -> str:
    payload = {k: row.get(k) for k in HASHED_FIELDS}
    return hashlib.sha256((prev_hash or "").encode("utf-8") + canonical(payload)).hexdigest()
```

- `sort_keys=True` so key order cannot change the digest.
- `separators=(",", ":")` so pretty-printing cannot.
- `ensure_ascii=False` so a non-ASCII detail hashes as the text it is, rather than as an
  escape sequence a different `json` version might spell differently.
- Fields are pulled by name from `HASHED_FIELDS`, so a row carrying extra keys hashes the
  same as one that does not.

**Every column of `events` except `prev_hash` and `hash` is covered.** Those two are
excluded by construction: `prev_hash` is the chaining input, prepended to the digest rather
than serialised into it, and `hash` is the output.

**Redaction happens before hashing.** `detail` is passed through `clean()` and truncated to
10,000 characters *inside* `_append()`, before the hash is computed. A detail redacted after
hashing could never verify. `clean()` does two things: it replaces the literal values of
`OPENAI_API_KEY`, `CODEX_API_KEY`, `XAI_API_KEY` and `ANTHROPIC_API_KEY` as they exist in
the process environment, and it regex-strips anything matching
`(?:sk-|xai-)[A-Za-z0-9_-]{12,}`. It follows that a secret which is neither one of those four
variables at redaction time nor shaped like those two prefixes is **not** removed, and that a
detail longer than 10,000 characters is stored, hashed and verified in its truncated form.

A test asserts that **every** hashed field changes the hash; a field silently dropped from
the covered set is the failure mode that makes a chain decorative.

---

## 4. Verification from the inside

`Store.verify_chain()` returns a **report**, not a boolean, because "the chain is broken"
and "these rows predate the chain" are different facts and collapsing them would
misrepresent both.

Per row, walking in `seq` order from the genesis:

| Check | Problem reported |
|---|---|
| a hash exists in the chained region | `seq N: chained region has no hash` |
| `prev_hash` equals the previous row's `hash` | `seq N: prev_hash does not match the previous row (a row was inserted, removed or reordered here)` |
| `seq` is exactly `previous + 1` | `seq N: follows M, so the chain was truncated or renumbered` |
| recomputed hash equals the stored hash | `seq N: content does not match its hash (this row was modified after it was written)` |
| no hash on a row before the genesis | `seq N: carries a hash before the chain genesis` |
| a genesis exists at all | `no chain genesis found; nothing is verifiable` |

A modified row, altered directly with `sqlite3` rather than through the API:

```
$ sqlite3 …/missions.sqlite3 'UPDATE events SET detail="tampered" WHERE seq=12;'
$ shadowfetch-missions audit verify
events            35
  chained         35
  unchained       0 (written before the chain existed; pinned by the genesis digest, not individually verifiable)
chain             BROKEN
head              seq 35 34f6a1ed5eb81bc0
external anchor   agrees (shadowfetch-audit)
  journal head    seq 35
PROBLEM           seq 12: content does not match its hash (this row was modified after it was written)
exit=1
```

---

## 5. The external anchor

### Why it exists

A hash chain cannot detect truncation from the inside. Detecting it needs a record the
mission worker's uid cannot rewrite. journald is that record: it is root-owned, the worker
runs unprivileged, and an append to it survives anything done to the SQLite file afterwards.

### What is mirrored

After **every committed append**, `Store.mirror()` sends the event's *head* to journald over
a plain `AF_UNIX` datagram to `/dev/log`, at `authpriv.notice`, under
`SYSLOG_IDENTIFIER=shadowfetch-audit`. No new dependency: `python3-systemd` is still not
required.

```python
MIRRORED_FIELDS = ("chain", "seq", "hash", "mission", "event", "at")
```

`detail` is **never** mirrored. What *does* leave the database is the mission id, the event
name and the timestamp — enough to correlate, and enough that anyone who can read the
journal learns which missions existed and what happened to them. Real lines:

```
2026-09-08T19:59:53-04:00 pop-os shadowfetch-audit[1859459]: {"at":"2026-09-08T23:59:53+00:00","chain":"5c436519f26f45388528725e20878396","event":"approval-required","hash":"07de83832910fc51396ac3ea8b5a62197e27fa03225ef651ccc82ce9e81a67cf","mission":"*","seq":2}
```

The mirror runs **after** the transaction commits. The database row is the record of truth;
mirroring inside the transaction would let a journal failure roll back an event that really
happened. `sf_audit.mirror()` never raises — it returns `(ok, reason)`.

### One identifier, many databases

Every mission database on a host mirrors to the same identifier: the operator's, another
user's, and every test run. Without a discriminator, a fresh database at seq 2 compared
against a journal carrying another store's seq 50 would report **truncated** — a false
accusation of tampering. So each chain mints a `chain_id` at genesis, carries it on every
mirrored line, and `read_head()` filters by it. A chain that cannot state its id reports
`unverified` rather than comparing itself against somebody else's entries.

The MCP's own chain (§12) mirrors to this **same identifier** when
`shadowfetch-missions` is installed, borrowing `sf_audit.mirror` at runtime. Its lines carry
its own `chain`, `mission: null` and an `event` of the form `mcp:<server>.<tool>`, so the
chain filter keeps the two apart — and both consume the same read window.

### Reading the anchor

`sf_audit.read_head(chain)` runs `journalctl -t shadowfetch-audit -o cat --no-pager -n 5000`
and takes the maximum `seq` among lines whose `chain` matches. It distinguishes *cannot
tell* from *nothing there*: `journalctl` missing, `journalctl` exiting non-zero, and zero
readable entries each produce their own `reason` string. A user outside the
`systemd-journal` group sees an empty journal, and calling that a verified absence would be
exactly the kind of unearned claim this phase exists to remove.

---

## 6. The five verdicts, and what `ok` means

| Verdict | Condition | Is it a finding? |
|---|---|---|
| `agrees` | journal head seq == database head seq, and the hashes match | no |
| `behind` | journal head seq < database head seq | **no** |
| `truncated` | journal head seq > database head seq | yes — sets `ok: false` |
| `conflict` | same seq, different hash: the log was rewritten after it was mirrored | yes — sets `ok: false` |
| `unverified` | the journal could not be read, has no entries for this chain, or either head is unknown | not a pass either |
| `degraded` | the mirror has recorded failures | not a pass either |

**`behind` is not a finding, and reporting it as one would train people to ignore the
anchor.** The mirror is asynchronous — it runs after the commit — and journals rotate, so
the journal legitimately trails the database. Only the *other* direction is evidence: the
journal knowing about an event the database does not.

**Verdict precedence.** The checks are an `if/elif` chain and `degraded` is tested **first**.
While the mirror is failing, the anchor reports `degraded` and the head comparison is not
performed at all — so a truncation that happens during a mirror outage is not reported as
truncation. That is honest (nothing can be concluded from a head that was never written) but
it means `degraded` masks the finding rather than adding to it.

**`ok` is a combined verdict.** `truncated` and `conflict` set `report["ok"] = False`;
`degraded` and `unverified` do not. So `chain BROKEN` in the printed output can mean the
chain's own rows are all fine and only the anchor disagrees — the `problems` list says
which. Deleting the last two rows:

```
$ sqlite3 …/missions.sqlite3 'DELETE FROM events WHERE seq > (SELECT MAX(seq)-2 FROM events);'
$ shadowfetch-missions audit verify
events            33
  chained         33
  unchained       0 (written before the chain existed; pinned by the genesis digest, not individually verifiable)
chain             BROKEN
head              seq 33 8726cd11c660e061
external anchor   truncated (shadowfetch-audit)
  journal head    seq 35
PROBLEM           the journal records event 35 but the database stops at 33: 2 event(s) were removed from the end of the log
exit=1
```

and the machine-readable form, showing that every row that survives still verifies and the
only problem is the anchor's:

```json
{
    "ok": false, "events": 33, "chained": 33, "unchained": 0,
    "first_chained_seq": 1, "head_seq": 33,
    "problems": ["the journal records event 35 but the database stops at 33: 2 event(s) were removed from the end of the log"],
    "anchor": {
        "identifier": "shadowfetch-audit",
        "chain": "0b1c831aad114b0c94a89ecbee92450d",
        "readable": true, "reason": null,
        "journal_head_seq": 35, "database_head_seq": 33,
        "last_mirrored_seq": 35, "mirror_failures": 0, "last_mirror_error": null,
        "verdict": "truncated"
    }
}
```

**Exit codes of `shadowfetch-missions audit verify`:** `0` when `ok` and the anchor verdict
is not `unverified`/`degraded`; `1` when `ok` is false; **`2` when the verdict is
`unverified` or `degraded`** — those are not passes, because truncation remains undetectable
while they hold.

### What the anchor still cannot see

- **It is a high-water mark, not a per-event audit.** If mirroring fails for events 10–12 and
  succeeds for 13, the journal head is 13, the database head is 13, and the verdict is
  `agrees`. The hole in the middle of the journal is invisible, and nothing retries a failed
  mirror.
- **Only the last 5,000 journal entries under the identifier are scanned**, and the chain
  filter is applied *after* that window. A busy host with several chains can push a quiet
  chain's entries out of the window, at which point it reports `unverified` rather than
  `agrees`. This is not hypothetical: one throwaway chain in the course of writing this
  document produced 1,006 entries — a fifth of the window — in five seconds.
- **Root can rewrite the journal**, so this is tamper *evidence*, not tamper proofing.
- **The mirror is not protected in transit.** `/dev/log` is a local socket; anything that can
  write to it can write plausible lines under the identifier.
- **A rotated journal reports the horizon it can see**, as a `reason`, not as a failure.

---

## 7. Degraded audit is a state, not a silence

`sf_audit.MirrorState` is a small JSON file, `audit-mirror.json`, kept **beside** the
database rather than inside it: a mirror failure has to survive the transaction that
provoked it. It counts failures and keeps the last error text. Its own write failures are
swallowed — a bookkeeping failure must never take down a caller whose database row is
already committed.

Exercised by pointing the real `mirror()` at a socket that is not there and appending
through the ordinary API:

```
### mirror state beside the database
{
  "failures": 2,
  "last_error": "FileNotFoundError: [Errno 2] No such file or directory",
  "last_mirrored_seq": null,
  "last_success_at": null
}

### verify_chain(): chain intact, audit degraded
{
  "ok": true, "events": 2, "chained": 2, "unchained": 0,
  "problems": [
    "the audit mirror has failed 2 time(s); last error: FileNotFoundError: [Errno 2] No such file or directory. Events are still recorded in the database, but truncation is not externally detectable while this persists"
  ]
}
{
  "identifier": "shadowfetch-audit",
  "chain": "ddd12c305adc447b9332f8ccef959ce3",
  "readable": true,
  "reason": "no entries for this chain are readable; either none were written, they have rotated away, or this user cannot read the journal",
  "journal_head_seq": null, "database_head_seq": 2,
  "last_mirrored_seq": null, "mirror_failures": 2,
  "last_mirror_error": "FileNotFoundError: [Errno 2] No such file or directory",
  "verdict": "degraded"
}
```

A mirror outage does **not** make the chain report broken: `ok` stays true and the chain's
own verdict is untouched. Those are different facts.

**The counter resets on the next success.** `record_success()` sets `failures` to 0 and
clears `last_error`, so `degraded` reports a *current* outage only. A failure followed by a
success leaves no trace in this file, and the events that were missed during it are never
re-mirrored — see the high-water-mark limitation in §6.

---

## 8. Genesis, and the rows that predate the chain

Rows written before schema v3 were never protected. Back-filling hashes over them would
**manufacture tamper evidence for a period that had none** — the log would then assert
something no mechanism ever guaranteed. They keep NULL `prev_hash`/`hash`, and
`verify_chain()` reports them as `unchained` rather than as problems.

What the genesis row can honestly do is **pin** them: it records how many there were and a
digest over their canonical form, so an alteration of a pre-chain row *after* this moment is
still detectable, while one *before* it is not. That distinction is the whole point.

A v1 database — four legacy events, one legacy mission — opened by this build:

```
### a v1 database opened by this build
{
  "ok": true, "events": 6, "chained": 1, "unchained": 5,
  "first_chained_seq": 6, "problems": []
}

### the migrated mission row
{'kind': 'media', 'capability': 'media_export', 'provider_id': 'offline-media', 'state': 'completed'}

### the genesis row
seq 6 | mission * | event audit-chain-started
prev_hash 0000000000000000000000000000000000000000000000000000000000000000
{
  "chain_id": "eec0fc93db0b495db711a3f983e667fa",
  "from_schema_version": 1,
  "note": "events before this row predate the chain and are not individually verifiable; this digest pins the set as it stood when the chain began",
  "to_schema_version": 3,
  "unchained_digest": "1bcf98cf270c66bb37c8ed7483ec4549c94ad48631d3dadfc91372ecec492931",
  "unchained_events": 5
}

### every row, as stored
  seq  1  queued             prev_hash=None               hash=None
  seq  2  running            prev_hash=None               hash=None
  seq  3  waiting-review     prev_hash=None               hash=None
  seq  4  reviewed           prev_hash=None               hash=None
  seq  5  schema-migrated    prev_hash=None               hash=None
  seq  6  audit-chain-started prev_hash=0000000000000000   hash=80b72f79b8833d33
```

Note seq 5: the migration's own row, written by the one raw INSERT (§2), unchained, and
pinned by the genesis a moment later.

In a database created fresh by this build the genesis is seq 1 with
`unchained_events: 0` and `unchained_digest` equal to the SHA-256 of the empty string —
the honest value for "there was nothing here before me".

`Store.chain_id()` reads the id back out of that row and caches it **per Store instance**,
not per process, so a test opening several stores gets several ids.

---

## 9. The event vocabulary

`sf_missions.py` is the only module that appends to this table. Names come from
`MISSION_TRANSITIONS` and `TASK_TRANSITIONS` wherever an edge defines one, so the vocabulary
has exactly one definition per name and `create()` derives its event name from the table
rather than spelling it.

### Mission lifecycle

| Event | Emitted by | Actor | Correlation |
|---|---|---|---|
| `queued` | `Store.create()` | `user` | — |
| `running` | `run_mission()` via `transition()` | `worker` | — |
| `waiting-review` | `finish_execution()` | `orchestrator` | — |
| `failed` | `finish_execution()`, or `recover()` after a crash | `orchestrator` / `worker` | — |
| `cancelled` | `Store.cancel()` on a queued mission; `finish_execution()` on a running one; `recover()` for a cancel that was requested before the worker died | `user` / `orchestrator` / `worker` | — |
| `completed` | `review(…, "accept")` | `user` | — |
| `undone` | `review(…, "undo")` | `user` | — |
| `retry-queued` | `Store.retry()` | `user` | — |
| `cancel-requested` | `Store.cancel()` on a running mission — a *request*, not a state change | `orchestrator` (see §11) | — |
| `reviewed` | `review()`; detail is the bare decision `accept` / `undo` | `user` | — |

### Tasks

| Event | Emitted by | Actor | Correlation |
|---|---|---|---|
| `task-created` | `Store.create_task()` | `orchestrator` | `task_id` |
| `task-started` | `task_transition(→running)`, from `Executor.task()` | `orchestrator` | `task_id` |
| `task-succeeded` | `Executor.task()` on clean exit | `orchestrator` | `task_id` |
| `task-failed` | `Executor.task()` on an exception; `reconcile()` for a task a crash left running | `orchestrator` / `worker` | `task_id` |
| `task-cancelled` | `Executor.task()` on the `Cancelled` path | `orchestrator` | `task_id` |
| `task-skipped` | **declared in `TASK_TRANSITIONS`; no caller in the engine** | — | — |

### Sessions, processes and provider activity

| Event | Emitted by | Actor | Correlation |
|---|---|---|---|
| `session-opened` | `Store.open_session()`, before the process starts | `orchestrator` | `task_id`, `session_id` |
| `session-closed` | `Store.close_session()` | `orchestrator` | `task_id`, `session_id` |
| `process-started` | `Executor.run_process()` | `orchestrator` | whatever is in scope |
| `process-finished` | `Executor.run_process()`; detail carries the exit code and the log path | `orchestrator` | whatever is in scope |
| `inference-finished` | `Executor.agent_turn()` after a complete successful turn | `orchestrator` | `task_id`, `session_id` |
| `tool-observed` | `Store.record_tool_execution()` | **`provider`** | `task_id`, `session_id`, `tool_execution_id` |
| `tool-record-failed` | `Executor.record_tool_activity()` when a reported tool record could not be stored | `orchestrator` | `task_id`, `session_id` |

### Work products

| Event | Emitted by | Actor |
|---|---|---|
| `checkpoint-started` / `checkpoint-created` | `Executor.execute()`; the second carries the recovery id | `orchestrator` |
| `report-published` | `Executor.report()` | `orchestrator` |
| `export-verified` | `Executor.media()`, per output | `orchestrator` |
| `test-run` | `Store.record_test_run()`; detail carries exit code and duration | `orchestrator` |
| `git-structure-recorded` | `Store.record_git_change()`; emitted **even when nothing changed** | `orchestrator` |
| `validation-guard-reused` | `Executor.validation_guard()` on a retry | `orchestrator` |
| `step-resumed` | `Executor.report()` / `Executor.media()` when a prior attempt's output is reused and **no inference was replayed** | `orchestrator` |

### Policy, approval and review

| Event | Emitted by | Actor |
|---|---|---|
| `policy-denied` | `require_approval()` before raising | `orchestrator` |
| `approval-required` | `require_approval()` before raising `ApprovalRequired` | `orchestrator` |
| `approval-used` | `require_approval()` when a valid approval covers the decision | `orchestrator` |
| `approval-granted` | `Store.grant_approval()`; detail names subject, granter and method | `user` |
| `approval-revoked` | `Store.revoke_approval()` | `user` |
| `review-opened` | `Store.open_review()` | `orchestrator` |
| `review-summary-failed` | `run_mission()` when the summary could not be built — the mission still reaches review | `orchestrator` |

### System

| Event | Emitted by | Actor | Mission |
|---|---|---|---|
| `audit-chain-started` | `Store.start_chain()`, once per database | `orchestrator` | `*` |
| `schema-migrated` | the v1→v2 migration, by raw INSERT — **unchained** | NULL | `*` |
| `reconciled` | `Store.reconcile()`, **only when something was settled** | `worker` | `*` |

---

## 10. Actors, correlation and `mission = "*"`

Four actor values. Three are named constants — `ACTOR_USER`, `ACTOR_ORCHESTRATOR`,
`ACTOR_WORKER` — and the fourth, `"provider"`, is written as a bare literal in
`record_tool_execution()`. `orchestrator` is the default in `_append()`, so any caller that
does not pass one gets it.

Correlation runs in both directions. `Executor` keeps `self.task_id` and `self.session_id`
as the scope currently in force and stamps them onto every event it emits, so a reader who
starts at a mission id can reach the task, the session, the tool execution and the process
log. `Store.session_for_firebreak()` closes the loop the other way: given a systemd scope
name or a `.session` filename, it names the mission and task.

`mission = "*"` marks an event that belongs to the database rather than to any one mission.
**These rows are invisible to `shadowfetch-missions events <id>`**, which filters by mission
id. They are reachable through `watch`, through `audit verify`, and by reading the table.

---

## 11. Known gaps in the spine

1. **Truncation is undetectable from inside the database.** The journald anchor is the only
   thing that sees it, and it is `unverified` for any user who cannot read the journal.
2. **The anchor is a high-water mark.** Mirror failures in the middle of a chain leave a hole
   nothing detects and nothing retries (§6).
3. **`read_head()` scans only the last 5,000 journal entries** under the identifier before
   filtering by chain id — a window shared with every other mission database on the host and
   with the MCP's chain (§5, §6).
4. **`degraded` suppresses the head comparison** rather than supplementing it (§6).
5. **The degraded counter resets on the next success**, so a past outage leaves no record
   (§7).
6. **Pre-chain rows are pinned as a set, not individually.** An alteration made before the
   genesis row was written is undetectable, by design (§8).
7. **`cancel-requested` records `actor: orchestrator`** although a person produces it;
   `Store.cancel()` does not pass `actor=ACTOR_USER` for that event.
8. **`Store.record_artifact()` and `Store.decide_review()` append no event.** Artifact rows
   and review decisions are visible through `records` and the receipt; the separately emitted
   `reviewed` event is the only trace of a decision in the chain.
9. **`task-skipped` is a declared edge with no caller** (§9), so its name appears in the
   vocabulary and never in a log.
10. **`clean()` removes only the secrets it can name or recognise by shape** — four
    environment variables' current values, plus `sk-…`/`xai-…` tokens of 12 characters or
    more. A credential that is neither is not stripped from `detail`.
11. **Details are truncated to 10,000 characters before hashing**, so the chain protects the
    truncated text, not the original.

---

## 12. Chains this is not

Two other append-only records exist in this tree, and they are **separate** — different
files, different vocabularies, different verifiers. Nothing joins them automatically; the
shared `session-id` is what a person correlates on.

- **The MCP audit log** (`packages/shadowfetch-fireline/.../sf_mcp.py`). Its own JSON Lines
  chain with its own `AUDIT_HASHED_FIELDS` (`seq, at, chain, phase, server, tool, category,
  decision, reason, correlation, args, outcome, pid`), `audit_hash()` and
  `_audit_canonical()` — deliberately the same construction, not the same log. It cannot be
  the same log: `shadowfetch-missions` Depends on `shadowfetch-fireline` and not the reverse,
  so on a Fireline-only machine those modules are absent — and handing the agent-facing
  process a write handle on Mission Control's chain would let an agent append to the record
  that describes it. A mutating tool call is chained into it or **refused**; reads proceed
  unrecorded and say so. Verified with `shadowfetch-mcp audit verify`, which exits non-zero on
  a broken chain. Its journald anchor **is** Mission Control's when that package is present
  (§5), which is the one part of the record an agent running as the same uid cannot rewrite.

  Its `correlation` field has four values — `absent`, `malformed`, `unknown`, `observed` —
  and only `observed` means a Firebreak session record exists on disk under that id. The file
  says plainly that this is weaker than "the session is real": anything running as this uid
  can create such a file, so `observed` raises the cost of a forged correlation without making
  one impossible.
- **Firebreak session records.** Append-only JSON Lines, one `started` record written before
  the sandbox is spawned and one `ended` record from a `finally`, each an `O_APPEND`+`fsync`
  write, nothing ever rewritten. A session that never reached the sandbox gets
  `exit_reason: "not-started"` rather than a start with no end. Every field is recorded as
  **requested**, with a sibling enforcement map read out of the built argv rather than echoed
  from the request.

---

## 13. Reading it

```
shadowfetch-missions audit verify          # the chain, the head, the anchor verdict, problems
shadowfetch-missions --json audit verify   # the whole report
shadowfetch-missions watch --since <seq>   # raw chained rows, followed; resumable exactly once
shadowfetch-missions watch --no-follow --limit N
shadowfetch-missions events <mission-id>   # one mission's at/event/detail (no "*" rows)
shadowfetch-missions records <mission-id>  # the entity rows the events point at
```

`watch` resumes by sequence number: a client reconnects with the last `seq` it saw and
receives exactly what it missed, once — no duplicates, because the query is strictly
greater-than, and no gaps, because the chain refuses to renumber. Backpressure is the
consumer's: this is a generator over a database, not a queue, so a slow client reads slowly
and the events wait in SQLite. Nothing is buffered on their behalf and nothing is dropped,
because the failure mode of a bounded in-memory buffer is losing the audit records a slow
client most needs.
