# The audit event spine

One append-only, hash-chained table, an external anchor that can see what the chain cannot,
and an event vocabulary with exactly one definition per name.

**Version.** Brought forward to **Phase 3.1** on the `release/4.0.0` branch (schema **v4**).
It was first written against `7978259` ("Phase 3 Steps 19, 20, 21, 23, 24, 25"); everything
Phase 3.1 changed — mission-state classification (§4), the v4 legacy pin (§8), the whole-log
anchor comparison and the store identity (§5), and the single exit-code ladder (§6) — is
described here as it stands, with the superseded behaviour kept only under **Historical
note** headings. The chain lives in
`packages/shadowfetch-missions/data/usr/lib/shadowfetch/missions/sf_missions.py`; the
external anchor in `sf_audit.py` beside it. Proofs are in
`packages/shadowfetch-missions/tests/test_audit_chain.py` and `test_schema_v3.py`, and the
attacks in `tools/attacks/attack_integrity.py`, which `make attacks` runs and `make test`
ends with.

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
  reported as such — §8.
- that the log is **complete**. Nothing forces a caller to emit an event; the chain protects
  what was written, not what should have been.
- anything against **root**. Root can rewrite both the database and the journal.
- anything about the **content's truth**. A correctly chained event can say something false
  about the world; the chain says only that this text is what was written at that sequence
  number.
- anything about the **`missions` table**, which is not chained. The chain is about the LOG.
  Whether the mission rows agree with the log is a second question, asked and answered
  separately by `verify_states()` — §4 — and reported in the same `audit verify` output
  under its own verdict, because collapsing the two would let one of them borrow the other's
  credibility.

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
| `event` | a name from §9 |
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
later in the same migration and pins it along with every other pre-chain row (§8).

Two raw rows, as stored:

```json
{"actor":"orchestrator","at":"2026-09-09T05:24:22+00:00","detail":"{\"chain_id\": \"c84a6d8cd66b4f03a749fd509d51251f\", \"from_schema_version\": 0, \"note\": \"events before this row predate the chain and are not individually verifiable; this digest pins the set as it stood when the chain began\", \"to_schema_version\": 4, \"unchained_digest\": \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\", \"unchained_events\": 0}","event":"audit-chain-started","hash":"6733f2c9fef1cc44e24479c6baa68cae03a4f62cecd8fcdedf881afc03d797f7","mission":"*","prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","seq":1,"session_id":null,"task_id":null,"tool_execution_id":null}
{"actor":"orchestrator","at":"2026-09-09T05:24:22+00:00","detail":"the step began","event":"task-started","hash":"31569494fa0a2d67e623795554829c922b18f5b4939d28fa297e62e94508023f","mission":"mission-183bf38cebdb4a28","prev_hash":"01110fb4c544864172502ad6be495009c5b50d7cec96ad05e1bb3452bb18981b","seq":5,"session_id":null,"task_id":"task-1b9a3639c9d84b1c","tool_execution_id":null}
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

One further check exists because SQLite will store bytes in a TEXT-affinity column and
`canonical()` cannot serialise them: a `detail` that is not text is reported as a **problem**
rather than hashed. It used to raise `TypeError` out of `verify_chain()`, which failed closed
but left an operator with a traceback instead of a verdict and left `--json` emitting nothing
parseable.

| Check | Problem reported |
|---|---|
| `detail` is text | `seq N: detail is bytes, not text, so this row cannot be hashed and was written by something other than the engine` |

A modified row, altered directly with `sqlite3` rather than through the API:

```
$ sqlite3 …/missions.sqlite3 'UPDATE events SET detail="tampered" WHERE seq=5;'
$ shadowfetch-missions audit verify
events            10
  chained         10
  unchained       0 (written before the chain existed; pinned by the genesis digest, not individually verifiable)
chain             BROKEN
mission states    agrees (1 replayed against the transition table)
head              seq 10 edc77f36f663fc41
external anchor   agrees (shadowfetch-audit)
  journal head    seq 10
PROBLEM           seq 5: content does not match its hash (this row was modified after it was written)
exit=1
```

### The mission rows are replayed against the log

`verify_chain()` calls `Store.verify_states()` and carries its result at `report["states"]`.
The chain's own verdict is kept separately as `report["chain_ok"]`, and `report["ok"]` is
false if **either** disagrees — which is why the transcript above can print `chain BROKEN` on
one line and `mission states agrees` on the next.

The reason is stated in the code and is worth repeating here: the chain proves no EVENT was
altered and says nothing whatever about the `missions` table, which carries no hash. So
`UPDATE missions SET state='completed'` was indistinguishable from work that ran — and the
engine would then narrate the forged state back into the log, appending *"a human changed
their mind about accepted work"* for a mission that had never run. The replay takes each
mission's event trail, walks it through `MISSION_TRANSITIONS`, and compares where it lands
with what the row says. It needs no new storage.

### The five classifications

Separate words, because they call for different actions.

| Class | Meaning | A problem? |
|---|---|---|
| `VALID_CURRENT` | the trail replays cleanly and ends where the row says | no |
| `LEGACY_PRECHAIN` | the mission is named in the v4 legacy pin, or its first event precedes the genesis | no |
| `STATE_DIVERGENCE` | the row's state is not where its events end — that state was written without an event | yes |
| `CORRUPTED_HISTORY` | the trail contains an edge `MISSION_TRANSITIONS` forbids | yes |
| `MISSING_HISTORY` | the row exists, has no events at all, and is not in the pin | yes |

`MISSING_HISTORY` is a finding only because two other things are true at once, and it is
worth being explicit about the pair:

- **`Store.create()` writes the mission row and its first event in ONE transaction.** They
  used to be written on two connections, so an interruption between them left a real mission
  with no events — the exact shape a fabricated row has. Atomic creation is what makes
  "event-less" mean "not made by this engine".
- **The v4 migration pins the missions that legitimately have none** in a chained event
  (§8). Before that, `verify_states()` excused every event-less mission as pre-chain, which
  is an inference from ABSENCE — and an attacker obtains absence by writing nothing.

Verbatim, three forged rows against three throwaway stores:

```
### UPDATE missions SET state='completed' on a queued mission
  "classes":  {"mission-51b3ffa4346a473b": "STATE_DIVERGENCE"},
  "verdict":  "disagrees",
  "problems": ["mission mission-51b3ffa4346a473b: the row says 'completed' but its events
                end at 'queued'; that state was written without an event"]

### the same, and then the engine is asked to move it to 'undone'
  "classes":  {"mission-c2e65f2eb0844434": "CORRUPTED_HISTORY"},
  "problems": ["mission mission-c2e65f2eb0844434: event 3 records queued -> undone, which
                the transition table forbids; the row was changed outside the engine"]

### a mission row INSERTed straight into the table, with no events at all
  "classes":  {"mission-235c01fb99e5461f": "MISSING_HISTORY"},
  "problems": ["mission mission-235c01fb99e5461f: the row says 'completed' and the log has
                no history for it at all. Creation and its first event commit together, and
                this mission is not in the chained legacy pin, so the row was written
                outside the engine"]
```

All three print `chain intact` and `mission states disagrees`, and all three exit 1.

**What the replay does not do.** It detects at verify time; it prevents nothing at write
time, and it cannot recover the state the mission actually had. A `CORRUPTED_HISTORY` trail
also stays classified as corrupt for the life of the database: the forbidden edge is a
chained event and nothing rewrites it.

**Historical note.** Through Phase 3 nothing replayed the trail. The
`state-jump-forged-row` attack in `tools/attacks/attack_integrity.py` reported that as a
finding in the plainest words it had — *"not prevented, not detected"* — and `audit verify`
reported a clean log over a mission that had never run.

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
MIRRORED_FIELDS = ("store", "chain", "seq", "hash", "mission", "event", "at")
```

`detail` is **never** mirrored. What *does* leave the database is the mission id, the event
name and the timestamp — enough to correlate, and enough that anyone who can read the
journal learns which missions existed and what happened to them. A real payload:

```
{"at":"2026-09-09T05:12:26+00:00","chain":"1d5b516f47f248ca97049ef2c52db8cb","event":"waiting-review","hash":"8ff6f8b01aa96e2c5b684cad059f19bb5c9957e2767e4ae897c1608b4930033a","mission":"mission-12d974daf2dc4574","seq":4,"store":"18e0770b32b96622"}
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

### The store identity: the one name the database cannot restate about itself

`sf_audit.store_identity(db_path)` is `sha256(absolute path)[:16]`, and it rides on every
mirrored line as `store`.

The chain id is minted into an events row, so a uid that can write the events table can also
mint a new one — deleting the genesis and re-chaining produced a log that verified clean,
because `read_head()` is keyed by the id the database hands it and the new id simply had no
journal history. Absence of evidence read far too much like a pass. The store identity is
derived from the path the **operator opened**, not from anything inside the file, so entries
this store mirrored under an earlier chain id stay attributable to it. `read_head()` collects
those as `other_chains`, and `verify_chain()` reports a re-minted chain as a **conflict**:

```
PROBLEM  this store has previously mirrored chain id(s) e0051f7b63d6 (4 event(s)), and now
         presents 71d65e7f1967. A chain id is minted once at genesis, so the log was
         re-minted after those events were recorded
```

A database genuinely **copied to a different path** is a different store and has no journal
history there. That reports `unverified` — the honest answer to "I have never seen this
before" — and is not a pass.

### Reading the anchor

`sf_audit.read_head(chain, store=…)` runs
`journalctl -t shadowfetch-audit -o cat --no-pager -n 5000` and reads every line whose
`chain` matches, not only the newest. It returns four things:

| Key | What it holds |
|---|---|
| `head_seq` / `head_hash` | the highest sequence number the journal can see for this chain |
| `heads` | **every** visible `seq → hash`, so a rewrite deep in the log is comparable |
| `conflicts` | a `seq` mirrored more than once with **different** hashes |
| `other_chains` | chain ids seen for **this store** other than the one the database claims |

Two details in there are load-bearing. **The earliest line for a sequence number wins, not
the latest**: `journalctl` emits oldest-first, so the first line for a `seq` is the one
written when the event was appended, and anything after it arrived later. And a second,
differing line for one `seq` is **reported rather than resolved** — the engine mirrors each
`seq` exactly once, `/dev/log` is a local datagram socket within reach of the mission uid,
and picking a winner would mean deciding which forgery to believe.

It distinguishes *cannot tell* from *nothing there*: `journalctl` missing, `journalctl`
exiting non-zero, and zero readable entries each produce their own `reason` string. A user
outside the `systemd-journal` group sees an empty journal, and calling that a verified
absence would be exactly the kind of unearned claim this phase exists to remove.

---

## 6. The six verdicts, and what `ok` means

| Verdict | Condition | Is it a finding? |
|---|---|---|
| `agrees` | journal head seq == database head seq, and the hashes match | no |
| `behind` | journal head seq < database head seq | **no** |
| `truncated` | journal head seq > database head seq | yes — sets `ok: false` |
| `conflict` | any of: the heads' hashes differ; a mirrored `seq` the journal still holds disagrees with the stored row (`rewritten_seqs`); one `seq` mirrored twice with different hashes (`mirror_conflicts`); this store has mirrored another chain id (`other_chains_for_this_store`) | yes — sets `ok: false` |
| `unverified` | the journal could not be read, has no entries for this chain, or either head is unknown | not a pass either |
| `degraded` | the mirror has recorded failures **and** the comparison found nothing | not a pass either |

**`behind` is not a finding, and reporting it as one would train people to ignore the
anchor.** The mirror is asynchronous — it runs after the commit — and journals rotate, so
the journal legitimately trails the database. Only the *other* direction is evidence: the
journal knowing about an event the database does not.

**Verdict precedence: findings always win.** `truncated` and `conflict` are conclusions drawn
from the journal, and nothing local may overwrite them. `degraded` is only reached when the
comparison found nothing — the code tests `anchor["verdict"] in ("agrees", "behind",
"unverified")` before setting it — while `anchor["degraded"]` stays separately readable
either way and the mirror-failure line is appended to `problems` regardless of the verdict.
Local bookkeeping may add a caveat; it may never remove a finding.

> **Historical note.** This was an `if/elif` chain with `degraded` tested **first**, and
> earlier versions of this document defended that as honest. It was a suppression switch.
> `audit-mirror.json` lives beside the database, owned by the same uid that writes the
> events, so an attacker could truncate the log and then write `{"failures": 1}` into a file
> they already controlled: `ok=False` became `ok=True`, *"2 event(s) were removed from the
> end of the log"* became *"the audit mirror has failed 1 time(s)"*, and exit 1 became exit
> 2 — while the CLI printed the database head and the journal head two lines apart without
> comparing them. Deleting the file never helped the attacker; only writing it did.

**`ok` is a combined verdict.** It is false if the chain's own rows fail, **or** the anchor
reports `truncated`/`conflict`, **or** the mission-state replay disagrees (§4). `degraded`
and `unverified` do not set it. So `chain BROKEN` in the printed output can mean the chain's
own rows are all fine and only the anchor disagrees — `chain_ok`, the `mission states` line
and the `problems` list say which. Deleting the last two rows:

```
$ sqlite3 …/missions.sqlite3 'DELETE FROM events WHERE seq > (SELECT MAX(seq)-2 FROM events);'
$ shadowfetch-missions audit verify
events            7
  chained         7
  unchained       0 (written before the chain existed; pinned by the genesis digest, not individually verifiable)
chain             BROKEN
mission states    agrees (1 replayed against the transition table)
head              seq 7 151e19d4cbe4f61b
external anchor   truncated (shadowfetch-audit)
  journal head    seq 9
PROBLEM           the journal records event 9 but the database stops at 7: 2 event(s) were removed from the end of the log
exit=1
```

and the machine-readable form, showing that every row that survives still verifies, the
mission rows still agree with what is left of the log, and the only problem is the anchor's:

```json
{
    "ok": false, "events": 7, "chained": 7, "unchained": 0,
    "first_chained_seq": 1, "head_seq": 7, "chain_ok": false,
    "problems": ["the journal records event 9 but the database stops at 7: 2 event(s) were removed from the end of the log"],
    "anchor": {
        "identifier": "shadowfetch-audit",
        "chain": "031f1adf6e694f5195758e1323b59365",
        "readable": true, "reason": null,
        "journal_head_seq": 9, "database_head_seq": 7,
        "last_mirrored_seq": 9, "mirror_failures": 0, "last_mirror_error": null,
        "verdict": "truncated",
        "rewritten_seqs": [], "other_chains_for_this_store": {}, "mirror_conflicts": {}
    },
    "states": {
        "missions": 1, "replayed": 1, "predates_chain": 0,
        "classes": {"mission-d07f274c25164dd6": "VALID_CURRENT"},
        "legacy_reasons": {}, "problems": [],
        "counts": {"VALID_CURRENT": 1}, "verdict": "agrees"
    }
}
```

### The exit-code contract

One function, `audit_exit_code(report)`, computes the ladder from the report and nothing
else, **before** anything is rendered:

| Code | Meaning |
|---|---|
| `0` | `ok`, and the anchor verdict is not `unverified` or `degraded` |
| `1` | `ok` is false — a broken chain, a journal finding, or a disagreeing state replay |
| `2` | `unverified` or `degraded`. **Not a pass**: truncation remains undetectable while either holds |

It **fails closed**: a report with no `ok` at all returns 1, because the only way to be told
a log is intact is for the verifier to have said so.

> **Historical note.** The ladder used to sit inside `if not args.json:`, so the caller most
> likely to pass `--json` — a CI gate, a cron check, the LaunchAgent pattern this project
> already uses — was told a tampered log had passed. Exit status is a property of the
> RESULT, never of how it is being printed; text and `--json` now return the same code from
> the same call.

### What the anchor still cannot see

- **A hole in the middle of the journal is still invisible.** The anchor compares every
  sequence number the journal *can see* against the stored row, so a rewrite deep in the log
  is caught (`rewritten_seqs`). What it cannot do is notice an event that was never mirrored
  at all: if mirroring fails for events 10–12 and succeeds for 13, there is nothing to
  compare 10–12 against, the heads agree, and nothing retries a failed mirror. `degraded`
  is the only signal that this happened, and it survives only until the next success (§7).
- **Only the last 5,000 journal entries under the identifier are scanned**, and the chain
  filter is applied *after* that window. A busy host with several chains can push a quiet
  chain's entries out of the window, at which point it reports `unverified` rather than
  `agrees`. This is not hypothetical: one throwaway chain in the course of writing this
  document produced 1,006 entries — a fifth of the window — in five seconds.
- **Root can rewrite the journal**, so this is tamper *evidence* and nothing stronger.
- **The mirror is not protected in transit.** `/dev/log` is a local socket; anything that can
  write to it can write plausible lines under the identifier. That is exactly why a second,
  differing line for one `seq` is reported as a `mirror_conflict` rather than resolved.
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
  "failures": 3,
  "last_error": "FileNotFoundError: [Errno 2] No such file or directory",
  "last_mirrored_seq": null,
  "last_success_at": null
}

### verify_chain(): chain intact, audit degraded
{
  "ok": true, "chain_ok": true, "events": 3,
  "problems": [
    "the audit mirror has failed 3 time(s); last error: FileNotFoundError: [Errno 2] No such file or directory. Events are still recorded in the database, but events written while this persists are not externally anchored"
  ]
}
{
  "identifier": "shadowfetch-audit",
  "chain": "59c0c06b1c3d4246b8c91505d3fd00e7",
  "readable": true,
  "reason": "no entries for this chain are readable; either none were written, they have rotated away, or this user cannot read the journal",
  "journal_head_seq": null, "database_head_seq": 3,
  "last_mirrored_seq": null, "mirror_failures": 3,
  "last_mirror_error": "FileNotFoundError: [Errno 2] No such file or directory",
  "degraded": true, "verdict": "degraded",
  "rewritten_seqs": [], "other_chains_for_this_store": {}, "mirror_conflicts": {}
}
```

A mirror outage does **not** make the chain report broken: `ok` stays true and the chain's
own verdict is untouched. Those are different facts.

**`degraded` is a caveat, never a substitute for a comparison.** The verdict reads
`degraded` here only because the journal had nothing to compare against; had the same store
been truncated, it would read `truncated` with the mirror-failure line printed **alongside**
the removal (§6, Historical note). `anchor["degraded"]` is set independently of the verdict
precisely so a caller can ask "is the mirror unwell?" without the verdict having been spent
on answering it.

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

A v1 database — five legacy events, two legacy missions, one of which never recorded an
event at all — opened by this build, which migrates it to **v4**:

```
### every row, as stored, after the upgrade
  seq  1  queued                  mission-legacy-with-events  prev=None              hash=None
  seq  2  running                 mission-legacy-with-events  prev=None              hash=None
  seq  3  waiting-review          mission-legacy-with-events  prev=None              hash=None
  seq  4  reviewed                mission-legacy-with-events  prev=None              hash=None
  seq  5  completed               mission-legacy-with-events  prev=None              hash=None
  seq  6  schema-migrated         *                           prev=None              hash=None
  seq  7  audit-chain-started     *                           prev=0000000000000000  hash=f1dc936a769a12a2
  seq  8  legacy-missions-pinned  *                           prev=f1dc936a769a12a2  hash=451b7c99a8cd99cb

### verify after the upgrade
{
  "ok": true, "chain_ok": true,
  "events": 8, "chained": 2, "unchained": 6, "first_chained_seq": 7, "problems": []
}
```

Note seq 6: the migration's own row, written by the one raw INSERT (§2), unchained, and
pinned by the genesis a moment later.

In a database created fresh by this build the genesis is seq 1 with
`unchained_events: 0` and `unchained_digest` equal to the SHA-256 of the empty string —
the honest value for "there was nothing here before me".

`Store.chain_id()` reads the id back out of that row and caches it **per Store instance**,
not per process, so a test opening several stores gets several ids.

### `legacy-missions-pinned`: writing an absence down positively

Schema v4 adds one thing, and it is not a table. Immediately after `start_chain()`, the
migration appends a **chained** event naming every mission that had no events at all at that
moment:

```json
{
  "count": 1,
  "from_schema_version": 1,
  "missions": ["mission-legacy-no-events"],
  "note": "missions that existed with no recorded history when this database was upgraded; after this point an event-less mission is unexplained, because creation and its first event commit together",
  "pinned_at_schema_version": 4
}
```

`verify_states()` used to excuse **every** event-less mission as pre-chain. That is an
inference drawn from ABSENCE, and an attacker obtains absence by writing nothing — so a
fabricated row with `state='completed'` verified as healthy. The pin writes the same fact
down once, positively, into an event the hash chain protects. Afterwards an event-less
mission is either named there or it was invented, which is a real dichotomy only because
`Store.create()` is atomic (§4).

The two ways a mission earns the `LEGACY_PRECHAIN` classification are both recorded in the
chain, and `verify_states()` says which one applied:

```json
"legacy_reasons": {
  "mission-legacy-no-events":   "named in the chained legacy pin written at the v4 upgrade",
  "mission-legacy-with-events": "its first event (seq 1) precedes the chain genesis at seq 7"
}
```

A mission row inserted **after** the upgrade gets neither, and is reported:

```json
"classes":  {"mission-invented-after": "MISSING_HISTORY"},
"problems": ["mission mission-invented-after: the row says 'completed' and the log has no
              history for it at all. Creation and its first event commit together, and this
              mission is not in the chained legacy pin, so the row was written outside the
              engine"]
```

Three properties of the pin, stated plainly because each is a limit:

- **It is trust-on-first-use.** It believes the database as it stands at upgrade time. It
  cannot recover provenance that was never recorded, and it is the strongest claim available
  to a build that was not present when those rows were written.
- **An empty pin is not written.** A pin naming nothing grants no exemption, so writing one
  would add an event to every fresh database to say there was nothing to say. Absence of the
  pin and an empty pin mean the same thing to `legacy_missions()`, which returns an empty
  set for both.
- **It is written once.** The migration returns early if any `legacy-missions-pinned` event
  already exists, so a later upgrade cannot mint a second, wider exemption.

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
| `retry-queued` | `Store.retry()`, and any other caller of the `failed`/`cancelled → queued` edge | `user` | — |
| `retry-budget-exhausted` | `transition()` or `finish_execution()` when `requeue_refusal()` blocks a fourth attempt — **the mission row is left untouched** | the actor that asked | — |
| `cancel-requested` | `Store.cancel()` on a running mission — a *request*, not a state change | `user` | — |
| `reviewed` | `review()`; detail is the bare decision `accept` / `undo` | `user` | — |

`retry-budget-exhausted` is the one event in this table that records something that did
**not** happen, and it is deliberate: the refusal is appended inside the same transaction
that declines to move the row, and the `TransitionError` is raised only after that
transaction commits. Raising from inside it would roll back the only evidence that a fourth
attempt was asked for, and "no event" reads exactly like "nobody ever tried". `MAX_ATTEMPTS`
is 3, published by `capabilities()` as `max_attempts`, and `requeue_refusal(event, attempt)`
is the single place that answers the question — keyed on the **edge's event name**, not on
which verb is asking, because three different verbs reach that edge.

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
| `approval-granted` | `Store.grant_approval()`; detail carries every field of `APPROVAL_WITNESSED_FIELDS` **plus `record_sha256` over the whole record** | `user` |
| `approval-revoked` | `Store.revoke_approval()`; detail is JSON naming the approval, the instant and the revoke's own reason | `user` |
| `review-opened` | `Store.open_review()` | `orchestrator` |
| `review-summary-failed` | `run_mission()` when the summary could not be built — the mission still reaches review | `orchestrator` |

### System

| Event | Emitted by | Actor | Mission |
|---|---|---|---|
| `audit-chain-started` | `Store.start_chain()`, once per database | `orchestrator` | `*` |
| `legacy-missions-pinned` | the v3→v4 migration, once per database, **chained** — §8; not written when it would name nothing | `orchestrator` | `*` |
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
2. **An event that was never mirrored has nothing to be compared against.** The anchor now
   compares every `seq` the journal still holds, so a rewrite deep in the log is caught — but
   a mirror failure leaves a hole in the journal that nothing detects and nothing retries
   (§6).
3. **`read_head()` scans only the last 5,000 journal entries** under the identifier before
   filtering by chain id — a window shared with every other mission database on the host and
   with the MCP's chain (§5, §6).
4. **The degraded counter resets on the next success**, so a past outage leaves no record
   (§7). This is the surviving half of what used to be two gaps: `degraded` no longer
   suppresses the head comparison.
5. **Pre-chain rows are pinned as a set, not individually.** An alteration made before the
   genesis row was written is undetectable, by design (§8).
6. **The legacy pin is trust-on-first-use** (§8). It records the database as it stood at the
   v4 upgrade; it cannot tell an honest pre-chain mission from one somebody inserted the
   minute before upgrading.
7. **The chain id and the legacy pin both live in rows this uid can delete.** Re-minting is
   now evidence rather than amnesia, because the store identity is derived from the database's
   path (§5) — but the journal is what carries that evidence, so on a host with no readable
   journal the re-mint reports `unverified` like everything else.
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
12. **The mission-state replay detects; it does not prevent and it does not repair.** A
    forged row is reported at verify time (§4) and the state it displaced is not recoverable.

> **Historical note — two gaps that were on this list and are not now.** *"`degraded`
> suppresses the head comparison"* was fixed by reporting degradation alongside the
> comparison (§6). *"`cancel-requested` records `actor: orchestrator` although a person
> produces it"* was fixed by passing `actor=ACTOR_USER`; both events `Store.cancel()` can
> emit now record the person.

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
