# Mission Control persisted state

What Mission Control writes to disk, what each field means, how a 4.0.0 database is
brought forward, and how to add the next migration without breaking someone's queue.

**Version.** Schema version 2, introduced by `14bfd0e` ("Phase 2 Step 5") and
unchanged at `85472f7` (2026‑09‑08). All of it lives in
`packages/shadowfetch-missions/data/usr/lib/shadowfetch/missions/sf_missions.py`;
the proofs live in `packages/shadowfetch-missions/tests/test_schema_migration.py`.

---

## 1. Where it lives

```
$SHADOWFETCH_MISSIONS_STATE
  or  $XDG_STATE_HOME/shadowfetch/missions
  or  ~/.local/state/shadowfetch/missions
```

`Store.__init__` resolves that, creates it `0700` and re-chmods it `0700` every time,
and refuses to run at all if it is the workspace root or inside it:

```python
if self.root == workspace_root() or workspace_root() in self.root.parents:
    raise MissionError("Mission controller state must be outside the workspace root")
```

That is the containment boundary: an agent gets a writable workspace, and the queue,
the receipts, the logs and the recovery indexes are outside it by construction.

| Path | What it is |
|---|---|
| `missions.sqlite3` | the database, chmod `0600`, WAL journal, `busy_timeout=30000` |
| `execution.lock` | `flock`ed by `run_mission()` and by `review()`; serialises execution and review |
| `worker.lock` | `flock`ed by `worker()`; one queue consumer per state directory |
| `<mission-id>/` | one directory per mission, created `0700` on demand |

Inside a mission's directory:

| File | Written by | Contents |
|---|---|---|
| `before.json` | `Executor.execute()` | `tree_index(ws)` at checkpoint time — the execution baseline |
| `after-index.json` | `Executor.receipt()` | `recovery_index(ws)` at finish; `review(..., "undo")` refuses if the workspace has changed since |
| `changes.diff` | `Executor.receipt()` | the rendered change summary |
| `changes.json` | `Executor.receipt()` | the typed change record (`GitChange.as_dict()`) |
| `receipt.json` | `Executor.receipt()` | §5 |
| `<label>.log` | `Executor.run_process()` | one per process, capped at `MAX_OUTPUT` (2 MB); `label` comes from `Invocation.label` |
| `agent-request.txt` | `Executor.agent_turn()` | the prompt handed to the provider on stdin — **transient**, unlinked in a `finally` |

---

## 2. The tables

Created by `Store.__init__`'s `executescript`, which is the **4.0.0 DDL verbatim**.
The two v2 columns and the v2 index are added by `Store.migrate()` — so even a brand
new database gets them via `ALTER TABLE`, not from the `CREATE TABLE`. That is
deliberate: there is exactly one code path that produces the v2 shape, and the tests
exercise it on every database.

### `missions`

| Column | Type | Written by | Meaning |
|---|---|---|---|
| `id` | TEXT PK | `Store.create` | `mission-` + 16 hex characters |
| `title` | TEXT NOT NULL | `Store.create` | 1–160 characters, stripped |
| `kind` | TEXT NOT NULL | `Store.create` | **legacy**: `code` \| `report` \| `media`. Derived from the capability via `CAPABILITY_LEGACY_KIND` and still written, so a 4.0.0 reader sees what it always saw |
| `capability` | TEXT | v2 | `code_change` \| `sourced_report` \| `media_export`. NULL only on an unrecognised legacy row |
| `provider_id` | TEXT | v2 | the manifest `id` of the provider, e.g. `codex`, `offline-media`. NULL only on an unrecognised legacy row |
| `state` | TEXT NOT NULL | `Store.*` | `queued` \| `running` \| `waiting-review` \| `completed` \| `failed` \| `cancelled` \| `undone` |
| `workspace` | TEXT NOT NULL | `Store.create` | absolute path, always a direct child of the workspace root |
| `prompt` | TEXT NOT NULL | `Store.create` | 1–20 000 characters, verbatim |
| `config` | TEXT NOT NULL | `Store.create` | a JSON object, §4 |
| `created_at` | TEXT NOT NULL | `Store.create` | UTC ISO‑8601, second precision |
| `updated_at` | TEXT NOT NULL | `Store.update` / `finish_execution` | same format |
| `attempt` | INTEGER NOT NULL DEFAULT 0 | `run_mission` | incremented on each run; `Store.retry` refuses at 3 |
| `error` | TEXT | `finish_execution` | the failure text a person reads; NULL on success |
| `checkpoint` | TEXT | `Executor.execute` | the Fireline recovery id, taken from `checkpoint_call("snapshot", …)["id"]`. Undo is impossible without it |
| `artifacts` | TEXT NOT NULL DEFAULT `'[]'` | `Executor.receipt` | JSON array of absolute published paths |
| `receipt` | TEXT | `Executor.receipt` | absolute path to `receipt.json` |
| `cancel_requested` | INTEGER NOT NULL DEFAULT 0 | `Store.cancel` | polled by `Executor.check()` between every process read |

`Store.unpack()` JSON-decodes `config` and `artifacts` before any caller sees a row,
so every dict returned by `get()`, `list()` and `page()` has them as real objects.

`Store.update()` accepts only `state`, `attempt`, `error`, `checkpoint`, `artifacts`,
`receipt`, `cancel_requested` — anything else raises `Invalid controller update`.
Nothing after creation may rewrite `kind`, `capability`, `provider_id`, `config`,
`prompt` or `workspace`.

### `events`

```sql
CREATE TABLE events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT, mission TEXT NOT NULL,
    at TEXT NOT NULL, event TEXT NOT NULL, detail TEXT NOT NULL);
```

Append-only. `detail` is passed through `clean()` and truncated to 10 000 characters.
`Store.events(mid)` orders by `seq`, so the ordering is insertion order even when two
events share a timestamp.

Event names in use: `queued`, `running`, `cancel-requested`, `retry-queued`,
`interrupted`, `checkpoint-started`, `checkpoint-created`, `process-started`,
`process-finished`, `inference-finished`, `report-published`, `export-verified`,
`step-resumed`, `validation-guard-reused`, `reviewed`, `schema-migrated`, plus one
final event whose name **is** the terminal state (`waiting-review`, `failed`,
`cancelled`) written by `finish_execution()`.

`mission = '*'` is not a mission id. It is used once, by the migration, so a
store-wide event has somewhere to live.

### `steps`

```sql
CREATE TABLE steps (
    mission TEXT NOT NULL, name TEXT NOT NULL, result TEXT NOT NULL,
    PRIMARY KEY (mission, name));
```

Idempotence records, written with `INSERT OR REPLACE`, values JSON. Used names:

| Name | Holds |
|---|---|
| `media-<n>` | one completed export: input path, `input_sha256`, output path, `sha256`, `bytes`, `decode_verified`, `profile`. A retry re-uses it only if both hashes still match |
| `report-published` | `{path: sha256}` for every published report artifact |
| `report-provenance` | the inference records from the original report attempt, so a retry can cite historical evidence without re-running inference |
| `validation-guard` | the pristine pre-execution index of test/validation files, recorded once and reused on every retry so a later attempt cannot adopt an earlier attempt's edits as its baseline |

### Indexes

```sql
CREATE INDEX missions_queue      ON missions(state, created_at);   -- 4.0.0
CREATE INDEX missions_capability ON missions(capability, provider_id);  -- v2
```

---

## 3. Schema versioning and the migration

### `PRAGMA user_version`

SQLite gives every database a 32‑bit integer in its header that no table occupies and
no query can accidentally join against. `SCHEMA_VERSION = 2` is stored there, read
once per `Store()` construction, and is the only thing that decides whether a
migration runs.

**4.0.0 had none.** `PHASE2_BASELINE.md` records it literally:

```
PRAGMA user_version = 0
tables: missions, events, sqlite_sequence, steps
```

No `user_version`, no `schema_version` column, no migrations table. There was nothing
to version because there was nothing to migrate: `kind` was the capability, the
provider selector and the method name all at once, and provider identity lived in the
JSON `config` blob as `"runtime"`. Introducing the v2 columns is what forced the
question, and Step 5 answered it by writing the version into the header rather than
into a table, so a reader can tell what it is holding without parsing anything.

### What v0/v1 → v2 does

`Store.migrate(db)` runs inside the caller's `with db:` transaction, so a failure
leaves the old shape intact and the version unchanged.

```python
if version < 2:
    #  ALTER TABLE missions ADD COLUMN capability  TEXT     (if absent)
    #  ALTER TABLE missions ADD COLUMN provider_id TEXT     (if absent)
    for mid, kind, raw in db.execute(
            "SELECT id, kind, config FROM missions "
            "WHERE capability IS NULL OR provider_id IS NULL"):
        config     = json.loads(raw) if raw else {}      # a bad blob becomes {}
        capability = LEGACY_KIND_CAPABILITY.get(kind)
        runtime    = config.get("runtime")
        provider   = LEGACY_RUNTIME_PROVIDER.get(runtime, runtime)
        if capability is None or not provider:
            continue                                     # left NULL, never guessed
        db.execute("UPDATE missions SET capability=?, provider_id=? WHERE id=?", ...)
    db.execute("CREATE INDEX IF NOT EXISTS missions_capability ON missions(capability, provider_id)")
db.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
```

The derivations, in full:

| From | To |
|---|---|
| `kind = "code"` | `capability = "code_change"` |
| `kind = "report"` | `capability = "sourced_report"` |
| `kind = "media"` | `capability = "media_export"` |
| `config.runtime = "codex"` | `provider_id = "codex"` |
| `config.runtime = "offline"` | `provider_id = "offline-media"` |

`LEGACY_RUNTIME_PROVIDER = {"codex": "codex", "offline": "offline-media"}`. **The
`offline` → `offline-media` rename is the only rename the migration performs**, and it
happened because the offline media runtime became a provider with a manifest, and a
manifest `id` must match its filename. The legacy string stays readable in the config
blob, so nothing is lost.

### What is deliberately not touched

Everything else. The migration adds two columns and fills them from data the row
already carried; it does not drop, rename or reinterpret anything:

* `kind` is **kept and still written** by `Store.create()` on new missions, so a 4.0.0
  reader sees exactly what it saw before.
* `config` is not rewritten. `config["runtime"]` keeps its legacy spelling.
* `events` and `steps` are untouched.
* `title`, `state`, `error`, `checkpoint`, `prompt`, `workspace`, `attempt`,
  `artifacts` and `receipt` are untouched.
* Review and undo predicates still hold: a mission awaiting review keeps its
  checkpoint, and so do completed and failed missions.

`test_schema_migration.py` builds a database from the verbatim 4.0.0 DDL containing
one mission in **every state 4.0.0 could produce** — queued, running, waiting-review,
completed, failed, cancelled, undone — migrates it, and asserts each of those points.

### An unrecognised row

A row whose `kind` or `runtime` this build does not recognise is **left with NULL
`capability` and NULL `provider_id`** rather than guessed at. It still reads, still
lists, still shows its receipt, and still supports undo. Only re-execution is refused,
and 4.0.0 refused exactly that case too:

```
This mission uses a retired provider. Create a new mission; prior results remain
available for review and Undo
```

`test_an_unrecognised_row_is_left_alone_rather_than_guessed_at` inserts a mission with
`kind = "hologram"` and `runtime = "telepathy"` and asserts both columns stay NULL.

### Three copies must agree

`Executor.execute()` reads provider identity from three places and refuses if they
disagree:

```python
claimed = {self.mission.get("provider_id"),          # the v2 column
           config.get("provider_id"),                 # the config blob
           LEGACY_RUNTIME_PROVIDER.get(runtime, runtime) if runtime else None}
claimed.discard(None)
provider_id = next(iter(claimed)) if len(claimed) == 1 else None
```

An unrecognised runtime string is treated as a **claim**, not an absence: it names a
provider this build does not have, and treating it as missing would let a record that
says `"local"` be quietly executed by whatever the column happens to say. 4.0.0
refused that case rather than picking a winner, and so does this.

### The migration records itself

```
event = "schema-migrated"
detail = "v0 -> v2: derived capability and provider_id for 4 existing mission(s);
          no record was altered otherwise"
```

written against `mission = '*'`, because *a migration that leaves no trace cannot be
audited*. It is written only when at least one row was actually migrated, so a second
open neither changes rows nor re-logs.

### A newer database is refused

```python
if version > SCHEMA_VERSION:
    raise MissionError(
        f"This mission database was written by a newer Shadowfetch "
        f"(schema v{version}; this build understands v{SCHEMA_VERSION}). "
        "Upgrade rather than risk reinterpreting its records.")
```

Downgrade-and-reinterpret is the failure that silently destroys a queue. The `Store()`
constructor raises, so the CLI reports the error as JSON and no command runs.

---

## 4. The `config` JSON blob

One object per mission, written once by `Store.create()` and never rewritten.

```json
{
  "runtime": "offline",
  "provider_id": "offline-media",
  "capability": "media_export",
  "model": "",
  "inputs": ["notes.txt"],
  "test": null,
  "network": "none",
  "timeout": 900
}
```

| Key | Written by | Read by | Notes |
|---|---|---|---|
| `runtime` | `Store.create` | `Executor.execute` (consensus check), `Executor.code()` (into `validation.json`), `Executor.receipt()` (as `receipt["runtime"]`), `missions_page.py` (`config.get('runtime', 'local')` in the detail pane) | **Legacy.** The pre-Phase-2 provider name, kept at its old spelling so a 4.0.0 reader and every existing receipt still make sense |
| `provider_id` | `Store.create` | `Executor.provider`, `Executor.execute` | The manifest id. Duplicates the v2 column on purpose — they are cross-checked |
| `capability` | `Store.create` | not read; the column is authoritative | Duplicated for the same reason |
| `model` | `Store.create` | `Store.create` (refuses non-empty), `CodexCliProvider.accepts` | **Legacy and always `""`.** `Store.create` raises `Mission model selection is unavailable; local AI is deferred` for any non-empty value |
| `inputs` | `Store.create` | `Executor.input_text`, `Executor.media`, provider `accepts()` | Workspace-relative paths, ≤ `MAX_FILES` (40), each validated by `scoped()` and rejected by `is_private()` |
| `test` | `Store.create` | `Executor.code`, `Executor.guards_validation` | A JSON argument array; required for `code`, `null` otherwise. ≤ 100 arguments and ≤ 20 000 characters total |
| `network` | `Store.create` | `Executor.run_process` (non-provider path), provider `accepts()` | `none` \| `allow`. Defaults from the provider's `network_policy` when the caller did not specify |
| `timeout` | `Store.create` | `Executor.__init__` deadline, `run_process` `--cpu-seconds`, `receipt["limits"]` | 10–7200 seconds. **This, not `SandboxSpec.cpu_seconds`, is what Firebreak receives** |

Nothing in the blob is a security decision. Network posture, credentials, read grants
and resource caps come from the provider manifest at execution time, not from here —
`config["network"]` is a person's consent, checked by the provider's `accepts()`.

---

## 5. `receipt.json`

Written by `Executor.receipt()` on every outcome, including failure and cancellation,
and its path is stored in `missions.receipt`.

```
schema                    always 1 — the receipt's own version, unrelated to SCHEMA_VERSION
mission, title, kind, state, workspace, checkpoint
started_at, finished_at
runtime                   config["runtime"], the LEGACY provider name
network                   config["network"]
error                     the failure text, or null
artifacts                 [{path, sha256, bytes}] for every published file that exists
tests                     [{command, exit, log}] from Executor.code()
inferences                [{provider, provider_version, model, model_selection, usage,
                            observed_at, attempt, response_sha256, log, reused}]
diff, changes             absolute paths to changes.diff / changes.json
diff_truncated            whether the change summary hit its byte limit
review_required           state == "waiting-review"
recovery_index_preserved  whether after-index.json was deliberately not refreshed
limits                    {timeout_seconds, sandbox_rss_mb, sandbox_address_space,
                           sandbox_processes, queue_concurrency}
recovery_scope            "Workspace files only; external network effects cannot be undone"
```

Two things about the receipt are worth knowing before you rely on it:

* **It names the legacy runtime, not the provider.** There is no `capability` or
  `provider_id` key; a reviewer sees `"runtime": "offline"`, not `"offline-media"`.
  The `inferences` array *does* carry `provider` and `provider_version`, but only for
  capabilities that take an agent turn — a media export produces no inference record.
* **`limits.sandbox_rss_mb` and `limits.sandbox_processes` are hard-coded** `3072` and
  `96`, not read from the `SandboxSpec` that actually ran. A provider that declared
  smaller limits gets a receipt that overstates them.

---

## 6. Adding a future migration

A checklist, derived from what v2 did.

1. **Bump `SCHEMA_VERSION`** in `sf_missions.py` and extend its docstring with a line
   describing the new version in one sentence.
2. **Add a `if version < N:` block** to `Store.migrate()`, *after* the existing ones
   and *before* the final `PRAGMA user_version` write. Never reorder or edit an
   existing block — someone's database is at that version right now.
3. **Only add.** Add columns with `ALTER TABLE … ADD COLUMN` (SQLite cannot drop one
   without rewriting the table); add indexes with `CREATE INDEX IF NOT EXISTS`. Do not
   drop, rename or retype anything a previous version wrote, and do not rewrite an
   existing value that a person or an older build could still be reading.
4. **Guard every step.** Check `PRAGMA table_info(missions)` before adding a column, as
   v2 does, so a partially-migrated database converges instead of erroring.
5. **Derive, never guess.** Fill new columns only from data the row already carries. A
   row you cannot derive is left NULL and reported at execution time — it must still
   read, list, show its receipt and support undo.
6. **Stay inside the caller's transaction.** `migrate()` is called from inside
   `with self.db()`; do not open a second connection, do not `commit()`, do not
   `PRAGMA` anything that implicitly commits. A failure must leave the old shape and
   the old `user_version` intact.
7. **Be idempotent.** Opening the store twice must change nothing and must not re-log
   the migration event. Gate the log on "did I actually migrate a row".
8. **Record it.** Insert one `schema-migrated` event against `mission = '*'` saying
   what was derived, for how many rows, and what was not touched.
9. **Keep the legacy shape readable.** If you introduce a new spelling for something
   that already has one, keep writing the old one too, as `kind` and
   `config["runtime"]` still are, until a release explicitly retires it.
10. **Extend `test_schema_migration.py`,** which is the actual contract. It should
    contain: a fresh database opens at the new version; an existing database at every
    prior version moves forward; one mission in **every state** survives with every
    pre-existing field byte-identical; the new field is correctly derived; events and
    steps are untouched; migrating twice changes nothing and logs once; an
    unrecognised row is left alone; and a database from the future is refused.
11. **Check the readers.** `packages/shadowfetch-control-center/tests/test_capabilities_contract.py`
    asserts every key the desktop reads is still emitted, and `capabilities()`
    publishes `schema_version`. If your migration changes what the UI sees, that test
    is where it must be re-agreed — the two packages are built separately and only a
    test can stop the engine renaming something the desktop depends on.
