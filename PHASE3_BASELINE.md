# Phase 3 Baseline

*State of the tree at `d24113c`, the final Phase 2.5 commit, measured before any
Phase 3 change. Every number here was produced by a command.*

---

## 1. Identity

| | |
|---|---|
| HEAD | `d24113c` — *Phase 2.5: baseline, implementation, test results and remaining risks* |
| Branch | `release/4.0.0` |
| Working tree | clean (`git status --porcelain` empty) |
| Operational schema version | **2** (`SCHEMA_VERSION = 2`, stored in `PRAGMA user_version`) |
| Provider interface version | **1** (`INTERFACE_VERSION = 1`) |
| Approved providers | `codex`, `offline-media` |
| Registered providers | the same two; `codex` reports `available=false` (no dedicated account) |

### Approved-provider policy state

`/usr/share/shadowfetch/provider-policy/approved.json`, `schema_version: 1`, two
entries, each pinning `manifest_sha256`, package, interface version,
capabilities, credential identities, network policy, egress allowlist,
`executable_trust` and a `trust` class. Both `distro-managed`.

---

## 2. Gates and tests at baseline

```
make test
  Ran 404 tests  OK (skipped=4)      packages/shadowfetch-missions
  Ran  50 tests  OK
  Ran  98 tests  OK
  Ran  26 tests  OK
  Ran  36 tests  OK
  Ran  49 tests  OK
  Ran  26 tests  OK
  Ran  13 tests  OK                  packages/shadowfetch-fireline
  Ran 162 tests  OK                  tools/tests (release gate)
  ----------------------------------------------------------------
  864 tests total

make source-gate    SOURCE_GATE_PASSED
make package-gate   PACKAGE_GATE_PASSED
```

Provider conformance and the Phase 2.5 trust tests are inside the 404: 33
conformance assertions run against each of four providers (`codex`,
`offline-media`, and the `conformance-echo` / `conformance-localmodel`
fixtures).

Firebreak integration tests: `packages/shadowfetch-fireline/tests` (13 tests,
all reachable) plus the `skipUnless(sandbox_available())` empirical class in
`packages/shadowfetch-missions/tests/test_sandbox_spec_audit.py`, which does run
on this host — bubblewrap, `systemd-run` and a user D-Bus session are all
present.

---

## 3. P0 FOUND AND FIXED BEFORE THE BASELINE WAS COMMITTED

**The only provider available on this host could not execute a single mission.**

Phase 2.5 (`43372e4`) made `verify_invocation()` check *which* program an adapter
returns. The `offline-media` adapter runs **two** programs — `/usr/bin/ffprobe`
to inspect and `/usr/bin/ffmpeg` to encode — and its manifest declared one. Every
`media_export` mission had failed since that commit:

```
state : failed
error : offline-media: /usr/bin/ffprobe is not a program this manifest declares.
        Declared: /usr/bin/ffmpeg
events: queued → running → checkpoint-started → checkpoint-created → failed
```

**Why 864 green tests missed it.** `verify_invocation()` appeared in the
conformance suite exactly once, fed a *deliberate substitute* (`/usr/bin/true`)
to prove substitution is refused. **Nothing ever passed an adapter's own
`build_invocation()` output through the check the orchestrator actually applies.**
The media tests additionally patch `FFMPEG`/`FFPROBE` to fixture binaries, so the
real mismatch could not appear.

Fixed here rather than deferred: a control plane cannot be built on a provider
layer that cannot execute. See `PHASE3_IMPLEMENTATION.md` §0.

A second, *host-state* blocker is recorded rather than fixed: `/usr/bin/shadowfetch-firebreak`
on this box comes from the installed `shadowfetch-fireline 3.0.0` package and
rejects 4.0.0's flags (`unknown run option: --memory-mb`). `executable()`
resolves it through `shutil.which` first. Every measurement below that needed a
sandbox prepended the source tree's `packages/shadowfetch-fireline/data/usr/bin`
to `PATH`. This is an environment limitation, not a repository defect.

---

## 4. The SQLite schema

Three tables. All DDL is one `executescript` in `Store.__init__`
(`sf_missions.py:283-298`); two columns and one index exist **only** via
`migrate()`, so even a new database reaches v2 through `ALTER TABLE`.

```sql
CREATE TABLE missions (
    id TEXT PRIMARY KEY, title TEXT NOT NULL, kind TEXT NOT NULL,
    state TEXT NOT NULL, workspace TEXT NOT NULL, prompt TEXT NOT NULL,
    config TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
    attempt INTEGER NOT NULL DEFAULT 0, error TEXT,
    checkpoint TEXT, artifacts TEXT NOT NULL DEFAULT '[]', receipt TEXT,
    cancel_requested INTEGER NOT NULL DEFAULT 0);
CREATE TABLE events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT, mission TEXT NOT NULL,
    at TEXT NOT NULL, event TEXT NOT NULL, detail TEXT NOT NULL);
CREATE TABLE steps (
    mission TEXT NOT NULL, name TEXT NOT NULL, result TEXT NOT NULL,
    PRIMARY KEY (mission, name));
CREATE INDEX missions_queue ON missions(state, created_at);
-- added by migrate():
ALTER TABLE missions ADD COLUMN capability TEXT;
ALTER TABLE missions ADD COLUMN provider_id TEXT;
CREATE INDEX missions_capability ON missions(capability, provider_id);
```

No triggers, no views, no foreign keys, no CHECK constraints. `events.mission`
is plain TEXT and deliberately carries the non-mission sentinel `'*'`.

There is **no `v0 → v1` step**: v1 never existed on disk. `migrate()` has a
single `if version < 2:` block, so 0 → 2 and 1 → 2 are one path. A database
written by a *newer* schema is refused outright from the `Store()` constructor.

**Entities that do not exist yet:** `Task`, `AgentSession`, `ToolExecution`,
`Approval`, `Review`, `Artifact`, `TestRun`, `GitChange`. Phase 2 left W-26 at
roughly 1 of 10.

---

## 5. Mission states, and the absence of a state machine

Seven states, enumerated once as data (`capabilities()`), consulted by no write
path:

```
queued, running, waiting-review, completed, failed, cancelled, undone
```

`ACTIVE = ("queued", "running")` is used exactly once. **`FINAL` is dead code.**

**There is no central transition validation.** `Store.update()` is the single
generic writer and validates the *column name* only:

```
== Store.update(COMPLETED, state=running)  -> ACCEPTED, persisted
== Store.update(COMPLETED, state=banana)   -> ACCEPTED, persisted
== Store.update(workspace=/etc)            -> REFUSED  (column not in allow-list)
```

Guards exist, but only inside the high-level verbs (`cancel`, `retry`,
`run_mission`, `review`), each written independently at its own call site.

**The damaging case, executed:** forcing an `undone` mission back to `queued`
let `run_mission` execute it again. It **overwrote `receipt.json`**, destroying
the successful receipt including its artifact SHA-256s; it did **not** take a new
checkpoint, leaving the row pointing at a recovery point that no longer matches
the workspace; and **the forced transition emitted no event at all** — the log
jumps from `reviewed|undo` straight to `running`.

---

## 6. Observed lifecycle behavior

| operation | observed |
|---|---|
| create | one INSERT at `state="queued"`, then a *separate* `event()` on a second connection. There is no distinct "queue" verb — create *is* queue |
| run | `queued → running` under the global lock, then terminal state chosen **by exception class** in `run_mission` |
| cancel (queued) | immediate `queued → cancelled` |
| cancel (running) | sets `cancel_requested=1` only; polled by `Executor.check()`. Takes **no lock**; three separate connections |
| complete | `waiting-review → completed` via `review --decision accept` |
| review | `finish_execution()` is the one place an event insert and a state update share a transaction |
| undo | `waiting-review/failed/cancelled/completed → undone`, gated on a checkpoint, no newer mission on the workspace, and `after-index.json` matching the live workspace |
| restart, QUEUED mission | picked up normally |
| restart, RUNNING mission | `recover()` rewrites the row to `failed`, attempt **not** incremented, receipt still NULL |

**The restart case has a real consequence, executed.** After a `kill -9` mid-encode,
a 524,336-byte partial artifact remained in the workspace and:

```
review --decision undo   -> "No final workspace index; inspect interrupted work
                             and use shadowfetch-checkpoint for manual recovery"
review --decision accept -> "Only successful missions awaiting review can be accepted"
```

**Mission Control cannot undo its own interrupted mission.** The user is sent to
a separate CLI by hand. `retry` does work and reuses the *original* checkpoint.

---

## 7. Polling, locks and idle cost — measured, not estimated

Four independent instruments (`/proc` deltas, `strace -f -c`, a real
`sqlite3` trace callback with wrapped `flock`, and `EXPLAIN QUERY PLAN`).

### Worker

`time.sleep(1)` at `sf_missions.py:1417` — fixed, unconditional, no backoff, no
inotify, no signal path. Measured inter-tick interval over 65 ticks: min
1.00005 s, median 1.001577 s, max 1.002849 s.

| | per tick | per minute |
|---|---|---|
| wake-ups (`clock_nanosleep`) | 1 | **60.0** |
| scheduler dispatches | — | 75.0 |
| SQLite connections opened+closed | 2 | **119.8** |
| SQL statements executed | 8 (4 PRAGMA + 4 SELECT) | **479.2** |
| `execution.lock` acquisitions | 1 | **59.9** |
| SQLite POSIX record locks | 54 | **3,240** |
| total traced syscalls | 125 | **7,500** |

**Idle CPU: 0.128 % of one core** (0.230 s per 180 s; two counters agree
within 3 %). **≈1.3 ms of CPU per tick.**

**The queries are not the problem — connection churn is.** `Store.db()` opens a
fresh connection per call, so SQLite creates `-wal` and `-shm`, extends the
`-shm` to 32 KiB with eight 1-byte writes, mmaps, checkpoints, unlinks both and
closes — **twice per second, forever**. That is 42 of the 54 record locks and all
16 `pwrite64`s per tick. An idle worker with an empty queue dirties
**65,536 B/s = 225 MiB/hour** of page cache (`write_bytes ==
cancelled_write_bytes` exactly, so this is churn that never reaches the device).

Both polling queries are **indexed, not table scans**:

```
SELECT COUNT(*) FROM missions WHERE state IN ('queued');
  `--SEARCH missions USING COVERING INDEX missions_queue (state=?)
SELECT * FROM missions WHERE state IN ('queued') ORDER BY created_at DESC,rowid DESC;
  |--SEARCH missions USING INDEX missions_queue (state=?)
  `--USE TEMP B-TREE FOR ORDER BY
```

Idle cost is **O(1) in queue size**: 0.128 % empty vs 0.142 % with 2,000 rows.

`Store.list()` passes `limit=None` → `LIMIT -1`, so every queued row is fetched
and JSON-deserialized each tick. At idle that is zero rows.

### Wake latency (insert → pickup), n = 12, phase-decorrelated

**min 0.0812 s, median 0.4470 s, mean 0.4434 s, max 0.9769 s** — exactly the
uniform [0, 1 s] a 1 Hz poll predicts. The `state='running'` write costs a
further 0.8 ms. Note `now()` uses `timespec="seconds"`, so **the schema itself
cannot resolve this latency**.

### GUI

`QTimer` at **3000 ms** (`missions_page.py:376-379`), refreshing only when
visible. Measured over 60 s with 12 missions and one selected:

```
  20/min  shadowfetch-missions --json list
  20/min  shadowfetch-missions --json show   <id>
  20/min  shadowfetch-missions --json events <id>
  20/min  shadowfetch-missions --json diff   <id>
  ------------------------------------------------
  80 subprocess spawns per minute
  Qt page CPU        0.150 % of a core
  reaped CLI children 7.220 % of a core
  combined            7.370 % of a core
```

The UI never touches the database — it shells out to the CLI for everything.

### Locks

One **global** `execution.lock` (`flock`), not per-workspace, which is why
`capabilities()` reports `max_parallel: 1`. `review()` waits up to 10 s;
`run_mission` and `retry` do not wait at all. `Store.cancel()` and
`Store.recover()` take no lock themselves.

---

## 8. Audit and event behavior today

`events(seq, mission, at, event, detail)`. Written by exactly three INSERTs
(`migrate()`, `Store.event()`, `finish_execution()`); read by `Store.events()`
and one QA script. **Nothing in the engine ever branches on an event row** — it
is a display timeline, not a control record.

* **Append-only in practice, not by construction.** `git grep "DELETE FROM|DROP TABLE|VACUUM"` has **no matches** tree-wide and there is no `UPDATE events`. But there is no trigger, no constraint, and nothing prevents either.
* **No hash chain.** `git grep prev_hash` → zero hits. No `seq`-continuity check, no `verify()`.
* **No journald mirror.** Nothing writes `SYSLOG_IDENTIFIER=shadowfetch-audit`; `python3-systemd` is not a dependency. `packages/shadowfetch-fireline/debian/changelog` nonetheless still advertises "journald audit" — a Step 25 item.
* **No correlation identity.** Firebreak mints its own `fb-<date>-<uuid8>` session id internally; Mission Control never sees it and cannot map either direction.
* **MCP calls are invisible.** `sf_mcp.py` contains no logging, audit or journal call at all. `checkpoint.undo` is a fully agent-facing MCP tool needing only a workspace name and an id that `checkpoint.list` hands over — destructive, ungated, unaudited, and unreachable from the `events` table.
* **Firebreak overwrites its only session record**, rewriting `<sid>.session` in place with `ended`/`exit` rather than appending a lifecycle row.
* Detail is redacted (`clean()` + env-secret substitution) and clipped to 10,000 chars.

---

## 9. What Phase 3 inherits

Every item below is a Phase 3 exit-criterion with a measured starting point.

| # | W | Gap | Baseline evidence |
|---|---|---|---|
| 1 | W-26 | 8 of 10 domain entities do not exist | §4 |
| 2 | W-27 | No state machine; any string persists | §5 |
| 3 | W-33 | No hash chain, no `verify()`, no journald | §8 |
| 4 | W-33 | No correlation identity anywhere | §8 |
| 5 | W-34 | No `ToolExecution`; provider events are text | §8 |
| 6 | W-35 | No `Approval`, no `PolicyEngine` | — |
| 7 | W-36 | 1 Hz worker + 3 s GUI poll = 80 spawns/min | §7 |
| 8 | W-36 | Global execution lock; `max_parallel: 1` | §7 |
| 9 | W-37 | Firebreak overwrites its session record | §8 |
| 10 | W-38 | Agent-facing destructive MCP, ungated, unaudited | §8 |
| 11 | — | Crash leaves a mission that cannot be undone | §6 |
| 12 | — | Cancellation does not reach the systemd scope | §6 |

W-30, W-31, W-32 remain **DEFERRED** from Phase 2 and are re-evaluated in Step 24.
