# Multi-agent safety

What actually happens when more than one agent runs, measured rather than read.

Measured on `release/4.0.0` at `9ca3a58`, on shadowfetch-linux (Pop!_OS, kernel
`7.1.5-76070105-generic`, 16 cores, Python 3.12.3, SQLite 3.45.1), 2026-09-09.
Every number below came from a command in this file, run against a throwaway
state root under `/tmp`. Nothing here was run against `~/.local/state`.

The working tree was being edited by other stages while these ran, so the
numbers are from the WORKING TREE at that moment, not from the commit alone.
Nothing measured here touches a file another stage was changing: the engine
edits landed in the receipt's enforcement note, and both defects below were
re-measured against the tree as it stood after them — 17 of 240 and 11 of 18,
against the 19 of 240 and 6 of 18 quoted from the full-suite run. Every rate in
this document is a rate, not a constant; re-run the probe rather than quoting
the number back.

`capabilities()` reports `max_parallel: 1`. That number is **true of one worker
process and false of the system**, and telling those apart is the whole reason
this document exists. The worker consumes its queue in a single-threaded loop
while holding `worker.lock` exclusively — but the CLI never takes that lock, the
lock lives under a state root that an environment variable selects, and the lock
hierarchy is deliberately built so two workspaces proceed at once. Two agents on
this machine are not an unsupported configuration; they are the default outcome
of running `shadowfetch-missions run` while the worker is up.

## Vocabulary

The same six words the engine reports with — from
`sf_providers.SANDBOX_ENFORCEMENT` and `sf_policy.POLICY_MEDIATION` — used here
with the same meanings, plus one distinction this document has to keep making:

| word | means |
| --- | --- |
| **enforced** | a layer outside this codebase prevents it — the kernel, systemd, nftables, a SQLite transaction, a POSIX file lock — **and** an adversarial probe in `tools/probes/stage_o_multi_agent.py` proves it. |
| **partial** | prevented in the measured cases, with a named case it does not cover. |
| **not_enforced** | not prevented. Said plainly. |
| **observed** | recorded when it happens, and nothing stops it. |
| **not_applicable** | the situation cannot arise here. |

And, separately from all of those, the distinction this stage exists to draw:

> **A single-threaded worker is not a control.** Every row below says which
> layer holds the property, and whether it would still hold with a second caller
> present. Where the answer is "only because the shipped worker runs one mission
> at a time", the row says so in those words.
>
> Measured answer, stated up front: **no property in this document depends on
> the worker being single-threaded.** Serialization is done by `flock` and by a
> SQLite compare-and-swap; separation of sandboxes, scopes and checkpoints is
> structural. What the single-threaded worker does provide is the *impression*
> that only one mission runs at a time, and §2 shows that impression is false
> the moment anyone types `shadowfetch-missions run`. Three genuine gaps were
> found, and none of them is closed by the worker's shape: the cross-state-root
> workspace lock (§1), the approval check/use window (§7), and the first-open
> race (§5).

## How to reproduce everything here

```
cd ~/projects/shadowfetch-4.0.0
python3 tools/probes/stage_o_multi_agent.py                 # all 23 probes
python3 tools/probes/stage_o_multi_agent.py O5 O4           # by prefix
cd packages/shadowfetch-missions/tests
python3 -m unittest test_multi_agent_safety -v              # 31 tests
```

The probe harness pins `PATH` to `/usr/local/sbin:/usr/local/bin:/usr/sbin:
/usr/bin:/sbin:/bin` and selects the source Firebreak and checkpoint engine
through the engine's own explicit override variables
(`SHADOWFETCH_FIREBREAK_TEST_BIN`, `SHADOWFETCH_CHECKPOINT_BIN`) rather than by
putting the build tree on `PATH`. `ffmpeg`, `systemctl` and `bwrap` are named by
absolute path. A build tree on `PATH` would let the environment choose which
binary answers a security question, which is the defect class this program
already closed once.

## At a glance

| # | Question | Answer | Layer | Status |
|---|---|---|---|---|
| 1 | Two workers, same state root | One consumes the queue; the other returns immediately | `flock(LOCK_EX\|LOCK_NB)` on `<state root>/worker.lock` | **enforced** |
| 2 | …and the loser reports it how? | Exit 0, empty stdout — identical to a worker that drained the queue | none | **observed** |
| 3 | Two workers, different state roots | Both run. Both may run on the same workspace | none | **not_enforced** |
| 4 | CLI `run` while a worker holds the workspace | Refused immediately, nothing changed | `execution.lock` shared + per-workspace exclusive `flock` | **enforced** |
| 5 | CLI `run` and a worker on different workspaces | Both execute simultaneously | none — this is the design | **not_applicable** (by intent) |
| 6 | The same mission started twice | Exactly one start | per-workspace `flock`, and under it `transition(expect=…)` inside `BEGIN IMMEDIATE` | **enforced** (two layers) |
| 7 | Firebreak sessions, systemd scopes | Disjoint per invocation | session id per invocation; `systemd-run --scope --unit=<sid>` | **enforced** |
| 8 | Checkpoints | Per-workspace namespace on disk, per-workspace lock | filesystem layout + `flock` | **enforced** |
| 9 | The audit chain | ONE chain, shared by every caller of a state root | — | by design; see §5 |
| 10 | Concurrent appends forking the chain | Never | `BEGIN IMMEDIATE` around read-head-then-append | **enforced** |
| 11 | Two processes opening a fresh database | Integrity holds; some callers crash | `BEGIN IMMEDIATE` on the genesis insert / **nothing** for the DDL | **partial** — see DEFECT 2 |
| 12 | One mission's approval used by another | Impossible | subject keying in `find_approval()` | **enforced** |
| 13 | A revoke racing the approval check | **Lands in the gap. 19 of 240 races ran on a withdrawn approval** | re-read under `BEGIN IMMEDIATE`, then released | **not_enforced** — see DEFECT 1 |
| 14 | A revoke after the mission starts | Recorded, stops nothing | none | **not_enforced**, by design; `cancel()` is the live stop |
| 15 | Cancellation of a running mission | Stops it in under a second | `Executor.check()` polled in the read loop + `kill_tree` + scope | **enforced** |
| 16 | Two credential identities in one worker process | Each invocation sees only its own | `bwrap --clearenv` + one `--setenv` per granted identity | **enforced** |
| 17 | One mission's undo reaching another workspace | Refused three different ways | recorded after-index, newer-mission guard, per-workspace checkpoint store | **enforced** |

Two probes fail on purpose. They are the two defects, and both are written up
below with an exact anchor and replacement under **BLOCKED**.

---

## 1. Two workers started simultaneously

### Which wins, and what the loser does

`worker()` opens `<state root>/worker.lock` and takes `flock(LOCK_EX|LOCK_NB)`.
The winner holds it for the entire loop; the loser gets `BlockingIOError` and
`return 0` immediately.

```
$ python3 tools/probes/stage_o_multi_agent.py O1-worker-lock-admits
```

> two REAL worker processes start on one state root at the same instant with one
> queued mission
>
> ```
> worker records: [{"entered_at": 1788981707.3080869, "left_at": 1788981707.3083756,
>                   "outcome": "returned", "pid": 2360142, "rc": 0},
>                  {"entered_at": 1788981707.3080826, "left_at": 1788981710.2036016,
>                   "outcome": "returned", "pid": 2360143, "rc": 0}]
> held for (seconds, sorted): [0.0, 2.896]
> mission state waiting-review, attempt 1
> 'running' events: 1   agent sessions: 3
> ```

**enforced.** One `running` event, attempt 1, one set of agent sessions. There
is no window in which both consumed the mission: the loser never reached the
queue read at all — it returned in 0.0003 s.

### The loser is silent, and that is a reporting defect

```
$ python3 tools/probes/stage_o_multi_agent.py O1-the-losing-worker
```

> ```
> $ shadowfetch-missions --json worker --once   (rc=0)
> stdout: ''
> stderr: ''
> still queued afterwards: ['mission-6e5e8c9353404181']
> ```

**observed, not a control.** The safety property holds — the queue is untouched.
The reporting does not: exit 0 with empty stdout is exactly what a worker that
drained its queue returns. A systemd unit, a supervisor or an operator cannot
tell "idle" from "another worker owns this state root". Pinned by
`WorkerAdmission.test_a_refused_worker_is_indistinguishable_from_an_idle_one`,
which asserts the two exit codes are equal precisely so that giving the refusal
its own status makes the test go red.

### The lock's actual scope: one state root

```
$ python3 tools/probes/stage_o_multi_agent.py O1-worker-lock-is-scoped
```

> ```
> first  worker.lock: /tmp/sf-stage-o-atbm2a76/state/worker.lock  (held)
> second worker.lock: /tmp/sf-stage-o-atbm2a76/state-b/worker.lock
> second acquisition: ACQUIRED
> ```

**not_enforced beyond one state root.** `SHADOWFETCH_MISSIONS_STATE` selects the
lock file. Two agents that do not share it are not serialized by `worker.lock`
in any way.

### And that reaches the workspace

`Store.lock_path()` puts `execution-<sha256 prefix>.lock` inside the **state**
root, while the workspace it names lives under the **workspace** root. Two
callers differing only in `SHADOWFETCH_MISSIONS_STATE` therefore take two
different files for one directory.

```
$ python3 tools/probes/stage_o_multi_agent.py O1-two-state-roots
```

> ```
> [{"entered_at": 1788981711.7689335, "left_at": 1788981712.4690025,
>   "state_root": "/tmp/sf-stage-o-atbm2a76/state",
>   "workspace": "/tmp/sf-stage-o-atbm2a76/ws/w4"},
>  {"entered_at": 1788981711.7689729, "left_at": 1788981712.4694060,
>   "state_root": "/tmp/sf-stage-o-atbm2a76/state-c",
>   "workspace": "/tmp/sf-stage-o-atbm2a76/ws/w4"}]
> overlap = 0.700030s
> ```

**not_enforced.** 0.700030 s of genuine overlap on one workspace by two real
processes. What still holds underneath it:

* the checkpoint engine serializes snapshot and undo per workspace on its own
  `flock` (`<workspace root>/.sf-checkpoints/<name>/.sfh/lock`, §4);
* `review(…, "undo")` refuses a workspace whose recovery index moved (§6).

What does **not** hold: the agents' own writes into the workspace are serialized
by nothing at all, so the "one writer per Undo boundary" property that the
per-workspace lock exists to give is simply absent across state roots. This is a
**gap, not an accident**: the lock is doing exactly what its file path says it
does. Closing it means putting the lock beside the thing it protects.

---

## 2. A CLI `run` and a worker

### On the same mission, and on the same workspace: refused

Both entry points reach `run_mission()`, which takes
`store.lock(workspace=…, wait_seconds=0)`.

```
$ python3 tools/probes/stage_o_multi_agent.py O2-cli-run-is-refused
```

> ```
> $ shadowfetch-missions --json run mission-c3fde181fffc48f5   (rc=1)
> stdout: {"error": "Another mission is executing on /tmp/…/ws/w5; this task remains queued"}
> identical: True
> ```

**enforced, and inert.** Mission row, event list, session count and audit head
are byte-identical before and after.

Two callers racing the *same* mission:

```
$ python3 tools/probes/stage_o_multi_agent.py O2-the-same-mission
```

> ```
> pid 2369896  outcome ran      state waiting-review
> pid 2369897  outcome refused  MissionError: Another mission is executing on …/ws/w7
> attempt 1, state waiting-review, 'running' events 1
> ```

**enforced, twice over.** Either layer alone would refuse it, and the second one
is the one that matters when the first is absent — see the next section.

### The layer under the lock

`transition(mid, running, expect=queued)` reads and writes the row inside one
`BEGIN IMMEDIATE` transaction: a compare-and-swap at the SQLite level, which
holds between callers that share **no lock file at all**.

```
$ python3 tools/probes/stage_o_multi_agent.py O2-the-state-transition
```

> ```
> outcomes: ['refused', 'won', 'refused', 'refused', 'refused', 'refused', 'refused', 'refused']
> winners: 1   refusals: ['TransitionError: This mission is running, not queued; it changed while you were looking at']
> 'running' events: 1   final state: running
> chain ok=True events=112 head_seq=112
> ```

**enforced.** Eight processes, no execution lock between them, one winner. This
is the property that keeps the cross-state-root gap in §1 from being a
double-execution bug: two agents can both write a workspace, but they cannot
both start the same mission.

### On different workspaces: they genuinely run at once

```
$ python3 tools/probes/stage_o_multi_agent.py O2-cli-and-worker
```

> ```
> mission mission-015a6b962fbf sandbox windows:
>   [(1788996785.043020, 1788996785.143267),
>    (1788996785.221489, 1788996790.603443),
>    (1788996790.683939, 1788996791.278650)]
> mission mission-08094584e313 sandbox windows:
>   [(1788996785.209031, 1788996785.320357),
>    (1788996785.403304, 1788996792.705471),
>    (1788996792.780050, 1788996793.409993)]
> largest overlap = 5.200139s between sess-9e400ff4017447d4 and sess-315bf648e3194d6b
> samples in which systemd held scopes belonging to BOTH missions: 106 of 193 (50 ms apart);
>   first such sample: ['sess-57e4c8b7a7224c0e.scope', 'sess-9e400ff4017447d4.scope']
> distinct scope units recorded by the two missions: 6
> final states: both waiting-review
> ```

Two witnesses agree: Firebreak's own microsecond session records show 5.200139 s
of overlap, and systemd itself listed scopes belonging to both missions in 106
consecutive samples.

**`max_parallel: 1` is a property of the worker, not of the installation.** The
CLI never takes `worker.lock`. The real concurrency ceiling is the number of
callers. Two consequences that are not obvious from the number:

* Each concurrent sandbox gets its **own** `systemd-run --scope` with its own
  `MemoryMax` and `TasksMax`. The receipt's `limits.sandbox_rss_mb: 3072` is a
  per-session budget; two callers is 6 GiB of ceiling, not 3.
* `limits.queue_concurrency: 1` in the receipt describes the queue this worker
  drained, not how many missions were executing on the box while it did so.

---

## 3. Two missions in different workspaces, run by two callers

```
$ python3 tools/probes/stage_o_multi_agent.py O3-concurrent-missions
```

> ```
> largest sandbox overlap = 0.671540s between sess-6a2e5311b6dd4589 and sess-ddc08ef2164f4c80
> firebreak sessions: 6   distinct scope units: 6
> workspace per mission: {"mission-55ee75201ace44fa": "…/ws/w9b",
>                         "mission-bcd22a28559f416d": "…/ws/w9a"}
> agent_sessions rows: {'mission-bcd22a28559f416d': 3, 'mission-55ee75201ace44fa': 3}
> sessions attributed to the wrong workspace: []
> ```

**enforced, and structurally so.** The session id is minted per invocation, the
systemd scope is named after it, and the bind mount is the mission's own
workspace. None of that depends on there being one consumer — this is a control,
not an accident.

---

## 4. Checkpoints

```
$ python3 tools/probes/stage_o_multi_agent.py O3-checkpoint-stores
```

> ```
> checkpoint ids: {"mission-d5a40380d67047f0": "20260909-152602-065474",
>                  "mission-f59a41d554d344b8": "20260909-152602-590651"}
> stores under …/ws/.sf-checkpoints: {"w9a": ["20260909-152602-590651.json"],
>                                     "w9b": ["20260909-152602-065474.json"]}
> checkpoint_call('diff', workspace='w9b', checkpoint='20260909-152602-590651')
>   -> _ToolError: no such checkpoint: 20260909-152602-590651
> per-workspace checkpoint locks: ['…/.sf-checkpoints/w9a/.sfh/lock',
>                                  '…/.sf-checkpoints/w9b/.sfh/lock']
> ```

**enforced by the filesystem.** `_ckpt_store()` is
`<workspace root>/.sf-checkpoints/<workspace name>/`, so a recovery id is only
meaningful inside the workspace that produced it — it is not merely refused, it
is not addressable. The `_CkptLock` beside it is per workspace, which is why a
snapshot and an undo on one workspace still serialize **even when the callers
share no Mission Control state root**. That is the one part of §1's gap the
checkpoint engine covers on its own.

---

## 5. The audit chain under concurrency

### It is shared, not separated — deliberately

```
$ python3 tools/probes/stage_o_multi_agent.py O3-the-audit-chain
```

> ```
> total events 56; rows belonging to the pair 54
> mission changes from one row to the next within the pair: 20
> first twelve interleaved rows:
>   [(3,'d344b8','queued'), (4,'7047f0','queued'), (5,'d344b8','running'),
>    (6,'7047f0','running'), (7,'d344b8','task-created'), (8,'7047f0','task-created'),
>    (9,'d344b8','task-started'), (10,'7047f0','task-started'),
>    (11,'7047f0','checkpoint-started'), (12,'d344b8','checkpoint-started'), …]
> genesis rows: 1   contiguous seq: True
> verify_chain: ok=True events=56 chained=56 unchained=0 head_seq=56
> ```

One chain, one genesis, contiguous sequence numbers, twenty interleavings
between two concurrently executing missions. The cost of the design is stated
plainly: every concurrent caller contends for the same write lock, and a chain
broken by any caller is broken for all of them. The benefit is that a per-mission
chain could be truncated one mission at a time.

### Racing appends cannot fork it

A fork is two rows claiming one predecessor. Counted on the rows, not read off
`verify()`'s verdict:

```
$ python3 tools/probes/stage_o_multi_agent.py O4-racing-appends
```

> ```
> writers reported appended: 200 of 200
> total rows 203; contiguous seq 1..203: True
> duplicate prev_hash values (a fork): 0
> verify_chain: ok=True chained=203 unchained=0 head_seq=203
> wall time for 200 contended appends: 0.245s (1.23 ms/append)
> ```

**enforced by `BEGIN IMMEDIATE`.** `append_event()` takes the write lock before
it reads the head, so "read the head, hash against it, insert" is one atomic step
against every other connection.

### …and `verify()` would notice one

The zero above only means something if a fork is detectable, so one is injected:

```
$ python3 tools/probes/stage_o_multi_agent.py O4-an-injected-fork
```

> ```
> before the injection: ok=True events=7 head_seq=7
> injected seq 8 with prev_hash of seq 5
> after: ok=False events=8 head_seq=8
> problems: ['seq 8: prev_hash does not match the previous row (a row was inserted,
>             removed or reordered here)',
>            'the database holds 1 event(s) after seq 7, which the journal still does
>             not have 1.0s later. …']
> audit_exit_code -> 1
> ```

**enforced.** The chain check and the external anchor both fire, and the exit
code moves off 0.

### Two processes opening a fresh database

`Store.__init__` creates the schema, migrates it and writes the chain genesis
**before any caller holds `worker.lock` or `execution.lock`**. It is the one
window in which two workers genuinely have no lock between them.

```
$ python3 tools/probes/stage_o_multi_agent.py O4-two-processes
```

> ```
> outcomes: ['opened', 'opened', 'raised', 'raised', 'raised', 'raised']
> errors: ['OperationalError: database is locked',
>          'OperationalError: duplicate column name: provider_id']
> (repeat runs also produce 'IntegrityError: UNIQUE constraint failed: events.seq')
> genesis rows: 1 at seq [1]
> chain ids in the database: ['b8909df6afa5494bb710ba4f17e942d7']
> chain ids the processes reported: ['b8909df6afa5494bb710ba4f17e942d7']
> PRAGMA user_version = 5 (current 5)
> verify_chain: ok=True events=2 problems=[]
> ```

**partial.** The integrity half holds and it is the half that matters most: a
second genesis would give the database two chain ids, `chain_id()` takes the
first, and every event mirrored to journald under the other one would be
unfindable for the life of the installation. That does not happen — the genesis
`INSERT` serializes it.

The availability half does not hold. See DEFECT 2.

---

## 6. Undo cannot be redirected onto another workspace

`Store.update()` refuses the `workspace` field outright, so reaching this needs
database access. Given that, three separate things are in the way, and a single
attempt only ever measures the first:

```
$ python3 tools/probes/stage_o_multi_agent.py O3-undo-cannot
```

> ```
> older onto a written workspace:
>     refused: MissionError: A newer mission has changed this workspace. Undo newer missions first
>     target unchanged: True
> newest onto a different workspace:
>     refused: MissionError: Workspace changed after this mission. Preserve your newer edits,
>              then use shadowfetch-checkpoint for deliberate manual recovery
>     target unchanged: True
> onto a byte-identical clone:
>     refused: MissionError: Workspace undo failed: no such checkpoint: 20260909-152502-187151
>     target unchanged: True
> the clone's recovery index equals the mission's recorded after-index: True
> audit verify after three tampers: ok=True problems=[]
> ```

**enforced.** The third case is the one that matters: the clone was built
specifically so the recorded `after-index.json` comparison would pass, and what
refused it was the checkpoint engine's own namespace.

**What is NOT enforced:** `audit verify` reports the log intact after all three
tampers. The chained `queued` event records the workspace the mission was
created for —

> `media_export via offline-media; scope=/tmp/…/ws/w11a; network=none`

— and nothing ever compares it with the mutable `missions.workspace` column. A
redirected mission is refused at the point of use and is **not detected as
tampering**. That is a smaller gap than it sounds (the redirect achieves
nothing) but it belongs in `docs/TRUST_BOUNDARIES.md` as UNDETECTABLE.

Related, and enforced: a workspace cannot be spelled two ways into two lock
files. `workspace()` refuses a symlink and anything that is not a direct child of
the workspace root, and `lock_path()` hashes the resolved path:

> ```
> "symlink alias":     refused: MissionError: A workspace cannot be a symbolic link
> "nested directory":  refused: MissionError: Choose an existing direct folder inside …/ws
> lock_path() over 4 spellings -> ['…/state/execution-b92bfa37b0244fc60224184ad99efdb1.lock']
> ```

Two locks for one directory cannot be reached by naming. Only by using two state
roots (§1).

---

## 7. Approvals under concurrency

### One mission's approval cannot be used by another

```
$ python3 tools/probes/stage_o_multi_agent.py O5-an-approval-is-not
```

> ```
> the two decisions have identical scopes: True
>   scope: {"capability": "sourced_report", "credential_ids": ["CODEX_API_KEY"],
>           "egress_hosts": ["api.openai.com","chatgpt.com","auth.openai.com"],
>           "network": "allowlist", "paths": [], "provider": "codex",
>           "workspace": "/tmp/…/ws/w13"}
> require_approval(second) -> refused: ApprovalRequired: … no approval exists for
>   mission:mission-4ad1e5a8b4f54165
> second mission events: ['queued', 'approval-required']
> ```

**enforced.** `find_approval()` selects by subject `mission:<id>` before it ever
compares a scope, so two callers cannot share one human decision even when the
decisions are byte-identical.

### A revoke DOES land between the check and the use

This is the finding of the stage. `require_approval()` re-reads `revoked_at`
under `BEGIN IMMEDIATE` — the same write lock `revoke_approval()` takes — and its
comment says:

> "a revoke either lands before the mission starts or after it — never in the
> window between the check and the start, which produced a log reading granted,
> revoked, used, in that order."

That is false. The re-read takes the write lock and **releases it**; the
`approval-used` append and the `approval_id` update then happen on two further
connections.

```
$ python3 tools/probes/stage_o_multi_agent.py O5-a-revoke
```

> 240 REAL races between the full `run_mission()` and a separate PROCESS revoking
> the approval, offset swept in 50 µs steps across 6.0 ms
>
> ```
> trials that used the approval: 100; held for approval: 140
> INVERTED (an approval consumed after its own revocation was chained): 19 of 240
> of those, missions that actually STARTED on the withdrawn approval: 19
>   {"approval_id":"appr-1f8f7b06c8c54c81","delay_ms":2.0,"revoked_seq":653,
>    "run":"ran","state":"failed","trial":40,"used_seq":654}
>   {"approval_id":"appr-07f9eb3770da474e","delay_ms":2.35,"revoked_seq":691,
>    "run":"ran","state":"failed","trial":47,"used_seq":692}
>   {"approval_id":"appr-dc1b942d10194c43","delay_ms":2.6,"revoked_seq":741,
>    "run":"ran","state":"failed","trial":52,"used_seq":742}
> verify_chain: ok=True problems=[]
> ```

**not_enforced.** 19 of 240 — 7.9 % of races at this sweep; repeat runs gave 25
of 240 and, against `require_approval()` alone, 20 of 300 and 16 of 200. It is
not a logging-order quibble: every inverted trial transitioned to `running`,
took a workspace checkpoint and began work on a decision that had already been
withdrawn and chained.

The sweep resolution is load-bearing. The first version of this probe spread 24
revokes across the ~500 ms the whole mission takes, found nothing, and would have
reported the invariant as holding. The window is microseconds wide and sits a few
milliseconds into the call.

Fix, anchor and verification: **DEFECT 1** below.

### Revocation is not a kill switch; cancellation is

```
$ python3 tools/probes/stage_o_multi_agent.py O5-revocation
```

> ```
> escalating mission events: ['queued','approval-granted','approval-used','running',
>   'task-created','task-started','checkpoint-started','checkpoint-created',
>   'task-succeeded','task-created','task-started','task-failed','failed']
> 'approval-used' appears 1 time(s), before 'running': True
> revoked after the run; the mission's events gained: ['approval-revoked']
> --- cancellation ---
> reached running with a live session: True
> cancel() -> the runner returned 0.480s later
> final state: cancelled
> ```

**not_enforced (revocation), enforced (cancellation).** The approval is read
exactly once, before the state moves, and nothing reads it again. The withdrawal
*is* written to the mission's own event list, so the log reads granted, used,
ran, revoked and a reader can see the order — but no mechanism acts on it.

What does act is `cancel()`: the flag is read by `Executor.check()` between steps
**and every 200 ms inside the process read loop**, and `kill_tree` plus the
`--collect` systemd scope take the process tree down. Measured at 0.480 s from
`cancel()` to the runner returning. A person who wants a running mission stopped
has to use that.

---

## 8. The credential environment

Two identities live in one worker process at once —
`load_provider_credentials()` reads the whole credential directory into
`os.environ`. **The separation is per invocation, not per process.**

```
$ python3 tools/probes/stage_o_multi_agent.py O6
```

> ```
> both identities set in the orchestrator process: ['ANTHROPIC_API_KEY','CODEX_API_KEY']
> credentials_for():
>   claude: declared ['ANTHROPIC_API_KEY'], resolved ['ANTHROPIC_API_KEY'], values correct
>   codex:  declared ['CODEX_API_KEY'],     resolved ['CODEX_API_KEY'],     values correct
> what each sandbox could see (two Firebreak runs, one identity each):
>   ANTHROPIC_API_KEY -> visible: ['ANTHROPIC_API_KEY']   rc 0
>   CODEX_API_KEY     -> visible: ['CODEX_API_KEY']       rc 0
> ```

**enforced by `bwrap --clearenv` plus one `--setenv` per granted identity**, in
the sandbox's own mount and process namespace. The sandbox does not inherit the
orchestrator's environment and then have things removed from it; it starts with
nothing. Three gates stack:

1. `Executor.credentials_for()` resolves only what the provider's manifest
   declares;
2. `run_process()` intersects those names with the invocation's
   `spec.credential_ids`, so an adapter that narrowed them is honoured;
3. Firebreak refuses any `--credential-env` name outside its own `CREDENTIALS`
   set, and `--clearenv` means an un-granted variable never arrives at all.

> ```
> $ shadowfetch-firebreak run --credential-env STAGE_O_SECRET   (rc=1)
> stderr: Firebreak: Credential grant must name a supported provider environment variable
> $ shadowfetch-firebreak run -- python3 -c "'STAGE_O_SECRET' in os.environ"   (rc=0)
> the sandbox saw it: False
> ```

Residual, stated plainly: any code running **in the worker process itself** —
not in a sandbox — sees every configured identity. Provider adapter code does
not run there; the orchestrator does.

---

## Defects found by this stage

### DEFECT 1 — a revoked approval can still start a mission

**Severity:** a human's withdrawal of consent is silently ineffective in a
measurable fraction of races, and the code comment asserts the opposite.

**Measured:** 19 of 240 (`tools/probes/stage_o_multi_agent.py O5-a-revoke`, the
full-suite run of 2026-09-09), 25 of 240 on a repeat, and 20 of 300 / 16 of 200
against `require_approval()` alone. Every inverted trial started the mission.

**Cause:** `require_approval()` re-reads `revoked_at` inside a `BEGIN IMMEDIATE`
transaction and then closes it. `store.event("approval-used", …)` and
`store.update(approval_id=…)` follow on two further connections. A revoke that
commits in that gap is chained *before* the use.

**Fix verified in an isolated copy** (`packages/shadowfetch-missions/data` copied
to a scratch tree, patched there, raced 300 times against the unpatched
original):

```
--- ORIGINAL --- inverted: 20 of 300   chain_ok true  chain_events 1202
--- PATCHED  --- inverted:  0 of 300   chain_ok true  chain_events 1202
```

The exact anchor and replacement are under **BLOCKED** below. `test_multi_agent_
safety.ApprovalsUnderConcurrency.test_a_revoke_racing_the_check_never_produces_
used_after_revoked` is **red on arrival** and goes green deterministically once
the replacement is applied. Do not relax it.

### DEFECT 2 — a caller that loses the first-open race gets a traceback

**Severity:** availability and diagnosability, not integrity. Two systemd workers
restarted together land here; so does a desktop client started next to a worker
on a machine whose mission database does not exist yet.

**Measured:**

```
$ python3 tools/probes/stage_o_multi_agent.py O4-a-caller
18 concurrent `shadowfetch-missions --json list` invocations over 3 fresh state roots
produced parseable JSON on stdout: 12 of 18
produced an empty stdout and a traceback: 6
the last line of stderr in each failure:
  ['sqlite3.OperationalError: database is locked',
   'sqlite3.OperationalError: duplicate column name: provider_id']
```

and, at the module level, 16 of 48 concurrent `Store()` constructions raising
(8 trials of 6), with three distinct causes:

* `sqlite3.OperationalError: database is locked` from
  `sf_missions.py` `Store.db()` at `db.execute("PRAGMA journal_mode=WAL")` —
  it is the **first** statement, before `busy_timeout` is set, and SQLite does
  not invoke the busy handler for a journal-mode conversion;
* `sqlite3.OperationalError: duplicate column name: provider_id` (also
  `capability`, `actor`, `hash`, `prev_hash`) from `Store.migrate()` — Python's
  `sqlite3` does not auto-begin a transaction for DDL, so two openers both see a
  column missing and both `ALTER TABLE`;
* `sqlite3.IntegrityError: UNIQUE constraint failed: events.seq` — two openers
  both computing seq for the chain genesis. The primary key is what stops the
  second one, which is why the integrity half of this still holds.

**And the CLI cannot report either.** `main()` catches
`(MissionError, ValueError, OSError)`. `sqlite3.Error` is none of those, so it
escapes as a traceback on stderr with **empty stdout** — and Mission Control's
desktop client parses stdout as JSON. Pinned deterministically by
`FirstOpenRace.test_the_cli_error_handler_does_not_cover_that_exception`.

Integrity is unaffected: one genesis, one chain id, correct `user_version`,
`verify_chain()` ok on every one of the 8 trials, patched and unpatched alike.

**Fix verified in an isolated copy** (BLOCKED 2 + 3A + 3B applied to a scratch
copy of the package, then the same races run against it and against the
unpatched original):

```
--- ORIGINAL ---  module: 16 raising callers across 8 trials x 6 = 48 opens
                  CLI: 12 of 18 produced JSON on stdout; 6 did not
                  integrity: genesis=[1] user_version=[5] chain_ok=[True]
--- PATCHED  ---  module: 0 raising callers across 8 trials x 6 = 48 opens
                  CLI: 18 of 18 produced JSON on stdout; 0 did not
                  integrity: genesis=[1] user_version=[5] chain_ok=[True]
```

---

## BLOCKED — changes for the lead

All three are in `packages/shadowfetch-missions/data/usr/lib/shadowfetch/missions/sf_missions.py`,
which is outside this stage's territory. Anchors were taken from `9ca3a58` and
each matches exactly once.

### BLOCKED 1 — close the approval check/use window (DEFECT 1)

Verified: 20/300 inversions before, 0/300 after, chain intact both ways.

**Anchor** (in `require_approval()`):

```python
    row, why = store.find_approval(subject, decision.scope)
    if row is not None:
        # Re-read under the write lock the revoke path also takes. Without this
        # the approval was consulted once and a revocation arriving a moment
        # later was simply missed -- the mission ran on a withdrawn decision.
        with store.db() as db:
            db.execute("BEGIN IMMEDIATE")
            fresh = db.execute(
                "SELECT revoked_at, expires_at FROM approvals WHERE id=?",
                (row["id"],)).fetchone()
        if fresh is None or fresh["revoked_at"]:
            row, why = None, (
                f"{row['id']} was revoked at "
                f"{fresh['revoked_at'] if fresh else 'an unknown time'} while this "
                "mission was starting")
    if row is None:
        store.event(mission["id"], "approval-required", "; ".join(decision.reasons),
                    actor=ACTOR_ORCHESTRATOR)
        raise ApprovalRequired(
            "This mission needs approval before it can run: "
            + "; ".join(decision.reasons) + ". " + (why or ""),
            decision=decision, subject=subject)
    store.event(mission["id"], "approval-used", f"{row['id']} granted by "
                f"{row['granted_by']} via {row['method']}",
                actor=ACTOR_ORCHESTRATOR)
    store.update(mission["id"], approval_id=row["id"])
    return row["id"]
```

**Replacement:**

```python
    row, why = store.find_approval(subject, decision.scope)
    used = None
    if row is not None:
        # ONE transaction for the re-read, the record of use, and the mission's
        # approval_id. Re-reading under BEGIN IMMEDIATE was not enough on its
        # own: it took the write lock revoke_approval() takes and then RELEASED
        # it, and "approval-used" was appended afterwards on a second
        # connection. A revoke landing in that gap was chained BEFORE the use,
        # this function still returned the approval id, and run_mission() went
        # on to move the mission to running and execute it -- which is exactly
        # the "granted, revoked, used" log the re-read was added to prevent.
        # Measured at 25 of 240 races against a separate revoking process, with
        # the offset swept in 50us steps; all 25 of those missions started.
        # Holding the lock across all three makes a revoke land wholly before
        # this (and be seen) or wholly after it (and be honestly ordered after
        # the use, which is the residual: there is no re-check once a mission is
        # running, and cancel() is the only live stop).
        with store.db() as db:
            db.execute("BEGIN IMMEDIATE")
            fresh = db.execute(
                "SELECT revoked_at, expires_at FROM approvals WHERE id=?",
                (row["id"],)).fetchone()
            if fresh is None or fresh["revoked_at"]:
                row, why = None, (
                    f"{row['id']} was revoked at "
                    f"{fresh['revoked_at'] if fresh else 'an unknown time'} while this "
                    "mission was starting")
            else:
                used = store._append(
                    db, mission=mission["id"], event="approval-used",
                    actor=ACTOR_ORCHESTRATOR,
                    detail=f"{row['id']} granted by {row['granted_by']} "
                           f"via {row['method']}")
                db.execute(
                    "UPDATE missions SET approval_id=?,updated_at=? WHERE id=?",
                    (row["id"], now(), mission["id"]))
    if row is None:
        store.event(mission["id"], "approval-required", "; ".join(decision.reasons),
                    actor=ACTOR_ORCHESTRATOR)
        raise ApprovalRequired(
            "This mission needs approval before it can run: "
            + "; ".join(decision.reasons) + ". " + (why or ""),
            decision=decision, subject=subject)
    # AFTER the commit, like every other mirrored append: anchoring a row that a
    # rollback could still remove would record an event that never happened.
    store.mirror(used)
    return row["id"]
```

### BLOCKED 2 — make `journal_mode=WAL` survive a concurrent first open (DEFECT 2)

**Anchor** (`Store.db()`):

```python
    @contextlib.contextmanager
    def db(self):
        db = sqlite3.connect(self.db_path, timeout=30)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA busy_timeout=30000")
        try:
            with db:
                yield db
        finally:
            db.close()
```

**Replacement:**

```python
    @contextlib.contextmanager
    def db(self):
        db = sqlite3.connect(self.db_path, timeout=30)
        db.row_factory = sqlite3.Row
        # busy_timeout FIRST. journal_mode=WAL was the opening statement, and
        # converting a rollback-journal database to WAL needs a moment's
        # exclusive access that SQLite does NOT run the busy handler for -- so a
        # second process opening the same new database got SQLITE_BUSY
        # immediately. Measured at 4 of 6 simultaneous first opens, and 4 of 18
        # CLI invocations, which main() cannot even report because
        # sqlite3.Error is not a MissionError, a ValueError or an OSError.
        # Retrying is correct: the mode is a property of the FILE, so whoever
        # wins sets it once and every later opener inherits it.
        db.execute("PRAGMA busy_timeout=30000")
        deadline = time.monotonic() + 30
        while True:
            try:
                db.execute("PRAGMA journal_mode=WAL")
                break
            except sqlite3.OperationalError:
                if time.monotonic() >= deadline:
                    db.close()
                    raise MissionError(
                        "The mission database is busy while another Mission "
                        "Control process is opening it; try again shortly")
                time.sleep(0.02)
        try:
            with db:
                yield db
        finally:
            db.close()
```

### BLOCKED 3 — make the migration atomic, and let the CLI report a busy database

Two one-line changes that close the `duplicate column name` half of DEFECT 2 and
stop any remaining SQLite error escaping as a traceback.

**Anchor A** (`Store.__init__`, the end of the schema bootstrap):

```python
            """)
            self.migrate(db)
```

**Replacement A:**

```python
            """)
            # BEGIN IMMEDIATE around the WHOLE migration. migrate()'s own
            # docstring says it "runs inside the caller's transaction" -- and
            # no caller opened one, so its ALTER TABLEs ran in autocommit
            # (Python's sqlite3 auto-begins for DML, never for DDL). Two
            # processes opening one new database therefore both saw a column
            # missing and both added it: 'duplicate column name: provider_id',
            # measured at 4 of 6 simultaneous first opens. With the write lock
            # held, the loser waits, then re-reads user_version and returns.
            db.execute("BEGIN IMMEDIATE")
            self.migrate(db)
```

**Anchor B** (the CLI's error handler, one line):

```python
    except (MissionError, ValueError, OSError) as exc:
```

**Replacement B:**

```python
    # sqlite3.Error included. It is not a MissionError, a ValueError or an
    # OSError, so a busy or locked database escaped this handler entirely:
    # empty stdout, a traceback on stderr, and a desktop client that parses
    # stdout as JSON handed nothing at all.
    except (MissionError, ValueError, OSError, sqlite3.Error) as exc:
```

### BLOCKED 4 — the two honesty items, for whoever owns the surfaces

Neither is a code change this stage can specify safely, so they are recorded
rather than patched:

1. **`capabilities()["max_parallel"]`** is read by the Control Center as though
   it described the installation. It describes one worker process. Either the
   key should carry that scope, or the surfaces that render it should say
   "per worker". Measured: 5.200139 s of overlapping sandbox time between a
   worker and a CLI run, with systemd holding both scopes in 106 consecutive
   samples.
2. **A refused worker exits 0 in silence.** Giving it a distinct exit status or
   a one-line stderr message would make "another worker owns this state root"
   visible to a supervisor. `WorkerAdmission.test_a_refused_worker_is_
   indistinguishable_from_an_idle_one` will go red when that lands, which is the
   intended signal to update it.

---

## What Stage O did not settle

* **The cross-state-root gap (§1) is not closed, only measured.** Moving
  `execution-<digest>.lock` beside the workspace it protects would close it, and
  would need the workspace root to be writable by every caller that may run a
  mission there. That is a design decision, not a patch.
* **There is no re-check of an approval once a mission is running**, and there is
  no design here that would add one without also deciding what "stop" means for a
  half-written workspace. `cancel()` is the answer today and it works; that this
  document can say so is the result of measuring it, not of assuming it.
* **`audit verify` does not compare `missions.workspace` with the workspace the
  chained `queued` event names** (§6). The redirect achieves nothing, so this is
  a detection gap rather than an exploit, but it is a real UNDETECTABLE row.
* **Nothing here tested more than two concurrent callers on one workspace.**
  Every overlap measurement in this document is a pair.
