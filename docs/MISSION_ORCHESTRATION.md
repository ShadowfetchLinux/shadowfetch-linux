# Mission orchestration

The domain model Phase 3 added between "a person asked for something" and "a process
ran", and the path a mission actually takes through it.

**Version.** Brought forward to **Phase 3.1** on the `release/4.0.0` branch. It was first
written against `7978259` ("Phase 3 Steps 19, 20, 21, 23, 24, 25") plus the Step 18 work
(`tool_executions`, `stream_events`, receipt schema 2, the `records` and `watch` verbs).
Everything described here lives in
`packages/shadowfetch-missions/data/usr/lib/shadowfetch/missions/sf_missions.py`.

The persisted schema is **v4**. `docs/MISSION_SCHEMA.md` describes it at **v2** and has not
been brought forward; the v3 tables are described in §2 here and in `DOMAIN_SCHEMA`, and v4
adds no table at all — it adds one chained event, `legacy-missions-pinned`, which
`docs/AUDIT_EVENTS.md` §8 documents.

What Phase 3.1 changed in this document: `Store.create()` is atomic (§3), the retry budget
belongs to the edge rather than to a verb (§3), the mission rows are replayed against the log
(§3), and `cancel-requested` records the person who produced it (§3, §11). Superseded
behaviour is kept only under **Historical note** headings.

Every command output below was run on the build host against a throwaway store
(`SHADOWFETCH_MISSIONS_STATE` and `SHADOWFETCH_AGENT_WORKSPACES` pointed at a
`mktemp -d`), with the source-tree Firebreak first on `PATH`. Nothing is paraphrased.

---

## 1. What this is not

- It is **not a scheduler.** `max_parallel` is 1. Tasks carry a `depends_on` column so a
  DAG stays expressible, and nothing reads it. There is no queue fan-out, no priority, no
  work stealing.
- It is **not a resumption engine.** No provider here supports resuming a turn, and
  reconciliation deliberately does not try (§8).
- It is **not an enforcement layer.** Policy decides, Firebreak enforces, and the session
  record says per field which is which. A field in `declared_but_not_enforced` reached no
  mechanism — **as of 4.1.0 that array is empty**, because every declarable field now
  reaches one. The key is still emitted: an absent key and an empty one are different
  claims, and only one of them is checkable. What remains are residuals on enforced
  fields, not unenforced fields. See `docs/AGENT_ARCHITECTURE.md` and
  `sf_policy.POLICY_MEDIATION` for the matrix.

---

## 2. The domain model

Nine record types. Missions, events and steps existed at 4.0.0; the rest are v3.

| Entity | Table | Created by | Read by |
|---|---|---|---|
| **Mission** | `missions` | `Store.create()` — the thing a person asked for | CLI `list`/`show`, desktop, `review()` |
| **Task** | `tasks` | `Store.create_task()` via `Executor.task()` — one step the engine performs | CLI `records`, receipt, reconciliation |
| **AgentSession** | `agent_sessions` | `Store.open_session()` via `Executor.run_invocation()` — one provider execution | CLI `records`, receipt, review summary, `session_for_firebreak()` |
| **ToolExecution** | `tool_executions` | `Store.record_tool_execution()` — one tool action a provider *reported* | CLI `records`, receipt |
| **Approval** | `approvals` | `Store.grant_approval()` — one human decision | `require_approval()`, receipt |
| **Review** | `reviews` | `Store.open_review()` — the decision a person is being asked to make | CLI `records` |
| **Artifact** | `artifacts` | `Store.record_artifact()` — digest and size **at write time** | review summary, receipt |
| **TestRun** | `test_runs` | `Store.record_test_run()` — what validation actually ran | review summary, receipt |
| **GitChange** | `git_changes` | `Store.record_git_change()` — structural repository delta | review summary, receipt |
| Event | `events` | `Store._append()` — the chained spine | `docs/AUDIT_EVENTS.md` |

Three tables the Phase 3 audit proposed are deliberately **absent**, and a test asserts
their absence: `schema_version` (Phase 2 already delivered `PRAGMA user_version`; a second
mechanism for one fact is two sources of truth), `agent_providers` (the registry is
manifests on disk pinned by digest; a database mirror could disagree with the file the
policy pins, and the audit requirement is met per *session*, where it is a fact about an
execution), and `workspaces` (deferred, not rejected — missions carry a workspace name and
both locking and approval scoping key on it).

**Mission vs Task.** A task is a step the engine performs; a mission is a thing a person
asked for. They fail for different reasons and at different granularities, which is why
they are modelled separately rather than as one row with more columns.

**Session vs Task.** A task can contain several sessions. The media export below is one
`media` task holding three sessions — probe, encode, verify — because each is a separate
sandboxed process with its own requested and effective sandbox.

Which task kind a capability's work becomes is a data table, not a branch:

```python
CAPABILITY_TASK_KIND = {
    "code_change":    TaskKind.INFERENCE,
    "sourced_report": TaskKind.INFERENCE,
    "media_export":   TaskKind.MEDIA,
}
```

A new capability adds a row. `TaskKind` also declares `CHECKPOINT`, `VALIDATION`,
`PUBLISH` and `REVIEW_PREP`; `CHECKPOINT` and `VALIDATION` have callers, **`PUBLISH` and
`REVIEW_PREP` do not** — they are declared and unused at this revision.

---

## 3. Mission state machine

Seven states, kept at their 4.0.0 spelling: renaming them would rewrite the meaning of
every existing row. `MISSION_TRANSITIONS` maps `(from, to)` to `(event, reason)`, and the
reason is what a refusal quotes back.

| FROM | TO | EVENT | REASON |
|---|---|---|---|
| *(none)* | `queued` | `queued` | a new mission enters the queue |
| `queued` | `running` | `running` | the worker claimed a queued mission |
| `queued` | `cancelled` | `cancelled` | a queued mission was cancelled before it started |
| `running` | `waiting-review` | `waiting-review` | execution finished and its work awaits a human decision |
| `running` | `failed` | `failed` | execution raised, or was interrupted with no owner |
| `running` | `cancelled` | `cancelled` | a running mission honoured a cancellation request |
| `waiting-review` | `completed` | `completed` | a human accepted the work |
| `waiting-review` | `undone` | `undone` | a human rejected the work and the workspace was restored |
| `failed` | `undone` | `undone` | a human restored the workspace after a failure |
| `cancelled` | `undone` | `undone` | a human restored the workspace after a cancellation |
| `completed` | `undone` | `undone` | a human changed their mind about accepted work |
| `failed` | `queued` | `retry-queued` | a human retried a failed mission |
| `cancelled` | `queued` | `retry-queued` | a human retried a cancelled mission |

`ACTIVE = (queued, running)`. `FINAL = (completed, undone)` — terminal in the sense that
execution will not resume from there on its own. `failed` and `cancelled` are *not* final:
they can be retried, which is a new transition and not a resumption.

### The three guarantees

**One transaction covers the read, the validation, the write and the event.** A state
change with no event, and an event describing a change that rolled back, are both
unrepresentable. At baseline (`d24113c`) neither held: forcing `undone -> queued` emitted
nothing at all.

**`state` is not writable directly.** It was on `Store.update()`'s allow-list at 4.0.0,
which is why every guard lived in a high-level verb a caller could simply not use.

**Creation is atomic too.** `Store.create()` writes the mission row and its first `queued`
event in **one** `BEGIN IMMEDIATE` transaction. They used to be written on two different
connections, so an interruption between them left a real mission with no events at all —
which is the exact shape a fabricated row has, and the reason a verifier could not tell the
two apart. Making creation atomic is what lets `verify_states()` stop excusing event-less
rows (below). The event's *name* still comes from `MISSION_TRANSITIONS[(None, QUEUED)]`, so
the vocabulary has one definition even on the one edge with no prior state.

```
### refusing an illegal mission transition
Refused waiting-review -> running: a waiting-review mission cannot become running. From waiting-review a mission may become: completed, undone

### refusing a direct state write
Mission state cannot be set directly; use Store.transition(), which validates the change and records it

### refusing an illegal task transition
Refused task succeeded -> running: a succeeded task cannot become running. From succeeded a task may become: nothing
```

A person can act on the first message. `invalid state` cannot be acted on.

`transition(..., expect=<state>)` is optimistic concurrency for callers that already read
the row: if the state moved underneath them the transition is refused rather than applied
to a mission they were not looking at. Extra keyword fields (`attempt`, `error`,
`cancel_requested`, `approval_id`, `checkpoint`, `artifacts`, `receipt`) are written in the
same transaction so they cannot drift out of step with the state they describe.

### The retry budget belongs to the edge, not to a verb

`MAX_ATTEMPTS` is 3, published by `capabilities()` as `max_attempts`, and
`requeue_refusal(event, attempt)` is the **one** function that answers "may this requeue?".
It is keyed on the edge's **event name** — `retry-queued` — rather than on who is asking,
because three different verbs reach that edge and each one was, at some point, the one that
did not know about the budget. Both `transition()` and `finish_execution()` ask it; a path
that reaches a requeue without asking is the only way back to the old defect, and there is
now exactly one place to look.

A refusal is **recorded and then raised**. The `retry-budget-exhausted` event commits with
the same transaction that declines to touch the mission row, and the `TransitionError` is
raised after that transaction closes — raising from inside it would roll the event back
along with it, and "no event" reads exactly like "nobody ever tried". Three verbs against a
mission already at the ceiling, verbatim:

```
mission is 'failed' with attempt=3 (capabilities() publishes max_attempts=3)
transition(mid,'queued')            TransitionError: Refused failed -> queued: retry budget exhausted (3 attempts); create a new reviewed mission
retry(mid)                          MissionError: Retry budget exhausted (three attempts); create a new reviewed mission
finish_execution(mid,'queued')      TransitionError: Refused failed -> queued: retry budget exhausted (3 attempts); create a new reviewed mission
state after all three: failed attempt 3
  queued                   media_export via offline-media; scope=…/ws/probe
  running                  the worker claimed a queued mission
  failed                   execution raised, or was interrupted with no owner
  retry-budget-exhausted   Refused failed -> queued: retry budget exhausted (3 attempts); …
  retry-budget-exhausted   Refused failed -> queued: retry budget exhausted (3 attempts); …
verify_chain ok = True
```

Two refusal events, not three: `Store.retry()` checks the ceiling itself and raises a
`MissionError` before it reaches `transition()`, so the CLI's wording stays the one people
know. `verify_chain()` still passes afterwards — a recorded refusal is an ordinary chained
event, not a hole punched by the guard.

> **Historical note.** The budget lived only in `Store.retry()`, so an in-process caller —
> the worker, the desktop, any future orchestrator — got a fourth attempt by calling
> `transition()` directly, and the event it wrote carried the table's own reason, *"a human
> retried a failed mission"*. Moving it into `transition()` then left `finish_execution()`
> reaching the same edge on its own. Two verbs with the same hole is why the question is now
> asked of the edge.

### The mission rows are replayed against the log

`Store.verify_states()` walks each mission's event trail through `MISSION_TRANSITIONS` and
compares where it lands with what the row says, classifying every mission as
`VALID_CURRENT`, `LEGACY_PRECHAIN`, `STATE_DIVERGENCE`, `CORRUPTED_HISTORY` or
`MISSING_HISTORY`. `verify_chain()` carries the result and `audit verify` prints it on its
own line beside the chain's:

```
chain             intact
mission states    disagrees (1 replayed against the transition table)
PROBLEM           mission mission-51b3ffa4346a473b: the row says 'completed' but its events end at 'queued'; that state was written without an event
```

The `missions` table is not hash-chained and cannot be, so this is detection at verify time
and not prevention at write time. `docs/AUDIT_EVENTS.md` §4 documents the classes, the
`MISSING_HISTORY`/legacy-pin pair, and what the replay does not do.

### Two events that are deliberately not state changes

- **`cancel-requested`** is a *request*. `Store.cancel()` on a running mission sets a flag
  that `Executor.check()` observes; the state moves only when execution actually stops. It
  records `actor=ACTOR_USER`, because a person produces it. Pressing Stop twice appends one
  event, not two — the second call is a no-op returning the row, because two events would
  read as two decisions.

  The flag and the event are written in **one** transaction with the state re-read inside
  it. `cancel()` used to read the state in `get()` and write the flag in a separate
  `update()`, so a mission that reached `waiting-review` in between got a
  `cancel_requested` flag on a terminal row and a `cancel-requested` event appended *after*
  its terminal event — a log recording a decision that was not possible when it was written.
- **`reviewed`** is what the *person chose*, as opposed to what the mission became. A
  mission reaches `undone` from four states, so the decision is not recoverable from the
  state event. Its detail is the bare decision string (`accept` / `undo`) because consumers
  read it as a value.

---

## 4. Task state machine

| FROM | TO | EVENT | REASON |
|---|---|---|---|
| *(none)* | `pending` | `task-created` | the mission planned this step |
| `pending` | `running` | `task-started` | the step began |
| `pending` | `skipped` | `task-skipped` | an earlier attempt already completed this step |
| `pending` | `cancelled` | `task-cancelled` | the mission was cancelled before this step ran |
| `running` | `succeeded` | `task-succeeded` | the step finished |
| `running` | `failed` | `task-failed` | the step raised |
| `running` | `cancelled` | `task-cancelled` | the step was cancelled while running |

Same contract as a mission transition, including the shared transaction with its event.
`started_at` is stamped on entry to `running`; `finished_at` on entry to any of
`succeeded` / `failed` / `cancelled` / `skipped`.

**Two of these seven edges have no caller in the engine.** `pending -> skipped` and
`pending -> cancelled` are declared and reachable only through the API. Nothing in
`Executor`, `run_mission()` or `reconcile()` drives them: the resume paths short-circuit
inside the task body (`step-resumed`) rather than skipping the task, and reconciliation
settles only tasks that are `running`. A task left `pending` by a crash therefore **stays
`pending` forever** — see §11.

`Executor.task()` is a context manager, so the row is settled on the cancel and failure
paths too. That is the point: a task that did not finish says so, rather than staying
`running` forever the way missions used to.

---

## 5. AgentSession

A session is not a state machine — it is opened, and later closed. What matters is *when*.

`Store.open_session()` writes the row **before the process starts**, and mints the id that
is handed to Firebreak as `--session-id`. Firebreak adopts it rather than minting its own,
so a person holding a systemd scope name, a `.session` file or an event row can get back to
the mission, and `Store.session_for_firebreak()` does that lookup in the reverse direction.
If the process dies between this row and its first output, the row still exists and still
says what was requested — the case the baseline could not reconstruct at all.

Every provider execution goes through `Executor.run_invocation()`, and the session is
opened there. That makes "no provider runs without a record" an invariant rather than a
convention.

**Requested, effective and enforcement are three separate things, in three columns.**

| Column | What it is |
|---|---|
| `requested_sandbox` | the ceiling derived from the provider's manifest |
| `effective_sandbox` | what the invocation actually asked for, which an adapter may only narrow |
| `enforcement` | per field: `enforced`, `partial`, `not_enforced`, `not_representable`, `not_applicable`, each with the mechanism |
| `network_requested` / `network_effective` | what the session asked for vs what Firebreak was actually told |
| `credentials_requested` / `credentials_granted` | **identities only**; a value has never reached this row |
| `egress_requested` | recorded as *requested*, marked `not_enforced`. It is not a restriction |

A single `sandbox` blob would make a declared control indistinguishable from an enforced
one, which is the failure mode this phase exists to remove.
`sf_providers.sandbox_enforcement()` is the single answer both this row and the receipt
use, so a UI cannot decide differently.

`verify_invocation()` re-derives the ceiling from the manifest inside `run_invocation()`,
so an adapter that never calls `narrow()`, or builds a `SandboxSpec` from scratch, is still
bounded by what it declared.

**ToolExecution honesty.** `decision` defaults to `"observed"`, not `"auto_allow"`. Nothing
intercepted the call and nothing could have refused it; the vocabulary is deliberately
different from the `PolicyEngine`'s for that reason. `tool_records()` matches only on a
`tool` key in a provider's event data — guessing structure out of a progress message's
prose would manufacture rows a reviewer would believe.

---

## 6. Locks

Three lock files, two of which form a hierarchy.

| Lock | Held by | Mode | Claim |
|---|---|---|---|
| `execution.lock` | `Store.lock()` | `LOCK_EX` | "nothing may execute anywhere" — recovery, and anything reasoning across workspaces |
| `execution.lock` | `Store.lock(workspace=…)` | `LOCK_SH` | "a workspace operation is in progress" |
| `execution-<sha256[:32]>.lock` | `Store.lock(workspace=…)` | `LOCK_EX` | "nothing else may touch THIS workspace" |
| `worker.lock` | `worker()` | `LOCK_EX` non-blocking | one queue consumer per state directory |

The shared level is what makes the hierarchy work: two workspaces hold it at once and both
proceed, while a whole-system holder excludes them all. The first Phase 3 version gave each
workspace its own file and nothing else, so a worker holding the global lock during
recovery — exactly when nothing may start — stopped excluding anything. Four review-lock
tests caught it.

The per-workspace file is named by digest because a workspace name is user-supplied and
would otherwise choose a filename in the state directory. The human label is kept for the
refusal message.

Observed:

```
### two different workspaces
alpha: acquired
beta : acquired

### the same workspace twice
alpha (first) : acquired
alpha (second): refused -- Another mission is executing on alpha; this task remains queued

### a whole-system holder excludes every workspace
global: acquired
alpha : refused -- Another mission is executing on all workspaces; this task remains queued

### a workspace holder excludes the whole-system lock
alpha : acquired
global: refused -- Another mission is executing on all workspaces; this task remains queued

### lock files in the state directory
  execution-070223ea6634bed354d3860be25365a4.lock
  execution-9e606eabce7752e9b01ea0d678e35ca9.lock
  execution.lock
lock_path(None) -> (PosixPath('…/state/execution.lock'), 'all workspaces')
lock_path(alpha) -> (PosixPath('…/state/execution-070223ea6634bed354d3860be25365a4.lock'), 'alpha')
workspace_key(alpha) -> /tmp/tmp.gRyRpiOOg5/ws/alpha
```

Who takes what:

- `run_mission()` — the workspace lock, for the whole execution, `wait_seconds=0`. A second
  mission on the same workspace is refused and stays queued.
- `review()` — the workspace lock with `wait_seconds=10`. A published result can still be
  releasing its lock and an idle worker owns the global lock during recovery, so acquisition
  is retried. Only acquisition — never a partially applied review.
- `retry()` — the workspace lock.
- `worker()` startup reconciliation — the **global** lock, once.
- `worker.lock` is not part of the hierarchy. It limits queue consumers only; a CLI
  `shadowfetch-missions run` bypasses it entirely and competes for the execution locks like
  anything else.

**`workspace_key()` normalises before comparing.** Missions store the *resolved path*;
callers variously hold a name or a path. A filter that finds nothing because the caller
spelled it the other way is a silent no-op, and Phase 3 shipped exactly that bug in
workspace-scoped reconciliation before its tests were written.

---

## 7. A mission, end to end

`run_mission(store, mid)`:

1. Read the mission's workspace **before** taking the lock — the lock is per workspace and
   there is no way to know which one without it.
2. Take the workspace lock. Fail fast: `wait_seconds=0`.
3. `store.recover(workspace=…)` — settle any stale `running` row for this workspace now
   that we hold its lock and can be sure no live process owns it.
4. Re-read the mission. Refuse if its workspace changed while it was starting, or if it is
   no longer `queued`.
5. **`require_approval()`, before the state moves.** A `deny` decision emits `policy-denied`
   and raises `MissionError`. An `escalate` decision with no covering approval emits
   `approval-required` and raises `ApprovalRequired`; with one, it emits `approval-used` and
   stores `approval_id`. Placing the gate here means there is no window in which an
   unapproved mission is running, and every entry point — CLI, worker, desktop — is covered
   because they all come through this function.
6. Refuse if another mission on the same workspace is `waiting-review`. Two missions may
   target one workspace, but a result must be reviewed before another can mutate it, or the
   Undo boundary stops meaning anything.
7. `transition(queued -> running)`, incrementing `attempt`, clearing `error`.
8. `Executor.execute()`:
   - capture `git_structure()` **before** any provider runs;
   - unless a checkpoint already exists: a `checkpoint` task that writes `before.json`
     (`tree_index`) and calls the checkpoint engine for a recovery id;
   - one task for the capability's own work, whose kind comes from `CAPABILITY_TASK_KIND`.
     Splitting it further would put provider-shaped knowledge back into the orchestrator;
   - `record_structure()` — recorded **even when nothing changed**, because "no structural
     change" is a finding and its absence is indistinguishable from never having looked.
9. `Executor.receipt(state, error)` in a `finally`: writes `changes.diff`, `changes.json`,
   `after-index.json` and `receipt.json` (schema 2). A receipt that cannot be persisted
   turns the mission into a failure rather than being skipped.
10. If the outcome is `waiting-review`, `open_review_for()` builds the review object from
    what was **recorded**, never recomputed from the workspace as it stands now. If that
    raises, the failure is recorded as `review-summary-failed` and the mission still reaches
    review — a summary that cannot be built must not lose the work it was summarising.
11. `finish_execution()` — the terminal transition and its event in one transaction, after
    the receipt exists. Readers see either the previous state or the complete transaction.

A real `media_export` mission, start to finish. Workspace `alpha` held a 5,390-byte
`clip.mp4`; provider `offline-media`; policy `auto_allow`, so no approval:

```
queued            media_export via offline-media; scope=…/ws/alpha; network=none
running           the worker claimed a queued mission
task-created      checkpoint (step 1)
task-started      the step began
checkpoint-started  Taking workspace recovery point
checkpoint-created  20260908-195430-117151
task-succeeded    the step finished
task-created      media (step 2)
task-started      the step began
session-opened    offline-media 4.0.0 attempt 1
process-started   probe-input-1
process-finished  probe-input-1: exit 0; log=…/probe-input-1.log
session-closed    exit 0; completed
session-opened    offline-media 4.0.0 attempt 1
process-started   export-1
process-finished  export-1: exit 0; log=…/export-1.log
session-closed    exit 0; completed
session-opened    offline-media 4.0.0 attempt 1
process-started   verify-export-1
process-finished  verify-export-1: exit 0; log=…/verify-export-1.log
session-closed    exit 0; completed
export-verified   01-clip.mp4
task-succeeded    the step finished
review-opened     awaiting a human decision
waiting-review    Execution finished. Inspect artifacts and diff, then Accept or Undo
```

and the records it left:

```
{ "tasks": 2, "sessions": 3, "tool_executions": 0, "test_runs": 0,
  "git_changes": 0, "reviews": 1, "artifacts": 2, "approvals": 0 }
```

`git_changes` is 0 because this workspace is not a git repository: `git_structure()`
returns `None` on both sides and `record_structure()` records nothing rather than a
fabricated empty delta. `tool_executions` is 0 because ffmpeg reports no tool events —
that is a true absence, not a gap in the recording.

A mission that needs a human first, refused at step 5:

```
ApprovalRequired: This mission needs approval before it can run: this mission requests
network access (allowlist), which reaches the internet from inside the sandbox; this
mission is given credential identities: CODEX_API_KEY. no approval exists for
mission:mission-1788688cffe54935
state after refusal: queued
```

`state after refusal: queued` is the assertion that matters. "It raised" is a weaker claim
than "it did not start".

**Approval is checked once, at the start.** Revoking an approval mid-run does not stop
anything; `Store.cancel()` is what stops a running mission. The scope is recomputed at run
time from the provider's *declared ceiling*, never from what the mission claimed when it
was approved — an approval derived from something an adapter chooses later would be an
approval for whatever it felt like doing.

---

## 8. Reconciliation

`Store.reconcile(workspace=None, reason=…)`. The caller must already hold the matching
lock: whole-system for `workspace=None`, that workspace otherwise. Reconciling a row
somebody else is executing would mark a **live** mission failed, which is the one outcome
worse than leaving a stale row.

Order is deliberate:

1. **Tasks**, then **sessions**, for every `running` mission in scope. A `running` task
   becomes `failed` with "The worker stopped while this step was running"; a session with no
   `ended_at` is closed with outcome "interrupted: the worker stopped before this session
   was closed". Settling the mission first would emit its terminal event *before* the
   records that explain it.
2. **Missions**, through the same `recover()` the worker and the tests already use, so
   exactly one place decides cancelled-versus-failed:
   - `cancel_requested` set → `cancelled`. The person asked to stop and the worker died
     before it could say so. Recording that as a failure invites retrying work somebody
     explicitly stopped, and loses the one fact that distinguishes the two cases.
   - otherwise → `failed`, "Execution was interrupted. Inspect changes, then Retry or Undo;
     no automatic replay."
3. **Waiting work is counted, never touched.** Queued missions whose policy decision needs
   an approval that does not exist are counted in `waiting_approval`; `waiting-review`
   missions are counted in `reviews`. A mission awaiting a person is in a correct state and
   "fixing" it would discard the wait.

A quiet system emits **no event at all** — `reconciled` is appended only when something was
actually settled. One every startup would drown the log it exists to serve.

Observed, driving a mission to the shape a crash leaves behind (mission `running`, one task
`running`, one session never closed):

```
### before reconciliation
mission running | task running | session ended_at None

### reconcile(workspace=<name>) under the workspace lock
{
  "missions": ["mission-b102a19f56cf4b91"],
  "tasks":    ["task-59f61f242a87401e"],
  "sessions": ["sess-b6d63d0e5d5f45ce"],
  "reviews": 1,
  "waiting_approval": 0,
  "reason": "documentation probe"
}

### after reconciliation
mission failed | task failed | session outcome interrupted: the worker stopped before this session was closed
error: Execution was interrupted. Inspect changes, then Retry or Undo; no automatic replay.
```

### What reconciliation deliberately does NOT do

- **It never resumes a provider.** No provider here supports resumption, and re-running a
  turn that may already have had effects — a file written, a request sent, a token spent —
  is a decision only a person can make. Partial work is preserved and the mission becomes
  retriable.
- **It does not undo the workspace.** Cancel and Undo are different actions; conflating them
  destroys work a person may want. The checkpoint stays available for an explicit Undo.
- **It does not clean up partial artifacts.** After `kill -9` mid-encode the baseline left a
  524,336-byte partial file in the workspace; that is still what happens. It is visible in
  the diff and the reviewer decides.
- **It does not touch tasks that never started.** Only `running` tasks are settled. A
  `pending` task left by a crash stays `pending` (§4).
- **It does not re-check approvals.** Counting them is all it does.

---

## 9. The worker and its wake-up model

```python
worker(store, once=False)
```

1. Take `worker.lock` non-blocking. A second worker simply returns 0 — not an error, and
   not a queue with two consumers.
2. Install SIGTERM/SIGINT handlers that set `stopping` and call `store.cancel()` on every
   running mission.
3. **Reconcile once, at startup, under the whole-system lock.** Not every tick. Repeating it
   was harmless only because it found nothing to do; in a wake-up-driven loop it would be a
   poll wearing a different name. If another process holds the global lock, that process is
   already reconciling and this one skips it.
4. Loop: read the queued missions ordered by `(created_at, id)`, run each, then block in
   `Wakeup.wait()`.

`ApprovalRequired` is caught and the mission is left queued: waiting for a person is not a
failure and not something to retry in a loop. Any other `MissionError` is also swallowed
and the loop continues.

### Wakeup

`Wakeup` watches the state **directory** with `inotify` over `ctypes` —
`IN_MODIFY | IN_CLOSE_WRITE | IN_MOVED_TO | IN_CREATE`. Not the database file: in WAL mode
the writes land in `-wal`, and `-wal`/`-shm` are created and unlinked constantly, so a watch
on one inode is stale within a second. `inotify` rather than a cooperative FIFO because a
FIFO only wakes for writers that remember to signal it.

`WAKE_FALLBACK_SECONDS = 30` is a **fallback**, not a poll interval: the longest the worker
can sleep through a missed notification. The wake-up is a hint, never the data — the queue
is re-read either way, so a spurious wake costs one query and a missed one costs at most the
fallback.

What Step 19 replaced, measured at baseline with an **empty** queue (`/proc` deltas,
`strace -f -c`, a real sqlite3 trace callback with wrapped `flock`, `EXPLAIN QUERY PLAN`):

| | 1 Hz poll | Wakeup |
|---|---|---|
| idle CPU | 0.128% of a core | 0.000% (unmeasurable at tick resolution) |
| context switches | 218 per 180 s | 4 total in 90 s |
| write syscalls | 2,880 per 180 s | 1 total |
| dirtied bytes | 225 MiB/hour | 0 |
| wake latency | 0.447 s median | 0.0003 s median |

The queries were never the cost — they are indexed and O(1) in queue size. The cost was
opening and closing two SQLite connections twice a second forever.

Confirmed on this host:

```
event_driven: True | reason: None | fallback: 30 seconds
woken by an event: True | latency: 0.0003s
```

### Honest degradation

If `inotify` cannot be set up — old kernel, unsupported filesystem, per-user watch limit
reached — `Wakeup` becomes a plain `time.sleep(fallback)` and says so **once** on stderr:

```
shadowfetch-missions: inotify unavailable (<reason>); falling back to a 30s poll.
New missions may wait that long.
```

Exercised against an unwatchable directory:

```
event_driven: False | reason: FileNotFoundError: [Errno 2] inotify_add_watch failed
wait() returned: False after 0.20s
```

That is the old behaviour at a slower rate. A fallback that *looked* event-driven would hide
a stall behind an apparently healthy worker.

### A defect this model has at this revision

**A queued mission that needs approval makes the worker spin.** `require_approval()` writes
an `approval-required` event before raising, that write lands in the watched directory, and
the pending `inotify` event is still in the fd when the loop reaches `wake.wait()` — so the
worker wakes immediately, retries the same mission, and writes another event.

Measured on the throwaway store, one queued mission needing approval, `timeout 5` on the
worker:

```
events before: 37
worker exit=124
events after : 1042
approval-required|1006
```

1,006 identical events in five seconds, each one mirrored to journald. Proof of the
mechanism, separately:

```
quiet directory, wait(0.2): False
after our OWN write, wait(5): True in 0.0000s
```

A refusal that raises **without** writing — "Review the previous mission for this workspace
before running another", a workspace that vanished — does not spin, because nothing wakes the
watcher. Only the refusal paths that emit an event do: `approval-required` and
`policy-denied`. This is a defect, not a designed limitation, and it is not fixed here.

---

## 10. Reading the control plane

Everything in this document is reachable from the CLI, which is the desktop's IPC boundary
— there is no HTTP listener and the desktop owns none of this state.

| Command | Returns |
|---|---|
| `shadowfetch-missions show <id>` | the mission row |
| `shadowfetch-missions records <id>` | tasks, sessions, tool executions, test runs, git changes, reviews, artifacts, approvals |
| `shadowfetch-missions events <id>` | that mission's events (`at`, `event`, `detail`) |
| `shadowfetch-missions watch --since <seq>` | the raw chained event rows, followed |
| `shadowfetch-missions policy show <id>` | the decision, the mediation matrix and `advisory_fields` |
| `shadowfetch-missions approvals [<id>]` | approval rows |
| `shadowfetch-missions audit verify` | the chain, the mission-state replay, the head and the anchor verdict — see `docs/AUDIT_EVENTS.md` |

`audit verify` is the one verb here whose **exit status** is part of its answer: `0` intact,
`1` tampered, `2` unverified-or-degraded. The ladder is computed once by `audit_exit_code()`
from the report itself, so `--json` and the text form return the same code, and a report with
no verdict at all counts as a failure.

Until Step 18 landed in the working tree, `records` did not exist and the desktop printed
"not reported. The mission CLI has no command that returns tasks" rather than inferring task
state from event names — which would have reimplemented the task state machine in Qt.

---

## 11. Limitations, collected

Stated here rather than scattered, because every one of them is a thing a reader might
otherwise assume works.

1. **Approval is a start-time gate, not a continuous one.** Revocation mid-run stops
   nothing. Cancel does.
2. **`depends_on` is stored and never read.** There is no DAG execution; missions are a
   linear task sequence with `max_parallel` 1.
3. **`TaskKind.PUBLISH` and `TaskKind.REVIEW_PREP` have no callers**, and neither do the
   `pending -> skipped` and `pending -> cancelled` task edges. A task left `pending` by a
   crash is never settled.
4. **The worker spins on approval-blocked missions** (§9). 1,006 events in 5 seconds,
   measured.
5. **Validation shares inference's network posture.** `network_requested` and
   `network_effective` are separate columns and `enforcement` carries
   `stricter_than_inference: not_implemented`, so the gap appears in every receipt rather
   than in a document nobody opens at review time. It is not closed.
6. **Egress allowlists and masked paths reached no mechanism. CLOSED in 4.1.0.** Both are
   enforced now: the allowlist as an nftables ruleset with default DROP in the sandbox's
   own network namespace, installed by a helper that owns that namespace before bwrap
   runs; masked paths as real mounts, an empty tmpfs over a directory and `/dev/null`
   over a file. The residuals are narrower than the old gap and are not the same claim:
   `--net allow` with NO declared destination installs no ruleset and reaches the LAN,
   DNS still leaves through the NAT's forwarder, and masking is by PATH so a hardlink to
   the same inode under an unmasked name is still readable. A syscall filter was added at
   the same time, applied to every sandbox and deliberately not declarable. The old text
   is worth keeping in view: it said `--mask-path` was "record-only — it reaches no bwrap
   argument", which was exactly right, and is what got fixed.
7. **Tool actions inside a provider turn are `not_observable`.** A `tool_executions` row
   exists only because the provider reported it, with `decision: "observed"` — nothing
   intercepted it and nothing could have refused it.
8. **A forged mission row is detected, not prevented.** The `missions` table carries no hash,
   so `UPDATE missions SET state=…` lands. `verify_states()` reports it at verify time (§3)
   and cannot recover the state it displaced.
9. **`record_artifact()` and `decide_review()` emit no event.** Artifact and review-decision
   rows are visible through `records` and the receipt, not through the event stream. The
   `reviewed` event that `review()` emits separately is the only trace of a decision in the
   chain.
10. **Reconciliation cannot distinguish "the worker died" from "the worker is alive but
    lockless."** It relies entirely on the caller holding the right lock. Nothing checks a
    pid.
11. **`docs/MISSION_SCHEMA.md` is at schema v2** and does not describe any v3 table, nor the
    v4 legacy pin.

> **Historical note.** This list carried *"`cancel-requested` is recorded with `actor:
> orchestrator`, although a person is what produces it"*. `Store.cancel()` passes
> `actor=ACTOR_USER` now, so both events it can emit record the person.
