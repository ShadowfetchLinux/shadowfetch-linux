# Agent Session Lifecycle

*Shadowfetch Linux 4.0.x — Phase 3, Steps 5, 6, 12, 16 and 21, brought forward to
**Phase 3.1**. Companion to `APPROVAL_POLICY.md` (what a human agreed to),
`PROVIDER_TRUST.md` (what is known about the provider) and
`AGENT_ARCHITECTURE.md` (the seam itself).*

This document answers one question: **what is recorded about one provider
execution, from before it starts to after it is settled, and what is not?**

Everything below is read out of `sf_missions.py`, `sf_providers.py` and
`shadowfetch-firebreak`, or is literal output from a real run on the build host.
Limitations are in **§10** and are as load-bearing as the rest.

---

## 1. The object

An **AgentSession** is one execution of one provider program. It sits between
"mission" and "process":

```
mission  ──▶  task  ──▶  agent session  ──▶  Firebreak/bwrap  ──▶  the program
                              │
                              └──▶  tool_executions (only what the provider reports)
```

A mission has many sessions. The offline media export opens three for a single
`media` task — probe, encode, verify — each a separate program with its own row:

```
session sess-230aee2650194896  /usr/bin/ffprobe  exit 0  completed
session sess-065a1a38425f4f69  /usr/bin/ffmpeg   exit 0  completed
session sess-72a36cf9a37e4725  /usr/bin/ffmpeg   exit 0  completed
```

A workspace test command is **not** an agent session. It runs through the same
sandbox but is recorded as a `test_runs` row, because it is the person's own
command rather than a provider turn.

---

## 2. Why the id is minted before execution

`Store.open_session()` writes the row and mints the id **before** the process
starts, and its docstring says why:

> If the process dies between this row and its first output, the row still
> exists and still says what was requested — which is exactly the case the
> baseline could not reconstruct.

Two things follow that a post-hoc id could not give:

1. **A crash between launch and first output is still attributable.** The row
   naming the provider, the sandbox and the command exists before there is
   anything to attribute.
2. **The sandbox and the orchestrator share one identity.** The id is handed to
   Firebreak as `--session-id`; Firebreak adopts it rather than minting its own.
   Before this, Firebreak minted its own id and Mission Control never saw it, so
   a person holding a systemd scope name had no way back to the mission.

The id is `"sess-" + uuid4().hex[:16]`.

---

## 3. Mint to close, in order

Every provider execution goes through `Executor.run_invocation()`. That is the
invariant, not a convention — opening the session anywhere else, in each caller,
would make it a convention that a new caller could forget. There are three call
sites and all three are inside the executor.

| # | step | code | what it guarantees |
|---|---|---|---|
| 1 | Re-derive the ceiling from the manifest and refuse anything above it | `verify_invocation(invocation, manifest)` | an adapter that never calls `narrow()`, or builds a `SandboxSpec` from scratch, is still bounded by what it declared |
| 2 | Classify the program by who could replace it | `classify_executable(program)` | `executable_trust` is a fact about the filesystem, not a claim by the provider |
| 3 | **Write the row** | `Store.open_session(...)` | the record exists before the process does |
| 4 | Emit `session-opened` in the same transaction | `_append(...)` | a session with no event, and an event with no session, are both unrepresentable |
| 5 | Build the Firebreak argv, carrying `--session-id` / `--mission` / `--task` | `Executor.run_process` | one identity across three systems |
| 6 | Firebreak writes its own `started` record **before spawning** | `append_record(record, manifest)` | a session that cannot be recorded is not executed |
| 7 | Run | `subprocess.Popen` under `systemd-run --scope` | limits land on the session's own cgroup |
| 8 | Firebreak writes its `ended` record from a `finally` | `append_record(...)` | append-only; nothing is ever rewritten |
| 9 | **Close the row** on every path | `Store.close_session(...)` | §6 |

Step 9 has a comment worth repeating, because it records a shipped defect:

```python
else:
    # Deliberately NOT `return` inside the try: a return there skips the
    # else clause, which is how the first version of this closed no
    # session at all on the success path.
```

Every row read `exit None / outcome None` while the suite stayed green, because
nothing asserted the closed shape. It does now.

---

## 4. The `--session-id` handshake, and correlation in both directions

### 4.1 What Mission Control sends

```python
if self.session_id:
    wrapper.extend(["--session-id", self.session_id, "--mission", self.mid])
    if self.task_id:
        wrapper.extend(["--task", self.task_id])
```

Two hops, two flag names, and it is worth keeping them apart. Mission Control
names each granted credential **identity** with `--credential-env NAME`; Firebreak
is what turns that into bwrap's `--clearenv` plus one `--setenv` per name. The
value travels in Firebreak's environment, never in either argv (§7). Which
identities may be named is intersected with the invocation's `SandboxSpec` first,
so an adapter that narrowed `credential_ids` actually narrows what is passed —
before that, the narrowing was ignored: fail-safe, since the manifest still
bounded it, but decorative, and decorative is worse than absent because it reads
as a control.

Two of Mission Control's declared fields have **no** flag on this hop at all:
`egress_allowlist` and `masked_paths`. Firebreak accepts `--egress-host` and
`--mask-path`, both record-only, and Mission Control passes neither — so those
declarations reach neither a mechanism nor Firebreak's own session record. §6 and
`PHASE3_REMAINING_RISKS.md` say so in the same words.

### 4.2 What Firebreak does with it

`session_id(supplied)` adopts the caller's id if there is one, otherwise mints
`fb-<timestamp>-<8 hex>`. The shape is validated, not trusted:

```python
SESSION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
```

because the id becomes **a systemd unit name (`--unit=`), a filename, and an
environment variable inside the sandbox** — three injection surfaces. The
orchestrator is not hostile, but "the caller is trusted" is the assumption this
codebase keeps finding was wrong somewhere else. `../../etc/passwd`,
`unit;rm -rf /`, `--property=Foo=bar`, a leading dash, an embedded newline and
anything over 64 characters are all refused.

The record says which of the two happened, because **only adoption proves the
orchestrator was involved**:

```
$ shadowfetch-firebreak run --workspace demo --net none --no-checkpoint \
    --session-id sess-doc0123456789ab --mission mission-doc0123456789 \
    --task task-doc0123 --workspace-mode read-only -- /bin/echo hi

  record: 'started'
  schema: 2
  session: 'sess-doc0123456789ab'
  run: 'e634572d5e364687af7713a6a56aa9f6'
  session_id_source: 'orchestrator'
  mission: 'mission-doc0123456789'
  task: 'task-doc0123'
  scope_unit: 'sess-doc0123456789ab.scope'
  workspace_mode_requested: 'read-only'
  executable_resolved: '/usr/bin/echo'
  executable_resolution: 'literal-path'
  network_requested: 'none'
  network_effective: 'none'
  enforcement.network: {"mechanism": "bwrap --unshare-net: the sandbox gets its own
                        empty network namespace", "status": "enforced"}
  enforcement.workspace_mode: {"mechanism": "bwrap --ro-bind on the workspace",
                        "status": "enforced"}

  {"record": "ended", "session": "sess-doc0123456789ab", "run": "e634572d...",
   "mission": "mission-doc0123456789", "task": "task-doc0123",
   "exit": 0, "exit_reason": "completed", ...}
```

The `run` id is separate from the session id and minted per execution, so a
`started` and an `ended` record still pair up unambiguously if a session id is
ever reused.

### 4.3 Resolving in each direction

**Mission → session** is a shipped command:

```
$ shadowfetch-missions --json records <mission-id>
   → {"mission": …, "tasks": [...], "sessions": [...], "tool_executions": [...],
      "test_runs": [...], "git_changes": [...], "reviews": [...],
      "artifacts": [...], "approvals": [...]}
```

**Session → mission** exists three ways at rest:

* the Firebreak `.session` file carries `mission` and `task` on both records;
* the systemd scope is named `<session-id>.scope`, and the session id *is* the
  agent-session primary key;
* `agent_sessions` has an index on `firebreak_session`, and
  `Store.session_for_firebreak(id)` resolves `WHERE firebreak_session=? OR id=?`
  — the `OR id=?` is what makes it work whether or not the closing write
  happened (§6).

An unknown id resolves to `None` rather than guessing.

**The limitation:** `session_for_firebreak()` has **no caller outside its own
tests**. No CLI verb and no desktop code calls it, so today the reverse lookup is
a Python API and an index, not a command a person can run. Reversing by hand
means reading the `.session` file's `mission` field, or grepping `records` output
for the session id.

---

## 5. Every field, and why it is there

`agent_sessions`, schema v3. Grouped by the question it answers.

**Who ran, and under what claim**

| column | why |
|---|---|
| `id` | the one identity; also the Firebreak session and the systemd unit stem |
| `mission_id`, `task_id` | where this execution sits; `task_id` may be null for work outside a task |
| `provider_id`, `provider_version` | which provider, at which version |
| `provider_trust` | from the approved-provider policy, not from the manifest's own say-so |
| `attempt` | the mission attempt this session belongs to; a retry opens new sessions rather than reusing rows |

**What program actually executed**

| column | why |
|---|---|
| `executable` | the resolved absolute path |
| `executable_trust` | `classify_executable()`'s verdict — computed from ownership and writability of the file *and every directory above it*, because replacing a directory entry is as good as replacing its target |
| `command` | the full argv, truncated to 4000 characters |

**What it was allowed to do — three separate things**

| column | why |
|---|---|
| `requested_sandbox` | the ceiling the manifest declares |
| `effective_sandbox` | what the invocation actually asked for, which may only be narrower |
| `enforcement` | per field: what the mechanism actually reaches |
| `read_grants` | the paths bound read-only into the sandbox |
| `network_requested` | `none` / `allowlist` — the mission's posture |
| `egress_requested` | the declared hosts, recorded **as requested** |
| `network_effective` | what Firebreak is actually told, which is `none` or `allow` and nothing else |
| `credentials_requested` | identities the manifest declares |
| `credentials_granted` | identities actually placed in the environment |

**How it ended**

| column | why |
|---|---|
| `started_at`, `ended_at` | `ended_at IS NULL` is what reconciliation looks for |
| `exit_code` | null when the process never reported one |
| `outcome` | the sentence, not just the number (§6) |
| `firebreak_session` | the sandbox's own id; written on close |
| `usage` | provider usage as reported by the adapter — **never written by this build** (§10.2) |

---

## 6. Why requested, effective and enforcement are three things

A single `sandbox` column would make a declared control indistinguishable from an
enforced one. That is the failure mode this phase exists to remove, so the row
keeps them apart:

* **requested** — what the provider's manifest declares it may have.
* **effective** — what this particular invocation asked for. `narrow()` and
  `verify_invocation()` guarantee it is never broader.
* **enforcement** — per field, what mechanism applies it, produced by
  `sf_providers.sandbox_enforcement(spec)`.

The enforcement map has five statuses and each is a different fact:

| status | meaning |
|---|---|
| `enforced` | a mechanism outside our code applies it |
| `partial` | applied, with a named residual |
| `not_enforced` | declared, applied by nothing |
| `not_representable` | there is no way to express it at all |
| `not_applicable` | this session declared nothing for this field |

From a real offline session, verbatim:

```json
"network":        {"status": "enforced",
                   "mechanism": "bwrap --unshare-net for 'none'; 'allowlist' collapses
                                 to the host network, see egress_allowlist"},
"workspace_mode": {"status": "enforced", "mechanism": "bwrap --ro-bind for read-only,
                                                       --bind otherwise"},
"memory_mb":      {"status": "enforced", "mechanism": "systemd MemoryMax with
                                                       MemorySwapMax=0, so the cap bounds
                                                       the workload rather than the
                                                       resident set"},
"processes":      {"status": "enforced", "mechanism": "systemd TasksMax"},
"cpu_seconds":    {"status": "partial",  "mechanism": "RLIMIT_CPU at the tighter of the
                                                       declaration and the mission timeout.
                                                       Per-PROCESS, so a provider that forks
                                                       gets a fresh budget for each child"},
"egress_allowlist": {"status": "not_applicable",
                     "mechanism": "this session declared no egress host"},
"masked_paths":     {"status": "not_applicable",
                     "mechanism": "this session declared no masked path"},
"credential_ids":   {"status": "not_applicable",
                     "mechanism": "this session was granted no credential identity"},
"read_grants":      {"status": "not_applicable",
                     "mechanism": "this session was granted no read access outside its workspace"},
"account_mount":    {"status": "not_applicable",
                     "mechanism": "this session mounts no provider account"},
"syscall_profile":  {"status": "not_representable",
                     "mechanism": "no schema property and no bwrap --seccomp anywhere"}
```

Every `not_applicable` message says **what was not asked for**, from
`UNUSED_MEANS_NOT_APPLICABLE`, rather than the generic *"this session declared
nothing for this field"*. `not_applicable` on its own reads as a gap; naming the
absent thing is what distinguishes "there was nothing to apply" from "a control
that should have applied did not".

`network` reads `enforced` above because that session's posture is `none`. The
same field on an `allowlist` session reads:

```json
"network": {"status": "partial",
            "mechanism": "bwrap --unshare-net enforces network on/off. This session is
                          not 'none', so the sandbox has the host's network and the
                          declared destinations are not filtered -- see egress_allowlist"}
```

Three of those statuses are corrections of claims that had shipped:

* `network` used to read `enforced` unconditionally, so Mission Control said
  *enforced* about an allowlist session while Firebreak's record for the **same
  session** said *not_enforced*. It is now `partial` whenever the posture is not
  `none`: the on/off decision holds, the destination does not.
* `credential_ids` used to read `enforced` for a session granted no credentials,
  because `all([])` is `True` — a control reported as working for a session that
  never asked for it. It now reads `not_applicable`.
* the same `all([])` shape was fixed **for every field a session does not use**,
  not just the one that was noticed: `account_mount` said `enforced` for a session
  that mounts no account, which is a claim about a mechanism that never ran.

Firebreak computes its own enforcement map independently, **out of the argv about
to be spawned** rather than echoed back from the request. Two records describing
the same session must agree or one of them is misleading somebody.

---

## 7. Credentials: identities are recorded, values are not

`credentials_requested` and `credentials_granted` hold **names**. A value has
never reached these columns and must not. `Executor.open_session()` says so at
the point of writing:

```python
# Identities only. A value has never reached this row and must not.
credentials_granted=tuple(sorted(secrets or {})),
```

A test asserts every recorded credential still matches `^[A-Z0-9_]+$` — *"this
looks like a value, not an identity"*.

The values are resolved outside the sandbox and handed to Firebreak, which
injects them at the boundary after `--clearenv`; they never appear in an argv.
Firebreak's own record strikes secrets **three ways**, because the first two were
not enough: by `--setenv` position, by secret-shaped option name, and by
**equality** against the values actually resolved. The third exists because a
credential value did reach a 0600 fsynced record during Phase 3 — `mytool
--api-key s3cr3t` landed verbatim — and the claim that it could not was refuted
by an executed exploit rather than by argument. A text redactor cannot recognise
a short or arbitrary value.

The mission receipt carries the approval's scope, granter and method, and no
credential value has ever been in an approval row either.

---

## 8. How a session is settled

`close_session()` records `ended_at`, `exit_code`, `outcome` and — on one path
only — `firebreak_session`. Every column below is literal output from a real run
on the build host.

| path | how it is reached | `exit_code` | `outcome` | `firebreak_session` |
|---|---|---|---|---|
| success | provider exits 0 | `0` | `completed` | set |
| non-zero exit | provider exits n | `1` | `provider exited 1` | set |
| cancel | `Cancelled` raised (Stop) | `None` | `cancelled` | **null** |
| failure | any other exception | as far as it got | `failed: <message, 200 chars>` | **null** |
| crash | worker died; settled later by `reconcile()` | `None` | `interrupted: the worker stopped before this session was closed` | **null** |

### 8.1 Failure

```
$ shadowfetch-missions run <mission>          # input that is not a media file
mission state: failed
  session sess-647c22eba35a483b | exit_code 1 | outcome: provider exited 1
  firebreak_session column: 'sess-647c22eba35a483b'
  task 1 checkpoint succeeded
  task 2 media failed | Cannot inspect media: broken.mkv
```

A provider that runs and exits non-zero is not an exception; it took the `else`
branch, so its `firebreak_session` is written.

### 8.2 Cancel

```
$ shadowfetch-missions --json cancel <mission>
cancel -> running cancel_requested= 1

mission state: cancelled
  session sess-a45e9041e76f41a8 | exit_code: 0    | outcome: completed | firebreak_session: 'sess-a45e…'
  session sess-3df597bf20184d16 | exit_code: None | outcome: cancelled | firebreak_session: None
  task 1 checkpoint succeeded
  task 2 media cancelled
```

Cancel and Undo are different actions: a cancelled mission keeps its workspace
changes and its checkpoint. Pressing Stop twice appends no second request event —
the same decision made twice is one decision.

### 8.3 Crash

Killed with `SIGKILL` mid-encode, so none of our own cleanup ran:

```
--- rows immediately after the kill ---
mission state: running
  session sess-3fdc60f6d6cf4f6f | ended_at: 2026-09-08T23:56:31+00:00 | outcome: completed
  session sess-02e8ccb2c1ae4162 | ended_at: None                     | outcome: None
  task 1 checkpoint succeeded
  task 2 media running

--- shadowfetch-missions worker --once   (reconciles at startup) ---
mission state: failed | error: Execution was interrupted. Inspect changes, then
                                Retry or Undo; no automatic replay.
  session sess-02e8ccb2c1ae4162 | ended_at: 2026-09-08T23:56:36+00:00
    outcome: interrupted: the worker stopped before this session was closed
    firebreak_session column: None
  task 2 media failed | The worker stopped while this step was running
```

Reconciliation runs **once**, at worker startup, under the whole-system lock —
not on a tick. Its order matters: tasks and sessions are settled *first*, then
the mission, so the terminal event does not arrive before the records that
explain it.

Three rules it follows:

* **Provider processes are not resumed.** Re-running a turn that may already have
  had effects — a file written, a request sent — is a decision only a person can
  make. Partial work is preserved and the mission becomes retriable.
* **Waiting work is reported, never touched.** A mission awaiting approval or
  review is in a correct state; "fixing" it would discard the wait. The report
  counts them (`waiting_approval`, `reviews`) and changes nothing.
* **A quiet system emits no reconciliation event at all.** One every startup
  would drown the log it exists to serve.

A cancelled-then-interrupted mission records `cancelled`, not `failed`: calling
it a failure would invite retrying work somebody explicitly stopped.

---

## 9. Tool executions inside a session

`tool_executions` rows hang off a session, with `(session_id, seq)` unique so a
provider that repeats a record does not create a second row. They store redacted
arguments plus a digest, timing, exit status and change counts.

They are written with `decision = "observed"`. That word is exact:

> A provider's internal tool calls are visible **only if it reports them on its
> own stream; nothing intercepts them.**

That is the `tool_actions_inside_a_turn` row of the policy capability matrix, and
its mediation level is `not_observable`. A provider that reports nothing produces
a session with zero tool rows and an execution nobody can enumerate. **The
absence of tool rows is not evidence that no tools ran.**

Recording is deliberately never fatal: a malformed or duplicated tool record is a
provider quirk, and losing a completed mission over one would trade the work for
its description. The failure is recorded as a `tool-record-failed` event instead.

---

## 10. Known limitations

**10.1 A provider's internal actions are self-reported.** §9. This is the largest
gap in the record and no part of it is enforced.

**10.2 `agent_sessions.usage` is never written.** The column exists and
`close_session()` accepts a `usage=` argument; no call site in the engine passes
one, and every row reads `"usage": null`. Provider usage is recorded elsewhere —
on the receipt's `inferences` entries — so the fact is not lost, but a reader
querying the session table for it will find nothing.

**10.3 `firebreak_session` is written only on the clean path.** It is set in the
`else` branch of `run_invocation`, so cancelled, failed and interrupted sessions
leave it null (§8). Reverse lookup still works, because
`session_for_firebreak()` matches `firebreak_session=? OR id=?` and the two ids
are equal by construction — but a query written against the column alone will
miss exactly the sessions somebody is most likely to be investigating.

**10.4 The reverse lookup has no shipped caller.** §4.3.

**10.5 The desktop does not show sessions.** The Control tab calls `show`,
`events`, `diff`, `policy show` and `approvals` — not `records`. Since `show`
carries no record sets, the Steps / Agent sessions / Test runs / Repository
sections print *"not reported. The mission CLI has no command that returns
sessions; their events appear in Activity."* That sentence is now stale in one
respect: the CLI **does** have `records`. The desktop has not been wired to it.

**10.6 The `events` verb drops the correlation columns; `watch` does not.**
Event rows carry `task_id`, `session_id` and `tool_execution_id`, and those
fields are covered by the hash chain (`HASHED_FIELDS`). But `Store.events()`
selects three columns only:

```
$ shadowfetch-missions --json events <mission> | ... sorted(rows[0].keys())
['at', 'detail', 'event']
```

`watch` streams the whole row, so it is the verb to use when the question is
which session an event belongs to:

```
$ shadowfetch-missions watch --no-follow | ... sorted(rows[0].keys())
['actor', 'at', 'detail', 'event', 'hash', 'mission', 'prev_hash', 'seq',
 'session_id', 'task_id', 'tool_execution_id']

11 session-opened | task: task-b6346174ed7742a1 | session: sess-d56830ccf7744669 | actor: orchestrator
14 session-closed | task: task-b6346174ed7742a1 | session: sess-d56830ccf7744669 | actor: orchestrator
```

The desktop Activity panel renders `events`, not `watch`, so the correlation is
absent there.

**10.7 The audit directory is not the desktop's state directory.** Firebreak
writes `<session-id>.session` under `~/.local/state/shadowfetch/firebreak` taken
from the **passwd entry**, not from `XDG_STATE_HOME` — an ambient desktop
variable should not decide where security audit state lands. It is relocatable
only through `SHADOWFETCH_FIREBREAK_STATE`, it refuses a directory owned by
another user, and every relocated record carries
`audit_directory_relocated: true`. Anything spawning missions must forward that
variable, or its records land in the operator's real audit directory — which is
exactly what happened during Phase 3, 100 files deep, when a rename left one
forwarding line behind.

**10.8 A session id may be reused across runs; a `run` id may not.** Firebreak
accepts whatever id the orchestrator supplies and does not require uniqueness.
Pairing `started` with `ended` is done by the per-execution `run` id.
