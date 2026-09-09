# Phase 3 — Mission Control as an orchestration control plane

Phase 2.5 left Mission Control able to run an agent through a provider seam.
It could not tell you afterwards who authorised the run, which executable
actually started, what the sandbox was asked for versus what it applied, or
whether the state in the database was one the engine had ever reached.

Phase 3 is that record. The invariant it was built against:

> No mission execution should occur without a persistent identity, a valid
> state transition, a persisted approval where required, and an audit trail
> sufficient to reconstruct what happened.

## What changed

### Schema: v2 → v3

`PRAGMA user_version` migration, applied inside one transaction. (The first
draft used `executescript()`, which issues an implicit COMMIT and made the
migration non-atomic; an interruption test caught it.)

Eight new tables, all correlated by `mission`, `task_id`, `session_id`:

| table | what it records |
|---|---|
| `tasks` | the units a mission decomposes into, with their own state machine |
| `sessions` | one provider execution: which executable, which trust, requested vs effective sandbox, per-field enforcement, credentials requested vs granted |
| `approvals` | scope, granter, method, grant/expiry/revocation instants |
| `tool_executions` | tool actions a provider reported, arguments digested then redacted |
| `test_runs` | command, executable, posture, guard state, exit code, log |
| `git_changes` | structural before/after of the workspace |
| `reviews` | the human decision that closed the mission |
| `artifacts` | what the run produced, by path and digest |

`events` gained `task_id`, `session_id`, `tool_execution_id`, `actor`,
`prev_hash`, `hash`.

### The state machine is a table, and it is the only writer

`MISSION_TRANSITIONS` maps `(from, to)` to `(event name, the reason the edge
exists)`. A refusal quotes that reason back, so "a completed mission cannot run
again" is actionable where "invalid state" is not.

`Store.update()` no longer accepts `state`. It used to, and
`Store.update(mid, state="banana")` was accepted and persisted — every guard
lived in a high-level verb a caller could simply not call. State changes go
through `Store.transition()`, which validates the edge, writes the row, and
appends the event **in one transaction**. `expect=` gives optimistic
concurrency for callers that already read the row.

The same lesson was applied twice more during adversarial testing: the
three-attempt retry budget lived only in `Store.retry()`, so an in-process
caller got a fourth attempt by calling `transition()` directly — the budget now
belongs to the `failed -> queued` edge. And `Store.cancel()` read the state in
one transaction and wrote the flag in another, so in 97/100 trials it accepted
a stop request for a mission that had already reached `waiting-review`; it is
now one transaction with the state re-read inside it.

### The audit log is hash-chained and externally anchored

Every event is hashed over canonical JSON of its own fields plus its
predecessor's hash. `Store._append()` is the only `INSERT` into `events`.

A chain proves no row was **altered**. It cannot prove no row was **removed
from the end** — delete the last three events and every survivor still
verifies. So each event's head (`seq`, `hash`) is mirrored to journald under
`SYSLOG_IDENTIFIER=shadowfetch-audit`, which is root-owned while the worker is
not, and `audit verify` compares the journal against the database.

Two defects found by attacking this and fixed:

* The anchor compared `max(seq)` only, so a rewrite deep in the log was
  detected for exactly as long as the rewritten row stayed newest — one honest
  append later, the heads agreed again over a row that said `REWRITTEN BY THE
  ATTACKER`. The journal still held the pre-tamper hash. Nothing read it.
  Every mirrored seq is compared now.
* `audit-mirror.json` is local bookkeeping owned by the same uid that writes
  the events, and `verify_chain()` branched on its failure count **first**.
  Truncating the log and then writing `{"failures": 1}` turned `ok=False` into
  `ok=True` and replaced "2 events were removed from the end of the log" with
  "the mirror has failed once". Degradation is reported *alongside* the
  comparison now; it can add a caveat and it can never remove a finding.

### The mission rows are replayed against the log

The chain covers events. The `missions` table is not chained, so
`UPDATE missions SET state='completed'` was indistinguishable from work that
ran — and the engine would then narrate the forged state back into the log,
appending *"a human changed their mind about accepted work"* for a mission that
had never run. `Store.verify_states()` replays each mission's event trail
through `MISSION_TRANSITIONS` and reports both impossible edges and a final
state no event explains. It needs no new storage.

### Approval is enforced by the engine, not by a dialog

`sf_policy.py` owns one decision function. `PolicyEngine.evaluate()` returns a
`Decision` (`AUTO_ALLOW` / `ESCALATE` / `DENY`) with its reasons, its scope, its
mediation, and its advisory fields. `_decide()` is the only constructor, so a
decision cannot be built without them.

The sharpest defect the attack suite found was here. Provider resolution
existed **twice** — once in the approval gate, once in the Executor — and the
Executor knew one fallback the gate did not. A mission naming its provider only
in `config["runtime"]` was un-gated by the approval check and then executed
anyway. Two copies of a resolution rule is not a style problem; it is a
security boundary one caller can be taught to see past. There is now one
`mission_provider_id()`.

Also fixed under attack: expiry compared as text rather than as an instant, a
non-date expiry treated as valid, a forged approval row accepted without a
witness, a scope widened after grant, revocation TOCTOU, and a refusal that
left the mission `running`.

### Identity is one string, end to end

A session id minted by the orchestrator is passed to Firebreak
(`--session-id`, `--mission`, `--task`), which adopts it rather than minting its
own and writes an append-only JSON Lines `<sid>.session` record. A person
holding a systemd scope name or a `.session` file can get back to the mission.
Firebreak's `redacted_argv()` strikes credentials three ways: by position after
`--setenv`, by option name, and by value equality.

### The worker stopped burning the machine

Polling replaced with inotify (via ctypes) plus a 30-second fallback:

| | before | after |
|---|---|---|
| idle CPU | 0.128% of a core | 0.000% |
| context switches | 218 / 180s | 4 / 90s |
| write syscalls | 2880 / 180s | 1 |
| dirtied bytes | 225 MiB/hour | 0 |
| wake latency (median) | 0.447s | 0.0003s |

## What Phase 3 deliberately did NOT do

Held to the brief:

* No Claude Code, Grok, Cursor, or additional cloud providers.
* No credential broker. Credentials are still passed as environment through
  Firebreak's `--setenv`, redacted on every path that stores or prints them.
* **No egress enforcement.** `egress_allowlist` is recorded and reaches no
  filter. It is reported as `not_enforced` everywhere it appears.
* No approval prompt for anything the system cannot actually stop. A dialog
  over an unstoppable action is theatre, and theatre in a security surface
  teaches people to trust a control that does not exist.
* Cancel and Undo stayed separate verbs. Cancelling does not revert the
  workspace.

## The vocabulary, and why it is not one boolean

`enforced` / `partial` / `not_enforced` / `not_representable` /
`not_applicable` / `observed` are distinct and stay distinct. So do
`fully_mediated` / `partially_mediated` / `observable_only` / `not_observable`
for policy, and `DECLARED` / `APPROVED` / `REQUESTED` / `EFFECTIVE` /
`ENFORCED` / `OBSERVED` for a field's journey.

Three collapses were found by attacking the honesty surfaces themselves:

* `all([]) is True`, so every control with nothing to apply reported itself
  working. `account_mount: "enforced"` for a session that mounts no account is
  a claim about a mechanism that never ran. Unused fields are
  `not_applicable`, with a message saying what was not asked for.
* `_mediation_for()` hard-coded `path_masking` as not-relied-on, with a comment
  saying the caller would set it. No caller did — so a mission declaring
  `masked_paths` was never told masking reaches nothing, on the one surface
  built to disclose exactly that. And the egress caveat was attached only to
  the literal string `allowlist`, so a broader posture escalated for network
  access and then dropped the caveat.
* The validation run's enforcement map was a **constant**. Every receipt said
  `network_isolation: enforced` whatever posture the tests actually got. It is
  derived from the posture now, through the same table every other surface
  reads.
