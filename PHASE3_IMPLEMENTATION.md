# Phase 3 — Mission Control as an orchestration control plane

*Current as of **Phase 3.1** on `release/4.0.0` (schema v4). Where Phase 3.1
changed something this document already described, the current behaviour is what
is written and the superseded behaviour is named as the defect it was — this file
is a record of what the code does, not of what a plan intended.*

Phase 2.5 left Mission Control able to run an agent through a provider seam.
It could not tell you afterwards who authorised the run, which executable
actually started, what the sandbox was asked for versus what it applied, or
whether the state in the database was one the engine had ever reached.

Phase 3 is that record. The invariant it was built against:

> No mission execution should occur without a persistent identity, a valid
> state transition, a persisted approval where required, and an audit trail
> sufficient to reconstruct what happened.

## What changed

### Schema: v2 → v3 → v4

`PRAGMA user_version` migration, applied inside one transaction. (The first
draft used `executescript()`, which issues an implicit COMMIT and made the
migration non-atomic; an interruption test caught it.)

Eight new tables at v3, all correlated by `mission`, `task_id`, `session_id`:

| table | what it records |
|---|---|
| `tasks` | the units a mission decomposes into, with their own state machine |
| `agent_sessions` | one provider execution: which executable, which trust, requested vs effective sandbox, per-field enforcement, credentials requested vs granted |
| `approvals` | scope, granter, method, grant/expiry/revocation instants |
| `tool_executions` | tool actions a provider reported, arguments digested then redacted |
| `test_runs` | command, executable, posture, guard state, exit code, log |
| `git_changes` | structural before/after of the workspace |
| `reviews` | the human decision that closed the mission |
| `artifacts` | what the run produced, by path and digest |

`events` gained `task_id`, `session_id`, `tool_execution_id`, `actor`,
`prev_hash`, `hash`.

**v4 adds no table.** It adds one chained event, `legacy-missions-pinned`, written
immediately after `start_chain()` and naming every mission that had no events at
all at the moment of upgrade. `verify_states()` used to excuse *every* event-less
mission as pre-chain — an inference from ABSENCE, which an attacker obtains by
writing nothing, so a fabricated row with `state='completed'` verified healthy.
The pin writes the same fact down positively, once, where the hash chain protects
it. It is trust-on-first-use and says so; it is not written when it would name
nothing, because a pin that grants no exemption is an event everybody counts and
nobody reads.

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

**`Store.create()` is one transaction too.** The mission row and its first
`queued` event used to be written on two different connections, so an
interruption between them left a real mission with no events at all — the exact
shape a fabricated row has, and the reason a verifier could not tell the two
apart. Atomic creation is the precondition that lets `verify_states()` treat an
unexplained event-less row as a finding rather than excusing it.

The same lesson was applied three more times during adversarial testing:

* The three-attempt retry budget lived only in `Store.retry()`, so an in-process
  caller got a fourth attempt by calling `transition()` directly. Moving it into
  `transition()` then left `finish_execution()` reaching the same edge on its
  own. `requeue_refusal(event, attempt)` is now the single guard, keyed on the
  **edge's event name** rather than on which verb is asking, and both verbs ask
  it. A refusal appends a `retry-budget-exhausted` event that commits while the
  mission row is left untouched — recorded, then raised, because "no event"
  reads exactly like "nobody ever tried".
* `Store.cancel()` read the state in one transaction and wrote the flag in
  another, so in 97/100 trials it accepted a stop request for a mission that had
  already reached `waiting-review`; it is now one transaction with the state
  re-read inside it, and the event records `actor=ACTOR_USER`, because a person
  is what produces it.
* `grant_approval()` would chain an event for a mission that does not exist —
  real, hashed, and invisible, because `Store.events()` checks the mission
  first. A pre-plantable approval is worth refusing on its own.

### The audit log is hash-chained and externally anchored

Every event is hashed over canonical JSON of its own fields plus its
predecessor's hash. **`Store._append()` is the only `INSERT` into `events` in the
running engine, with one deliberate exception**: the v1→v2 migration writes its
`schema-migrated` row with a raw INSERT, because it runs before the chain columns
exist. `start_chain()` runs a moment later in the same migration and pins it with
every other pre-chain row. That exception is stated the same way in
`docs/AUDIT_EVENTS.md` §2; an unqualified "the only INSERT" is a claim the tree
contradicts, and the whole point of this surface is not making those.

A chain proves no row was **altered**. It cannot prove no row was **removed
from the end** — delete the last three events and every survivor still
verifies. So each event's head is mirrored to journald under
`SYSLOG_IDENTIFIER=shadowfetch-audit`, which is root-owned while the worker is
not, and `audit verify` compares the journal against the database.

Four defects found by attacking this and fixed:

* The anchor compared `max(seq)` only, so a rewrite deep in the log was
  detected for exactly as long as the rewritten row stayed newest — one honest
  append later, the heads agreed again over a row that said `REWRITTEN BY THE
  ATTACKER`. The journal still held the pre-tamper hash. Nothing read it.
  Every mirrored seq is compared now, and the **earliest** line for a sequence
  number wins, because `journalctl` emits oldest-first and anything after the
  first line arrived later. A second, differing line for one `seq` is reported
  as a conflict rather than resolved: picking a winner would mean deciding which
  forgery to believe.
* `audit-mirror.json` is local bookkeeping owned by the same uid that writes
  the events, and `verify_chain()` branched on its failure count **first**.
  Truncating the log and then writing `{"failures": 1}` turned `ok=False` into
  `ok=True` and replaced "2 events were removed from the end of the log" with
  "the mirror has failed once". Degradation is reported *alongside* the
  comparison now; it can add a caveat and it can never remove a finding.
* The chain id is minted into an events row, so deleting the genesis and
  re-chaining produced a log that verified clean — the new id simply had no
  journal history, and absence of evidence read like a pass. Every mirrored line
  now carries a **store identity**, `sha256(absolute db path)[:16]`, which is the
  one name in the record the database cannot restate about itself. Entries this
  store mirrored under an earlier chain id stay attributable to it, and a
  re-minted chain is a conflict rather than an absence.
* `verify_chain()` raised `TypeError` out of `canonical()` on a `detail` SQLite
  had accepted as bytes. It failed closed, but an operator got a traceback with
  no verdict and `--json` produced nothing parseable. A non-text `detail` is now
  reported as a problem in the ordinary way.

### The audit exit code is a property of the result, not of the rendering

`audit_exit_code(report)` computes the ladder — `0` intact, `1` tampered, `2`
unverified-or-degraded — from the report and nothing else, **before** anything is
printed, and fails closed on a report with no `ok` at all. It used to sit inside
`if not args.json:`, so the caller most likely to pass `--json` — a CI gate, a
cron check, the LaunchAgent pattern this project already uses — was told a
tampered log had passed. `2` is not a pass: it means truncation remains
undetectable.

### The mission rows are replayed against the log

The chain covers events. The `missions` table is not chained, so
`UPDATE missions SET state='completed'` was indistinguishable from work that
ran — and the engine would then narrate the forged state back into the log,
appending *"a human changed their mind about accepted work"* for a mission that
had never run. `Store.verify_states()` replays each mission's event trail
through `MISSION_TRANSITIONS` and reports both impossible edges and a final
state no event explains. It needs no new storage.

It **classifies** rather than returning a boolean, because the five outcomes call
for different actions: `VALID_CURRENT`, `LEGACY_PRECHAIN` (named in the v4 pin,
or its first event precedes the genesis — and it says which), `STATE_DIVERGENCE`
(a state written without an event), `CORRUPTED_HISTORY` (an edge the table
forbids) and `MISSING_HISTORY` (a row the log has never heard of). The chain's own
verdict is kept separately as `report["chain_ok"]`, and `audit verify` prints a
`mission states` line beside `chain`, so neither claim borrows the other's
credibility. It detects; it does not prevent and it does not repair.

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
non-date expiry treated as valid (now refused at grant time, and treated as
expired if it reaches the table another way), a forged approval row accepted
without a witness, a scope widened after grant, revocation TOCTOU, and a refusal
that left the mission `running`.

**The approval record is witnessed as a whole.** Enumerating fields at the
comparison site is how this went wrong: the grant event already carried subject,
granter, method and expiry, and the check compared `scope_sha256` alone — so
eight of ten direct edits to the `approvals` table went undetected, including
reviving an expired approval. `APPROVAL_WITNESSED_FIELDS` is one list, the grant
event carries `record_sha256` over all of it, and `find_approval()` recomputes
the same digest from the stored row, so a field added later is covered by both
sides or by neither. `revoked_at` is deliberately outside that digest —
revocation is legitimately mutable and has its own chained event — and revocation
is therefore read from the **chain**, so clearing the column with SQL no longer
revives an approval. `revoke_approval()` also stopped overwriting the grant's
`reason`: that field is part of the grant's provenance, and letting a revoke
rewrite it made an honest revocation look like tampering.

### Identity is one string, end to end

A session id minted by the orchestrator is passed to Firebreak
(`--session-id`, `--mission`, `--task`), which adopts it rather than minting its
own and writes an append-only JSON Lines `<sid>.session` record. A person
holding a systemd scope name or a `.session` file can get back to the mission.
Credential **identities** cross the same boundary as `--credential-env NAME`,
intersected with the invocation's `SandboxSpec` so an adapter's narrowing is
honoured rather than decorative; Firebreak is what turns each name into bwrap
`--clearenv` plus one `--setenv`. Its `redacted_argv()` strikes credentials three
ways: by position after `--setenv`, by option name, and by value equality.

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
* No credential broker. Credentials are still delivered as environment —
  `--credential-env` from Mission Control, `--setenv` from Firebreak into bwrap —
  redacted on every path that stores or prints them.
* **No egress enforcement, and no path masking.** `egress_allowlist` and
  `masked_paths` are recorded and reach no filter and no mount. Both are reported
  as `not_enforced` everywhere they appear. Firebreak has `--egress-host` and
  `--mask-path` and calls both RECORDED ONLY in its own `--help`; Mission Control
  passes neither. The missing piece is a mechanism, not a flag — saying "Firebreak
  has no masking flag", as several surfaces in this tree once did, pointed the
  reader at the wrong fix.
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
