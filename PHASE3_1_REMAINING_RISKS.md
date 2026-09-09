# Phase 3.1 — remaining risks

The success criterion for this phase was:

> A normal user who can tamper with Mission Control's local files should not be
> able to rewrite the core provenance story — what mission existed, what history
> occurred, who approved it, or whether the audit is original — without
> Shadowfetch detecting the inconsistency.

That is now true for the four named provenance questions. It is **not** true for
everything, and this document is the list of what a normal uid can still do.
Every line was measured, not reasoned about.

## What is now detected

| attack | before | after |
|---|---|---|
| fabricate a mission with no events | ok=True, exit 0 | `MISSING_HISTORY`, exit 1 |
| edit a pinned legacy mission | ok=True, exit 0 | `STATE_DIVERGENCE`, exit 1 |
| forge an unchained legacy pin | reclassified the row, verdict `agrees` | pin not honoured, reported |
| append a second legacy pin | exit 1 → exit 0 | refused by count, exit 1 |
| delete the genesis and re-mint the chain | `problems=[]`, "chain intact" | anchor `conflict`, names the old chain id |
| rewrite an event and forge the journal line | detection erased | per-seq `conflict`, both hashes named |
| append a forged tail, then one honest append | ok=True, exit 0 | unmirrored seq inside the journal window, exit 1 |
| rewrite `granted_by` / `method` / `granted_at` / `expires_at` / `reason` | **8 of 10 undetected** | **0 of 10** |
| revive an expired approval | accepted | refused |
| clear `revoked_at` after a revoke | accepted | refused from the chain |
| exceed the retry budget via `finish_execution()` | accepted | refused and recorded |
| any of the above under `--json` | exit 0 | same exit code as text |

## P1 — what a normal uid can still do

**Receipts are rewritable, including their own audit block.** `receipt.json` is a
file the mission uid owns. It embeds an `audit` section asserting the chain was
intact when it was written, and nothing verifies that assertion later. A receipt
is a **rendering of evidence, not evidence**; the database and the chain are the
evidence. Undetectable.

**The domain tables are not chained.** `agent_sessions`, `tool_executions`,
`test_runs`, `git_changes` and `tasks` can be edited directly — including a tool
call's `decision`, its `approval_id` and its `exit_status`. Only `missions` and
`approvals` are witnessed. The chained `tool-observed` event records the tool's
name and would not disagree. Undetectable. This is the largest remaining gap and
is the natural next piece of work.

**A truncation that also flushes the journal read window.** `read_head` reads the
last 5000 matching entries. Truncate the events table, then replay the surviving
seqs with their true hashes until the forged region falls out of that window, and
no hash conflicts arise because the replayed hashes match. Undetectable.

**Same-uid journal forgery is not attributable.** The mirror runs as the mission
user, so an attacker holding that uid writes journal entries carrying the same
`_UID` as the engine. Phase 3.1 switched `read_head` to `-o json` to use
journald's trusted fields, which gives a non-forgeable **ordering** and makes a
cross-user write visible — but it cannot tell the engine from an attacker at the
same uid. Only a privileged sink could, and this phase was told not to add one.

**Journal injection is a denial of service against the audit verdict.** One
forged line for a seq past the head makes an untouched database report a
disagreement. The message no longer accuses the database, but the report still
goes non-zero. An attacker cannot forge a clean bill of health this way; they can
deny one.

**Firebreak `.session` records are rewritable and relocatable.**
`SHADOWFETCH_FIREBREAK_STATE` moves the audit directory, and what lands there can
be deleted. The MCP gate's `_session_recorded()` is one `is_file()` call — it
reads nothing, so it records `observed`, not `verified`. Undetectable.

**On a host with no readable journal, a rewritten migration pin grants a
permanent exemption.** The pin's own rewrite is caught only by the anchor.

## Still declared and NOT enforced (unchanged from Phase 3)

* `egress_allowlist` reaches no filter. A mission with `network=allowlist` has
  the host's network, including loopback services and abstract unix sockets.
* `masked_paths` masks nothing. Firebreak's `--mask-path` **exists and is
  record-only** — the earlier claim that there was no such flag was false in its
  reason though right in its conclusion.
* `syscall_profile` is not representable: no schema property, no `--seccomp`.
* `cpu_seconds` is `RLIMIT_CPU`, which is **per-process**, so a provider that
  forks gets a fresh budget for every child.
* No live cloud provider has been exercised end to end.

## Environment

The Firebreak installed on the build box is **3.0.0-1**, a bash script with no
`systemd-run`, no `--clearenv`, no rlimits, and `--ro-bind / /`. Every ENFORCED
row in the sandbox table is true of the repo's Firebreak 4.0.0 and **not** of the
binary currently installed. The engine has no version or capability check for the
Firebreak it invokes, so the mismatch surfaces as an unrelated downstream error.

## Performance claims

The Phase 3 figures were measured once. They were remeasured for this phase with
a committed script (`tools/probes/worker_measure.sh`), three independent 20s idle
windows on the build box: **0.0000% of a core, 0 context switches, 0 write
syscalls, 0 bytes dirtied**. Wake latency measured **0.0029s median (n=5)** — an
order of magnitude larger than the figure quoted in Phase 3, because this
measurement includes mission creation. The "1444× improvement" claim compared
against a baseline that was not remeasured and **has been withdrawn**. What is
demonstrably true: the worker is event-driven rather than polling.


## Step 16 — the independent final attack pass

Four independent attackers, each on a distinct angle, run against the hardened
tree. They found **six** things. All six are fixed; the two most serious are
recorded here because both were introduced or missed by this phase itself.

### Fixed: the anchor was read through PATH (CRITICAL)

`sf_audit` invoked `journalctl` by bare name. A normal desktop uid controls
`PATH` — and on this very box `~/.local/bin` is user-writable and precedes
`/usr/bin`. A shadowed `journalctl` moved a truncated log from
`exit 1 / anchor 'truncated'` to `exit 0 / anchor 'agrees'`, printing
*"chain intact, external anchor agrees"*.

That is not the denial of service already documented. It is a **forged clean
bill of health**, obtained through the one mechanism the whole anchor exists to
provide, by a user with no privilege at all. It is now resolved from a fixed
list of absolute paths and run with a clean environment; if no journalctl is
found the anchor reports itself unreadable, which is exit 2 and not a pass.
Verified with the real attack (`tools/probes/path_attack.py`).

### Fixed: the retry budget trusted numbers the attacker controls (HIGH)

Two ways through. `transition(mid, "queued", attempt=0)` handed the guard the
**caller's own** counter, and `attempt` is an unwitnessed column, so resetting it
bought unlimited retries. `Store.attempts_taken()` now counts the chained
`retry-queued` events and takes the **higher** of that and the column — an
attacker can lower the column and cannot lower the chain.

### Fixed: the store binding was largely illusory (HIGH)

`store_identity()`'s docstring said a copied database "will have no journal
history". `read_head()` filtered by chain id alone, so a byte-for-byte copy at a
new path verified clean and a re-mint was defeated simply by relocating the
database. Lines mirrored by a different store are no longer adopted as this
store's own.

Also fixed: `audit verify --json` — the flag written *after* the subcommand,
where anyone would naturally put it — was not recognised as JSON mode at all.

### The harnesses had to change with it

Three attacks blinded the anchor by emptying `PATH`. That no longer works, which
is the point. They now empty the absolute-path candidate list, and carry that
patch into the CLI child process — the simulation had been stopping at the
process boundary, so the child was quietly reporting a readable anchor.

### Confirmed still open, and worse than first described

**Migration trust-on-first-use launders fabricated history.** An attacker who
seeds fabricated `completed` missions with no events into a genuine *pre-v4*
database **before its first 4.0.0 run** gets the engine to pin those rows as
authentic pre-chain history. The pin is then a real engine-appended, real
engine-mirrored event; the chain and the journal are never touched, and verify
reports `exit 0 / states agrees / anchor agrees` **with a fully working
journal**. The documented claim "fabricate a mission with no events →
MISSING_HISTORY, exit 1" holds only for a database that is already v4.

This is the honest ceiling of trust-on-first-use, and `pin_legacy_missions()`
says so in its own docstring — but the risk was understated here and is
corrected now. Closing it needs provenance from before this build existed, which
by definition does not exist; the practical mitigation is to upgrade a database
on a host the operator controls, and that is an operational instruction, not a
mechanism.

**A deleted mission row orphans its events silently.** `verify_states()` replays
only missions that still exist, so deleting the `missions` row of a mission that
really ran — leaving its chained and mirrored events in place — passes at exit 0.
Making a mission disappear is undetected; inventing one is not.

**A forged approval is honoured at runtime on a journal-less host.**
`require_approval` trusts the local chain and never consults the anchor, so a
self-consistent forged `approval-granted` tail plus a matching row is executed.
On a journaled host the later `audit verify` catches it as an anchor conflict.

## Recommended Phase 4 first commit

**Chain the domain tables**, starting with `tool_executions`. It is the largest
undetectable gap, the receipt already reprints those rows as fact, and the
mechanism — a witnessed digest compared at read time — is the one Phase 3.1 has
already built twice and tested. Egress enforcement remains the largest gap
between what is *declared* and what is *applied*, and should follow immediately.
