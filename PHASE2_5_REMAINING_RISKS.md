# Phase 2.5 Remaining Risks

*What this phase did not close, each with an owner and a reason. Ordered by what
would hurt most.*

Every item here is also asserted somewhere: the sandbox table in
`test_sandbox_spec_audit.py` fails a build if a field's status drifts in either
direction, so nothing on this list can quietly start being claimed as a control,
and nothing off it can quietly stop being one.

---

## P1 — `egress_allowlist` enforces nothing

**Owner: Phase 4.** Firebreak has exactly two network postures: `none`
(`--unshare-net`) and `allow` (the host network, unfiltered). `allowlist`
collapses to `allow`. A provider approved for `api.openai.com` can reach
anything the host can reach, including `127.0.0.1`.

The hosts are recorded, bounded by the schema, refused on widening by `narrow()`
and `verify_invocation()`, and capped by the approved-provider policy — all of
which constrains what a provider may *declare*, and none of which constrains
where its packets go. **This must not be described to users as a control**, and
the shipped documentation now says so in three places.

A real allowlist needs a filtering proxy the sandbox is pointed at, or netfilter
rules in the network namespace. Both are Phase 4 work, and the brief for this
phase said explicitly not to start them.

## P1 — `masked_paths` enforces nothing

**Owner: Phase 4.** Firebreak has no masking flag. Same shape as above: declared,
schema-bounded, and the one field whose safe direction is inverted (an adapter
may only ADD masks), checked in both `narrow()` and `verify_invocation()` — and
reaching no mechanism.

## P2 — no syscall profile is even expressible

**Owner: unscheduled.** There is no schema property for one and no
`bwrap --seccomp` anywhere in Firebreak. A provider runs with the full syscall
surface of the sandbox user. This is the only row in the audit table marked *not
representable* rather than *not enforced*, and it is worth separating: the other
two have a place to go.

## P2 — `cpu_seconds` is per-process, so forking resets it

**Owner: Phase 4.** `RLIMIT_CPU` is inherited, not shared. Measured: six children
burned ~9s of CPU under a 2s cap and the run exited 0. A whole-session budget
needs a cgroup or a watchdog, not an rlimit. `TasksMax` bounds how many children
there can be, so the multiplier is bounded but real.

## P2 — a cancelled turn's partial output parses as a completed one

**Owner: Phase 3.** Now that cancellation preserves partial output (it used to
write a zero-byte log), an adapter's synthesised terminal event reads that log as
a successful turn. Nothing in a byte stream distinguishes "the process finished"
from "the process was killed".

On the real path this is harmless: `run_process` raises `Cancelled` before
`parse_stream` is consulted. It becomes a live hazard the moment anything shows a
person their partial output, which is a natural next feature — and that feature
must supply the fact itself rather than asking the stream. Asserted in both
cancel tests so the assumption is visible rather than implied.

## P2 — the registry is cached for the worker's lifetime

**Owner: Phase 3.** A newly approved provider needs a worker restart. More
sharply: `ProviderRegistry` memoises one adapter instance per manifest, so an
adapter storing per-turn state on itself would leak it into the next person's
mission.

Closed by contract rather than by machinery:
`test_parse_stream_does_not_mutate_the_adapter` runs for every provider. Adding
an `end_mission()` lifecycle method was considered and rejected — no shipped
provider needs it, both satisfy the contract unchanged, and a warm cache can be
keyed by the mission id in the request instead.

## P3 — approval is per-machine, not per-mission

**Owner: Phase 3.** Nothing scopes a provider's approval to a workspace, a person
or a time window. An approved provider is approved for every mission on the
system. This is the right granularity for a single-user workstation and the wrong
one for anything else.

## P3 — the policy is protected by dpkg file ownership, not by a signature

**Owner: unscheduled.** `approved.json` is trusted because
`shadowfetch-missions` owns the file and dpkg refuses to let another package
overwrite it. That is a real mechanism — it is the same one protecting the
adapters and the schema — but it is not a signature: anything running as root can
edit the file, and the digests inside it would then be re-derived rather than
re-reviewed. Signing the policy and verifying it at load would raise this to
"root must also hold a key".

## P3 — no live Codex verification

**Owner: whoever configures a dedicated account.** See
`PHASE2_5_TEST_RESULTS.md`. The CLI is installed; Mission Control
authentication is not configured, and this phase does not alter credentials.
Every Codex path is covered by unit tests and recorded fixture streams. The same
applies to `account_mount`, whose enforcement is verified by source reading only.

## P3 — no idle timeout on a stalled provider

**Owner: Phase 3.** A model server that heartbeats but never generates runs until
the whole mission budget is spent — up to two hours. The deadline does eventually
stop it, and partial output now survives that path, but nothing notices sooner.

## P3 — `usage` from a provider is written into the receipt unchecked

**Owner: Phase 3.** Carried forward from `PHASE2_REMAINING_RISKS.md` §8 and
reproduced on the real path during this phase: a non-dict `usage` reaches
`Executor.inferences[0]["usage"]` and the receipt. Harmless today because neither
shipped provider reports usage often; a token-streaming server reports it on
every turn.

---

## What is NOT on this list, and why

* **"A malicious package could add a provider."** It cannot: it would have to
  overwrite a file `shadowfetch-missions` owns, and the manifest digest is
  pinned. Attack 01 of the adversarial pass.
* **"An adapter could ask for more than it declared."** It cannot, at three
  independent points: `narrow()`, `verify_invocation()`, and the policy ceiling.
  Attacks 03, 04, 05, 13, 14.
* **"An adapter could run a different program."** Closed in this phase — it was
  open until `43372e4`, and only the adversarial pass found it. Attack 15.
* **"The environment could redirect provider discovery."** Removed. Attack 10.
