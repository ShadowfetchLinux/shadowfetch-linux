# Phase 3.1 baseline — measured, not recalled

Recorded before any hardening change, at the tree the post-Phase-3 audit read.

```
branch    release/4.0.0
HEAD      e623c1382a41a0de0bad808621c7699c8f18e873
tag       phase3-audited            -> e623c13   (pushed)
branch    phase3-audited-e623c13    -> e623c13   (pushed)
remote    origin/release/4.0.0      -> e623c13   (0 ahead, 0 behind)
tree      clean
schema    SCHEMA_VERSION = 3
```

Phase 3 was 67 commits unpushed until this baseline. It is now on GitHub, and
the tag and branch above are the durable pre-hardening reference. They do not
move.

## Verifier behaviour today

Every row below is output from the real engine against a real database built by
the real `Store`, driven `queued -> running -> waiting-review`. Nothing is
inferred from documentation.

| case | `verify_chain()` | detected? | text exit | `--json` exit |
|---|---|---|---:|---:|
| valid database | ok=True chain_ok=True states=agrees anchor=agrees | n/a | 0 | 0 |
| modified event row | ok=False, "seq 4: content does not match its hash" | yes | 1 | **0** |
| deleted event (tail) | ok=False, anchor=truncated, states=disagrees | yes | 1 | **0** |
| **fabricated mission row** | **ok=True, states=agrees, problems: NONE** | **NO** | **0** | **0** |
| retry budget at the ceiling | ok=False, states=disagrees | after the fact | 1 | **0** |

Two facts fall out of that table.

**A fabricated mission verifies healthy.** `INSERT INTO missions(... state='completed')`
with zero events produces `ok=True`, verdict `agrees`, no problems, and exit 0.
The `predates_chain` exemption — added so migrated pre-v3 rows are not falsely
accused — is obtainable by an attacker simply by writing no events.

**`--json` returns 0 in every case, including the two where the text mode
correctly returns 1.** Any automation reading the JSON is told a tampered log
passed.

## Approval provenance today

Ten direct edits to the `approvals` table, each against its own freshly built
mission, with a control that passes first (an untouched approval is accepted):

| edit | result |
|---|---|
| `granted_by` -> 'somebody-else' | **ACCEPTED — not detected** |
| `method` -> 'forged' | **ACCEPTED — not detected** |
| `granted_at` -> 1999 | **ACCEPTED — not detected** |
| `expires_at` extended to 2099-12 | **ACCEPTED — not detected** |
| `expires_at` removed (never expires) | **ACCEPTED — not detected** |
| an already-EXPIRED approval revived | **ACCEPTED — not detected** |
| `revoked_at` cleared after a real revoke | **ACCEPTED — not detected** |
| `reason` rewritten | **ACCEPTED — not detected** |
| approval `id` rewritten | refused (no grant event names it) |
| scope changed to another provider | refused (scope digest mismatch) |

**8 of 10 undetected.** The grant event already records `subject`, `granted_by`,
`method` and `expires_at` — `find_approval()` compares `scope_sha256` and
nothing else. The evidence is in the chain, unread.

An earlier draft of this probe refused every case for the wrong reason (a scope
missing its workspace) and its control did not pass. Those numbers were
discarded. A probe whose control fails measures nothing.

## Retry budget today

With the mission at `failed` and `attempt` already at the published ceiling of 3:

* `Store.transition(mid, 'queued')` — **refused**: "retry budget exhausted (3 attempts)"
* `Store.finish_execution(mid, 'queued', None)` — **ACCEPTED**

`finish_execution()` calls `transition_allowed()`, which permits the
`failed -> queued` edge, and never consults `MAX_ATTEMPTS`. The budget is on one
path to that edge and not the other.

## Store.create() is not atomic

The mission row is inserted in one transaction and the `queued` event appended
by a separate `self.event()` call on a second connection. An interruption
between them leaves a mission row with no events — which is exactly the shape
the fabricated-row case above shows verifying as healthy.

## Gates at this commit

`make test` (620 unit tests + 60 adversarial attacks), `make source-gate` and
`make package-gate` all passed at e623c13 earlier in this session, and one real
`media_export` mission ran end to end with `audit verify` exit 0. The re-run
started for this baseline is recorded in PHASE3_1_TEST_RESULTS.md.

## Claims carried forward with a warning label

The Phase 3 worker performance figures (idle CPU 0.128% -> 0.000%, wake latency
1444x) were measured once, in this session, and were NOT independently
reproduced by the audit. They are treated as non-authoritative until remeasured
(Phase 3.1 Step 12).

## What this baseline is for

Phase 3 claimed trustworthy provenance. The measurements above say that a person
holding the mission uid can, today, without detection:

* invent a mission that never ran, in any state they like
* rewrite who approved a mission, by what method, and when it expired
* revive an expired approval and erase a revocation
* get a fourth attempt out of a three-attempt budget
* and have every one of those pass `audit verify --json` with exit 0

Phase 3.1 exists to close that list.
