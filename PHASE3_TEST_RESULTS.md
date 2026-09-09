# Phase 3 — test results

## Suites

| suite | tests | subject |
|---|---:|---|
| `test_schema_v3.py` | 33 | migration v2→v3, atomicity, the eight tables |
| `test_state_machine.py` | 25 | every edge and every refusal in `MISSION_TRANSITIONS` |
| `test_audit_chain.py` | 22 | hashing, canonical form, `verify_chain`, the anchor |
| `test_correlation.py` | 21 | mission ↔ task ↔ session ↔ tool ids across surfaces |
| `test_approvals.py` | 37 | scope, expiry, revocation, witness, the gate |
| `test_cancellation.py` | 13 | request vs stop vs undo; cancel is not undo |
| `test_records.py` | 20 | tool executions, test runs, git changes, reviews |
| `test_worker_loop.py` | 16 | inotify wakeup, fallback, reconciliation, recovery |
| `test_stream_and_receipt.py` | 25 | event stream and receipt v2 |
| `test_control_surface.py` | 39 | the desktop's contract with the engine |
| pre-existing missions suites | 272 | providers, redaction, sandbox spec, migration |

`make test` runs all of them plus the four adversarial modules.

## Adversarial suites — `tools/attacks/`

These assert what the system **refuses**. A unit test written against an
implementation structurally cannot notice a guard the implementation never had;
these were written against the *claims*.

| module | attacks | result |
|---|---:|---|
| `attack_approval.py` | 20 | 20 PASS |
| `attack_integrity.py` | 15 | 15 PASS |
| `attack_lifecycle.py` | 7 | 7 PASS |
| `attack_concurrency.py` | 18 | 18 PASS |

**60/60.** They did not start there. First run: approval 12/20, integrity
10/15, lifecycle 5/7, concurrency 13/18 — 20 findings, every one real.

### The findings that mattered most

**Provider-id laundering — a complete approval bypass.** Provider resolution
existed twice, and the Executor knew a fallback the approval gate did not. A
mission naming its provider only in `config["runtime"]` passed the gate
un-evaluated and then ran. Fixed with one `mission_provider_id()`.

**`audit-mirror.json` was a suppression switch.** Truncate the log, then write
`{"failures": 1}` into a file the same uid already owns: `ok=False` became
`ok=True`, "2 events were removed from the end of the log" became "the mirror
has failed once", and the CLI printed `chain intact`, `head seq 4` and
`journal head seq 6` on three consecutive lines without comparing them.
Deleting the file did *not* help the attacker — which is what made writing it
worth reporting.

**Rewrite-then-cover.** The anchor compared one row, so a rewrite was
detectable only until the next honest append. The journal still held the
pre-tamper hash for the rewritten seq; nothing compared it.

**A forged mission state.** `UPDATE missions SET state='completed'` was
accepted, and `transition(mid, 'undone')` then appended *"a human changed their
mind about accepted work"* for a mission that had never run — the audit trail
asserting something that did not happen. `verify_chain()` was right to stay
silent (it verifies events, not states); the gap was that nothing else checked.

**The retry budget was in the verb, not on the edge** — the exact defect Phase 3
had already fixed for `state` itself.

**`Store.cancel()` was not atomic.** 97/100 trials accepted a stop request for
a mission already in `waiting-review`, appending `cancel-requested` *after* the
terminal event.

**A credential in a tool name was stored verbatim** while `args_redacted` in the
same row was scrubbed.

**Five honesty findings**, which matter because honesty is this phase's central
claim: a vacuously `enforced` field, a caveat that never fired, an egress
caveat attached to one literal string, a constant enforcement map on every test
run, and a session record disagreeing with Firebreak's own map.

### Mutation testing

Ran against the control-surface and policy suites. Eight mutations survived,
including a heading that compared a value with itself and a caveat widget that
could be deleted without failing a test. Tests sharpened until they died.

## Environment limits, stated rather than hidden

* The external anchor needs journald and a readable journal. Where
  `journalctl` is absent or the user cannot read it, the verdict is
  `unverified` — reported as such, never folded into `ok`.
* Attack modules run as the mission uid. Every claim they make about
  containment is bounded by that: a gate with the agent's own privileges is
  worth what a file the agent can create is worth, and the modules say so.
* No shipped provider emits `data['tool']`, so the tool-execution ingestion is
  declared and provider-neutral but nothing that ships exercises it. The
  malformed-input attacks feed it directly.
* Only `offline-media` and `codex` are wired. **No live cloud provider
  integration has been exercised end-to-end in this phase.**
