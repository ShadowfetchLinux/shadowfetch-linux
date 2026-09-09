# Phase 3.1 — test results

All three gates run at `795becf` on `release/4.0.0`, build box
(AMD Ryzen 7 5700G, Linux 7.1.5, Python 3.12.3).

| gate | result |
|---|---|
| `make test` | **exit 0** — 640 missions tests + every other package suite + all five adversarial modules |
| `make source-gate` | **`SOURCE_GATE_PASSED`** (includes gitleaks over full git history) |
| `make package-gate` | **`PACKAGE_GATE_PASSED`** — 16 packages, Debian 13 dependency solve and runtime install |

## Unit suites

620 → **640** missions tests. The 20 new ones are `tests/test_phase31.py` (18)
plus two in `test_audit_chain.py` for the journald ordering and uid rules.

`test_phase31.py` covers what the phase changed, by name:

* atomic creation, including a **fault injection** that explodes `_append` inside
  `create()` and asserts no mission row survives
* all five mission classes: `VALID_CURRENT`, `MISSING_HISTORY`,
  `STATE_DIVERGENCE`, `LEGACY_PRECHAIN`, and a pin read out of a broken chain
* the legacy pin is written even when empty; a second pin is reported
* the retry budget refuses through **both** `transition()` and
  `finish_execution()`, records `retry-budget-exhausted`, and still allows an
  attempt under the ceiling
* every approval provenance field is witnessed; `revoked_at` cleared does not
  revive; a revoke no longer rewrites the grant's `reason`
* the exit ladder is derived from the report alone and **fails closed**

That suite exists because a check agent observed the phase was carried entirely
by adversarial modules and no unit test named any of the new code. An attack that
stops finding anything looks exactly like an attack that passes; a unit test that
stops passing does not.

## Adversarial suites — 81 scenarios, all passing

| module | scenarios | result |
|---|---:|---|
| `attack_approval.py` | 20 | 20/20 |
| `attack_integrity.py` | 15 | 15/15 |
| `attack_lifecycle.py` | 7 | 7/7 |
| `attack_concurrency.py` | 18 | 18/18 |
| **`attack_verifier.py`** (new) | 21 | 21/21 |

`attack_verifier.py` attacks the audit verifier itself, and it opened at
**18/21**. All three failures were in code written earlier in this same phase to
close the fabricated-mission finding:

1. a pinned mission was exempt from replay **forever**, and the pin publishes its
   ids in plaintext
2. a forged unchained pin **deleted the mission finding** while the chain break
   printed above it
3. skipping the empty pin left the slot **open forever** for a later pin

It then found two more sharing one root — a hand-chained forged tail that one
honest append could cover — and my first fix for that consulted
`audit-mirror.json`, a file the attacker owns, which restored `ok=True`. That is
the suppression-switch shape for the third time in this codebase, and that time I
built it.

Unlike `attack_integrity.py`, none of its note text is hard-coded: every sentence
is built from values measured in that run. That was the defect being fixed in the
older module, where six notes still opened with "FINDING" over defects the engine
had closed.

Stability: three consecutive runs, identical results, ~25s.

## Worker measurement (Step 12)

Reproducible via `tools/probes/worker_measure.sh`, three independent 20-second
idle windows:

```
sample 1: cpu 0 ticks = 0.0000% of a core | vol ctxt +0 | write syscalls +0 | write_bytes +0
sample 2: cpu 0 ticks = 0.0000% of a core | vol ctxt +0 | write syscalls +0 | write_bytes +0
sample 3: cpu 0 ticks = 0.0000% of a core | vol ctxt +0 | write syscalls +0 | write_bytes +0
wake latency: n=5  median 0.0029s  max 0.0054s
```

The wake latency is an order of magnitude larger than the Phase 3 figure because
this measurement includes mission creation. The Phase 3 "1444× improvement" claim
compared against a baseline that was not remeasured and **has been withdrawn**.

## Not hidden

* **4 tests skipped**, all environment-gated (journal readability and
  bubblewrap availability). They skip rather than pass falsely.
* The installed Firebreak on this box is **3.0.0-1** and does not match the
  branch. The sandbox enforcement table describes the repo's 4.0.0 Firebreak.
* **No live cloud provider was exercised.** `offline-media` and `codex` are the
  only wired providers.
* One residual is documented rather than fixed: on a host with no readable
  journal, a rewritten migration pin still grants a permanent exemption.
* The domain tables (`tool_executions`, `agent_sessions`, `test_runs`) remain
  unchained and directly editable. See PHASE3_1_REMAINING_RISKS.md.
