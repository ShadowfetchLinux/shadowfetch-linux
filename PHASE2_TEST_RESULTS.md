# Phase 2 — Test results

Every figure is literal output from the build host. Baseline for comparison is
`PHASE2_BASELINE.md`: `make test` exit 0 with **487** unittest tests.

---

## Validation strategy

Three kinds of evidence, because unit tests alone would not have caught what
this phase actually got wrong:

1. **Behaviour preservation.** The 4.0.0 suites must keep passing, and where a
   test pinned the removed coupling it was adapted to assert the same *safety
   property* through the new seam — never deleted, never weakened.
2. **The architectural proof, executed.** A third provider added as data plus an
   adapter, with the protected files hashed before and after.
3. **Adversarial attack, executed.** Each of the ten review questions answered by
   *trying to do the thing*, not by reading the code.

---

## Suite totals

| Suite | Result |
|---|---|
| `packages/shadowfetch-missions/tests` | **229 passed, 1 skipped** |
| `packages/shadowfetch-control-center/tests` | **50 passed** |
| `tools/tests` | **162 passed** |
| `packages/shadowfetch-fireline` (script suites) | **56 + 20 passed**, `test_firebreak_4` OK |
| `packages/shadowfetch-defaults`, `firewatchd`, `fireproof`, `hwscan`, `phoenix` | unchanged from Phase 1, all passing |

Within the missions suite:

| Group | Tests |
|---|---|
| pre-existing mission behaviour | 58 |
| schema migration (new) | 13 |
| provider conformance (new) | ~60, parameterised over every registered provider |
| shared redaction (new) | 59 |

`make test` exits **0**, with **687 unittest tests** across 9 suites plus 95
script assertions (`test_fireline_mcp` 56, `test_fireline_privilege` 20,
`test_firebreak.sh` 19). The baseline was 487, so Phase 2 added **200 tests**.

**No test was deleted or weakened to obtain a pass.**

---

## Tests adapted, and why

Four assertions pinned the coupling this phase removed. Each was adapted so the
same safety property is asserted through the new seam, and each is called out
here because "I changed a test" deserves scrutiny.

| Test | Pinned | Now asserts |
|---|---|---|
| 25 mission tests faking `Executor.codex` | the provider-named method | the same fake on `agent_turn`, every assertion unchanged |
| `test_report_requires_explicit_cloud_permission` | the string "explicit network" | unchanged — the **provider's** refusal was reworded to keep it |
| `test_legacy_provider_is_not_silently_sent_to_cloud` | "retired provider" for an unknown runtime | unchanged — `execute()` now treats an unrecognised runtime as a *conflicting claim*, restoring the original semantics |
| 3 UI tests asserting `--runtime codex` / `--runtime offline` | the UI knowing which provider does what | the fixture supplies a real capabilities document, so media gets no network control **because its provider declares none**, and a cloud provider demands consent **because it declares that it does** |

The last row is the important one: those tests are now stronger, because they
exercise the registry-driven path instead of a hard-coded mapping.

---

## The architectural proof

```
════ 1. fingerprint the files a new provider must NOT require editing ════
   sf_missions.py, missions_page.py, tools/providers/validate_manifest.py

════ 2. add a third provider: one manifest + one adapter, no code edits ════

════ 3. the registry discovers it from data alone ════
   providers: ['codex', 'example-agent', 'offline-media']
   who can do code_change: ['codex', 'example-agent']
   example-agent available: True

════ 4. THE INVARIANT: same capability, different provider ════
   CodeChange + codex          -> code_change via codex
   CodeChange + example-agent  -> code_change via example-agent
   MediaExport + example-agent -> Example Agent does not perform media export

════ 5. both rows persist capability and provider separately ════
   via codex  |code|code_change|codex
   via example|code|code_change|example-agent

════ 6. did any protected file change? ════
   ✅ Mission Control, the UI and the gate are byte-identical.
```

Re-run unchanged after the adversarial and documentation passes.

---

## Behaviour preservation, executed

**A real media mission, end to end**, against the 4.0.0 Firebreak:

```
state: waiting-review | capability: media_export | provider: offline-media | error: none
events: queued running checkpoint-started checkpoint-created
        process-started process-finished (probe/encode/verify per input)
        export-verified ... waiting-review
✅ 01-tone.wav    192078 bytes, decodes
✅ 02-clip.mp4      6015 bytes, decodes
leftover probe scratch files: 0
```

**The capabilities contract**, checked key by key against the recorded baseline:

```
baseline keys present : 23 / 23
MISSING (regressions) : none
added by Phase 2      : 60 keys
```

**The gate, live:**

```
$ make source-gate
PASS: provider manifests validated: codex, offline-media
PASS: Gitleaks Git history
SOURCE_GATE_PASSED
```

---

## Migration, executed

A database built with the **verbatim 4.0.0 schema** containing one mission in
every state 4.0.0 could produce, plus one row with an unrecognisable kind and
runtime:

```
rows before: 8  readable after: 8
unreadable after migration: none
rows whose original fields changed: none
user_version: 2
unrecognised legacy row derived as: (None, None)   (NULL = not guessed at)
...and it is still listable: True
```

13 dedicated migration tests cover empty, existing-4.0.x, queued, completed,
pending-review and failed databases, idempotence, and refusal of a
newer-schema database.

---

## Adversarial architecture review

Each question answered by attempting the attack.

| # | Question | Answer |
|---|---|---|
| 1 | Can adding a provider still require modifying generic execution code? | **NO** — 0 provider-identity branches in `sf_missions.py`; third provider added with it byte-identical |
| 2 | Can a provider obtain undeclared credentials? | **NO** — refused via `narrow()`, via a scratch-built spec, and via the env allowlist |
| 3 | Can a provider silently request broader network than it declares? | **NO** for widening. The allowlist itself is *not* enforced by the sandbox — see risks |
| 4 | Can an invalid manifest reach runtime? | **NO** — absent from `ids()`, `get()` fails closed, error surfaced |
| 5 | Can an old mission become unreadable after migration? | **NO** — 8/8 readable, zero fields changed |
| 6 | Can provider stream garbage corrupt Mission Control state? | **NO** — 11 hostile streams (NUL bytes, 500 KB line, JSON bomb, broken surrogates, truncated JSON), zero parser crashes |
| 7 | Can PATH manipulation substitute the provider executable? | **NO** — 0 `shutil.which` in provider code; resolution is from declared candidates |
| 8 | Can identity and capability become accidentally coupled again? | **NO** — separate columns, capability dispatch only, two providers per capability demonstrated |
| 9 | Can UI hard-coding prevent a valid third provider appearing? | **NO** — 0 provider names in the dialog's logic, enforced by a contract test |
| 10 | Can the gates regress into freezing a provider list? | **NO by construction** — but no approved-provider allowlist exists; see risks |

Sample of the Q6 hostile-stream run:

```
  empty                events=    0 typed=True turn_ok=False
  nul bytes            events=    1 typed=True turn_ok=False
  huge single line     events=    1 typed=True turn_ok=False
  json bomb            events=    1 typed=True turn_ok=False
  truncated json       events=    1 typed=True turn_ok=False
  unicode soup         events=    1 typed=True turn_ok=False
  fake completion      events=    2 typed=True turn_ok=False
  parser crashes: none
```

The last line matters: a stream emitting `turn.completed` *and* an error is not
treated as a successful turn.

---

## What the tests caught that review did not

Recorded because it is the argument for building the conformance suite at all.

- The suite **failed the shipped Codex provider** for reaching `shutil.which`
  through a sibling module, matching a finding the architecture review reached
  independently. That drove the declarative-candidates rewrite.
- Re-enabling those assertions after the rewrite immediately found a **second**
  PATH lookup, in `sf_mission_account`.
- The differential test of `sf_jsonschema` against the reference `jsonschema`
  package agreed on 22/22 documents, which is what made a hand-written validator
  defensible.
- My own bug — the receipt reading a lazily-populated slot — was caught by the
  suite within one run of introducing it.

---

## Environment note

`shadowfetch-fireline 3.0.0-1` is installed on the build host and its Firebreak
predates `--memory-mb`, so `executable()` finds a binary that rejects the flag
and any real mission fails there. This is **pre-existing** — `v4.0.0` passed the
same flag — and is an artifact of the dev box. Put
`packages/shadowfetch-fireline/data/usr/bin` first on `PATH` to exercise the real
execution path, as every end-to-end run above did.
