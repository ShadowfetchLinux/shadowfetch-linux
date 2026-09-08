# Phase 2 — Shared Agent Abstractions: implementation

**Goal.** Create the stable architectural seam that makes future agent
integrations possible. Not the integrations themselves: no orchestration, no
credential broker, no Claude, Grok, Cursor or local providers.

**The invariant.** Mission capability and agent provider must become separate
concepts, so the system can express *"run this CodeChange mission with provider
X"* without touching task-level Mission Control business logic.

Baseline: `PHASE2_BASELINE.md`, recorded at `e576679` before any change.

---

## What the coupling actually was

The baseline proved it rather than asserting it. All three attempts to vary
capability independently of provider were **refused**:

```
--kind code  --runtime offline  -> "Code and report missions require Codex"
--kind media --runtime codex    -> "Media missions use the offline runtime"
--kind code  --network none     -> "Code and report missions require Codex"
```

Ten sites across three packages plus three release gates. The sharpest was
`Executor.execute()`:

```python
getattr(self, self.mission["kind"])()
```

A mission's *kind* was simultaneously the capability, the provider selector, and
the **name of the method that implemented it**.

---

## Step 2 — The provider freeze is replaced, not deleted

`tools/mission_provider_contract.py` did two jobs and only one was worth keeping.

**Kept, unchanged:** the `REMOVED_AI_PATH` blacklist. No artifact may ship any
part of the retired local-AI stack. It is the first thing the new gate checks.

**Removed:** the AST freeze, which parsed `capabilities()` out of the mission
source and asserted the provider set was exactly `{codex, offline}`. It made
adding any provider a release failure, and it validated the *shape of source
code* rather than the behaviour of the system — a rename could satisfy it while
a genuinely dangerous provider walked past.

`tools/providers/validate_manifest.py` validates the manifests that actually
ship and their relationship to the code beside them: schema conformance using
the **same stdlib validator the installed system uses**, unique ids matching
filenames, the named adapter actually shipping, capabilities from the known set,
credential ids that are identities rather than values, network policy consistent
with its allowlist, and every offered capability having a provider.

And the check the old gate could never make, because it only looked at one
function: **provider adapter code that no validated manifest names is refused.**

All three call sites moved in one commit. Each passes a `read` callable for its
own context — source tree, extracted `.deb`, `squash_cat` for the ISO.

## Step 3 — The seam

`sf_providers.py`: `Capability`, `AgentProvider`, `ProviderRegistry`,
`SandboxSpec`, `Invocation`, `AgentEvent`, `Readiness`, `Acceptance`. Nothing in
it knows what Codex or ffmpeg are.

Providers are **data**. A manifest under `/usr/share/shadowfetch/providers`
names an adapter module, and only a validated manifest can make a module a
provider. The registry never scans arbitrary Python.

The manifest schema is real JSON Schema, validated by `sf_jsonschema` — a
stdlib-only validator, because no shipped package depends on
`python3-jsonschema` and live-build never installs it. Relying on it would mean
a registry that works on the build host and fails on a user's machine. That
validator **refuses a schema keyword it does not implement** rather than
ignoring it, since a silently skipped constraint is the failure mode that makes
hand-written validators dangerous. Differentially tested against the real
`jsonschema` package on 22 documents, 20 of them rejections: it agrees on every
one.

## Step 4 — Codex and offline-media behind the interface

`Executor.codex()` is gone. `agent_turn()` writes the prompt, asks the provider
to build an `Invocation`, runs it with generic plumbing, and reads back
normalized `AgentEvent`s. It contains no provider name and no branch on provider
identity. The Codex argv, sandbox posture and turn semantics are unchanged —
they live in the adapter now.

`media()` routes through `OfflineMediaProvider` for all three of its ffmpeg
stages, and stopped recovering ffprobe's JSON by searching a mixed log for
`{"streams"` — ffprobe writes to a file with `-o`, so there is no prose to
parse.

**offline-media is deliberately a provider** even though it is ffmpeg with no
model, no credentials and no network. If the interface carries both it and a
cloud CLI without the orchestrator branching, the interface is about *doing work
in a sandbox* rather than *talking to a language model*.

## Step 5 — Capability and provider are separately persisted

4.0.0 had **no schema versioning of any kind**: `PRAGMA user_version` was 0, no
`schema_version` column, no migrations table.

v2 adds `capability` and `provider_id` as columns, derived from what each row
already carried. `kind` is kept and still written, so a 4.0.0 reader sees what
it saw before. The only rename is `runtime=offline` → `provider_id=offline-media`,
and the legacy string stays readable in the config blob.

The migration runs in the caller's transaction, is idempotent, records itself as
an event, leaves an unrecognised row's new columns NULL rather than guessing, and
**refuses a database written by a newer schema** rather than reinterpreting it.

## Steps 6 & 8 — Registry and capabilities

`provider_for(capability, provider_id)` is the only place Mission Control chooses
who performs work, and it contains no provider names. Unknown providers fail
closed; a broken adapter is reported unavailable rather than crashing startup.

`capabilities()` is assembled from the registry. **All 23 baseline key paths are
preserved exactly**, including `runtimes` keyed by the legacy runtime name and
carrying `kinds`; 60 keys are added. That includes `summary` — a key
`missions_page.py:106` has always read and the 4.0.0 engine never emitted, so the
Readiness row silently never rendered.

The Control Center reads `capability_kinds` and `providers` and shows a chooser
only when more than one provider can do the job. No provider name remains in its
logic. When the engine has not described itself, the UI names no provider and
lets the engine choose, and never widens a connection choice the person made.

## Step 7 — The conformance suite

A reusable suite every provider must pass, parameterised over the registry rather
than written per provider, using fixture transports throughout.

It earned its place immediately: it traces a manifest's executable resolver into
the sibling modules it delegates to, and **failed the shipped Codex provider for
reaching `shutil.which` through a helper** — the same defect the architecture
review found independently. The suite was right and the code was wrong.

## Steps 9 & 10 — Prose parsing and redaction

Three places where one component parsed another's human output are gone: the
checkpoint id regex, the ffprobe log scrape, and (in the same work) the
checkpoint CLI gained `--json` while its existing sentences stayed byte-identical,
because they are now rendered *from* the structured result.

`sf_redact.py` is one shared implementation with a stateful sliding window, used
by Mission Control's log writer (which reads 65536-byte blocks, so a credential
straddling a boundary was previously never seen whole), Firebreak, and the
Control Center transport.

---

## The adversarial pass

An independent review of the committed seam found that several properties this
code asserted **in its own docstrings** were conventions rather than mechanisms.
Each is now a mechanism:

| Claim | Was | Now |
|---|---|---|
| "no PATH resolution of a provider program" | **False.** `codex.json` declared a resolver; the chain ended at `shutil.which('codex')`, including `~/.local/bin` | `executable.kind: "candidates"` — the manifest declares absolute/`~` globs; the resolver kind is retired; no PATH lookup remains anywhere in the chain |
| "an adapter cannot widen what it declared" | A convention. `narrow()` is opt-in and `Invocation(sandbox=…)` accepted any spec built from scratch | `verify_invocation()` re-derives the ceiling from the manifest on every execution |
| `narrow()` covers every field | It omitted `masked_paths`, whose safe direction is inverted, so an adapter could drop every mask | Checked in both `narrow()` and `verify_invocation()` |
| no provider name in generic code | `if provider.id == "codex"` in the credential path; npm layout names in the read-grant widener | `credential_aliases` and `runtime_root_markers` are manifest data |
| adapter import is safe | Verified the file, then imported **by name** through a `sys.path` the engine mutates in five places | Loaded from the verified path, and reused only when an existing module came from exactly that file |
| the manifest-root env override is harmless | Unclamped — it selects the document deciding credentials and network | Honoured only from a directory the user owns that is not group- or world-writable, and it says so when it refuses |

A blanket "system directories only" rule would have **deleted Codex support**,
since that CLI genuinely lives under the user's home. So trust is declared and
checked: `executable.trust` is `"system"` by default and `"user-runtime"`
requires user ownership and non-world-writability. 4.0.0 checked nothing.

## The documentation pass

Writing the developer documentation exposed six more defects, three real. The
sharpest: **the conformance assertions that caught the PATH defect had gone
inert**, skipping unless `kind` was the retired `resolver`, so Codex's executable
declaration was checked by nothing while the suite reported skips. Running them
again immediately found a *second* PATH lookup in `sf_mission_account`.

Also fixed: `cpu_seconds` never reached Firebreak (a provider declaring 60s got
900s while `verify_invocation()` made the declaration look enforced), and the
receipt — the audit artifact of this phase — did not name the capability or the
provider.

---

## The architectural proof

Run end to end, with a third provider added as **one manifest and one adapter**:

```
providers discovered from data alone: codex, example-agent, offline-media
who can do code_change:               codex, example-agent
CodeChange + codex          -> code_change via codex
CodeChange + example-agent  -> code_change via example-agent
MediaExport + example-agent -> "Example Agent does not perform media export"
persisted rows: via codex  |code|code_change|codex
                via example|code|code_change|example-agent

sf_missions.py, missions_page.py and validate_manifest.py: BYTE-IDENTICAL
```

The baseline recorded that `--kind code --runtime offline` answered *"Code and
report missions require Codex with explicit network access."* Capability and
provider now vary independently.
