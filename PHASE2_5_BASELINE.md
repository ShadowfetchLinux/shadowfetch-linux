# Phase 2.5 Baseline

*State of the tree at `fb9b32a`, the final Phase 2 commit, measured before any
Phase 2.5 change.*

## Tests

| suite | count | result |
|---|---|---|
| `packages/shadowfetch-missions` | 252 | OK (1 skip) |
| `tools/tests` (release gate) | 143 | OK |
| `packages/shadowfetch-fireline` | 11 | OK |
| every suite via `make test` | 687 | OK |
| `make source-gate` | — | `SOURCE_GATE_PASSED` |

**A fresh checkout of `fb9b32a` did not have 252 passing tests — it had 132.**
`.gitignore` carries `*.log`, and two of the provider conformance fixtures are
`.log` files, so `test_provider_conformance.py` died with `FileNotFoundError` at
import in any clone. The suite passed only in a working tree that happened to
contain untracked files. This is measured, not inferred:

```
fb9b32a: Ran 132 tests  FAILED (errors=1)      <- Phase 2 final, fresh worktree
4351129: Ran 184 tests  FAILED (errors=1)      <- mid-Phase-2.5, same cause
5c16039: Ran 358 tests  OK (skipped=3)         <- after the .gitignore exception
```

## Providers

Two, both shipped: `codex` (code_change, sourced_report) and `offline-media`
(media_export). `conformance-echo` exists as a test fixture only.

Readiness on this host at baseline, unchanged since:

```
codex          available=False  Run shadowfetch-mission-account login for a
                                dedicated account, or save a user-owned 0600
                                CODEX_API_KEY environment file and restart the
                                idle worker. Credential presence does not verify
                                authentication.
offline-media  available=True
```

## Conformance

23 assertions per provider, run against `codex`, `offline-media` and the
`conformance-echo` fixture. Interface version 1.

## The P1 this phase exists to close

`PHASE2_REMAINING_RISKS.md` §3: Phase 2 replaced the AST provider freeze with a
JSON Schema, so **any package that landed a schema-valid manifest in
`/usr/share/shadowfetch/providers` became a provider**, with whatever
capabilities, credentials and network posture it declared. Nothing recorded
that a human had ever agreed to run it.

Demonstrated at baseline, before the fix: a copy of `offline-media.json` with
its `id` changed to `helpful-agent` and dropped into the discovery directory was
loaded, activated, and offered for its declared capability.

## Declared-but-unenforced at baseline

From `PHASE2_REMAINING_RISKS.md` §1–§2 and `AGENT_ARCHITECTURE.md` §6.6:

| field | status at baseline |
|---|---|
| `egress_allowlist` | declared, validated, narrowable, **reaches nothing** |
| `masked_paths` | declared, validated, narrowable, **reaches nothing** |
| `cpu_seconds` | fixed during Phase 2; §6.6 still said it was unenforced |
| `workspace_mode` | **not in §6.6 at all** — the field with a live enforcement hole was not on the known-gaps list |
| `memory_mb` | passed and enforced — swap not considered |
| *syscall profile* | not representable; not recorded anywhere |

## Executable trust at baseline

A path-prefix test. A program under `/usr/bin/`, `/usr/sbin/`, `/usr/libexec/`,
`/usr/lib/`, `/usr/local/lib/shadowfetch/`, `/bin/`, `/sbin/` or `/opt/` was
trusted, with no examination of the ownership or mode of the file or of any
directory above it. `trust: "user-runtime"` additionally accepted any
group-writable program, recorded as a residual risk.

## Interface shape at baseline

Both shipped providers are batch-shaped: Codex emits one JSONL record per
completed item, ffmpeg at `loglevel=error` emits almost nothing. No provider
exercised incremental output, an explicit session, heartbeats, tool rounds, or a
stream with no guaranteed terminal record. An interface validated against only
those two had not been validated.
