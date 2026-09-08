# Phase 2 — Baseline

Recorded before any Phase 2 change. **This document exists to prove the refactor
preserves existing behaviour.** Every figure is literal output from the build
host, not a description of intent.

---

## 1. Working tree

```
$ git status --short
(no output — clean)
```

## 2. Commit under test

```
e5766794e484b720a772396ddbdba5ccc40f0208
e576679 Architecture audit and decisions, with the Phase 1 evidence addendum
Bob Corbin <Robertcorbin84@gmail.com>   Tue Sep 8 06:23:08 2026 -0400
branch:   release/4.0.0
describe: v4.0.0-28-ge576679
```

## 3. Test baseline

```
$ make test
exit = 0
unittest suites OK: 9
unittest tests:     487
plus script suites: test_fireline_mcp 12 passed / test_fireline_privilege 20 passed
                    test_firebreak.sh 19 passed
```

Per-suite (from the same run): missions 58 · control-center 43 · defaults 98 ·
firewatchd 26 · fireproof 36 · hwscan 49 · phoenix 26 · fireline 11 · tools 140.

*(The `ACCEPTANCE_FAILED` lines in that output are the acceptance verifier's own
failure-path unit tests, not a suite failure — `make test` exits 0.)*

## 4. Source gate

```
$ make source-gate
exit = 0
PASS: Gitleaks candidate tree (701 files)
PASS: Gitleaks Git history
SOURCE_GATE_PASSED
```

## 5. Mission Control capabilities — the UI contract

Full key-path dump. **Any key the Control Center reads must still exist after
Phase 2**; this is the input to the cross-package contract test (Step 8).

```
/version = '4.0.0'
/workspace_root = '<workspace root>'
/runtimes/offline/kinds = [media]
/runtimes/offline/requires_network_approval = False
/runtimes/codex/kinds = [code, report]
/runtimes/codex/installed = True
/runtimes/codex/api_key_configured = False
/runtimes/codex/dedicated_account_present = False
/runtimes/codex/worker_environment_file = '~/.config/shadowfetch/missions/codex.env'
/runtimes/codex/worker_environment_file_present = False
/runtimes/codex/configuration = 'Run shadowfetch-mission-account login for a dedicated account, …'
/runtimes/codex/requires_network_approval = True
/runtimes/codex/authentication = 'Dedicated Codex account or worker API key; …'
/tools/bwrap = True
/tools/ffmpeg = True
/tools/ffprobe = True
/tools/shadowfetch-firebreak = True
/kinds = [code, report, media]
/states = [queued, running, waiting-review, completed, failed, cancelled, undone]
/max_attempts = 3
/max_parallel = 1
/local_ai = 'deferred'
/grok_bot = 'Launch the official desktop cloud teammate separately; …'
```

Note the shape: **`runtimes` is keyed by provider id and each provider carries the
`kinds` it may perform.** Capability is expressed as a property of the provider,
which is the coupling this phase must invert.

## 6. SQLite schema

```sql
CREATE TABLE missions (
    id TEXT PRIMARY KEY, title TEXT NOT NULL, kind TEXT NOT NULL,
    state TEXT NOT NULL, workspace TEXT NOT NULL, prompt TEXT NOT NULL,
    config TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
    attempt INTEGER NOT NULL DEFAULT 0, error TEXT,
    checkpoint TEXT, artifacts TEXT NOT NULL DEFAULT '[]', receipt TEXT,
    cancel_requested INTEGER NOT NULL DEFAULT 0);
CREATE TABLE events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT, mission TEXT NOT NULL,
    at TEXT NOT NULL, event TEXT NOT NULL, detail TEXT NOT NULL);
CREATE TABLE steps (
    mission TEXT NOT NULL, name TEXT NOT NULL, result TEXT NOT NULL,
    PRIMARY KEY (mission, name));
CREATE INDEX missions_queue ON missions(state, created_at);
```

```
PRAGMA user_version = 0
tables: missions, events, sqlite_sequence, steps
db mode: 0600, state dir 0700
```

**There is no schema versioning of any kind** — no `user_version`, no
`schema_version` column, no migrations table. Phase 2 introduces it (Step 5).

Provider identity lives inside the JSON `config` blob, not a column:

```
mission-edb1…|media |queued|{"runtime":"offline","model":"","inputs":["notes.txt"],"test":null,"network":"none","timeout":900}
mission-528e…|code  |queued|{"runtime":"codex", "model":"","inputs":[],            "test":["true"],"network":"allow","timeout":900}
mission-f970…|report|queued|{"runtime":"codex", "model":"","inputs":["notes.txt"],"test":null,"network":"allow","timeout":900}
```

Events carry the kind in prose: `queued | "media; scope=…; network=none"`.

## 7. Representative execution flows

### 7a / 7b — creation succeeds for all three kinds

`media` → `runtime=offline, network=none`.
`code` → `runtime=codex, network=allow, test=["true"]`.
`report` → `runtime=codex, network=allow, inputs=[…]`.

### 7c — the coupling, demonstrated

This is the baseline's most important record. **Today the system cannot express
"this capability with that provider".** All three attempts are refused:

```
$ … create --kind code  --runtime offline --network none
{"error": "Code and report missions require Codex with explicit network access"}

$ … create --kind media --runtime codex   --network allow
{"error": "Media missions use the offline runtime without network access"}

$ … create --kind code  --network none
{"error": "Code and report missions require Codex with explicit network access"}
```

At the end of Phase 2 the first of these must become expressible for any
provider that *declares* the capability, without editing Mission Control
business logic.

### Where the coupling is written

| Site | Line | Coupling |
|---|---|---|
| `Store.create` | 382 | `runtime = runtime or ("offline" if kind == "media" else "codex")` — kind picks the provider |
| `Store.create` | 383 | `kind not in ("code","report","media") or runtime not in ("offline","codex")` — both frozen inline |
| `Store.create` | 391-393 | kind ↔ runtime ↔ network asserted together |
| `Executor.execute` | 816-819 | `expected = "offline" if kind == "media" else "codex"` |
| `Executor.execute` | 831 | `getattr(self, self.mission["kind"])()` — **kind IS the implementation method name** |
| `capabilities()` | 919-928 | provider dict hard-coded, keyed by runtime, carrying `kinds` |
| CLI | 980 | `--runtime choices=("offline","codex")` |
| UI `missions_page.py` | 166 | `runtime = "offline" if kind == "media" else "codex"` |
| UI `missions_page.py` | 168-169 | codex⇒network coupling repeated in the UI |
| `tools/mission_provider_contract.py` | 26 | gate asserts `set(runtimes) == {"codex","offline"}` by AST |

Ten sites, three packages, plus three release gates. Adding a provider today
means editing all of them.

## 8. The provider freeze being replaced

`tools/mission_provider_contract.py` does **two** jobs. Only the second is being
replaced:

1. **`REMOVED_AI_PATH` payload blacklist** — refuses any shipped path matching the
   retired local-AI surface (`shadowfetch-buzz*`, `sf_local_compute.py`,
   `local_ai_page.py`, `ai-ignition`, …). **This security invariant must survive
   into the new gate**, and is called from all three gates with a path inventory.
2. **AST source-shape freeze** — parses `capabilities()` out of the mission source
   and asserts `set(runtimes) == {"codex","offline"}` and `local_ai == "deferred"`.
   This is what makes adding a provider a gate failure, and it is what ADR-0006
   replaces with manifest-and-policy validation of data rather than source shape.

Call sites, all of which must move in one logical change:
`tools/source_gate_4_0_0.py:316`, `tools/package_gate_4_0_0.py:239`,
`tools/iso_gate_4_0_0.py:774`.
