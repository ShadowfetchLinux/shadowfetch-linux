# Agent architecture

How Mission Control decides *what* work is being done, *who* does it, and what the
sandbox is allowed to give them.

**Version.** This describes `release/4.0.0` at `85472f7` (2026‑09‑08). The provider
seam was built by Steps 3–8 (`5dd2083` … `d462552`) and then hardened by `2d4b1cf`,
"Phase 2 adversarial pass: turn the claimed properties into enforced ones". Behaviour
that arrived with that pass is marked **(hardening)** throughout, because the Step 3–8
commit messages describe the earlier, weaker version of it.

The files:

| File | What lives there |
|---|---|
| `packages/shadowfetch-missions/data/usr/lib/shadowfetch/missions/sf_providers.py` | `Capability`, `AgentProvider`, `ProviderRegistry`, `SandboxSpec`, `Invocation`, `AgentEvent`, `Readiness`, `Acceptance`, manifest loading, `resolve_executable`, `trusted_executable`, `verify_invocation` |
| `.../missions/sf_provider_codex.py` | The Codex CLI adapter |
| `.../missions/sf_provider_offline_media.py` | The ffmpeg/ffprobe adapter |
| `.../missions/sf_jsonschema.py` | The stdlib-only manifest validator |
| `.../missions/sf_missions.py` | Mission Control: the store, the executor, the CLI |
| `packages/shadowfetch-missions/data/usr/share/shadowfetch/providers/*.json` | The shipped manifests and their schema |
| `tools/providers/validate_manifest.py` | The release gate over the shipped provider payload |
| `packages/shadowfetch-missions/tests/provider_conformance.py` | The assertions every provider must pass |

Companions: `docs/PROVIDER_MANIFEST.md` (field reference),
`docs/PROVIDER_DEVELOPMENT.md` (how to write one), `docs/MISSION_SCHEMA.md`
(what is persisted).

---

## 1. Capability versus provider

A **capability** is what a person wants done. A **provider** is who does it.

`sf_providers.Capability` holds three values, and they are plain strings rather than
an `Enum` because they are persisted in SQLite and appear in receipts:

```python
CODE_CHANGE    = "code_change"
SOURCED_REPORT = "sourced_report"
MEDIA_EXPORT   = "media_export"
```

### Why they were one thing

Before Phase 2 a mission had only a `kind`, and that one field did three jobs at
once. `PHASE2_BASELINE.md` records ten sites across three packages; the three that
matter are:

```python
# Store.create
runtime = runtime or ("offline" if kind == "media" else "codex")   # kind chose the runtime
# Executor.execute
expected = "offline" if kind == "media" else "codex"               # and asserted it again
getattr(self, self.mission["kind"])()                              # and named the method
```

That last line is the clearest statement of the problem: a mission's `kind` was
*literally the name of the Python method that implemented it*. `kind` also fixed the
network posture, so the system could not express "this capability, that provider".
The baseline recorded all three attempts being refused:

```
$ … create --kind code  --runtime offline --network none
{"error": "Code and report missions require Codex with explicit network access"}
$ … create --kind media --runtime codex   --network allow
{"error": "Media missions use the offline runtime without network access"}
$ … create --kind code  --network none
{"error": "Code and report missions require Codex with explicit network access"}
```

### What it is now

`Executor.CAPABILITY_METHOD` maps a capability to a Mission Control routine:

```python
CAPABILITY_METHOD = {
    Capability.CODE_CHANGE:    "code",
    Capability.SOURCED_REPORT: "report",
    Capability.MEDIA_EXPORT:   "media",
}
...
getattr(self, self.CAPABILITY_METHOD[capability])()
```

This is **not** provider dispatch. `code()`, `report()` and `media()` are Mission
Control's own business logic — the validation guard, citation checking, test
execution, artifact publishing — and the provider supplies only the agent turn
*inside* them. Adding a provider does not touch this table.

Who performs the work is decided in exactly one function, and it contains no
provider names:

```python
def provider_for(capability, provider_id=None):
    reg = registry()
    if provider_id:
        provider = reg.get(provider_id)
        if not provider.supports(capability):
            raise ProviderError(f"{provider.display_name} does not perform "
                                f"{capability.replace('_', ' ')}")
        return provider
    chosen = reg.default_for(capability)
    ...
```

`ProviderRegistry.default_for()` returns the single available provider for a
capability, or nothing. Choosing between two equally able providers is an
orchestration decision this phase deliberately does not make; `provider_for()`
raises `"More than one provider can do this; name one with --provider: …"` instead.

### Legacy names are translated, not honoured specially

`kind` did not disappear. `Store.create()` still accepts `kind=` and `runtime=`,
translates them through `LEGACY_KIND_CAPABILITY` / `LEGACY_RUNTIME_PROVIDER`, and
still writes the `kind` column and the `config["runtime"]` string, so a 4.0.0 reader
sees what it always saw. The CLI kept `--kind` and `--runtime` as aliases for
`--capability` and `--provider`. `--runtime` lost its
`choices=("offline","codex")`: a provider list baked into the CLI was one of the
things that made a new provider unaddable.

---

## 2. The registry lifecycle

`ProviderRegistry.__init__` does everything up front and never raises for a bad
provider. Mission Control has to keep running so a person can read, review and undo
existing missions even when no agent is installed.

**Discovery.** The root is `/usr/share/shadowfetch/providers`, or the
`SHADOWFETCH_PROVIDER_MANIFESTS` override, or — when neither exists — the
`data/usr/share/shadowfetch/providers` directory found by walking up from
`sf_providers.py`, which is how the source tree works. Every `*.json` in it except
`provider-manifest.schema.json` is a candidate.

**(hardening)** The override is no longer honoured unconditionally. The document it
selects decides network policy, credential identities, read grants and resource
caps, so an environment-selected manifest root is the same defect class as an
environment-selected executable, one layer up. It is accepted only from a real
directory (not a symlink) owned by root or the invoking user and not group- or
world-writable; otherwise a line goes to stderr and the packaged root is used.

**Validation.** `load_manifest()` parses the JSON, validates it against the schema
with `sf_jsonschema.validate`, then checks `path.stem == document["id"]` so a
provider cannot be shadowed by a second file claiming its id.

**Adapter import.** `_instantiate()` refuses an `adapter_module` that does not match
`^sf_provider_[a-z0-9_]+$` (the schema already constrains it; the check is repeated
so the guarantee is local), refuses one whose `.py` file is not in the registry's
`module_root`, and imports it. **(hardening)** The import is by *file location*, not
by name through `sys.path`:

```python
spec = importlib.util.spec_from_file_location(module_name, self.module_root / f"{module_name}.py")
module = importlib.util.module_from_spec(spec)
sys.modules.setdefault(module_name, module)
spec.loader.exec_module(module)
```

`sf_missions.py` inserts several directories onto `sys.path`, so an import by name
could have resolved to a same-named module elsewhere while the existence check above
passed against `module_root`.

**Instantiation.** The registry — not the adapter — builds the `SandboxSpec` and
hands it in: `klass(manifest, sandbox_from_manifest(manifest))`.

### Failure modes, and how each is reported

| Failure | Where it lands | What a person sees |
|---|---|---|
| No manifest directory | `registry.errors` | `No provider manifest directory at /usr/share/shadowfetch/providers` |
| Schema missing or unparseable | `registry.errors`; **no providers load at all** | `Provider manifest schema is unavailable: …` |
| Manifest is not JSON | `registry.errors`, manifest skipped | `codex.json: is not valid JSON: …` |
| Manifest fails the schema | `registry.errors`, manifest skipped | `codex.json: sandbox_profile.cpu_seconds: above maximum 7200` |
| Filename ≠ `id` | `registry.errors`, manifest skipped | `…: manifest filename must match its id 'x', so a provider cannot be shadowed…` |
| Two manifests, same `id` | `registry.errors`, **both** dropped | `…: duplicate provider id 'x'; refusing both` |
| Unsupported `interface_version` | Entry exists, `usable = False` | `needs provider interface v99, this system implements v1` |
| Adapter module not installed | Entry exists, `usable = False` | `adapter module sf_provider_x is not installed at …` |
| Adapter raises on import or construction | Entry exists, `usable = False` | `adapter failed to load: RuntimeError: …` |
| Class is not an `AgentProvider` | Entry exists, `usable = False` | `X is not an AgentProvider` |
| `readiness()` itself raises | Caught in `ProviderRegistry.readiness()` | `Readiness(available=False, missing=("readiness",), reason="readiness check failed: …")` |
| The registry constructor itself raises | `sf_missions.registry()` substitutes `_EmptyRegistry` | Every query returns empty; `errors` carries the reason |

The distinction between "skipped" and "unusable" is visible: a skipped manifest never
appears in `ids()`; an unusable one appears in `ids()` and in `describe()` but never
in `list()` or `for_capability()`, and `get()` raises
`Provider 'x' is unavailable: <reason>`.

`registry()` in `sf_missions.py` caches one registry per process in `_REGISTRY`.
There is no invalidation: a provider installed while the mission worker is running is
not seen until the worker restarts.

---

## 3. The invocation lifecycle, end to end

```
 Control Center / CLI
   │  capabilities()                       ← registry.describe(), plus the legacy view
   ▼
 Store.create(capability=…, provider_id=…)
   │  provider_for(capability, provider_id) → AgentProvider
   │  provider.accepts(capability, config)  → Acceptance      ← refuses here, with a reason
   ▼  row inserted: kind, capability, provider_id, config
 run_mission() → Executor.execute()
   │  the three recorded copies of provider identity must agree
   │  provider_for(...) again; accepts() again
   │  checkpoint_call("snapshot", …)        ← workspace recovery point
   │  getattr(self, CAPABILITY_METHOD[capability])()
   ▼
 Executor.code() / report()                 Executor.media()
   │  agent_turn(prompt)                    │  build_invocation(stage=probe|encode|verify)
   ▼                                        ▼
 provider.build_invocation(capability, request) → Invocation
   │  Executor.credentials_for(provider)    ← identities → values, HERE and nowhere else
   ▼
 Executor.run_invocation(invocation, secrets)
   │  verify_invocation(invocation, manifest)   ← (hardening) the ceiling, re-derived
   ▼
 Executor.run_process(...)                  ← the only place a Firebreak argv is built
   │  shadowfetch-firebreak run --workspace … --net … --memory-mb … --processes …
   │    [--codex-account] [--credential-env NAME]… [--read GRANT]… -- <executable> <argv>
   ▼
 stdout+stderr → <label>.log
   ▼
 provider.parse_stream(log.read_text()) → [AgentEvent, …]
   │  provider.turn_succeeded(events) / final_message(events) / usage(events)
   ▼
 Executor.inferences[] → receipt.json, mission state → waiting-review
```

`Executor.agent_turn()` is the piece worth reading in full, because it contains no
provider name and no branch on provider identity:

```python
provider = self.provider
capability = self.mission.get("capability") or LEGACY_KIND_CAPABILITY.get(self.mission["kind"])
acceptance = provider.accepts(capability, self.mission["config"])
if not acceptance.ok:
    raise MissionError(acceptance.reason)

request_path = self.directory / "agent-request.txt"
atomic(request_path, prompt)
invocation = provider.build_invocation(capability, {
    "prompt_path": str(request_path), "read_only": read_only,
    "config": self.mission["config"]})
secrets = self.credentials_for(provider)
...
code, tail, log = self.run_invocation(invocation, secrets)
...
events = provider.parse_stream(log.read_text())
if not provider.turn_succeeded(events):
    raise MissionError(f"{provider.display_name} did not record a complete successful turn; …")
answer = provider.final_message(events)
```

The prompt file is written to the mission's controller directory and unlinked in a
`finally` block, so a prompt does not outlive the turn.

`Executor.provider` is a lazy property rather than something `execute()` sets, so
anything holding an `Executor` — a receipt writer, a test, a future inspector — can
ask who the provider is without running the mission.

### Media is the same machinery, three times

`Executor.media()` calls `build_invocation` three times per input file with
`stage="probe" | "encode" | "verify"` and runs each through the same
`run_invocation()`. The probe writes its JSON to a file (`ffprobe … -o <path>`) and
the adapter reads it with `OfflineMediaProvider.read_probe()`. The 4.0.0 code
recovered that JSON by searching the mixed process log for the literal `{"streams"`,
because Firebreak appends a session trailer to the same stream — one component
parsing another component's human-readable output to get structured data. There is
no prose to parse now.

---

## 4. Stream normalisation

`AgentEvent` exists because providers emit wildly different native output and Mission
Control must consume exactly one thing. It is a frozen dataclass with a `type`,
optional `text` and a `data` dict, and `__post_init__` refuses an unknown type:

```
message         the answer a person reads
progress        something happened; not for a person
usage           resource accounting reported mid-stream (neither shipped provider emits it)
log             output that was not understood — carried, never dropped
error           the provider said it failed
turn-complete   the provider finished a turn
```

Two very different streams reduce to it:

**Codex** emits one JSON object per line. `CodexCliProvider.parse_stream` maps
`turn.completed` → `TURN_COMPLETE` (carrying `usage`), `turn.failed`/`error` →
`ERROR`, `item.completed` with an `agent_message` item → `MESSAGE`, any other
`item.completed` → `PROGRESS`, any other object → `PROGRESS`. A line that is not
JSON, or is JSON but not an object — Firebreak's session trailer, a partial write, an
interleaved warning — becomes a `LOG` event truncated to 2000 characters. It never
raises.

**ffmpeg** emits diagnostics, not turn events. `OfflineMediaProvider.parse_stream`
matches `^(frame|size|time)=` as `PROGRESS`, everything else as `LOG`, and then
appends a `TURN_COMPLETE` unconditionally:

```python
events.append(AgentEvent(AgentEvent.TURN_COMPLETE, "", {"usage": None}))
```

That is deliberate and it is the honest thing for ffmpeg: failure lives in the exit
status, not in the stream, and `Executor.agent_turn()` / `Executor.media()` check the
exit code before they look at events. The conformance suite's media profile records
this in its `notes` and distinguishes its failure fixture by `exit_code`.

The default outcome rules on `AgentProvider` are derived from the events, so an
adapter usually does not implement them:

```python
def turn_succeeded(self, events):   # a completion, and no error
def usage(self, events):            # the last TURN_COMPLETE's data["usage"]
def final_message(self, events):    # the last non-empty MESSAGE text
```

`CodexCliProvider` overrides none of them — after parsing, `turn.completed` /
`turn.failed` *is* the generic rule.

A provider's output is untrusted input. `parse_stream` must tolerate malformed,
partial and interleaved output; the conformance suite runs a 21-case hostile battery
(empty, `None`, a bare `{`, truncated JSON, NUL bytes, a 200 000-character line, 3000
lines, surrogate-escaped binary, 200-deep nesting…) against every provider and fails
it if `parse_stream` or `final_message` raises.

---

## 5. Readiness and acceptance

They answer different questions and surface in different places.

**`Readiness`** — *can this provider be used at all right now?* A property of the
installation, not of a mission. `installed` (is the program there), `authenticated`
(is there a credential or account), `missing` (a tuple of names), `facts` (a
free-form dict the UI may republish), `reason` (prose for a person), and
`available = installed and authenticated`.

`OfflineMediaProvider` returns `authenticated=True` unconditionally, with the comment
that says why: an offline tool is authenticated by definition, and saying so
explicitly keeps the UI from inventing a sign-in prompt for a provider that has no
account. The conformance suite asserts exactly this for any provider whose profile
declares no authentication seam.

Where it surfaces: `capabilities()` merges `Readiness.as_dict()` into every entry of
its `providers` map, builds the `summary` line
(`"Ready: …. Needs attention: … (<reason>)"`), and republishes four historically
Codex-specific facts at the top of the legacy `runtimes` entry when a provider
reports them — `api_key_configured`, `dedicated_account_present`,
`worker_environment_file`, `worker_environment_file_present`. Nothing in
`capabilities()` names a provider to do this. `missions_page.py` shows the summary in
its Readiness row, appends `" · needs setup"` to an unavailable provider in the
chooser, and puts `reason` in the setup label.

**`Acceptance`** — *will you do this particular job?* `Acceptance.yes()` or
`Acceptance.no(reason)`. The base implementation refuses any capability the manifest
does not declare; adapters refine it and must give a person something they can act
on. `CodexCliProvider` refuses when `config["network"] != "allow"` and when a model
was named; `OfflineMediaProvider` refuses a non-`none` network and an empty input
list.

Where it surfaces: `Store.create()` calls `accepts()` before inserting the row and
raises `MissionError(acceptance.reason)` — so the refusal *is* the error text the
person sees at creation. `Executor.execute()` and `Executor.agent_turn()` call it
again before running, because a config can be edited and a provider can change.

This is what replaced the three hard-coded `kind`/`runtime`/`network` rules from the
baseline. A provider now states its own requirements.

---

## 6. The security model

Five properties are structural — enforced by types, by the registry or by the
orchestrator — rather than conventional. Phase 1 found real defects of each class.

### 6.1 The registry builds the sandbox; an adapter can only narrow it

`sandbox_from_manifest(manifest)` is the single constructor of the ceiling, and the
registry calls it, not the adapter:

```python
provider = klass(manifest, sandbox_from_manifest(manifest))
```

`SandboxSpec` is frozen. `SandboxSpec.narrow(**changes)` **refuses exactly these**:

| Attempted change | Refusal |
|---|---|
| `network` changed when the declared network is `"none"` | `An adapter may not add network access it did not declare` |
| `credential_ids` not a subset of the declared set | `An adapter may not request undeclared credentials` |
| A non-empty `account_mount` different from the declared one | `An adapter may not mount a credential store it did not declare` |
| `egress_allowlist` not a subset | `An adapter may not add egress hosts it did not declare` |
| `read_grants` not a subset | `An adapter may not add read grants it did not declare` |
| A declared `masked_paths` entry dropped **(hardening)** | `An adapter may not drop a masked path it was given` |
| `memory_mb`, `cpu_seconds` or `processes` raised | `An adapter may not raise its declared <field>` |
| `read-only` workspace changed to writable | `An adapter may not upgrade a read-only workspace to writable` |

`masked_paths` is the one field whose safe direction is inverted — adding a mask
narrows, removing one widens — which is exactly why the subset check was missing at
first and why it reads backwards from the others.

`SandboxSpec.__post_init__` additionally refuses an unknown `workspace_mode`, an
unknown `network`, a `network="none"` spec that carries an egress allowlist, and any
read grant that is not an absolute path.

### 6.2 The ceiling is re-derived at invocation time **(hardening)**

`narrow()` is a convenience an adapter can simply not call, and `Invocation(sandbox=…)`
accepts any `SandboxSpec` an adapter constructs from scratch. Without a second check,
"an adapter cannot widen what it declared" is a convention, not a mechanism. So
`Executor.run_invocation()` calls `verify_invocation(invocation, manifest)` before
anything runs, and it re-derives the ceiling from the manifest rather than trusting
the spec it was handed:

```
claude-cli: requested memory_mb=9999 above its declared 3072
```

It refuses: a missing sandbox, network on a `none` provider, undeclared credentials,
undeclared egress hosts, undeclared read grants, a dropped masked path, any raised
resource cap, a read-only workspace upgraded to writable, an undeclared account
mount, an `env_allowlist` naming an undeclared credential, and an executable that
fails its trust tier (§6.3).

### 6.3 A provider program is located from declared data, and re-checked **(hardening)**

The manifest names *where a program may live*; the adapter does not get to decide.
`resolve_executable(manifest)` implements it and there is no `PATH` in it:

* `executable.kind = "absolute"` — one fixed path.
* `executable.kind = "candidates"` — an ordered list of absolute or `~/`-relative
  globs, tried in order; the first existing, executable, trust-passing match wins.
  A pattern that is neither absolute nor `~/`-relative is skipped, so a relative
  lookup can never happen.
* `executable.kind = "none"` — the provider runs nothing.

Whatever comes back is then re-checked by `trusted_executable()`, because an adapter
is packaged code but its *output* is not trusted:

```python
TRUSTED_EXEC_PREFIXES = ("/usr/bin/", "/usr/sbin/", "/usr/libexec/", "/usr/lib/",
                         "/usr/local/lib/shadowfetch/", "/bin/", "/sbin/", "/opt/")
```

`trust: "system"` (the default) requires one of those prefixes. `trust: "user-runtime"`
permits a program under the user's home — because the Codex CLI genuinely is an npm
install — and then requires that it be owned by the invoking user and not
world-writable. Declaring the tier makes the exception visible in the manifest and at
the release gate instead of being silently universal. `codex.json` declares it and
lists six candidate globs including `~/.nvm/versions/node/*/bin/codex`.

`Invocation.__post_init__` still refuses a non-absolute executable outright, and
`verify_invocation()` re-runs `trusted_executable()` with the manifest's declared
tier at the moment of execution.

**What this replaced.** Before the hardening, `codex.json` used a third kind,
`"resolver"`, naming `sf_provider_codex.codex_executable()`, which delegated to
`sf_mission_account.codex_executable()`, which is `shutil.which('codex')`. The
program was absolute but the *environment chose it*. Two conformance assertions
failed on that, correctly, and the adapter now carries a comment saying so.

`Executor.run_process()` never consults `PATH` on a provider's behalf — the only
`shutil.which()` left is for the workspace test command, which is the person's own:

```python
resolved = str(command[0]) if invocation is not None else shutil.which(command[0])
```

**(hardening)** When a program lives outside `/usr/`, `/bin/`, `/sbin/` or `/lib/`,
the sandbox needs read access to its runtime distribution so it can load its own
files. Which parent directory that is used to be `if parent.name in ("codex", "@openai")`
in the orchestrator; it is now `invocation.manifest_executable["runtime_root_markers"]`
— declared data. Without markers, only the program's own directory is granted.

### 6.4 An `Invocation` carries credential identities, never values

`Invocation.env_allowlist` is a tuple of names. `__post_init__` rejects any entry that
does not match `[A-Z][A-Z0-9_]*`, so a value cannot be smuggled through the field
that is supposed to hold a name:

```python
raise ProviderError(f"Environment allowlist entries are names, not values: {name!r}")
```

Values are resolved in exactly one place, `Executor.credentials_for(provider)`, which
no provider supplied and no provider can influence: it reads the identities out of
`provider.manifest["credential_ids"]` and looks each one up in the worker's own
environment. **(hardening)** Historical spellings are data too —
`credential_aliases: {"OPENAI_API_KEY": "CODEX_API_KEY"}` in `codex.json` replaced the
one `if provider.id == "codex":` branch that survived Step 8. There is now no provider
name in that function.

The value never enters an argv. `run_process()` passes only the *name* to Firebreak:

```python
for name in sorted(env or {}):
    wrapper.extend(["--credential-env", name])
```

and puts the value into the child process environment, where `shadowfetch-firebreak`
picks it up. The conformance suite plants sentinel values in the environment and
asserts none of them appears anywhere in the built invocation.

When no credential value resolves and the manifest declared an `account_mount`,
`agent_turn()` falls back to the dedicated mission account: it takes
`sf_mission_account.account_lock(account_home())` for the duration of the turn and
requires `auth.json` to exist, refusing with
`"<display name> authentication is not configured: …"` otherwise.

### 6.5 `account_mount` is declared data

The dedicated Codex credential store is not requested by name in the orchestrator.
The manifest declares `sandbox_profile.account_mount: "codex-account"`,
`sandbox_from_manifest` copies it onto the `SandboxSpec`, and `run_process()` forwards
it without knowing who asked:

```python
if codex_account or (spec is not None and spec.account_mount and not env):
    wrapper.append("--" + (spec.account_mount if ... else "codex-account"))
```

The mount is added only when no credential *value* resolved, which is the
account-versus-API-key fallback expressed as data.

The schema constrains `account_mount` to the enum `["codex-account"]`, so a new
provider cannot declare its own credential store without a schema change *and* a
matching Firebreak flag. That closed set is intentional — the flag has to exist on the
other side — but it means "declare a mount" is not something a provider author can do
unilaterally.

### 6.6 What Firebreak is actually told

`run_process()` is the only place in the engine that builds a Firebreak command line.
From an `Invocation`'s `SandboxSpec` it passes:

| Spec field | Firebreak flag | Enforced? |
|---|---|---|
| `firebreak_network` | `--net none` / `--net allow` | **`none`: yes** — `--unshare-net`, and `connect()` fails with `ENETUNREACH`. **`allow`: the on/off decision only** — no network namespace is created, so the sandbox keeps the host's network, its loopback services and its abstract sockets, and no destination is filtered. `sandbox_enforcement()` reports this row as `partial` for any spec that is not `none` |
| `memory_mb` | `--memory-mb` | yes |
| `processes` | `--processes` | yes |
| `read_grants` | one `--read` each | yes |
| `account_mount` | `--codex-account` | yes |
| declared credential names | one `--credential-env NAME` each | yes |
| `cpu_seconds` | `--cpu-seconds` | yes, per process. `min(spec.cpu_seconds, mission timeout)` — the tighter of the two. `RLIMIT_CPU` is per-process, so a forking provider gets a fresh budget per child |
| `workspace_mode` | `--workspace-mode` | yes. `--ro-bind` for `read-only`, `--bind` otherwise |
| `egress_allowlist` | — | **no.** `firebreak_network` collapses `allowlist` → `allow`; the hosts are declared for audit and for a future egress filter |
| `masked_paths` | — | **no.** Checked by `narrow()` and `verify_invocation()`, never forwarded |
| *syscall profile* | — | **not representable.** No schema property, and no `bwrap --seccomp` anywhere |

Two rows changed in Phase 2.5. `cpu_seconds` was passed the mission's own budget
rather than the spec's; `workspace_mode` reached nothing at all, and the read-only
restriction held only because the Codex adapter volunteered `--sandbox read-only` in
its own argv — provider-supplied code enforcing its own restraint, which is what a
sandbox boundary exists in order not to depend on.

`memory_mb` is qualified. `MemoryMax` holds the resident set, and Phase 2.5 added
`MemorySwapMax=0`; before that a process touched 4096 MiB under a 256 MiB cap and
exited 0, the excess going to swap. The cap now bounds the workload rather than
depending on host swap configuration.

The two remaining gaps are recorded here, in
`PHASE2_5_REMAINING_RISKS.md`, and in `test_sandbox_spec_audit.py`, whose table fails
a build if a field's status drifts from what is actually enforced. They must not be
described to users as controls.

---

## 7. What Phase 2 deliberately did not do

* **No orchestration.** There is no scheduler, no fan-out, no fallback between
  providers, no retry across providers. `default_for()` picks the single available
  provider or nothing, and `provider_for()` makes ambiguity a visible error rather
  than a silent choice. `max_parallel` is still 1 and one execution lock still
  serialises the queue.
* **No credential broker.** `credentials_for()` reads the worker's own environment.
  There is no keyring, no per-mission credential scoping, no rotation, and no audit of
  a credential's use beyond the receipt recording that the mission ran.
* **No new providers.** The two that ship are the two that shipped in 4.0.0, moved
  behind the interface with byte-identical argv. The third provider
  (`conformance-echo`) exists only in `tests/fixtures/` and does not ship — that is
  the point of it.
* **No UI redesign.** `missions_page.py` keeps its shape. The provider chooser is
  hidden while only one provider can perform the selected capability, so a
  single-provider install looks exactly as it did.
* **No local AI.** `capabilities()["local_ai"]` is still `"deferred"` and the release
  gate's `REMOVED_AI_PATH` blacklist still refuses any shipped path belonging to the
  retired local-AI stack.

---

## 8. Known gaps

Recorded here rather than left for the next reader to rediscover.

Three gaps this document originally recorded were closed in response to it, and
are described here as history rather than as current state — see the commit
"close the findings from the documentation review".

1. **`masked_paths` and `egress_allowlist` are declared but not enforced at the
   sandbox boundary.** §6.6. Both are schema-bounded, narrowable and checked by
   `verify_invocation()`; neither reaches Firebreak, because Firebreak has no
   masking or egress-filtering flag to receive them. They are audit records and
   future enforcement points, and should not be described to users as controls.
   **`cpu_seconds` was in this list and no longer is:** `run_process()` now passes
   `min(spec.cpu_seconds, mission timeout)`, so a provider's declared ceiling is
   the one that applies when it is the tighter of the two.
2. **The registry is cached for the process lifetime** with no invalidation, so a
   newly installed provider needs a worker restart. This is the first thing a
   provider author will hit.
3. **`trust: "user-runtime"` used to accept any group-writable program.** npm and
   nvm install 0775 under the user's personal group, so only world-writability was
   refused, and on a machine whose users share a primary group another member could
   replace the Codex binary. Phase 2.5 measures the group instead of waiving it: a
   group with no member but the owner is a private group and is accepted; a shared
   one classifies the program `untrusted`. See `docs/PROVIDER_TRUST.md`.
4. **`account_mount` is a closed enum** (`["codex-account"]`) matching Firebreak's
   only credential-mount flag, so a third-party provider needing a dedicated account
   directory requires both a schema and a Firebreak change.

**Closed since this was written.** The receipt now carries `capability`,
`provider_id` and `provider_version`. The conformance suite's executable checks
were inert — they skipped unless `kind` was the retired `resolver` — and now run
for every provider with a `candidates` branch; running them immediately found a
second PATH lookup in `sf_mission_account`, which is gone. The schema's
`executable.description` no longer describes a kind that does not exist.
