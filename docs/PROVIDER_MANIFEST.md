# Provider manifest reference

A provider is **data plus an adapter module**. The data is one JSON file under
`/usr/share/shadowfetch/providers/`, validated against
`provider-manifest.schema.json` by both the running system and the release gate. A
Python module in the adapter directory is not a provider until a validated manifest
names it.

**Version.** Manifest schema version 1, on `release/4.0.0` at `85472f7`
(2026‑09‑08). Fields marked **(hardening)** arrived with `2d4b1cf`, the Phase 2
adversarial pass; that commit also retired the `executable.kind` value `"resolver"`,
so a manifest written against an earlier draft will now be rejected.

Source of truth:
`packages/shadowfetch-missions/data/usr/share/shadowfetch/providers/provider-manifest.schema.json`.

The schema sets `"additionalProperties": false` at the top level and inside
`sandbox_profile` and `executable`. **A key not listed below is a hard rejection**,
not an ignored extra.

---

## 1. Where manifests live and how they are found

| | Path |
|---|---|
| Installed manifests | `/usr/share/shadowfetch/providers/*.json` |
| The schema | `/usr/share/shadowfetch/providers/provider-manifest.schema.json` |
| Adapters | `/usr/lib/shadowfetch/missions/sf_provider_*.py` |
| In the source tree | `packages/shadowfetch-missions/data/` + the same paths |

`sf_providers._default_root()` picks the root in this order:

1. `$SHADOWFETCH_PROVIDER_MANIFESTS`, if set **and safe** (below);
2. `/usr/share/shadowfetch/providers`, if it is a directory;
3. the first `data/usr/share/shadowfetch/providers` found walking up from
   `sf_providers.py` — this is what makes the source tree work without installing;
4. `/usr/share/shadowfetch/providers` regardless, so the failure message names the
   real path.

`ProviderRegistry` globs `*.json` in that root, skips
`provider-manifest.schema.json`, and validates each one. The schema is read from
**the same directory as the manifests**, so a test root must carry a copy (or a
symlink) of it. The conformance suite links the real schema rather than copying it,
deliberately: a fixture that only passed against a stale copy of the schema would
prove nothing.

### The `SHADOWFETCH_PROVIDER_MANIFESTS` test seam

It is a test and QA seam, and its scope is narrow by construction: it selects *data*
that is then fully validated, never an executable, and every adapter that data can
name must still be a real file inside the registry's `module_root`.

**(hardening)** It is not honoured unconditionally. The document it selects decides
network policy, credential identities, read grants and resource caps, so an
environment-selected manifest root is the same defect class as an
environment-selected executable, one layer up. The directory must exist, not be a
symlink, be owned by root or the invoking user, and not be group- or world-writable.
Otherwise a line goes to stderr and the packaged root is used:

```
ignoring SHADOWFETCH_PROVIDER_MANIFESTS=/tmp/x: it must be a directory you own that
is not group- or world-writable
```

The unit tests never use the variable — they construct
`ProviderRegistry(root=…, module_root=…)` directly — so it exists for manual QA:

```sh
SHADOWFETCH_PROVIDER_MANIFESTS=~/my-manifests \
  python3 /usr/lib/shadowfetch/missions/sf_missions.py capabilities
```

---

## 2. Every field

### Top level

#### `schema_version` — integer, **required**, must be exactly `1`
The version of the manifest *format*, bumped only when the format changes
incompatibly. Not the provider's version.
**Wrong:** any other value fails `must be 1`; the manifest is skipped with an error
in `registry.errors` and the provider does not exist.

#### `id` — string, **required**, `^[a-z][a-z0-9-]{1,38}[a-z0-9]$`
Stable provider identity. It is persisted in the `provider_id` column of every
mission row, so it is effectively permanent: never reuse an id for a different
provider.
**Wrong:** a bad pattern skips the manifest. An id that does not equal the filename
stem is refused separately (§3). An id already claimed by another manifest causes
**both** manifests to be dropped.

#### `display_name` — string, **required**, 1–60 characters
What a person sees: the Control Center's provider chooser, the Readiness summary
line, and every refusal message (`"<display_name> does not perform code change"`,
`"<display_name> failed (exit 1): …"`).
**Wrong:** over 60 characters is a rejection. It is not truncated for you.

#### `interface_version` — integer, **required**, ≥ 1
Which `AgentProvider` ABI the adapter implements. `sf_providers.INTERFACE_VERSION`
is `1`.
**Wrong:** a mismatch is *not* a load failure — the registry creates an entry, marks
it unusable, and reports `needs provider interface v99, this system implements v1`.
The provider appears in `ids()` and `describe()` and is never returned by `list()`,
`for_capability()` or `get()`. The release gate refuses it outright
(`SUPPORTED_INTERFACE_VERSIONS = {1}`).

#### `adapter_module` — string, **required**, `^sf_provider_[a-z0-9_]{1,40}$`
The Python module implementing the adapter, resolved **only** against the registry's
`module_root` (`/usr/lib/shadowfetch/missions`). The pattern cannot express a dotted
path or a traversal; `ProviderRegistry._instantiate()` re-checks it anyway so the
guarantee is local to the code that acts on it, and **(hardening)** loads the module
from that exact file rather than by name through `sys.path`.
**Wrong:** a bad name, or a name whose `.py` file is not in `module_root`, produces
an unusable entry: `adapter module sf_provider_x is not installed at
/usr/lib/shadowfetch/missions`. The release gate additionally refuses a manifest
naming an adapter that does not ship.

#### `adapter_class` — string, **required**, `^[A-Z][A-Za-z0-9]{2,48}$`
The class inside that module, constructed as
`klass(manifest, sandbox_from_manifest(manifest))`.
**Wrong:** a missing attribute or a constructor that raises gives
`adapter failed to load: AttributeError: …`. A class that is not an `AgentProvider`
subclass gives `X is not an AgentProvider`. Either way the entry is unusable and the
rest of the registry keeps working.

#### `capabilities` — array of enum, **required**, ≥ 1 item, unique
Any of `"code_change"`, `"sourced_report"`, `"media_export"`. Capability is *what*
the user wants; the provider is *who* performs it.
**Wrong:** an unknown string is a schema rejection. Under-declaring is silent and
total: `for_capability()` will never offer the provider, the Control Center's
chooser will never list it for that mission kind, and `accepts()` refuses with
`"<display_name> does not perform …"`. Over-declaring is worse — the provider is
offered work its `build_invocation()` cannot build, and the conformance suite fails
it.

#### `credential_ids` — array of string, **required** (may be `[]`), unique,
`^[A-Z][A-Z0-9_]{2,60}$`
Credential **identities**, never values. `Executor.credentials_for()` looks each one
up in the mission worker's environment and hands the value to Firebreak as
`--credential-env NAME`. An adapter puts the same list in `Invocation.env_allowlist`
and never sees a value.
**Wrong:** an entry that is not a bare identifier is rejected by the schema *and*
separately by the release gate (`credential_ids must be identities, not values`).
`[]` means the provider gets nothing: `env_allowlist` must be empty, and both the
conformance suite and `verify_invocation()` enforce that.

#### `credential_aliases` **(hardening)** — object, optional
Maps a historical environment variable name to a declared identity, e.g.
`{"OPENAI_API_KEY": "CODEX_API_KEY"}`. Both key and value must match
`^[A-Z][A-Z0-9_]{2,60}$`, and the value must also appear in `credential_ids` or the
alias is ignored at runtime. It exists so the orchestrator needs no per-provider
branch to honour an older spelling — it replaced the last
`if provider.id == "codex":` in `sf_missions.py`.
**Wrong:** a value not present in `credential_ids` silently does nothing. The schema
cannot express that cross-check.

#### `network_policy` — enum, **required**, `"none"` or `"allowlist"`
The **most** network this provider may ever request. `"none"` runs the sandbox with
no network. `"allowlist"` additionally requires a non-empty `egress_allowlist`. An
adapter cannot widen it: `narrow()` refuses to add network to a `"none"` spec, and
`verify_invocation()` refuses it again at execution time.
**Wrong:** see §3. Practically: declaring `"allowlist"` when you do not need it hands
your provider a connection a reviewer has to justify; declaring `"none"` when you do
need it means every invocation runs `--net none` and your program simply cannot
reach anything.

`Store.create()` uses this for the mission's default when the caller did not
specify: `network = "none" if manifest["network_policy"] == "none" else "allow"`.
`capabilities()` publishes `requires_network_approval = network_policy != "none"`,
which is what the Control Center uses to decide whether to demand explicit consent.

#### `egress_allowlist` — array of string, optional, unique, hostname pattern
(`^(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`, so a
leading `*.` wildcard is allowed)
The hosts this provider may reach.
**Not enforced at the sandbox boundary today.** `SandboxSpec.firebreak_network`
collapses `"allowlist"` to Firebreak's `allow`, because `allow` is the strongest
posture the current sandbox can express. The list is carried on the `SandboxSpec`,
republished by `capabilities()`, checked by `narrow()` and `verify_invocation()`, and
is what a future egress filter will enforce. Declaring hosts you do not contact will
make that future change harmless; declaring hosts you do not need makes it break you.

#### `package` — string, **required**, `^[a-z][a-z0-9+.-]+$`
The Debian package that ships this manifest and its adapter. Republished by
`capabilities()`. Informational at runtime; the gate's job is to check the manifest
and the adapter it names ship together in one artifact.

#### `version` — string, **required**, `^[0-9]+\.[0-9]+\.[0-9]+`
The provider's own version. Recorded on every inference record as `provider_version`,
so a receipt says which build of the adapter produced an answer.

#### `notes` — string, optional, ≤ 2000 characters
Free prose. Not shown to a person anywhere; documentation for whoever reads the
manifest next.

---

### `sandbox_profile` — object, **required**, `additionalProperties: false`

This is the **ceiling**. `sandbox_from_manifest()` turns it into the `SandboxSpec`
the registry hands to the adapter, and `verify_invocation()` re-derives it from the
manifest at execution time so nothing can widen it.

#### `workspace_mode` — enum, **required**, `"read-only"` or `"workspace-write"`
`read-only` means the provider may not modify the mission workspace at all.
`workspace-write` means it may write inside the workspace and nowhere else.
**Wrong:** declaring `read-only` for a code-change provider makes its work
impossible. Declaring `workspace-write` when you only read hands the agent a writable
project directory it did not need — and per-invocation narrowing is available, which
is how `CodexCliProvider` handles a sourced report:

```python
read_only = capability == Capability.SOURCED_REPORT or bool(request.get("read_only"))
if read_only:
    sandbox = sandbox.narrow(workspace_mode="read-only")
```

#### `memory_mb` — integer, **required**, 64 – 32768
Passed to Firebreak as `--memory-mb`. Enforced.

#### `cpu_seconds` — integer, **required**, 10 – 7200
**Declared but not passed to the sandbox.** `Executor.run_process()` gives
`--cpu-seconds` the *mission's* `config["timeout"]`, not the spec's value. The schema
bound, the `narrow()` check, `verify_invocation()` and the conformance assertion all
operate on the declared number; Firebreak does not receive it. Declare it honestly
anyway — it is what a reviewer reads, and it is the number a future fix will use.

#### `processes` — integer, **required**, 1 – 512
Passed to Firebreak as `--processes`. Enforced.

#### `read_grants` — array of absolute paths, optional, unique, `^/[^\0]*$`
Paths the provider may read **outside** its workspace. Each becomes an explicit
`--read <path>` on the Firebreak command line. Firebreak's own denylist still applies
on top: no filesystem root, no whole home directory, no credential store.
**Wrong:** a relative path is refused twice — by the schema pattern, and by
`SandboxSpec.__post_init__` (`Read grants must be absolute paths: …`). Granting more
than you need is the failure that will not announce itself; grant the smallest
directory that works.

#### `account_mount` — enum, optional, currently only `"codex-account"`
A named credential store the sandbox should mount, declared as data so the
orchestrator forwards it without knowing which provider asked: `run_process()`
appends `"--" + spec.account_mount`, and only when no credential value resolved.
**Wrong:** any other string is a schema rejection. A new provider **cannot** declare
its own mount without changing the schema *and* adding a matching flag to
`shadowfetch-firebreak`. The closed set is intentional — the flag has to exist on the
other side — but it means this is not a field a provider author can use freely today.

#### `masked_paths` — array of absolute paths, optional, unique
Paths that must not be visible even if another grant would expose them.
**Declared and checked, but never forwarded.** `narrow()` refuses to drop one and
`verify_invocation()` refuses an invocation that dropped one, but `run_process()`
does not pass them to Firebreak. Do not rely on this field for containment.

---

### `executable` — object, optional, `additionalProperties: false`

How the provider's program is located. `PATH` resolution is deliberately not an
option, in any form: Phase 1 removed several `PATH`- and environment-selected
privileged executables, and this format does not allow the class back in.

#### `kind` — enum, **required within the object**: `"absolute"`, `"candidates"`, `"none"`

* **`"absolute"`** — requires `path`, `^/[^\0]*$`. One fixed program.
  `offline-media.json` uses this: `{ "kind": "absolute", "path": "/usr/bin/ffmpeg" }`.
  The conformance suite asserts the declared path is actually the executable of at
  least one invocation the adapter builds, so a declaration nothing uses cannot pass.
* **`"candidates"`** **(hardening)** — requires `candidates`, a non-empty array of
  absolute or `~/`-relative globs. This is the preferred form, because the manifest —
  not the environment — decides what may run. `resolve_executable()` tries them in
  order and returns the first existing, executable, trust-passing match; matches
  within one glob are sorted in reverse, so the lexicographically highest — typically
  the newest versioned directory — wins. A pattern that is neither absolute nor
  `~/`-relative is skipped, so a relative lookup can never happen. Put packaged
  locations first; later entries are fallbacks.
* **`"none"`** — the provider runs no program of its own. Nothing is checked.

Omitting the whole `executable` block is legal (it is not in the top-level `required`
list) and is treated as `{"kind": "none"}` by the release gate, which means neither
the gate nor `resolve_executable()` can help you. Declare it.

> The schema's own `executable.description` still describes a `"resolver"` kind. That
> kind was removed from the `kind` enum during the hardening pass; the prose is stale.

#### `trust` — enum, optional, `"system"` (default) or `"user-runtime"` **(hardening)**
Where the program is allowed to live. `trusted_executable()` enforces it on whatever
`resolve_executable()` returns, and again inside `verify_invocation()` at execution
time.

* `"system"` — the resolved path must start with one of
  `/usr/bin/`, `/usr/sbin/`, `/usr/libexec/`, `/usr/lib/`,
  `/usr/local/lib/shadowfetch/`, `/bin/`, `/sbin/`, `/opt/`.
* `"user-runtime"` — additionally permits a program under the user's home, and then
  requires it to be **owned by the invoking user** and **not world-writable**. This
  exists because the Codex CLI is genuinely an npm install. Declaring it makes the
  exception visible in review instead of universal.

**Wrong:** a program outside the trusted prefixes with `trust` unset (or `"system"`)
is refused at readiness time (the provider reports itself not installed) and again at
execution time:

```
Provider executable /home/u/evil is outside the packaging-owned directories and its
manifest does not declare a user-runtime executable. …
```

A group-writable `user-runtime` program is currently accepted, because npm and nvm
install 0775 under the user's personal group. That residual risk is named in
`trusted_executable()`'s docstring.

The release gate does **not** currently inspect `trust`; it only checks that
`candidates` entries are absolute or `~/`-relative. Declaring `"user-runtime"` is
therefore visible in review but is not gate-refused, so it is a judgement call at
review time rather than a mechanical one.

#### `candidates` — array of string, required when `kind` is `"candidates"`, ≥ 1, unique, `^(~/|/)[^\0]*$`
Ordered globs. `~/` means the invoking user's home. Example, from `codex.json`:

```json
"candidates": [
  "/usr/bin/codex",
  "/usr/local/bin/codex",
  "~/.nvm/versions/node/*/bin/codex",
  "~/.local/share/npm/bin/codex",
  "~/.npm-global/bin/codex",
  "~/.local/bin/codex"
]
```

#### `runtime_root_markers` — array of string, optional, unique, `^[@A-Za-z0-9._-]{1,64}$` **(hardening)**
Directory names that, if found among the executable path's parents, mark the root of
its runtime distribution. `run_process()` grants the sandbox `--read` on that root so
the program can load its own files. Without markers, only the executable's own
directory is granted. `codex.json` declares `["codex", "@openai"]`; that logic used to
be a literal tuple in the orchestrator.
**Wrong:** omitting it for a program that needs sibling files (a node CLI, a Python
entry point) means the program starts and then fails to import its own modules.

---

## 3. Cross-field rules

Enforced in three places — the JSON Schema, the release gate
(`tools/providers/validate_manifest.py`), and `sf_providers.load_manifest()` — so the
same failure produces different wording depending on which caught it.

| Rule | Where | Message |
|---|---|---|
| `network_policy: "allowlist"` ⟹ `egress_allowlist` with ≥ 1 host | schema `allOf`, gate | *"An allowlist network policy without an allowlist would be an unbounded grant wearing a policy's name."* |
| `network_policy: "none"` ⟹ `egress_allowlist` has 0 items | schema `allOf`, gate | `declares no network yet carries an egress allowlist` |
| `executable.kind: "absolute"` ⟹ `path` present and absolute | schema `if/then`, gate | `executable path must be absolute` |
| `executable.kind: "candidates"` ⟹ `candidates` present, every entry `/` or `~/` | schema `if/then`, gate | `executable candidate 'codex' is not absolute; a provider program is never located through PATH` |
| Filename stem must equal `id` | `load_manifest()`, gate | `manifest filename must match its id 'x', so a provider cannot be shadowed by a second file claiming the same id` |
| `id` unique across the manifest set | registry, gate | `duplicate provider id 'x'; refusing both` |
| Adapter named by the manifest must ship | gate | `names adapter sf_provider_x but usr/lib/shadowfetch/missions/sf_provider_x.py does not ship` |
| Adapter code must be named by **some** manifest | gate | `Provider adapter code ships that no validated manifest names, so it could be reached without policy review` |
| Every capability the product offers must have ≥ 1 provider | gate | `No shipped provider performs: media_export` |
| No shipped path may match `REMOVED_AI_PATH` | gate | `Deferred local-AI payload remains: …` |

The filename rule is the one that surprises people: `codex.json` must contain
`"id": "codex"`. It exists so a second file cannot claim an installed provider's
identity and win a glob ordering race.

---

## 4. A real manifest, annotated

`offline-media.json`, exactly as it ships. (JSON has no comments; annotations follow.)

```json
{
  "schema_version": 1,
  "id": "offline-media",
  "display_name": "Offline media export (ffmpeg)",
  "interface_version": 1,
  "adapter_module": "sf_provider_offline_media",
  "adapter_class": "OfflineMediaProvider",
  "capabilities": ["media_export"],
  "credential_ids": [],
  "network_policy": "none",
  "egress_allowlist": [],
  "sandbox_profile": {
    "workspace_mode": "workspace-write",
    "memory_mb": 3072,
    "cpu_seconds": 900,
    "processes": 96,
    "read_grants": [],
    "masked_paths": []
  },
  "executable": { "kind": "absolute", "path": "/usr/bin/ffmpeg" },
  "package": "shadowfetch-missions",
  "version": "4.0.0",
  "notes": "A deliberately non-LLM provider. …"
}
```

* `id` is `offline-media` and the file is `offline-media.json`. The legacy runtime
  string for the same thing is `offline`; `LEGACY_RUNTIME_PROVIDER` maps one to the
  other, and that rename is the only one the v2 database migration performs.
* One capability, so `for_capability("media_export")` returns this provider and
  nothing else and `default_for()` picks it with no ambiguity.
* `credential_ids: []` and `network_policy: "none"` together mean the invocation
  carries no `env_allowlist`, the `SandboxSpec` carries no `egress_allowlist` (it
  could not — `SandboxSpec.__post_init__` refuses that combination), and every
  invocation runs `--net none`.
* `workspace_mode: "workspace-write"` because exports are written into
  `mission-output/<mission-id>/` inside the workspace.
* `executable.kind: "absolute"` names ffmpeg; the adapter also runs
  `/usr/bin/ffprobe`. The conformance assertion is that the *declared* path is used by
  at least one invocation, not that it is the only program — the probe stage
  legitimately runs ffprobe.

And the cloud provider, `codex.json`, showing the other posture:

```json
{
  "capabilities": ["code_change", "sourced_report"],
  "credential_ids": ["CODEX_API_KEY"],
  "credential_aliases": { "OPENAI_API_KEY": "CODEX_API_KEY" },
  "network_policy": "allowlist",
  "egress_allowlist": ["api.openai.com", "chatgpt.com", "auth.openai.com"],
  "sandbox_profile": {
    "workspace_mode": "workspace-write",
    "memory_mb": 3072, "cpu_seconds": 900, "processes": 96,
    "read_grants": [], "masked_paths": [],
    "account_mount": "codex-account"
  },
  "executable": {
    "kind": "candidates",
    "trust": "user-runtime",
    "candidates": ["/usr/bin/codex", "/usr/local/bin/codex",
                   "~/.nvm/versions/node/*/bin/codex", "~/.local/share/npm/bin/codex",
                   "~/.npm-global/bin/codex", "~/.local/bin/codex"],
    "runtime_root_markers": ["codex", "@openai"]
  }
}
```

Two capabilities, one credential identity plus one historical alias, three egress
hosts, a declared account mount, and an explicitly declared user-runtime executable
with its search order and its runtime root markers.

## 5. The minimum legal manifest

Every required key and nothing else. Verified to load:

```json
{
  "schema_version": 1,
  "id": "minimal-example",
  "display_name": "Minimal example",
  "interface_version": 1,
  "adapter_module": "sf_provider_minimal_example",
  "adapter_class": "MinimalExampleProvider",
  "capabilities": ["sourced_report"],
  "credential_ids": [],
  "network_policy": "none",
  "sandbox_profile": {
    "workspace_mode": "read-only",
    "memory_mb": 512,
    "cpu_seconds": 60,
    "processes": 8
  },
  "package": "shadowfetch-missions",
  "version": "1.0.0"
}
```

It declares no `executable`, so nothing can check how its program is found. Add
`executable` in anything real.

---

## 6. Why the validator is hand-written

`sf_jsonschema.py` is a stdlib-only JSON Schema subset validator, and the manifest is
validated with it in both the running engine and the release gate — the gate imports
the very same module the installed system uses, so the two cannot disagree.

The reason is packaging, and the module docstring states it: no shipped Shadowfetch
package depends on `python3-jsonschema`, and live-build never installs it. Depending
on it would mean a registry that works on the build host and fails on a user's
machine — a manifest that validates in CI and leaves the desktop with no providers at
all.

The dangerous failure mode for a hand-written validator is **silently ignoring a
keyword it does not implement**: the schema author believes a constraint is enforced
and it never runs. So `check_schema()` runs first, on every call to `validate()`, and
**refuses** a schema containing any keyword outside its supported set, and refuses an
unknown `"type"`:

```python
unknown = sorted(set(schema) - _SUPPORTED)
if unknown:
    raise SchemaError(
        f"{path}: unsupported schema keyword(s) {', '.join(unknown)}. This "
        "validator refuses rather than ignoring them, because a silently "
        "skipped constraint is worse than no constraint.")
```

A constraint either runs or the whole validation is an error. It is never quietly
skipped.

Supported: `type`, `enum`, `const`, `required`, `properties`, `additionalProperties`,
`propertyNames`, `items`, `minItems`, `maxItems`, `uniqueItems`, `minLength`,
`maxLength`, `pattern`, `minimum`, `maximum`, `allOf`, `anyOf`, `oneOf`, `not`,
`if`/`then`/`else`, plus the annotation-only keywords `$schema`, `$id`, `title`,
`description`, `examples`, `default`, `deprecated`.

**If you extend the schema, you may only use keywords from that list.** Adding
`$ref`, `patternProperties`, `dependentRequired`, `minProperties`, `prefixItems`,
`format` or `multipleOf` does not weaken validation — it breaks it completely, because
every `load_manifest()` call raises `SchemaError` and the registry loads **no
providers at all**. Extend `sf_jsonschema.py` first if you need one.

Two behaviours differ from a full implementation and are worth knowing:

* `pattern` uses `re.search`, not a full match. Anchor your patterns with `^…$` — the
  shipped schema does.
* `uniqueItems` compares with `==` over a list, which is O(n²) but correct for the
  small arrays a manifest carries.

The commit that introduced it records that it was differentially tested against the
real `jsonschema` package on 22 documents, 20 of them rejections, and agreed on every
one.
