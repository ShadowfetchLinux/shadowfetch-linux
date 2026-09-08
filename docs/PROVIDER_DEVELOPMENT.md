# Writing an agent provider

A walkthrough. Follow it start to finish and you will have a new provider that
Mission Control discovers, the Control Center offers, and the release gate accepts —
**without editing Mission Control, the CLI, the desktop UI or the gate**. That claim
is enforced by a test; see §9.

**Version.** Written against `release/4.0.0` at `85472f7` (2026‑09‑08), which
includes `2d4b1cf` (the Phase 2 adversarial pass) and `988173b` (the conformance
suite). Field semantics are in `docs/PROVIDER_MANIFEST.md`; the surrounding
architecture is in `docs/AGENT_ARCHITECTURE.md`.

The running example is a hypothetical **Claude CLI provider**. Everything below was
executed against the real registry: it loads, filters by capability, narrows for a
read-only report, builds a deterministic invocation, normalises its stream and
survives the hostile battery. The *argv* is a plausible shape, not a verified command
line for any real product — replace it with what your program actually accepts.

---

## The two files you write

```
packages/shadowfetch-missions/data/usr/share/shadowfetch/providers/claude-cli.json
packages/shadowfetch-missions/data/usr/lib/shadowfetch/missions/sf_provider_claude_cli.py
```

Plus, for the conformance suite, one profile and two stream fixtures under
`packages/shadowfetch-missions/tests/`.

That is the whole surface.

---

## 1. Write the manifest

The filename stem **must** equal the `id`. Start from this:

```json
{
  "schema_version": 1,
  "id": "claude-cli",
  "display_name": "Claude Code CLI (cloud)",
  "interface_version": 1,
  "adapter_module": "sf_provider_claude_cli",
  "adapter_class": "ClaudeCliProvider",
  "capabilities": ["code_change", "sourced_report"],
  "credential_ids": ["ANTHROPIC_API_KEY"],
  "network_policy": "allowlist",
  "egress_allowlist": ["api.anthropic.com"],
  "sandbox_profile": {
    "workspace_mode": "workspace-write",
    "memory_mb": 3072,
    "cpu_seconds": 900,
    "processes": 96,
    "read_grants": [],
    "masked_paths": []
  },
  "executable": {
    "kind": "candidates",
    "candidates": ["/usr/bin/claude",
                   "/usr/lib/claude-cli/bin/claude",
                   "/opt/claude/bin/claude"],
    "runtime_root_markers": ["claude-cli"]
  },
  "package": "shadowfetch-missions",
  "version": "1.0.0",
  "notes": "Reads its prompt on stdin and emits one JSON object per line."
}
```

Decisions worth making deliberately:

* **`capabilities`** — declare only what `build_invocation()` can actually build.
  Over-declaring gets you offered work you cannot do; under-declaring makes you
  invisible for that mission kind.
* **`network_policy`** — the *most* network you may ever request. It also becomes the
  mission's default network setting in `Store.create()` and drives
  `requires_network_approval` in the desktop, which is what makes the UI demand
  explicit consent.
* **`sandbox_profile`** — the ceiling. You can narrow per invocation; you can never
  widen. Ask for the least that works.
* **`credential_ids`** — identities. If the list is empty, your `env_allowlist` must
  be empty too, and both the conformance suite and `verify_invocation()` enforce it.
* **`executable.candidates`** — packaged locations first. Every entry must start with
  `/` or `~/`; there is no third option, deliberately.

Validate it before you write any Python:

```sh
PYTHONPATH=packages/shadowfetch-missions/data/usr/lib/shadowfetch/missions \
python3 -c '
import sf_providers as p
m = p.load_manifest("packages/shadowfetch-missions/data/usr/share/shadowfetch/providers/claude-cli.json")
print(m["id"], "->", p.sandbox_from_manifest(m))'
```

A `ManifestError` here names the exact JSON path that failed.

---

## 2. Write the adapter

### What you must implement

Three methods raise `NotImplementedError` on the base class. They are the contract:

| Method | Must return |
|---|---|
| `readiness(self)` | a `Readiness` — is the program installed, is there a credential, and if not, what should a person do |
| `build_invocation(self, capability, request)` | an `Invocation` — one process for the orchestrator to run |
| `parse_stream(self, text)` | a `list[AgentEvent]` — your native output, normalised. **Never raises.** |

### What you get for free

| Member | Default behaviour | Override when |
|---|---|---|
| `id`, `display_name`, `version`, `interface_version` | read from the manifest | never |
| `capabilities()`, `supports(c)` | the manifest's `capabilities` | never — a second opinion is a bug, and the suite fails you for it |
| `accepts(capability, config)` | refuses an undeclared capability with a reason, accepts anything else | you have a real precondition (network, inputs, an unsupported option) |
| `sandbox_for(capability, config)` | the registry-built `SandboxSpec` | you want to *narrow* for a particular job |
| `turn_succeeded(events)` | a `turn-complete` and no `error` | your native protocol says something more specific |
| `usage(events)` | the last `turn-complete`'s `data["usage"]` | your usage arrives elsewhere |
| `final_message(events)` | the last non-empty `message` text | you have more than one kind of message |

`sf_providers.resolve_executable(manifest)` is also given to you — it implements the
whole `executable` block. You should not write your own lookup.

### What you must not do

* **Do not widen the sandbox.** Start from `sandbox_for()` and use `.narrow(...)`.
  Constructing a fresh `SandboxSpec` with larger values is refused at execution time
  by `verify_invocation()` and caught earlier by the conformance suite
  (`conformance-widen` exists precisely to prove it is caught).
* **Do not put a credential value anywhere.** `env_allowlist` holds *names*;
  `Invocation.__post_init__` rejects anything that is not `[A-Z][A-Z0-9_]*`. Never
  read a secret into argv, into a file the invocation points at, or into the label.
* **Do not let `parse_stream()` raise.** A provider's output is untrusted input.
* **Do not resolve your program yourself.** §3.
* **Do not import `sf_missions`.** The dependency runs one way. An adapter that
  reaches into the orchestrator has re-created the coupling this phase removed.
* **Do not execute anything.** `build_invocation()` returns a description; the
  orchestrator runs it inside Firebreak. An adapter that calls `subprocess` itself
  has escaped the sandbox by definition.
* **Do not do failable work in `__init__`.** A constructor that raises makes the whole
  provider unusable with `adapter failed to load: …`. Probe the world in
  `readiness()`, where the failure is reportable.
* **Keep `build_invocation()` deterministic.** Same request in, byte-identical argv
  out — `test_argv_is_deterministic` builds each request twice and compares.

### The complete adapter

```python
"""Claude CLI provider adapter.

Nothing in this file is imported by the orchestrator. It becomes reachable only
because claude-cli.json, a validated manifest, names it.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

try:
    from sf_providers import (Acceptance, AgentEvent, AgentProvider, Capability,
                              Invocation, ProviderError, Readiness, resolve_executable)
except ImportError:  # source tree
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from sf_providers import (Acceptance, AgentEvent, AgentProvider, Capability,
                              Invocation, ProviderError, Readiness, resolve_executable)

CREDENTIAL = "ANTHROPIC_API_KEY"


class ClaudeCliProvider(AgentProvider):
    """A cloud coding agent, run inside Firebreak with explicit network consent."""

    CAPABILITIES = (Capability.CODE_CHANGE, Capability.SOURCED_REPORT)

    # -- readiness ---------------------------------------------------------
    def readiness(self) -> Readiness:
        # The manifest says where the program may live; resolve_executable
        # applies that declaration and the trust tier. No lookup lives here.
        binary = resolve_executable(self.manifest)
        missing = []
        facts = {}
        if binary:
            facts["executable"] = binary
        else:
            missing.append("claude executable")

        api_key_configured = bool(os.environ.get(CREDENTIAL))
        facts["api_key_configured"] = api_key_configured
        if not api_key_configured:
            missing.append("authentication")

        return Readiness(
            installed=bool(binary),
            authenticated=api_key_configured,
            missing=tuple(missing),
            facts=facts,
            reason="" if (binary and api_key_configured) else (
                f"Install the Claude CLI and save a user-owned 0600 {CREDENTIAL} "
                "environment file for the mission worker, then restart the idle "
                "worker. A stored credential is not a verified login."),
        )

    # -- acceptance --------------------------------------------------------
    def accepts(self, capability: str, config: dict) -> Acceptance:
        base = super().accepts(capability, config)      # refuses undeclared work
        if not base.ok:
            return base
        config = config or {}
        if config.get("network") != "allow":
            return Acceptance.no(
                "Claude is a cloud agent and requires explicit network approval for "
                "this mission. Allow a connection for it, or choose a provider that "
                "works offline.")
        if config.get("model"):
            return Acceptance.no(
                "Mission model selection is unavailable; the CLI default is used.")
        return Acceptance.yes()

    # -- invocation --------------------------------------------------------
    def build_invocation(self, capability: str, request: dict) -> Invocation:
        binary = resolve_executable(self.manifest)
        if not binary:
            raise ProviderError("The Claude CLI is not installed")
        request = request or {}
        prompt_path = request.get("prompt_path")
        if not prompt_path:
            raise ProviderError("Claude requires a prompt file")

        # A sourced report never writes; narrow the workspace for it. narrow()
        # can only remove permission, so this can never be a widening.
        read_only = (capability == Capability.SOURCED_REPORT
                     or bool(request.get("read_only")))
        sandbox = self.sandbox_for(capability, request.get("config") or {})
        if read_only:
            sandbox = sandbox.narrow(workspace_mode="read-only")

        argv = (
            "--print",
            "--output-format", "stream-json",
            "--permission-mode", "plan" if read_only else "acceptEdits",
        )
        return Invocation(
            executable=binary,
            # Carried so the orchestrator can honour the declared trust tier and
            # runtime_root_markers without knowing which provider this is.
            manifest_executable=self.manifest.get("executable"),
            argv=argv,
            stdin_path=str(prompt_path),
            # Identities only. The value is injected at the Firebreak boundary by
            # code that did not come from a provider, and never travels here.
            env_allowlist=tuple(self.manifest.get("credential_ids") or ()),
            sandbox=sandbox,
            label="claude",
        )

    # -- stream ------------------------------------------------------------
    def parse_stream(self, text: str):
        """One JSON object per line. Anything else on the stream -- Firebreak's
        session trailer, a partial write, an interleaved warning -- is carried
        through as a log event rather than being allowed to break the turn."""
        events = []
        for line in (text or "").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except ValueError:
                events.append(AgentEvent(AgentEvent.LOG, line[:2000]))
                continue
            if not isinstance(raw, dict):
                events.append(AgentEvent(AgentEvent.LOG, line[:2000]))
                continue
            kind = raw.get("type")
            if kind == "result":
                if raw.get("is_error"):
                    events.append(AgentEvent(
                        AgentEvent.ERROR,
                        str(raw.get("result") or "the agent reported a failure")[:2000],
                        {"raw_type": kind}))
                else:
                    events.append(AgentEvent(AgentEvent.MESSAGE,
                                             str(raw.get("result") or "")))
                events.append(AgentEvent(AgentEvent.TURN_COMPLETE, "",
                                         {"usage": raw.get("usage")}))
            elif kind == "error":
                events.append(AgentEvent(AgentEvent.ERROR,
                                         str(raw.get("message") or kind)[:2000],
                                         {"raw_type": kind}))
            else:
                events.append(AgentEvent(AgentEvent.PROGRESS, "", {"raw_type": kind}))
        return events
```

Note what is *not* there: no `subprocess`, no path lookup of its own, no reference to
`sf_missions`, no credential value, and no override of `turn_succeeded()` — after
parsing, `result`/`error` *is* the generic rule.

Observed behaviour of exactly this pair, in a real `ProviderRegistry`:

```
errors: []                              ids: ['claude-cli']
capabilities: ('code_change', 'sourced_report')      supports media_export: False
accepts media_export: "Claude Code CLI (cloud) does not perform media export"
accepts code_change with no network: "Claude is a cloud agent and requires explicit …"
code_change sandbox: workspace-write / allow    sourced_report sandbox: read-only
deterministic argv: True
success stream -> ['progress', 'message', 'turn-complete'], final "The launch is Friday."
failure stream -> ['progress', 'error', 'turn-complete'], turn_succeeded False
hostile battery failures: 0
```

---

## 3. Locating your executable without `PATH`

**You do not write a lookup.** The manifest declares where the program may live and
`sf_providers.resolve_executable(manifest)` applies that declaration.

```json
"executable": { "kind": "absolute", "path": "/usr/bin/ffmpeg" }
```

```json
"executable": {
  "kind": "candidates",
  "candidates": ["/usr/bin/claude", "/opt/claude/bin/claude"]
}
```

`candidates` entries are absolute or `~/`-relative globs, tried in the order you list
them; the first existing, executable, trust-passing match wins. A pattern that is
neither absolute nor `~/`-relative is skipped, so a relative lookup cannot happen.
When the program is simply not installed, `resolve_executable()` returns `None` —
that is a readiness answer, not an error. Report it in `readiness()` and raise
`ProviderError` from `build_invocation()`.

Whatever comes back is re-checked by `trusted_executable()`, because an adapter is
packaged code but its *output* is not trusted. `trust: "system"` (the default)
requires one of:

```
/usr/bin/  /usr/sbin/  /usr/libexec/  /usr/lib/  /usr/local/lib/shadowfetch/
/bin/  /sbin/  /opt/
```

`trust: "user-runtime"` additionally permits a program under the user's home — it
exists because the Codex CLI is genuinely an npm install — and then requires that the
file be owned by the invoking user and not world-writable. **Declare
`"user-runtime"` only if you must**, because it is the exception being made visible;
prefer packaging your program into a system directory.

The check runs twice: once when your adapter resolves the program, and again inside
`verify_invocation()` at the moment of execution. A program outside the tier is
refused with:

```
Provider executable /home/u/evil is outside the packaging-owned directories and its
manifest does not declare a user-runtime executable. …
```

### What the conformance suite forbids in your source

The suite parses your adapter's AST and fails you for `shutil.which(...)`, any call
named `which` or `get_exec_path`, and reads of `os.environ["PATH"]` /
`os.environ.get("PATH")`. It is a source assertion on purpose: the defect it guards
against — a provider program chosen by whatever `PATH` happens to say — is invisible
at runtime on a machine where `PATH` is benign.

> **History worth knowing.** Before the hardening pass, `codex.json` declared a third
> kind, `"resolver"`, naming a function in the adapter, and that function delegated to
> `sf_mission_account.codex_executable()` — which is `shutil.which('codex')`. The
> program was absolute but the environment chose it, and on the build host it resolved
> to `~/.nvm/versions/node/v22.22.3/…/codex`. Two conformance assertions failed on
> that, correctly, and `"resolver"` was removed in favour of `candidates` + `trust`.
> If your program can only be found somewhere user-writable, that is a packaging
> problem, not an adapter problem.

### Sibling files your program needs

If your executable lives outside `/usr/`, `/bin/`, `/sbin/` or `/lib/`, the sandbox
needs read access to its runtime distribution. Declare
`executable.runtime_root_markers` — directory names that, if found among the
program's parents, mark that root. `codex.json` declares `["codex", "@openai"]`.
Without markers, only the executable's own directory is granted, and a node or Python
CLI will start and then fail to import its own modules.

---

## 4. Normalising your native stream

`Executor.agent_turn()` hands you the **entire** captured log — stdout and stderr
merged, truncated at 2 MB, with Firebreak's own session trailer appended — and expects
a list of `AgentEvent`. Six types exist:

```
message         the answer a person reads (final_message takes the last non-empty one)
progress        something happened; not for a person
usage           resource accounting reported mid-stream
log             output you did not understand — carry it, never drop it
error           the provider said it failed
turn-complete   the provider finished a turn
```

Rules that are actually enforced:

1. **Never raise.** The suite runs a 21-case hostile battery against every provider:
   empty string, `None`, blank lines, a bare `{`, truncated JSON, NUL bytes, single
   quotes, `null`, an array, a bare string, a null item, a numeric `type`, a missing
   `type`, a 200 000-character line, 3000 lines, non-ASCII text, CRLF line endings,
   surrogate-escaped binary, and 200-deep nesting. `parse_stream()` **and**
   `final_message()` must survive all of them.
2. **Unparseable input becomes a `log` event** — not an exception and not silence.
   Truncate it (the shipped adapters use `[:2000]` for logs and `[:500]` for
   progress), so one enormous line cannot fill the receipt.
3. **A successful turn must contain exactly one thing the executor can see:** an event
   of type `turn-complete`, with no `error` event, unless you override
   `turn_succeeded()`.
4. **Failure must be distinguishable from success.** The suite requires your profile
   to supply at least one of each and asserts the two fixtures are not the same bytes.

Two shapes exist in the tree and both are legitimate:

* **The stream carries the outcome** (Codex, and the example above). Emit `error` on
  failure and `turn-complete` on success; the default `turn_succeeded()` works.
* **The exit status carries the outcome** (ffmpeg). `OfflineMediaProvider` appends
  `turn-complete` unconditionally and never emits an `error` event, because ffmpeg
  reports failure by exiting non-zero — and the executor checks the exit code *before*
  it looks at events. If that is your shape, say so in your profile's `notes` and
  distinguish your failure fixture by `exit_code`, as the media profile does.

---

## 5. Declaring and receiving credentials

You declare identities. You never see values.

```json
"credential_ids": ["ANTHROPIC_API_KEY"]
```

```python
env_allowlist=tuple(self.manifest.get("credential_ids") or ())
```

That is the whole of your involvement. What happens next, in code you did not write
and cannot influence:

1. `Executor.credentials_for(provider)` reads each declared identity out of the
   mission worker's own environment. If the manifest declares `credential_aliases`, a
   historical spelling of the same identity is honoured too — as data, with no
   provider-named branch anywhere.
2. `Executor.run_invocation()` calls `verify_invocation()` (which refuses an
   `env_allowlist` naming an undeclared credential) and passes the values to
   `run_process()`.
3. `run_process()` puts each **name** on the Firebreak command line as
   `--credential-env NAME` and each **value** into the child process environment.
   `shadowfetch-firebreak` decides what crosses into the sandbox.

The conformance suite plants sentinel values (`SENTINEL-…-MUST-NOT-LEAK-…`) in the
environment for every declared identity and asserts none appears in the executable,
argv, `env_allowlist`, `stdin_path`, `label` or the sandbox's `credential_ids`.

If your provider needs no credential, declare `"credential_ids": []`, leave
`env_allowlist` empty, and have `readiness()` return `authenticated=True`.
`OfflineMediaProvider` does exactly that, with the comment explaining why: an offline
tool is authenticated by definition, and saying so explicitly keeps the UI from
inventing a sign-in prompt for a provider that has no account.

**A dedicated credential store** (`sandbox_profile.account_mount`) is a closed enum
today — only `"codex-account"` — because the mount needs a matching flag on
`shadowfetch-firebreak`. Adding one is a schema change plus a Firebreak change, not
something you can do from a manifest alone.

---

## 6. Declaring network and sandbox needs

Everything in `sandbox_profile` is a **ceiling**. The registry builds the
`SandboxSpec` from it and hands it to your constructor; you may narrow it, and
`verify_invocation()` re-derives the ceiling from the manifest before anything runs,
so you cannot widen it even by building a spec from scratch:

```python
sandbox = self.sandbox_for(capability, config)          # the registry's spec
sandbox = sandbox.narrow(workspace_mode="read-only")    # allowed: removes permission
sandbox = sandbox.narrow(processes=4)                   # allowed: lowers a cap
sandbox = sandbox.narrow(read_grants=("/etc",))         # ProviderError
sandbox = sandbox.narrow(memory_mb=4096)                # ProviderError
```

`narrow()` refuses: adding network to a `none` spec, requesting an undeclared
credential, mounting an undeclared credential store, adding an egress host, adding a
read grant, dropping a declared masked path, raising `memory_mb` / `cpu_seconds` /
`processes`, and upgrading a read-only workspace to writable. Masked paths are the one
field whose safe direction is inverted — adding a mask narrows, removing one widens.

Guidance per field:

* **`network_policy`** — `none` if you can. If you need `allowlist`, list every host
  you actually contact. The list is not enforced by the sandbox today (Firebreak
  speaks `none`/`allow`), but it is recorded so a reviewer can see what was permitted,
  and it is what a future egress filter will use.
* **`workspace_mode`** — declare the *widest* mode any of your capabilities needs,
  then narrow per invocation. `code_change` needs `workspace-write`; `sourced_report`
  should be narrowed to `read-only`.
* **`read_grants`** — the smallest absolute directories that let your program work.
  Each becomes an explicit `--read`; Firebreak's denylist still applies on top (no
  filesystem root, no whole home directory, no credential store).
* **`memory_mb` / `processes`** — enforced. Ask for what you need.
* **`cpu_seconds`** — declared, schema-bounded (10–7200), narrowable, checked by
  `verify_invocation()`, and **not currently passed to Firebreak** (the mission's own
  timeout is). Declare it honestly anyway.
* **`masked_paths`** — declared and checked, never forwarded. Do not rely on it for
  containment.

---

## 7. Run the conformance suite

Every provider passes the same assertions. The suite is
`packages/shadowfetch-missions/tests/provider_conformance.py` (not named `test*.py`,
because its assertions are parameterised by a provider and mean nothing without one);
`test_provider_conformance.py` supplies the profiles and generates one `TestCase` per
provider.

### Write a profile

A `ProviderProfile` is everything the suite cannot read out of your manifest:

```python
def claude_requests(tmp):
    prompt = tmp / "prompt.md"
    prompt.write_text("Summarize the launch\n", encoding="utf-8")
    base = {"prompt_path": str(prompt), "config": {"network": "allow"}}
    return {
        Capability.CODE_CHANGE:    [dict(base), dict(base, read_only=True)],
        Capability.SOURCED_REPORT: [dict(base)],
    }

CLAUDE_PROFILE = ProviderProfile(
    provider_id="claude-cli",
    build_requests=claude_requests,        # >=1 valid request per DECLARED capability
    accept_configs={Capability.CODE_CHANGE:    {"network": "allow"},
                    Capability.SOURCED_REPORT: {"network": "allow"}},
    refusals=(                             # (capability, config, substring of the reason)
        (Capability.CODE_CHANGE, {}, "connection"),
        (Capability.CODE_CHANGE, {"network": "none"}, "connection"),
        (Capability.SOURCED_REPORT, {"network": "allow", "model": "x"},
         "model selection is unavailable"),
        (Capability.MEDIA_EXPORT, {"network": "allow"}, "does not perform"),
    ),
    streams=(                              # >=1 success and >=1 failure, different bytes
        StreamCase(name="claude_success.jsonl", text=stream("claude_success.jsonl"),
                   expect_types=("progress", "message", "turn-complete"),
                   expect_final="The launch is Friday.", expect_success=True, exit_code=0),
        StreamCase(name="claude_failed.jsonl", text=stream("claude_failed.jsonl"),
                   expect_types=("progress", "error", "turn-complete"),
                   expect_final="", expect_success=False, exit_code=1),
    ),
    binary_absent=claude_binary_absent,    # context managers over YOUR OWN seam
    binary_present=claude_binary_present,
    auth_absent=claude_auth_absent,        # or None if you have no account
    auth_present=claude_auth_present,
    invocation_context=claude_binary_present,
)
```

The environment seams are context managers over your own manifest or module, so no
live credential, no network and no real binary is ever used. Because the executable
now comes from the manifest, the seam is a manifest patch:

```python
@contextlib.contextmanager
def _claude_program(candidates):
    manifest = SHIPPED_REGISTRY.get("claude-cli").manifest
    original = manifest["executable"]["candidates"]
    manifest["executable"]["candidates"] = candidates
    try:
        yield
    finally:
        manifest["executable"]["candidates"] = original

def claude_binary_present(): return _claude_program(["/usr/bin/true"])
def claude_binary_absent():  return _claude_program(["/nonexistent/bin/claude"])
def claude_auth_present():   return mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "fixture"})
```

Put your captured streams in `tests/fixtures/providers/streams/`. Register the case:

```python
CASES = [..., ProviderCase(SHIPPED_REGISTRY, "claude-cli", CLAUDE_PROFILE, "claude_cli")]
PROFILES = {..., "claude-cli": CLAUDE_PROFILE}
```

`RegistryTests.test_every_registered_provider_has_a_conformance_profile` makes a
missing profile a loud failure rather than a silent gap.

### Run it

```sh
cd packages/shadowfetch-missions/tests
python3 -m unittest test_provider_conformance -v
```

### What each failure means

| Assertion | What it is telling you |
|---|---|
| `test_capabilities_are_internally_consistent_with_the_manifest` | Your adapter's `CAPABILITIES` constant disagrees with the manifest, or you overrode `capabilities()`. The manifest is the single source of truth. |
| `test_rejects_a_capability_it_does_not_declare_with_a_reason` | `accepts()` said yes to something you did not declare, or refused without a human-readable reason (four words minimum). Call `super().accepts()` first. |
| `test_registry_offers_this_provider_only_for_declared_capabilities` | `for_capability()` disagrees with your declaration — almost always a manifest typo. |
| `test_accepts_a_valid_request_and_refuses_the_documented_ones` | Your `accepts()` and your profile's `accept_configs`/`refusals` disagree. Either the precondition is wrong or the profile is. |
| `test_readiness_reports_a_missing_binary_with_a_reason` | With the program absent, `readiness()` must report `installed=False`, name it in `missing`, and carry a non-empty `reason`. |
| `test_readiness_reports_an_available_binary` | Your `binary_present` seam does not make `readiness()` see a program. **Note:** `resolve_executable()` requires the file to be executable (`os.access(..., X_OK)`), so a fixture that merely writes a file without `chmod +x` will fail here. |
| `test_readiness_reports_missing_authentication` / `…available_authentication` | Authentication state is not reflected. If you have no account, pass `auth_absent=None` and return `authenticated=True` — the suite then asserts you do *not* invent a sign-in prompt. |
| `test_a_readiness_call_that_raises_is_reported_not_propagated` | Structural; it should pass for free. If it fails, something is wrong with the registry, not your provider. |
| `test_every_invocation_uses_an_absolute_executable` | A relative or empty executable, or a relative `stdin_path`. |
| `test_the_manifest_executable_declaration_is_honoured` | `kind: "absolute"` but no invocation uses that path. **This assertion currently has no branch for `kind: "candidates"`** and silently checks nothing for such a provider — see §10. |
| `test_argv_is_deterministic` | Two builds of the same request differ — a timestamp, a temp name, an unsorted set. Sort your inputs. |
| `test_environment_allowlist_holds_no_undeclared_name_and_no_value` | An undeclared identity in `env_allowlist`, **or a credential value found anywhere in the invocation**. Treat the second as an incident, not a test failure. |
| `test_the_sandbox_it_carries_never_exceeds_the_manifest` | You built a `SandboxSpec` broader than your manifest — or built one from scratch instead of narrowing the one you were given. Also fires if `invocation.sandbox` is `None`. |
| `test_credential_identities_are_a_subset_of_the_manifest` | The same, for credentials. With `credential_ids: []` both `env_allowlist` and `sandbox.credential_ids` must be empty. |
| `test_a_captured_native_stream_normalises_to_the_expected_events` | Your parser and your fixture disagree — check the expected type sequence element by element. |
| `test_malformed_partial_and_interleaved_output_is_tolerated` | `parse_stream()` or `final_message()` raised on the hostile battery. The failure message names the case. |
| `test_end_of_turn_is_detected_and_failure_is_distinguishable` | No `turn-complete` on a successful stream, success and failure not distinguishable, or your profile omitted one of the two. |
| `test_a_long_running_invocation_is_built_with_bounded_limits` | A sandbox field is non-positive, above the schema ceiling (7200 s / 32768 MB / 512 processes) or above your own declaration. |
| `test_no_provider_obtains_an_implicit_network_grant` | A `none` provider produced a spec with network or an egress list, or an `allowlist` provider declared no hosts. |
| `test_narrow_refuses_to_add_anything_the_manifest_did_not_declare` | Structural; passes for free unless `SandboxSpec` itself changed. |
| `test_the_adapter_does_not_resolve_its_program_through_path` | `shutil.which`, `which`, `get_exec_path` or a `PATH` read in your adapter. §3. |
| `test_the_declared_resolver_chain_does_not_reach_path_resolution` | The same, one hop away, in a shipped sibling module your adapter imports. Skips unless `executable.kind` is the removed `"resolver"`, so today it never runs — §10. |

There are also six deliberately-broken fixture providers under
`tests/fixtures/providers/` — `conformance-widen`, `-relative`, `-secret`, `-which`,
`-crash`, `-undeclared` — each of which must fail a named subset of these assertions.
If you change the suite and they stop failing, you have weakened it.

---

## 8. Package it

Files go into the `shadowfetch-missions` package, whose `.install` is `data/* /` — so
the source path *is* the install path:

| Source | Installs to |
|---|---|
| `packages/shadowfetch-missions/data/usr/share/shadowfetch/providers/claude-cli.json` | `/usr/share/shadowfetch/providers/claude-cli.json` |
| `packages/shadowfetch-missions/data/usr/lib/shadowfetch/missions/sf_provider_claude_cli.py` | `/usr/lib/shadowfetch/missions/sf_provider_claude_cli.py` |

Set `"package": "shadowfetch-missions"` in the manifest to match.

`tools/providers/validate_manifest.py` runs from all three release gates
(`tools/source_gate_4_0_0.py`, `tools/package_gate_4_0_0.py`,
`tools/iso_gate_4_0_0.py`) against that artifact's own path inventory. **You do not
edit it.** It refuses your provider if:

* the manifest is not valid JSON, or does not satisfy the schema (using the same
  `sf_jsonschema` the runtime uses, so gate and runtime cannot disagree);
* the filename stem does not equal the `id`, or two manifests claim one id;
* a capability is outside `{code_change, sourced_report, media_export}`;
* `interface_version` is not 1;
* the adapter module the manifest names does not ship;
* `executable.kind` is `"absolute"` and the path is not absolute, or `"candidates"`
  and any entry does not start with `/` or `~/`, or is an unknown kind;
* a `credential_ids` entry is not a bare identity;
* `network_policy` and `egress_allowlist` disagree;
* **adapter code ships that no validated manifest names** — an orphan
  `sf_provider_*.py` is refused, because it could be reached without policy review;
* any shipped path matches `REMOVED_AI_PATH` (the retired local-AI stack), or
  `sf_missions.py` mentions `sf_local_compute`;
* after all that, some capability has no provider at all.

Run the gate's own tests plus the source gate before you propose the change:

```sh
python3 -m unittest discover -s tools/tests -v      # includes test_provider_manifest_gate
make source-gate
```

---

## 9. The files you must not have to edit — and the test that enforces it

```
packages/shadowfetch-missions/data/usr/lib/shadowfetch/missions/sf_missions.py
packages/shadowfetch-missions/data/usr/bin/shadowfetch-missions
packages/shadowfetch-control-center/data/usr/share/shadowfetch/control-center/sfcc/missions_page.py
tools/providers/validate_manifest.py
```

That list is `PROTECTED_FILES` in `provider_conformance.py`, and it is checked two
ways:

* `ThirdProviderProofTests.test_the_third_provider_is_discovered_without_touching_protected_files`
  takes a SHA-256 of each of the four files, builds a registry containing a third
  provider that exists only in `tests/fixtures/`, runs the entire conformance suite
  against it, and re-hashes. Any change fails the test.
* `ThirdProviderProofTests.test_no_protected_file_mentions_the_third_provider` greps
  all four for the fixture provider's name in any spelling.

Two further tests keep the claim honest: `test_the_third_provider_does_not_ship`
asserts the fixture is absent from both shipped directories, and
`test_the_third_provider_is_discovered_purely_from_its_manifest` builds a registry
whose module directory still contains the adapter but whose manifest directory does
not — and the provider is simply not there. Remove the manifest and the adapter is
just a file again.

If you find yourself needing to edit one of those four files to make your provider
work, that is the finding: the seam is missing something, and the fix belongs in the
seam rather than in a per-provider branch.

---

## 10. Two soft spots to know about

Both are in the conformance suite rather than the runtime, and both mean an assertion
you might expect to protect you is currently inert:

1. `test_the_manifest_executable_declaration_is_honoured` has branches for
   `kind == "absolute"` and for the removed `kind == "resolver"` — and none for
   `"candidates"`. A provider using the preferred form has its executable declaration
   checked by nothing there.
2. `test_the_declared_resolver_chain_does_not_reach_path_resolution` and
   `SecurityTests.test_no_shipped_executable_resolver_reaches_path_through_a_helper`
   both skip unless `executable.kind == "resolver"`, which no manifest can declare any
   more.

Until those are updated, verify by hand that your program is genuinely found from your
declared candidates:

```sh
PYTHONPATH=packages/shadowfetch-missions/data/usr/lib/shadowfetch/missions \
python3 -c '
import sf_providers as p
m = p.load_manifest(".../providers/claude-cli.json")
print(p.resolve_executable(m))'
```

---

## Checklist

- [ ] Manifest written; filename stem equals `id`; `load_manifest()` accepts it.
- [ ] Adapter implements `readiness()`, `build_invocation()`, `parse_stream()`.
- [ ] `CAPABILITIES` constant matches the manifest exactly.
- [ ] Executable located by `resolve_executable(self.manifest)`; no `which`, no
      `PATH`, in the adapter or in anything it imports.
- [ ] `trust` left at `"system"` unless the program genuinely is a user runtime.
- [ ] `env_allowlist` is the manifest's `credential_ids` and nothing else.
- [ ] Sandbox obtained from `sandbox_for()` and only ever `.narrow()`ed.
- [ ] `parse_stream()` survives the hostile battery; unknown lines become `log`.
- [ ] `accepts()` refuses with a reason a person can act on.
- [ ] `ProviderProfile` written, with a success stream, a failure stream and
      environment seams; registered in `CASES` and `PROFILES`.
- [ ] `python3 -m unittest test_provider_conformance` is green.
- [ ] `make source-gate` is green.
- [ ] `git diff --stat` touches none of the four protected files.
