# Stage M — Cursor as an AgentProvider: DEFERRED, with the blockers measured

Stage M asks whether Cursor can be onboarded as a provider to the same standard
as the shipped Codex and offline-media providers. It cannot be, today, on this
machine. This records exactly what was checked and what has to be true before
the next attempt, so that attempt starts from evidence rather than from a guess.

**No provider ships. There is no `sf_provider_cursor.py`, no `cursor.json`
manifest, and no `cursor.approved-entry.json`.** An approved-entry file is a
`manifest_sha256` over a manifest; writing one for a manifest that does not
exist would be a pin over nothing.

Verdict: **DEFERRED**, not UNSUPPORTED. Cursor Agent does ship a real
non-interactive CLI artifact — Shadowfetch already pins one — so there is no
evidence the product is architecturally unsuitable the way a localhost-transport
local model is (Stage L / PHASE2_5). What is missing is the ability to verify
anything about it here, plus two grants that live in lead-owned files.

---

## What is actually on this machine

Cursor is **not installed**, in any form.

| probe | result |
|---|---|
| `find / -xdev -name 'cursor-agent*'` (with and without sudo) | nothing |
| `~/.local/share/cursor-agent/` | absent |
| `~/.local/bin/cursor-agent` | absent |
| `/usr/bin`, `/usr/local/bin`, `/opt`, `/snap/bin`, flatpak | nothing |
| npm globals under `~/.nvm/versions/node/v22.22.3/lib/node_modules` | `@anthropic-ai`, `@openai`, wrangler, playwright — no cursor |
| `dpkg -l \| grep -i cursor` | only `breeze-cursor-theme`, `libxcursor1`, `node-cli-cursor` — X11/Node packages, unrelated |
| `env \| grep -i cursor` | nothing |
| any cursor token/auth/credential file under `$HOME` | nothing |

Two residues survive, and they are the whole reason Cursor looks present:

* `~/.cursor/cli-config.json` — 817 bytes, mtime **2026-08-19 12:24:19**
* `~/.cache/cursor-compile-cache/v24.5.0-x64-…/` — 780 KB, same second

Both were written by a single run. `strings` on a cache entry names its producer:

```
/home/rtx5060ti/projects/shadowfetch-2.1.5/work/qa-2.1.5/vendor-installers/cursor-expanded/6634.index.jsa
```

So a Cursor vendor installer was expanded once under the **2.1.5 QA vendor-installer
tree**, run once, and removed with that tree. `~/projects/shadowfetch-2.1.5` no
longer exists. `~/.local/state/shadowfetch/code-agents/` does not exist either,
so the supported installer (`shadowfetch-code-agent cursor setup`) has **never**
been run on this box.

There is no Cursor account, subscription or API key on this machine.

---

## What the distro already knows (and what that settles)

`packages/shadowfetch-defaults/data/usr/bin/shadowfetch-code-agent:65-77` pins
Cursor Agent as an optional user-space download:

```
VERSION="2026.08.11-e8db854"
ARTIFACT_URL="https://downloads.cursor.com/lab/2026.08.11-e8db854/linux/x64/agent-cli-package.tar.gz"
ARTIFACT_SHA256="bfff4bf6f4e9dd30c1d0ef0a70b6077b074015dd2948e4c50685d53afdcfce5a"
BINARY_SHA256="eed61c5224668c9236334c4c68936a16aecc37374b592f59e31eb50433817831"
TARGET_DIR="$DATA_HOME/cursor-agent/versions/$VERSION"   # ~/.local/share/...
TARGET_BIN="$TARGET_DIR/cursor-agent"
LINK_BIN="$BIN_DIR/cursor-agent"                          # ~/.local/bin/cursor-agent
```

This **settles the executable question**, which would otherwise have been the
hard part. A future manifest needs no invention:

```json
"executable": {
  "kind": "candidates",
  "trust": "user-runtime",
  "candidates": [
    "~/.local/share/cursor-agent/versions/*/cursor-agent",
    "~/.local/bin/cursor-agent"
  ],
  "runtime_root_markers": ["cursor-agent"]
}
```

`user-runtime` is the correct declaration and is exactly what Codex already
uses: the installer creates `$TARGET_DIR` mode `0700` under the user's own
`~/.local/share`, so `classify_executable()` will return `USER_MANAGED`, which
`ACCEPTED_EXECUTABLE_TRUST["user-runtime"]` accepts. Nothing here needs a new
trust tier and nothing needs `developer`.

Note what the distro does **not** know: it treats Cursor purely as an
interactive terminal tool (`setup`/`doctor`/`open`/`status`). Nowhere in this
repo is a headless invocation, an output format, or a turn protocol recorded.
`docs/RESEARCH-3.5.0.md:57-64` cites only the vendor install page.

---

## What blocks it

### B1 — the conformance profile cannot be filled honestly (my territory, and it is the real blocker)

`tests/provider_conformance.py` requires a `ProviderProfile`, and the suite
asserts on captured native output:

* `provider_conformance.py:637` — `assertTrue(self.profile.streams, "a profile must supply captured streams")`
* `provider_conformance.py:665-668` — a profile must include **both** a successful and a failed turn
* `provider_conformance.py:678-679` — success and failure fixtures must not be the same bytes
* `provider_conformance.py:640-641` — `parse_stream` must reproduce an **exact** event-type sequence and an exact final message

With no binary and no account, every one of the following would be written from
memory and then asserted as fact:

* the argv for a non-interactive run, and the flag that selects machine-readable output
* the event vocabulary of that output, and which event ends a turn
* how a failed turn is distinguishable from a successful one
* the equivalent of Codex's `--ignore-user-config` / `--ignore-rules` / `approval_policy="never"` hardening (`sf_provider_codex.py:118-128`) — i.e. whether a workspace-local `.cursor/` directory, **which the agent itself can write**, can re-decide its own approval posture
* whether the pinned binary self-updates in place, which would matter because the trust classification is done once per invocation

Fabricating those and labelling them "captured streams" is precisely what the
honesty rules forbid, and the suite's own wording ("captured") makes the lie
explicit rather than incidental. **This is why nothing shipped.**

Downloading the pinned artifact would not fix it: the artifact yields a binary,
not an account, and `cursor-agent` cannot complete a turn unauthenticated. A
success/failure stream pair is unobtainable on this machine either way. That is
what makes this DEFERRED rather than merely unfinished.

### B2 — `CURSOR_API_KEY` is refused at the Firebreak boundary (LEAD-OWNED — BLOCKED)

`packages/shadowfetch-fireline/data/usr/bin/shadowfetch-firebreak` defines a
closed credential allowlist (the `CREDENTIALS = {...}` set literal near the top
of the file — line 27 as of md5 `4c41fb633f622d847ea10c1f45d06bb6`; **this file
is currently `M` in `git status`, so cite it by content, not by line**):

```
CREDENTIALS = {"OPENAI_API_KEY", "CODEX_API_KEY", "ANTHROPIC_API_KEY", "XAI_API_KEY",
               "GEMINI_API_KEY", ... , "SSH_AUTH_SOCK"}
```

and it refuses anything outside that set:

```
if not requested <= CREDENTIALS - {"SSH_AUTH_SOCK"}:
    raise Error("Credential grant must name a supported provider environment variable")
```

`CURSOR_API_KEY` is not a member — verified against the live working-tree copy,
not a cached read: `grep -c CURSOR_API_KEY … == 0`. A manifest declaring
`"credential_ids": ["CURSOR_API_KEY"]` would pass the JSON Schema, pass the
registry, build a valid `Invocation` carrying the identity — and then **fail at
run time** when Firebreak is asked to grant it. That is the exact failure shape
this program exists to prevent: a declaration that reads like a control and
reaches no mechanism.

**Exact change required, for the lead:**

> File: `packages/shadowfetch-fireline/data/usr/bin/shadowfetch-firebreak`
> Anchor: the `CREDENTIALS = {"OPENAI_API_KEY", "CODEX_API_KEY", …}` set literal
> (line 27 at md5 `4c41fb633f622d847ea10c1f45d06bb6`; the file is under active
> edit, so match the literal rather than the line number).
> Change: add the single element `"CURSOR_API_KEY"` to that set.
> Nothing else. The set is order-insensitive; no other site needs to change,
> because the refusal, the grant loop and the receipt all read this one set.

I did not make this edit. It is in a lead-owned file.

### B3 — a `cursor-agent login` session store is not representable (schema + LEAD-OWNED firebreak — BLOCKED)

Cursor's normal auth path is an interactive `login` that writes a session store,
not an API key. That path cannot be expressed:

* `provider-manifest.schema.json` (line 146), `sandbox_profile.account_mount`
  is `"enum": ["codex-account"]` — a single hardcoded value.
* `shadowfetch-firebreak` hardcodes the mount and its environment:
  ```
  command += ["--bind", str(dedicated), "/home/agent/.codex"]
  environment["CODEX_HOME"] = "/home/agent/.codex"
  ```
  behind an `args.codex_account` flag, and reaches into `sf_mission_account` for
  the path.

So the only auth route open to a Cursor provider is the API-key identity — which
is B2. Generalising `account_mount` into a named-store mechanism is a
worthwhile piece of work, but it touches a lead-owned file and the shared
schema, and it is not Stage M's to do.

Firebreak does at least remove one hazard for free: it builds a **fresh empty
`/home/agent`** (the `command += ["--dev", "/dev", … "--dir", "/home/agent", …]`
line, 501 at the md5 above; its own self-check asserts this at 402-403) and
`--clearenv`s, so the host's `~/.cursor/cli-config.json` — which on this very
box carries `"approvalMode": "allowlist"`, `"permissions": {"allow": ["Shell(ls)"]}`
and `"sandbox": {"mode": "disabled"}` — does **not** reach the sandbox. The
residual question is the workspace-local `.cursor/` directory, which is inside
the writable bind and is therefore agent-writable; see B1.

---

## What is *not* a blocker (so it is not re-litigated)

* **Executable location and trust.** Solved above; `user-runtime` + a candidates
  list, same shape as Codex. No `shutil.which()`, no PATH, nothing new required.
* **Network posture.** Cursor is a cloud agent, so `network_policy: "allowlist"`
  with an `egress_allowlist`. `egress_allowlist` remains **NOT ENFORCED**
  (Stage C is blocked; see `STAGE_C_FINDINGS.md`), so a Cursor provider would
  reach whatever the host reaches. That is a pre-existing, documented property
  shared with Codex — it is not a Cursor-specific regression, and it must not be
  described as a permission in the manifest notes.
* **Credential values in the sandbox.** The broker (Stage D) is not built, so
  the key would reach the sandbox as an environment value via
  `--credential-env`, exactly as Codex's does. Same posture, no new claim.
* **Capabilities.** `code_change` and `sourced_report` are the obvious fit and
  need no schema change.

---

## What a future attempt must do, in order

1. Have the lead land the B2 one-line `CREDENTIALS` change. Without it the
   provider is non-functional however good the adapter is.
2. Install via the supported path only — `shadowfetch-code-agent cursor setup`,
   which verifies the pinned SHA-256 — on a machine that is **not** the release
   build host, and obtain a real Cursor account.
3. Capture, from real runs, and commit under
   `tests/fixtures/providers/streams/`: one successful turn, one failed turn,
   and one interleaved/partial stream (Codex ships all three).
4. Determine and record, from the installed binary rather than from memory:
   the non-interactive argv, the machine-readable output flag, the turn-complete
   and error events, and whether a flag exists that makes the agent ignore
   workspace-local `.cursor/` configuration and rules. **If no such flag exists,
   stop and report that** — it means a sandboxed agent can rewrite the file that
   decides its own approval posture, and that is a finding, not a detail.
5. Check whether the binary self-updates in place. If it does, say so in the
   manifest notes; the trust classification is evaluated per invocation and a
   self-replacing binary is a different maintenance story from Codex's.
6. Only then write the adapter, the manifest and
   `cursor.approved-entry.json`, and run
   `python3 -m unittest test_provider_conformance` targeted at the new provider.

---

## What was deliberately not done

* **No GUI automation.** Cursor's editor is not an AgentProvider and scraping it
  would not be one either.
* **No adapter written from memory.** An `sf_provider_cursor.py` whose argv,
  flags and event vocabulary were recalled rather than observed would pass the
  conformance suite against fixtures that were invented to match it — a suite
  proving only that two guesses agree.
* **No download onto the release build host.** Six agents are working this tree
  mid-release; and as B1 explains, the binary alone would not have unblocked the
  stage.
* **No edits outside territory.** B2 and B3 are written up as exact changes and
  left to the lead.
