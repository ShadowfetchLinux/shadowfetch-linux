# ARCHITECTURE_DECISIONS.md — Shadowfetch Linux

Architecture Decision Records for the Mission Control orchestration rebuild and the release/security work it depends on. Status is `Proposed` unless a decision merely ratifies something the codebase already does correctly.

---

## ADR-0001 — `AgentProvider` as the single agent abstraction

**Status:** Proposed

**Context.** There is no provider abstraction. "Provider" is `config["runtime"]` with two legal values (`codex`, `offline`), welded 1:1 to mission `kind`, re-validated in five places (`sf_missions.py:274, 275, 283-286, 476, 691`), dispatched by `getattr(self, self.mission["kind"])()` (`:706`), hand-listed in `capabilities()` (`:798`), repeated in the CLI choices (`:845, :849`) and mirrored in the UI (`missions_page.py:139, 166`). There are 31 `codex` references in one file. Because `kind` *is* the method *is* the provider, "run this same code mission with Claude" cannot be expressed at all. Grok Bot exists as a second launcher page with its own auth, its own permissions and no sandbox — evidence that the current shape does not extend. The only seam is a hard-coded `{"provider": "codex", ...}` inference record at `:517`.

**Decision.** Introduce `sf_providers.py` defining `AgentProvider` (`id`, `capabilities()`, `accepts()`, `readiness()`, `sandbox_profile()`, `credential_grants()`, `build_invocation()`, `stream_events()`), the value types `SandboxSpec`, `Invocation` and `AgentEvent`, and a `ProviderRegistry`. Move `Executor.codex` verbatim into `CodexCliProvider` and `Executor.media` into `OfflineMediaProvider`; `Executor` keeps only generic run/stream/receipt plumbing. Add a `capability` column so "what the human wants" (`CodeChange`, `SourcedReport`, `MediaExport`) is separate from "who does it". Replace all five scattered validations with one `provider.accepts(capability, config)` call. Every provider must pass a shared conformance suite before registration.

**Consequences.**
- Adding a provider becomes one package plus one manifest; `sf_missions.py`, the CLI, the gates and the UI are untouched — enforced by a no-op test provider in CI.
- Security-relevant branches (network coupling, credential grants) stop drifting because there is one code path.
- Requires ADR-0006 to land first or simultaneously: the current gate makes any new runtime a build failure.
- Short-term cost: a behaviour-preserving refactor of the highest-risk file in the tree, mitigated by the conformance suite landing with the interface.

**Alternatives considered.** *Keep branching and add `elif` arms* — rejected: each provider multiplies the branch count, and the branches that drift are the security-relevant ones. *A subprocess plugin protocol only (no in-process interface)* — rejected as the primary abstraction: it would put stream normalisation and sandbox-profile decisions outside the orchestrator's type system, though it remains available for third-party providers under ADR-0005.

---

## ADR-0002 — SQLite for operational state, journald for tamper evidence

**Status:** Proposed

**Context.** Mission state is already SQLite (WAL, `0600`, dir `0700`, refusing a state root inside the workspace) and that part works. What is missing: a schema version and migrations (today it is `CREATE TABLE IF NOT EXISTS` only), the domain nouns the orchestration layer needs, and any tamper evidence — the DB, the per-mission logs, the receipts and the Firebreak session manifests are all owned and writable by the same uid the agent runs as, and the Firebreak record is overwritten in place at exit. `debian/control` claims a journald audit that does not exist.

**Decision.** Keep SQLite as the operational store and extend it with the full domain schema (§7 of the audit) plus a `schema_version` table and forward migrations. Add an append-only, hash-chained `events` table as the system of record. Mirror every appended row — and specifically the chain head — to journald with `SYSLOG_IDENTIFIER=shadowfetch-audit`, because the journal is root-owned and the agent's uid cannot rewrite it; that mirror is the external high-water mark that makes truncation detectable. Do not introduce a daemon-backed database.

**Consequences.**
- Crash-safe, transactional, no extra service, and the existing tests keep working.
- Tamper evidence becomes real without granting anything new to the desktop session.
- Migrations become mandatory engineering: old missions must stay listable and undoable, and the chain gets a genesis row recording that everything before the migration is unchained.
- Journald mirroring adds a dependency on `python3-systemd` (or `systemd-cat`) in the missions package.

**Alternatives considered.** *PostgreSQL or a broker-owned store* — rejected: availability and privilege cost exceed the benefit for single-machine state. *Files only (JSONL)* — rejected: the concurrency the worker already has (flock + WAL) would have to be rebuilt worse. *Signing every row with a key on the same machine* — rejected as sufficient on its own; a chain plus an off-uid mirror gives most of the value with none of the key-management burden.

---

## ADR-0003 — Firebreak is the enforcement boundary; the mechanism is namespaces + seccomp + Landlock + brokered egress

**Status:** Proposed

**Context.** Firebreak's filesystem work is genuinely good (userns/pidns/utsns/ipcns, `--new-session`, `--clearenv` with an explicit allowlist, a 14-entry `/etc` allowlist, private `/home/agent`, one rw workspace bind, a systemd scope with limits). Everything else is absent: `--net allow` simply omits `--unshare-net` (`:112-113`), so the sandbox shares the host network namespace *and* the host abstract AF_UNIX namespace — and `sf_missions.py:285-286` makes that mandatory for every code and report mission. There is no seccomp, no `--cap-drop`, no uid remap, nested userns is available, and the process runs as the human's uid. The workspace is always read-write even for "read-only" report missions, in-workspace secrets are not masked, and the sandbox binary itself is resolved through a `PATH` that a user-writable `EnvironmentFile` can set.

**Decision.** Firebreak becomes a provider-neutral, step-scoped primitive with five enforcement layers:
1. `--unshare-net` **unconditionally**; "network" becomes `none | allowlist:<hosts>` implemented with pasta/slirp4netns plus an authenticated local CONNECT proxy run by the broker, whose log is the network audit trail. Raw `allow` is retained for one release only, behind an explicit recorded `Approval`.
2. A seccomp denylist (`--seccomp`) covering `ptrace`, `keyctl`/`add_key`/`request_key`, `userfaultfd`, `bpf`, `io_uring_setup`, `perf_event_open`, `clone`/`unshare` with `CLONE_NEWUSER`, and obsolete socket families; plus `--unshare-cgroup`.
3. Landlock (ABI 3+) as a second filesystem layer so workspace-only writes survive a mount-namespace bug.
4. A dedicated subuid via `--uid`/`--gid` + `newuidmap`, so an escape lands on an unprivileged identity rather than the human's account.
5. Step-scoped `SandboxSpec`s: `--workspace-mode {rw,ro}`, `--mask <relpath>` (tmpfs over `.env`/`.ssh`/keys inside the bind), and per-step network (allowlist for inference, none for validation and media).

The binary is resolved by absolute path, never `PATH`; `SHADOWFETCH_CHECKPOINT_BIN` is removed; `SHADOWFETCH_AGENT_WORKSPACES` is validated with the denylist `read_grants()` already implements.

**Consequences.**
- The boundary becomes real against a hostile or prompt-injected agent, not just accidental damage.
- Provider CLIs that assume ambient network need an explicit allowlist entry — declared by the provider manifest (ADR-0001/ADR-0005), which is where that knowledge belongs.
- Requires bubblewrap with seccomp support, a kernel with Landlock and `newuidmap` configuration at install time; the readiness `check` subcommand must record and gate on these rather than being a command nobody runs.
- Some cost in launch latency and in debugging opacity; mitigated by recording the resolved bwrap argv in the session manifest.

**Alternatives considered.** *VM isolation (microVM per session)* — stronger, rejected for now: it breaks the workspace-in-place model and the checkpoint/undo story, and costs far more than the four gaps above. *Containers (podman)* — rejected: it moves the trust problem to a daemon and does not by itself solve credentials or egress. *Leave `allow` as-is and rely on review* — rejected: exfiltration is irreversible and the receipt already admits network effects cannot be undone.

---

## ADR-0004 — Approval is a persisted, scoped, expiring object enforced in the engine

**Status:** Proposed

**Context.** All consent lives in the Qt dialog (`missions_page.py:36-214`). The engine's `create()` performs validation only and `run` executes immediately, so any local process can `shadowfetch-missions --json create --network allow … && run` and obtain an unattended agent turn with the user's cloud account and unrestricted egress. Inside a run, `approval_policy="never"` is hard-coded and no tool call is ever surfaced, so nothing is blockable except a whole-mission cancel. Meanwhile `auth_admin_keep` on Phoenix and bundle-install means one password grants a session-long capability with no record.

**Decision.** Every mission run requires a valid `Approval` row (subject, scope = capability + provider + workspace + network + credential ids + paths, granted_by, method, granted_at, expires_at, revoked_at). `run` refuses without one. Approvals are minted through an interactive path — polkit (`org.shadowfetch.fireline.policy` is the existing precedent) or a desktop prompt — so the GUI becomes one client of the mechanism rather than its only location; non-interactive callers need an explicitly pre-granted, scoped, expiring approval. Inside a run, the broker consults `PolicyEngine.evaluate_tool()` **before** each action: `auto_allow` inside the declared boundary, `escalate` to a desktop prompt (which blocks the call) otherwise, `deny` for a never-list. Every verdict is a `ToolExecution` row and an `Event`.

**Consequences.**
- "The human keeps control" becomes true rather than aspirational, and automation gets a first-class way to pre-authorise a bounded scope.
- Latency and prompt fatigue are real risks; managed by making the auto-allow boundary generous *inside* the workspace and strict at every edge (network, credentials, paths outside, git/exec surfaces).
- The provider's own approval channel must be wired to the policy evaluator, which means `approval_policy="never"` is removed and each adapter needs an approval transport — part of the conformance suite.

**Alternatives considered.** *Keep approval in the GUI* — rejected: it is bypassable by any local process and cannot express mid-run decisions. *Post-hoc review only* — rejected: exfiltration and host-execution hooks are not undoable. *Blanket allow with alerting* — rejected: the product's stated promise is blockability.

---

## ADR-0005 — Providers are packaged Debian plugins with a declarative manifest and a strict version relationship

**Status:** Proposed

**Context.** Today the one provider is code inside the orchestrator, its credential handling is inside the *sandbox launcher* (`--codex-account`, and Firebreak importing `sf_mission_account` while declaring no dependency on the missions package), and its capability set is a hand-typed dict that a release gate AST-parses. `shadowfetch-fireproof` already demonstrates the failure mode of undeclared cross-package injection by dropping a Python module into `shadowfetch-control-center`'s package directory. `shadowfetch-missions` depends on `shadowfetch-fireline (>= 4.0.0)` with an open upper bound across a security boundary.

**Decision.** One Debian binary package per provider (`shadowfetch-provider-codex`, `-claude`, `-grok`, `-cursor`, `-local`, `-offline-media`), each shipping:
- `/usr/share/shadowfetch/providers.d/<id>.json` — id, display name, capabilities, credential ids, network policy + allowlist, sandbox profile, adapter module path, and the adapter's own version;
- `/usr/lib/shadowfetch/providers/<id>/provider.py` implementing `AgentProvider`.

The registry scans `providers.d/` at startup and validates each manifest against a JSON Schema and a signed approved-provider policy. Providers declare `Depends: shadowfetch-missions (>= X), shadowfetch-missions (<< X+1)` and the interface version they implement; the orchestrator refuses a manifest whose interface version it does not support. Firebreak loses all provider-specific flags; credentials become `credential_ids` resolved by the broker (ADR-0011). All cross-package coupling — including `fireproof_page.py` — moves to declared plugin directories with an explicit API constant.

**Consequences.**
- dpkg can finally see the relationships; a provider can be installed, upgraded and removed independently, and an incompatible pair is refused rather than failing at runtime.
- The gate changes from freezing a source shape to validating data (ADR-0006).
- Tightening `shadowfetch-fireline` to `(<< 4.1.0)` may force coordinated uploads; that is the correct cost for a security boundary.

**Alternatives considered.** *Python entry points inside one package* — rejected: it keeps all providers in one upgrade unit and gives dpkg no visibility. *Downloading providers at runtime* — rejected outright on a distribution with a signed-repo trust model.

---

## ADR-0006 — Replace the AST provider freeze with a manifest-and-policy gate

**Status:** Proposed

**Context.** `tools/mission_provider_contract.py:25` asserts `set(runtimes) == {"codex","offline"}` and `local_ai == "deferred"`, pinning per-runtime kinds and network flags, and is called from `source_gate_4_0_0.py:217`, `package_gate_4_0_0.py:239` and `iso_gate_4_0_0.py:774`. It obtains its data by AST-parsing `capabilities()` for a module-level function containing a single literal `return {...}`. So adding a provider fails three gates, a registry-driven `capabilities()` makes `ast.literal_eval` raise `ValueError`, and a rename makes a bare `next()` raise `StopIteration` — a type the source gate does not catch, producing an unrelated traceback rather than a policy failure. The gate conflates two things: "the deferred local-AI payload must not reappear" (a legitimate payload blacklist, `REMOVED_AI_PATH`) and "the provider set is exactly these two" (a version stamp).

**Decision.** Split it. Keep `REMOVED_AI_PATH` as a payload blacklist. Replace the capability assertion with `tools/providers/validate_manifest.py`, which (a) validates every shipped `providers.d/*.json` against a JSON Schema, (b) checks each provider id against a signed approved-provider policy file, and (c) asserts the *behavioural* invariants that actually matter: no code path invokes a provider binary without a Firebreak wrapper; no path reaches `network != none` without a recorded `Approval`; no credential name reaches a sandbox without an explicit grant; no provider binary is resolved through `PATH`. Fix the bare `next()` to raise `RuntimeError`.

**Consequences.**
- Adding a provider becomes a reviewed manifest change, not a gate edit.
- The gate starts testing properties rather than source text, so it keeps working through refactors.
- The approved-provider policy file becomes a release artifact that must be signed and versioned.

**Alternatives considered.** *Delete the gate* — rejected: the local-AI deferral is a real, auditable claim. *Keep the AST check and edit it per release* — rejected: it is exactly the pattern that produced six copies of every other gate (ADR-0007).

---

## ADR-0007 — One gate implementation per family, plus a per-version data file

**Status:** Proposed

**Context.** `tools/` holds six copies each of `source_gate`, `package_gate`, `iso_gate`, `verify_acceptance` and five of `build_release_evidence` — 14,461 lines, of which only ~2,717 are the live 4.0.0 copies. `verify_acceptance_4_0_0.py` differs from the 2.1.4 copy in three hunks; `source_gate` is 98% identical to its predecessor. The unit tests target the **2.1.4/2.1.5** copies (26 of 106 tools tests are byte-identical duplicate pairs), so the gate logic that actually runs for 4.0.0 — `critical_payload_parity_gate`, `drkonqi_gate`, the diverged `payload_gate`/`main` and every per-version constant — has no test. `Makefile:16`'s `VERSION_TOKEN` silently selects the file, and `package_release_evidence_4_0_0.py` hardcodes 25 version-suffixed tool paths (omitting `source_gate_4_0_0.py` itself).

**Decision.** Collapse to `tools/release/{source_gate,package_gate,iso_gate,acceptance,evidence}.py` plus `tools/release/versions/<version>.toml` holding every literal that differs between versions (version, edition, codename, `EXPECTED_BINARIES`, `EXPECTED_SOURCES`, `REQUIRED_ROOT_FILES`, `REQUIRED_EXECUTABLES`, `CRITICAL_PACKAGE_PAYLOADS`, `MAX_SQUASHFS_BYTES`, signing fingerprint, Valid-Until floor). Entry point `tools/release/gate.py --version X {source,package,iso,accept,evidence}`; `VERSION_TOKEN` disappears. Move the existing pure-function tests onto the single implementation. Replace the hand-maintained `QA_SOURCES` tuple with a glob. Keep the frozen per-version scripts under `tools/archive/` only if re-auditing a shipped image is a real requirement.

**Consequences.**
- ~11,700 frozen lines removed; the tests finally cover the code that gates the release.
- Cutting a version becomes one TOML file.
- One-time risk: the collapse must be done between releases and validated by re-running each archived version's gate against its recorded evidence.

**Alternatives considered.** *Keep copying* — rejected; it is already producing untested live gates. *A single gate with no version data* — rejected: the per-version expectations are real and must be reviewable as data.

---

## ADR-0008 — Restore and enforce version control for the release tree

**Status:** Proposed

**Context.** `~/projects/shadowfetch-4.0.0/.git` is a worktree pointer to a deleted parent repository, so every git command fails. Consequences: `source_gate_4_0_0.py:88-94` dies on `git ls-files` before running anything, the `gitleaks git` history scan and `git diff --check` never run, and `pre_release_check.sh:38` *silently skips* its credential-state check while still printing `PRE_RELEASE_CHECK_PASSED`. There is no blame, no diff against 3.5.0, and no way to distinguish shipped content from a later hand-edit — including for the SHA-256 constants that are the only supply-chain control on the vendored drkonqi tarball, the NVIDIA keyring and the 2.1.3 migration manifest. Build artifacts (`debian/<pkg>/` staging trees, `__pycache__`, `repo/conf/distributions`) are tracked or committed alongside sources. Independently verified: GitHub tag `v4.0.0` (commit `57e637a7`) matches the working tree on 693 of 695 tracked blobs.

**Decision.** Repair non-destructively: `mv .git .git.broken-worktree`, `git init`, add the GitHub remote, `git fetch --tags`, `git reset --mixed v4.0.0` (index only, working tree untouched), confirm only the two `.debhelper` build outputs differ, then remove the backup. Add a `.gitignore` for `packages/*/debian/<pkg>/`, `.debhelper/`, `*.substvars`, `debhelper-build-stamp`, `__pycache__/`, `*.pyc`, `live-build/{chroot,binary,cache}/` and `work/`, and `git rm --cached` the twelve tracked build outputs. Make the absence of git a **loud failure**: `pre_release_check.sh` records a failure rather than skipping; `source_gate` raises a named "history scan unavailable" error and offers a `--no-git` fallback that still runs `gitleaks dir`. Delete the four stale `work/candidate-source*.bundle` files, which are 12 commits behind the release. Verify each vendored SHA against upstream once and record the verification in-tree, since no history can attest to them retroactively.

**Consequences.**
- The secret-scan gate becomes runnable; provenance questions become answerable; `distclean` stops deleting tracked files.
- A check that cannot run can never again report as passed.
- One-time care is required so the repair does not touch working-tree bytes.

**Alternatives considered.** *Re-init with a single squashed commit and no remote* — acceptable fallback if the GitHub tag were unavailable, rejected here because a real history exists. *Leave it and rely on the ISO checksum* — rejected: the checksum proves what shipped, not what changed or whether a secret was ever committed.

---

## ADR-0009 — One source of truth per fact: version, identity, palette, release pointer

**Status:** Proposed

**Context.** The same facts are restated across the tree and have already drifted. The signing fingerprint appears in five files (`Makefile:43`, `iso_gate:33`, `publish_release:27`, `retain_source_signature:9`, `worker/src/index.js:12`). The Umbra palette exists in five places with three different reds and greens, one of which (`shadowfetch-fireproof`) renders *inside* the Control Center window; the Ice look-and-feel declares itself as the Dark package, so choosing Ice installs the Fire splash and reports "Shadowfetch Dark" as active. The site's `release.ts` was written specifically to end "the version was written down in fifteen places" and there are now twenty hardcoded `4.0.0` literals plus a retyped 64-character ISO SHA-256 in page prose. "Current release" is defined three different ways (manifest date + numeric semver; newest R2 upload timestamp; a test with a *string* tiebreak). `stamp_version.py` rewrites eight tracked files in place with no backup and no revert.

**Decision.** One authority per fact, everything else generated or imported.
- **Theme:** ship `/usr/share/shadowfetch/theme/palette.json` (keyed by element, named roles) from `shadowfetch-branding`; generate `.colors`, `.colorscheme`, `theme.conf`, `Splash.qml` colours and the Guide's exported CSS from it; `sfcc`, Welcome and the Fireproof page import one loader. Add a gate failing on any literal `#rrggbb` outside the palette module. Fix `org.shadowfetch.ice/contents/defaults` to name itself, with a gate asserting each look-and-feel's `Theme`/`LookAndFeelPackage` equals its own plugin name.
- **Version/identity:** the signing fingerprint lives in the per-version release TOML (ADR-0007) and is read everywhere; `stamp_version.py` becomes transactional (validate all, then write, with a restore-on-failure backup); the site imports `VERSION`/`ISO_SHA256` from `release.ts` with a test forbidding stray version literals.
- **Release pointer:** `publish_release` writes `releases/CURRENT.json` **last**; the artifact worker reads that one key and HEADs the named objects instead of sorting an unpaginated 100-object listing by upload time.
- **Ordering:** one exported `currentOf(manifests)` shared by `release.ts`, the feed builder and the tests.

**Consequences.**
- A release becomes one manifest plus one TOML; key rotation becomes a one-line change.
- Re-uploading an old ISO can no longer silently promote it to "current".
- Generated theme files must be regenerated at package build time, adding a build step.

**Alternatives considered.** *Lint for drift and keep the copies* — rejected: the copies have already diverged in ways a lint cannot judge (which red is correct?). *Runtime deduplication only* — rejected: the ISO and the site need build-time artifacts.

---

## ADR-0010 — One append-only, hash-chained event log with a single correlation identity

**Status:** Proposed

**Context.** Evidence is split across four uncorrelated stores: the `events` table, per-mission log files, `receipt.json`, and Firebreak's `<sid>.session` manifest — which omits the agent command entirely and is **overwritten** at exit, and whose location is chosen by a caller-settable `XDG_STATE_HOME`. There is no join key: Mission Control never learns the Firebreak session id and Firebreak never learns the mission id. The four MCP servers log nothing at all, including `checkpoint.undo`. Agent tool calls are never parsed. All four stores are writable by the uid the agent runs as. `debian/control` and the changelog both claim a journald audit that does not exist.

**Decision.** `events` is the single system of record: append-only (no `UPDATE`, no `DELETE`), each row carrying `prev_hash` and `hash = sha256(prev_hash || canonical(row))`, with `verify()` reporting the first break. One correlation identity is threaded end to end: the orchestrator mints a session id, passes it to Firebreak as `--session-id`, and Firebreak stamps it into a manifest that now includes the redacted `agent_command`, the resolved bwrap argv, read grants, credential identities and the egress log — and *appends* an end record rather than rewriting. The broker writes a `ToolExecution` row and an `Event` for every agent action before it runs, with its policy verdict. Every row is mirrored to journald so the chain head leaves the user's trust domain. The Firebreak audit directory is resolved from the passwd entry, not `$XDG_STATE_HOME`. `receipt.json` gains the credential identities, read grants, masked paths, egress destinations and the `GitChange` summary, so review shows actual exposure.

**Consequences.**
- "What did this agent have access to, and what did it do?" becomes one query with a verified chain.
- Tampering becomes detectable; deletion becomes visible as a gap against journald.
- Log volume grows (a chatty agent produces many tool executions); mitigated by digesting arguments and outputs rather than storing them inline, with full payloads in the per-mission directory.

**Alternatives considered.** *Keep the four stores and correlate by timestamp* — rejected: it is what exists and it does not answer the question. *auditd rules* — rejected as the primary mechanism: it cannot see agent-level semantics, though it remains complementary. *Remote log shipping* — out of scope for a single-machine product.

---

## ADR-0011 — Credentials live in a broker; the sandbox gets a channel, never a secret

**Status:** Proposed

**Context.** `shadowfetch-firebreak:133` bind-mounts the dedicated Codex account directory **read-write** onto `/home/agent/.codex` and sets `CODEX_HOME`, while `:116-117` requires `net == "allow"` for that grant — so the agent holds a long-lived OAuth refresh token at a known path with guaranteed egress, in a run where prompts may be built from untrusted documents and `approval_policy="never"`. The env-var scrub (`shell_environment_policy.exclude`) protects only the environment path. Firebreak's own `CREDENTIALS` allowlist already names 25 credentials (`ANTHROPIC_API_KEY`, `XAI_API_KEY`, `GITHUB_TOKEN`, `AWS_SECRET_ACCESS_KEY`, …), so this problem multiplies with every provider. Redaction is per-64KiB block over four names plus two prefixes, so a token straddling a read boundary is written verbatim to a retained log.

**Decision.** A host-side `shadowfetch-brokerd` holds every credential. Firebreak binds **one unix socket** into the sandbox; the provider adapter's transport calls the broker, which uses the credential and returns only the result. No token, key or session file is ever bind-mounted or set in the sandbox environment. Providers declare `credential_ids`, never values. The granted credential *identities* are recorded in the session manifest and the receipt so review shows the exposure. Secret redaction moves to a shared `shadowfetch.secrets` module with a sliding window across reads, the union of Firebreak's credential names, and provider prefix patterns (`ghp_`, `github_pat_`, `AKIA`, `AIza`, `hf_`, `xoxb-`, `glpat-`, …), applied to logs, events, receipts and diffs.

**Consequences.**
- The single most valuable secret on the machine leaves the agent's reach; the fix generalises to every future provider instead of adding a `--claude-account` flag per vendor.
- Interim step for one release: `--ro-bind` a minimal copy with out-of-band refresh, so the write and sibling-file exposure close immediately even before the broker ships.
- Provider CLIs that insist on reading a credential file need an adapter shim (a broker-backed proxy endpoint plus a synthetic config), which is real work and is where most of the per-provider effort will go.

**Alternatives considered.** *Short-TTL minted tokens bound in* — better than today, rejected as the end state: it still puts a bearer secret inside the sandbox. *Keyring/agent socket* — effectively the broker, but without a policy or audit point; the broker adds both.

---

## ADR-0012 — Network egress is namespaced and brokered, and is never chosen by a colour theme

**Status:** Proposed

**Context.** `--net allow` means "no network namespace", so the sandbox keeps the host's loopback services (verified: ollama, sshd, NFS, SMB, CUPS and eight more) and the host's abstract socket namespace (verified: `@/tmp/.X11-unix/X0`, `@cuda-uvmfd-*`) — the very things the mount-namespace work was meant to hide. The default is derived from `element()`, i.e. the user picks their egress policy by picking fire or ice; and the element itself is read from an agent-writable `~/.config/shadowfetch/element` or a `$SHADOWFETCH_ELEMENT` environment variable, once, at import. Code and report missions cannot opt out. Validation of agent-authored code inherits the mission's network setting. The receipt records only the string `"allow"` — never a destination.

**Decision.** Always create a network namespace. `network` becomes `none | allowlist:<hosts>` (raw `allow` only behind an explicit recorded `Approval`, for one release). `allowlist` is implemented with pasta/slirp4netns plus an authenticated CONNECT proxy run by the broker, enforcing a per-mission destination list assembled from the provider manifest's allowlist plus any human-approved additions; the proxy log (timestamp, host, bytes) becomes the network audit trail and is written into the session manifest and the receipt. Network is a property of the **step**: allowlist for inference, `none` for validation and media. The fail-closed default comes from `/etc/shadowfetch/fireline.policy`, not from the theme; the per-user element file may only make the posture *stricter*, and the environment override is removed or gated behind an explicit developer flag.

**Consequences.**
- Exfiltration becomes observable and, for anything off the allowlist, blockable; localhost services and abstract sockets become unreachable.
- Some workflows break honestly (a mission that needs `npm install` must declare the registry), which is the intended outcome.
- Adds a runtime dependency on pasta/slirp4netns and a proxy process; latency and a small failure surface are added to every mission.

**Alternatives considered.** *`--unshare-net` plus loopback blocking only* — a valid interim step (it closes the abstract-socket and localhost holes immediately) but leaves egress unrecorded. *nftables rules in the host netns* — rejected: per-mission scoping is fragile and there is still no destination record. *Keep the theme default* — rejected outright: a security default must not be a colour scheme.

---

## ADR-0013 — The desktop subscribes to an event stream; it does not poll

**Status:** Proposed

**Context.** The Missions page re-polls `list` every 3 s and re-fetches `show`/`events`/`diff` on every selection change; the worker busy-loops at 1 Hz, taking the exclusive lock and JSON-decoding up to 1,000 rows twice per second, for every desktop user at every login, forever — which is precisely why `REVIEW_LOCK_WAIT_SECONDS` had to be invented. `max_parallel` is 1 because the execution lock is global. A completed mission is noticed up to 3 s late and only while the page is visible. There is no place to surface a tool call awaiting approval before it runs, and the readiness row in the New Mission dialog reads a `summary` key `capabilities()` never returns.

**Decision.** Add `shadowfetch-missions --json watch`, a long-lived line-delimited stream over the `events` table (`AuditLog.subscribe`), consumed by a streaming variant of `JsonCommand`; optionally exposed as a session-bus signal for other clients. The worker blocks on inotify over the state directory (or systemd path/socket activation) with a long fallback timeout, runs `recover()` only at startup and on wake, and selects the next queued mission with a direct indexed query instead of a full scan. The execution lock is scoped per workspace so `max_parallel > 1`. The UI renders the structured readiness facts `capabilities()` already computes and gates the Queue button on them, with a cross-package test asserting every key the UI reads exists.

**Consequences.**
- Idle cost drops to near zero; pending approvals can be surfaced in real time, which is a precondition for ADR-0004.
- Lock contention that forced the review workaround disappears; concurrent missions become possible.
- A streaming client is more code than a poll and needs careful reconnection and backpressure handling.

**Alternatives considered.** *Shorten the poll interval* — rejected: it worsens the exact contention that caused the workaround. *Full D-Bus service for Mission Control* — attractive for multi-client use, deferred: it adds a bus name, a policy and an activation story for a benefit a stream already delivers.

---

## ADR-0014 — Every privileged operation has its own polkit action with a validated argv grammar

**Status:** Proposed

**Context.** `org.freedesktop.policykit.exec.path` binds an action to a *program path*, not a verb, and pkexec passes the caller's whole argv. Four of the six annotated helpers are written as if the action named a verb. `org.shadowfetch.fireline.check` sets `allow_active=yes` on a binary whose `run` subcommand executes `nargs=REMAINDER` argv as root; `phoenix-recovery-report` takes an unvalidated output path and does `mkdir`/`tar`/`chmod`/`chown` as root; four more privileged operations run through pkexec with no registered action at all, including `pkexec /bin/sh -c`. Only one argv contract is enforced anywhere in the build, and it looks at a single call site one file away from the two shipped defects. Meanwhile the GUI names `pkexec`, `systemctl` and the shadowfetch tools relatively and wraps commands in a login shell that honours `~/.local/bin`.

**Decision.** Three rules, enforced by the source gate.
1. Every privileged operation gets its own polkit action annotated onto a helper that either takes **no arguments** or validates every argument against an allowlist. No `allow_active=yes` action may point at a program that can exec caller-supplied argv. `pkexec /bin/sh -c` is deleted in favour of a named helper.
2. Every `pkexec` argv appearing in the source must be covered by a shipped `.policy` file, and must be checked against the helper's declared grammar (`--contract --json`) by a contract test — the generic form of the check that already exists for one call site.
3. Every privileged or system binary is invoked by absolute path; `terminal_command(str)` becomes `terminal_argv(list[str])` running a non-login shell in a sanitised PATH; helpers construct their subprocess environment explicitly rather than `dict(os.environ, ...)` (which currently lets `APT_CONFIG` reach root apt when the helper is invoked outside pkexec).

**Consequences.**
- The class of defect that shipped two dead 4.0.0 buttons becomes a build failure, and the latent local-root grant disappears.
- Administrators gain per-operation polkit rules and useful authentication prompts instead of "run /bin/sh as the super user".
- More helpers and more `.policy` files to maintain; the contract test makes that cost visible rather than silent.

**Alternatives considered.** *A single privileged D-Bus broker for all desktop actions* — architecturally cleaner and the right long-term direction (see `shadowfetch-gpud`), rejected as the immediate step because it is a large rewrite of six working helpers. *Argument validation without per-action ids* — rejected: it leaves administrators with no way to allow or deny individual operations.

---

## ADR-0015 — No evidence, no publish: acceptance is signed, artifact-bound, and the only credentialled path

**Status:** Proposed

**Context.** The shipped 4.0.0 ISO is live while `qa/4.0.0/acceptance.json` records 13 of 18 required cases as `pending` with empty evidence and a null bundle hash — `publish_release_4_0_0.py` refuses that manifest today, so publication happened outside it. R2 holds a 4.0.0 ISO next to a 3.5.0-1 APT tree, all eight evidence artifacts 404, and the live `InRelease` expires 2026-09-20. `make acceptance-audit` runs with `--allow-pending` and therefore cannot fail on missing evidence; `record` stores whatever `--status` it is given, with a hash of a file in the same developer-writable tree, bound to nothing; a 0-byte log and a solid-black 1280×720 PNG both pass. Meanwhile the VM acceptance layer (16 scripts) is entirely human-driven and its only automated reference copies its *source* into the evidence bundle without running it. The `.github/CI-SECRETS.md` document still instructs exporting the ISO/APT signing private key into GitHub Actions for a pipeline that does not exist.

**Decision.**
1. **Publication is gated by construction.** R2 write credentials are reachable only through the publisher, which runs `verify_acceptance --version X` with **no** `--allow-pending`; the publish invocation (argv, user, timestamp, ISO sha256) is recorded back into the manifest as a `PUB` case. Ordering follows the documented safety order: APT trees, key, sidecars and evidence first; the ISO **last**; `InRelease` last within APT. The download page gates on checksum *and* signature presence, not merely on a release existing.
2. **Acceptance is evidence-bound and signed.** Every evidence entry carries `artifact_sha256` and `produced_by` (the exact command line); evidence whose mtime predates the artifact is refused; zero-byte and low-entropy screenshots are refused; the manifest is GPG-signed over a canonical serialisation and `verify` checks the signature. `waived` joins `pass`/`fail`/`pending` and requires `{approver, reason, date}`, so "knowingly accepted" is distinguishable from "not done". The required-case set is checksummed so it cannot silently shrink. `make acceptance-audit` (structure, `--allow-pending`) is separated from `make acceptance-gate` (hard).
3. **Acceptance is automated where it can be.** `make vm-acceptance` drives the QA harness and records each result in the same action, starting with `INSTALL-01`, `UPGRADE-01` and `RECOVERY-01`. CI runs `make source-gate` and `make package-gate` rather than a hand-rolled subset. Coverage is measured and published.
4. **Destructive release tooling is guarded.** `make iso` refuses to delete an artifact matching an accepted manifest; `r2_prune_release.py` validates that the kept release exists, caps deletions and never removes `.asc`/`.sha256`; retirement is declarative (`releases/RETIRED.json`) and shared by the prune tool and the worker's 410 pages; the stray-deploy guard is generalised to both Linux web properties; `CI-SECRETS.md` is rewritten to describe the pipeline that exists and the unused `RELEASE_GITHUB_TOKEN` is revoked.
5. **A signed index is refreshable without a release.** `make refresh-index` re-exports and re-signs `apt/dists/**` from the existing pool under `pre_release_check.sh` only, so `Valid-Until` can never again become a dated outage that requires a full rebuild the acceptance gate would reject.

**Consequences.**
- The shipped artifact and the release record can no longer disagree, and "was 4.0.0 gated?" becomes answerable.
- Releases get slower until the VM cases are automated; that is the correct trade for a distribution that ships a root-privileged recovery mechanism.
- Signing the manifest introduces key handling in the acceptance flow, which must reuse the existing release key discipline (never in CI).

**Alternatives considered.** *Trust the operator* — rejected empirically; it produced this state. *Publish first, record later* — rejected: it is indistinguishable from the current failure. *Drop the manifest and rely on gate exit codes* — rejected: the manifest is the only durable, reviewable record of what was verified for a given artifact.

---

# Addendum — decisions revised by Phase 1 evidence

Phase 1 executed W-01..W-21. Most of this document's decisions were confirmed
by implementation. Three were changed by what implementation found, and are
recorded here rather than edited in place, so the original reasoning and the
correction both remain readable.

## ADR-0004 addendum — the git repair prediction was exactly right

This document predicted that repairing the release tree's git would leave
"only the two `.debhelper` build outputs" differing from `v4.0.0`. That held.
The working tree was hashed before and after the repair and the digest was
unchanged (`1be19a72…`), and the only files differing from the tag were ten
generated `*.debhelper` outputs already covered by `.gitignore:76`. **The
4.0.0 release tree is byte-identical to the published tag.** No decision
changes; the confirmation is worth recording because it is what made every
other Phase 1 change safe to reason about.

## ADR revision — W-13 is not a recording exercise

**Original position.** The audit treated the 4.0.0 acceptance gap as unrecorded
work: regenerate the evidence, finish through `publish_release_4_0_0.py`.

**What the evidence shows.** The QA tree holds 3,977 files, of which **16**
postdate the shipped ISO — all already bound to the five passing cases.
Everything else describes an earlier build candidate. Worse:

- SRC-01 and PKG-01 were never run against the shipped source at all. The last
  gates ran at `c551dfcd`; the published artifact is `e1293bfa`.
- RESOURCE-01 and STRESS-01 are recorded `pending`, but their own notes
  document runs that **failed**.
- `evidence_bundle_path` names a tarball that does not exist, which is why its
  hash is null. There is no SBOM.

**Revised decision.** W-13 cannot be completed by recording, and it was not
attempted. Mapping candidate6 evidence onto candidate12 cases would convert an
honest gap into a false attestation about a published operating system. The
deliverable is the inventory plus a gate (W-14) that now refuses the manifest.
Closing it requires either re-running QA against the shipped artifact or
waiving cases with a named approver and written reasons — an owner decision,
not an engineering one.

## ADR revision — the privileged-execution defect class is broader than W-09 recorded

**Original position.** W-09 enumerated the login shell and two mission command
overrides.

**What the adversarial pass found.** `shadowfetch-workbench` ran
`pkexec` on a program path taken from `SHADOWFETCH_WORKBENCH_HELPER`. That is
the same class and more direct than the PATH indirection W-09 described: no
search path is involved, the environment-supplied path is executed as root
after the user answers an ordinary authentication prompt. Its `is_file()` and
`X_OK` checks do not help, because an attacker-planted file satisfies both.

**Revised decision.** The rule is not "sanitise PATH for privileged tools" but
**the program passed to `pkexec` must be a compile-time constant**. Phase 2
should treat any `pkexec` argument that is not a literal path as a defect by
construction, and the credential broker design should assume the same for
whatever it invokes.

## Standing guard confirmed for Phase 2

`tools/mission_provider_contract.py` pins the provider set to
`{codex, offline}` with `local_ai == "deferred"`, enforced by
`source_gate_4_0_0.py:217`, `package_gate_4_0_0.py:239` and
`iso_gate_4_0_0.py:774`. Adding any provider — the entire point of the
AgentProvider abstraction — fails all three gates until the contract and its
three call sites move together. This is deliberate anti-drift, not a defect.
Phase 2's first commit should change them as one unit rather than discovering
this in CI.
