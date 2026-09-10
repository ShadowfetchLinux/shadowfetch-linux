# Provider Trust

*Shadowfetch Linux 4.0.x — Phase 2.5. Companion to `AGENT_ARCHITECTURE.md`
(what the seam is), `PROVIDER_MANIFEST.md` (what a manifest may say) and
`PROVIDER_DEVELOPMENT.md` (how to write one).*

This document answers one question: **what does the system actually know about a
provider before it runs it, and what does it merely have on file?**

Everything below is either enforced by code and pinned by a test, or listed in
§7 as declared-and-not-enforced. There is no third category. If you find a claim
here that is not in one of those two lists, it is a bug in this document.

---

## 1. Why this exists

Phase 2 replaced a hard-coded provider list — an AST comparison against frozen
source — with a JSON Schema. That bought extensibility: a provider became data,
addable without editing Python. It also removed the only thing standing between
"a file appeared in a directory" and "a program runs with credentials and
network access", because **a schema says a manifest is well FORMED. It never
says anyone agreed to run it.**

Any package that dropped a schema-valid file into
`/usr/share/shadowfetch/providers` became a provider, asking for whatever
capabilities, credentials and network posture it liked.
`PHASE2_REMAINING_RISKS.md` recorded that as the leading P1. Phase 2.5 closes it
without taking back what Phase 2 bought.

---

## 2. The three questions asked before a provider runs

| | question | answered by | if the answer is no |
|---|---|---|---|
| 1 | Is this manifest well formed? | JSON Schema, `sf_jsonschema` | the provider does not load, error recorded |
| 2 | Did a human approve **these bytes**? | `/usr/share/shadowfetch/provider-policy/approved.json` | the provider does not load, error names the policy |
| 3 | Is the program one a third party cannot replace? | `classify_executable()` | refused at readiness **and** at execution |

Question 1 is Phase 2. Questions 2 and 3 are Phase 2.5. All three are asked
every time a registry is built; none of them can be answered by anything a
provider ships.

---

## 3. The approved-provider policy

`/usr/share/shadowfetch/provider-policy/approved.json` is reviewed **data**,
shipped by `shadowfetch-missions`. A provider is active only if it has an entry
there and its manifest file hashes to the `manifest_sha256` recorded in it.

```json
"codex": {
  "package": "shadowfetch-missions",
  "interface_version": 1,
  "capabilities": ["code_change", "sourced_report"],
  "credential_ids": ["CODEX_API_KEY"],
  "network_policy": "allowlist",
  "egress_allowlist": ["api.openai.com", "chatgpt.com", "auth.openai.com"],
  "executable_trust": "user-runtime",
  "manifest_sha256": "9508a119…",
  "trust": "distro-managed"
}
```

### Why it is not in the discovery directory

A third-party package may add a file to `providers/` without a dpkg conflict; it
cannot overwrite a file another package already owns. Keeping the policy in a
directory of its own, owned by `shadowfetch-missions`, is what makes the pin
meaningful against a *package* rather than merely against a typo.

### What the pin is worth

The digest is over **bytes**. This is strictly stronger than the AST freeze it
replaces: the freeze compared a parse tree and could be satisfied by equivalent
code; this cannot be satisfied by anything except the reviewed file. Editing a
manifest after approval — even to fix a typo — invalidates it, and the refusal
says so and says what to do:

```
provider 'codex': manifest digest 4f2a91c0... does not match the approved
9508a119.... The manifest changed after it was approved; re-review it and
re-seal the policy.
```

### Intersection, never union

Effective privilege is the intersection of what the manifest requests and what
the policy permits. A manifest asking for **more** than it was approved for is
refused outright rather than quietly clamped, because a manifest that no longer
matches what a human reviewed is a manifest whose review is void — and silently
narrowing it would hide both the mis-packaging and the attack. Where a policy is
deliberately **narrower** than a manifest, the policy wins and the effective
manifest is genuinely narrower.

`test_approved_provider_policy.py` proves this both ways: the intersection test
asserts that the specific privilege a union implementation would have granted is
absent, because a union that happened to equal the intersection would otherwise
pass.

### Fail closed

No policy file, an unreadable one, a malformed one, an unknown `schema_version`,
or an entry missing a required field ⇒ **zero active providers** and a recorded
error. There is no `except` branch anywhere in `load_policy()` that returns an
empty-but-valid policy. A system that cannot tell you what it is allowed to run
runs nothing.

### Sealing is a human act

`tools/providers/seal_policy.py` records an approval. It requires `--yes`, and
it prints the privilege diff against the current entry before it writes.

It is deliberately in **no** make target. A policy a build step can rewrite is
not a policy — it is a cache of whatever the tree happens to contain.

### The gate applies the same code

`tools/providers/validate_manifest.py` imports `ApprovedPolicy` from the runtime
module rather than reimplementing the check, so the two cannot drift: a provider
the gate admits and the runtime would refuse is a release that silently loses a
provider. The gate additionally refuses a policy that approves a provider the
artifact does not ship, which is how a stale entry survives a provider's
removal.

### A provider is still added as data

One manifest, one adapter, one approval entry. No Python edit anywhere. The
conformance suite proves it with a third provider and a byte-for-byte comparison
of the gate's own source, and the approval entry is the only thing Phase 2.5
added to that list.

---

## 4. Executable trust

### Absolute is not trusted

The Phase 2 check was a path-prefix test. `/usr/local/bin` is `root:staff 0775`
on plenty of machines; `/opt` is routinely handed to an installer. A root-owned
binary inside a directory a third party can write is a binary a third party can
replace — renaming a directory entry is as good as editing the file — and the
old check never looked above the file at all.

### The four classes

Derived from observed ownership and mode of the file **and every parent
directory**:

| class | meaning |
|---|---|
| `distro-managed` | packaging-owned path, root-owned every step from `/`, nothing writable by anyone else |
| `user-managed` | writable only by root and the invoking user |
| `developer` | integrity fine, provenance unmanaged: root-owned, nobody else writable, outside the packaging-owned directories |
| `untrusted` | somebody else can substitute it |

### Declaration ≠ classification

A manifest's `executable.trust` (`system` / `user-runtime` / `developer`) is a
**requirement** — what a provider asks to be allowed. The four classes are what
its program turned out to be. They are spelled differently on purpose: one
vocabulary for both is how a declaration comes to look like a control.

The mapping is a **set per declaration**, not a rank:

| declaration | accepts |
|---|---|
| `system` | `distro-managed` |
| `user-runtime` | `distro-managed`, `user-managed` |
| `developer` | `distro-managed`, `user-managed`, `developer` |

"Root-owned in an unmanaged directory" and "user-owned under `$HOME`" are not
comparable, and forcing them onto one axis makes one of the two orderings wrong.

`untrusted` is accepted by **no** declaration. No manifest may consent on the
user's behalf to a program a third party controls.

### Group-writability is measured, not waived

Debian gives each user a private group, so npm and nvm's 0775 installs under
`$HOME` are writable by a group of one. That is materially different from 0775
under `staff` or `adm`. Phase 2 accepted all group-writability for user runtimes
and recorded the gap; `_private_group()` now checks the member list, so the npm
case passes and the shared-group case classifies `untrusted`.

The sticky bit is honoured: a world-writable `/tmp` in the path does not let
anyone substitute another user's file, and treating it as though it did would be
factually wrong.

### The policy caps it too

How far outside the packaging system a provider's program may live is a
privilege, so an approval entry without `executable_trust` is **refused**, not
defaulted. The effective value is the narrower of manifest and policy.

---

## 5. What a provider can never do

Each of these is a mechanism, not a convention, and each has a test.

* **Widen its own sandbox.** The registry builds the `SandboxSpec` from the
  effective manifest; an adapter may `narrow()` and cannot widen. Checked again
  by `verify_invocation()` at the moment of execution, so an adapter that
  constructs a spec by hand is caught.
* **Choose its own program by environment.** No PATH resolution exists in the
  package; the manifest's `candidates` are absolute or `~`-relative, and the
  resolved answer is re-classified.
* **Select its own manifest.** `SHADOWFETCH_PROVIDER_MANIFESTS` used to point
  discovery anywhere the invoking user owned. Even clamped for ownership and
  mode, an environment variable deciding which credentials a provider may
  request is the Phase-1 PATH defect one layer up. Setting it now writes a
  warning to stderr and changes nothing; tests inject a root through the
  `ProviderRegistry` constructor, which is explicit and local to the caller.
* **See a credential value it did not declare.** Firebreak runs `--clearenv` and
  re-adds only named identities; the value is injected at the boundary by code
  that never came from a provider.
* **Be reached by name from the engine.** No file in `PROTECTED_FILES` compares
  against a provider id — asserted on the syntax tree, for every provider the
  registry knows.

---

## 6. What is trusted, and by what

| thing | trusted because | if that is wrong |
|---|---|---|
| the manifest | dpkg file ownership + a sha256 a human sealed | a package would have to replace a file `shadowfetch-missions` owns |
| the adapter module | named by an approved manifest, loaded from the package's own module directory | same |
| the policy | ships in a directory of its own, owned by `shadowfetch-missions` | same |
| the program | classified from filesystem ownership and mode, every level | root, or the invoking user, is already compromised |
| the schema | ships beside the manifests, parsed by the same validator the gate uses | same as the manifest |

Everything in the left column reduces to one of two assumptions: **dpkg file
ownership holds**, or **root and the invoking user are not already
compromised**. Nothing reduces to "the provider behaved."

---

## 7. Declared and NOT enforced

**This table is empty as of 4.1.0.** Every declarable field reaches a mechanism.
What remains are RESIDUALS on fields that are enforced — recorded below, because
a control with an unstated limit is the same problem in a better disguise.

| field | residual |
|---|---|
| `egress_allowlist` | Enforced by nftables in the sandbox's own network namespace, default DROP, **only where hosts are declared.** `--net allow` with no declared destination attaches a NAT and installs no ruleset, so it reaches the LAN; the decision reports `network_destination` as `observable_only` for that case. Names are resolved ON THE HOST at launch, IPv4 only, and a host that resolves to nothing refuses the run rather than starting it unfiltered. DNS still leaves: the sandbox resolves through the NAT's forwarder, which the ruleset must permit or nothing routes. |
| `masked_paths` | Enforced by real mounts — an empty tmpfs over a directory, `/dev/null` over a file — with no cooperation from the payload. Masking is BY PATH, so a hardlink to the same inode under an unmasked name is still readable. |
| *syscall profile* | Applied to every sandbox and **not declarable**, deliberately: a manifest property here would be a provider choosing its own syscall surface. Firebreak seals a classic-BPF program in a memfd and passes `bwrap --seccomp <fd>`; 46 syscalls answer `EPERM`, self-tested before any argv exists, refusing the run rather than degrading. |
| `cpu_seconds` | `RLIMIT_CPU` is per-process, so a provider that forks gets a fresh budget for each child. A whole-session budget needs a cgroup, not an rlimit. |
| *credential values* | A granted identity's VALUE arrives by `--setenv`, so anything the agent starts can read it. What is enforced is that an undeclared identity is absent, and that a value never travels in an argv or into any record. |

> **Historical note.** Until 4.1.0 the first three rows above were in a table
> headed "reach no enforcement mechanism — they must not be described to users
> as controls". `egress_allowlist` read "Firebreak has two network postures,
> `none` and `allow`… `allowlist` collapses to `allow`"; `masked_paths` read
> "Firebreak has no masking flag"; the syscall profile read "no `bwrap
> --seccomp` anywhere". All three shipped in 4.1.0. The wording is kept here
> because a reader who acted on the old text needs to know it changed, not to
> discover the change by its absence.

`test_sandbox_spec_audit.py` holds this list as a machine-readable table and
fails a build if any field's status drifts from what is actually enforced — in
either direction. A field cannot quietly stop being enforced, and cannot quietly
start being claimed.

---

## 8. What Phase 2.5 did not establish

* **Live Codex integration is NOT VERIFIED.** The CLI is installed on the build
  host; provider authentication is not configured, and this phase does not alter
  credentials. Every Codex path is covered by unit tests and recorded fixture
  streams only. See `PHASE2_5_TEST_RESULTS.md`.
* **`account_mount` enforcement is source-read only.** Demonstrating it needs a
  signed-in Mission Control account, which the audit must not touch.
* **There is no credential broker.** Credential values are resolved in the
  engine and handed to Firebreak. Phase 3.
* **A provider is trusted per-machine, not per-mission.** Nothing scopes a
  provider's approval to a workspace, a person or a time window.
* **The registry is cached for the worker's lifetime.** A newly approved
  provider needs a worker restart, and an adapter that stores per-turn state on
  itself would leak it into the next person's mission. The conformance suite
  forbids the latter (`test_parse_stream_does_not_mutate_the_adapter`); the
  restart is a known limitation.

---

## 9. So: can Mission Control trust the provider layer?

**For approvals, audit and orchestration: yes.** Who may run, with what
capabilities, credentials and network posture, is decided by reviewed data that
a provider cannot influence, verified against bytes, applied identically by the
runtime and the release gate, and failing closed at every step.

**For containment: to the boundary in §7, and no further.** The workspace,
network on/off, read grants, credential identities, memory, CPU and process
count are enforced by bubblewrap and cgroups. Egress destinations and path
masking are not, and a syscall profile is not even expressible. Any feature
built on top of this must treat those three as *recorded intent*, not as
controls — and the audit table will fail a build if that ever quietly changes.
