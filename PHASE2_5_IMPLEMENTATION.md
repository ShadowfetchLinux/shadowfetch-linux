# Phase 2.5 Implementation

*Nine commits on top of `fb9b32a`. What changed, why, and what each thing was
before.*

## The shape of every finding in this phase

Each defect below has the same form: **a check that exists, runs, and does not
cover the thing it appears to cover.** Phase 2 found `cpu_seconds` in that state
— schema-bounded, narrow()-checked, verify_invocation()-checked, and passed to
Firebreak nowhere. Phase 2.5 was written on the assumption that it would not be
the only one. It was not.

| what looked enforced | what was actually checked |
|---|---|
| "a manifest is validated" | that it is well FORMED — never that anyone approved it |
| "the executable is trusted" | its path PREFIX — not who can replace it |
| `workspace_mode` | narrowing and widening — the value reached nothing |
| `memory_mb` | resident memory — swap was uncapped |
| an adapter's program | its trust TIER — not WHICH program |
| `credential_ids` narrowing | nothing; the argv came from the resolved secrets |
| the redactor's flush | the normal exit only |

---

## 1. The approved-provider policy (`7f79609`)

`/usr/share/shadowfetch/provider-policy/approved.json`. A provider is active
only if it has an entry there **and** its manifest hashes to the recorded
`manifest_sha256`. Package, interface version, capabilities, credential
identities, egress hosts and network rank are all bounded by the entry.

Effective privilege is the **intersection**, never the union. Anything above the
ceiling is refused outright rather than clamped: a manifest that no longer
matches what a human reviewed is a manifest whose review is void, and silently
narrowing it hides both mis-packaging and attack. Where a policy is deliberately
narrower, it genuinely narrows.

Fails closed at every step: no policy, unreadable, malformed, unknown
`schema_version`, or a missing required field ⇒ zero providers and a recorded
error.

The release gate imports `ApprovedPolicy` from the runtime module rather than
reimplementing it, so gate and runtime cannot disagree, and additionally refuses
a policy approving a provider the artifact does not ship.

`tools/providers/seal_policy.py` records an approval: `--yes` required, prints
the privilege diff first, and is deliberately in **no** make target.

**Also in this commit:** `SHADOWFETCH_PROVIDER_MANIFESTS` no longer selects the
discovery root. Even clamped for ownership and mode, an environment variable
deciding which credentials a provider may request is the Phase-1 PATH defect one
layer up. It now warns on stderr and changes nothing.

## 2. The declared-vs-effective sandbox audit (`720cf16`)

All ten `SandboxSpec` fields traced through five stages — DECLARED / VALIDATED /
NARROWED / PASSED / ENFORCED — as a machine-readable table that fails a build if
a field's status drifts **in either direction**. Empirical where it can be: real
sandboxed processes in throwaway `/tmp` workspaces, and for negative results,
proving absence rather than asserting it.

No fixes in that commit. The audit's product is an honest table, and mixing the
repairs into it would make both harder to review.

## 3. Executable trust classification (`16f39cd`)

Four classes derived from observed ownership and mode of the file **and every
parent directory**: `distro-managed`, `user-managed`, `developer`, `untrusted`.
Absolute is not trusted — `/usr/local/bin` is `root:staff 0775` on plenty of
machines, and a root-owned binary in a directory a third party can write is a
binary a third party can replace.

Declaration and classification are spelled differently on purpose. The mapping
is a set per declaration, not a rank: "root-owned in an unmanaged directory" and
"user-owned under `$HOME`" are not comparable.

Group-writability is now **measured**: Debian's private-per-user groups are
accepted, shared groups are not. That closes the residual Phase 2 recorded
rather than carrying it forward. The sticky bit is honoured.

The policy approves the latitude explicitly — an entry without
`executable_trust` is refused, not defaulted — and the narrower of manifest and
policy applies.

## 4. Delivering the undelivered sandbox fields (`4351129`)

* **`workspace_mode`** now reaches Firebreak (`--workspace-mode`, `--ro-bind`).
  It previously reached nothing, and the restriction held only because the Codex
  adapter volunteered `--sandbox read-only` in its own argv — provider-supplied
  code enforcing its own restraint, which is what a sandbox boundary exists in
  order not to depend on.
* **`memory_mb`** gains `MemorySwapMax=0`. A process had touched 4096 MiB under
  a 256 MiB cap and exited 0.
* **`credential_ids`** narrowing by an adapter is honoured.
* **The schema floors** match Firebreak's own bounds, so a manifest cannot pass
  every static check and then die at run time.

A caller building Firebreak's arguments by hand must state the workspace
posture. Deliberately **not** `getattr(args, "workspace_mode",
"workspace-write")`: that default is the permissive one.

## 5. Stressing the interface with a token-streaming provider (`5c16039`)

A local-model provider as a conformance **fixture**: incremental token deltas,
an explicit session, heartbeats, tool rounds, a native cancel event, no
guaranteed terminal record. 15 recorded stream fixtures.

**The interface needed no change, which is the headline.** No `AgentSession`, no
`open_session`/`submit`/`stream_events`/`cancel`/`close_session`, no
`TEXT_DELTA`/`SESSION_STARTED`/`TOOL_REQUEST`/`STATUS`. Fourteen distinct native
event names reduce to the existing six with nothing dropped or mislabelled.

No host-network bypass was created to make it work. Firebreak has two postures,
`none` and `allow`; a socket-based model server needs a bridge program the
sandbox executes, which is a Firebreak change plus a bridge binary, not an
`AgentProvider` change.

**Three transport defects**, none reachable by either shipped provider:

1. The redactor was never flushed on an abnormal exit. Cancelling a generation
   shorter than the 20608-byte carry window wrote a **zero-byte log**.
2. The output cap kept the head, and a terminal event is by definition last, so
   an exit-0 success was reported as "did not record a complete successful turn".
3. Every 65536-byte read was decoded independently, so a character on a read
   boundary became replacement characters and the turn still succeeded.

**Also:** the conformance `.log` fixtures were gitignored, so no fresh clone
could run that suite at all.

## 6. Conformance suite expansion (`6446ccf`)

Eight assertions per provider across manifest trust, interface generality and
streaming, including the **stateless-adapter contract** — recommended over
adding an `end_mission()` lifecycle method, since both shipped adapters already
satisfy it and adding lifecycle machinery with no stateful provider to justify
it is what the brief warned against.

## 7. Capability/provider separation (`3e06175`)

Phase 2 proved a third provider could be added as data. That is weaker than the
invariant this rests on. With only the shipped two, every capability has exactly
one provider and "capability chose the runtime" is indistinguishable from
"capability IS the runtime". The local-model fixture declares the same
capabilities as Codex, so the distinction is finally testable.

The engine-branches-on-no-provider-id assertion is on the **syntax tree**, not
the text — `sf_missions.py` legitimately contains `"codex"` inside
`LEGACY_RUNTIME_PROVIDER`, a migration map a 4.0.0 database still needs read.

## 8. Documentation (`93790db`)

`docs/PROVIDER_TRUST.md` is new. Four claims in the shipped documentation were
wrong after this phase's fixes and two were wrong before it; §6.6 of
`AGENT_ARCHITECTURE.md` omitted `workspace_mode` entirely, so the one field with
a live enforcement hole was not even on the known-gaps list.

## 9. WHICH program, not what kind (`43372e4`)

`verify_invocation()` checked the trust tier of an adapter's program and never
its identity, so any adapter could substitute any other distro-managed binary —
`/bin/sh` for a provider declaring `/usr/bin/ffmpeg` — and inherit that
provider's credentials, network grant and read grants.

Found by attack 15 of the adversarial pass, and **only because the attack's
first form passed for the wrong reason**: a program in `/tmp` was refused on its
tier. Retrying with a program of the right tier showed the hole.
