# Phase 2 — Remaining risks

What Phase 2 did **not** close, each with an owner or a decision. Ordered by
consequence. Several of these were found by an adversarial review of the seam
*after* it was built, which is why they are stated as facts rather than worries.

---

## 1. `egress_allowlist` is declared and validated — but nothing filters egress

A manifest with `network_policy: "allowlist"` must name its hosts, the schema
rejects an empty list, the registry refuses an adapter that adds a host, and the
allowlist is recorded on the receipt. **None of that is an egress control.**
`SandboxSpec.firebreak_network` collapses `allowlist` to Firebreak's `allow`,
which shares the host network namespace with no filtering, because Firebreak has
no egress filter to give it — `git grep egress` in the fireline package returns
nothing.

So Codex's declaration of `api.openai.com` is an **audit record and a future
enforcement point**, not a restriction that holds today. The `SandboxSpec`
docstring says so, and this is repeated here because a reader could reasonably
assume otherwise from the schema.

**Phase 3 or later.** Real enforcement needs a filtering proxy or a netns with
DNS/IP rules inside Firebreak. Until then, do not describe the allowlist as a
control in user-facing material.

## 2. `masked_paths` is declared, validated, published — and enforced nowhere

Same shape as the above, and worse because the name implies protection.
`masked_paths` travels from manifest to `SandboxSpec` to the UI, and
`verify_invocation()` refuses an adapter that *drops* a mask. But Firebreak has
no masking flag, so no mask is applied to anything.

It was kept rather than removed because the declaration is the hard part to
retrofit and the enforcement is a Firebreak change. **It should not be presented
to users as a security feature until Firebreak can honour it.**

## 3. There is no approved-provider policy

The gate validates a manifest's *shape*; nothing constrains *which* providers may
ship. Any Debian package that lands a schema-valid manifest and an adapter under
`/usr/lib/shadowfetch/missions/` becomes a provider on next start, with whatever
`credential_ids` and `network_policy` it declares — on a system whose premise is
that the sandbox is the trust boundary. `ANTHROPIC_API_KEY`,
`AWS_SECRET_ACCESS_KEY` and `GITHUB_TOKEN` are all schema-valid declarations.

The old AST freeze accidentally prevented this by freezing the provider set
entirely, which is why removing it is a net *reduction* in one narrow sense even
though it was the right thing to do.

**Recommended for Phase 3, and it is small:** `tools/providers/approved_providers.json`
listing each permitted provider id with a `manifest_sha256` pin, checked by the
existing gate. That is strictly stronger than the old freeze (it pins content,
not just names) and still lets a provider be added by editing **data**, so the
architectural property this phase bought is preserved.

## 4. `SHADOWFETCH_PROVIDER_MANIFESTS` remains an environment override

It is now clamped — honoured only from a directory the invoking user owns that is
not group- or world-writable, and it says so on stderr when it refuses (observed
refusing a 0775 `/tmp` fixture). But it is still an environment variable that
selects the document deciding credentials, network posture and resource caps.

**Residual:** a process that can set it *and* write a directory it owns can
present its own provider set to the next Mission Control it starts. The user's
own session can already do worse, so this is a defence-in-depth gap rather than a
privilege boundary, but it is the Phase-1 defect class one layer up and should be
gated behind an explicit test flag rather than being always-on.

## 5. `trust: "user-runtime"` accepts a group-writable program

The Codex CLI is genuinely an npm package under the user's home, so a blanket
"packaging-owned directories only" rule would have deleted Codex support.
`executable.trust: "user-runtime"` therefore permits it, requiring the file to be
owned by the invoking user and not world-writable.

**It does not reject group-writable**, because npm and nvm install `0775` under
the user's personal group and rejecting that would refuse every real install. On
a machine where the user's primary group has other members, another member of
that group can replace the Codex binary. Documented rather than silently
accepted; the fix is upstream in how the CLI is installed, or a shipped
system-packaged Codex.

## 6. Two providers is not a real test of "many"

The seam is proven with a third provider fixture, which is the right proof, but
every shipped provider is still either a JSONL cloud CLI or ffmpeg. The interface
has not yet met a long-running local model that streams tokens continuously and
holds state between turns — the case that most often breaks a turn-shaped
abstraction. `AgentEvent` has a `PROGRESS` type and the executor reads
incrementally, so the shape is plausible, but it is untested.

**Phase 3 should add the local-model provider early rather than last**, because
it is the one most likely to demand an interface change, and changing the
interface is cheapest while only two adapters implement it.

## 7. `CAPABILITY_METHOD` still lives in Mission Control

Adding a *capability* (as opposed to a provider) requires editing
`sf_missions.py`: the `Capability` constants, `CAPABILITY_METHOD`, and the legacy
kind maps. That is deliberate — capability implementations *are* Mission
Control's business logic, and the phase's goal was provider extensibility — but
it should be stated so nobody expects a new capability to be free. A provider is
data; a capability is code.

## 8. Smaller items

- **`usage` is not type-checked.** A provider emitting
  `{"type":"turn.completed","usage":"not-a-dict"}` has that string recorded in
  the inference record. It corrupts nothing, but the receipt then carries a
  malformed value. Worth a type guard in `AgentProvider.usage()`.
- **The migration writes an events row with `mission='*'`.** There are no foreign
  keys so nothing breaks, but `Store.events(mid)` cannot reach it and QA tooling
  that queries the events table directly will see a row with no mission. A
  dedicated `schema_migrations` table would be cleaner.
- **`run_process` still PATH-resolves Shadowfetch's own tools** (`firebreak`,
  `ffmpeg`, `ffprobe`) via `executable()`. Provider programs no longer go through
  it, but PATH-resolving the *sandbox wrapper itself* is arguably the more
  dangerous of the two. Worth pinning to absolute paths in Phase 3.
- **The build host has `shadowfetch-fireline 3.0.0-1` installed**, whose Firebreak
  predates `--memory-mb`, so `executable()` finds a binary that rejects the flag
  and any real mission fails there. Pre-existing (4.0.0 passed the same flag),
  an artifact of the dev box, not of the code. Put
  `packages/shadowfetch-fireline/data/usr/bin` first on `PATH` to exercise the
  real path.

## 9. Carried forward from Phase 1, still open

The Phase 1 risk register stands. In particular the **live APT index expires
2026-09-20** and 4.0.0 still has **no acceptance evidence for 13 of 18 required
cases**. Phase 2 changed neither. See `PHASE1_REMAINING_RISKS.md`.
