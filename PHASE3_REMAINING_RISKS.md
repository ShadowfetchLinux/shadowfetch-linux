# Phase 3 — remaining risks

*Current as of **Phase 3.1** on `release/4.0.0`.*

Nothing here is hidden in a comment. Every item below is also reported by the
running system, on the receipt, in `audit verify`, or in the desktop's
enforcement panel.

## The security-sensitive field table

Each column is a separate fact. Collapsing any two of them is the failure mode
this phase exists to prevent.

**PASSED TO ENFORCEMENT names the flag Mission Control actually emits**, which is
not always the flag the kernel eventually sees. There are two hops —
`sf_missions.run_process()` → `shadowfetch-firebreak` → `bwrap`/`systemd-run` —
and writing the second hop's flag in the first hop's column hid a real question:
whether Mission Control passes anything at all.

| field | REQUESTED | VALIDATED | NARROWED | PASSED TO ENFORCEMENT | ACTUALLY ENFORCED | AUDITED |
|---|---|---|---|---|---|---|
| `workspace_mode` | manifest | `read-only`/`workspace-write` only | adapter may tighten | `--workspace-mode` | **yes** — bwrap `--ro-bind` / `--bind` | session row + receipt |
| `network` | manifest | `none`/`allowlist` only | may tighten, never widen | `--net` | **on/off only** — bwrap `--unshare-net` for `none`; `allowlist` collapses to the host network | requested **and** effective, both stored |
| `egress_allowlist` | manifest | rejected if `network=none` | may shrink | **no** — Firebreak's `--egress-host` exists and is record-only; Mission Control does not pass it | **NO** — there are two network postures and no destination filter anywhere | stored, and named in `declared_but_not_enforced` |
| `read_grants` | manifest | absolute paths only | may shrink | `--read` per grant | **yes** — bwrap `--ro-bind` | session row |
| `masked_paths` | manifest | checked on widening | may grow | **no** — Firebreak's `--mask-path` exists and is record-only; Mission Control does not pass it | **NO** — nothing tmpfs's, unbinds or otherwise hides a declared path | stored, named in `declared_but_not_enforced`, and named in the decision's relied-on-but-not-enforced list |
| `credential_ids` | manifest | must be declared identities | may shrink, and the narrowing is honoured | `--credential-env` per identity, intersected with the invocation's spec | **yes** — Firebreak turns each one into bwrap `--clearenv` plus one `--setenv`; the value travels in Firebreak's environment, never in an argv | requested **vs** granted, both stored; values never stored |
| `account_mount` | manifest | must name a known mount | may drop | `--<mount>` | **yes** — bwrap `--bind` | session row |
| `memory_mb` | manifest | integer | may lower | `--memory-mb` | **yes** — systemd `MemoryMax` with `MemorySwapMax=0` | session row |
| `processes` | manifest | integer | may lower | `--processes` | **yes** — systemd `TasksMax` | session row |
| `cpu_seconds` | manifest | integer | may lower | `--cpu-seconds`, at the tighter of the declaration and the mission timeout | **partial** — `RLIMIT_CPU` is per-**process**, so a provider that forks gets a fresh budget per child | session row, marked `partial` |
| `syscall_profile` | — | — | — | **no** | **not representable** — no schema property, no `--seccomp` anywhere | named in `declared_but_not_enforced` |

A field a session does not use reports `not_applicable`, not `enforced`.

## P1 risks

**Egress is unenforced and that is load-bearing.** A mission with
`network=allowlist` has the host's network. The hosts it declared are recorded
for audit and filtered by nothing. Any threat model that assumes an agent
cannot reach an arbitrary host is wrong today. Phase 4.

**Path masking is unenforced.** `masked_paths` declaring `/home/agent/.ssh` and
`/etc/shadow` masks neither. The sandbox's read surface is what the bind mounts
give it, not what the mask list says.

The **reason** is worth stating correctly, because it was recorded wrongly for
most of Phase 3 and the wrong reason pointed at the wrong fix. It is *not* that
"Firebreak has no masking flag": Firebreak accepts `--mask-path`, its own
`--help` calls it **RECORDED ONLY**, and its session record reports the paths as
`not_enforced` with the mechanism *"these paths are recorded and reach nothing"*.
Nothing behind the flag hides anything, and Mission Control does not pass it at
all — so a declared mask reaches neither a mechanism nor Firebreak's record. The
missing piece is the mechanism, not the flag.

**`RLIMIT_CPU` is per-process.** A provider that forks gets a fresh CPU budget
for every child. The mission timeout is the real ceiling.

**Approval is bounded by the uid.** The engine runs as the same user that owns
the database, so an attacker who already has that uid can write rows. What the
chain and the journal give is *detection*, not prevention — and the journal is
root-owned, so detection survives what prevention cannot. Root can rewrite the
journal; the module says so in its docstring rather than implying otherwise.

Detection is now on the path a mission actually takes rather than left to a
person: `find_approval()` refuses a row with no `approval-granted` event behind
it, refuses a row whose fields disagree with the digest that event carries, and
reads revocation from the chain rather than from the `revoked_at` column. What it
cannot do is prevent the write, and it cannot help an approval whose grant event
was itself removed — that is a chain problem, and `audit verify` is what reports
it. `docs/APPROVAL_POLICY.md` §7.6 has the refusal texts.

**A forged mission row is detected at verify time, not prevented.** The
`missions` table carries no hash, so `UPDATE missions SET state='completed'`
lands and the engine reads it back. `Store.verify_states()` replays each
mission's event trail through `MISSION_TRANSITIONS` and reports the mismatch —
`audit verify` prints a `mission states` verdict beside the chain's and exits 1 —
but the state that was displaced is not recoverable. Same shape as the approval
row: the uid owns the database, so the honest claim is evidence.

**The `.session` correlation is worth what a file the agent can create is
worth.** The MCP gate's `_session_recorded()` is one `is_file()` call. It reads
nothing, so the file's contents are not evidence and are not treated as
evidence: the recorded word is `observed`, not `verified`.

**A duplicated `turn.completed` overrides the real usage figures** — the last
one wins in `parse_stream`. Not exploited for anything beyond token accounting,
but it is a provider-controlled value winning over an earlier provider-
controlled value with no record that it happened.

**No live cloud provider has been exercised.** `offline-media` and `codex` are
the only wired providers, and everything the phase asserts about cloud
providers is a design claim, not a measurement.

## Not risks, but limits worth naming

* The tool-execution path is declared and provider-neutral, and no shipped
  provider emits `data['tool']`. It has been tested with malformed input fed
  directly, not with a real producer.
* `audit verify` exits `2` for `unverified` and `degraded`, `1` for a broken
  chain or a disagreeing state replay, `0` otherwise. `2` is not a pass.
* Undo restores workspace files. It cannot undo an external effect, and the
  receipt says exactly that in `recovery_scope`.
* The mirror is a per-event anchor for the events it managed to write, and blind
  to the ones it did not. `verify_chain()` compares every sequence number the
  journal still holds, so a rewrite deep in the log is a finding — but an event
  that was never mirrored has nothing to be compared against, and nothing retries
  a failed mirror. `degraded` is the only signal, and it resets on the next
  success.

## Closed since the Phase 3 transcript

Kept here rather than deleted, because each was a *stated* risk and a reader of
the older document needs to know it moved.

* **`degraded` could suppress the journal comparison.** `audit-mirror.json` is
  attacker-writable, and the verdict branched on it first. Degradation is now
  reported alongside the comparison; local bookkeeping may add a caveat and may
  never remove a finding.
* **The anchor compared one row.** A rewrite deep in the log survived one honest
  append. Every mirrored `seq` is compared now, and a re-minted chain id is a
  conflict rather than an absence, because the journal is keyed by a store
  identity derived from the database's path.
* **The retry budget lived in one verb.** `requeue_refusal()` is keyed on the
  edge's event, both `transition()` and `finish_execution()` ask it, and the
  refusal is recorded before it is raised.
* **An approval row was compared to the chain by hand, on `scope_sha256` alone.**
  See above.
* **`expires_at` was compared as a string**, so a non-UTC offset outlived its own
  expiry and a non-timestamp never expired at all.
* **The audit exit code was computed inside the text branch**, so `--json` — the
  form a CI gate uses — reported success over a tampered log.

## Recommended Phase 4 start

1. **Egress enforcement.** It is the largest gap between what is declared and
   what is applied, the receipts already name it on every mission, and the
   allowlists are already collected and validated — the data is in place and
   only the mechanism is missing. Path masking sits behind the same work: both
   flags exist on Firebreak, both are record-only, and neither is passed.
2. **The credential broker**, so an injected environment variable stops being the
   delivery path.
3. **Then** additional providers. Adding a provider before 1 and 2 widens the
   blast radius of two known-unenforced controls.
