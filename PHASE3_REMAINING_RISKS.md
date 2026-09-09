# Phase 3 — remaining risks

Nothing here is hidden in a comment. Every item below is also reported by the
running system, on the receipt, in `audit verify`, or in the desktop's
enforcement panel.

## The security-sensitive field table

Each column is a separate fact. Collapsing any two of them is the failure mode
this phase exists to prevent.

| field | REQUESTED | VALIDATED | NARROWED | PASSED TO ENFORCEMENT | ACTUALLY ENFORCED | AUDITED |
|---|---|---|---|---|---|---|
| `workspace_mode` | manifest | `read-only`/`workspace-write` only | adapter may tighten | `--workspace-mode` | **yes** — bwrap `--ro-bind` / `--bind` | session row + receipt |
| `network` | manifest | `none`/`allowlist` only | may tighten, never widen | `--net` | **on/off only** — bwrap `--unshare-net` for `none`; `allowlist` collapses to the host network | requested **and** effective, both stored |
| `egress_allowlist` | manifest | rejected if `network=none` | may shrink | **no** | **NO** — reaches no filter | stored, and named in `declared_but_not_enforced` |
| `read_grants` | manifest | absolute paths only | may shrink | `--read` per grant | **yes** — bwrap `--ro-bind` | session row |
| `masked_paths` | manifest | checked on widening | may grow | **no** | **NO** — Firebreak has no masking flag | stored, named in `declared_but_not_enforced`, and now named in the decision's relied-on-but-not-enforced list |
| `credential_ids` | manifest | must be declared identities | may shrink | `--setenv` per identity | **yes** — `--clearenv` plus one `--setenv` | requested **vs** granted, both stored; values never stored |
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

**`RLIMIT_CPU` is per-process.** A provider that forks gets a fresh CPU budget
for every child. The mission timeout is the real ceiling.

**Approval is bounded by the uid.** The engine runs as the same user that owns
the database, so an attacker who already has that uid can write rows. What the
chain and the journal give is *detection*, not prevention — and the journal is
root-owned, so detection survives what prevention cannot. Root can rewrite the
journal; the module says so in its docstring rather than implying otherwise.

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

## Recommended Phase 4 start

1. **Egress enforcement.** It is the largest gap between what is declared and
   what is applied, the receipts already name it on every mission, and the
   allowlists are already collected and validated — the data is in place and
   only the mechanism is missing.
2. **The credential broker**, so `--setenv` stops being the delivery path.
3. **Then** additional providers. Adding a provider before 1 and 2 widens the
   blast radius of two known-unenforced controls.
