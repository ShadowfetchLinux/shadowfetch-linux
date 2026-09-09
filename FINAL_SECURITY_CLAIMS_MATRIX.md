# FINAL_SECURITY_CLAIMS_MATRIX

`docs/SECURITY_CLAIMS_MATRIX.md` is the long form: one section per control, with
the code, the tests, the adversarial result and the residual. THIS document is
the short form, and it answers one question — **what may a person say about
Shadowfetch Linux 4.0.0 without saying something false?**

A claim is permitted here only when a LAYER prevents the behaviour and an
adversarial test proves it. "The code checks for it" earns nothing. Where a
control has a residual, the residual travels with the claim: a sentence that
drops it is not a shorter version of the claim, it is a different and untrue
claim.

## The vocabulary, which is not decorative

| word | what it means | what it does NOT mean |
| --- | --- | --- |
| `enforced` | a layer outside the payload prevents it | that no attack exists |
| `partial` | prevented with a stated residual | "mostly enforced" |
| `not_enforced` | nothing prevents it; it is recorded only | that it is unlikely |
| `not_applicable` | the field was not asked for | that it was satisfied |
| `not_representable` | the system cannot express the thing at all | that it is safe |
| `observed` | recorded as seen; not verified | authenticated, proven, or trusted |

The policy engine's parallel set — `fully_mediated`, `partially_mediated`,
`observable_only`, `not_observable` — answers a different question: not "is it
applied" but "can this system see or decide it at all". The two are deliberately
not merged.

## What may be claimed

### Yes, plainly

**"Syscalls are filtered."** This was in the forbidden list, and belonged there:
there was no profile and nothing that could apply one. A classic-BPF filter is
now applied to every sandbox — assembled in Firebreak's own source, sealed in a
memfd, handed to `bwrap --seccomp <fd>` — and 46 syscalls answer EPERM. It is
self-tested against the real kernel before any argv exists and the run is
refused rather than started unfiltered if the kernel will not take it. The
residual travels with it: 21 of the 46 were already denied and are defence in
depth rather than new enforcement, nested user namespaces are still creatable
on purpose, and a 32-bit payload is killed rather than filtered.

**"An agent runs in its own mount, PID, UTS, IPC, user and NETWORK namespace."**
Both postures. `none` leaves the network namespace empty; `allow` creates it
before bwrap and attaches a user-space NAT to it. Measured: the host's loopback
services and the host's abstract AF_UNIX namespace are unreachable from inside,
in both postures.

**The LAN is a different question, and an earlier draft of this document got it
wrong** — as did three strings in the code, now corrected. With the network on
and NO destination declared, an adversarial review reached the host's own LAN
address, the docker bridge and the LAN router from inside the sandbox:
`--disable-host-loopback` blocks `127.0.0.1` and nothing else. The LAN is out of
reach only where an allowlist is declared, because it is the nftables default
DROP that excludes it — which makes "no destinations declared" the posture to
watch, not the safe middle ground it reads as.

**"An agent cannot read or write the mission database, the approvals, the audit
chain, the receipts, or the Firebreak manifests."** Not by permission — by
ABSENCE. Those paths are not in the sandbox's mount namespace at all. `/var` is
absent so the journal cannot be read; `/dev/log` is absent so no forged anchor
line can be sent.

**"A provider only reaches the destinations it declares."** With the residuals
below, and only where hosts ARE declared: an nftables ruleset with a default
DROP, installed in the sandbox's own network namespace by the process that
created it, before the payload starts.

**"Paths a provider declares as masked are not visible to it."** An empty tmpfs
over a directory, `/dev/null` over a file, in the sandbox's own mount namespace.
No cooperation from the payload is involved.

**"A read-only workspace is read-only."** `bwrap --ro-bind`. Before this
existed, a provider declaring `workspace_mode: read-only` got a fully writable
workspace and the restriction held only because one adapter volunteered
`--sandbox read-only` in its own argv — provider code choosing its own
restraint, which is the thing a sandbox boundary exists in order not to depend
on.

**"Memory and process limits are enforced."** systemd `MemoryMax` and
`TasksMax` on a per-session scope.

**"The audit history is tamper-evident."** A hash-chained append-only event log
anchored in journald, with the domain records a receipt reprints bound into the
chain, and a verifier that distinguishes a fabricated mission
(`MISSING_HISTORY`) from a legacy one (`LEGACY_PRECHAIN`) from a rewritten one.

**"An approval covers exactly what was agreed."** Capability, provider,
workspace, network posture, credential identities, read grants AND destinations,
each witnessed by a per-field digest so an edit to `expires_at`, `granted_by` or
`method` is detected. Widening any of them after the grant stops the approval
covering the mission.

**"A provider is data, not code."** A manifest, an adapter, a sealed policy
entry and a conformance case. Four ship. Adding one costs no edit to the engine,
the policy or the sandbox — which is a claim the release gate checks, not a
claim about intent.

### Yes, but never without the residual

**Egress allowlist.** Three residuals, all of which must travel with it:
* **BY ADDRESS.** A name is resolved once, on the host, at launch. An address
  set that changes afterwards is unreachable until the next run.
* **IPv4 ONLY.** The ruleset matches `ip daddr`, so an IPv6 destination is not
  filtered by it — and is unreachable one step earlier instead: the NAT provides
  no IPv6 route at all, so a connection fails with `Network is unreachable`
  rather than reaching the default drop. Same outcome, different mechanism, and
  the difference matters the day the NAT is given IPv6.
* **DNS LEAVES.** The sandbox resolves through the NAT's forwarder, which the
  ruleset must permit or nothing routes at all. A payload can encode data in a
  query name. An allowlist narrows where bytes may be SENT; it is not a claim
  that nothing can be signalled out.

**Path masking.** BY PATH. A hardlink to the same inode under an unmasked name
is still readable. A path outside the workspace is refused rather than masked.

**CPU limit.** `RLIMIT_CPU` is per-process, so a provider that forks gets a
fresh budget for each child. `partial`, and the word is chosen.

**Network on/off with no destinations declared.** The network is on, a NAT is
attached, and NOTHING filters: the sandbox reaches anything the host can reach.
The decision reports `observable_only` and names it in `advisory_fields`, so no
surface presents it as a control.

### No — these may not be claimed at all

**"Credentials are protected from the agent."** They are not. Firebreak resolves
the declared identities from the worker's environment and passes the VALUES with
`bwrap --setenv`. Anything the agent starts can read them. There is no
credential broker. What IS true and may be said: an UNDECLARED identity is not
in the sandbox's environment, and a credential value never travels in the
Invocation, in an argv, or into any record — `redacted_argv()` strikes them by
equality, not merely by shape, so a short or arbitrary value the text redactor
could not recognise is still removed.

**"Missions run in parallel."** `max_parallel` is 1 and the shipped worker
consumes its queue single-threaded under an exclusive lock. The lock hierarchy
PERMITS concurrent workspaces and two separate callers reach that today — so
the single-threaded worker is the reason, and a reason is not a control.

**"The sandbox uid is separated from the desktop uid."** It is the same uid.
User-namespace root inside is not a different principal outside.

## Where the evidence is thinnest

Ranked, because this is what rots first:

1. **The approval per-field digest and the chain-sourced revocation** are pinned
   by a probe and a manual check, not by an attack that fails if they regress.
   A regression here restores a PERMISSIVE behaviour, which no failing test
   announces.
2. **The claude provider has never completed a real authenticated turn** — no
   credential exists on the build host. Four of its five stream fixtures are
   synthetic, written to the schema of real captures, and the profile docstring
   says so.
3. **The btrfs checkpoint path is unproven** on this hardware; the tar path is
   what the tests exercise.
4. **The ISO gate and the evidence packager have not been run end to end** in
   this phase.

## The rule that generated this document

If a sentence in a UI, a README, a release note or a support reply cannot be
traced to a row above, it is not a claim this system has earned. The failure
this program keeps finding is not a missing control — it is a true-sounding
sentence written beside one that was never built.
