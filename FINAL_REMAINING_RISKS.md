# FINAL_REMAINING_RISKS

Everything below is a fact about the shipped code, measured. Nothing here is a
worry; the worries are cheap and this document does not carry them. It is
ordered by what would hurt someone, not by how hard it was to find.

A note on how to read it. This program repeatedly found that the dangerous
sentence is not the missing control — it is the true-sounding sentence written
beside one that was never built. So each risk below says what IS true, what is
NOT, and where a surface currently says which.

---

## 1. A credential is readable by anything the agent starts

**Status: not fixed. A broker exists and nothing wires it.**

Firebreak resolves each declared identity from the worker's environment and
passes the VALUE with `bwrap --setenv`. Anything the agent starts reads it out
of its own environment. `env` is one command, unlimited, and unrecorded.

`sf_broker.py` ships — a credential broker holding values outside the sandbox
and answering over one AF_UNIX socket per session, single-issue, refusable, on
a hash-chained record — with 93 tests and a Firebreak `--credential-broker`
flag that suppresses the `--setenv`. **No shipped manifest uses it**;
`sf_providers.credential_delivery()` returns `environment` for all four.

And the honest limit of the broker itself, which must not be softened: **an
attacker sharing the sandbox holds the same ticket as the legitimate consumer
and can simply ask first.** bwrap maps both to the mission uid, so the broker
cannot tell them apart. What brokering excludes is *removing* the other runner
— an eviction attack that worked before it was fixed, where 24 stalled
connections saturated the handler slots, the consumer got `overloaded` and the
thief redeemed. Whoever redeems holds the value, so every shell they start
inherits it: the exposure moves from *every process, whole run, unrecorded* to
*the redeemer's process tree, from redemption on, recorded*. That is a real
narrowing and it is not unreachability. Only a proxying broker — one that makes
the API call so the secret never enters the sandbox — changes that row.

**Cost of switching, stated because it is not free:** an environment value
cannot fail to be delivered; a brokered one can. A broker that is not running,
or an endpoint never bound, is a mission that cannot authenticate. It fails
loudly and a refusal never spends the grant, so it is denial and never theft —
but `--setenv` has no such failure mode.

## 2. Data can leave a sandbox whose egress filter is working perfectly

**Status: inherent to an address filter. Stated everywhere it is claimed.**

The filter is real: nftables, default DROP, in the sandbox's own network
namespace, installed before the payload runs. Measured — allowlisted address
REACHED, un-allowlisted `blocked:TimeoutError`, `net=none` blocks both, and a
payload cannot tear it down from inside (uid 0 in a user namespace holds no
`CAP_NET_ADMIN` over a namespace the helper owns; `nft`, `ip link` all refused).

Three ways out remain, and each travels with the claim:

* **DNS queries leave.** The sandbox resolves through the NAT's forwarder,
  which the ruleset must permit or nothing routes at all. An adversarial review
  encoded a label and watched it be answered. A payload can carry data out in a
  query name.
* **Filtering is BY ADDRESS**, resolved once, on the host, at launch. A CDN
  that moves is unreachable until the next run — that is the safe direction,
  but it means the allowlist is not a name-based control.
* **IPv4 only.** The ruleset matches `ip daddr`. An IPv6 destination is
  unreachable one step earlier — the NAT provides no IPv6 route — so the same
  outcome by a different mechanism, which stops being true the day the NAT
  gains IPv6.

## 3. The network is on and nothing filters it, unless a destination is declared

**Status: correct behaviour, easily misread.**

`--net allow` with NO `--egress-host` attaches a NAT and installs no ruleset:
the sandbox reaches the LAN and the whole internet. An adversarial review
reached the host's own LAN address, the docker bridge and the LAN router from
inside.

The decision reports `network_destination` as `observable_only` and lists it in
`advisory_fields`, and `sandbox_enforcement()` downgrades the network row to
`partial` for exactly this case. Three code strings claimed the sandbox "cannot
reach the host's loopback, abstract sockets **or LAN**" — the LAN half was
false in this posture and is corrected. Loopback and abstract sockets are
genuinely unreachable in both postures.

## 4. Syscalls are filtered; twenty-one of the forty-six rows change nothing

**Status: enforced, with the residual measured per row.**

A classic-BPF filter is applied to every sandbox — assembled in Firebreak's own
source, sealed in a memfd, self-tested against the real kernel before any argv
exists, and refused rather than degraded if the kernel will not take it. 46
syscalls answer EPERM. **25 of those rows changed an observed outcome and 16
were outright successes** a payload could perform.

The other 21 were already EPERM and stayed EPERM through an escalation attempt:
they are defence in depth, not new enforcement, and the source table carries the
measured baseline per row so a later reader cannot round that up.

What it costs: no `ptrace` means no debugger or profiler inside a sandbox; no
`perf_event_open`; no `dmesg`; no nested bwrap. **A 32-bit payload is killed
with SIGSYS**, because seccomp matches syscall NUMBERS and 165 is `mount` on
x86_64 and `getpgrp` on i386 — the architecture gate refuses the personality
rather than filtering the wrong table, and this host does carry an i386 runtime.
Nested user namespaces remain creatable on purpose, because glibc, node and
chrome build their own; `bwrap --disable-userns` works here and is deliberately
not shipped. Only the PAYLOAD is filtered — systemd-run, the namespace helper
and slirp4netns are Firebreak's own code.

**Landlock is not used**, and the reason is a measurement: ABI 9 is present,
and the shipped `bubblewrap 0.11.0` has no Landlock support at all. A ruleset
installed before bwrap is inherited across `execve` and would forbid bwrap its
own bind mounts.

## 5. Firebreak trusts the environment it is invoked with, up to a point

**Status: narrowed, with the remaining edge stated.**

An adversarial review neutralised the egress filter with one variable: a
`PYTHONPATH` pointing at a `sitecustomize.py` ran attacker code inside the
namespace helper *before* `nft` installed the ruleset, blanked the ruleset, and
the sandbox then reached un-allowlisted addresses **while the session record
said `enforced`**. An `LD_PRELOAD` constructor fired in `systemd-run`, in
`unshare` and in `bwrap` itself.

The launch chain now gets a built environment, the helper interpreter runs
`-I -S`, the shebang no longer asks `$PATH` which Python to be, and Firebreak
re-execs itself isolated when the environment is hostile. Measured after:
exactly ONE interpreter runs the attacker's code — the pre-exec launcher, which
does nothing but exec — and the filter holds.

**What is not defended:** somebody who can replace the file. Nothing can defend
that, and the code says so rather than implying otherwise.

## 6. An approval is not re-checked once a mission is running

**Status: known, no design to fix it.**

The check/use window is closed — the re-read, the `approval-used` record and the
mission's `approval_id` are one transaction now, measured at 20/300 inversions
before and 0/300 after. But once a mission is *running*, revoking its approval
does not stop it. `cancel()` is the answer today and it works. Adding a re-check
means deciding what "stop" means for a half-written workspace, which is a design
question this phase did not answer.

## 7. Concurrency is safe for two callers; nothing tested more

Every overlap measurement in `docs/MULTI_AGENT_SAFETY.md` is a pair. Two workers,
one consumer (a real `flock`); one mission cannot start twice (SQLite
`BEGIN IMMEDIATE`, which holds even when two callers share no lock file); 200
racing appends never fork the chain. Also true and worth knowing: `max_parallel`
is 1 and describes ONE WORKER PROCESS, not the installation — the impression
that one mission runs at a time is false the moment anyone types
`shadowfetch-missions run`, and 5.2 seconds of overlapping sandbox time between
a worker and a CLI run were measured. The cross-state-root gap is measured and
not closed.

## 8. The blast-radius classifier is built and wired to nothing

`sf_blast.py` classifies a mission across reachable / destructible /
exfiltratable / durable. It is not called by `open_review_for()`, the CLI or the
desktop, so nothing shows a person what a mission could do before they approve
it. When it is wired, note what it cannot see: the workspace is bound
read-WRITE and the mission can rewrite `.git/config` while it runs, so anything
derived from that file is a statement about the file at read time. That is why a
failed reading now produces UNKNOWN and appears in `unseen`, never a reassuring
sentence — the classifier was made to say "no remote configured" by a mission
appending two lines to its own config.

## 9. The duplication barrier is a scanner, not a layer

`tools/drift_gate.py check_desktop_helpers` is a CI-time scanner over source
SHAPE. It reports a front-end that assembles a reserved path in any spelling it
can fold, builds any privileged argv, reads a catalog directory under any name,
or stops loading the shared library. **It prevents nothing at runtime**, and a
spelling it cannot fold is a spelling it cannot see — an argv head reached
through a subscript, a catalog reader over a hard-coded filename list, a helper
under a name prefix nobody listed, and a path built with `chr()` all get past it
today, each planted and recorded as a test so the list cannot silently age.

The ENFORCED part of that seam is smaller and lives in the library:
`sf_desktop.py` resolves every program it runs from `PROGRAMS` by absolute path.

## 10. Two required acceptance cases carry recorded FAILURES

`RESOURCE-01` and `STRESS-01` sit at `pending` with failures written in their
notes: a 2704-second concurrent load run that failed with repeated Redis
admission / HTTP 503 and health-exec faults, and a 16 GiB rerun that also failed
with seven bridge 503s, one relay readiness 503 and a 120-second container
timeout. **To the gate, `pending` reads exactly like never having been run.**
They need remediation and a clean 45-minute run, or a waiver with a named
approver. Silence is the one option that should be off the table.

## 11. The accepted artifact is not the software

The ISO on disk predates Stages A, B, C and E: all four `shadowfetch-fireline`
critical payloads differ from source. The ISO gate detects this and fails, which
is the gate working. A new candidate invalidates every recorded acceptance case.
See `FINAL_RELEASE_REPORT.md` for the order this has to be dealt with in.

## 12. Work items that are NOT done and had no deferral recorded

Found by reconciliation. Each is genuinely absent, and until now nothing in the
tree said so:

* **W-47 — TOCTOU.** `scoped()`, `tree_index()` and `recovery_index()` still
  walk components with check-then-use; no dir-fd, no `O_NOFOLLOW`, no `fstat`.
  No test pins it.
* **W-51 — the element.** Still owned by `theme.py`, still read once at import,
  still `$SHADOWFETCH_ELEMENT` first. ADR-0012's `/etc/shadowfetch/fireline.policy`
  does not exist.
* **W-64 — `shadowfetch-gpud`.** Nothing shipped; zero references anywhere. GPU
  "rollback" prints a sentence and restores nothing; a failed MOK enrolment
  warns and then exits 0 saying "verified".
* **W-65 — the deploy guard.** Still scalar, still names one worker, and neither
  Linux property routes through it. Its shim is shadowed on `PATH` by another
  `wrangler`, so the one accidental coverage path is broken too.
* **W-70 — durability.** Directory `fsync` exists in two places and is missing
  from the mission engine's own atomic write, the audit mirror, the Phoenix
  journal and six more. No `events(mission,seq)` index. The SIGTERM handler
  still does SQLite reads and writes from signal context.

## 13. Deployment discrepancies on the machine every measurement was taken on

`shadowfetch-fireline 3.0.0` is what is INSTALLED — the 3.x bash Firebreak whose
argv is `bwrap --ro-bind / /`. `/usr/share/shadowfetch/providers` and
`/usr/share/shadowfetch/provider-policy` do not exist there. Every sandbox
verdict in this program was measured against the branch's Firebreak 4 running
from the source tree, and holds only where Firebreak 4 is what runs. This is
why the ISO parity gate failing is the right outcome and not a nuisance.

---

## What would change these

In the order that would reduce the most risk:

1. **Wire the broker** and switch the two cloud providers to it (§1). The
   residual stays, but the exposure narrows and becomes recorded.
2. **Cut a candidate that matches the source** (§11). Everything about release
   readiness is downstream of this.
3. **Wire the blast-radius classifier** into the approval surface (§8). It is
   built and tested; nobody sees it.
4. **Deal with RESOURCE-01 and STRESS-01** honestly (§10).
5. **W-47** (§12) — a TOCTOU in the path that decides which files a mission may
   touch is the most consequential of the undone items.
