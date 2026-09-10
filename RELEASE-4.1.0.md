# Shadowfetch Linux 4.1.0 — Egress and Syscall Filters

Codename: Umbra (permanent — the APT suite stays `umbra`). Signing fingerprint
unchanged: `8F13 CE15 35EE 1F4A 2916 A1F7 3C5C 900B 7BE8 0CA1`. The subtitle
names the two filters this release adds; it does not claim the sandbox as a
whole is now enforced, because the credential broker and the blast-radius
classifier are built and wired to nothing.

Status: NOT RELEASED. This file is a release contract, not a claim that 4.1.0
has shipped. 4.0.0 (2026-09-06) remains the current public release until an
image built from this source passes `make iso-gate` and the required acceptance
cases carry evidence bound to it. See **Release state** at the end for exactly
what stands in the way. There is no press release for 4.1.0, by decision.

- Version: 4.1.0
- Codename / repository suite: `umbra`
- Architecture: amd64; desktop KDE Plasma 6; installer Calamares
- Source branch: `release/4.0.0` — the checkout path is named for 4.0.0 and is
  not the version
- Source commit the shipped image is built from: `78ee38ceac0ff989d596e5a5e0b97aac17c3b936`
  (tree `163b434ebbd572522c781cc92ff48f90f7fda01c`), on branch `release/4.0.0`.
  The prior candidate was `a9e8cf21`; this commit adds the mission-worker
  idle-spin fix (see "Fixed after the first cut" below), so the ISO was rebuilt.
- ISO: `shadowfetch-4.1.0-amd64.iso`, 3,980,670,976 bytes, SHA-256
  `e19e96302f97e94d5284f8fbef181c9b0e49ca7b746afe5e66e4bc6d5c551f25`, detached
  signature `shadowfetch-4.1.0-amd64.iso.asc` verifying against
  `8F13CE1535EE1F4A2916A1F73C5C900B7BE80CA1`. The signed APT `InRelease` was
  re-signed in this build (Valid-Until 2027-03-09).

## Fixed after the first cut: the mission worker idle CPU spin

A first 4.1.0 candidate (`40cb0969`) was cut and its acceptance cases proven,
then QA's under-load screenshot caught the shipped `shadowfetch-missions`
service worker holding ~100% of one CPU core continuously on an idle queue. The
Phase-3 event-driven worker loop inotify-watches the mission state directory,
and in WAL mode the worker's own queue reads open and close the database's
`-wal`/`-shm` sidecars in that same directory -- create/modify/close-write
events that `Wakeup.wait()` found readable immediately, every iteration, so the
worker woke itself on its own reads and never blocked. The loop was new since
4.0.0, so 4.1.0 would have been the first release to ship it. The fix drains the
inotify descriptor before `select()`, so self-generated events are discarded and
the worker blocks for a genuinely new external change; a regression test pins
both halves (a self-event must not wake it; an external write must). On a fresh
install of the corrected image the idle worker holds ~0.4% CPU and a new mission
is still picked up in under a second. The whole packages -> repo -> ISO chain was
rebuilt (candidate `e19e9630`) and every artifact-bound acceptance case
re-proven against the new digest.

## Why 4.1.0 and not 4.0.1

Since 4.0.0 the sandbox gained controls that were previously declared and
applied by nothing, and several surfaces stopped saying things that were not
true. Both of those change behaviour that working setups depend on. Seven
changes will break something that worked on 4.0.0. They are first in this
document because a person whose cron job stops running deserves to find the
reason in the first screenful, not in a feature list.

---

# READ THIS FIRST: what breaks

## 1. A mission created without `--provider` can now fail

Three providers serve `code_change` and `sourced_report` — `codex`, `claude`
and `localmodel` — and the engine will not choose between them:

```
More than one provider can do this; name one with --provider: <ids>
```

`shadowfetch-missions create` resolves the provider at creation, so this is a
creation-time failure, not a run-time one. Auto-selection survives in exactly
one case: where precisely one provider for that capability is READY (or exactly
one is installed at all). All three ship in `shadowfetch-missions`, so a machine
with two runtimes configured — and equally a machine with none configured — gets
the refusal. `media_export` is unaffected: `offline-media` is still the only
provider for it.

**What you do:** add `--provider codex` (or `claude`, or `localmodel`) to every
`create`. The 4.0.0 spelling `--runtime` is still accepted as an alias.

**Why:** choosing between two equally able providers is an orchestration
decision, and `provider_for()` is the one place that decision would be made. It
contains no provider names, and this phase deliberately did not teach it to
prefer one.

## 2. An approval recorded before this release stops covering a networked mission

`Scope` gained `egress_hosts`, because destinations became an enforced privilege
(see *nftables egress filter* below). An approval is bound to `mission:<id>` and
matched by containment against the mission's scope. A grant written before this
release carries no `egress_hosts` at all, which reads as *no destinations*: it
still covers a mission that wants none, and stops covering one that wants any.

```
this mission may reach destinations the approval does not cover: <hosts>
```

This hits any queued or retried mission on `codex` (`api.openai.com`,
`chatgpt.com`, `auth.openai.com`) or `claude` (`api.anthropic.com`) whose
network is not `none`. A mission created with `--network none` has its egress
allowlist cleared and is unaffected.

**What you do:** approve it again — `shadowfetch-missions approve <id>`.

**Why:** the direction is deliberate. The alternative is honouring an old grant
for destinations nobody was ever shown. Before this, `attack_approval`'s
egress-widened-after-approval scenario reported THE DESTINATION CHANGE WAS NOT
PREVENTED AND WAS NOT DETECTED. It now reports PREVENTED.

One related refusal: an approval scope whose `egress_hosts` is a bare string is
rejected rather than parsed. `tuple("corp*")` is `('c','o','r','p','*')`, and
`'*'` is the wildcard that would make the grant cover every destination.

## 3. `--net allow` no longer reaches anything on the host

Posture `allow` used to create no network namespace at all, so a sandbox that
merely needed the internet also kept the host's loopback services, the host's
abstract `AF_UNIX` namespace and every LAN service the desktop user could reach.
Both postures unshare the network now; `allow` reaches the outside through a
`slirp4netns` NAT attached to that namespace with `--disable-host-loopback`.

Measured through the real Firebreak against real listeners — a TCP server on
`127.0.0.1` and an abstract `AF_UNIX` socket — not against argv:

```
before, net=allow   loopback REACHED   abstract REACHED   internet REACHED
after,  net=allow   loopback blocked   abstract blocked   internet REACHED
after,  net=none    loopback blocked   abstract blocked   internet blocked
```

If an agent in a Firebreak session talked to a service on your `127.0.0.1` — a
local inference server, a database, a proxy — it now cannot.

**What you do:** expose the service over a unix domain socket and grant the
directory that contains it with `--read`. `AF_UNIX` is addressed by filesystem
path rather than by network namespace, so a bind-mounted socket is connectable
from a namespace with no interfaces at all, and a read-only bind is sufficient.
That is the transport the shipped `localmodel` provider uses, and
`tests/test_localmodel_transport.py` proves all three halves on this kernel:
socket bound → `connect()` succeeds and bytes flow; socket not bound → the path
does not exist; TCP to host `127.0.0.1` → connection refused. The grant
directory must contain the socket and nothing else.

Two more consequences of the same change:

* **DNS now works inside a networked sandbox, and did not before.** The bound
  `/etc/resolv.conf` named `127.0.0.53`, which inside the sandbox's own network
  namespace is its own empty loopback, so every cloud provider failed at
  `getaddrinfo` while an IP address was reachable the whole time. A networked
  sandbox now gets a resolver pointing at the NAT's forwarder at `10.0.2.3`.
  The cost travels with it: see *What is still not protected*.
* **A networked run is refused, not degraded.** If no `slirp4netns` exists at a
  trusted absolute path, Firebreak refuses rather than falling back to sharing
  the host's network — a fallback would hand back exactly the containment the
  session asked for.

## 4. A syscall filter denies 46 calls in every sandbox

A classic-BPF filter is assembled in Firebreak's own source, sealed in a memfd,
self-tested against the real kernel before any argv exists, and handed to
`bwrap --seccomp`. If the kernel will not take it, the run is refused rather
than started unfiltered.

What that costs, plainly:

* **No `ptrace`, `process_vm_readv` or `process_vm_writev`** — no debugger and
  no profiler inside a sandbox. Attach from outside.
* **No `perf_event_open`.**
* **No `syslog`** — `dmesg` from inside a sandbox fails.
* **No nested bwrap.** `mount`, `pivot_root`, `chroot`, `open_tree`, `fsopen`
  and the rest of that group are denied, so a payload cannot build its own
  mount namespace. `unshare` and `clone` are deliberately NOT denied, because
  glibc, node and chrome build their own user namespaces and denying those
  would break ordinary workloads; the filter is inherited into whatever
  namespace the payload makes, and the operations that namespace would be for
  are denied.
* **No `io_uring`.** `io_uring_setup` was `REACHED:3` inside a Firebreak sandbox
  before this. A runtime that requires a ring will not run.
* **A 32-bit payload is killed with SIGSYS.** seccomp matches syscall NUMBERS,
  and 165 is `mount` on x86_64 and `getpgrp` on i386. The architecture gate
  refuses the personality rather than filtering the wrong table, and this build
  host does carry an i386 runtime.

The honest size of it, measured rather than asserted: 46 rows are denied, and
Firebreak's own `seccomp_reachable()` returns 24 — the subset this sandbox
actually permitted before the filter existed. 16 of the 46 were outright
successes a payload could perform. The remaining rows were already EPERM on
permission grounds and stayed EPERM through an escalation attempt; they are
defence in depth, not new enforcement, and the source table carries the measured
baseline per row so that cannot be rounded up later.

Only the PAYLOAD is filtered. `systemd-run`, the namespace helper and
`slirp4netns` are Firebreak's own code.

## 5. `shadowfetch-update` is now a shim over `fireproof`

It updates nothing. It translates the old command line onto `fireproof(1)` and
execs it: eleven lines of dispatch where there were 342 lines of a second
updater. There is no `apt`, no `apt-get`, no `dpkg`, no `snapper`, no `sudo` and
no plan hash below that line.

Gone with it:

* **Its own two-entry removal allowlist.** The old program refused any package
  removal except `libprocesscore10` (when the plan installed
  `libprocesscore11`) and `milou` (when the plan installed
  `qml6-module-org-kde-milou`). Removal policy is Fireproof's now.
* **Its own `apt-get update`, its own `apt-get -s full-upgrade` simulation and
  its own sha256 plan fingerprint.**
* **`flatpak update --user -y`. This has NO replacement.** `shadowfetch-update`
  no longer updates user Flatpaks. If you relied on that, run it yourself or put
  it in your own routine.
* **The one-time 2.1.3 AI-package retirement no longer runs inside the
  interactive update.** It was never this program's to own and is not lost: it
  has its own unit, `shadowfetch-migrate-2.1.3-ai.service`, gated on the same
  marker and the same sha256-verified manifest, running at `multi-user.target`.
  The behavioural difference is real — the retirement completes at the next
  boot rather than during the update.

New spellings, all of them aliases: `shadowfetch-update` → `fireproof update`,
`--check` → `fireproof check`, `--verify` → `fireproof verify`, `--rollback` →
`fireproof rollback`. An unknown option or a second argument exits 2.

**Why:** the old program relabelled the SAME snapper Point that Fireproof
labels — different description, no `fireproof=pre` userdata — and then recorded
that Point nowhere. So `shadowfetch-update` mutated the machine while
`/var/lib/shadowfetch/fireproof-state.json` still described the PREVIOUS
Fireproof transaction, and the next `fireproof rollback` would have restored the
wrong system state. Two systems independently deciding snapshot behaviour is
precisely how a rollback and an update come to disagree about what state a
machine is in.

## 6. `/etc/apt/apt.conf.d/52shadowfetch-unattended.conf` is removed on upgrade

The maintscript line is `rm_conffile /etc/apt/apt.conf.d/52shadowfetch-unattended.conf 4.1.0-1~`.
Per `dpkg-maintscript-helper(1)` the prior-version is the version DOING the
removal, so this fires on every upgrade from below 4.1.0-1 — which is the whole
installed base. An unmodified copy is deleted and a locally modified one is kept
for reference as `…conf.dpkg-bak`. If you edited that file, your edits are in
the `.dpkg-bak` and are no longer applied.

An earlier draft of this section quoted `4.0.0-1~`, which is what the file
itself said until this release corrected it: read literally, that is a removal
that skips every machine running 4.0.0-1, i.e. everyone. The value is now on
`VERSION_SITES` in `tools/drift_gate.py` and asserted with its version by
`packages/shadowfetch-fireproof/tests/test_single_update_authority.py`, which
previously matched the line without the number and so could not see it.

**The effective behaviour of the machine does not change, and that is the point.**
That file set `APT::Periodic::Unattended-Upgrade "1"` and
`Remove-Unused-Dependencies "true"`; `85fireproof` sets `Unattended-Upgrade "0"`.
APT reads `apt.conf.d` in filename order, so `85fireproof` won and always had.
The documented behaviour — "auto-apply security updates" — was never the actual
behaviour. Had the other file won, packages would have been installed AND
REMOVED with no analyze, no approval, no verify battery and no recorded Phoenix
Point, leaving the rollback record describing a different transaction than the
one on disk.

There is now one `APT::Periodic` declaration in the product, and
`packages/shadowfetch-fireproof/tests/test_single_update_authority.py` fails if
a second one appears anywhere under `packages/`:

```
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "0";
APT::Periodic::Unattended-Upgrade "0";
APT::Periodic::AutocleanInterval "0";
```

Package lists refresh daily so the Fireproof badge stays honest. Nothing is
downloaded or installed unattended.

## 7. A workspace root owned by another uid is refused at the boundary

If `~/Workspaces` (or `$SHADOWFETCH_AGENT_WORKSPACES`) is not owned by the
invoking user, Firebreak now refuses with:

> The workspace root `<path>` belongs to uid `<n>`, not to you (uid `<m>`).
> Nothing can be created in it, so every mission would fail somewhere later with
> a permission error that does not say this. Give it to your own user, or point
> `SHADOWFETCH_AGENT_WORKSPACES` somewhere you own.

Nothing in the packages creates that directory as root — the shipped tool makes
it as the invoking user, mode 700 — but an image, a restore or a stray `sudo`
can, and on 4.0.0 every mission on that machine then failed somewhere far from
the cause. It does not attempt a repair: changing the ownership of a directory
the caller does not own is a privileged operation, and this codebase makes those
explicit rather than convenient.

**What you do:** `chown` it, or point `SHADOWFETCH_AGENT_WORKSPACES` somewhere
you own.

---

# What is new

The words below are the codebase's own and are not decorative. `enforced` means
a layer outside the payload prevents the behaviour and an adversarial test
proves it. `partial` means prevented with a stated residual. `not_enforced`
means nothing prevents it and it is recorded only. `observed` means recorded as
seen, not verified. A sentence that drops a residual is not a shorter version of
a claim; it is a different and untrue one.

## Enforced

**An nftables egress filter** (`enforced` where hosts are declared). A helper
unshares user+net before bwrap, `slirp4netns` attaches the NAT from outside, the
helper installs a default-DROP ruleset itself and execs bwrap without
`--unshare-net`. Measured: the allowlisted address REACHED, an un-allowlisted
address `blocked:TimeoutError`, `net=none` blocks both, and a payload cannot
tear the ruleset down from inside — uid 0 in a user namespace holds no
`CAP_NET_ADMIN` over a namespace the helper owns, and `nft` and `ip link` both
refused. Residuals, which travel with every statement of it: filtering is BY
ADDRESS, resolved once on the host at launch; IPv4 only; DNS leaves.

**A seccomp-BPF syscall filter** (`enforced`, residual measured per row). See
breaking change 4. This was on the forbidden-claims list for 4.0.0 and belonged
there: there was no profile and nothing that could apply one.

**A network namespace in both postures** (`enforced`). See breaking change 3.

**Masked paths** (`enforced`, BY PATH). `--mask-path` was accepted by Firebreak
and applied by nothing — its own help text said RECORDED ONLY — and Mission
Control never passed it at all. A provider could declare that `.env` and the
private keys in a workspace were masked, the receipt printed the declaration as
fact, and the agent read every one of them. An empty tmpfs now hides a directory
and `/dev/null` over a file makes reads fail, applied after the workspace bind,
requiring no cooperation from the payload. Measured through the real Firebreak against
direct opens, absolute paths, relative traversal, symlinks, nested private keys,
a file inside a masked directory and renaming the target — every one of them
read the secret before and is denied after; a masked directory listed
`['token.txt']` before and `[]` after. The limitation, stated wherever the
mechanism is described: a hardlink to the same inode under an unmasked name is
still readable.

**A read-only workspace is read-only** (`enforced`). `bwrap --ro-bind`. Before
this, a provider declaring `workspace_mode: read-only` got a fully writable
workspace, and the restriction held only because one adapter volunteered
`--sandbox read-only` in its own argv — provider code choosing its own
restraint, which is the thing a sandbox boundary exists in order not to depend
on.

**Domain records bound into the audit chain.** 4.0.0 made missions, events and
approvals tamper-evident and stopped there; the rows a receipt QUOTES as fact —
which provider ran, which executable, what the sandbox enforced, which
credentials were granted, whether the tests passed, who reviewed it — were
directly editable while `audit verify` reported the chain intact. Before: every
one of 16 direct edits to a domain table undetected. After: 0 of 16, including
inventing a whole artifact row.

**The approval check/use window is closed.** `require_approval()` re-read
`revoked_at` under `BEGIN IMMEDIATE` and then RELEASED it, and the
`approval-used` record and the mission's `approval_id` followed on two further
connections; a revoke landing in that gap was chained BEFORE the use — the exact
"granted, revoked, used" log the code's own comment claimed to prevent. All
three steps are one transaction now: **20 of 300 inversions before, 0 of 300
after**. Approvals are also witnessed field by field, so an edit to
`expires_at`, `granted_by` or `method` is detected, and now cover destinations.

**Two more providers, four in total.** `claude` (cloud, `api.anthropic.com`,
`ANTHROPIC_API_KEY`) and `localmodel` (on-device, `network_policy: none`, no
credentials, reached over one unix socket) join `codex` and `offline-media`.
Each is a manifest, an adapter, a sealed policy entry and a conformance case;
none is a branch in the engine. `seal_policy` could not seal a NEW provider at
all before this — it never emitted `executable_trust`, which `approve()` refuses
an entry without — so a brand-new provider was sealed into a policy that would
refuse it at runtime. `local_ai` is now read from the registry instead of the
literal string `"deferred"`, which stopped being true the moment an on-device
provider shipped.

**A hardened launch chain.** An adversarial review neutralised the whole egress
filter with one variable: a `PYTHONPATH` pointing at a `sitecustomize.py` ran
attacker code inside the namespace helper BEFORE `nft` installed the ruleset,
blanked the ruleset, and the sandbox then reached `8.8.8.8` and the LAN with an
allowlist naming neither — while the session record said `enforced`. The launch
chain now gets a built environment and the helper interpreter runs `-I -S`.

Firebreak's own interpreter took three tries, and the two failures are worth
recording because they are the same mistake twice. The first fix re-executed
Firebreak isolated *when it saw one of ten hostile variable names*, using an
environment marker to avoid looping. Three ways past it, each measured:

* **The marker was an off switch.** Anyone who can set `PYTHONPATH` can set
  `SHADOWFETCH_FIREBREAK_ISOLATED=1`, and then the guard skipped itself. With
  both set, an injected `sitecustomize.py` was still resident — in the process
  that decides containment — at exit.
* **`usercustomize.py` needs no variable at all.** `~/.local/lib/python3.12/
  site-packages` is writable by anything running unprivileged in the session,
  Python imports it at interpreter start, and Mission Control forwards `HOME`.
  A guard triggered by a list of variable NAMES is blind to it by construction.
* **The injected module runs first, so it can rebind `os.execve`.** The call
  then returned instead of replacing the process and execution fell through
  into the program body, in the poisoned interpreter.

All three have one root cause: any check inside the file runs after the code
that was injected into its interpreter. So the guard is no longer the primary
defence. The shebang is `#!/usr/bin/python3 -IS`, which makes the interpreter
isolated from its first instruction — `site` never imports `sitecustomize` or
`usercustomize`, so nothing runs before the module body at all. The in-body
re-exec is kept for `python3 /usr/bin/shadowfetch-firebreak`, which bypasses the
shebang; there its loop guard is `sys.flags`, which cannot be set from the
environment, and an `execve` that RETURNS now exits 70 rather than carrying on.

Measured after, with a `sitecustomize.py` that logs at import and at exit:
nothing loads at all on the shebang path — not with `PYTHONPATH`, not with the
old marker set, not from the user-site directory. On the shebang-bypassing path
exactly one interpreter loads it, the pre-exec launcher, and that launcher
execs away or refuses. Five tests measure this rather than reading the source;
the test they replace searched the file for the string `_ISOLATION_MARKER` and
asserted a measurement it never took, which is why it stayed green through all
three holes. What is not defended is somebody who can replace the file; nothing
can defend that, and the code says so.

**A current-release pointer with a writer.** It had a reader and no writer.
Ordering is the control: the signed APT `InRelease` is the last of the objects,
the ISO's bytes are then streamed back and re-hashed, and only after that is
`releases/CURRENT.json` written.

**`weekly_release.sh` is deleted** — cron-driven, passwordless sudo, credentials
from an erased crew, a Discord token, and a publish step.

## Built, tested, and wired to nothing

These two are real code with real tests and **no caller**. Listing them as
features without that sentence would be the precise failure this release exists
to remove.

**The credential broker.** `sf_broker.py` holds credential values outside the
sandbox and answers over one `AF_UNIX` socket per session — single-issue,
refusable, on a hash-chained record — with 93 tests, and Firebreak has a
`--credential-broker` flag that suppresses the `--setenv`. **No shipped manifest
uses it.** `sf_providers.credential_delivery()` returns `environment` for all
four providers. Credentials still reach the sandbox as environment variables.

Its own limit, which must not be softened when it is wired: an attacker sharing
the sandbox holds the same ticket as the legitimate consumer and can simply ask
first — bwrap maps both to the mission uid, so the broker cannot tell them
apart. What brokering excludes is *removing* the other runner: an eviction
attack that worked before it was fixed, where 24 stalled connections saturated
the handler slots, the consumer got `overloaded` and the thief redeemed. Whoever
redeems holds the value, so every shell they start inherits it. The exposure
would move from *every process, whole run, unrecorded* to *the redeemer's
process tree, from redemption on, recorded*. That is a real narrowing and it is
not unreachability. Only a proxying broker — one that makes the API call so the
secret never enters the sandbox — changes that. And switching is not free: an
environment value cannot fail to be delivered and a brokered one can, so a
broker that is not running is a mission that cannot authenticate.

**The blast-radius classifier.** `sf_blast.py` classifies a mission across
reachable / destructible / exfiltratable / durable, with 82 tests. It is not
called by `open_review_for()`, the CLI or the desktop, so **nothing shows a
person what a mission could do before they approve it.** One property it already
has, because it was broken and fixed: a mission appending two lines to its own
`.git/config` made it report "no remote configured" while `git remote -v` showed
the push remote. A reassuring finding can no longer be constructed without the
evidence it rests on — a failed reading produces UNKNOWN and appears in
`unseen`, never a reassuring sentence — and an AST test walks the module's own
source to prove no site bypasses that door.

## Corrected, not added

Some of this release is sentences that were false being deleted.

* Three code strings claimed a sandbox "cannot reach the host's loopback,
  abstract sockets **or LAN**". The LAN half was false with the network on and
  no destinations declared, and is corrected.
* The receipt a person reads before ACCEPTING agent work named two enforced
  controls as decorative, and named two fields absent from the list it claimed
  to explain. It is derived from that list now.
* The shared-desktop duplication barrier was a set of string greps that a rename
  defeated. It is AST-shaped now and says **DETECTED**, not ENFORCED, because it
  is a CI-time scanner over source shape and prevents nothing at runtime.
* The acceptance gate never opened the artifact it accepts, and a REQUIRED case
  was passing on twelve bytes. Evidence entries now carry `artifact_sha256`,
  stamped from the manifest so a person can neither forget it nor choose it. All
  five previously recorded passes fail this check, and should.
* `make iso-gate` teed its verdict into its own evidence file — the proof that
  the ISO gate passed was the gate saying so.
* The worker unit named one provider's credential file, so a second provider's
  key reached nothing while its readiness reported it present.

---

# What is still not protected

Summarised from `FINAL_REMAINING_RISKS.md`, which carries the measurements.

**Credentials are readable by anything the agent starts.** Firebreak resolves
each declared identity from the worker's environment and passes the VALUE with
`bwrap --setenv`. `env` is one command, unlimited, and unrecorded. What IS true:
an undeclared identity is not in the sandbox's environment at all, and a
credential value never travels in an Invocation, in an argv or into any record —
`redacted_argv()` strikes them by equality, not by shape.

**DNS queries leave a sandbox whose egress filter is working perfectly.** The
sandbox resolves through the NAT's forwarder, which the ruleset must permit or
nothing routes at all. An adversarial review encoded a label and watched it be
answered. A payload can carry data out in a query name. An allowlist narrows
where bytes may be SENT; it is not a claim that nothing can be signalled out.

**The network on with no declared destination is not filtered at all.**
`--net allow` with no `--egress-host` attaches a NAT and installs no ruleset: an
adversarial review reached the host's own LAN address, the docker bridge and the
LAN router from inside. `--disable-host-loopback` blocks `127.0.0.1` and nothing
else. The decision reports `network_destination` as `observable_only` and lists
it in `advisory_fields`, and the network row is downgraded to `partial` for
exactly this case — so no surface presents it as a control. It is the posture to
watch, not the safe middle ground it reads as.

Also true, and shorter:

* **An approval is not re-checked once a mission is running.** Revoking it does
  not stop the mission; `cancel()` does, and works. What "stop" means for a
  half-written workspace is a design question this phase did not answer.
* **Concurrency is proven for two callers and nothing more.** `max_parallel` is
  1 and describes ONE WORKER PROCESS, not the installation — 5.2 seconds of
  overlapping sandbox time between a worker and a CLI run were measured.
* **Path masking is by path**, so a hardlink to the same inode under an unmasked
  name is still readable. **The CPU limit is `partial`** — `RLIMIT_CPU` is
  per-process, so a provider that forks gets a fresh budget per child.
* **The sandbox uid is the desktop uid.** User-namespace root inside is not a
  different principal outside.
* **Landlock is not used.** ABI 9 is present on this kernel, and the shipped
  `bubblewrap 0.11.0` has no Landlock support at all; a ruleset installed before
  bwrap is inherited across `execve` and would forbid bwrap its own bind mounts.
* **`claude` has never completed a real authenticated turn** — no credential
  exists on the build host, and four of its five stream fixtures are synthetic,
  written to the schema of real captures. Its profile docstring says so.
* **The btrfs checkpoint path is unproven** on this hardware; the tar path is
  what the tests exercise.
* **Five work items are simply not done** and had no deferral recorded until
  now: a TOCTOU in `scoped()` / `tree_index()` / `recovery_index()` (W-47, the
  most consequential), the element still owned by `theme.py` (W-51),
  `shadowfetch-gpud` shipping nothing while GPU "rollback" prints a sentence and
  restores nothing (W-64), a scalar deploy guard whose shim is shadowed on
  `PATH` (W-65), and directory `fsync` missing from the mission engine's atomic
  write, the audit mirror and the Phoenix journal (W-70).

---

# Upgrading

The supported in-place path is the signed Shadowfetch APT repository:

```bash
sudo apt update
fireproof update          # shadowfetch-update still works and means this
```

Afterwards, in this order:

1. Add `--provider` to anything that calls `shadowfetch-missions create`.
2. Re-approve any mission that was approved but had not yet run.
3. Check that your workspace root is owned by you.
4. Move `flatpak update --user` into your own routine if you relied on it.
5. If an agent needed a host `127.0.0.1` service, move that service to a unix
   socket and grant its directory.

---

# Release state

Recorded in `FINAL_RELEASE_REPORT.md`; repeated here because a release note that
omitted it would be the kind of sentence this program keeps deleting.

Measured on 2026-09-09 against this tree, not copied forward:

| gate | verdict |
| --- | --- |
| `make test` | **PASS** (exit 0) — 2,357 tests plus the six adversarial suites |
| adversarial suites | **PASS** — approval 20/20, concurrency 18/18, domain 0-of-16-undetected, integrity 15/15, lifecycle 7/7, verifier 21/21 |
| `drift_gate` | **PASS with BLOCKED** (exit 0) — 0 DRIFT, 5 BLOCKED across 10 checks; the BLOCKED items are named duplications with remedies |
| `source_gate` | **PASS** (exit 0) |
| `package_gate` | **needs `make packages` first** — the `.deb`s under `build/` are still `4.0.0-1`, so it compares this release against the last one's artifacts and refuses |
| `iso_gate` | **WILL FAIL** |
| `acceptance --version 4.1.0` (strict) | **FAILS, 21 errors** — 18 required cases `pending`, and the three artifact digests unrecorded |

`source_gate` had been failing and nobody could see it. It runs `make test`
first, that was red, and the gate stopped there — so the SECOND failure behind
it, `gitleaks dir` reporting `leaks found: 1`, only surfaced once the tests went
green. The finding was an R2 object path in a release-pointer test fixture,
matched by the default `generic-api-key` rule because the field is spelled
`key`; it is now allowlisted by exact path and exact value shape, and a real key
planted in that same file is still caught.

The acceptance failure is the honest state of a release whose artifact does not
exist. `qa/4.1.0/acceptance.json` carries every case at `pending` and null
digests, and the verifier refuses it — which is the verifier working. Nothing in
this change makes it pass.

The ISO gate failing is the gate working. `critical_payload_parity_gate`
compares the squashfs payload byte for byte against freshly built packages, and
all four `shadowfetch-fireline` critical payloads in the image on disk differ
from source — the network namespace work, the egress filter, the masked paths
and the sandbox resolver all landed after that image was cut. There is no way to
make it pass except by building a new image.

Done in this change, and listed because earlier drafts of this section said
otherwise:

* **The version identity is finished.** Every Shadowfetch-owned
  `debian/changelog` reads `4.1.0-1`, `versions/4.0.0.toml` says
  `historical = true`, and `versions/4.1.0.toml` is the sole live file — the
  ambiguity `gate.load_release(None)` and `drift_gate`'s `load_truth()` refuse
  rather than guess.
* **`INSTALL-01` is no longer blocked.** It failed five times at ~294 s with
  "expected exactly one 'calamares' application, found 0"; the cause was that a
  root process cannot connect to the session user's D-Bus bus at all — it is
  dropped at EXTERNAL auth — so Calamares registered nowhere, and separately
  `--firmware uefi` had never actually booted because `vm.py` split `-name`
  from its value. `INSTALL-01` and `RECOVERY-01` are now recorded `pass` in
  `qa/4.0.0/acceptance.json` from real BIOS+UEFI and project-recovery runs,
  with 11 and 12 evidence files, every one bound to the shipped ISO
  `137c1f29e206…` and re-hashed clean (29 of 29 files, 0 mismatches).

Still outstanding before 4.1.0 can be cut:

* Build a candidate from a quiesced tree, record its commit and tree, run
  `make packages` then `make iso-gate`; re-record the six recorded acceptance
  passes against the new artifact. They are bound to the 4.0.0 ISO, which is
  the right binding and the wrong artifact for this release.
* `RESOURCE-01` and `STRESS-01` sit at `pending` with recorded FAILURES in the
  4.0.0 notes — a 2704-second concurrent load run that failed with repeated
  Redis admission / HTTP 503 and health-exec faults, and a 16 GiB rerun that
  failed with seven bridge 503s, one relay readiness 503 and a 120-second
  container timeout. To the gate, `pending` reads exactly like never having
  been run. They need remediation and a clean 45-minute run, or a waiver with a
  named approver. (`qa/4.1.0/acceptance.json` carries no notes at all: results
  were dropped rather than copied, so that history lives in the 4.0.0 manifest.)
* One harness blocker remains: the 3.5.0 base image the upgrade clones layer on
  no longer exists on this host. `UPGRADE-01` has also been retitled for this
  release — it asked for an upgrade from 3.5, and the supported in-place path
  to 4.1.0 is from 4.0.
* Release evidence does not exist yet — none of the five generated documents,
  and `approved-inputs.json` has never been authored.
* **"Reproducibly" is a recorded claim, not a check.** The manifest records a
  source commit and tree and both resolve, but nothing reads them, there is no
  rebuild-and-compare step, and `live-build` is not bit-reproducible. What
  exists is provenance written down, which is worth having and is not the same
  claim.

Every sandbox verdict in this release was measured against the branch's
Firebreak 4 running from the source tree. The Firebreak INSTALLED on the build
host is `shadowfetch-fireline 3.0.0`, whose argv is `bwrap --ro-bind / /`. The
verdicts hold where Firebreak 4 is what runs, which is another way of saying the
parity gate is right to refuse.
