# Stage C — brokered egress: the dead end, and the way past it

Stage C asks for destination-controlled egress: a provider requesting
`api.openai.com` must not thereby gain `github.com`, `127.0.0.1`, `192.168.x.x`
or the open internet.

**RESOLVED. `egress_allowlist` is ENFORCED.** This document is kept as written
because the dead end it records is the reason the working design looks the way
it does, and a reader who deletes it will walk back into the same wall. The
resolution is at the end.

The measurements below were taken while the answer was still "no". They are
still true: the failure they describe is a real property of trying to reach
INTO a namespace bwrap owns.

## What was proven to work

`nft` rules CAN be installed inside the sandbox's own network namespace with no
privilege on the host. In a user namespace you hold `CAP_NET_ADMIN` over the
network namespace you created, so:

```
nsenter --target <bwrap-child-pid> --user --net --preserve-credentials nft -f -
```

returns 0 and installs the ruleset. Two details cost real time and are worth
recording:

* `--user` must come **before** `--net`. nsenter applies in argument order, and
  a netns owned by another user namespace can only be joined from inside the
  userns that owns it. With `--net` first: *"reassociate to namespace 'ns/net'
  failed: Operation not permitted"*.
* an nft ruleset written on one line needs `;` before each closing `}`. Without
  it the install fails with a syntax error while the surrounding code happily
  reports success — which is how a "filter installed" line appeared over a
  ruleset that had never been accepted.

## What blocks it

**Joining the sandbox's namespace at all prevents the NAT from attaching
afterwards, and attaching the NAT first makes the namespace unjoinable.** Both
directions were measured against the same harness, one case per process:

| what was done before the NAT | nft install | allowed host | denied host |
|---|---|---|---|
| nothing | — | REACHED | REACHED |
| `nsenter … /usr/bin/true` (enter, run nothing) | — | blocked | blocked |
| `nsenter … nft -f` (install rules) | ok | blocked | blocked |

The `true` row is the decisive one: **no rules at all**, merely entering the
namespace, and connectivity never comes up. So the failure is not the ruleset.

In the other order — slirp4netns first, then nsenter — the join is refused:
`reassociate to namespace 'ns/net' failed: Operation not permitted`, reproducibly,
and the *same* nsenter invocation succeeds against the *same* pid moments earlier
before slirp has attached.

`pasta` does not rescue it: `Couldn't switch to pasta namespaces: Operation not
permitted`, in every ordering including with no prior join.

So on this platform, with bwrap 0.11 creating the user namespace, the
"attach connectivity from outside, filter from outside" architecture cannot have
both halves.

## The path that remains

Configure **from inside** the sandbox, before the payload: a wrapper that holds
`CAP_NET_ADMIN` (bwrap `--cap-add`), installs the allowlist, drops the
capability, and only then execs the agent command. The drop has to be reliable
and adversarially tested — a payload that can flush the ruleset makes the whole
control theatre, and that is the failure mode this program exists to avoid.

Also worth testing next time: whether bwrap can be made to join a
pre-existing, pre-configured namespace (create the netns and NAT first, then run
bwrap inside it) rather than creating its own.

## What Stage B already achieved, and what it does not

Not nothing, and this is the part that matters to a user: **every session now has
its own network namespace**, so the host's loopback services, abstract AF_UNIX
sockets and LAN are out of reach in both postures. Measured against real
listeners. A sandbox with `net=allow` can reach *the internet*, and cannot reach
*your machine*.

What it cannot yet do is distinguish one internet destination from another. Until
Stage C lands:

* `egress_allowlist` is **recorded, not enforced**, and every surface says so
* a provider requesting `api.openai.com` can reach any public address
* the honest user-facing claim is "agents cannot reach your local services",
  **not** "agents can only reach the hosts they declared"


---

# THE RESOLUTION — invert the ownership

Everything above tries to reach into a namespace bwrap created. That is the
wrong direction, and no ordering of it works: joining the namespace stops
slirp4netns attaching afterwards, and attaching first makes it unjoinable.
Both directions were measured, above.

The way past it is not a better nsenter. It is to make the namespace OURS from
the first instant:

1. A helper runs `unshare --user --map-root-user --net --fork`, so the network
   namespace exists before bwrap does and the helper holds `CAP_NET_ADMIN` over
   it — no reaching in from outside is required at all.
2. The helper writes its own pid to a file and then BLOCKS on a FIFO. A payload
   that ran before this point would run on an unconfigured interface, so the
   block is the ordering guarantee, not a convenience.
3. The launcher polls for that pid, attaches `slirp4netns --configure
   --disable-host-loopback` to it, waits for slirp's ready fd, and then writes
   to the FIFO.
4. The helper wakes, brings `lo` up, installs the nftables ruleset ITSELF, and
   `os.execv`s bwrap — WITHOUT `--unshare-net`, so the sandbox inherits a
   namespace that is already NAT'd and already filtered.

The whole tree runs under one `systemd-run --scope`, so the cgroup limits still
cover the helper, the sandbox and everything they start.

## Measured after the change

```
WITH allowlist   RESULT {"allowed": "REACHED", "denied": "blocked:TimeoutError"}
no allowlist     RESULT {"allowed": "REACHED", "denied": "REACHED"}
net=none         RESULT {"allowed": "blocked:OSError", "denied": "blocked:OSError"}
```

Stage B containment re-verified intact: the host's loopback services and the
host's abstract AF_UNIX namespace remain unreachable in both postures.

## What the change forced, which was more than the filter

* **DNS was broken in every networked sandbox** and nobody had noticed, because
  nothing had ever needed a name inside one. `/etc/resolv.conf` was bound from
  the host, where it names systemd-resolved's stub at 127.0.0.53 — which inside
  the sandbox's own namespace is the sandbox's own empty loopback. Every cloud
  provider addresses its API by name, so every turn would have failed at
  `getaddrinfo` while an IP address was reachable the whole time. The networked
  posture now binds a resolver naming the NAT's forwarder.
* **The recorded argv was no longer the argv that ran.** The record was built
  from the bwrap command line, and the helper that owns the namespace and
  installs the filter was spliced in afterwards — so `enforcement()`, which
  reads the argv rather than the request, reported a namespace nobody created,
  on a session that was fully contained. The argv is assembled before the
  record now, and spawned unchanged.
* **A refusal stopped being auditable.** Building that argv can refuse — an
  egress host that resolves to no address is refused rather than run unfiltered
  — and because the started record was written after it, the refusal left no
  trace at all. There is a `refused` record now.
* **Destinations became a PRIVILEGE, so the approval had to carry them.**
  `attack_approval.py`'s `egress-widened-after-approval` used to pass on the
  CLAIM: the engine said destinations were `observable_only` and named them
  advisory, so nobody was told the hosts were enforced. Once they were enforced,
  that branch stopped being available — an enforced privilege outside the
  approved scope is one that can be widened after the human agreed. `Scope` now
  carries `egress_hosts`, and the attack reports PREVENTED.

## The residuals, which travel with the claim

* **BY ADDRESS.** Names resolve once, on the host, at launch. A CDN that moves
  is unreachable until the next run. The sandbox never gets to choose what a
  name means, which is the point.
* **IPv4 only.** The ruleset matches `ip daddr`; IPv6 falls to the default drop.
* **DNS leaves.** Queries go through the NAT's forwarder, which the ruleset must
  permit or nothing routes. A payload can encode data in a query name. This
  narrows where bytes may be SENT and is not a claim that nothing can be
  signalled out.
* **The network on with NO hosts declared is not filtered at all.** A NAT is
  attached and no ruleset is installed. The decision reports `observable_only`
  and lists it in `advisory_fields`, so no surface calls it a control.
