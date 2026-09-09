# Stage C — brokered egress: BLOCKED, with the mechanism measured

Stage C asks for destination-controlled egress: a provider requesting
`api.openai.com` must not thereby gain `github.com`, `127.0.0.1`, `192.168.x.x`
or the open internet. This records exactly how far it got and why it stopped,
so the next attempt starts from evidence rather than from the same dead end.

**Stage C is NOT implemented. `egress_allowlist` remains NOT ENFORCED and is
described that way everywhere it appears.**

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
