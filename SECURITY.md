# Security policy

Shadowfetch Linux publishes signed ISO releases, a signed APT repository, SHA-256 checksums, detached GPG signatures, and a public signing key.

## Verify downloads

Verify the ISO before installing it. The checksum proves the file downloaded intact; the GPG signature proves the file matches what Shadowfetch signed.

Current signing key fingerprint:

`8F13 CE15 35EE 1F4A 2916 A1F7 3C5C 900B 7BE8 0CA1`

Current verification guide: https://www.shadowfetchlinux.org/verify

Security model: https://www.shadowfetchlinux.org/security

A normal GPG "not certified with a trusted signature" warning means you have not personally trusted the key; it is not the same as a failed signature. Compare the fingerprint above before trusting the download.

## Agent containment boundary

Shadowfetch runs coding agents inside Firebreak: bubblewrap plus a systemd user
scope. Report a gap against what the system applies, not against what a manifest
declares. Six words are used throughout the source and the documentation and they
do not mean the same thing: DECLARED (a manifest asks for it), APPROVED (a person
granted it), REQUESTED (this run asks for it), EFFECTIVE (the value that reached
the sandbox), ENFORCED (a mechanism outside Shadowfetch's own code applies it and
an attempt to exceed it fails) and OBSERVED (recorded, applied by nothing).

ENFORCED today, every one of the ten declarable fields: the workspace bind
(`--ro-bind` for a read-only mission, so a write returns `EROFS`), read grants,
the network on/off decision (`--unshare-net` for `none`, where `connect()` fails
with `ENETUNREACH`), the **egress allowlist** (nftables in the sandbox's own
network namespace, default DROP, permitting only the addresses the declared names
resolved to plus the NAT itself), **masked paths** (bwrap mounts over each
declared path — an empty tmpfs over a directory, `/dev/null` over a file — with
no cooperation from the payload), credential identities (`--clearenv` and one
`--setenv` per granted name), the dedicated account mount, memory (`MemoryMax`
with `MemorySwapMax=0`) and the process count (`TasksMax`). `cpu_seconds` is
enforced per process by `RLIMIT_CPU`, so a task that forks gets a fresh budget
for each child.

Also applied, and deliberately NOT declarable: a **syscall filter**. Firebreak
assembles a classic-BPF program in its own source, seals it in a memfd and passes
`bwrap --seccomp <fd>`; 46 syscalls answer `EPERM`. A self-test loads the real
program and makes one denied and one permitted call under it before any argv
exists, and refuses the run rather than degrading if either answer is wrong. No
provider can ask for a different profile, because a manifest property here would
be a provider choosing its own syscall surface — the thing a sandbox boundary
exists in order not to depend on.

WHAT IS STILL NOT A CONTROL, stated because an allowlist that is enforced in one
posture and absent in another is worth more confusion than it saves:

* **`--net allow` with no declared destination is not filtered at all.** It
  attaches a NAT and installs no ruleset, so it reaches the LAN. The declarable
  value `allowlist` collapses to `allow` unless destinations are declared; it is
  the declared destinations that produce the ruleset. The session record reports
  `network_destination` as `observable_only` for this case and the network row is
  downgraded to `partial`, so no surface presents it as a control.
* **DNS leaves a sandbox whose filter is working.** The sandbox resolves through
  the NAT's forwarder, which the ruleset must permit or nothing routes at all. An
  allowlist narrows where bytes may be SENT; it is not a claim that nothing can be
  signalled out in a query name.
* **Masking is BY PATH.** A hardlink to the same inode under an unmasked name is
  still readable.
* **A granted credential's VALUE is in the sandbox environment.** It arrives by
  `--setenv`, so anything the agent starts can read it; what is enforced is that
  an undeclared identity is not there at all, and that a value never travels in an
  argv or into any record.
* **The agent runs as the invoking user's own uid.** User-namespace root inside
  the sandbox is not a different principal outside it.

`docs/PROVIDER_TRUST.md` section 7 and the machine-readable table in
`packages/shadowfetch-missions/tests/test_sandbox_spec_audit.py` are the authority
for that split. The table fails the build if a field's status drifts in either
direction, so a control cannot quietly stop being enforced and cannot quietly start
being claimed.

## Reporting security-sensitive findings

Use the security surface for private or security-sensitive findings. Do not attach secrets, private keys, password exports, access tokens, or unredacted diagnostics to public issues.

For hardware and install bugs, GitHub Issues are fine. If you include `shadowfetch-health --json`, remove anything you consider private before posting.

## Public issue boundaries

Please do not post:

- password CSVs or browser export files;
- private keys, tokens, or credentials;
- full disk serial inventories if you do not want them public;
- logs that include private hostnames, usernames, or network names without redaction.

Use GitHub Issues for support questions, hardware reports, and non-sensitive installation notes: https://github.com/ShadowfetchLinux/shadowfetch-linux/issues
