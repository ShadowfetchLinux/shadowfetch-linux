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

ENFORCED today: the workspace bind (`--ro-bind` for a read-only mission, so a write
returns `EROFS`), read grants, the network on/off decision (`--unshare-net` for
`none`), credential identities (`--clearenv` and one `--setenv` per granted name),
the dedicated account mount, memory (`MemoryMax` with `MemorySwapMax=0`) and the
process count (`TasksMax`). `cpu_seconds` is enforced per process by `RLIMIT_CPU`,
so a task that forks gets a fresh budget for each child.

NOT ENFORCED today, and not to be treated as controls: the egress allowlist —
Firebreak has two network postures, `none` and `allow`, and no destination filter,
so a session that is not `none` reaches the host's whole network, its loopback
services and its abstract sockets; masked paths — there is no masking flag; and any
syscall profile — no seccomp policy is applied or expressible. The agent also runs
as the invoking user's own uid. These are recorded with the session and reach no
mechanism; a refusal on one of them is a verdict written afterwards, not a block.

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
