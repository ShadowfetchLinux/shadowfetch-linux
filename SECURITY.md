# Security policy

Shadowfetch Linux publishes signed ISO releases, a signed APT repository, SHA-256 checksums, detached GPG signatures, and a public signing key.

## Verify downloads

Verify the ISO before installing it. The checksum proves the file downloaded intact; the GPG signature proves the file matches what Shadowfetch signed.

Current signing key fingerprint:

`8F13 CE15 35EE 1F4A 2916 A1F7 3C5C 900B 7BE8 0CA1`

Current verification guide: https://www.shadowfetchlinux.org/verify

Security model: https://www.shadowfetchlinux.org/security

A normal GPG "not certified with a trusted signature" warning means you have not personally trusted the key; it is not the same as a failed signature. Compare the fingerprint above before trusting the download.

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
