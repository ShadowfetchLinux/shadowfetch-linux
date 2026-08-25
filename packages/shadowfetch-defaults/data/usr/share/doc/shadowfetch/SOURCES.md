# Shadowfetch Linux — Corresponding Source

Shadowfetch Linux is built from Debian and KDE. The corresponding source for
every upstream package is available from Debian
(https://www.debian.org/distrib/packages and its snapshot archive) and from
each project upstream, under that package's own license.

## Shadowfetch's own components

The Shadowfetch packages are published
under the MIT License, except theme assets derived from KDE Breeze (the Umbra
SDDM/Plasma theme), which remain under their original LGPL-2.1+/GPL-2.0+ terms.

The local Buzz compose definition in shadowfetch-defaults is adapted from
Block's Buzz project under Apache-2.0. Upstream source:
https://github.com/block/buzz . Buzz Desktop itself is not embedded in the ISO;
it is downloaded from the official release only after the user opts in.

The optional Codex CLI is not embedded in the ISO. After explicit user consent,
Shadowfetch downloads the official OpenAI installer, verifies the release-pinned
installer SHA-256, and installs the selected digest-verified release for that
desktop user. Upstream source: https://github.com/openai/codex .

Claude Code, Grok Build, and Cursor Agent are also optional and are not embedded
in the ISO. After explicit user consent, Shadowfetch downloads the selected
release from the vendor's official HTTPS endpoint, verifies the release-pinned
artifact SHA-256, and installs it only for that desktop user. These third-party
products remain subject to their vendors' account, service, and license terms.
Official documentation is linked from `CODING-AGENTS.md`.

### Written offer for corresponding source

The complete corresponding source for the Shadowfetch packages of THIS release
is published as a signed tarball alongside the release:

    https://shadowfetch.com/linux/apt/sources/shadowfetch-source-3.0.0.tar.gz

Its SHA-256 is published next to it (…tar.gz.sha256). The project's public home
and issue tracker are at https://github.com/ShadowfetchLinux/shadowfetch-linux .
For the corresponding source of any upstream Debian/KDE component shipped in
this image, email signing@shadowfetch.com and we will provide the exact source
for the version shipped, at no more than the cost of distribution.
