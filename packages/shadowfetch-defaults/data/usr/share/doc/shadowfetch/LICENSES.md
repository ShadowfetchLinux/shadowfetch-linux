# Shadowfetch Linux — Licensing

Shadowfetch Linux is a Debian derivative. It is composed almost entirely of
free/open-source software from Debian, KDE, and other upstreams, each licensed
under its own terms (GPL-2.0+, GPL-3.0+, LGPL-2.1+, MIT, BSD, Apache-2.0, and
others). Those licenses and the corresponding source are available from Debian
(https://www.debian.org/distrib/packages) and each project upstream.

## Shadowfetch's own components

The Shadowfetch packages are published
under the MIT License, EXCEPT theme assets derived from KDE's Breeze
(the Umbra SDDM/Plasma theme), which remain under Breeze's LGPL-2.1+/GPL-2.0+
terms as required.

The Buzz compose definition is adapted from the Apache-2.0 Buzz project at
https://github.com/block/buzz. The optional Buzz Desktop package retains its
upstream Apache-2.0 license and is downloaded only after explicit user consent.

The optional Codex CLI is maintained by OpenAI under Apache-2.0 at
https://github.com/openai/codex. It is downloaded only after explicit user
consent and is installed for the current desktop user, not embedded in the ISO.

The optional Claude Code, Grok Build, and Cursor Agent downloads are not
embedded in the ISO. They are third-party products governed by their vendors'
terms and are downloaded only after explicit user consent. Shadowfetch's MIT
license does not grant rights to those downloaded products.

## Written offer for source

The complete corresponding source for the Shadowfetch packages is:
  * published at https://github.com/ShadowfetchLinux/shadowfetch-linux
  * available as a source tarball at
      https://shadowfetch.com/linux/apt/sources/shadowfetch-source-3.0.0.tar.gz

For source of any upstream Debian/KDE component, contact
signing@shadowfetch.com and we will direct you to, or provide, the exact
corresponding source for the version shipped.
