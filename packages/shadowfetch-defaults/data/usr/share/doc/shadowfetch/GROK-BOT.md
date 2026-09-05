# Grok Bot on Shadowfetch Linux 4.0

Grok Bot is a featured optional native application in Welcome and Mission
Control. Choose it during first-boot setup to install the official Linux
application, then open it and sign in with your own account. The normal desktop
remains usable if you skip the choice or the download fails.

Grok Bot and Grok Build are separate products. Grok Bot provides a desktop
interface to cloud teammates and their persistent cloud computer. Grok Build is
the optional terminal coding agent installed with `shadowfetch-code-agent grok`.
The Grok Bot helper does not expose a headless task API or pretend its cloud
computer is part of Shadowfetch's local Firebreak boundary.

## Installation and access

The initial package is native Grok Bot **0.43.0 for amd64**, downloaded from the
vendor only when selected. It is about 99 MiB to download and 338 MiB installed,
plus any missing Debian dependencies. At least 1 GiB free space is required.
The ISO contains Shadowfetch's setup integration and provenance, without the
proprietary vendor binary or anyone's credentials.

```sh
shadowfetch-grok-bot setup
shadowfetch-grok-bot status --json
shadowfetch-grok-bot doctor
shadowfetch-grok-bot open
```

Welcome uses `setup --yes --no-open` after the user selects installation and
reviews its consequences. An administrator authentication dialog permits the
native Debian package installation. The vendor package creates its normal
application entry, browser sign-in URI handler, sandbox integration and signed
APT source (`https://downloads.cursor.com/aptrepo`, suite `grok-bot`). Later
system updates can install newer vendor releases.

Choose **Get started** in the native application and complete the vendor's
browser sign-in. Grok Bot uses a Cursor account and eligible Cursor or linked
SuperGrok plan. Access and included usage can change; review the current vendor
information. Shadowfetch does not include a paid subscription, and an xAI API
key is not a replacement for this app's account sign-in. Grok Bot requires
cloud data storage, and its service usage and privacy settings belong to the
vendor account. Local Shadowfetch missions do not require a Grok Bot plan.

Ice pauses this integration's cloud installation and launch. Switch to Fire
when you choose to use the cloud application. This launch preference does not
cancel any already-running vendor cloud routines; manage those inside Grok Bot.

## Integrity and updates

The release pin was obtained by following **x.ai/bot → More downloads → Linux
→ .deb x64** to the vendor's HTTPS endpoint on September 5, 2026 UTC. Its redirect
resolved to the versioned official package in the shipped provenance manifest:

```text
grok-bot_0.43.0_amd64.deb
103320044 bytes
SHA-256 451ecae8fcbda48a7c75dfc74a0da8f1d6452f6063b72330cbbaad29f3455380
```

Setup checks the size, SHA-256 and Debian package name, version and architecture
before running the package manager. A mismatch stops installation. The native
executable, application payload and desktop entry are checked against the
release pin, followed by Debian's installed package manifest verification.
This is a Shadowfetch integrity pin on an official HTTPS download; it is not
presented as a detached vendor signature. The downloaded Debian metadata gives
`License: unknown`; the application remains proprietary and subject to the
vendor's terms. Shadowfetch does not grant redistribution rights to it.

Normal newer vendor versions are accepted after their installed Debian package
manifest passes verification. The helper reports `vendor-updated-dpkg-manifest`
instead of claiming a match with the original 4.0 release pin. Setup leaves a
newer verified release in place. It refuses package-manager operations that
would remove another package, and never adds `--no-sandbox` when launching.

The local installation receipt is `/var/lib/shadowfetch/grok-bot/installation.json`.
It records release provenance without account credentials. Native application
startup output is private to the desktop user at
`~/.local/state/shadowfetch/grok-bot/launch.log` (or the configured XDG state
directory). Do not publish that log without reviewing it for personal data.

## Verification states

- `status --json` reports native installation and local integrity; it exits 0
  even when the optional app is absent.
- `doctor` exits 0 when installed files verify, or 1 when missing or changed.
- `authenticated` is always `null`: this helper does not inspect account secrets
  or claim that package installation proves a successful sign-in or agent task.
- Opening the app starts the real vendor process. Confirm that its window appears
  and finish its account flow before claiming a working cloud teammate.

## Official references

- Download: <https://x.ai/bot>
- Setup and Linux platforms: <https://docs.x.ai/grok-bot/get-started>
- Cloud computer, data and account behavior: <https://docs.x.ai/grok-bot/faq>
- Grok Bot terms: <https://cursor.com/terms/grok-bot>
- Cursor terms: <https://cursor.com/terms-of-service>
- Cursor privacy: <https://cursor.com/privacy>

Shadowfetch is an independent distribution. Grok Bot, Grok, Cursor and their
marks belong to their respective owners; this integration does not imply
vendor sponsorship or endorsement.
