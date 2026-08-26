# Shadowfetch Linux 3.1.0 Fire Edition — "Fire and Ice"

Codename: Umbra (permanent). 3.1 subtitle: "Fire and Ice".

Status: IN DEVELOPMENT. The public stable release remains 3.0.0 until every
required item in `qa/3.1.0/acceptance.json` has fresh evidence from the final
3.1.0 ISO and all public files pass independent download verification.

## The idea

Shadowfetch 3.1 ships TWO complete identities and lets you pick at install:

  Fire  run hot — Umbra gold, the ember desktop, and agent sandboxes that may
        use the network by default. Setup leads with creative, gaming and
        full-auto agent profiles.
  Ice   run cold — glacier azure, the frost desktop, and Firebreak agent
        sandboxes that start with NO network (you grant it per session).
        Setup leads with the private developer and fully-local AI profiles.

The element is one word — `fire` or `ice` — chosen at the GRUB boot menu or the
Welcome "Choose your element" page, stamped to `/etc/shadowfetch/element` (system
default) and `~/.config/shadowfetch/element` (per user). It is the single source
of truth that branches:

  * theme  — Plasma color scheme (ShadowfetchDark / ShadowfetchIce), accent
             (#D8A24A / #4AA2D8), wallpaper (UmbraFire / UmbraIce), Konsole
             scheme, look-and-feel (org.shadowfetch.dark / .ice).
  * Welcome — palette, the edition tag (Fire/Ice Edition), the ORDER and COPY of
             the setup profiles, and which coding agents each profile preselects.
  * Firebreak — the agent sandbox network default (fire=allow, ice=none), stated
             plainly in the session banner.
  * Control Center — the accent palette (sfcc/theme.py reads the element).

Switch any time: `shadowfetch-element set fire|ice` re-themes the running session.

## Plain-language AI/agent rule

Every setup profile description ends with one explicit sentence saying exactly
what it does about AI — "installs no AI tools", or "preselects the Claude Code
and Codex CLI coding agents", or "installs Buzz and preselects all four coding
agents (Codex CLI, Claude Code, Grok Build, Cursor)". The user never guesses.

## New/changed in 3.1

- NEW shadowfetch-element (in shadowfetch-defaults): read/set/apply the element.
- NEW boot-time stamp: GRUB Fire/Ice menu entries -> sf.element= -> a oneshot
  service writes /etc/shadowfetch/element before the display manager.
- NEW Ice theme assets: ShadowfetchIce.colors, ShadowfetchGlacier.colorscheme,
  org.shadowfetch.ice look-and-feel, UmbraIce/UmbraFrost/UmbraDrift wallpapers,
  umbra-ice-4k.jpg (all added to the .install ship-lists).
- Welcome: element-aware palette + ACCENTS + edition tag; a "Choose your element"
  page; build_profile_presets(element) with plain AI sentences; profiles now
  actually preseed the AI-workspace agent checkboxes.
- Firebreak: --net default follows the element; the element is printed in the
  session banner; help documents it.
- Control Center: sfcc/theme.py accent follows the element.
- Calamares: sources-final carries the chosen element into the installed system.

## Carried forward

Everything in 3.0.0 "Backfire": the Fireline agent-safety system (firebreak /
checkpoint / MCP suite), AI Ignition, Guide + System Passport, Phoenix, Fireproof,
Buzz, signed ISO + APT, zero telemetry.
