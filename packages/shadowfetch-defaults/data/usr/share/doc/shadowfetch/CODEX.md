# Codex CLI on Shadowfetch Linux 3.5.0

Shadowfetch can optionally install the official OpenAI Codex CLI during the
first-run setup. Codex is not embedded in the ISO and is not required for Buzz
or for local models.

The setup downloads OpenAI's official standalone installer from
`https://chatgpt.com/codex/install.sh`, verifies the release-pinned installer
SHA-256, and asks that installer for Codex CLI 0.150.1. OpenAI's installer then
verifies the selected release archive before activation.

To install or repair the pinned release later, run:

    shadowfetch-codex setup

To inspect the local installation without signing in, run:

    shadowfetch-codex doctor
    shadowfetch-codex status

To open Codex in Konsole, run:

    shadowfetch-codex open

Codex is installed only for the current desktop user under `~/.local/bin`.
Shadowfetch does not include, request, copy, or share an OpenAI credential.
The first Codex launch offers the sign-in methods supported by OpenAI.

Official documentation: https://learn.chatgpt.com/docs/codex/cli
Upstream source: https://github.com/openai/codex
