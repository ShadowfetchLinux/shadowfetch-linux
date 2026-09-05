# Optional coding agents on Shadowfetch Linux 3.5.0

First-run setup offers four independent, unchecked coding-agent choices:

- OpenAI Codex CLI 0.150.1
- Anthropic Claude Code 2.1.227
- xAI Grok Build CLI 1.0.5
- Cursor Agent 2026.08.11-e8db854

Buzz remains a separate local-AI workspace. None of these cloud coding agents
is required for Buzz, and a failed optional download cannot block the base
desktop or another selected tool.

Shadowfetch downloads each selected release from its vendor's official HTTPS
endpoint and verifies a release-pinned SHA-256 before installation. The files
are installed only for the current desktop user. They are not embedded in the
ISO, and Shadowfetch does not collect, copy, or preconfigure account
credentials. Authentication begins only when the user opens a tool.

Use the shared helper for Claude Code, Grok Build, or Cursor Agent:

    shadowfetch-code-agent claude setup
    shadowfetch-code-agent grok setup
    shadowfetch-code-agent cursor setup

Replace `setup` with `doctor`, `status`, or `open` to verify, inspect, or launch
one tool. Codex keeps its dedicated compatibility helper:

    shadowfetch-codex setup
    shadowfetch-codex doctor
    shadowfetch-codex status
    shadowfetch-codex open

Grok and Cursor both advertise a generic `agent` alias upstream. Shadowfetch
does not install that ambiguous alias: use `grok` for Grok Build and
`cursor-agent` for Cursor Agent. This allows both products to coexist without
overwriting each other.

Official documentation:

- Codex: https://learn.chatgpt.com/docs/codex/cli
- Claude Code: https://code.claude.com/docs/en/getting-started
- Grok Build: https://docs.x.ai/build/overview
- Cursor Agent: https://docs.cursor.com/en/cli/installation

Third-party account, service, and license terms apply to each downloaded tool.

Shadowfetch 4.0 also offers **Grok Bot**, the separate native cloud teammate app,
as a featured first-boot choice. Use `shadowfetch-grok-bot setup` and
`shadowfetch-grok-bot open`. Grok Bot uses its own browser-based account sign-in
and requires an eligible vendor plan; it is not the Grok Build CLI and does
not accept an xAI API key through this installer. See `GROK-BOT.md` for setup,
provenance, privacy and update behavior.
