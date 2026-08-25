# Shadowfetch Linux 3.0.0 Fire Edition — "Backfire"

Codename: Umbra (permanent — APT suite stays `umbra`; 3.0 is conveyed by the
"Backfire" subtitle, exactly as 2.0.0 used "Bedrock").

Status: IN DEVELOPMENT. The public stable release remains 2.1.5 until every
required item in `qa/3.0.0/acceptance.json` has fresh evidence from the final
3.0.0 ISO and all public files pass independent download verification.

## Why "Backfire"

A backfire is a fire set deliberately to contain a larger fire. Agentic
programs are now a fact of modern workflows — and running them full-auto on a
bare host is the wildfire. Shadowfetch 3.0 is the controlled burn: the first
desktop OS where autonomous agents are **contained, observed, and reversible
by default**.

## Release identity (one sentence)

The agent-safe local-AI workstation: full-auto coding agents and local models
turnkey out of the box — every agent sandboxed, every action auditable in
Firewatch, every session one Phoenix Point away from undo — private, signed,
zero-telemetry, on hardware you own.

## Research basis (2026-08, six-agent deep-research sweep; evidence archived
in `work/research-3.0/`)

- 90% of developers use coding agents weekly (JetBrains 2026); consensus after
  the Replit DB wipe / Gemini CLI file loss: never run full-auto on the bare
  host — yet no desktop OS ships the safe harness. This is the gap.
- Windows 10 free consumer ESU quietly extended to 2027-10-12: the switcher
  wave runs through 3.0's entire cycle. Zorin 18 took 2M downloads in <3
  months, ~75% from Windows. Remaining holdouts are risk-averse — Phoenix
  rollback is exactly their reassurance.
- MCP won (Linux Foundation governance, 10K+ servers) and its security is the
  ecosystem's open wound (30+ CVEs in 60 days; tool-poisoning worms). Only an
  OS with signed packaging can ship a trusted MCP surface.
- Local-AI trust moment: OpenAI's train-by-default ToS change, Recall's
  reputation — "the AI runs HERE and you can watch it" is the story.
- Our own 8/10 review said "AI-ready, not turnkey" (nouveau on an RTX 5080).
  NVIDIA-at-first-boot is the single highest-leverage adoption fix.

## THE FIRELINE (agentic centerpiece — one integrated system)

1. **Firebreak** (`shadowfetch-firebreak`, new package `shadowfetch-fireline`)
   — run ANY installed agent (Claude Code, Codex CLI, Goose, Cursor, Grok
   Build, Aider) full-auto inside bubblewrap with per-project filesystem
   scope, hostname/session identity, and an automatic workspace checkpoint
   before the session. Kernel preconditions (unprivileged userns, Landlock)
   verified by a Passport check.
2. **Agent Checkpoints** (`shadowfetch-agent-workspace` v2) — ~/Workspaces
   become Btrfs subvolumes; every Firebreak session takes a pre-run snapshot;
   post-session diff review ("what the agent touched"); one-command
   `undo` restores the workspace. Phoenix philosophy at workspace granularity,
   fully user-space (no root needed for snapshot/diff).
3. **Audit journal** — Firebreak emits structured journald records (session
   start/end, scope, checkpoint id, exit); `shadowfetch-firebreak log` renders
   the per-agent timeline. Firewatch integration follows in 3.x.
4. **Shadowfetch MCP suite** (`shadowfetch-mcp`) — signed first-party MCP
   stdio servers: `passport` (read-only system self-check), `phoenix`
   (list/create restore points), `checkpoint` (workspace snapshot/diff), and
   `fs` (scoped read-only file access). An agent on Shadowfetch can literally
   call a checkpoint before touching anything. Zero third-party deps.
5. **Secret hygiene** — Firebreak strips known credential variables from the
   sandbox environment by default (opt-in passthrough per profile); KWallet
   broker follows in 3.x.

## Headline features (ranked by research)

1. **AI Ignition** — first-boot: hwscan/Passport size the GPU → consent-gated
   proprietary NVIDIA driver via the proven `shadowfetch-gpu` path (Phoenix
   Point first) → one-click Apache-2.0 model tiered by VRAM. Fixes the 8/10
   review verbatim. (Welcome + gpu; config baked, bulk downloaded.)
2. **Firebreak** — see Fireline. (New `shadowfetch-fireline` package.)
3. **Agent Checkpoints** — see Fireline. (`shadowfetch-agent-workspace` v2.)
4. **Shadowfetch MCP suite** — see Fireline. (`shadowfetch-mcp`.)
5. **Audit journal + secret hygiene** — see Fireline.
6. **Windows Exile mode** — Calamares NTFS detect + user-folder/browser
   import (extends shipped `shadowfetch-browser-import`), Windows-familiar
   layout preset, first-week Guide checklist. (3.0.x train.)
7. **Expanded verified-agent roster** — add Goose (MCP-native) to the four
   shipped installers; fully-local lane: Aider preconfigured against Buzz's
   llama-server. OpenClaw only with the hardening wrapper (loopback-only,
   sandbox-wrapped) — its CVE record forbids a bare one-click.
8. **Offline voice** — faster-whisper dictation + Kokoro TTS (NOT archived
   Piper), consent-gated model download. (3.0.x train.)
9. **Gaming bundle + anti-cheat honesty** — one-click Steam/Proton-GE/
   gamemode/MangoHud first-boot bundle + a Passport pre-check that NAMES the
   anti-cheat titles that will not run (Vanguard/EA/GTA-online).
10. **Published numbers** — tokens/sec per reference GPU, ISO-to-first-token,
    rollback time, on the benchmark surface. Quantified claims beat adjectives
    (CachyOS lesson).
11. **shadowfetch-hardware ships** — the staged, tested offline firmware
    diagnoser leaves `next-release/` and lands in `shadowfetch-defaults`.

## Hook matrix (many hooks, one identity)

| Audience | Pitch |
|---|---|
| Agentic developer (PRIMARY) | The only OS where full-auto is safe by default — and undo is one command. |
| Privacy local-AI user | No prompt leaves the machine; watch the tokens/sec to prove it. |
| Windows 10 refugee | Your PC isn't obsolete; this system can't be broken by an update — and you can always go back. |
| Curated-setup developer | One first-boot choice → a configured multi-agent + local-model environment; every choice one snapshot from undo. |
| Gamer (supporting) | Steam + Proton one click; an honest "will my games run?" answer first. |
| Creator | The full creative stack, plus local generation — no subscription, no cloud. |
| Homelab | One click turns this box into the private brain for your smart home. (3.0.x) |

## Explicit cuts (decided, do not revisit casually)

- No bundled chat-widget gimmick. No Shadowfetch-hosted inference or relay.
- No gaming-distro positioning (Valve/Bazzite own that lane).
- No immutable/OSTree rebase — Phoenix+Fireproof already deliver the benefit.
- No Open WebUI bundling; no Ollama branding (llama.cpp engine, Ollama-compatible API).
- No Piper TTS (archived); no Llama-family models in the default catalog
  (Apache-2.0 only: Qwen, Gemma, gpt-oss, Devstral).
- Nothing heavy baked into the ISO — squashfs ceiling stands (~547 MiB head-
  room): bake config, download bulk.
- No first-party coding agent — Shadowfetch wins as the safest HOST for all
  vendor agents.
- One identity in marketing: the agent-safe local-AI workstation. Everything
  else is a hook, not a headline.

## AI and agent contract (carried forward from 2.1.5, extended)

- No open model bundled in the ISO; every model download is consent-gated.
- Buzz remains optional and loopback-only by default.
- Every agent installer is release-pinned, SHA-256-verified, user-owned; no
  credential is ever embedded, copied, or read by Shadowfetch.
- NEW: any agent launched through Firebreak runs filesystem-scoped to its
  workspace, with a checkpoint taken first and an audit record written.
- NEW: first-party MCP servers are read-only by default; anything that writes
  (checkpoint create/restore) says so in its tool description and touches only
  the workspace it was scoped to.

## Release gates (same discipline as 2.1.5)

- Source/behavior/ShellCheck/secret/retired-runtime gates pass.
- Firebreak: sandboxed agent cannot read outside its scope (adversarial
  fixture); checkpoint/undo round-trips byte-identical; audit records present.
- MCP servers: schema-valid initialize/list/call over stdio; passport output
  passes the privacy scrubber; fs server refuses paths outside scope.
- AI Ignition: NVIDIA path validated on the physical RTX 5060 Ti; simulate-
  first; Phoenix Point around the transaction; clean rollback proven.
- Full ISO structure/checksum/signature, BIOS+UEFI boot, clean installs,
  2.1.5→3.0.0 upgrade preserving user files, Buzz state, and workspaces.
- Fresh screenshots from the exact final ISO; staged website/GitHub/Archive
  metadata verified before publication; publish only after all gates green.

## Launch

Ride the 2026-10-13 Windows-10 consumer-ESU news moment; land before Ubuntu
26.10's AI previews. Lead story: "the first desktop OS built for the agentic
era." Ship only when the NVIDIA path is bulletproof.
