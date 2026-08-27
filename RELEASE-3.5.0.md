# Shadowfetch Linux 3.5.0 - Fire and Ice Workbench

Status: release candidate under construction. This document is the source
contract for build, VM validation and release evidence. It is not a publication
claim.

## Flagship hook

One Linux workstation, two explicit operating postures, four production
workspaces.

- **Fire** is connected and throughput-oriented. It leads with software,
  production operations, creative work and optional cloud coding agents.
- **Ice** is private and local-first. Firebreak agent sessions start with no
  network access, and the AI Lab leads without preselecting a cloud agent.
- **Element Workbench** turns either posture into a ready project with a fixed
  tool plan, plain-language consequences, project-only agent writes, provenance,
  tests, runbooks and receipts.

The hook is not merely a theme switch. The selected element changes the
security default that an agent receives and the recommendations the user sees.

## Product contract

Shadowfetch Linux 3.5.0 remains an amd64 Debian testing snapshot derivative
with KDE Plasma 6, Calamares, Btrfs/Phoenix recovery, Fireproof updates,
Firewatch telemetry, Ember performance modes, Buzz, and optional verified
coding agents. OpenClaw and Hermes remain retired.

The ISO contains a useful offline desktop, the four Workbench project
templates, Firebreak, diagnostics and the setup interfaces. It does not embed
model weights, cloud credentials, API keys, third-party accounts or hidden
post-install downloads.

## Element Workbench profiles

| Profile | Primary tools | Default fit | Boundary |
| --- | --- | --- | --- |
| Software Studio | Git, Python, Node.js, Podman, Distrobox, PostgreSQL and SQLite clients | Fire | Dev Container metadata is repeatability, not a security boundary. Firebreak remains the agent sandbox. |
| AI Lab | Buzz, JupyterLab, Hugging Face CLI, Podman, Vulkan and GPU diagnostics | Ice | Models are selected and downloaded only after explicit consent. License, revision and checksum belong in the project manifest. |
| Production Ops | Podman, Buildah, Skopeo, Ansible, Redis diagnostics and runbooks | Fire | No provider credential is copied by Shadowfetch. Publishing and production changes remain user-authorized actions. |
| Creative AI | Krita, Blender, Kdenlive, OBS, FFmpeg, Darktable and provenance ledgers | Fire | Source, consent, license, model revision and output provenance remain visible project data. |

Every profile must expose the approximate installed footprint, network use,
account requirements, accelerator expectations, package state and command
state before installation. The graphical and command-line plans use the same
root-owned manifest.

## AI and agent contract

- Buzz remains the shared local-model workspace and asks before model download.
- Codex CLI is pinned to 0.150.1 through OpenAI's digest-verified installer.
- Claude Code, Grok Build and Cursor Agent retain independent, release-pinned,
  user-owned installers and native sign-in.
- Firebreak supplies project-only writes, stripped secret variables, an
  element-aware network default and a visible launch receipt.
- Checkpoint and Phoenix provide project and system recovery paths.
- Distrobox and Dev Containers are compatibility/repeatability tools; the UI
  and docs never call them security sandboxes.
- No agent is silently granted a model, account, credential, publishing right
  or full-home write access.

## User experience contract

- First boot reaches a responsive Plasma desktop without requiring a model or
  account.
- Welcome presents Guide, Element Workbench, Fire/Ice selection, app profiles,
  graphics, optional apps, Buzz and coding agents in that order of intent.
- Control Center exposes Workbench as a first-class section rather than a wall
  of unrelated package checkboxes.
- A profile install is one signed APT transaction. On Btrfs, Phoenix wraps it
  automatically.
- Project creation is unprivileged, refuses overwrite, uses a private
  `~/Workspaces` root and creates no real secret file.
- All new surfaces fit 1366x768 and 1920x1080 without clipped text or overlap.

## Build contract

- Version: `3.5.0`
- Codename/repository suite: `umbra`
- Architecture: `amd64`
- Exact build snapshot: `20260726T000000Z`
- Output: `shadowfetch-3.5.0-amd64.iso`
- Required sidecars: SHA-256, detached GPG signature, source packages, SBOM,
  package manifest and evidence bundle.
- Source branch: `release/3.5.0`
- Build lane: `/home/rtx5060ti/projects/shadowfetch-3.5.0`

The 3.1.0 source tree and ISO are immutable inputs, not build destinations.

## Acceptance gates

1. Source gate: tests, Python compilation, ShellCheck, desktop-file validation,
   JSON validation, secret scan and retired-runtime scan pass.
2. Package gate: every 3.5.0 custom binary/source package builds, the signed
   repository allowlist is exact, and package install/upgrade/remove simulations
   are clean.
3. ISO gate: fresh hybrid BIOS/UEFI ISO, signature, checksum, embedded package
   versions, GRUB element entries, no secret material, no model weights, and
   required Workbench files pass.
4. Fire VM: live boot, Workbench render, Software Studio create/plan, Firebreak
   network-allow banner, stress and clean shutdown pass.
5. Ice VM: live boot, Workbench render, AI Lab create/plan, Firebreak network-none
   banner, stress and clean shutdown pass.
6. Installed VM: Calamares installs to a fresh disk, the chosen element survives
   reboot, package database is clean, and Workbench creates a project as the
   installed user.
7. Recovery: cancelled downloads make no package mutation; injected package
   failure is visible; Phoenix/checkpoint restore paths are exercised.
8. Sustained load: CPU, memory, storage, package queries, rootless container
   smoke and UI responsiveness run concurrently for at least 45 minutes with no
   kernel oops, failed Shadowfetch service, corrupt package state or frozen UI.
9. Visual QA: 1366x768 and 1920x1080 captures for Fire and Ice include Welcome,
   Workbench, AI choices, desktop and one under-load state.
10. Evidence: exact ISO hash, signature fingerprint, VM commands, screenshots,
    logs, SBOM and residual risks are collected before any publication decision.

## Publication boundary

Building, signing and passing the local gates does not publish 3.5.0. Website,
GitHub, R2 or Archive.org changes require a separate explicit release decision
after the evidence bundle is complete.
