# Shadowfetch Linux 4.0.0 — Mission Control

Status: implementation and validation in progress. This file is a release contract, not a claim that 4.0 has shipped. The public 3.5 image remains the current release until publication verification passes.

## Release objective

Deliver the complete Mission Control desktop: persistent tasks, visible scopes, real code/document/media workflows, reviewed results, cancellation/retry/recovery, hardware-aware local AI and resource management. Integrate the official Grok Bot Linux desktop app as a featured installation choice alongside the existing agents. Publish the signed ISO, corresponding source, GitHub release, updated shadowfetchlinux.org, actual screenshots and a reviewer letter after stress and acceptance testing.

## Product requirements

1. Native Mission Control is a first-class desktop surface. It creates and tracks real jobs, shows allowed files/tools/network, progress, artifacts, test output, failure details and results ready for review.
2. Mission state persists across service and computer restarts. Cancellation stops the task's process group. Retry checks state and does not blindly replay external effects.
3. Firebreak gives agents a private home and explicitly scoped filesystem access. A required recovery checkpoint must exist before a mission mutates files. Permission and receipt state stays outside the agent-writable project.
4. Fire offers explicit connected execution; Ice provides local execution with external networking disabled. Local inference crosses only a narrow local broker boundary.
5. Software missions run a supported coding runtime, verify the requested tests and present the actual patch. Document missions generate a report from selected sources with citations using actual local inference. Media missions produce validated exports without overwriting originals.
6. CPU, memory, process and heavy-job admission limits preserve a responsive desktop. Local model setup records the model, actual hardware and a measured successful inference result.
7. The desktop launcher and file manager can send selected projects or files into Mission Control. GUI and CLI share the same engine.
8. Grok Bot is the official native desktop product, separate from Grok Build CLI. Its package comes from the official vendor download source with a pinned digest and reviewed metadata. Setup shows download, disk, network and account requirements; native account sign-in remains with the provider. A cloud service is never labeled as Ice/local inference.
9. Grok Bot has prominent first-boot presentation, a dedicated Control Center surface and desktop launch entry. Screenshots must include the actual vendor application and its real setup/launch state.
10. BIOS and UEFI fresh installs boot from disk. A 3.5-to-4.0 upgrade preserves selected user data and has a documented recovery path. Btrfs and non-Btrfs recovery limits remain explicit.
11. At least 45 minutes of concurrent CPU, memory, storage, container and mission/UI load complete with clean kernel, service, package and filesystem audits.
12. Screenshots come from the built release desktop at 1366×768 and 1920×1080. Capture Fire, Ice, Welcome, Mission Control, Grok Bot, installation, results/recovery and under-load states. Do not substitute design mockups.
13. The signed ISO, APT binaries and corresponding source, package manifest, SBOM, evidence bundle, Git tag/release, website and reviewer letter all describe the same verified release.

## Build identity

- Version: 4.0.0; codename/repository suite: Umbra / `umbra`.
- Architecture: amd64; desktop: KDE Plasma 6; installer: Calamares.
- Source: `/home/rtx5060ti/projects/shadowfetch-4.0.0`, branch `release/4.0.0`.
- Development mirror: task-owned Mac workspace; builds and publishing execute on Linux.
- Base snapshot is inherited from 3.5 pending package/build validation; no unsupported claim of a base-OS migration.
- Exact source commit, ISO size/hash/signature and release date are recorded only after the final build.

## Evidence

`qa/4.0.0/acceptance.json` contains the complete gate inventory. Every case starts pending with no inherited 3.5 evidence. A test manifest is an index into actual logs, artifacts and runtime captures; its status alone is insufficient to prove a feature works.

## Publication boundaries

The user authorized end-to-end GitHub and website publication for 4.0. Publish only after the tested release is concrete. Native vendor apps retain their licenses and account requirements. Never embed keys, credentials, private operating data or account state in source, packages, screenshots or the ISO.

The public distro Worker is `shadowfetch-linux-site`, published by `rtx5060ti` from `/home/rtx5060ti/.sfbuild/release-sources/shadowfetch-linux-site`. Artifacts/APT remain on the established `.com/linux` routes. Worker `shadowfetch-astro` may ship only through the designated Linux release cycle; preserve `/news`. No broad R2 pruning or unrelated service changes are part of this release.

## Reviewer deliverables

After acceptance, generate a ready-to-send reviewer letter in editable Word, PDF and plain text, a screenshot gallery with a prominent actual Grok Bot capture, verification instructions, exact release links, test results and known limitations. The letter is prepared for the user to send; this task does not authorize unsolicited outreach.
