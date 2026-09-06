# Shadowfetch Linux 4.0 — Mission Control

**Your computer. Your agents. Work you can inspect.**

Shadowfetch Linux is an independent Debian testing derivative with KDE Plasma 6, a creative desktop, reviewed updates and recovery tools. Version 4.0 adds a native Mission Control desktop: give a task a project, choose its connection and provider, then review the files, tests and changes it produces. For the first time in Shadowfetch Linux, Grok Bot is a featured optional choice at startup.

> **Publication draft — final acceptance and artifact facts remain unresolved.** Replace every `{{PLACEHOLDER}}` from the accepted release evidence before replacing the tracked README. The two URLs below are reserved for genuine final-ISO captures; they do not yet assert that those images have been published.

![Shadowfetch Linux 4.0 Mission Control with actual task results and review actions](https://www.shadowfetchlinux.org/linux-assets/linux-4.0.0-mission-control.webp)

*Mission Control: a persistent queue with activity, output files, diffs and review. Final capture state: {{FINAL_MISSION_SCREENSHOT_STATE}}.*

![Official Grok Bot native Linux application on Shadowfetch Linux 4.0](https://www.shadowfetchlinux.org/linux-assets/linux-4.0.0-grok-bot.webp)

*Official native Grok Bot. Final capture state: {{FINAL_GROK_SCREENSHOT_STATE}}. A launch or sign-in screen does not prove an authenticated account or a completed cloud task.*

[Download](https://www.shadowfetchlinux.org/download) · [Mission Control](https://www.shadowfetchlinux.org/mission-control) · [Grok Bot](https://www.shadowfetchlinux.org/grok-bot) · [Screenshots](https://www.shadowfetchlinux.org/screenshots) · [Release notes](RELEASE-4.0.0.md)

## Current release

| Fact | Value |
| --- | --- |
| Version / codename | 4.0.0 / Umbra |
| Publication date / channel | {{PUBLICATION_DATE}} / {{RELEASE_CHANNEL}} |
| ISO | {{FINAL_ISO_FILENAME}} |
| Size | {{FINAL_ISO_BYTES}} bytes — {{FINAL_ISO_SIZE_LABEL}} |
| SHA-256 | `{{FINAL_ISO_SHA256}}` |
| ISO product source commit / tree | `{{FINAL_SOURCE_COMMIT}}` / `{{FINAL_SOURCE_TREE}}` |
| Base / desktop | Debian testing snapshot 20260726T000000Z / KDE Plasma 6 |
| Architecture / APT suite | amd64 / `umbra` |
| Final boot acceptance | {{FINAL_BIOS_AND_UEFI_ACCEPTANCE}} |

Signing-key fingerprint: `8F13 CE15 35EE 1F4A 2916  A1F7 3C5C 900B 7BE8 0CA1`.

## What 4.0 adds

| Feature | What you can do |
| --- | --- |
| **Mission Control** | Create work in an existing Workbench project, watch the persistent queue, inspect activity and failures, and review files, receipts and changes. Open the same form from Workbench or Dolphin. |
| **Code and tests** | Request a scoped change and select the exact test program and arguments. Bounded edit/test/repair attempts leave a diff and validation record. Use your configured Codex cloud provider. |
| **Reports with sources** | Select project text files and generate a report with citations. Review the source support for each claim. |
| **Media exports** | Export selected media with deterministic FFmpeg workflows; inspect stream validation, sizes and digests alongside the files. |
| **Review and recovery** | Successful tasks wait for review. Accept a result, cancel running work, retry failed work or restore the local checkpoint. Restore refuses conflicts with newer project edits. |
| **Featured Grok Bot** | Select the official native desktop in Welcome or use its dedicated Mission Control page. The verified installer discloses the download, administrator approval and vendor update source. Sign in inside the vendor app. |
| **Offline workspaces** | Keep project files together and use deterministic media tools without an AI provider. Local AI is deferred in 4.0. |

Grok Bot is separate from the Grok Build CLI. Codex, Claude Code, Grok Build and Cursor Agent remain independent optional coding tools with their own account setup. Grok Bot needs an eligible vendor account and plan; a model API key does not replace its native sign-in.

Welcome keeps profile descriptions in a scrollable list with fixed navigation, and every wallpaper remains reachable through a horizontal row. The Control Center health header reports failed system units; user services and application health need their own checks. A focused DrKonqi helper lets the finite login crash-pickup scan finish, including an empty scan, while retaining KDE’s per-crash reporting path and runtime guard.

Element Workbench, the creative application stack, Guide, Ember, Firewatch, Phoenix and Fireproof remain available. Fireproof simulates and rechecks updates; supported Btrfs layouts provide Phoenix snapshot recovery. Recovery depends on the snapshots and available space.

## Scope, connections and data

Fire exposes connected workflows. Ice starts sandboxed agent sessions without an external network and pauses Grok Bot installation and launch. Each mission presents its connection choice. Generated code, tests and media tools run in Firebreak with writes scoped to the approved project and a restricted filesystem view. Code and source-report missions require configured Codex access and explicit network approval; media exports can run offline.

Local AI is deferred for this release. The upgrade retires Shadowfetch's Buzz integration and managed relay startup while preserving user data and separately installed vendor software.

No Shadowfetch account is required to use the desktop. Model weights and provider account sessions are not bundled. Optional vendor applications retain their own network behavior, settings, licenses and account requirements.

Receipts, prompts and source material can be private. Review files before sharing them. Local restoration cannot reverse external effects from an approved network action.

## Verify and install

The [download page](https://www.shadowfetchlinux.org/download) links the ISO, checksum, detached signature, SBOM, package manifest and release evidence. Use the exact accepted filename below. These commands download and verify files; they do not write a USB device.

```sh
ISO='{{FINAL_ISO_FILENAME}}'
ARTIFACT_BASE='https://www.shadowfetch.com/linux/download'
curl --fail --location --remote-name "$ARTIFACT_BASE/$ISO"
curl --fail --location --remote-name "$ARTIFACT_BASE/$ISO.sha256"
curl --fail --location --remote-name "$ARTIFACT_BASE/$ISO.asc"
curl --fail --location --remote-name https://www.shadowfetch.com/linux/shadowfetch.gpg.asc
gpg --show-keys --with-fingerprint shadowfetch.gpg.asc
# Compare the fingerprint with the value above before importing.
gpg --import shadowfetch.gpg.asc
gpg --verify "$ISO.asc" "$ISO"
sha256sum --check "$ISO.sha256"
```

Continue only after the signature and checksum both verify. A GPG warning about personal key trust differs from a failed signature. Write the verified ISO with a USB image writer, then follow the [installation guide](https://www.shadowfetchlinux.org/install).

The live session uses `shadow` / `shadow` with passwordless sudo. The installer creates the chosen user and removes the live account; final installed-account validation is recorded in the release evidence. See the [verification guide](https://www.shadowfetchlinux.org/verify), [Secure Boot guide](https://www.shadowfetchlinux.org/secure-boot) and [known issues](https://www.shadowfetchlinux.org/known-issues).

## Hardware and limits

Use a 64-bit Intel/AMD computer. Plan for 8 GB RAM and 100 GB disk space for a comfortable desktop; demanding creative projects need additional memory and storage. These planning figures are not a physical-hardware certification.

Secure Boot has no Microsoft-trusted shim. Intel/AMD use Mesa; NVIDIA setup is an explicit, simulate-first workflow. VM rendering tests do not establish physical NVIDIA, AMD or Intel acceleration performance, and hybrid laptops need their own validation. Phoenix Points require a supported Btrfs root; ext4 does not provide the same snapshot recovery. Debian testing can change faster than Debian stable.

Final release acceptance: **{{FINAL_REQUIRED_GATES_PASSED}} / {{FINAL_REQUIRED_GATES_TOTAL}}**; evidence: **{{FINAL_EVIDENCE_DOSSIER_URL}}**. The release notes identify the actual install paths, graphics environment, provider tests and stress measurements.

## Build from source

The project uses Debian live-build, Debian source packages and a signed reprepro repository. Build on a Debian host; privileged build steps use sudo. Package builds and source tests do not require production publishing credentials.

```sh
make deps          # install build dependencies
make test          # focused behavior checks
make source-gate   # tests, parsers, linters and secret scans
make packages      # build the Debian packages into build/
```

The release build uses the configured signing key:

```sh
make repo          # signed local APT repository
make package-gate  # package, repository and clean-install checks
make iso           # privileged image assembly, signature and ISO gate
make qemu          # launch the resulting image for a smoke test
```

`make iso` produces `shadowfetch-4.0.0-amd64.iso` in the repository root. `VERSION ?= 4.0.0` and `CODENAME ?= umbra` live in the Makefile. Signing and publishing require the maintainer's private key and authorized publisher credentials, which are not in this repository. Consult `make help`, [release notes](RELEASE-4.0.0.md) and `.github/CI-SECRETS.md` before release operations.

Source map: `packages/shadowfetch-missions/` contains the queue and execution engine; `packages/shadowfetch-control-center/` contains the native Qt UI; `packages/shadowfetch-welcome/` contains first boot; `packages/shadowfetch-defaults/` supplies integration helpers; `packages/shadowfetch-drkonqi-pickup/` contains the pinned KDE pickup source, correction and behavior checks. `live-build/` assembles the desktop, `tools/` holds gates and release tooling, and `qa/4.0.0/` indexes acceptance evidence.

## Support and contributing

Use [GitHub Issues](https://github.com/ShadowfetchLinux/shadowfetch-linux/issues) for bugs, installation reports and hardware notes. Include the exact ISO and checksum result, firmware/boot mode, CPU/GPU/RAM, disk layout, the failing step and redacted `shadowfetch-health --json` output. For mission bugs, include the workflow, state and redacted receipt. Report security-sensitive findings through [SECURITY.md](SECURITY.md).

Patches to packages, build tools, tests and documentation are welcome. Run `make source-gate` before submitting. Do not post password exports, private keys, tokens, private source files or unredacted account logs.

## Licensing

The ISO aggregates upstream packages under their respective licenses. Most Shadowfetch-authored code and packaging use **GPL-3.0-or-later**; see [LICENSE](LICENSE) and each package’s copyright file. The DrKonqi pickup helper’s own code and packaging use **GPL-3.0-only**; its compiled KDE source retains **GPL-3.0-only OR LicenseRef-KDE-Accepted-GPL**. The source package includes the upstream archive, signature, release key and downstream patch. Other upstream source retains its original license notices. Shadowfetch and Umbra names, marks and artwork are reserved under [TRADEMARKS.md](TRADEMARKS.md); rebrand derivative distributions. Optional vendor applications retain their own licenses and terms. Shadowfetch Linux is independent and does not imply Debian or vendor endorsement.

[Docs](https://www.shadowfetchlinux.org/docs) · [Security model](https://www.shadowfetchlinux.org/security) · [Release feed](https://www.shadowfetchlinux.org/releases.json) · [Previous 3.5 release](RELEASE-3.5.0.md)
