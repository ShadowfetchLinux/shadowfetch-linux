# next-release/

Planning notes and staged files that are deliberately **not** in any
package. `debian/*.install` lists every shipped file explicitly by path, so
nothing in this directory can reach a build by accident.

## 3.6 planning

- [`3.6-secure-boot.md`](3.6-secure-boot.md) — what 3.6 can honestly do
  about known-issues #1 (unsigned Secure Boot) without Microsoft-trusted
  keys, without rebuilding the 3.5.0 ISO, and without spending the last
  of the 4 GiB budget. Phoenix/Fireproof snapshot rollback is already
  shipped in 3.5.0; this note does not re-open that bet.

## Staged for 2.2.0 — not shipped

Finished and tested binaries, still not in any package.

## shadowfetch-hardware

Reads `shadowfetch-facts --json` and turns two of its readings — devices with no
kernel driver bound, and firmware the kernel requested and did not get — into a
named Debian package and a command.

Tested 2026-07-26:
  * healthy machine -> "nothing to repair"
  * injected fault (unbound RTL8852BE + missing rtw89/rtw8852b_fw.bin) -> maps
    both signals to firmware-realtek
  * `--network=none` -> detects it cannot reach the archive, prints the
    packages.debian.org URL, the dpkg line and the update-initramfs step
  * warns when non-free-firmware is absent from apt sources, which is the
    blocker *after* the missing blob and explains nothing on its own

Design note: the blob-to-package map is a static table, not an apt-file lookup.
apt-file needs to download a Contents index, which needs the network, which is
the thing that is broken. A repair tool that requires working networking to
diagnose broken networking is useless exactly when it is needed.

To ship it: add a line to
`packages/shadowfetch-defaults/debian/shadowfetch-defaults.install`, move the
file into `data/usr/bin/`, and bump the changelog.

## Still to write for 2.2.0

  * shadowfetch-source — package-source recommendation (Debian vs backports vs
    Flatpak), the "software freshness confusion" pain point.
