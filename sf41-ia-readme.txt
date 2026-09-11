Shadowfetch Linux 4.1.0 (Umbra) - Egress and Syscall Filters
This is the signed 4.1.0 amd64 hybrid ISO (Fire and Ice; KDE Plasma 6; Calamares installer).
SHA-256: e19e96302f97e94d5284f8fbef181c9b0e49ca7b746afe5e66e4bc6d5c551f25
Size: 3980670976 bytes
OpenPGP fingerprint: 8F13CE1535EE1F4A2916A1F73C5C900B7BE80CA1
Source commit (ISO): 78ee38ceac0ff989d596e5a5e0b97aac17c3b936
Release-tooling commit: aa8fd1b22e8e3c8a098a28e43fd6b156fbb74b56
Verify: gpg --verify shadowfetch-4.1.0-amd64.iso.asc shadowfetch-4.1.0-amd64.iso
        sha256sum -c shadowfetch-4.1.0-amd64.iso.sha256

What is new in 4.1.0: the "Egress and Syscall Filters" release adds an nftables
egress allowlist and a loaded seccomp syscall filter to the Firebreak agent
sandbox. Read-this-first behaviour changes since 4.0.0: a mission created without
--provider now fails when more than one provider can serve the capability; a
stored approval no longer covers a mission that names new destinations; the
mission worker no longer spins a CPU core at idle (a Phase-3 regression fixed in
this build); and the Welcome/CLI copy now states an on-device model provider
ships but no model is bundled.

Website: https://www.shadowfetchlinux.org/download
Source:  https://github.com/ShadowfetchLinux/shadowfetch-linux/releases/tag/v4.1.0
License: https://www.gnu.org/licenses/gpl-3.0.html
