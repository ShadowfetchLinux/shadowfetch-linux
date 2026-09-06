#!/usr/bin/env python3
"""Focused release gates for the Shadowfetch Linux 2.1.5 maintenance release."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
import py_compile
import re
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
DEFAULTS = ROOT / "packages" / "shadowfetch-defaults"
WELCOME = ROOT / "packages" / "shadowfetch-welcome" / "src" / "shadowfetch-welcome"
CONTROL = ROOT / "packages" / "shadowfetch-control-center" / "data"
PASSPORT = DEFAULTS / "data/usr/bin/shadowfetch-passport"
CODEX = DEFAULTS / "data/usr/bin/shadowfetch-codex"
CODE_AGENTS = DEFAULTS / "data/usr/bin/shadowfetch-code-agent"
MIGRATION_HELPER = DEFAULTS / "data/usr/libexec/shadowfetch-migrate-2.1.3-ai"
MIGRATION_MANIFEST = (
    DEFAULTS / "data/usr/share/shadowfetch/migrations/2.1.3-ai-packages"
)
PLYMOUTH = (
    ROOT
    / "packages/shadowfetch-branding/data/usr/share/plymouth/themes/"
    "shadowfetch/shadowfetch.script"
)
PHOENIX_RESTORE = (
    ROOT / "packages/shadowfetch-phoenix/usr/libexec/phoenix-restore"
)


class FireEdition215Tests(unittest.TestCase):
    def test_phoenix_atomic_exchange_treats_root_as_a_path(self):
        restore = PHOENIX_RESTORE.read_text()
        self.assertIn(
            'mv --exchange --no-target-directory "$MNT/@new" "$MNT/@"',
            restore,
        )
        self.assertNotIn('mv --exchange "$MNT/@new" "$MNT/@"', restore)
        self.assertIn('grub-reboot "$submenu_id>$entry_id"', restore)
        self.assertIn('BOOT_ARCHIVE="/boot/phoenix-kernel-backup-$TS"', restore)
        self.assertIn('update-grub >/dev/null 2>&1', restore)
        self.assertIn('rollback_external_boot', restore)

    def test_release_version_and_package_versions_match(self):
        makefile = (ROOT / "Makefile").read_text()
        match = re.search(r"(?m)^VERSION\s+\?= ([0-9]+\.[0-9]+\.[0-9]+)$", makefile)
        self.assertIsNotNone(match)
        version = match.group(1)
        for changelog in (ROOT / "packages").glob("shadowfetch-*/debian/changelog"):
            first = changelog.read_text().splitlines()[0]
            self.assertIn(f"({version}-1)", first, changelog)

    def test_canonical_identity_keeps_verified_raw_artifact_routes(self):
        canonical = "https://www.shadowfetchlinux.org"
        repository = "https://github.com/ShadowfetchLinux/shadowfetch-linux"
        artifact_base = "https://www.shadowfetch.com/linux"
        os_release = (
            ROOT
            / "packages/shadowfetch-branding/data/usr/share/shadowfetch/"
            "os-release.shadowfetch"
        ).read_text()
        self.assertIn(f'HOME_URL="{canonical}/"', os_release)
        self.assertIn(f'BUG_REPORT_URL="{repository}/issues"', os_release)

        makefile = (ROOT / "Makefile").read_text()
        self.assertIn(f"PUBLIC_SITE ?= {canonical}", makefile)
        self.assertIn(f"ARTIFACT_BASE ?= {artifact_base}", makefile)

        apt_sources = (
            ROOT / "live-build/config/archives/shadowfetch.list.binary",
            ROOT / "live-build/config/hooks/0099-apt-source.hook.chroot",
            ROOT
            / "packages/shadowfetch-phoenix/usr/share/shadowfetch/apt-recovery/"
            "umbra.sources",
        )
        for source in apt_sources:
            content = source.read_text()
            self.assertIn(f"{artifact_base}/apt", content, source)
            self.assertNotIn(f"{canonical}/apt", content, source)

    def test_debian_revision_versions_use_quilt_source_format(self):
        formats = sorted((ROOT / "packages").glob("*/debian/source/format"))
        self.assertEqual(16, len(formats))
        for source_format in formats:
            self.assertEqual("3.0 (quilt)", source_format.read_text().strip())
        makefile = (ROOT / "Makefile").read_text()
        repo = makefile.split("repo: packages", 1)[1].split("\niso: repo", 1)[0]
        self.assertIn(".orig.tar.xz", repo)
        self.assertIn("--sort=name", repo)
        self.assertIn("dpkg-source -b $$pkg", repo)
        self.assertIn("debsign --no-conf -k$(REPO_KEY_ID)", repo)

    def test_retired_runtimes_are_absent_from_active_image_source(self):
        retired = re.compile(
            r"openclaw|\bhermes\b|\bollama\b|open[- ]?webui|llama\.cpp|llama-server",
            re.IGNORECASE,
        )
        roots = [
            DEFAULTS / "data",
            WELCOME,
            CONTROL,
            ROOT / "live-build" / "config" / "includes.chroot",
            ROOT / "live-build" / "config" / "package-lists",
        ]
        findings = []
        for root in roots:
            paths = [root] if root.is_file() else root.rglob("*")
            for path in paths:
                if not path.is_file() or "__pycache__" in path.parts:
                    continue
                if path == MIGRATION_MANIFEST:
                    continue
                flags = getattr(path.stat(), "st_flags", 0)
                if flags & getattr(stat, "SF_DATALESS", 0):
                    continue
                try:
                    content = path.read_text()
                except UnicodeDecodeError:
                    continue
                if retired.search(content):
                    findings.append(str(path.relative_to(ROOT)))
        self.assertEqual([], findings)

    def test_competing_model_helpers_and_package_are_removed(self):
        for path in (
            DEFAULTS / "data/usr/bin/shadowfetch-ai",
            DEFAULTS / "data/usr/bin/shadowfetch-assistant",
            DEFAULTS / "data/usr/bin/shadowfetch-llm",
            DEFAULTS / "data/usr/libexec/shadowfetch-ai-provision",
            DEFAULTS / "data/usr/share/applications/shadowfetch-ai.desktop",
            DEFAULTS / "data/usr/share/applications/shadowfetch-ai-webui.desktop",
            DEFAULTS / "data/usr/share/applications/shadowfetch-assistant.desktop",
            DEFAULTS / "data/usr/share/applications/shadowfetch-llm.desktop",
            ROOT / "live-build/config/includes.chroot/usr/local/share/applications/"
            "shadowfetch-local-ai.desktop",
            ROOT / "live-build/config/includes.chroot/usr/share/desktop-directories/"
            "shadowfetch-ai.directory",
            ROOT / "live-build/config/includes.chroot/usr/local/share/applications/"
            "shadowfetch-control-center.desktop",
            ROOT / "live-build/config/includes.chroot/usr/local/share/applications/"
            "shadowfetch-welcome.desktop",
            DEFAULTS / "data/etc/systemd/system/ollama.service.d/10-localhost.conf",
            ROOT / "packages/shadowfetch-ai-workspace",
        ):
            self.assertFalse(path.exists(), path)
        self.assertNotIn("shadowfetch-ai-workspace", (ROOT / "Makefile").read_text())
        self.assertEqual(
            [
                "shadowfetch-ai-workspace",
                "llama.cpp",
                "llama.cpp-services",
                "llama.cpp-tools",
                "llama.cpp-tools-extra",
                "libllama0",
                "whisper.cpp",
                "libwhisper1",
                "whisper.cpp-tools",
            ],
            MIGRATION_MANIFEST.read_text().splitlines(),
        )

    def test_repo_is_rebuilt_from_an_exact_package_allowlist(self):
        makefile = (ROOT / "Makefile").read_text()
        repo = makefile.split("repo: packages", 1)[1].split("\niso: repo", 1)[0]
        self.assertIn("rm -rf $(REPO_DIR)/db $(REPO_DIR)/dists $(REPO_DIR)/pool", repo)
        self.assertIn('"$$tmp/expected-binary" "$$tmp/actual-binary"', repo)
        self.assertIn('"$$tmp/expected-source" "$$tmp/actual-source"', repo)
        self.assertIn("Repo allowlist passed", repo)

    def test_iso_build_is_fresh_and_propagates_live_build_failures(self):
        makefile = (ROOT / "Makefile").read_text()
        iso = makefile.split("\niso: repo", 1)[1].split("\n# Detached GPG", 1)[0]
        self.assertIn(
            "rm -f $(ROOT)/$(ISO_NAME) $(ROOT)/$(ISO_NAME).sha256 "
            "$(ROOT)/$(ISO_NAME).asc",
            iso,
        )
        self.assertIn("set -euo pipefail", iso)
        self.assertIn('cmp "$(BUILD_DIR)/served-InRelease"', iso)
        self.assertIn("sudo lb build 2>&1 | tee", iso)
        self.assertNotIn("lb build ||", iso)
        self.assertGreaterEqual(iso.count("-nt $(LB_BUILD_MARKER)"), 2)
        self.assertIn("xargs -0 sha256sum > SHA256SUMS", iso)
        self.assertIn("sha256sum --check --quiet SHA256SUMS", iso)
        self.assertIn("sha256sum --check", iso)
        self.assertIn("--verify $(ROOT)/$(ISO_NAME).asc", makefile)
        self.assertIn("@$(MAKE) iso-gate", iso)
        self.assertIn(
            "ISO_GATE := $(ROOT)/tools/iso_gate_$(VERSION_TOKEN).py",
            makefile,
        )
        self.assertIn("ISO_GATE_LOG", makefile)

    def test_first_boot_uses_utc_rtc_and_network_time(self):
        firstboot = (
            DEFAULTS / "data/usr/lib/shadowfetch/firstboot.sh"
        ).read_text()
        core_packages = (
            ROOT / "live-build/config/package-lists/shadowfetch-core.list.chroot"
        ).read_text().splitlines()
        self.assertIn(
            "timedatectl set-local-rtc 0 --adjust-system-clock", firstboot
        )
        self.assertNotIn("timedatectl set-local-rtc 1", firstboot)
        self.assertIn(
            "systemctl enable --now systemd-timesyncd.service", firstboot
        )
        self.assertIn("systemd-timesyncd", core_packages)

    def test_plymouth_has_visible_unlock_prompt_and_safe_status_rendering(self):
        script = PLYMOUTH.read_text()
        self.assertIn("UNLOCK ENCRYPTED DRIVE", script)
        self.assertIn("Enter your disk passphrase, then press Enter", script)
        self.assertIn("Plymouth.SetDisplayPasswordFunction", script)
        self.assertIn("Plymouth.SetDisplayPromptFunction", script)
        self.assertIn("if (is_secret)", script)
        self.assertIn("Plymouth.SetDisplayNormalFunction", script)
        self.assertIn('Image("dot-gold.png").Scale', script)
        self.assertNotIn("Plymouth.GetTime", script)
        self.assertNotIn("Plymouth.SetUpdateStatusFunction", script)
        self.assertNotIn("Image.Text(text", script)

    def test_installed_ssh_is_reachable_through_the_default_firewall(self):
        firstboot = (
            DEFAULTS / "data/usr/lib/shadowfetch/firstboot.sh"
        ).read_text()
        postinst = (DEFAULTS / "debian/postinst").read_text()
        for script in (firstboot, postinst):
            self.assertIn("ufw limit OpenSSH", script)
            self.assertIn("ufw limit 22/tcp", script)
        self.assertIn('"$1" = "configure"', postinst)
        self.assertIn("ssh-keygen -A", postinst)
        self.assertIn("systemctl reset-failed ssh.service", postinst)
        self.assertIn("systemctl restart ssh.service", postinst)
        self.assertIn("/etc/ssh/ssh_host_ed25519_key", postinst)
        self.assertIn("/etc/ssh/ssh_host_rsa_key", postinst)


    def test_codex_upstream_contract_is_locked(self):
        lock = json.loads((ROOT / "qa/3.5.0/upstream-codex.json").read_text())
        helper = CODEX.read_text()
        self.assertEqual("0.150.1", lock["release"])
        self.assertEqual(
            "https://learn.chatgpt.com/docs/codex/cli", lock["documentation"]
        )
        self.assertEqual(
            "https://chatgpt.com/codex/install.sh", lock["installer"]["url"]
        )
        self.assertRegex(lock["installer"]["sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual("desktop-user", lock["installation"]["scope"])
        self.assertFalse(lock["installation"]["credentials_embedded"])
        self.assertTrue(
            lock["installation"]["archive_digest_verified_by_upstream_installer"]
        )
        self.assertIn(f'CODEX_VERSION="{lock["release"]}"', helper)
        self.assertIn(f'INSTALLER_URL="{lock["installer"]["url"]}"', helper)
        self.assertIn(f'INSTALLER_SHA256="{lock["installer"]["sha256"]}"', helper)

    def test_codex_setup_is_opt_in_verified_and_user_owned(self):
        helper = CODEX.read_text()
        welcome = WELCOME.read_text()
        install_manifest = (
            DEFAULTS / "debian/shadowfetch-defaults.install"
        ).read_text()
        self.assertIn('"label": "OpenAI Codex CLI"', welcome)
        self.assertIn("checkbox.setChecked(False)", welcome)
        self.assertIn('self._on_next({"coding_agents": coding_agents})', welcome)
        self.assertIn("Official Codex installer SHA-256 verified", helper)
        self.assertIn("sha256sum --check --status", helper)
        self.assertIn("--proto '=https'", helper)
        self.assertIn("CODEX_NON_INTERACTIVE=true", helper)
        self.assertIn("CODEX_INSTALLER_USE_RELEASES_OPENAI_COM=true", helper)
        self.assertIn('if ((EUID == 0))', helper)
        self.assertIn('BIN_DIR="${CODEX_INSTALL_DIR:-$HOME/.local/bin}"', helper)
        self.assertIn("No OpenAI credential was stored by Shadowfetch", helper)
        self.assertNotIn("OPENAI_API_KEY", helper)
        self.assertNotIn("auth.json", helper)
        self.assertNotRegex(helper, r"curl[^\n|]*\|\s*(?:ba)?sh\b")
        self.assertIn("data/usr/bin/shadowfetch-codex", install_manifest)
        self.assertIn("data/usr/share/doc/shadowfetch/CODEX.md", install_manifest)


    def test_additional_coding_agents_are_locked_and_user_owned(self):
        lock = json.loads(
            (ROOT / "qa/2.1.5/upstream-coding-agents.json").read_text()
        )
        helper = CODE_AGENTS.read_text()
        expected = {
            "claude": (
                "2.1.227",
                "https://downloads.claude.ai/claude-code-releases/2.1.227/linux-x64/claude",
                "6832dc3f1797b890b71116e5f2dbbf9a83fd3d0498c235b4b0f9cd0e6e499ad6",
                "claude",
            ),
            "grok": (
                "1.0.5",
                "https://x.ai/cli/grok-1.0.5-linux-x86_64",
                "9ba87444e1819e8f6104adbbf4676a870c204380aa5c3e1c38a926c4ea677238",
                "grok",
            ),
            "cursor": (
                "2026.08.11-e8db854",
                "https://downloads.cursor.com/lab/2026.08.11-e8db854/linux/x64/agent-cli-package.tar.gz",
                "bfff4bf6f4e9dd30c1d0ef0a70b6077b074015dd2948e4c50685d53afdcfce5a",
                "cursor-agent",
            ),
        }
        self.assertEqual("linux-x86_64", lock["platform"])
        self.assertEqual("desktop-user", lock["installation"]["scope"])
        self.assertFalse(lock["installation"]["selected_by_default"])
        self.assertFalse(lock["installation"]["credentials_embedded"])
        self.assertFalse(lock["installation"]["credentials_copied_by_shadowfetch"])
        self.assertFalse(lock["installation"]["failure_blocks_base_setup"])
        for key, (release, url, digest, command) in expected.items():
            agent = lock["agents"][key]
            self.assertEqual(release, agent["release"])
            self.assertEqual(url, agent["artifact"]["url"])
            self.assertEqual(digest, agent["artifact"]["sha256"])
            self.assertEqual(command, agent["command"])
            self.assertIn(f'VERSION="{release}"', helper)
            self.assertIn(f'ARTIFACT_URL="{url}"', helper)
            self.assertIn(f'ARTIFACT_SHA256="{digest}"', helper)

    def test_coding_agent_choices_are_grouped_verified_and_independent(self):
        helper = CODE_AGENTS.read_text()
        welcome = WELCOME.read_text()
        install_manifest = (
            DEFAULTS / "debian/shadowfetch-defaults.install"
        ).read_text()
        for label in (
            "OpenAI Codex CLI",
            "Anthropic Claude Code",
            "xAI Grok Build",
            "Cursor Agent",
        ):
            self.assertIn(label, welcome)
        self.assertIn("Coding agents", welcome)
        self.assertIn("Select available agents", welcome)
        self.assertIn("QGridLayout", welcome)
        self.assertIn("agent_grid.addWidget(card, index // 2, index % 2)", welcome)
        self.assertIn("checkbox.setChecked(False)", welcome)
        self.assertIn('"coding_agents": coding_agents', welcome)
        self.assertIn("for agent in CODING_AGENTS", welcome)
        self.assertIn('command.extend(["setup", "--yes", "--no-open"])', welcome)
        self.assertIn("sha256sum --check --status", helper)
        self.assertIn("--proto '=https'", helper)
        self.assertIn('if ((EUID == 0))', helper)
        self.assertIn('BIN_DIR="${SHADOWFETCH_CODE_AGENT_BIN_DIR:-$HOME/.local/bin}"', helper)
        self.assertIn("credentials_stored_by_shadowfetch=false", helper)
        self.assertNotIn("API_KEY", helper)
        self.assertNotIn("auth.json", helper)
        self.assertNotRegex(helper, r"curl[^\n|]*\|\s*(?:ba)?sh\b")
        self.assertNotIn('"$BIN_DIR/agent"', helper)
        self.assertIn("data/usr/bin/shadowfetch-code-agent", install_manifest)
        self.assertIn("data/usr/share/doc/shadowfetch/CODING-AGENTS.md", install_manifest)

    def test_nvidia_rtx_5080_contract_is_locked(self):
        lock = json.loads((ROOT / "qa/2.1.5/upstream-nvidia.json").read_text())
        self.assertTrue(lock["repository"]["signature_verified"])
        self.assertRegex(lock["repository"]["signing_fingerprint"], r"^[0-9A-F]{40}$")
        self.assertEqual("0x2C02", lock["rtx_5080"]["pci_device_id"])
        self.assertTrue(lock["rtx_5080"]["open_kernel_supported"])
        self.assertRegex(lock["keyring"]["sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(
            lock["driver_assistant"]["supported_gpus_sha256"],
            r"^[0-9a-f]{64}$",
        )
        self.assertRegex(
            lock["release_time_packages"]["nvidia_open"]["version"],
            r"^610\.",
        )

    def test_legacy_nvidia_metapackage_installs_no_driver(self):
        control = (ROOT / "packages/shadowfetch-meta/debian/control").read_text()
        nvidia = control.split("Package: shadowfetch-nvidia", 1)[1]
        for package in (
            "nvidia-driver",
            "nvidia-settings",
            "nvidia-vaapi-driver",
            "libnvidia-encode1",
            "firmware-nvidia-gsp",
        ):
            self.assertNotRegex(nvidia, rf"(?m)^ {re.escape(package)},?$")
        self.assertIn("shadowfetch-defaults (= ${binary:Version})", nvidia)
        self.assertIn("Run shadowfetch-gpu", nvidia)

    def test_current_source_packages_target_umbra(self):
        package_names = (
            "shadowfetch-meta", "shadowfetch-welcome", "shadowfetch-themes",
            "shadowfetch-defaults", "shadowfetch-branding", "grub-btrfs",
            "shadowfetch-ember", "shadowfetch-firewatchd", "shadowfetch-phoenix",
            "shadowfetch-menus", "shadowfetch-control-center",
            "shadowfetch-fireproof", "shadowfetch-hwscan",
        )
        for package in package_names:
            first = (ROOT / "packages" / package / "debian/changelog").read_text().splitlines()[0]
            self.assertIn(") umbra; urgency=", first, package)

    def test_fireproof_uses_current_polkit_and_packaging_helpers(self):
        control = (ROOT / "packages/shadowfetch-fireproof/debian/control").read_text()
        postinst = (ROOT / "packages/shadowfetch-fireproof/debian/postinst").read_text()
        postrm = (ROOT / "packages/shadowfetch-fireproof/debian/postrm").read_text()
        self.assertNotIn("policykit-1", control)
        self.assertRegex(control, r"(?m)^ polkitd,$")
        self.assertRegex(control, r"(?m)^ pkexec,$")
        for script in (postinst, postrm):
            self.assertIn("deb-systemd-helper", script)
            self.assertNotRegex(script, r"(?m)^\s*systemctl\b")


    def test_live_user_cleanup_requires_a_nonempty_account_name(self):
        cleanup = (
            ROOT
            / "live-build/config/includes.chroot/usr/local/sbin/"
            "sf-remove-live-user"
        ).read_text()
        self.assertIn("LIVE_USER=shadow", cleanup)
        self.assertIn('rm -rf -- "/home/${LIVE_USER:?}"', cleanup)
        self.assertNotIn('rm -rf "/home/$USER"', cleanup)
        self.assertIn('grep -q "^${LIVE_USER}:" /etc/shadow', cleanup)

    def test_installed_manifest_keeps_workspaces_and_no_retired_launchers(self):
        manifest = (DEFAULTS / "debian/shadowfetch-defaults.install").read_text()
        for expected in (
            "data/usr/libexec/shadowfetch-migrate-2.1.3-ai",
            "data/usr/lib/systemd/system/shadowfetch-migrate-2.1.3-ai.service",
            "data/usr/share/shadowfetch/migrations/2.1.3-ai-packages",
            "data/usr/bin/shadowfetch-passport",
        ):
            self.assertIn(expected, manifest)
        self.assertNotRegex(
            manifest,
            re.compile(r"openclaw|hermes|shadowfetch-(?:assistant|llm|ai)(?:\s|\.)", re.I),
        )
        self.assertNotIn("80shadowfetch-snapshot", manifest)
        self.assertNotIn("apt-snapshot.sh", manifest)
        self.assertFalse(
            (DEFAULTS / "data/etc/apt/apt.conf.d/80shadowfetch-snapshot").exists()
        )
        self.assertFalse(
            (DEFAULTS / "data/usr/lib/shadowfetch/apt-snapshot.sh").exists()
        )

    def test_runtime_dependencies_cover_first_run_preflight(self):
        control = (DEFAULTS / "debian/control").read_text()
        depends = control.split("Depends:", 1)[1].split("Recommends:", 1)[0]
        for package in (
            "curl",
            "iproute2",
            "konsole",
            "libnotify-bin",
            "pciutils",
            "pkexec",
            "polkitd",
            "podman",
            "psmisc",
            "sudo",
            "vulkan-tools",
            "wl-clipboard",
            "xclip",
            "xdg-utils",
        ):
            self.assertRegex(depends, rf"(?m)^ {re.escape(package)},?$", package)
        self.assertNotRegex(depends, r"(?m)^ zstd,?$")

    def test_vendor_units_and_udev_rules_use_vendor_paths(self):
        manifest = (DEFAULTS / "debian/shadowfetch-defaults.install").read_text()
        for name in (
            "flatpak-system-update.service",
            "flatpak-system-update.timer",
            "rfkill-unblock.service",
            "shadowfetch-regdomain.service",
        ):
            self.assertIn(f"data/usr/lib/systemd/system/{name}", manifest)
            self.assertFalse((DEFAULTS / "data/etc/systemd/system" / name).exists())
        rule = "60-shadowfetch-ioschedulers.rules"
        self.assertIn(f"data/usr/lib/udev/rules.d/{rule}", manifest)
        self.assertFalse((DEFAULTS / "data/etc/udev/rules.d" / rule).exists())
        maintscript = (DEFAULTS / "debian/shadowfetch-defaults.maintscript").read_text()
        for old_path in (
            "/etc/systemd/system/flatpak-system-update.service",
            "/etc/systemd/system/flatpak-system-update.timer",
            "/etc/systemd/system/rfkill-unblock.service",
            "/etc/systemd/system/shadowfetch-regdomain.service",
            "/etc/udev/rules.d/60-shadowfetch-ioschedulers.rules",
            "/etc/apt/apt.conf.d/80shadowfetch-snapshot",
            "/etc/systemd/system/ollama.service.d/10-localhost.conf",
        ):
            self.assertIn(f"rm_conffile {old_path} 2.1.4-1~", maintscript)

    def test_pre_2_1_4_postinst_marks_retirement_without_deleting_user_data(self):
        postinst = (DEFAULTS / "debian/postinst").read_text()
        self.assertIn('dpkg --compare-versions "$2" lt \'2.1.4~\'', postinst)
        self.assertIn("2.1.3-ai.pending", postinst)
        self.assertIn("systemctl disable --now llama-server.service", postinst)
        self.assertIn(
            "a458253d5a6b22fbb3c73677ba88d7d87307da985b85ba6d1935dec5f51ffc92",
            postinst,
        )
        self.assertNotRegex(postinst, r"rm\s+-rf\s+/(?:home|var/lib)")

    def test_retired_package_helper_has_an_exact_no_data_deletion_contract(self):
        helper = MIGRATION_HELPER.read_text()
        unit = (
            DEFAULTS
            / "data/usr/lib/systemd/system/shadowfetch-migrate-2.1.3-ai.service"
        ).read_text()
        self.assertIn(
            "6eeddfe229f65e64288c34b88e23ad19a859de31688d73d29817244f064d6dd5",
            helper,
        )
        self.assertIn("apt-get -s", helper)
        self.assertIn('cmp -s "$temporary/expected" "$temporary/planned"', helper)
        self.assertIn('remove "${installed[@]}"', helper)
        self.assertNotIn("purge", helper)
        self.assertNotRegex(helper, r"rm\s+-rf\s+/(?:home|var/lib)")
        self.assertIn("ConditionPathExists=", unit)
        self.assertIn("ExecCondition=", unit)
        self.assertIn("SuccessExitStatus=75", unit)

    def test_systemd_units_do_not_use_invalid_directive_names(self):
        invalid = ("ConditionPathIsExecutable=", "ProtectClocks=")
        findings = []
        for path in (ROOT / "packages").glob("shadowfetch-*/data/**/*.service"):
            content = path.read_text()
            for directive in invalid:
                if directive in content:
                    findings.append(f"{path.relative_to(ROOT)}: {directive}")
        self.assertEqual([], findings)

    def test_packaged_launchers_have_one_owner_and_one_main_category(self):
        main_categories = {
            "AudioVideo", "Audio", "Video", "Development", "Education",
            "Game", "Graphics", "Network", "Office", "Science", "Settings",
            "System", "Utility",
        }
        owners = {}
        installed_sources = set()
        for package in (ROOT / "packages").iterdir():
            if not package.is_dir():
                continue
            for manifest in (package / "debian").glob("*.install"):
                for raw_line in manifest.read_text().splitlines():
                    line = raw_line.strip()
                    if not line or line.startswith("#"):
                        continue
                    fields = line.split()
                    if len(fields) < 2 or "usr/share/applications" not in fields[-1]:
                        continue
                    source = package / fields[0]
                    self.assertTrue(source.is_file(), source)
                    target = f"usr/share/applications/{source.name}"
                    self.assertNotIn(
                        target,
                        owners,
                        f"{target}: {owners.get(target)} and {source}",
                    )
                    owners[target] = source
                    installed_sources.add(source.resolve())
                    content = source.read_text()
                    match = re.search(r"(?m)^Categories=([^\n]+)$", content)
                    self.assertIsNotNone(match, source)
                    categories = {value for value in match.group(1).split(";") if value}
                    selected = categories & main_categories
                    self.assertEqual(1, len(selected), f"{source}: {sorted(selected)}")
            for source_root in (
                package / "data/usr/share/applications",
                package / "usr/share/applications",
            ):
                if source_root.is_dir():
                    for source in source_root.glob("*.desktop"):
                        self.assertIn(
                            source.resolve(),
                            installed_sources,
                            f"unused launcher: {source}",
                        )
        self.assertIn("usr/share/applications/shadowfetch-agent-workspace.desktop", owners)


    def test_welcome_catalog_has_no_model_download_records(self):
        catalog = (
            ROOT
            / "packages/shadowfetch-welcome/data/usr/share/shadowfetch/welcome/catalog"
        )
        records = [json.loads(path.read_text()) for path in catalog.glob("*.json")]
        self.assertTrue(records)
        self.assertNotIn("model", {record["kind"] for record in records})
        self.assertEqual([], list(catalog.glob("model-*.json")))
        readme = (catalog / "README").read_text()
        self.assertNotIn("Buzz's native Compute workflow", readme)
        self.assertNotIn("shadowfetch-ai", readme)


    def test_shipped_programs_and_build_hooks_are_executable(self):
        paths = (
            MIGRATION_HELPER,
            DEFAULTS / "data/usr/bin/shadowfetch-gpu",
            DEFAULTS / "data/usr/bin/shadowfetch-update",
            DEFAULTS / "data/usr/bin/shadowfetch-agent-workspace",
            PASSPORT,
            ROOT / "live-build/config/hooks/0020-gpu-firstboot.hook.chroot",
            WELCOME,
        )
        for path in paths:
            self.assertTrue(os.access(path, os.X_OK), path)

    def test_shell_and_python_entrypoints_parse(self):
        shell_files = [
            MIGRATION_HELPER,
            DEFAULTS / "data/usr/bin/shadowfetch-gpu",
            DEFAULTS / "data/usr/bin/shadowfetch-update",
            DEFAULTS / "data/usr/bin/shadowfetch-agent-workspace",
        ]
        for path in shell_files:
            result = subprocess.run(
                ["bash", "-n", str(path)], capture_output=True, text=True
            )
            self.assertEqual(0, result.returncode, result.stderr)
        python_files = (
            WELCOME,
            DEFAULTS / "data/usr/bin/shadowfetch-health",
            DEFAULTS / "data/usr/bin/shadowfetch-facts",
            PASSPORT,
            CONTROL / "usr/share/shadowfetch/control-center/sfcc/app.py",
            CONTROL / "usr/share/shadowfetch/control-center/sfcc/guide_page.py",
            CONTROL / "usr/share/shadowfetch/control-center/sfcc/agents_page.py",
            CONTROL / "usr/share/shadowfetch/control-center/sfcc/firewatch_page.py",
        )
        with tempfile.TemporaryDirectory() as temporary:
            for index, path in enumerate(python_files):
                py_compile.compile(
                    str(path),
                    cfile=str(Path(temporary) / f"{index}.pyc"),
                    doraise=True,
                )

    @staticmethod
    def _passport_module(name):
        loader = importlib.machinery.SourceFileLoader(name, str(PASSPORT))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        module = importlib.util.module_from_spec(spec)
        loader.exec_module(module)
        return module

    def test_system_passport_is_allowlisted_redacted_and_ready(self):
        module = self._passport_module("sf_passport_qa")

        def section(data):
            return {"available": True, "source": "fixture", "data": data}

        facts = {"facts": {
            "system": section({
                "hostname": "private-workstation",
                "os_name": "Shadowfetch Linux",
                "kernel": "6.12.0",
                "arch": "x86_64",
                "virtualisation": "none",
                "container": False,
            }),
            "graphics": section({
                "cards": [{"name": "Test GPU", "driver": "amdgpu",
                           "slot": "0000:01:00.0"}],
                "renderer": "AMD Radeon Test",
                "accelerated": True,
                "software_rendering": False,
            }),
            "network": section({
                "interfaces": [{
                    "name": "wlan0", "state": "UP",
                    "mac": "aa:bb:cc:dd:ee:ff", "driver": "iwlwifi",
                    "wireless": True,
                }],
                "has_carrier": True,
            }),
            "devices": section({
                "devices": [{
                    "slot": "0000:00:1f.3", "class": "Audio device",
                    "name": "Private Audio", "driver": "snd_hda_intel",
                }],
                "unbound_count": 0,
                "unbound_important": [],
            }),
            "firmware": section({"missing_count": 0, "missing": []}),
            "memory": section({"total_gib": 16.0, "available_gib": 12.0}),
            "storage": section({
                "root_free_gib": 120.0,
                "root_used_pct": 20,
                "btrfs_root": True,
                "snapper_present": True,
                "filesystems": [{
                    "mount": "/", "device": "/dev/nvme0n1p2",
                }],
            }),
            "packages": section({"dpkg_consistent": True}),
            "services": section({"failed_count": 0, "failed_units": []}),
        }}
        hwscan = {
            "gpus": [{"flags": []}],
            "verdict": {
                "sentence": "This machine can run local models.",
                "suffixes": [],
            },
        }
        probes = {
            "live_session": False,
            "camera_count": 1,
            "bluetooth_count": 1,
            "audio_session": "ready",
            "disk_count": 1,
            "largest_disk_gib": 512.0,
            "uefi": True,
            "secure_boot": "disabled",
        }
        passport = module.build_passport(
            facts, hwscan, probes, release_version="2.1.5",
            generated_at="2026-08-18T00:00:00Z",
        )
        encoded = json.dumps(passport)
        self.assertEqual("ready", passport["verdict"]["status"])
        self.assertEqual([], module.privacy_issues(passport))
        for secret in (
            "private-workstation",
            "aa:bb:cc:dd:ee:ff",
            "0000:01:00.0",
            "0000:00:1f.3",
            "/dev/nvme0n1p2",
            "wlan0",
        ):
            self.assertNotIn(secret, encoded)
        self.assertTrue(passport["privacy"]["local_only"])
        self.assertFalse(passport["privacy"]["upload_performed"])
        report = module.html_report(passport)
        self.assertIn("Shadowfetch System Passport", report)
        self.assertNotIn("private-workstation", report)

    def test_system_passport_escalates_real_compatibility_failures(self):
        module = self._passport_module("sf_passport_attention_qa")
        unavailable = {
            "available": False,
            "source": "fixture",
            "note": "missing",
        }
        facts = {"facts": {
            "system": {"available": True, "source": "fixture", "data": {
                "os_name": "Shadowfetch Linux",
                "kernel": "6.12.0",
                "arch": "x86_64",
                "virtualisation": "none",
                "container": False,
            }},
            "graphics": {"available": True, "source": "fixture", "data": {
                "cards": [{"name": "GPU", "driver": None}],
                "renderer": "llvmpipe",
                "accelerated": False,
                "software_rendering": True,
            }},
            "network": {"available": True, "source": "fixture", "data": {
                "interfaces": [],
                "has_carrier": False,
            }},
            "devices": unavailable,
            "firmware": unavailable,
            "memory": {"available": True, "source": "fixture",
                       "data": {"total_gib": 3.0}},
            "storage": {"available": True, "source": "fixture", "data": {
                "root_free_gib": 4.0,
                "btrfs_root": False,
                "snapper_present": False,
            }},
            "packages": {"available": True, "source": "fixture",
                         "data": {"dpkg_consistent": False}},
            "services": {"available": True, "source": "fixture",
                         "data": {"failed_count": 2}},
        }}
        probes = {
            "live_session": False,
            "camera_count": 0,
            "bluetooth_count": 0,
            "audio_session": "unknown",
            "disk_count": 0,
            "largest_disk_gib": None,
            "uefi": False,
            "secure_boot": "not-available",
        }
        passport = module.build_passport(facts, None, probes, "2.1.5")
        self.assertEqual("needs-attention", passport["verdict"]["status"])
        self.assertGreaterEqual(passport["verdict"]["attention_count"], 4)
        routes = {
            item.get("route") for item in passport["checks"]
            if item["status"] == "attention"
        }
        self.assertIn("drivers", routes)
        self.assertIn("software", routes)


    def test_missions_are_first_and_live_setup_keeps_the_passport(self):
        app = (
            CONTROL / "usr/share/shadowfetch/control-center/sfcc/app.py"
        ).read_text()
        guide = (
            CONTROL / "usr/share/shadowfetch/control-center/sfcc/guide_page.py"
        ).read_text()
        welcome = WELCOME.read_text()
        control_manifest = (
            ROOT / "packages/shadowfetch-control-center/debian/"
            "shadowfetch-control-center.install"
        ).read_text()
        self.assertRegex(app, r"SECTIONS\s*=\s*\[\s*\(\"missions\"")
        self.assertIn('"passport": "guide"', app)
        self.assertIn("GuidePage(self.open_route)", app)
        self.assertIn("shadowfetch-passport", guide)
        self.assertIn("Nothing is uploaded", guide)
        self.assertGreaterEqual(welcome.count("Check this computer"), 2)
        self.assertIn('[control, "--page", "guide"]', welcome)
        self.assertIn("guide_page.py", control_manifest)
        self.assertIn("shadowfetch-guide.desktop", control_manifest)

    def test_first_run_reclaims_focus_after_plasma_splash(self):
        welcome = WELCOME.read_text()
        self.assertIn('if mode in ("ignition", "wizard"):', welcome)
        self.assertIn(
            "QTimer.singleShot(2500, self._activate_window)", welcome
        )
        self.assertIn("def _activate_window(self):", welcome)
        self.assertIn("if win is None or not win.isVisible():", welcome)

    @unittest.skipUnless(importlib.util.find_spec("PyQt6"), "PyQt6 is not installed")
    def test_guide_verdict_badge_has_contrasting_text(self):
        control_center = (
            CONTROL / "usr/share/shadowfetch/control-center"
        )
        script = textwrap.dedent(
            f"""
            import sys
            sys.path.insert(0, {str(control_center)!r})

            from PyQt6.QtWidgets import QApplication
            from sfcc.guide_page import GuidePage

            app = QApplication([])
            page = GuidePage(lambda _route: None)
            page._started = True
            page._render({{
                "verdict": {{
                    "status": "ready-with-notes",
                    "title": "Ready with one note",
                    "summary": "One optional driver is recommended.",
                }},
                "context": {{
                    "mode": "live-session",
                    "operating_system": "Shadowfetch Linux 2.1.5",
                    "architecture": "x86_64",
                }},
                "capabilities": {{}},
                "checks": [],
            }})
            assert page.state.text() == "Ready with notes"
            style = page.state.styleSheet()
            assert "background: #d8a24a" in style
            assert "color: #151515" in style
            page.show()
            app.processEvents()
            page.close()
            """
        )
        env = os.environ.copy()
        env["QT_QPA_PLATFORM"] = "offscreen"
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            env=env,
            timeout=20,
        )
        self.assertEqual(0, result.returncode, result.stderr)

    @unittest.skipUnless(importlib.util.find_spec("PyQt6"), "PyQt6 is not installed")
    def test_welcome_stylesheet_parses_in_offscreen_qt(self):
        script = textwrap.dedent(
            f"""
            import importlib.machinery
            import importlib.util
            from pathlib import Path

            path = Path({str(WELCOME)!r})
            loader = importlib.machinery.SourceFileLoader("sf_welcome_qa", str(path))
            spec = importlib.util.spec_from_loader(loader.name, loader)
            module = importlib.util.module_from_spec(spec)
            loader.exec_module(module)
            app = module.QApplication([])
            window = module.ShadowfetchWelcome(mode="catalog")
            window.show()
            app.processEvents()
            window.close()
            """
        )
        env = os.environ.copy()
        env["QT_QPA_PLATFORM"] = "offscreen"
        with tempfile.TemporaryDirectory() as home:
            env["HOME"] = home
            result = subprocess.run(
                [sys.executable, "-c", script],
                capture_output=True,
                text=True,
                env=env,
                timeout=20,
            )
        self.assertEqual(0, result.returncode, result.stderr)

    @unittest.skipUnless(importlib.util.find_spec("PyQt6"), "PyQt6 is not installed")
    def test_coding_agent_selector_and_queue_are_independent(self):
        script = textwrap.dedent(
            f"""
            import importlib.machinery
            import importlib.util
            from pathlib import Path

            path = Path({str(WELCOME)!r})
            loader = importlib.machinery.SourceFileLoader("sf_agent_choice_qa", str(path))
            spec = importlib.util.spec_from_loader(loader.name, loader)
            module = importlib.util.module_from_spec(spec)
            loader.exec_module(module)
            app = module.QApplication([])

            submitted = []
            module.ELEMENT = "fire"
            choice = module.AgentSetupPage(submitted.append)
            assert tuple(choice.coding_agents) == ("grok-bot", "codex", "claude", "grok", "cursor")
            assert not any(box.isChecked() for box in choice.coding_agents.values())
            choice.select_all_agents.setChecked(True)
            assert all(box.isChecked() for box in choice.coding_agents.values())
            choice.coding_agents["grok"].setChecked(False)
            assert not choice.select_all_agents.isChecked()
            choice._submit()
            assert submitted[-1]["coding_agents"] == {{
                "grok-bot": True, "codex": True, "claude": True, "grok": False, "cursor": True,
            }}

            install = module.InstallPage(lambda: None)
            install.coding_agent_states = {{
                "grok-bot": "not-requested", "codex": "failed", "claude": "pending",
                "grok": "pending", "cursor": "pending",
            }}
            started = []
            install._start_coding_agent_setup = lambda agent: started.append(agent["key"])
            install._start_next_ai()
            assert started == ["claude"]
            install.coding_agent_states["claude"] = "failed"
            install._start_next_ai()
            assert started == ["claude", "grok"]
            """
        )
        env = os.environ.copy()
        env["QT_QPA_PLATFORM"] = "offscreen"
        with tempfile.TemporaryDirectory() as home:
            env["HOME"] = home
            result = subprocess.run(
                [sys.executable, "-c", script],
                capture_output=True,
                text=True,
                env=env,
                timeout=20,
            )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertNotIn("Could not parse stylesheet", result.stderr)

    def test_help_paths_are_read_only(self):
        paths = (
            DEFAULTS / "data/usr/bin/shadowfetch-gpu",
            DEFAULTS / "data/usr/bin/shadowfetch-agent-workspace",
        )
        for path in paths:
            result = subprocess.run(
                ["bash", str(path), "--help"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            self.assertEqual(0, result.returncode, f"{path}: {result.stderr}")
            self.assertIn("USAGE", result.stdout, path)


    def test_welcome_cancellation_escalates_without_blocking_the_ui(self):
        welcome = WELCOME.read_text()
        command_worker = welcome.split("class CommandWorker", 1)[1].split(
            "class StreamingCommandWorker", 1
        )[0]
        worker = welcome.split("class StreamingCommandWorker", 1)[1].split(
            "class Card", 1
        )[0]
        for content in (command_worker, worker):
            for expected in (
                "start_new_session=True",
                "threading.Thread",
                "os.killpg",
                "signal.SIGINT",
                "signal.SIGTERM",
                "signal.SIGKILL",
            ):
                self.assertIn(expected, content)
        self.assertNotIn("subprocess.run", command_worker)
        self.assertIn(
            'for name in ("coding_agent_worker", "worker")', welcome
        )
        self.assertIn("worker.cancel()", welcome)
        self.assertIn("Setup is still running", welcome)
        self.assertIn("Cancel setup", welcome)
        self.assertIn("Retry failed tools", welcome)

    def test_user_workspace_helpers_reject_unsafe_invocation(self):
        workspace = (DEFAULTS / "data/usr/bin/shadowfetch-agent-workspace").read_text()
        self.assertIn("EUID != 0", workspace)
        self.assertIn('[[ "$ROOT" != / ]]', workspace)
        self.assertIn("realpath -m", workspace)
        self.assertGreaterEqual(workspace.count('"$safe" != ..'), 1)
        self.assertIn('"$name" != ..', workspace)


    def test_no_shipped_helper_uses_an_unverified_pipe_installer(self):
        for directory in (DEFAULTS / "data/usr/bin", DEFAULTS / "data/usr/libexec"):
            for path in directory.iterdir():
                if not path.is_file():
                    continue
                try:
                    content = path.read_text()
                except UnicodeDecodeError:
                    continue
                self.assertNotRegex(
                    content, r"curl[^\n|]*\|\s*(?:ba)?sh\b", path
                )

    def test_graphics_claims_require_measured_hardware_renderer(self):
        welcome = WELCOME.read_text()
        gpu = (DEFAULTS / "data/usr/bin/shadowfetch-gpu").read_text()
        hook = (
            ROOT / "live-build/config/hooks/0020-gpu-firstboot.hook.chroot"
        ).read_text()
        self.assertNotIn("already give you full acceleration", welcome)
        for content in (welcome, gpu, hook):
            self.assertRegex(content, r"llvmpipe.*lavapipe")
            self.assertIn("vulkaninfo", content)
        self.assertIn("No DRM render node", gpu)
        self.assertIn("/dev/dri/renderD*", gpu)
        self.assertIn("--distro debian:13", gpu)
        self.assertIn("apt_install_no_remove", gpu)
        self.assertIn("-s install", gpu)
        self.assertIn("--no-remove install -y", gpu)
        self.assertIn("grep -q '^Remv '", gpu)
        self.assertNotIn("nvidia-driver-assistant --install", gpu)
        self.assertIn('DRIVER_CLEANUP_DIR=""', gpu)
        self.assertIn('DRIVER_RECOVERY_POINT=""', gpu)
        self.assertIn(
            "Phoenix Point ${DRIVER_RECOVERY_POINT} is available for recovery",
            gpu,
        )
        self.assertRegex(
            gpu,
            r"recommended.*\^\(nvidia-open\|cuda-drivers\)",
        )

    def test_update_simulates_twice_and_refuses_unverified_removals(self):
        update = (DEFAULTS / "data/usr/bin/shadowfetch-update").read_text()
        self.assertIn("apt-get -s", update)
        self.assertIn("/^Remv /", update)
        self.assertIn("validate_removals", update)
        self.assertIn("plan_fingerprint", update)
        self.assertIn("will not apply unverified package removals", update)
        self.assertIn("libprocesscore10", update)
        self.assertIn("libprocesscore11", update)
        self.assertIn("qml6-module-org-kde-milou", update)
        self.assertIn("transaction=(--no-remove full-upgrade)", update)
        self.assertIn("flock -n", update)
        self.assertIn("80snapper", update)
        self.assertIn("write_snapper_rows", update)
        self.assertIn("snapper_first_pre_after", update)
        self.assertRegex(
            update,
            re.compile(r"load_migration_plan\(\).*?\n    return 0\n}", re.S),
        )
        self.assertNotRegex(update, r"\$\([^)]*snapper_rows")
        self.assertNotRegex(update, r"snapper[^\n]*create")
        self.assertIn("trap cleanup EXIT", update)
        self.assertNotRegex(update, r"trap\s+['\"]")

    def test_branding_refreshes_os_release_after_package_updates(self):
        branding = ROOT / "packages/shadowfetch-branding/debian"
        postinst = (branding / "postinst").read_text()
        triggers = (branding / "triggers").read_text()
        self.assertIn("configure|triggered", postinst)
        self.assertIn("/usr/share/shadowfetch/os-release.shadowfetch", postinst)
        self.assertIn("VERSION_ID=\\\"$version\\\"", postinst)
        self.assertIn("install -m 0644 \"$source\" /usr/lib/os-release", postinst)
        self.assertEqual("interest-noawait /usr/lib/os-release\n", triggers)


    @staticmethod
    def _write_executable(path: Path, body: str) -> None:
        path.write_text("#!/bin/sh\nset -eu\n" + textwrap.dedent(body))
        path.chmod(0o755)


    @unittest.skipUnless(Path("/usr/bin/flock").exists(), "Linux failure-injection test")
    def test_update_rejects_solver_removal_before_apply(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fake = root / "bin"
            fake.mkdir()
            marker = root / "upgrade-applied"
            self._write_executable(
                fake / "df",
                """
                printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\\n'
                printf 'fake 1 1 99999999 1%% /\\n'
                """,
            )
            self._write_executable(fake / "curl", "exit 0\n")
            self._write_executable(fake / "upower", "exit 0\n")
            self._write_executable(fake / "fuser", "exit 1\n")
            self._write_executable(fake / "dpkg", "exit 0\n")
            self._write_executable(fake / "apt", "exit 0\n")
            self._write_executable(fake / "sudo", 'exec "$@"\n')
            self._write_executable(
                fake / "apt-get",
                f"""
                case " $* " in
                    *" -s "*) printf 'Remv protected-package [1.0]\\n' ;;
                    *" full-upgrade "*) touch {marker!s} ;;
                esac
                """,
            )
            env = os.environ.copy()
            env.update({
                "HOME": str(root / "home"),
                "XDG_STATE_HOME": str(root / "state"),
                "PATH": f"{fake}:/usr/bin:/bin",
            })
            (root / "home").mkdir()
            result = subprocess.run(
                [str(DEFAULTS / "data/usr/bin/shadowfetch-update"), "--check"],
                env=env,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertNotEqual(0, result.returncode)
            self.assertIn("Unverified proposed removals", result.stdout)
            self.assertIn("protected-package", result.stdout)
            self.assertFalse(marker.exists(), "upgrade ran despite the removal plan")

    @unittest.skipUnless(Path("/usr/bin/flock").exists(), "Linux transition test")
    def test_update_accepts_only_a_verified_debian_replacement(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fake = root / "bin"
            fake.mkdir()
            marker = root / "upgrade-applied"
            self._write_executable(
                fake / "df",
                """
                printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\n'
                printf 'fake 1 1 99999999 1%% /\n'
                """,
            )
            self._write_executable(fake / "curl", "exit 0\n")
            self._write_executable(fake / "upower", "exit 0\n")
            self._write_executable(fake / "fuser", "exit 1\n")
            self._write_executable(fake / "dpkg", "exit 0\n")
            self._write_executable(fake / "apt", "exit 0\n")
            self._write_executable(fake / "sudo", 'exec "$@"\n')
            self._write_executable(
                fake / "apt-get",
                f"""
                case " $* " in
                    *" -s "*)
                        printf 'Remv milou [4:6.6.5-2]\\n'
                        printf 'Inst qml6-module-org-kde-milou (4:6.7.2-2)\\n'
                        ;;
                    *" full-upgrade "*) touch {marker!s} ;;
                esac
                """,
            )
            env = os.environ.copy()
            env.update({
                "HOME": str(root / "home"),
                "XDG_STATE_HOME": str(root / "state"),
                "PATH": f"{fake}:/usr/bin:/bin",
            })
            (root / "home").mkdir()
            result = subprocess.run(
                [str(DEFAULTS / "data/usr/bin/shadowfetch-update"), "--check"],
                env=env,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertIn("Verified replacement or retirement removals", result.stdout)
            self.assertIn("milou", result.stdout)
            self.assertFalse(marker.exists(), "check mode applied the upgrade")


if __name__ == "__main__":
    unittest.main()
