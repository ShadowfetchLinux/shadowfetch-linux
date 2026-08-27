#!/usr/bin/env python3
"""Regression checks for the Shadowfetch 3.5.0 installer contract."""

from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
CALAMARES = ROOT / "live-build/config/includes.chroot/etc/calamares"


class CalamaresContractTests(unittest.TestCase):
    def test_installer_has_complete_disk_tooling(self) -> None:
        packages = (
            ROOT
            / "live-build/config/package-lists/shadowfetch-installer.list.chroot"
        ).read_text(encoding="utf-8").splitlines()
        active = {
            line.partition("#")[0].strip()
            for line in packages
            if line.partition("#")[0].strip()
        }
        self.assertIn("util-linux-extra", active)
        self.assertIn("lvm2", active)

    def test_requirements_use_private_https_probe(self) -> None:
        welcome = (CALAMARES / "modules/welcome.conf").read_text(encoding="utf-8")
        self.assertIn(
            "internetCheckUrl:   https://www.shadowfetchlinux.org/", welcome
        )
        self.assertNotIn("http://example.com", welcome)

    def test_password_contract_uses_supported_check(self) -> None:
        users = (CALAMARES / "modules/users.conf").read_text(encoding="utf-8")
        self.assertIn("minLength: 8", users)
        self.assertNotIn("nonempty:", users)

    def test_machine_identity_is_fresh_per_install(self) -> None:
        machineid = (CALAMARES / "modules/machineid.conf").read_text(
            encoding="utf-8"
        )
        for setting in (
            "systemd-style: uuid",
            "dbus-symlink: true",
            "entropy-copy: false",
        ):
            self.assertIn(setting, machineid)
        self.assertNotIn("\nsymlink:", machineid)

    def test_finish_page_uses_current_restart_schema(self) -> None:
        finished = (CALAMARES / "modules/finished.conf").read_text(
            encoding="utf-8"
        )
        self.assertIn("restartNowMode: user-checked", finished)
        self.assertNotIn("restartNowEnabled", finished)
        self.assertNotIn("restartNowChecked", finished)

    def test_branding_declares_stylesheet_choice(self) -> None:
        stylesheet = CALAMARES / "branding/debian/stylesheet.qss"
        self.assertTrue(stylesheet.is_file())
        self.assertIn("inherits the active Qt widget style", stylesheet.read_text())


if __name__ == "__main__":
    unittest.main()
