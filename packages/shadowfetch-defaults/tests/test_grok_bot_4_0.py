#!/usr/bin/env python3
"""Grok Bot installer failure boundaries; no downloads, installs or account use."""
import argparse
import contextlib
import hashlib
import fcntl
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "data/usr/bin/shadowfetch-grok-bot"
LOADER = importlib.machinery.SourceFileLoader("shadowfetch_grok_bot", str(SOURCE))
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
BOT = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(BOT)


def completed(output="", code=0):
    return subprocess.CompletedProcess([], code, stdout=output, stderr="")


class GrokBotTests(unittest.TestCase):
    def test_provenance_matches_installer_pin(self):
        meta = json.loads((ROOT / "data/usr/share/shadowfetch/grok-bot/release.json").read_text())
        self.assertEqual(meta["artifact_sha256"], BOT.SHA256)
        self.assertEqual(meta["artifact_bytes"], BOT.DOWNLOAD_BYTES)
        self.assertEqual(meta["artifact_url"], BOT.URL)
        self.assertEqual(meta["version"], BOT.VERSION)
        self.assertFalse(meta["redistributed_in_iso"])
        self.assertFalse(meta["api_keys_supported_by_installer"])

    def test_official_url_is_https_and_versioned(self):
        from urllib.parse import urlsplit
        parsed = urlsplit(BOT.URL)
        self.assertEqual((parsed.scheme, parsed.hostname), ("https", "downloads.cursor.com"))
        self.assertIn("/linux/x64/", parsed.path)
        self.assertTrue(parsed.path.endswith(f"grok-bot_{BOT.VERSION}_amd64.deb"))

    def test_ice_blocks_setup_before_privilege_or_network(self):
        with patch.object(BOT, "require_platform"), patch.object(BOT, "element", return_value="ice"), patch.object(BOT, "system_install") as install:
            with self.assertRaisesRegex(BOT.SetupError, "Switch to Fire"):
                BOT.setup(argparse.Namespace(yes=True, no_open=True))
            install.assert_not_called()

    def test_ice_blocks_native_launch(self):
        with patch.object(BOT, "require_platform"), patch.object(BOT, "element", return_value="ice"), patch.object(BOT.subprocess, "Popen") as launch:
            with self.assertRaises(BOT.SetupError):
                BOT.open_app()
            launch.assert_not_called()

    def test_element_env_then_user_then_system(self):
        with tempfile.TemporaryDirectory() as folder:
            config = Path(folder) / "config"
            (config / "shadowfetch").mkdir(parents=True)
            (config / "shadowfetch/element").write_text("ice\n")
            system = Path(folder) / "system-element"
            system.write_text("fire\n")
            with patch.dict(os.environ, {"XDG_CONFIG_HOME": str(config), "SHADOWFETCH_ELEMENT": ""}), patch.object(BOT, "SYSTEM_ELEMENT", system):
                self.assertEqual(BOT.element(), "ice")
                with patch.dict(os.environ, {"SHADOWFETCH_ELEMENT": "fire"}):
                    self.assertEqual(BOT.element(), "fire")
                (config / "shadowfetch/element").unlink()
                self.assertEqual(BOT.element(), "fire")

    def test_no_download_without_noninteractive_consent(self):
        with patch.object(BOT, "require_platform"), patch.object(BOT, "require_fire"), patch.object(BOT.sys.stdin, "isatty", return_value=False), contextlib.redirect_stdout(io.StringIO()), patch.object(BOT, "system_install") as install:
            with self.assertRaisesRegex(BOT.SetupError, "setup --yes"):
                BOT.setup(argparse.Namespace(yes=False, no_open=True))
            install.assert_not_called()

    def test_nonroot_cannot_use_privileged_entrypoint(self):
        with patch.object(BOT.os, "geteuid", return_value=1000), patch.object(BOT, "run") as runner:
            with self.assertRaisesRegex(BOT.SetupError, "administrator"):
                BOT.system_install()
            runner.assert_not_called()

    def test_unsupported_architecture(self):
        with patch.object(BOT.platform, "system", return_value="Linux"), patch.object(BOT.platform, "machine", return_value="aarch64"):
            with self.assertRaisesRegex(BOT.SetupError, "x86_64"):
                BOT.require_platform()

    def test_reject_bad_download_before_dpkg(self):
        with tempfile.TemporaryDirectory() as folder:
            artifact = Path(folder) / "bad.deb"
            artifact.write_bytes(b"untrusted")
            with patch.object(BOT, "run") as runner:
                with self.assertRaisesRegex(BOT.SetupError, "SHA-256"):
                    BOT.verify_artifact(artifact)
                runner.assert_not_called()

    def test_reject_same_size_bad_hash(self):
        with tempfile.TemporaryDirectory() as folder:
            artifact = Path(folder) / "bad.deb"
            artifact.write_bytes(b"abcd")
            with patch.object(BOT, "DOWNLOAD_BYTES", 4), patch.object(BOT, "SHA256", hashlib.sha256(b"1234").hexdigest()), patch.object(BOT, "run") as runner:
                with self.assertRaises(BOT.SetupError):
                    BOT.verify_artifact(artifact)
                runner.assert_not_called()

    def inspect_fixture(self, fields):
        artifact = Path(self.folder) / "fixture.deb"
        artifact.write_bytes(b"fixture")
        with patch.object(BOT, "DOWNLOAD_BYTES", 7), patch.object(BOT, "SHA256", hashlib.sha256(b"fixture").hexdigest()), patch.object(BOT, "run", side_effect=lambda argv, **kw: completed(fields[argv[-1]])):
            BOT.verify_artifact(artifact)

    def test_package_identity_must_match_name_version_and_arch(self):
        for key, value in (("Package", "other"), ("Version", "0.1.0"), ("Architecture", "arm64")):
            with self.subTest(key=key), tempfile.TemporaryDirectory() as self.folder:
                fields = {"Package": "grok-bot", "Version": BOT.VERSION, "Architecture": "amd64", key: value}
                with self.assertRaisesRegex(BOT.SetupError, "identity"):
                    self.inspect_fixture(fields)

    def test_matching_artifact_accepted(self):
        with tempfile.TemporaryDirectory() as self.folder:
            self.inspect_fixture({"Package": "grok-bot", "Version": BOT.VERSION, "Architecture": "amd64"})

    def test_partial_package_not_reported_installed(self):
        with patch.object(BOT, "run", return_value=completed("install ok unpacked\t0.43.0\tamd64")):
            self.assertIsNone(BOT.installed_package())

    def test_wrong_arch_package_not_reported_installed(self):
        with patch.object(BOT, "run", return_value=completed("install ok installed\t0.43.0\tarm64")):
            self.assertIsNone(BOT.installed_package())

    def test_correct_package_reported(self):
        with patch.object(BOT, "run", return_value=completed("install ok installed\t0.43.0\tamd64")):
            self.assertEqual(BOT.installed_package(), "0.43.0")

    def test_absent_status_is_not_authentication(self):
        with patch.object(BOT, "installed_package", return_value=None), patch.object(BOT, "element", return_value="fire"):
            result = BOT.status()
        self.assertFalse(result["installed"])
        self.assertFalse(result["launchable"])
        self.assertIsNone(result["authenticated"])
        self.assertEqual(result["state"], "not-installed")

    def test_verified_install_remains_unlaunchable_in_ice(self):
        with patch.object(BOT, "installed_package", return_value=BOT.VERSION), patch.object(BOT, "integrity", return_value=(True, "test")), patch.object(BOT, "element", return_value="ice"):
            result = BOT.status()
        self.assertTrue(result["verified"])
        self.assertFalse(result["launchable"])
        self.assertIsNone(result["authenticated"])

    def test_pinned_file_tamper_rejected(self):
        with patch.object(BOT, "trusted_regular", return_value=True), patch.object(BOT.os, "access", return_value=True), patch.object(BOT, "digest", return_value="wrong"), patch.object(BOT, "run") as runner:
            self.assertEqual(BOT.integrity(BOT.VERSION), (False, "release-pin-mismatch"))
            runner.assert_not_called()

    def test_dpkg_manifest_tamper_rejected(self):
        with patch.object(BOT, "trusted_regular", return_value=True), patch.object(BOT.os, "access", return_value=True), patch.object(BOT, "digest", side_effect=lambda path: BOT.PINNED_FILES[path]), patch.object(BOT, "run", return_value=completed("??5?????? /opt/Grok Bot/resource\n")):
            self.assertEqual(BOT.integrity(BOT.VERSION), (False, "package-manifest-mismatch"))

    def test_newer_vendor_update_is_not_downgraded_or_claimed_as_pin(self):
        with patch.object(BOT, "trusted_regular", return_value=True), patch.object(BOT.os, "access", return_value=True), patch.object(BOT, "run", return_value=completed("")):
            self.assertEqual(BOT.integrity("0.44.0"), (True, "vendor-updated-dpkg-manifest"))

    def test_older_vendor_version_needs_update(self):
        with patch.object(BOT, "trusted_regular", return_value=True), patch.object(BOT.os, "access", return_value=True), patch.object(BOT, "run", return_value=completed("", code=1)):
            self.assertEqual(BOT.integrity("0.30.0"), (False, "older-than-release-pin"))

    def test_status_and_doctor_exit_codes(self):
        with patch.object(BOT, "status", return_value={"verified": False}), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(BOT.main(["status", "--json"]), 0)
            self.assertEqual(BOT.main(["doctor", "--json"]), 1)

    def test_launch_rejects_root(self):
        with patch.object(BOT, "require_platform"), patch.object(BOT, "require_fire"), patch.object(BOT.os, "geteuid", return_value=0):
            with self.assertRaisesRegex(BOT.SetupError, "not as root"):
                BOT.open_app()

    def test_consent_is_specific_about_native_cloud_costs(self):
        self.assertIn("cloud data storage", BOT.CONSENT)
        self.assertIn("APT update source", BOT.CONSENT)
        self.assertIn("Administrator authentication", BOT.CONSENT)
        self.assertIn(BOT.TERMS_URL, BOT.CONSENT)

    def test_concurrent_install_is_rejected_before_network(self):
        with tempfile.TemporaryDirectory() as folder:
            lock_path = Path(folder) / "setup.lock"
            with lock_path.open("w") as held:
                fcntl.flock(held.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                with patch.object(BOT.os, "geteuid", return_value=0), patch.object(BOT, "require_platform"), patch.object(BOT, "SYSTEM_STATE", Path(folder)), patch.object(BOT, "LOCK", lock_path), patch.object(BOT.Path, "is_file", return_value=True), patch.object(BOT.os, "umask"), patch.dict(os.environ), patch.object(BOT, "run") as runner:
                    with self.assertRaisesRegex(BOT.SetupError, "already running"):
                        BOT.system_install()
                    runner.assert_not_called()

    def test_apt_failure_never_writes_success_receipt(self):
        real_temporary_directory = tempfile.TemporaryDirectory
        with real_temporary_directory() as folder:
            artifact = Path(folder) / f"grok-bot_{BOT.VERSION}_amd64.deb"
            artifact.write_bytes(b"fixture")
            with contextlib.ExitStack() as stack:
                stack.enter_context(patch.object(BOT.os, "geteuid", return_value=0))
                stack.enter_context(patch.object(BOT, "require_platform"))
                stack.enter_context(patch.object(BOT, "SYSTEM_STATE", Path(folder)))
                stack.enter_context(patch.object(BOT, "LOCK", Path(folder) / "setup.lock"))
                stack.enter_context(patch.object(BOT.Path, "is_file", return_value=True))
                stack.enter_context(patch.object(BOT.os, "umask"))
                stack.enter_context(patch.dict(os.environ))
                stack.enter_context(patch.object(BOT, "installed_package", return_value=None))
                stack.enter_context(patch.object(BOT.shutil, "disk_usage", return_value=type("Disk", (), {"free": 2 * 1024 ** 3})()))
                stack.enter_context(patch.object(BOT.tempfile, "TemporaryDirectory", return_value=contextlib.nullcontext(folder)))
                stack.enter_context(patch.object(BOT, "verify_artifact"))
                runner = stack.enter_context(patch.object(BOT, "run", side_effect=[completed(), completed(code=100)]))
                receipt = stack.enter_context(patch.object(BOT, "write_receipt"))
                stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
                with self.assertRaisesRegex(BOT.SetupError, "package manager"):
                    BOT.system_install()
                self.assertIn("--no-remove", runner.call_args_list[1].args[0])
                receipt.assert_not_called()

    def test_healthy_newer_install_does_not_download(self):
        with tempfile.TemporaryDirectory() as folder, contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(BOT.os, "geteuid", return_value=0))
            stack.enter_context(patch.object(BOT, "require_platform"))
            stack.enter_context(patch.object(BOT, "SYSTEM_STATE", Path(folder)))
            stack.enter_context(patch.object(BOT, "LOCK", Path(folder) / "setup.lock"))
            stack.enter_context(patch.object(BOT.Path, "is_file", return_value=True))
            stack.enter_context(patch.object(BOT.os, "umask"))
            stack.enter_context(patch.dict(os.environ))
            stack.enter_context(patch.object(BOT, "installed_package", return_value="0.44.0"))
            stack.enter_context(patch.object(BOT, "integrity", return_value=(True, "vendor-updated-dpkg-manifest")))
            runner = stack.enter_context(patch.object(BOT, "run"))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            BOT.system_install()
            runner.assert_not_called()


if __name__ == "__main__":
    unittest.main()
