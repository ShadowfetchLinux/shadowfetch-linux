"""Unit tests for the live ISO gate (tools/release/iso_gate.py).

These cases existed before Stage Q, but only as byte-identical pairs targeting
tools/iso_gate_2_1_4.py and tools/iso_gate_2_1_5.py -- archived copies. The ISO
gate that actually ran for 4.0.0 had NO test. They now run against the one live
implementation, which is the point of the consolidation.
"""

import importlib.machinery
import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
RELEASE_DIR = ROOT / "tools" / "release"
if str(RELEASE_DIR) not in sys.path:
    sys.path.insert(0, str(RELEASE_DIR))

import gate  # noqa: E402

SRC = RELEASE_DIR / "iso_gate.py"
_loader = importlib.machinery.SourceFileLoader("release_iso_gate_test", str(SRC))
_spec = importlib.util.spec_from_loader("release_iso_gate_test", _loader)
iso_gate = importlib.util.module_from_spec(_spec)
_loader.exec_module(iso_gate)


class ImagePackageAllowlistTests(unittest.TestCase):
    """The installed allowlist is derived from version data, not transcribed."""

    def setUp(self) -> None:
        self.release = gate.load_release("4.0.0")

    def test_every_installed_package_carries_the_release_version(self) -> None:
        packages = iso_gate.image_packages(self.release)
        self.assertEqual("4.0.0-1", packages["shadowfetch-missions"])
        self.assertEqual("4.14-2", packages["grub-btrfs"])

    def test_the_nvidia_setup_package_is_published_but_not_installed(self) -> None:
        """It is a post-install helper: expecting it in the image would fail the gate."""
        self.assertIn("shadowfetch-nvidia", self.release.binary_versions)
        self.assertNotIn("shadowfetch-nvidia", iso_gate.image_packages(self.release))

    def test_the_image_allowlist_is_otherwise_the_published_set(self) -> None:
        excluded = set(self.release.section("packages")["image_excluded"])
        self.assertEqual(
            set(self.release.binary_versions) - excluded,
            set(iso_gate.image_packages(self.release)),
        )


class IsoGateTests(unittest.TestCase):
    PARTITION_CONFIG = """
efi:
  mountPoint: /boot/efi
  recommendedSize: 512MiB
  minimumSize: 300MiB
  label: EFI
partitionLayout:
  - name: boot
    filesystem: ext4
    noEncrypt: true
    mountPoint: /boot
    size: 2G
  - name: root
    filesystem: btrfs
    mountPoint: /
    size: 100%
"""

    def test_calamares_order_uses_exec_phase_not_show_phase(self):
        settings = """
sequence:
  - show:
      - welcome
      - users
      - summary
  - exec:
      - partition
      - unpackfs
      - shellprocess
      - users
      - sources-final
      - umount
  - show:
      - finished
"""
        self.assertEqual(
            [
                "partition",
                "unpackfs",
                "shellprocess",
                "users",
                "sources-final",
                "umount",
            ],
            iso_gate.validate_calamares_exec_sequence(settings),
        )

    def test_calamares_rejects_cleanup_after_user_creation(self):
        settings = """
sequence:
  - exec:
      - unpackfs
      - users
      - shellprocess
      - sources-final
      - umount
"""
        with self.assertRaisesRegex(RuntimeError, "unsafe"):
            iso_gate.validate_calamares_exec_sequence(settings)

    def test_calamares_requires_one_of_each_safety_boundary(self):
        settings = """
sequence:
  - exec:
      - unpackfs
      - shellprocess
      - users
      - sources-final
"""
        with self.assertRaisesRegex(RuntimeError, "exactly once"):
            iso_gate.validate_calamares_exec_sequence(settings)

    def test_partition_contract_has_one_calamares_managed_esp(self):
        document = iso_gate.validate_partition_contract(self.PARTITION_CONFIG)
        self.assertEqual("512MiB", document["efi"]["recommendedSize"])

    def test_partition_contract_rejects_duplicate_layout_esp(self):
        config = self.PARTITION_CONFIG.replace(
            "  - name: root",
            "  - name: EFI\n"
            "    type: c12a7328-f81f-11d2-ba4b-00a0c93ec93b\n"
            "    filesystem: fat32\n"
            "    mountPoint: /boot/efi\n"
            "  - name: root",
        )
        with self.assertRaisesRegex(RuntimeError, "duplicates"):
            iso_gate.validate_partition_contract(config)

    def test_partition_contract_rejects_wrong_efi_size(self):
        config = self.PARTITION_CONFIG.replace("512MiB", "300MiB")
        with self.assertRaisesRegex(RuntimeError, "EFI settings mismatch"):
            iso_gate.validate_partition_contract(config)

    def test_partition_contract_requires_unencrypted_boot_partition(self):
        config = self.PARTITION_CONFIG.replace("    noEncrypt: true\n", "")
        with self.assertRaisesRegex(RuntimeError, "clear /boot contract mismatch"):
            iso_gate.validate_partition_contract(config)

    def test_partition_contract_rejects_forced_gpt(self):
        config = "defaultPartitionTableType: gpt\n" + self.PARTITION_CONFIG
        with self.assertRaisesRegex(RuntimeError, "msdos for BIOS"):
            iso_gate.validate_partition_contract(config)

    def test_partition_contract_rejects_custom_bios_grub(self):
        config = self.PARTITION_CONFIG.replace(
            "  - name: boot",
            "  - name: bios_grub\n"
            "    filesystem: unformatted\n"
            "    noEncrypt: true\n"
            "    size: 2M\n"
            "  - name: boot",
        )
        with self.assertRaisesRegex(RuntimeError, "must not synthesize"):
            iso_gate.validate_partition_contract(config)

    def test_grub_installer_resolves_mapper_stack_without_uuid_sed(self):
        installer = (ROOT / "live-build/config/includes.chroot/usr/local/sbin/sf-install-grub").read_text()
        iso_gate.validate_grub_installer_contract(installer)
        with self.assertRaisesRegex(RuntimeError, "unsafe legacy logic"):
            iso_gate.validate_grub_installer_contract(
                installer + "\ngrub-probe --target=device / | sed -E 's/p?[0-9]+$//'\n"
            )
        with self.assertRaisesRegex(RuntimeError, "incomplete"):
            iso_gate.validate_grub_installer_contract(
                installer.replace(
                    'dpkg --install "$GRUB_PC_DEB"',
                    "false",
                )
            )

    def test_grub_cache_hook_pins_and_verifies_the_live_binary_version(self):
        hook = (
            ROOT / "live-build/config/hooks/0014-cache-bios-grub-package.hook.chroot"
        ).read_text()
        for required in (
            "VERSION=$(dpkg-query -W -f='${Version}' grub-pc-bin)",
            'apt-get download "grub-pc=$VERSION"',
            'PACKAGE=$(dpkg-deb --field "$1" Package)',
            'PACKAGE_VERSION=$(dpkg-deb --field "$1" Version)',
            'PACKAGE_ARCHITECTURE=$(dpkg-deb --field "$1" Architecture)',
            "sha256sum grub-pc.deb > grub-pc.deb.sha256",
        ):
            with self.subTest(required=required):
                self.assertIn(required, hook)

    def test_nvidia_gate_catches_abi_suffixed_driver_libraries(self):
        rejected = (
            "nvidia-driver",
            "nvidia-open-610",
            "libnvidia-ml1",
            "libnvidia-cfg1",
            "libnvidia-compute-550",
        )
        for package in rejected:
            with self.subTest(package=package):
                self.assertRegex(package, iso_gate.PROPRIETARY_NVIDIA_PACKAGE)
        allowed = (
            "nvidia-detect",
            "nvidia-alternative",
            "nvidia-installer-cleanup",
            "glx-alternative-nvidia",
        )
        for package in allowed:
            with self.subTest(package=package):
                self.assertNotRegex(package, iso_gate.PROPRIETARY_NVIDIA_PACKAGE)

    def test_build_time_downloader_gate_catches_libdvd_packages(self):
        installed = {
            "bash",
            "libdvd-pkg",
            "libdvdcss2",
            "libdvdcss-dev",
            "libdvdcss2-dbgsym",
        }
        self.assertEqual(
            [
                "libdvd-pkg",
                "libdvdcss-dev",
                "libdvdcss2",
                "libdvdcss2-dbgsym",
            ],
            iso_gate.forbidden_build_time_packages(installed),
        )


if __name__ == "__main__":
    unittest.main()
