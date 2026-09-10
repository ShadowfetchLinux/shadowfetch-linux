"""Reject release changes that expand a pickup-only correction into crash routing."""

import importlib.util
from pathlib import Path
import sys
import unittest

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))
import drkonqi_pickup_contract as contract


class PickupContractTests(unittest.TestCase):
    DROPIN = "\n".join(("[Service]", "ExecStart=",
                           "ExecStart=/" + contract.HELPER + " --settle-first --pickup --uid %U", ""))

    def test_only_pickup_command_override_is_accepted(self):
        contract.validate_dropin("# Keep upstream unit restrictions\n" + self.DROPIN)
        contract.validate_package_paths([
            contract.HELPER, contract.DROPIN,
            "usr/share/doc/shadowfetch-drkonqi-pickup/copyright",
        ])

    def test_timeout_or_failure_suppression_is_rejected(self):
        for extra in ("RuntimeMaxSec=0", "SuccessExitStatus=15", "ExecStartPost=/bin/true",
                      "[Unit]\nConditionPathExists=/never", "Restart=always"):
            with self.subTest(extra=extra), self.assertRaises(RuntimeError):
                contract.validate_dropin(self.DROPIN + extra + "\n")

    def test_missing_reset_or_pickup_scope_is_rejected(self):
        for content in (self.DROPIN.replace("ExecStart=\n", ""),
                        self.DROPIN.replace(" --pickup", ""),
                        self.DROPIN.replace(" --uid %U", ""),
                        self.DROPIN.replace(" --settle-first", "")):
            with self.subTest(content=content), self.assertRaises(RuntimeError):
                contract.validate_dropin(content)

    def test_vendor_and_global_paths_cannot_be_owned_by_correction(self):
        for path in (*contract.UPSTREAM_UNITS, contract.UPSTREAM_PROCESSOR,
                     "usr/lib/systemd/system/drkonqi-coredump-processor@.service.d/override.conf",
                     "etc/systemd/user/service.d/override.conf", "usr/bin/drkonqi",
                     "usr/share/doc/shadowfetch-drkonqi-pickup/../../outside"):
            with self.subTest(path=path), self.assertRaises(RuntimeError):
                contract.validate_package_paths([contract.HELPER, path])

    def test_modified_vendor_unit_is_rejected(self):
        for path in contract.UPSTREAM_UNITS:
            with self.subTest(path=path), self.assertRaises(RuntimeError):
                contract.validate_upstream_unit(path, b"[Service]\nExecStart=/bin/true\n")

    def test_package_and_iso_gates_share_exact_payload_contract(self):
        # Stage Q collapsed the version-copied gate families. The package
        # allowlist, the source set and the smoke set are version DATA now, so
        # this reads the same file the gates read rather than three separate
        # transcriptions inside two copied modules.
        release_dir = TOOLS / "release"
        if str(release_dir) not in sys.path:
            sys.path.insert(0, str(release_dir))
        import gate

        spec = importlib.util.spec_from_file_location(
            "drkonqi_iso_gate", release_dir / "iso_gate.py"
        )
        iso_gate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(iso_gate)

        # The LIVE release. Naming a version here meant this cross-check
        # compared a stale constant against the stale data file that agreed
        # with it: two wrong halves matching is what it is designed to catch.
        release = gate.load_release(None)
        self.assertEqual(release.binary_versions[contract.PACKAGE], contract.VERSION)
        self.assertIn(contract.PACKAGE, release.source_packages)
        self.assertIn(contract.PACKAGE, release.smoke_install)
        self.assertEqual(
            iso_gate.image_packages(release)[contract.PACKAGE], contract.VERSION
        )
        self.assertEqual(set(iso_gate.CRITICAL_PACKAGE_PAYLOADS[contract.PACKAGE]),
                         {contract.HELPER, contract.DROPIN})
        self.assertLessEqual(set(contract.UPSTREAM_UNITS), iso_gate.REQUIRED_ROOT_FILES)


if __name__ == "__main__":
    unittest.main()
