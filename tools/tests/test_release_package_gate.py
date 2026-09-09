"""Unit tests for the live package gate (tools/release/package_gate.py).

Before Stage Q the package gate had no test at any version: six copies, 2,886
lines, and nothing exercised the container script, the allowlist derivation or
the repository expectations. What is proved here is the part the consolidation
made testable -- that the per-release inputs come from the version data file
rather than from hand-edited literals inside a copied module.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
from pathlib import Path
import sys
import unittest


TOOLS = Path(__file__).resolve().parents[1]
RELEASE_DIR = TOOLS / "release"
if str(RELEASE_DIR) not in sys.path:
    sys.path.insert(0, str(RELEASE_DIR))

import gate  # noqa: E402

SRC = RELEASE_DIR / "package_gate.py"
_loader = importlib.machinery.SourceFileLoader("release_package_gate_test", str(SRC))
_spec = importlib.util.spec_from_loader("release_package_gate_test", _loader)
package_gate = importlib.util.module_from_spec(_spec)
_loader.exec_module(package_gate)


class ContainerScriptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.release = gate.load_release("4.0.0")
        self.script = package_gate.container_script(self.release)

    def test_every_published_package_has_a_pinned_candidate_check(self) -> None:
        for package, version in self.release.binary_versions.items():
            with self.subTest(package=package):
                self.assertIn(f"{package}={version}", self.script)

    def test_the_apt_suite_comes_from_the_release_data(self) -> None:
        self.assertIn(f"file:/repo {self.release.codename} main", self.script)

    def test_retired_local_ai_binaries_are_asserted_absent(self) -> None:
        """The absence is the claim, so it must be a test in the script, not a comment."""
        for path in self.release.section("packages")["container_smoke"]["absent"]:
            with self.subTest(path=path):
                self.assertIn(f"[ ! -e {path} ]", self.script)

    def test_the_smoke_commands_come_from_the_release_data(self) -> None:
        for command in self.release.section("packages")["container_smoke"]["present"]:
            with self.subTest(command=command):
                self.assertIn(command, self.script)

    def test_the_script_still_ends_on_its_success_marker(self) -> None:
        self.assertIn("DEBIAN13_PACKAGE_INSTALL_PASS", self.script)
        self.assertIn("dpkg --audit", self.script)

    def test_a_version_bump_needs_no_module_edit(self) -> None:
        """The whole point of Stage Q: change the data, the gate follows."""
        bumped = gate.ReleaseData(
            version="4.1.0",
            path=self.release.path,
            document={
                **self.release.document,
                "release": {**self.release.release, "version": "4.1.0"},
            },
        )
        script = package_gate.container_script(bumped)
        self.assertIn("shadowfetch-missions=4.1.0-1", script)
        self.assertNotIn("shadowfetch-missions=4.0.0-1", script)
        # A third-party pin must NOT follow the Shadowfetch version.
        self.assertIn("grub-btrfs=4.14-2", script)


class ProgramTableTests(unittest.TestCase):
    def test_using_a_program_before_it_is_resolved_is_a_loud_error(self) -> None:
        package_gate.PROGRAMS.clear()
        with self.assertRaises(RuntimeError) as caught:
            package_gate.program("dpkg-deb")
        self.assertIn("was not resolved before use", str(caught.exception))

    def test_every_signature_deciding_program_is_classified_security(self) -> None:
        roles = dict(package_gate.REQUIRED_PROGRAMS)
        for name in ("gpg", "gpgv", "dpkg-deb", "dpkg-source"):
            with self.subTest(name=name):
                self.assertEqual(gate.ROLE_SECURITY, roles[name])


class ReleaseConsistencyTests(unittest.TestCase):
    """Cross-checks the copied modules could never make, because each held its
    own transcription of the same lists."""

    def setUp(self) -> None:
        self.release = gate.load_release("4.0.0")

    def test_the_source_set_covers_every_published_binary(self) -> None:
        """Every binary must come from a source in the signed Sources index.

        shadowfetch-meta builds the metapackages plus shadowfetch-nvidia, so
        those three binaries have no same-named source.
        """
        from_meta = {"shadowfetch-desktop", "shadowfetch-creative-base", "shadowfetch-nvidia"}
        unexplained = (
            set(self.release.binary_versions)
            - self.release.source_packages
            - from_meta
        )
        self.assertEqual(set(), unexplained)

    def test_the_smoke_set_has_no_duplicates(self) -> None:
        smoke = self.release.smoke_install
        self.assertEqual(len(smoke), len(set(smoke)))


if __name__ == "__main__":
    unittest.main()
