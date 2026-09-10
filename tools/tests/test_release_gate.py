"""Tests for the shared release-gate foundation.

Two things are proved here that no test proved before Stage Q:

  * the trusted-program invariant is ENFORCED, not merely documented -- a shim
    earlier on PATH is not used, a program that exists only in a user-writable
    directory is refused, and a pinned binary that changes between resolution
    and invocation is refused at the point of invocation;
  * a release is cut from a version DATA file, so the package versions, the
    stamped literals and the release identity all follow the file rather than
    a hand-edited copy of a module.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest


TOOLS = Path(__file__).resolve().parents[1]
RELEASE_DIR = TOOLS / "release"
if str(RELEASE_DIR) not in sys.path:
    sys.path.insert(0, str(RELEASE_DIR))

import gate  # noqa: E402


def write_executable(path: Path, content: str = "#!/bin/sh\nexit 0\n") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


class TrustedProgramResolutionTests(unittest.TestCase):
    """The invariant: no PATH lookup may decide a security question."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.empty_trust = self.root / "empty-trust.toml"
        self.empty_trust.write_text("", encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def resolver(self, trust_file: Path | None = None) -> gate.ProgramResolver:
        return gate.ProgramResolver(trust_file or self.empty_trust)

    def test_system_program_resolves_to_an_absolute_root_owned_path(self) -> None:
        program = self.resolver().resolve("sh", gate.ROLE_SECURITY)
        self.assertTrue(program.path.is_absolute())
        self.assertEqual(gate.TRUST_SYSTEM, program.trust)
        self.assertIn(str(program.path.parent), gate.SYSTEM_PROGRAM_DIRECTORIES)

    def test_a_shim_earlier_on_path_is_not_used(self) -> None:
        """The defect this closes: PATH deciding which binary attests a fact.

        A forged 'sh' placed first on PATH would win under shutil.which(). It
        must lose here, because PATH is never consulted.
        """
        shim_dir = self.root / "evil"
        write_executable(shim_dir / "sh", "#!/bin/sh\necho forged\n")
        original = os.environ.get("PATH", "")
        os.environ["PATH"] = f"{shim_dir}{os.pathsep}{original}"
        try:
            program = self.resolver().resolve("sh", gate.ROLE_SECURITY)
        finally:
            os.environ["PATH"] = original
        self.assertNotEqual(shim_dir / "sh", program.path)
        self.assertIn(str(program.path.parent), gate.SYSTEM_PROGRAM_DIRECTORIES)

    def test_program_only_in_a_user_writable_directory_is_refused(self) -> None:
        """gitleaks lived in ~/.local/bin on the build host. Unpinned, that must fail."""
        writable = self.root / "userbin"
        write_executable(writable / "sf-fake-scanner")
        original = os.environ.get("PATH", "")
        os.environ["PATH"] = f"{writable}{os.pathsep}{original}"
        try:
            with self.assertRaises(gate.UntrustedProgram) as caught:
                self.resolver().resolve("sf-fake-scanner", gate.ROLE_SECURITY)
        finally:
            os.environ["PATH"] = original
        message = str(caught.exception)
        self.assertIn("not available at a trusted absolute path", message)
        self.assertIn("PATH is deliberately not consulted", message)
        self.assertIn("security fact", message)

    def test_a_correct_pin_makes_an_out_of_tree_program_usable(self) -> None:
        binary = write_executable(self.root / "userbin" / "sf-fake-scanner")
        trust = self.root / "trust.toml"
        trust.write_text(
            f'[program.sf-fake-scanner]\npath = "{binary}"\n'
            f'sha256 = "{gate.sha256(binary)}"\n',
            encoding="utf-8",
        )
        program = self.resolver(trust).resolve("sf-fake-scanner", gate.ROLE_SECURITY)
        self.assertEqual(gate.TRUST_PINNED, program.trust)
        self.assertEqual([str(binary), "--version"], program.argv("--version"))

    def test_a_pin_that_does_not_match_the_bytes_is_refused(self) -> None:
        binary = write_executable(self.root / "userbin" / "sf-fake-scanner")
        trust = self.root / "trust.toml"
        trust.write_text(
            f'[program.sf-fake-scanner]\npath = "{binary}"\nsha256 = "{"0" * 64}"\n',
            encoding="utf-8",
        )
        with self.assertRaises(gate.UntrustedProgram) as caught:
            self.resolver(trust).resolve("sf-fake-scanner", gate.ROLE_SECURITY)
        self.assertIn("does not match the recorded", str(caught.exception))

    def test_substitution_after_resolution_is_refused_at_invocation(self) -> None:
        """Resolving once and trusting forever would leave the swap window open."""
        binary = write_executable(self.root / "userbin" / "sf-fake-scanner")
        trust = self.root / "trust.toml"
        trust.write_text(
            f'[program.sf-fake-scanner]\npath = "{binary}"\n'
            f'sha256 = "{gate.sha256(binary)}"\n',
            encoding="utf-8",
        )
        program = self.resolver(trust).resolve("sf-fake-scanner", gate.ROLE_SECURITY)
        self.assertTrue(program.argv())  # usable before substitution
        write_executable(binary, "#!/bin/sh\necho forged\nexit 0\n")
        with self.assertRaises(gate.UntrustedProgram) as caught:
            program.argv()
        self.assertIn("has changed", str(caught.exception))

    def test_a_relative_pin_path_is_refused(self) -> None:
        trust = self.root / "trust.toml"
        trust.write_text(
            '[program.sf-fake-scanner]\npath = "userbin/sf-fake-scanner"\n'
            f'sha256 = "{"0" * 64}"\n',
            encoding="utf-8",
        )
        with self.assertRaises(gate.UntrustedProgram) as caught:
            self.resolver(trust).resolve("sf-fake-scanner", gate.ROLE_SECURITY)
        self.assertIn("must be an absolute path", str(caught.exception))

    def test_a_program_name_may_not_carry_a_path(self) -> None:
        with self.assertRaises(gate.UntrustedProgram):
            self.resolver().resolve("../../tmp/sh", gate.ROLE_SECURITY)


class NoPathLookupInGatesTests(unittest.TestCase):
    """Enforcement, not convention: no gate module may reach for PATH."""

    def test_no_release_module_calls_shutil_which(self) -> None:
        offenders = [
            path.name
            for path in sorted(RELEASE_DIR.glob("*.py"))
            if "shutil.which" in path.read_text(encoding="utf-8")
        ]
        self.assertEqual([], offenders)

    def test_no_release_module_reads_the_path_environment_variable(self) -> None:
        lookups = ('environ["PATH"]', 'environ.get("PATH"', 'getenv("PATH"')
        offenders = [
            path.name
            for path in sorted(RELEASE_DIR.glob("*.py"))
            if any(item in path.read_text(encoding="utf-8") for item in lookups)
        ]
        self.assertEqual([], offenders)


class ImportPathOrderTests(unittest.TestCase):
    """tools/ must precede tools/release/ on sys.path.

    The two directories share a name: tools/acceptance/ is a PACKAGE (the VM
    acceptance harness) and tools/release/acceptance.py is a MODULE (the release
    verifier). With tools/release/ first, a bare `import acceptance` anywhere in
    the process binds to the module, and `from acceptance import release_link`
    then fails with an ImportError naming neither directory. That is not
    hypothetical: it is what Stage Q's first cut did.
    """

    def test_importing_gate_leaves_tools_ahead_of_the_release_directory(self) -> None:
        self.assertIn(str(TOOLS), sys.path)
        self.assertIn(str(RELEASE_DIR), sys.path)
        self.assertLess(
            sys.path.index(str(TOOLS)), sys.path.index(str(RELEASE_DIR))
        )

    def test_a_consumer_putting_the_release_directory_first_is_corrected(self) -> None:
        original = list(sys.path)
        try:
            sys.path.insert(0, str(RELEASE_DIR))
            gate._order_import_path()
            self.assertLess(
                sys.path.index(str(TOOLS)), sys.path.index(str(RELEASE_DIR))
            )
            self.assertEqual(1, sys.path.count(str(RELEASE_DIR)))
        finally:
            sys.path[:] = original

    @unittest.skipUnless(
        (TOOLS / "acceptance" / "__init__.py").is_file(),
        "the tools/acceptance harness package is not present in this tree",
    )
    def test_the_shared_name_still_resolves_to_the_harness_package(self) -> None:
        spec = importlib.util.find_spec("acceptance")
        self.assertIsNotNone(spec)
        self.assertEqual(
            (TOOLS / "acceptance" / "__init__.py").resolve(),
            Path(spec.origin).resolve(),
        )


class ReleaseDataTests(unittest.TestCase):
    """Cutting a release must need one data file, not a copied module."""

    def setUp(self) -> None:
        # The LIVE release, selected the way every gate selects it. Naming a
        # version here made this class one more site a bump has to edit, and
        # a bump that missed it left the class asserting that the PREVIOUS
        # release was still current -- which it did, and which passed.
        self.release = gate.load_release(None)
        self.version = self.release.version

    def test_the_live_version_data_file_exists_and_is_not_historical(self) -> None:
        self.assertRegex(self.version, r"^\d+\.\d+\.\d+$")
        self.assertFalse(self.release.historical)
        self.assertTrue((gate.VERSIONS_DIR / f"{self.version}.toml").is_file())

    def test_binary_versions_are_derived_not_transcribed(self) -> None:
        """Checked against the CHANGELOGS, not against the same formula.

        binary_versions is literally f"{version}-{revision}", so asserting
        that shape back at it proves only that Python interpolates -- which is
        what replacing the old hard-coded "4.0.0-1" with a derived string did
        to this test. debian/changelog is the independent source: it is what
        dpkg-buildpackage actually stamps on the .deb, and a release whose
        derived versions disagree with it publishes a manifest for packages
        that do not exist.
        """
        import re

        versions = self.release.binary_versions
        checked = 0
        for name, declared in versions.items():
            changelog = gate.ROOT / "packages" / name / "debian" / "changelog"
            if not changelog.is_file():
                continue  # third-party, or built from another source tree
            first = changelog.read_text(encoding="utf-8").splitlines()[0]
            match = re.match(rf"{re.escape(name)} \(([^)]+)\)", first)
            with self.subTest(package=name):
                self.assertIsNotNone(match, first)
                self.assertEqual(match.group(1), declared)
            checked += 1
        self.assertGreaterEqual(checked, 10,
                                "almost no package changelogs were compared")
        # A third-party package keeps its own pin rather than the release version.
        self.assertEqual("4.14-2", versions["grub-btrfs"])
        self.assertNotIn(self.version, versions["grub-btrfs"])

    def test_stamped_tokens_follow_the_version(self) -> None:
        self.assertEqual(
            (f'SERVER_VERSION = "{self.version}"',),
            self.release.stamped_tokens("mcp_server"),
        )
        self.assertIn(
            f"Shadowfetch Linux {self.version}",
            self.release.stamped_tokens("installer_slideshow"),
        )

    def test_iso_name_and_acceptance_manifest_follow_the_version(self) -> None:
        self.assertEqual(
            f"shadowfetch-{self.version}-amd64.iso", self.release.iso_name
        )
        self.assertEqual(
            gate.ROOT / "qa" / self.version / "acceptance.json",
            self.release.acceptance_manifest(),
        )

    def test_the_smoke_set_is_a_subset_of_the_published_binaries(self) -> None:
        self.assertTrue(
            set(self.release.smoke_install).issubset(set(self.release.binary_versions))
        )

    def test_a_shipped_release_stays_loadable_and_declares_itself_historical(
        self,
    ) -> None:
        """History is data, not a deleted file. Every earlier release's own
        gate data must still load -- and must say it is historical, because
        two live files is the ambiguity load_release(None) refuses."""
        earlier = sorted(
            path.stem
            for path in gate.VERSIONS_DIR.glob("*.toml")
            if path.stem != self.version
        )
        self.assertTrue(earlier, "a bump left no earlier release data behind")
        for version in earlier:
            with self.subTest(version=version):
                shipped = gate.load_release(version)
                self.assertEqual(version, shipped.version)
                self.assertTrue(shipped.historical)

    def test_an_unknown_version_names_what_is_available(self) -> None:
        with self.assertRaises(gate.MissingReleaseData) as caught:
            gate.load_release("9.9.9")
        self.assertIn("no release data for 9.9.9", str(caught.exception))
        self.assertIn(self.version, str(caught.exception))


class ReleaseDataFileConsistencyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_a_file_whose_declared_version_disagrees_with_its_name_is_refused(
        self,
    ) -> None:
        """A copy-pasted data file with a forgotten version string must not load."""
        (self.directory / "5.0.0.toml").write_text(
            '[release]\nversion = "4.0.0"\n', encoding="utf-8"
        )
        with self.assertRaises(gate.MissingReleaseData) as caught:
            gate.load_release("5.0.0", directory=self.directory)
        self.assertIn("but the file is named", str(caught.exception))

    def test_ambiguity_is_refused_rather_than_guessed(self) -> None:
        for version in ("5.0.0", "5.1.0"):
            (self.directory / f"{version}.toml").write_text(
                f'[release]\nversion = "{version}"\n', encoding="utf-8"
            )
        with self.assertRaises(gate.MissingReleaseData) as caught:
            gate.load_release(None, directory=self.directory)
        self.assertIn("no release version selected", str(caught.exception))

    def test_a_historical_file_is_not_selected_as_the_default(self) -> None:
        (self.directory / "5.0.0.toml").write_text(
            '[release]\nversion = "5.0.0"\n', encoding="utf-8"
        )
        (self.directory / "4.9.0.toml").write_text(
            '[release]\nversion = "4.9.0"\nhistorical = true\n', encoding="utf-8"
        )
        self.assertEqual(
            "5.0.0", gate.load_release(None, directory=self.directory).version
        )


if __name__ == "__main__":
    unittest.main()
