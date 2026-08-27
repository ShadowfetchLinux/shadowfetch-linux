#!/usr/bin/env python3
"""Release-specific source gates for the 3.5.0 Element Workbench."""

from __future__ import annotations

import json
import os
import py_compile
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
DEFAULTS = ROOT / "packages/shadowfetch-defaults"
WELCOME = ROOT / "packages/shadowfetch-welcome"
CONTROL = ROOT / "packages/shadowfetch-control-center"
WORKBENCH = DEFAULTS / "data/usr/bin/shadowfetch-workbench"
ELEMENT = DEFAULTS / "data/usr/bin/shadowfetch-element"
FIREBREAK = ROOT / "packages/shadowfetch-fireline/data/usr/bin/shadowfetch-firebreak"
MANIFEST = DEFAULTS / "data/usr/share/shadowfetch/workbench/profiles.json"
CATALOG = WELCOME / "data/usr/share/shadowfetch/welcome/catalog"


class Workbench350Tests(unittest.TestCase):
    def test_release_is_3_5_0_and_every_custom_package_matches(self):
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertRegex(makefile, r"(?m)^VERSION\s+\?= 3\.5\.0$")
        for changelog in (ROOT / "packages").glob("shadowfetch-*/debian/changelog"):
            self.assertIn("(3.5.0-1)", changelog.read_text().splitlines()[0], changelog)

    def test_element_and_firebreak_versions_are_stamped_and_home_is_optional(self):
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertIn("data/usr/bin/shadowfetch-element", makefile)
        self.assertIn("data/usr/bin/shadowfetch-firebreak", makefile)
        self.assertIn("3.5.0", ELEMENT.read_text(encoding="utf-8"))
        self.assertIn('VERSION="3.5.0"', FIREBREAK.read_text(encoding="utf-8"))

        env = dict(os.environ, SHADOWFETCH_ELEMENT="ice")
        env.pop("HOME", None)
        proc = subprocess.run(
            [str(ELEMENT)], env=env, capture_output=True, text=True, check=False,
        )
        self.assertEqual(0, proc.returncode, proc.stderr)
        self.assertEqual("ice", proc.stdout.strip())

        proc = subprocess.run(
            [str(FIREBREAK), "--version"],
            env={key: value for key, value in os.environ.items() if key != "HOME"},
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(0, proc.returncode, proc.stderr)
        self.assertEqual(
            "shadowfetch-firebreak (Shadowfetch Linux) 3.5.0",
            proc.stdout.strip(),
        )

    def test_live_build_invalidates_first_party_archive_cache(self):
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertIn("cache/packages.chroot", makefile)
        self.assertIn("cache/packages.binary", makefile)
        self.assertIn("-name 'shadowfetch-*.deb'", makefile)
        self.assertIn("-name 'grub-btrfs_*.deb'", makefile)

    def test_four_profiles_have_plain_consequences_and_signed_catalog_records(self):
        data = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(1, data["schema_version"])
        profiles = data["profiles"]
        self.assertEqual(
            ["software-studio", "ai-lab", "production-ops", "creative-ai"],
            [profile["id"] for profile in profiles],
        )
        for profile in profiles:
            for key in ("network", "accounts", "accelerator", "installed_disk_gb",
                        "catalog_id", "commands", "capabilities"):
                self.assertTrue(profile.get(key), (profile["id"], key))
            record = json.loads((CATALOG / f"{profile['catalog_id']}.json").read_text())
            self.assertEqual(profile["catalog_id"], record["id"])
            self.assertEqual("preset", record["kind"])
            self.assertEqual("workbench", record["section"])
            self.assertTrue(record["packages"])
            self.assertNotIn("url", record)

    def test_ai_profile_is_model_free_and_ice_recommended(self):
        data = json.loads(MANIFEST.read_text(encoding="utf-8"))
        profile = next(item for item in data["profiles"] if item["id"] == "ai-lab")
        self.assertEqual("ice", profile["recommended_element"])
        record = json.loads((CATALOG / "workbench-ai-lab.json").read_text())
        joined = " ".join(record["packages"]).lower()
        self.assertNotRegex(joined, r"openclaw|hermes|ollama|model|weights|safetensors|gguf")
        self.assertIn("python3-huggingface-hub", record["packages"])
        self.assertIn("jupyterlab", record["packages"])

    def test_profile_catalog_uses_snapshot_available_3d_tools(self):
        record = json.loads((CATALOG / "workbench-creative-ai.json").read_text())
        self.assertIn("freecad", record["packages"])
        self.assertIn("openscad", record["packages"])
        self.assertNotIn("blender", record["packages"])

    def test_debian_install_manifests_have_no_patch_markers(self):
        for manifest in (ROOT / "packages").glob("shadowfetch-*/debian/*.install"):
            lines = manifest.read_text(encoding="utf-8").splitlines()
            self.assertNotIn("@@", lines, manifest)

    def test_every_first_party_package_has_copyright_metadata(self):
        for package in (ROOT / "packages").glob("shadowfetch-*"):
            if (package / "debian/control").is_file():
                self.assertTrue((package / "debian/copyright").is_file(), package)

    def test_workbench_help_is_read_only_and_python_parses(self):
        py_compile.compile(str(WORKBENCH), doraise=True)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "never-created"
            env = dict(os.environ, SHADOWFETCH_WORKBENCH_ROOT=str(root))
            proc = subprocess.run(
                [sys.executable, str(WORKBENCH), "--help"],
                env=env, capture_output=True, text=True, check=False,
            )
            self.assertEqual(0, proc.returncode, proc.stderr)
            self.assertFalse(root.exists())

    def test_ai_workspace_creation_is_private_atomic_and_secret_free(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "workspaces"
            env = dict(
                os.environ,
                SHADOWFETCH_WORKBENCH_ROOT=str(root),
                SHADOWFETCH_WORKBENCH_MANIFEST=str(MANIFEST),
                SHADOWFETCH_WORKBENCH_CATALOG=str(CATALOG),
                SHADOWFETCH_ELEMENT="ice",
            )
            proc = subprocess.run(
                [sys.executable, str(WORKBENCH), "create", "ai-lab", "Private Lab"],
                env=env, capture_output=True, text=True, check=False,
            )
            self.assertEqual(0, proc.returncode, proc.stderr)
            project = root / "private-lab"
            self.assertTrue(project.is_dir())
            self.assertTrue((project / "AGENTS.md").is_file())
            self.assertTrue((project / "models/MANIFEST.md").is_file())
            self.assertTrue((project / "pyproject.toml").is_file())
            receipt = json.loads((project / ".shadowfetch/workbench.json").read_text())
            self.assertEqual("ice", receipt["element"])
            self.assertEqual("none", receipt["network_default"])
            self.assertFalse((project / ".env").exists())
            second = subprocess.run(
                [sys.executable, str(WORKBENCH), "create", "ai-lab", "Private Lab"],
                env=env, capture_output=True, text=True, check=False,
            )
            self.assertNotEqual(0, second.returncode)

    def test_workbench_install_has_one_locked_privilege_path(self):
        source = WORKBENCH.read_text(encoding="utf-8")
        self.assertIn('subprocess.run(["pkexec", str(helper), "install"', source)
        self.assertNotRegex(source, re.compile(r"curl\s+[^\n]*\|\s*(?:ba)?sh"))
        self.assertNotIn("shell=True", source)
        self.assertNotRegex(source, re.compile(r"API_KEY\s*=|TOKEN\s*=|PASSWORD\s*=", re.I))

    def test_control_center_and_welcome_expose_workbench_without_catalog_duplication(self):
        app = (CONTROL / "data/usr/share/shadowfetch/control-center/sfcc/app.py").read_text()
        page = (CONTROL / "data/usr/share/shadowfetch/control-center/sfcc/workbench_page.py").read_text()
        welcome = (WELCOME / "src/shadowfetch-welcome").read_text()
        self.assertIn('(\"workbench\", \"Workbench\", \"Fire & Ice projects\")', app)
        self.assertIn("class WorkbenchPage", page)
        self.assertIn('rec.get("section") == "workbench"', welcome)
        self.assertIn("Open Element Workbench", welcome)

    def test_workbench_actions_fit_the_1366_layout_contract(self):
        page = (CONTROL / "data/usr/share/shadowfetch/control-center/sfcc/workbench_page.py").read_text()
        self.assertIn("actions = QGridLayout()", page)
        self.assertIn("actions.addWidget(self.install, 0, 0, 1, 2)", page)
        self.assertIn("actions.addWidget(create, 1, 0)", page)
        self.assertIn("actions.addWidget(plan, 1, 1)", page)
        self.assertIn("self.grid.setContentsMargins(0, 4, 0, 4)", page)

    def test_codex_pin_is_current_for_this_release_and_digest_verified(self):
        codex = (DEFAULTS / "data/usr/bin/shadowfetch-codex").read_text()
        self.assertIn('CODEX_VERSION="0.150.1"', codex)
        self.assertIn('INSTALLER_SHA256="ba92dd27e5c06f0d3bbc58bfa4b9cfb6599cd2742fbb1f92a2765e6c07dedb5a"', codex)
        self.assertIn("sha256sum --check --status", codex)


if __name__ == "__main__":
    unittest.main()
