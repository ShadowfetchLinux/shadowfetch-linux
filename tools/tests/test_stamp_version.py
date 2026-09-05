import importlib.util
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('stamp_version', Path(__file__).resolve().parents[1] / 'stamp_version.py')
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class StampTests(unittest.TestCase):
    def test_stamps_identity_without_replacing_upstream_versions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            files = {
                'packages/shadowfetch-branding/data/usr/share/shadowfetch/os-release.shadowfetch': 'VERSION_ID="3.5.0"\nVERSION="3.5.0 (Umbra)"\nPRETTY_NAME="Shadowfetch Linux 3.5.0"\n',
                'packages/shadowfetch-themes/data/usr/share/sddm/themes/umbra/metadata.desktop': '[SddmGreeterTheme]\nVersion=3.5.0\nQtVersion=6.8.2\n',
                'packages/shadowfetch-defaults/data/usr/share/doc/shadowfetch/LICENSES.md': '# Shadowfetch Linux 3.5.0\nCodex 0.150.1\n',
                'packages/shadowfetch-defaults/data/usr/share/doc/shadowfetch/SOURCES.md': '# Shadowfetch Linux 3.5.0\nVendor 0.43.0\n',
                'packages/shadowfetch-defaults/data/usr/share/doc/shadowfetch/BUZZ.md': '# Shadowfetch Linux 3.5.0\nBuzz 0.5.17\n',
            }
            for name, variable in MODULE.PROGRAM_VERSIONS.items():
                files[name] = variable + ' = "3.5.0"\nUPSTREAM_VERSION = "0.43.0"\n'
            for name, text in files.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text)
            old = MODULE.ROOT
            try:
                MODULE.ROOT = root
                MODULE.stamp('4.0.0')
            finally:
                MODULE.ROOT = old
            self.assertIn('VERSION_ID="4.0.0"', (root / next(iter(files))).read_text())
            self.assertIn('QtVersion=6.8.2', (root / list(files)[1]).read_text())
            self.assertIn('Codex 0.150.1', (root / list(files)[2]).read_text())
            self.assertIn('Vendor 0.43.0', (root / list(files)[3]).read_text())
            for name, variable in MODULE.PROGRAM_VERSIONS.items():
                self.assertIn(variable + ' = "4.0.0"', (root / name).read_text())
                self.assertIn('UPSTREAM_VERSION = "0.43.0"', (root / name).read_text())

    def test_rejects_non_version_input(self):
        with self.assertRaises(ValueError):
            MODULE.stamp('4.0.0; command')
