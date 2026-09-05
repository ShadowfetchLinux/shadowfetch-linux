#!/usr/bin/env python3
"""Stamp distro identity without rewriting independent upstream versions."""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
PROGRAM_VERSIONS = {
    'packages/shadowfetch-defaults/data/usr/bin/shadowfetch-element': 'VERSION',
    'packages/shadowfetch-fireline/data/usr/bin/shadowfetch-firebreak': 'VERSION',
    'packages/shadowfetch-fireline/data/usr/bin/shadowfetch-ai-ignition': 'VERSION',
    'packages/shadowfetch-fireline/data/usr/lib/shadowfetch/mcp/sf_mcp.py': 'SERVER_VERSION',
    'packages/shadowfetch-missions/data/usr/lib/shadowfetch/missions/sf_missions.py': 'VERSION',
}


def stamp(version: str) -> None:
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version):
        raise ValueError('version must be MAJOR.MINOR.PATCH')
    share = ROOT / 'packages/shadowfetch-branding/data/usr/share/shadowfetch'
    (share / 'version').write_text(version + '\n')
    path = share / 'os-release.shadowfetch'
    text = path.read_text()
    text = re.sub(r'(?m)^VERSION_ID=.*$', f'VERSION_ID="{version}"', text)
    text = re.sub(r'(?m)^VERSION=.*$', f'VERSION="{version} (Umbra)"', text)
    text = re.sub(r'(?m)^PRETTY_NAME=.*$', f'PRETTY_NAME="Shadowfetch Linux {version} (Umbra)"', text)
    path.write_text(text)
    for filename, variable in PROGRAM_VERSIONS.items():
        path = ROOT / filename
        content, count = re.subn(r'(?m)^(' + variable + r'\s*=\s*)["\'][0-9]+\.[0-9]+\.[0-9]+["\']', lambda match: match[1] + '"' + version + '"', path.read_text())
        if count != 1:
            raise ValueError(f'{filename}: expected exactly one distro version assignment')
        path.write_text(content)
    path = ROOT / 'packages/shadowfetch-themes/data/usr/share/sddm/themes/umbra/metadata.desktop'
    text = re.sub(r'(?m)^Version=.*$', f'Version={version}', path.read_text())
    path.write_text(text)
    for filename in ('LICENSES.md', 'SOURCES.md', 'BUZZ.md'):
        path = ROOT / 'packages/shadowfetch-defaults/data/usr/share/doc/shadowfetch' / filename
        text = re.sub(r'(Shadowfetch Linux\s+)[0-9]+\.[0-9]+\.[0-9]+', lambda match: match[1] + version, path.read_text())
        path.write_text(text)
    print(f'Stamped Shadowfetch Linux {version} identity')


if __name__ == '__main__':
    stamp(sys.argv[1])
