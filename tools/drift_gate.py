#!/usr/bin/env python3
"""Stage X drift gate: fail when a copy diverges from its single source.

Why this exists
---------------
ARCHITECTURE_AUDIT.md:19 names duplication "the dominant maintenance cost and
the direct cause of shipped defects", and ADR-0009 (ARCHITECTURE_DECISIONS.md
:157) requires one authority per fact.  Six facts are restated across this
tree today: the theme palette, the release version, the signing fingerprint,
the current-release pointer, the workspace-name rule and the shared desktop
helper argv.

Deduplication that is not GATED comes back.  This file is the gate.  The
authorities it compares against are:

    tools/release/versions/<v>.toml  version, codename, signing fingerprint
                                     (Stage Q's release data -- this gate reads
                                     it rather than keeping a second copy)
    tools/truth/palette.json         theme palette (3 named surfaces)
    tools/truth/release.json         release-pointer contract, canonical URLs
    WORKSPACE_NAME_RULE (below)      the workspace-name rule, as a corpus

Two finding kinds, and they are NOT the same thing
--------------------------------------------------
    DRIFT    a copy disagrees with its source.  Always exit non-zero.
    BLOCKED  the duplication is real and detected, but removing it needs a
             change outside this stage's file territory.  Printed on every
             run so it cannot be forgotten; exits non-zero only under
             --strict, so it does not red the release gate for work another
             agent owns.

A BLOCKED finding is NOT an enforced control.  It is an OBSERVATION with a
named remedy.  Do not read this file's exit code as "the tree is deduplicated"
-- read the printed report.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import ast
import re
import subprocess
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]
TRUTH = ROOT / "tools/truth"

VERSIONS_DIR = ROOT / "tools/release/versions"

sys.path.insert(0, str(ROOT / "tools"))
import generate_theme_assets  # noqa: E402


def load_truth() -> dict:
    """Release identity, read from Stage Q's per-release gate data.

    Deliberately NOT a copy: tools/release/versions/<v>.toml already carries
    version, edition, subtitle, codename, display codename and the signing
    fingerprint, so this gate reads that file rather than restating it.

    The live release is the one file that is not marked historical. Two live
    files, or none, is itself an ambiguity about "which release is this tree",
    so it raises rather than picking one.
    """
    live = []
    for path in sorted(VERSIONS_DIR.glob("*.toml")):
        with path.open("rb") as handle:
            data = tomllib.load(handle)
        if not data.get("release", {}).get("historical", False):
            live.append((path, data["release"]))
    if len(live) != 1:
        raise RuntimeError(
            f"{VERSIONS_DIR} has {len(live)} non-historical release data files; "
            f"exactly one names the release this tree builds")
    path, release = live[0]
    pointer = json.loads((TRUTH / "release.json").read_text(encoding="utf-8"))
    return {
        "version": release["version"],
        "edition": release["edition"],
        "subtitle": release["subtitle"],
        "codename": release["codename"],
        "codename_display": release["display_codename"],
        "iso_name": f"shadowfetch-{release['version']}-amd64.iso",
        "signing": {"fingerprint": release["signing_fingerprint"]},
        "release_pointer": pointer["release_pointer"],
        "urls": pointer["urls"],
        "_data_file": str(path.relative_to(ROOT)),
    }


# --------------------------------------------------------------------------- #
# findings
# --------------------------------------------------------------------------- #

class Finding:
    __slots__ = ("kind", "check", "site", "detail", "remedy")

    def __init__(self, kind: str, check: str, site: str, detail: str, remedy: str = ""):
        assert kind in ("DRIFT", "BLOCKED")
        self.kind, self.check, self.site = kind, check, site
        self.detail, self.remedy = detail, remedy

    def __str__(self) -> str:
        text = f"{self.kind:<7} [{self.check}] {self.site}\n          {self.detail}"
        if self.remedy:
            text += f"\n          remedy: {self.remedy}"
        return text


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8", errors="replace")


def line_of(rel: str, needle: str) -> int:
    """1-indexed line a substring first appears on, for a useful file:line."""
    try:
        for number, text in enumerate(read(rel).splitlines(), 1):
            if needle in text:
                return number
    except OSError:
        pass
    return 0


def site(rel: str, needle: str = "") -> str:
    return f"{rel}:{line_of(rel, needle)}" if needle else rel


# --------------------------------------------------------------------------- #
# check: version
# --------------------------------------------------------------------------- #
# Every place the release version is retyped.  ADR-0009 counted twenty; these
# are the ones that are a fact rather than prose.  (rel path, regex, label)
VERSION_SITES: list[tuple[str, str, str]] = [
    ("packages/shadowfetch-branding/data/usr/share/shadowfetch/version",
     r"\A(\S+)\s*\Z", "shipped /usr/share/shadowfetch/version"),
    ("packages/shadowfetch-branding/data/usr/share/shadowfetch/os-release.shadowfetch",
     r'(?m)^VERSION_ID="([^"]+)"', "os-release VERSION_ID"),
    ("packages/shadowfetch-branding/data/usr/share/shadowfetch/os-release.shadowfetch",
     r'(?m)^VERSION="([0-9.]+) ', "os-release VERSION"),
    ("packages/shadowfetch-branding/data/usr/share/shadowfetch/os-release.shadowfetch",
     r'(?m)^PRETTY_NAME="Shadowfetch Linux ([0-9.]+) ', "os-release PRETTY_NAME"),
    ("packages/shadowfetch-themes/data/usr/share/sddm/themes/umbra/metadata.desktop",
     r"(?m)^Version=(\S+)\s*$", "SDDM theme metadata"),
    ("packages/shadowfetch-defaults/data/usr/bin/shadowfetch-element",
     r'(?m)^VERSION="([^"]+)"', "shadowfetch-element VERSION"),
    ("packages/shadowfetch-defaults/data/usr/bin/shadowfetch-grok-bot",
     r"shadowfetch-grok-bot ([0-9]+\.[0-9]+\.[0-9]+)", "grok-bot --version string"),
    ("packages/shadowfetch-fireline/data/usr/bin/shadowfetch-firebreak",
     r'(?m)^VERSION\s*=\s*"([^"]+)"', "firebreak VERSION"),
    ("packages/shadowfetch-fireline/data/usr/lib/shadowfetch/mcp/sf_mcp.py",
     r'(?m)^SERVER_VERSION\s*=\s*"([^"]+)"', "MCP SERVER_VERSION"),
    ("packages/shadowfetch-missions/data/usr/lib/shadowfetch/missions/sf_missions.py",
     r'(?m)^VERSION\s*=\s*"([^"]+)"', "sf_missions VERSION"),
    ("packages/shadowfetch-drkonqi-pickup/CMakeLists.txt",
     r"project\([^)]*VERSION\s+([0-9.]+)", "drkonqi-pickup CMake project version"),
    ("README.md", r"(?m)^\| Version / codename \| (\S+) /", "README fact table"),
]


def check_version(truth: dict) -> list[Finding]:
    """Every retyped copy of the release version agrees with the release data."""
    want = truth["version"]
    findings = []
    for rel, pattern, label in VERSION_SITES:
        try:
            text = read(rel)
        except OSError as exc:
            findings.append(Finding("DRIFT", "version", rel,
                                    f"{label}: unreadable ({exc})"))
            continue
        match = re.search(pattern, text)
        if match is None:
            findings.append(Finding(
                "DRIFT", "version", rel,
                f"{label}: the version could not be located "
                f"(pattern {pattern!r} no longer matches)",
                "update VERSION_SITES in tools/drift_gate.py, or restore the assignment"))
        elif match.group(1) != want:
            found = match.group(1)
            findings.append(Finding(
                "DRIFT", "version", site(rel, found),
                f"{label} is {found!r}; tools/truth/release.json says {want!r}",
                "make the copy match tools/truth/release.json. "
                "tools/stamp_version.py rewrites the shipped-identity subset; "
                "the Makefile, README, the CMake project version and the "
                "acceptance manifest are hand-maintained."))

    # The acceptance manifest names the release AND the artifacts by version.
    manifest = f"qa/{want}/acceptance.json"
    try:
        data = json.loads(read(manifest))
    except (OSError, ValueError) as exc:
        findings.append(Finding("DRIFT", "version", manifest,
                                f"acceptance manifest unreadable: {exc}"))
    else:
        if data.get("release", {}).get("version") != want:
            findings.append(Finding(
                "DRIFT", "version", site(manifest, '"version"'),
                f"release.version is {data.get('release', {}).get('version')!r}, "
                f"expected {want!r}"))
        iso = truth["iso_name"]
        if data.get("artifact", {}).get("iso_path") != iso:
            findings.append(Finding(
                "DRIFT", "version", site(manifest, "iso_path"),
                f"artifact.iso_path is {data.get('artifact', {}).get('iso_path')!r}, "
                f"expected {iso!r}"))
        for key in ("edition", "codename", "subtitle"):
            expected = truth["codename_display"] if key == "codename" else truth[key]
            if data.get("release", {}).get(key) != expected:
                findings.append(Finding(
                    "DRIFT", "version", site(manifest, f'"{key}"'),
                    f"release.{key} is {data.get('release', {}).get(key)!r}, "
                    f"expected {expected!r}"))
    return findings


# --------------------------------------------------------------------------- #
# check: signing fingerprint
# --------------------------------------------------------------------------- #
# A 40-hex key fingerprint is a SECURITY fact: every one of these decides
# which key a verification path will trust.  Retyping it five times (ADR-0009)
# means one typo silently moves one verification path to a key nobody chose.
# Files that MUST name the signing key. Kept short on purpose: Stage Q moved
# and deleted several gate modules mid-stage, and a gate that lists paths goes
# red on a rename rather than on a wrong key. The real check below is a sweep --
# EVERY 40-hex fingerprint anywhere in the tree must be this key.
FINGERPRINT_REQUIRED = (
    "Makefile",
    "README.md",
    "SECURITY.md",
    "repo/conf/distributions",
    "web/shadowfetch-linux-worker/src/index.js",
)
FINGERPRINT_SWEEP_SKIP = (
    "repo/dists/", "repo/pool/", "qa/2.", "qa/3.",
    "docs/RELEASE-", "RELEASE-", "PHASE",
)
_HEX40 = re.compile(r"(?i)\b((?:[0-9A-F]{4}\s+){9}[0-9A-F]{4}|[0-9A-F]{40})\b")
# A 40-hex token is not automatically a key claim: this tree also carries Git
# commit/tree SHA-1s (qa/<v>/acceptance.json source_commit / source_tree) and an
# upstream vendor build hash inside a URL, all 40 hex. Treating those as keys
# would make the check cry wolf, and a check that cries wolf gets switched off.
#
# So: when the line assigns to a NAMED field, that field's name decides -- a
# value under "source_commit" is never a key claim however close a fingerprint
# label happens to sit. Only an unnamed value (a bare line, a Markdown code
# span, an HTML fragment) falls back to a three-line label window, which is what
# SECURITY.md needs: its label sits three lines above the key.
_KEY_CONTEXT = re.compile(
    r"(?i)fingerprint|signing[- _]?key|signwith|gpg|repo[_ ]?key|key[_ ]?id|keyring")
_ASSIGNED_FIELD = re.compile(r"""^\s*["']?([A-Za-z][A-Za-z0-9_\-]*)["']?\s*\??[:=]""")
# Other people's keys, each named. A 40-hex key claim that is neither ours nor
# one of these fails the gate: every signing key in the tree is accounted for.
OTHER_KEYS = {
    "0AAC775BB6437A8D9AF7A3ACFE0784117FBCE11D":
        "KDE release signing key -- drkonqi vendor provenance, allowlisted in "
        ".gitleaks.toml",
    "B3CB366552540BE06EE9AD9711968C44928CAEFC":
        "KDE release signing SUBKEY -- same provenance record",
}
_TEXT_SUFFIXES = frozenset(
    {".py", ".js", ".md", ".json", ".toml", ".sh", ".yml", ".yaml", ".conf",
     ".txt", ".desktop", ".policy", ".service", ".install", ".control", ""})


def _sweep_files() -> list[Path]:
    """Tracked-ish text files worth scanning for a fingerprint literal.

    os.walk with directory PRUNING, not rglob: live-build/chroot contains a
    docker socket and root-owned trees, and a security sweep that dies on
    EACCES halfway through has scanned an unknown fraction of the tree.
    """
    # vendor/ is NOT pruned: a vendored provenance record is exactly where a
    # third party's signing key gets written down, and an unswept key claim is
    # the one this check most needs to see.
    prune = {".git", "__pycache__", "node_modules", ".wrangler", ".debhelper",
             "live-build", "build", "work", "next-release", "debian"}
    out = []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in prune]
        base = Path(dirpath)
        for name in filenames:
            path = base / name
            rel = str(path.relative_to(ROOT))
            if any(rel.startswith(prefix) for prefix in FINGERPRINT_SWEEP_SKIP):
                continue
            if path.is_symlink() or path.suffix not in _TEXT_SUFFIXES:
                continue
            try:
                if path.stat().st_size > 2_000_000:
                    continue
            except OSError:
                continue
            out.append(path)
    return out


def check_fingerprint(truth: dict) -> list[Finding]:
    """Every key claim in the tree names the release key, or a named third party."""
    want = truth["signing"]["fingerprint"].upper()
    findings = []

    for rel in FINGERPRINT_REQUIRED:
        try:
            text = read(rel)
        except OSError as exc:
            findings.append(Finding("DRIFT", "fingerprint", rel, f"unreadable ({exc})"))
            continue
        if not _HEX40.search(text):
            findings.append(Finding(
                "DRIFT", "fingerprint", rel,
                "no 40-hex fingerprint found; this file is meant to name the "
                "signing key",
                "restore it, or remove this path from FINGERPRINT_REQUIRED"))

    for path in _sweep_files():
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for number, line in enumerate(lines):
            match = _HEX40.search(line)
            if match is None:
                continue
            field = _ASSIGNED_FIELD.match(line)
            if field is not None:
                if not _KEY_CONTEXT.search(field.group(1)):
                    continue  # e.g. "source_commit", "release_build", "URL"
            else:
                window = "\n".join(lines[max(0, number - 3):number + 1])
                if not _KEY_CONTEXT.search(window):
                    continue  # a commit SHA or a build hash, not a key claim
            value = re.sub(r"\s+", "", match.group(1)).upper()
            if value == want or value in OTHER_KEYS:
                continue
            findings.append(Finding(
                "DRIFT", "fingerprint",
                f"{path.relative_to(ROOT)}:{number + 1}",
                f"names key {value}; {truth['_data_file']} says {want}",
                "one of the two is wrong -- decide which key actually signs "
                "this release. A third party's key belongs in OTHER_KEYS in "
                "tools/drift_gate.py, with its owner named."))
    return findings


# --------------------------------------------------------------------------- #
# check: generated theme assets
# --------------------------------------------------------------------------- #

def check_release_data(truth: dict) -> list[Finding]:
    """The Makefile and the acceptance manifest agree with the release data."""
    findings = []
    match = re.search(r"(?m)^VERSION\s*\?=\s*(\S+)\s*$", read("Makefile"))
    if match is None or match.group(1) != truth["version"]:
        findings.append(Finding(
            "DRIFT", "release-data", site("Makefile", "VERSION  ?="),
            f"Makefile VERSION is {match.group(1) if match else None!r}; "
            f"{truth['_data_file']} names {truth['version']!r}",
            "the release data file is the authority; make the Makefile match"))
    manifest = f"qa/{truth['version']}/acceptance.json"
    try:
        recorded = json.loads(read(manifest))["artifact"]["signing_fingerprint"]
    except (OSError, ValueError, KeyError) as exc:
        findings.append(Finding("DRIFT", "release-data", manifest,
                                f"signing_fingerprint unreadable: {exc}"))
    else:
        if recorded.upper() != truth["signing"]["fingerprint"].upper():
            findings.append(Finding(
                "DRIFT", "release-data", site(manifest, "signing_fingerprint"),
                f"acceptance manifest recorded {recorded}, release data says "
                f"{truth['signing']['fingerprint']}"))
    return findings


def check_theme_assets(_truth: dict) -> list[Finding]:
    """The generated colour schemes match what palette.json renders."""
    palette = generate_theme_assets.load_palette()
    return [
        Finding("DRIFT", "theme-assets", str(path.relative_to(ROOT)), reason,
                "python3 tools/generate_theme_assets.py --write")
        for path, reason in generate_theme_assets.check(palette)
    ]


# --------------------------------------------------------------------------- #
# check: palette literals in files the generator does not own
# --------------------------------------------------------------------------- #
# Splash.qml, theme.conf and contents/defaults embed colours inside layout or
# config that is not pure data, so they are CHECKED rather than generated.
_HEX = re.compile(r"#[0-9a-fA-F]{6}\b")
_RGB_TRIPLE = re.compile(r"\b([0-9]{1,3},[0-9]{1,3},[0-9]{1,3})\b")

# Stray hexes that already ship and are not palette roles.  This is a RATCHET,
# not an allowlist of good practice: each entry is a colour nobody named, and a
# NEW one fails the gate.  Removing an entry (by naming the colour in
# palette.json) is always correct.
UNNAMED_TODAY: dict[str, set[str]] = {
    # app.py's entry is gone, not moved: #101114 is theme.SIDEBAR now, and the
    # ratchet only ever loosens by a colour being named.
    "packages/shadowfetch-control-center/data/usr/share/shadowfetch/control-center/sfcc/grok_bot_page.py":
        {"#101115", "#71634b", "#f5f4ef"},
    "packages/shadowfetch-control-center/data/usr/share/shadowfetch/control-center/sfcc/ember_page.py":
        {"#f5d79a", "#f7b47a", "#f0937f"},
    "packages/shadowfetch-control-center/data/usr/share/shadowfetch/control-center/sfcc/theme.py":
        {"#2a2413", "#2a1815", "#101114", "#191b1f", "#33342e", "#302c24"},
    "packages/shadowfetch-welcome/src/shadowfetch-welcome":
        {"#11161e", "#2a313b", "#11151b", "#333a44", "#6b727b", "#29b6f6", "#9b7ede"},
    "packages/shadowfetch-fireproof/data/usr/bin/shadowfetch-fireproof": set(),
    "packages/shadowfetch-defaults/data/usr/bin/shadowfetch-passport": set(),
    "packages/shadowfetch-control-center/data/usr/share/shadowfetch/control-center/sfcc/guide_page.py":
        set(),
}

SURFACE_OF = {
    "packages/shadowfetch-control-center/data/usr/share/shadowfetch/control-center/sfcc/theme.py": "app-chrome",
    "packages/shadowfetch-control-center/data/usr/share/shadowfetch/control-center/sfcc/app.py": "app-chrome",
    "packages/shadowfetch-control-center/data/usr/share/shadowfetch/control-center/sfcc/ember_page.py": "app-chrome",
    "packages/shadowfetch-control-center/data/usr/share/shadowfetch/control-center/sfcc/grok_bot_page.py": "app-chrome",
    "packages/shadowfetch-fireproof/data/usr/bin/shadowfetch-fireproof": "app-chrome",
    "packages/shadowfetch-welcome/src/shadowfetch-welcome": "document",
    "packages/shadowfetch-defaults/data/usr/bin/shadowfetch-passport": "document",
    "packages/shadowfetch-control-center/data/usr/share/shadowfetch/control-center/sfcc/guide_page.py": "document",
}

SPLASH = ("packages/shadowfetch-themes/data/usr/share/plasma/look-and-feel/"
          "{plugin}/contents/splash/Splash.qml")
THEME_CONF = "packages/shadowfetch-themes/data/usr/share/sddm/themes/umbra/theme.conf"


def _surface_values(palette: dict, surface: str) -> set[str]:
    node = palette["surfaces"][surface]
    values = {v.lower() for k, v in node.get("roles", {}).items() if not k.startswith("_")}
    for element in node.get("element_roles", {}).values():
        values |= {v.lower() for v in element.values()}
    values |= {v.lower() for k, v in palette["semantic"].items() if not k.startswith("_")}
    for element in palette["elements"].values():
        values |= {element[k].lower() for k in ("accent", "accent_bright", "accent_deep")}
    return values


def check_palette_literals(_truth: dict) -> list[Finding]:
    """No colour ships that is neither a palette role nor a recorded stray."""
    palette = generate_theme_assets.load_palette()
    findings: list[Finding] = []

    for rel, surface in SURFACE_OF.items():
        allowed = _surface_values(palette, surface) | {
            value.lower() for value in UNNAMED_TODAY.get(rel, set())}
        try:
            text = read(rel)
        except OSError as exc:
            findings.append(Finding("DRIFT", "palette", rel, f"unreadable ({exc})"))
            continue
        seen = {m.group(0).lower() for m in _HEX.finditer(text)}
        strays = sorted(seen - allowed)
        if strays:
            findings.append(Finding(
                "DRIFT", "palette", site(rel, strays[0]),
                f"{len(strays)} colour(s) on the '{surface}' surface are neither a "
                f"palette role nor a recorded stray: {', '.join(strays)}",
                "name them in tools/truth/palette.json, or reuse an existing role"))
        unused = sorted(v for v in UNNAMED_TODAY.get(rel, set()) if v.lower() not in seen)
        if unused:
            findings.append(Finding(
                "DRIFT", "palette", rel,
                f"UNNAMED_TODAY still lists {', '.join(unused)}, which this file no "
                f"longer contains -- the ratchet has gone slack",
                "delete those entries from UNNAMED_TODAY in tools/drift_gate.py"))

    recorded = sum(len(v) for v in UNNAMED_TODAY.values())
    if recorded:
        findings.append(Finding(
            "BLOCKED", "palette", "tools/drift_gate.py:UNNAMED_TODAY",
            f"{recorded} shipped colours are still unnamed literals across "
            f"{sum(1 for v in UNNAMED_TODAY.values() if v)} files. They are frozen "
            f"(a new one fails this gate) but not deduplicated.",
            "ADR-0009: ship /usr/share/shadowfetch/theme/palette.json from "
            "shadowfetch-branding and have sfcc/Welcome/Fireproof import one loader. "
            "That needs a debian/*.install change, which is outside Stage X territory."))

    # Splash.qml and theme.conf embed the element accent by hand.
    for element, node in palette["elements"].items():
        rel = SPLASH.format(plugin=node["look_and_feel"])
        try:
            text = read(rel)
        except OSError as exc:
            findings.append(Finding("DRIFT", "palette", rel, f"unreadable ({exc})"))
            continue
        seen = {m.group(0).lower() for m in _HEX.finditer(text)}
        expected = {
            node["accent"].lower(),
            palette["surfaces"]["desktop"]["roles"]["mist"].lower(),
            palette["surfaces"]["desktop"]["roles"]["window"].lower(),
            palette["surfaces"]["desktop"]["roles"]["splash_bar"].lower(),
        }
        strays = sorted(seen - expected)
        if strays:
            findings.append(Finding(
                "DRIFT", "palette", site(rel, strays[0]),
                f"{element} splash uses {', '.join(strays)}; the desktop palette "
                f"expects {', '.join(sorted(expected))}",
                "correct the QML, or name the colour in palette.json"))

    fire_accent = palette["elements"]["fire"]["accent"]
    try:
        conf = read(THEME_CONF)
    except OSError as exc:
        findings.append(Finding("DRIFT", "palette", THEME_CONF, f"unreadable ({exc})"))
    else:
        match = re.search(r"(?m)^color=(#[0-9a-fA-F]{6})\s*$", conf)
        if match is None or match.group(1).lower() != fire_accent.lower():
            findings.append(Finding(
                "DRIFT", "palette", site(THEME_CONF, "color="),
                f"SDDM accent is {match.group(1) if match else 'absent'}; the Fire "
                f"accent is {fire_accent}"))
    return findings


# --------------------------------------------------------------------------- #
# check: look-and-feel packages must name themselves
# --------------------------------------------------------------------------- #
# ADR-0009: "the Ice look-and-feel declares itself as the Dark package, so
# choosing Ice installs the Fire splash and reports 'Shadowfetch Dark' as
# active."  Three keys inside one file decide this and they are copies of the
# directory name.
LNF_DEFAULTS = ("packages/shadowfetch-themes/data/usr/share/plasma/look-and-feel/"
                "{plugin}/contents/defaults")


def _ini_value(text: str, group: str, key: str) -> str | None:
    """Read key= from a [group] section of a Plasma 'defaults' file."""
    current = None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("[") and line.endswith("]"):
            current = line
        elif current == group and line.startswith(key + "="):
            return line[len(key) + 1:]
    return None


def check_lookandfeel(_truth: dict) -> list[Finding]:
    """Each look-and-feel package names itself, not the other one."""
    palette = generate_theme_assets.load_palette()
    findings = []
    for element, node in palette["elements"].items():
        plugin = node["look_and_feel"]
        rel = LNF_DEFAULTS.format(plugin=plugin)
        try:
            text = read(rel)
        except OSError as exc:
            findings.append(Finding("DRIFT", "look-and-feel", rel, f"unreadable ({exc})"))
            continue
        expected = {
            ("[ksplashrc][KSplash]", "Theme"): plugin,
            ("[kdeglobals][KDE]", "LookAndFeelPackage"): plugin,
            ("[kdeglobals][General]", "ColorScheme"): node["plasma_color_scheme"],
            ("[kdeglobals][General]", "Name"): node["look_and_feel_name"],
            ("[kdeglobals][General]", "AccentColor"):
                generate_theme_assets.rgb(node["accent"]),
            ("[Wallpaper]", "Image"): node["wallpaper_image"],
        }
        for (group, key), want in expected.items():
            got = _ini_value(text, group, key)
            if got != want:
                findings.append(Finding(
                    "DRIFT", "look-and-feel", site(rel, key + "="),
                    f"{element}: {group} {key}={got!r}, expected {want!r}",
                    "a look-and-feel package that names another package installs "
                    "that package's splash and reports the wrong theme as active"))
    return findings


ELEMENT_APPLIER = "packages/shadowfetch-defaults/data/usr/bin/shadowfetch-element"
FIRST_LOGIN = "packages/shadowfetch-defaults/data/usr/lib/shadowfetch/first-login.sh"
SKEL_KDEGLOBALS = "packages/shadowfetch-defaults/data/etc/skel/.config/kdeglobals"


def check_element_assets(_truth: dict) -> list[Finding]:
    """The element->asset map agrees with palette.json, and is complete.

    shadowfetch-element:46-48 restates, in bash, which colour scheme, wallpaper
    and Konsole scheme each element uses. palette.json is the source; this holds
    the copy to it and notices what the copy leaves out.
    """
    palette = generate_theme_assets.load_palette()
    findings: list[Finding] = []
    try:
        applier = read(ELEMENT_APPLIER)
    except OSError as exc:
        return [Finding("DRIFT", "element-assets", ELEMENT_APPLIER, f"unreadable ({exc})")]

    for element, node in palette["elements"].items():
        for key in ("plasma_color_scheme", "konsole_scheme", "wallpaper_package"):
            if node[key] not in applier:
                findings.append(Finding(
                    "DRIFT", "element-assets", site(ELEMENT_APPLIER, "apply_session"),
                    f"the {element} branch does not name {key} {node[key]!r}; "
                    f"tools/truth/palette.json says it should",
                    "keep the bash map and palette.json in step"))

    # An element whose look-and-feel package nothing applies is a package that
    # ships and never runs: choosing Ice leaves the Fire splash installed.
    applied: list[str] = []
    for rel in (ELEMENT_APPLIER, FIRST_LOGIN, SKEL_KDEGLOBALS):
        try:
            applied.append(read(rel))
        except OSError:
            applied.append("")
    everywhere = "\n".join(applied)
    unreachable = [
        element for element, node in palette["elements"].items()
        if node["look_and_feel"] not in everywhere
    ]
    if unreachable:
        findings.append(Finding(
            "BLOCKED", "element-assets", site(FIRST_LOGIN, "plasma-apply-lookandfeel"),
            f"no code path applies the look-and-feel package for: "
            f"{', '.join(unreachable)}. first-login.sh applies "
            f"{palette['elements']['fire']['look_and_feel']} unconditionally and "
            f"etc/skel/.config/kdeglobals hard-codes it, while shadowfetch-element "
            f"switches only the colour scheme, wallpaper and Konsole scheme. The "
            f"splash and window-decoration half of the element never switches.",
            "shadowfetch-element's apply_session() gains "
            "'plasma-apply-lookandfeel -a <package>' and first-login.sh reads the "
            "chosen element. Both files are shipped tools outside Stage X "
            "territory, so this is DETECTED, not fixed."))
    return findings


# --------------------------------------------------------------------------- #
# check: the workspace-name rule
# --------------------------------------------------------------------------- #
# THE SINGLE SOURCE.  Firebreak's rule is the strictest and it is the security
# boundary (it decides which directory an agent sandbox may write to), so it is
# the authority.  Every other implementation must agree DECISION FOR DECISION.
#
# This check does not compare source text.  It EXECUTES each implementation
# against the corpus, because three regexes that look alike can still disagree
# -- which is exactly what ARCHITECTURE_AUDIT.md:249 found ("already disagree
# on leading-dot names").
WORKSPACE_NAME_RULE = """A workspace name is one path segment, directly under the
workspace root: non-empty, no '/' or '\\\\', not '.' or '..', not starting with
'.', at most 160 characters, no control characters (ord < 32 or ord == 127)."""

# (name, valid, why)
WORKSPACE_CORPUS: tuple[tuple[str, bool, str], ...] = (
    ("project", True, "ordinary"),
    ("Project-2_final.v3", True, "mixed case, dash, underscore, dots inside"),
    ("a" * 160, True, "at the length limit"),
    ("", False, "empty"),
    (".", False, "self"),
    ("..", False, "parent"),
    (".ssh", False, "hidden: an agent must not be handed a dotfile directory"),
    (".config", False, "hidden"),
    ("a/b", False, "path separator escapes the root"),
    ("../etc", False, "traversal"),
    ("a\\b", False, "backslash: a separator on some filesystems, and a "
                    "quoting hazard in every shell that reads the manifest"),
    ("a" * 161, False, "over the length limit"),
    ("bad\nname", False, "newline: forges a line in any line-oriented record"),
    ("bad\x00name", False, "NUL"),
    ("bad\x7fname", False, "DEL"),
    ("bad\tname", False, "tab"),
)


def _load_module(name: str, rel: str):
    spec = importlib.util.spec_from_loader(
        name, importlib.machinery.SourceFileLoader(name, str(ROOT / rel)))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _firebreak_verdicts() -> dict[str, bool]:
    """True when Firebreak accepts the NAME (directory existence aside)."""
    module = _load_module("_sfx_firebreak",
                          "packages/shadowfetch-fireline/data/usr/bin/shadowfetch-firebreak")
    verdicts = {}
    for name, _, _ in WORKSPACE_CORPUS:
        if not name:
            # Firebreak treats "" as "derive from cwd", a different question.
            verdicts[name] = False
            continue
        try:
            module.workspace(name)
            verdicts[name] = True
        except module.Error as exc:
            # "missing or escapes" means the NAME passed and the directory did
            # not exist; only the name message is a name rejection.
            verdicts[name] = "direct non-hidden folder name" not in str(exc)
        except Exception:  # noqa: BLE001 - any other failure is a rejection
            verdicts[name] = False
    return verdicts


def _mcp_verdicts() -> dict[str, bool]:
    module = _load_module(
        "_sfx_mcp",
        "packages/shadowfetch-fireline/data/usr/lib/shadowfetch/mcp/sf_mcp.py")
    verdicts = {}
    for name, _, _ in WORKSPACE_CORPUS:
        try:
            module._safe_name(name)
            verdicts[name] = True
        except Exception:  # noqa: BLE001
            verdicts[name] = False
    return verdicts


def _mission_client_verdicts() -> dict[str, bool]:
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    sys.path.insert(0, str(
        ROOT / "packages/shadowfetch-control-center/data/usr/share/shadowfetch/"
               "control-center"))
    module = _load_module(
        "_sfx_mission_client",
        "packages/shadowfetch-control-center/data/usr/share/shadowfetch/"
        "control-center/sfcc/mission_client.py")
    verdicts = {}
    for name, _, _ in WORKSPACE_CORPUS:
        try:
            module.workspace_path(name)
            verdicts[name] = True
        except ValueError as exc:
            # workspace_path also refuses a directory that does not exist yet.
            # That is not a NAME decision, so separate the two by message.
            verdicts[name] = "does not exist yet" in str(exc)
        except Exception:  # noqa: BLE001
            verdicts[name] = False
    return verdicts


IMPLEMENTATIONS = (
    ("shadowfetch-firebreak:131 workspace()", _firebreak_verdicts,
     "packages/shadowfetch-fireline/data/usr/bin/shadowfetch-firebreak"),
    ("sf_mcp.py:789 _safe_name()", _mcp_verdicts,
     "packages/shadowfetch-fireline/data/usr/lib/shadowfetch/mcp/sf_mcp.py"),
    ("mission_client.py:55 workspace_path()", _mission_client_verdicts,
     "packages/shadowfetch-control-center/data/usr/share/shadowfetch/"
     "control-center/sfcc/mission_client.py"),
)

# The bash tool SANITISES rather than validates, so it cannot be compared
# verdict-for-verdict.  Its contract is weaker and checkable: whatever it
# emits must be a name the rule accepts.
AGENT_WORKSPACE = "packages/shadowfetch-defaults/data/usr/bin/shadowfetch-agent-workspace"


def _rule_accepts(name: str) -> bool:
    return bool(
        isinstance(name, str) and name and len(name) <= 160
        and name not in (".", "..") and not name.startswith(".")
        and "/" not in name and "\\" not in name
        and not any(ord(c) < 32 or ord(c) == 127 for c in name)
    )


def check_workspace_name(_truth: dict) -> list[Finding]:
    """Every workspace-name implementation decides the corpus the same way."""
    findings: list[Finding] = []

    # The corpus is only an authority if the rule as written agrees with it.
    for name, valid, why in WORKSPACE_CORPUS:
        if _rule_accepts(name) != valid:
            findings.append(Finding(
                "DRIFT", "workspace-name", "tools/drift_gate.py:WORKSPACE_CORPUS",
                f"the corpus and _rule_accepts() disagree on {name!r} ({why})"))
    if findings:
        return findings

    for label, probe, rel in IMPLEMENTATIONS:
        try:
            verdicts = probe()
        except Exception as exc:  # noqa: BLE001
            findings.append(Finding(
                "DRIFT", "workspace-name", rel,
                f"{label} could not be exercised: {type(exc).__name__}: {exc}",
                "the rule cannot be proven to hold for an implementation that "
                "will not run"))
            continue
        disagreements = [
            (name, verdicts[name], valid, why)
            for name, valid, why in WORKSPACE_CORPUS
            if verdicts.get(name) != valid
        ]
        for name, got, want, why in disagreements:
            findings.append(Finding(
                "BLOCKED", "workspace-name", f"{rel} ({label})",
                f"{name!r}: this implementation says "
                f"{'ACCEPT' if got else 'REJECT'}, the rule says "
                f"{'ACCEPT' if want else 'REJECT'} -- {why}",
                "adopt the rule in WORKSPACE_NAME_RULE. This file is another "
                "agent's territory in Stage X, so the divergence is DETECTED, "
                "not fixed."))

    # The sanitiser's output must always be an acceptable name.
    try:
        text = read(AGENT_WORKSPACE)
    except OSError as exc:
        findings.append(Finding("DRIFT", "workspace-name", AGENT_WORKSPACE,
                                f"unreadable ({exc})"))
        return findings
    if "sanitize()" not in text and "sanitize " not in text:
        findings.append(Finding(
            "DRIFT", "workspace-name", AGENT_WORKSPACE,
            "the sanitize() helper this check exercises is gone"))
        return findings
    # THE SHIPPED FUNCTION, LIFTED OUT AND RUN. This block used to carry its
    # own copy of the pipeline and execute that -- a second implementation of
    # the very thing this file exists to stop, inside the detector. It graded a
    # sanitiser nobody ships: when the real one was fixed, the gate went on
    # reporting the old answers, and had the real one regressed the gate would
    # have gone on reporting the good ones.
    start = text.index("sanitize()")
    end = text.index("\n}", start) + 2
    script = text[start:end] + "\n"
    for name, _, _ in WORKSPACE_CORPUS:
        if "\x00" in name:
            continue  # argv cannot carry a NUL; the shell never sees this one
        result = subprocess.run(
            ["bash", "-c", script + 'sanitize "$1"', "_", name],
            capture_output=True, text=True, check=False)
        produced = result.stdout.rstrip("\n")
        if produced == "":
            continue  # empty output is rejected by the caller's own guard
        if not _rule_accepts(produced):
            # BLOCKED rather than DRIFT because the remedy is a change to a
            # shipped tool rather than a disagreement between two copies. The
            # finding is real: a sanitiser that returns ".ssh" lets the tool
            # create ~/Workspaces/.ssh, which Firebreak then refuses to open,
            # and the caller's only guard is `!= .` and `!= ..`.
            findings.append(Finding(
                "BLOCKED", "workspace-name", site(AGENT_WORKSPACE, "sanitize()"),
                f"sanitize({name!r}) produced {produced!r}, which the workspace-name "
                f"rule rejects -- this tool can create a workspace the security "
                f"boundary will not open",
                "sanitize() becomes: printf '%s' \"$1\" | tr -d '\\000-\\037\\177' | "
                "tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9._-]+/-/g; "
                "s/^[.-]+//; s/-+$//' | cut -c1-48   "
                "(drop control characters, strip leading dots as well as dashes)"))
    return findings


# --------------------------------------------------------------------------- #
# check: shared desktop helper paths and argv
# --------------------------------------------------------------------------- #
# ARCHITECTURE_AUDIT.md:19 -- "the correct argv existed in two places and the
# third copy was written from a docstring", which shipped seven dead Install
# buttons that failed AFTER the user entered an admin password.  The one gate
# that checked this (package_gate_4_0_0.py:331) looked at a single call site.
# This one enumerates them.
HELPER_PATHS = {
    "bundle-install": "/usr/libexec/shadowfetch-bundle-install",
    "hwscan-cli": "/usr/libexec/shadowfetch-hwscan",
    "hwscan-json": "/var/lib/shadowfetch/hwscan.json",
    "catalog-dir": "/usr/share/shadowfetch/welcome/catalog",
    "phoenix-restore": "/usr/libexec/phoenix-restore",
}
HELPER_CONSUMERS = (
    # The Control Center's copy of these paths moved to sfcc/desktop.py, which
    # busutil re-exports. Reading busutil here would report five false drifts
    # against a file that no longer spells any of them out.
    "packages/shadowfetch-control-center/data/usr/share/shadowfetch/"
    "control-center/sfcc/desktop.py",
    "packages/shadowfetch-welcome/src/shadowfetch-welcome",
)
BUNDLE_CALL_SITES = (
    "packages/shadowfetch-control-center/data/usr/share/shadowfetch/"
    "control-center/sfcc/desktop.py",
    "packages/shadowfetch-control-center/data/usr/share/shadowfetch/"
    "control-center/sfcc/software_page.py",
    "packages/shadowfetch-control-center/data/usr/share/shadowfetch/"
    "control-center/sfcc/workbench_page.py",
    "packages/shadowfetch-welcome/src/shadowfetch-welcome",
)
# The builder writes the constant unquoted (`[pkexec, BUNDLE_HELPER, ...]`
# where pkexec is itself a named path), the call sites wrote it quoted. Both
# spellings are the same argv and both have to be checked.
_PKEXEC_BUNDLE = re.compile(
    r'\[\s*(?:"pkexec"|pkexec)\s*,\s*([A-Za-z_.]+)\s*,\s*("install")?',
    re.MULTILINE)


def bundle_builder_source(text: str):
    """The source of `bundle_install_argv`, if this file is the one that
    defines it.

    Scoped to that ONE function deliberately. The same module builds other
    pkexec argvs whose verb is not "install" -- apt_snapshot_toggle_argv says
    "enable" -- and a whole-file scan reads those as a bundle call with the
    wrong verb, which is a finding about a contract they were never under.
    """
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "bundle_install_argv":
            return ast.get_source_segment(text, node) or ""
    return None


def check_desktop_helpers(_truth: dict) -> list[Finding]:
    """The two desktop front-ends agree on helper paths and pkexec argv."""
    findings = []
    for rel in HELPER_CONSUMERS:
        try:
            text = read(rel)
        except OSError as exc:
            findings.append(Finding("DRIFT", "desktop-helpers", rel,
                                    f"unreadable ({exc})"))
            continue
        for label, path in HELPER_PATHS.items():
            if path not in text:
                findings.append(Finding(
                    "DRIFT", "desktop-helpers", rel,
                    f"does not name the shared {label} path {path!r}; the two "
                    f"desktop front-ends must agree on where the helper lives",
                    "keep both copies identical, or import one constant"))

    for rel in BUNDLE_CALL_SITES:
        try:
            text = read(rel)
        except OSError as exc:
            findings.append(Finding("DRIFT", "desktop-helpers", rel,
                                    f"unreadable ({exc})"))
            continue
        builder = bundle_builder_source(text)
        scope = text if builder is None else builder
        calls = _PKEXEC_BUNDLE.findall(scope)
        bundle_calls = [c for c in calls if "BUNDLE" in c[0].upper()
                        or c[0] == "helper"]
        if not bundle_calls:
            # A site that DELEGATES is not a site that drifted. The Control
            # Center pages call desktop.bundle_install_argv() now, so the argv
            # is spelled once, in the builder, which is checked on its own
            # source above. Demanding the literal at every page would push the
            # copies back out, which is the drift this check exists to stop.
            if builder is None and "bundle_install_argv(" in text:
                continue
            findings.append(Finding(
                "DRIFT", "desktop-helpers", rel,
                "no pkexec bundle-install call found and nothing delegates to "
                "bundle_install_argv(); this file is one of the call sites the "
                "argv contract covers"))
            continue
        for constant, verb in bundle_calls:
            if verb != '"install"':
                findings.append(Finding(
                    "DRIFT", "desktop-helpers", site(rel, constant),
                    f'pkexec {constant} is called without the "install" verb; the '
                    f"helper exits 2 AFTER the admin password prompt",
                    'the contract is ["pkexec", <helper>, "install", <catalog id>]'))

    findings.append(Finding(
        "BLOCKED", "desktop-helpers", "sfcc/busutil.py + shadowfetch-welcome",
        "load_catalog(), the hwscan freshness rule and the five helper paths are "
        "still implemented twice, in two divergent shapes (busutil returns a list "
        "filtered by kind and tolerates a JSON array; Welcome returns a dict keyed "
        "by id and does not). The gate holds them to the same PATHS and the same "
        "argv; it cannot make them one implementation.",
        "ADR/W-30: a shared desktop library imported by both. That is a new "
        "installed module in two packages (debian/*.install), outside Stage X "
        "territory."))
    return findings


# --------------------------------------------------------------------------- #
# check: the current-release pointer
# --------------------------------------------------------------------------- #

def check_release_pointer(truth: dict) -> list[Finding]:
    """"The current release" is defined in one place, not derived twice."""
    pointer = truth["release_pointer"]
    findings = []
    worker = "web/shadowfetch-linux-worker/src/index.js"
    try:
        text = read(worker)
    except OSError as exc:
        return [Finding("DRIFT", "release-pointer", worker, f"unreadable ({exc})")]

    implemented = pointer["key"] in text
    if pointer["status"] == "NOT IMPLEMENTED" and implemented:
        findings.append(Finding(
            "DRIFT", "release-pointer", site(worker, pointer["key"]),
            f"the worker now reads {pointer['key']}, but tools/truth/release.json "
            f"still records the pointer as NOT IMPLEMENTED",
            "update release_pointer.status in tools/truth/release.json"))
    elif not implemented:
        findings.append(Finding(
            "BLOCKED", "release-pointer", site(worker, "async function latestRelease"),
            '"the current release" is still derived by sorting an unpaginated '
            "100-object R2 listing by upload time. Re-uploading an old ISO "
            "promotes it to current, and the site and the publisher can disagree "
            "about which release is live.",
            f"ADR-0009: {pointer['written_by']} writes {pointer['key']} LAST; "
            f"{pointer['read_by']} reads that one key. Changing the live artifact "
            "worker is outside Stage X territory."))
    return findings


# --------------------------------------------------------------------------- #
# driver
# --------------------------------------------------------------------------- #

CHECKS = (
    ("version", check_version),
    ("fingerprint", check_fingerprint),
    ("release-data", check_release_data),
    ("theme-assets", check_theme_assets),
    ("palette", check_palette_literals),
    ("look-and-feel", check_lookandfeel),
    ("element-assets", check_element_assets),
    ("workspace-name", check_workspace_name),
    ("desktop-helpers", check_desktop_helpers),
    ("release-pointer", check_release_pointer),
)


def run(only: tuple[str, ...] = ()) -> list[Finding]:
    truth = load_truth()
    findings: list[Finding] = []
    for name, fn in CHECKS:
        if only and name not in only:
            continue
        try:
            findings.extend(fn(truth))
        except Exception as exc:  # noqa: BLE001 - a check that crashes is a failure
            findings.append(Finding(
                "DRIFT", name, "tools/drift_gate.py",
                f"the {name} check raised {type(exc).__name__}: {exc}"))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--only", action="append", default=[],
                        choices=[name for name, _ in CHECKS],
                        help="run just this check (repeatable)")
    parser.add_argument("--strict", action="store_true",
                        help="exit non-zero for BLOCKED findings too")
    parser.add_argument("--list", action="store_true", help="list the checks")
    args = parser.parse_args(argv)

    if args.list:
        for name, fn in CHECKS:
            print(f"{name:<16} {(fn.__doc__ or '').strip().splitlines()[0] if fn.__doc__ else ''}")
        return 0

    findings = run(tuple(args.only))
    drift = [f for f in findings if f.kind == "DRIFT"]
    blocked = [f for f in findings if f.kind == "BLOCKED"]

    for finding in drift + blocked:
        print(finding)
        print()

    print(f"drift gate: {len(drift)} DRIFT, {len(blocked)} BLOCKED "
          f"across {len(args.only) or len(CHECKS)} checks")
    if drift:
        print("DRIFT_GATE_FAILED", file=sys.stderr)
        return 1
    if blocked and args.strict:
        print("DRIFT_GATE_FAILED (--strict: blocked findings count)", file=sys.stderr)
        return 1
    if blocked:
        print("DRIFT_GATE_PASSED_WITH_BLOCKED -- the duplications above are "
              "DETECTED, not removed.")
    else:
        print("DRIFT_GATE_PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
