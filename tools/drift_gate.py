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
    # The conffile-removal trigger. dpkg-maintscript-helper fires rm_conffile
    # only for upgrades FROM BELOW this version, so a stale value is not a
    # cosmetic mismatch -- at 4.0.0-1~ the removal would have skipped every
    # machine running 4.0.0-1, which is the whole installed base. Only the
    # line this release adds is anchored; the 2.1.4-1~ lines above it are
    # history and must not move.
    ("packages/shadowfetch-defaults/debian/shadowfetch-defaults.maintscript",
     r"rm_conffile /etc/apt/apt\.conf\.d/52shadowfetch-unattended\.conf ([0-9.]+)-\d+~",
     "unattended-upgrades conffile removal trigger"),
    # The pickup contract's binary version. No gate imports it -- its only
    # reader is its own test -- and that test compared it against release data
    # it loaded BY NAME, so both sides went stale together and stayed green.
    ("tools/drkonqi_pickup_contract.py",
     r'(?m)^VERSION = "([0-9.]+)-\d+"', "drkonqi pickup contract VERSION"),
    # A Shadowfetch package that floors a Shadowfetch SIBLING must floor it at
    # this release. shadowfetch-missions went to 4.1.0 still asking apt for
    # `shadowfetch-fireline (>= 4.0.0)`, which the RELEASED 4.0.0 firebreak
    # satisfies -- and that firebreak (shipped commit e1293bfa) contains none
    # of --egress-host, --seccomp or --credential-broker, the flags the 4.1.0
    # engine passes it. A partial upgrade paired the new engine with a sandbox
    # that rejects its argv. Being on this list also means the stamper rewrites
    # it, so the floor now moves with the release instead of being remembered.
    ("packages/shadowfetch-missions/debian/control",
     r"shadowfetch-fireline \(>= ([0-9.]+)\)", "missions -> fireline floor"),
    ("README.md", r"(?m)^\| Version / codename \| (\S+) /", "README fact table"),
    # The build section names the ISO and the Makefile default in prose. It was
    # not on this list, so the stamper (which imports it) left both at 4.0.0
    # while the Makefile beside them moved -- a README telling a reader to
    # expect an artifact the build does not produce.
    ("README.md", r"`make iso` produces `shadowfetch-([0-9.]+)-amd64\.iso`",
     "README build section ISO name"),
    ("README.md", r"`VERSION \?= ([0-9.]+)` and `CODENAME",
     "README build section Makefile default"),
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
# The ONE implementation of the desktop facts W-30 names.  Until Stage W these
# lived twice -- once behind sfcc/busutil.py, once inside shadowfetch-welcome --
# and this check could only hold the two copies to the same paths and the same
# argv, which is why it also emitted a BLOCKED finding saying so.  The module
# moved to the package both front-ends depend on, and the check changed shape
# with it: it no longer asks whether two copies agree, it asks whether there is
# one.  Those are different claims and only the second one is deduplication.
DESKTOP_LIBRARY = ("packages/shadowfetch-defaults/data/usr/lib/shadowfetch/"
                   "desktop/sf_desktop.py")
DESKTOP_LIBRARY_DIR = "/usr/lib/shadowfetch/desktop"
DESKTOP_LIBRARY_MODULE = "sf_desktop"
DESKTOP_LIBRARY_PACKAGE = "shadowfetch-defaults"

# A file at the shared path proves nothing on its own; these are the facts it
# has to actually implement for the front-ends to have stopped implementing
# them.  Each name is one of the things the audit found written twice.
DESKTOP_LIBRARY_API = (
    "def trusted_program(",     # which binary runs, from a fixed table
    "def trusted_env(",         # and what PATH its children inherit
    "def load_catalog(",        # the bundle catalog, list shape
    "def catalog_by_id(",       # the same records, Welcome's dict shape
    "def installed_map(",       # "already on your system", one dpkg-query
    "def hwscan_is_fresh(",     # the freshness rule
    "def load_hwscan(",         # fact file or CLI
    "def hwscan_cached(",       # fact file only, for the UI thread
    "def bundle_install_argv(", # the privileged argv
    "def start_detached(",      # launch
)

HELPER_PATHS = {
    "bundle-install": "/usr/libexec/shadowfetch-bundle-install",
    "hwscan-cli": "/usr/libexec/shadowfetch-hwscan",
    "hwscan-json": "/var/lib/shadowfetch/hwscan.json",
    "catalog-dir": "/usr/share/shadowfetch/welcome/catalog",
    "phoenix-restore": "/usr/libexec/phoenix-restore",
}

# The two desktop front-end entry points.  Each has to LOAD the library, and
# neither may spell a helper path out again -- a second spelling is the drift
# coming back, whether or not it currently agrees.
FRONT_ENDS = (
    "packages/shadowfetch-control-center/data/usr/share/shadowfetch/"
    "control-center/sfcc/desktop.py",
    "packages/shadowfetch-welcome/src/shadowfetch-welcome",
)

# "One module, imported by both" is a claim about an INSTALLED system, not
# about this tree: it is false if the module is not shipped, and false if a
# front-end's package does not pull in the package that ships it.  Both
# front-ends raise ImportError without it, so both need a hard Depends.
LIBRARY_INSTALL = ("packages/shadowfetch-defaults/debian/"
                   "shadowfetch-defaults.install")
FRONT_END_CONTROL = {
    "packages/shadowfetch-welcome/debian/control": "shadowfetch-welcome",
    "packages/shadowfetch-control-center/debian/control":
        "shadowfetch-control-center",
}

# Every file this check reads.  The name is older than the contents: in Stage X
# it held the two front-ends and nothing else, because comparing their copies
# was the most the gate could do.
HELPER_CONSUMERS = (FRONT_ENDS + (DESKTOP_LIBRARY, LIBRARY_INSTALL)
                    + tuple(FRONT_END_CONTROL))

# Where the privileged bundle argv may be built (the library) and where it must
# instead be delegated (everywhere else).
BUNDLE_CALL_SITES = (
    DESKTOP_LIBRARY,
    "packages/shadowfetch-control-center/data/usr/share/shadowfetch/"
    "control-center/sfcc/software_page.py",
    "packages/shadowfetch-control-center/data/usr/share/shadowfetch/"
    "control-center/sfcc/workbench_page.py",
    "packages/shadowfetch-welcome/src/shadowfetch-welcome",
)
# Every desktop file that must DELEGATE to the library rather than implement a
# desktop fact of its own: both front-end entry points, and the two Control
# Center pages that carry an Install button.  The library is deliberately not
# here -- it is the one place these things are built.
DELEGATING_SITES = tuple(dict.fromkeys(
    FRONT_ENDS + tuple(rel for rel in BUNDLE_CALL_SITES if rel != DESKTOP_LIBRARY)))

# A program whose argv either asks the user for an administrator password or
# runs as root once they have typed it, plus Shadowfetch's own helpers, whose
# resolution is the library's trusted-program table and nothing else.  A
# delegating site may not assemble one of these argvs AT ALL.  That is the
# honest form of this rule: not a list of forbidden spellings that a new
# spelling walks past, but one legal source for the whole shape.
PRIVILEGED_HEADS = ("pkexec", "sudo", "doas", "pfexec", "run0")
PRIVILEGED_PREFIXES = ("shadowfetch-", "phoenix-", "ember-")

# Calls that enumerate a directory.  A function that walks a directory and
# decodes JSON out of it is a catalog reader whatever it has been named.
DIR_ENUMERATORS = ("glob", "iglob", "listdir", "scandir", "iterdir", "rglob",
                   "walk")

# How a front-end may get hold of the library.  `import sf_desktop` resolves
# through sys.modules BEFORE sys.path, so a module already registered under
# that name is returned and an existence check performed a line earlier decides
# nothing (ATTACK B).  spec_from_file_location executes the file that was
# checked and never consults sys.modules.
FILE_LOADERS = ("spec_from_file_location", "SourceFileLoader")


def _constant_truth(test):
    """True/False when the source itself decides a branch, else None."""
    if isinstance(test, ast.Constant):
        return bool(test.value)
    return None


def walk_reachable(node):
    """ast.walk, minus the branches the source itself decides are dead.

    ATTACK C: `imports_module()` counted `if False:\n    import sf_desktop` as
    proof that a front-end loads the shared library.  That import binds nothing
    at runtime, so the front-end was free to bind the name to anything at all
    and still satisfy the check.
    """
    yield node
    if isinstance(node, (ast.If, ast.While)):
        yield from walk_reachable(node.test)
        decided = _constant_truth(node.test)
        bodies = ([node.body, node.orelse] if decided is None
                  else [node.body] if decided else [node.orelse])
        for body in bodies:
            for child in body:
                yield from walk_reachable(child)
        return
    for child in ast.iter_child_nodes(node):
        yield from walk_reachable(child)


def parse_fragment(source):
    """An AST for a source fragment that may be indented (a nested def)."""
    try:
        return ast.parse(source)
    except (SyntaxError, IndentationError):
        pass
    try:
        return ast.parse("if True:\n" + "\n".join(
            "    " + line for line in source.splitlines()))
    except (SyntaxError, IndentationError):
        return None


def _fold_args(node, env, depth):
    """The folded elements of a tuple/list argument, or of a single one."""
    elements = node.elts if isinstance(node, (ast.Tuple, ast.List)) else [node]
    parts = [_fold_str(element, env, depth + 1) for element in elements]
    return None if any(part is None for part in parts) else parts


def _fold_call(node, env, depth):
    func = node.func
    name = getattr(func, "id", None)
    attr = getattr(func, "attr", None)
    args = [_fold_str(argument, env, depth + 1) for argument in node.args]
    whole = bool(args) and all(argument is not None for argument in args)
    if name in ("Path", "PurePath", "PosixPath", "PurePosixPath", "str"):
        # Path("/usr/libexec", "shadowfetch-bundle-install") joins; str() is a
        # single argument and os.path.join of one element is that element.
        return os.path.join(*args) if whole else None
    if attr == "join" and getattr(getattr(func, "value", None), "attr", None) == "path":
        return os.path.join(*args) if whole else None            # os.path.join
    if attr == "join" and node.args:                             # "/".join([...])
        separator = _fold_str(func.value, env, depth + 1)
        parts = _fold_args(node.args[0], env, depth)
        return None if separator is None or parts is None else separator.join(parts)
    if attr == "format" and not node.keywords:
        template = _fold_str(func.value, env, depth + 1)
        if template is None or not whole:
            return None
        try:
            return template.format(*args)
        except (IndexError, KeyError, ValueError):
            return None
    if attr in ("normpath", "realpath", "abspath") and whole:
        return os.path.normpath(args[0])
    return None


def _fold_str(node, env, depth=0):
    """The string `node` evaluates to, when the source decides it.

    This exists because the check it replaces asked `path in code`, and
    `"/usr/libexec/" "shadowfetch-bundle-install"` is not that substring while
    naming that exact file.  CPython folds adjacent literals before this
    scanner ever sees them, which is precisely why the AST catches for free the
    form the source grep could not see at all; `+`, os.path.join, a pathlib
    `/`, %-formatting, .format, str.join, f-strings and names bound to any of
    those are the forms an author reaches for next.
    """
    if depth > 12:
        return None
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else None
    if isinstance(node, ast.Name):
        values = env.get(node.id) or []
        # A name bound to two different strings folds to neither: this scanner
        # reports what the source proves.  Both bound values are still scanned
        # where they are written, so nothing is lost by declining here.
        return values[0] if len(values) == 1 else None
    if isinstance(node, ast.JoinedStr):
        parts = []
        for piece in node.values:
            inner = piece.value if isinstance(piece, ast.FormattedValue) else piece
            folded = _fold_str(inner, env, depth + 1)
            if folded is None:
                return None
            parts.append(folded)
        return "".join(parts)
    if isinstance(node, ast.BinOp):
        left = _fold_str(node.left, env, depth + 1)
        if isinstance(node.op, ast.Add):
            right = _fold_str(node.right, env, depth + 1)
            return None if left is None or right is None else left + right
        if isinstance(node.op, ast.Div):          # Path("/usr/libexec") / helper
            right = _fold_str(node.right, env, depth + 1)
            return None if left is None or right is None else os.path.join(left, right)
        if isinstance(node.op, ast.Mod):          # "%s/%s" % (directory, helper)
            parts = _fold_args(node.right, env, depth)
            if left is None or parts is None:
                return None
            try:
                return left % tuple(parts)
            except (TypeError, ValueError):
                return None
        return None
    if isinstance(node, ast.Call):
        return _fold_call(node, env, depth)
    return None


def fold_env(tree):
    """Names bound to a string this scanner can decide from the source alone.

    Collected wherever they are bound rather than at module level only -- a
    second implementation hidden inside a function body is still a second
    implementation -- and iterated to a fixed point, so that
    `_HELPER = _DIR + "/shadowfetch-bundle-install"` resolves once `_DIR` has.
    """
    env = {}
    for _ in range(4):
        changed = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                targets = [t for t in node.targets if isinstance(t, ast.Name)]
                value = node.value
            elif (isinstance(node, ast.AnnAssign) and node.value
                  and isinstance(node.target, ast.Name)):
                targets, value = [node.target], node.value
            else:
                continue
            folded = _fold_str(value, env)
            if folded is None:
                continue
            for target in targets:
                bucket = env.setdefault(target.id, [])
                if folded not in bucket:
                    bucket.append(folded)
                    changed = True
        if not changed:
            break
    return env


def _prose_ids(tree):
    """Node ids of docstrings and bare string statements: prose, not code.

    The house style is to name the file a constant points at, so a scanner that
    cannot tell a path in a sentence from a path in an argv teaches the next
    author to delete the sentence.  code_text() does this by line number for
    the substring scans; the AST scans need the node identities.
    """
    return {id(node.value) for node in ast.walk(tree)
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)}


def assembled_path_hits(text):
    """(line, reserved path) for every reserved helper path this source names
    with anything other than one plain literal.

    The verifier's plant assembled `/usr/libexec/shadowfetch-bundle-install`
    out of two adjacent literals and walked past `path in code` with a complete
    second bundle installer behind it.
    """
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    env = fold_env(tree)
    prose = _prose_ids(tree)
    reserved = tuple(HELPER_PATHS.values())
    hits, seen = [], set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.expr) or id(node) in prose:
            continue
        # Constants are NOT skipped. `"/usr/libexec/" "shadowfetch-bundle-"
        # "install"` reaches this scanner as ONE Constant already folded by
        # CPython, and the source it was folded from is exactly what the
        # substring scan cannot see. A path that IS written as one plain
        # literal is de-duplicated by the caller, which skips any path the
        # substring scan has already reported for this file.
        value = _fold_str(node, env)
        if not value:
            continue
        for path in reserved:
            if value == path or value.startswith(path.rstrip("/") + "/"):
                key = (getattr(node, "lineno", 0), path)
                if key not in seen:
                    seen.add(key)
                    hits.append(key)
    return sorted(hits)


def privileged_argv_displays(text):
    """(line, program) for every list/tuple in this source whose FIRST element
    is a privileged program or a Shadowfetch helper.

    Every display, not only the ones passed as the first positional argument of
    run/Popen/CommandWorker: the check this replaces looked nowhere else, so a
    builder that RETURNED the argv was invisible, `Popen(_install_argv(id))`
    passed an ast.Call, and `argv = [...]` bound one line earlier was never
    looked at.
    """
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    env = fold_env(tree)
    prose = _prose_ids(tree)
    hits, seen = [], set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.List, ast.Tuple)) or not node.elts:
            continue
        if id(node) in prose:
            continue
        head = _fold_str(node.elts[0], env)
        if not head:
            continue
        program = head.rsplit("/", 1)[-1]
        if program in PRIVILEGED_HEADS or program.startswith(PRIVILEGED_PREFIXES):
            key = (getattr(node, "lineno", 0), head)
            if key not in seen:
                seen.add(key)
                hits.append(key)
    return sorted(hits)


def catalog_reader_functions(text):
    """(line, name) for every function here that walks a directory and decodes
    JSON out of it -- the shape of load_catalog(), whatever it is called.

    The check this replaces grepped for `def load_catalog(` and
    `def hwscan_cached(`.  A rename defeated it, and nothing else did.
    """
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        enumerates = decodes = False
        for inner in ast.walk(node):
            if not isinstance(inner, ast.Call):
                continue
            attr = getattr(inner.func, "attr", None)
            name = getattr(inner.func, "id", None)
            if attr in DIR_ENUMERATORS or name in DIR_ENUMERATORS:
                enumerates = True
            if (attr in ("load", "loads")
                    and getattr(getattr(inner.func, "value", None), "id", None) == "json"):
                decodes = True
        if enumerates and decodes:
            found.append((node.lineno, node.name))
    return sorted(found)


def library_program_paths(text):
    """The absolute program paths the shared library declares in PROGRAMS.

    Read so that a front-end naming one of them can be told apart from a
    front-end naming a program the table does not carry at all. The first is
    this check's own duplication; the second is a hole in the table.
    """
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return set()
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Assign) and isinstance(node.value, ast.Dict)):
            continue
        if not any(getattr(target, "id", None) == "PROGRAMS"
                   for target in node.targets):
            continue
        paths = set()
        for value in node.value.values:
            if isinstance(value, ast.Tuple) and value.elts:
                first = value.elts[0]
                if isinstance(first, ast.Constant) and isinstance(first.value, str):
                    paths.add(first.value)
        return paths
    return set()


def library_resolution(text):
    """How this front-end gets the library: by file, by name, or not at all."""
    kinds = set()
    if imports_module(text, DESKTOP_LIBRARY_MODULE):
        kinds.add("name")
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return kinds
    for node in walk_reachable(tree):
        if isinstance(node, ast.Call):
            called = getattr(node.func, "attr", None) or getattr(node.func, "id", None)
            if called in FILE_LOADERS:
                kinds.add("file")
    return kinds


def builder_bundle_argvs(builder):
    """(helper constant, verb as written) for every pkexec argv this builder
    produces.

    Read from the AST rather than with a regex over the RAW function source:
    `[pkexec, helper, "install", id]` and `["pkexec", BUNDLE_HELPER, "install",
    id]` are the same argv and both are read here, and a comment can no longer
    supply one.  A verb laundered through a variable is not the literal
    "install" and is still reported -- that property is the point of the check
    and is kept exactly.
    """
    tree = parse_fragment(builder)
    if tree is None:
        return []
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.List, ast.Tuple)) or len(node.elts) < 2:
            continue
        head = node.elts[0]
        if not (getattr(head, "id", None) == "pkexec"
                or (isinstance(head, ast.Constant) and head.value == "pkexec")):
            continue
        helper = node.elts[1]
        constant = (getattr(helper, "id", None)
                    or getattr(helper, "attr", None)
                    or (helper.value if isinstance(helper, ast.Constant) else ""))
        verb = node.elts[2] if len(node.elts) > 2 else None
        spelled = (f'"{verb.value}"'
                   if isinstance(verb, ast.Constant) and isinstance(verb.value, str)
                   else None)
        out.append((str(constant), spelled))
    return out


def builder_resolves_pkexec_by_table(builder):
    """True when the builder resolves pkexec through trusted_program().

    Read from the AST, because the substring check this replaces ran over the
    raw source: `# trusted_program("pkexec")` in a comment satisfied it while
    the code called shutil.which("pkexec").  That plant was measured, not
    theorised -- it reported "DRIFT findings: 0".
    """
    tree = parse_fragment(builder)
    if tree is None:
        return False
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call)
                and (getattr(node.func, "id", None) == "trusted_program"
                     or getattr(node.func, "attr", None) == "trusted_program")
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and node.args[0].value == "pkexec"):
            return True
    return False


def imports_module(text: str, name: str) -> bool:
    """True when this source really imports `name`.

    Reading the import statement rather than searching for the word: both
    front-ends also name the module in the ImportError they raise without it,
    so a file that stopped importing it would still have contained the string.
    `import something as sf_desktop` binds the name and imports another module,
    which is the same failure wearing the right label.

    Reading only REACHABLE statements, because it used to read all of them:
    `if False:` + `import sf_desktop` satisfied this function while the name
    was bound to something else entirely (ATTACK C).
    """
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return False
    for node in walk_reachable(tree):
        if isinstance(node, ast.Import):
            if any(alias.name == name for alias in node.names):
                return True
        elif isinstance(node, ast.ImportFrom) and node.module == name:
            return True
    return False


def code_text(text: str) -> str:
    """`text` with comments and docstrings blanked, line numbers preserved.

    Every count below is about CODE.  The house style here is to name the
    defect a change removed and to say which file a constant points at, so a
    scanner that cannot tell a path in a sentence from a path in an argv either
    fires on the explanation or teaches the next author to delete it.  That is
    the same reason tools/tests/test_privileged_operations.py reads code_lines()
    rather than the file.  String literals that are not docstrings are KEPT:
    the constants this check is about are string literals.
    """
    lines = text.splitlines()
    prose = set()
    try:
        tree = ast.parse(text)
    except SyntaxError:
        tree = None          # debian/control and *.install are not Python
    if tree is not None:
        for node in ast.walk(tree):
            if (isinstance(node, ast.Expr)
                    and isinstance(node.value, ast.Constant)
                    and isinstance(node.value.value, str)):
                prose.update(range(node.lineno,
                                   (node.end_lineno or node.lineno) + 1))
    return "\n".join("" if (number in prose or line.lstrip().startswith("#"))
                      else line
                      for number, line in enumerate(lines, 1))


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


def depends_field(text: str, package: str) -> str:
    """The Depends field of one binary stanza in a debian/control, as one
    string.  Comment lines are dropped the way dpkg drops them, so a `#` note
    inside the field cannot be read as a dependency."""
    lines = [line for line in text.splitlines() if not line.startswith("#")]
    stanza, collecting, field, in_field = [], False, [], False
    for line in lines:
        if line.startswith("Package:"):
            collecting = line.split(":", 1)[1].strip() == package
        if not collecting:
            continue
        stanza.append(line)
    for line in stanza:
        if line.startswith("Depends:"):
            in_field = True
            field.append(line.split(":", 1)[1])
            continue
        if in_field:
            if line[:1].isspace() and line.strip():
                field.append(line.strip())
            elif line.strip() and not line[:1].isspace():
                break
    return " ".join(field)


def check_desktop_helpers(_truth: dict) -> list[Finding]:
    """There is ONE desktop library, both front-ends load it, and nothing
    restates what it says.

    Every finding below is a way for the duplication to come back: a front-end
    spelling a helper path again -- in any spelling that folds to the same
    file -- a front-end assembling a privileged argv at all, a function that
    reads the catalog directory whatever it is called, the library losing one
    of the facts it was created to hold, or the packaging silently making
    "both import one module" untrue on an installed system while it stays true
    in this tree.

    DETECTED, not ENFORCED.  The two words are not interchangeable here
    (docs/PRIVILEGED_OPERATIONS.md: ENFORCED means the enforcement layer
    prevents the behaviour AND an adversarial test proves it).  This is a
    CI-time scanner over source SHAPE: it reads what the tree says, it stops no
    process from doing anything, and a spelling it cannot fold is a spelling it
    cannot see -- a program name reached through a dict subscript, a path built
    with chr(), a privileged helper under a name prefix nobody added to
    PRIVILEGED_PREFIXES.  Those three were planted and MISSED, deliberately
    measured rather than guessed.

    The row this check first shipped under said ENFORCED over "one
    implementation of catalog/hwscan/launch/installed-map/privileged argv".
    The barrier underneath was `path in code` plus a grep for
    `def load_catalog(`, and an adversarial verifier walked a complete second
    catalog reader and a complete second bundle installer past it on the first
    attempt, with every test green.  The word was wrong before the code was.

    What IS enforced on this seam is smaller and lives in the library:
    sf_desktop.py resolves every program it runs from PROGRAMS, so a front-end
    that CALLS the library cannot be handed a $PATH-resolved binary.  What this
    check adds is DETECTION of a front-end that stops calling it.
    """
    findings = []

    # -- the library itself ------------------------------------------------
    try:
        library = read(DESKTOP_LIBRARY)
    except OSError as exc:
        return [Finding(
            "DRIFT", "desktop-helpers", DESKTOP_LIBRARY,
            f"the one shared desktop library is unreadable ({exc}); with no "
            f"library there is nothing for the two front-ends to share",
            "W-30: sf_desktop.py is the single implementation of catalog, "
            "hwscan, launch and the privileged install argv")]

    library_code = code_text(library)
    for api in DESKTOP_LIBRARY_API:
        if library_code.count(api) != 1:
            findings.append(Finding(
                "DRIFT", "desktop-helpers", site(DESKTOP_LIBRARY, api),
                f"the shared library defines `{api}` {library_code.count(api)} times, "
                f"expected exactly once; every front-end reads this fact from "
                f"here and from nowhere else",
                "restore the definition, or move its callers with it"))

    for label, path in HELPER_PATHS.items():
        count = library_code.count(path)
        if count != 1:
            findings.append(Finding(
                "DRIFT", "desktop-helpers", site(DESKTOP_LIBRARY, path),
                f"the {label} path {path!r} is written {count} times in the "
                f"library; the whole point of the library is that it is the "
                f"one place this path is written",
                "name it once and refer to the constant"))

    # -- and nothing else implements them ----------------------------------
    #
    # Four scans, because the two this replaces were string greps that a rename
    # or a second spelling defeated: an adversarial verifier planted a complete
    # second catalog reader and a complete second privileged argv builder in a
    # front-end and got 0 findings out of them.  The first scan below is the
    # original substring one, kept because it catches a reserved path named
    # inside a longer string, which the folding scan deliberately does not.
    # The other three read SHAPE: what a string actually resolves to, what a
    # list display's head actually is, and what a function actually does.
    labels = {path: label for label, path in HELPER_PATHS.items()}
    declared = library_program_paths(library)
    for rel in DELEGATING_SITES:
        try:
            text = read(rel)
        except OSError as exc:
            findings.append(Finding("DRIFT", "desktop-helpers", rel,
                                    f"unreadable ({exc})"))
            continue
        code = code_text(text)
        for label, path in HELPER_PATHS.items():
            if path in code:
                findings.append(Finding(
                    "DRIFT", "desktop-helpers", site(rel, path),
                    f"a desktop front-end spells the {label} path {path!r} out "
                    f"again. Two spellings of one path is how the front-ends "
                    f"came to disagree in the first place, and a second copy "
                    f"that happens to match today is still a second copy",
                    f"read it from the shared library ({DESKTOP_LIBRARY})"))
        for lineno, path in assembled_path_hits(text):
            if path in code:
                continue                  # already reported by the scan above
            findings.append(Finding(
                "DRIFT", "desktop-helpers", f"{rel}:{lineno}",
                f"a desktop front-end assembles the {labels[path]} path "
                f"{path!r} out of fragments. It is the same file wearing a "
                f"spelling a substring search cannot see, which is how a second "
                f"bundle installer was planted in a front-end and reported clean",
                f"read it from the shared library ({DESKTOP_LIBRARY})"))
        for lineno, program in privileged_argv_displays(text):
            # Two different findings wearing one shape, and collapsing them
            # would be the same mistake this check was pulled up for.
            #
            #   a bare name, or a path the library ALREADY declares -- this
            #   stage's duplication, and in the bare case the session's $PATH
            #   decides which binary the administrator password is typed into;
            #
            #   an absolute path to a program the table does not carry at all
            #   -- a real gap, in another package's page AND in the table, and
            #   not something this stage's files can close. DETECTED.
            if not program.startswith("/") or program in declared:
                findings.append(Finding(
                    "DRIFT", "desktop-helpers", f"{rel}:{lineno}",
                    f"a desktop front-end builds a privileged argv itself: the "
                    f"list at this line begins with {program!r}. Every argv that "
                    f"asks for an administrator password, and every argv naming "
                    f"a Shadowfetch helper, is built by the shared library and "
                    f"nowhere else -- a front-end that assembles one has taken "
                    f"back the decision about which binary the password is typed "
                    f"into, which is the divergence W-30's fifth item is about",
                    f"call bundle_install_argv() / trusted_program() in "
                    f"{DESKTOP_LIBRARY}"))
            else:
                findings.append(Finding(
                    "BLOCKED", "desktop-helpers", f"{rel}:{lineno}",
                    f"a desktop page builds a privileged argv from its own "
                    f"declaration of {program!r}, a program the shared library's "
                    f"trusted-program table does not carry. The path is absolute, "
                    f"so the session's PATH does not choose the binary -- but the "
                    f"table is supposed to be the one place a Shadowfetch program "
                    f"is named and classified, and this is a second place.",
                    f"add it to PROGRAMS in {DESKTOP_LIBRARY} with a trust "
                    f"classification, then have the page call "
                    f"trusted_program(...) instead of its own constant. Both "
                    f"halves are outside this stage's territory."))
        for lineno, name in catalog_reader_functions(text):
            findings.append(Finding(
                "DRIFT", "desktop-helpers", f"{rel}:{lineno}",
                f"`{name}()` walks a directory and decodes JSON out of it: that "
                f"is a second catalog reader, whatever it is called. Two "
                f"front-ends disagreeing about the contents of one directory -- "
                f"one of them rejecting the array form -- is the defect W-30 "
                f"names, and the function's NAME is not what made the old one a "
                f"reader",
                f"call load_catalog() / catalog_by_id() in {DESKTOP_LIBRARY}"))
        if rel not in FRONT_ENDS:
            continue                      # only the entry points load the library
        resolution = library_resolution(text)
        if not resolution or DESKTOP_LIBRARY_DIR not in code:
            findings.append(Finding(
                "DRIFT", "desktop-helpers", rel,
                f"this front-end does not load the shared desktop library "
                f"({DESKTOP_LIBRARY_DIR}/{DESKTOP_LIBRARY_MODULE}.py), so "
                f"whatever it is using for the catalog, the hwscan rule or the "
                f"privileged argv is a second implementation",
                "load the library the way sfcc/desktop.py does"))
        elif "file" not in resolution:
            findings.append(Finding(
                "BLOCKED", "desktop-helpers", site(rel, "import sf_desktop"),
                "this front-end checks that the library file exists and then "
                "resolves the module BY NAME. `import` consults sys.modules "
                "before sys.path, so a module already registered under that "
                "name is returned and the existence check just performed "
                "decides nothing: a planted sf_desktop was accepted, with "
                "PKEXEC back to the bare word and the install argv resolved "
                "through $PATH again. It needs code execution inside the "
                "process already, so it is defence in depth and not a privilege "
                "boundary -- but it is the PATH-shadowing shape this program "
                "has been bitten by before, and the loader's own docstring "
                "rests its safety case on the aliasing. sfcc/desktop.py was "
                "fixed; this front-end belongs to another package.",
                "load the file that was just checked: spec = "
                "importlib.util.spec_from_file_location('sf_desktop', location "
                "/ 'sf_desktop.py'); module = importlib.util.module_from_spec("
                "spec); sys.modules['sf_desktop'] = module; "
                "spec.loader.exec_module(module)"))

    # -- the packaging that makes that true on an installed system ---------
    try:
        install = read(LIBRARY_INSTALL)
    except OSError as exc:
        findings.append(Finding("DRIFT", "desktop-helpers", LIBRARY_INSTALL,
                                f"unreadable ({exc})"))
    else:
        shipped = any(DESKTOP_LIBRARY_DIR.lstrip("/") in line
                      and "sf_desktop.py" in line
                      for line in install.splitlines())
        if not shipped:
            findings.append(Finding(
                "DRIFT", "desktop-helpers", LIBRARY_INSTALL,
                f"{DESKTOP_LIBRARY_PACKAGE} does not ship the shared library "
                f"to {DESKTOP_LIBRARY_DIR}. Both front-ends import it by that "
                f"absolute path, so an unshipped library is two ImportErrors "
                f"on an installed system and a green tree here",
                f"add sf_desktop.py to {LIBRARY_INSTALL}"))

    for rel, package in sorted(FRONT_END_CONTROL.items()):
        try:
            control = read(rel)
        except OSError as exc:
            findings.append(Finding("DRIFT", "desktop-helpers", rel,
                                    f"unreadable ({exc})"))
            continue
        if DESKTOP_LIBRARY_PACKAGE not in depends_field(control, package):
            findings.append(Finding(
                "DRIFT", "desktop-helpers", site(rel, "Depends:"),
                f"{package} imports the shared desktop library but does not "
                f"Depends on {DESKTOP_LIBRARY_PACKAGE}, which ships it. The "
                f"front-end raises ImportError without it; Recommends or "
                f"nothing at all means that is allowed to happen",
                f"Depends: {DESKTOP_LIBRARY_PACKAGE} (= ${{binary:Version}})"))

    # -- the privileged argv is built once and delegated everywhere else ---
    for rel in BUNDLE_CALL_SITES:
        try:
            text = read(rel)
        except OSError as exc:
            findings.append(Finding("DRIFT", "desktop-helpers", rel,
                                    f"unreadable ({exc})"))
            continue
        builder = bundle_builder_source(text)
        if builder is None:
            # A site that DELEGATES is not a site that drifted. Every page and
            # both front-ends call bundle_install_argv() now, so the argv is
            # spelled once, in the builder, which is checked on its own source
            # below. Demanding the literal at every call site would push the
            # copies back out, which is the drift this check exists to stop.
            if "bundle_install_argv(" in text:
                continue
            findings.append(Finding(
                "DRIFT", "desktop-helpers", rel,
                "this file is one of the sites the privileged bundle-install "
                "argv contract covers, and it neither builds the argv nor "
                "delegates to bundle_install_argv()"))
            continue
        if rel != DESKTOP_LIBRARY:
            findings.append(Finding(
                "DRIFT", "desktop-helpers", site(rel, "def bundle_install_argv"),
                "a second bundle_install_argv() outside the shared library. "
                "The duplication W-30 removed was exactly this: the correct "
                "argv existing in two places, one of which named pkexec by a "
                "bare word the session's PATH resolved",
                f"delete it and call the one in {DESKTOP_LIBRARY}"))
            continue
        calls = builder_bundle_argvs(builder)
        bundle_calls = [c for c in calls if "BUNDLE" in c[0].upper()
                        or c[0] == "helper"]
        if not bundle_calls:
            findings.append(Finding(
                "DRIFT", "desktop-helpers", site(rel, "def bundle_install_argv"),
                "the shared builder no longer produces a pkexec bundle-install "
                "argv; every Install button in both front-ends is built here"))
            continue
        for constant, verb in bundle_calls:
            if verb != '"install"':
                findings.append(Finding(
                    "DRIFT", "desktop-helpers", site(rel, constant),
                    f'pkexec {constant} is called without the "install" verb; the '
                    f"helper exits 2 AFTER the admin password prompt",
                    'the contract is ["pkexec", <helper>, "install", <catalog id>]'))
        if not builder_resolves_pkexec_by_table(builder):
            findings.append(Finding(
                "DRIFT", "desktop-helpers", site(rel, "def bundle_install_argv"),
                "the shared builder does not resolve pkexec through the trusted "
                "program table. A bare name here is resolved by whatever PATH "
                "the session hands the process, and this argv is what asks for "
                "an administrator password",
                'pkexec = trusted_program("pkexec")'))

    findings.append(Finding(
        "BLOCKED", "desktop-helpers",
        "sfcc/busutil.py:nm_connectivity_full + shadowfetch-welcome:NMWatcher",
        "`net`, the one member of W-30's list this stage did not move, is still "
        "implemented twice. The Control Center reads NetworkManager's "
        "Connectivity property through dbus-python; Welcome reads the same "
        "property from the same daemon through Qt DBus and falls back to "
        "polling nm-online. Catalog, hwscan, launch, the installed-package map "
        "and the privileged install argv are now one implementation and are "
        "checked above; connectivity is not.",
        "sharing it means one of the two front-ends changing its D-Bus stack -- "
        "dbus-python inside a Qt event loop, or QtDBus inside the Control "
        "Center. DETECTED, not fixed, and deliberately not papered over with a "
        "third wrapper that would make three implementations."))
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
    # THE READER AND THE WRITER ARE TWO FACTS, and the status has to be checked
    # against both. This fired only when the status was the exact string
    # "NOT IMPLEMENTED", so once it became "READER IMPLEMENTED, WRITER PENDING"
    # neither branch could reach it -- the gate over a status string could no
    # longer notice that the string was stale, which is the failure it exists
    # to catch, one level up. The status is now derived from what the two files
    # actually contain and compared with what is written down.
    try:
        publisher = read(pointer["written_by"])
    except OSError:
        publisher = ""
    writes = pointer["key"] in publisher
    expected = {
        (False, False): "NOT IMPLEMENTED",
        (True, False): "READER IMPLEMENTED, WRITER PENDING",
        (False, True): "WRITER IMPLEMENTED, READER PENDING",
        (True, True): "IMPLEMENTED",
    }[(implemented, writes)]
    if pointer["status"] != expected:
        findings.append(Finding(
            "DRIFT", "release-pointer", site("tools/truth/release.json", "status"),
            f"the reader {'does' if implemented else 'does not'} read "
            f"{pointer['key']} and the writer {'does' if writes else 'does not'} "
            f"write it, so the status is {expected!r}; release.json records "
            f"{pointer['status']!r}",
            f"set release_pointer.status to {expected!r} in tools/truth/release.json"))
    if not implemented:
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
