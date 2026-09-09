#!/usr/bin/env python3
"""Ship list and reverse manifest: the package graph must describe the product.

Four properties, all decided from the source tree so they can fail before a
build rather than after an ISO -- plus a fifth, check_built_payload(), which
re-decides the first one against the .debs the build actually produced:

  1. REVERSE MANIFEST. Every payload file a package will pack into its source
     package is either covered by a debian/*.install line or listed in
     debian/not-installed, and every file in the built .deb came from one of
     those lines.
     debhelper's own dh_missing cannot do this here: it compares against
     debian/tmp, and no Shadowfetch package stages into debian/tmp -- every
     .install line names a path in the source tree directly. So dh_missing
     runs, finds an empty source directory, and passes trivially in compat 13
     where its default is --fail-missing. It has never checked anything. Two
     wallpapers (UmbraEmblem, UmbraVault) sat in shadowfetch-branding's data
     tree unshipped and unreferenced without anything noticing.

  2. PRIVATE-NAMESPACE OWNERSHIP. usr/share/shadowfetch/<name>/ and
     usr/lib/shadowfetch/<name>/ are Shadowfetch's own trees: one package's
     directory is another package's plugin point. When two packages write into
     the same private tree they must declare a relationship, in at least one
     direction. shadowfetch-fireproof dropped a Python module into
     shadowfetch-control-center's `sfcc` package with neither debian/control
     mentioning the other.

  3. CROSS-PACKAGE IMPORTS. A shipped script that puts another package's
     directory on sys.path, or imports a module another package installs, must
     declare a relationship on that package. This is the class of breakage a
     partial install exposes and a full install hides: on the ISO everything is
     present, so the missing edge is invisible until somebody installs one
     package on its own.

  4. PILLAR CLOSURE. Installing shadowfetch-desktop must install the
     architecture. live-build/config/package-lists is a build-time seed, not a
     dependency declaration: an ISO built from those lists has Mission Control,
     Firebreak, Phoenix, Fireproof, Firewatch, hwscan and the launcher, while
     `apt install shadowfetch-desktop` on any other machine had none of them.
     Every locally built package a package list names must be reachable from
     shadowfetch-desktop, and the pillars must be reachable through Depends.

Exit 0 and print PASS lines, or raise and print the failure. Importable:
package_gate calls check_all() before it builds anything, and
check_built_payload() against the .debs it extracts, so the gate fails on the
same facts -- once from the source text, once from the artifact.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
PACKAGES = ROOT / "packages"
PACKAGE_LISTS = ROOT / "live-build/config/package-lists"

# Trees Shadowfetch owns outright. A directory under one of these belongs to
# whichever package established it, and a second package writing there is a
# plugin seam, not a coincidence of the FHS. usr/bin and usr/share/applications
# are shared by every package on the system by design and are not listed.
PRIVATE_NAMESPACES = ("usr/share/shadowfetch", "usr/lib/shadowfetch")

# Any of these in debian/control is an explicit statement that the two packages
# know about each other. Enhances is the accurate one for a plugin: it installs
# nothing, and it says which package the payload belongs to.
RELATIONSHIP_FIELDS = (
    "Depends", "Pre-Depends", "Recommends", "Suggests", "Enhances",
    "Breaks", "Conflicts", "Replaces", "Provides",
)

# The metapackage a user installs, and what installing it has to mean.
DESKTOP = "shadowfetch-desktop"
REQUIRED_PILLARS = {
    "shadowfetch-control-center": "Mission Control, the desktop itself",
    "shadowfetch-fireline": "Firebreak, the agent sandbox",
    "shadowfetch-missions": "the mission engine Mission Control drives",
    "shadowfetch-phoenix": "Phoenix Points, the recovery pillar",
    "shadowfetch-fireproof": "safe system updates",
    "shadowfetch-firewatchd": "Firewatch telemetry, and Ember's only load source",
    "shadowfetch-hwscan": "the hardware fact file every surface reads",
    "shadowfetch-ember": "Ember Mode",
    "shadowfetch-menus": "the seven-category launcher",
    "shadowfetch-welcome": "first-boot setup",
}

# Packages whose payload is produced by a build system instead of .install
# lines. Their file list is pinned elsewhere -- the compiled pickup helper and
# its one drop-in are asserted path by path by tools/drkonqi_pickup_contract.py
# and re-checked against the built .deb in package_gate's payload_gate -- so a
# reverse manifest over the source tree would be checking the wrong artifact.
NO_INSTALL_LIST = {"shadowfetch-drkonqi-pickup"}

# One path is deliberately not a declared edge. Nine Shadowfetch programs read
# /usr/share/shadowfetch/version for the string they print after --version, all
# of them with a literal fallback to "unknown", and none of them behaves
# differently without it. Nine Recommends on shadowfetch-branding would state
# nothing that shadowfetch-desktop's Depends does not already state, and would
# make the useful findings harder to see. Anything added here needs both of the
# same facts on the record: the reader degrades without failing, and the edge
# carries no behaviour.
COSMETIC_PATHS = frozenset({"usr/share/shadowfetch/version"})

_EXECUTABLE_SHEBANG = re.compile(rb"^#!")
# Absolute Shadowfetch paths written as string literals. Both forms below have
# already gone undeclared in this tree: an exact installed path, and a
# private-namespace directory that a script puts on sys.path.
_ABSOLUTE_PATH = re.compile(
    r"[\"'](/usr/(?:bin|sbin|lib|libexec|share)/[A-Za-z0-9._/-]*shadowfetch[A-Za-z0-9._/-]*)[\"']")
_SFCC_IMPORT = re.compile(r"^\s*from\s+sfcc\.([A-Za-z_][A-Za-z0-9_]*)\s+import", re.M)


class ShipListError(RuntimeError):
    """A ship-list fact does not hold."""


# ---- reading the package graph ---------------------------------------------

def parse_control(path: Path) -> list[dict[str, str]]:
    """deb822 stanzas, with '#' comment lines dropped as dpkg drops them."""
    stanzas: list[dict[str, str]] = []
    current: dict[str, str] = {}
    key: str | None = None
    for raw in path.read_text(encoding="utf-8").splitlines():
        if raw.startswith("#"):
            continue
        if not raw.strip():
            if current:
                stanzas.append(current)
                current, key = {}, None
            continue
        if raw[0].isspace() and key:
            current[key] += " " + raw.strip()
            continue
        key, _, value = raw.partition(":")
        key = key.strip()
        current[key] = value.strip()
    if current:
        stanzas.append(current)
    return stanzas


def relationship_targets(stanza: dict[str, str]) -> set[str]:
    """Every package name this stanza names in any relationship field."""
    targets: set[str] = set()
    for field in RELATIONSHIP_FIELDS:
        for clause in stanza.get(field, "").split(","):
            for alternative in clause.split("|"):
                name = alternative.strip().split()[0] if alternative.strip() else ""
                if name:
                    targets.add(name)
    return targets


def depends_targets(stanza: dict[str, str]) -> set[str]:
    targets: set[str] = set()
    for field in ("Depends", "Pre-Depends"):
        for clause in stanza.get(field, "").split(","):
            for alternative in clause.split("|"):
                name = alternative.strip().split()[0] if alternative.strip() else ""
                if name:
                    targets.add(name)
    return targets


def source_packages() -> dict[str, Path]:
    return {
        directory.name: directory
        for directory in sorted(PACKAGES.iterdir())
        if (directory / "debian/control").is_file()
    }


def binary_stanzas() -> tuple[dict[str, dict[str, str]], dict[str, str]]:
    """(binary name -> its control stanza, binary name -> source directory)."""
    stanzas: dict[str, dict[str, str]] = {}
    origin: dict[str, str] = {}
    for source, directory in source_packages().items():
        for stanza in parse_control(directory / "debian/control"):
            name = stanza.get("Package")
            if not name:
                continue
            if name in stanzas:
                raise ShipListError(f"two sources declare binary package {name}")
            stanzas[name] = stanza
            origin[name] = source
    return stanzas, origin


# ---- reading the ship lists -------------------------------------------------

def source_files(directory: Path) -> list[Path]:
    """The files dpkg-source will pack, relative to the package directory.

    Tracked files AND untracked ones that .gitignore does not cover, because
    dpkg-buildpackage packs the working tree, not the index: a payload file
    added this afternoon is in the source package whether or not anyone has
    committed it, and it is exactly the file most likely to be missing from a
    ship list. Ignored paths are excluded, which is what keeps __pycache__ and
    the debhelper staging trees out (.gitignore covers both).
    """
    listing = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", "."],
        cwd=directory, text=True, check=True, stdout=subprocess.PIPE,
    ).stdout
    return [Path(name) for name in listing.split("\0") if name]


def install_lines(directory: Path, binaries: list[str]) -> dict[str, list[tuple[str, str]]]:
    """binary package -> [(source glob, destination directory)]."""
    entries: dict[str, list[tuple[str, str]]] = {}
    for binary in binaries:
        candidates = [directory / f"debian/{binary}.install"]
        if len(binaries) == 1:
            candidates.append(directory / "debian/install")
        pairs: list[tuple[str, str]] = []
        for candidate in candidates:
            if not candidate.is_file():
                continue
            for raw in candidate.read_text(encoding="utf-8").splitlines():
                line = raw.split("#", 1)[0].strip()
                if not line:
                    continue
                fields = line.split()
                if len(fields) != 2:
                    raise ShipListError(
                        f"{candidate.relative_to(ROOT)}: expected 'source destination', got {raw!r}")
                pairs.append((fields[0], fields[1]))
        if pairs:
            entries[binary] = pairs
    return entries


def not_installed(directory: Path) -> list[str]:
    path = directory / "debian/not-installed"
    if not path.is_file():
        return []
    return [
        line.split("#", 1)[0].strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.split("#", 1)[0].strip()
    ]


def expand(directory: Path, glob: str) -> list[Path]:
    """Source-side matches of one .install glob, relative to the package dir."""
    if any(character in glob for character in "*?["):
        return sorted(directory.glob(glob))
    candidate = directory / glob
    return [candidate] if candidate.exists() else []


def shipped_paths(directory: Path, pairs: list[tuple[str, str]],
                  present: set[Path]) -> tuple[dict[str, Path], set[Path]]:
    """(installed path in the filesystem -> its source file, source files used).

    dh_install copies a named directory into the destination, so a directory on
    the source side ships every file beneath it.
    """
    installed: dict[str, Path] = {}
    consumed: set[Path] = set()
    for glob, destination in pairs:
        matches = expand(directory, glob)
        if not matches:
            raise ShipListError(
                f"{directory.name}: install line matches nothing: {glob} {destination}")
        for match in matches:
            relative = match.relative_to(directory)
            target = destination.strip("/")
            if match.is_dir():
                for source in sorted(present):
                    if source == relative or relative in source.parents:
                        consumed.add(source)
                        inner = source.relative_to(relative.parent)
                        installed[f"{target}/{inner}".strip("/")] = source
            else:
                consumed.add(relative)
                installed[f"{target}/{match.name}".strip("/")] = relative
    return installed, consumed


def payload_roots(pairs: list[tuple[str, str]], directory: Path) -> set[Path]:
    """The top-level source trees a package declares it ships out of.

    Only these are swept by the reverse manifest: tests/, docs/ and debian/ are
    not payload, and a package is entitled to carry files that are not payload.
    """
    roots: set[Path] = set()
    for glob, _ in pairs:
        head = Path(glob).parts[0]
        if (directory / head).is_dir():
            roots.add(Path(head))
    return roots


# ---- the four checks --------------------------------------------------------

def unshipped(tracked: set[Path], consumed: set[Path], roots: set[Path],
              exempt: list[str]) -> tuple[list[str], int]:
    """(payload files nothing ships and nothing excuses, files swept).

    Only files under a declared payload root are payload at all: a package is
    entitled to carry tests/, docs/ and debian/ without shipping them.
    """
    findings: list[str] = []
    swept = 0
    for candidate in sorted(tracked):
        if not any(root == candidate or root in candidate.parents for root in roots):
            continue
        swept += 1
        if candidate in consumed:
            continue
        posix = candidate.as_posix()
        if any(posix == pattern or Path(posix).match(pattern) for pattern in exempt):
            continue
        findings.append(posix)
    return findings, swept


def build_ship_lists() -> dict[str, dict[str, Path]]:
    """binary package -> {installed path: source file}, and check 1 on the way."""
    stanzas, origin = binary_stanzas()
    ship: dict[str, dict[str, Path]] = {}
    undeclared: list[str] = []
    swept = 0
    for source, directory in source_packages().items():
        binaries = [name for name, home in origin.items() if home == source]
        entries = install_lines(directory, binaries)
        tracked = set(source_files(directory))
        payload = {path for path in tracked if path.parts[0] != "debian"}
        if not entries:
            # A metapackage carries no payload, and a build-system package's
            # payload is pinned against the built .deb instead. Anything else
            # with files and no ship list is shipping something nobody declared.
            if payload and source not in NO_INSTALL_LIST:
                raise ShipListError(
                    f"{source}: no debian/*.install and not a declared build-system "
                    f"package; its shipped file set is undeclared")
            continue
        exempt = not_installed(directory)
        consumed_here: set[Path] = set()
        roots_here: set[Path] = set()
        for binary, pairs in entries.items():
            installed, consumed = shipped_paths(directory, pairs, tracked)
            ship[binary] = installed
            consumed_here |= consumed
            roots_here |= payload_roots(pairs, directory)
        findings, counted = unshipped(tracked, consumed_here, roots_here, exempt)
        swept += counted
        undeclared += [f"{source}: {posix}" for posix in findings]
    if undeclared:
        raise ShipListError(
            "payload files that no package ships and debian/not-installed does not "
            "declare: " + ", ".join(sorted(undeclared)))
    print(f"PASS: reverse manifest ({swept} payload files, every one shipped or declared)")
    return ship


def check_private_namespaces(ship: dict[str, dict[str, Path]],
                             stanzas: dict[str, dict[str, str]]) -> None:
    trees: dict[str, set[str]] = {}
    for binary, installed in ship.items():
        for path in installed:
            for namespace in PRIVATE_NAMESPACES:
                if not path.startswith(namespace + "/"):
                    continue
                remainder = path[len(namespace) + 1:]
                if "/" not in remainder:
                    continue  # a bare file at the namespace root owns nothing
                tree = f"{namespace}/{remainder.split('/', 1)[0]}"
                trees.setdefault(tree, set()).add(binary)
    shared = {tree: owners for tree, owners in trees.items() if len(owners) > 1}
    undeclared: list[str] = []
    for tree, owners in sorted(shared.items()):
        ordered = sorted(owners)
        for index, one in enumerate(ordered):
            for other in ordered[index + 1:]:
                if (other in relationship_targets(stanzas.get(one, {}))
                        or one in relationship_targets(stanzas.get(other, {}))):
                    continue
                undeclared.append(f"{tree}: {one} and {other} share it and neither "
                                  f"debian/control names the other")
    if undeclared:
        raise ShipListError("undeclared private-namespace sharing: " + "; ".join(undeclared))
    detail = ", ".join(f"{tree}={'+'.join(sorted(owners))}" for tree, owners in sorted(shared.items()))
    print(f"PASS: private-namespace ownership ({len(trees)} trees; shared and declared: {detail or 'none'})")


def owner_map(ship: dict[str, dict[str, Path]]) -> dict[str, str]:
    return {path: binary for binary, installed in ship.items() for path in installed}


def resolved_owners(text: str, owner_of: dict[str, str]) -> set[str]:
    """Which packages the absolute paths in one payload resolve to.

    An exact installed path resolves to its owner -- shadowfetch-workbench
    reaching for Welcome's /usr/libexec/shadowfetch-bundle-install. A directory
    inside a private namespace resolves to the single package that fills it --
    Firebreak putting the mission engine's module directory on sys.path. A
    directory outside those namespaces (/usr/bin, /usr/share/applications)
    resolves to nobody: everything on the system shares it.
    """
    owners: set[str] = set()
    for literal in _ABSOLUTE_PATH.findall(text):
        relative = literal.strip("/")
        if relative in COSMETIC_PATHS:
            continue
        exact = owner_of.get(relative)
        if exact:
            owners.add(exact)
            continue
        if not relative.startswith(PRIVATE_NAMESPACES):
            continue
        beneath = {package for path, package in owner_of.items()
                   if path.startswith(relative + "/")}
        if len(beneath) == 1:
            owners |= beneath
    for module in _SFCC_IMPORT.findall(text):
        exact = owner_of.get(f"usr/share/shadowfetch/control-center/sfcc/{module}.py")
        if exact:
            owners.add(exact)
    return owners


def check_cross_package_resolution(ship: dict[str, dict[str, Path]],
                                   stanzas: dict[str, dict[str, str]],
                                   origin: dict[str, str],
                                   packages_root: Path = PACKAGES) -> None:
    owner_of = owner_map(ship)
    findings: list[str] = []
    scanned = 0
    for binary, installed in sorted(ship.items()):
        directory = packages_root / origin[binary]
        declared = relationship_targets(stanzas.get(binary, {}))
        for path, source in sorted(installed.items()):
            file = directory / source
            # Programs only. A .desktop entry or a document naming another
            # package's path is a reference; a program naming it is a
            # resolution, and only a resolution fails at runtime.
            if not (path.endswith(".py")
                    or _EXECUTABLE_SHEBANG.match(file.read_bytes()[:64])):
                continue
            scanned += 1
            text = file.read_text(encoding="utf-8", errors="replace")
            for target in sorted(resolved_owners(text, owner_of) - {binary}):
                if target not in declared:
                    findings.append(
                        f"{binary} ships {path}, which resolves paths owned by "
                        f"{target}, and debian/control declares no relationship on it")
    if findings:
        raise ShipListError("undeclared cross-package resolution: " + "; ".join(findings))
    print(f"PASS: cross-package resolution ({scanned} shipped program payloads)")


def closure(root: str, stanzas: dict[str, dict[str, str]], *, strong_only: bool) -> set[str]:
    """Locally built packages reachable from `root`. Depends only, or Depends
    plus the softer fields that still install by default."""
    reached: set[str] = set()
    frontier = [root]
    while frontier:
        name = frontier.pop()
        stanza = stanzas.get(name)
        if stanza is None:
            continue
        targets = depends_targets(stanza) if strong_only else (
            depends_targets(stanza) | {
                alternative.strip().split()[0]
                for clause in stanza.get("Recommends", "").split(",")
                for alternative in clause.split("|") if alternative.strip()
            })
        for target in targets:
            if target in stanzas and target not in reached:
                reached.add(target)
                frontier.append(target)
    return reached


def list_named_packages() -> dict[str, str]:
    """package name -> the live-build list that names it."""
    named: dict[str, str] = {}
    for path in sorted(PACKAGE_LISTS.iterdir()):
        if not path.is_file():
            continue
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.split("#", 1)[0].strip()
            if line:
                named.setdefault(line, path.name)
    return named


def check_pillar_closure(stanzas: dict[str, dict[str, str]],
                         named: dict[str, str] | None = None) -> None:
    if DESKTOP not in stanzas:
        raise ShipListError(f"{DESKTOP} is not declared by any package")
    strong = closure(DESKTOP, stanzas, strong_only=True)
    missing = [f"{pillar} ({why})" for pillar, why in sorted(REQUIRED_PILLARS.items())
               if pillar not in strong]
    if missing:
        raise ShipListError(
            f"{DESKTOP} does not install the product; its Depends closure omits: "
            + "; ".join(missing))
    print(f"PASS: {DESKTOP} Depends closure carries all {len(REQUIRED_PILLARS)} pillars")

    soft = closure(DESKTOP, stanzas, strong_only=False)
    named = list_named_packages() if named is None else named
    secret = sorted(
        f"{name} (seeded by {source}, unreachable from {DESKTOP})"
        for name, source in named.items()
        if name in stanzas and name != DESKTOP and name not in soft)
    if secret:
        raise ShipListError(
            "live-build package lists supply Shadowfetch packages the package graph "
            "does not declare: " + "; ".join(secret))
    local_named = sorted(name for name in named if name in stanzas)
    print(f"PASS: every locally built package a package list names is reachable from "
          f"{DESKTOP} ({len(local_named)} packages)")


# ---- the same facts, against the built artifact -----------------------------

# What debhelper adds to a payload on its own. Everything else in a .deb has to
# come from a ship list, or the ship list is a description of a package that
# was not built. dh_compress gzips what lands under usr/share/doc, which is why
# a declared doc is satisfied by itself or by itself plus .gz.
DEBHELPER_ADDED = (
    "usr/share/doc/{package}/changelog.Debian.gz",
    "usr/share/doc/{package}/NEWS.Debian.gz",
    "usr/share/doc/{package}/copyright",
    "usr/share/lintian/overrides/{package}",
)


def check_built_payload(ship: dict[str, dict[str, Path]],
                        built: dict[str, set[str]]) -> None:
    """Every file in every .deb is a file some ship list declared.

    The source-side checks read .install lines; this one reads the artifact, so
    a ship list that describes a package nobody built -- or a package that
    grew a file no ship list mentions -- cannot pass. Packages with no ship
    list (the metapackages, the cmake-built pickup correction) are not checked
    here; their payload contract lives in package_gate's own payload_gate.
    """
    problems: list[str] = []
    checked = 0
    for package, paths in sorted(built.items()):
        declared = ship.get(package)
        if declared is None:
            continue
        allowed = set(declared)
        allowed |= {f"{path}.gz" for path in declared
                    if path.startswith("usr/share/doc/")}
        allowed |= {pattern.format(package=package) for pattern in DEBHELPER_ADDED}
        checked += len(paths)
        for path in sorted(paths - allowed):
            problems.append(f"{package} ships {path}, which no ship list declares")
        for path in sorted(set(declared) - paths - {p[:-3] for p in paths if p.endswith(".gz")}):
            problems.append(f"{package} declares {path}, which the built package does not contain")
    if problems:
        raise ShipListError("built payload disagrees with the ship lists: "
                            + "; ".join(problems))
    print(f"PASS: built payload matches the ship lists ({checked} files in "
          f"{len([p for p in built if p in ship])} packages)")


# ---- entry points -----------------------------------------------------------

def check_all() -> None:
    stanzas, origin = binary_stanzas()
    ship = build_ship_lists()
    check_private_namespaces(ship, stanzas)
    check_cross_package_resolution(ship, stanzas, origin)
    check_pillar_closure(stanzas)


def main() -> int:
    argparse.ArgumentParser(description=__doc__).parse_args()
    check_all()
    print("\nSHIP_LIST_PASSED")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ShipListError, subprocess.CalledProcessError) as exc:
        print(f"SHIP_LIST_FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1)
