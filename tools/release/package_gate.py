#!/usr/bin/env python3
"""Validate a Shadowfetch Linux release's packages and signed APT repository.

ONE implementation for every release. The package allowlist, the source set,
the container smoke commands and every version-stamped literal are DATA in
tools/release/versions/<version>.toml -- before Stage Q each of those lived as
17 hand-edited "<version>-1" strings inside a copied module.

Every program is resolved to a trusted absolute path by gate.ProgramResolver:
gpgv decides whether the repository signature is genuine and dpkg-deb decides
what the packages contain, so neither may come from a PATH lookup.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile

import gate
from gate import ROLE_QUALITY, ROLE_SECURITY, output, run, sha256

from providers.validate_manifest import validate_provider_payload

import ship_list_check

from drkonqi_pickup_contract import (
    DROPIN, HELPER, PACKAGE as PICKUP_PACKAGE, validate_dropin, validate_package_paths,
)


ROOT = gate.ROOT
BUILD = ROOT / "build"
REPO = ROOT / "repo"

# dpkg-deb reads the payload the gate then judges, dpkg-source reproduces the
# corresponding source, and gpg/gpgv decide whether the index and every .dsc are
# genuinely signed. lintian and podman decide quality and installability facts.
REQUIRED_PROGRAMS = (
    ("dpkg-deb", ROLE_SECURITY),
    ("dpkg-source", ROLE_SECURITY),
    ("gpg", ROLE_SECURITY),
    ("gpgv", ROLE_SECURITY),
    ("desktop-file-validate", ROLE_QUALITY),
    ("lintian", ROLE_QUALITY),
    ("podman", ROLE_QUALITY),
)

# Set once in main(). The gate functions below read the release through these
# rather than taking eight parameters each; the copied modules used file-scope
# constants for exactly this data, so this keeps the call sites unchanged.
RELEASE: gate.ReleaseData
PROGRAMS: dict[str, gate.TrustedProgram] = {}


def program(name: str) -> gate.TrustedProgram:
    try:
        return PROGRAMS[name]
    except KeyError:  # pragma: no cover - a programming error, not a gate failure
        raise RuntimeError(f"{name} was not resolved before use") from None


RETIRED_RUNTIME = re.compile(
    rb"openclaw|\bhermes\b|\bollama\b|open[- ]?webui|llama\.cpp|llama-server",
    re.IGNORECASE,
)
MIGRATION_MANIFEST_PATH = (
    "usr/share/shadowfetch/migrations/2.1.3-ai-packages"
)
EXPECTED_MIGRATION_MANIFEST = b"""shadowfetch-ai-workspace
llama.cpp
llama.cpp-services
llama.cpp-tools
llama.cpp-tools-extra
libllama0
whisper.cpp
libwhisper1
whisper.cpp-tools
"""


def parse_deb822(path: Path) -> list[dict[str, str]]:
    return gate.parse_deb822(path.read_text(encoding="utf-8"))


def container_script(release: gate.ReleaseData) -> str:
    """The Debian 13 install script. Pure, so a test can read it without podman."""
    codename = release.codename
    binaries = release.binary_versions
    smoke = release.smoke_install
    all_packages = " ".join(sorted(binaries))
    smoke_packages = " ".join(smoke)
    candidate_checks = " ".join(
        f"{package}={version}" for package, version in sorted(binaries.items())
    )
    installed_checks = " ".join(f"{package}={binaries[package]}" for package in smoke)
    # STAGE W. Everything else in this script names every package explicitly,
    # so none of it can notice a metapackage that does not install the product.
    # This solve is given ONE name and --no-install-recommends, and the real apt
    # resolver decides: through 4.0.0 it would have planned a Plasma desktop
    # with no Mission Control, no Phoenix, no Fireproof and no Firewatch,
    # because only live-build's package list ever named them.
    pillars = " ".join(sorted(ship_list_check.REQUIRED_PILLARS))
    container_smoke = release.section("packages")["container_smoke"]
    present = "\n".join(f"{command} >/dev/null" for command in container_smoke["present"])
    absent = "\n".join(f"[ ! -e {path} ]" for path in container_smoke["absent"])
    return f"""
set -eux
export DEBIAN_FRONTEND=noninteractive
# The disposable slim container excludes translations/docs by default. Install
# complete packages here so the upstream DrKonqi integrity check is meaningful.
rm -f /etc/dpkg/dpkg.cfg.d/docker
apt-get update
apt-get install -y --no-install-recommends ca-certificates gnupg
gpg --batch --dearmor --output /usr/share/keyrings/shadowfetch.gpg /repo/shadowfetch.gpg.asc
printf '%s\n' 'deb [signed-by=/usr/share/keyrings/shadowfetch.gpg] file:/repo {codename} main' > /etc/apt/sources.list.d/shadowfetch.list
apt-get update
for item in {candidate_checks}; do
    package=${{item%%=*}}
    expected=${{item#*=}}
    candidate=$(apt-cache policy "$package" | awk '/Candidate:/ {{print $2; exit}}')
    [ "$candidate" = "$expected" ] || {{ echo "$package: expected candidate $expected, got $candidate" >&2; exit 1; }}
done
apt-get --simulate install {all_packages}
apt-get --simulate --no-install-recommends install shadowfetch-desktop > /tmp/desktop-plan
for pillar in {pillars}; do
    grep -q "^Inst $pillar " /tmp/desktop-plan || {{ echo "shadowfetch-desktop does not install $pillar" >&2; exit 1; }}
done
apt-get install -y --no-install-recommends {smoke_packages}
for item in {installed_checks}; do
    package=${{item%%=*}}
    expected=${{item#*=}}
    actual=$(dpkg-query -W -f='${{Version}}' "$package")
    [ "$actual" = "$expected" ] || {{ echo "$package: expected installed $expected, got $actual" >&2; exit 1; }}
done
{present}
{absent}
[ -z "$(dpkg --verify drkonqi)" ]
dpkg --audit
echo DEBIAN13_PACKAGE_INSTALL_PASS
"""


def package_inventory() -> dict[str, Path]:
    dpkg_deb = program("dpkg-deb")
    expected_binaries = RELEASE.binary_versions
    package_paths: dict[str, Path] = {}
    for deb in sorted(BUILD.glob("*.deb")):
        package = output(dpkg_deb.argv("-f", str(deb), "Package"))
        version = output(dpkg_deb.argv("-f", str(deb), "Version"))
        architecture = output(dpkg_deb.argv("-f", str(deb), "Architecture"))
        if package in package_paths:
            raise RuntimeError(f"duplicate binary package artifact: {package}")
        if architecture not in {"all", "amd64"}:
            raise RuntimeError(f"{package}: unexpected architecture {architecture}")
        package_paths[package] = deb
        print(f"PACKAGE {package} {version} {architecture} sha256={sha256(deb)}")
    if set(package_paths) != set(expected_binaries):
        missing = sorted(set(expected_binaries) - set(package_paths))
        extra = sorted(set(package_paths) - set(expected_binaries))
        raise RuntimeError(f"binary allowlist mismatch; missing={missing}, extra={extra}")
    for package, expected in expected_binaries.items():
        actual = output(dpkg_deb.argv("-f", str(package_paths[package]), "Version"))
        if actual != expected:
            raise RuntimeError(f"{package}: expected {expected}, got {actual}")
    print(f"PASS: exact binary inventory ({len(package_paths)} packages)")
    return package_paths


def payload_gate(package_paths: dict[str, Path], extracted: Path) -> None:
    owners: dict[str, list[str]] = defaultdict(list)
    built: dict[str, set[str]] = defaultdict(set)
    executable_candidates: list[tuple[str, int]] = []
    for package, deb in sorted(package_paths.items()):
        process = subprocess.Popen(
            program("dpkg-deb").argv("--fsys-tarfile", str(deb)),
            stdout=subprocess.PIPE,
        )
        assert process.stdout is not None
        with tarfile.open(fileobj=process.stdout, mode="r|*") as archive:
            for member in archive:
                relative = member.name.removeprefix("./").rstrip("/")
                if not relative:
                    continue
                if member.isfile() or member.issym() or member.islnk():
                    owners[relative].append(package)
                    built[package].add(relative)
                if member.isfile() and (
                    relative.startswith(("usr/bin/", "usr/sbin/", "usr/libexec/"))
                    or "/usr/libexec/" in "/" + relative
                ):
                    executable_candidates.append((relative, member.mode))
        if process.wait() != 0:
            raise RuntimeError(f"could not inspect payload for {package}")
        subprocess.run(program("dpkg-deb").argv("-x", str(deb), str(extracted)), check=True)

    # STAGE W. The ship lists are a description of the packages until they are
    # checked against the ones that were built. A .deb carrying a file no
    # debian/*.install names, or a ship list naming a file the build dropped,
    # fails here -- the source-side reverse manifest in check_all() cannot see
    # either, because it reads the .install text and not the artifact.
    ship_list_check.check_built_payload(ship_list_check.build_ship_lists(), dict(built))

    duplicates = {path: value for path, value in owners.items() if len(value) > 1}
    if duplicates:
        sample = ", ".join(f"{path}={value}" for path, value in sorted(duplicates.items())[:10])
        raise RuntimeError(f"duplicate package file ownership: {sample}")
    print(f"PASS: unique file ownership ({len(owners)} payload paths)")

    bad_modes = [path for path, mode in executable_candidates if not mode & 0o111]
    if bad_modes:
        raise RuntimeError("non-executable program payloads: " + ", ".join(sorted(bad_modes)))
    print(f"PASS: executable modes ({len(executable_candidates)} program payloads)")

    pickup_paths = [path for path, packages in owners.items() if PICKUP_PACKAGE in packages]
    validate_package_paths(pickup_paths)
    for path in (HELPER, DROPIN):
        if owners.get(path) != [PICKUP_PACKAGE]:
            raise RuntimeError("Pickup correction has missing or wrong file owner: " + path)
        if (extracted / path).is_symlink() or not (extracted / path).is_file():
            raise RuntimeError("Pickup correction must contain a regular payload file: " + path)
    validate_dropin((extracted / DROPIN).read_text())
    if (extracted / HELPER).read_bytes()[:4] != b"\x7fELF":
        raise RuntimeError("DrKonqi pickup helper must be a compiled ELF executable")
    print("PASS: compiled pickup helper owns only its narrow service override")

    release_payload = {
        "usr/bin/shadowfetch-missions": "shadowfetch-missions",
        "usr/lib/shadowfetch/missions/sf_missions.py": "shadowfetch-missions",
        "usr/lib/systemd/user/shadowfetch-missions.service": "shadowfetch-missions",
        "usr/bin/shadowfetch-grok-bot": "shadowfetch-defaults",
        "usr/share/shadowfetch/grok-bot/release.json": "shadowfetch-defaults",
        "usr/share/applications/shadowfetch-mission-control.desktop": "shadowfetch-control-center",
        "usr/share/applications/shadowfetch-grok-bot-setup.desktop": "shadowfetch-control-center",
        "usr/share/kio/servicemenus/shadowfetch-mission.desktop": "shadowfetch-control-center",
        "usr/share/shadowfetch/control-center/sfcc/missions_page.py": "shadowfetch-control-center",
        "usr/share/shadowfetch/control-center/sfcc/grok_bot_page.py": "shadowfetch-control-center",
    }
    for path, owner in release_payload.items():
        if owners.get(path) != [owner]:
            raise RuntimeError(
                f"{RELEASE.version} package payload missing or wrong owner: {path}"
            )
    def _read(relative):
        try:
            return (extracted / relative).read_text(encoding="utf-8")
        except OSError:
            return None
    result = validate_provider_payload(owners, (extracted / "usr/lib/shadowfetch/missions/sf_missions.py").read_text(), read=_read)
    print("PASS: provider manifests validated: " + ", ".join(result["providers"]))
    print("PASS: Mission Control/Grok payload ownership; local AI stack absent")

    required_guide_payload = {
        "usr/bin/shadowfetch-passport",
        "usr/share/applications/shadowfetch-guide.desktop",
        "usr/share/shadowfetch/control-center/sfcc/guide_page.py",
    }
    missing_guide = sorted(required_guide_payload - set(owners))
    if missing_guide:
        raise RuntimeError(
            "Shadowfetch Guide package payload is incomplete: "
            + ", ".join(missing_guide)
        )
    passport = (extracted / "usr/bin/shadowfetch-passport").read_text(
        encoding="utf-8"
    )
    for token in ('"local_only": True', '"upload_performed": False',
                  "privacy_issues(document)"):
        if token not in passport:
            raise RuntimeError(f"System Passport contract is absent: {token}")
    print("PASS: Shadowfetch Guide package payload and privacy contract")

    required_codex_payload = {
        "usr/bin/shadowfetch-codex",
        "usr/bin/shadowfetch-code-agent",
        "usr/share/doc/shadowfetch/CODEX.md",
        "usr/share/doc/shadowfetch/CODING-AGENTS.md",
    }
    missing_codex = sorted(required_codex_payload - set(owners))
    if missing_codex:
        raise RuntimeError(
            "Codex setup package payload is incomplete: "
            + ", ".join(missing_codex)
        )
    codex = (extracted / "usr/bin/shadowfetch-codex").read_text(
        encoding="utf-8"
    )
    for token in RELEASE.section("pinned_artifacts")["codex"]:
        if token not in codex:
            raise RuntimeError(f"Codex setup contract is absent: {token}")
    code_agents = (extracted / "usr/bin/shadowfetch-code-agent").read_text(
        encoding="utf-8"
    )
    for token in RELEASE.section("pinned_artifacts")["code_agent"]:
        if token not in code_agents:
            raise RuntimeError(f"Coding-agent setup contract is absent: {token}")
    print("PASS: coding-agent pinned artifacts and user-owned package contract")

    required_workbench_payload = {
        "usr/bin/shadowfetch-workbench",
        "usr/share/applications/shadowfetch-workbench.desktop",
        "usr/share/doc/shadowfetch/WORKBENCH.md",
        "usr/share/shadowfetch/workbench/profiles.json",
        "usr/share/shadowfetch/control-center/sfcc/workbench_page.py",
        "usr/share/shadowfetch/welcome/catalog/workbench-software-studio.json",
        "usr/share/shadowfetch/welcome/catalog/workbench-ai-lab.json",
        "usr/share/shadowfetch/welcome/catalog/workbench-production-ops.json",
        "usr/share/shadowfetch/welcome/catalog/workbench-creative-ai.json",
    }
    missing_workbench = sorted(required_workbench_payload - set(owners))
    if missing_workbench:
        raise RuntimeError(
            "Element Workbench package payload is incomplete: "
            + ", ".join(missing_workbench)
        )
    manifest = json.loads(
        (extracted / "usr/share/shadowfetch/workbench/profiles.json").read_text(
            encoding="utf-8"
        )
    )
    profiles = manifest.get("profiles", [])
    expected_profiles = list(RELEASE.section("workbench")["profiles"])
    if [profile.get("id") for profile in profiles] != expected_profiles:
        raise RuntimeError(
            f"Element Workbench profile allowlist differs from {RELEASE.version}"
        )
    workbench = (extracted / "usr/bin/shadowfetch-workbench").read_text(
        encoding="utf-8"
    )
    for token in (
        'subprocess.run(["pkexec", str(helper), "install"',
        '"network_default": network_default',
        'if target.exists() or target.is_symlink()',
    ):
        if token not in workbench:
            raise RuntimeError(f"Element Workbench safety contract is absent: {token}")
    print("PASS: Element Workbench payload, profiles and privilege boundary")

    mcp = (extracted / "usr/lib/shadowfetch/mcp/sf_mcp.py").read_text(encoding="utf-8")
    for token in RELEASE.stamped_tokens("mcp_server"):
        if token not in mcp:
            raise RuntimeError(
                f"Fireline MCP protocol is not stamped for {RELEASE.version}: {token}"
            )
    print("PASS: Fireline MCP version; local model ignition absent")

    required_recovery_payload = {
        "usr/libexec/phoenix-apt-repair",
        "usr/share/shadowfetch/apt-recovery/KEYRING.README",
        "usr/share/shadowfetch/apt-recovery/debian.sources",
        "usr/share/shadowfetch/apt-recovery/umbra-archive-keyring.gpg",
        "usr/share/shadowfetch/apt-recovery/umbra.sources",
    }
    missing_recovery = sorted(required_recovery_payload - set(owners))
    if missing_recovery:
        raise RuntimeError(
            "Phoenix source-repair payload is incomplete: "
            + ", ".join(missing_recovery)
        )
    recovery_sources = (
        extracted / "usr/share/shadowfetch/apt-recovery/debian.sources"
    ).read_text(encoding="utf-8")
    if "deb-src http://deb.debian.org/debian/ testing " not in recovery_sources:
        raise RuntimeError("Phoenix Debian recovery sources omit installer source entries")
    print("PASS: Phoenix source-repair helper and recovery payload")

    retired: list[str] = []
    for path in extracted.rglob("*"):
        if not path.is_file() or path.is_symlink() or path.stat().st_size > 4 * 1024 * 1024:
            continue
        try:
            content = path.read_bytes()
        except OSError:
            continue
        if b"\0" in content[:4096]:
            continue
        relative = path.relative_to(extracted).as_posix()
        if relative == MIGRATION_MANIFEST_PATH:
            if content != EXPECTED_MIGRATION_MANIFEST:
                raise RuntimeError(
                    "2.1.3 migration manifest differs from the reviewed package set"
                )
            continue
        if RETIRED_RUNTIME.search(content):
            retired.append(relative)
    if retired:
        raise RuntimeError("retired runtime residue in packages: " + ", ".join(sorted(retired)))
    print("PASS: retired runtime payload scan and exact migration manifest")

    desktop_files = [
        path
        for path in extracted.rglob("*.desktop")
        if "applications" in path.parts or "autostart" in path.parts
    ]
    run(
        f"desktop entry validation ({len(desktop_files)} files)",
        program("desktop-file-validate").argv(*map(str, desktop_files)),
    )


def repository_gate() -> list[Path]:
    codename = RELEASE.codename
    expected_binaries = RELEASE.binary_versions
    expected_sources = RELEASE.source_packages
    packages_index = REPO / f"dists/{codename}/main/binary-amd64/Packages"
    sources_index = REPO / f"dists/{codename}/main/source/Sources"
    inrelease = REPO / f"dists/{codename}/InRelease"
    for path in (packages_index, sources_index, inrelease, REPO / "shadowfetch.gpg.asc"):
        if not path.is_file():
            raise RuntimeError(f"missing repository artifact: {path}")

    binary_records = parse_deb822(packages_index)
    binary_versions = {record["Package"]: record["Version"] for record in binary_records}
    if binary_versions != expected_binaries:
        raise RuntimeError(f"repository binary index mismatch: {binary_versions}")
    source_records = parse_deb822(sources_index)
    sources = {record["Package"] for record in source_records}
    if sources != expected_sources:
        raise RuntimeError(
            f"repository source index mismatch; missing={sorted(expected_sources - sources)}, "
            f"extra={sorted(sources - expected_sources)}"
        )

    valid_line = next(
        (line for line in inrelease.read_text(encoding="utf-8").splitlines() if line.startswith("Valid-Until: ")),
        None,
    )
    if not valid_line:
        raise RuntimeError("InRelease has no Valid-Until")
    valid_until = parsedate_to_datetime(valid_line.split(": ", 1)[1]).astimezone(timezone.utc)
    remaining = (valid_until - datetime.now(timezone.utc)).total_seconds()
    if remaining < 7 * 24 * 60 * 60:
        raise RuntimeError(f"repository expires too soon: {valid_until.isoformat()}")

    dscs = sorted(BUILD.glob("src/*.dsc"))
    if len(dscs) != len(expected_sources):
        raise RuntimeError(f"expected {len(expected_sources)} dsc files, got {len(dscs)}")

    with tempfile.TemporaryDirectory(prefix="shadowfetch-keyring-") as temporary:
        keyring = Path(temporary) / "shadowfetch.gpg"
        run(
            "dearmor repository signing key",
            program("gpg").argv(
                "--batch", "--yes", "--dearmor",
                "--output", str(keyring), str(REPO / "shadowfetch.gpg.asc"),
            ),
        )
        run(
            "InRelease signature verification",
            program("gpgv").argv("--keyring", str(keyring), str(inrelease)),
        )
        for dsc in dscs:
            run(
                f"source descriptor signature {dsc.name}",
                program("gpgv").argv("--keyring", str(keyring), str(dsc)),
            )
    print(
        f"PASS: signed APT index ({len(binary_records)} binary, {len(source_records)} source, "
        f"valid_until={valid_until.isoformat()})"
    )

    with tempfile.TemporaryDirectory(prefix="shadowfetch-sources-") as temporary:
        destination = Path(temporary)
        extracted_sources: set[str] = set()
        for index, dsc in enumerate(dscs):
            source = next(
                line.split(":", 1)[1].strip()
                for line in dsc.read_text(encoding="utf-8").splitlines()
                if line.startswith("Source:")
            )
            extracted_sources.add(source)
            run(
                f"extract source {source}",
                program("dpkg-source").argv(
                    "-x", str(dsc), str(destination / f"{index:02d}-{source}")
                ),
            )
        if extracted_sources != expected_sources:
            raise RuntimeError(f"extracted source set mismatch: {extracted_sources}")
    print(f"PASS: corresponding source extraction ({len(dscs)} packages)")
    return dscs


def container_install_gate() -> None:
    run(
        "Debian 13 dependency solve and runtime package install",
        program("podman").argv(
            "run",
            "--rm",
            "--volume",
            f"{REPO}:/repo:ro",
            "docker.io/library/debian:trixie-slim",
            "sh",
            "-c",
            container_script(RELEASE),
        ),
    )


def main(argv: list[str] | None = None) -> int:
    global RELEASE
    parser = argparse.ArgumentParser(description=__doc__)
    gate.add_version_argument(parser)
    parser.add_argument("--skip-container", action="store_true")
    args = parser.parse_args(argv)
    RELEASE = gate.load_release(args.version)
    os.environ.setdefault("LC_ALL", "C.UTF-8")

    # Resolve every program before any package is opened: a gate that discovers
    # halfway through that it cannot verify a signature has already printed a
    # page of PASS lines.
    resolver = gate.ProgramResolver()
    required = REQUIRED_PROGRAMS
    if args.skip_container:
        required = tuple(item for item in required if item[0] != "podman")
    for resolved in resolver.require(required):
        PROGRAMS[resolved.name] = resolved
    print(
        f"Shadowfetch Linux {RELEASE.version} package gate "
        f"(data: {RELEASE.path.name}, suite: {RELEASE.codename})"
    )

    # STAGE W. The package graph must describe the product: every pillar
    # reachable from shadowfetch-desktop through Depends, no live-build package
    # list quietly supplying one, no undeclared cross-package module drop, and
    # every payload file either shipped or declared unshipped. Cheapest check in
    # the gate and the one with the widest blast radius, so it runs first.
    ship_list_check.check_all()

    package_paths = package_inventory()
    with tempfile.TemporaryDirectory(prefix="shadowfetch-packages-") as temporary:
        payload_gate(package_paths, Path(temporary))
    run(
        "Lintian binary error gate",
        program("lintian").argv(
            "--display-level=error", *map(str, package_paths.values())
        ),
    )
    repository_gate()
    if not args.skip_container:
        container_install_gate()
    print("\nPACKAGE_GATE_PASSED")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.CalledProcessError, tarfile.TarError) as exc:
        print(f"PACKAGE_GATE_FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1)
