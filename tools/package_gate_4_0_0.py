#!/usr/bin/env python3
"""Validate Shadowfetch Linux 4.0.0 packages and signed APT repository."""

from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile

from drkonqi_pickup_contract import (
    DROPIN, HELPER, PACKAGE as PICKUP_PACKAGE, validate_dropin, validate_package_paths,
)


ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "build"
REPO = ROOT / "repo"
CODENAME = "umbra"
EXPECTED_BINARIES = {
    "grub-btrfs": "4.14-2",
    "shadowfetch-branding": "4.0.0-1",
    "shadowfetch-control-center": "4.0.0-1",
    "shadowfetch-creative-base": "4.0.0-1",
    "shadowfetch-defaults": "4.0.0-1",
    "shadowfetch-desktop": "4.0.0-1",
    "shadowfetch-drkonqi-pickup": "4.0.0-1",
    "shadowfetch-ember": "4.0.0-1",
    "shadowfetch-fireproof": "4.0.0-1",
    "shadowfetch-fireline": "4.0.0-1",
    "shadowfetch-firewatchd": "4.0.0-1",
    "shadowfetch-hwscan": "4.0.0-1",
    "shadowfetch-menus": "4.0.0-1",
    "shadowfetch-missions": "4.0.0-1",
    "shadowfetch-nvidia": "4.0.0-1",
    "shadowfetch-phoenix": "4.0.0-1",
    "shadowfetch-themes": "4.0.0-1",
    "shadowfetch-welcome": "4.0.0-1",
}
EXPECTED_SOURCES = {
    "grub-btrfs",
    "shadowfetch-branding",
    "shadowfetch-control-center",
    "shadowfetch-defaults",
    "shadowfetch-drkonqi-pickup",
    "shadowfetch-ember",
    "shadowfetch-fireproof",
    "shadowfetch-fireline",
    "shadowfetch-firewatchd",
    "shadowfetch-hwscan",
    "shadowfetch-menus",
    "shadowfetch-meta",
    "shadowfetch-missions",
    "shadowfetch-phoenix",
    "shadowfetch-themes",
    "shadowfetch-welcome",
}
SMOKE_INSTALL = (
    "grub-btrfs",
    "shadowfetch-branding",
    "shadowfetch-control-center",
    "shadowfetch-defaults",
    "shadowfetch-drkonqi-pickup",
    "shadowfetch-ember",
    "shadowfetch-fireproof",
    "shadowfetch-fireline",
    "shadowfetch-firewatchd",
    "shadowfetch-hwscan",
    "shadowfetch-menus",
    "shadowfetch-phoenix",
    "shadowfetch-missions",
    "shadowfetch-welcome",
)
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


def run(label: str, command: list[str], *, cwd: Path = ROOT) -> subprocess.CompletedProcess[str]:
    print(f"\n>>> {label}")
    result = subprocess.run(command, cwd=cwd, text=True, check=True)
    print(f"PASS: {label}")
    return result


def output(command: list[str]) -> str:
    return subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        check=True,
        stdout=subprocess.PIPE,
    ).stdout.strip()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_deb822(path: Path) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    current: dict[str, str] = {}
    key: str | None = None
    for raw in path.read_text(encoding="utf-8").splitlines():
        if not raw:
            if current:
                records.append(current)
                current = {}
                key = None
            continue
        if raw[0].isspace() and key:
            current[key] += "\n" + raw[1:]
            continue
        key, value = raw.split(":", 1)
        current[key] = value.lstrip()
    if current:
        records.append(current)
    return records


def package_inventory() -> dict[str, Path]:
    package_paths: dict[str, Path] = {}
    for deb in sorted(BUILD.glob("*.deb")):
        package = output(["dpkg-deb", "-f", str(deb), "Package"])
        version = output(["dpkg-deb", "-f", str(deb), "Version"])
        architecture = output(["dpkg-deb", "-f", str(deb), "Architecture"])
        if package in package_paths:
            raise RuntimeError(f"duplicate binary package artifact: {package}")
        if architecture not in {"all", "amd64"}:
            raise RuntimeError(f"{package}: unexpected architecture {architecture}")
        package_paths[package] = deb
        print(f"PACKAGE {package} {version} {architecture} sha256={sha256(deb)}")
    if set(package_paths) != set(EXPECTED_BINARIES):
        missing = sorted(set(EXPECTED_BINARIES) - set(package_paths))
        extra = sorted(set(package_paths) - set(EXPECTED_BINARIES))
        raise RuntimeError(f"binary allowlist mismatch; missing={missing}, extra={extra}")
    for package, expected in EXPECTED_BINARIES.items():
        actual = output(["dpkg-deb", "-f", str(package_paths[package]), "Version"])
        if actual != expected:
            raise RuntimeError(f"{package}: expected {expected}, got {actual}")
    print(f"PASS: exact binary inventory ({len(package_paths)} packages)")
    return package_paths


def payload_gate(package_paths: dict[str, Path], extracted: Path) -> None:
    owners: dict[str, list[str]] = defaultdict(list)
    executable_candidates: list[tuple[str, int]] = []
    for package, deb in sorted(package_paths.items()):
        process = subprocess.Popen(
            ["dpkg-deb", "--fsys-tarfile", str(deb)],
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
                if member.isfile() and (
                    relative.startswith(("usr/bin/", "usr/sbin/", "usr/libexec/"))
                    or "/usr/libexec/" in "/" + relative
                ):
                    executable_candidates.append((relative, member.mode))
        if process.wait() != 0:
            raise RuntimeError(f"could not inspect payload for {package}")
        subprocess.run(["dpkg-deb", "-x", str(deb), str(extracted)], check=True)

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
        "usr/lib/shadowfetch/missions/sf_local_compute.py": "shadowfetch-missions",
        "usr/lib/systemd/user/shadowfetch-missions.service": "shadowfetch-missions",
        "usr/bin/shadowfetch-grok-bot": "shadowfetch-defaults",
        "usr/bin/shadowfetch-model-check": "shadowfetch-defaults",
        "usr/share/shadowfetch/grok-bot/release.json": "shadowfetch-defaults",
        "usr/share/applications/shadowfetch-mission-control.desktop": "shadowfetch-control-center",
        "usr/share/applications/shadowfetch-grok-bot-setup.desktop": "shadowfetch-control-center",
        "usr/share/kio/servicemenus/shadowfetch-mission.desktop": "shadowfetch-control-center",
        "usr/share/shadowfetch/control-center/sfcc/missions_page.py": "shadowfetch-control-center",
        "usr/share/shadowfetch/control-center/sfcc/grok_bot_page.py": "shadowfetch-control-center",
        "usr/share/shadowfetch/control-center/sfcc/local_model_card.py": "shadowfetch-control-center",
    }
    for path, owner in release_payload.items():
        if owners.get(path) != [owner]:
            raise RuntimeError(f"4.0 package payload missing or wrong owner: {path}")
    print("PASS: Mission Control, local compute and Grok Bot payload ownership")

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
    for token in (
        'CODEX_VERSION="0.150.1"',
        'INSTALLER_SHA256="ba92dd27e5c06f0d3bbc58bfa4b9cfb6599cd2742fbb1f92a2765e6c07dedb5a"',
        'BIN_DIR="${CODEX_INSTALL_DIR:-$HOME/.local/bin}"',
    ):
        if token not in codex:
            raise RuntimeError(f"Codex setup contract is absent: {token}")
    code_agents = (extracted / "usr/bin/shadowfetch-code-agent").read_text(
        encoding="utf-8"
    )
    for token in (
        'VERSION="2.1.227"',
        'VERSION="1.0.5"',
        'VERSION="2026.08.11-e8db854"',
        'ARTIFACT_SHA256="6832dc3f1797b890b71116e5f2dbbf9a83fd3d0498c235b4b0f9cd0e6e499ad6"',
        'ARTIFACT_SHA256="9ba87444e1819e8f6104adbbf4676a870c204380aa5c3e1c38a926c4ea677238"',
        'ARTIFACT_SHA256="bfff4bf6f4e9dd30c1d0ef0a70b6077b074015dd2948e4c50685d53afdcfce5a"',
        'BIN_DIR="${SHADOWFETCH_CODE_AGENT_BIN_DIR:-$HOME/.local/bin}"',
    ):
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
    if [profile.get("id") for profile in profiles] != [
        "software-studio", "ai-lab", "production-ops", "creative-ai"
    ]:
        raise RuntimeError("Element Workbench profile allowlist differs from 4.0.0")
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

    ignition = (extracted / "usr/bin/shadowfetch-ai-ignition").read_text(
        encoding="utf-8"
    )
    mcp = (extracted / "usr/lib/shadowfetch/mcp/sf_mcp.py").read_text(
        encoding="utf-8"
    )
    model_catalog = json.loads(
        (extracted / "usr/share/shadowfetch/ai-ignition/models.json").read_text(
            encoding="utf-8"
        )
    )
    if 'VERSION = "4.0.0"' not in ignition or 'SERVER_VERSION = "4.0.0"' not in mcp:
        raise RuntimeError("Fireline protocol surfaces are not stamped for 4.0.0")
    if not str(model_catalog.get("engine", "")).startswith("Buzz-managed local inference"):
        raise RuntimeError("AI Ignition does not delegate model ownership to Buzz")
    print("PASS: Fireline and AI Ignition 4.0.0 Buzz ownership contract")

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
        if relative == "usr/lib/shadowfetch/missions/sf_local_compute.py":
            content = content.replace(b'"llama-server"', b'"buzz-native-process-identity"')
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
        ["desktop-file-validate", *map(str, desktop_files)],
    )


def repository_gate() -> list[Path]:
    packages_index = REPO / f"dists/{CODENAME}/main/binary-amd64/Packages"
    sources_index = REPO / f"dists/{CODENAME}/main/source/Sources"
    inrelease = REPO / f"dists/{CODENAME}/InRelease"
    for path in (packages_index, sources_index, inrelease, REPO / "shadowfetch.gpg.asc"):
        if not path.is_file():
            raise RuntimeError(f"missing repository artifact: {path}")

    binary_records = parse_deb822(packages_index)
    binary_versions = {record["Package"]: record["Version"] for record in binary_records}
    if binary_versions != EXPECTED_BINARIES:
        raise RuntimeError(f"repository binary index mismatch: {binary_versions}")
    source_records = parse_deb822(sources_index)
    sources = {record["Package"] for record in source_records}
    if sources != EXPECTED_SOURCES:
        raise RuntimeError(
            f"repository source index mismatch; missing={sorted(EXPECTED_SOURCES - sources)}, "
            f"extra={sorted(sources - EXPECTED_SOURCES)}"
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
    if len(dscs) != len(EXPECTED_SOURCES):
        raise RuntimeError(f"expected {len(EXPECTED_SOURCES)} dsc files, got {len(dscs)}")

    with tempfile.TemporaryDirectory(prefix="shadowfetch-keyring-") as temporary:
        keyring = Path(temporary) / "shadowfetch.gpg"
        run(
            "dearmor repository signing key",
            ["gpg", "--batch", "--yes", "--dearmor", "--output", str(keyring), str(REPO / "shadowfetch.gpg.asc")],
        )
        run(
            "InRelease signature verification",
            ["gpgv", "--keyring", str(keyring), str(inrelease)],
        )
        for dsc in dscs:
            run(
                f"source descriptor signature {dsc.name}",
                ["gpgv", "--keyring", str(keyring), str(dsc)],
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
                ["dpkg-source", "-x", str(dsc), str(destination / f"{index:02d}-{source}")],
            )
        if extracted_sources != EXPECTED_SOURCES:
            raise RuntimeError(f"extracted source set mismatch: {extracted_sources}")
    print(f"PASS: corresponding source extraction ({len(dscs)} packages)")
    return dscs


def container_install_gate() -> None:
    if not shutil.which("podman"):
        raise RuntimeError("podman is required for the Debian 13 package gate")
    all_packages = " ".join(sorted(EXPECTED_BINARIES))
    smoke_packages = " ".join(SMOKE_INSTALL)
    candidate_checks = " ".join(
        f"{package}={version}" for package, version in sorted(EXPECTED_BINARIES.items())
    )
    installed_checks = " ".join(
        f"{package}={EXPECTED_BINARIES[package]}" for package in SMOKE_INSTALL
    )
    script = f"""
set -eux
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends ca-certificates gnupg
gpg --batch --dearmor --output /usr/share/keyrings/shadowfetch.gpg /repo/shadowfetch.gpg.asc
printf '%s\n' 'deb [signed-by=/usr/share/keyrings/shadowfetch.gpg] file:/repo {CODENAME} main' > /etc/apt/sources.list.d/shadowfetch.list
apt-get update
for item in {candidate_checks}; do
    package=${{item%%=*}}
    expected=${{item#*=}}
    candidate=$(apt-cache policy "$package" | awk '/Candidate:/ {{print $2; exit}}')
    [ "$candidate" = "$expected" ] || {{ echo "$package: expected candidate $expected, got $candidate" >&2; exit 1; }}
done
apt-get --simulate install {all_packages}
apt-get install -y --no-install-recommends {smoke_packages}
for item in {installed_checks}; do
    package=${{item%%=*}}
    expected=${{item#*=}}
    actual=$(dpkg-query -W -f='${{Version}}' "$package")
    [ "$actual" = "$expected" ] || {{ echo "$package: expected installed $expected, got $actual" >&2; exit 1; }}
done
/usr/bin/shadowfetch-buzz --help >/dev/null
/usr/bin/shadowfetch-codex --help >/dev/null
/usr/bin/shadowfetch-gpu --help >/dev/null
/usr/bin/shadowfetch-update --help >/dev/null
/usr/libexec/shadowfetch-drkonqi-pickup --help >/dev/null
[ -z "$(dpkg --verify drkonqi)" ]
dpkg --audit
echo DEBIAN13_PACKAGE_INSTALL_PASS
"""
    run(
        "Debian 13 dependency solve and runtime package install",
        [
            "podman",
            "run",
            "--rm",
            "--volume",
            f"{REPO}:/repo:ro",
            "docker.io/library/debian:trixie-slim",
            "sh",
            "-c",
            script,
        ],
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skip-container", action="store_true")
    args = parser.parse_args()
    os.environ.setdefault("LC_ALL", "C.UTF-8")
    for command in ("dpkg-deb", "dpkg-source", "desktop-file-validate", "gpg", "gpgv", "lintian"):
        if not shutil.which(command):
            raise RuntimeError(f"required command is missing: {command}")

    package_paths = package_inventory()
    with tempfile.TemporaryDirectory(prefix="shadowfetch-packages-") as temporary:
        payload_gate(package_paths, Path(temporary))
    run(
        "Lintian binary error gate",
        ["lintian", "--display-level=error", *map(str, package_paths.values())],
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
