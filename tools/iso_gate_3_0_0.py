#!/usr/bin/env python3
"""Validate the final Shadowfetch Linux 3.0.0 ISO as a release artifact."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Iterator

import yaml


ROOT = Path(__file__).resolve().parents[1]
VERSION = "3.0.0"
CODENAME = "umbra"
ISO_NAME = f"shadowfetch-{VERSION}-amd64.iso"
EXPECTED_SIGNING_FINGERPRINT = "8F13CE1535EE1F4A2916A1F73C5C900B7BE80CA1"
MAX_SQUASHFS_BYTES = 4 * 1024 * 1024 * 1024 - 1

EXPECTED_CUSTOM_PACKAGES = {
    "grub-btrfs": "4.14-2",
    "shadowfetch-branding": "3.0.0-1",
    "shadowfetch-control-center": "3.0.0-1",
    "shadowfetch-creative-base": "3.0.0-1",
    "shadowfetch-defaults": "3.0.0-1",
    "shadowfetch-desktop": "3.0.0-1",
    "shadowfetch-ember": "3.0.0-1",
    "shadowfetch-fireproof": "3.0.0-1",
    "shadowfetch-fireline": "3.0.0-1",
    "shadowfetch-firewatchd": "3.0.0-1",
    "shadowfetch-hwscan": "3.0.0-1",
    "shadowfetch-menus": "3.0.0-1",
    "shadowfetch-phoenix": "3.0.0-1",
    "shadowfetch-themes": "3.0.0-1",
    "shadowfetch-welcome": "3.0.0-1",
}

REQUIRED_IMAGE_FILES = {
    "boot/grub/grub.cfg",
    "boot/grub/themes/umbra/theme.txt",
    "live/filesystem.squashfs",
    "live/initrd.img",
    "live/vmlinuz",
}

REQUIRED_ROOT_FILES = {
    "etc/apt/sources.list.d/shadowfetch.list",
    "etc/calamares/modules/partition.conf",
    "etc/calamares/modules/shellprocess.conf",
    "etc/calamares/settings.conf",
    "etc/os-release",
    "etc/systemd/system/shadowfetch-live-nossh.service",
    "etc/systemd/system/sysinit.target.wants/shadowfetch-live-nossh.service",
    "etc/systemd/system/sshd-keygen.service.d/10-shadowfetch-hostkeys.conf",
    "etc/ufw/ufw.conf",
    "usr/bin/add-calamares-desktop-icon",
    "usr/bin/shadowfetch-buzz",
    "usr/bin/shadowfetch-control",
    "usr/bin/shadowfetch-passport",
    "usr/bin/shadowfetch-welcome",
    "usr/lib/shadowfetch/firstboot.sh",
    "usr/lib/systemd/user/shadowfetch-buzz.service",
    "usr/lib/systemd/system/shadowfetch-migrate-2.1.3-ai.service",
    "usr/libexec/shadowfetch-buzz-provision",
    "usr/libexec/shadowfetch-buzz-stack",
    "usr/libexec/shadowfetch-migrate-2.1.3-ai",
    "usr/libexec/phoenix-apt-repair",
    "usr/local/sbin/sf-remove-live-user",
    "usr/share/applications/shadowfetch-buzz.desktop",
    "usr/share/applications/shadowfetch-guide.desktop",
    "usr/share/applications/shadowfetch-local-ai.desktop",
    "usr/share/shadowfetch/control-center/sfcc/guide_page.py",
    "usr/share/shadowfetch/buzz/compose.yml",
    "usr/share/shadowfetch/installer-packages/grub-pc.deb",
    "usr/share/shadowfetch/installer-packages/grub-pc.deb.sha256",
    "usr/share/shadowfetch/migrations/2.1.3-ai-packages",
    "usr/share/shadowfetch/apt-recovery/KEYRING.README",
    "usr/share/shadowfetch/apt-recovery/debian.sources",
    "usr/share/shadowfetch/apt-recovery/umbra-archive-keyring.gpg",
    "usr/share/shadowfetch/apt-recovery/umbra.sources",
    "usr/share/shadowfetch/os-release.shadowfetch",
    "usr/share/shadowfetch/version",
    "var/lib/dpkg/status",
}

REQUIRED_EXECUTABLES = {
    "usr/bin/add-calamares-desktop-icon",
    "usr/bin/shadowfetch-buzz",
    "usr/bin/shadowfetch-control",
    "usr/bin/shadowfetch-passport",
    "usr/bin/shadowfetch-welcome",
    "usr/libexec/shadowfetch-buzz-provision",
    "usr/libexec/shadowfetch-buzz-stack",
    "usr/libexec/shadowfetch-migrate-2.1.3-ai",
    "usr/libexec/phoenix-apt-repair",
    "usr/local/sbin/sf-remove-live-user",
}

RETIRED_PACKAGE = re.compile(
    r"^(?:openclaw(?:-|$)|hermes(?:-|$)|ollama(?:-|$)|"
    r"llama\.cpp(?:-|$)|libllama(?:-|$)|shadowfetch-ai-workspace$)",
    re.IGNORECASE,
)

PROPRIETARY_NVIDIA_PACKAGE = re.compile(
    r"^(?:nvidia-driver(?:-|$)|nvidia-kernel(?:-|$)|nvidia-open(?:-|$)|"
    r"cuda-drivers(?:-|$)|xserver-xorg-video-nvidia(?:-|$)|"
    r"libnvidia-(?:cfg|compute|decode|encode|glcore|ml)(?:[0-9]+|[-.]|$))",
    re.IGNORECASE,
)

FORBIDDEN_BUILD_TIME_PACKAGES = frozenset(
    {
        "libdvd-pkg",
        "libdvdcss2",
        "libdvdcss-dev",
        "libdvdcss2-dbgsym",
    }
)

SECRET_PATH = re.compile(
    r"^(?:root|home/[^/]+)/(?:(?:\.ssh/(?:id_[^/]+|authorized_keys))|"
    r"(?:\.aws/credentials)|(?:\.config/gcloud/application_default_credentials\.json)|"
    r"(?:\.config/gh/hosts\.yml)|(?:\.config/rclone/rclone\.conf)|"
    r"(?:\.gnupg/private-keys-v1\.d/))",
    re.IGNORECASE,
)


def command_for_privilege(command: list[str]) -> list[str]:
    if os.geteuid() == 0:
        return command
    return ["sudo", *command]


def run(
    label: str,
    command: list[str],
    *,
    cwd: Path = ROOT,
    capture: bool = False,
) -> subprocess.CompletedProcess[str]:
    print(f"\n>>> {label}")
    result = subprocess.run(
        command,
        cwd=cwd,
        text=True,
        check=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
    )
    if capture and result.stdout:
        print(result.stdout.rstrip())
    print(f"PASS: {label}")
    return result


def output(command: list[str], *, cwd: Path = ROOT) -> str:
    return subprocess.run(
        command,
        cwd=cwd,
        text=True,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout.strip()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(4 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_deb822(text: str) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    current: dict[str, str] = {}
    key: str | None = None
    for raw in text.splitlines():
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


def parse_os_release(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value.strip().strip('"')
    return values


def calamares_exec_sequence(settings: str) -> list[str]:
    """Return the single Calamares execution phase from parsed YAML."""
    try:
        document = yaml.safe_load(settings)
    except yaml.YAMLError as exc:
        raise RuntimeError(f"Calamares settings are not valid YAML: {exc}") from exc
    if not isinstance(document, dict) or not isinstance(document.get("sequence"), list):
        raise RuntimeError("Calamares settings have no sequence list")
    phases = [
        phase["exec"]
        for phase in document["sequence"]
        if isinstance(phase, dict) and "exec" in phase
    ]
    if len(phases) != 1 or not isinstance(phases[0], list):
        raise RuntimeError(f"expected one Calamares exec phase, found {len(phases)}")
    if not all(isinstance(module, str) for module in phases[0]):
        raise RuntimeError("Calamares exec phase contains a non-string module")
    return phases[0]


def validate_calamares_exec_sequence(settings: str) -> list[str]:
    sequence = calamares_exec_sequence(settings)
    required = ("unpackfs", "shellprocess", "users", "sources-final", "umount")
    duplicates = [module for module in required if sequence.count(module) != 1]
    if duplicates:
        raise RuntimeError(
            "Calamares exec sequence must contain each required module exactly once: "
            + ", ".join(duplicates)
        )
    positions = [sequence.index(module) for module in required]
    if positions != sorted(positions):
        raise RuntimeError(
            f"Calamares cleanup sequence is unsafe: "
            f"{dict(zip(required, positions, strict=True))}"
        )
    return sequence


def validate_partition_contract(partition: str) -> dict:
    """Require firmware-native tables, one ESP, clear /boot and encrypted root."""
    try:
        document = yaml.safe_load(partition)
    except yaml.YAMLError as exc:
        raise RuntimeError(f"Calamares partition config is not valid YAML: {exc}") from exc
    if not isinstance(document, dict):
        raise RuntimeError("Calamares partition config is not an object")
    efi = document.get("efi")
    expected_efi = {
        "mountPoint": "/boot/efi",
        "recommendedSize": "512MiB",
        "minimumSize": "300MiB",
        "label": "EFI",
    }
    if not isinstance(efi, dict) or any(efi.get(key) != value for key, value in expected_efi.items()):
        raise RuntimeError(f"Calamares EFI settings mismatch: {efi!r}")
    layout = document.get("partitionLayout")
    if not isinstance(layout, list) or not all(isinstance(item, dict) for item in layout):
        raise RuntimeError("Calamares partitionLayout is not a list of objects")
    duplicate_esps = [
        item
        for item in layout
        if item.get("mountPoint") == "/boot/efi"
        or str(item.get("type", "")).lower() == "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
    ]
    if duplicate_esps:
        raise RuntimeError(f"partitionLayout duplicates Calamares' EFI partition: {duplicate_esps!r}")
    if document.get("defaultPartitionTableType") not in (None, ""):
        raise RuntimeError("Calamares must select msdos for BIOS and GPT for UEFI")
    if document.get("createHybridBootloaderLayout") is True:
        raise RuntimeError("Calamares hybrid partition layout is not firmware-native")
    bios = [item for item in layout if item.get("name") == "bios_grub"]
    boots = [item for item in layout if item.get("mountPoint") == "/boot"]
    roots = [item for item in layout if item.get("mountPoint") == "/"]
    if bios:
        raise RuntimeError(f"partitionLayout must not synthesize a GPT BIOS boot partition: {bios!r}")
    if (
        len(boots) != 1
        or boots[0].get("filesystem") != "ext4"
        or boots[0].get("noEncrypt") is not True
        or boots[0].get("size") != "2G"
    ):
        raise RuntimeError(f"partitionLayout clear /boot contract mismatch: {boots!r}")
    if (
        len(roots) != 1
        or roots[0].get("filesystem") != "btrfs"
        or roots[0].get("noEncrypt") is True
    ):
        raise RuntimeError(f"partitionLayout Btrfs root contract mismatch: {roots!r}")
    return document


def validate_grub_installer_contract(installer: str) -> None:
    """Reject mapper-unsafe disk guessing and cross-firmware GRUB installs."""
    required = (
        "physical_disk_for()",
        "node=${1%%\\[*}",
        'lsblk -s -nro NAME "$node"',
        "for mountpoint in /boot/efi /boot /; do",
        'lsblk -dnro TYPE "$disk"',
        "grub-install --target=i386-pc --recheck \"$DISK\"",
        "grub-install --target=x86_64-efi --efi-directory=/boot/efi",
        "GRUB_PC_DEB=$GRUB_PC_DIR/grub-pc.deb",
        "sha256sum --check grub-pc.deb.sha256",
        "dpkg-deb --field \"$GRUB_PC_DEB\" Version",
        "dpkg --remove grub-efi-amd64",
        "dpkg --install \"$GRUB_PC_DEB\"",
        "grub-pc grub-pc/install_devices multiselect $DISK",
        "rm -rf \"$GRUB_PC_DIR\"",
    )
    missing = [token for token in required if token not in installer]
    if missing:
        raise RuntimeError(f"GRUB installer physical-disk contract is incomplete: {missing!r}")
    forbidden = (
        "grub-probe --target=device / | sed",
        "sfdisk --part-type",
        "i386-pc bonus install",
    )
    present = [token for token in forbidden if token in installer]
    if present:
        raise RuntimeError(f"GRUB installer retains unsafe legacy logic: {present!r}")


def validate_grub_package_payload(squashfs: Path) -> None:
    """Verify the exact offline grub-pc package carried for BIOS installs."""
    package_path = "usr/share/shadowfetch/installer-packages/grub-pc.deb"
    checksum_path = package_path + ".sha256"
    package = squash_cat(squashfs, package_path, binary=True)
    checksum = squash_cat(squashfs, checksum_path)
    status_text = squash_cat(squashfs, "var/lib/dpkg/status")
    assert isinstance(package, bytes) and isinstance(checksum, str)
    assert isinstance(status_text, str)

    match = re.fullmatch(r"([0-9a-f]{64})  grub-pc\.deb\n?", checksum)
    actual = hashlib.sha256(package).hexdigest()
    if not match or match.group(1) != actual:
        raise RuntimeError("offline BIOS GRUB package checksum mismatch")

    installed = {
        record["Package"]: record
        for record in parse_deb822(status_text)
        if record.get("Status") == "install ok installed"
    }
    grub_pc_bin = installed.get("grub-pc-bin")
    if not grub_pc_bin:
        raise RuntimeError("live image does not contain grub-pc-bin")

    with tempfile.TemporaryDirectory(prefix="shadowfetch-grub-pc-") as temporary:
        local = Path(temporary) / "grub-pc.deb"
        local.write_bytes(package)
        metadata = {
            field: output(["dpkg-deb", "--field", str(local), field])
            for field in ("Package", "Version", "Architecture")
        }
    expected = {
        "Package": "grub-pc",
        "Version": grub_pc_bin.get("Version"),
        "Architecture": grub_pc_bin.get("Architecture"),
    }
    if metadata != expected:
        raise RuntimeError(
            f"offline BIOS GRUB package metadata mismatch: expected={expected}, got={metadata}"
        )
    print(
        "PASS: offline BIOS GRUB package checksum and metadata match "
        f"grub-pc-bin {metadata['Version']} {metadata['Architecture']}"
    )


def artifact_gate(iso: Path, marker: Path) -> None:
    checksum = Path(str(iso) + ".sha256")
    signature = Path(str(iso) + ".asc")
    public_key = ROOT / "repo/shadowfetch.gpg.asc"
    for path in (iso, checksum, signature, public_key, marker):
        if not path.is_file():
            raise RuntimeError(f"missing release artifact: {path}")

    marker_ns = marker.stat().st_mtime_ns
    stale = [path for path in (iso, checksum, signature) if path.stat().st_mtime_ns <= marker_ns]
    if stale:
        raise RuntimeError("release artifacts predate the build marker: " + ", ".join(map(str, stale)))

    line = checksum.read_text(encoding="utf-8").strip()
    match = re.fullmatch(r"([0-9a-f]{64})  (\S+)", line)
    if not match or match.group(2) != iso.name:
        raise RuntimeError(f"malformed checksum sidecar: {line!r}")
    actual = sha256(iso)
    if actual != match.group(1):
        raise RuntimeError(f"ISO checksum mismatch: expected {match.group(1)}, got {actual}")
    print(f"PASS: ISO SHA256 {actual} size={iso.stat().st_size}")

    with tempfile.TemporaryDirectory(prefix="shadowfetch-iso-keyring-") as temporary:
        keyring = Path(temporary) / "shadowfetch.gpg"
        run(
            "dearmor release signing key",
            ["gpg", "--batch", "--yes", "--dearmor", "--output", str(keyring), str(public_key)],
        )
        fingerprints = re.findall(
            r"^fpr:+([0-9A-F]+):$",
            output(["gpg", "--batch", "--with-colons", "--show-keys", str(keyring)]),
            re.MULTILINE,
        )
        if EXPECTED_SIGNING_FINGERPRINT not in fingerprints:
            raise RuntimeError(f"release key fingerprint mismatch: {fingerprints}")
        run(
            "detached ISO signature",
            ["gpgv", "--keyring", str(keyring), str(signature), str(iso)],
        )
    print(f"PASS: release signing fingerprint {EXPECTED_SIGNING_FINGERPRINT}")


def boot_gate(iso: Path) -> None:
    report = run(
        "El Torito and system-area inspection",
        ["xorriso", "-indev", str(iso), "-report_el_torito", "plain", "-report_system_area", "plain"],
        capture=True,
    ).stdout or ""
    requirements = {
        "volume label": "Volume id    : 'SHADOWFETCH'",
        "El Torito": "Boot record  : El Torito",
        "BIOS boot image": "BIOS  y",
        "UEFI boot image": "UEFI  y",
        "BIOS image path": "/boot/grub/i386-pc/eltorito.img",
        "UEFI image path": "/efi.img",
        "protective MBR": "MBR protective-msdos-label",
        "GPT hybrid": "GPT",
    }
    missing = [label for label, needle in requirements.items() if needle not in report]
    if missing:
        raise RuntimeError("ISO boot structure is incomplete: " + ", ".join(missing))
    print("PASS: BIOS and UEFI hybrid boot structure")


@contextmanager
def mounted_iso(iso: Path) -> Iterator[Path]:
    with tempfile.TemporaryDirectory(prefix="shadowfetch-iso-mount-") as temporary:
        mountpoint = Path(temporary)
        mounted = False
        try:
            run(
                "read-only ISO loop mount",
                command_for_privilege(
                    ["mount", "-o", "loop,ro,nosuid,nodev,noexec", str(iso), str(mountpoint)]
                ),
            )
            mounted = True
            mount_info = output(["findmnt", "-no", "FSTYPE,OPTIONS", "--target", str(mountpoint)])
            fields = mount_info.split(None, 1)
            if not fields or fields[0] != "iso9660" or len(fields) < 2:
                raise RuntimeError(f"unexpected ISO mount: {mount_info}")
            options = set(fields[1].split(","))
            for required in ("ro", "nosuid", "nodev", "noexec"):
                if required not in options:
                    raise RuntimeError(f"ISO mount lacks {required}: {mount_info}")
            print(f"PASS: read-only mount options {mount_info}")
            yield mountpoint
        finally:
            if mounted:
                run("ISO unmount", command_for_privilege(["umount", str(mountpoint)]))


def internal_manifest_gate(mountpoint: Path) -> Path:
    manifest = mountpoint / "SHA256SUMS"
    if not manifest.is_file():
        raise RuntimeError("ISO has no internal SHA256SUMS")
    names: set[str] = set()
    for index, raw in enumerate(manifest.read_text(encoding="utf-8").splitlines(), 1):
        match = re.fullmatch(r"[0-9a-f]{64}  (.+)", raw)
        if not match:
            raise RuntimeError(f"invalid internal checksum line {index}: {raw!r}")
        name = match.group(1).removeprefix("./")
        pure = PurePosixPath(name)
        if pure.is_absolute() or ".." in pure.parts or name in names:
            raise RuntimeError(f"unsafe or duplicate checksum target: {name}")
        names.add(name)
    missing = sorted(REQUIRED_IMAGE_FILES - names)
    if missing:
        raise RuntimeError("internal checksum manifest misses final image files: " + ", ".join(missing))
    run(
        f"internal ISO checksums ({len(names)} files)",
        ["sha256sum", "--check", "--strict", "--quiet", "SHA256SUMS"],
        cwd=mountpoint,
    )
    for name in REQUIRED_IMAGE_FILES:
        if not (mountpoint / name).is_file():
            raise RuntimeError(f"required ISO file is absent: {name}")
    print("PASS: kernel, initrd, squashfs, final GRUB config and Umbra theme are covered")
    return mountpoint / "live/filesystem.squashfs"


def squashfs_inventory(squashfs: Path) -> tuple[dict[str, str], str]:
    size = squashfs.stat().st_size
    if size > MAX_SQUASHFS_BYTES:
        raise RuntimeError(f"squashfs exceeds the 4 GiB file ceiling: {size}")
    stats = run(
        "squashfs metadata",
        ["unsquashfs", "-s", str(squashfs)],
        capture=True,
    ).stdout or ""
    if not re.search(r"(?im)^Compression\s+xz\s*$", stats):
        raise RuntimeError("squashfs is not xz-compressed")

    print("\n>>> squashfs path and mode inventory")
    process = subprocess.Popen(
        ["unsquashfs", "-lln", str(squashfs)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    assert process.stdout is not None
    inventory: dict[str, str] = {}
    pattern = re.compile(
        r"^(\S+)\s+\d+/\d+\s+\d+\s+\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}\s+"
        r"squashfs-root(?:/(.*))?$"
    )
    diagnostic: list[str] = []
    for raw in process.stdout:
        line = raw.rstrip("\n")
        match = pattern.match(line)
        if not match:
            if line:
                diagnostic.append(line)
            continue
        path = (match.group(2) or "").split(" -> ", 1)[0]
        if path:
            inventory[path] = match.group(1)
    if process.wait() != 0:
        raise RuntimeError("could not inventory squashfs: " + " | ".join(diagnostic[-10:]))
    if len(inventory) < 10000:
        raise RuntimeError(f"implausibly small squashfs inventory: {len(inventory)} paths")
    print(f"PASS: squashfs size={size} headroom={MAX_SQUASHFS_BYTES - size} paths={len(inventory)}")
    return inventory, stats


def squash_cat(squashfs: Path, path: str, *, binary: bool = False) -> str | bytes:
    result = subprocess.run(
        ["unsquashfs", "-cat", str(squashfs), path],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if binary:
        return result.stdout
    return result.stdout.decode("utf-8")


def forbidden_build_time_packages(installed: set[str]) -> list[str]:
    return sorted(installed & FORBIDDEN_BUILD_TIME_PACKAGES)


def package_gate(squashfs: Path) -> None:
    status_text = squash_cat(squashfs, "var/lib/dpkg/status")
    assert isinstance(status_text, str)
    installed = {
        record["Package"]: record["Version"]
        for record in parse_deb822(status_text)
        if record.get("Status") == "install ok installed"
    }
    custom = {
        package: version
        for package, version in installed.items()
        if package.startswith("shadowfetch-") or package == "grub-btrfs"
    }
    if custom != EXPECTED_CUSTOM_PACKAGES:
        missing = sorted(set(EXPECTED_CUSTOM_PACKAGES) - set(custom))
        extra = sorted(set(custom) - set(EXPECTED_CUSTOM_PACKAGES))
        mismatched = sorted(
            package
            for package in set(custom) & set(EXPECTED_CUSTOM_PACKAGES)
            if custom[package] != EXPECTED_CUSTOM_PACKAGES[package]
        )
        raise RuntimeError(
            f"installed custom package mismatch; missing={missing}, extra={extra}, "
            f"versions={[(name, custom[name]) for name in mismatched]}"
        )
    retired = sorted(package for package in installed if RETIRED_PACKAGE.search(package))
    if retired:
        raise RuntimeError("retired runtime packages remain installed: " + ", ".join(retired))
    nvidia = sorted(package for package in installed if PROPRIETARY_NVIDIA_PACKAGE.search(package))
    if nvidia:
        raise RuntimeError("proprietary NVIDIA driver packages are preinstalled: " + ", ".join(nvidia))
    if "buzz" in installed or "shadowfetch-nvidia" in installed:
        raise RuntimeError("Buzz or the deferred NVIDIA metapackage was installed without consent")
    if "grub-efi-amd64" not in installed or "grub-pc-bin" not in installed or "grub-pc" in installed:
        raise RuntimeError("live image GRUB package baseline is not hybrid-media safe")
    build_time_packages = forbidden_build_time_packages(set(installed))
    if build_time_packages:
        raise RuntimeError(
            "unpinned build-time downloader packages are installed: "
            + ", ".join(build_time_packages)
        )
    if "systemd-timesyncd" not in installed:
        raise RuntimeError("systemd-timesyncd is not installed")
    print(
        f"PASS: installed package contract ({len(installed)} total, "
        f"{len(custom)} exact Shadowfetch packages, no retired runtime, proprietary NVIDIA driver, "
        "or build-time downloader)"
    )


def retired_path(path: str) -> bool:
    lowered = path.lower()
    exact_prefixes = (
        "etc/openclaw/",
        "etc/hermes/",
        "etc/ollama/",
        "opt/openclaw/",
        "opt/hermes/",
        "usr/share/openclaw/",
        "usr/share/ollama/",
        "usr/share/llama.cpp/",
        "var/lib/openclaw/",
        "var/lib/hermes/",
        "var/lib/ollama/",
    )
    if lowered.startswith(exact_prefixes):
        return True
    basename = PurePosixPath(lowered).name
    if lowered.startswith(("usr/bin/", "usr/sbin/")) and (
        basename == "openclaw"
        or basename == "hermes"
        or basename == "ollama"
        or basename.startswith("llama-")
    ):
        return True
    if lowered.startswith(("etc/systemd/", "usr/lib/systemd/")) and re.search(
        r"(?:openclaw|hermes|ollama|shadowfetch-llama|llama-server)", basename
    ):
        return True
    if lowered.startswith("usr/libexec/") and re.search(
        r"(?:openclaw|hermes|ollama|shadowfetch-llama)", basename
    ):
        return True
    return False


def payload_gate(squashfs: Path, inventory: dict[str, str]) -> None:
    missing = sorted(REQUIRED_ROOT_FILES - set(inventory))
    if missing:
        raise RuntimeError("required installed-image files are absent: " + ", ".join(missing))
    bad_modes = sorted(
        path for path in REQUIRED_EXECUTABLES if "x" not in inventory[path]
    )
    if bad_modes:
        raise RuntimeError("installed helpers are not executable: " + ", ".join(bad_modes))

    retired = sorted(path for path in inventory if retired_path(path))
    if retired:
        raise RuntimeError("retired runtime paths remain in squashfs: " + ", ".join(retired))
    models = sorted(
        path for path in inventory if path.lower().endswith((".gguf", ".safetensors"))
    )
    if models:
        raise RuntimeError("model weights were embedded in the ISO: " + ", ".join(models))
    secrets = sorted(path for path in inventory if SECRET_PATH.search(path))
    if secrets:
        raise RuntimeError("private credentials or keys were embedded: " + ", ".join(secrets))

    compose = squash_cat(squashfs, "usr/share/shadowfetch/buzz/compose.yml")
    helper = squash_cat(squashfs, "usr/bin/shadowfetch-buzz")
    service = squash_cat(squashfs, "usr/lib/systemd/user/shadowfetch-buzz.service")
    passport = squash_cat(squashfs, "usr/bin/shadowfetch-passport")
    recovery_sources = squash_cat(
        squashfs, "usr/share/shadowfetch/apt-recovery/debian.sources"
    )
    guide = squash_cat(
        squashfs, "usr/share/shadowfetch/control-center/sfcc/guide_page.py"
    )
    launcher = squash_cat(squashfs, "usr/share/applications/shadowfetch-guide.desktop")
    assert all(isinstance(item, str) for item in (
        compose, helper, service, passport, recovery_sources, guide, launcher
    ))
    image_lines = [line.strip() for line in compose.splitlines() if line.strip().startswith("image:")]
    if len(image_lines) != 5:
        raise RuntimeError(f"expected five Buzz container images, found {len(image_lines)}")
    for line in image_lines:
        if line == "image: ${BUZZ_IMAGE}":
            continue
        if not re.fullmatch(r"image: \S+@sha256:[0-9a-f]{64}", line):
            raise RuntimeError(f"Buzz image is not immutable: {line}")
    published = [line.strip() for line in compose.splitlines() if re.match(r'^\s*-\s*["\']?[^#]*:\d+["\']?\s*$', line)]
    if published != ['- "127.0.0.1:${BUZZ_HTTP_PORT:-3000}:3000"']:
        raise RuntimeError(f"unexpected Buzz published ports: {published}")
    if "network_mode: host" in compose or ":latest" in compose:
        raise RuntimeError("Buzz compose bypasses isolation or uses a mutable tag")
    if not re.search(r'BUZZ_IMAGE="ghcr\.io/block/buzz@sha256:[0-9a-f]{64}"', helper):
        raise RuntimeError("Buzz relay image is not digest-pinned by the setup helper")
    if "ConditionPathExists=%h/.local/share/shadowfetch/buzz/.env" not in service:
        raise RuntimeError("Buzz service can start before the user has completed setup")
    print("PASS: Buzz is consent-gated, loopback-only and digest-pinned")
    for token in (
        '"local_only": True', '"upload_performed": False',
        "privacy_issues(document)", "shadowfetch-facts", "--output",
    ):
        if token not in passport:
            raise RuntimeError(f"System Passport contract is absent: {token}")
    if "shadowfetch-passport" not in guide or "Nothing is uploaded" not in guide:
        raise RuntimeError("Guide UI is not wired to the private Passport")
    if "Exec=shadowfetch-control --page guide" not in launcher:
        raise RuntimeError("Guide launcher does not open the Guide route")
    print("PASS: Shadowfetch Guide and private System Passport are installed")
    if "deb-src http://deb.debian.org/debian/ testing " not in recovery_sources:
        raise RuntimeError("Phoenix recovery sources differ from installed-system policy")
    print("PASS: Phoenix source-repair payload matches installed-system policy")


def identity_and_installer_gate(squashfs: Path, inventory: dict[str, str]) -> None:
    version = squash_cat(squashfs, "usr/share/shadowfetch/version")
    os_release = squash_cat(squashfs, "etc/os-release")
    canonical = squash_cat(squashfs, "usr/share/shadowfetch/os-release.shadowfetch")
    assert isinstance(version, str) and isinstance(os_release, str) and isinstance(canonical, str)
    if version.strip() != VERSION:
        raise RuntimeError(f"version file reports {version.strip()!r}")
    for label, content in (("/etc/os-release", os_release), ("canonical os-release", canonical)):
        values = parse_os_release(content)
        required = {
            "NAME": "Shadowfetch Linux",
            "ID": "shadowfetch",
            "VERSION_ID": VERSION,
            "VERSION_CODENAME": CODENAME,
        }
        mismatched = {key: values.get(key) for key, expected in required.items() if values.get(key) != expected}
        if mismatched or "Umbra" not in values.get("PRETTY_NAME", ""):
            raise RuntimeError(f"{label} identity mismatch: {mismatched or values.get('PRETTY_NAME')}")

    apt_source = squash_cat(squashfs, "etc/apt/sources.list.d/shadowfetch.list")
    assert isinstance(apt_source, str)
    if apt_source.strip() != "deb https://www.shadowfetch.com/linux/apt umbra main":
        raise RuntimeError(f"unexpected installed APT source: {apt_source.strip()!r}")
    key_paths = sorted(
        path
        for path in inventory
        if re.fullmatch(r"etc/apt/trusted\.gpg\.d/shadowfetch[^/]*\.(?:gpg|key)", path)
    )
    if not key_paths:
        raise RuntimeError("installed image has no Shadowfetch APT signing key")
    fingerprints: set[str] = set()
    with tempfile.TemporaryDirectory(prefix="shadowfetch-installed-key-") as temporary:
        for index, key_path in enumerate(key_paths):
            content = squash_cat(squashfs, key_path, binary=True)
            assert isinstance(content, bytes)
            local = Path(temporary) / f"key-{index}.gpg"
            local.write_bytes(content)
            listing = output(["gpg", "--batch", "--with-colons", "--show-keys", str(local)])
            fingerprints.update(re.findall(r"^fpr:+([0-9A-F]+):$", listing, re.MULTILINE))
    if EXPECTED_SIGNING_FINGERPRINT not in fingerprints:
        raise RuntimeError(f"installed APT key fingerprint mismatch: {sorted(fingerprints)}")

    shellprocess = squash_cat(squashfs, "etc/calamares/modules/shellprocess.conf")
    settings = squash_cat(squashfs, "etc/calamares/settings.conf")
    partition = squash_cat(squashfs, "etc/calamares/modules/partition.conf")
    grub_installer = squash_cat(squashfs, "usr/local/sbin/sf-install-grub")
    desktop_icon = squash_cat(squashfs, "usr/bin/add-calamares-desktop-icon")
    hostkey_dropin = squash_cat(
        squashfs,
        "etc/systemd/system/sshd-keygen.service.d/10-shadowfetch-hostkeys.conf",
    )
    cleanup = squash_cat(squashfs, "usr/local/sbin/sf-remove-live-user")
    nossh = squash_cat(squashfs, "etc/systemd/system/shadowfetch-live-nossh.service")
    ufw = squash_cat(squashfs, "etc/ufw/ufw.conf")
    firstboot = squash_cat(squashfs, "usr/lib/shadowfetch/firstboot.sh")
    assert all(
        isinstance(item, str)
        for item in (
            shellprocess,
            settings,
            partition,
            grub_installer,
            desktop_icon,
            hostkey_dropin,
            cleanup,
            nossh,
            ufw,
            firstboot,
        )
    )
    if '"sh /usr/local/sbin/sf-remove-live-user"' not in shellprocess or "|| true" in shellprocess:
        raise RuntimeError("Calamares does not fail closed on live-account cleanup")
    validate_calamares_exec_sequence(settings)
    validate_partition_contract(partition)
    validate_grub_installer_contract(grub_installer)
    validate_grub_package_payload(squashfs)
    if "Shadowfetch replacement for Debian's live-session desktop-icon helper" not in desktop_icon:
        raise RuntimeError("the corrected Calamares desktop-icon helper is not installed")
    if not re.search(r"(?m)^ConditionFirstBoot=$", hostkey_dropin) or (
        "ConditionPathExists=!/etc/ssh/ssh_host_ed25519_key" not in hostkey_dropin
    ):
        raise RuntimeError("installed SSH host-key generation is not first-install safe")
    for required in (
        "LIVE_USER=shadow",
        'rm -rf -- "/home/${LIVE_USER:?}"',
        'grep -q "^${LIVE_USER}:" /etc/shadow',
    ):
        if required not in cleanup:
            raise RuntimeError(f"live-user cleanup lacks verification: {required}")
    if "ConditionPathExists=/run/live/medium" not in nossh or "mask ssh.service ssh.socket" not in nossh:
        raise RuntimeError("live-session SSH hardening is incomplete")
    if not inventory["etc/systemd/system/sysinit.target.wants/shadowfetch-live-nossh.service"].startswith("l"):
        raise RuntimeError("live-session SSH hardening service is not enabled")
    if not re.search(r"(?m)^ENABLED=yes$", ufw):
        raise RuntimeError("UFW is not enabled in the live image")
    if (
        "timedatectl set-local-rtc 0 --adjust-system-clock" not in firstboot
        or "timedatectl set-local-rtc 1" in firstboot
        or "systemctl enable --now systemd-timesyncd.service" not in firstboot
    ):
        raise RuntimeError("first boot does not enforce UTC RTC and network time")
    if "etc/sudoers.d/shadowfetch-live-shadow" not in inventory:
        raise RuntimeError("live account contract changed without updating installer cleanup QA")
    print("PASS: version, APT trust, Calamares cleanup, UFW and live-session SSH hardening")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iso", type=Path, default=ROOT / ISO_NAME)
    parser.add_argument("--marker", type=Path, default=ROOT / f"build/.live-build-{VERSION}-started")
    args = parser.parse_args()
    iso = args.iso.resolve()
    marker = args.marker.resolve()
    os.environ.setdefault("LC_ALL", "C.UTF-8")
    for command in (
        "dpkg-deb",
        "findmnt",
        "gpg",
        "gpgv",
        "mount",
        "sha256sum",
        "sudo",
        "umount",
        "unsquashfs",
        "xorriso",
    ):
        if not shutil.which(command):
            raise RuntimeError(f"required ISO gate command is missing: {command}")

    artifact_gate(iso, marker)
    boot_gate(iso)
    with mounted_iso(iso) as mountpoint:
        squashfs = internal_manifest_gate(mountpoint)
        inventory, _ = squashfs_inventory(squashfs)
        package_gate(squashfs)
        payload_gate(squashfs, inventory)
        identity_and_installer_gate(squashfs, inventory)
    print("\nISO_GATE_PASSED")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.CalledProcessError, UnicodeDecodeError) as exc:
        print(f"ISO_GATE_FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1)
