#!/usr/bin/env python3
"""Build reproducible Shadowfetch Linux 3.1.0 release evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote


VERSION = "3.1.0"
CODENAME = "Umbra"
WEBSITE = "https://www.shadowfetchlinux.org"
GITHUB = "https://github.com/ShadowfetchLinux/shadowfetch-linux"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_deb822(path: Path) -> list[dict[str, str]]:
    paragraphs: list[dict[str, str]] = []
    current: dict[str, str] = {}
    last_key: str | None = None

    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not raw_line:
            if current:
                paragraphs.append(current)
                current = {}
                last_key = None
            continue
        if raw_line[0].isspace() and last_key:
            current[last_key] += "\n" + raw_line.strip()
            continue
        key, separator, value = raw_line.partition(":")
        if not separator:
            continue
        last_key = key
        current[key] = value.strip()

    if current:
        paragraphs.append(current)
    return paragraphs


def source_name(value: str, fallback: str) -> str:
    if not value:
        return fallback
    return re.sub(r"\s*\([^)]*\)\s*$", "", value).strip()


def build_package_manifest(
    packages_index: Path, sources_index: Path, iso_sha256: str
) -> str:
    binaries = sorted(
        parse_deb822(packages_index),
        key=lambda item: (item.get("Package", ""), item.get("Architecture", "")),
    )
    sources = sorted(
        parse_deb822(sources_index), key=lambda item: item.get("Package", "")
    )

    lines = [
        f"Shadowfetch Linux {VERSION} signed repository package manifest",
        f"ISO SHA-256: {iso_sha256}",
        f"Binary packages: {len(binaries)}",
        f"Source packages: {len(sources)}",
        "",
        "BINARY PACKAGES",
        "package\tversion\tarchitecture\tsource\tsize\tsha256\tfilename",
    ]
    for package in binaries:
        name = package.get("Package", "")
        lines.append(
            "\t".join(
                (
                    name,
                    package.get("Version", ""),
                    package.get("Architecture", ""),
                    source_name(package.get("Source", ""), name),
                    package.get("Size", ""),
                    package.get("SHA256", ""),
                    package.get("Filename", ""),
                )
            )
        )

    lines.extend(("", "SOURCE PACKAGES", "package\tversion\tsha256\tfilename"))
    for package in sources:
        checksums = [
            line for line in package.get("Checksums-Sha256", "").splitlines() if line.strip()
        ]
        if not checksums:
            lines.append(
                "\t".join((package.get("Package", ""), package.get("Version", ""), "", ""))
            )
            continue
        for checksum_line in checksums:
            parts = checksum_line.split()
            checksum = parts[0] if parts else ""
            filename = parts[2] if len(parts) >= 3 else ""
            lines.append(
                "\t".join(
                    (
                        package.get("Package", ""),
                        package.get("Version", ""),
                        checksum,
                        filename,
                    )
                )
            )
    return "\n".join(lines) + "\n"


def build_sbom(status_file: Path, iso_sha256: str, timestamp: str) -> dict[str, object]:
    installed = [
        package
        for package in parse_deb822(status_file)
        if package.get("Status") == "install ok installed"
    ]
    installed.sort(key=lambda item: (item.get("Package", ""), item.get("Architecture", "")))

    components: list[dict[str, object]] = []
    for package in installed:
        name = package.get("Package", "unknown")
        version = package.get("Version", "unknown")
        architecture = package.get("Architecture", "unknown")
        source = source_name(package.get("Source", ""), name)
        purl = (
            f"pkg:deb/debian/{quote(name, safe='')}@{quote(version, safe='')}"
            f"?arch={quote(architecture, safe='')}"
        )
        properties = [
            {"name": "shadowfetch:dpkg-status", "value": package.get("Status", "")},
            {"name": "shadowfetch:source-package", "value": source},
        ]
        if package.get("Multi-Arch"):
            properties.append(
                {"name": "shadowfetch:multi-arch", "value": package["Multi-Arch"]}
            )
        components.append(
            {
                "type": "library",
                "bom-ref": purl,
                "name": name,
                "version": version,
                "purl": purl,
                "properties": properties,
            }
        )

    serial = uuid.uuid5(
        uuid.NAMESPACE_URL, f"shadowfetch-linux-{VERSION}:{iso_sha256}"
    )
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "Shadowfetch release evidence generator",
                        "version": VERSION,
                    }
                ]
            },
            "component": {
                "type": "operating-system",
                "name": "Shadowfetch Linux Fire Edition",
                "version": VERSION,
                "description": f"Shadowfetch Linux {VERSION} {CODENAME} exact ISO package inventory",
                "externalReferences": [
                    {"type": "website", "url": WEBSITE},
                    {"type": "vcs", "url": GITHUB},
                ],
                "properties": [
                    {"name": "shadowfetch:codename", "value": CODENAME},
                    {"name": "shadowfetch:iso-sha256", "value": iso_sha256},
                ],
            },
        },
        "components": components,
    }


def build_sources_report(chroot: Path, component_count: int, iso_sha256: str) -> str:
    apt_root = chroot / "etc/apt"
    source_files = [apt_root / "sources.list"]
    source_files.extend(sorted((apt_root / "sources.list.d").glob("*")))
    lines = [
        f"Shadowfetch Linux {VERSION} SBOM source inputs",
        f"ISO SHA-256: {iso_sha256}",
        f"Installed dpkg components: {component_count}",
        "Inventory source: live-build/chroot/var/lib/dpkg/status",
        "",
        "APT SOURCES",
    ]
    for path in source_files:
        if not path.is_file():
            continue
        lines.append(f"[{path.relative_to(chroot)}]")
        for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw_line.strip()
            if line and not line.startswith("#"):
                lines.append(line)
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def build_dossier(manifest: dict[str, object], timestamp: str) -> str:
    artifact = manifest["artifact"]
    cases = manifest["cases"]
    required = [case for case in cases if case["phase"] == "prepublish" and case["required"]]
    optional = [case for case in cases if case["phase"] == "prepublish" and not case["required"]]
    passed = sum(case["status"] == "pass" for case in required)

    lines = [
        f"# Shadowfetch Linux {VERSION} prepublication release dossier",
        "",
        f"Codename: {CODENAME}",
        "",
        f"Evidence timestamp: {timestamp}",
        "",
        "## Artifact identity",
        "",
        f"- ISO: `{artifact['iso_path']}`",
        f"- Size: `{artifact['iso_size_bytes']}` bytes",
        f"- SHA-256: `{artifact['iso_sha256']}`",
        f"- Detached signature: `{artifact['signature_path']}`",
        f"- Signing fingerprint: `{artifact['signing_fingerprint']}`",
        f"- Canonical website: {WEBSITE}",
        f"- Canonical source: {GITHUB}",
        "",
        "This is a prepublication dossier. It records the exact candidate and does not claim that any public destination has been updated.",
        "",
        "## Release intent",
        "",
        "Shadowfetch Linux 3.1.0 keeps the Fire Edition and Umbra visual identity while making the first Linux session more useful and more honest. Shadowfetch Guide and its private System Passport explain what works without uploading machine identity. Buzz is the single optional local-AI workspace, recommends an open model only after consent, and keeps its relay and compute listeners loopback-only by default. Codex, Claude Code, Grok Build, and Cursor Agent are independent, verified, user-owned options with no credentials preloaded.",
        "",
        "The release also strengthens safe updates and Phoenix rollback on separate-/boot Btrfs installations, preserves a tested 2.1.4 upgrade path, improves new-generation NVIDIA guidance, and keeps renderer claims measured rather than assumed.",
        "",
        "## QA position",
        "",
        f"- Required prepublication cases passing before REL-01 packaging: {passed} of {len(required)}",
        f"- Optional prepublication cases: {len(optional)}",
        "- Publication cases are intentionally pending until all prepublication gates pass.",
        "",
        "## Disclosures",
        "",
        "- No open model is bundled in the ISO. Buzz recommends and downloads a model only after the user confirms sharing in Settings > Compute.",
        "- During the tested network interruption, Buzz did not falsely report success, but automatic transfer resume was not observed. The disclosed clean retry required removal of only the disposable incomplete cache object before real inference completed.",
        "- Codex, Claude Code, Grok Build, and Cursor Agent require their own supported sign-in after installation; Shadowfetch includes no vendor credential.",
        "- NVIDIA workflow and rollback were tested against the physical RTX 5060 Ti host. The ISO retains AMD and Intel Mesa paths, but no active physical AMD or Intel renderer was available, so performance on those paths is not claimed.",
        "- Secure Boot remains an unsigned-image caveat documented on the site.",
        "",
        "## Claims-to-evidence index",
        "",
        "| Case | Requirement | Required | Status | Evidence |",
        "| --- | --- | --- | --- | --- |",
    ]
    for case in cases:
        if case["phase"] != "prepublish":
            continue
        evidence_paths = [item.get("path", "") for item in case.get("evidence", [])]
        evidence = "<br>".join(f"`{path}`" for path in evidence_paths) or "None recorded"
        title = str(case["title"]).replace("|", "\\|")
        lines.append(
            f"| {case['id']} | {title} | {'yes' if case['required'] else 'no'} | {case['status']} | {evidence} |"
        )
    lines.append("")
    return "\n".join(lines)


def write_text(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parent.parent
    )
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()

    root = args.root.resolve()
    output = (args.output_dir or root / "work" / f"release-{VERSION}").resolve()
    output.mkdir(parents=True, exist_ok=True)

    manifest_path = root / "qa" / VERSION / "acceptance.json"
    packages_index = root / "repo/dists/umbra/main/binary-amd64/Packages"
    sources_index = root / "repo/dists/umbra/main/source/Sources"
    chroot = root / "live-build/chroot"
    status_file = chroot / "var/lib/dpkg/status"
    iso_path = root / f"shadowfetch-{VERSION}-amd64.iso"

    for required_path in (
        manifest_path,
        packages_index,
        sources_index,
        status_file,
        iso_path,
    ):
        if not required_path.is_file():
            raise SystemExit(f"missing release input: {required_path}")

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    artifact = manifest.get("artifact", {})
    iso_sha256 = sha256_file(iso_path)
    if artifact.get("iso_sha256") != iso_sha256:
        raise SystemExit(
            f"ISO hash mismatch: manifest={artifact.get('iso_sha256')} actual={iso_sha256}"
        )
    if artifact.get("iso_size_bytes") != iso_path.stat().st_size:
        raise SystemExit("ISO size does not match the acceptance manifest")

    timestamp = datetime.fromtimestamp(iso_path.stat().st_mtime, timezone.utc).isoformat()
    package_manifest = build_package_manifest(packages_index, sources_index, iso_sha256)
    sbom = build_sbom(status_file, iso_sha256, timestamp)
    sources_report = build_sources_report(chroot, len(sbom["components"]), iso_sha256)
    dossier = build_dossier(manifest, timestamp)
    facts = {
        "version": VERSION,
        "codename": CODENAME,
        "iso": artifact,
        "candidateTimestamp": timestamp,
        "website": WEBSITE,
        "source": GITHUB,
        "publicationStatus": "prepublication",
    }

    outputs = {
        output / f"dossier-{VERSION}.md": dossier,
        output / f"packages-{VERSION}.manifest": package_manifest,
        output / f"sbom-sources-{VERSION}.txt": sources_report,
        output / f"release-facts-{VERSION}.json": json.dumps(facts, indent=2) + "\n",
        output / f"sbom-{VERSION}.cdx.json": json.dumps(sbom, indent=2) + "\n",
    }
    for path, content in outputs.items():
        write_text(path, content)

    checksums = [
        f"{sha256_file(path)}  {path.name}" for path in sorted(outputs)
    ]
    write_text(output / f"release-evidence-{VERSION}.sha256", "\n".join(checksums) + "\n")
    print(
        f"RELEASE_EVIDENCE_READY output={output} components={len(sbom['components'])} "
        f"binary_packages={len(parse_deb822(packages_index))} "
        f"source_packages={len(parse_deb822(sources_index))}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
