#!/usr/bin/env python3
"""Reproducible source and secret gate for a Shadowfetch Linux release.

ONE implementation for every release. The version-varying inputs live in
tools/release/versions/<version>.toml; see tools/release/gate.py for why the
version-copied gate families were collapsed.

Every program this gate runs is resolved to a trusted absolute path by
gate.ProgramResolver. That is not cosmetic here: gitleaks decides whether a
credential shipped, and before Stage Q it was located by PATH lookup and run by
bare name, on a host where PATH resolves it inside a builder-writable directory.
"""

from __future__ import annotations

import argparse
import ast
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

import gate
from gate import ROLE_QUALITY, ROLE_SECURITY, run

from providers.validate_manifest import validate_provider_payload


ROOT = gate.ROOT

# What each program is allowed to decide. gitleaks and git are the security
# pair: gitleaks decides "no secret is present", and git decides WHICH FILES are
# scanned and supplies the history that is scanned. A forged git would silently
# shrink the candidate set; a forged gitleaks would report a clean tree.
REQUIRED_PROGRAMS = (
    ("git", ROLE_SECURITY),
    ("gitleaks", ROLE_SECURITY),
    ("shellcheck", ROLE_QUALITY),
    ("desktop-file-validate", ROLE_QUALITY),
    ("make", ROLE_QUALITY),
    ("bash", ROLE_QUALITY),
    ("sh", ROLE_QUALITY),
)
BLOCKED_PREFIXES = (
    "build/",
    "repo/",
    "work/",
    "live-build/binary/",
    "live-build/cache/",
    "live-build/chroot/",
)
ACTIVE_IMAGE_ROOTS = (
    "packages/shadowfetch-defaults/data",
    "packages/shadowfetch-missions/data",
    "packages/shadowfetch-fireline/data",
    "packages/shadowfetch-welcome/src/shadowfetch-welcome",
    "packages/shadowfetch-control-center/data",
    "live-build/config/includes.chroot",
    "live-build/config/package-lists",
)
RETIRED_RUNTIME = re.compile(
    r"openclaw|\bhermes\b|\bollama\b|open[- ]?webui|llama\.cpp|llama-server",
    re.IGNORECASE,
)
MIGRATION_MANIFEST = (
    "packages/shadowfetch-defaults/data/usr/share/shadowfetch/"
    "migrations/2.1.3-ai-packages"
)
EXPECTED_MIGRATION_PACKAGES = (
    "shadowfetch-ai-workspace",
    "llama.cpp",
    "llama.cpp-services",
    "llama.cpp-tools",
    "llama.cpp-tools-extra",
    "libllama0",
    "whisper.cpp",
    "libwhisper1",
    "whisper.cpp-tools",
)
FORBIDDEN_BUILD_TIME_DOWNLOADERS = frozenset({"libdvd-pkg"})
GUIDE_FILES = (
    "packages/shadowfetch-defaults/data/usr/bin/shadowfetch-passport",
    "packages/shadowfetch-control-center/data/usr/share/shadowfetch/"
    "control-center/sfcc/guide_page.py",
    "packages/shadowfetch-control-center/data/usr/share/applications/"
    "shadowfetch-guide.desktop",
)
PHOENIX_RECOVERY_FILES = (
    "packages/shadowfetch-phoenix/usr/libexec/phoenix-apt-repair",
    "packages/shadowfetch-phoenix/usr/share/shadowfetch/apt-recovery/debian.sources",
    "packages/shadowfetch-phoenix/usr/share/shadowfetch/apt-recovery/umbra.sources",
    "packages/shadowfetch-phoenix/usr/share/shadowfetch/apt-recovery/"
    "umbra-archive-keyring.gpg",
)
EXPECTED_DEBIAN_RECOVERY = """# Shadowfetch Linux -- Debian testing.
# Written at install time from the suite this image was built against, so it
# cannot disagree with the installed userland. See https://wiki.debian.org/SourcesList
deb http://deb.debian.org/debian/ testing main contrib non-free non-free-firmware
deb-src http://deb.debian.org/debian/ testing main contrib non-free non-free-firmware
deb http://deb.debian.org/debian/ testing-updates main contrib non-free non-free-firmware
deb-src http://deb.debian.org/debian/ testing-updates main contrib non-free non-free-firmware
"""


class GitHistoryUnavailable(RuntimeError):
    """Git cannot enumerate this tree, so the Git-history secret scan cannot run."""


NO_GIT_REMEDY = (
    "the Git-history secret scan cannot run and the candidate file list cannot be "
    "derived from the index. Repair the repository, or re-run with --no-git to scan "
    "the working tree only -- history is then NOT scanned."
)
NO_GIT_SKIP_DIRECTORIES = frozenset(
    {".git", "__pycache__", ".debhelper", "node_modules", ".wrangler"}
)


def git_tree_status(git: gate.TrustedProgram) -> str:
    """Return "" when Git can enumerate ROOT, otherwise the reason it cannot."""
    probe = subprocess.run(
        git.argv("rev-parse", "--is-inside-work-tree"),
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if probe.returncode != 0:
        detail = probe.stderr.decode("utf-8", "replace").strip().splitlines()
        return (
            f"{ROOT} is not a usable Git work tree "
            f"({detail[-1] if detail else 'git rev-parse failed'})"
        )
    if probe.stdout.strip() != b"true":
        return f"{ROOT} is not inside a Git work tree"
    return ""


def candidate_files(git: gate.TrustedProgram) -> list[Path]:
    reason = git_tree_status(git)
    if reason:
        raise GitHistoryUnavailable(f"Git is unusable: {reason}; {NO_GIT_REMEDY}")
    result = subprocess.run(
        git.argv("ls-files", "--cached", "--others", "--exclude-standard", "-z"),
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip().splitlines()
        raise GitHistoryUnavailable(
            f"git ls-files failed in {ROOT} "
            f"({detail[-1] if detail else f'exit status {result.returncode}'}); "
            f"{NO_GIT_REMEDY}"
        )
    candidates: list[Path] = []
    for raw in result.stdout.split(b"\0"):
        if not raw:
            continue
        relative = os.fsdecode(raw)
        if relative.startswith(BLOCKED_PREFIXES):
            continue
        path = ROOT / relative
        if path.is_file():
            candidates.append(path)
    return sorted(set(candidates))


def is_debhelper_staging(path: Path) -> bool:
    """True for a packages/<source>/debian/<binary>/ tree.

    dpkg-buildpackage rebuilds these on every build: they are byte copies of files
    already enumerated from their real location, so scanning them adds nothing and
    reports the originals' allowlisted matches at a path no allowlist covers.
    """
    parts = path.relative_to(ROOT).parts
    return (
        len(parts) == 4
        and parts[0] == "packages"
        and parts[2] == "debian"
        and (path / "DEBIAN").is_dir()
    )


def filesystem_candidate_files() -> list[Path]:
    """Enumerate the working tree without Git, for the --no-git fallback scan.

    This cannot honour .gitignore, so it applies the same BLOCKED_PREFIXES as the
    Git path plus the generated directories Git would have excluded.
    """
    candidates: list[Path] = []
    for directory, subdirectories, names in os.walk(ROOT):
        base = Path(directory)
        keep: list[str] = []
        for name in subdirectories:
            if name in NO_GIT_SKIP_DIRECTORIES:
                continue
            relative = (base / name).relative_to(ROOT).as_posix() + "/"
            if relative.startswith(BLOCKED_PREFIXES):
                continue
            if is_debhelper_staging(base / name):
                continue
            keep.append(name)
        subdirectories[:] = sorted(keep)
        for name in names:
            path = base / name
            relative = path.relative_to(ROOT).as_posix()
            if relative.startswith(BLOCKED_PREFIXES):
                continue
            if path.is_file():
                candidates.append(path)
    return sorted(set(candidates))


def first_line(path: Path) -> str:
    try:
        with path.open("rb") as handle:
            return handle.readline(512).decode("utf-8", "replace").strip()
    except OSError:
        return ""


def shell_files(candidates: list[Path]) -> tuple[list[Path], list[Path]]:
    owned: list[Path] = []
    vendored: list[Path] = []
    for path in candidates:
        relative = path.relative_to(ROOT)
        if not relative.parts or relative.parts[0] not in {"live-build", "packages", "tools"}:
            continue
        line = first_line(path)
        if not line.startswith("#!"):
            continue
        if not re.search(r"(?:^|/|\s)(?:ba|da|k|z)?sh(?:\s|$)", line):
            continue
        if relative.parts[:2] == ("packages", "grub-btrfs"):
            vendored.append(path)
        else:
            owned.append(path)
    return owned, vendored


def parser_gates(candidates: list[Path], validate: gate.TrustedProgram) -> None:
    python_files: list[Path] = []
    json_files: list[Path] = []
    xml_files: list[Path] = []
    desktop_files: list[Path] = []
    for path in candidates:
        line = first_line(path)
        if path.suffix == ".py" or (line.startswith("#!") and "python" in line):
            python_files.append(path)
        if path.suffix == ".json":
            json_files.append(path)
        if path.suffix in {".menu", ".xml"}:
            xml_files.append(path)
        if path.suffix == ".desktop" and (
            "applications" in path.parts
            or "autostart" in path.parts
            or path.name == "shadowfetch-welcome.desktop"
        ):
            desktop_files.append(path)

    for path in python_files:
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    print(f"PASS: Python parse ({len(python_files)} files)")

    # Test fixtures under tests/fixtures/ are DATA, never installed, and some
    # are deliberately malformed -- a conformance suite that proves the
    # registry rejects an unparseable manifest has to contain one. Parsing
    # them here would make "the gate passes" require that no test can
    # describe a broken input.
    parseable = [p for p in json_files
                 if "/tests/fixtures/" not in p.as_posix()]
    skipped = len(json_files) - len(parseable)
    for path in parseable:
        json.loads(path.read_text(encoding="utf-8"))
    print(f"PASS: JSON parse ({len(parseable)} files"
          + (f"; {skipped} deliberately-invalid test fixtures skipped)" if skipped else ")"))

    for path in xml_files:
        ET.parse(path)
    print(f"PASS: XML/menu parse ({len(xml_files)} files)")

    if desktop_files:
        run(
            f"desktop entry validation ({len(desktop_files)} files)",
            validate.argv(*map(str, desktop_files)),
        )


def secret_gates(
    candidates: list[Path],
    gitleaks: gate.TrustedProgram,
    *,
    scan_history: bool = True,
) -> None:
    with tempfile.TemporaryDirectory(prefix="shadowfetch-source-gate-") as temporary:
        mirror = Path(temporary)
        for source in candidates:
            relative = source.relative_to(ROOT)
            destination = mirror / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
        run(
            f"Gitleaks candidate tree ({len(candidates)} files)",
            gitleaks.argv(
                "dir",
                ".",
                "--no-banner",
                "--no-color",
                "--redact",
                "--config",
                str(mirror / ".gitleaks.toml"),
            ),
            cwd=mirror,
        )
    if not scan_history:
        print(
            "WARNING: Git history was NOT secret-scanned (--no-git): only the "
            f"{len(candidates)} working-tree files above were scanned. A secret "
            "removed from the tree but still present in history would be missed."
        )
        return
    run(
        "Gitleaks Git history",
        gitleaks.argv(
            "git",
            ".",
            "--no-banner",
            "--no-color",
            "--redact",
            "--config",
            str(ROOT / ".gitleaks.toml"),
        ),
    )


def retired_runtime_gate() -> None:
    payload_paths = [p.relative_to(data).as_posix() for data in (ROOT / "packages").glob("*/data") for p in data.rglob("*") if p.is_file() or p.is_symlink()]
    missions_data = ROOT / "packages/shadowfetch-missions/data"
    def _read(relative):
        try:
            return (missions_data / relative).read_text(encoding="utf-8")
        except OSError:
            return None
    result = validate_provider_payload(payload_paths, (missions_data / "usr/lib/shadowfetch/missions/sf_missions.py").read_text(), read=_read)
    print("PASS: provider manifests validated: " + ", ".join(result["providers"]))
    findings: list[str] = []
    for value in ACTIVE_IMAGE_ROOTS:
        root = ROOT / value
        paths = [root] if root.is_file() else root.rglob("*")
        for path in paths:
            if not path.is_file() or "__pycache__" in path.parts:
                continue
            if path.relative_to(ROOT).as_posix() == MIGRATION_MANIFEST:
                continue
            try:
                content = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            if RETIRED_RUNTIME.search(content):
                findings.append(path.relative_to(ROOT).as_posix())
    if findings:
        raise RuntimeError(
            "retired runtime references remain in the active image: "
            + ", ".join(sorted(findings))
        )
    print("PASS: retired OpenClaw, Hermes and competing runtime scan")


def migration_manifest_gate() -> None:
    path = ROOT / MIGRATION_MANIFEST
    packages = tuple(path.read_text(encoding="utf-8").splitlines())
    if packages != EXPECTED_MIGRATION_PACKAGES:
        raise RuntimeError(
            "2.1.3 migration manifest differs from the reviewed package set"
        )
    if len(packages) != len(set(packages)):
        raise RuntimeError("2.1.3 migration manifest contains duplicates")
    print("PASS: exact 2.1.3 retired-package migration manifest")


def forbidden_build_time_downloader_entries(content: str) -> list[str]:
    entries: set[str] = set()
    for raw_line in content.splitlines():
        line = raw_line.partition("#")[0].strip()
        if not line:
            continue
        package = line.split()[0]
        if package in FORBIDDEN_BUILD_TIME_DOWNLOADERS:
            entries.add(package)
    return sorted(entries)


def build_time_downloader_gate() -> None:
    findings: list[str] = []
    package_lists = ROOT / "live-build" / "config" / "package-lists"
    for path in sorted(package_lists.glob("*.list.chroot")):
        blocked = forbidden_build_time_downloader_entries(
            path.read_text(encoding="utf-8")
        )
        findings.extend(
            f"{path.relative_to(ROOT).as_posix()}:{package}" for package in blocked
        )
    if findings:
        raise RuntimeError(
            "packages with unpinned build-time downloads remain in the image: "
            + ", ".join(findings)
        )
    print("PASS: no package-list entries with unpinned build-time downloads")


def guide_contract_gate() -> None:
    missing = [value for value in GUIDE_FILES if not (ROOT / value).is_file()]
    if missing:
        raise RuntimeError("Shadowfetch Guide source is incomplete: " + ", ".join(missing))
    passport = (ROOT / GUIDE_FILES[0]).read_text(encoding="utf-8")
    guide = (ROOT / GUIDE_FILES[1]).read_text(encoding="utf-8")
    launcher = (ROOT / GUIDE_FILES[2]).read_text(encoding="utf-8")
    for token in (
        '"local_only": True',
        '"upload_performed": False',
        "privacy_issues(document)",
        "shadowfetch-facts",
    ):
        if token not in passport:
            raise RuntimeError(f"System Passport contract is absent: {token}")
    for forbidden in ("import requests", "import urllib", "http.client", "curl", "wget"):
        if forbidden in passport:
            raise RuntimeError(f"System Passport contains a network client: {forbidden}")
    if "shadowfetch-passport" not in guide or "Nothing is uploaded" not in guide:
        raise RuntimeError("Guide UI does not expose the private Passport contract")
    if "Exec=shadowfetch-control --page guide" not in launcher:
        raise RuntimeError("Guide launcher route is incorrect")
    print("PASS: Shadowfetch Guide source and local-only Passport contract")


def platform_contract_gate() -> None:
    missing = [value for value in PHOENIX_RECOVERY_FILES if not (ROOT / value).is_file()]
    if missing:
        raise RuntimeError("Phoenix source-repair source is incomplete: " + ", ".join(missing))

    install_manifest = (
        ROOT / "packages/shadowfetch-phoenix/debian/shadowfetch-phoenix.install"
    ).read_text(encoding="utf-8")
    installed_sources = {
        line.partition("#")[0].split()[0]
        for line in install_manifest.splitlines()
        if line.partition("#")[0].split()
    }
    required_sources = {
        "usr/libexec/phoenix-apt-repair",
        "usr/share/shadowfetch/apt-recovery/*",
    }
    if not required_sources.issubset(installed_sources):
        raise RuntimeError("Phoenix source-repair files are absent from the package manifest")

    recovery_sources = (
        ROOT / "packages/shadowfetch-phoenix/usr/share/shadowfetch/apt-recovery/"
        "debian.sources"
    ).read_text(encoding="utf-8")
    if recovery_sources != EXPECTED_DEBIAN_RECOVERY:
        raise RuntimeError("Phoenix Debian recovery sources differ from installer output")

    sddm = (
        ROOT / "packages/shadowfetch-defaults/data/etc/sddm.conf.d/"
        "10-shadowfetch.conf"
    ).read_text(encoding="utf-8")
    compositor = (
        "CompositorCommand=kwin_wayland --drm --no-lockscreen "
        "--no-global-shortcuts --locale1"
    )
    if "DisplayServer=wayland" not in sddm or compositor not in sddm:
        raise RuntimeError("SDDM Wayland greeter lacks the installed KWin compositor command")
    print("PASS: Phoenix recovery packaging and SDDM greeter contracts")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    gate.add_version_argument(parser)
    parser.add_argument(
        "--no-git",
        action="store_true",
        help=(
            "run without Git: enumerate the working tree directly and still secret-scan "
            "it with 'gitleaks dir'. The Git history is NOT scanned, 'git diff --check' "
            "is skipped, and the run reports SOURCE_GATE_PASSED_WITHOUT_GIT_HISTORY."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    release = gate.load_release(args.version)
    os.environ.setdefault("LC_ALL", "C.UTF-8")
    os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")

    # Resolve every program before doing any work, so a host that cannot supply
    # a trusted gitleaks fails at the top rather than after a long parse pass
    # and then quietly skipping the only secret scan.
    resolver = gate.ProgramResolver()
    resolver.require(REQUIRED_PROGRAMS)
    git = resolver.resolve("git", ROLE_SECURITY)
    gitleaks = resolver.resolve("gitleaks", ROLE_SECURITY)
    shellcheck = resolver.resolve("shellcheck", ROLE_QUALITY)
    desktop_validate = resolver.resolve("desktop-file-validate", ROLE_QUALITY)
    make = resolver.resolve("make", ROLE_QUALITY)
    shells = {
        "bash": resolver.resolve("bash", ROLE_QUALITY),
        "sh": resolver.resolve("sh", ROLE_QUALITY),
    }

    if args.no_git:
        print(
            "WARNING: --no-git requested. The Git history secret scan and the Git "
            "whitespace check will NOT run; this is a degraded gate."
        )
        candidates = filesystem_candidate_files()
    else:
        candidates = candidate_files(git)
    if not candidates:
        raise RuntimeError("candidate source set is empty")
    apple_double = [path for path in candidates if path.name.startswith("._")]
    if apple_double:
        raise RuntimeError(
            "AppleDouble metadata files found: "
            + ", ".join(str(path.relative_to(ROOT)) for path in apple_double)
        )
    print(
        f"Shadowfetch Linux {release.version} source gate: "
        f"{len(candidates)} candidate files (data: {release.path.name})"
    )

    run("behavioral and unit tests", make.argv("test"))
    if args.no_git:
        print("SKIPPED: Git whitespace validation (--no-git)")
    else:
        run("Git whitespace validation", git.argv("diff", "--check"))

    owned_shell, vendored_shell = shell_files(candidates)
    if owned_shell:
        run(
            f"ShellCheck Shadowfetch scripts ({len(owned_shell)} files)",
            shellcheck.argv("--severity=warning", "-x", *map(str, owned_shell)),
        )
    if vendored_shell:
        run(
            f"ShellCheck vendored scripts ({len(vendored_shell)} files)",
            shellcheck.argv("--severity=error", "-x", *map(str, vendored_shell)),
        )
    for path in (*owned_shell, *vendored_shell):
        shell = shells["bash" if "bash" in first_line(path) else "sh"]
        subprocess.run(shell.argv("-n", str(path)), check=True)
    print(f"PASS: shell parser ({len(owned_shell) + len(vendored_shell)} files)")

    parser_gates(candidates, desktop_validate)
    build_time_downloader_gate()
    guide_contract_gate()
    platform_contract_gate()
    secret_gates(candidates, gitleaks, scan_history=not args.no_git)
    migration_manifest_gate()
    retired_runtime_gate()
    if args.no_git:
        print("\nSOURCE_GATE_PASSED_WITHOUT_GIT_HISTORY")
    else:
        print("\nSOURCE_GATE_PASSED")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        OSError,
        RuntimeError,
        subprocess.CalledProcessError,
        SyntaxError,
    ) as exc:
        print(f"SOURCE_GATE_FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1)
