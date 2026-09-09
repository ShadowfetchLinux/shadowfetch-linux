#!/usr/bin/env python3
"""Shared foundation for the Shadowfetch Linux release gates.

STAGE Q -- why this module exists.

The release gates were version-copied families. tools/ held six copies each of
source_gate, package_gate, iso_gate and verify_acceptance and five of
build_release_evidence: 29 modules, 15,265 lines, of which only ~3,000 were the
live 4.0.0 copies. Cutting a release meant copying a module and editing the
version strings inside it, which produced two defects that were both real:

  1. The unit tests were left pointing at the OLD copies. tools/tests held the
     only ISO-gate tests against iso_gate_2_1_5.py, so every line of gate logic
     that actually ran for 4.0.0 -- critical_payload_parity_gate, drkonqi_gate,
     the diverged payload_gate and main -- had no test at all.
  2. Fixes landed in one copy. The Git-unavailable handling, the evidence
     entropy floor and the waiver contract exist only in the 4.0.0 copies; the
     2.1.x copies still carry the bugs they were written with.

There is now ONE implementation per gate family. Everything that changes purely
because the version number changed lives in versions/<version>.toml. Cutting a
release needs that one data file. Anything that changes because the PRODUCT
changed -- a new package, a new payload path -- is an edit to the single live
module, which is a content change and not duplication.

The historical modules were deleted rather than archived. They are recoverable
from Git (tags v2.1.5, v3.0.0, v3.5.0, v4.0.0), which is a stronger
reproducibility record than a copy in the working tree because it also carries
the tree the gate ran against. Running today's implementation against an old
version's data file is NOT the gate that shipped that release, and this module
never claims it is: see ReleaseData.historical.

PERMANENT INVARIANT -- trusted program resolution.

Any executable whose output establishes, verifies, enforces or attests a
security fact must be invoked through an explicit trusted ABSOLUTE path and
must carry a defined trust classification. No PATH lookup, anywhere.

The defect this closes was live in this tree. source_gate_4_0_0.py located
gitleaks with a PATH lookup and then ran it by bare name, and on the build host
PATH resolves gitleaks to /home/<builder>/.local/bin/gitleaks -- a directory the
builder can write. The secret scan is the only control that
decides "no credential shipped in this release"; anything able to drop a file
in that directory could make it pass unconditionally. shellcheck had the same
exposure. Both are now resolved through this module.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path
import stat
import subprocess
import sys
import tomllib
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"
RELEASE_DIR = TOOLS / "release"
VERSIONS_DIR = RELEASE_DIR / "versions"
TRUST_FILE = RELEASE_DIR / "trusted-programs.toml"

def _order_import_path() -> None:
    """Put tools/ ahead of tools/release/ on sys.path, keeping both importable.

    Both directories end up on sys.path: the gates are executed as scripts from
    tools/release/, and they import providers.validate_manifest and
    drkonqi_pickup_contract from tools/. Order is not cosmetic here, because the
    two directories share a name: tools/acceptance/ is a PACKAGE (the VM
    acceptance harness) and tools/release/acceptance.py is a MODULE (the release
    verifier). With tools/release/ first, a plain `import acceptance` anywhere in
    the process silently binds to this gate instead of the harness package, and
    `from acceptance import release_link` then fails with an ImportError that
    names neither directory. Ordering here fixes it for every importer at once,
    rather than depending on which module happened to touch sys.path first.
    """
    here = str(RELEASE_DIR)
    tools = str(TOOLS)
    while here in sys.path:
        sys.path.remove(here)
    if tools not in sys.path:
        sys.path.insert(0, tools)
    sys.path.insert(sys.path.index(tools) + 1, here)


_order_import_path()


# --------------------------------------------------------------------------
# Trusted program resolution
# --------------------------------------------------------------------------

# Directories administered by root: the distribution's own, then the local
# admin's. A program found here is trusted structurally -- the file and every
# parent directory are root-owned and not group- or world-writable (checked, not
# assumed), so nothing the builder runs as itself can substitute the binary.
# Distribution directories come first so a stray local build cannot shadow the
# packaged tool that a release was gated with before.
SYSTEM_PROGRAM_DIRECTORIES = (
    "/usr/bin",
    "/bin",
    "/usr/sbin",
    "/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
)

# What the program's output is allowed to decide. This does NOT relax
# resolution -- every program is resolved the same way -- it records which
# facts rest on which binary so a reader of the trust report can see it.
ROLE_SECURITY = "security"  # decides a security fact (secrets, signatures, digests)
ROLE_QUALITY = "quality"  # decides a correctness or lint fact

TRUST_SYSTEM = "system"  # root-owned path under a root-owned system directory
TRUST_PINNED = "pinned"  # operator-declared absolute path, SHA-256 recorded


class UntrustedProgram(RuntimeError):
    """A required program cannot be resolved to a trusted absolute path."""


def _writable_by_non_root(path: Path) -> bool:
    info = path.stat()
    if info.st_uid != 0:
        return True
    return bool(info.st_mode & (stat.S_IWGRP | stat.S_IWOTH))


def _root_owned_chain(path: Path) -> str:
    """Return "" when path and every parent are root-owned and not group/other writable."""
    current = path
    while True:
        try:
            if _writable_by_non_root(current):
                return f"{current} is writable by a non-root account"
        except OSError as exc:
            return f"{current} cannot be inspected: {exc}"
        if current.parent == current:
            return ""
        current = current.parent


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True)
class TrustedProgram:
    """An executable resolved to an absolute path with a recorded trust basis."""

    name: str
    path: Path
    trust: str
    role: str
    digest: str | None = None

    def argv(self, *arguments: str) -> list[str]:
        """Absolute argv for this program, re-verifying a digest pin first.

        A pinned program sits outside the root-owned system directories, so its
        bytes are re-hashed immediately before every invocation rather than once
        at startup. This is not a perfect seal: a replacement written between
        this check and execve would not be caught. The remedy for anything in
        ROLE_SECURITY is to install it into a root-owned directory so it
        resolves as TRUST_SYSTEM; the pin exists so a host that has not done
        that yet still refuses a *substituted* binary instead of trusting PATH.
        """
        if self.trust == TRUST_PINNED:
            actual = _sha256_file(self.path)
            if actual != self.digest:
                raise UntrustedProgram(
                    f"{self.name}: pinned binary at {self.path} has changed; "
                    f"recorded sha256 {self.digest}, found {actual}"
                )
        return [str(self.path), *arguments]

    def describe(self) -> str:
        pin = f" sha256={self.digest[:16]}..." if self.digest else ""
        return f"{self.name} [{self.role}/{self.trust}] {self.path}{pin}"


def _load_pins(trust_file: Path) -> dict[str, dict[str, str]]:
    if not trust_file.is_file():
        return {}
    with trust_file.open("rb") as handle:
        document = tomllib.load(handle)
    pins = document.get("program", {})
    if not isinstance(pins, dict):
        raise UntrustedProgram(f"{trust_file}: [program] must be a table")
    return pins


class ProgramResolver:
    """Resolves gate programs to trusted absolute paths, and reports how."""

    def __init__(self, trust_file: Path | None = None) -> None:
        # The environment does NOT get to redirect the pin policy. An override
        # read from SHADOWFETCH_TRUSTED_PROGRAMS meant an env var could point
        # every ROLE_SECURITY pin at an attacker's file -- the same shape as the
        # PATH defect these pins exist to close. A test passes trust_file
        # explicitly, which is a caller decision rather than ambient state.
        self.trust_file = trust_file or TRUST_FILE
        self._pins = _load_pins(self.trust_file)
        self._resolved: dict[str, TrustedProgram] = {}

    def resolve(self, name: str, role: str) -> TrustedProgram:
        if name in self._resolved:
            return self._resolved[name]
        program = self._resolve_uncached(name, role)
        self._resolved[name] = program
        return program

    def _resolve_uncached(self, name: str, role: str) -> TrustedProgram:
        if "/" in name:
            raise UntrustedProgram(f"program name must not contain a path: {name!r}")
        reasons: list[str] = []
        for directory in SYSTEM_PROGRAM_DIRECTORIES:
            candidate = Path(directory) / name
            if not candidate.is_file() or not os.access(candidate, os.X_OK):
                continue
            # Resolve symlinks: /usr/bin/foo -> /etc/alternatives/foo -> target.
            # Every hop must be root-administered or the link is a substitution
            # point even though the first path component looked safe.
            real = candidate.resolve()
            problem = _root_owned_chain(real) or _root_owned_chain(candidate.parent)
            if problem:
                reasons.append(f"{candidate}: {problem}")
                continue
            return TrustedProgram(name=name, path=candidate, trust=TRUST_SYSTEM, role=role)

        pin = self._pins.get(name)
        if isinstance(pin, dict):
            program = self._pinned(name, role, pin)
            if program is not None:
                return program
            reasons.append(f"{self.trust_file}: pin for {name} is unusable")

        searched = ", ".join(SYSTEM_PROGRAM_DIRECTORIES)
        detail = ("; " + "; ".join(reasons)) if reasons else ""
        raise UntrustedProgram(
            f"{name} is not available at a trusted absolute path. Searched {searched}"
            f"{detail}. Install it into a root-owned system directory, or record an "
            f"absolute path and its sha256 under [program.{name}] in {self.trust_file}. "
            "PATH is deliberately not consulted: this program's output decides a "
            f"{role} fact."
        )

    def _pinned(self, name: str, role: str, pin: dict[str, str]) -> TrustedProgram | None:
        path_value = pin.get("path")
        digest = pin.get("sha256")
        if not isinstance(path_value, str) or not path_value.startswith("/"):
            raise UntrustedProgram(
                f"[program.{name}].path must be an absolute path in {self.trust_file}"
            )
        if not isinstance(digest, str) or len(digest) != 64:
            raise UntrustedProgram(
                f"[program.{name}].sha256 must be 64 hex characters in {self.trust_file}"
            )
        path = Path(path_value)
        if not path.is_file() or not os.access(path, os.X_OK):
            return None
        actual = _sha256_file(path)
        if actual != digest.lower():
            raise UntrustedProgram(
                f"{name}: pinned binary at {path} does not match the recorded "
                f"sha256; recorded {digest.lower()}, found {actual}. Either the tool "
                "was upgraded (record the new digest) or it was substituted."
            )
        return TrustedProgram(
            name=name, path=path, trust=TRUST_PINNED, role=role, digest=actual
        )

    def require(self, requirements: Iterable[tuple[str, str]]) -> list[TrustedProgram]:
        """Resolve every program up front so a gate fails before doing any work."""
        programs = [self.resolve(name, role) for name, role in requirements]
        print("\n>>> trusted program resolution")
        for program in programs:
            print(f"  {program.describe()}")
        security = sum(1 for p in programs if p.role == ROLE_SECURITY)
        pinned = sum(1 for p in programs if p.trust == TRUST_PINNED)
        print(
            f"PASS: {len(programs)} programs resolved to trusted absolute paths "
            f"({security} security-deciding, {pinned} digest-pinned)"
        )
        return programs


# --------------------------------------------------------------------------
# Version data
# --------------------------------------------------------------------------


class MissingReleaseData(RuntimeError):
    """No version data file for the requested release."""


@dataclass(frozen=True)
class ReleaseData:
    """The version-varying inputs to the gates, loaded from versions/<v>.toml."""

    version: str
    path: Path
    document: dict[str, Any] = field(repr=False)

    # -- release identity ---------------------------------------------------
    @property
    def release(self) -> dict[str, Any]:
        return self.document["release"]

    @property
    def edition(self) -> str:
        return self.release["edition"]

    @property
    def codename(self) -> str:
        """APT suite name, lower case (for example "umbra")."""
        return self.release["codename"]

    @property
    def display_codename(self) -> str:
        """Codename as it is written in os-release and the acceptance manifest."""
        return self.release["display_codename"]

    @property
    def revision(self) -> str:
        return self.release["package_revision"]

    @property
    def iso_name(self) -> str:
        return f"shadowfetch-{self.version}-amd64.iso"

    @property
    def signing_fingerprint(self) -> str:
        return self.release["signing_fingerprint"]

    @property
    def historical(self) -> bool:
        """True when this data describes a release older than the live one.

        Read this before making a reproducibility claim. Re-running the live
        gate against historical data re-gates that release with TODAY's logic;
        it does not reproduce the gate that shipped it. For that, check out the
        tag and run the gate module that was in the tree.
        """
        return bool(self.release.get("historical", False))

    # -- packages -----------------------------------------------------------
    @property
    def binary_versions(self) -> dict[str, str]:
        """Every binary package the release publishes, with its exact version.

        Shadowfetch packages are stamped <version>-<revision> and are listed by
        name only; third-party packages carry their own pinned version.
        """
        packages = self.document["packages"]
        versions = {
            name: f"{self.version}-{self.revision}"
            for name in packages["shadowfetch_binaries"]
        }
        for name, pinned in packages.get("third_party", {}).items():
            versions[name] = pinned
        return dict(sorted(versions.items()))

    @property
    def source_packages(self) -> set[str]:
        return set(self.document["packages"]["sources"])

    @property
    def smoke_install(self) -> tuple[str, ...]:
        return tuple(self.document["packages"]["smoke_install"])

    # -- generic section access --------------------------------------------
    def section(self, name: str) -> dict[str, Any]:
        value = self.document.get(name)
        if not isinstance(value, dict):
            raise MissingReleaseData(
                f"{self.path}: section [{name}] is missing or is not a table"
            )
        return value

    def stamped_tokens(self, name: str) -> tuple[str, ...]:
        """Tokens that carry the version and must appear in a shipped payload.

        Stored with {version} placeholders so a release bump does not require
        editing each literal, which is how a stale "3.5.0" stamp survived into a
        copied gate before.
        """
        raw = self.section("stamps").get(name, [])
        return tuple(item.format(version=self.version, edition=self.edition) for item in raw)

    def acceptance_manifest(self) -> Path:
        return ROOT / "qa" / self.version / "acceptance.json"


def available_versions(directory: Path | None = None) -> list[str]:
    directory = directory or VERSIONS_DIR
    return sorted(path.stem for path in directory.glob("*.toml"))


def load_release(version: str | None = None, *, directory: Path | None = None) -> ReleaseData:
    """Load version data. Precedence: argument, SHADOWFETCH_RELEASE_VERSION, sole file."""
    directory = directory or VERSIONS_DIR
    if version is None:
        version = os.environ.get("SHADOWFETCH_RELEASE_VERSION") or None
    if version is None:
        candidates = available_versions(directory)
        live = [v for v in candidates if not _is_historical(directory / f"{v}.toml")]
        if len(live) != 1:
            raise MissingReleaseData(
                "no release version selected: pass --version, set "
                "SHADOWFETCH_RELEASE_VERSION, or leave exactly one non-historical "
                f"data file in {directory} (found {live or candidates})"
            )
        version = live[0]
    path = directory / f"{version}.toml"
    if not path.is_file():
        raise MissingReleaseData(
            f"no release data for {version}: expected {path}. "
            f"Available: {', '.join(available_versions(directory)) or 'none'}"
        )
    with path.open("rb") as handle:
        document = tomllib.load(handle)
    declared = document.get("release", {}).get("version")
    if declared != version:
        raise MissingReleaseData(
            f"{path}: release.version is {declared!r} but the file is named {version!r}"
        )
    return ReleaseData(version=version, path=path, document=document)


def _is_historical(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return bool(tomllib.load(handle).get("release", {}).get("historical", False))
    except (OSError, tomllib.TOMLDecodeError):
        return False


def add_version_argument(parser) -> None:
    parser.add_argument(
        "--version",
        default=None,
        help=(
            "release to gate; selects tools/release/versions/<version>.toml. "
            "Defaults to SHADOWFETCH_RELEASE_VERSION, then to the sole "
            "non-historical data file."
        ),
    )


# --------------------------------------------------------------------------
# Shared helpers (identical in every copied gate before Stage Q)
# --------------------------------------------------------------------------


# The PATH every gate subprocess inherits. Resolving a program to a trusted
# absolute path is not enough on its own: the program then resolves ITS OWN
# helpers through whatever PATH it inherits. /usr/bin/dpkg-deb, correctly
# resolved and relied on to report what a package contains, executed a forged
# `tar` from the builder-writable ~/.local/bin and reported
# "Package: totally-not-this-package / Version: 9.9.9-forged", exit 0.
SUBPROCESS_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"


def trusted_env(extra: dict | None = None) -> dict:
    """The environment a gate subprocess runs with: the caller's, with PATH
    replaced by trusted directories only."""
    env = dict(os.environ)
    env["PATH"] = SUBPROCESS_PATH
    if extra:
        env.update(extra)
    return env


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
        env=trusted_env(),
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
        env=trusted_env(),
        text=True,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout.strip()


def sha256(path: Path) -> str:
    return _sha256_file(path)


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
