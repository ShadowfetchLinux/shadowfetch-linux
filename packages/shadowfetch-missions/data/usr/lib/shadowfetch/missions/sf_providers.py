"""Shared agent abstractions: capability, provider, sandbox, invocation, events.

The one idea in this module is that a CAPABILITY is what a person wants done and
a PROVIDER is who does it. Before this existed the two were the same thing: a
mission's "kind" chose the runtime, named the method that implemented it, and
fixed the network posture, so "run this code change with a different agent" was
not expressible at all.

Nothing here knows about Codex, ffmpeg, or any other particular agent. Providers
are DATA -- a manifest under /usr/share/shadowfetch/providers -- plus an adapter
module named by that manifest. The registry never scans arbitrary Python; a
module becomes a provider only because a validated manifest named it.

Three security properties are structural rather than conventional, because
Phase 1 found real defects of each kind:

  * The registry, not the adapter, builds the SandboxSpec from the manifest.
    An adapter may NARROW what it was granted and can never widen it, so a
    provider cannot request network or credentials it did not declare.

  * An Invocation carries credential IDENTITIES, never credential VALUES. The
    value is injected at the Firebreak boundary by code that never came from a
    provider.

  * An Invocation's executable is CLASSIFIED by who can modify it, and the
    class must be one its manifest declared. An adapter may look its program
    up however it likes; classify_executable() re-checks the answer against
    the ownership and mode of the file and of every directory above it, so a
    program anyone else could substitute cannot be executed.
"""
from __future__ import annotations

import dataclasses
import hashlib
import importlib
import importlib.util
import json
import os
import re
import stat
import sys
from pathlib import Path

try:
    import sf_jsonschema
except ImportError:  # source tree
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import sf_jsonschema

__all__ = [
    "Capability", "CAPABILITIES", "LEGACY_KIND_CAPABILITY", "CAPABILITY_LEGACY_KIND",
    "INTERFACE_VERSION", "ProviderError", "ManifestError",
    "SandboxSpec", "Invocation", "AgentEvent", "Readiness", "Acceptance",
    "AgentProvider", "ProviderRegistry", "load_manifest", "manifest_schema",
    "trusted_executable", "TRUSTED_EXEC_PREFIXES", "verify_invocation",
    "sandbox_enforcement", "unenforced_fields", "SANDBOX_ENFORCEMENT",
    "ENFORCED", "PARTIAL", "NOT_ENFORCED", "NOT_REPRESENTABLE",
    "ApprovedPolicy", "PolicyError", "load_policy", "manifest_digest",
    "resolve_executable",
]

INTERFACE_VERSION = 1
"""The AgentProvider ABI this runtime implements. A manifest declaring a
different interface_version is reported unavailable with a reason rather than
imported and failed later."""

MANIFEST_DIR = Path("/usr/share/shadowfetch/providers")

# The approved-provider policy deliberately does NOT live in the discovery
# directory. A third-party package may add a file to providers/ without a
# dpkg conflict; it cannot overwrite a file another package owns. Keeping the
# policy in its own directory, shipped by shadowfetch-missions, is what makes
# the pin meaningful against a package rather than merely against a typo.
POLICY_DIR = Path("/usr/share/shadowfetch/provider-policy")
POLICY_NAME = "approved.json"

# Directories the packaging system owns. Membership here is ONE condition of
# being distro-managed, not the whole test: the prefix says where a file is,
# and says nothing about who may replace it.
PACKAGED_EXEC_PREFIXES = ("/usr/bin/", "/usr/sbin/", "/usr/libexec/",
                          "/usr/lib/", "/usr/local/lib/shadowfetch/",
                          "/bin/", "/sbin/", "/opt/")


class ExecutableTrust:
    """What a program's location actually proves about who can change it.

    These are OBSERVATIONS, derived from the filesystem. A manifest's
    executable.trust field is a REQUIREMENT, spelled differently on purpose --
    "system"/"user-runtime" is what a provider asks to be allowed; these four
    are what its program turned out to be. Conflating the two is how a
    declaration comes to look like a control.
    """

    DISTRO_MANAGED = "distro-managed"   # packaged path, root-owned all the way up
    USER_MANAGED = "user-managed"       # the invoking user's own space, nobody else writable
    DEVELOPER = "developer"             # integrity fine, provenance unmanaged
    UNTRUSTED = "untrusted"             # somebody else can substitute it


# What each manifest declaration will accept. Deliberately a set per
# declaration rather than a rank: "root-owned in an unmanaged directory" and
# "user-owned under $HOME" are not comparable, and forcing them onto one axis
# would make one of the two orderings wrong.
ACCEPTED_EXECUTABLE_TRUST = {
    "system": (ExecutableTrust.DISTRO_MANAGED,),
    "user-runtime": (ExecutableTrust.DISTRO_MANAGED, ExecutableTrust.USER_MANAGED),
    "developer": (ExecutableTrust.DISTRO_MANAGED, ExecutableTrust.USER_MANAGED,
                  ExecutableTrust.DEVELOPER),
}

# How much latitude each declaration asks for, so a policy can approve less.
EXECUTABLE_TRUST_LATITUDE = {"system": 0, "user-runtime": 1, "developer": 2}

# Retained: Phase 2 code and tests refer to this name.
TRUSTED_EXEC_PREFIXES = PACKAGED_EXEC_PREFIXES


def _private_group(gid: int, uid: int) -> bool:
    """True if gid is a per-user group whose only member is that user.

    Debian gives each user a group of the same name, so npm and nvm install
    0775 under $HOME group-writable by a group of one. That is materially
    different from 0775 under a shared group like staff or adm, and the
    difference decides whether "group-writable" means someone else can swap the
    binary. Phase 2 accepted all group-writability for user runtimes and
    recorded the gap in PHASE2_REMAINING_RISKS; this measures it instead.
    """
    try:
        import grp
        import pwd
        user = pwd.getpwuid(uid)
        group = grp.getgrgid(gid)
    except (ImportError, KeyError, OSError):
        return False
    if set(group.gr_mem) - {user.pw_name}:
        return False
    return group.gr_gid == user.pw_gid or group.gr_name == user.pw_name


def _substitutable_by_others(info, uid: int):
    """Why a third party could replace this inode, or None if none could."""
    mode = info.st_mode
    if info.st_uid not in (0, uid):
        return f"owned by uid {info.st_uid}"
    if stat.S_ISDIR(mode) and mode & stat.S_ISVTX:
        # Sticky: only an entry's own owner may replace it, so a world-writable
        # /tmp does not let anyone substitute another user's file.
        return None
    if mode & 0o002:
        return "world-writable"
    if mode & 0o020 and not _private_group(info.st_gid, uid):
        return f"writable by shared group gid {info.st_gid}"
    return None


def classify_executable(path, *, uid: int | None = None):
    """Return (ExecutableTrust value, human reason) for a program.

    The walk covers every directory above the file as well as the file itself,
    because replacing a directory entry is as good as replacing its target --
    a check that stops at the file's own mode misses the more likely attack.
    """
    uid = os.getuid() if uid is None else uid
    resolved = Path(path).resolve()
    if not resolved.is_absolute():
        return ExecutableTrust.UNTRUSTED, f"{resolved} is not an absolute path"
    try:
        info = resolved.stat()
    except OSError as exc:
        return ExecutableTrust.UNTRUSTED, f"{resolved} cannot be inspected: {exc}"
    if not stat.S_ISREG(info.st_mode):
        return ExecutableTrust.UNTRUSTED, f"{resolved} is not a regular file"
    if not os.access(str(resolved), os.X_OK):
        return ExecutableTrust.UNTRUSTED, f"{resolved} is not executable"

    root_owned_throughout = True
    for component in (resolved, *resolved.parents):
        try:
            cinfo = component.stat()
        except OSError as exc:
            return ExecutableTrust.UNTRUSTED, f"{component} cannot be inspected: {exc}"
        problem = _substitutable_by_others(cinfo, uid)
        if problem is not None:
            return (ExecutableTrust.UNTRUSTED,
                    f"{component} is {problem}, so the program can be substituted "
                    "by someone other than root or the invoking user")
        if cinfo.st_uid != 0:
            root_owned_throughout = False

    if str(resolved).startswith(tuple(PACKAGED_EXEC_PREFIXES)):
        if root_owned_throughout:
            return (ExecutableTrust.DISTRO_MANAGED,
                    f"{resolved} is root-owned throughout a packaging-owned directory")
        return (ExecutableTrust.USER_MANAGED,
                f"{resolved} is in a packaging-owned directory but part of its path "
                f"is owned by uid {uid} rather than root")
    if root_owned_throughout:
        return (ExecutableTrust.DEVELOPER,
                f"{resolved} is root-owned and nobody else can write it, but it is "
                "outside the packaging-owned directories, so nothing vouches for "
                "where it came from")
    return (ExecutableTrust.USER_MANAGED,
            f"{resolved} is writable only by root and uid {uid}")


def trusted_executable(path, *, trust="system"):
    """Return the resolved absolute path, or raise if the program is not of a
    class its manifest declared.

    An adapter is packaged code, but its OUTPUT is not trusted: whatever it says
    its program is, that answer is classified here and matched against the
    manifest's declaration.

    trust="system"        accepts only distro-managed programs. The default,
                          and what a provider should use.
    trust="user-runtime"  additionally accepts a program in the invoking user's
                          own space -- an npm or pip CLI -- provided no third
                          party can substitute it. The Codex CLI is genuinely
                          installed that way; declaring it makes the exception
                          visible in the manifest, at the release gate and in
                          the approved-provider policy rather than universal.
    trust="developer"     additionally accepts an unmanaged root-owned location.
                          Only usable by a provider a policy approved for it.

    UNTRUSTED is never accepted by any declaration, because it means a third
    party can replace the program, which no manifest may consent to on the
    user's behalf.
    """
    if not path:
        raise ProviderError("Provider executable was not found")
    accepted = ACCEPTED_EXECUTABLE_TRUST.get(trust)
    if accepted is None:
        raise ProviderError(
            f"Provider declares unknown executable trust {trust!r}; refusing to "
            f"execute. Known: {', '.join(sorted(ACCEPTED_EXECUTABLE_TRUST))}")
    tier, reason = classify_executable(path)
    if tier not in accepted:
        raise ProviderError(
            f"Provider executable classifies as {tier}: {reason}. Its manifest "
            f"declares executable trust {trust!r}, which accepts "
            f"{', '.join(accepted)}. Refusing to execute it.")
    return str(Path(path).resolve())
SCHEMA_NAME = "provider-manifest.schema.json"


class Capability:
    """What the user wants. Deliberately not an Enum: these values are persisted
    in SQLite and appear in receipts, so they are plain strings with a stable
    spelling, and adding one must not require a migration."""

    CODE_CHANGE = "code_change"
    SOURCED_REPORT = "sourced_report"
    MEDIA_EXPORT = "media_export"


CAPABILITIES = (Capability.CODE_CHANGE, Capability.SOURCED_REPORT, Capability.MEDIA_EXPORT)

LEGACY_KIND_CAPABILITY = {
    "code": Capability.CODE_CHANGE,
    "report": Capability.SOURCED_REPORT,
    "media": Capability.MEDIA_EXPORT,
}
CAPABILITY_LEGACY_KIND = {v: k for k, v in LEGACY_KIND_CAPABILITY.items()}


class ProviderError(Exception):
    """A provider could not be used. The message is shown to a person."""


class ManifestError(ProviderError):
    """A provider manifest is malformed or dishonest."""


class PolicyError(ProviderError):
    """A provider is not approved, or asks for more than it was approved for."""


# --------------------------------------------------------------------------- #
# Value types
# --------------------------------------------------------------------------- #

@dataclasses.dataclass(frozen=True)
class SandboxSpec:
    """Everything the sandbox needs to know, and nothing a provider chose freely.

    Built by the registry from the manifest. `narrow()` is the only way an
    adapter may change it, and it can only ever remove permission.
    """

    workspace_mode: str
    network: str
    egress_allowlist: tuple = ()
    read_grants: tuple = ()
    masked_paths: tuple = ()
    credential_ids: tuple = ()
    account_mount: str = ""
    memory_mb: int = 3072
    cpu_seconds: int = 900
    processes: int = 96

    def __post_init__(self):
        if self.workspace_mode not in ("read-only", "workspace-write"):
            raise ProviderError(f"Unknown workspace mode: {self.workspace_mode}")
        if self.network not in ("none", "allowlist"):
            raise ProviderError(f"Unknown network policy: {self.network}")
        if self.network == "none" and self.egress_allowlist:
            raise ProviderError("A sandbox with no network cannot carry an egress allowlist")
        for grant in self.read_grants:
            if not str(grant).startswith("/"):
                raise ProviderError(f"Read grants must be absolute paths: {grant}")

    @property
    def firebreak_network(self) -> str:
        """Firebreak speaks none/allow; allowlist is the strongest posture the
        current sandbox can express. The declared hosts are still recorded on
        the receipt so a reviewer can see what was permitted, and they are what
        a future egress filter will enforce."""
        return "none" if self.network == "none" else "allow"

    def narrow(self, **changes) -> "SandboxSpec":
        """Return a spec no broader than this one. Widening raises."""
        candidate = dataclasses.replace(self, **changes)
        if candidate.network != self.network and self.network == "none":
            raise ProviderError("An adapter may not add network access it did not declare")
        if not set(candidate.credential_ids) <= set(self.credential_ids):
            raise ProviderError("An adapter may not request undeclared credentials")
        if candidate.account_mount and candidate.account_mount != self.account_mount:
            raise ProviderError("An adapter may not mount a credential store it did not declare")
        if not set(candidate.egress_allowlist) <= set(self.egress_allowlist):
            raise ProviderError("An adapter may not add egress hosts it did not declare")
        if not set(candidate.read_grants) <= set(self.read_grants):
            raise ProviderError("An adapter may not add read grants it did not declare")
        # Masks are the one field whose safe direction is inverted: adding a
        # mask narrows, removing one widens.
        if not set(self.masked_paths) <= set(candidate.masked_paths):
            raise ProviderError("An adapter may not drop a masked path it was given")
        for field in ("memory_mb", "cpu_seconds", "processes"):
            if getattr(candidate, field) > getattr(self, field):
                raise ProviderError(f"An adapter may not raise its declared {field}")
        if self.workspace_mode == "read-only" and candidate.workspace_mode != "read-only":
            raise ProviderError("An adapter may not upgrade a read-only workspace to writable")
        return candidate


@dataclasses.dataclass(frozen=True)
class Invocation:
    """One process the orchestrator will run on a provider's behalf.

    The generic executor consumes this and needs to know nothing about which
    provider produced it. That is the whole point: there is no branch on
    provider identity anywhere downstream of here.
    """

    executable: str
    argv: tuple = ()
    stdin_path: str | None = None
    env_allowlist: tuple = ()
    sandbox: SandboxSpec | None = None
    label: str = "provider"
    manifest_executable: dict | None = None
    """The manifest executable block, carried so the orchestrator can honour
    declared runtime_root_markers and trust tier without knowing the provider."""

    def __post_init__(self):
        if not self.executable or not str(self.executable).startswith("/"):
            raise ProviderError(
                f"Provider executable must be an absolute path, got {self.executable!r}. "
                "Provider programs are never resolved through PATH.")
        for name in self.env_allowlist:
            if not re.fullmatch(r"[A-Z][A-Z0-9_]*", str(name)):
                raise ProviderError(f"Environment allowlist entries are names, not values: {name!r}")
        if self.stdin_path is not None and not str(self.stdin_path).startswith("/"):
            raise ProviderError("stdin_path must be absolute")

    @property
    def command(self) -> list:
        return [self.executable, *self.argv]


@dataclasses.dataclass(frozen=True)
class AgentEvent:
    """One normalized thing that happened during a provider turn.

    Providers emit wildly different native streams -- Codex emits JSONL turn
    events, ffmpeg emits progress lines. Mission Control consumes only this.
    """

    type: str
    text: str = ""
    data: dict = dataclasses.field(default_factory=dict)

    MESSAGE = "message"
    PROGRESS = "progress"
    USAGE = "usage"
    LOG = "log"
    ERROR = "error"
    TURN_COMPLETE = "turn-complete"

    def __post_init__(self):
        allowed = {self.MESSAGE, self.PROGRESS, self.USAGE, self.LOG,
                   self.ERROR, self.TURN_COMPLETE}
        if self.type not in allowed:
            raise ProviderError(f"Unknown agent event type: {self.type!r}")


@dataclasses.dataclass(frozen=True)
class Readiness:
    """Whether a provider can actually be used right now, and if not, why."""

    installed: bool
    authenticated: bool
    missing: tuple = ()
    facts: dict = dataclasses.field(default_factory=dict)
    reason: str = ""

    @property
    def available(self) -> bool:
        return self.installed and self.authenticated

    def as_dict(self) -> dict:
        return {
            "installed": self.installed,
            "authenticated": self.authenticated,
            "available": self.available,
            "missing": list(self.missing),
            "facts": dict(self.facts),
            "reason": self.reason,
        }


@dataclasses.dataclass(frozen=True)
class Acceptance:
    """A provider's answer to "can you do this particular job?"."""

    ok: bool
    reason: str = ""

    @classmethod
    def yes(cls) -> "Acceptance":
        return cls(True, "")

    @classmethod
    def no(cls, reason: str) -> "Acceptance":
        return cls(False, reason)


# --------------------------------------------------------------------------- #
# The provider interface
# --------------------------------------------------------------------------- #

class AgentProvider:
    """Base class every adapter implements.

    An adapter is handed its validated manifest and the SandboxSpec the registry
    derived from it. It may narrow that spec; it cannot widen it, and it never
    sees a credential value.
    """

    def __init__(self, manifest: dict, sandbox: SandboxSpec):
        self.manifest = manifest
        self._sandbox = sandbox

    # -- identity ----------------------------------------------------------
    @property
    def id(self) -> str:
        return self.manifest["id"]

    @property
    def display_name(self) -> str:
        return self.manifest["display_name"]

    @property
    def version(self) -> str:
        return self.manifest["version"]

    @property
    def interface_version(self) -> int:
        return self.manifest["interface_version"]

    # -- capability discovery ---------------------------------------------
    def capabilities(self) -> tuple:
        return tuple(self.manifest["capabilities"])

    def supports(self, capability: str) -> bool:
        return capability in self.capabilities()

    # -- readiness ---------------------------------------------------------
    def readiness(self) -> Readiness:
        raise NotImplementedError

    # -- task acceptance ---------------------------------------------------
    def accepts(self, capability: str, config: dict) -> Acceptance:
        """Default: accept any declared capability. Adapters refine, and must
        give a person a reason when they refuse."""
        if not self.supports(capability):
            return Acceptance.no(
                f"{self.display_name} does not perform {capability.replace('_', ' ')}")
        return Acceptance.yes()

    # -- sandbox -----------------------------------------------------------
    def sandbox_for(self, capability: str, config: dict) -> SandboxSpec:
        """The registry-built spec, optionally narrowed. Never widened."""
        return self._sandbox

    # -- invocation --------------------------------------------------------
    def build_invocation(self, capability: str, request: dict) -> Invocation:
        raise NotImplementedError

    # -- streaming ---------------------------------------------------------
    def parse_stream(self, text: str):
        """Normalize this provider's native output into AgentEvents.

        Must tolerate malformed, partial and interleaved output: the stream is
        untrusted, and a provider that emits garbage must not be able to corrupt
        Mission Control state.
        """
        raise NotImplementedError

    def turn_succeeded(self, events) -> bool:
        """Did the provider finish a complete turn? Default: it emitted a
        completion and no error. Adapters override only if their native
        protocol says something more specific."""
        completed = any(e.type == AgentEvent.TURN_COMPLETE for e in events)
        failed = any(e.type == AgentEvent.ERROR for e in events)
        return completed and not failed

    def usage(self, events):
        for event in reversed(list(events)):
            if event.type == AgentEvent.TURN_COMPLETE:
                return event.data.get("usage")
        return None

    def final_message(self, events) -> str:
        """The answer a person reads, extracted from normalized events."""
        messages = [e.text for e in events if e.type == AgentEvent.MESSAGE and e.text]
        return messages[-1] if messages else ""


# --------------------------------------------------------------------------- #
# Manifest loading
# --------------------------------------------------------------------------- #

def declared_executables(manifest) -> set:
    """Every path a manifest's executable declaration currently resolves to.

    resolve_executable() answers "which one shall we run"; this answers "which
    ones was this provider ever allowed to run", which is the question
    verify_invocation() has to ask. Same expansion rules, no trust filtering --
    the tier is checked separately, and mixing the two would make a refusal say
    the wrong thing.
    """
    block = (manifest or {}).get("executable") or {}
    kind = block.get("kind")
    # A helper is declared, so it is allowed, and it is subject to the same
    # trust classification as the main program -- verify_invocation() checks
    # the tier separately and does not care which of the two it is looking at.
    helpers = {str(Path(p).resolve()) for p in (block.get("helper_programs") or ())}
    if kind == "absolute":
        return {str(Path(block["path"]).resolve())} | helpers
    if kind != "candidates":
        return helpers
    home = Path.home()
    found = set()
    for pattern in block.get("candidates") or ():
        pattern = str(pattern)
        if pattern.startswith("~/"):
            base, relative = home, pattern[2:]
        elif pattern.startswith("/"):
            base, relative = Path("/"), pattern[1:]
        else:
            continue                       # never a relative lookup
        try:
            matches = sorted(base.glob(relative))
        except (OSError, ValueError):
            continue
        for match in matches:
            found.add(str(match.resolve()))
    return found | helpers


def resolve_executable(manifest):
    """Locate a provider program from its DECLARED candidates. No PATH.

    Candidates are absolute paths or globs, optionally starting with ~ for the
    invoking user's home, tried in the order the manifest lists them. The
    first existing executable file that passes the declared trust tier wins.
    Returns None when the program is simply not installed, which is a
    readiness answer rather than an error.
    """
    block = (manifest or {}).get("executable") or {}
    kind = block.get("kind")
    trust = block.get("trust", "system")
    if kind == "absolute":
        path = Path(block["path"])
        if not (path.is_file() and os.access(path, os.X_OK)):
            return None
        try:
            return trusted_executable(path, trust=trust)
        except ProviderError:
            return None
    if kind != "candidates":
        return None
    home = Path.home()
    for pattern in block.get("candidates") or ():
        pattern = str(pattern)
        if pattern.startswith("~/"):
            base, relative = home, pattern[2:]
        elif pattern.startswith("/"):
            base, relative = Path("/"), pattern[1:]
        else:
            continue                       # never a relative lookup
        try:
            matches = sorted(base.glob(relative), reverse=True)
        except (OSError, ValueError):
            continue
        for match in matches:
            if not (match.is_file() and os.access(match, os.X_OK)):
                continue
            try:
                return trusted_executable(match, trust=trust)
            except ProviderError:
                continue
    return None


def _schema_path(root: Path) -> Path:
    return Path(root) / SCHEMA_NAME


def manifest_schema(root: Path | None = None) -> dict:
    root = Path(root) if root else _default_root()
    path = _schema_path(root)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ManifestError(f"Provider manifest schema is unavailable: {path}: {exc}") from exc
    except ValueError as exc:
        raise ManifestError(f"Provider manifest schema is not valid JSON: {path}: {exc}") from exc


def _default_root() -> Path:
    """The production provider discovery root. Not environment-selectable.

    SHADOWFETCH_PROVIDER_MANIFESTS used to point this anywhere the invoking
    user owned. Even clamped for ownership and mode, that is an environment
    variable deciding which credentials and network posture a provider may
    request -- the Phase-1 defect class one layer up from PATH. It is gone.

    Tests and fixtures inject a root through the ProviderRegistry constructor
    instead, which is explicit, local to the caller, and cannot be set by
    something else in the session. See docs/PROVIDER_TRUST.md.
    """
    if os.environ.get("SHADOWFETCH_PROVIDER_MANIFESTS"):
        sys.stderr.write(
            "ignoring SHADOWFETCH_PROVIDER_MANIFESTS: the provider discovery root "
            "is not environment-selectable in production; pass root= to "
            "ProviderRegistry for tests\n")
    if MANIFEST_DIR.is_dir():
        return MANIFEST_DIR
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "data/usr/share/shadowfetch/providers"
        if candidate.is_dir():
            return candidate
    return MANIFEST_DIR


def load_manifest(path, *, schema: dict | None = None) -> dict:
    """Read and fully validate one manifest. Raises ManifestError."""
    path = Path(path)
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ManifestError(f"{path.name}: cannot be read: {exc}") from exc
    except ValueError as exc:
        raise ManifestError(f"{path.name}: is not valid JSON: {exc}") from exc
    if schema is None:
        schema = manifest_schema(path.parent)
    try:
        sf_jsonschema.validate(document, schema)
    except sf_jsonschema.ValidationError as exc:
        raise ManifestError(f"{path.name}: {exc}") from exc
    except sf_jsonschema.SchemaError as exc:
        raise ManifestError(f"{path.name}: manifest schema is unusable: {exc}") from exc
    if path.stem != document["id"]:
        raise ManifestError(
            f"{path.name}: manifest filename must match its id {document['id']!r}, "
            "so a provider cannot be shadowed by a second file claiming the same id")
    return document


def manifest_digest(path) -> str:
    """SHA-256 of a manifest file, exactly as it ships."""
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


NETWORK_RANK = {"none": 0, "allowlist": 1}


class ApprovedPolicy:
    """Which providers Shadowfetch permits, and the ceiling for each.

    This is reviewed DATA, not source. Adding a provider means adding an entry
    here and shipping its manifest; it does not mean editing Python. That is
    the property Phase 2 bought and this class must not take back.
    """

    def __init__(self, document: dict, source: str = "<injected>"):
        self.source = source
        if not isinstance(document, dict):
            raise PolicyError(f"{source}: approved-provider policy must be an object")
        if document.get("schema_version") != 1:
            raise PolicyError(
                f"{source}: unsupported policy schema_version "
                f"{document.get('schema_version')!r}")
        entries = document.get("providers")
        if not isinstance(entries, dict):
            raise PolicyError(f"{source}: policy has no providers object")
        self.entries = entries
        self.document = document

    def __contains__(self, provider_id):
        return provider_id in self.entries

    def ids(self):
        return sorted(self.entries)

    def approve(self, manifest: dict, digest: str) -> dict:
        """Return the EFFECTIVE manifest, or raise PolicyError.

        Effective privilege is the intersection of what the manifest requests
        and what the policy permits -- never the union. Any request that
        exceeds the ceiling is refused outright rather than quietly clamped,
        because a provider that asked for more than it may have is either
        mis-packaged or hostile, and silently narrowing it would hide both.
        """
        provider_id = manifest.get("id")
        entry = self.entries.get(provider_id)
        if entry is None:
            raise PolicyError(
                f"provider {provider_id!r} is not in the approved-provider policy "
                f"({self.source}). A schema-valid manifest is not sufficient to "
                "become a provider.")

        expected = entry.get("manifest_sha256")
        if not expected or expected != digest:
            raise PolicyError(
                f"provider {provider_id!r}: manifest digest {digest[:16]}... does not "
                f"match the approved {str(expected)[:16]}.... The manifest changed "
                "after it was approved; re-review it and re-seal the policy.")

        if manifest.get("package") != entry.get("package"):
            raise PolicyError(
                f"provider {provider_id!r}: manifest claims package "
                f"{manifest.get('package')!r}, policy approved "
                f"{entry.get('package')!r}")

        if manifest.get("interface_version") != entry.get("interface_version"):
            raise PolicyError(
                f"provider {provider_id!r}: manifest declares provider interface "
                f"v{manifest.get('interface_version')}, policy approved "
                f"v{entry.get('interface_version')}")

        for field in ("capabilities", "credential_ids", "egress_allowlist"):
            requested = set(manifest.get(field) or ())
            permitted = set(entry.get(field) or ())
            excess = sorted(requested - permitted)
            if excess:
                raise PolicyError(
                    f"provider {provider_id!r} requests {field} it was not approved "
                    f"for: {', '.join(excess)}")

        declared_exec = (manifest.get("executable") or {}).get("trust", "system")
        approved_exec = entry.get("executable_trust")
        if approved_exec is None:
            raise PolicyError(
                f"provider {provider_id!r}: policy entry has no executable_trust. "
                "How far outside the packaging system a provider's program may "
                "live is a privilege, so it is approved explicitly or not at all.")
        if declared_exec not in EXECUTABLE_TRUST_LATITUDE:
            raise PolicyError(
                f"provider {provider_id!r} declares unknown executable trust "
                f"{declared_exec!r}")
        if approved_exec not in EXECUTABLE_TRUST_LATITUDE:
            raise PolicyError(
                f"provider {provider_id!r}: policy approves unknown executable "
                f"trust {approved_exec!r}")
        if EXECUTABLE_TRUST_LATITUDE[declared_exec] > EXECUTABLE_TRUST_LATITUDE[approved_exec]:
            raise PolicyError(
                f"provider {provider_id!r} declares executable trust "
                f"{declared_exec!r}, approved only for {approved_exec!r}")

        wanted = NETWORK_RANK.get(manifest.get("network_policy"), 99)
        allowed = NETWORK_RANK.get(entry.get("network_policy"), -1)
        if wanted > allowed:
            raise PolicyError(
                f"provider {provider_id!r} requests network policy "
                f"{manifest.get('network_policy')!r}, approved for "
                f"{entry.get('network_policy')!r}")

        # The intersection. Equal to the manifest today, because anything
        # broader was already refused -- but computed rather than assumed, so
        # a policy narrower than a manifest genuinely narrows.
        effective = dict(manifest)
        for field in ("capabilities", "credential_ids", "egress_allowlist"):
            if field in manifest:
                permitted = set(entry.get(field) or ())
                effective[field] = [v for v in manifest[field] if v in permitted]
        # min() rather than the manifest's own value, so a policy deliberately
        # narrower than a manifest narrows what actually runs.
        if EXECUTABLE_TRUST_LATITUDE[approved_exec] < EXECUTABLE_TRUST_LATITUDE[declared_exec]:
            narrower = approved_exec
        else:
            narrower = declared_exec
        if manifest.get("executable"):
            effective["executable"] = {**manifest["executable"], "trust": narrower}
        if not effective.get("capabilities"):
            raise PolicyError(
                f"provider {provider_id!r} has no approved capability left after "
                "applying policy")
        effective["_policy"] = {
            "source": self.source,
            "package": entry.get("package"),
            "manifest_sha256": digest,
            "trust": entry.get("trust", "distro-managed"),
            "executable_trust": narrower,
        }
        return effective


def load_policy(root=None) -> ApprovedPolicy:
    """Read the approved-provider policy from a trusted location."""
    root = Path(root) if root else _default_policy_root()
    path = Path(root) / POLICY_NAME
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise PolicyError(
            f"approved-provider policy is unavailable at {path}: {exc}. Mission "
            "Control will not activate any provider without one.") from exc
    except ValueError as exc:
        raise PolicyError(f"approved-provider policy is not valid JSON: {path}: {exc}") from exc
    return ApprovedPolicy(document, source=str(path))


def _default_policy_root() -> Path:
    if POLICY_DIR.is_dir():
        return POLICY_DIR
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "data/usr/share/shadowfetch/provider-policy"
        if candidate.is_dir():
            return candidate
    return POLICY_DIR


def sandbox_from_manifest(manifest: dict) -> SandboxSpec:
    """The ceiling. An adapter may narrow this and nothing may widen it."""
    profile = manifest["sandbox_profile"]
    return SandboxSpec(
        workspace_mode=profile["workspace_mode"],
        network=manifest["network_policy"],
        egress_allowlist=tuple(manifest.get("egress_allowlist") or ()),
        read_grants=tuple(profile.get("read_grants") or ()),
        masked_paths=tuple(profile.get("masked_paths") or ()),
        credential_ids=tuple(manifest.get("credential_ids") or ()),
        account_mount=profile.get("account_mount", ""),
        memory_mb=profile["memory_mb"],
        cpu_seconds=profile["cpu_seconds"],
        processes=profile["processes"],
    )


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
# What each sandbox field actually reaches
# --------------------------------------------------------------------------- #
ENFORCED = "enforced"
PARTIAL = "partial"
NOT_ENFORCED = "not_enforced"
NOT_REPRESENTABLE = "not_representable"

# field -> (status, mechanism). Mirrors the machine-readable table in
# packages/shadowfetch-missions/tests/test_sandbox_spec_audit.py, which fails a
# build if a field's status drifts in either direction. If you change one,
# change both -- that test is the reason this cannot quietly rot.
SANDBOX_ENFORCEMENT = {
    "workspace_mode": (ENFORCED,
                       "bwrap --ro-bind for read-only, --bind otherwise"),
    "network": (ENFORCED,
                "bwrap --unshare-net for 'none'; 'allowlist' collapses to the "
                "host network, see egress_allowlist"),
    "read_grants": (ENFORCED, "bwrap --ro-bind per grant"),
    "credential_ids": (ENFORCED,
                       "bwrap --clearenv plus one --setenv per declared identity"),
    "account_mount": (ENFORCED, "bwrap --bind of the dedicated account home"),
    "memory_mb": (ENFORCED,
                  "systemd MemoryMax with MemorySwapMax=0, so the cap bounds the "
                  "workload rather than the resident set"),
    "processes": (ENFORCED, "systemd TasksMax"),
    "cpu_seconds": (PARTIAL,
                    "RLIMIT_CPU at the tighter of the declaration and the mission "
                    "timeout. Per-PROCESS, so a provider that forks gets a fresh "
                    "budget for each child"),
    "egress_allowlist": (NOT_ENFORCED,
                         "Firebreak has two network postures, none and allow. "
                         "'allowlist' collapses to allow, so the hosts are recorded "
                         "for audit and reach no filter. Phase 4"),
    "masked_paths": (NOT_ENFORCED,
                     "Firebreak has no masking flag; the paths are checked on "
                     "widening and reach nothing. Phase 4"),
    "syscall_profile": (NOT_REPRESENTABLE,
                        "no schema property and no bwrap --seccomp anywhere"),
}


def sandbox_enforcement(spec=None) -> dict:
    """Per-field enforcement status for a SandboxSpec, as a plain dict.

    Callable with no spec to get the static table -- a UI explaining what the
    system can do has no particular sandbox in hand. With a spec, fields the
    sandbox does not actually use are marked not_applicable, so a receipt does
    not warn about an egress allowlist that is empty anyway.
    """
    result = {}
    for field, (status, mechanism) in SANDBOX_ENFORCEMENT.items():
        entry = {"status": status, "mechanism": mechanism}
        if spec is not None and status in (NOT_ENFORCED, PARTIAL):
            value = getattr(spec, field, None)
            if value in (None, (), [], ""):
                entry["status"] = "not_applicable"
                entry["mechanism"] = "this session declared nothing for this field"
        result[field] = entry
    return result


def unenforced_fields(spec=None) -> list:
    """The fields a caller must not describe as protection. One list, so a UI,
    a receipt and a review cannot each decide differently."""
    status = sandbox_enforcement(spec)
    return sorted(name for name, entry in status.items()
                  if entry["status"] in (NOT_ENFORCED, NOT_REPRESENTABLE))

def verify_invocation(invocation, manifest):
    """Check a built Invocation against the ceiling its manifest declares.

    narrow() is a convenience an adapter can simply not call, and
    Invocation(sandbox=...) accepts any SandboxSpec an adapter constructs from
    scratch. Without this, "an adapter cannot widen what it declared" is a
    convention. This is the mechanism: the orchestrator re-derives the ceiling
    from the manifest and refuses anything above it, whatever the adapter did.
    """
    ceiling = sandbox_from_manifest(manifest)
    spec = invocation.sandbox
    if spec is None:
        raise ProviderError(
            f"{manifest['id']}: built an invocation with no sandbox specification")
    if spec.network != ceiling.network and ceiling.network == "none":
        raise ProviderError(
            f"{manifest['id']}: requested network {spec.network!r} but declares none")
    checks = (
        ("credential", set(spec.credential_ids), set(ceiling.credential_ids)),
        ("egress host", set(spec.egress_allowlist), set(ceiling.egress_allowlist)),
        ("read grant", set(spec.read_grants), set(ceiling.read_grants)),
    )
    for what, got, allowed in checks:
        extra = sorted(got - allowed)
        if extra:
            raise ProviderError(
                f"{manifest['id']}: requested undeclared {what}(s): {', '.join(extra)}")
    # Masks may only be ADDED. This is the one field whose safe direction is
    # inverted, which is exactly why it was missed in narrow().
    dropped = sorted(set(ceiling.masked_paths) - set(spec.masked_paths))
    if dropped:
        raise ProviderError(
            f"{manifest['id']}: dropped declared masked path(s): {', '.join(dropped)}")
    for field in ("memory_mb", "cpu_seconds", "processes"):
        if getattr(spec, field) > getattr(ceiling, field):
            raise ProviderError(
                f"{manifest['id']}: requested {field}={getattr(spec, field)} above its "
                f"declared {getattr(ceiling, field)}")
    if ceiling.workspace_mode == "read-only" and spec.workspace_mode != "read-only":
        raise ProviderError(f"{manifest['id']}: upgraded a read-only workspace to writable")

    # WHICH program, not merely what kind of program. Checking only the trust
    # tier let an adapter substitute any OTHER distro-managed binary -- /bin/sh
    # for a provider declaring /usr/bin/ffmpeg -- and inherit that provider's
    # credentials and network grant. The adapter is packaged code, but the seam
    # exists precisely because its OUTPUT is not trusted, and "whatever it says
    # its program is, that answer is checked here" was only half true.
    block = (manifest or {}).get("executable") or {}
    if invocation.executable:
        if block.get("kind") == "none":
            raise ProviderError(
                f"{manifest['id']}: built an invocation with a program "
                f"({invocation.executable}) but its manifest declares none")
        allowed = declared_executables(manifest)
        if str(Path(invocation.executable).resolve()) not in allowed:
            raise ProviderError(
                f"{manifest['id']}: {invocation.executable} is not a program this "
                f"manifest declares. Declared: "
                f"{', '.join(sorted(allowed)) or '(nothing currently installed)'}")
    if spec.account_mount and spec.account_mount != ceiling.account_mount:
        raise ProviderError(
            f"{manifest['id']}: requested credential mount {spec.account_mount!r} "
            "which it does not declare")
    trusted_executable(invocation.executable,
                       trust=(manifest.get("executable") or {}).get("trust", "system"))
    undeclared = sorted(set(invocation.env_allowlist) - set(ceiling.credential_ids))
    if undeclared:
        raise ProviderError(
            f"{manifest['id']}: invocation environment names undeclared "
            f"credential(s): {', '.join(undeclared)}")
    return invocation


@dataclasses.dataclass(frozen=True)
class _Entry:
    manifest: dict
    provider: AgentProvider | None
    error: str = ""

    @property
    def usable(self) -> bool:
        return self.provider is not None


class ProviderRegistry:
    """Manifest-driven discovery. Unknown providers fail closed; a broken
    adapter is reported unavailable rather than crashing Mission Control."""

    def __init__(self, root: Path | None = None, *, module_root: Path | None = None,
                 policy=None, policy_root: Path | None = None):
        self.root = Path(root) if root else _default_root()
        self.module_root = Path(module_root) if module_root else Path(__file__).resolve().parent
        self._entries: dict = {}
        self._errors: list = []
        # policy= is dependency injection for tests. policy_root= points at a
        # policy file. Neither is reachable from the environment.
        self._policy = policy
        self._policy_root = policy_root
        self._load()

    # -- loading -----------------------------------------------------------
    def _load(self) -> None:
        if not self.root.is_dir():
            self._errors.append(f"No provider manifest directory at {self.root}")
            return
        try:
            schema = manifest_schema(self.root)
        except ManifestError as exc:
            self._errors.append(str(exc))
            return
        if self._policy is None:
            try:
                self._policy = load_policy(self._policy_root)
            except PolicyError as exc:
                # No policy means no providers. Failing open here would make
                # deleting one file equivalent to approving everything.
                self._errors.append(str(exc))
                return
        for path in sorted(self.root.glob("*.json")):
            if path.name == SCHEMA_NAME:
                continue
            try:
                manifest = load_manifest(path, schema=schema)
            except ManifestError as exc:
                self._errors.append(str(exc))
                continue
            try:
                manifest = self._policy.approve(manifest, manifest_digest(path))
            except PolicyError as exc:
                self._errors.append(str(exc))
                continue
            if manifest["id"] in self._entries:
                self._errors.append(
                    f"{path.name}: duplicate provider id {manifest['id']!r}; refusing both")
                self._entries.pop(manifest["id"], None)
                continue
            self._entries[manifest["id"]] = self._instantiate(manifest)

    def _instantiate(self, manifest: dict) -> _Entry:
        if manifest["interface_version"] != INTERFACE_VERSION:
            return _Entry(manifest, None,
                          f"needs provider interface v{manifest['interface_version']}, "
                          f"this system implements v{INTERFACE_VERSION}")
        module_name = manifest["adapter_module"]
        # The schema already constrains the name to sf_provider_[a-z0-9_]+, so
        # it cannot traverse; this check makes the guarantee local and explicit.
        if not re.fullmatch(r"sf_provider_[a-z0-9_]+", module_name):
            return _Entry(manifest, None, f"illegal adapter module name {module_name!r}")
        if not (self.module_root / f"{module_name}.py").is_file():
            return _Entry(manifest, None,
                          f"adapter module {module_name} is not installed at {self.module_root}")
        try:
            # Load from the VERIFIED file, not by name through sys.path.
            # sf_missions.py inserts several directories onto sys.path, so an
            # import by name could resolve to a same-named module elsewhere
            # while the existence check above passed against module_root.
            target = (self.module_root / f"{module_name}.py").resolve()
            existing = sys.modules.get(module_name)
            loaded_from = Path(getattr(existing, "__file__", "") or "/nonexistent")
            if existing is not None and loaded_from.resolve() == target:
                # Already imported from exactly the file we verified. Reuse it,
                # so there is ONE module object for this adapter: two copies
                # would mean anything patching or inspecting the adapter could
                # be looking at a different object than the registry uses.
                module = existing
            else:
                spec = importlib.util.spec_from_file_location(module_name, target)
                module = importlib.util.module_from_spec(spec)
                sys.modules[module_name] = module
                spec.loader.exec_module(module)
            klass = getattr(module, manifest["adapter_class"])
            provider = klass(manifest, sandbox_from_manifest(manifest))
        except Exception as exc:  # a broken adapter must not take the engine down
            return _Entry(manifest, None, f"adapter failed to load: {exc.__class__.__name__}: {exc}")
        if not isinstance(provider, AgentProvider):
            return _Entry(manifest, None,
                          f"{manifest['adapter_class']} is not an AgentProvider")
        return _Entry(manifest, provider)

    # -- queries -----------------------------------------------------------
    def get(self, provider_id: str) -> AgentProvider:
        entry = self._entries.get(provider_id)
        if entry is None:
            raise ProviderError(
                f"Unknown provider {provider_id!r}. Installed providers: "
                + (", ".join(sorted(self._entries)) or "none"))
        if not entry.usable:
            raise ProviderError(f"Provider {provider_id!r} is unavailable: {entry.error}")
        return entry.provider

    def list(self) -> list:
        return [e.provider for e in self._entries.values() if e.usable]

    def ids(self) -> list:
        return sorted(self._entries)

    def for_capability(self, capability: str) -> list:
        return [p for p in self.list() if p.supports(capability)]

    def default_for(self, capability: str) -> AgentProvider | None:
        """The provider used when a person did not name one. Deliberately the
        single available provider, or nothing: silently choosing between two is
        an orchestration decision this phase does not make."""
        candidates = [p for p in self.for_capability(capability) if p.readiness().available]
        if len(candidates) == 1:
            return candidates[0]
        installed = self.for_capability(capability)
        return installed[0] if len(installed) == 1 else None

    def readiness(self, provider_id: str) -> Readiness:
        entry = self._entries.get(provider_id)
        if entry is None:
            return Readiness(False, False, missing=("manifest",),
                             reason=f"No provider {provider_id!r} is installed")
        if not entry.usable:
            return Readiness(False, False, missing=("adapter",), reason=entry.error)
        try:
            return entry.provider.readiness()
        except Exception as exc:
            return Readiness(False, False, missing=("readiness",),
                             reason=f"readiness check failed: {exc.__class__.__name__}: {exc}")

    def manifest(self, provider_id: str) -> dict:
        entry = self._entries.get(provider_id)
        if entry is None:
            raise ProviderError(f"Unknown provider {provider_id!r}")
        return dict(entry.manifest)

    @property
    def policy(self) -> ApprovedPolicy | None:
        """The policy this registry applied, for callers that must show or check
        it. Read-only by convention: the document it wraps is the loaded one."""
        return self._policy

    @property
    def errors(self) -> list:
        return list(self._errors) + [
            f"{pid}: {e.error}" for pid, e in self._entries.items() if not e.usable]

    def describe(self) -> dict:
        """Registry-shaped view for the UI and for capabilities()."""
        out = {}
        for pid, entry in self._entries.items():
            readiness = self.readiness(pid)
            manifest = entry.manifest
            out[pid] = {
                "display_name": manifest["display_name"],
                "capabilities": list(manifest["capabilities"]),
                "interface_version": manifest["interface_version"],
                "version": manifest["version"],
                "package": manifest["package"],
                "network_policy": manifest["network_policy"],
                "egress_allowlist": list(manifest.get("egress_allowlist") or []),
                "credential_ids": list(manifest.get("credential_ids") or []),
                "sandbox_profile": dict(manifest["sandbox_profile"]),
                "requires_network_approval": manifest["network_policy"] != "none",
                "available": readiness.available,
                **readiness.as_dict(),
            }
        return out
