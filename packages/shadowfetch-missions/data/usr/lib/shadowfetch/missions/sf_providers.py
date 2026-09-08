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

  * An Invocation's executable must be an absolute path AND must resolve
    inside a packaging-owned directory. An adapter may look its program up
    however it likes; trusted_executable() re-checks the answer, so a binary
    in a user-writable location -- ~/.local/bin, say -- cannot be executed.
"""
from __future__ import annotations

import dataclasses
import importlib
import importlib.util
import json
import os
import re
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
    "resolve_executable",
]

INTERFACE_VERSION = 1
"""The AgentProvider ABI this runtime implements. A manifest declaring a
different interface_version is reported unavailable with a reason rather than
imported and failed later."""

MANIFEST_DIR = Path("/usr/share/shadowfetch/providers")

# A provider program may only be executed from a directory the packaging
# system owns. This is the mechanism behind "no PATH resolution": even an
# adapter that resolves its binary through PATH cannot return one from a
# user-writable location, because trusted_executable() re-checks the answer.
TRUSTED_EXEC_PREFIXES = ("/usr/bin/", "/usr/sbin/", "/usr/libexec/",
                        "/usr/lib/", "/usr/local/lib/shadowfetch/",
                        "/bin/", "/sbin/", "/opt/")


def trusted_executable(path, *, trust="system"):
    """Return the resolved absolute path, or raise if it fails its trust tier.

    An adapter is packaged code, but its OUTPUT is not trusted: whatever it
    says its program is, that answer is checked here.

    trust="system"        the program must live in a packaging-owned directory.
                          This is the default and what a provider should use.
    trust="user-runtime"  the program is a user-installed runtime -- an npm or
                          pip CLI -- so it legitimately lives under the user's
                          home. It must then be owned by the invoking user and
                          not world-writable. This tier exists because the
                          Codex CLI is genuinely installed that way; declaring
                          it makes the exception visible in the manifest and at
                          the release gate instead of being silently universal.

    Group-writability is accepted for user-runtime because npm and nvm install
    0775 under the user's personal group. That is a real residual gap on a
    machine with shared groups, and it is recorded in PHASE2_REMAINING_RISKS.
    """
    if not path:
        raise ProviderError("Provider executable was not found")
    resolved = Path(path).resolve()
    if not resolved.is_absolute():
        raise ProviderError(f"Provider executable is not absolute: {resolved}")
    if str(resolved).startswith(tuple(TRUSTED_EXEC_PREFIXES)):
        return str(resolved)
    if trust != "user-runtime":
        raise ProviderError(
            f"Provider executable {resolved} is outside the packaging-owned "
            "directories and its manifest does not declare a user-runtime "
            "executable. A program in a user-writable location is not run as "
            "part of a mission unless a provider declares that it is one.")
    try:
        info = resolved.stat()
    except OSError as exc:
        raise ProviderError(f"Provider executable {resolved} cannot be inspected: {exc}")
    if info.st_uid != os.getuid():
        raise ProviderError(
            f"Provider executable {resolved} is not owned by the user running "
            "the mission; refusing to execute it.")
    if info.st_mode & 0o002:
        raise ProviderError(
            f"Provider executable {resolved} is world-writable; refusing to "
            "execute it.")
    return str(resolved)
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
    override = os.environ.get("SHADOWFETCH_PROVIDER_MANIFESTS")
    if override:
        # A test/QA seam, but not an unconditional one. The document it selects
        # decides network policy, credential identities, read grants and
        # resource caps -- so an environment-selected manifest root is the
        # Phase-1 defect class one layer up from PATH. It is honoured only from
        # a directory the invoking user owns and that no one else can write.
        candidate = Path(override).expanduser()
        try:
            info = candidate.stat()
            safe = (candidate.is_dir() and not candidate.is_symlink()
                    and info.st_uid in (0, os.getuid())
                    and not info.st_mode & 0o022)
        except OSError:
            safe = False
        if safe:
            return candidate
        sys.stderr.write(
            f"ignoring SHADOWFETCH_PROVIDER_MANIFESTS={candidate}: it must be a "
            "directory you own that is not group- or world-writable\n")
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

    def __init__(self, root: Path | None = None, *, module_root: Path | None = None):
        self.root = Path(root) if root else _default_root()
        self.module_root = Path(module_root) if module_root else Path(__file__).resolve().parent
        self._entries: dict = {}
        self._errors: list = []
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
        for path in sorted(self.root.glob("*.json")):
            if path.name == SCHEMA_NAME:
                continue
            try:
                manifest = load_manifest(path, schema=schema)
            except ManifestError as exc:
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
