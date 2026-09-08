"""Release gate for agent providers: validate DATA and POLICY, not source shape.

What this replaces
------------------
tools/mission_provider_contract.py did two jobs. The first was a payload
blacklist that refuses any shipped path belonging to the retired local-AI stack;
that job is preserved here unchanged, because it is a real security invariant
and nothing about the provider abstraction makes it less necessary.

The second job was an AST freeze: it parsed capabilities() out of the mission
source and asserted the provider set was exactly {codex, offline}. That made
adding any provider a gate failure, which is the opposite of what this project
now needs, and it validated the SHAPE OF SOURCE CODE rather than the behaviour
of the system -- a rename could satisfy it while a genuinely dangerous provider
slipped past.

This gate instead validates the provider manifests that actually ship, and the
relationship between them and the code that ships beside them. Adding a third
valid provider requires no edit to this file. Adding an invalid one, or adding
provider code with no manifest, fails.

Callable identically from the source, package and ISO gates: each supplies a
`read` callable for its own context (source tree, extracted .deb, squashfs).
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_MISSIONS_DATA = ROOT / "packages/shadowfetch-missions/data/usr/lib/shadowfetch/missions"
if str(_MISSIONS_DATA) not in sys.path:
    sys.path.insert(0, str(_MISSIONS_DATA))

import sf_jsonschema  # the same validator the installed system uses

MANIFEST_DIR = "usr/share/shadowfetch/providers"
SCHEMA_PATH = f"{MANIFEST_DIR}/provider-manifest.schema.json"
ADAPTER_DIR = "usr/lib/shadowfetch/missions"

# ---------------------------------------------------------------------------
# Preserved from the old contract, unchanged. The retired local-AI stack must
# never reappear in any artifact.
# ---------------------------------------------------------------------------
REMOVED_AI_PATH = re.compile(
    r"^(?:usr/bin/(?:shadowfetch-(?:buzz(?:-[^/]+)?|model-check|ai-ignition)|buzz(?:-desktop)?)$|"
    r"usr/libexec/shadowfetch-buzz(?:-[^/]+)?$|"
    r"usr/lib/systemd/user/shadowfetch-buzz[^/]*$|"
    r"usr/share/applications/shadowfetch-buzz\.desktop$|"
    r"usr/share/shadowfetch/(?:buzz|ai-ignition)(?:/|$)|"
    r"usr/lib/shadowfetch/missions/sf_local_compute\.py$|"
    r"usr/share/shadowfetch/control-center/sfcc/(?:local_model_card|local_ai_page)\.py$)"
)

VALID_CAPABILITIES = frozenset({"code_change", "sourced_report", "media_export"})
SUPPORTED_INTERFACE_VERSIONS = frozenset({1})
ADAPTER_NAME = re.compile(r"^sf_provider_[a-z0-9_]+$")


class ProviderPolicyError(RuntimeError):
    """A shipped provider set violates policy."""


def _default_read(relative: str):
    path = ROOT / "packages/shadowfetch-missions/data" / relative
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def validate_provider_payload(paths, mission_source, *, read=None):
    """Validate one artifact's provider payload.

    paths          any iterable of shipped paths relative to the image root.
                   A dict is accepted (the package gate passes its owner map);
                   only the keys are used.
    mission_source text of sf_missions.py in that artifact.
    read           read(relative_path) -> str | None, for this artifact's
                   context. Defaults to the source tree.
    """
    read = read or _default_read
    inventory = sorted(paths)

    # -- 1. the preserved blacklist -------------------------------------
    retired = sorted(p for p in inventory if REMOVED_AI_PATH.search(p))
    if retired:
        raise ProviderPolicyError("Deferred local-AI payload remains: " + ", ".join(retired))
    if "sf_local_compute" in (mission_source or ""):
        raise ProviderPolicyError("Mission backend still loads the removed local provider")

    # -- 2. discover what actually ships --------------------------------
    manifest_paths = sorted(
        p for p in inventory
        if p.startswith(MANIFEST_DIR + "/") and p.endswith(".json")
        and not p.endswith("provider-manifest.schema.json"))
    adapter_paths = sorted(
        p for p in inventory
        if p.startswith(ADAPTER_DIR + "/")
        and ADAPTER_NAME.match(Path(p).stem) and p.endswith(".py"))

    # An artifact that ships no mission payload at all (some gates pass a
    # narrow inventory) has nothing to say about providers.
    if not manifest_paths and not adapter_paths:
        return {"providers": [], "checked": False}

    if not manifest_paths:
        raise ProviderPolicyError(
            "Provider adapter code ships with no manifest: " + ", ".join(adapter_paths))

    schema_text = read(SCHEMA_PATH)
    if not schema_text:
        raise ProviderPolicyError(
            f"Provider manifest schema is missing from the artifact: {SCHEMA_PATH}")
    try:
        schema = json.loads(schema_text)
    except ValueError as exc:
        raise ProviderPolicyError(f"Provider manifest schema is not valid JSON: {exc}") from exc

    # -- 3. validate each manifest ---------------------------------------
    seen = {}
    declared_adapters = set()
    for relative in manifest_paths:
        name = Path(relative).name
        text = read(relative)
        if text is None:
            raise ProviderPolicyError(f"{name}: manifest could not be read from the artifact")
        try:
            manifest = json.loads(text)
        except ValueError as exc:
            raise ProviderPolicyError(f"{name}: manifest is not valid JSON: {exc}") from exc
        try:
            sf_jsonschema.validate(manifest, schema)
        except sf_jsonschema.ValidationError as exc:
            raise ProviderPolicyError(f"{name}: manifest does not satisfy the schema: {exc}") from exc
        except sf_jsonschema.SchemaError as exc:
            raise ProviderPolicyError(f"{name}: manifest schema is unusable: {exc}") from exc

        provider_id = manifest["id"]
        if Path(relative).stem != provider_id:
            raise ProviderPolicyError(
                f"{name}: manifest filename must match its id {provider_id!r}, so a "
                "provider cannot be shadowed by another file claiming the same id")
        if provider_id in seen:
            raise ProviderPolicyError(
                f"duplicate provider id {provider_id!r} in {seen[provider_id]} and {name}")
        seen[provider_id] = name

        # capabilities are meaningful, not free text
        unknown = sorted(set(manifest["capabilities"]) - VALID_CAPABILITIES)
        if unknown:
            raise ProviderPolicyError(
                f"{name}: declares unknown capability {', '.join(unknown)}")

        if manifest["interface_version"] not in SUPPORTED_INTERFACE_VERSIONS:
            raise ProviderPolicyError(
                f"{name}: declares provider interface v{manifest['interface_version']}, "
                f"this release implements {sorted(SUPPORTED_INTERFACE_VERSIONS)}")

        # the adapter it names must actually ship
        adapter = manifest["adapter_module"]
        if not ADAPTER_NAME.match(adapter):
            raise ProviderPolicyError(f"{name}: illegal adapter module {adapter!r}")
        adapter_path = f"{ADAPTER_DIR}/{adapter}.py"
        if adapter_path not in inventory:
            raise ProviderPolicyError(
                f"{name}: names adapter {adapter} but {adapter_path} does not ship")
        declared_adapters.add(adapter_path)

        # the provider program is never found through PATH
        executable = manifest.get("executable") or {"kind": "none"}
        kind = executable.get("kind")
        if kind == "absolute":
            if not str(executable.get("path", "")).startswith("/"):
                raise ProviderPolicyError(f"{name}: executable path must be absolute")
        elif kind == "resolver":
            adapter_text = read(adapter_path) or ""
            resolver = executable.get("resolver", "")
            if f"def {resolver}(" not in adapter_text:
                raise ProviderPolicyError(
                    f"{name}: names executable resolver {resolver}() which {adapter} does not define")
        elif kind != "none":
            raise ProviderPolicyError(f"{name}: unknown executable kind {kind!r}")

        # credential identities are declared, never inline values
        for credential in manifest.get("credential_ids") or []:
            if not re.fullmatch(r"[A-Z][A-Z0-9_]*", credential):
                raise ProviderPolicyError(
                    f"{name}: credential_ids must be identities, not values: {credential!r}")

        # network requirements are declared and self-consistent
        policy = manifest["network_policy"]
        allowlist = manifest.get("egress_allowlist") or []
        if policy == "allowlist" and not allowlist:
            raise ProviderPolicyError(
                f"{name}: declares an allowlist network policy with no hosts, which is an "
                "unbounded grant wearing a policy's name")
        if policy == "none" and allowlist:
            raise ProviderPolicyError(
                f"{name}: declares no network yet carries an egress allowlist")

    # -- 4. no provider may arrive through unvalidated code --------------
    undeclared = sorted(set(adapter_paths) - declared_adapters)
    if undeclared:
        raise ProviderPolicyError(
            "Provider adapter code ships that no validated manifest names, so it could be "
            "reached without policy review: " + ", ".join(undeclared))

    # -- 5. every capability the product offers must have a provider ------
    offered = set()
    for provider_id, name in seen.items():
        text = read(f"{MANIFEST_DIR}/{provider_id}.json")
        offered |= set(json.loads(text)["capabilities"])
    missing = sorted(VALID_CAPABILITIES - offered)
    if missing:
        raise ProviderPolicyError(
            "No shipped provider performs: " + ", ".join(missing))

    return {"providers": sorted(seen), "checked": True}


__all__ = ["validate_provider_payload", "ProviderPolicyError", "REMOVED_AI_PATH"]
