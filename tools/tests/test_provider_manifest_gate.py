"""The release gate validates provider DATA and POLICY, not source shape.

The old gate (tools/mission_provider_contract.py) asserted by AST that the
provider set was exactly {codex, offline}. It is gone. These tests pin what
replaced it, and in particular the property that the old gate could not have:

    a third valid provider passes the gate WITHOUT editing gate source.

That is the architectural proof for Phase 2, so it is asserted here as well as
in the conformance suite.
"""
import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from providers.validate_manifest import (validate_provider_payload,
                                         ProviderPolicyError, REMOVED_AI_PATH)

DATA = ROOT / "packages/shadowfetch-missions/data"
MISSION_SOURCE = (DATA / "usr/lib/shadowfetch/missions/sf_missions.py").read_text()
MANIFEST_DIR = "usr/share/shadowfetch/providers"
ADAPTER_DIR = "usr/lib/shadowfetch/missions"

SHIPPED = [
    f"{MANIFEST_DIR}/provider-manifest.schema.json",
    f"{MANIFEST_DIR}/codex.json",
    f"{MANIFEST_DIR}/offline-media.json",
    f"{ADAPTER_DIR}/sf_provider_codex.py",
    f"{ADAPTER_DIR}/sf_provider_offline_media.py",
    f"{ADAPTER_DIR}/sf_providers.py",
    f"{ADAPTER_DIR}/sf_missions.py",
    "usr/bin/shadowfetch-missions",
]


def real_read(relative):
    try:
        return (DATA / relative).read_text(encoding="utf-8")
    except OSError:
        return None


def overlay(**files):
    """A reader that serves `files` and falls back to what really ships."""
    def read(relative):
        if relative in files:
            return files[relative]
        return real_read(relative)
    return read


def manifest(name):
    return json.loads(real_read(f"{MANIFEST_DIR}/{name}.json"))


class ShippedPayloadPasses(unittest.TestCase):
    def test_the_real_payload_validates(self):
        result = validate_provider_payload(SHIPPED, MISSION_SOURCE, read=real_read)
        self.assertTrue(result["checked"])
        self.assertEqual(result["providers"], ["codex", "offline-media"])

    def test_a_dict_of_owners_is_accepted(self):
        """The package gate passes its path->owner map, not a list."""
        owners = {p: ["shadowfetch-missions"] for p in SHIPPED}
        result = validate_provider_payload(owners, MISSION_SOURCE, read=real_read)
        self.assertEqual(result["providers"], ["codex", "offline-media"])


class RetiredPayloadStillRefused(unittest.TestCase):
    """The one job of the old gate that had to survive."""

    def test_removed_local_ai_payload_fails(self):
        for path in ("usr/bin/shadowfetch-buzz",
                     "usr/libexec/shadowfetch-buzz-stack",
                     "usr/lib/systemd/user/shadowfetch-buzz.service",
                     "usr/share/shadowfetch/buzz/compose.yml",
                     "usr/bin/shadowfetch-model-check",
                     "usr/lib/shadowfetch/missions/sf_local_compute.py",
                     "usr/share/shadowfetch/control-center/sfcc/local_model_card.py",
                     "usr/share/shadowfetch/ai-ignition/models.json"):
            with self.subTest(path=path), self.assertRaisesRegex(ProviderPolicyError, "payload remains"):
                validate_provider_payload(SHIPPED + [path], MISSION_SOURCE, read=real_read)

    def test_mission_source_reloading_the_local_provider_fails(self):
        with self.assertRaisesRegex(ProviderPolicyError, "removed local provider"):
            validate_provider_payload(SHIPPED, MISSION_SOURCE + "\nimport sf_local_compute\n",
                                      read=real_read)

    def test_ordinary_agent_tooling_still_passes(self):
        validate_provider_payload(
            SHIPPED + ["usr/bin/shadowfetch-grok-bot", "usr/bin/podman"],
            MISSION_SOURCE, read=real_read)


class MalformedManifestsFail(unittest.TestCase):
    def _reject(self, doc, pattern, name="codex"):
        read = overlay(**{f"{MANIFEST_DIR}/{name}.json": json.dumps(doc)})
        with self.assertRaisesRegex(ProviderPolicyError, pattern):
            validate_provider_payload(SHIPPED, MISSION_SOURCE, read=read)

    def test_not_json(self):
        read = overlay(**{f"{MANIFEST_DIR}/codex.json": "{ this is not json"})
        with self.assertRaisesRegex(ProviderPolicyError, "not valid JSON"):
            validate_provider_payload(SHIPPED, MISSION_SOURCE, read=read)

    def test_missing_required_field(self):
        doc = manifest("codex"); doc.pop("credential_ids")
        self._reject(doc, "does not satisfy the schema")

    def test_unknown_capability(self):
        doc = manifest("codex"); doc["capabilities"] = ["code_change", "telepathy"]
        self._reject(doc, "does not satisfy the schema")

    def test_undeclared_extra_field(self):
        doc = manifest("codex"); doc["backdoor"] = True
        self._reject(doc, "does not satisfy the schema")

    def test_unsupported_interface_version(self):
        doc = manifest("codex"); doc["interface_version"] = 99
        self._reject(doc, "interface v99")

    def test_filename_must_match_id(self):
        doc = manifest("codex"); doc["id"] = "not-codex"
        self._reject(doc, "filename must match its id")

    def test_duplicate_id_across_files(self):
        doc = manifest("offline-media"); doc["id"] = "codex"
        read = overlay(**{f"{MANIFEST_DIR}/offline-media.json": json.dumps(doc)})
        with self.assertRaisesRegex(ProviderPolicyError, "filename must match its id"):
            validate_provider_payload(SHIPPED, MISSION_SOURCE, read=read)

    def test_adapter_module_that_does_not_ship(self):
        doc = manifest("codex"); doc["adapter_module"] = "sf_provider_ghost"
        self._reject(doc, "does not ship")

    def test_illegal_adapter_module_name(self):
        doc = manifest("codex"); doc["adapter_module"] = "os"
        self._reject(doc, "does not satisfy the schema")

    def test_resolver_the_adapter_does_not_define(self):
        doc = manifest("codex"); doc["executable"] = {"kind": "resolver", "resolver": "nowhere"}
        self._reject(doc, "does not define")

    def test_credential_value_instead_of_identity(self):
        doc = manifest("codex"); doc["credential_ids"] = ["sk-live-abcdef"]
        self._reject(doc, "does not satisfy the schema")

    def test_allowlist_policy_with_no_hosts(self):
        doc = manifest("codex"); doc["egress_allowlist"] = []
        self._reject(doc, "does not satisfy the schema")

    def test_no_network_but_hosts_declared(self):
        doc = manifest("offline-media"); doc["egress_allowlist"] = ["evil.example.com"]
        read = overlay(**{f"{MANIFEST_DIR}/offline-media.json": json.dumps(doc)})
        with self.assertRaisesRegex(ProviderPolicyError, "does not satisfy the schema"):
            validate_provider_payload(SHIPPED, MISSION_SOURCE, read=read)


class ProviderCannotArriveThroughCodeAlone(unittest.TestCase):
    """The inverse check the old gate never had."""

    def test_adapter_without_a_manifest_fails(self):
        paths = SHIPPED + [f"{ADAPTER_DIR}/sf_provider_smuggled.py"]
        with self.assertRaisesRegex(ProviderPolicyError, "no validated manifest names"):
            validate_provider_payload(paths, MISSION_SOURCE, read=real_read)

    def test_manifests_without_any_adapter_fails(self):
        paths = [p for p in SHIPPED if not p.startswith(f"{ADAPTER_DIR}/sf_provider_")]
        with self.assertRaisesRegex(ProviderPolicyError, "does not ship"):
            validate_provider_payload(paths, MISSION_SOURCE, read=real_read)

    def test_every_capability_must_have_a_provider(self):
        paths = [p for p in SHIPPED
                 if p not in (f"{MANIFEST_DIR}/offline-media.json",
                              f"{ADAPTER_DIR}/sf_provider_offline_media.py")]
        with self.assertRaisesRegex(ProviderPolicyError, "No shipped provider performs"):
            validate_provider_payload(paths, MISSION_SOURCE, read=real_read)


class ThirdProviderNeedsNoGateEdit(unittest.TestCase):
    """THE architectural proof for Phase 2.

    A new, valid provider is added as data plus an adapter. If this test needs
    tools/providers/validate_manifest.py to change, the gate has regressed into
    freezing a provider list again and the phase has failed.
    """

    THIRD = {
        "schema_version": 1,
        "id": "example-agent",
        "display_name": "Example Agent",
        "interface_version": 1,
        "adapter_module": "sf_provider_example_agent",
        "adapter_class": "ExampleAgentProvider",
        "capabilities": ["code_change"],
        "credential_ids": ["EXAMPLE_AGENT_TOKEN"],
        "network_policy": "allowlist",
        "egress_allowlist": ["api.example.com"],
        "sandbox_profile": {
            "workspace_mode": "workspace-write",
            "memory_mb": 2048, "cpu_seconds": 600, "processes": 32,
            "read_grants": [], "masked_paths": [],
        },
        "executable": {"kind": "absolute", "path": "/usr/bin/example-agent"},
        "package": "shadowfetch-example-agent",
        "version": "1.0.0",
    }

    def test_a_third_valid_provider_passes_unmodified_gate_source(self):
        gate_before = (ROOT / "tools/providers/validate_manifest.py").read_bytes()
        paths = SHIPPED + [
            f"{MANIFEST_DIR}/example-agent.json",
            f"{ADAPTER_DIR}/sf_provider_example_agent.py",
        ]
        read = overlay(**{
            f"{MANIFEST_DIR}/example-agent.json": json.dumps(self.THIRD),
            f"{ADAPTER_DIR}/sf_provider_example_agent.py":
                "from sf_providers import AgentProvider\n"
                "class ExampleAgentProvider(AgentProvider):\n    pass\n",
        })
        result = validate_provider_payload(paths, MISSION_SOURCE, read=read)
        self.assertEqual(result["providers"], ["codex", "example-agent", "offline-media"])
        self.assertEqual(gate_before,
                         (ROOT / "tools/providers/validate_manifest.py").read_bytes(),
                         "the gate source changed while accepting a third provider")

    def test_a_third_INVALID_provider_is_still_refused(self):
        broken = dict(self.THIRD, network_policy="allowlist", egress_allowlist=[])
        paths = SHIPPED + [f"{MANIFEST_DIR}/example-agent.json",
                           f"{ADAPTER_DIR}/sf_provider_example_agent.py"]
        read = overlay(**{
            f"{MANIFEST_DIR}/example-agent.json": json.dumps(broken),
            f"{ADAPTER_DIR}/sf_provider_example_agent.py": "x = 1\n",
        })
        with self.assertRaises(ProviderPolicyError):
            validate_provider_payload(paths, MISSION_SOURCE, read=read)


if __name__ == "__main__":
    unittest.main(verbosity=2)
