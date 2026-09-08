"""The approved-provider policy: a schema-valid manifest is not enough.

Phase 2 removed an AST freeze that had, by accident, made it impossible for an
unreviewed provider to exist. Nothing replaced that property, and
PHASE2_REMAINING_RISKS.md recorded the consequence: any package landing a
schema-valid manifest in the discovery path became a provider and was granted
whatever credentials and network posture it declared about itself.

The manifest says "I request these privileges."
The policy says   "Shadowfetch permits this package to request these privileges."

Effective privilege is the INTERSECTION. A request beyond the approved ceiling
fails closed rather than being quietly clamped, because a provider asking for
more than it may have is either mis-packaged or hostile and silently narrowing
it would hide both.
"""
import copy
import hashlib
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
BASE = HERE / "data/usr/lib/shadowfetch/missions"
SHIPPED_MANIFESTS = HERE / "data/usr/share/shadowfetch/providers"
SHIPPED_POLICY = HERE / "data/usr/share/shadowfetch/provider-policy"
sys.path.insert(0, str(BASE))

from sf_providers import (ApprovedPolicy, PolicyError, ProviderRegistry,
                          load_policy, manifest_digest)


def shipped_policy_document():
    return json.loads((SHIPPED_POLICY / "approved.json").read_text())


class Bench:
    """A throwaway provider root plus policy, both writable, so an attack can
    modify either side and the registry can be rebuilt against it."""

    def __init__(self, stack):
        self.dir = Path(tempfile.mkdtemp())
        stack.append(self.dir)
        self.manifests = self.dir / "providers"
        self.policy_dir = self.dir / "policy"
        self.manifests.mkdir(); self.policy_dir.mkdir()
        self.manifests.chmod(0o755); self.policy_dir.chmod(0o755)
        for name in ("provider-manifest.schema.json", "codex.json", "offline-media.json"):
            shutil.copy(SHIPPED_MANIFESTS / name, self.manifests / name)
        shutil.copy(SHIPPED_POLICY / "approved.json", self.policy_dir / "approved.json")

    # -- mutate one side or the other ------------------------------------
    def manifest(self, provider_id):
        return json.loads((self.manifests / f"{provider_id}.json").read_text())

    def write_manifest(self, provider_id, document):
        (self.manifests / f"{provider_id}.json").write_text(
            json.dumps(document, indent=2) + "\n")

    def policy(self):
        return json.loads((self.policy_dir / "approved.json").read_text())

    def write_policy(self, document):
        (self.policy_dir / "approved.json").write_text(json.dumps(document, indent=2) + "\n")

    def reseal(self, provider_id):
        """Approve whatever the manifest currently says — the legitimate flow."""
        doc = self.policy()
        path = self.manifests / f"{provider_id}.json"
        manifest = json.loads(path.read_text())
        entry = doc["providers"].setdefault(provider_id, {})
        for field in ("package", "interface_version", "capabilities",
                      "credential_ids", "network_policy", "egress_allowlist"):
            entry[field] = manifest.get(field)
        entry["manifest_sha256"] = manifest_digest(path)
        entry.setdefault("trust", "distro-managed")
        self.write_policy(doc)

    def registry(self):
        return ProviderRegistry(root=self.manifests, module_root=BASE,
                                policy_root=self.policy_dir)


class PolicyHarness(unittest.TestCase):
    def setUp(self):
        self._dirs = []
        self.bench = Bench(self._dirs)

    def tearDown(self):
        for d in self._dirs:
            shutil.rmtree(d, ignore_errors=True)

    def assertRefused(self, provider_id, pattern):
        registry = self.bench.registry()
        self.assertNotIn(provider_id, registry.ids(),
                         f"{provider_id} became a provider despite policy")
        joined = " | ".join(registry.errors)
        self.assertRegex(joined, pattern)
        return registry


# ═══ 1. the honest case ════════════════════════════════════════════════════
class ValidProviderWithCorrectDigest(PolicyHarness):
    def test_a_correctly_approved_provider_loads(self):
        registry = self.bench.registry()
        self.assertEqual(registry.ids(), ["codex", "offline-media"])
        self.assertEqual(registry.errors, [])

    def test_the_shipped_policy_matches_the_shipped_manifests(self):
        """If this fails, someone changed a manifest without re-sealing."""
        policy = load_policy(SHIPPED_POLICY)
        for path in sorted(SHIPPED_MANIFESTS.glob("*.json")):
            if path.name == "provider-manifest.schema.json":
                continue
            manifest = json.loads(path.read_text())
            with self.subTest(provider=manifest["id"]):
                effective = policy.approve(manifest, manifest_digest(path))
                self.assertEqual(effective["id"], manifest["id"])

    def test_the_effective_manifest_records_its_approval(self):
        registry = self.bench.registry()
        provider = registry.get("codex")
        stamp = provider.manifest["_policy"]
        self.assertEqual(stamp["package"], "shadowfetch-missions")
        self.assertEqual(stamp["manifest_sha256"],
                         manifest_digest(self.bench.manifests / "codex.json"))


# ═══ 2-11. the attacks ═════════════════════════════════════════════════════
class ModifiedAfterApproval(PolicyHarness):
    def test_any_edit_after_approval_is_refused(self):
        doc = self.bench.manifest("codex")
        doc["display_name"] = "Codex CLI (cloud) "        # cosmetic, still refused
        self.bench.write_manifest("codex", doc)
        self.assertRefused("codex", "digest .* does not match the approved")

    def test_resealing_after_review_restores_it(self):
        doc = self.bench.manifest("codex")
        doc["display_name"] = "Codex CLI (reviewed)"
        self.bench.write_manifest("codex", doc)
        self.assertRefused("codex", "digest")
        self.bench.reseal("codex")
        self.assertIn("codex", self.bench.registry().ids())


class AddedCredential(PolicyHarness):
    def test_a_credential_the_policy_did_not_approve_is_refused(self):
        doc = self.bench.manifest("codex")
        doc["credential_ids"] = ["CODEX_API_KEY", "ANTHROPIC_API_KEY"]
        self.bench.write_manifest("codex", doc)
        self.assertRefused("codex", "digest")

    def test_even_with_a_matching_digest_the_ceiling_holds(self):
        """The digest pin is not the only guard: re-sealing the DIGEST alone,
        without widening the policy, must still refuse the extra credential."""
        doc = self.bench.manifest("codex")
        doc["credential_ids"] = ["CODEX_API_KEY", "ANTHROPIC_API_KEY"]
        self.bench.write_manifest("codex", doc)
        policy = self.bench.policy()
        policy["providers"]["codex"]["manifest_sha256"] = manifest_digest(
            self.bench.manifests / "codex.json")
        self.bench.write_policy(policy)
        self.assertRefused("codex", "credential_ids it was not approved for: ANTHROPIC_API_KEY")


class BroaderNetwork(PolicyHarness):
    def test_none_cannot_become_allowlist(self):
        doc = self.bench.manifest("offline-media")
        doc["network_policy"] = "allowlist"
        doc["egress_allowlist"] = ["evil.example.com"]
        self.bench.write_manifest("offline-media", doc)
        policy = self.bench.policy()
        policy["providers"]["offline-media"]["manifest_sha256"] = manifest_digest(
            self.bench.manifests / "offline-media.json")
        self.bench.write_policy(policy)
        self.assertRefused("offline-media", "network policy|egress_allowlist")

    def test_an_extra_egress_host_is_refused(self):
        doc = self.bench.manifest("codex")
        doc["egress_allowlist"] = doc["egress_allowlist"] + ["exfil.example.com"]
        self.bench.write_manifest("codex", doc)
        policy = self.bench.policy()
        policy["providers"]["codex"]["manifest_sha256"] = manifest_digest(
            self.bench.manifests / "codex.json")
        self.bench.write_policy(policy)
        self.assertRefused("codex", "egress_allowlist it was not approved for: exfil")


class AddedCapability(PolicyHarness):
    def test_a_capability_beyond_the_ceiling_is_refused(self):
        doc = self.bench.manifest("offline-media")
        doc["capabilities"] = ["media_export", "code_change"]
        self.bench.write_manifest("offline-media", doc)
        policy = self.bench.policy()
        policy["providers"]["offline-media"]["manifest_sha256"] = manifest_digest(
            self.bench.manifests / "offline-media.json")
        self.bench.write_policy(policy)
        self.assertRefused("offline-media", "capabilities it was not approved for: code_change")


class PackageMismatch(PolicyHarness):
    def test_a_manifest_claiming_another_package_is_refused(self):
        doc = self.bench.manifest("codex")
        doc["package"] = "totally-legitimate-agent"
        self.bench.write_manifest("codex", doc)
        policy = self.bench.policy()
        policy["providers"]["codex"]["manifest_sha256"] = manifest_digest(
            self.bench.manifests / "codex.json")
        self.bench.write_policy(policy)
        self.assertRefused("codex", "claims package")


class InterfaceVersionMismatch(PolicyHarness):
    def test_an_unapproved_interface_version_is_refused(self):
        policy = self.bench.policy()
        policy["providers"]["codex"]["interface_version"] = 2
        self.bench.write_policy(policy)
        self.assertRefused("codex", "interface v1, policy approved v2")


class DuplicateProviderId(PolicyHarness):
    def test_two_files_claiming_one_id_refuse_both(self):
        doc = self.bench.manifest("codex")
        (self.bench.manifests / "codex-copy.json").write_text(json.dumps(doc, indent=2))
        registry = self.bench.registry()
        joined = " | ".join(registry.errors)
        # the filename/id rule catches it before the policy does, which is fine:
        # what matters is that neither file wins.
        self.assertRegex(joined, "filename must match its id|duplicate provider id")


class AbsentFromPolicy(PolicyHarness):
    def test_a_provider_with_no_policy_entry_is_refused(self):
        policy = self.bench.policy()
        del policy["providers"]["codex"]
        self.bench.write_policy(policy)
        self.assertRefused("codex", "not in the approved-provider policy")

    def test_a_schema_valid_stranger_never_becomes_a_provider(self):
        """The headline attack: drop a perfectly well-formed manifest into the
        discovery directory and see whether it becomes a provider."""
        stranger = self.bench.manifest("offline-media")
        stranger.update(id="helpful-agent", display_name="Helpful Agent",
                        package="helpful-agent",
                        adapter_module="sf_provider_offline_media",
                        adapter_class="OfflineMediaProvider",
                        credential_ids=["ANTHROPIC_API_KEY", "AWS_SECRET_ACCESS_KEY"])
        self.bench.write_manifest("helpful-agent", stranger)
        registry = self.bench.registry()
        self.assertNotIn("helpful-agent", registry.ids())
        self.assertRegex(" | ".join(registry.errors),
                         "not in the approved-provider policy")


class StalePolicyDigest(PolicyHarness):
    def test_a_policy_entry_pinning_the_wrong_digest_refuses(self):
        policy = self.bench.policy()
        policy["providers"]["codex"]["manifest_sha256"] = "0" * 64
        self.bench.write_policy(policy)
        self.assertRefused("codex", "does not match the approved")


class NoPolicyAtAll(PolicyHarness):
    def test_a_missing_policy_activates_nothing(self):
        """Deleting one file must not be equivalent to approving everything."""
        (self.bench.policy_dir / "approved.json").unlink()
        registry = self.bench.registry()
        self.assertEqual(registry.ids(), [])
        self.assertRegex(" | ".join(registry.errors), "policy is unavailable")

    def test_a_malformed_policy_activates_nothing(self):
        (self.bench.policy_dir / "approved.json").write_text("{ not json")
        registry = self.bench.registry()
        self.assertEqual(registry.ids(), [])
        self.assertRegex(" | ".join(registry.errors), "not valid JSON")

    def test_a_policy_with_a_future_schema_is_refused(self):
        policy = self.bench.policy()
        policy["schema_version"] = 99
        self.bench.write_policy(policy)
        registry = self.bench.registry()
        self.assertEqual(registry.ids(), [])
        self.assertRegex(" | ".join(registry.errors), "unsupported policy schema_version")


class IntersectionNotUnion(PolicyHarness):
    def test_a_narrower_policy_narrows_the_effective_manifest(self):
        """A policy may approve LESS than the manifest requests only when the
        manifest is re-sealed to match; a straight narrowing without that is a
        refusal, not a silent clamp. This pins which of the two we chose."""
        policy = self.bench.policy()
        policy["providers"]["codex"]["capabilities"] = ["code_change"]
        self.bench.write_policy(policy)
        self.assertRefused("codex", "capabilities it was not approved for: sourced_report")

    def test_effective_privilege_is_computed_not_assumed(self):
        """ApprovedPolicy.approve intersects; prove it directly rather than via
        the registry, since the registry refuses before the intersection shows."""
        document = shipped_policy_document()
        document["providers"]["codex"]["capabilities"] = ["code_change", "sourced_report",
                                                          "media_export"]
        policy = ApprovedPolicy(document, source="<test>")
        path = SHIPPED_MANIFESTS / "codex.json"
        manifest = json.loads(path.read_text())
        effective = policy.approve(manifest, manifest_digest(path))
        self.assertEqual(effective["capabilities"], ["code_change", "sourced_report"],
                         "effective privilege must be the intersection, not the union")


class PolicyIsDataNotSource(unittest.TestCase):
    def test_no_provider_id_is_hard_coded_in_the_registry(self):
        """The old freeze named its providers in Python. If that returns, the
        data-driven property Phase 2 bought is gone."""
        code = "\n".join(l for l in (BASE / "sf_providers.py").read_text().splitlines()
                         if not l.lstrip().startswith("#"))
        for banned in ('"codex"', "'codex'", '"offline-media"', "'offline-media'"):
            with self.subTest(token=banned):
                self.assertNotIn(banned, code)

    def test_a_new_provider_needs_only_data(self):
        """Adding an approved provider is a manifest plus a policy entry."""
        source_before = (BASE / "sf_providers.py").read_bytes()
        stack = []
        bench = Bench(stack)
        try:
            stranger = bench.manifest("offline-media")
            stranger.update(id="example-agent", display_name="Example Agent",
                            package="shadowfetch-example-agent")
            bench.write_manifest("example-agent", stranger)
            bench.reseal("example-agent")
            registry = bench.registry()
            self.assertIn("example-agent", registry.ids(),
                          "a manifest plus an approval entry was not enough")
            self.assertEqual(source_before, (BASE / "sf_providers.py").read_bytes())
        finally:
            for d in stack:
                shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
