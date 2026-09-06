"""Source/package/ISO gates reject restored local-AI payload or false capabilities."""
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from mission_provider_contract import validate_provider_payload

SOURCE = (ROOT / 'packages/shadowfetch-missions/data/usr/lib/shadowfetch/missions/sf_missions.py').read_text()


class ProviderPayloadTests(unittest.TestCase):
    def test_coding_agents_and_container_tools_remain_supported(self):
        validate_provider_payload(['usr/bin/shadowfetch-grok-bot', 'usr/bin/shadowfetch-codex', 'usr/bin/podman', 'usr/libexec/shadowfetch-retire-local-ai'], SOURCE)

    def test_old_stack_components_fail_each_artifact_gate(self):
        for path in ('usr/bin/shadowfetch-buzz', 'usr/libexec/shadowfetch-buzz-stack', 'usr/lib/systemd/user/shadowfetch-buzz.service', 'usr/share/shadowfetch/buzz/compose.yml', 'usr/bin/shadowfetch-model-check', 'usr/lib/shadowfetch/missions/sf_local_compute.py', 'usr/share/shadowfetch/control-center/sfcc/local_model_card.py', 'usr/share/shadowfetch/ai-ignition/models.json'):
            with self.subTest(path=path), self.assertRaisesRegex(RuntimeError, 'payload remains'):
                validate_provider_payload([path], SOURCE)

    def test_unsupported_provider_or_network_claim_is_rejected(self):
        for source in (SOURCE.replace('"runtimes": {"offline":', '"runtimes": {"local":'), SOURCE.replace('"kinds": ["media"]', '"kinds": ["code", "media"]'), SOURCE.replace('"requires_network_approval": True', '"requires_network_approval": False')):
            with self.assertRaises(RuntimeError):
                validate_provider_payload([], source)


if __name__ == '__main__':
    unittest.main()
