import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock

spec = importlib.util.spec_from_file_location("publisher4", Path(__file__).resolve().parents[1] / "publish_release_4_0_0.py")
publisher = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = publisher
spec.loader.exec_module(publisher)

class PublisherTests(unittest.TestCase):
    def test_different_immutable_object_is_never_overwritten(self):
        item = publisher.Object(Path("candidate"), "apt/pool/existing.deb", "a" * 64, 100)
        client = Mock()
        client.head_object.return_value = {"ContentLength": 200}
        with self.assertRaisesRegex(ValueError, "Refusing to replace"):
            publisher.existing_matches(client, item)
        client.upload_file.assert_not_called()
        client.delete_object.assert_not_called()

    def test_auth_failure_is_not_treated_as_missing_object(self):
        class Denied(Exception):
            response = {"Error": {"Code": "403"}}
        client = Mock()
        client.head_object.side_effect = Denied()
        with self.assertRaises(Denied):
            publisher.existing_matches(client, publisher.Object(Path("candidate"), "releases/image.iso", "a" * 64, 100))

    def test_plan_rejects_wrong_iso_before_network(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / publisher.ISO).write_bytes(b"different image")
            (root / "qa/4.0.0").mkdir(parents=True)
            (root / "qa/4.0.0/acceptance.json").write_text(json.dumps({"artifact": {"iso_sha256": "0" * 64, "iso_size_bytes": 15}}))
            with self.assertRaisesRegex(ValueError, "ISO differs"):
                publisher.publication_plan(root)

    def test_plan_publishes_all_artifacts_before_signed_apt_switch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = [publisher.ISO, publisher.ISO + ".asc", publisher.ISO + ".sha256", "repo/shadowfetch.gpg.asc", "repo/pool/main/test.deb", "repo/dists/umbra/main/binary-amd64/Packages", "repo/dists/umbra/Release.gpg", "repo/dists/umbra/Release", "repo/dists/umbra/InRelease"]
            paths += ["work/release-4.0.0/" + name for name in publisher.EVIDENCE]
            for name in paths:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(name.encode())
            (root / "qa/4.0.0").mkdir(parents=True)
            artifact = {"iso_sha256": publisher.digest(root / publisher.ISO), "iso_size_bytes": (root / publisher.ISO).stat().st_size, "evidence_bundle_sha256": publisher.digest(root / "work/release-4.0.0/evidence-bundle-4.0.0.tar.gz")}
            (root / "qa/4.0.0/acceptance.json").write_text(json.dumps({"artifact": artifact}))
            plan = publisher.publication_plan(root)
            self.assertEqual("apt/dists/umbra/InRelease", plan[-1].key)
            self.assertTrue(all(not item.mutable for item in plan if item.key.startswith(("releases/", "apt/pool/"))))
