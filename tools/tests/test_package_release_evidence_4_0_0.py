import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys
import tarfile
import tempfile
import unittest

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))
spec = importlib.util.spec_from_file_location("bundle4", TOOLS / "package_release_evidence_4_0_0.py")
bundle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bundle)


def digest(data):
    return hashlib.sha256(data).hexdigest()


class EvidenceBundleTests(unittest.TestCase):
    def fixture(self, root):
        def write(name, data):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        for name in bundle.QA_SOURCES:
            write(name, ("fixture " + name).encode())
        write("candidate.iso", b"test ISO")
        write("candidate.iso.asc", b"test signature")
        write("work/qa-4.0.0/evidence/real.log", b"actual fixture evidence")
        write("work/private/API Keys.txt", b"UNREFERENCED SECRET MUST NOT ENTER BUNDLE")
        artifact = {"iso_path": "candidate.iso", "iso_sha256": digest(b"test ISO"),
                    "iso_size_bytes": 8, "signature_path": "candidate.iso.asc", "signing_fingerprint": "A" * 40}
        manifest = {"schema_version": 1, "release": {"version": "4.0.0", "edition": "Fire and Ice", "codename": "Umbra"},
                    "evidence_root": "work/qa-4.0.0/evidence", "artifact": artifact,
                    "cases": [{"id": "SRC-01", "phase": "prepublish", "required": True, "status": "pass", "evidence": [{"kind": "log", "path": "real.log", "sha256": digest(b"actual fixture evidence")}]},
                              {"id": "EVIDENCE-01", "phase": "prepublish", "required": True, "status": "pending", "evidence": []},
                              {"id": "PUB-01", "phase": "postpublish", "required": True, "status": "pending", "evidence": []}]}
        write("qa/4.0.0/acceptance.json", json.dumps(manifest).encode())
        checksums = []
        for name in bundle.GENERATED:
            data = json.dumps({"publicationStatus": "prepublication", "iso": artifact}).encode() if name.startswith("release-facts-") else name.encode()
            write("work/release-4.0.0/" + name, data)
            checksums.append(f"{digest(data)}  {name}\n")
        write("work/release-4.0.0/" + bundle.CHECKSUMS, "".join(checksums).encode())
        write("approved.json", json.dumps({"schema_version": 1, "screenshots": [], "documents": []}).encode())
        (root / "second-output").mkdir()
        return manifest

    def test_reproducible_sorted_bundle_matches_contents_and_leaves_acceptance(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.fixture(root)
            before = (root / "qa/4.0.0/acceptance.json").read_bytes()
            first = bundle.package(root, "work/release-4.0.0", "approved.json")
            second = bundle.package(root, "second-output", "approved.json")
            self.assertEqual(first["sha256"], second["sha256"])
            self.assertEqual(before, (root / "qa/4.0.0/acceptance.json").read_bytes())
            with tarfile.open(first["bundle"]) as tar:
                names = tar.getnames()
                self.assertEqual(sorted(names), names)
                self.assertFalse(any("API Keys" in name for name in names))
                expected = []
                for member in tar:
                    self.assertEqual((0, 0, 0), (member.uid, member.gid, member.mtime))
                    expected.append(f"{digest(tar.extractfile(member).read())}  {member.name}\n")
                self.assertEqual("".join(expected), Path(first["contents"]).read_text())

    def test_tampered_reference_and_pending_gate_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manifest = self.fixture(root)
            (root / "work/qa-4.0.0/evidence/real.log").write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "SHA256 mismatch"):
                bundle.package(root, "work/release-4.0.0", "approved.json")
            manifest["cases"][0]["status"] = "pending"
            (root / "qa/4.0.0/acceptance.json").write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "has not passed"):
                bundle.package(root, "work/release-4.0.0", "approved.json")
            self.assertFalse((root / "work/release-4.0.0" / bundle.BUNDLE).exists())

    def test_symlink_parent_escape_and_self_hash_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manifest = self.fixture(root)
            evidence = root / "work/qa-4.0.0/evidence"
            (evidence / "alias").symlink_to(evidence, target_is_directory=True)
            for path in ("alias/real.log", "../evidence/real.log", "/etc/passwd"):
                manifest["cases"][0]["evidence"][0]["path"] = path
                (root / "qa/4.0.0/acceptance.json").write_text(json.dumps(manifest))
                with self.assertRaises(ValueError):
                    bundle.package(root, "work/release-4.0.0", "approved.json")
            manifest["artifact"]["evidence_bundle_sha256"] = "1" * 64
            (root / "qa/4.0.0/acceptance.json").write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "Circular bundle digest"):
                bundle.package(root, "work/release-4.0.0", "approved.json")

    def test_screenshot_requires_exact_approved_digest(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manifest = self.fixture(root)
            # Header fixture tests approval binding; real capture quality is reviewed externally.
            png = b"\x89PNG\r\n\x1a\n" + b"\0\0\0\rIHDR" + struct.pack(">II", 1920, 1080)
            (root / "work/qa-4.0.0/evidence/capture.png").write_bytes(png)
            manifest["cases"][0]["evidence"].append({"kind": "screenshot", "path": "capture.png", "sha256": digest(png)})
            (root / "qa/4.0.0/acceptance.json").write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "not been explicitly approved"):
                bundle.package(root, "work/release-4.0.0", "approved.json")
            (root / "approved.json").write_text(json.dumps({"schema_version": 1, "screenshots": [{"path": "capture.png", "sha256": digest(png), "approved": True}], "documents": []}))
            result = bundle.package(root, "work/release-4.0.0", "approved.json")
            self.assertGreater(result["members"], 0)


if __name__ == "__main__":
    unittest.main()
