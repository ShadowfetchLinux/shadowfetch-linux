"""The current-release pointer, written by the publisher that produces it.

The reader was built, tested and shipped first, and the pointer it reads was
written by nobody: `/linux/releases.json` therefore answered "which release is
live" by listing the bucket and guessing, which promoted any re-uploaded old
image. These tests are about the WRITER -- that the document it produces is one
the reader accepts, that it describes the ISO on disk rather than a manifest,
and that running the publisher twice does not rewrite the one mutable object
every reader consults.
"""
import hashlib
import importlib.machinery
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

_loader = importlib.machinery.SourceFileLoader(
    "publish_release_under_test", str(ROOT / "tools/publish_release_4_0_0.py"))
_spec = importlib.util.spec_from_loader(_loader.name, _loader)
publisher = importlib.util.module_from_spec(_spec)
# Registered BEFORE exec: @dataclass resolves its annotations through
# sys.modules[cls.__module__], and a module that is not there yet makes the
# decorator fail on a file that imports perfectly well by itself.
sys.modules[_loader.name] = publisher
_loader.exec_module(publisher)

import release_pointer  # noqa: E402  (the publisher put its directory on sys.path)


class PointerWriter(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.iso_path = self.root / publisher.ISO
        self.iso_path.write_bytes(b"not really an image, but real bytes")
        os.utime(self.iso_path, (1_700_000_000, 1_700_000_000))
        self.iso = publisher.object_for(self.iso_path, "releases/" + publisher.ISO)

    def test_the_document_is_one_the_reader_accepts(self):
        item = publisher.pointer_object(self.root, self.iso)
        document = json.loads(item.path.read_text())
        # validate() raises on anything it will not serve.
        self.assertEqual(release_pointer.validate(document), document)
        self.assertEqual(item.key, "releases/CURRENT.json")
        self.assertTrue(item.mutable, "the pointer must be replaceable")

    def test_it_describes_the_iso_on_disk_and_not_a_manifest(self):
        item = publisher.pointer_object(self.root, self.iso)
        document = json.loads(item.path.read_text())
        digest = hashlib.sha256(self.iso_path.read_bytes()).hexdigest()
        self.assertEqual(document["iso"]["sha256"], digest)
        self.assertEqual(document["iso"]["size_bytes"],
                         self.iso_path.stat().st_size)
        self.assertEqual(document["iso"]["filename"], publisher.ISO)
        self.assertEqual(document["signing_key_fingerprint"],
                         publisher.FINGERPRINT)

    def test_running_the_publisher_twice_rewrites_nothing(self):
        """A default of "now" would mutate the one object every reader consults
        on every run, including a re-run that uploaded nothing."""
        first = publisher.pointer_object(self.root, self.iso).sha256
        second = publisher.pointer_object(self.root, self.iso).sha256
        self.assertEqual(first, second)

    def test_a_stated_publication_moment_wins(self):
        item = publisher.pointer_object(self.root, self.iso, "2026-09-09T12:00:00Z")
        self.assertEqual(json.loads(item.path.read_text())["published"],
                         "2026-09-09T12:00:00Z")

    def test_the_pointer_is_written_after_the_bytes_are_proven(self):
        """Order is the whole control: a pointer written before the ISO
        advertises, for the length of an upload, an image the bucket does not
        hold. The upload happens after the streamed-back digest check."""
        source = (ROOT / "tools/publish_release_4_0_0.py").read_text()
        verified = source.index("R2_RELEASE_BYTES_VERIFIED")
        written = source.index("R2_CURRENT_POINTER_WRITTEN")
        self.assertLess(verified, written)


if __name__ == "__main__":
    unittest.main(verbosity=2)
