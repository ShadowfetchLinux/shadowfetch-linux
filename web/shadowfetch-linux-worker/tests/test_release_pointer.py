#!/usr/bin/env python3
"""releases/CURRENT.json is the answer to "which release is live". Validate it hard.

Whatever this document says becomes the download the world is offered, and the
release a prune run is allowed to keep. Every field that decides either of those
is checked, and the Worker's own validator (src/index.js, pointerProblem) is
tested against the same cases in tests/worker.test.mjs so the two cannot drift.
"""

import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import release_pointer

FINGERPRINT = "8F13CE1535EE1F4A2916A1F73C5C900B7BE80CA1"
DIGEST = "b" * 64

GOOD = {
    "schema": "shadowfetch.linux-current.v1",
    "version": "4.0.0",
    "published": "2026-09-06T00:00:00Z",
    "iso": {
        "filename": "shadowfetch-4.0.0-amd64.iso",
        "key": "releases/shadowfetch-4.0.0-amd64.iso",
        "size_bytes": 3_400_000_000,
        "sha256": DIGEST,
    },
    "sidecars": {
        "sha256": "releases/shadowfetch-4.0.0-amd64.iso.sha256",
        "signature": "releases/shadowfetch-4.0.0-amd64.iso.asc",
    },
    "signing_key_fingerprint": FINGERPRINT,
}


def mutate(**changes):
    document = json.loads(json.dumps(GOOD))
    for path, value in changes.items():
        target = document
        parts = path.split(".")
        for part in parts[:-1]:
            target = target[part]
        if value is release_pointer:  # sentinel: delete the field
            target.pop(parts[-1], None)
        else:
            target[parts[-1]] = value
    return document


DELETE = release_pointer


class ValidationTests(unittest.TestCase):
    def test_good_document_validates(self) -> None:
        self.assertEqual(release_pointer.problems(GOOD), [])
        self.assertIs(release_pointer.validate(GOOD), GOOD)

    def test_rejects_non_objects(self) -> None:
        for value in (None, [], "current", 3):
            with self.subTest(value=value):
                self.assertTrue(release_pointer.problems(value))

    def test_rejects_a_foreign_schema(self) -> None:
        self.assertTrue(any(
            "schema" in p for p in release_pointer.problems(mutate(schema="something.else.v1"))
        ))

    def test_rejects_a_version_that_is_not_semver(self) -> None:
        for bad in ("4.0", "v4.0.0", "4.0.0-rc1", "", 400):
            with self.subTest(version=bad):
                self.assertTrue(release_pointer.problems(mutate(version=bad)))

    def test_rejects_a_filename_that_does_not_match_the_version(self) -> None:
        """The trap this closes: a pointer that says 4.0.0 while naming the
        3.5.0 image would hand out 3.5.0 bytes as the current release."""
        document = mutate(**{
            "iso.filename": "shadowfetch-3.5.0-amd64.iso",
            "iso.key": "releases/shadowfetch-3.5.0-amd64.iso",
        })
        self.assertTrue(any("filename" in p for p in release_pointer.problems(document)))

    def test_rejects_a_key_outside_the_release_prefix(self) -> None:
        document = mutate(**{"iso.key": "shadowfetch-4.0.0-amd64.iso"})
        self.assertTrue(any("iso.key" in p for p in release_pointer.problems(document)))

    def test_rejects_bad_sizes(self) -> None:
        for bad in (0, -1, "3400000000", 3.5, True, DELETE):
            with self.subTest(size=bad):
                self.assertTrue(release_pointer.problems(mutate(**{"iso.size_bytes": bad})))

    def test_rejects_bad_digests(self) -> None:
        for bad in ("", DIGEST.upper(), DIGEST[:63], DIGEST + "c", "zz" * 32, DELETE):
            with self.subTest(sha256=bad):
                self.assertTrue(release_pointer.problems(mutate(**{"iso.sha256": bad})))

    def test_rejects_a_malformed_fingerprint(self) -> None:
        for bad in (FINGERPRINT.lower(), FINGERPRINT[:39], "", DELETE):
            with self.subTest(fingerprint=bad):
                self.assertTrue(
                    release_pointer.problems(mutate(signing_key_fingerprint=bad))
                )

    def test_reports_every_fault_at_once(self) -> None:
        document = mutate(version="4.0", **{"iso.sha256": "nope"})
        self.assertGreaterEqual(len(release_pointer.problems(document)), 2)

    def test_validate_raises_with_the_reasons(self) -> None:
        with self.assertRaises(ValueError) as caught:
            release_pointer.validate(mutate(schema="x"))
        self.assertIn("schema", str(caught.exception))


class BuildTests(unittest.TestCase):
    def test_build_reads_size_and_digest_from_the_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            iso = Path(directory) / "shadowfetch-4.0.0-amd64.iso"
            iso.write_bytes(b"not really an iso, but real bytes")
            document = release_pointer.build("4.0.0", iso, "2026-09-06T00:00:00Z", FINGERPRINT)
        self.assertEqual(document["iso"]["size_bytes"], 33)
        self.assertEqual(release_pointer.problems(document), [])
        self.assertEqual(document["iso"]["key"], "releases/shadowfetch-4.0.0-amd64.iso")

    def test_build_refuses_an_iso_that_is_not_the_named_version(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            iso = Path(directory) / "shadowfetch-3.5.0-amd64.iso"
            iso.write_bytes(b"x")
            with self.assertRaises(ValueError):
                release_pointer.build("4.0.0", iso, "2026-09-06T00:00:00Z", FINGERPRINT)

    def test_build_accepts_a_precomputed_digest_but_checks_its_shape(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            iso = Path(directory) / "shadowfetch-4.0.0-amd64.iso"
            iso.write_bytes(b"bytes")
            document = release_pointer.build(
                "4.0.0", iso, "2026-09-06T00:00:00Z", FINGERPRINT, sha256=DIGEST,
            )
            self.assertEqual(document["iso"]["sha256"], DIGEST)
            with self.assertRaises(ValueError):
                release_pointer.build(
                    "4.0.0", iso, "2026-09-06T00:00:00Z", FINGERPRINT, sha256="short",
                )

    def test_build_refuses_a_malformed_version(self) -> None:
        with self.assertRaises(ValueError):
            release_pointer.build("4.0", Path("/nonexistent"), "now", FINGERPRINT)


if __name__ == "__main__":
    unittest.main()
