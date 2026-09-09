#!/usr/bin/env python3
"""The ad-hoc uploader is the other program that can destroy a published artifact.

It cannot delete, but overwriting a published ISO, checksum or signature in place
is the same damage by another route: the bytes change while the published
SHA-256 does not. These tests pin what it refuses.
"""

import contextlib
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import r2_prune_release
import r2_s3_publish
from r2_s3_publish import check_key_allowed, check_overwrite_allowed, content_type, is_immutable

POLICY = r2_prune_release.load_policy()


class NotFound(Exception):
    response = {"Error": {"Code": "404"}}


class FakeS3Client:
    def __init__(self, existing=None) -> None:
        self.existing = dict(existing or {})
        self.uploaded = []

    def head_object(self, Bucket, Key):  # noqa: N803 - mirrors boto3 kwargs
        if Key not in self.existing:
            raise NotFound(Key)
        return self.existing[Key]

    def upload_file(self, filename, bucket, key, ExtraArgs=None, Config=None, Callback=None):  # noqa: N803
        body = Path(filename).read_bytes()
        self.uploaded.append((key, ExtraArgs))
        self.existing[key] = {
            "ContentLength": len(body),
            "Metadata": dict((ExtraArgs or {}).get("Metadata", {})),
        }

    def list_multipart_uploads(self, **kwargs):
        return {"Uploads": [], "IsTruncated": False}


class KeyPolicyTests(unittest.TestCase):
    def test_release_artifacts_are_immutable(self) -> None:
        for key in (
            "releases/shadowfetch-4.0.0-amd64.iso",
            "releases/shadowfetch-4.0.0-amd64.iso.sha256",
            "releases/shadowfetch-4.0.0-amd64.iso.asc",
        ):
            self.assertTrue(is_immutable(key), key)
        for key in ("apt/dists/umbra/InRelease", "assets/logo.png", "releases/CURRENT.json"):
            self.assertFalse(is_immutable(key), key)

    def test_the_pointer_is_never_writable_here(self) -> None:
        with self.assertRaises(RuntimeError) as caught:
            check_key_allowed("releases/CURRENT.json", POLICY)
        self.assertIn("gated publisher", str(caught.exception))

    def test_a_retired_image_url_cannot_be_re_armed(self) -> None:
        with self.assertRaises(RuntimeError) as caught:
            check_key_allowed("releases/shadowfetch-2.1.1-amd64.iso", POLICY)
        self.assertIn("410", str(caught.exception))

    def test_key_traversal_is_refused(self) -> None:
        for key in ("/releases/x.iso", "releases/../secret"):
            with self.subTest(key=key):
                with self.assertRaises(RuntimeError):
                    check_key_allowed(key, POLICY)

    def test_a_current_release_key_is_allowed(self) -> None:
        check_key_allowed("releases/shadowfetch-4.0.0-amd64.iso", POLICY)
        check_key_allowed("apt/dists/umbra/InRelease", POLICY)

    def test_content_type_labels_the_public_key_as_a_key(self) -> None:
        self.assertEqual(content_type("shadowfetch.gpg.asc"), "application/pgp-keys")
        self.assertEqual(content_type("releases/x.iso"), "application/x-iso9660-image")
        self.assertEqual(content_type("releases/x.iso.asc"), "application/pgp-signature")


class OverwriteTests(unittest.TestCase):
    def test_an_existing_immutable_artifact_is_never_replaced(self) -> None:
        client = FakeS3Client({"releases/shadowfetch-4.0.0-amd64.iso": {"ContentLength": 10}})
        for replace in (False, True):
            with self.subTest(replace=replace):
                with self.assertRaises(RuntimeError) as caught:
                    check_overwrite_allowed(client, "b", "releases/shadowfetch-4.0.0-amd64.iso", replace)
                self.assertIn("immutable", str(caught.exception))

    def test_a_mutable_object_needs_replace(self) -> None:
        client = FakeS3Client({"apt/dists/umbra/InRelease": {"ContentLength": 10}})
        with self.assertRaises(RuntimeError):
            check_overwrite_allowed(client, "b", "apt/dists/umbra/InRelease", False)
        check_overwrite_allowed(client, "b", "apt/dists/umbra/InRelease", True)

    def test_a_new_key_is_allowed(self) -> None:
        check_overwrite_allowed(FakeS3Client(), "b", "releases/shadowfetch-4.0.0-amd64.iso", False)


class UploadTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.iso = Path(self.directory.name) / "shadowfetch-4.0.0-amd64.iso"
        self.iso.write_bytes(b"pretend-iso-bytes")
        self.digest = hashlib.sha256(self.iso.read_bytes()).hexdigest()
        token = Path(self.directory.name) / "token"
        token.write_text("fake-token\n")
        self.token = token

    def run_cli(self, key, extra=(), client=None):
        client = client or FakeS3Client()
        argv = [
            "r2_s3_publish.py", str(self.iso), key,
            "--token-file", str(self.token),
            "--endpoint", "https://r2.example.invalid",
            "--bucket", "test-bucket",
        ] + list(extra)
        out = io.StringIO()
        error = None
        status = None
        with mock.patch.object(r2_s3_publish, "boto3") as boto3_stub, mock.patch.object(
            r2_s3_publish, "token_id", return_value="fake-id"
        ), mock.patch.object(sys, "argv", argv), contextlib.redirect_stdout(out):
            boto3_stub.client.return_value = client
            try:
                status = r2_s3_publish.main()
            except BaseException as exc:
                error = exc
        return client, out.getvalue(), status, error

    def test_upload_stamps_the_real_digest_and_version(self) -> None:
        client, out, status, error = self.run_cli("releases/shadowfetch-4.0.0-amd64.iso")
        self.assertIsNone(error)
        self.assertEqual(status, 0)
        _key, extra = client.uploaded[0]
        self.assertEqual(extra["Metadata"]["sha256"], self.digest)
        self.assertEqual(extra["Metadata"]["release"], "4.0.0")
        self.assertNotEqual(extra["Metadata"]["release"], "1.9.0")
        self.assertEqual(json.loads(out.splitlines()[-1])["sha256"], self.digest)

    def test_upload_refuses_to_replace_a_published_iso(self) -> None:
        client = FakeS3Client({"releases/shadowfetch-4.0.0-amd64.iso": {"ContentLength": 99}})
        client, _out, _status, error = self.run_cli(
            "releases/shadowfetch-4.0.0-amd64.iso", ["--replace"], client
        )
        self.assertIsInstance(error, RuntimeError)
        self.assertEqual(client.uploaded, [])

    def test_upload_refuses_the_pointer_key(self) -> None:
        client, _out, _status, error = self.run_cli("releases/CURRENT.json")
        self.assertIsInstance(error, RuntimeError)
        self.assertEqual(client.uploaded, [])


if __name__ == "__main__":
    unittest.main()
