#!/usr/bin/env python3

import json
from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import contextlib
import io
import tempfile
from unittest import mock

import r2_prune_release
from r2_prune_release import (
    binary_pool_keys,
    obsolete_release_objects,
    protected_release_keys,
    release_iso_key,
    source_pool_keys,
)


class ReleaseIndexTests(unittest.TestCase):
    def test_binary_pool_keys(self) -> None:
        packages = """Package: shadowfetch-meta
Filename: pool/main/s/shadowfetch-meta/shadowfetch-meta_2.1.4-1_all.deb
"""
        self.assertEqual(
            binary_pool_keys(packages),
            {
                "apt/pool/main/s/shadowfetch-meta/"
                "shadowfetch-meta_2.1.4-1_all.deb"
            },
        )

    def test_source_pool_keys(self) -> None:
        sources = """Package: shadowfetch-meta
Directory: pool/main/s/shadowfetch-meta
Files:
 abc123 100 shadowfetch-meta_2.1.4-1.dsc
 def456 200 shadowfetch-meta_2.1.4.orig.tar.xz
 ghi789 300 shadowfetch-meta_2.1.4-1.debian.tar.xz
Checksums-Sha256:
 111aaa 100 shadowfetch-meta_2.1.4-1.dsc
"""
        self.assertEqual(
            source_pool_keys(sources),
            {
                "apt/pool/main/s/shadowfetch-meta/"
                "shadowfetch-meta_2.1.4-1.dsc",
                "apt/pool/main/s/shadowfetch-meta/"
                "shadowfetch-meta_2.1.4.orig.tar.xz",
                "apt/pool/main/s/shadowfetch-meta/"
                "shadowfetch-meta_2.1.4-1.debian.tar.xz",
            },
        )


# --- W-07: pruning must never be able to destroy the whole release history ---

PACKAGES = (
    "Package: shadowfetch-meta\n"
    "Filename: pool/main/s/shadowfetch-meta/shadowfetch-meta_4.0.0-1_all.deb\n"
)
SOURCES = (
    "Package: shadowfetch-meta\n"
    "Directory: pool/main/s/shadowfetch-meta\n"
    "Files:\n"
    " abc123 100 shadowfetch-meta_4.0.0-1.dsc\n"
)

RELEASE_OBJECTS = [
    {"Key": "releases/shadowfetch-2.1.1-amd64.iso", "Size": 3_000_000_000},
    {"Key": "releases/shadowfetch-2.1.1-amd64.iso.asc", "Size": 833},
    {"Key": "releases/shadowfetch-2.1.1-amd64.iso.sha256", "Size": 96},
    {"Key": "releases/shadowfetch-4.0.0-amd64.iso", "Size": 3_400_000_000},
    {"Key": "releases/shadowfetch-4.0.0-amd64.iso.asc", "Size": 833},
    {"Key": "releases/shadowfetch-4.0.0-amd64.iso.sha256", "Size": 96},
]
POOL_OBJECTS = [
    {
        "Key": "apt/pool/main/s/shadowfetch-meta/shadowfetch-meta_2.1.1-1_all.deb",
        "Size": 900,
    },
    {
        "Key": "apt/pool/main/s/shadowfetch-meta/shadowfetch-meta_4.0.0-1_all.deb",
        "Size": 1000,
    },
    {
        "Key": "apt/pool/main/s/shadowfetch-meta/shadowfetch-meta_4.0.0-1.dsc",
        "Size": 100,
    },
]
BUCKET = RELEASE_OBJECTS + POOL_OBJECTS

# What a correct `--version 4.0.0` prune has always removed, and must keep removing.
EXPECTED_OBSOLETE = [
    "apt/pool/main/s/shadowfetch-meta/shadowfetch-meta_2.1.1-1_all.deb",
    "releases/shadowfetch-2.1.1-amd64.iso",
    "releases/shadowfetch-2.1.1-amd64.iso.asc",
    "releases/shadowfetch-2.1.1-amd64.iso.sha256",
]


def legacy_obsolete_release_objects(objects: list[dict], version: str) -> list[dict]:
    """The pre-hardening selection, copied verbatim, to pin the original defect.

    Original code:
        release_prefix = f"releases/shadowfetch-{args.version}-amd64.iso"
        obsolete = [item for item in list_prefix(client, args.bucket, "releases/")
                    if not item["Key"].startswith(release_prefix)]
    """
    release_prefix = f"releases/shadowfetch-{version}-amd64.iso"
    return [item for item in objects if not item["Key"].startswith(release_prefix)]


class FakeBody:
    def __init__(self, text: str) -> None:
        self._text = text

    def read(self) -> bytes:
        return self._text.encode("utf-8")


class FakePaginator:
    def __init__(self, objects: list[dict]) -> None:
        self._objects = objects

    def paginate(self, Bucket, Prefix):  # noqa: N803 - mirrors boto3 kwargs
        yield {
            "Contents": [
                item for item in self._objects if item["Key"].startswith(Prefix)
            ]
        }


class FakeS3Client:
    """Stands in for the boto3 S3 client. Records deletes; never issues one."""

    def __init__(self, objects: list[dict]) -> None:
        self.objects = list(objects)
        self.deleted: list[str] = []
        self._blobs = {
            "apt/dists/umbra/main/binary-amd64/Packages": PACKAGES,
            "apt/dists/umbra/main/source/Sources": SOURCES,
        }

    def get_object(self, Bucket, Key):  # noqa: N803 - mirrors boto3 kwargs
        return {"Body": FakeBody(self._blobs[Key])}

    def get_paginator(self, name):
        assert name == "list_objects_v2"
        return FakePaginator(self.objects)

    def delete_objects(self, Bucket, Delete):  # noqa: N803 - mirrors boto3 kwargs
        self.deleted.extend(entry["Key"] for entry in Delete["Objects"])
        return {"Deleted": Delete["Objects"]}


class ObsoleteReleaseSelectionTests(unittest.TestCase):
    def test_legacy_logic_deleted_every_release_on_a_malformed_version(self) -> None:
        """The defect: an unmatched keep-prefix made the whole bucket obsolete."""
        for typo in ("4.0.O", "", " 4.0.0", "v4.0.0", "4.0", "4.0.0-amd64"):
            with self.subTest(version=typo):
                legacy = legacy_obsolete_release_objects(RELEASE_OBJECTS, typo)
                self.assertEqual(
                    [item["Key"] for item in legacy],
                    [item["Key"] for item in RELEASE_OBJECTS],
                    "old code selected every release object for deletion",
                )
                with self.assertRaises(ValueError):
                    obsolete_release_objects(RELEASE_OBJECTS, typo)

    def test_legacy_logic_deleted_everything_for_an_absent_version(self) -> None:
        """A well-formed but wrong version (4.0.1 for 4.0.0) was equally fatal."""
        legacy = legacy_obsolete_release_objects(RELEASE_OBJECTS, "4.0.1")
        self.assertEqual(len(legacy), len(RELEASE_OBJECTS))
        with self.assertRaises(RuntimeError) as caught:
            obsolete_release_objects(RELEASE_OBJECTS, "4.0.1")
        self.assertIn("is not present in the bucket", str(caught.exception))

    def test_release_iso_key_shape(self) -> None:
        self.assertEqual(
            release_iso_key("4.0.0"), "releases/shadowfetch-4.0.0-amd64.iso"
        )
        for bad in ("", "4.0", "4.0.0.1", "v4.0.0", "4.0.0 ", "latest", None):
            with self.subTest(version=bad):
                with self.assertRaises(ValueError):
                    release_iso_key(bad)

    def test_keeps_the_named_release_and_its_sidecars(self) -> None:
        obsolete = obsolete_release_objects(RELEASE_OBJECTS, "4.0.0")
        self.assertEqual(
            sorted(item["Key"] for item in obsolete),
            [
                "releases/shadowfetch-2.1.1-amd64.iso",
                "releases/shadowfetch-2.1.1-amd64.iso.asc",
                "releases/shadowfetch-2.1.1-amd64.iso.sha256",
            ],
        )
        selected = {item["Key"] for item in obsolete}
        self.assertFalse(
            selected & protected_release_keys("releases/shadowfetch-4.0.0-amd64.iso")
        )


class PruneCommandTests(unittest.TestCase):
    def setUp(self) -> None:
        handle = tempfile.NamedTemporaryFile(
            "w", suffix=".token", delete=False, encoding="utf-8"
        )
        handle.write("fake-cloudflare-token\n")
        handle.close()
        self.token_path = handle.name
        self.addCleanup(Path(self.token_path).unlink)

    def run_cli(self, extra_argv: list[str], objects: list[dict] | None = None):
        client = FakeS3Client(BUCKET if objects is None else objects)
        argv = [
            "r2_prune_release.py",
            "--token-file",
            self.token_path,
            "--endpoint",
            "https://r2.example.invalid",
            "--bucket",
            "test-bucket",
        ] + extra_argv
        out, err = io.StringIO(), io.StringIO()
        error: BaseException | None = None
        status = None
        with mock.patch.object(r2_prune_release, "boto3") as boto3_stub, mock.patch.object(
            r2_prune_release, "token_id", return_value="fake-id"
        ), mock.patch.object(sys, "argv", argv), contextlib.redirect_stdout(
            out
        ), contextlib.redirect_stderr(
            err
        ):
            boto3_stub.client.return_value = client
            try:
                status = r2_prune_release.main()
            except BaseException as exc:  # SystemExit from argparse, RuntimeError guards
                error = exc
        return client, out.getvalue(), err.getvalue(), status, error

    @staticmethod
    def delete_lines(output: str) -> list[str]:
        return [line for line in output.splitlines() if line.startswith("DELETE ")]

    @staticmethod
    def preview_lines(output: str) -> list[str]:
        return [line for line in output.splitlines() if line.startswith("WOULD_DELETE ")]

    def test_typo_version_refuses_before_touching_the_bucket(self) -> None:
        client, out, err, _status, error = self.run_cli(
            ["--version", "4.0.O", "--apply"]
        )
        self.assertIsInstance(error, SystemExit)
        self.assertEqual(error.code, 2)
        self.assertIn("semantic version", err)
        self.assertEqual(client.deleted, [])
        self.assertEqual(self.delete_lines(out), [])

    def test_empty_version_refuses(self) -> None:
        client, out, _err, _status, error = self.run_cli(["--version", "", "--apply"])
        self.assertIsInstance(error, SystemExit)
        self.assertEqual(client.deleted, [])
        self.assertEqual(self.delete_lines(out), [])

    def test_absent_release_refuses_to_delete_anything(self) -> None:
        client, out, _err, _status, error = self.run_cli(
            ["--version", "9.9.9", "--apply"]
        )
        self.assertIsInstance(error, RuntimeError)
        self.assertIn("is not present in the bucket", str(error))
        self.assertEqual(client.deleted, [])
        self.assertEqual(self.delete_lines(out), [])

    def test_max_deletes_bound_aborts_and_still_previews(self) -> None:
        client, out, _err, _status, error = self.run_cli(
            ["--version", "4.0.0", "--apply", "--max-deletes", "2"]
        )
        self.assertIsInstance(error, RuntimeError)
        self.assertIn("--max-deletes=2", str(error))
        self.assertEqual(client.deleted, [])
        self.assertEqual(self.delete_lines(out), [])
        self.assertEqual(len(self.preview_lines(out)), len(EXPECTED_OBSOLETE))

    def test_apply_and_dry_run_are_mutually_exclusive(self) -> None:
        client, _out, _err, _status, error = self.run_cli(
            ["--version", "4.0.0", "--apply", "--dry-run"]
        )
        self.assertIsInstance(error, SystemExit)
        self.assertEqual(client.deleted, [])

    def test_dry_run_previews_without_deleting(self) -> None:
        client, out, _err, status, error = self.run_cli(["--version", "4.0.0"])
        self.assertIsNone(error)
        self.assertEqual(status, 0)
        self.assertEqual(client.deleted, [])
        self.assertEqual(
            sorted(line.split(" ", 1)[1] for line in self.preview_lines(out)),
            EXPECTED_OBSOLETE,
        )
        summary = json.loads(out.splitlines()[0])
        self.assertEqual(summary["kept_release"], "releases/shadowfetch-4.0.0-amd64.iso")
        self.assertFalse(summary["over_max_deletes"])

    def test_correct_invocation_still_prunes_the_genuinely_obsolete(self) -> None:
        """Invariant: a real, present version prunes exactly what it pruned before."""
        client, out, _err, status, error = self.run_cli(
            ["--version", "4.0.0", "--apply"]
        )
        self.assertIsNone(error)
        self.assertEqual(status, 0)
        self.assertEqual(sorted(client.deleted), EXPECTED_OBSOLETE)
        self.assertEqual(len(self.delete_lines(out)), len(EXPECTED_OBSOLETE))
        for kept in (
            "releases/shadowfetch-4.0.0-amd64.iso",
            "releases/shadowfetch-4.0.0-amd64.iso.asc",
            "releases/shadowfetch-4.0.0-amd64.iso.sha256",
            "apt/pool/main/s/shadowfetch-meta/shadowfetch-meta_4.0.0-1_all.deb",
            "apt/pool/main/s/shadowfetch-meta/shadowfetch-meta_4.0.0-1.dsc",
        ):
            self.assertNotIn(kept, client.deleted)


if __name__ == "__main__":
    unittest.main()
