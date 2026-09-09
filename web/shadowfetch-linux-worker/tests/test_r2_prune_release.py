#!/usr/bin/env python3
"""Adversarial tests for the one program that deletes published release artifacts.

Each class pins a way this tool could destroy something it must not:
  ReleaseIndexTests            the APT index parsing it prunes from
  ObsoleteReleaseSelectionTests  what may and may not enter the delete set
  PointerAgreementTests        pruning against a pointer that names another release
  PruneCommandTests            the CLI end to end against a fake bucket
"""

import contextlib
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
import release_pointer
from r2_prune_release import (
    binary_pool_keys,
    classify_release_objects,
    check_pointer_agreement,
    load_policy,
    obsolete_release_objects,
    protected_release_keys,
    release_iso_key,
    retired_index,
    source_pool_keys,
)

POLICY = load_policy()
FINGERPRINT = "8F13CE1535EE1F4A2916A1F73C5C900B7BE80CA1"
DIGEST = "a" * 64


class ReleaseIndexTests(unittest.TestCase):
    def test_binary_pool_keys(self) -> None:
        packages = """Package: shadowfetch-meta
Filename: pool/main/s/shadowfetch-meta/shadowfetch-meta_2.1.4-1_all.deb
"""
        self.assertEqual(
            binary_pool_keys(packages),
            {"apt/pool/main/s/shadowfetch-meta/shadowfetch-meta_2.1.4-1_all.deb"},
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
                "apt/pool/main/s/shadowfetch-meta/shadowfetch-meta_2.1.4-1.dsc",
                "apt/pool/main/s/shadowfetch-meta/shadowfetch-meta_2.1.4.orig.tar.xz",
                "apt/pool/main/s/shadowfetch-meta/shadowfetch-meta_2.1.4-1.debian.tar.xz",
            },
        )


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

POINTER = {
    "schema": release_pointer.SCHEMA,
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

# A bucket shaped like the real one: the current release and its published
# evidence, a retired release with its sidecars, an older release that is still
# served and has NOT been retired, and the pointer.
RELEASE_OBJECTS = [
    {"Key": "releases/CURRENT.json", "Size": 512},
    {"Key": "releases/shadowfetch-2.1.1-amd64.iso", "Size": 3_000_000_000},
    {"Key": "releases/shadowfetch-2.1.1-amd64.iso.asc", "Size": 833},
    {"Key": "releases/shadowfetch-2.1.1-amd64.iso.sha256", "Size": 96},
    {"Key": "releases/shadowfetch-3.5.0-amd64.iso", "Size": 3_200_000_000},
    {"Key": "releases/shadowfetch-3.5.0-amd64.iso.sha256", "Size": 96},
    {"Key": "releases/shadowfetch-4.0.0-amd64.iso", "Size": 3_400_000_000},
    {"Key": "releases/shadowfetch-4.0.0-amd64.iso.asc", "Size": 833},
    {"Key": "releases/shadowfetch-4.0.0-amd64.iso.sha256", "Size": 96},
    {"Key": "releases/dossier-4.0.0.md", "Size": 40_000},
    {"Key": "releases/evidence-bundle-4.0.0.tar.gz", "Size": 900_000},
    {"Key": "releases/sbom-4.0.0.cdx.json", "Size": 1_200_000},
]
POOL_OBJECTS = [
    {"Key": "apt/pool/main/s/shadowfetch-meta/shadowfetch-meta_2.1.1-1_all.deb", "Size": 900},
    {"Key": "apt/pool/main/s/shadowfetch-meta/shadowfetch-meta_4.0.0-1_all.deb", "Size": 1000},
    {"Key": "apt/pool/main/s/shadowfetch-meta/shadowfetch-meta_4.0.0-1.dsc", "Size": 100},
]
BUCKET = RELEASE_OBJECTS + POOL_OBJECTS

# The complete delete set for a correct `--version 4.0.0`: one retired ISO body
# and one unreferenced package. Nothing else in that bucket may be deleted.
EXPECTED_OBSOLETE = [
    "apt/pool/main/s/shadowfetch-meta/shadowfetch-meta_2.1.1-1_all.deb",
    "releases/shadowfetch-2.1.1-amd64.iso",
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


class NoSuchKey(Exception):
    response = {"Error": {"Code": "NoSuchKey"}}


class FakePaginator:
    def __init__(self, objects: list[dict]) -> None:
        self._objects = objects

    def paginate(self, Bucket, Prefix):  # noqa: N803 - mirrors boto3 kwargs
        yield {"Contents": [item for item in self._objects if item["Key"].startswith(Prefix)]}


class FakeS3Client:
    """Stands in for the boto3 S3 client. Records deletes; never issues one."""

    def __init__(self, objects: list[dict], pointer: object | None = POINTER) -> None:
        self.objects = list(objects)
        self.deleted: list[str] = []
        self._blobs = {
            "apt/dists/umbra/main/binary-amd64/Packages": PACKAGES,
            "apt/dists/umbra/main/source/Sources": SOURCES,
        }
        if pointer is not None:
            self._blobs[release_pointer.KEY] = json.dumps(pointer)

    def get_object(self, Bucket, Key):  # noqa: N803 - mirrors boto3 kwargs
        if Key not in self._blobs:
            raise NoSuchKey(Key)
        return {"Body": FakeBody(self._blobs[Key])}

    def get_paginator(self, name):
        assert name == "list_objects_v2"
        return FakePaginator(self.objects)

    def delete_objects(self, Bucket, Delete):  # noqa: N803 - mirrors boto3 kwargs
        self.deleted.extend(entry["Key"] for entry in Delete["Objects"])
        return {"Deleted": Delete["Objects"]}


class ObsoleteReleaseSelectionTests(unittest.TestCase):
    def selected(self, version="4.0.0", objects=None):
        return sorted(
            item["Key"]
            for item in obsolete_release_objects(objects or RELEASE_OBJECTS, version, POLICY)
        )

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
                    obsolete_release_objects(RELEASE_OBJECTS, typo, POLICY)

    def test_legacy_logic_deleted_everything_for_an_absent_version(self) -> None:
        """A well-formed but wrong version (4.0.1 for 4.0.0) was equally fatal."""
        legacy = legacy_obsolete_release_objects(RELEASE_OBJECTS, "4.0.1")
        self.assertEqual(len(legacy), len(RELEASE_OBJECTS))
        with self.assertRaises(RuntimeError) as caught:
            obsolete_release_objects(RELEASE_OBJECTS, "4.0.1", POLICY)
        self.assertIn("is not present in the bucket", str(caught.exception))

    def test_release_iso_key_shape(self) -> None:
        self.assertEqual(release_iso_key("4.0.0"), "releases/shadowfetch-4.0.0-amd64.iso")
        for bad in ("", "4.0", "4.0.0.1", "v4.0.0", "4.0.0 ", "latest", None):
            with self.subTest(version=bad):
                with self.assertRaises(ValueError):
                    release_iso_key(bad)

    def test_only_the_retired_body_is_deletable(self) -> None:
        self.assertEqual(self.selected(), ["releases/shadowfetch-2.1.1-amd64.iso"])

    def test_kept_release_and_its_sidecars_survive(self) -> None:
        selected = set(self.selected())
        self.assertFalse(
            selected & protected_release_keys("releases/shadowfetch-4.0.0-amd64.iso", POLICY)
        )

    def test_retired_sidecars_survive_because_the_410_page_offers_them(self) -> None:
        """SEC-PRUNE-04: the old keep-set deleted exactly the .sha256/.asc that
        the retirement page tells people to verify against. Live check on
        2026-09-09 found both 2.0.0 and 2.1.1 sidecars already 404."""
        selected = set(self.selected())
        for sidecar in (
            "releases/shadowfetch-2.1.1-amd64.iso.asc",
            "releases/shadowfetch-2.1.1-amd64.iso.sha256",
        ):
            self.assertNotIn(sidecar, selected)
        legacy = {item["Key"] for item in legacy_obsolete_release_objects(RELEASE_OBJECTS, "4.0.0")}
        self.assertLessEqual(
            {
                "releases/shadowfetch-2.1.1-amd64.iso.asc",
                "releases/shadowfetch-2.1.1-amd64.iso.sha256",
            },
            legacy,
            "the old rule did delete them; this test exists because of that",
        )

    def test_published_evidence_for_the_current_release_survives(self) -> None:
        """The dossier, SBOM and evidence bundle do not start with the ISO key,
        so the old rule deleted the current release's own evidence."""
        selected = set(self.selected())
        for evidence in (
            "releases/dossier-4.0.0.md",
            "releases/evidence-bundle-4.0.0.tar.gz",
            "releases/sbom-4.0.0.cdx.json",
        ):
            self.assertNotIn(evidence, selected)

    def test_an_iso_that_is_not_declared_retired_is_never_deleted(self) -> None:
        """3.5.0 still serves its bytes and is deliberately not in the policy."""
        self.assertNotIn("releases/shadowfetch-3.5.0-amd64.iso", self.selected())
        reasons = {
            d.key: d.reason
            for d in classify_release_objects(RELEASE_OBJECTS, "4.0.0", POLICY)
        }
        self.assertIn("not declared", reasons["releases/shadowfetch-3.5.0-amd64.iso"])

    def test_the_pointer_object_is_never_deletable(self) -> None:
        self.assertNotIn("releases/CURRENT.json", self.selected())

    def test_retain_sidecars_false_makes_a_sidecar_deletable(self) -> None:
        policy = json.loads(json.dumps(POLICY))
        for entry in policy["retired"]:
            if entry["version"] == "2.1.1":
                entry["retain_sidecars"] = False
        selected = {
            item["Key"]
            for item in obsolete_release_objects(RELEASE_OBJECTS, "4.0.0", policy)
        }
        self.assertIn("releases/shadowfetch-2.1.1-amd64.iso.sha256", selected)

    def test_every_policy_entry_maps_to_an_iso_name(self) -> None:
        index = retired_index(POLICY)
        self.assertEqual(len(index), len(POLICY["retired"]))
        self.assertIn("shadowfetch-2.0.0-amd64.iso", index)


class PointerAgreementTests(unittest.TestCase):
    def test_matching_pointer_is_accepted(self) -> None:
        check_pointer_agreement(POINTER, "4.0.0")

    def test_pointer_naming_another_release_aborts(self) -> None:
        other = json.loads(json.dumps(POINTER))
        other["version"] = "3.5.0"
        other["iso"]["filename"] = "shadowfetch-3.5.0-amd64.iso"
        other["iso"]["key"] = "releases/shadowfetch-3.5.0-amd64.iso"
        with self.assertRaises(RuntimeError) as caught:
            check_pointer_agreement(other, "4.0.0")
        self.assertIn("refusing to prune", str(caught.exception))

    def test_corrupt_pointer_aborts_rather_than_being_ignored(self) -> None:
        broken = json.loads(json.dumps(POINTER))
        broken["iso"]["sha256"] = "not-a-digest"
        with self.assertRaises(ValueError):
            check_pointer_agreement(broken, "4.0.0")


class PruneCommandTests(unittest.TestCase):
    def setUp(self) -> None:
        handle = tempfile.NamedTemporaryFile("w", suffix=".token", delete=False, encoding="utf-8")
        handle.write("fake-cloudflare-token\n")
        handle.close()
        self.token_path = handle.name
        self.addCleanup(Path(self.token_path).unlink)

    def run_cli(self, extra_argv, objects=None, pointer=POINTER):
        client = FakeS3Client(BUCKET if objects is None else objects, pointer)
        argv = [
            "r2_prune_release.py",
            "--token-file", self.token_path,
            "--endpoint", "https://r2.example.invalid",
            "--bucket", "test-bucket",
        ] + extra_argv
        out, err = io.StringIO(), io.StringIO()
        error = None
        status = None
        with mock.patch.object(r2_prune_release, "boto3") as boto3_stub, mock.patch.object(
            r2_prune_release, "token_id", return_value="fake-id"
        ), mock.patch.object(sys, "argv", argv), contextlib.redirect_stdout(
            out
        ), contextlib.redirect_stderr(err):
            boto3_stub.client.return_value = client
            try:
                status = r2_prune_release.main()
            except BaseException as exc:  # SystemExit from argparse, RuntimeError guards
                error = exc
        return client, out.getvalue(), err.getvalue(), status, error

    @staticmethod
    def delete_lines(output):
        return [line for line in output.splitlines() if line.startswith("DELETE ")]

    @staticmethod
    def preview_lines(output):
        return [line for line in output.splitlines() if line.startswith("WOULD_DELETE ")]

    def test_typo_version_refuses_before_touching_the_bucket(self) -> None:
        client, out, err, _status, error = self.run_cli(["--version", "4.0.O", "--apply"])
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
        pointer = json.loads(json.dumps(POINTER))
        pointer["version"] = "9.9.9"
        pointer["iso"]["filename"] = "shadowfetch-9.9.9-amd64.iso"
        pointer["iso"]["key"] = "releases/shadowfetch-9.9.9-amd64.iso"
        client, out, _err, _status, error = self.run_cli(
            ["--version", "9.9.9", "--apply"], pointer=pointer
        )
        self.assertIsInstance(error, RuntimeError)
        self.assertIn("is not present in the bucket", str(error))
        self.assertEqual(client.deleted, [])
        self.assertEqual(self.delete_lines(out), [])

    def test_pointer_disagreement_aborts_before_any_delete(self) -> None:
        pointer = json.loads(json.dumps(POINTER))
        pointer["version"] = "3.5.0"
        pointer["iso"]["filename"] = "shadowfetch-3.5.0-amd64.iso"
        pointer["iso"]["key"] = "releases/shadowfetch-3.5.0-amd64.iso"
        client, out, _err, _status, error = self.run_cli(
            ["--version", "4.0.0", "--apply"], pointer=pointer
        )
        self.assertIsInstance(error, RuntimeError)
        self.assertIn("names 3.5.0", str(error))
        self.assertEqual(client.deleted, [])
        self.assertEqual(self.delete_lines(out), [])

    def test_absent_pointer_still_prunes_and_says_so(self) -> None:
        """Buckets published before the pointer existed must remain prunable."""
        client, out, _err, status, error = self.run_cli(
            ["--version", "4.0.0", "--apply"],
            objects=[o for o in BUCKET if o["Key"] != "releases/CURRENT.json"],
            pointer=None,
        )
        self.assertIsNone(error)
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(out.splitlines()[0])["pointer"], "absent")
        self.assertEqual(sorted(client.deleted), EXPECTED_OBSOLETE)

    def test_max_deletes_bound_aborts_and_still_previews(self) -> None:
        client, out, _err, _status, error = self.run_cli(
            ["--version", "4.0.0", "--apply", "--max-deletes", "1"]
        )
        self.assertIsInstance(error, RuntimeError)
        self.assertIn("--max-deletes=1", str(error))
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
        self.assertEqual(summary["pointer"], "agrees")
        self.assertFalse(summary["over_max_deletes"])

    def test_apply_deletes_exactly_the_declared_obsolete(self) -> None:
        client, out, _err, status, error = self.run_cli(["--version", "4.0.0", "--apply"])
        self.assertIsNone(error)
        self.assertEqual(status, 0)
        self.assertEqual(sorted(client.deleted), EXPECTED_OBSOLETE)
        self.assertEqual(len(self.delete_lines(out)), len(EXPECTED_OBSOLETE))
        for kept in (
            "releases/CURRENT.json",
            "releases/shadowfetch-4.0.0-amd64.iso",
            "releases/shadowfetch-4.0.0-amd64.iso.asc",
            "releases/shadowfetch-4.0.0-amd64.iso.sha256",
            "releases/shadowfetch-2.1.1-amd64.iso.asc",
            "releases/shadowfetch-2.1.1-amd64.iso.sha256",
            "releases/shadowfetch-3.5.0-amd64.iso",
            "releases/dossier-4.0.0.md",
            "releases/evidence-bundle-4.0.0.tar.gz",
            "apt/pool/main/s/shadowfetch-meta/shadowfetch-meta_4.0.0-1_all.deb",
            "apt/pool/main/s/shadowfetch-meta/shadowfetch-meta_4.0.0-1.dsc",
        ):
            self.assertNotIn(kept, client.deleted)

    def test_retained_objects_are_reported(self) -> None:
        _client, out, _err, _status, _error = self.run_cli(["--version", "4.0.0"])
        retained = [line for line in out.splitlines() if line.startswith("RETAIN ")]
        self.assertTrue(any("CURRENT.json" in line for line in retained))
        self.assertTrue(any("2.1.1-amd64.iso.sha256" in line for line in retained))


if __name__ == "__main__":
    unittest.main()
