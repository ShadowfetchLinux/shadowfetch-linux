#!/usr/bin/env python3
"""The retirement policy is one document with two consumers, and must stay that way.

policy/retirement.json is read by tools/r2_prune_release.py and mirrored into
src/retirement.js for the Worker. If those two drift, the 410 pages and the
delete set disagree -- which is exactly how the 2.0.0 and 2.1.1 checksum and
signature sidecars came to be deleted while their retirement pages went on
telling people to verify against them.
"""

import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import sync_retirement_policy as sync


class MirrorTests(unittest.TestCase):
    def test_mirror_matches_the_policy_exactly(self) -> None:
        policy = sync.load_policy()
        mirrored = sync.mirror_document(sync.MIRROR_PATH.read_text(encoding="utf-8"))
        self.assertEqual(
            mirrored, policy,
            "src/retirement.js has diverged; run tools/sync_retirement_policy.py --write",
        )

    def test_render_round_trips(self) -> None:
        policy = sync.load_policy()
        self.assertEqual(sync.mirror_document(sync.render(policy)), policy)

    def test_mirror_may_hold_the_policy_and_nothing_else(self) -> None:
        """A hand-added helper in the generated file is itself a divergence."""
        tampered = sync.render(sync.load_policy()) + "\nexport function retiredFor() {}\n"
        with self.assertRaises(Exception):
            sync.mirror_document(tampered)

    def test_missing_binding_is_reported(self) -> None:
        with self.assertRaises(ValueError):
            sync.mirror_document("// nothing here\n")


class PolicyContentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = sync.load_policy()
        self.versions = {entry["version"] for entry in self.policy["retired"]}

    def test_shipped_policy_validates(self) -> None:
        self.assertEqual(sync.validate(self.policy), [])

    def test_validation_catches_a_duplicate_declaration(self) -> None:
        policy = json.loads(json.dumps(self.policy))
        policy["retired"].append(dict(policy["retired"][0]))
        self.assertTrue(any("declared twice" in p for p in sync.validate(policy)))

    def test_validation_catches_an_unknown_status(self) -> None:
        policy = json.loads(json.dumps(self.policy))
        policy["retired"][0]["status"] = "deleted"
        self.assertTrue(any("status" in p for p in sync.validate(policy)))

    def test_a_withdrawal_must_name_its_decision(self) -> None:
        policy = json.loads(json.dumps(self.policy))
        for entry in policy["retired"]:
            if entry["status"] == "withdrawn":
                entry.pop("decision")
        self.assertTrue(any("decision" in p for p in sync.validate(policy)))

    def test_archive_urls_must_be_https(self) -> None:
        policy = json.loads(json.dumps(self.policy))
        policy["retired"][0]["archive"] = "http://archive.org/insecure"
        self.assertTrue(any("archive URL" in p for p in sync.validate(policy)))

    def test_the_two_versions_that_answered_404_are_declared(self) -> None:
        """2.1.3 and 2.1.4 were published, pruned, and left answering 404 --
        'this never existed' -- until they were declared here (checked live
        2026-09-09). Removing them re-opens that hole."""
        self.assertIn("2.1.3", self.versions)
        self.assertIn("2.1.4", self.versions)

    def test_images_that_still_serve_bytes_are_not_declared_retired(self) -> None:
        """Retiring a live image turns a working download into a 410. On
        2026-09-09 these four answered 200 at /linux/download/, so declaring one
        of them retired is a product decision, never a tidy-up."""
        for still_served in ("2.1.5", "3.0.0", "3.5.0", "4.0.0"):
            self.assertNotIn(still_served, self.versions)

    def test_every_retired_entry_carries_a_route_for_the_user(self) -> None:
        """A 410 has to say where the image went, or admit that it is gone."""
        for entry in self.policy["retired"]:
            if entry.get("archive") is None:
                self.assertNotEqual(
                    entry.get("status"), "withdrawn",
                    f"{entry['version']}: a withdrawal with no archive and no reason "
                    "leaves the user nothing",
                )
            else:
                self.assertTrue(entry["archive"].startswith("https://archive.org/"))

    def test_sidecar_suffixes_cover_what_the_pages_link(self) -> None:
        self.assertIn(".sha256", self.policy["sidecar_suffixes"])
        self.assertIn(".asc", self.policy["sidecar_suffixes"])


if __name__ == "__main__":
    unittest.main()
