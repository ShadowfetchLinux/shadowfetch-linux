"""W-19 regression: no Shadowfetch apt source may be [trusted=yes].

[trusted=yes] tells apt to accept a repository without checking the signature
on its Release file, which disables the chain of trust for every package the
distro installs. Every Shadowfetch source entry -- the build-time one, the one
live-build ships in the image, and the one the late chroot hook rewrites --
must instead name the repository key by path with signed-by=, and the key must
be the one that actually signs the published repository.

These assertions all fail against the pre-fix tree, where
live-build/config/archives/shadowfetch.list.chroot read

    deb [trusted=yes] http://127.0.0.1:8089/ umbra main
"""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]

KEYRING = "/usr/share/keyrings/shadowfetch.gpg"
SIGNED_BY = "[signed-by=%s]" % KEYRING

# Every place a Shadowfetch apt source entry is written.
SOURCE_FILES = (
    "live-build/config/archives/shadowfetch.list.chroot",
    "live-build/config/archives/shadowfetch.list.binary",
    "live-build/config/hooks/0099-apt-source.hook.chroot",
)

DEB_LINE = re.compile(r"^\s*(?:echo\s+')?deb(?:-src)?\s+(?P<rest>\S.*)$", re.MULTILINE)


def deb_entries(text):
    """The apt source entries a file defines, including ones inside echo '...'."""
    return [match.group("rest").rstrip("'\"") for match in DEB_LINE.finditer(text)]


class AptSourceTrustTests(unittest.TestCase):
    def test_no_shadowfetch_source_entry_is_trusted_yes(self):
        for rel in SOURCE_FILES:
            with self.subTest(source=rel):
                for entry in deb_entries((ROOT / rel).read_text()):
                    self.assertNotIn("trusted=yes", entry)
                    self.assertNotIn("trusted=true", entry)

    def test_every_shadowfetch_source_entry_names_the_keyring(self):
        for rel in SOURCE_FILES:
            with self.subTest(source=rel):
                entries = deb_entries((ROOT / rel).read_text())
                self.assertTrue(entries, "no deb entry found in " + rel)
                for entry in entries:
                    self.assertIn(SIGNED_BY, entry)

    def test_the_keyring_path_is_absolute_and_under_usr_share_keyrings(self):
        self.assertTrue(KEYRING.startswith("/usr/share/keyrings/"))

    def test_the_build_stages_that_keyring_into_the_chroot(self):
        """signed-by= only works if the file is there before apt update.

        live-build's chroot pass runs `apt-get update` inside lb_chroot_archives,
        before hooks, before includes.chroot and before any package install.
        config/archives/*.deb is the one slot that lands in the chroot earlier,
        so `make iso` has to stage the keyring package there.
        """
        makefile = (ROOT / "Makefile").read_text()
        self.assertIn(
            "dpkg-deb --root-owner-group --build $(BUILD_DIR)/archive-keyring "
            "$(LB_DIR)/config/archives/shadowfetch-archive-keyring.deb",
            makefile)
        self.assertIn(
            "$(BUILD_DIR)/archive-keyring/usr/share/keyrings/shadowfetch.gpg",
            makefile)
        # ...built from the same armored key reprepro signs the repo with.
        self.assertIn(
            "@$(GPG) --dearmor < $(REPO_DIR)/shadowfetch.gpg.asc",
            makefile)

    def test_the_shipped_key_is_the_key_reprepro_signs_with(self):
        distributions = ROOT / "repo" / "conf" / "distributions"
        if not distributions.exists():
            self.skipTest("repo/conf/distributions is a build artifact")
        sign_with = [line.split(":", 1)[1].strip()
                     for line in distributions.read_text().splitlines()
                     if line.startswith("SignWith:")]
        self.assertEqual(1, len(sign_with))
        makefile = (ROOT / "Makefile").read_text()
        self.assertIn("REPO_KEY_ID ?= " + sign_with[0], makefile)

    def test_the_hook_refuses_to_write_an_entry_it_cannot_satisfy(self):
        hook = (ROOT / "live-build/config/hooks/0099-apt-source.hook.chroot").read_text()
        self.assertIn("test -s %s\n" % KEYRING, hook)
        self.assertLess(hook.index("test -s %s" % KEYRING),
                        hook.index("sources.list.d/shadowfetch.list"))


if __name__ == "__main__":
    unittest.main()
