"""shadowfetch-workbench must not let the environment choose what pkexec runs.

Phase 1 W-09, found in the adversarial pass. The shipped code read

    helper = Path(os.environ.get("SHADOWFETCH_WORKBENCH_HELPER", DEFAULT_HELPER))
    ...
    subprocess.run(["pkexec", str(helper), "install", profile["catalog_id"]])

so setting one variable in the user's session -- no privilege required --
decided which program they were about to authenticate as root.
"""
import re
import unittest
from pathlib import Path

WORKBENCH = (Path(__file__).resolve().parents[1]
             / "data/usr/bin/shadowfetch-workbench")


class PrivilegedHelperIsFixed(unittest.TestCase):
    def setUp(self):
        self.src = WORKBENCH.read_text()

    def test_helper_is_not_read_from_the_environment(self):
        # Code use, not any mention: the fix carries a comment naming the
        # variable so the history stays readable.
        code = "\n".join(l for l in self.src.splitlines()
                         if not l.lstrip().startswith("#"))
        self.assertNotIn("SHADOWFETCH_WORKBENCH_HELPER", code,
                         "the pkexec target is selectable from the environment")
        self.assertNotIn("environ.get(\"SHADOWFETCH_WORKBENCH_HELPER", self.src)

    def test_helper_is_the_packaged_absolute_path(self):
        self.assertIn('DEFAULT_HELPER = Path("/usr/libexec/shadowfetch-bundle-install")',
                      self.src)
        self.assertIn("    helper = DEFAULT_HELPER", self.src)

    def test_every_pkexec_target_in_this_file_is_a_fixed_path(self):
        """No pkexec call site may take its program from os.environ."""
        for match in re.finditer(r'"pkexec"[^\]]*\]', self.src):
            call = match.group(0)
            self.assertNotIn("environ", call, call)


if __name__ == "__main__":
    unittest.main(verbosity=2)
