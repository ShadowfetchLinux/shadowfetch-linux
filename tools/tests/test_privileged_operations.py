"""Stage V -- contract tests for every privileged operation in the tree.

Three groups:

  ShellEscalationTests   No shipped code may escalate to a generic shell, and
                         no polkit action may hand out arbitrary argv.  The
                         Control Center's apt-snapshot switch did exactly that
                         on every real install until Stage V.

  PolkitActionTests      Every action a caller can reach through pkexec is
                         pinned to one executable that exists in this tree,
                         and every PASSWORDLESS action (allow_active=yes) is
                         pinned and points at a helper with a closed argv
                         grammar.

  EmberDurationTests     Adversarial argv tests for /usr/libexec/ember-duration
                         -- the one root helper any active local user can run
                         with NO password.  Nothing else in the tree covers it.

The inventory these tests defend is written up in docs/PRIVILEGED_OPERATIONS.md.

Honesty note: PKEXEC_ABSOLUTE_EXEMPT below is not an exemption from the rule.
It is the exact, enumerated list of call sites where `pkexec` is still resolved
through PATH because a release gate (tools/iso_gate_4_0_0.py) and three package
test files pin the literal string.  Those sites are NOT enforced; the list makes
that visible and makes any NEW unpinned site fail.
"""

import os
import re
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PACKAGES = ROOT / "packages"

# Build copies and the live-build chroot are stale duplicates of the sources.
SKIP_PARTS = ("debian", "live-build", "chroot", "__pycache__", "tests", ".git")


def shipped_files():
    """Every regular file a package actually ships, sources included."""
    for path in PACKAGES.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        rel = path.relative_to(ROOT).parts
        if any(part in SKIP_PARTS for part in rel):
            continue
        if path.suffix in (".png", ".jpg", ".svg", ".gz", ".pyc", ".gpg"):
            continue
        yield path


def read(path):
    try:
        return path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return ""


_XML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)


def code_lines(path):
    """(lineno, line) for lines that can execute.

    Whole-line comments are dropped, and XML comments are blanked in place so
    line numbers stay true.  This matters because the house style is to name
    the defect a change removed: three comments added by this very review
    quote the shell escalation they deleted, and a scanner that cannot tell
    code from prose would either flag them or push the next author into
    deleting the explanation.
    """
    text = read(path)
    if path.suffix in (".policy", ".xml", ".conf", ".service", ".rules"):
        text = _XML_COMMENT.sub(lambda m: "\n" * m.group(0).count("\n"), text)
    for lineno, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith(("#", "//", "<!--", "*")):
            continue
        yield lineno, line


def installed_paths():
    """{installed absolute path: file in this tree}.

    A package stages usr/... under its own directory, so the installed path of
    packages/shadowfetch-phoenix/usr/libexec/phoenix-restore is
    /usr/libexec/phoenix-restore.  Both the polkit exec.path annotations and
    the root-helper delegation checks are expressed in installed paths.
    """
    out = {}
    for path in shipped_files():
        rel = str(path.relative_to(ROOT))
        if "/usr/" in rel:
            out["/usr/" + rel.split("/usr/", 1)[1]] = path
    return out


class ShellEscalationTests(unittest.TestCase):

    # `pkexec` (or sudo) immediately followed by a shell, in any argv shape:
    #   ["pkexec", "/bin/sh", "-c", ...]        pkexec /bin/sh -c '...'
    #   pkexec sh -c ...                         pkexec bash -c ...
    SHELL_ESCALATION = re.compile(
        r"""(?:pkexec|\bsudo)\b["'\s,\]\[]{1,6}
            (?:/(?:usr/)?bin/)?(?:sh|bash|dash|zsh)\b""",
        re.VERBOSE)

    def test_no_shipped_file_escalates_to_a_generic_shell(self):
        """A root shell is not a scoped authorization.

        Whatever the argv happens to be at the call site, the action polkit
        authorises is org.freedesktop.policykit.exec on a shell: the user is
        asked to approve "run a program as another user", the dialog names the
        shell, and nothing in the grant constrains what the shell then does.
        """
        offenders = []
        for path in shipped_files():
            for lineno, line in code_lines(path):
                if self.SHELL_ESCALATION.search(line):
                    offenders.append("%s:%d: %s"
                                     % (path.relative_to(ROOT), lineno,
                                        line.strip()))
        self.assertEqual(offenders, [], "generic shell escalation:\n" +
                         "\n".join(offenders))

    def test_no_shipped_file_passes_its_own_argv_through_an_escalator(self):
        """`pkexec "$@"` / `sudo "$@"` is arbitrary argv as root."""
        pattern = re.compile(r'(?:pkexec|\bsudo)\s+(?:"\$@"|\$@|\$\*)')
        offenders = ["%s:%d" % (path.relative_to(ROOT), lineno)
                     for path in shipped_files()
                     for lineno, line in code_lines(path)
                     if pattern.search(line)]
        self.assertEqual(offenders, [], "argv pass-through to root: %s"
                         % offenders)


# Sites where the pkexec PROGRAM is still the bare word "pkexec", i.e. resolved
# through the caller's PATH.  These are session-side callers, so this is not a
# root escalation -- a hostile PATH entry runs as the user, not as root -- but
# it lets a same-user process swallow the operation while reporting success, or
# imitate the authentication dialog.  Each of these is pinned by a release gate
# or a package test that greps for the literal, so changing it here alone would
# red the gate; see docs/PRIVILEGED_OPERATIONS.md, "Open findings".
PKEXEC_ABSOLUTE_EXEMPT = {
    "packages/shadowfetch-defaults/data/usr/bin/shadowfetch-workbench":
        "tools/iso_gate_4_0_0.py:817 and "
        "packages/shadowfetch-defaults/tests/test_workbench_3_5_0.py:158 "
        "assert the literal",
    "packages/shadowfetch-control-center/data/usr/share/shadowfetch/"
    "control-center/sfcc/workbench_page.py":
        "packages/shadowfetch-control-center/tests/"
        "test_privileged_invocation.py asserts the literal",
    "packages/shadowfetch-control-center/data/usr/share/shadowfetch/"
    "control-center/sfcc/software_page.py":
        "packages/shadowfetch-control-center/tests/"
        "test_privileged_invocation.py asserts the literal",
    "packages/shadowfetch-welcome/src/shadowfetch-welcome":
        "packages/shadowfetch-welcome/tests/test_catalog_actions.py:130 "
        "asserts the literal",
    # Outside Stage V's file territory (shadowfetch-fireproof UI, and the
    # Control Center Ember page): recorded, not yet fixed.
    "packages/shadowfetch-fireproof/data/usr/bin/fireproof":
        "outside Stage V file territory",
    "packages/shadowfetch-fireproof/data/usr/bin/shadowfetch-fireproof":
        "outside Stage V file territory",
    "packages/shadowfetch-control-center/data/usr/share/shadowfetch/"
    "control-center/sfcc/ember_page.py":
        "outside Stage V file territory",
}


class PkexecResolutionTests(unittest.TestCase):
    """pkexec decides whether a privileged operation happened at all."""

    BARE = re.compile(r"""["'](pkexec)["']""")

    def _bare_sites(self):
        sites = {}
        for path in shipped_files():
            rel = str(path.relative_to(ROOT))
            for lineno, line in code_lines(path):
                if self.BARE.search(line):
                    sites.setdefault(rel, []).append(lineno)
        return sites

    def test_only_the_recorded_sites_resolve_pkexec_through_path(self):
        unexpected = sorted(set(self._bare_sites()) - set(PKEXEC_ABSOLUTE_EXEMPT))
        self.assertEqual(
            unexpected, [],
            "new call site resolving pkexec through PATH; name it absolutely "
            "(/usr/bin/pkexec, or busutil.PKEXEC): %s" % unexpected)

    def test_the_exemption_list_does_not_rot(self):
        """Every recorded site must still exist, so a fix removes its entry."""
        stale = sorted(set(PKEXEC_ABSOLUTE_EXEMPT) - set(self._bare_sites()))
        self.assertEqual(stale, [],
                         "these sites no longer resolve pkexec through PATH; "
                         "delete them from PKEXEC_ABSOLUTE_EXEMPT: %s" % stale)

    def test_busutil_names_pkexec_absolutely(self):
        busutil = (PACKAGES / "shadowfetch-control-center/data/usr/share/"
                              "shadowfetch/control-center/sfcc/busutil.py")
        self.assertIn('PKEXEC = "/usr/bin/pkexec"', read(busutil))


class PolkitActionTests(unittest.TestCase):

    NS = ""

    def _actions(self):
        """(policy path, action id, defaults dict, exec.path or None)."""
        for path in shipped_files():
            if path.suffix != ".policy":
                continue
            tree = ET.parse(path)
            for action in tree.getroot().findall("action"):
                defaults = {}
                node = action.find("defaults")
                if node is not None:
                    for child in node:
                        defaults[child.tag] = (child.text or "").strip()
                exec_path = None
                for annotate in action.findall("annotate"):
                    if annotate.get("key") == "org.freedesktop.policykit.exec.path":
                        exec_path = (annotate.text or "").strip()
                yield path, action.get("id"), defaults, exec_path

    def test_the_tree_still_ships_the_actions_this_review_inventoried(self):
        found = {aid for _, aid, _, _ in self._actions()}
        for expected in (
                "org.shadowfetch.phoenix.restore",
                "org.shadowfetch.phoenix.recovery-report",
                "org.shadowfetch.phoenix.apt-snapshot",
                "com.shadowfetch.ember.duration",
                "org.shadowfetch.bundle-install",
                "org.shadowfetch.ignition-state",
                "org.shadowfetch.fireproof.update"):
            self.assertIn(expected, found)

    def test_passwordless_actions_are_pinned_to_one_executable(self):
        """allow_active=yes means no password at all.  Such an action must
        never be reachable for an arbitrary program: without exec.path,
        pkexec would authorise this action for whatever the caller named."""
        for path, aid, defaults, exec_path in self._actions():
            if defaults.get("allow_active") != "yes":
                continue
            with self.subTest(action=aid):
                self.assertIsNotNone(
                    exec_path,
                    "%s in %s is passwordless with no exec.path annotation"
                    % (aid, path.relative_to(ROOT)))
                self.assertTrue(exec_path.startswith("/"),
                                "%s: exec.path must be absolute" % aid)

    def test_passwordless_actions_never_grant_inactive_or_remote_callers(self):
        for path, aid, defaults, _ in self._actions():
            if defaults.get("allow_active") != "yes":
                continue
            with self.subTest(action=aid):
                self.assertEqual(defaults.get("allow_any"), "no", aid)
                self.assertEqual(defaults.get("allow_inactive"), "no", aid)

    def test_every_exec_path_names_a_helper_this_tree_ships(self):
        """A dangling exec.path is an action with no defined behaviour."""
        shipped = installed_paths()
        for path, aid, _, exec_path in self._actions():
            if exec_path is None:
                continue
            with self.subTest(action=aid):
                self.assertIn(exec_path, shipped,
                              "%s points at %s, which no package in this tree "
                              "ships" % (aid, exec_path))
                self.assertTrue(os.access(shipped[exec_path], os.X_OK),
                                "%s is not executable in the tree" % exec_path)

    @staticmethod
    def _checks_root(text):
        return "id -u" in text or "geteuid" in text or "getuid" in text

    def test_every_exec_path_helper_is_actually_shipped_by_its_package(self):
        """An exec.path helper that the .deb does not install is worse than a
        missing feature: the action exists, pkexec finds no program, and the
        caller sees exit 127 -- indistinguishable from "the user cancelled"
        at most of the call sites in this tree.  The apt-snapshot switch spent
        its whole life in that state, which is why it fell back to a shell.
        """
        for policy, aid, _, exec_path in self._actions():
            if exec_path is None:
                continue
            # policy path: packages/<pkg>/.../usr/share/polkit-1/actions/...
            pkg_root = policy
            while pkg_root.parent != PACKAGES:
                pkg_root = pkg_root.parent
            manifests = list((pkg_root / "debian").glob("*.install"))
            if not manifests:
                continue          # package stages its tree another way
            listed = "\n".join(m.read_text() for m in manifests)
            with self.subTest(action=aid, helper=exec_path):
                self.assertIn(
                    exec_path.lstrip("/"), listed,
                    "%s points at %s, but %s does not install it"
                    % (aid, exec_path, pkg_root.name))

    def test_helpers_behind_polkit_actions_refuse_to_run_unprivileged(self):
        """Defence in depth: a root helper must not assume polkit did its job.

        Every exec.path helper either checks euid itself, or is a thin shim
        that execs an ABSOLUTE path to another shipped helper which does --
        shadowfetch-ignition-state is the second shape, because pkexec maps one
        action to one program path and the passwordless state verbs therefore
        need their own path into shadowfetch-bundle-install.
        """
        by_install_path = installed_paths()

        for policy, aid, _, exec_path in self._actions():
            if exec_path is None:
                continue
            helper = by_install_path.get(exec_path)
            if helper is None:
                continue          # covered by the exec.path existence test
            text = read(helper)
            with self.subTest(action=aid, helper=exec_path):
                if self._checks_root(text):
                    continue
                execs = re.findall(r"^\s*exec\s+(\S+)", text, re.MULTILINE)
                self.assertTrue(
                    execs,
                    "%s is a pkexec target that neither checks euid nor "
                    "delegates" % exec_path)
                for target in execs:
                    self.assertTrue(
                        target.startswith("/"),
                        "%s execs %r, which is resolved through PATH -- a "
                        "PATH-resolved program run as root is a root "
                        "escalation" % (exec_path, target))
                    delegate = by_install_path.get(target)
                    self.assertIsNotNone(
                        delegate, "%s execs %s, which this tree does not ship"
                        % (exec_path, target))
                    self.assertTrue(
                        self._checks_root(read(delegate)),
                        "%s delegates to %s, which never checks that it is "
                        "root" % (exec_path, target))


# --------------------------------------------------------------------------
# ember-duration: the ONLY root helper reachable with no password at all.
# --------------------------------------------------------------------------

EMBER_DURATION = PACKAGES / "shadowfetch-ember/usr/libexec/ember-duration"

# Absolute paths the helper writes, and the assignment lines that name them.
# Every rewrite asserts its hit count, so an edit that changes how a root path
# is reached fails loudly instead of silently escaping the sandbox.
EMBER_PATH_LINES = (
    "RUNDIR=/run/shadowfetch",
    "PROFILES_DIR=/usr/share/shadowfetch/ember/profiles",
    "DROPDIR=/run/systemd/system/shadowfetch-ember.service.d",
)


class EmberSandbox:
    def __init__(self, base: Path):
        self.base = base
        self.bin = base / "bin"
        self.run = base / "run"
        self.profiles = base / "profiles"
        self.dropdir = base / "dropin"
        for d in (self.bin, self.run, self.profiles):
            d.mkdir(parents=True)
        (self.profiles / "gaming.conf").write_text("duration_seconds=7200\n")
        (self.profiles / "local-ai.conf").write_text("duration_seconds=0\n")

        (self.bin / "id").write_text("#!/bin/sh\necho 0\n")
        (self.bin / "systemctl").write_text(
            "#!/bin/sh\nprintf 'systemctl %s\\n' \"$*\" >> \"$SB_LOG\"\n")
        for name in ("id", "systemctl"):
            (self.bin / name).chmod(0o755)

        text = EMBER_DURATION.read_text()
        for line in EMBER_PATH_LINES:
            assert text.count(line) == 1, (
                "ember-duration no longer names %r exactly once; this harness "
                "would escape the sandbox" % line)
        text = text.replace(EMBER_PATH_LINES[0], f"RUNDIR={self.run}")
        text = text.replace(EMBER_PATH_LINES[1], f"PROFILES_DIR={self.profiles}")
        text = text.replace(EMBER_PATH_LINES[2], f"DROPDIR={self.dropdir}")
        self.script = base / "ember-duration"
        self.script.write_text(text)
        self.script.chmod(0o755)
        self.log = base / "calls.log"

    def run_helper(self, *args, timeout=20):
        env = dict(os.environ)
        env["PATH"] = f"{self.bin}:/usr/bin:/bin"
        env["LC_ALL"] = "C"
        env["SB_LOG"] = str(self.log)
        return subprocess.run(["/bin/sh", str(self.script), *args],
                              capture_output=True, text=True, env=env,
                              timeout=timeout, check=False)

    @property
    def marker(self):
        return self.run / "ember-profile"

    @property
    def dropin(self):
        return self.dropdir / "50-ember-duration.conf"

    def wrote_nothing(self):
        return not self.marker.exists() and not self.dropin.exists()


class EmberDurationTests(unittest.TestCase):
    """com.shadowfetch.ember.duration is allow_active=yes: any active local
    user runs this helper as root without authenticating.  Its argv grammar is
    therefore the whole of its authorization, so it is tested adversarially."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="ember-duration.")
        self.addCleanup(self._tmp.cleanup)
        self.sb = EmberSandbox(Path(self._tmp.name))

    def assertRefused(self, *args):
        r = self.sb.run_helper(*args)
        self.assertNotEqual(r.returncode, 0,
                            "helper accepted %r" % (args,))
        self.assertTrue(self.sb.wrote_nothing(),
                        "helper wrote state while refusing %r" % (args,))
        return r

    # ---- profile ids -----------------------------------------------------

    def test_profile_id_cannot_traverse_out_of_the_profiles_directory(self):
        # A REACHABLE target outside the profiles directory: with only the
        # "$PROFILES_DIR/$profile.conf must exist" check, ../escape would
        # resolve and be accepted.  It is the charset rule that stops it, so
        # the file is planted to make this test prove the charset rule rather
        # than the existence check.
        (self.sb.base / "escape.conf").write_text("duration_seconds=60\n")
        for bad in ("../escape", "../../etc/passwd", "../gaming", "a/b",
                    "/etc/passwd", ".", "..", "gaming/../gaming"):
            with self.subTest(profile=bad):
                self.assertRefused("--profile", bad)

    def test_profile_id_charset_is_closed(self):
        # Same construction: each of these names a definition that EXISTS, so
        # only the charset rule can refuse them.
        for name in ("Gaming", "gam_ing", "gam ing", "gam$ing"):
            (self.sb.profiles / (name + ".conf")).write_text("x=1\n")
        for bad in ("Gaming", "gam_ing", "gaming;id", "gam ing", "gam$ing",
                    "gam`id`ing", "gam\ning"):
            with self.subTest(profile=bad):
                self.assertRefused("--profile", bad)

    def test_profile_must_resolve_to_a_shipped_definition(self):
        self.assertRefused("--profile", "not-a-real-profile")

    def test_profile_flag_without_a_value_is_refused(self):
        self.assertRefused("--profile")
        self.assertRefused("--profile", "")

    def test_a_valid_profile_writes_exactly_its_id(self):
        r = self.sb.run_helper("--profile", "gaming")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.sb.marker.read_text(), "gaming\n")

    def test_profile_off_clears_the_marker(self):
        self.sb.run_helper("--profile", "gaming")
        r = self.sb.run_helper("--profile", "off")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(self.sb.marker.exists())

    # ---- durations -------------------------------------------------------

    def test_duration_outside_the_documented_range_is_refused(self):
        for bad in ("0", "1", "59", "86401", "999999999"):
            with self.subTest(duration=bad):
                self.assertRefused(bad)

    def test_duration_must_be_digits_only(self):
        for bad in ("-1", "60s", "6 0", "0x3c", "6e2", "60;id", "+60", " 60"):
            with self.subTest(duration=bad):
                self.assertRefused(bad)

    def test_a_valid_duration_writes_only_runtimemaxsec(self):
        r = self.sb.run_helper("7200")
        self.assertEqual(r.returncode, 0, r.stderr)
        text = self.sb.dropin.read_text()
        self.assertIn("RuntimeMaxSec=7200", text)
        self.assertNotIn("ExecStart", text)
        self.assertEqual(len([l for l in text.splitlines()
                              if "=" in l and not l.startswith("#")]), 1)

    def test_off_removes_the_dropin(self):
        self.sb.run_helper("7200")
        r = self.sb.run_helper("off")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(self.sb.dropin.exists())

    # ---- shape -----------------------------------------------------------

    def test_no_arguments_does_nothing(self):
        self.assertRefused()

    def test_unknown_flags_are_refused(self):
        for bad in ("--duration", "--exec", "-c", "--profile=gaming",
                    "--help=x", "enable"):
            with self.subTest(argument=bad):
                self.assertRefused(bad)

    def test_help_and_version_take_no_privileged_action(self):
        for flag in ("-h", "--help", "--version"):
            with self.subTest(flag=flag):
                r = self.sb.run_helper(flag)
                self.assertEqual(r.returncode, 0)
        self.assertTrue(self.sb.wrote_nothing())

    def test_the_polkit_action_is_pinned_to_this_helper(self):
        policy = read(PACKAGES / "shadowfetch-ember/usr/share/polkit-1/"
                                 "actions/com.shadowfetch.ember.policy")
        self.assertIn(
            '<annotate key="org.freedesktop.policykit.exec.path">'
            '/usr/libexec/ember-duration</annotate>', policy)

    def test_the_control_center_probe_can_reach_the_pinned_helper(self):
        """busutil probes three helper names; only the annotated one is
        passwordless, so the probe list must contain it or the switch would
        silently start prompting for an admin password."""
        busutil = read(PACKAGES / "shadowfetch-control-center/data/usr/share/"
                                  "shadowfetch/control-center/sfcc/busutil.py")
        self.assertIn('"/usr/libexec/ember-duration"', busutil)


if __name__ == "__main__":
    unittest.main()
