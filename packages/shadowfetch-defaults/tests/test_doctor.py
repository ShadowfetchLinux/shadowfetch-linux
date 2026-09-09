"""shadowfetch-doctor: the properties that make it safe to run and to send.

Four things are being pinned here, and each one is a defect that has actually
shipped somewhere before:

  1. A SUPPORT BUNDLE NEVER CONTAINS A CREDENTIAL. The headline test plants
     real-shaped secrets in paths the bundle DOES collect from and asserts
     none of them survives into the archive, and plants more in paths a home
     directory holds (ssh keys, shell history, browser profile) and asserts
     the tool refuses to read those at all. The two are separate controls --
     redaction and the allowlist -- and both have to hold on their own.
  2. NO PATH LOOKUP DECIDES A SECURITY FACT. journalctl or systemctl resolved
     through a user-writable PATH can forge a clean answer. Every executable
     comes from the TRUSTED_TOOLS table by absolute path.
  3. "NOT INSPECTED" IS NOT "PASS". A diagnostic that prints a tick when it
     could not look converts ignorance into assurance.
  4. THERE IS ONE REDACTOR. If sf_redact cannot be loaded, --support refuses;
     it does not fall back to a weaker local copy that would drift.
"""
from __future__ import annotations

import importlib.machinery
import importlib.util
import io
import json
import os
import pwd
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
DOCTOR_PATH = (Path(__file__).resolve().parents[1]
               / "data/usr/bin/shadowfetch-doctor")
MISSIONS_LIB = (ROOT / "packages/shadowfetch-missions/data/usr/lib/shadowfetch/missions")


def load_doctor():
    # The program has no .py suffix, so it needs an explicit source loader.
    loader = importlib.machinery.SourceFileLoader("shadowfetch_doctor",
                                                  str(DOCTOR_PATH))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    # @dataclass resolves annotations through sys.modules[cls.__module__], so
    # the module has to be registered before its body runs.
    sys.modules[loader.name] = module
    loader.exec_module(module)
    return module


doctor = load_doctor()
SOURCE = DOCTOR_PATH.read_text(encoding="utf-8")


def code_only(source: str) -> str:
    """The source with comments and string literals removed.

    The invariant is about CODE USE, not any mention: the module docstring
    names shutil.which precisely to say it is not used, and an assertion that
    cannot tell the two apart would push that explanation out of the file.
    """
    import tokenize
    kept = []
    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        if token.type in (tokenize.COMMENT, tokenize.STRING):
            continue
        if token.string:
            kept.append(token.string)
    return "".join(kept)


CODE = code_only(SOURCE)


# --------------------------------------------------------------------------- #
# Planted secrets. Every one has a shape sf_redact's rule table recognises --
# a vendor prefix, a credential-shaped name, a PEM block, an Authorization
# header. That is deliberate: a support bundle must not depend on the secret
# also being present in this process's environment, which is the only other
# thing sf_redact can strike out.
# --------------------------------------------------------------------------- #

PLANTED = {
    "openai_project_key": "sk-proj-" + "A7bQ2xLm9pRt4YvKc1De" * 2,
    "github_pat": "ghp_" + "9xK2mQ7bT4vL1yR8pZ3c" * 2,
    "named_assignment": "CODEX_API_KEY=hunter2hunter2hunter2hunter2",
    "bearer_header": "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.QQQQQQQQ.RRRRRRRR",
    # Built at runtime, never written as a literal. A file containing a real
    # PEM header IS a finding to the release secret scanner, and a test fixture
    # is not a good reason to teach the repository to ignore that shape.
    "pem_block": ("-----BEGIN " + "OPENSSH PRIVATE KEY" + "-----\n"
                  "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB\n"
                  "-----END " + "OPENSSH PRIVATE KEY" + "-----"),
}

#: Planted where the tool must never look. These are deliberately NOT
#: secret-shaped: if one of them appeared in a bundle, redaction would not have
#: saved us, so their absence proves the allowlist and nothing else.
UNREADABLE_PLANTS = {
    ".ssh/id_ed25519": "plaintext-private-key-body-9f3ac1d0e5b74a2871",
    ".bash_history": "psql postgres://carol:corr3ct-h0rse@db.internal/prod",
    ".config/google-chrome/Default/Login Data": "chrome-saved-password-blob-4471",
    "Documents/tax-return-2025.txt": "national insurance QQ123456C",
    ".local/state/shadowfetch/missions.db": "mission-store-row-7719",
}


def build_sysroot(base: Path) -> Path:
    """A synthetic machine with secrets in both kinds of place."""
    root = base / "sysroot"
    (root / "etc").mkdir(parents=True)
    (root / "proc").mkdir(parents=True)
    (root / "usr/share/shadowfetch").mkdir(parents=True)
    (root / "etc/apt/sources.list.d").mkdir(parents=True)

    # A collected file with a secret in it. os-release is a real collector
    # target, and "someone pasted a token into a config file" is exactly the
    # accident a bundle has to survive.
    (root / "etc/os-release").write_text(
        'PRETTY_NAME="Shadowfetch Linux"\nID=shadowfetch\n'
        "# left here by a script: %s\n" % PLANTED["openai_project_key"])
    (root / "proc/cmdline").write_text(
        "BOOT_IMAGE=/vmlinuz root=UUID=abc ro token=%s\n" % PLANTED["github_pat"])
    (root / "proc/version").write_text("Linux version 7.1.5-test\n")
    (root / "proc/meminfo").write_text("MemTotal: 1024 kB\nMemAvailable: 512 kB\n")
    (root / "proc/mounts").write_text("/dev/sda1 / btrfs rw 0 0\n")
    (root / "proc/modules").write_text("nvidia 1 - Live 0x0\n")
    (root / "usr/share/shadowfetch/version").write_text("4.0.0\n")
    (root / "etc/apt/sources.list").write_text(
        "deb [signed-by=/usr/share/keyrings/shadowfetch.gpg] "
        "https://www.shadowfetch.com/linux/apt umbra main\n")
    (root / "etc/apt/sources.list.d/private.list").write_text(
        "deb https://user:%s@packages.example/ stable main\n"
        % "s3cr3t-p4ssw0rd-value")

    home = Path(pwd.getpwuid(os.geteuid()).pw_dir)
    fake_home = root / str(home).lstrip("/")

    # A Firebreak session record: only collected with --include-sessions, and
    # even then it goes through the redactor.
    sessions = fake_home / ".local/state/shadowfetch/firebreak"
    sessions.mkdir(parents=True)
    (sessions / "0001.session").write_text(json.dumps({
        "session_id": "0001",
        "agent_command": ["codex", "--key", PLANTED["named_assignment"]],
        "header": PLANTED["bearer_header"],
        "key_material": PLANTED["pem_block"],
    }) + "\n")

    for relative, secret in UNREADABLE_PLANTS.items():
        target = fake_home / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(secret + "\n")
    return root


def bundle_members(archive: Path) -> dict[str, bytes]:
    out = {}
    with tarfile.open(archive, "r:gz") as tar:
        for member in tar.getmembers():
            handle = tar.extractfile(member)
            if handle is not None:
                out[member.name] = handle.read()
    return out


class SupportBundlePrivacy(unittest.TestCase):
    """The test the assignment asks for, in both of its halves."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.sysroot = build_sysroot(self.base)
        self.env = {
            "PATH": "/usr/bin:/bin",
            "OPENAI_API_KEY": PLANTED["openai_project_key"],
            "GITHUB_TOKEN": PLANTED["github_pat"],
            "SHADOWFETCH_ELEMENT": "ice",
        }
        self.host = doctor.Host(root=self.sysroot, env=self.env)

    def _build(self, **kwargs) -> dict[str, bytes]:
        destination = self.base / "bundle.tar.gz"
        doctor.build_bundle(destination, self.host,
                            extra_redactor_dirs=[str(MISSIONS_LIB)], **kwargs)
        self.assertTrue(destination.exists())
        # A support artefact is private from the moment it exists.
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
        return bundle_members(destination)

    def test_planted_credentials_are_absent_from_every_bundle_member(self):
        members = self._build(include_sessions=True)
        self.assertTrue(members, "the bundle is empty")
        blob = b"\n".join(members.values())
        for name, secret in PLANTED.items():
            with self.subTest(secret=name):
                self.assertNotIn(secret.encode(), blob,
                                 "%s survived into the support bundle" % name)
        # The bare password inside a URL, planted in an apt source entry.
        self.assertNotIn(b"s3cr3t-p4ssw0rd-value", blob)

    def test_the_secret_is_gone_from_the_specific_file_it_was_planted_in(self):
        """A whole-blob search can pass because a collector silently failed.

        This asserts the file was collected AND is clean, so "we redacted it"
        cannot be confused with "we never read it".
        """
        members = self._build(include_sessions=True)
        os_release = members["shadowfetch-support/system/os-release"]
        self.assertIn(b"Shadowfetch Linux", os_release,
                      "os-release was not actually collected")
        self.assertNotIn(PLANTED["openai_project_key"].encode(), os_release)
        self.assertIn(b"[REDACTED]", os_release)

        session = members["shadowfetch-support/firebreak/sessions/0001.session"]
        self.assertIn(b"session_id", session, "the session record was not collected")
        for key in ("named_assignment", "bearer_header", "pem_block"):
            self.assertNotIn(PLANTED[key].encode(), session)

    def test_credential_identities_survive_but_values_do_not(self):
        """Redacting the NAME would destroy the record of what was granted.

        sf_redact makes the same distinction for the same reason: the identity
        is the audit trail, the value is the secret.
        """
        members = self._build()
        environment = json.loads(members["shadowfetch-support/environment.json"])
        self.assertIn("OPENAI_API_KEY", environment["credential_identities_present"])
        self.assertIn("GITHUB_TOKEN", environment["names"])
        serialised = json.dumps(environment)
        self.assertNotIn(PLANTED["openai_project_key"], serialised)
        self.assertNotIn(PLANTED["github_pat"], serialised)
        self.assertEqual(environment["posture_values"], {"SHADOWFETCH_ELEMENT": "ice"})

    def test_home_directory_contents_are_never_read(self):
        """The second control: these plants are not secret-shaped on purpose.

        If one of them reached the archive, redaction could not have removed
        it, so their absence is proof about the allowlist rather than about
        sf_redact.
        """
        members = self._build(include_sessions=True)
        blob = b"\n".join(members.values())
        for relative, secret in UNREADABLE_PLANTS.items():
            with self.subTest(path=relative):
                self.assertNotIn(secret.encode(), blob)

    def test_reading_a_home_path_outside_the_state_subtree_is_refused(self):
        home = Path(pwd.getpwuid(os.geteuid()).pw_dir)
        for relative in (".ssh/id_ed25519", ".bash_history",
                         ".config/google-chrome/Default/Login Data",
                         "Documents/tax-return-2025.txt"):
            with self.subTest(path=relative):
                with self.assertRaises(doctor.Refused):
                    self.host.read_text(str(home / relative))
                with self.assertRaises(doctor.Refused):
                    self.host.exists(str(home / relative))

    def test_the_never_collect_list_is_refused_even_for_metadata(self):
        for path in ("/etc/shadow", "/etc/ssh/ssh_host_rsa_key",
                     "/etc/ssl/private/server.key", "/proc/self/environ",
                     "/root/.bashrc"):
            with self.subTest(path=path):
                with self.assertRaises(doctor.Refused):
                    self.host.read_text(path)
                with self.assertRaises(doctor.Refused):
                    self.host.exists(path)

    def test_mission_state_is_probed_but_not_read(self):
        """Metadata and content are two policies, and the split is real.

        The permission check needs to stat ~/.local/state/shadowfetch; nothing
        may read what is inside it except the Firebreak session records.
        """
        home = Path(pwd.getpwuid(os.geteuid()).pw_dir)
        self.assertTrue(self.host.exists(str(home / ".local/state/shadowfetch")))
        with self.assertRaises(doctor.Refused):
            self.host.read_text(str(home / ".local/state/shadowfetch/missions.db"))

    def test_session_contents_need_an_explicit_opt_in(self):
        members = self._build()
        self.assertNotIn("shadowfetch-support/firebreak/sessions/0001.session", members)
        listing = json.loads(
            members["shadowfetch-support/firebreak/sessions-listing.json"])
        self.assertEqual([entry["name"] for entry in listing["sessions"]],
                         ["0001.session"])
        manifest = json.loads(members["shadowfetch-support/MANIFEST.json"])
        self.assertFalse(manifest["include_sessions"])
        self.assertTrue(any("--include-sessions" in entry["reason"]
                            for entry in manifest["skipped"]))

    def test_session_collection_is_capped_and_says_so(self):
        """An uncapped bundle from the build host collected 1,423 session
        files. A truncated bundle must report that it is truncated, or a
        reader concludes the missing sessions never happened."""
        # The cap must be a small, reviewable number. Asserting only that the
        # cap is HONOURED is not enough: raising it to 100000 honours it and
        # ships the whole session history, which is the defect this exists to
        # prevent.
        self.assertLessEqual(doctor.MAX_SESSIONS_COLLECTED, 100)
        self.assertGreaterEqual(doctor.MAX_SESSIONS_COLLECTED, 1)
        sessions = (self.sysroot / str(Path(pwd.getpwuid(os.geteuid()).pw_dir)).lstrip("/")
                    / ".local/state/shadowfetch/firebreak")
        extra = doctor.MAX_SESSIONS_COLLECTED + 7
        for index in range(extra):
            path = sessions / ("bulk-%04d.session" % index)
            path.write_text('{"session_id": "bulk-%04d"}\n' % index)
            os.utime(path, (1_700_000_000 + index, 1_700_000_000 + index))
        members = self._build(include_sessions=True)
        collected = [name for name in members
                     if name.startswith("shadowfetch-support/firebreak/sessions/")]
        self.assertEqual(len(collected), doctor.MAX_SESSIONS_COLLECTED)
        # Newest first: the last-written bulk record must be in, the oldest out.
        self.assertIn("shadowfetch-support/firebreak/sessions/bulk-%04d.session"
                      % (extra - 1), collected)
        self.assertNotIn("shadowfetch-support/firebreak/sessions/bulk-0000.session",
                         collected)
        manifest = json.loads(members["shadowfetch-support/MANIFEST.json"])
        reasons = " ".join(entry["reason"] for entry in manifest["skipped"])
        self.assertIn("withheld", reasons)
        listing = json.loads(
            members["shadowfetch-support/firebreak/sessions-listing.json"])
        self.assertEqual(listing["total_present"], extra + 1)
        self.assertEqual(listing["withheld"],
                         extra + 1 - doctor.MAX_SESSIONS_COLLECTED)


class ManifestDescribesTheArchive(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        host = doctor.Host(root=build_sysroot(base), env={"PATH": "/usr/bin:/bin"})
        self.destination = base / "bundle.tar.gz"
        _, self.manifest = doctor.build_bundle(
            self.destination, host, extra_redactor_dirs=[str(MISSIONS_LIB)])
        self.members = bundle_members(self.destination)

    def test_every_archive_member_is_named_in_the_manifest(self):
        """Nothing rides along unlisted.

        MANIFEST.json is the one exception and the manifest says so in its own
        'self' field: a hash cannot cover the file it is written into.
        """
        manifest = json.loads(self.members["shadowfetch-support/MANIFEST.json"])
        listed = {entry["path"] for entry in manifest["collected"]}
        actual = {name[len("shadowfetch-support/"):] for name in self.members}
        self.assertEqual(manifest["self"]["path"], "MANIFEST.json")
        self.assertNotIn("MANIFEST.json", listed)
        self.assertEqual(actual, listed | {"MANIFEST.json"},
                         "the manifest and the archive disagree about what is in it")

    def test_the_returned_manifest_is_the_one_inside_the_archive(self):
        embedded = json.loads(self.members["shadowfetch-support/MANIFEST.json"])
        self.assertEqual(self.manifest, embedded)

    def test_manifest_hashes_are_of_the_bytes_actually_in_the_archive(self):
        """Post-redaction hashes. A hash of the pre-redaction bytes would
        describe a file that never existed and could not be verified."""
        import hashlib
        manifest = json.loads(self.members["shadowfetch-support/MANIFEST.json"])
        for entry in manifest["collected"]:
            blob = self.members["shadowfetch-support/" + entry["path"]]
            with self.subTest(path=entry["path"]):
                self.assertEqual(entry["bytes"], len(blob))
                self.assertEqual(entry["sha256"], hashlib.sha256(blob).hexdigest())

    def test_manifest_states_the_standing_refusals(self):
        manifest = json.loads(self.members["shadowfetch-support/MANIFEST.json"])
        self.assertEqual(manifest["never_collected"], list(doctor.NEVER_COLLECTED))
        self.assertIn("credential", " ".join(manifest["never_collected"]).lower())
        self.assertIn("shell history", " ".join(manifest["never_collected"]).lower())
        self.assertIn("every byte", manifest["redactor"]["applied_to"])

    def test_no_subprocess_output_is_claimed_when_the_root_is_synthetic(self):
        """Honesty about a limit of the test seam itself: against a synthetic
        root nothing is executed, and the manifest says so instead of
        describing THIS machine's journal as if it were the subject's."""
        manifest = json.loads(self.members["shadowfetch-support/MANIFEST.json"])
        reasons = " ".join(entry["reason"] for entry in manifest["skipped"])
        self.assertIn("synthetic root", reasons)
        self.assertNotIn("shadowfetch-support/services/journal.txt", self.members)


class OneRedactorOnly(unittest.TestCase):
    def test_support_refuses_when_the_shared_redactor_is_unavailable(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            host = doctor.Host(root=build_sysroot(base), env={})
            with self.assertRaises(doctor.RedactorUnavailable):
                # No extra dirs, and REDACTOR_DIRS is redirected away from the
                # installed copy so the refusal is exercised on a machine that
                # happens to have shadowfetch-missions installed.
                original = doctor.REDACTOR_DIRS
                doctor.REDACTOR_DIRS = (str(base / "nowhere"),)
                try:
                    doctor.build_bundle(base / "b.tar.gz", host)
                finally:
                    doctor.REDACTOR_DIRS = original

    def test_there_is_no_second_redactor_in_this_file(self):
        """A local re-implementation is the thing that drifts and then stops
        catching a shape the real rules catch."""
        for forbidden in ("def redact(", "def _redact(", "PLACEHOLDER=",
                          "re.sub(", "CREDENTIAL_VALUE"):
            self.assertNotIn(forbidden, CODE,
                             "shadowfetch-doctor grew its own redactor")

    def test_redaction_has_exactly_one_call_site(self):
        """Structural, not a promise about every call site: if there is one
        place bytes are redacted and one place bytes are stored, no future
        collector can bypass it by accident."""
        self.assertEqual(CODE.count("redact_bytes("), 1)
        self.assertEqual(CODE.count("self._blobs[path]="), 1)


class TrustedPathInvariant(unittest.TestCase):
    """No executable that answers a security question is found on PATH."""

    def test_no_path_lookup_anywhere_in_the_source(self):
        for forbidden in ("shutil.which", "distutils.spawn", "os.defpath",
                          "shell=True", "environ[", "environ.get(PATH"):
            self.assertNotIn(forbidden, CODE,
                             "%s resolves a program through a writable PATH" % forbidden)

    def test_the_docstring_still_explains_the_invariant(self):
        """The explanation lives in the file, and the assertion above must not
        be the reason someone deletes it."""
        self.assertIn("shutil.which", SOURCE)
        self.assertIn("TRUSTED_TOOLS", SOURCE)

    def test_every_trusted_tool_path_is_absolute(self):
        for name, candidates in doctor.TRUSTED_TOOLS.items():
            for candidate in candidates:
                with self.subTest(tool=name, path=candidate):
                    self.assertTrue(candidate.startswith("/"))
                    self.assertTrue(Path(candidate).is_absolute())

    def test_every_tool_has_a_declared_trust_requirement(self):
        self.assertEqual(set(doctor.TRUSTED_TOOLS), set(doctor.REQUIRED_TRUST))
        for name, accepted in doctor.REQUIRED_TRUST.items():
            with self.subTest(tool=name):
                self.assertTrue(accepted, "%s accepts nothing" % name)
                self.assertNotIn(doctor.Trust.UNTRUSTED, accepted)

    def test_the_only_subprocess_call_takes_argv0_from_the_table(self):
        """One exec site, and its program is the resolved table entry."""
        self.assertEqual(CODE.count("subprocess.run("), 1)
        self.assertIn("argv=[chosen.path,*args]", CODE)

    def test_a_substitutable_tool_is_refused_rather_than_believed(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = Path(tmp) / "journalctl"
            fake.write_text("#!/bin/sh\nexit 0\n")
            fake.chmod(0o777)                       # world-writable: substitutable
            trust, reason = doctor.classify_executable(fake)
            self.assertEqual(trust, doctor.Trust.UNTRUSTED, reason)

    def test_run_refuses_a_tool_that_does_not_classify(self):
        host = doctor.Host()
        original = doctor.TRUSTED_TOOLS["journalctl"]
        doctor.TRUSTED_TOOLS["journalctl"] = ("/nonexistent/journalctl",)
        try:
            host._tools.pop("journalctl", None)
            outcome = host.run("journalctl", ["--no-pager"])
        finally:
            doctor.TRUSTED_TOOLS["journalctl"] = original
        self.assertFalse(outcome.ok)
        self.assertFalse(outcome.evidence.ok)
        self.assertIn("no trusted path", outcome.evidence.note)

    @unittest.skipUnless((MISSIONS_LIB / "sf_providers.py").is_file(),
                         "shadowfetch-missions sources are not in this tree")
    def test_classification_agrees_with_the_missions_implementation(self):
        """The duplication is bounded because this asserts it cannot drift."""
        sys.path.insert(0, str(MISSIONS_LIB))
        try:
            import sf_providers
        finally:
            sys.path.remove(str(MISSIONS_LIB))
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            world = base / "world"; world.write_text("#!/bin/sh\n"); world.chmod(0o777)
            mine = base / "mine"; mine.write_text("#!/bin/sh\n"); mine.chmod(0o755)
            for candidate in ("/usr/bin/env", "/bin/sh", str(world), str(mine),
                              str(DOCTOR_PATH)):
                if not Path(candidate).exists():
                    continue
                with self.subTest(path=candidate):
                    self.assertEqual(doctor.classify_executable(candidate)[0],
                                     sf_providers.classify_executable(candidate)[0])


class NotInspectedIsNotAPass(unittest.TestCase):
    def test_skip_is_its_own_status(self):
        self.assertIn(doctor.SKIP, doctor.STATUSES)
        self.assertNotEqual(doctor.SKIP, doctor.PASS)

    def test_a_check_that_cannot_look_reports_skip(self):
        """An empty synthetic root has none of the hardening config, and the
        security check must say so rather than pass for lack of a mismatch."""
        with tempfile.TemporaryDirectory() as tmp:
            empty = Path(tmp) / "empty"
            empty.mkdir()
            findings = {f.id: f for f in doctor.check_security(
                doctor.Host(root=empty, env={}))}
            self.assertEqual(findings["sec.sysctl"].status, doctor.SKIP)
            self.assertTrue(findings["sec.sysctl"].summary.startswith("Not inspected"))

    def test_release_check_blocks_on_skip_as_well_as_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            empty = Path(tmp) / "empty"
            empty.mkdir()
            document, code = doctor.release_check(doctor.Host(root=empty, env={}))
            self.assertEqual(code, 2)
            self.assertFalse(document["passed"])
            statuses = {entry["status"] for entry in document["blocking"]}
            self.assertIn(doctor.SKIP, statuses,
                          "a not-inspected gated check did not block the release")
            self.assertIn("not a pass", document["rule"])

    def test_only_pass_and_info_clear_the_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            empty = Path(tmp) / "empty"
            empty.mkdir()
            document, _ = doctor.release_check(doctor.Host(root=empty, env={}))
            cleared = [entry for entry in document["findings"]
                       if entry not in document["blocking"]]
            for entry in cleared:
                with self.subTest(check=entry["id"]):
                    self.assertIn(entry["status"], (doctor.PASS, doctor.INFO))

    def test_human_output_says_a_skip_is_not_a_pass(self):
        findings = [doctor.Finding("x.y", "system", "T", doctor.SKIP,
                                   "Not inspected: no reason")]
        text = doctor.human_report(doctor.report_document(findings, doctor.Host()))
        self.assertIn("NOT INSPECTED", text)
        self.assertIn("not a pass", text)

    def test_a_collector_that_raises_costs_one_category_not_the_run(self):
        original = doctor.CHECKS["gpu"]

        def explode(host):
            raise RuntimeError("planted")

        doctor.CHECKS["gpu"] = explode
        try:
            findings = doctor.diagnose(doctor.Host(), ["gpu", "broker"])
        finally:
            doctor.CHECKS["gpu"] = original
        ids = {f.id: f for f in findings}
        self.assertEqual(ids["gpu.collector"].status, doctor.FAIL)
        self.assertIn("planted", ids["gpu.collector"].summary)
        self.assertIn("broker.present", ids)


class HonestAboutWhatIsNotEnforced(unittest.TestCase):
    """A control counts as enforced only when something prevents the
    behaviour. These assert the tool says so out loud."""

    def test_egress_destination_filtering_is_reported_as_not_enforced(self):
        findings = {f.id: f for f in doctor.check_firebreak(doctor.Host())}
        egress = findings["fb.egress_filtering"]
        self.assertEqual(egress.status, doctor.INFO)
        self.assertFalse(egress.detail["enforced"])
        self.assertIn("NOT ENFORCED", egress.summary)
        self.assertIn("RECORDED, not enforced", egress.detail["explanation"])

    def test_the_credential_broker_is_reported_as_not_implemented(self):
        with tempfile.TemporaryDirectory() as tmp:
            empty = Path(tmp) / "empty"
            empty.mkdir()
            finding = doctor.check_broker(doctor.Host(root=empty, env={}))[0]
        self.assertEqual(finding.status, doctor.INFO)
        self.assertFalse(finding.detail["implemented"])
        self.assertIn("Firebreak --setenv", finding.detail["credential_delivery"])
        self.assertNotEqual(finding.status, doctor.PASS,
                            "an unimplemented control must never read as a pass")

    def test_a_half_installed_broker_is_a_failure_not_a_note(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "root"
            partial = root / doctor.BROKER_PATHS[0].lstrip("/")
            partial.mkdir(parents=True)
            finding = doctor.check_broker(doctor.Host(root=root, env={}))[0]
        self.assertEqual(finding.status, doctor.FAIL)
        self.assertIn("PARTIALLY", finding.summary)


class ReportShape(unittest.TestCase):
    def test_every_category_has_a_collector_and_vice_versa(self):
        self.assertEqual(set(doctor.CATEGORIES), set(doctor.CHECKS))

    def test_every_finding_is_machine_readable_and_sourced(self):
        findings = doctor.diagnose(doctor.Host())
        self.assertTrue(findings)
        for finding in findings:
            with self.subTest(check=finding.id):
                self.assertIn(finding.status, doctor.STATUSES)
                self.assertIn(finding.category, doctor.CATEGORIES)
                self.assertTrue(finding.summary)
                self.assertTrue(finding.evidence,
                                "a finding with no provenance cannot be checked")
                json.dumps(finding.as_dict())          # must round-trip

    def test_finding_ids_are_unique(self):
        ids = [f.id for f in doctor.diagnose(doctor.Host())]
        self.assertEqual(len(ids), len(set(ids)))

    def test_json_mode_is_valid_json_on_stdout(self):
        result = subprocess.run(
            [sys.executable, str(DOCTOR_PATH), "--json", "--category", "broker"],
            capture_output=True, text=True, timeout=120)
        document = json.loads(result.stdout)
        self.assertEqual(document["schema"], doctor.SCHEMA_VERSION)
        self.assertEqual(document["tool"], "shadowfetch-doctor")
        self.assertEqual(set(document["summary"]), set(doctor.STATUSES))

    def test_help_and_version_have_no_side_effects(self):
        """Asking a tool what it does must never cause it to do the thing."""
        before = sorted(Path.cwd().iterdir())
        for flag in ("--help", "--version"):
            result = subprocess.run([sys.executable, str(DOCTOR_PATH), flag],
                                    capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(sorted(Path.cwd().iterdir()), before)

    def test_support_and_release_check_are_mutually_exclusive(self):
        result = subprocess.run(
            [sys.executable, str(DOCTOR_PATH), "--support", "--release-check"],
            capture_output=True, text=True, timeout=60)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not allowed with", result.stderr)


class PackagedCorrectly(unittest.TestCase):
    def test_the_program_is_executable_and_installed_by_the_package(self):
        self.assertTrue(os.access(DOCTOR_PATH, os.X_OK),
                        "shadowfetch-doctor is not executable in the source tree")
        install = (ROOT / "packages/shadowfetch-defaults/debian"
                   / "shadowfetch-defaults.install").read_text()
        self.assertRegex(install, r"data/usr/bin/shadowfetch-doctor\s+usr/bin/")


if __name__ == "__main__":
    unittest.main()
