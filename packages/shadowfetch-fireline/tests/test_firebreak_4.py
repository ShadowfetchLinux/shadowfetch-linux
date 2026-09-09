import argparse
import errno
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

BASE = Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader("firebreak", str(BASE / "data/usr/bin/shadowfetch-firebreak"))
spec = importlib.util.spec_from_loader("firebreak", loader)
fb = importlib.util.module_from_spec(spec)
loader.exec_module(fb)
sys.path.insert(0, str(BASE / "data/usr/lib/shadowfetch/mcp"))
import sf_mcp

class ScopeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name).resolve()
        self.ws = self.base / "Workspaces" / "project"
        self.ws.mkdir(parents=True)
        (self.ws / "seed.txt").write_text("original")
        self.env = patch.dict(os.environ, {"SHADOWFETCH_AGENT_WORKSPACES":str(self.ws.parent), "SHADOWFETCH_FIREBREAK_STATE":str(self.base / "state"), "SHADOWFETCH_ELEMENT":"ice"})
        self.env.start()
    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()
    def args(self, **values):
        defaults = dict(net=None, read=[], credential_env=[], keep_secrets=False, workspace_mode="workspace-write", agent_command=["true"])
        defaults.update(values)
        return argparse.Namespace(**defaults)
    def test_read_only_workspace_mode_binds_the_workspace_read_only(self):
        """The posture reaches bwrap. Before --workspace-mode existed, a provider
        declaring read-only got --bind and could write the tree it was given."""
        command, *_ = fb.arguments(self.args(workspace_mode="read-only"), self.ws, "test")
        joined = " ".join(command)
        self.assertIn("--ro-bind " + str(self.ws) + " " + str(self.ws), joined)
        self.assertNotIn("--bind " + str(self.ws) + " " + str(self.ws), joined)

    def test_the_default_workspace_mode_still_binds_writable(self):
        command, *_ = fb.arguments(self.args(), self.ws, "test")
        joined = " ".join(command)
        self.assertIn("--bind " + str(self.ws) + " " + str(self.ws), joined)
        self.assertNotIn("--ro-bind " + str(self.ws) + " " + str(self.ws), joined)

    def test_private_root_clean_environment_network_off(self):
        with patch.dict(os.environ, {"SECRET_CUSTOM":"must-not-pass", "OPENAI_API_KEY":"test-not-for-sandbox"}):
            command, net, grants, names = fb.arguments(self.args(), self.ws, "test")
        self.assertEqual(net, "none")
        self.assertIn("--clearenv", command)
        self.assertIn("--unshare-net", command)
        self.assertIn("/home/agent", command)
        self.assertNotIn("test-not-for-sandbox", command)
        self.assertNotIn("must-not-pass", command)
        self.assertNotIn(["--ro-bind", "/", "/"], [command[i:i+3] for i in range(len(command))])
        self.assertNotIn("/etc/shadow", command)
        self.assertNotIn(str(Path.home()), command)
    def test_account_grant_refused_offline(self):
        with self.assertRaisesRegex(fb.Error, "explicit cloud"):
            fb.arguments(self.args(codex_account=True), self.ws, "account-test")

    def test_account_grant_is_dedicated_and_recorded(self):
        module_dir = BASE.parent / "shadowfetch-missions/data/usr/lib/shadowfetch/missions"
        sys.path.insert(0, str(module_dir))
        import sf_mission_account as account
        with patch.object(Path, "home", return_value=self.base):
            dedicated = account.account_home(create=True)
            auth = dedicated / "auth.json"
            auth.write_text('{}')
            auth.chmod(0o600)
            command, net, grants, names = fb.arguments(self.args(net="allow", codex_account=True), self.ws, "account-test")
        triples = [command[i:i+3] for i in range(len(command))]
        self.assertIn(["--bind", str(dedicated), "/home/agent/.codex"], triples)
        self.assertIn(["--setenv", "CODEX_HOME", "/home/agent/.codex"], triples)
        self.assertEqual(names, ["codex-account"])
        self.assertNotIn(str(dedicated.parent), command)
        self.assertNotIn(str(self.base / ".codex"), command)
        self.assertNotIn(str(dedicated.parent / "mission-account.lock"), command)

    def test_account_grant_requires_credentials(self):
        module_dir = BASE.parent / "shadowfetch-missions/data/usr/lib/shadowfetch/missions"
        sys.path.insert(0, str(module_dir))
        import sf_mission_account as account
        with patch.object(Path, "home", return_value=self.base):
            account.account_home(create=True)
            with self.assertRaisesRegex(fb.Error, "Sign in"):
                fb.arguments(self.args(net="allow", codex_account=True), self.ws, "account-test")

    def test_individual_credential_only(self):
        with patch.dict(os.environ, {"CODEX_API_KEY":"designated-test-key", "UNRELATED_SECRET":"private"}):
            command, _, _, names = fb.arguments(self.args(credential_env=["CODEX_API_KEY"]), self.ws, "test")
        self.assertEqual(names, ["CODEX_API_KEY"])
        self.assertIn("designated-test-key", command)
        self.assertNotIn("private", command)
    def test_explicit_read_grant_does_not_add_parent(self):
        doc = self.base / "selected.txt"
        doc.write_text("selected")
        command, _, _, _ = fb.arguments(self.args(read=[str(doc)]), self.ws, "test")
        self.assertIn(["--ro-bind",str(doc),str(doc)], [command[i:i+3] for i in range(len(command))])
        self.assertNotIn(["--ro-bind",str(self.base),str(self.base)], [command[i:i+3] for i in range(len(command))])
    def test_read_grants_cannot_expose_controller_or_whole_home(self):
        for path in ("/", str(Path.home()), str(self.ws.parent), str(fb.state()), str(self.base)):
            with self.subTest(path=path), self.assertRaises(fb.Error):
                fb.read_grants([path], self.ws)
    def test_workspace_symlink_escape_and_checkpoint_store_escape(self):
        (self.ws.parent / "escape").symlink_to(self.base)
        with self.assertRaises(fb.Error):
            fb.workspace("escape")
        with self.assertRaises(sf_mcp._ToolError):
            sf_mcp.build_checkpoint().tools["snapshot"].handler({"workspace":"escape"})
        (self.ws.parent / ".sf-checkpoints").symlink_to(self.base)
        with self.assertRaises(sf_mcp._ToolError):
            sf_mcp.build_checkpoint().tools["snapshot"].handler({"workspace":"project"})
    def test_checkpoint_preserves_links_without_reading_targets(self):
        target = self.base / "outside.txt"
        target.write_text("outside-secret")
        (self.ws / "link").symlink_to(target)
        server = sf_mcp.build_checkpoint()
        result = server.tools["snapshot"].handler({"workspace":"project"})
        cid = result.split()[1]
        (self.ws / "link").unlink()
        (self.ws / "seed.txt").write_text("changed")
        server.tools["undo"].handler({"workspace":"project", "checkpoint":cid})
        self.assertTrue((self.ws / "link").is_symlink())
        self.assertEqual(os.readlink(self.ws / "link"), str(target))
        self.assertEqual(target.read_text(), "outside-secret")
    def test_malicious_archive_rejected_before_outside_write(self):
        store = sf_mcp._ckpt_store(self.ws)
        for members in (["../../outside"], ["project/link", "project/link/pwn"]):
            with self.subTest(members=members):
                arc = store / "bad.tar.gz"
                with tarfile.open(arc,"w:gz") as tf:
                    for name in members:
                        info = tarfile.TarInfo(name)
                        if name.endswith("link"):
                            info.type = tarfile.SYMTYPE
                            info.linkname = str(self.base)
                            tf.addfile(info)
                        else:
                            info.size = 3
                            tf.addfile(info,io.BytesIO(b"bad"))
                with self.assertRaises(sf_mcp._ToolError):
                    sf_mcp._restore_tree(store,{"id":"bad","method":"tar","archive":"bad.tar.gz","workspace":"project"})
                self.assertFalse((self.base / "pwn").exists())
    def test_checkpoint_diff_and_undo_do_not_clobber_snapshot(self):
        server = sf_mcp.build_checkpoint()
        cid = server.tools["snapshot"].handler({"workspace":"project"}).split()[1]
        (self.ws / "seed.txt").write_text("changed")
        server.tools["diff"].handler({"workspace":"project","checkpoint":cid})
        server.tools["undo"].handler({"workspace":"project","checkpoint":cid})
        self.assertEqual((self.ws / "seed.txt").read_text(), "original")


# --------------------------------------------------------------------------- #
# STAGE F -- the syscall filter
# --------------------------------------------------------------------------- #
AUDIT_ARCH_X86_64 = 0xC000003E
AUDIT_ARCH_I386 = 0x40000003
DENY = 0x00050000 | 1                     # SECCOMP_RET_ERRNO(EPERM)
ALLOW = 0x7FFF0000
KILL = 0x80000000

# Calls a payload uses constantly. If the filter ever answers one of these the
# sandbox is broken, not secure, and the list is here so that a table edit which
# collides with one is caught by a test rather than by a failing agent run.
PAYLOAD_SYSCALLS = {"read": 0, "write": 1, "close": 3, "mmap": 9, "rt_sigaction": 13,
                    "ioctl": 16, "socket": 41, "connect": 42, "clone": 56,
                    "execve": 59, "exit": 60, "futex": 202, "openat": 257,
                    "unshare": 272, "seccomp": 317, "getrandom": 318,
                    "clone3": 435, "exit_group": 231}


def evaluate(program, arch, nr):
    """Run the assembled program the way the kernel's BPF machine would.

    Spelled out rather than trusted, because the whole filter is jump offsets
    and an offset that is one too large silently ALLOWS the call it was written
    to deny. Nothing else about the program would look any different.
    """
    instructions = [struct.unpack_from("=HBBI", program, offset)
                    for offset in range(0, len(program), 8)]
    data = {0: nr & 0xFFFFFFFF, 4: arch}
    accumulator = 0
    counter = 0
    for _ in range(10000):
        code, jt, jf, k = instructions[counter]
        counter += 1
        if code == 0x20:                                  # BPF_LD|BPF_W|BPF_ABS
            accumulator = data[k]
        elif code == 0x15:                                # BPF_JMP|BPF_JEQ|BPF_K
            counter += jt if accumulator == k else jf
        elif code == 0x35:                                # BPF_JMP|BPF_JGE|BPF_K
            counter += jt if accumulator >= k else jf
        elif code == 0x06:                                # BPF_RET|BPF_K
            return k
        else:
            raise AssertionError("unknown opcode 0x%02x" % code)
    raise AssertionError("the program does not terminate")


class SyscallProgramTests(unittest.TestCase):
    """The program itself, before any kernel is involved."""

    def test_every_denied_number_returns_eperm_and_nothing_else_does(self):
        """The measurement this replaced: before Stage F every one of these
        numbers returned whatever the capability check said, which for mount,
        chroot, pivot_root, fsopen and open_tree was EPERM until one
        unshare(CLONE_NEWUSER|CLONE_NEWNS), after which they returned 0."""
        program = fb.seccomp_program()
        for name, number, _, _ in fb.SECCOMP_DENY:
            with self.subTest(denied=name):
                self.assertEqual(evaluate(program, AUDIT_ARCH_X86_64, number), DENY)
        for name, number in PAYLOAD_SYSCALLS.items():
            with self.subTest(permitted=name):
                self.assertEqual(evaluate(program, AUDIT_ARCH_X86_64, number), ALLOW)

    def test_a_foreign_personality_is_killed_rather_than_run_unfiltered(self):
        """165 is mount on x86_64 and getpgrp on i386. A filter that let another
        personality through would deny nothing at all to a task that asked in a
        different dialect, so the architecture gate is the first instruction."""
        program = fb.seccomp_program()
        for number in (165, 0, 1, 435):
            self.assertEqual(evaluate(program, AUDIT_ARCH_I386, number), KILL)

    def test_the_x32_numbering_is_refused(self):
        """x32 reports AUDIT_ARCH_X86_64 and renumbers every call above
        0x40000000, so the deny list would miss all of it."""
        program = fb.seccomp_program()
        for number in (0, 1, 165, 425):
            self.assertEqual(evaluate(program, AUDIT_ARCH_X86_64, 0x40000000 | number),
                             DENY)

    def test_the_jump_arithmetic_holds_for_a_table_of_any_size(self):
        """Sizes, because the offsets are computed from the table length and a
        table that grows is the way this breaks."""
        for size in (1, 2, 17, 60, 249):
            with self.subTest(size=size):
                table = tuple(("synthetic%d" % n, 3000 + n, fb.PERMITTED, None)
                              for n in range(size))
                with patch.object(fb, "SECCOMP_DENY", table):
                    program = fb.seccomp_program()
                for _, number, _, _ in table:
                    self.assertEqual(evaluate(program, AUDIT_ARCH_X86_64, number), DENY)
                self.assertEqual(evaluate(program, AUDIT_ARCH_X86_64, 2999), ALLOW)
                self.assertEqual(evaluate(program, AUDIT_ARCH_X86_64, 3000 + size), ALLOW)

    def test_a_table_too_big_for_a_one_byte_jump_refuses_to_assemble(self):
        """Past ~250 entries the offset wraps and the program starts ALLOWING
        what it lists. Silence there would be the worst possible failure."""
        table = tuple(("synthetic%d" % n, 3000 + n, fb.PERMITTED, None)
                      for n in range(300))
        with patch.object(fb, "SECCOMP_DENY", table):
            with self.assertRaisesRegex(fb.SeccompUnavailable, "single-byte"):
                fb.seccomp_program()

    def test_the_table_is_distinct(self):
        numbers = [row[1] for row in fb.SECCOMP_DENY]
        names = [row[0] for row in fb.SECCOMP_DENY]
        self.assertEqual(len(set(numbers)), len(numbers))
        self.assertEqual(len(set(names)), len(names))

    def test_the_filter_takes_away_things_that_were_measurably_reachable(self):
        """A deny list of calls that were already refused is a claim with no
        content. These were measured REACHED inside a real Firebreak sandbox by
        tools/probes/stage_f_syscalls.py before the filter existed:
        io_uring_setup REACHED:3, ptrace REACHED:0, keyctl REACHED:986675458,
        add_key REACHED:837273778, process_vm_readv REACHED:16, and mount
        REACHED:0 after one unshare(CLONE_NEWUSER|CLONE_NEWNS)."""
        reachable = fb.seccomp_reachable()
        for name in ("io_uring_setup", "ptrace", "keyctl", "add_key",
                     "process_vm_readv", "mount", "chroot", "pivot_root"):
            self.assertIn(name, reachable)
        self.assertGreaterEqual(len(reachable), 20)

    def test_calls_a_payload_needs_are_deliberately_absent(self):
        """unshare and clone stay permitted so a payload can still sandbox
        ITSELF -- glibc starts threads with clone3, and node and chrome build
        their own namespaces. The filter does not need them: it is inherited
        into whatever namespace the payload makes, and what that namespace would
        be FOR is denied. uselib stays out for the opposite reason: it answered
        ENOSYS, so denying it would read like a control and remove nothing."""
        numbers = {row[1] for row in fb.SECCOMP_DENY}
        for name in ("unshare", "clone", "clone3", "seccomp", "socket", "connect"):
            self.assertNotIn(PAYLOAD_SYSCALLS[name], numbers, name)
        self.assertNotIn(134, numbers)                    # uselib


class SyscallDescriptorTests(unittest.TestCase):
    """The descriptor bwrap is handed, and what the record says about it."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.ws = self.base / "Workspaces" / "project"
        self.ws.mkdir(parents=True)
        self.env = patch.dict(os.environ, {
            "SHADOWFETCH_AGENT_WORKSPACES": str(self.ws.parent),
            "SHADOWFETCH_FIREBREAK_STATE": str(self.base / "state"),
            "SHADOWFETCH_ELEMENT": "ice"})
        self.env.start()
        self.addCleanup(self.env.stop)

    def spec(self, **values):
        defaults = dict(net=None, read=[], credential_env=[], keep_secrets=False,
                        workspace_mode="workspace-write", agent_command=["true"],
                        memory_mb=4096, cpu_seconds=900, processes=128,
                        egress_host=[], mask_path=[], codex_account=False)
        defaults.update(values)
        return argparse.Namespace(**defaults)

    def built(self, **values):
        args = self.spec(**values)
        command, net, grants, credentials = fb.arguments(args, self.ws, "stage-f")
        fd = fb.seccomp_fd_in(command)
        self.addCleanup(lambda: os.close(fd) if fd is not None else None)
        return args, command, net, grants, credentials

    def test_the_descriptor_holds_the_program_and_cannot_be_rewritten(self):
        """The bytes enforcement() checks have to be the bytes bwrap loads. A
        plain memfd left a window between the two in which anything holding the
        descriptor -- this process included -- could swap the program."""
        args, command, *_ = self.built()
        fd = fb.seccomp_fd_in(command)
        program = fb.seccomp_program()
        self.assertEqual(os.pread(fd, len(program) + 1, 0), program)
        # bwrap reads from the current offset, so it must still be at the start.
        self.assertEqual(os.lseek(fd, 0, os.SEEK_CUR), 0)
        with self.assertRaises(OSError) as sealed:
            os.pwrite(fd, b"\x00" * 8, 0)
        self.assertEqual(sealed.exception.errno, errno.EPERM)

    def test_the_argv_hands_bwrap_that_descriptor_and_the_row_reads_it_back(self):
        args, command, net, grants, credentials = self.built()
        fd = fb.seccomp_fd_in(command)
        self.assertIn("--seccomp", command)
        self.assertEqual(command[command.index("--seccomp") + 1], str(fd))
        row = fb.enforcement(command, args, self.ws, grants, credentials, net)["syscall_profile"]
        self.assertEqual(row["status"], fb.ENFORCED)
        self.assertIn(fb.seccomp_digest(), row["mechanism"])
        self.assertIn("seccomp-BPF", row["mechanism"])

    def test_a_descriptor_holding_something_else_is_reported_not_enforced(self):
        """THE POINT OF READING THE DESCRIPTOR. A row that checked only for the
        flag would call this session filtered; the program bwrap would load is
        not the program this build assembles."""
        args, command, net, grants, credentials = self.built()
        decoy = os.memfd_create("not-the-filter", 0)
        self.addCleanup(os.close, decoy)
        os.write(decoy, b"\x00" * len(fb.seccomp_program()))
        forged = list(command)
        forged[forged.index("--seccomp") + 1] = str(decoy)
        row = fb.enforcement(forged, args, self.ws, grants, credentials, net)["syscall_profile"]
        self.assertEqual(row["status"], fb.NOT_ENFORCED)
        self.assertIn("does not hold", row["mechanism"])

    def test_an_argv_without_the_flag_is_reported_not_enforced(self):
        args, command, net, grants, credentials = self.built()
        index = command.index("--seccomp")
        stripped = command[:index] + command[index + 2:]
        row = fb.enforcement(stripped, args, self.ws, grants, credentials, net)["syscall_profile"]
        self.assertEqual(row["status"], fb.NOT_ENFORCED)
        self.assertIn("no seccomp program", row["mechanism"])

    def test_a_descriptor_that_cannot_be_sealed_is_a_refusal_and_not_a_traceback(self):
        """SeccompUnavailable is the only exception _run() catches to write a
        refusal record. Until this was fixed, an OSError from the sealing call
        escaped as a bare traceback: the run still stopped, correctly, but left
        the audit directory looking as though nobody had asked -- which is the
        exact failure the egress filter's refusal record already exists for."""
        with patch.object(fb.fcntl, "fcntl",
                          side_effect=OSError(errno.EINVAL, "no sealing here")):
            with self.assertRaisesRegex(fb.SeccompUnavailable, "could not be sealed"):
                fb.seccomp_filter_fd()
        with patch.object(fb.os, "memfd_create",
                          side_effect=OSError(errno.ENOSYS, "no memfd here")):
            with self.assertRaisesRegex(fb.SeccompUnavailable, "no anonymous descriptor"):
                fb.seccomp_filter_fd()

    def test_a_kernel_that_will_not_load_the_filter_produces_no_argv_at_all(self):
        """Match the egress filter: refuse rather than start unfiltered. Before
        this, there was nothing to refuse -- a session simply ran."""
        with patch.object(fb, "seccomp_selftest",
                          side_effect=fb.SeccompUnavailable("kernel refused it")):
            with self.assertRaises(fb.SeccompUnavailable):
                fb.arguments(self.spec(), self.ws, "stage-f")

    def test_the_self_test_measures_the_filter_rather_than_describing_it(self):
        """It loads the real program in a child and makes a denied call and a
        permitted call under it. A version check would pass on a kernel where
        the program does not actually deny anything."""
        fb._SECCOMP_VERIFIED = None
        self.addCleanup(setattr, fb, "_SECCOMP_VERIFIED", None)
        # The words come from the child that ran under the filter: it sends
        # them with write(2), which the filter permits, only after adjtimex --
        # measured REACHED:0 in this sandbox before Stage F -- returned EPERM
        # under it. A self-test that merely checked a kernel version would say
        # the same thing on a kernel that denies nothing.
        self.assertEqual(fb.seccomp_selftest(),
                         "seccomp-bpf self-test: denied-EPERM permitted-write")


LIVE_SANDBOX = (os.path.isfile("/usr/bin/bwrap")
                and shutil.which("systemd-run") is not None
                and Path("/run/user/%d/bus" % os.getuid()).is_socket())

LIVE_PROBE = r"""
import ctypes, errno, json, os
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
def raw(nr, *a):
    conv = [ctypes.c_char_p(x) if isinstance(x, bytes) else ctypes.c_long(x) for x in a]
    ctypes.set_errno(0)
    if libc.syscall(ctypes.c_long(nr), *conv) == -1:
        return "blocked:" + errno.errorcode.get(ctypes.get_errno(), "?")
    return "REACHED"
out = {}
out["mount"] = raw(165, b"none", b"/tmp", b"tmpfs", 0, 0)
out["ptrace"] = raw(101, 16, os.getpid(), 0, 0)
out["keyctl"] = raw(250, 0, -3, 1)
out["io_uring_setup"] = raw(425, 1, 0)
out["name_to_handle_at"] = raw(303, -100, b"/tmp", 0, 0, 0)
out["adjtimex"] = raw(159, 0)
out["process_vm_readv"] = raw(310, os.getpid(), 0, 1, 0, 1, 0)
# The escalation the capability check does not survive: a user namespace of the
# payload's own, in which it holds every capability, and mount tried again.
pid = os.fork()
if pid == 0:
    step = raw(272, 0x10000000 | 0x00020000)
    os.write(1, ("ESCALATED " + json.dumps({
        "unshare": step,
        "mount_after_unshare": raw(165, b"none", b"/tmp", b"tmpfs", 0, 0),
        "chroot_after_unshare": raw(161, b"/tmp")}) + "\n").encode())
    os._exit(0)
os.waitpid(pid, 0)
with open("written-by-the-payload.txt", "w") as handle:
    handle.write("workspace still writable")
import subprocess, threading
out["python3"] = subprocess.run(["/usr/bin/python3", "-c", "print('ok')"],
                                capture_output=True, text=True).stdout.strip()
box = []
t = threading.Thread(target=lambda: box.append("threads work")); t.start(); t.join()
out["threads"] = box[0]
out["workspace_write"] = open("written-by-the-payload.txt").read()
print("DENIED " + json.dumps(out))
"""


@unittest.skipUnless(LIVE_SANDBOX, "needs bwrap, systemd-run and a user bus")
class SyscallFilterSandboxTests(unittest.TestCase):
    """A real sandbox. Everything above is about the program; this is the kernel."""

    FIREBREAK = BASE / "data/usr/bin/shadowfetch-firebreak"

    def test_a_real_sandbox_denies_the_reachable_calls_and_still_works(self):
        """Every one of these was REACHED here before Stage F -- see the
        docstring of test_the_filter_takes_away_things_that_were_measurably
        _reachable for the values -- and mount came back after one unshare."""
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp).resolve()
            ws = base / "Workspaces" / "live"
            ws.mkdir(parents=True)
            (ws / "probe.py").write_text(LIVE_PROBE)
            environment = dict(os.environ)
            environment["SHADOWFETCH_AGENT_WORKSPACES"] = str(ws.parent)
            environment["SHADOWFETCH_FIREBREAK_STATE"] = str(base / "state")
            environment["SHADOWFETCH_ELEMENT"] = "ice"
            done = subprocess.run(
                [sys.executable, str(self.FIREBREAK), "run", "--workspace", "live",
                 "--net", "none", "--no-checkpoint", "--memory-mb", "1024",
                 "--cpu-seconds", "120", "--processes", "32",
                 "--", "/usr/bin/python3", "probe.py"],
                capture_output=True, text=True, timeout=300, env=environment)
        denied = next((json.loads(l[len("DENIED "):]) for l in done.stdout.splitlines()
                       if l.startswith("DENIED ")), None)
        escalated = next((json.loads(l[len("ESCALATED "):]) for l in done.stdout.splitlines()
                          if l.startswith("ESCALATED ")), None)
        self.assertIsNotNone(denied, done.stdout + done.stderr)
        self.assertIsNotNone(escalated, done.stdout + done.stderr)
        for call in ("mount", "ptrace", "keyctl", "io_uring_setup",
                     "name_to_handle_at", "adjtimex", "process_vm_readv"):
            self.assertEqual(denied[call], "blocked:EPERM", call)
        # The escalation still happens -- unshare is deliberately permitted --
        # and buys nothing, because the filter came with it.
        self.assertEqual(escalated["unshare"], "REACHED")
        self.assertEqual(escalated["mount_after_unshare"], "blocked:EPERM")
        self.assertEqual(escalated["chroot_after_unshare"], "blocked:EPERM")
        # A sandbox that cannot do these is broken, not secure.
        self.assertEqual(denied["python3"], "ok")
        self.assertEqual(denied["threads"], "threads work")
        self.assertEqual(denied["workspace_write"], "workspace still writable")

    def test_bwrap_refuses_to_start_when_the_descriptor_is_not_readable(self):
        """Why an inheritance failure cannot silently produce an unfiltered run.
        The descriptor crosses two execve's before bwrap reads it; if it did not
        arrive, this is what happens instead of a sandbox."""
        done = subprocess.run(
            ["/usr/bin/bwrap", "--ro-bind", "/usr", "/usr", "--symlink", "usr/bin",
             "/bin", "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64",
             "/lib64", "--unshare-user", "--seccomp", "77", "--", "/usr/bin/true"],
            capture_output=True, text=True, timeout=60)
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("seccomp", done.stderr.lower())


if __name__ == "__main__":
    unittest.main(verbosity=2)
