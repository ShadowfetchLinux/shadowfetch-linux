"""Fake-filesystem harness for the Phoenix recovery scripts.

Nothing in here touches the real machine. Every privileged or destructive
command phoenix-restore calls (mount, umount, btrfs, grub-reboot, update-grub,
grub-editenv, blkid, findmnt, id, mktemp, sync) is replaced by a stub on PATH,
and the two absolute paths the script cannot be told about - /boot and the
/run mktemp template - are rewritten to sandbox paths in a COPY of the script.

The rewrite is deliberate: /boot must NOT become an environment-controlled path
in a tool that runs as root through pkexec, so the test adapts the script
instead of the script adapting to the test. Every rewrite asserts its hit count,
so a future edit that changes how /boot is reached fails the tests loudly rather
than silently escaping the sandbox.
"""

import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PHOENIX = ROOT / "packages/shadowfetch-phoenix"
RESTORE = PHOENIX / "usr/libexec/phoenix-restore"
REPORT = PHOENIX / "usr/libexec/phoenix-recovery-report"
CHECK_LAYOUT = PHOENIX / "usr/libexec/phoenix-check-layout"

OLD_KERNEL = "6.1.0-old"      # the kernel of the Point being restored
NEW_KERNEL = "6.9.0-new"      # the kernel of the root being replaced
FAKE_UUID = "fakeuuid-0000-1111-2222-333344445555"


def a_block_device() -> str:
    """Any existing block device node. The stubs never read or write it; the
    script only needs `test -b` to succeed on the path findmnt reports."""
    dev = Path("/dev")
    names = sorted(p.name for p in dev.iterdir() if p.name.startswith("loop"))
    names += sorted(p.name for p in dev.iterdir())
    for name in names:
        path = dev / name
        try:
            if stat.S_ISBLK(os.stat(path).st_mode):
                return str(path)
        except OSError:
            continue
    raise unittest.SkipTest("no block device node available for the harness")


EXCHANGE_HELPER = '''\
"""renameat2(RENAME_EXCHANGE) - what `mv --exchange` (coreutils >= 9.5) does.

Shadowfetch ships against coreutils >= 9.5; build hosts older than that get
this shim so the tests still exercise the real atomic-exchange syscall rather
than a copy-and-swap imitation.
"""
import ctypes, os, sys

AT_FDCWD, RENAME_EXCHANGE = -100, 2
libc = ctypes.CDLL(None, use_errno=True)
fn = getattr(libc, "renameat2", None)
old, new = sys.argv[1].encode(), sys.argv[2].encode()
if fn is not None:
    fn.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                   ctypes.c_char_p, ctypes.c_uint]
    rc = fn(AT_FDCWD, old, AT_FDCWD, new, RENAME_EXCHANGE)
else:                                   # x86_64 SYS_renameat2
    rc = libc.syscall(316, AT_FDCWD, old, AT_FDCWD, new, RENAME_EXCHANGE)
if rc != 0:
    err = ctypes.get_errno()
    sys.stderr.write("renameat2: %s\\n" % os.strerror(err))
    sys.exit(1)
'''


def real_mv_supports_exchange(where: Path) -> bool:
    a, b = where / "_mv_a", where / "_mv_b"
    a.mkdir()
    b.mkdir()
    try:
        return subprocess.run(
            ["mv", "--exchange", "--no-target-directory", str(a), str(b)],
            capture_output=True, check=False).returncode == 0
    finally:
        shutil.rmtree(a, ignore_errors=True)
        shutil.rmtree(b, ignore_errors=True)


def kernel_supports_exchange(where: Path) -> bool:
    helper = where / "_exchange_probe.py"
    helper.write_text(EXCHANGE_HELPER)
    a, b = where / "_k_a", where / "_k_b"
    a.mkdir()
    b.mkdir()
    try:
        return subprocess.run(["python3", str(helper), str(a), str(b)],
                              capture_output=True, check=False).returncode == 0
    finally:
        shutil.rmtree(a, ignore_errors=True)
        shutil.rmtree(b, ignore_errors=True)
        helper.unlink(missing_ok=True)


def tree_state(root: Path) -> dict:
    """Every path under root plus the contents of small files: the comparison
    used to prove --dry-run changed nothing."""
    state = {}
    for path in sorted(root.rglob("*")):
        rel = str(path.relative_to(root))
        if path.is_dir():
            state[rel] = "<dir>"
        elif path.is_symlink():
            state[rel] = "<link>" + os.readlink(path)
        else:
            state[rel] = path.read_bytes()[:4096]
    return state


class Sandbox:
    """A fake Btrfs volume, a fake external /boot and a stub PATH."""

    def __init__(self, base: Path):
        self.base = base
        self.bin = base / "bin"
        self.volume = base / "volume"
        self.boot = base / "boot"
        self.runtmp = base / "run"
        self.state = base / "state"
        self.log = base / "calls.log"
        self.dev = a_block_device()
        for d in (self.bin, self.volume, self.boot, self.runtmp, self.state):
            d.mkdir(parents=True, exist_ok=True)

    # -- fake volume -------------------------------------------------------
    def build_volume(self) -> None:
        root = self.volume / "@"
        (root / "var/lib/shadowfetch").mkdir(parents=True)
        (root / f"lib/modules/{NEW_KERNEL}").mkdir(parents=True)
        (root / "generation").write_text("OLD-ROOT\n")

        point = self.volume / "@snapshots/1/snapshot"
        (point / "var/lib/shadowfetch").mkdir(parents=True)
        (point / f"lib/modules/{OLD_KERNEL}").mkdir(parents=True)
        (point / "generation").write_text("POINT-1\n")

    def build_boot(self) -> None:
        (self.boot / "grub").mkdir(parents=True)
        for kernel in (OLD_KERNEL, NEW_KERNEL):
            for prefix in ("vmlinuz", "initrd.img", "config", "System.map"):
                (self.boot / f"{prefix}-{kernel}").write_text(f"{prefix} {kernel}\n")
        (self.boot / "grub/grub.cfg").write_text(
            "menuentry 'Shadowfetch' --id 'gnulinux-simple' {}\n"
            f"submenu 'Advanced' --id 'gnulinux-advanced-{FAKE_UUID}' {{\n"
            f"  menuentry 'old' --id 'gnulinux-{OLD_KERNEL}-advanced-{FAKE_UUID}' {{}}\n"
            f"  menuentry 'new' --id 'gnulinux-{NEW_KERNEL}-advanced-{FAKE_UUID}' {{}}\n"
            "}\n")
        (self.boot / "grub/grubenv").write_text("# GRUB Environment Block\n")

    # -- stubs -------------------------------------------------------------
    def write_stub(self, name: str, body: str) -> None:
        path = self.bin / name
        path.write_text("#!/bin/sh\n" + body)
        path.chmod(0o755)

    def build_stubs(self, kill_on_update_grub: str = "") -> None:
        log = self.log
        self.write_stub("id", f"""
printf 'id %s\\n' "$*" >> "{log}"
case "${{1:-}}" in
  -u) echo 0 ;;
  -gn) echo testgroup ;;
  *) echo 0 ;;
esac
""")
        self.write_stub("findmnt", f"""
printf 'findmnt %s\\n' "$*" >> "{log}"
what=
for a in "$@"; do
  case "$a" in FSTYPE|SOURCE) what=$a ;; esac
done
case "$what" in
  FSTYPE) echo btrfs ;;
  SOURCE) echo '{self.dev}[/@]' ;;
esac
""")
        self.write_stub("blkid", f"""
printf 'blkid %s\\n' "$*" >> "{log}"
echo '{FAKE_UUID}'
""")
        # mktemp -d <run>/phoenix-restore.XXXXXX must land ON the fake volume:
        # the script then treats it as the mounted top-level.
        self.write_stub("mktemp", f"""
printf 'mktemp %s\\n' "$*" >> "{log}"
echo '{self.volume}'
""")
        self.write_stub("mount", f"""
printf 'mount %s\\n' "$*" >> "{log}"
: > '{self.state}/mounted'
""")
        self.write_stub("umount", f"""
printf 'umount %s\\n' "$*" >> "{log}"
rm -f '{self.state}/mounted'
""")
        self.write_stub("mountpoint", f"""
printf 'mountpoint %s\\n' "$*" >> "{log}"
target=
for a in "$@"; do case "$a" in -*) ;; *) target=$a ;; esac; done
case "$target" in
  '{self.boot}') exit 0 ;;
  '{self.volume}') [ -f '{self.state}/mounted' ] ;;
  *) exit 1 ;;
esac
""")
        self.write_stub("btrfs", f"""
printf 'btrfs %s\\n' "$*" >> "{log}"
case "$1 $2" in
  'subvolume show')     [ -d "$3" ] ;;
  'subvolume snapshot') cp -a "$3" "$4" ;;
  'subvolume delete')   rm -rf "$3" ;;
  'filesystem sync')    : ;;
  *) : ;;
esac
""")
        self.write_stub("grub-reboot", f"""
printf 'grub-reboot %s\\n' "$*" >> "{log}"
""")
        self.write_stub("grub-editenv", f"""
printf 'grub-editenv %s\\n' "$*" >> "{log}"
""")
        self.write_stub("sync", f"""
printf 'sync %s\\n' "$*" >> "{log}"
""")
        # Only on a build host older than coreutils 9.5: keep `mv --exchange`
        # working (through the same renameat2 syscall) so the exchange under
        # test is the real one. Every other mv goes to the real binary.
        self.mv_shim = not real_mv_supports_exchange(self.base)
        if self.mv_shim:
            helper = self.bin / "mv-exchange-helper.py"
            helper.write_text(EXCHANGE_HELPER)
            real_mv = shutil.which("mv", path="/usr/bin:/bin")
            self.write_stub("mv", f"""
if [ "$1" = "--exchange" ] && [ "$2" = "--no-target-directory" ]; then
    printf 'mv --exchange %s %s\\n' "$3" "$4" >> "{log}"
    exec python3 '{helper}' "$3" "$4"
fi
exec '{real_mv}' "$@"
""")
        kill_line = ""
        if kill_on_update_grub:
            # Models the interruption in the finding: the signal arrives once
            # /boot has been staged for the restored Point and before the root
            # subvolume exchange. One shot only - the rollback runs update-grub
            # again and must not be re-interrupted by the harness.
            kill_line = (
                f'if [ ! -f "{self.state}/signalled" ]; then\n'
                f'  : > "{self.state}/signalled"\n'
                f'  kill -{kill_on_update_grub} "$PPID" 2>/dev/null || true\n'
                f'  sleep 1\n'
                'fi\n')
        self.write_stub("update-grub", f"""
printf 'update-grub %s\\n' "$*" >> "{log}"
{kill_line}""")

    # -- running -----------------------------------------------------------
    def script_copy(self, source: Path, name: str) -> Path:
        text = source.read_text()
        boot_hits = text.count("/boot")
        text = text.replace("/boot", str(self.boot))
        run_hits = text.count("/run/phoenix-restore.XXXXXX")
        text = text.replace("/run/phoenix-restore.XXXXXX",
                            str(self.runtmp / "phoenix-restore.XXXXXX"))
        target = self.base / name
        target.write_text(text)
        target.chmod(0o755)
        self.rewrites = (boot_hits, run_hits)
        return target

    def run(self, script: Path, *args: str, timeout: int = 60):
        env = dict(os.environ)
        env["PATH"] = f"{self.bin}:{env.get('PATH', '')}"
        env["LC_ALL"] = "C"
        return subprocess.run(["/bin/sh", str(script), *args],
                              capture_output=True, text=True,
                              timeout=timeout, env=env, check=False)


class SandboxTestCase(unittest.TestCase):
    """Base class: one throwaway sandbox per test."""

    requires_exchange = True

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="phoenix-harness.")
        self.addCleanup(self._tmp.cleanup)
        base = Path(self._tmp.name)
        if (self.requires_exchange
                and not real_mv_supports_exchange(base)
                and not kernel_supports_exchange(base)):
            self.skipTest("no renameat2(RENAME_EXCHANGE) on this host")
        self.sb = Sandbox(base)
        self.sb.build_volume()
        self.sb.build_boot()
