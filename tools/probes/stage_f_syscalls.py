#!/usr/bin/env python3
"""Stage F: which syscalls does a real Firebreak sandbox actually let through?

Run this BEFORE the filter exists to get the baseline, and again afterwards.
The two columns are the whole argument: a denial that turns "REACHED" into
"blocked:EPERM" removed something the sandbox really had, and a denial that was
already "blocked:EPERM" before the filter existed removed nothing and must not
be claimed as if it had. Both outcomes are printed side by side so neither can
be quietly rounded up.

Every attempt runs in its own forked child, because some of them (chroot,
unshare, a successful mount) change the process that makes them, and because a
filter whose action is SIGSYS kills the caller rather than returning.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

# Which Firebreak to measure. The default is the one in the tree; point
# SHADOWFETCH_FIREBREAK_BIN at a copy taken before a change to get the
# before-and-after in two commands instead of by editing the tree back.
FB = Path(os.environ.get(
    "SHADOWFETCH_FIREBREAK_BIN",
    str(Path.home() / "projects/shadowfetch-4.0.0/packages/shadowfetch-fireline"
                      "/data/usr/bin/shadowfetch-firebreak")))
ROOT = Path(os.environ.get("SHADOWFETCH_AGENT_WORKSPACES", str(Path.home() / "Workspaces")))
WS = ROOT / "stagef"

PROBE = r'''
import ctypes, errno, json, os, struct, sys, time

libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long

def raw(nr, *args):
    """One syscall, by number, straight past glibc's wrappers.

    By number because that is the only thing a seccomp filter can see: a libc
    wrapper may substitute a different syscall (openat for open, clone3 for
    clone) and the measurement would then be of a syscall nobody denied.
    """
    conv = []
    for a in args:
        if isinstance(a, bytes):
            conv.append(ctypes.c_char_p(a))
        elif isinstance(a, int):
            conv.append(ctypes.c_long(a))
        else:
            conv.append(a)
    ctypes.set_errno(0)
    res = libc.syscall(ctypes.c_long(nr), *conv)
    if res == -1:
        code = ctypes.get_errno()
        return "blocked:" + errno.errorcode.get(code, str(code))
    return "REACHED:" + str(res)

CLONE_NEWUSER = 0x10000000
AT_FDCWD = -100

def t_mount():
    os.makedirs("/tmp/sf-mnt", exist_ok=True)
    return raw(165, b"none", b"/tmp/sf-mnt", b"tmpfs", 0, 0)
def t_umount2():      return raw(166, b"/tmp/sf-not-a-mount", 0)
def t_pivot_root():   return raw(155, b"/tmp/sf-not-a-dir", b"/tmp/sf-not-a-dir")
def t_chroot():       return raw(161, b"/tmp")
def t_open_tree():    return raw(428, AT_FDCWD, b"/tmp", 1)          # OPEN_TREE_CLONE
def t_move_mount():   return raw(429, -1, b"", -1, b"", 0)
def t_fsopen():       return raw(430, b"tmpfs", 0)
def t_fsconfig():     return raw(431, -1, 0, 0, 0, 0)
def t_fsmount():      return raw(432, -1, 0, 0)
def t_fspick():       return raw(433, AT_FDCWD, b"/tmp", 0)
def t_mount_setattr():return raw(442, AT_FDCWD, b"", 0, 0, 0)
def t_unshare_userns():return raw(272, CLONE_NEWUSER)
def t_setns():        return raw(308, -1, 0)
def t_ptrace():
    pid = os.fork()
    if pid == 0:
        time.sleep(4)
        os._exit(0)
    try:
        return raw(101, 16, pid, 0, 0)          # PTRACE_ATTACH on our own child
    finally:
        try:
            os.kill(pid, 9); os.waitpid(pid, 0)
        except OSError:
            pass
def t_process_vm_readv():
    buf = ctypes.create_string_buffer(16)
    src = ctypes.create_string_buffer(b"stage-f-readable", 17)
    local = (ctypes.c_void_p * 2)(ctypes.cast(buf, ctypes.c_void_p).value, 16)
    remote = (ctypes.c_void_p * 2)(ctypes.cast(src, ctypes.c_void_p).value, 16)
    return raw(310, os.getpid(), ctypes.byref(local), 1, ctypes.byref(remote), 1, 0)
def t_process_vm_writev():
    dst = ctypes.create_string_buffer(16)
    src = ctypes.create_string_buffer(b"stage-f-writable", 17)
    local = (ctypes.c_void_p * 2)(ctypes.cast(src, ctypes.c_void_p).value, 16)
    remote = (ctypes.c_void_p * 2)(ctypes.cast(dst, ctypes.c_void_p).value, 16)
    return raw(311, os.getpid(), ctypes.byref(local), 1, ctypes.byref(remote), 1, 0)
def t_keyctl():       return raw(250, 0, -3, 1)                      # GET_KEYRING_ID(session, create)
def t_add_key():      return raw(248, b"user", b"sf-stage-f", b"x", 1, -3)
def t_request_key():  return raw(249, b"user", b"sf-stage-f", 0, -3)
def t_bpf():
    attr = struct.pack("=IIIII", 1, 4, 4, 1, 0) + b"\0" * 100        # BPF_MAP_TYPE_ARRAY
    buf = ctypes.create_string_buffer(attr, len(attr))
    return raw(321, 0, ctypes.byref(buf), 20)                        # BPF_MAP_CREATE
def t_userfaultfd():  return raw(323, 0)
def t_perf_event_open():
    attr = bytearray(128)
    struct.pack_into("=IIQ", attr, 0, 1, 128, 0)                     # SW / size / CPU_CLOCK
    buf = ctypes.create_string_buffer(bytes(attr), 128)
    return raw(298, ctypes.byref(buf), 0, -1, -1, 0)
def t_io_uring_setup():
    params = ctypes.create_string_buffer(120)
    return raw(425, 1, ctypes.byref(params))
def t_io_uring_enter():  return raw(426, -1, 0, 0, 0, 0, 0)
def t_io_uring_register():return raw(427, -1, 0, 0, 0)
def t_init_module():  return raw(175, 0, 0, b"")
def t_finit_module(): return raw(313, -1, b"", 0)
def t_delete_module():return raw(176, b"sf-no-such-module", 0)
def t_kexec_load():   return raw(246, 0, 0, 0, 0)
def t_kexec_file_load():return raw(320, -1, -1, 0, b"", 0)
def t_swapon():       return raw(167, b"/tmp/sf-not-a-swapfile", 0)
def t_swapoff():      return raw(168, b"/tmp/sf-not-a-swapfile")
def t_reboot():       return raw(169, 0, 0, 0, 0)                    # bad magic; cap check comes first
def t_settimeofday():
    tv = struct.pack("=qq", int(time.time()), 0)
    buf = ctypes.create_string_buffer(tv, 16)
    return raw(164, ctypes.byref(buf), 0)
def t_clock_settime():
    now = time.clock_gettime(time.CLOCK_REALTIME)
    ts = struct.pack("=qq", int(now), int((now % 1) * 1e9))
    buf = ctypes.create_string_buffer(ts, 16)
    return raw(227, 0, ctypes.byref(buf))
def t_adjtimex():
    buf = ctypes.create_string_buffer(208)
    return raw(159, ctypes.byref(buf))
def t_clock_adjtime():
    buf = ctypes.create_string_buffer(208)
    return raw(305, 0, ctypes.byref(buf))
def t_open_by_handle_at():
    handle = struct.pack("=Ii", 8, 1) + b"\0" * 8
    buf = ctypes.create_string_buffer(handle, len(handle))
    return raw(304, -1, ctypes.byref(buf), 0)
def t_name_to_handle_at():
    buf = ctypes.create_string_buffer(128)
    struct.pack_into("=Ii", buf, 0, 120, 0)
    mnt = ctypes.c_int(0)
    return raw(303, AT_FDCWD, b"/tmp", ctypes.byref(buf), ctypes.byref(mnt), 0)
def t_syslog():
    buf = ctypes.create_string_buffer(256)
    return raw(103, 3, ctypes.byref(buf), 256)                       # SYSLOG_ACTION_READ_ALL
def t_quotactl():     return raw(179, 0, b"/dev/null", 0, 0)
def t_acct():         return raw(163, 0)
def t_iopl():         return raw(172, 3)
def t_ioperm():       return raw(173, 0, 1, 1)
def t_fanotify_init():return raw(300, 0, 0)
def t_vhangup():      return raw(153)
def t_uselib():       return raw(134, b"/tmp/sf-not-a-library")
def t_kcmp():         return raw(312, os.getpid(), os.getpid(), 0, 0, 0)

# THE ESCALATION CHAIN. mount and chroot come back EPERM above, and that is not
# because the kernel refuses them to this workload -- it is because bwrap drops
# every capability before exec. One unshare(CLONE_NEWUSER|CLONE_NEWNS) hands the
# payload a user namespace it owns, with a full capability set in it and a mount
# namespace owned by it, and the same calls are tried again there. Whatever this
# section REACHES is what the sandbox really permits; the plain rows above only
# say what the FIRST attempt costs.
CLONE_NEWNS = 0x00020000

def escalate():
    return raw(272, CLONE_NEWUSER | CLONE_NEWNS)

def t_esc_mount():
    os.makedirs("/tmp/sf-esc", exist_ok=True)
    step = escalate()
    if step.startswith("blocked"):
        return "unshare " + step
    return "unshare ok -> mount " + raw(165, b"none", b"/tmp/sf-esc", b"tmpfs", 0, 0)
def t_esc_chroot():
    step = escalate()
    if step.startswith("blocked"):
        return "unshare " + step
    return "unshare ok -> chroot " + raw(161, b"/tmp")
def t_esc_pivot_root():
    os.makedirs("/tmp/sf-piv/old", exist_ok=True)
    step = escalate()
    if step.startswith("blocked"):
        return "unshare " + step
    mounted = raw(165, b"none", b"/tmp/sf-piv", b"tmpfs", 0, 0)
    return "unshare ok -> mount " + mounted + " -> pivot_root " + raw(155, b"/tmp/sf-piv", b"/tmp/sf-piv")
def t_esc_fsopen():
    step = escalate()
    if step.startswith("blocked"):
        return "unshare " + step
    return "unshare ok -> fsopen " + raw(430, b"tmpfs", 0)
def t_esc_open_tree():
    step = escalate()
    if step.startswith("blocked"):
        return "unshare " + step
    return "unshare ok -> open_tree " + raw(428, AT_FDCWD, b"/tmp", 1)
def t_esc_userfaultfd():
    step = escalate()
    if step.startswith("blocked"):
        return "unshare " + step
    return "unshare ok -> userfaultfd " + raw(323, 0)
def t_esc_bpf():
    step = escalate()
    if step.startswith("blocked"):
        return "unshare " + step
    attr = struct.pack("=IIIII", 1, 4, 4, 1, 0) + b"\0" * 100
    buf = ctypes.create_string_buffer(attr, len(attr))
    return "unshare ok -> bpf " + raw(321, 0, ctypes.byref(buf), 20)
def t_esc_setns_host_net():
    # Rejoining a namespace by fd. There is nothing to rejoin from inside, but
    # the errno separates "the kernel would have considered it" from "the filter
    # never let it ask".
    step = escalate()
    if step.startswith("blocked"):
        return "unshare " + step
    return "unshare ok -> setns " + raw(308, -1, 0)

# The permitted side. A sandbox that cannot do these is broken, not secure.
def p_write_workspace():
    path = os.path.join(os.getcwd(), "stage-f-write.txt")
    with open(path, "w") as handle:
        handle.write("written")
    with open(path) as handle:
        return "REACHED:" + handle.read()
def p_fork_exec():
    import subprocess as sp
    out = sp.run(["/usr/bin/python3", "-c", "print('child-ok')"],
                 capture_output=True, text=True, timeout=30)
    return "REACHED:" + out.stdout.strip() if out.returncode == 0 else "blocked:rc" + str(out.returncode)
def p_thread():
    import threading
    box = []
    t = threading.Thread(target=lambda: box.append("threaded"))
    t.start(); t.join()
    return "REACHED:" + (box[0] if box else "none")
def p_mmap_large():
    import mmap
    m = mmap.mmap(-1, 64 * 1024 * 1024)
    m[0:4] = b"abcd"
    value = bytes(m[0:4]).decode()
    m.close()
    return "REACHED:" + value
def p_socket_dns():
    import socket
    try:
        infos = socket.getaddrinfo("api.openai.com", 443, socket.AF_INET, socket.SOCK_STREAM)
    except OSError as exc:
        return "blocked:getaddrinfo:" + type(exc).__name__
    return "REACHED:" + infos[0][4][0]
def p_socket_connect_allowed():
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(15)
    try:
        s.connect(("api.openai.com", 443))
        return "REACHED:connected"
    except OSError as exc:
        return "blocked:" + type(exc).__name__ + ":" + str(exc)[:40]
    finally:
        s.close()
def p_socket_connect_denied():
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(8)
    try:
        s.connect(("1.1.1.1", 443))
        return "REACHED:connected"
    except OSError as exc:
        return "blocked:" + type(exc).__name__ + ":" + str(exc)[:40]
    finally:
        s.close()
def p_openat_read_etc():
    with open("/etc/passwd") as handle:
        return "REACHED:" + str(len(handle.read())) + "b"
def p_clone3_threads():
    # glibc >= 2.34 starts threads with clone3 and falls back to clone on
    # ENOSYS. A filter that answers clone3 with EPERM instead breaks every
    # threaded payload, so the outcome of this one decides whether clone3 may
    # appear in a deny list at all.
    import threading
    done = []
    ts = [threading.Thread(target=lambda: done.append(1)) for _ in range(8)]
    for t in ts: t.start()
    for t in ts: t.join()
    return "REACHED:" + str(len(done)) + " threads"

DENIED = [n for n in sorted(dir()) if n.startswith("t_")]
PERMITTED = [n for n in sorted(dir()) if n.startswith("p_")]

def attempt(fn):
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        try:
            value = fn()
        except BaseException as exc:
            value = "error:" + type(exc).__name__ + ":" + str(exc)[:60]
        try:
            os.write(write_fd, json.dumps(value).encode()[:2000])
        except OSError:
            pass
        os._exit(0)
    os.close(write_fd)
    with os.fdopen(read_fd, "rb") as handle:
        data = handle.read()
    _, status = os.waitpid(pid, 0)
    if os.WIFSIGNALED(status):
        return "KILLED:SIG%d" % os.WTERMSIG(status)
    if not data:
        return "no-result:exit%d" % os.WEXITSTATUS(status)
    return json.loads(data)

out = {"denied": {}, "permitted": {}}
scope = dict(globals())
for name in DENIED:
    out["denied"][name[2:]] = attempt(scope[name])
for name in PERMITTED:
    out["permitted"][name[2:]] = attempt(scope[name])
print("RESULT " + json.dumps(out))
'''


def run(label, extra):
    WS.mkdir(parents=True, exist_ok=True)
    (WS / "probe.py").write_text(PROBE)
    cmd = [sys.executable, str(FB), "run", "--workspace", "stagef",
           "--no-checkpoint", "--memory-mb", "2048", "--cpu-seconds", "300",
           "--processes", "64", *extra, "--", "/usr/bin/python3", "probe.py"]
    done = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
    line = next((l for l in done.stdout.splitlines() if l.startswith("RESULT ")), None)
    if not line:
        print("\n== %s == NO RESULT rc=%d" % (label, done.returncode))
        print(done.stdout[-3000:])
        print(done.stderr[-3000:])
        return None
    return json.loads(line[7:])


if __name__ == "__main__":
    postures = {
        "net-none": ["--net", "none"],
        "net-allow+egress": ["--net", "allow", "--egress-host", "api.openai.com"],
    }
    results = {}
    for label, extra in postures.items():
        if len(sys.argv) > 1 and sys.argv[1] not in ("all", label):
            continue
        results[label] = run(label, extra)
    for label, result in results.items():
        if not result:
            continue
        print("\n===== %s =====" % label)
        print("-- candidates for denial --")
        for name, value in result["denied"].items():
            print("   %-22s %s" % (name, value))
        print("-- must keep working --")
        for name, value in result["permitted"].items():
            print("   %-22s %s" % (name, value))
    out = os.environ.get("SHADOWFETCH_STAGE_F_OUT", "/tmp/stage_f_measurements.json")
    Path(out).write_text(json.dumps(results, indent=2, sort_keys=True))
    print("\nwritten " + out)
