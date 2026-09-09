#!/usr/bin/env python3
"""Does a read grant onto a directory containing a unix socket defeat network 'none'?

The blast-radius classifier claims a read grant whose directory holds an
AF_UNIX socket is an EXFILTRATION path even when the sandbox has no network,
because a socket is not a file: bwrap --ro-bind carries the inode into the
sandbox's mount namespace, and the kernel exempts special files from the
read-only mount check (sb_permission() returns 0 for S_ISSOCK), so connect()
succeeds and bytes flow both ways to a process on the HOST side of the
namespace.

That is a claim about the kernel, and the standard here is that a claim about
a layer is worth nothing until the layer has been asked. This probe asks it,
through the SHIPPED Firebreak rather than a hand-built bwrap line, so what is
measured is the posture a mission actually gets.

Control arm: the same payload with the grant removed. If the control reaches
the socket too, the probe proves nothing about the grant and says so.
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

REPO = Path.home() / "projects/shadowfetch-4.0.0"
FIREBREAK = REPO / "packages/shadowfetch-fireline/data/usr/bin/shadowfetch-firebreak"
PYTHON = "/usr/bin/python3"          # trusted absolute path, never PATH

WS_ROOT = Path(os.environ.get("SHADOWFETCH_AGENT_WORKSPACES",
                              str(Path.home() / "Workspaces")))
WS_NAME = "blastsock"

SECRET = b"HOST-SIDE-SECRET-b7f21c"

PAYLOAD = r'''
import json, os, socket, sys
grant = sys.argv[1]
out = {}
sock_path = os.path.join(grant, "agent.sock")
out["grant_listing"] = sorted(os.listdir(grant)) if os.path.isdir(grant) else "ABSENT"
try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(sock_path)
    s.sendall(b"WORKSPACE-BYTES-LEAVING")
    out["reply"] = s.recv(64).decode("utf-8", "replace")
    out["connect"] = "REACHED"
    s.close()
except OSError as exc:
    out["connect"] = "blocked:%s:%s" % (type(exc).__name__, exc.errno)
# A plain file in the same grant, for contrast: read-only binds do stop writes.
try:
    with open(os.path.join(grant, "plain.txt")) as handle:
        out["plain_read"] = handle.read().strip()
except OSError as exc:
    out["plain_read"] = "denied:" + type(exc).__name__
try:
    with open(os.path.join(grant, "plain.txt"), "a") as handle:
        handle.write("x")
    out["plain_write"] = "WROTE"
except OSError as exc:
    out["plain_write"] = "blocked:%s:%s" % (type(exc).__name__, exc.errno)
print("RESULT " + json.dumps(out))
'''


def serve(listener, received):
    """The host-side process the sandbox is not supposed to be able to talk to."""
    try:
        conn, _ = listener.accept()
    except OSError:
        return
    with conn:
        received.append(conn.recv(256))
        conn.sendall(SECRET)


def run(label, grant, extra):
    ws = WS_ROOT / WS_NAME
    ws.mkdir(parents=True, exist_ok=True)
    (ws / "probe.py").write_text(PAYLOAD)
    argv = [PYTHON, str(FIREBREAK), "run", "--workspace", WS_NAME,
            "--net", "none", "--no-checkpoint", "--memory-mb", "1024",
            "--cpu-seconds", "60", "--processes", "32",
            "--workspace-mode", "workspace-write", *extra,
            "--", PYTHON, "probe.py", str(grant)]
    done = subprocess.run(argv, capture_output=True, text=True, timeout=180)
    line = next((l for l in done.stdout.splitlines() if l.startswith("RESULT ")), None)
    if line is None:
        return {"_error": "no output (exit %d): %s"
                          % (done.returncode, (done.stderr or "").strip()[-400:])}
    return json.loads(line[7:])


def main():
    grant = Path(tempfile.mkdtemp(prefix="blast-grant-", dir="/tmp"))
    (grant / "plain.txt").write_text("an ordinary file in the same grant\n")
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(grant / "agent.sock"))
    listener.listen(4)
    received = []
    thread = threading.Thread(target=serve, args=(listener, received), daemon=True)
    thread.start()

    granted = run("granted", grant, ["--read", str(grant)])
    print("WITH THE READ GRANT (network posture: none)")
    for key, value in sorted(granted.items()):
        print("   %-16s %s" % (key, value))
    print("   %-16s %s" % ("host received", received[0] if received else "NOTHING"))

    # Control: no grant at all. The socket must be unreachable, or the measured
    # difference above is not attributable to the grant.
    listener.close()
    listener2 = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    (grant / "agent.sock").unlink()
    listener2.bind(str(grant / "agent.sock"))
    listener2.listen(4)
    received2 = []
    threading.Thread(target=serve, args=(listener2, received2), daemon=True).start()
    control = run("control", grant, [])
    print("\nCONTROL, same payload, NO read grant")
    for key, value in sorted(control.items()):
        print("   %-16s %s" % (key, value))
    print("   %-16s %s" % ("host received", received2[0] if received2 else "NOTHING"))

    listener2.close()
    shutil.rmtree(grant, ignore_errors=True)

    reached = granted.get("connect") == "REACHED" and bool(received)
    control_blocked = control.get("connect") != "REACHED" and not received2
    print("\nVERDICT")
    if reached and control_blocked:
        print("   A read grant containing a unix socket is a TWO-WAY channel out of a")
        print("   sandbox whose network posture is 'none'. The grant is the cause: the")
        print("   control could not reach it. Classifier: exfiltration, observed.")
        return 0
    if not control_blocked:
        print("   Probe inconclusive: the control reached the socket too.")
        return 2
    print("   The socket was NOT reachable through the grant. The classifier's")
    print("   socket finding would be false and must be removed.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
