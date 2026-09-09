#!/usr/bin/env python3
"""Is a unix socket in the WORKSPACE a channel out, the way one in a read grant is?

tools/probes/blast_socket_grant.py measured the grant case and the blast-radius
classifier reported it. The classifier did NOT report the workspace case: it
scanned grants for S_ISSOCK and read workspace entries only for hardlink
candidates, so a live AF_UNIX socket sitting in the workspace was invisible and
`exfiltratable` came out 'none'.

That is the wrong way round. The grant is bound --ro-bind; the workspace is
bound --bind, read-WRITE. The narrower mount was the one being watched.

This probe asks the shipped Firebreak, at network posture 'none', three things:

  connect     can a payload in the sandbox reach a socket the HOST is listening
              on inside the workspace, and do bytes go both ways?
  write       does a plain file in the workspace take a write, where the same
              operation in a read grant fails EROFS (errno 30) -- i.e. is the
              workspace demonstrably the WIDER mount?
  manufacture can the payload CREATE a socket in the workspace itself? If it
              can, then anything the classifier says about the workspace's
              contents is a statement about read time and not a control.
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
from pathlib import Path

REPO = Path.home() / "projects/shadowfetch-4.0.0"
FIREBREAK = REPO / "packages/shadowfetch-fireline/data/usr/bin/shadowfetch-firebreak"
PYTHON = "/usr/bin/python3"          # trusted absolute path, never PATH

WS_ROOT = Path(os.environ.get("SHADOWFETCH_AGENT_WORKSPACES",
                              str(Path.home() / "Workspaces")))
WS_NAME = "blastwssock"

SECRET = b"HOST-SIDE-SECRET-workspace-9c31ab"

PAYLOAD = r'''
import json, os, socket, stat, sys
out = {}
here = os.getcwd()
out["workspace_listing"] = sorted(os.listdir(here))
# 1. reach the socket the HOST is listening on, inside the workspace
try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(os.path.join(here, "agent.sock"))
    s.sendall(b"WORKSPACE-BYTES-LEAVING")
    out["reply"] = s.recv(64).decode("utf-8", "replace")
    out["connect"] = "REACHED"
    s.close()
except OSError as exc:
    out["connect"] = "blocked:%s:%s" % (type(exc).__name__, exc.errno)
# 2. is this mount writable, where a read grant is not?
try:
    with open(os.path.join(here, "plain.txt"), "a") as handle:
        handle.write("x")
    out["plain_write"] = "WROTE"
except OSError as exc:
    out["plain_write"] = "blocked:%s:%s" % (type(exc).__name__, exc.errno)
# 3. can the payload manufacture a socket of its own here?
try:
    own = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    own.bind(os.path.join(here, "mine.sock"))
    out["manufacture"] = "BOUND st_mode=%s" % stat.S_ISSOCK(
        os.lstat(os.path.join(here, "mine.sock")).st_mode)
    own.close()
except OSError as exc:
    out["manufacture"] = "blocked:%s:%s" % (type(exc).__name__, exc.errno)
# 4. and rewrite its own .git/config, which is what makes every git row here a
#    statement about read time rather than a control
try:
    os.makedirs(os.path.join(here, ".git"), exist_ok=True)
    with open(os.path.join(here, ".git", "config"), "a") as handle:
        handle.write("[status]\n\tshort\n")
    out["rewrote_git_config"] = "WROTE"
except OSError as exc:
    out["rewrote_git_config"] = "blocked:%s:%s" % (type(exc).__name__, exc.errno)
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


def main():
    ws = WS_ROOT / WS_NAME
    if ws.exists():
        shutil.rmtree(ws, ignore_errors=True)
    ws.mkdir(parents=True, exist_ok=True)
    (ws / "probe.py").write_text(PAYLOAD)
    (ws / "plain.txt").write_text("an ordinary file in the workspace\n")

    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(ws / "agent.sock"))
    listener.listen(4)
    received = []
    threading.Thread(target=serve, args=(listener, received), daemon=True).start()

    argv = [PYTHON, str(FIREBREAK), "run", "--workspace", WS_NAME,
            "--net", "none", "--no-checkpoint", "--memory-mb", "1024",
            "--cpu-seconds", "60", "--processes", "32",
            "--workspace-mode", "workspace-write",
            "--", PYTHON, "probe.py"]
    done = subprocess.run(argv, capture_output=True, text=True, timeout=180)
    line = next((l for l in done.stdout.splitlines() if l.startswith("RESULT ")), None)
    if line is None:
        print("no output (exit %d): %s" % (done.returncode,
                                           (done.stderr or "").strip()[-600:]))
        return 2
    result = json.loads(line[7:])

    print("A UNIX SOCKET IN THE WORKSPACE (network posture: none, "
          "workspace-mode: workspace-write)")
    for key, value in sorted(result.items()):
        print("   %-20s %s" % (key, value))
    print("   %-20s %s" % ("host received", received[0] if received else "NOTHING"))

    listener.close()

    reached = result.get("connect") == "REACHED" and bool(received)
    writable = result.get("plain_write") == "WROTE"
    print("\nVERDICT")
    if reached and writable:
        print("   A unix socket in the WORKSPACE is a two-way channel out of a sandbox")
        print("   whose network posture is 'none' -- the same fact")
        print("   tools/probes/blast_socket_grant.py measured for a read grant. And the")
        print("   workspace bind took a write where the grant's --ro-bind refused one")
        print("   with EROFS, so this mount is strictly the WIDER of the two.")
        print("   The payload also manufactured a socket of its own here (%s) and"
              % result.get("manufacture"))
        print("   rewrote its own .git/config (%s), so what sf_blast reads from the"
              % result.get("rewrote_git_config"))
        print("   workspace is a statement about READ TIME, never a control.")
        return 0
    if not reached:
        print("   The socket was NOT reachable from the workspace. sf_blast's")
        print("   workspace.socket finding would be false and must be removed.")
        return 1
    print("   Inconclusive: the workspace did not take a write, so it is not the")
    print("   read-write mount this probe assumes.")
    return 2


if __name__ == "__main__":
    sys.exit(main())
