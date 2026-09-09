#!/usr/bin/env python3
"""Stage B, through the real Firebreak, against real listening services.

CLI arguments are not proof. This starts a TCP listener on the host's loopback
and an abstract AF_UNIX socket, then runs a genuine `shadowfetch-firebreak run`
in each posture and asks the sandbox to reach them.
"""
import json, os, socket, subprocess, sys, tempfile, threading
from pathlib import Path

FB = Path.home() / "projects/shadowfetch-4.0.0/packages/shadowfetch-fireline/data/usr/bin/shadowfetch-firebreak"
ABSTRACT = "sf-stage-b-live"

PROBE = r'''
import json, socket
out = {}
for name, fn in (
    ("host_loopback_tcp", lambda: socket.create_connection(("127.0.0.1", PORT), timeout=3)),
    ("internet_tcp",      lambda: socket.create_connection(("1.1.1.1", 443), timeout=6)),
):
    try:
        s = fn(); s.close(); out[name] = "REACHED"
    except OSError as e:
        out[name] = "blocked:" + type(e).__name__
try:
    a = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); a.settimeout(3)
    a.connect("\0ABS"); a.close(); out["host_abstract_unix"] = "REACHED"
except OSError as e:
    out["host_abstract_unix"] = "blocked:" + type(e).__name__
print("PROBE " + json.dumps(out))
'''


def listeners():
    tcp = socket.socket(); tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind(("127.0.0.1", 0)); tcp.listen(8)
    uds = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    uds.bind("\0" + ABSTRACT); uds.listen(8)
    def serve(s):
        while True:
            try: c, _ = s.accept(); c.close()
            except OSError: return
    for s in (tcp, uds):
        threading.Thread(target=serve, args=(s,), daemon=True).start()
    return tcp.getsockname()[1]


port = listeners()
ws_root = Path(os.environ.get("SHADOWFETCH_AGENT_WORKSPACES",
                              str(Path.home() / "Workspaces")))
ws = ws_root / "stageb"
ws.mkdir(parents=True, exist_ok=True)
script = ws / "probe.py"
script.write_text(PROBE.replace("PORT", str(port)).replace("ABS", ABSTRACT))

print("host listeners: 127.0.0.1:%d and abstract \\0%s\n" % (port, ABSTRACT))
print("%-10s %s" % ("POSTURE", "WHAT THE SANDBOX COULD REACH"))
print("-" * 78)
for net in ("none", "allow"):
    cmd = [sys.executable, str(FB), "run", "--workspace", "stageb", "--net", net,
           "--no-checkpoint", "--memory-mb", "1024", "--cpu-seconds", "60",
           "--processes", "32", "--workspace-mode", "workspace-write",
           "--", "/usr/bin/python3", "probe.py"]
    done = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    line = next((l for l in done.stdout.splitlines() if l.startswith("PROBE ")), None)
    if line:
        got = json.loads(line[6:])
        print("%-10s %s" % (net, json.dumps(got)))
    else:
        print("%-10s no probe output (exit %d): %s" % (net, done.returncode,
                                                       (done.stderr or "").strip()[-200:]))
