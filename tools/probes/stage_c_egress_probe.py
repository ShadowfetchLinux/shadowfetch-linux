#!/usr/bin/env python3
"""usage: egress2.py <ruleset-name> <allowed-ip> <denied-ip>"""
import json, os, subprocess, sys, time

BWRAP, SLIRP, NSENTER, NFT = "/usr/bin/bwrap", "/usr/bin/slirp4netns", "/usr/bin/nsenter", "/usr/sbin/nft"
which, allowed, denied = sys.argv[1], sys.argv[2], sys.argv[3]

RULESETS = {
    "none": None,
    "touch": "",
    "permissive": "table inet t { chain out { type filter hook output priority 0; policy accept; counter; } }",
    "noct": ("table inet t { chain out { type filter hook output priority 0; policy drop;"
             " oif \"lo\" counter accept;"
             " ip daddr 10.0.2.0/24 counter accept;"
             " ip daddr %s counter accept;"
             " counter drop; } }" % allowed),
    "withct": ("table inet t { chain out { type filter hook output priority 0; policy drop;"
               " ct state established,related counter accept;"
               " oif \"lo\" counter accept;"
               " ip daddr 10.0.2.0/24 counter accept;"
               " ip daddr %s counter accept;"
               " counter drop; } }" % allowed),
}
rules = RULESETS[which]

PROBE = (
    "import json,socket,time\n"
    "out={}\n"
    "for n,ip in (('allowed','" + allowed + "'),('denied','" + denied + "')):\n"
    "    for _ in range(3):\n"
    "        try:\n"
    "            s=socket.create_connection((ip,443),timeout=5); s.close(); out[n]='REACHED'; break\n"
    "        except OSError as e:\n"
    "            out[n]='blocked:'+type(e).__name__; time.sleep(0.6)\n"
    "print('RESULT '+json.dumps(out))\n"
    "time.sleep(6)\n")

info_r, info_w = os.pipe(); block_r, block_w = os.pipe(); ready_r, ready_w = os.pipe()
cmd = [BWRAP, "--ro-bind", "/usr", "/usr", "--symlink", "usr/bin", "/bin",
       "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64",
       "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
       "--unshare-user", "--unshare-pid", "--unshare-net", "--die-with-parent",
       "--info-fd", str(info_w), "--block-fd", str(block_r),
       "--", "/usr/bin/python3", "-c", PROBE]
proc = subprocess.Popen(cmd, pass_fds=(info_w, block_r),
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
os.close(info_w); os.close(block_r)
info = b""
with os.fdopen(info_r, "rb") as h:
    while b"}" not in info:
        c = h.read(1)
        if not c: break
        info += c
pid = json.loads(info.decode())["child-pid"]
applied = "none"
if rules == "":
    r = subprocess.run([NSENTER, "--target", str(pid), "--user", "--net",
                        "--preserve-credentials", "/usr/bin/true"],
                       capture_output=True, text=True, timeout=30)
    applied = "entered-only(rc=%d)" % r.returncode
elif rules:
    r = subprocess.run([NSENTER, "--target", str(pid), "--user", "--net",
                        "--preserve-credentials", NFT, "-f", "-"],
                       input=rules, capture_output=True, text=True, timeout=30)
    applied = "ok" if r.returncode == 0 else "FAIL:" + r.stderr.strip()[:100]
nat = subprocess.Popen([SLIRP, "--configure", "--mtu=65520", "--disable-host-loopback",
                        "--ready-fd", str(ready_w), str(pid), "tap0"],
                       pass_fds=(ready_w,), stdout=subprocess.DEVNULL,
                       stderr=subprocess.PIPE, text=True)
os.close(ready_w)
with os.fdopen(ready_r, "rb") as h: h.read(1)
time.sleep(1.0)
os.close(block_w)
counters = ""
if rules:
    time.sleep(5)
    d = subprocess.run([NSENTER, "--target", str(pid), "--user", "--net",
                        "--preserve-credentials", NFT, "list", "ruleset"],
                       capture_output=True, text=True, timeout=20)
    counters = " | ".join(l.strip() for l in (d.stdout or "").splitlines()
                          if "counter packets" in l)
out, err = proc.communicate(timeout=120)
try: nat.terminate(); nat.wait(timeout=5)
except Exception: pass
line = next((l for l in out.splitlines() if l.startswith("RESULT ")), None)
print("%-11s install=%-6s %s" % (which, applied,
      json.dumps(json.loads(line[7:]) if line else {"err": err.strip()[-120:]}, sort_keys=True)))
if counters: print("            counters: " + counters[:400])
