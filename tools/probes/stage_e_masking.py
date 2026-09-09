#!/usr/bin/env python3
"""Stage E through the real Firebreak: can the sandbox read a masked file?

The prompt lists the tricks that matter -- direct open, symlink, relative
traversal, absolute path, rename, nested path. Each is tried for real.
"""
import json, os, subprocess, sys
from pathlib import Path
FB = Path.home() / "projects/shadowfetch-4.0.0/packages/shadowfetch-fireline/data/usr/bin/shadowfetch-firebreak"
root = Path(os.environ.get("SHADOWFETCH_AGENT_WORKSPACES", str(Path.home() / "Workspaces")))
ws = root / "stagee"
(ws / "nested").mkdir(parents=True, exist_ok=True)
(ws / ".env").write_text("OPENAI_API_KEY=sk-thisIsTheSecretValue\n")
(ws / "nested" / "id_rsa").write_text("-----BEGIN PRIVATE KEY-----\nsecret\n")
(ws / "secrets").mkdir(exist_ok=True)
(ws / "secrets" / "token.txt").write_text("token-in-a-masked-directory\n")
link = ws / "env-link"
if link.exists() or link.is_symlink(): link.unlink()
link.symlink_to(ws / ".env")

PROBE = r'''
import json, os
out = {}
def read(label, path):
    try:
        with open(path) as f:
            data = f.read()
        out[label] = ("EMPTY" if data == "" else "READ:" + data.strip()[:34])
    except OSError as e:
        out[label] = "denied:" + type(e).__name__
read("direct", ".env")
read("absolute", os.path.abspath(".env"))
read("relative_traversal", "nested/../.env")
read("symlink", "env-link")
read("nested_file", "nested/id_rsa")
read("masked_dir_file", "secrets/token.txt")
out["masked_dir_listing"] = sorted(os.listdir("secrets"))
try:
    os.rename(".env", "moved.env"); out["rename"] = "RENAMED"
    read("after_rename", "moved.env")
except OSError as e:
    out["rename"] = "denied:" + type(e).__name__
print("RESULT " + json.dumps(out))
'''
(ws / "probe.py").write_text(PROBE)

for label, masks in (("no masks", []),
                     ("masked", ["--mask-path", str(ws / ".env"),
                                 "--mask-path", str(ws / "nested" / "id_rsa"),
                                 "--mask-path", str(ws / "secrets")])):
    cmd = [sys.executable, str(FB), "run", "--workspace", "stagee", "--net", "none",
           "--no-checkpoint", "--memory-mb", "1024", "--cpu-seconds", "60",
           "--processes", "32", "--workspace-mode", "workspace-write",
           *masks, "--", "/usr/bin/python3", "probe.py"]
    done = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    line = next((l for l in done.stdout.splitlines() if l.startswith("RESULT ")), None)
    print("\n%s:" % label)
    if line:
        for k, v in json.loads(line[7:]).items():
            print("   %-20s %s" % (k, v))
    else:
        print("   no output (exit %d): %s" % (done.returncode, (done.stderr or "").strip()[-300:]))
    # restore for the next pass
    if (ws / "moved.env").exists():
        (ws / "moved.env").rename(ws / ".env")
