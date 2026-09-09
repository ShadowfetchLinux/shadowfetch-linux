#!/usr/bin/env python3
"""Does a second name for a masked inode still read the secret?

SANDBOX_ENFORCEMENT["masked_paths"] says masking is BY PATH and names the
residual: "a hardlink to the same inode under an unmasked name is still
readable". Stage E measured the tricks that a mask DOES stop -- direct open,
absolute path, relative traversal, symlink, nested file, rename. It did not
measure the one the comment admits, so the blast-radius classifier would be
reporting a defeat nobody in this tree had actually seen.

This probe measures it, through the shipped Firebreak. Three arms:

  no mask     the control: the secret is readable, so the probe can tell a
              working mask from a broken probe.
  masked      the declared path, which must come back unreadable. NOT "empty":
              a masked FILE is /dev/null ro-bound over it and bwrap mounts that
              nodev, so the read fails EACCES. An earlier draft of this probe
              asserted EMPTY, called the shipped behaviour a Stage E regression
              and would have had someone hunting a bug that was in the probe.
              Only a masked DIRECTORY is empty; a masked file is denied.
  hardlink    a second directory entry for the SAME inode, not named in the
              mask. If this reads the secret, the mask is defeated by a name
              the declaration never mentioned, and the classifier is right to
              call the mask's protection UNKNOWN rather than applied.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

REPO = Path.home() / "projects/shadowfetch-4.0.0"
FIREBREAK = REPO / "packages/shadowfetch-fireline/data/usr/bin/shadowfetch-firebreak"
PYTHON = "/usr/bin/python3"          # trusted absolute path, never PATH

WS_ROOT = Path(os.environ.get("SHADOWFETCH_AGENT_WORKSPACES",
                              str(Path.home() / "Workspaces")))
WS_NAME = "blastlink"
SECRET = "OPENAI_API_KEY=sk-maskedButHardlinked\n"

PAYLOAD = r'''
import json, os
out = {}
def read(label, path):
    try:
        with open(path) as handle:
            data = handle.read()
        out[label] = "EMPTY" if data == "" else "READ:" + data.strip()[:40]
    except OSError as exc:
        out[label] = "denied:" + type(exc).__name__
read("declared_name", ".env")
read("second_name_same_inode", "backup/.env.bak")
try:
    a, b = os.stat(".env"), os.stat("backup/.env.bak")
    out["same_inode_inside"] = (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino)
    out["declared_nlink"] = a.st_nlink
except OSError as exc:
    out["same_inode_inside"] = "stat failed: " + type(exc).__name__
print("RESULT " + json.dumps(out))
'''


def build():
    ws = WS_ROOT / WS_NAME
    (ws / "backup").mkdir(parents=True, exist_ok=True)
    secret = ws / ".env"
    link = ws / "backup" / ".env.bak"
    for path in (secret, link):
        if path.exists() or path.is_symlink():
            path.unlink()
    secret.write_text(SECRET)
    os.link(secret, link)               # a HARDLINK, not a symlink
    (ws / "probe.py").write_text(PAYLOAD)
    return ws, secret


def run(ws, masks):
    argv = [PYTHON, str(FIREBREAK), "run", "--workspace", WS_NAME,
            "--net", "none", "--no-checkpoint", "--memory-mb", "1024",
            "--cpu-seconds", "60", "--processes", "32",
            "--workspace-mode", "workspace-write", *masks,
            "--", PYTHON, "probe.py"]
    done = subprocess.run(argv, capture_output=True, text=True, timeout=180)
    line = next((l for l in done.stdout.splitlines() if l.startswith("RESULT ")), None)
    if line is None:
        return {"_error": "no output (exit %d): %s"
                          % (done.returncode, (done.stderr or "").strip()[-400:])}
    return json.loads(line[7:])


def main():
    ws, secret = build()
    print("On the host: %s has st_nlink=%d" % (secret, secret.stat().st_nlink))

    arms = (("no mask (control)", []),
            ("mask .env", ["--mask-path", str(secret)]))
    results = {}
    for label, masks in arms:
        # Rebuild each arm: a mask arm that ran second on a mutated tree would
        # be measuring the previous arm's leftovers.
        ws, secret = build()
        results[label] = run(ws, masks)
        print("\n%s:" % label)
        for key, value in sorted(results[label].items()):
            print("   %-24s %s" % (key, value))

    control = results["no mask (control)"]
    masked = results["mask .env"]
    print("\nVERDICT")
    if not str(control.get("declared_name", "")).startswith("READ:"):
        print("   Probe broken: the control could not read the secret either.")
        return 2
    # Denied OR empty. Both are the mask working; only "READ:" is a failure.
    # See the module docstring for why this is not a single equality test.
    declared_blocked = not str(masked.get("declared_name", "")).startswith("READ:")
    second_reads = str(masked.get("second_name_same_inode", "")).startswith("READ:")
    if declared_blocked and second_reads:
        print("   The mask stops the DECLARED name and nothing else. A second")
        print("   directory entry for the same inode still returns the secret, so a")
        print("   mask over a file with st_nlink > 1 protects a name, not content.")
        print("   Classifier: masked_paths reduce reachability only where the inode")
        print("   has one name; otherwise the reduction is UNKNOWN.")
        return 0
    if declared_blocked and not second_reads:
        print("   The hardlink did NOT read the secret. The classifier's hardlink")
        print("   finding would be false and must be removed.")
        return 1
    print("   The mask did not stop the declared name (%r); that is a Stage E"
          % masked.get("declared_name"))
    print("   regression, not a blast-radius finding.")
    return 3


if __name__ == "__main__":
    sys.exit(main())
