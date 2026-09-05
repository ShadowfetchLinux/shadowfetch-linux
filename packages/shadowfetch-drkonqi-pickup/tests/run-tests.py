#!/usr/bin/env python3
"""Run native protocol tests with a private /run and /tmp, never host sockets."""
import argparse
import os
from pathlib import Path
import subprocess
import sys

parser = argparse.ArgumentParser()
parser.add_argument('--build-dir', required=True, type=Path)
args = parser.parse_args()
root = Path(__file__).resolve().parent.parent
build = args.build_dir.resolve(strict=True)
assert build.is_relative_to(root), 'Build directory must be inside package source'
command = [sys.executable, str(root/'tests/validate.py'), '--build-dir', str(build)]
if Path('/run/.containerenv').is_file():
    # A fresh QA/build container already has private /run and /tmp.
    raise SystemExit(subprocess.run(command).returncode)

marker = os.memfd_create('shadowfetch-drkonqi-private-test', os.MFD_CLOEXEC)
try:
    os.write(marker, b'shadowfetch-private-test-namespace\n')
    os.lseek(marker, 0, 0)
    wrapped = ['bwrap', '--unshare-all', '--die-with-parent', '--new-session',
               '--ro-bind', '/', '/', '--tmpfs', '/run', '--tmpfs', '/tmp', '--tmpfs', '/var/log',
               '--proc', '/proc', '--dev', '/dev', '--bind', str(build), str(build),
               '--file', str(marker), '/run/.shadowfetch-drkonqi-private-test',
               '--chdir', str(root), '--', *command]
    raise SystemExit(subprocess.run(wrapped, pass_fds=(marker,)).returncode)
finally:
    os.close(marker)
