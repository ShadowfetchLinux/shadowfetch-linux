#!/usr/bin/env python3
"""Exercise real rootless, offline containers using a fixed pulled image ID."""
import argparse
import hashlib
import json
import os
import signal
import subprocess
import sys
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--duration", type=int, required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    if os.geteuid() == 0 or args.duration < 10 or not args.run_id.replace("-", "").isalnum() or not args.image.startswith("sha256:"):
        parser.error("A desktop user, duration >=10, fixed SHA256 image and safe run ID are required")
    stopped = False
    def stop(sig, frame):
        nonlocal stopped
        stopped = True
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, stop)
    name = "sfqa-stress-" + args.run_id
    expected = hashlib.sha256(bytes(32 * 1024 * 1024)).hexdigest()
    command = 'set -eu; dd if=/dev/zero of=/tmp/load.bin bs=1M count=32 2>/dev/null; sha256sum /tmp/load.bin'
    start = time.monotonic()
    rows, failures = [], []
    process = None
    try:
        while time.monotonic() - start < args.duration and not stopped:
            before = time.monotonic()
            process = subprocess.Popen(["podman", "run", "--name", name, "--rm", "--pull=never", "--network=none", "--memory=256m", "--pids-limit=64", args.image, "sh", "-c", command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
            while process.poll() is None and time.monotonic() - before < 90 and not stopped:
                time.sleep(.2)
            if process.poll() is None:
                subprocess.run(["podman", "rm", "--force", "--ignore", name], capture_output=True, timeout=20)
                process.terminate()
            stdout, stderr = process.communicate(timeout=20)
            row = {"container_cycle": len(rows) + 1, "elapsed": round(time.monotonic() - start, 3), "seconds": round(time.monotonic() - before, 3), "exit": process.returncode, "stdout": stdout, "stderr": stderr}
            if process.returncode or stdout.strip() != expected + "  /tmp/load.bin":
                failures.append({"error": "Container exit or actual data checksum failed", **row})
            rows.append(row)
            print(json.dumps(row), flush=True)
            if failures:
                break
            for _ in range(10):
                if stopped or time.monotonic() - start >= args.duration:
                    break
                time.sleep(.5)
    except Exception as exc:
        failures.append({"error": str(exc)})
    finally:
        if process and process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=10)
        cleanup = subprocess.run(["podman", "rm", "--force", "--ignore", name], capture_output=True, text=True, timeout=30)
        if cleanup.returncode:
            failures.append({"error": "Container cleanup failed", "stderr": cleanup.stderr})
    coverage = rows[-1]["elapsed"] - rows[0]["elapsed"] if len(rows) > 1 else 0
    if len(rows) < max(1, args.duration // 120) or (args.duration >= 120 and coverage < .75 * args.duration):
        failures.append({"error": "Insufficient sustained container activity"})
    print(json.dumps({"summary": True, "cycles": len(rows), "coverage_seconds": coverage, "expected_sha256": expected, "image_id": args.image, "failures": failures, "cancelled": stopped}), flush=True)
    return 130 if stopped else 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
