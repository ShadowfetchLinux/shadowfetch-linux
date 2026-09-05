#!/usr/bin/env python3
"""Measure real installed CLI responsiveness and resource pressure under load."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--duration", type=int, required=True)
    parser.add_argument("--max-latency", type=float, default=15)
    args = parser.parse_args()
    if args.duration < 10 or args.max_latency <= 0:
        parser.error("duration >=10 and positive max-latency are required")
    stopped = False
    def stop(sig, frame):
        nonlocal stopped
        stopped = True
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, stop)
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    started = time.monotonic()
    rows, errors = [], []
    while time.monotonic() - started < args.duration and not stopped:
        timings = {}
        for label, argv in (("missions", ["shadowfetch-missions", "--json", "list"]), ("workbench", ["shadowfetch-workbench", "list", "--json"]), ("grok", ["shadowfetch-grok-bot", "status", "--json"])):
            before = time.monotonic()
            try:
                result = subprocess.run(argv, capture_output=True, text=True, timeout=args.max_latency)
                value = json.loads(result.stdout)
                if result.returncode or (label == "grok" and not value.get("verified")):
                    raise RuntimeError(label + " is unavailable or failed verification")
            except Exception as exc:
                errors.append({"probe": label, "error": str(exc)})
            timings[label] = round(time.monotonic() - before, 3)
        memory = {line.split(":")[0]: int(line.split()[1]) for line in Path("/proc/meminfo").read_text().splitlines() if len(line.split()) > 1}
        if Path("/proc/sys/kernel/random/boot_id").read_text().strip() != boot:
            errors.append({"error": "Boot identity changed"})
        row = {"probe_cycle": len(rows) + 1, "elapsed": round(time.monotonic() - started, 3), "latency_seconds": timings, "load": os.getloadavg(), "memory_available_kib": memory.get("MemAvailable"), "pressure": {name: Path("/proc/pressure", name).read_text() for name in ("cpu", "memory", "io") if Path("/proc/pressure", name).exists()}, "failures_so_far": len(errors)}
        rows.append(row)
        print(json.dumps(row), flush=True)
        for _ in range(20):
            if stopped or time.monotonic() - started >= args.duration:
                break
            time.sleep(.5)
    values = sorted(value for row in rows for value in row["latency_seconds"].values())
    coverage = rows[-1]["elapsed"] - rows[0]["elapsed"] if len(rows) > 1 else 0
    if len(rows) < max(1, args.duration // 120) or (args.duration >= 120 and coverage < args.duration * .75):
        errors.append({"error": "Insufficient sustained responsiveness probes"})
    print(json.dumps({"summary": True, "cycles": len(rows), "coverage_seconds": coverage, "latency_max": max(values) if values else None, "latency_p95": values[min(len(values)-1, int(len(values)*.95))] if values else None, "errors": errors, "cancelled": stopped}), flush=True)
    return 130 if stopped else 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
