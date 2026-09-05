#!/usr/bin/env python3
"""Run real offline FFmpeg missions, validate outputs, and undo them under load.

A private controller state keeps test work separate from the desktop queue. The
real worker executes each mission; no inference or successful result is mocked.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import signal
import struct
import subprocess
import sys
import time
import wave


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(1024 ** 2), b""):
            h.update(block)
    return h.hexdigest()


def coverage_summary(cycles, duration):
    """Union of successful creation-to-Undo intervals clipped to the load window."""
    previous = 0.0
    coverage = 0.0
    completed = 0
    for row in cycles:
        begin, end = row['started'], row['finished']
        if begin < previous or end < begin:
            raise ValueError('Overlapping or backwards mission intervals')
        previous = end
        coverage += max(0.0, min(end, duration) - max(begin, 0.0))
        completed += end <= duration
    return {'coverage_seconds': coverage, 'completed_within_load_window': completed,
            'tail_cycles': len(cycles) - completed}


def check_artifacts(receipt, workspace):
    if receipt.get("state") != "waiting-review" or not receipt.get("checkpoint"):
        raise ValueError("Missing successful state or checkpoint")
    rows = receipt.get("artifacts", [])
    if len(rows) < 2:
        raise ValueError("Missing actual export or its manifest")
    paths = []
    for row in rows:
        path = Path(row["path"])
        if path.is_symlink() or workspace.resolve() not in path.resolve().parents:
            raise ValueError("Artifact is outside this QA workspace")
        if not path.is_file() or path.stat().st_size != row["bytes"] or digest(path) != row["sha256"]:
            raise ValueError("Published artifact hash/size does not match its receipt")
        paths.append(path)
    manifest = next((p for p in paths if p.name == "exports.json"), None)
    exports = json.loads(manifest.read_text()) if manifest else []
    if not exports or not all(row.get("decode_verified") for row in exports):
        raise ValueError("Missing actual decode verification")
    return paths


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--duration", type=int, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument('--load-start-monotonic', type=float)
    args = parser.parse_args()
    if os.geteuid() == 0 or not args.run_id.replace("-", "").isalnum() or args.duration < 10:
        parser.error("Run as the QA desktop user with a simple run id and duration >=10")
    out = args.output
    out.mkdir(parents=True, exist_ok=True, mode=0o700)
    if (out / "result.json").exists():
        parser.error("Refusing to overwrite a completed run")
    state = out / "controller"
    workspace = Path.home() / "Workspaces" / ("qa-media-" + args.run_id)
    workspace.mkdir(parents=True, exist_ok=False)
    source = workspace / "tone.wav"
    with wave.open(str(source), "wb") as stream:
        stream.setparams((1, 2, 48000, 0, "NONE", "not compressed"))
        stream.writeframes(b"".join(struct.pack("<h", int(9000 * math.sin(2 * math.pi * 440 * i / 48000))) for i in range(48000)))
    expected = digest(source)
    env = {**os.environ, "SHADOWFETCH_MISSIONS_STATE": str(state)}
    stopped = False
    active_id = None
    failures = []
    cycles = []
    sequence = 0
    cycle_deadline = None
    def stop(sig, frame):
        nonlocal stopped
        stopped = True
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, stop)
    def record(file, data):
        with (out / file).open("a") as log:
            log.write(json.dumps(data) + "\n")
    def command(argv, timeout=120):
        nonlocal sequence
        if cycle_deadline is not None:
            remaining = cycle_deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('Cycle exceeded production900-second budget plus120-second observation grace')
            timeout = min(timeout, remaining)
        sequence += 1
        started = time.monotonic()
        try:
            result = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            def decoded(value):
                return value.decode('utf-8','replace') if isinstance(value,bytes) else value or ''
            (out / f"command-{sequence:05d}.out").write_text(decoded(exc.stdout))
            (out / f"command-{sequence:05d}.err").write_text(decoded(exc.stderr))
            record("commands.jsonl", {"sequence":sequence,"argv":argv,"timeout":True,"timeout_seconds":timeout,"seconds":time.monotonic()-started})
            raise
        (out / f"command-{sequence:05d}.out").write_text(result.stdout)
        (out / f"command-{sequence:05d}.err").write_text(result.stderr)
        record("commands.jsonl", {"sequence": sequence, "argv": argv, "exit": result.returncode, "seconds": round(time.monotonic() - started, 3)})
        if result.returncode:
            raise RuntimeError(f"Command {sequence} failed: {result.returncode}")
        return result.stdout
    def mission(action, *values):
        return json.loads(command(["shadowfetch-missions", "--json", action, *map(str, values)]))
    started = args.load_start_monotonic if args.load_start_monotonic is not None else time.monotonic()
    if started > time.monotonic() or time.monotonic() - started > 120:
        parser.error('Load start must be the current shared guest monotonic window')
    with (out / "worker.log").open("w") as log:
        worker = subprocess.Popen(["shadowfetch-missions", "worker"], env=env, stdout=log, stderr=log, start_new_session=True)
        try:
            while time.monotonic() - started < args.duration and not stopped:
                cycle_start = time.monotonic()
                cycle_deadline = cycle_start + 1020
                try:
                    item = mission("create", "--kind", "media", "--workspace", workspace.name, "--title", "QA verified audio export", "--prompt", "Export and decode-verify the selected audio.", "--runtime", "local", "--network", "none", "--input", "tone.wav")
                    active_id = item["id"]
                    if item['config']['timeout'] != 900:
                        raise ValueError('Installed production timeout default differs from declared 900 seconds')
                    # Bounded observation includes durable state/receipt overhead.
                    # The engine still enforces its unchanged900-second budget.
                    while time.monotonic() - cycle_start < 1020 and not stopped:
                        if worker.poll() is not None:
                            raise RuntimeError("Mission worker exited")
                        item = mission("show", active_id)
                        if item.get("state") == "waiting-review":
                            break
                        if item.get("state") in ("failed", "cancelled", "undone", "completed"):
                            raise RuntimeError("Unexpected mission state: " + str(item))
                        time.sleep(3)
                    if item.get("state") != "waiting-review":
                        raise RuntimeError("Mission did not complete within its bounded timeout")
                    receipt_path = Path(item["receipt"])
                    if state.resolve() not in receipt_path.resolve().parents:
                        raise ValueError("Receipt escapes the private QA controller")
                    receipt = json.loads(receipt_path.read_text())
                    artifacts = check_artifacts(receipt, workspace)
                    evidence = out / active_id
                    evidence.mkdir()
                    shutil.copy2(receipt_path, evidence / "receipt.json")
                    for path in artifacts:
                        shutil.copy2(path, evidence / path.name)
                        if path.suffix == ".wav":
                            command(["ffmpeg", "-nostdin", "-v", "error", "-i", str(path), "-f", "null", "-"])
                            metadata = json.loads(command(["ffprobe", "-v", "error", "-show_streams", "-show_format", "-of", "json", str(path)]))
                            audio = next((s for s in metadata.get("streams", []) if s.get("codec_type") == "audio"), {})
                            if audio.get("codec_name") != "pcm_s16le" or audio.get("sample_rate") != "48000" or not .99 <= float(metadata.get("format", {}).get("duration", 0)) <= 1.01:
                                raise ValueError("Real exported codec, rate or duration does not match the fixture")
                    (evidence / "events.json").write_text(json.dumps(mission("events", active_id), indent=2))
                    reviewed = mission("review", active_id, "--decision", "undo")
                    if reviewed.get("state") != "undone" or (workspace / "mission-output").exists() or digest(source) != expected:
                        raise ValueError("Undo did not restore exact workspace state")
                    finished = time.monotonic() - started
                    row = {"mission": active_id, "started": cycle_start-started, "finished": finished, "elapsed": round(finished, 3), "seconds": round(time.monotonic() - cycle_start, 3), "completed_under_load": finished <= args.duration, "hashes_verified": True, "decode_verified": True, "undo_verified": True}
                    cycles.append(row)
                    record("cycles.jsonl", row)
                    print(json.dumps(row), flush=True)
                    active_id = None
                except Exception as exc:
                    row = {"error": str(exc), "mission": active_id, "elapsed": round(time.monotonic() - started, 3)}
                    failures.append(row)
                    record("failures.jsonl", row)
                    # Preserve the failed state and workspace; repeated operations
                    # on a failed recovery boundary could hide the original error.
                    break
                # Queue the next real mission immediately. No intentional idle.
        finally:
            cycle_deadline = None
            if active_id:
                try:
                    cleanup_deadline = time.monotonic() + 120
                    cycle_deadline = cleanup_deadline
                    current = mission("show", active_id)
                    if current.get("state") in ("running", "queued"):
                        mission("cancel", active_id)
                        while time.monotonic() < cleanup_deadline:
                            terminal = mission("show", active_id).get("state")
                            if terminal in ("failed", "cancelled", "waiting-review", "completed", "undone"):
                                record("cleanup.jsonl", {"mission": active_id, "terminal_state": terminal, "cancellation_confirmed": terminal == "cancelled"})
                                break
                            time.sleep(.5)
                        else:
                            raise RuntimeError("Mission did not reach any terminal or review state within cleanup deadline")
                    else:
                        record("cleanup.jsonl", {"mission":active_id,"terminal_state":current.get('state'),"cancellation_confirmed":current.get('state')=='cancelled'})
                except Exception as exc:
                    failures.append({"error": "Cleanup terminal state not verified: " + str(exc)})
                finally:
                    cycle_deadline = None
            if worker.poll() is None:
                os.killpg(worker.pid, signal.SIGTERM)
                try:
                    worker.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(worker.pid, signal.SIGKILL)
                    worker.wait(timeout=5)
    elapsed = time.monotonic() - started
    coverage = coverage_summary(cycles, args.duration)
    required_cycles = 3 if args.duration >= 2700 else 1
    if coverage['completed_within_load_window'] < required_cycles or coverage['coverage_seconds'] < args.duration * .75 or elapsed < args.duration:
        failures.append({"error": "Declared continuous-load acceptance criteria not met", "cycles": len(cycles), **coverage, "elapsed": elapsed})
    result = {"qa_profile":"production-default900s-v2", "cycles": len(cycles), **coverage, "elapsed_seconds": elapsed, "tail_seconds":max(0,elapsed-args.duration), "required_seconds": args.duration, "mission_budget_seconds":900, "observation_grace_seconds":120, "minimum_completed_within_load_window":required_cycles, "minimum_active_coverage_fraction":.75, "source_sha256": expected, "failures": failures, "cancelled": stopped, "model_inference": False, "status": "CANCELLED" if stopped else "FAIL" if failures else "PASS" if args.duration>=2700 else "SMOKE_PASS"}
    (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result), flush=True)
    return 130 if stopped else 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
