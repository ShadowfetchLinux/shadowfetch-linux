#!/usr/bin/env python3
"""Real rootless container load with bounded, separately reported cleanup.

QA-only v2. Pure tests inject the operation runner; they are not load evidence.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

LIMIT = 120
CLIENT_GRACE = 5


def text(value):
    return value.decode('utf-8', 'replace') if isinstance(value, bytes) else value or ''


def operation(argv, timeout=LIMIT, stopped=lambda: False):
    """Bound a Podman client without losing its first timeout or partial output.

    Detached conmon/container cleanup belongs to exact-name Podman rm below.
    Linux uninterruptible I/O can outlast signals; report an unexited client.
    """
    started = time.monotonic()
    result = {'argv': argv, 'timeout_seconds': timeout, 'rc': None,
              'stdout': '', 'stderr': '', 'error': None, 'client_pid': None,
              'client_exited': True, 'termination_errors': []}
    proc = None
    try:
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, start_new_session=True)
        result['client_pid'] = proc.pid
        try:
            result['client_start_ticks'] = Path(f'/proc/{proc.pid}/stat').read_text().rpartition(') ')[2].split()[19]
        except OSError:
            result['client_start_ticks'] = None
        while True:
            remaining = timeout - (time.monotonic() - started)
            if stopped() or remaining <= 0:
                result['error'] = 'cancelled' if stopped() else 'operation timeout'
                break
            try:
                stdout, stderr = proc.communicate(timeout=min(1.0, remaining))
                result.update(stdout=stdout, stderr=stderr, rc=proc.returncode)
                break
            except subprocess.TimeoutExpired as exc:
                result.update(stdout=text(exc.stdout), stderr=text(exc.stderr))
    except Exception as exc:
        result['error'] = result['error'] or 'client operation exception: ' + str(exc)
        if proc is not None:
            result['client_exited'] = proc.poll() is not None
            result['rc'] = proc.returncode
    finally:
        if proc is not None and proc.poll() is None:
            for signum in (signal.SIGTERM, signal.SIGKILL):
                try:
                    os.killpg(proc.pid, signum)
                except ProcessLookupError:
                    pass
                except OSError as exc:
                    result['termination_errors'].append(str(exc))
                try:
                    stdout, stderr = proc.communicate(timeout=CLIENT_GRACE)
                    result.update(stdout=stdout, stderr=stderr, rc=proc.returncode)
                    break
                except subprocess.TimeoutExpired as exc:
                    result.update(stdout=text(exc.stdout), stderr=text(exc.stderr))
                except Exception as exc:
                    result['termination_errors'].append('Client termination observation exception: ' + str(exc))
            result['client_exited'] = proc.poll() is not None
            result['rc'] = proc.returncode
            if not result['client_exited']:
                result['termination_errors'].append('Client remains after bounded TERM/KILL observation; owned-process cleanup required')
        if proc is not None:
            for stream in (proc.stdout, proc.stderr):
                if stream:
                    try:
                        stream.close()
                    except OSError as exc:
                        result['termination_errors'].append('Client output close failed: ' + str(exc))
        result['seconds'] = time.monotonic() - started
    return result


def run_profile(duration, image, run_id, *, run=operation, stopped=lambda: False,
                clock=time.monotonic, sleep=time.sleep, emit=lambda row: print(json.dumps(row), flush=True),
                load_start=None):
    name = 'sfqa-stress-' + run_id
    expected = hashlib.sha256(bytes(32 * 1024 * 1024)).hexdigest()
    command = 'set -eu; dd if=/dev/zero of=/tmp/load.bin bs=1M count=32 2>/dev/null; sha256sum /tmp/load.bin'
    start = clock() if load_start is None else load_start
    rows, failures, cleanup_errors, cleanup_operations = [], [], [], []
    primary_error = None
    final_exists = None
    def invoke(argv, cancel=lambda: False):
        try:
            return run(argv, timeout=LIMIT, stopped=cancel)
        except Exception as exc:
            return {'argv': argv, 'rc': None, 'error': 'operation wrapper exception: ' + str(exc),
                    'stdout': '', 'stderr': '', 'client_exited': None}
    try:
        while clock() - start < duration and not stopped():
            before = clock()
            value = invoke(['podman', 'run', '--name', name, '--rm', '--pull=never', '--network=none',
                            '--memory=256m', '--pids-limit=64', image, 'sh', '-c', command], stopped)
            row = {'container_cycle': len(rows) + 1, 'elapsed': clock() - start,
                   'seconds': clock() - before, 'exit': value.get('rc'),
                   'stdout': value.get('stdout', ''), 'stderr': value.get('stderr', ''), 'operation': value}
            rows.append(row)
            emit(row)
            if value.get('error') or value.get('rc') != 0 or value.get('stdout', '').strip() != expected + '  /tmp/load.bin':
                primary_error = {'error': 'Container operation or actual data checksum failed', 'cycle': len(rows), 'operation': value}
                failures.append(primary_error)
                break
            for _ in range(10):
                if stopped() or clock() - start >= duration:
                    break
                sleep(.5)
    except Exception as exc:
        primary_error = primary_error or {'error': 'Container loop exception: ' + str(exc)}
        if primary_error not in failures:
            failures.append(primary_error)
    finally:
        # Never retry work. Cleanup and existence observation are independent,
        # individually bounded operations, even when the first one fails.
        removal = invoke(['podman', 'rm', '--force', '--ignore', name])
        cleanup_operations.append(removal)
        if removal.get('error') or removal.get('rc') != 0:
            cleanup_errors.append({'error': 'Exact-name container removal failed', 'operation': removal})
        existence = invoke(['podman', 'container', 'exists', name])
        cleanup_operations.append(existence)
        if existence.get('error') or existence.get('rc') not in (0, 1):
            cleanup_errors.append({'error': 'Final exact-name container existence is unverified', 'operation': existence})
        else:
            final_exists = existence['rc'] == 0
            if final_exists:
                cleanup_errors.append({'error': 'Named QA container remains after cleanup', 'operation': existence})
        for value in [*(row['operation'] for row in rows), *cleanup_operations]:
            if value.get('client_exited') is not True:
                cleanup_errors.append({'error': 'Podman client exit was not verified', 'operation': value})
    coverage = max(0.0, min(rows[-1]['elapsed'], duration) - min(rows[0]['elapsed'], duration)) if len(rows) > 1 else 0.0
    minimum = max(1, duration // 120)
    if len(rows) < minimum or (duration >= 120 and coverage < .75 * duration):
        failures.append({'error': 'Insufficient sustained container activity', 'required_cycles': minimum,
                         'actual_cycles': len(rows), 'coverage_seconds': coverage})
    failed = bool(failures or cleanup_errors or final_exists is not False)
    return {'summary': True, 'qa_profile': 'production-default900s-v2',
            'status': 'CANCELLED' if stopped() else 'FAIL' if failed else 'PASS' if duration >= 2700 else 'SMOKE_PASS',
            'cycles': len(rows), 'minimum_cycles': minimum, 'coverage_seconds': coverage,
            'load_window_seconds': duration, 'elapsed_seconds': clock() - start,
            'tail_seconds': max(0.0, clock() - start - duration),
            'expected_sha256': expected, 'image_id': image, 'container_name': name,
            'operation_timeout_seconds': LIMIT, 'client_termination_grace_seconds': CLIENT_GRACE,
            'primary_error': primary_error, 'failures': failures, 'cleanup_errors': cleanup_errors,
            'cleanup_operations': cleanup_operations, 'final_container_exists': final_exists,
            'cancelled': stopped(), 'load_start_monotonic': start}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--duration', type=int, required=True)
    parser.add_argument('--image', required=True)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--load-start-monotonic', type=float)
    args = parser.parse_args()
    if os.geteuid() == 0 or args.duration < 10 or not args.run_id.replace('-', '').isalnum() or not re.fullmatch(r'(?:sha256:)?[a-f0-9]{64}', args.image):
        parser.error('Desktop user, duration>=10, fixed SHA256 image and safe run ID required')
    if args.load_start_monotonic is not None and (not math.isfinite(args.load_start_monotonic) or not 0 <= time.monotonic() - args.load_start_monotonic <= 120):
        parser.error('Load start must identify current shared guest monotonic window')
    if args.output.exists() or args.output.is_symlink():
        parser.error('Refusing to overwrite earlier container result')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    stopped = False
    def stop(sig, frame):
        nonlocal stopped
        stopped = True
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, stop)
    result = run_profile(args.duration, args.image, args.run_id,
                         stopped=lambda: stopped, load_start=args.load_start_monotonic)
    with args.output.open('x') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    args.output.chmod(0o600)
    print(json.dumps(result), flush=True)
    return 130 if result['cancelled'] else 1 if result['status'] == 'FAIL' else 0


if __name__ == '__main__':
    sys.exit(main())
