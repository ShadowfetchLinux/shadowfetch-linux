#!/usr/bin/env python3
"""Actual upstream/patched executables, fake journal, real local socket protocol.

Run only in the isolated QA container: /run/user/1000 and /tmp fixtures are owned
by this test container. No systemd unit or installed crash collector is touched.
"""
import json
import argparse
import os
from pathlib import Path
import socket
import subprocess
import threading
import time

ROOT = Path(__file__).resolve().parent.parent
parser = argparse.ArgumentParser()
parser.add_argument('--build-dir', type=Path, required=True)
args = parser.parse_args()
BUILD = args.build_dir.resolve()
SOCKET = Path('/run/user/1000/drkonqi-coredump-launcher')
assert Path('/run/.containerenv').is_file() or Path('/run/.shadowfetch-drkonqi-private-test').is_file(), 'Only run through private QA container or run-tests.py namespace'
SOCKET.parent.mkdir(parents=True, exist_ok=True)
Path('/tmp/qa-core').write_bytes(b'QA fixture, not a coredump\n')
Path('/tmp/qa-absent-core').unlink(missing_ok=True)
RESULTS = []


def run_case(name, variant, *, count=0, pickup=True, fault='', missing=False,
             socket_mode='listen', limit=None, timeout=3, expected_code=0,
             expected_count=0, native_journal=False, settle=False, payload=0, slow_read=False):
    SOCKET.unlink(missing_ok=True)
    received, server_errors = [], []
    stop = threading.Event()
    listener = None
    if socket_mode == 'listen':
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        listener.bind(str(SOCKET))
        listener.listen(16)
        listener.settimeout(.05)
    elif socket_mode == 'refuse':
        # Existing pathname with no listening socket exercises connect failure.
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        listener.bind(str(SOCKET))
        listener.close()
        listener = None

    def serve():
        nonlocal listener
        try:
            while not stop.is_set():
                try:
                    conn, _ = listener.accept()
                except socket.timeout:
                    continue
                conn.settimeout(2)
                with conn:
                    data = b''
                    while True:
                        chunk = conn.recv(262144)
                        if not chunk:
                            break
                        data += chunk
                        if slow_read:
                            time.sleep(.002)
                received.append(json.loads(data))
                if limit and len(received) >= limit:
                    listener.close()
                    listener = None
                    return
        except Exception as exc:
            server_errors.append(repr(exc))

    thread = threading.Thread(target=serve, daemon=True) if listener else None
    if thread:
        thread.start()
    command = [str(BUILD / ('processor-original' if variant == 'original' else 'shadowfetch-drkonqi-pickup')), '--uid', '1000']
    if pickup:
        command += ['--pickup']
    if settle:
        command += ['--settle-first']
    environment = dict(os.environ)
    if not native_journal:
        environment.update(LD_PRELOAD=str(BUILD/'libjournal-fixture.so'),
                           QA_JOURNAL_COUNT=str(count), QA_JOURNAL_FAULT=fault)
        if missing:
            environment['QA_MISSING_CORES'] = '1'
        if payload:
            environment['QA_PAYLOAD_BYTES'] = str(payload)
    started = time.monotonic()
    process = subprocess.Popen(command, env=environment, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
        code = process.returncode
    except subprocess.TimeoutExpired:
        process.terminate()
        stdout, stderr = process.communicate(timeout=2)
        code = 'TIMEOUT'
    elapsed = time.monotonic() - started
    # Complete the final socket read before stopping the private listener.
    time.sleep(.05)
    stop.set()
    if thread:
        thread.join(timeout=3)
    if listener:
        listener.close()
    SOCKET.unlink(missing_ok=True)
    passed = code == expected_code and len(received) == expected_count and not server_errors
    if settle:
        passed = passed and elapsed >= 60
    if received:
        passed = passed and len({x['COREDUMP_PID'] for x in received}) == len(received)
        passed = passed and all((x.get('_DRKONQI_PICKUP') == 'TRUE') == pickup for x in received)
        if payload:
            passed = passed and all(x.get('QA_PAYLOAD') == 'x' * payload for x in received)
    row = dict(name=name, variant=variant, result='PASS' if passed else 'FAIL',
               exit_code=code, expected_exit_code=expected_code, received=len(received),
               expected_received=expected_count, seconds=round(elapsed, 3),
               real_journal=native_journal, real_unix_socket=True,
               stderr=stderr.decode(errors='replace')[-4000:], server_errors=server_errors)
    RESULTS.append(row)
    print(json.dumps({k:v for k,v in row.items() if k != 'stderr'}), flush=True)


run_case('upstream-empty-reproduces-idle', 'original', timeout=1, expected_code='TIMEOUT')
run_case('pickup-empty-exits', 'patched')
run_case('pickup-one-pending-delivered', 'patched', count=1, expected_count=1)
run_case('pickup-multiple-pending-delivered', 'patched', count=5, expected_count=5)
run_case('pickup-delayed-segmented-socket-drains-before-exit', 'patched', count=2, expected_count=2, payload=131072, slow_read=True, timeout=8)
run_case('upstream-batch-truncation-reproduced', 'original', count=257, expected_count=256)
run_case('pickup-more-than-two-batches', 'patched', count=257, expected_count=257)
run_case('pickup-missing-cores-skipped-complete', 'patched', count=300, missing=True, expected_count=150)
run_case('pickup-no-socket-remains-nonfatal', 'patched', count=300, socket_mode='absent')
run_case('pickup-refused-socket-fails', 'patched', count=3, socket_mode='refuse', expected_code=1)
run_case('pickup-later-batch-error-wins', 'patched', count=257, limit=128, expected_code=1, expected_count=128)
for fault in ('match', 'fd', 'seek', 'read'):
    run_case(f'pickup-journal-{fault}-failure', 'patched', fault=fault, expected_code=1)
for variant in ('original', 'patched'):
    run_case('nonpickup-empty-keeps-waiting', variant, pickup=False, timeout=1, expected_code='TIMEOUT')
    run_case('nonpickup-pending-protocol-unchanged', variant, pickup=False, count=1, expected_count=1)
    run_case('nonpickup-missing-core-still-reported', variant, pickup=False, count=2, missing=True, expected_count=2)
    run_case('nonpickup-socket-error-still-fails', variant, pickup=False, count=1, socket_mode='refuse', expected_code=1)
run_case('native-empty-journal-exits', 'patched', native_journal=True)
run_case('native-empty-settle-first-exits-after-one-minute', 'patched', native_journal=True, settle=True, timeout=65)
report = {'schema_version':1, 'status':'PASS' if all(x['result']=='PASS' for x in RESULTS) else 'FAIL',
          'tests':RESULTS, 'case_count':len(RESULTS),
          'scope':'Private container; original/patched native Qt executables; deterministic journal ABI fixture and real SOCK_SEQPACKET; final two tests use real libsystemd journal.'}
(BUILD/'validation-results.json').write_text(json.dumps(report, indent=2)+'\n')
raise SystemExit(0 if report['status']=='PASS' else 1)
