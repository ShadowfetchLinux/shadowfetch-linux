#!/usr/bin/env python3
"""Installed Linux crash recovery and kernel-enforced resource acceptance.

Uses private real worker processes and controller state. Never stops the normal
desktop worker, injects mission state, substitutes a runtime, or performs inference.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import time
import wave


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() == 0:
        parser.error('Run as the logged-in desktop QA user')
    out = args.output.resolve()
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    roots = out / 'Workspaces'
    workspace = roots / 'durable'
    workspace.mkdir(parents=True)
    env = {**os.environ, 'SHADOWFETCH_AGENT_WORKSPACES': str(roots),
           'SHADOWFETCH_MISSIONS_STATE': str(out / 'controller'),
           'XDG_STATE_HOME': str(out / 'runtime-state')}
    rows, children = [], []

    def check(name, condition, detail=None):
        row = {'check': name, 'pass': bool(condition), 'detail': detail}
        rows.append(row)
        print(json.dumps(row), flush=True)
        if not condition:
            raise AssertionError(name)

    def command(argv, *, expected=0, current_env=env):
        result = subprocess.run(argv, env=current_env, text=True, capture_output=True, timeout=45)
        if result.returncode != expected:
            raise RuntimeError(f'Unexpected command exit {result.returncode}: {result.stderr[-1500:]} {result.stdout[-1500:]}')
        return result.stdout

    def cli(*args, expected=0):
        return json.loads(command(['shadowfetch-missions', '--json', *args], expected=expected))

    def sha(path):
        value = hashlib.sha256()
        with path.open('rb') as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                value.update(chunk)
        return value.hexdigest()

    def properties(unit):
        raw = command(['systemctl', '--user', 'show', unit, '--property=MainPID,ActiveState,TasksMax,MemoryMax,MemoryHigh,CPUQuotaPerSecUSec,ControlGroup'])
        props = dict(line.split('=', 1) for line in raw.splitlines() if '=' in line)
        group = Path('/sys/fs/cgroup') / props['ControlGroup'].lstrip('/')
        props['kernel'] = {name: (group / name).read_text().strip() for name in ('pids.max', 'memory.max', 'cpu.max')}
        return props

    try:
        unit_before = properties('shadowfetch-missions.service')
        quota, period = map(int, unit_before['kernel']['cpu.max'].split())
        check('production worker has real per-unit kernel resource limits',
              unit_before['ActiveState'] == 'active' and int(unit_before['MainPID']) > 0
              and unit_before['kernel']['pids.max'] == '128'
              and unit_before['kernel']['memory.max'] == str(4 * 1024**3)
              and quota / period == 2, unit_before)

        # A valid 128 MiB PCM source makes checkpoint preparation observable.
        # Only the actual worker writes task state; SQLite below is read-only.
        source = workspace / 'source.wav'
        with wave.open(str(source), 'wb') as audio:
            audio.setparams((1, 2, 48000, 0, 'NONE', 'not compressed'))
            block = b'\0' * (1024 * 1024)
            for _ in range(128):
                audio.writeframesraw(block)
        initial = sha(source)
        mission = cli('create', '--kind', 'media', '--workspace', workspace.name,
                      '--title', 'Real worker crash recovery', '--prompt', 'Export the selected PCM source',
                      '--input', source.name, '--network', 'none')
        log = (out / 'interrupted-worker.log').open('wb')
        worker = subprocess.Popen(['shadowfetch-missions', 'worker'], env=env,
                                  stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        children.append(worker)
        started = time.monotonic()
        db = sqlite3.connect(f'file:{out / "controller/missions.sqlite3"}?mode=ro', uri=True)
        try:
            while time.monotonic() - started < 15:
                events = db.execute('SELECT event FROM events WHERE mission=? ORDER BY seq', (mission['id'],)).fetchall()
                if ('checkpoint-started',) in events:
                    os.kill(worker.pid, signal.SIGSTOP)
                    break
                if worker.poll() is not None:
                    raise RuntimeError('Private worker exited before interruption')
                time.sleep(.005)
            else:
                raise RuntimeError('Private worker never began a checkpoint')
        finally:
            db.close()
        stopped = cli('show', mission['id'])
        events = cli('events', mission['id'])
        check('actual private worker interrupted inside real checkpoint preparation',
              stopped['state'] == 'running' and stopped['attempt'] == 1
              and any(item['event'] == 'checkpoint-started' for item in events)
              and not any(item['event'] == 'process-started' for item in events),
              {'worker_pid': worker.pid, 'mission': mission['id'], 'events': [item['event'] for item in events]})
        os.kill(worker.pid, signal.SIGKILL)
        check('actual private worker died from SIGKILL', worker.wait(timeout=5) == -signal.SIGKILL)
        log.close()
        # A genuine fresh production worker process recovers the same database.
        for _ in range(2):
            command(['shadowfetch-missions', 'worker', '--once'])
        recovered = cli('show', mission['id'])
        events = cli('events', mission['id'])
        check('restarted workers retain failure and never replay interrupted task',
              recovered['state'] == 'failed' and recovered['attempt'] == 1
              and 'no automatic replay' in recovered['error']
              and sum(item['event'] == 'running' for item in events) == 1
              and not recovered['artifacts'], recovered)
        check('crash and restart preserve exact source and produce no unreviewed output',
              sha(source) == initial and not (workspace / 'mission-output').exists(), {'source_sha256': initial})
        (out / 'recovery-events.json').write_text(json.dumps(events, indent=2))

        # An actual filesystem obstruction makes the required checkpoint fail.
        failed_root = out / 'failure-workspaces'
        failed_ws = failed_root / 'blocked'
        failed_ws.mkdir(parents=True)
        (failed_ws / 'notes.md').write_text('A required checkpoint must succeed before inference.\n')
        (failed_root / '.sf-checkpoints').write_text('QA obstruction: a file where a directory is required.\n')
        old_root = env['SHADOWFETCH_AGENT_WORKSPACES']
        env['SHADOWFETCH_AGENT_WORKSPACES'] = str(failed_root)
        failed = cli('create', '--kind', 'report', '--workspace', 'blocked', '--title', 'Required checkpoint failure',
                     '--prompt', 'Summarize the selected source', '--input', 'notes.md')
        failed = cli('run', failed['id'], expected=1)
        failure_events = cli('events', failed['id'])
        receipt = json.loads(Path(failed['receipt']).read_text())
        check('real checkpoint storage failure refuses execution with failed receipt',
              failed['state'] == 'failed' and 'snapshot failed' in failed['error']
              and not failed['checkpoint'] and receipt['state'] == 'failed'
              and not receipt['inferences'] and not receipt['artifacts']
              and not any(item['event'] == 'process-started' for item in failure_events)
              and (failed_ws / 'notes.md').read_text() == 'A required checkpoint must succeed before inference.\n',
              {'mission': failed, 'events': failure_events, 'receipt': receipt})
        env['SHADOWFETCH_AGENT_WORKSPACES'] = old_root

        # Inspect an actually running Firebreak scope and its kernel files.
        inner = ("import json,os,pathlib,resource,time; "
                 "p=pathlib.Path('scope-proof.json'); "
                 "p.write_text(json.dumps({'session':os.environ['SHADOWFETCH_FIREBREAK'],'address_space':resource.getrlimit(resource.RLIMIT_AS),'cpu_time':resource.getrlimit(resource.RLIMIT_CPU)})); "
                 "deadline=time.monotonic()+20\n"
                 "while not pathlib.Path('scope-release').exists() and time.monotonic()<deadline: time.sleep(.05)\n")
        scope_log = (out / 'scope.log').open('wb')
        scope = subprocess.Popen(['shadowfetch-firebreak', 'run', '--workspace', workspace.name,
                                  '--no-checkpoint', '--net', 'none', '--memory-mb', '512',
                                  '--cpu-seconds', '20', '--processes', '24', '--', 'python3', '-c', inner],
                                 env=env, stdout=scope_log, stderr=subprocess.STDOUT, start_new_session=True)
        children.append(scope)
        deadline = time.monotonic() + 15
        while not (workspace / 'scope-proof.json').exists() and time.monotonic() < deadline:
            if scope.poll() is not None:
                raise RuntimeError('Resource scope exited before proof')
            time.sleep(.05)
        proof = json.loads((workspace / 'scope-proof.json').read_text())
        props = properties(proof['session'] + '.scope')
        quota, period = map(int, props['kernel']['cpu.max'].split())
        check('running Firebreak has actual per-scope task memory and CPU limits',
              props['kernel']['pids.max'] == '24' and props['kernel']['memory.max'] == str(512 * 1024**2)
              and quota / period == 2 and proof['address_space'] == [512 * 1024**2] * 2
              and proof['cpu_time'] == [20, 21], {'scope': props, 'process_limits': proof})
        (workspace / 'scope-release').touch()
        check('real constrained process completes cleanly', scope.wait(timeout=5) == 0)
        scope_log.close()
        unit_after = properties('shadowfetch-missions.service')
        check('normal production worker remains active with identical PID',
              unit_after['ActiveState'] == 'active' and unit_after['MainPID'] == unit_before['MainPID'],
              {'before': unit_before['MainPID'], 'after': unit_after['MainPID']})
        result = {'status': 'PASS', 'checks': rows, 'mocked_execution': False,
                  'state_injected': False, 'model_inference': False,
                  'interruption_boundary': 'Actual private worker during required checkpoint preparation, before runtime execution'}
    except Exception as exc:
        result = {'status': 'FAIL', 'checks': rows, 'error': str(exc)}
    finally:
        (workspace / 'scope-release').touch()
        for child in children:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=5)
    (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result), flush=True)
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
