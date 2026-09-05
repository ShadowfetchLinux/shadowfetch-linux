#!/usr/bin/env python3
"""Exercise installed missions against a real, verified native Buzz model."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--model', required=True)
    parser.add_argument('--kind', choices=('code', 'report'), required=True)
    args = parser.parse_args()
    if os.geteuid() == 0:
        parser.error('Run as the desktop QA user')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    scope = Path.home() / 'Workspaces' / ('qa-native-' + args.kind + '-' + str(time.time_ns()))
    scope.mkdir(parents=True)
    env = {**os.environ, 'SHADOWFETCH_MISSIONS_STATE': str(output / 'controller'), 'PYTHONDONTWRITEBYTECODE': '1'}
    checks, commands = [], []
    mission = None

    def check(name, passed, detail=None):
        row = {'check': name, 'pass': bool(passed), 'detail': detail}
        checks.append(row)
        print(json.dumps(row), flush=True)
        if not passed:
            raise AssertionError(name)

    def cli(*values):
        result = subprocess.run(['shadowfetch-missions', '--json', *values], env=env, text=True, capture_output=True, timeout=950)
        row = {'args': values, 'exit': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr}
        commands.append(row)
        (output / 'commands.json').write_text(json.dumps(commands, indent=2))
        if result.returncode:
            raise AssertionError('CLI failed: ' + result.stdout[-2000:])
        return json.loads(result.stdout)

    try:
        capabilities = cli('capabilities')
        check('chosen model has native process ownership proof', any(m['name'] == args.model and m.get('local_only_verified') is True for m in capabilities['runtimes']['local']['models']))
        if args.kind == 'code':
            (scope / 'title.py').write_text('def normalize_title(title):\n    return title\n')
            tests = "from title import normalize_title\nassert normalize_title('  Shadowfetch \\n Linux  ') == 'Shadowfetch Linux'\nassert normalize_title('Ice\\tEdition') == 'Ice Edition'\nassert normalize_title('  café   日本語 ') == 'café 日本語'\nassert normalize_title('   ') == ''\nprint('4 independent normalization checks passed')\n"
            (scope / 'test_title.py').write_text(tests)
            baseline = subprocess.run(['python3', 'test_title.py'], cwd=scope, capture_output=True, text=True)
            check('baseline reproduces the code defect', baseline.returncode != 0, baseline.stderr[-1000:])
            inputs = ['--input', 'title.py', '--test-json', '["python3","test_title.py"]']
            prompt = 'Fix normalize_title in title.py so it trims leading and trailing whitespace and collapses every run of whitespace, including tabs and newlines, to one ordinary space. Preserve Unicode letters. An empty or whitespace-only input returns an empty string. Only edit title.py. Return the complete file as the required JSON files object.'
        else:
            (scope / 'release-notes.md').write_text('Shadowfetch Linux 4.0 includes three mission types: code, source reports, and media export.\nThe mission queue persists in a SQLite database outside the selected workspace.\nResults require review before they are accepted.\nA checkpoint can restore workspace files after a mission.\nRestoring workspace files cannot reverse external network actions.\nNative inference is verified using the model process and its owned loopback socket.\n')
            inputs = ['--input', 'release-notes.md']
            prompt = 'Write a short release-readiness briefing with exactly two factual bullet points and one limitation. Cover the mission types and review/recovery behavior. Every bullet must cite exact provided source line ranges, for example [S1:L1-L3]. Do not add facts beyond the source document.'
        before = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in scope.iterdir() if p.is_file()}
        created = cli('create', '--kind', args.kind, '--workspace', scope.name, '--title', 'Native Buzz ' + args.kind + ' acceptance', '--prompt', prompt, '--runtime', 'local', '--model', args.model, '--network', 'none', '--timeout', '900', *inputs)
        mission = created['id']
        started = time.monotonic()
        done = cli('run', mission)
        check('real inference reaches human review', done['state'] == 'waiting-review', {'elapsed_seconds': round(time.monotonic() - started, 3), 'mission': mission})
        receipt = json.loads(Path(done['receipt']).read_text())
        (output / 'receipt.json').write_text(json.dumps(receipt, indent=2))
        inferences = receipt.get('inferences', [])
        check('receipt proves actual native inference', bool(inferences) and all(i.get('compute', {}).get('local_only_verified') is True and i['compute'].get('pid') and i['compute'].get('process_start') for i in inferences), inferences)
        check('artifact receipt hashes match', bool(receipt['artifacts']) and all(Path(a['path']).stat().st_size == a['bytes'] and hashlib.sha256(Path(a['path']).read_bytes()).hexdigest() == a['sha256'] for a in receipt['artifacts']))
        changes = cli('diff', mission)['diff']
        (output / 'changes.diff').write_text(changes)
        (output / 'events.json').write_text(json.dumps(cli('events', mission), indent=2))
        if args.kind == 'code':
            independent = subprocess.run(['python3', 'test_title.py'], cwd=scope, env=env, text=True, capture_output=True)
            check('independent real code tests pass', independent.returncode == 0, independent.stdout + independent.stderr)
            check('original validation file was preserved', (scope / 'test_title.py').read_text() == tests)
            check('code diff records the actual repair', 'title.py' in changes and hashlib.sha256((scope / 'title.py').read_bytes()).hexdigest() != before['title.py'])
            (output / 'repaired-title.py').write_text((scope / 'title.py').read_text())
        else:
            report = next(Path(a['path']) for a in receipt['artifacts'] if Path(a['path']).name == 'report.md')
            text = report.read_text()
            (output / 'report.md').write_text(text)
            citations = re.findall(r'\[S1:L(\d+)(?:-L?(\d+))?\]', text)
            check('report has valid citations into actual input', bool(citations) and all(1 <= int(start) <= int(end or start) <= 6 for start, end in citations), citations)
            check('source document remains byte-identical', hashlib.sha256((scope / 'release-notes.md').read_bytes()).hexdigest() == before['release-notes.md'])
        check('accept records completed state', cli('review', mission, '--decision', 'accept')['state'] == 'completed')
        check('undo restores the checkpoint', cli('review', mission, '--decision', 'undo')['state'] == 'undone')
        after = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in scope.iterdir() if p.is_file()}
        check('original source hashes restored and artifacts removed', before == after and not (scope / 'mission-output').exists())
        status = 'PASS'
    except Exception as exc:
        status = 'FAIL'
        checks.append({'check': 'acceptance completed', 'pass': False, 'detail': str(exc)})
        if mission:
            try:
                latest = cli('show', mission)
                (output / 'failed-mission.json').write_text(json.dumps(latest, indent=2))
            except Exception:
                pass
    result = {'status': status, 'kind': args.kind, 'model': args.model, 'mission': mission, 'workspace': str(scope), 'checks': checks}
    (output / 'result.json').write_text(json.dumps(result, indent=2))
    print(json.dumps(result), flush=True)
    return 0 if status == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())
