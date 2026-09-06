"""Behavioral retirement tests use private fixtures and a fake service/container runner."""
import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / 'data/usr/libexec/shadowfetch-retire-buzz'
loader = importlib.machinery.SourceFileLoader('retire_buzz', str(PATH))
spec = importlib.util.spec_from_loader(loader.name, loader)
m = importlib.util.module_from_spec(spec)
loader.exec_module(m)


class RetirementTests(unittest.TestCase):
    def fixture(self, home):
        compose = home / '.local/share/shadowfetch/buzz/compose.yml'
        compose.parent.mkdir(parents=True)
        compose.write_text('legacy distro configuration fixture\n')
        link = home / '.config/systemd/user/default.target.wants' / m.UNIT
        link.parent.mkdir(parents=True)
        link.symlink_to('/usr/lib/systemd/user/' + m.UNIT)
        data = home / 'Models/model.gguf';data.parent.mkdir();data.write_bytes(b'preserve model')
        secret = compose.parent / '.env';secret.write_bytes(b'private fixture')
        return compose, link, data, secret

    def fake(self, calls, ids, unavailable=False):
        def run(args):
            calls.append(args)
            rc, out = 0, ''
            if args[:4] == ['systemctl', '--user', 'show', '--property=Version']:
                rc = 1 if unavailable else 0
            elif args[:4] == ['systemctl', '--user', 'show', m.UNIT]:
                rc, out = 4, 'LoadState=not-found\nFragmentPath=\nDropInPaths=\n'
            elif args[:3] == ['systemctl', '--user', 'stop']:
                rc = 5
            elif args[:3] == ['systemctl', '--user', 'is-active']:
                out = 'inactive\n'
            elif args[:2] == ['podman', 'ps']:
                out = '\n'.join(ids)
            elif args[:2] == ['podman', 'inspect']:
                if args[3] == '{{.State.Running}}':
                    out = 'false'
                else:
                    # Podman exposes .ID, unlike the Docker-style .Id spelling.
                    # The installed Podman rejects unknown template fields.
                    if args[3] != '[{{json .ID}},{{json .Name}},{{json .Config.Labels}}]':
                        return subprocess.CompletedProcess(args, 125, '', 'invalid inspect template')
                    ident = args[-1]
                    role = 'redis' if ident == 'a'*64 else 'unrelated'
                    out = json.dumps([ident, f'shadowfetch-buzz_{role}_1', {
                        'io.podman.compose.project': 'shadowfetch-buzz',
                        'com.docker.compose.service': role}])
            return subprocess.CompletedProcess(args, rc, out, '')
        return run

    def test_exact_owned_container_selection(self):
        valid = ['a'*64, 'shadowfetch-buzz_redis_1', {'io.podman.compose.project': 'shadowfetch-buzz', 'com.docker.compose.service': 'redis'}]
        self.assertTrue(m.owned_container(valid))
        for row in ([valid[0], 'personal_redis_1', valid[2]], [valid[0], valid[1], {'io.podman.compose.project':'personal', 'com.docker.compose.service':'redis'}], ['bad', valid[1], valid[2]], [None, valid[1], valid[2]], [valid[0], None, valid[2]], []):
            self.assertFalse(m.owned_container(row))

    def test_retirement_preserves_data_and_nonmatching_container(self):
        with tempfile.TemporaryDirectory() as t:
            home = Path(t);compose, link, model, secret = self.fixture(home)
            before = {p:p.read_bytes() for p in (compose, model, secret)};calls=[]
            with patch.object(m, 'COMPOSE_SHA', hashlib.sha256(compose.read_bytes()).hexdigest()), patch.object(m, 'run', self.fake(calls, ['a'*64, 'b'*64])):
                self.assertEqual('retired', m.retire_user(home, os.getuid())['status'])
                count=len(calls)
                self.assertEqual('already-retired', m.retire_user(home, os.getuid())['status'])
                self.assertEqual(count,len(calls))
            self.assertFalse(link.is_symlink())
            self.assertEqual(before, {p:p.read_bytes() for p in before})
            self.assertIn(['podman','update','--restart=no','a'*64], calls)
            self.assertIn(['podman','stop','--time','30','a'*64], calls)
            self.assertFalse(any(c[:2] in (['podman','stop'],['podman','update']) and c[-1]=='b'*64 for c in calls))
            self.assertFalse(any('rm' in c or 'prune' in c or 'down' in c for c in calls))

    def test_missing_manager_defers_and_next_login_retries(self):
        with tempfile.TemporaryDirectory() as t:
            home=Path(t);compose,link,*_=self.fixture(home);calls=[]
            with patch.object(m,'COMPOSE_SHA',hashlib.sha256(compose.read_bytes()).hexdigest()):
                with patch.object(m,'run',self.fake(calls, [], unavailable=True)):
                    self.assertEqual('deferred',m.retire_user(home,os.getuid())['status'])
                self.assertTrue(link.is_symlink())
                self.assertFalse(any(c[0]=='podman' for c in calls))
                with patch.object(m,'run',self.fake(calls, [])):
                    self.assertEqual('retired',m.retire_user(home,os.getuid())['status'])

    def test_user_override_and_modified_compose_are_untouched(self):
        for override in (True,False):
            with self.subTest(override=override), tempfile.TemporaryDirectory() as t:
                home=Path(t);compose,link,*_=self.fixture(home)
                if override:
                    (home/'.config/systemd/user'/m.UNIT).write_text('user-owned service')
                with patch.object(m,'run',side_effect=AssertionError('No commands allowed')):
                    expected='user-override-preserved' if override else 'custom-configuration-preserved'
                    self.assertEqual(expected,m.retire_user(home,os.getuid())['status'])
                self.assertTrue(link.is_symlink())

    def test_container_failure_never_marks_retirement_complete(self):
        with tempfile.TemporaryDirectory() as t:
            home=Path(t);compose,*_=self.fixture(home);calls=[];normal=self.fake(calls,['a'*64])
            def fail(args):
                if args[:2]==['podman','stop']:return subprocess.CompletedProcess(args,1,'','')
                return normal(args)
            with patch.object(m,'COMPOSE_SHA',hashlib.sha256(compose.read_bytes()).hexdigest()),patch.object(m,'run',fail):
                with self.assertRaises(RuntimeError):m.retire_user(home,os.getuid())
            self.assertFalse((home/'.local/state/shadowfetch/migrations/buzz-retired-4.0').exists())

    @unittest.skipUnless(sys.platform == 'linux' and os.geteuid() != 0, 'GNU utilities and a regular Linux user required')
    def test_workspace_create_list_open_without_vendor_runtime(self):
        with tempfile.TemporaryDirectory() as t:
            base = Path(t); bins = base / 'bin'; bins.mkdir()
            for command in ('realpath', 'mkdir', 'chmod', 'tr', 'sed', 'cut', 'cat', 'find', 'sort'):
                (bins / command).symlink_to(shutil.which(command))
            env = {'PATH': str(bins), 'HOME': t, 'SHADOWFETCH_AGENT_WORKSPACES': str(base / 'Workspaces')}
            helper = ROOT / 'data/usr/bin/shadowfetch-agent-workspace'
            def call(*args):
                return subprocess.run(['/bin/bash', str(helper), *args], env=env, capture_output=True, text=True, timeout=5)
            created = call('create', 'Demo Project')
            self.assertEqual(0, created.returncode, created.stderr)
            workspace = base / 'Workspaces/demo-project'
            self.assertTrue((workspace / 'AGENTS.md').is_file())
            self.assertTrue((workspace / 'TASKS.md').is_file())
            (workspace.parent / '.sf-checkpoints').mkdir()
            (workspace.parent / 'external').symlink_to(base, target_is_directory=True)
            self.assertEqual('demo-project', call('list').stdout.strip())
            self.assertEqual(str(workspace), call('open', 'demo-project').stdout.strip())
            self.assertNotEqual(0, call('open', 'external').returncode)
            self.assertNotEqual(0, call('run', 'demo-project').returncode)
            self.assertNotEqual(0, call('create', 'demo-project').returncode)

    def test_shipped_payload_has_no_local_runtime(self):
        install=(ROOT/'debian/shadowfetch-defaults.install').read_text()
        for name in ('shadowfetch-buzz','shadowfetch-model-check','shadowfetch-agent-doctor','shadowfetch-agent-tools'):
            self.assertFalse((ROOT/'data/usr/bin'/name).exists())
            self.assertNotIn('data/usr/bin/'+name+' ',install)
        self.assertIn('data/usr/bin/shadowfetch-grok-bot ',install)
        self.assertIn('data/usr/bin/shadowfetch-agent-workspace ',install)
        self.assertNotIn(' podman-compose,', (ROOT/'debian/control').read_text())


if __name__ == '__main__':unittest.main()
