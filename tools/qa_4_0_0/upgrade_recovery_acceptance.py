#!/usr/bin/env python3
"""Destructive recovery acceptance confined to the named disposable QEMU guest.

Host invocation must use vm_harness.sh exec final-upgrade. Never run on the host.
This helper does not reboot automatically; the host records evidence first.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.request

STATE = Path('/home/sfqa/.sf4-upgrade-qa')
USER_FILE = Path('/home/sfqa/Workspaces/upgrade-recovery-proof/personal-project.txt')
BASE = 'http://10.0.2.2:8094/build/'


def run(*args, check=True):
    result = subprocess.run(args, text=True, capture_output=True, timeout=600)
    if check and result.returncode:
        raise RuntimeError('Command failed: ' + repr(args) + '\n' + result.stdout[-3000:] + result.stderr[-3000:])
    return result


def guard():
    if os.geteuid() != 0 or os.uname().nodename != 'sfqa-final-upgrade':
        raise RuntimeError('This helper is restricted to root inside sfqa-final-upgrade')
    if run('systemd-detect-virt').stdout.strip() not in ('qemu', 'kvm'):
        raise RuntimeError('A disposable QEMU/KVM guest is required')
    root = run('findmnt', '-no', 'SOURCE,FSTYPE', '/').stdout.strip()
    if not root.startswith('/dev/vda') or not root.endswith(' btrfs'):
        raise RuntimeError('Expected the disposable virtio Btrfs root disk')
    if not Path('/home/sfqa').is_dir() or not run('findmnt', '-no', 'SOURCE', '/home').stdout.strip().endswith('[/@home]'):
        raise RuntimeError('Expected sfqa with a separate @home subvolume')


def packages():
    result = run('dpkg-query', '-W', '-f=${Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n', 'shadowfetch-*')
    return {line.split('\t')[0]: line.split('\t')[1:3] for line in result.stdout.splitlines() if line.endswith('\tii ')}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(name, data):
    STATE.mkdir(parents=True, exist_ok=True)
    (STATE / name).write_text(json.dumps(data, indent=2))


def verify_data(state):
    if not USER_FILE.is_file() or sha(USER_FILE) != state['user_sha256']:
        raise RuntimeError('Personal data hash changed')
    if Path('/etc/machine-id').read_text().strip() != state['machine_id']:
        raise RuntimeError('Machine identity changed')


def audit(state, version, *, allow_previous_candidate=False):
    verify_data(state)
    expected = set(state['packages']) | ({'shadowfetch-missions', 'shadowfetch-drkonqi-pickup'} if version == '4.0.0' else set())
    installed = packages()
    # Only the pre-refresh check may admit the preserved candidate4 inventory.
    # Post-upgrade and final acceptance always require the correction package.
    if allow_previous_candidate and version == '4.0.0' and 'shadowfetch-drkonqi-pickup' not in installed:
        expected.discard('shadowfetch-drkonqi-pickup')
    if set(installed) != expected or any(row[0] != version + '-1' for row in installed.values()):
        raise RuntimeError('Unexpected installed package names or versions: ' + repr(installed))
    if Path('/usr/share/shadowfetch/version').read_text().strip() != version:
        raise RuntimeError('Version marker does not match installed packages')
    if 'VERSION_ID="' + version + '"' not in Path('/etc/os-release').read_text():
        raise RuntimeError('os-release does not match installed packages')
    if 'boot=live' in Path('/proc/cmdline').read_text():
        raise RuntimeError('Expected installed disk boot')
    if run('findmnt', '-no', 'FSTYPE', '/boot').stdout.strip() != 'ext4':
        raise RuntimeError('Expected separate ext4 boot filesystem')
    if run('dpkg', '--audit').stdout.strip():
        raise RuntimeError('dpkg audit is not clean')
    failed = run('systemctl', '--failed', '--no-legend', '--plain').stdout.strip()
    if failed:
        raise RuntimeError('Failed system units: ' + failed)
    for unit in ('shadowfetch-firewatchd.service', 'shadowfetch-hwscan.service', 'phoenix-postboot.service'):
        run('systemctl', 'is-active', '--quiet', unit)
    if not Path('/var/lib/shadowfetch/phoenix-firstboot.done').is_file():
        raise RuntimeError('Phoenix setup is incomplete')
    run('systemctl', 'is-enabled', '--quiet', 'fireproof-postboot.timer')
    if Path('/var/lib/shadowfetch/phoenix-update-grub').exists():
        raise RuntimeError('Phoenix postboot GRUB completion is still pending')
    if version == '4.0.0':
        if 'shadowfetch-drkonqi-pickup' in installed:
            run('/usr/libexec/shadowfetch-drkonqi-pickup', '--help')
            if run('dpkg-query', '-W', '-f=${Version}', 'drkonqi').stdout != '6.6.5-3':
                raise RuntimeError('DrKonqi protocol version differs from tested release')
            if run('dpkg', '--verify', 'drkonqi', 'shadowfetch-drkonqi-pickup').stdout.strip():
                raise RuntimeError('DrKonqi or correction package payload was changed')
        for executable in ('shadowfetch-missions', 'shadowfetch-grok-bot'):
            run(executable, '--version')
        run('runuser', '-u', 'sfqa', '--', 'shadowfetch-model-check', 'status', '--json')
        run('runuser', '-u', 'sfqa', '--', 'env', 'HOME=/home/sfqa', 'XDG_RUNTIME_DIR=/run/user/1000', 'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus', 'systemctl', '--user', 'is-active', '--quiet', 'shadowfetch-missions.service')
        user_env = ['runuser', '-u', 'sfqa', '--', 'env', 'HOME=/home/sfqa',
                    'XDG_RUNTIME_DIR=/run/user/1000', 'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus']
        if not allow_previous_candidate:
            if run(*user_env, 'systemctl', '--user', '--failed', '--no-legend', '--plain').stdout.strip():
                raise RuntimeError('Failed desktop user services after upgrade')
            pickup_exec = run(*user_env, 'systemctl', '--user', 'show',
                              'drkonqi-coredump-pickup.service', '-p', 'ExecStart', '--value').stdout
            if '/usr/libexec/shadowfetch-drkonqi-pickup --settle-first --pickup --uid ' not in pickup_exec:
                raise RuntimeError('Login pickup is not using the correction')
        run('runuser', '-u', 'sfqa', '--', 'shadowfetch-missions', '--json', 'list')
    return {'status': 'PASS', 'version': version, 'packages': installed, 'personal_data_sha256': sha(USER_FILE), 'kernel': os.uname().release, 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'root': run('findmnt', '-no', 'SOURCE,FSTYPE,OPTIONS', '/').stdout.strip(), 'home': run('findmnt', '-no', 'SOURCE,FSTYPE', '/home').stdout.strip(), 'failed_system_units': [], 'dpkg_audit': 'clean'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'upgrade', 'refresh', 'audit', 'restore', 'verify-rollback'))
    parser.add_argument('--phase', default='first', choices=('first', 'second', 'final-refresh', 'final'))
    args = parser.parse_args()
    guard()
    if args.action == 'prepare':
        if STATE.exists():
            raise RuntimeError('Preparation already exists; inspect before any repeat')
        if Path('/usr/share/shadowfetch/version').read_text().strip() != '3.5.0':
            raise RuntimeError('The original immutable 3.5 installation is required')
        run('runuser', '-u', 'sfqa', '--', 'mkdir', '-p', str(USER_FILE.parent))
        USER_FILE.write_text('Personal Shadowfetch project: keep this file through upgrade, Phoenix rollback, and re-upgrade.\n')
        os.chown(USER_FILE, 1000, 1000)
        state = {'packages': packages(), 'user_sha256': sha(USER_FILE), 'machine_id': Path('/etc/machine-id').read_text().strip(), 'prepared_at': time.time(), 'original_boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
        number = run('snapper', '--no-dbus', '-c', 'root', 'create', '--print-number', '--description', '4.0 QA: before upgrade from 3.5').stdout.strip()
        if not number.isdecimal() or int(number) < 1:
            raise RuntimeError('Phoenix Point creation did not return an ID')
        state['snapshot'] = int(number)
        save('state.json', state)
        result = audit(state, '3.5.0')
        result['snapshot'] = int(number)
        save('baseline.json', result)
    else:
        state = json.loads((STATE / 'state.json').read_text())
        if args.action in ('upgrade', 'refresh'):
            audit(state, '4.0.0' if args.action == 'refresh' else '3.5.0',
                  allow_previous_candidate=args.action == 'refresh')
            dest = STATE / ('packages-' + args.phase)
            dest.mkdir(exist_ok=False)
            wanted = {**state['packages'], 'shadowfetch-missions': ['4.0.0-1', 'all'],
                      'shadowfetch-drkonqi-pickup': ['4.0.0-1', 'amd64']}
            hashes = {}
            for package, (_, architecture) in sorted(wanted.items()):
                filename = package + '_4.0.0-1_' + architecture + '.deb'
                target = dest / filename
                with urllib.request.urlopen(BASE + filename, timeout=180) as response, target.open('wb') as stream:
                    while data := response.read(1024 * 1024):
                        stream.write(data)
                hashes[filename] = sha(target)
            save('package-hashes-' + args.phase + '.json', hashes)
            files = [str(path) for path in sorted(dest.glob('*.deb'))]
            reinstall = ['--reinstall'] if args.action == 'refresh' else []
            os.environ['DEBIAN_FRONTEND'] = 'noninteractive'
            simulated = run('apt-get', '-o', 'DPkg::Lock::Timeout=120', '--no-remove', *reinstall, '-s', 'install', *files)
            (STATE / ('apt-simulation-' + args.phase + '.log')).write_text(simulated.stdout + simulated.stderr)
            if any(line.startswith('Remv ') for line in simulated.stdout.splitlines()):
                raise RuntimeError('Upgrade proposes package removal')
            installed = run('apt-get', '-o', 'DPkg::Lock::Timeout=120', '--no-remove', *reinstall, '-y', 'install', *files)
            (STATE / ('apt-upgrade-' + args.phase + '.log')).write_text(installed.stdout + installed.stderr)
            verify_data(state)
            result = {'status': 'UPGRADED_REBOOT_REQUIRED', 'phase': args.phase, 'package_hashes': hashes, 'personal_data_sha256': sha(USER_FILE), 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
            save('upgrade-' + args.phase + '.json', result)
        elif args.action == 'audit':
            result = audit(state, '4.0.0')
            previous = json.loads((STATE / ('upgrade-' + args.phase + '.json')).read_text())
            if result['boot_id'] == previous['boot_id']:
                raise RuntimeError('Upgrade requires a real reboot before installed audit')
            save('installed-' + args.phase + '.json', result)
        elif args.action == 'restore':
            audit(state, '4.0.0')
            restored = run('/usr/libexec/phoenix-restore', str(state['snapshot']))
            (STATE / 'phoenix-restore.log').write_text(restored.stdout + restored.stderr)
            result = {'status': 'RESTORED_REBOOT_REQUIRED', 'snapshot': state['snapshot'], 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
            save('restore.json', result)
        else:
            result = audit(state, '3.5.0')
            previous = json.loads((STATE / 'restore.json').read_text())
            if result['boot_id'] == previous['boot_id']:
                raise RuntimeError('Phoenix rollback has not rebooted')
            result['snapshot'] = state['snapshot']
            save('rollback.json', result)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
