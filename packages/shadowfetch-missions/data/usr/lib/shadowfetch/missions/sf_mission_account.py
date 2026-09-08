"""Dedicated Codex account storage; never imports the user's general Codex home."""
import sys
import argparse
import contextlib
import fcntl
import os
from pathlib import Path
import shutil
import stat
import subprocess


class AccountError(RuntimeError):
    pass


def codex_executable():
    """Locate the Codex CLI from the provider manifest's declared candidates.

    Deliberately not shutil.which. Two reasons. The provider conformance
    suite refuses any PATH resolution reachable from an adapter's import
    chain, and this module is in it. More importantly, a person must log in
    with the same binary a mission will run -- resolving them differently is
    a way to authenticate one program and execute another.
    """
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    try:
        from sf_providers import ProviderRegistry, resolve_executable
        return resolve_executable(ProviderRegistry().manifest('codex'))
    except Exception:
        return None


def account_home(*, create=False):
    home = Path.home()
    parent = home
    for part in ('.local', 'state', 'shadowfetch', 'mission-account'):
        parent = parent / part
        if create:
            try:
                parent.mkdir(mode=0o700)
            except FileExistsError:
                pass
        try:
            info = parent.lstat()
        except FileNotFoundError:
            raise AccountError('Sign in first with shadowfetch-mission-account login') from None
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            raise AccountError('Account storage must use user-owned directories without symlinks')
        if info.st_mode & 0o022:
            raise AccountError('Account storage parents must not be writable by other users')
    if stat.S_IMODE(parent.stat().st_mode) != 0o700:
        raise AccountError('Mission account directory must have mode 0700')
    auth = parent / 'auth.json'
    if auth.exists() or auth.is_symlink():
        info = auth.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or info.st_mode & 0o077:
            raise AccountError('Mission credentials must be a private user-owned regular file')
    return parent


@contextlib.contextmanager
def account_lock(home):
    """Serialize login/logout with missions, without following lock-file links."""
    fd = os.open(home.parent / 'mission-account.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or info.st_mode & 0o077:
            raise AccountError('Unsafe mission account lock')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise AccountError('Mission account is busy; wait for the current mission or login') from None
        yield
    finally:
        os.close(fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description='Sign in to a dedicated Mission Control Codex account')
    parser.add_argument('action', choices=('login', 'status', 'logout'))
    args = parser.parse_args(argv)
    try:
        if os.getuid() == 0:
            raise AccountError('Run this as your desktop user, not root')
        codex = codex_executable()
        if not codex:
            raise AccountError('Install Codex from the agent setup first')
        home = account_home(create=args.action == 'login')
        env = {key: os.environ[key] for key in ('PATH', 'HOME', 'LANG', 'TERM') if key in os.environ}
        env['CODEX_HOME'] = str(home)
        command = [codex, '-c', 'cli_auth_credentials_store="file"']
        command += ['login', '--device-auth'] if args.action == 'login' else ['login', 'status'] if args.action == 'status' else ['logout']
        with account_lock(home):
            old_umask = os.umask(0o077)
            try:
                result = subprocess.run(command, env=env, check=False)
            finally:
                os.umask(old_umask)
            account_home()
            return result.returncode
    except (AccountError, OSError) as exc:
        parser.exit(1, str(exc) + '\n')
