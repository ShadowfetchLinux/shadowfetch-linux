"""Account storage permissions and real advisory-lock exclusion."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / 'data/usr/lib/shadowfetch/missions/sf_mission_account.py'
spec = importlib.util.spec_from_file_location('mission_account', SOURCE)
account = importlib.util.module_from_spec(spec)
spec.loader.exec_module(account)


class AccountStorageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.patch = patch.object(account.Path, 'home', return_value=self.home)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def test_missing_login_does_not_create_storage(self):
        with self.assertRaises(account.AccountError):
            account.account_home()
        self.assertFalse((self.home / '.local').exists())

    def test_private_home_and_no_host_auth_import(self):
        host = self.home / '.codex'
        host.mkdir()
        (host / 'auth.json').write_text('synthetic-host-secret')
        p = account.account_home(create=True)
        self.assertEqual(p.stat().st_mode & 0o777, 0o700)
        self.assertFalse((p / 'auth.json').exists())

    def test_symlink_parent_refused(self):
        target = self.home / 'other'
        target.mkdir()
        (self.home / '.local').symlink_to(target)
        with self.assertRaises(account.AccountError):
            account.account_home(create=True)

    def test_shared_writable_parent_refused(self):
        p = account.account_home(create=True)
        p.parent.chmod(0o777)
        with self.assertRaises(account.AccountError):
            account.account_home()

    def test_public_credentials_refused(self):
        p = account.account_home(create=True)
        auth = p / 'auth.json'
        auth.write_text('{}')
        auth.chmod(0o644)
        with self.assertRaises(account.AccountError):
            account.account_home()
        auth.chmod(0o600)
        self.assertEqual(account.account_home(), p)

    def test_hardlinked_credentials_refused(self):
        p = account.account_home(create=True)
        auth = p / 'auth.json'
        auth.write_text('{}')
        auth.chmod(0o600)
        os.link(auth, p / 'alias')
        with self.assertRaises(account.AccountError):
            account.account_home()

    def test_real_lock_exclusion_and_release(self):
        p = account.account_home(create=True)
        with account.account_lock(p):
            with self.assertRaises(account.AccountError):
                with account.account_lock(p):
                    self.fail('Concurrent lock accepted')
        with account.account_lock(p):
            pass

    def test_symlink_lock_refused_without_touching_target(self):
        p = account.account_home(create=True)
        target = self.home / 'sentinel'
        target.write_text('preserve')
        (p.parent / 'mission-account.lock').symlink_to(target)
        with self.assertRaises(OSError):
            with account.account_lock(p):
                self.fail('Symlink accepted')
        self.assertEqual(target.read_text(), 'preserve')
