#!/usr/bin/env python3
"""What tools/stamp_version.py is trusted to do, proven against a real tree.

Every test here stamps a COPY of this repository under the temporary
directory, never the tree it is running in.  The copy holds the real files --
the real os-release, the real Makefile, the real drift gate -- because the two
defects these tests pin were both invisible to a fixture:

  * ATOMICITY.  stamp() used to be nine sequential write_text() calls.  A
    failure injected at write #5 left six of the gate's twelve version sites
    at the new version and six at the old.  test_failure_at_each_write_* runs
    that injection at every write and requires the tree to come back
    byte-identical.
  * COVERAGE.  The stamper wrote nine of the gate's twelve sites; the grok-bot
    --version string, the drkonqi-pickup CMake project version and the README
    fact table were left behind, which is the drift the gate then reported.
    test_site_list_is_the_gates_list and test_gate_reports_no_version_drift_*
    pin that a successful stamp is followed by a clean gate.
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import tomllib
import unittest

SPEC = importlib.util.spec_from_file_location(
    'stamp_version', Path(__file__).resolve().parents[1] / 'stamp_version.py')
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

ROOT = MODULE.ROOT
NEW = '9.9.9'          # deliberately unlike any release this tree has cut
SUPPORT = (
    'tools/drift_gate.py',
    'tools/generate_theme_assets.py',
    'tools/stamp_version.py',
    'tools/truth/release.json',
    'tools/truth/palette.json',
)


def copy_tree(destination: Path) -> Path:
    """A copy of just the files a stamp and a version-drift check touch.

    Not a whole-tree copy: this repository is hundreds of gigabytes with
    live-build/chroot in it.  The files are the real ones, copied with their
    modes, so the executable-bit and upstream-version assertions below mean
    something.
    """
    sites = MODULE.gate_version_sites(ROOT) + list(MODULE.EXTRA_SITES)
    wanted = {rel for rel, _pattern, _label in sites}
    wanted.update(SUPPORT)
    wanted.update(str(p.relative_to(ROOT))
                  for p in (ROOT / MODULE.VERSIONS_REL).glob('*.toml'))
    wanted.update(str(p.relative_to(ROOT))
                  for p in (ROOT / 'qa').glob('*/acceptance.json'))
    for rel in sorted(wanted):
        target = destination / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / rel, target)
    return destination


def snapshot(root: Path) -> dict[str, tuple[bytes, int]]:
    """Every file in the copy, by bytes and mode.

    __pycache__ is excluded and only that: it is an untracked side effect of
    running Python over the copy (the gate is imported for its site list, and
    the drift-gate subprocess imports its own modules), not a file any caller
    asked this tool to change.  Everything else is compared byte for byte.
    """
    out = {}
    for path in sorted(root.rglob('*')):
        if path.is_file() and '__pycache__' not in path.parts:
            out[str(path.relative_to(root))] = (path.read_bytes(),
                                                path.stat().st_mode & 0o7777)
    return out


def gate_values(root: Path, sites) -> dict[str, str]:
    """Read every site the way tools/drift_gate.py reads it."""
    out = {}
    for rel, pattern, label in sites:
        text = (root / rel).read_text(encoding='utf-8', errors='replace')
        match = re.search(pattern, text)
        out[label] = match.group(1) if match else '<no match>'
    return out


class StampTestCase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.tree = copy_tree(Path(self.temporary.name) / 'tree')
        self.sites = MODULE.gate_version_sites(self.tree) + list(MODULE.EXTRA_SITES)
        self.values = gate_values(self.tree, self.sites)
        # The version the tree carries, read through the gate's first site --
        # deliberately NOT from the release data. While a release is being cut
        # this tree legitimately holds two non-historical release data files
        # (it did while these tests were written), and a test that depended on
        # that would fail for a reason that has nothing to do with stamping.
        self.old = self.values[self.sites[0][2]]

    def cut_release_data_and_manifest(self, version: str) -> None:
        """Do, in the COPY, the two things the stamper refuses to do itself.

        A fixture, not a release.  The acceptance manifest it writes keeps the
        previous release's MEASURED fields (iso_sha256, iso_size_bytes,
        source_commit) under a new version number -- which is precisely why
        stamp_version.py refuses to author one.  It exists here only so the
        drift gate has something to compare against.
        """
        directory = self.tree / MODULE.VERSIONS_REL
        source = None
        for path in sorted(directory.glob('*.toml')):
            text = path.read_text(encoding='utf-8')
            with path.open('rb') as handle:
                data = tomllib.load(handle)
            if data.get('release', {}).get('version') == self.old:
                source = data['release']
            path.write_text(
                re.sub(r'(?m)^historical = false$', 'historical = true', text),
                encoding='utf-8')
        if source is None:
            with sorted(directory.glob('*.toml'))[0].open('rb') as handle:
                source = tomllib.load(handle)['release']

        release = {key: source[key] for key in
                   ('edition', 'subtitle', 'codename', 'display_codename',
                    'signing_fingerprint')}
        release['version'] = version
        # Written out rather than copied: the [release] table is the whole of
        # what drift_gate.load_truth() reads, and a fixture that carried the
        # rest of a real release file would drift with it.
        lines = ['# fixture: tools/tests/test_stamp_version.py', '[release]']
        lines += [f'{key} = "{value}"' for key, value in sorted(release.items())]
        lines.append('historical = false')
        (directory / f'{version}.toml').write_text('\n'.join(lines) + '\n',
                                                   encoding='utf-8')

        manifest = json.loads(
            (self.tree / f'qa/{self.old}/acceptance.json').read_text(encoding='utf-8'))
        manifest['release'] = {
            'version': version,
            'edition': release['edition'],
            'codename': release['display_codename'],
            'subtitle': release['subtitle'],
        }
        manifest['artifact']['iso_path'] = f'shadowfetch-{version}-amd64.iso'
        manifest['artifact']['signature_path'] = f'shadowfetch-{version}-amd64.iso.asc'
        manifest['artifact']['signing_fingerprint'] = release['signing_fingerprint']
        target = self.tree / f'qa/{version}/acceptance.json'
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')

    def require_one_version_in_the_tree(self):
        """Some assertions are about "the old version" and need there to be one.

        Other agents edit this tree; if its sites disagree with each other that
        is their finding to fix, not a stamper defect to report here.
        """
        if len(set(self.values.values())) != 1:
            self.skipTest(f'the tree\'s version sites disagree: {self.values}')

    def only_live_release_data(self, version: str) -> Path:
        """Leave exactly one non-historical release data file, naming version."""
        directory = self.tree / MODULE.VERSIONS_REL
        kept = None
        for path in sorted(directory.glob('*.toml')):
            text = path.read_text(encoding='utf-8')
            with path.open('rb') as handle:
                names = tomllib.load(handle).get('release', {}).get('version')
            if names == version and kept is None:
                kept = path
                continue
            path.write_text(
                re.sub(r'(?m)^historical = false$', 'historical = true', text),
                encoding='utf-8')
        return kept

    def run_main(self, argv):
        """main() with its report captured: (exit code, stdout, stderr)."""
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = MODULE.main(argv)
        return code, out.getvalue(), err.getvalue()

    def run_drift_gate(self, checks=('version', 'release-data')):
        argv = [sys.executable, str(self.tree / 'tools/drift_gate.py')]
        for check in checks:
            argv += ['--only', check]
        return subprocess.run(argv, capture_output=True, text=True, cwd=str(self.tree))


# --------------------------------------------------------------------------- #
# coverage: the stamper's sites ARE the gate's sites
# --------------------------------------------------------------------------- #

class CoverageTests(StampTestCase):
    def test_site_list_is_the_gates_list(self):
        """Not a copy of it. A copy is what let three sites go unstamped."""
        gate = MODULE.gate_version_sites(ROOT)
        self.assertGreaterEqual(len(gate), 12)
        planned = MODULE.plan(NEW, self.tree)[0]
        for site in MODULE.gate_version_sites(self.tree):
            self.assertIn(site, planned)
        self.assertIn(MODULE.EXTRA_SITES[0], planned)

    def test_successful_stamp_moves_every_gate_site(self):
        result = MODULE.stamp(NEW, self.tree)
        for label, value in gate_values(self.tree, self.sites).items():
            with self.subTest(site=label):
                self.assertEqual(value, NEW)
        self.assertTrue(result.written)

    def test_previously_left_behind_sites_are_stamped(self):
        """The three the old stamper missed, named so a regression is legible."""
        MODULE.stamp(NEW, self.tree)
        values = gate_values(self.tree, self.sites)
        for label in ('grok-bot --version string',
                      'drkonqi-pickup CMake project version',
                      'README fact table',
                      'Makefile VERSION ?='):
            with self.subTest(site=label):
                self.assertEqual(values[label], NEW)

    def test_gate_reports_no_version_drift_after_a_stamp(self):
        self.cut_release_data_and_manifest(NEW)
        result = MODULE.stamp(NEW, self.tree)
        self.assertEqual(result.outstanding, [])
        finished = self.run_drift_gate()
        self.assertIn('0 DRIFT', finished.stdout, finished.stdout + finished.stderr)
        self.assertEqual(finished.returncode, 0, finished.stdout + finished.stderr)

    def test_gate_reports_drift_before_the_stamp(self):
        """The same gate, same tree, un-stamped: the check can actually fail."""
        self.cut_release_data_and_manifest(NEW)
        started = self.run_drift_gate()
        self.assertNotEqual(started.returncode, 0)
        self.assertIn('DRIFT', started.stdout)


# --------------------------------------------------------------------------- #
# atomicity: all of the files, or none of them
# --------------------------------------------------------------------------- #

class AtomicityTests(StampTestCase):
    def write_count(self) -> int:
        with tempfile.TemporaryDirectory() as other:
            tree = copy_tree(Path(other) / 'tree')
            return len(MODULE.stamp(NEW, tree).written)

    def test_failure_at_each_write_leaves_the_tree_byte_identical(self):
        total = self.write_count()
        self.assertGreaterEqual(total, 8)
        for failing in range(1, total + 1):
            with self.subTest(replace_call=failing):
                tree = copy_tree(Path(self.temporary.name) / f'inject{failing}')
                before = snapshot(tree)
                real = MODULE._replace
                seen = {'n': 0}

                def injected(path, data, _real=real, _seen=seen, _at=failing):
                    _seen['n'] += 1
                    if _seen['n'] == _at:
                        raise OSError(f'injected failure at replace #{_at}')
                    return _real(path, data)

                MODULE._replace = injected
                try:
                    with self.assertRaises(MODULE.StampError) as caught:
                        MODULE.stamp(NEW, tree)
                finally:
                    MODULE._replace = real
                self.assertIn('as it was found', str(caught.exception))
                self.assertEqual(snapshot(tree), before)
                self.assertEqual([], list(tree.rglob('.stamp-*')))

    def test_a_failure_after_the_rename_still_rolls_that_file_back(self):
        """The write is os.replace, then an fsync of the DIRECTORY.

        Every injected failure above lands before the rename, so the rolled-
        back set was always exactly the files already appended to `written`.
        A failure BETWEEN the rename and the return is different: that file
        holds the new bytes, is not yet in `written`, and used to be left
        stamped while the error said "the tree is as it was found". A caller
        reading that message would have built from a mixed tree.
        """
        tree = copy_tree(Path(self.temporary.name) / 'postrename')
        before = snapshot(tree)
        real_fsync = os.fsync
        seen = {'dirs': 0}

        def injected(fd, _real=real_fsync, _seen=seen):
            # Only the directory fsync, which is the step after os.replace.
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                _seen['dirs'] += 1
                if _seen['dirs'] == 1:
                    raise OSError('injected failure fsyncing the directory')
            return _real(fd)

        os.fsync = injected
        try:
            with self.assertRaises(MODULE.StampError) as caught:
                MODULE.stamp(NEW, tree)
        finally:
            os.fsync = real_fsync

        # Two: the injected failure on the first, then the rollback's own
        # rewrite of the restored bytes. The second IS the restore happening.
        self.assertEqual(2, seen['dirs'],
                         'the rollback did not rewrite the renamed file')
        message = str(caught.exception)
        self.assertIn('as it was found', message)
        self.assertNotIn('THE RESTORE ALSO FAILED', message)
        self.assertEqual(snapshot(tree), before,
                         'the file whose rename had already succeeded was '
                         'left stamped while the error claimed a clean tree')
        self.assertEqual([], list(tree.rglob('.stamp-*')))

    def test_a_moved_anchor_writes_nothing(self):
        readme = self.tree / 'README.md'
        readme.write_text(re.sub(r'(?m)^\| Version / codename \|.*$', '',
                                 readme.read_text(encoding='utf-8')), encoding='utf-8')
        before = snapshot(self.tree)
        with self.assertRaises(MODULE.StampError) as caught:
            MODULE.stamp(NEW, self.tree)
        self.assertIn('matched 0 time(s)', str(caught.exception))
        self.assertIn('Nothing has been written', str(caught.exception))
        self.assertEqual(snapshot(self.tree), before)

    def test_a_duplicated_anchor_writes_nothing(self):
        """Two matches is ambiguity, not a licence to rewrite the first."""
        makefile = self.tree / 'Makefile'
        makefile.write_text(makefile.read_text(encoding='utf-8') +
                            f'\nVERSION ?= {self.old}\n', encoding='utf-8')
        before = snapshot(self.tree)
        with self.assertRaises(MODULE.StampError) as caught:
            MODULE.stamp(NEW, self.tree)
        self.assertIn('matched 2 time(s)', str(caught.exception))
        self.assertEqual(snapshot(self.tree), before)

    def test_a_missing_site_file_writes_nothing(self):
        (self.tree / 'README.md').unlink()
        remaining = snapshot(self.tree)
        with self.assertRaises(MODULE.StampError) as caught:
            MODULE.stamp(NEW, self.tree)
        self.assertIn('unreadable', str(caught.exception))
        self.assertEqual(snapshot(self.tree), remaining)

    def test_a_non_utf8_site_file_is_refused_not_mangled(self):
        readme = self.tree / 'README.md'
        readme.write_bytes(readme.read_bytes() + b'\xff\xfe')
        before = snapshot(self.tree)
        with self.assertRaises(MODULE.StampError) as caught:
            MODULE.stamp(NEW, self.tree)
        self.assertIn('not valid UTF-8', str(caught.exception))
        self.assertEqual(snapshot(self.tree), before)

    @unittest.skipIf(os.geteuid() == 0, 'root ignores directory permissions')
    def test_a_real_unwritable_directory_rolls_the_tree_back(self):
        """Not an injected exception: a directory the process cannot write."""
        blocked = (self.tree / MODULE.EXTRA_SITES[0][0]).parent
        before = snapshot(self.tree)
        mode = blocked.stat().st_mode
        os.chmod(blocked, 0o555)
        self.addCleanup(os.chmod, blocked, mode)
        with self.assertRaises(MODULE.StampError) as caught:
            MODULE.stamp(NEW, self.tree)
        os.chmod(blocked, mode)
        self.assertIn('write failed', str(caught.exception))
        self.assertEqual(snapshot(self.tree), before)

    def test_a_failed_restore_is_reported_not_swallowed(self):
        """The one outcome this tool cannot undo must name the files it left."""
        real = MODULE._replace
        seen = {'n': 0}

        def always_failing_after_first(path, data):
            seen['n'] += 1
            if seen['n'] == 1:
                return real(path, data)
            raise OSError('injected: every write after the first fails')

        MODULE._replace = always_failing_after_first
        try:
            with self.assertRaises(MODULE.StampError) as caught:
                MODULE.stamp(NEW, self.tree)
        finally:
            MODULE._replace = real
        message = str(caught.exception)
        self.assertIn('THE RESTORE ALSO FAILED', message)
        self.assertIn('tree is MIXED', message)

    def test_an_interrupt_rolls_back_and_stays_an_interrupt(self):
        """Ctrl-C must not come back as a StampError, and must still roll back."""
        before = snapshot(self.tree)
        real = MODULE._replace
        seen = {'n': 0}

        def interrupting(path, data):
            seen['n'] += 1
            if seen['n'] == 3:
                raise KeyboardInterrupt
            return real(path, data)

        MODULE._replace = interrupting
        noise = io.StringIO()
        try:
            with contextlib.redirect_stderr(noise):
                with self.assertRaises(KeyboardInterrupt):
                    MODULE.stamp(NEW, self.tree)
        finally:
            MODULE._replace = real
        self.assertIn('restored 2 file(s)', noise.getvalue())
        self.assertEqual(snapshot(self.tree), before)

    def test_nothing_is_written_when_every_site_already_agrees(self):
        self.require_one_version_in_the_tree()
        result = MODULE.stamp(self.old, self.tree)
        self.assertEqual(result.written, [])
        self.assertEqual(len(result.unchanged), len({rel for rel, _p, _l in self.sites}))


# --------------------------------------------------------------------------- #
# what must NOT change
# --------------------------------------------------------------------------- #

class PreservationTests(StampTestCase):
    def test_modes_survive_the_replace(self):
        """mkstemp makes 0600 files; these ship as executables in a .deb."""
        before = {rel: mode for rel, (_data, mode) in snapshot(self.tree).items()}
        MODULE.stamp(NEW, self.tree)
        after = {rel: mode for rel, (_data, mode) in snapshot(self.tree).items()}
        self.assertEqual(before, after)
        self.assertEqual(
            0o755,
            (self.tree / 'packages/shadowfetch-defaults/data/usr/bin/'
             'shadowfetch-element').stat().st_mode & 0o7777)

    def test_upstream_versions_are_not_rewritten(self):
        grok = (self.tree / 'packages/shadowfetch-defaults/data/usr/bin/'
                'shadowfetch-grok-bot')
        upstream = re.search(r'(?m)^VERSION = "([^"]+)"$',
                             grok.read_text(encoding='utf-8'))
        self.assertIsNotNone(upstream, 'grok-bot no longer pins an upstream version')
        MODULE.stamp(NEW, self.tree)
        text = grok.read_text(encoding='utf-8')
        self.assertIn(f'VERSION = "{upstream.group(1)}"', text)
        self.assertNotEqual(upstream.group(1), NEW)
        self.assertIn(f'shadowfetch-grok-bot {NEW};', text)

    def test_historical_mentions_of_the_old_version_survive(self):
        """sf_missions.py describes on-disk formats EARLIER releases wrote.
        Those sentences are about those releases and must keep saying them.

        Which releases is discovered, not written down. Counting mentions of
        the version the tree is ON and demanding more than one only held while
        this tree still carried prose about its own current version; the first
        bump that left the assignment as the sole mention broke it, and the
        property it meant to defend -- history survives a stamp -- was never
        the thing being measured."""
        self.require_one_version_in_the_tree()
        missions = (self.tree / 'packages/shadowfetch-missions/data/usr/lib/'
                    'shadowfetch/missions/sf_missions.py')
        text = missions.read_text(encoding='utf-8')
        history = {version: text.count(version)
                   for version in set(re.findall(r'\b\d+\.\d+\.\d+\b', text))
                   if version not in (self.old, NEW)}
        self.assertTrue(history,
                        'sf_missions.py names no earlier release; this test '
                        'can no longer prove history survives a stamp')
        before = text.count(self.old)
        MODULE.stamp(NEW, self.tree)
        after = missions.read_text(encoding='utf-8')
        # Exactly the assignment moved.
        self.assertEqual(after.count(self.old), before - 1)
        self.assertIn(f'VERSION = "{NEW}"', after)
        for version, count in sorted(history.items()):
            self.assertEqual(count, after.count(version),
                             f'the stamper rewrote a mention of {version}')

    def test_only_the_captured_range_of_a_line_changes(self):
        cmake = self.tree / 'packages/shadowfetch-drkonqi-pickup/CMakeLists.txt'
        MODULE.stamp(NEW, self.tree)
        text = cmake.read_text(encoding='utf-8')
        self.assertIn('cmake_minimum_required(VERSION 3.18)', text)
        self.assertIn(f'project(shadowfetch-drkonqi-pickup VERSION {NEW} '
                      'LANGUAGES CXX)', text)


# --------------------------------------------------------------------------- #
# the sites this tool refuses to author
# --------------------------------------------------------------------------- #

class OutstandingTests(StampTestCase):
    def test_missing_acceptance_manifest_is_named_and_exits_nonzero(self):
        code, out, err = self.run_main([NEW, '--root', str(self.tree)])
        self.assertEqual(code, 1)
        self.assertIn(f'qa/{NEW}/acceptance.json', out)
        self.assertIn('NOT STAMPED', out)
        self.assertNotIn('STAMP COMPLETE', out)
        self.assertIn('STAMP INCOMPLETE', err)
        sites = dict(MODULE.outstanding(NEW, self.tree))
        self.assertIn('does not exist', sites[f'qa/{NEW}/acceptance.json'])
        self.assertIn('MEASURED', sites[f'qa/{NEW}/acceptance.json'])

    def test_stale_release_data_is_named_and_exits_nonzero(self):
        kept = self.only_live_release_data(self.old)
        self.assertIsNotNone(kept, 'no release data names the stamped version')
        sites = dict(MODULE.outstanding(NEW, self.tree))
        stale = str(kept.relative_to(self.tree))
        self.assertIn(stale, sites)
        self.assertIn(f'names {self.old}, not {NEW}', sites[stale])
        self.assertEqual(1, self.run_main([NEW, '--root', str(self.tree)])[0])

    def test_two_live_release_data_files_are_named_not_guessed_between(self):
        """drift_gate.load_truth() refuses to pick one; so does this."""
        live = 0
        for path in sorted((self.tree / MODULE.VERSIONS_REL).glob('*.toml')):
            with path.open('rb') as handle:
                live += not tomllib.load(handle).get(
                    'release', {}).get('historical', False)
        if live < 2:
            extra = (self.tree / MODULE.VERSIONS_REL / '0.0.1.toml')
            extra.write_text('[release]\nversion = "0.0.1"\nhistorical = false\n',
                             encoding='utf-8')
            live += 1
        reasons = ' '.join(why for _site, why in MODULE.outstanding(NEW, self.tree))
        self.assertIn(f'{live} non-historical release data file(s)', reasons)

    def test_a_manifest_naming_another_release_is_not_accepted(self):
        self.cut_release_data_and_manifest(NEW)
        manifest = self.tree / f'qa/{NEW}/acceptance.json'
        data = json.loads(manifest.read_text(encoding='utf-8'))
        data['artifact']['iso_path'] = f'shadowfetch-{self.old}-amd64.iso'
        manifest.write_text(json.dumps(data, indent=2) + '\n', encoding='utf-8')
        reasons = ' '.join(why for _site, why in MODULE.outstanding(NEW, self.tree))
        self.assertIn('artifact.iso_path', reasons)

    def test_a_complete_tree_exits_zero(self):
        self.cut_release_data_and_manifest(NEW)
        code, out, _err = self.run_main([NEW, '--root', str(self.tree)])
        self.assertEqual(code, 0)
        self.assertIn('STAMP COMPLETE', out)
        self.assertNotIn('NOT STAMPED', out)
        self.assertEqual(MODULE.outstanding(NEW, self.tree), [])

    def test_outstanding_ok_still_prints_the_outstanding_sites(self):
        code, out, _err = self.run_main(
            [NEW, '--root', str(self.tree), '--outstanding-ok'])
        self.assertEqual(code, 0)
        self.assertIn('NOT STAMPED', out)
        self.assertIn(f'qa/{NEW}/acceptance.json', out)
        self.assertTrue(MODULE.outstanding(NEW, self.tree))

    def test_rejects_non_version_input(self):
        before = snapshot(self.tree)
        for bad in ('4.0.0; command', '4.0', 'v4.0.0', '4.0.0\n4.0.0', ''):
            with self.subTest(argument=bad):
                with self.assertRaises(MODULE.StampError):
                    MODULE.stamp(bad, self.tree)
        self.assertEqual(snapshot(self.tree), before)

    def test_refusal_exits_two_not_one(self):
        """A refusal and an incomplete stamp are different states."""
        code, out, err = self.run_main(['4.0', '--root', str(self.tree)])
        self.assertEqual(code, 2)
        self.assertIn('REFUSED', err)
        self.assertEqual(out, '')


if __name__ == '__main__':
    unittest.main(verbosity=2)
