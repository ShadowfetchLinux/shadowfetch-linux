#!/usr/bin/env python3
"""Stage H: adversarial tests for checkpoint durability and transactional undo.

These tests are written against the FAILURES, not the happy path. The one that
matters most is test_partial_recovery_is_never_reported_as_success: `undo` may
return only when the workspace has been compared to the checkpoint, path by
path and byte by byte, AFTER the exchange. Everything else here exists to make
sure the paths that lead to a partial recovery cannot quietly reach that
return.

Power loss is simulated honestly: the child process is forked and killed with
os._exit(9) at a named point inside the real undo, so no cleanup, no `finally`
and no flush runs -- which is what a power cut looks like from the filesystem's
point of view. What the parent then asserts is the only claim worth making:
whatever state the tree is in, it is ONE coherent state, `recover` says which,
and what `recover` says matches what is on disk.

Two things are simulated rather than caused, and are named as such:
  * "full disk" for the PRECHECK is a stubbed free-space reading. It proves the
    policy refuses and writes nothing; it does not prove kernel ENOSPC handling.
  * ENOSPC DURING a restore is an OSError injected where the engine opens the
    archive. It proves the workspace survives a failure there and that the
    failure arrives as a sentence naming which side of the exchange it was on.
Neither is claimed to be a real full filesystem; making one needs root.
"""
from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

FIRELINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(FIRELINE / "data/usr/lib/shadowfetch/mcp"))
import sf_mcp  # noqa: E402

CLI = [sys.executable, str(FIRELINE / "data/usr/bin/shadowfetch-checkpoint")]


def tree_state(root: Path) -> dict:
    """Everything that matters about a tree, as plain data, for comparison."""
    out = {}
    for path in sorted(root.rglob("*")):
        rel = str(path.relative_to(root))
        if path.is_symlink():
            out[rel] = ("link", os.readlink(path))
        elif path.is_dir():
            out[rel] = ("dir", stat.S_IMODE(path.lstat().st_mode))
        else:
            out[rel] = ("file", stat.S_IMODE(path.lstat().st_mode),
                        path.read_bytes())
    return out


class CheckpointCase(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="sf-stageh-"))
        self.ws = self.root / "proj"
        (self.ws / "src").mkdir(parents=True)
        (self.ws / "src/app.py").write_text("original\n")
        (self.ws / "README.md").write_text("keep\n")
        self._env = {}
        self.setenv("SHADOWFETCH_AGENT_WORKSPACES", str(self.root))
        self.store = self.root / ".sf-checkpoints/proj"

    def tearDown(self):
        for name, old in self._env.items():
            if old is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = old
        # chmod back: a 0o500 directory from a test would defeat the cleanup.
        for path in sorted(self.root.rglob("*"), reverse=True):
            if path.is_dir() and not path.is_symlink():
                try:
                    path.chmod(0o700)
                except OSError:
                    pass
        shutil.rmtree(self.root, ignore_errors=True)

    def setenv(self, name, value):
        self._env.setdefault(name, os.environ.get(name))
        if value is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = value

    # -- helpers ------------------------------------------------------------ #
    def snapshot(self, label="manual"):
        return sf_mcp.checkpoint_call("snapshot", workspace="proj", label=label)

    def undo(self, cid):
        return sf_mcp.checkpoint_call("undo", workspace="proj", checkpoint=cid)

    def agent_edits(self):
        (self.ws / "src/app.py").write_text("REWRITTEN-BY-AGENT")
        (self.ws / "README.md").unlink()
        (self.ws / "src/added.py").write_text("junk")

    def debris(self):
        """Staging debris anywhere the engine could have left some."""
        found = [p.name for p in self.root.iterdir()
                 if p.name.startswith(".sf-restore-")]
        found += [p.name for p in self.store.iterdir()
                  if p.name.startswith(".tmp-") or p.name.endswith(".part")]
        return found

    def journal(self):
        return sf_mcp._ckpt_journal_read(self.store)


# --------------------------------------------------------------------------- #
# THE RULE THAT MATTERS MOST
# --------------------------------------------------------------------------- #
class PartialRecovery(CheckpointCase):
    def test_partial_recovery_is_never_reported_as_success(self):
        """A restore that is missing a file must not return a result at all.

        The check is deliberately blunt: undo() is made to produce an
        incomplete tree, and the test asserts it RAISES. A returned dict is a
        success report, and there is no such thing as a partly successful undo.
        """
        cid = self.snapshot()["id"]
        self.agent_edits()
        before = tree_state(self.ws)
        real = sf_mcp._ckpt_materialize

        def lossy(store, meta, stage):
            real(store, meta, stage)
            (stage / "README.md").unlink()      # one file short of the truth

        with mock.patch.object(sf_mcp, "_ckpt_materialize", lossy):
            with self.assertRaises(sf_mcp._ToolError) as caught:
                self.undo(cid)
        self.assertIn("workspace unchanged", str(caught.exception))
        self.assertIn("README.md", str(caught.exception))
        self.assertEqual(tree_state(self.ws), before,
                         "a refused undo must not have touched the workspace")
        self.assertEqual(self.debris(), [], "staging debris was left behind")
        self.assertIsNone(self.journal())

    def test_altered_content_is_caught_before_the_exchange(self):
        """Right paths, wrong bytes. Only a digest catches this."""
        cid = self.snapshot()["id"]
        self.agent_edits()
        before = tree_state(self.ws)
        real = sf_mcp._ckpt_materialize

        def tampered(store, meta, stage):
            real(store, meta, stage)
            (stage / "src/app.py").write_text("original\n" + " ")  # same name

        with mock.patch.object(sf_mcp, "_ckpt_materialize", tampered):
            with self.assertRaises(sf_mcp._ToolError) as caught:
                self.undo(cid)
        self.assertIn("differs src/app.py", str(caught.exception))
        self.assertEqual(tree_state(self.ws), before)

    def test_post_exchange_mismatch_demands_recovery_and_does_not_return(self):
        """If the workspace does not match after the swap, say so loudly.

        This is the one failure the caller cannot treat as "nothing happened",
        so it gets its own wording, its own exit code, and a journal that stops
        every other operation until somebody deals with it.
        """
        cid = self.snapshot()["id"]
        self.agent_edits()
        real = sf_mcp._ckpt_swap

        def swap_then_damage(ws, stage, store, journal):
            displaced = real(ws, stage, store, journal)
            (ws / "src/app.py").write_text("half a restore")
            return displaced

        with mock.patch.object(sf_mcp, "_ckpt_swap", swap_then_damage):
            with self.assertRaises(sf_mcp._ToolError) as caught:
                self.undo(cid)
        message = str(caught.exception)
        self.assertTrue(message.startswith("RECOVERY REQUIRED"), message)
        self.assertIn("src/app.py", message)
        self.assertIsNotNone(self.journal(), "the journal must survive to block others")
        # and nothing else may proceed until it is dealt with
        for action, kwargs in (("snapshot", {}), ("diff", {"checkpoint": cid}),
                               ("undo", {"checkpoint": cid})):
            with self.assertRaises(sf_mcp._ToolError) as blocked:
                sf_mcp.checkpoint_call(action, workspace="proj", **kwargs)
            self.assertIn("recover", str(blocked.exception))


# --------------------------------------------------------------------------- #
# Power loss: the child is killed inside the real undo, at a named point
# --------------------------------------------------------------------------- #
class PowerLoss(CheckpointCase):
    """os._exit(9) in a forked child: no finally, no cleanup, no flush."""

    # Each name is a real window in undo(), not a convenient one:
    #   before-journal          the staged tree exists, nothing else does
    #   before-exchange         the journal is on disk, the swap has not run
    #   exchanged-unjournalled  the swap happened; the journal does not say so
    #   after-exchange          the swap happened and the journal says so
    #   before-journal-clear    verified and cleaned up, journal still present
    #   between-renames         the two-rename fallback, workspace name absent
    KILL_POINTS = ("before-journal", "before-exchange", "exchanged-unjournalled",
                   "after-exchange", "before-journal-clear", "between-renames")

    def _kill_at(self, point, cid):
        pid = os.fork()
        if pid == 0:                                     # child
            try:
                if point == "before-journal":
                    mock.patch.object(sf_mcp, "_ckpt_journal_write",
                                      lambda *a: os._exit(9)).start()
                elif point == "before-exchange":
                    mock.patch.object(sf_mcp, "_ckpt_exchange",
                                      lambda *a: os._exit(9)).start()
                elif point == "exchanged-unjournalled":
                    # The window between the RENAME_EXCHANGE syscall and the
                    # journal update that records it: the second journal write
                    # never lands, so the journal still says "exchange".
                    real_write = sf_mcp._ckpt_journal_write
                    seen = []

                    def once(store, record):
                        seen.append(1)
                        if len(seen) >= 2:
                            os._exit(9)
                        return real_write(store, record)
                    mock.patch.object(sf_mcp, "_ckpt_journal_write", once).start()
                elif point == "after-exchange":
                    real = sf_mcp._ckpt_swap

                    def swap(ws, stage, store, journal):
                        real(ws, stage, store, journal)
                        os._exit(9)
                    mock.patch.object(sf_mcp, "_ckpt_swap", swap).start()
                elif point == "before-journal-clear":
                    mock.patch.object(sf_mcp, "_ckpt_journal_clear",
                                      lambda *a: os._exit(9)).start()
                elif point == "between-renames":
                    mock.patch.object(sf_mcp, "_ckpt_exchange",
                                      lambda *a: False).start()
                    real_rename = os.rename

                    def rename(src, dst):
                        real_rename(src, dst)
                        if ".displaced." in str(dst):
                            # Kill AFTER the workspace has been renamed away and
                            # BEFORE the restored tree takes its name: the one
                            # moment the workspace does not exist at all.
                            os._exit(9)
                    mock.patch.object(os, "rename", rename).start()
                sf_mcp.checkpoint_call("undo", workspace="proj", checkpoint=cid)
            except BaseException:
                os._exit(1)
            os._exit(0)
        return os.waitpid(pid, 0)[1]

    def test_a_kill_anywhere_in_undo_leaves_one_coherent_state(self):
        for point in self.KILL_POINTS:
            with self.subTest(point=point):
                self.setUp()
                try:
                    cid = self.snapshot()["id"]
                    checkpoint_state = tree_state(self.ws)
                    self.agent_edits()
                    agent_state = tree_state(self.ws)
                    self.assertNotEqual(checkpoint_state, agent_state)

                    self._kill_at(point, cid)

                    # Whatever survived, it is one of the two coherent states
                    # (or, in the two-rename window, no workspace at all).
                    if self.ws.exists():
                        now = tree_state(self.ws)
                        self.assertIn(now, (checkpoint_state, agent_state),
                                      f"{point}: workspace is a mixture")

                    result = sf_mcp.checkpoint_call("recover", workspace="proj")
                    final = tree_state(self.ws)
                    # What recover SAYS must match what is on disk. Each of the
                    # three answers is a different claim about the workspace,
                    # and each is checked against the tree, not the journal.
                    if result["result"] == "completed":
                        self.assertEqual(final, checkpoint_state,
                                         f"{point}: claimed completed, is not")
                    elif result["result"] == "rolled-back":
                        self.assertEqual(final, agent_state,
                                         f"{point}: claimed rolled back, is not")
                    else:
                        # The undo died before it had begun to change anything,
                        # so there is nothing to repair -- and saying so is only
                        # true if the workspace is still the agent's tree.
                        self.assertEqual(result["result"], "nothing-to-recover",
                                         f"{point}: {result}")
                        self.assertEqual(final, agent_state,
                                         f"{point}: claimed untouched, is not")
                    self.assertIsNone(self.journal())
                    self.assertEqual(self.debris(), [],
                                     f"{point}: recover left debris")
                    # and the workspace is usable again
                    self.snapshot(label="after-recovery")
                finally:
                    self.tearDown()

    def test_recover_reports_nothing_to_recover_when_settled(self):
        cid = self.snapshot()["id"]
        self.agent_edits()
        self.undo(cid)
        result = sf_mcp.checkpoint_call("recover", workspace="proj")
        self.assertEqual(result["result"], "nothing-to-recover")


# --------------------------------------------------------------------------- #
# Space
# --------------------------------------------------------------------------- #
class Space(CheckpointCase):
    def test_precheck_refuses_a_snapshot_that_would_not_fit(self):
        """Stubbed free-space reading: proves the POLICY, not kernel ENOSPC."""
        with mock.patch.object(sf_mcp, "_ckpt_free", lambda path: 1024):
            with self.assertRaises(sf_mcp._ToolError) as caught:
                self.snapshot()
        self.assertIn("not enough free space", str(caught.exception))
        self.assertEqual(list(self.store.glob("*.json")), [],
                         "a refused snapshot must leave no checkpoint")
        self.assertEqual(self.debris(), [])

    def test_precheck_refuses_an_undo_that_would_not_fit(self):
        cid = self.snapshot()["id"]
        self.agent_edits()
        before = tree_state(self.ws)
        with mock.patch.object(sf_mcp, "_ckpt_free", lambda path: 1024):
            with self.assertRaises(sf_mcp._ToolError) as caught:
                self.undo(cid)
        self.assertIn("workspace unchanged", str(caught.exception))
        self.assertEqual(tree_state(self.ws), before)

    def test_a_write_failure_during_restore_leaves_the_workspace_intact(self):
        """Injected ENOSPC at the materialize step -- the old code would have
        already deleted the workspace by the time this happened."""
        cid = self.snapshot()["id"]
        self.agent_edits()
        before = tree_state(self.ws)

        real = tarfile.open

        def out_of_space(*args, **kwargs):
            if "w" in str(kwargs.get("mode", args[1] if len(args) > 1 else "")):
                return real(*args, **kwargs)
            raise OSError(28, "No space left on device")

        with mock.patch.object(tarfile, "open", out_of_space):
            with self.assertRaises(sf_mcp._ToolError) as caught:
                self.undo(cid)
        # A write failure below the engine still has to arrive as a sentence
        # that says which side of the exchange it happened on.
        self.assertTrue(str(caught.exception).startswith("workspace unchanged"),
                        str(caught.exception))
        self.assertIn("No space left on device", str(caught.exception))
        self.assertEqual(tree_state(self.ws), before)
        self.assertEqual(self.debris(), [])
        self.assertIsNone(self.journal())

    def test_a_failed_archive_never_becomes_a_checkpoint(self):
        real_open = tarfile.open

        def explode(*args, **kwargs):
            handle = real_open(*args, **kwargs)
            handle.close()
            raise OSError(28, "No space left on device")

        with mock.patch.object(tarfile, "open", explode):
            with self.assertRaises(OSError):
                self.snapshot()
        self.assertEqual(list(self.store.glob("*.json")), [])
        self.assertEqual([p.name for p in self.store.glob("*.part")], [])


# --------------------------------------------------------------------------- #
# Retention, quota, deduplication
# --------------------------------------------------------------------------- #
class Retention(CheckpointCase):
    def test_the_store_is_bounded_by_count(self):
        self.setenv("SHADOWFETCH_CKPT_KEEP", "3")
        kept = []
        for index in range(12):
            (self.ws / "src/app.py").write_text(f"revision {index}\n")
            kept.append(self.snapshot(label=f"r{index}")["id"])
        rows = sf_mcp.checkpoint_call("list", workspace="proj")["checkpoints"]
        self.assertEqual(len(rows), 3)
        self.assertEqual([row["id"] for row in rows], sorted(kept[-3:]))
        # pruning removes the DATA too, not only the listing
        self.assertEqual(len(list(self.store.glob("*.tar.gz"))), 3)
        self.assertEqual(len(list((self.store / ".sfh").glob("*.manifest.json"))), 3)
        # and what survived still restores
        self.agent_edits()
        self.undo(kept[-1])
        self.assertEqual((self.ws / "src/app.py").read_text(), "revision 11\n")

    def test_the_store_is_bounded_by_bytes_but_not_below_the_floor(self):
        self.setenv("SHADOWFETCH_CKPT_KEEP", "50")
        self.setenv("SHADOWFETCH_CKPT_MAX_BYTES", str(1 << 20))
        for index in range(8):
            (self.ws / "big.bin").write_bytes(os.urandom(400 * 1024))
            self.snapshot(label=f"b{index}")
        rows = sf_mcp.checkpoint_call("list", workspace="proj")["checkpoints"]
        self.assertGreaterEqual(len(rows), sf_mcp.CKPT_KEEP_FLOOR)
        self.assertLess(len(rows), 8, "the byte budget was not enforced")

    def test_an_unchanged_tree_is_deduplicated_not_copied(self):
        first = self.snapshot(label="one")
        second = self.snapshot(label="two")
        one = (self.store / first["archive"]).stat()
        two = (self.store / second["archive"]).stat()
        self.assertEqual(one.st_ino, two.st_ino,
                         "an identical tree was archived twice")
        self.assertGreaterEqual(one.st_nlink, 2)
        # and dropping one name leaves the other usable
        sf_mcp._ckpt_drop(self.store, first["id"],
                          json.loads((self.store / f"{first['id']}.json").read_text()))
        self.agent_edits()
        self.undo(second["id"])
        self.assertEqual((self.ws / "src/app.py").read_text(), "original\n")

    def test_a_changed_tree_is_not_deduplicated(self):
        first = self.snapshot()
        (self.ws / "src/app.py").write_text("different\n")
        second = self.snapshot()
        self.assertNotEqual((self.store / first["archive"]).stat().st_ino,
                            (self.store / second["archive"]).stat().st_ino)

    def test_prune_action_reports_what_it_dropped(self):
        for index in range(6):
            (self.ws / "src/app.py").write_text(f"r{index}\n")
            self.snapshot()
        self.setenv("SHADOWFETCH_CKPT_KEEP", "2")
        result = sf_mcp.checkpoint_call("prune", workspace="proj")
        self.assertEqual(len(result["dropped"]), 4)
        self.assertEqual(result["kept"], 2)
        self.assertEqual(len(sf_mcp.checkpoint_call(
            "list", workspace="proj")["checkpoints"]), 2)


# --------------------------------------------------------------------------- #
# Awkward trees: symlinks, modes, size, refusals
# --------------------------------------------------------------------------- #
class AwkwardTrees(CheckpointCase):
    def test_symlinks_survive_a_round_trip_and_are_not_followed(self):
        (self.ws / "link-to-file").symlink_to("src/app.py")
        (self.ws / "link-to-dir").symlink_to("src")
        (self.ws / "dangling").symlink_to("nowhere-at-all")
        outside = self.root / "outside.txt"
        outside.write_text("must not be touched\n")
        (self.ws / "escape").symlink_to(str(outside))
        cid = self.snapshot()["id"]
        before = tree_state(self.ws)

        (self.ws / "link-to-file").unlink()
        (self.ws / "link-to-file").symlink_to("README.md")
        (self.ws / "dangling").unlink()
        self.undo(cid)

        self.assertEqual(tree_state(self.ws), before)
        self.assertEqual(os.readlink(self.ws / "link-to-file"), "src/app.py")
        self.assertEqual(os.readlink(self.ws / "dangling"), "nowhere-at-all")
        self.assertEqual(outside.read_text(), "must not be touched\n",
                         "restore wrote through a symlink out of the workspace")

    def test_read_only_directories_and_files_are_restored(self):
        """A 0o500 directory used to make the restore fail with EACCES -- after
        the live workspace had already been deleted."""
        locked = self.ws / "locked"
        locked.mkdir()
        (locked / "inner.txt").write_text("inner\n")
        (locked / "inner.txt").chmod(0o400)
        locked.chmod(0o500)
        cid = self.snapshot()["id"]
        before = tree_state(self.ws)

        locked.chmod(0o700)
        (locked / "inner.txt").chmod(0o600)
        (locked / "inner.txt").write_text("agent wrote here\n")
        (locked / "extra.txt").write_text("extra\n")

        self.undo(cid)
        self.assertEqual(tree_state(self.ws), before)
        self.assertEqual(stat.S_IMODE(locked.lstat().st_mode), 0o500)
        self.assertEqual(stat.S_IMODE((locked / "inner.txt").lstat().st_mode), 0o400)
        self.assertFalse((locked / "extra.txt").exists())

    def test_a_large_workspace_round_trips(self):
        big = self.ws / "many"
        big.mkdir()
        for index in range(1500):
            (big / f"f{index:04d}.txt").write_text(f"content {index}\n" * 4)
        cid = self.snapshot()["id"]
        before = tree_state(self.ws)
        shutil.rmtree(big)
        (self.ws / "src/app.py").write_text("gone\n")
        self.undo(cid)
        self.assertEqual(tree_state(self.ws), before)
        self.assertEqual(len(list(big.iterdir())), 1500)

    def test_a_device_node_is_refused_at_snapshot_time(self):
        os.mkfifo(self.ws / "pipe")
        with self.assertRaises(sf_mcp._ToolError) as caught:
            self.snapshot()
        self.assertIn("cannot restore it", str(caught.exception))
        self.assertEqual(list(self.store.glob("*.json")), [])

    @unittest.skipIf(os.geteuid() == 0, "root can read a 0o000 directory")
    def test_an_unreadable_directory_is_refused_at_snapshot_time(self):
        blocked = self.ws / "blocked"
        blocked.mkdir()
        (blocked / "secret.txt").write_text("x")
        blocked.chmod(0o000)
        try:
            with self.assertRaises(sf_mcp._ToolError) as caught:
                self.snapshot()
            self.assertIn("permission denied", str(caught.exception))
            self.assertEqual(list(self.store.glob("*.json")), [])
        finally:
            blocked.chmod(0o700)


# --------------------------------------------------------------------------- #
# Broken and missing checkpoints
# --------------------------------------------------------------------------- #
class BrokenCheckpoints(CheckpointCase):
    def test_a_missing_checkpoint_changes_nothing(self):
        self.snapshot()
        self.agent_edits()
        before = tree_state(self.ws)
        with self.assertRaises(sf_mcp._ToolError) as caught:
            self.undo("20200101-000000-000000")
        self.assertIn("no such checkpoint", str(caught.exception))
        self.assertEqual(tree_state(self.ws), before)
        self.assertIsNone(self.journal())

    def test_a_corrupted_archive_is_refused_before_the_workspace_is_touched(self):
        cid = self.snapshot()["id"]
        self.agent_edits()
        before = tree_state(self.ws)
        archive = self.store / f"{cid}.tar.gz"
        raw = bytearray(archive.read_bytes())
        raw[len(raw) // 2] ^= 0xFF
        archive.write_bytes(bytes(raw))

        with self.assertRaises(sf_mcp._ToolError) as caught:
            self.undo(cid)
        self.assertTrue(str(caught.exception).startswith("workspace unchanged"),
                        str(caught.exception))
        self.assertEqual(tree_state(self.ws), before,
                         "a corrupt checkpoint must not cost the workspace")
        self.assertIsNone(self.journal())
        report = sf_mcp.checkpoint_call("verify", workspace="proj", checkpoint=cid)
        self.assertFalse(report["verified"])

    def test_a_truncated_archive_is_refused(self):
        cid = self.snapshot()["id"]
        self.agent_edits()
        before = tree_state(self.ws)
        archive = self.store / f"{cid}.tar.gz"
        archive.write_bytes(archive.read_bytes()[: 40])
        with self.assertRaises(sf_mcp._ToolError) as caught:
            self.undo(cid)
        self.assertTrue(str(caught.exception).startswith("workspace unchanged"),
                        str(caught.exception))
        self.assertEqual(tree_state(self.ws), before)

    def test_a_tampered_manifest_is_detected(self):
        cid = self.snapshot()["id"]
        manifest = self.store / ".sfh" / f"{cid}.manifest.json"
        entries = json.loads(manifest.read_text())
        entries[0]["sha256"] = "0" * 64
        manifest.write_text(json.dumps(entries))
        with self.assertRaises(sf_mcp._ToolError) as caught:
            self.undo(cid)
        self.assertIn("does not match the digest", str(caught.exception))

    def test_a_swapped_archive_is_detected_by_verify(self):
        """Same paths, different bytes: only the manifest digests catch it."""
        cid = self.snapshot()["id"]
        (self.ws / "src/app.py").write_text("SUBSTITUTED\n")
        forged = self.store / f"{cid}.tar.gz"
        forged.unlink()
        with tarfile.open(forged, "w:gz") as handle:
            handle.add(self.ws, arcname="proj")
        report = sf_mcp.checkpoint_call("verify", workspace="proj", checkpoint=cid)
        self.assertFalse(report["verified"])
        self.assertTrue(any("src/app.py" in problem for problem in report["problems"]))
        before = tree_state(self.ws)
        with self.assertRaises(sf_mcp._ToolError) as caught:
            self.undo(cid)
        self.assertIn("workspace unchanged", str(caught.exception))
        self.assertEqual(tree_state(self.ws), before)

    def test_verify_writes_nothing(self):
        cid = self.snapshot()["id"]
        before = sorted(p.name for p in self.store.rglob("*"))
        report = sf_mcp.checkpoint_call("verify", workspace="proj", checkpoint=cid)
        self.assertTrue(report["verified"])
        self.assertEqual(sorted(p.name for p in self.store.rglob("*")), before)


# --------------------------------------------------------------------------- #
# Repetition, concurrency, cleanup, and the PATH invariant
# --------------------------------------------------------------------------- #
class Operability(CheckpointCase):
    def test_undo_repeats_and_can_be_undone(self):
        cid = self.snapshot()["id"]
        self.checkpoint_state = tree_state(self.ws)
        self.agent_edits()
        agent_state = tree_state(self.ws)

        first = self.undo(cid)
        self.assertEqual(tree_state(self.ws), self.checkpoint_state)
        second = self.undo(cid)
        self.assertEqual(tree_state(self.ws), self.checkpoint_state)
        third = self.undo(cid)
        self.assertEqual(tree_state(self.ws), self.checkpoint_state)
        self.assertEqual(len({first["safety"]["id"], second["safety"]["id"],
                              third["safety"]["id"]}), 3)
        # the very first safety checkpoint still holds the agent's work
        self.undo(first["safety"]["id"])
        self.assertEqual(tree_state(self.ws), agent_state)

    def test_success_leaves_no_debris(self):
        cid = self.snapshot()["id"]
        self.agent_edits()
        self.undo(cid)
        self.assertEqual(self.debris(), [])
        self.assertIsNone(self.journal())
        self.assertFalse((self.store / ".sfh/undo.entries.json").exists())

    def test_debris_from_an_earlier_crash_is_reaped(self):
        cid = self.snapshot()["id"]
        stale_tmp = self.store / f".tmp-{cid}"
        stale_tmp.mkdir()
        (stale_tmp / "junk").write_text("x")
        stale_part = self.store / "orphan.tar.gz.part"
        stale_part.write_text("x")
        old = time.time() - (sf_mcp.CKPT_DEBRIS_TTL + 60)
        for path in (stale_tmp, stale_part):
            os.utime(path, (old, old))
        self.snapshot(label="next")
        self.assertFalse(stale_tmp.exists())
        self.assertFalse(stale_part.exists())

    def test_two_operations_do_not_interleave(self):
        self.setenv("SHADOWFETCH_CKPT_KEEP", "12")
        with mock.patch.object(sf_mcp, "CKPT_LOCK_SECONDS", 0.2):
            held = threading.Event()
            release = threading.Event()

            def hold():
                with sf_mcp._CkptLock(sf_mcp._ckpt_store(self.ws)):
                    held.set()
                    release.wait(10)

            worker = threading.Thread(target=hold)
            worker.start()
            try:
                held.wait(10)
                with self.assertRaises(sf_mcp._ToolError) as caught:
                    self.snapshot()
                self.assertIn("another checkpoint operation", str(caught.exception))
            finally:
                release.set()
                worker.join(10)

    def test_the_snapshot_method_is_not_decided_by_PATH(self):
        """PERMANENT INVARIANT: a forged tool on PATH cannot mint a checkpoint
        that claims to be a btrfs snapshot.

        Before Stage H the method came from `stat -f -c %T` and `btrfs` as
        resolved through PATH, and both are user-writable in an agent session.
        A checkpoint stamped "btrfs" whose subvolume does not exist restores
        nothing.
        """
        fake = self.root / "bin"
        fake.mkdir()
        for name, body in (("stat", "#!/bin/sh\necho btrfs\n"),
                           ("btrfs", "#!/bin/sh\nexit 0\n")):
            tool = fake / name
            tool.write_text(body)
            tool.chmod(0o755)
        self.setenv("PATH", f"{fake}:{os.environ['PATH']}")
        result = self.snapshot()
        self.assertEqual(result["method"], "tar")
        self.assertTrue((self.store / result["archive"]).is_file())
        self.assertFalse((self.store / result["id"]).exists(),
                         "a forged tool created a directory the engine trusts")
        # and it really restores
        self.agent_edits()
        self.undo(result["id"])
        self.assertEqual((self.ws / "src/app.py").read_text(), "original\n")

    def test_trusted_tool_rejects_a_writable_or_non_root_binary(self):
        impostor = self.root / "btrfs"
        impostor.write_text("#!/bin/sh\nexit 0\n")
        impostor.chmod(0o777)
        self.assertIsNone(sf_mcp._trusted_tool((str(impostor),)))
        self.assertIsNone(sf_mcp._trusted_tool(("/nonexistent/btrfs",)))

    def test_the_two_rename_fallback_still_restores_and_verifies(self):
        """Filesystems without RENAME_EXCHANGE take the journalled path."""
        cid = self.snapshot()["id"]
        self.checkpoint_state = tree_state(self.ws)
        self.agent_edits()
        with mock.patch.object(sf_mcp, "_ckpt_exchange", lambda a, b: False):
            self.undo(cid)
        self.assertEqual(tree_state(self.ws), self.checkpoint_state)
        self.assertEqual(self.debris(), [])
        self.assertIsNone(self.journal())

    def test_a_stale_journal_blocks_everything_until_recovered(self):
        cid = self.snapshot()["id"]
        sf_mcp._ckpt_journal_write(self.store, {
            "phase": "exchange", "workspace": "proj", "checkpoint": cid,
            "stage": None, "displaced": None, "safety": cid})
        with self.assertRaises(sf_mcp._ToolError) as caught:
            self.snapshot()
        self.assertIn("recover proj", str(caught.exception))
        # ...and recover refuses to guess when it has no record of the tree
        with self.assertRaises(sf_mcp._ToolError) as guess:
            sf_mcp.checkpoint_call("recover", workspace="proj")
        self.assertIn("RECOVERY REQUIRED", str(guess.exception))


# --------------------------------------------------------------------------- #
# The CLI contract operators and Firebreak read
# --------------------------------------------------------------------------- #
class CommandLine(CheckpointCase):
    def run_cli(self, *argv):
        return subprocess.run(CLI + list(argv), capture_output=True, text=True,
                              env=dict(os.environ), timeout=300)

    def test_a_refusal_is_a_sentence_not_a_traceback(self):
        done = self.run_cli("diff", "proj", "no-such-checkpoint")
        self.assertEqual(done.returncode, 1)
        self.assertNotIn("Traceback", done.stderr)
        self.assertEqual(done.stderr.strip(), "no such checkpoint: no-such-checkpoint")

    def test_recovery_required_has_its_own_exit_code(self):
        cid = self.snapshot()["id"]
        sf_mcp._ckpt_journal_write(self.store, {
            "phase": "exchange", "workspace": "proj", "checkpoint": cid,
            "stage": None, "displaced": None, "safety": cid})
        done = self.run_cli("recover", "proj")
        self.assertEqual(done.returncode, 4, done.stderr)
        self.assertIn("RECOVERY REQUIRED", done.stderr)
        # exit 1 is "nothing happened"; exit 4 is "something is half done"
        self.assertNotEqual(done.returncode, 1)

    def test_verify_prune_and_recover_are_available_to_an_operator(self):
        cid = self.snapshot()["id"]
        verified = self.run_cli("verify", "proj", cid)
        self.assertEqual(verified.returncode, 0, verified.stderr)
        self.assertIn("verifies", verified.stdout)

        payload = json.loads(self.run_cli("verify", "proj", cid, "--json").stdout)
        self.assertTrue(payload["verified"])
        self.assertEqual(set(payload), {"action", "workspace", "checkpoint",
                                        "method", "entries", "verified", "problems"})

        pruned = json.loads(self.run_cli("prune", "proj", "--json").stdout)
        self.assertEqual(set(pruned), {"action", "workspace", "dropped", "kept",
                                       "bytes"})
        recovered = json.loads(self.run_cli("recover", "proj", "--json").stdout)
        self.assertEqual(recovered["result"], "nothing-to-recover")

    def test_a_corrupt_checkpoint_is_a_sentence_not_a_traceback(self):
        """Found by hand, not by test: `undo` on a corrupt archive used to
        print a tarfile.ReadError stack trace. The transaction had done its
        job -- the workspace was untouched -- but nothing said so."""
        cid = self.snapshot()["id"]
        (self.ws / "src/app.py").write_text("agent work\n")
        (self.store / f"{cid}.tar.gz").write_bytes(b"not a gzip file at all")
        done = self.run_cli("undo", "proj", cid)
        self.assertEqual(done.returncode, 1, done.stderr)
        self.assertNotIn("Traceback", done.stderr)
        self.assertTrue(done.stderr.startswith("workspace unchanged"), done.stderr)
        self.assertEqual((self.ws / "src/app.py").read_text(), "agent work\n")

    def test_verify_fails_loudly_on_a_broken_checkpoint(self):
        cid = self.snapshot()["id"]
        (self.store / f"{cid}.tar.gz").write_bytes(b"not a tar")
        done = self.run_cli("verify", "proj", cid)
        self.assertEqual(done.returncode, 1)
        self.assertIn("DOES NOT verify", done.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
