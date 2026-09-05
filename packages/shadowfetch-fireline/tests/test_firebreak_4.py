import argparse
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

BASE = Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader("firebreak", str(BASE / "data/usr/bin/shadowfetch-firebreak"))
spec = importlib.util.spec_from_loader("firebreak", loader)
fb = importlib.util.module_from_spec(spec)
loader.exec_module(fb)
sys.path.insert(0, str(BASE / "data/usr/lib/shadowfetch/mcp"))
import sf_mcp

class ScopeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name).resolve()
        self.ws = self.base / "Workspaces" / "project"
        self.ws.mkdir(parents=True)
        (self.ws / "seed.txt").write_text("original")
        self.env = patch.dict(os.environ, {"SHADOWFETCH_AGENT_WORKSPACES":str(self.ws.parent), "XDG_STATE_HOME":str(self.base / "state"), "SHADOWFETCH_ELEMENT":"ice"})
        self.env.start()
    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()
    def args(self, **values):
        defaults = dict(net=None, read=[], credential_env=[], keep_secrets=False, agent_command=["true"])
        defaults.update(values)
        return argparse.Namespace(**defaults)
    def test_private_root_clean_environment_network_off(self):
        with patch.dict(os.environ, {"SECRET_CUSTOM":"must-not-pass", "OPENAI_API_KEY":"test-not-for-sandbox"}):
            command, net, grants, names = fb.arguments(self.args(), self.ws, "test")
        self.assertEqual(net, "none")
        self.assertIn("--clearenv", command)
        self.assertIn("--unshare-net", command)
        self.assertIn("/home/agent", command)
        self.assertNotIn("test-not-for-sandbox", command)
        self.assertNotIn("must-not-pass", command)
        self.assertNotIn(["--ro-bind", "/", "/"], [command[i:i+3] for i in range(len(command))])
        self.assertNotIn("/etc/shadow", command)
        self.assertNotIn(str(Path.home()), command)
    def test_individual_credential_only(self):
        with patch.dict(os.environ, {"CODEX_API_KEY":"designated-test-key", "UNRELATED_SECRET":"private"}):
            command, _, _, names = fb.arguments(self.args(credential_env=["CODEX_API_KEY"]), self.ws, "test")
        self.assertEqual(names, ["CODEX_API_KEY"])
        self.assertIn("designated-test-key", command)
        self.assertNotIn("private", command)
    def test_explicit_read_grant_does_not_add_parent(self):
        doc = self.base / "selected.txt"
        doc.write_text("selected")
        command, _, _, _ = fb.arguments(self.args(read=[str(doc)]), self.ws, "test")
        self.assertIn(["--ro-bind",str(doc),str(doc)], [command[i:i+3] for i in range(len(command))])
        self.assertNotIn(["--ro-bind",str(self.base),str(self.base)], [command[i:i+3] for i in range(len(command))])
    def test_read_grants_cannot_expose_controller_or_whole_home(self):
        for path in ("/", str(Path.home()), str(self.ws.parent), str(fb.state()), str(self.base)):
            with self.subTest(path=path), self.assertRaises(fb.Error):
                fb.read_grants([path], self.ws)
    def test_workspace_symlink_escape_and_checkpoint_store_escape(self):
        (self.ws.parent / "escape").symlink_to(self.base)
        with self.assertRaises(fb.Error):
            fb.workspace("escape")
        with self.assertRaises(sf_mcp._ToolError):
            sf_mcp.build_checkpoint().tools["snapshot"].handler({"workspace":"escape"})
        (self.ws.parent / ".sf-checkpoints").symlink_to(self.base)
        with self.assertRaises(sf_mcp._ToolError):
            sf_mcp.build_checkpoint().tools["snapshot"].handler({"workspace":"project"})
    def test_checkpoint_preserves_links_without_reading_targets(self):
        target = self.base / "outside.txt"
        target.write_text("outside-secret")
        (self.ws / "link").symlink_to(target)
        server = sf_mcp.build_checkpoint()
        result = server.tools["snapshot"].handler({"workspace":"project"})
        cid = result.split()[1]
        (self.ws / "link").unlink()
        (self.ws / "seed.txt").write_text("changed")
        server.tools["undo"].handler({"workspace":"project", "checkpoint":cid})
        self.assertTrue((self.ws / "link").is_symlink())
        self.assertEqual(os.readlink(self.ws / "link"), str(target))
        self.assertEqual(target.read_text(), "outside-secret")
    def test_malicious_archive_rejected_before_outside_write(self):
        store = sf_mcp._ckpt_store(self.ws)
        for members in (["../../outside"], ["project/link", "project/link/pwn"]):
            with self.subTest(members=members):
                arc = store / "bad.tar.gz"
                with tarfile.open(arc,"w:gz") as tf:
                    for name in members:
                        info = tarfile.TarInfo(name)
                        if name.endswith("link"):
                            info.type = tarfile.SYMTYPE
                            info.linkname = str(self.base)
                            tf.addfile(info)
                        else:
                            info.size = 3
                            tf.addfile(info,io.BytesIO(b"bad"))
                with self.assertRaises(sf_mcp._ToolError):
                    sf_mcp._restore_tree(store,{"id":"bad","method":"tar","archive":"bad.tar.gz","workspace":"project"})
                self.assertFalse((self.base / "pwn").exists())
    def test_checkpoint_diff_and_undo_do_not_clobber_snapshot(self):
        server = sf_mcp.build_checkpoint()
        cid = server.tools["snapshot"].handler({"workspace":"project"}).split()[1]
        (self.ws / "seed.txt").write_text("changed")
        server.tools["diff"].handler({"workspace":"project","checkpoint":cid})
        server.tools["undo"].handler({"workspace":"project","checkpoint":cid})
        self.assertEqual((self.ws / "seed.txt").read_text(), "original")

if __name__ == "__main__":
    unittest.main(verbosity=2)
