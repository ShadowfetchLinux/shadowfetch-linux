"""Phase 3 Step 17: the MCP surface declares, gates and records what it does.

The baseline was: sf_mcp.py contained no logging, audit or journal call at all,
and checkpoint.undo was a fully agent-facing destructive tool needing only a
workspace name and an id that checkpoint.list hands over.

Three properties are asserted here, and the third is the one that matters:

  1. every tool DECLARES a category, and the gate reads the declaration rather
     than the tool's name, so a tool added later is governed on registration;
  2. every call through the protocol is recorded in a chained log, and a call
     that changes something and cannot be recorded is REFUSED;
  3. a refusal CHANGED NOTHING -- the workspace and its checkpoint store are
     byte-identical afterwards, including the safety snapshot undo() would
     otherwise have taken on its way in.

The engine (checkpoint_call) is deliberately outside all of this: Mission
Control and shadowfetch-checkpoint are an orchestrator with its own audit chain
and a person at a terminal, not the agent surface. test_the_engine_path_is_not_
gated pins that boundary so it cannot be closed by accident.
"""
import contextlib
import hashlib
import importlib.machinery
import importlib.util
import io
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

BASE = Path(__file__).resolve().parents[1]
MCP_PY = BASE / "data/usr/lib/shadowfetch/mcp/sf_mcp.py"
_loader = importlib.machinery.SourceFileLoader("sf_mcp_audit_subject", str(MCP_PY))
_spec = importlib.util.spec_from_loader("sf_mcp_audit_subject", _loader)
sf_mcp = importlib.util.module_from_spec(_spec)
_loader.exec_module(sf_mcp)

SESSION = "fb-20260908-audittest"


def tree_digest(root: Path) -> str:
    """A byte-level fingerprint of a tree: names, kinds, modes, contents.

    Asserting that a refusal RAISED is not asserting that it changed nothing,
    and only the second claim is worth making about a destructive tool.
    """
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=str):
        relative = str(path.relative_to(root)).encode()
        if path.is_symlink():
            digest.update(b"L" + relative + b"\0" + os.readlink(path).encode() + b"\0")
        elif path.is_dir():
            digest.update(b"D" + relative + b"\0%o\0" % (path.stat().st_mode & 0o777))
        else:
            digest.update(b"F" + relative + b"\0%o\0" % (path.stat().st_mode & 0o777))
            digest.update(path.read_bytes() + b"\0")
    return digest.hexdigest()


class MCPCase(unittest.TestCase):
    """One temporary machine: a workspace root, a state root, no inherited env."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name).resolve()
        self.workspaces = self.base / "Workspaces"
        self.ws = self.workspaces / "proj"
        (self.ws / "src").mkdir(parents=True)
        (self.ws / "src/app.py").write_text("original\n")
        (self.ws / "keep.md").write_text("keep\n")
        self.state = self.base / "state"
        self.state.mkdir()
        self.scope = self.base / "scope"
        (self.scope / "src").mkdir(parents=True)
        (self.scope / "src/app.py").write_text("print('hi')\n")
        self.environment = {
            "SHADOWFETCH_AGENT_WORKSPACES": str(self.workspaces),
            # Both, and neither is XDG_STATE_HOME: that variable is ambient
            # and no longer moves either directory, so a fixture relying on it
            # would write into the operator's real state.
            "XDG_STATE_HOME": str(self.state),
            "SHADOWFETCH_MCP_STATE": str(self.state),
            "SHADOWFETCH_FIREBREAK_STATE": str(self.state / "shadowfetch/firebreak"),
            "SF_MCP_FS_ROOT": str(self.scope),
        }
        for name in ("SHADOWFETCH_MCP_DESTRUCTIVE", "SHADOWFETCH_MCP_SESSION",
                     "SHADOWFETCH_FIREBREAK"):
            os.environ.pop(name, None)
        self.env = patch.dict(os.environ, self.environment)
        self.env.start()
        # A working anchor, faked. The journald mirror is exercised on its own in
        # test_a_missing_anchor_is_reported_rather_than_assumed; every other test
        # would otherwise write to the real system journal to prove nothing.
        sf_mcp._SHARED_ANCHOR = lambda row: (True, None)
        sf_mcp._NOTED_FAILURE = None

    def tearDown(self):
        self.env.stop()
        sf_mcp._SHARED_ANCHOR = None
        sf_mcp._NOTED_FAILURE = None
        self.temp.cleanup()

    # -- helpers ------------------------------------------------------------ #
    def record_session(self, session=SESSION):
        """Write the Firebreak session record that makes correlation OBSERVED."""
        directory = self.state / "shadowfetch/firebreak"
        directory.mkdir(parents=True, exist_ok=True)
        (directory / (session + ".session")).write_text("{}\n")
        return session

    def operator(self, session=SESSION):
        """The environment an operator sets to hand an agent a destructive tool."""
        os.environ["SHADOWFETCH_MCP_DESTRUCTIVE"] = "allow"
        os.environ["SHADOWFETCH_MCP_SESSION"] = session

    def audit_path(self):
        return self.state / "shadowfetch/mcp" / sf_mcp.AUDIT_FILENAME

    def break_the_sink(self):
        """Put a regular file where the audit directory has to be.

        Chosen over chmod because it fails for root too: a test that quietly
        skips as root proves nothing on the machine that matters. Only the
        audit directory is broken -- moving XDG_STATE_HOME would also hide the
        Firebreak session record, and the call would then be refused for want
        of correlation without the audit path ever being reached.
        """
        self.audit_path().parent.parent.mkdir(parents=True, exist_ok=True)
        self.audit_path().parent.write_text("not a directory\n")

    def records(self):
        try:
            lines = self.audit_path().read_text().splitlines()
        except FileNotFoundError:
            return []
        return [json.loads(line) for line in lines if line.strip()]

    def calls(self):
        """Records for actual tool calls; the genesis row is not one."""
        return [row for row in self.records() if row["phase"] != sf_mcp.AUDIT_GENESIS]

    def snapshot_id(self):
        return sf_mcp.checkpoint_call("snapshot", workspace="proj",
                                      label="before-the-agent")["id"]

    def text(self, result):
        return result["content"][0]["text"]


class CategoryTests(MCPCase):
    def servers(self):
        return {"passport": sf_mcp.build_passport(), "phoenix": sf_mcp.build_phoenix(),
                "checkpoint": sf_mcp.build_checkpoint(), "fs": sf_mcp.build_fs()}

    def test_every_tool_declares_a_category(self):
        for name, server in self.servers().items():
            for tool in server.tools.values():
                with self.subTest(server=name, tool=tool.name):
                    self.assertIn(tool.category, sf_mcp.CATEGORIES)

    def test_the_categories_are_the_ones_the_surface_documents(self):
        """The whole tool surface, as data. A new tool changes this literal."""
        actual = {f"{name}.{tool.name}": tool.category
                  for name, server in self.servers().items()
                  for tool in server.tools.values()}
        self.assertEqual(actual, {
            "passport.system_passport": sf_mcp.READ_ONLY,
            "phoenix.list_restore_points": sf_mcp.READ_ONLY,
            "checkpoint.snapshot": sf_mcp.MUTATING,
            "checkpoint.list": sf_mcp.READ_ONLY,
            "checkpoint.diff": sf_mcp.READ_ONLY,
            "checkpoint.undo": sf_mcp.DESTRUCTIVE,
            "fs.list_dir": sf_mcp.READ_ONLY,
            "fs.read_file": sf_mcp.READ_ONLY,
        })

    def test_a_tool_cannot_be_registered_without_a_category(self):
        server = sf_mcp.Server("probe")
        with self.assertRaises(TypeError):
            server.tool("t", "d", {"type": "object"})(lambda args: "")
        self.assertEqual(server.tools, {})

    def test_an_unrecognised_category_is_refused(self):
        server = sf_mcp.Server("probe")
        with self.assertRaises(ValueError):
            server.tool("t", "d", {"type": "object"}, "mostly-harmless")(lambda a: "")
        self.assertEqual(server.tools, {})

    def test_tools_list_carries_the_category(self):
        listing = sf_mcp.build_checkpoint().handle(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})["result"]["tools"]
        by_name = {entry["name"]: entry for entry in listing}
        self.assertEqual(by_name["list"]["_meta"]["shadowfetch/category"],
                         sf_mcp.READ_ONLY)
        self.assertTrue(by_name["list"]["annotations"]["readOnlyHint"])
        self.assertEqual(by_name["snapshot"]["_meta"]["shadowfetch/category"],
                         sf_mcp.MUTATING)
        self.assertFalse(by_name["snapshot"]["annotations"]["readOnlyHint"])
        self.assertFalse(by_name["snapshot"]["annotations"]["destructiveHint"])


class AuditTests(MCPCase):
    def test_a_read_is_recorded(self):
        result = sf_mcp.build_fs().call("read_file", {"path": "src/app.py"})
        self.assertFalse(result["isError"])
        rows = self.calls()
        self.assertEqual(len(rows), 1)
        self.assertEqual(
            (rows[0]["server"], rows[0]["tool"], rows[0]["category"],
             rows[0]["decision"], rows[0]["phase"], rows[0]["outcome"]),
            ("fs", "read_file", sf_mcp.READ_ONLY, "allowed", "completed", "ok"))

    def test_a_mutation_is_recorded_before_it_happens(self):
        result = sf_mcp.build_checkpoint().call("snapshot", {"workspace": "proj"})
        self.assertFalse(result["isError"])
        rows = self.calls()
        self.assertEqual([row["phase"] for row in rows], ["requested", "completed"])
        self.assertLess(rows[0]["seq"], rows[1]["seq"])
        self.assertEqual(rows[0]["category"], sf_mcp.MUTATING)

    def test_the_record_names_what_the_call_touched(self):
        sf_mcp.build_checkpoint().call("snapshot", {"workspace": "proj",
                                                    "label": "mission:m-1"})
        arguments = json.loads(self.calls()[0]["args"])
        self.assertEqual(arguments, {"label": "mission:m-1", "workspace": "proj"})

    def test_the_correlation_state_is_recorded_not_invented(self):
        sf_mcp.build_fs().call("read_file", {"path": "src/app.py"})
        self.assertEqual(self.calls()[0]["correlation"],
                         {"session": None, "source": None,
                          "status": sf_mcp.CORRELATION_ABSENT})
        os.environ["SHADOWFETCH_FIREBREAK"] = self.record_session("fb-sandbox-01")
        sf_mcp.build_fs().call("read_file", {"path": "src/app.py"})
        self.assertEqual(self.calls()[1]["correlation"],
                         {"session": "fb-sandbox-01", "source": "SHADOWFETCH_FIREBREAK",
                          "status": sf_mcp.CORRELATION_OBSERVED})

    def test_the_log_is_private(self):
        sf_mcp.build_fs().call("list_dir", {"path": "."})
        self.assertEqual(self.audit_path().stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.audit_path().parent.stat().st_mode & 0o777, 0o700)

    def test_a_clean_log_verifies(self):
        server = sf_mcp.build_checkpoint()
        server.call("snapshot", {"workspace": "proj"})
        server.call("list", {"workspace": "proj"})
        report = sf_mcp.verify_audit(self.audit_path())
        self.assertTrue(report["ok"], report["problems"])
        self.assertEqual(report["records"], 4)      # genesis + 3
        self.assertEqual(report["head_seq"], 4)

    def test_the_chain_detects_an_altered_record(self):
        sf_mcp.build_checkpoint().call("snapshot", {"workspace": "proj"})
        rows = self.records()
        rows[-1]["args"] = json.dumps({"workspace": "somewhere-else"})
        self.audit_path().write_text(
            "\n".join(json.dumps(row, sort_keys=True, separators=(",", ":"))
                      for row in rows) + "\n")
        report = sf_mcp.verify_audit(self.audit_path())
        self.assertFalse(report["ok"])
        self.assertTrue(any("does not match its hash" in problem
                            for problem in report["problems"]), report["problems"])

    def test_the_chain_detects_a_removed_record(self):
        server = sf_mcp.build_checkpoint()
        server.call("snapshot", {"workspace": "proj"})
        server.call("list", {"workspace": "proj"})
        rows = self.records()
        del rows[1]
        self.audit_path().write_text(
            "\n".join(json.dumps(row, sort_keys=True, separators=(",", ":"))
                      for row in rows) + "\n")
        report = sf_mcp.verify_audit(self.audit_path())
        self.assertFalse(report["ok"])
        self.assertTrue(any("truncated or renumbered" in problem
                            for problem in report["problems"]), report["problems"])

    def test_concurrent_appends_do_not_fork_the_chain(self):
        """Two servers appending at once must not both chain onto one head."""
        def worker():
            log = sf_mcp.AuditLog()
            for _ in range(5):
                log.append({"phase": "completed", "server": "probe", "tool": "t",
                            "category": sf_mcp.READ_ONLY, "decision": "allowed",
                            "reason": "", "correlation": None, "args": "{}",
                            "outcome": "ok"}, durable=False)
        threads = [threading.Thread(target=worker) for _ in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        report = sf_mcp.verify_audit(self.audit_path())
        self.assertTrue(report["ok"], report["problems"])
        self.assertEqual(report["records"], 31)     # genesis + 6 * 5

    def test_an_unknown_tool_is_recorded(self):
        result = sf_mcp.build_fs().call("write_file", {"path": "x", "data": "y"})
        self.assertTrue(result["isError"])
        rows = self.calls()
        self.assertEqual((rows[0]["tool"], rows[0]["decision"], rows[0]["reason"]),
                         ("write_file", "denied", "no such tool"))

    # -- the sink is unusable ------------------------------------------------ #
    def test_a_read_survives_an_unusable_sink_and_says_so(self):
        """A read changes nothing, so refusing it would turn an audit outage
        into an outage. It must not pass silently either."""
        self.break_the_sink()
        noise = io.StringIO()
        with contextlib.redirect_stderr(noise):
            result = sf_mcp.build_fs().call("read_file", {"path": "src/app.py"})
        self.assertFalse(result["isError"])
        self.assertEqual(self.text(result), "print('hi')\n")
        self.assertIn("audit failure", noise.getvalue())

    def test_a_mutation_is_refused_when_it_cannot_be_recorded(self):
        self.break_the_sink()
        before = tree_digest(self.workspaces)
        with contextlib.redirect_stderr(io.StringIO()):
            result = sf_mcp.build_checkpoint().call("snapshot", {"workspace": "proj"})
        self.assertTrue(result["isError"])
        self.assertIn("could not be recorded", self.text(result))
        self.assertEqual(tree_digest(self.workspaces), before)
        self.assertFalse((self.workspaces / ".sf-checkpoints").exists())

    def test_a_missing_anchor_is_reported_rather_than_assumed(self):
        """No journald mirror is a state a person can find, not a silence."""
        sf_mcp._SHARED_ANCHOR = False
        noise = io.StringIO()
        with contextlib.redirect_stderr(noise):
            sf_mcp.build_fs().call("list_dir", {"path": "."})
        self.assertIn("external anchor", noise.getvalue())
        state = sf_mcp.audit_state()
        self.assertEqual(state["mirror_failures"], 1)
        self.assertIn("external anchor", state["last_mirror_error"])


class DestructiveTests(MCPCase):
    def setUp(self):
        super().setUp()
        self.checkpoint = self.snapshot_id()
        (self.ws / "src/app.py").write_text("rewritten by the agent\n")
        (self.ws / "keep.md").unlink()

    def refusal_changed_nothing(self, result, before):
        self.assertTrue(result["isError"])
        self.assertIn("Nothing was changed", self.text(result))
        self.assertEqual(tree_digest(self.workspaces), before)

    def test_undo_is_not_advertised_to_agents(self):
        listing = sf_mcp.build_checkpoint().handle(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})["result"]["tools"]
        self.assertEqual(sorted(entry["name"] for entry in listing),
                         ["diff", "list", "snapshot"])

    def test_a_denied_undo_changes_nothing(self):
        """Not merely that it errored: the workspace AND the checkpoint store
        are byte-identical, so undo did not even take its safety snapshot."""
        before = tree_digest(self.workspaces)
        result = sf_mcp.build_checkpoint().call(
            "undo", {"workspace": "proj", "checkpoint": self.checkpoint})
        self.refusal_changed_nothing(result, before)
        self.assertEqual((self.ws / "src/app.py").read_text(),
                         "rewritten by the agent\n")

    def test_a_denied_undo_is_recorded_as_denied(self):
        sf_mcp.build_checkpoint().call(
            "undo", {"workspace": "proj", "checkpoint": self.checkpoint})
        rows = self.calls()
        self.assertEqual([row["phase"] for row in rows], ["denied"])
        self.assertEqual(rows[0]["category"], sf_mcp.DESTRUCTIVE)
        self.assertEqual(json.loads(rows[0]["args"])["checkpoint"], self.checkpoint)

    def test_undo_is_refused_without_correlation_even_when_enabled(self):
        os.environ["SHADOWFETCH_MCP_DESTRUCTIVE"] = "allow"
        before = tree_digest(self.workspaces)
        result = sf_mcp.build_checkpoint().call(
            "undo", {"workspace": "proj", "checkpoint": self.checkpoint})
        self.refusal_changed_nothing(result, before)
        self.assertIn(sf_mcp.CORRELATION_ABSENT, self.text(result))

    def test_undo_is_refused_when_the_session_names_nothing(self):
        self.operator("fb-never-existed")
        before = tree_digest(self.workspaces)
        result = sf_mcp.build_checkpoint().call(
            "undo", {"workspace": "proj", "checkpoint": self.checkpoint})
        self.refusal_changed_nothing(result, before)
        self.assertIn(sf_mcp.CORRELATION_UNKNOWN, self.text(result))
        self.assertEqual(self.calls()[0]["correlation"]["status"],
                         sf_mcp.CORRELATION_UNKNOWN)

    def test_undo_is_refused_when_the_session_id_is_malformed(self):
        self.record_session()
        self.operator("../shadowfetch/firebreak/" + SESSION)
        before = tree_digest(self.workspaces)
        result = sf_mcp.build_checkpoint().call(
            "undo", {"workspace": "proj", "checkpoint": self.checkpoint})
        self.refusal_changed_nothing(result, before)
        self.assertIn(sf_mcp.CORRELATION_MALFORMED, self.text(result))

    def test_undo_runs_for_an_operator_with_a_recorded_session(self):
        self.record_session()
        self.operator()
        result = sf_mcp.build_checkpoint().call(
            "undo", {"workspace": "proj", "checkpoint": self.checkpoint})
        self.assertFalse(result["isError"], self.text(result))
        self.assertEqual((self.ws / "src/app.py").read_text(), "original\n")
        self.assertTrue((self.ws / "keep.md").exists())
        rows = self.calls()
        self.assertEqual([row["phase"] for row in rows], ["requested", "completed"])
        self.assertEqual(rows[0]["correlation"]["status"], sf_mcp.CORRELATION_OBSERVED)
        self.assertEqual(rows[0]["correlation"]["session"], SESSION)

    def test_undo_is_refused_when_it_cannot_be_recorded_and_changes_nothing(self):
        self.record_session()
        self.operator()
        before = tree_digest(self.workspaces)
        self.break_the_sink()
        with contextlib.redirect_stderr(io.StringIO()):
            result = sf_mcp.build_checkpoint().call(
                "undo", {"workspace": "proj", "checkpoint": self.checkpoint})
        self.assertTrue(result["isError"])
        self.assertIn("could not be recorded", self.text(result))
        self.assertEqual(tree_digest(self.workspaces), before)

    def test_the_engine_path_is_not_gated(self):
        """Mission Control and shadowfetch-checkpoint reach the engine directly.

        Gating it would break the mission engine's own recovery, which keeps its
        own audit chain. Recorded here so the boundary is deliberate: this is
        also why an agent with a shell is NOT covered by anything above.
        """
        self.assertNotIn("SHADOWFETCH_MCP_DESTRUCTIVE", os.environ)
        result = sf_mcp.checkpoint_call("undo", workspace="proj",
                                        checkpoint=self.checkpoint)
        self.assertEqual(result["checkpoint"], self.checkpoint)
        self.assertEqual((self.ws / "src/app.py").read_text(), "original\n")
        self.assertEqual(self.calls(), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
