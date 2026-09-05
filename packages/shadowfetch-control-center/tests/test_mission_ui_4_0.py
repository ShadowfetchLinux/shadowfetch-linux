"""Behavioral Qt coverage for the Mission Control contract and safety scopes.

Run with QT_QPA_PLATFORM=offscreen python3 -m unittest discover
-s packages/shadowfetch-control-center/tests. A real Qt runtime is required.
"""
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "packages/shadowfetch-control-center/data/usr/share/shadowfetch/control-center"))
from PyQt6.QtCore import QEventLoop, QTimer
from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import QApplication
from sfcc import theme
from sfcc.mission_client import JsonCommand, workspace_path
from sfcc.missions_page import NewMissionDialog, MissionsPage
from sfcc.grok_bot_page import GrokBotPage
from sfcc.local_model_card import LocalModelCard, ModelChooser

APP = QApplication.instance() or QApplication([])


class FakeClient:
    def __init__(self, *_):
        self.calls = []

    def call(self, args, callback):
        self.calls.append(args)
        if args[0] == "list":
            callback([], None)
        elif args[0] == "capabilities":
            callback({}, None)
        else:
            callback(None, "Test operation must provide a response explicitly.")

    def grok_status(self, callback):
        callback({"installed": False, "verified": False, "launchable": False, "download_bytes": 103320044}, None)


class MissionDialogTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {"SHADOWFETCH_AGENT_WORKSPACES": self.tmp.name})
        self.env.start()
        (Path(self.tmp.name) / "demo").mkdir()
        self.client = FakeClient()
        self.dialog = NewMissionDialog(None, self.client, lambda _: None)
        self.dialog.workspace.setText("demo")
        self.dialog.model.setText("installed-test-model")
        self.dialog.tests.setText('python3 -m unittest discover -s "tests with spaces"')

    def tearDown(self):
        self.dialog.close()
        self.dialog.deleteLater()
        self.env.stop()
        self.tmp.cleanup()

    def test_builds_literal_argv_and_explicit_scope(self):
        args = self.dialog.arguments()
        self.assertEqual(str(Path(self.tmp.name).resolve() / "demo"), args[args.index("--workspace") + 1])
        self.assertEqual(["python3", "-m", "unittest", "discover", "-s", "tests with spaces"], json.loads(args[args.index("--test-json") + 1]))
        self.assertIn("--network", args)
        self.assertIn("--runtime", args)

    def test_rejects_outside_or_nested_project(self):
        for path in ("../escape", "/etc", "demo/nested"):
            self.dialog.workspace.setText(path)
            with self.assertRaises(ValueError):
                self.dialog.arguments()

    def test_rejects_symlink_scope_escape(self):
        with tempfile.TemporaryDirectory() as outside:
            (Path(self.tmp.name) / "escape").symlink_to(outside)
            with self.assertRaises(ValueError):
                workspace_path("escape")

    def test_cloud_requires_explicit_connection(self):
        self.dialog.runtime.setCurrentIndex(self.dialog.runtime.findData("codex"))
        self.dialog.network.setCurrentIndex(self.dialog.network.findData("none"))
        with self.assertRaisesRegex(ValueError, "cloud connection"):
            self.dialog.arguments()
        self.dialog.network.setCurrentIndex(self.dialog.network.findData("allow"))
        args = self.dialog.arguments()
        self.assertEqual("codex", args[args.index("--runtime") + 1])
        self.assertNotIn("--model", args)

    def test_shared_model_requires_fire_and_native_model_can_use_ice(self):
        self.dialog.model.set_models([{"name": "shared-model", "local_only_verified": False}])
        self.dialog.model.setText("shared-model")
        self.dialog.network.setCurrentIndex(self.dialog.network.findData("none"))
        with self.assertRaisesRegex(ValueError, "shared compute"):
            self.dialog.arguments()
        self.dialog.model.set_models([{"name": "native-model", "local_only_verified": True}])
        self.dialog.model.setText("native-model")
        self.assertIn("Verified native", self.dialog.model_scope.text())
        self.assertIn("--model", self.dialog.arguments())

    def test_report_requires_relative_inputs(self):
        self.dialog.kind.setCurrentIndex(self.dialog.kind.findData("report"))
        with self.assertRaisesRegex(ValueError, "at least one"):
            self.dialog.arguments()
        self.dialog.inputs.setPlainText("../secret.md")
        with self.assertRaisesRegex(ValueError, "relative paths"):
            self.dialog.arguments()
        self.dialog.inputs.setPlainText("sources/brief.md\nnotes.md")
        args = self.dialog.arguments()
        self.assertEqual(2, args.count("--input"))
        self.assertNotIn("--test-json", args)

    def test_media_does_not_require_a_model(self):
        self.dialog.kind.setCurrentIndex(self.dialog.kind.findData("media"))
        self.dialog.model.clear()
        self.dialog.inputs.setPlainText("input.mp4")
        self.assertNotIn("--model", self.dialog.arguments())

    def test_validation_does_not_queue_invalid_work(self):
        self.dialog.workspace.setText("../../private")
        self.dialog._submit()
        self.assertEqual([], self.client.calls)
        self.assertTrue(self.dialog.queue.isEnabled())
        self.assertTrue(self.dialog.error.text())

    def test_form_fits_1366_desktop(self):
        self.dialog.resize(760, 660)
        self.dialog.show()
        APP.processEvents()
        self.assertLessEqual(self.dialog.height(), 680)
        self.assertLessEqual(self.dialog.width(), 800)
        self.assertTrue(self.dialog.queue.isVisible())


class JsonTransportTests(unittest.TestCase):
    def run_command(self, command, args, timeout=2000):
        result = []
        loop = QEventLoop()
        def done(data, error):
            result.append((data, error))
            loop.quit()
        job = JsonCommand(APP, command, args, done, timeout_ms=timeout)
        job.start()
        QTimer.singleShot(5000, loop.quit)
        loop.exec()
        self.assertEqual(1, len(result))
        return result[0]

    def test_missing_command_reports_once(self):
        data, error = self.run_command("/does/not/exist/shadowfetch-missions", [])
        self.assertIsNone(data)
        self.assertIn("Could not start", error)

    def test_json_error_preserves_actionable_detail(self):
        data, error = self.run_command(sys.executable, ["-c", 'import json,sys;print(json.dumps({"error":"Workspace is busy"}));sys.exit(3)'])
        self.assertIsNone(data)
        self.assertEqual("Workspace is busy", error)

    def test_invalid_output_is_not_success(self):
        data, error = self.run_command(sys.executable, ["-c", 'print("not json")'])
        self.assertIsNone(data)
        self.assertIn("invalid response", error)

    def test_timeout_kills_only_read_request(self):
        data, error = self.run_command(sys.executable, ["-c", "import time;time.sleep(60)"], timeout=30)
        self.assertIsNone(data)
        self.assertIn("did not answer", error)

    def test_success_parses_json(self):
        self.assertEqual(([{"id": "m1"}], None), self.run_command(sys.executable, ["-c", 'print(\'[ {"id":"m1"} ]\')']))


class PageStateTests(unittest.TestCase):
    def test_results_show_filenames_and_open_the_full_recorded_path(self):
        with patch("sfcc.missions_page.MissionClient", FakeClient):
            page = MissionsPage(lambda _: None)
            page.selected_id = "m1"
            output = "/home/sfqa/Workspaces/long-project/mission-output/m1/01-studio-tone.wav"
            page._shown("m1", {"id": "m1", "state": "waiting-review", "artifacts": [output]}, None)
            item = page.artifacts.item(0)
            self.assertEqual("01-studio-tone.wav", item.text())
            self.assertIn(output, item.toolTip())
            with patch.object(page, "_open_path") as open_path:
                page._open_artifact(item)
                open_path.assert_called_once_with(output)
            page.timer.stop()
            page.deleteLater()
            APP.processEvents()

    def test_review_controls_follow_state(self):
        with patch("sfcc.missions_page.MissionClient", FakeClient):
            page = MissionsPage(lambda _: None)
            page.selected = {"id": "m1", "state": "waiting-review", "checkpoint": "abc", "workspace": "/tmp/project", "receipt": "/tmp/receipt"}
            page._buttons()
            self.assertTrue(page.actions["accept"].isEnabled())
            self.assertTrue(page.actions["undo"].isEnabled())
            self.assertFalse(page.actions["cancel"].isEnabled())
            page.selected["state"] = "running"
            page._buttons()
            self.assertFalse(page.actions["undo"].isEnabled())
            self.assertFalse(page.actions["accept"].isEnabled())
            self.assertTrue(page.actions["cancel"].isEnabled())
            page.timer.stop()
            page.deleteLater()
            APP.processEvents()

    def test_late_detail_cannot_replace_selected_mission(self):
        with patch("sfcc.missions_page.MissionClient", FakeClient):
            page = MissionsPage(lambda _: None)
            page.selected_id = "new"
            page._shown("old", {"id": "old", "title": "Stale"}, None)
            self.assertNotEqual("Stale", page.detail_title.text())
            page.timer.stop()
            page.deleteLater()
            APP.processEvents()

    def test_grok_never_claims_authenticated(self):
        with patch("sfcc.grok_bot_page.MissionClient", FakeClient), patch.object(theme, "ELEMENT", "fire"):
            page = GrokBotPage(lambda _: None)
            page._status({"verified": True, "launchable": True, "installed": True, "installed_version": "0.43.0", "authenticated": None}, None)
            self.assertTrue(page.launch.isEnabled())
            self.assertIn("Sign-in status is managed inside", page.progress.text())
            page.timer.stop()
            page.deleteLater()
            APP.processEvents()

    def test_ice_blocks_grok_even_if_installed(self):
        with patch("sfcc.grok_bot_page.MissionClient", FakeClient), patch.object(theme, "ELEMENT", "ice"):
            page = GrokBotPage(lambda _: None)
            page._status({"verified": True, "launchable": True, "installed": True, "installed_version": "0.43.0"}, None)
            self.assertFalse(page.launch.isEnabled())
            self.assertFalse(page.install.isEnabled())
            page.timer.stop()
            page.deleteLater()
            APP.processEvents()


class LocalModelTests(unittest.TestCase):
    def test_listed_model_does_not_claim_inference_verified(self):
        card = LocalModelCard()
        card._status({"ready": True, "models": [{"id": "local-test"}], "hardware": {}}, None)
        self.assertEqual("local-test", card.model.text())
        self.assertIn("Run verification", card.state.text())
        self.assertTrue(card.verify_button.isEnabled())
        card.deleteLater()

    def test_real_pass_contract_shows_receipt(self):
        card = LocalModelCard()
        card._verified({"status": "pass", "elapsed_seconds": 1.25, "receipt": "/local/receipt.json"}, None)
        self.assertIn("inference passed", card.state.text())
        self.assertIn("1.25", card.state.text())
        self.assertIn("receipt.json", card.receipt.text())
        card.deleteLater()

    def test_model_failure_stays_actionable(self):
        card = LocalModelCard()
        card._verified(None, "The model ran out of memory")
        self.assertEqual("The model ran out of memory", card.state.text())
        self.assertNotIn("passed", card.state.text())
        card.deleteLater()

    def test_refresh_preserves_user_selected_model(self):
        chooser = ModelChooser()
        chooser.setText("selected")
        chooser.set_models([{"id": "other"}])
        self.assertEqual("selected", chooser.text())
        chooser.deleteLater()


class RealMissionContractTests(unittest.TestCase):
    """Exercise actual GUI argv against SQLite controller without executing work."""
    run_command = JsonTransportTests.run_command
    def test_real_queue_cancel_retry_round_trip(self):
        backend = ROOT / "packages/shadowfetch-missions/data/usr/bin/shadowfetch-missions"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            workspaces = root / "Workspaces"
            project = workspaces / "demo"
            project.mkdir(parents=True)
            with patch.dict(os.environ, {"SHADOWFETCH_AGENT_WORKSPACES": str(workspaces), "SHADOWFETCH_MISSIONS_STATE": str(root / "state")}):
                dialog = NewMissionDialog(None, FakeClient(), lambda _: None)
                dialog.workspace.setText("demo")
                dialog.model.setText("test-contract-only")
                dialog.tests.setText("python3 -m unittest")
                created, error = self.run_command(sys.executable, [str(backend), "--json", *dialog.arguments()])
                self.assertIsNone(error)
                self.assertEqual("queued", created["state"])
                self.assertEqual("local", created["config"]["runtime"])
                mid = created["id"]
                cancelled, error = self.run_command(sys.executable, [str(backend), "--json", "cancel", mid])
                self.assertIsNone(error)
                self.assertEqual("cancelled", cancelled["state"])
                retried, error = self.run_command(sys.executable, [str(backend), "--json", "retry", mid])
                self.assertIsNone(error)
                self.assertEqual("queued", retried["state"])
                events, error = self.run_command(sys.executable, [str(backend), "--json", "events", mid])
                self.assertIsNone(error)
                self.assertGreaterEqual(len(events), 3)
                dialog.deleteLater()


class WelcomeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        loader = importlib.machinery.SourceFileLoader("welcome4test", str(ROOT / "packages/shadowfetch-welcome/src/shadowfetch-welcome"))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        cls.welcome = importlib.util.module_from_spec(spec)
        with patch("pathlib.Path.home", return_value=Path(cls.tmp.name)):
            loader.exec_module(cls.welcome)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_grok_is_distinct_and_featured(self):
        agents = self.welcome.CODING_AGENT_BY_KEY
        self.assertEqual("shadowfetch-grok-bot", agents["grok-bot"]["helper"])
        self.assertEqual("Grok Build", agents["grok"]["name"])
        page = self.welcome.BuzzPage(lambda _: None)
        self.assertIn("grok-bot", page.coding_agents)
        page.deleteLater()

    def test_ice_select_all_does_not_enable_grok_download(self):
        values = []
        with patch.object(self.welcome, "ELEMENT", "ice"):
            page = self.welcome.BuzzPage(values.append)
            self.assertEqual("none", page.choice)
            page._toggle_all_agents(True)
            page._submit()
            self.assertFalse(values[0]["coding_agents"]["grok-bot"])
            page.deleteLater()

    def test_welcome_and_agents_fit_laptop(self):
        for page in (self.welcome.WelcomePage(lambda: None), self.welcome.BuzzPage(lambda _: None)):
            page.resize(1080, 690)
            page.show()
            APP.processEvents()
            self.assertLessEqual(page.height(), 700)
            self.assertLessEqual(page.width(), 1100)
            page.close()
            page.deleteLater()


if __name__ == "__main__":
    unittest.main()
