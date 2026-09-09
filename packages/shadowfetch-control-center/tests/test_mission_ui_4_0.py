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
from PyQt6.QtCore import QEventLoop, QObject, QTimer, Qt, pyqtSignal
from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import QApplication, QLabel, QPushButton, QWidget
from sfcc import theme
from sfcc.mission_client import JsonCommand, workspace_path
from sfcc.missions_page import NewMissionDialog, MissionsPage
from sfcc.grok_bot_page import GrokBotPage
from sfcc.workspaces_page import WorkspacesPage
from sfcc.firewatch_page import FirewatchPage

APP = QApplication.instance() or QApplication([])


CAPABILITIES = {
    "capability_kinds": {"code_change": "code", "sourced_report": "report",
                         "media_export": "media"},
    "providers": {
        "codex": {"display_name": "Codex CLI (cloud)",
                  "capabilities": ["code_change", "sourced_report"],
                  "requires_network_approval": True, "available": True,
                  "installed": True, "authenticated": True, "reason": ""},
        "offline-media": {"display_name": "Offline media export (ffmpeg)",
                          "capabilities": ["media_export"],
                          "requires_network_approval": False, "available": True,
                          "installed": True, "authenticated": True, "reason": ""},
    },
}


class FakeClient:
    def __init__(self, *_):
        self.calls = []

    def call(self, args, callback):
        self.calls.append(args)
        if args[0] == "list":
            callback([], None)
        elif args[0] == "capabilities":
            callback(CAPABILITIES, None)
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
        self.dialog = NewMissionDialog(None, self.client, lambda _: None,
                                       capabilities=CAPABILITIES)
        self.dialog.workspace.setText("demo")
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
        self.assertIn("--kind", args)

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
        self.dialog.network.setCurrentIndex(self.dialog.network.findData("none"))
        with self.assertRaisesRegex(ValueError, "cloud connection"):
            self.dialog.arguments()
        self.dialog.network.setCurrentIndex(self.dialog.network.findData("allow"))
        args = self.dialog.arguments()
        self.assertEqual("codex", args[args.index("--provider") + 1])
        self.assertNotIn("--model", args)

    def test_code_and_report_name_no_provider_and_have_no_model_controls(self):
        """With no capabilities document the UI must not invent a provider.

        This replaces an assertion that argv carried --runtime codex, which
        pinned the coupling Phase 2 removed. The safety property it was really
        protecting -- that a cloud mission still demands explicit network
        consent -- is asserted here and enforced by the provider itself.
        """
        self.assertFalse(hasattr(self.dialog, "model"))
        self.assertFalse(hasattr(self.dialog, "refresh_models"))
        dialog = NewMissionDialog(None, self.client, lambda _: None, capabilities=None)
        dialog.workspace.setText("demo")
        dialog.tests.setText("true")
        for kind in ("code", "report"):
            dialog.kind.setCurrentIndex(dialog.kind.findData(kind))
            dialog.inputs.setPlainText("brief.md")
            args = dialog.arguments()
            self.assertNotIn("--provider", args)
            self.assertNotIn("--runtime", args)
            self.assertEqual("allow", args[args.index("--network") + 1])
            self.assertNotIn("--model", args)
        self.assertFalse(hasattr(dialog, "model"))

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
        self.dialog.inputs.setPlainText("input.mp4")
        args = self.dialog.arguments()
        self.assertNotIn("--model", args)
        self.assertEqual("offline-media", args[args.index("--provider") + 1])
        self.assertEqual("none", args[args.index("--network") + 1])
        self.assertFalse(self.dialog.network.isEnabled())

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
    def test_review_deadline_observes_without_interrupting_child(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "restore-finished"
            events = []
            loop = QEventLoop()
            ticks = []
            heartbeat = QTimer()
            heartbeat.setInterval(10)
            heartbeat.timeout.connect(lambda: ticks.append(True))
            heartbeat.start()
            def done(data, error):
                events.append(("done", data, error))
                loop.quit()
            script = "import pathlib,time,json;time.sleep(.2);pathlib.Path(" + repr(str(marker)) + ").write_text('restored');print(json.dumps({'state':'undone'}))"
            job = JsonCommand(APP, sys.executable, ["-c", script], done,
                              timeout_ms=30, preserve_operation=True,
                              on_waiting=lambda message: events.append(("waiting", message)))
            job.start()
            QTimer.singleShot(5000, loop.quit)
            loop.exec()
            heartbeat.stop()
            self.assertEqual(["waiting", "done"], [e[0] for e in events])
            self.assertEqual(("done", {"state": "undone"}, None), events[-1])
            self.assertEqual("restored", marker.read_text())
            self.assertGreater(len(ticks), 3)

    def test_review_output_limit_does_not_interrupt_restoration(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "restore-finished"
            result = []
            loop = QEventLoop()
            def done(data, error):
                result.append((data, error))
                loop.quit()
            script = "import pathlib,time;print('x'*500,flush=True);time.sleep(.15);pathlib.Path(" + repr(str(marker)) + ").write_text('restored')"
            job = JsonCommand(APP, sys.executable, ["-c", script], done,
                              preserve_operation=True)
            job.MAX_BYTES = 64
            job.start()
            QTimer.singleShot(5000, loop.quit)
            loop.exec()
            self.assertEqual("restored", marker.read_text())
            self.assertEqual(1, len(result))
            self.assertIn("too much data", result[0][1])
            self.assertLessEqual(len(job._stdout), 64)

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
    def test_review_stays_pending_through_polling_and_busy_refusal_is_retained(self):
        mission = {"id": "m1", "state": "waiting-review", "checkpoint": "abc"}
        class ReviewClient(FakeClient):
            def call(self, args, callback):
                if args[0] == "show":
                    callback(mission.copy(), None)
                else:
                    super().call(args, callback)
            def review(self, args, callback, on_waiting):
                self.calls.append(args)
                self.complete_review, self.waiting = callback, on_waiting
        with patch("sfcc.missions_page.MissionClient", ReviewClient):
            page = MissionsPage(lambda _: None)
            APP.processEvents()
            page.timer.stop()
            page.selected_id = "m1"
            page.selected = mission.copy()
            page._action("accept")
            self.assertTrue(page.review_pending)
            page.client.waiting("Review is still running.")
            page._listed([mission], None)
            self.assertEqual("Review is still running.", page.notice.text())
            self.assertFalse(any(b.isEnabled() for b in page.actions.values()))
            page._action("accept")
            self.assertEqual(1, len([a for a in page.client.calls if a[0] == "review"]))
            error = "Mission controller is busy; this review was not applied. Try again shortly."
            with patch("sfcc.missions_page.QMessageBox.warning") as warning:
                page.client.complete_review(None, error)
                warning.assert_called_once()
            self.assertFalse(page.review_pending)
            page._listed([mission], None)
            self.assertEqual(error, page.notice.text())
            self.assertEqual("waiting-review", page.selected["state"])
            self.assertTrue(page.actions["accept"].isEnabled())
            self.assertEqual(1, len([a for a in page.client.calls if a[0] == "review"]))
            # A deliberate second action can finish; only its actual result
            # clears the pending flag and changes the displayed action state.
            page._action("accept")
            self.assertTrue(page.review_pending)
            with patch.object(page, "refresh") as refresh:
                page.client.complete_review({**mission, "state": "completed"}, None)
                refresh.assert_called_once()
            self.assertFalse(page.review_pending)
            self.assertEqual("completed", page.selected["state"])
            self.assertFalse(page.actions["accept"].isEnabled())
            self.assertEqual("", page.notice.text())
            page.deleteLater()
            APP.processEvents()

    def test_window_close_cannot_destroy_a_pending_review(self):
        from sfcc.app import ControlCenterWindow
        # Exercise the real native close event without starting system pages.
        # Since W-31 the page supplies the verdict AND the sentence through
        # blocking_reason(); the shell no longer reads one attribute name and
        # writes the warning itself.
        window = ControlCenterWindow.__new__(ControlCenterWindow)
        QWidget.__init__(window)

        class Busy(QWidget):
            blocked = True

            def blocking_reason(self):
                return "A restore is running." if self.blocked else None

        page = Busy(window)
        window.pages = [page]
        window.show()
        APP.processEvents()
        with patch("sfcc.app.QMessageBox.warning") as warning:
            self.assertFalse(window.close())
            warning.assert_called_once()
            self.assertIn("A restore is running.", warning.call_args[0])
        self.assertTrue(window.isVisible())
        page.blocked = False
        self.assertTrue(window.close())
        window.deleteLater()
        APP.processEvents()

    def test_the_page_that_is_busy_is_the_one_that_says_so(self):
        """MissionsPage owns the sentence about its own review, so a change to
        what review means cannot leave the warning describing the old thing."""
        with patch("sfcc.missions_page.MissionClient", FakeClient):
            page = MissionsPage(lambda _: None)
            page.timer.stop()
            self.assertIsNone(page.blocking_reason())
            page.review_pending = True
            self.assertIn("review", page.blocking_reason())
            page.deleteLater()
            APP.processEvents()

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


class DeferredTelemetryTests(unittest.TestCase):
    def test_watch_retains_system_tabs_without_model_actions(self):
        class Sensors(QObject):
            updated = pyqtSignal(dict)
            def acquire(self):
                pass
            def release(self):
                pass
        sensors = Sensors()
        sensors.last = {}
        page = FirewatchPage(sensors)
        self.assertEqual(["Overview", "Heat map"], [page.tabs.tabText(i) for i in range(page.tabs.count())])
        sensors.updated.emit({"available": False})
        sensors.updated.emit({"available": True, "models": [{"name": "legacy"}]})
        self.assertNotIn("Open Buzz", [button.text() for button in page.findChildren(QPushButton)])
        page.deleteLater()


class WorkspaceTests(unittest.TestCase):
    def test_workspaces_show_normal_folders_without_internal_or_symlink_entries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "project").mkdir()
            (root / ".sf-checkpoints").mkdir()
            (root / "linked").symlink_to(root / "project")
            with patch.dict(os.environ, {"SHADOWFETCH_AGENT_WORKSPACES": directory}), patch("sfcc.workspaces_page.busutil.load_hwscan", return_value={}):
                page = WorkspacesPage(None, lambda _: None)
                labels = [item.text() for item in page.findChildren(QLabel)]
                self.assertIn("project", labels)
                self.assertNotIn(".sf-checkpoints", labels)
                self.assertNotIn("linked", labels)
                buttons = [item.text() for item in page.findChildren(QPushButton)]
                self.assertIn("Open", buttons)
                self.assertNotIn("Buzz", buttons)
                self.assertNotIn("Verify with a real task", buttons)
                page.deleteLater()


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
                # The dialog is built with the REAL engine's capabilities,
                # which is what MissionsPage hands it at runtime. Built with
                # none it names no provider, and an engine with more than one
                # provider for the capability correctly refuses to guess --
                # that refusal is the engine's job and is asserted separately.
                capabilities, error = self.run_command(
                    sys.executable, [str(backend), "--json", "capabilities"])
                self.assertIsNone(error)
                dialog = NewMissionDialog(None, FakeClient(), lambda _: None,
                                          capabilities=capabilities)
                dialog.workspace.setText("demo")
                dialog.tests.setText("python3 -m unittest")
                arguments = dialog.arguments()
                created, error = self.run_command(sys.executable, [str(backend), "--json", *arguments])
                self.assertIsNone(error)
                self.assertEqual("queued", created["state"])
                # The provider the dialog named is the one the engine recorded.
                # Asserting a literal "codex" here would pin the coupling
                # Phase 2 removed and break whenever a provider is added.
                # provider_id, not `config.runtime`: runtime is the legacy
                # spelling and a provider is free to map to a different one.
                self.assertEqual(arguments[arguments.index("--provider") + 1],
                                 created["provider_id"])
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
        page = self.welcome.AgentSetupPage(lambda _: None)
        self.assertIn("grok-bot", page.coding_agents)
        page.deleteLater()

    def test_ice_select_all_does_not_enable_grok_download(self):
        values = []
        with patch.object(self.welcome, "ELEMENT", "ice"):
            page = self.welcome.AgentSetupPage(values.append)
            self.assertFalse(hasattr(page, "choice"))
            page._toggle_all_agents(True)
            page._submit()
            self.assertFalse(values[0]["coding_agents"]["grok-bot"])
            page.deleteLater()

    def test_profile_disclosures_remain_readable_at_minimum_window(self):
        submitted = []
        page = self.welcome.ProfilePage(submitted.append)
        page.resize(940, 680)
        page.show()
        QTest.qWait(100)
        descriptions = [label for label in page.profile_scroll.widget().findChildren(QLabel) if label.wordWrap()]
        self.assertEqual(len(self.welcome.PROFILE_PRESETS), len(descriptions))
        for label in descriptions:
            self.assertGreaterEqual(label.height(), label.heightForWidth(label.width()), label.text())
        self.assertGreater(page.profile_scroll.verticalScrollBar().maximum(), 0)
        first_checkbox, key = page.checks[0]
        first_checkbox.setChecked(True)
        page.profile_scroll.verticalScrollBar().setValue(page.profile_scroll.verticalScrollBar().maximum())
        submit = next(button for button in page.findChildren(QPushButton) if button.text().startswith("Apply presets"))
        self.assertLessEqual(submit.geometry().bottom(), page.height())
        QTest.mouseClick(submit, Qt.MouseButton.LeftButton)
        self.assertEqual([[key]], submitted)
        page.close()
        page.deleteLater()

    def test_all_wallpaper_choices_are_reachable_without_overlap(self):
        wallpapers = [f"/usr/share/wallpapers/Umbra{i}/contents/images/3840x2160.jpg" for i in range(11)]
        with patch("glob.glob", return_value=wallpapers):
            page = self.welcome.AccentPage(lambda *_: None)
        page.resize(940, 680)
        page.show()
        QTest.qWait(100)
        self.assertLessEqual(page.width(), 940)
        self.assertLessEqual(page.height(), 680)
        for left, right in zip(page._wp_btns, page._wp_btns[1:]):
            self.assertLess(left.geometry().right(), right.geometry().left())
        scrollbar = page.wallpaper_scroll.horizontalScrollBar()
        self.assertGreater(scrollbar.maximum(), 0)
        scrollbar.setValue(scrollbar.maximum())
        last = page._wp_btns[-1]
        viewport = page.wallpaper_scroll.viewport()
        origin = last.mapTo(viewport, last.rect().topLeft())
        self.assertGreaterEqual(origin.x(), 0)
        self.assertLessEqual(origin.x() + last.width(), viewport.width())
        with patch.object(self.welcome.subprocess, "Popen"):
            QTest.mouseClick(last, Qt.MouseButton.LeftButton)
        self.assertTrue(last.isChecked())
        self.assertEqual(1, sum(button.isChecked() for button in page._wp_btns))
        page.close()
        page.deleteLater()

    def test_welcome_and_agents_fit_laptop(self):
        for page in (self.welcome.WelcomePage(lambda: None), self.welcome.AgentSetupPage(lambda _: None)):
            page.resize(1080, 690)
            page.show()
            APP.processEvents()
            self.assertLessEqual(page.height(), 700)
            self.assertLessEqual(page.width(), 1100)
            page.close()
            page.deleteLater()


if __name__ == "__main__":
    unittest.main()
