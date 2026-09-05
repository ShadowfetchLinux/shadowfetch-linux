#!/usr/bin/env python3
"""Operate the installed Qt UI in a disposable logged-in release QA guest.

No fixtures or service substitutions: every page calls the installed helpers.
Write an action name to OUTPUT/action to advance; OUTPUT/status.json records
the visible state. Capture the whole guest frame with vm_harness.sh separately.
Qt window PNGs are additional layout evidence, not whole-desktop captures.
"""
import argparse
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import sys
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--mission", required=True)
parser.add_argument("--output", required=True, type=Path)
args = parser.parse_args()
args.output.mkdir(parents=True, exist_ok=True)
sys.path.insert(0, "/usr/share/shadowfetch/control-center")

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import QApplication, QMessageBox
from sfcc.app import ControlCenterWindow

app = QApplication([sys.argv[0]])
app.setQuitOnLastWindowClosed(False)
started = time.monotonic()
window = ControlCenterWindow()
construction_seconds = time.monotonic() - started
page = window.pages[0]
window.show()
window.open_route("missions:" + args.mission)
welcome = None
last_tick = time.monotonic()
gaps = []
stage = "starting"
last_command = None
checks = []


def record(name, passed, detail):
    checks.append({"name": name, "pass": bool(passed), "detail": detail})


def visible_window():
    return welcome if welcome is not None and welcome.isVisible() else window


def status(error=None):
    active = visible_window()
    mission = page.selected or {}
    data = {
        "stage": stage,
        "error": error,
        "pid": os.getpid(),
        "mission": mission.get("id"),
        "state": mission.get("state"),
        "results": [page.artifacts.item(i).data(Qt.ItemDataRole.UserRole) for i in range(page.artifacts.count())],
        "diff_characters": len(page.diff.toPlainText()),
        "notice": page.notice.text(),
        "active_window": active.windowTitle(),
        "window_size": [active.width(), active.height()],
        "screen_size": [app.primaryScreen().size().width(), app.primaryScreen().size().height()],
        "construction_seconds": round(construction_seconds, 3),
        "event_loop_max_gap_seconds": round(max(gaps, default=0), 3),
        "event_loop_samples": len(gaps),
        "checks": checks,
    }
    temporary = args.output / "status.tmp"
    temporary.write_text(json.dumps(data, indent=2) + "\n")
    temporary.replace(args.output / "status.json")
    active.grab().save(str(args.output / (stage + "-window.png")))


def show_control():
    if welcome is not None:
        welcome.hide()
    window.showNormal()
    window.raise_()
    window.activateWindow()


def load_welcome():
    global welcome
    if welcome is None:
        path = "/usr/bin/shadowfetch-welcome"
        loader = importlib.machinery.SourceFileLoader("sf_qa_welcome", path)
        spec = importlib.util.spec_from_loader(loader.name, loader)
        module = importlib.util.module_from_spec(spec)
        loader.exec_module(module)
        welcome = module.ShadowfetchWelcome(force=True)
        welcome.resize(1080, 720)
    window.hide()
    welcome.showNormal()
    welcome.raise_()
    welcome.activateWindow()


def execute(command):
    global stage
    stage = command
    if command in ("mission-results", "mission-diff", "mission-overview", "mission-activity"):
        show_control()
        window.open_route("missions:" + args.mission)
        index = {"mission-overview": 0, "mission-activity": 1, "mission-diff": 2, "mission-results": 3}[command]
        QTest.mouseClick(page.tabs.tabBar(), Qt.MouseButton.LeftButton,
                         pos=page.tabs.tabBar().tabRect(index).center())
    elif command == "mission-accept":
        record("accept_available", page.actions["accept"].isEnabled(), (page.selected or {}).get("state"))
        QTest.mouseClick(page.actions["accept"], Qt.MouseButton.LeftButton)
    elif command == "mission-restore-dialog":
        record("restore_available", page.actions["undo"].isEnabled(), (page.selected or {}).get("state"))
        # The confirmation runs a nested Qt event loop; this callback keeps the
        # controller available to inspect and explicitly confirm the real dialog.
        QTimer.singleShot(0, lambda: QTest.mouseClick(page.actions["undo"], Qt.MouseButton.LeftButton))
    elif command in ("confirm-restore", "cancel-restore"):
        dialog = app.activeModalWidget()
        if not isinstance(dialog, QMessageBox):
            raise RuntimeError("The real restore confirmation is not visible")
        record("restore_confirmation", "Restore" in dialog.windowTitle(), dialog.text())
        choice = QMessageBox.StandardButton.Yes if command == "confirm-restore" else QMessageBox.StandardButton.Cancel
        QTest.mouseClick(dialog.button(choice), Qt.MouseButton.LeftButton)
    elif command == "grok-setup":
        show_control()
        window.open_route("grok-bot")
    elif command == "local-ai":
        show_control()
        window.open_route("local-ai")
    elif command in ("welcome", "welcome-agents", "welcome-agent-select"):
        load_welcome()
        welcome.stack.setCurrentWidget(welcome.welcome if command == "welcome" else welcome.buzz)
        if command == "welcome-agent-select":
            checkbox = welcome.buzz.coding_agents["grok-bot"]
            record("native_grok_opt_in_default", not checkbox.isChecked(), "Before user checkbox click")
            QTest.mouseClick(checkbox, Qt.MouseButton.LeftButton)
            record("native_grok_selectable", checkbox.isChecked(), "Real Qt click, no installation step submitted")
    elif command in ("size-laptop", "size-desktop"):
        active = visible_window()
        width, height = (1080, 700) if command == "size-laptop" else (1440, 900)
        active.resize(width, height)
        available = app.primaryScreen().availableGeometry()
        frame = active.frameGeometry()
        frame.moveCenter(available.center())
        active.move(frame.topLeft())
        active.raise_()
        active.activateWindow()
        record(command, active.width() == width and active.height() == height, [active.width(), active.height()])
    elif command == "quit":
        status()
        app.quit()
        return
    else:
        raise ValueError("Unknown QA action: " + command)
    QTimer.singleShot(1800, status)


def tick():
    global last_tick, last_command
    now = time.monotonic()
    gaps.append(now - last_tick)
    last_tick = now
    path = args.output / "action"
    if path.exists():
        command = path.read_text().strip()
        path.unlink()
        last_command = command
        try:
            execute(command)
        except Exception as exc:
            record(command, False, str(exc))
            status(str(exc))


timer = QTimer()
timer.setInterval(100)
timer.timeout.connect(tick)
timer.start()
QTimer.singleShot(4000, status)
sys.exit(app.exec())
