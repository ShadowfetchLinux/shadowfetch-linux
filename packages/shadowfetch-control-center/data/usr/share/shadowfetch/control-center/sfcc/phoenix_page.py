"""Recover — the Phoenix page.

Lists Phoenix Points via snapperd's D-Bus, restores through the crash-atomic
pkexec /usr/libexec/phoenix-restore (which is supported and tested from
inside a "Last Known Good Flame" overlay session), maps one checkbox 1:1 to
DISABLE_APT_SNAPSHOT in /etc/default/snapper, and shows the honest ext4
banner when the root filesystem is not Btrfs.

The repair toolkit (software-source repair, driver reinstall, desktop
reset, recovery report, the text-mode recovery menu) is available on every
filesystem.
"""

import datetime
import os
import shutil
import subprocess
import tarfile
import tempfile
import time
from pathlib import Path

from PyQt6.QtCore import QProcess, Qt
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from sfcc import busutil, theme
from sfcc.theme import Card, ProcessDialog, label

EXT4_BANNER = "Phoenix Points require the Btrfs filesystem (chosen at install)."
OVERLAY_BANNER = ("You are riding a Phoenix Point — pick the Point below and "
                  "press Restore to make it permanent. Restore works from "
                  "this session; all changes land on the real system, not "
                  "this temporary one.")

_RESET_FILES = (
    "plasma-org.kde.plasma.desktop-appletsrc",
    "plasmashellrc",
    "kwinrc",
    "kwinrulesrc",
    "kglobalshortcutsrc",
    "plasmarc",
    "kscreenlockerrc",
    "ksmserverrc",
)


class ToolCard(Card):
    def __init__(self, title: str, detail: str, button: str, callback):
        super().__init__()
        self.setMinimumHeight(120)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 11, 14, 11)
        lay.setSpacing(5)
        lay.addWidget(label(title, "cardTitle"))
        copy = label(detail, "detail", wrap=True)
        lay.addWidget(copy)
        lay.addStretch(1)
        action = QPushButton(button)
        action.setFixedHeight(30)
        action.clicked.connect(callback)
        lay.addWidget(action, alignment=Qt.AlignmentFlag.AlignLeft)


class PhoenixPage(QWidget):
    """The Recover section."""

    def __init__(self):
        super().__init__()
        self._is_btrfs = busutil.root_fstype() == "btrfs"
        self._overlay = busutil.overlay_boot()
        self._preselect: int | None = busutil.overlay_point() if self._overlay else None

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        outer.addWidget(scroll)
        body = QWidget()
        scroll.setWidget(body)
        root = QVBoxLayout(body)
        root.setContentsMargins(24, 18, 24, 18)
        root.setSpacing(14)

        # ---- banners ------------------------------------------------------
        if self._overlay:
            banner = Card()
            banner.setObjectName("banner")
            b_lay = QVBoxLayout(banner)
            b_lay.setContentsMargins(16, 12, 16, 12)
            b_lay.addWidget(label("Riding a Phoenix Point", "cardTitle"))
            b_lay.addWidget(label(OVERLAY_BANNER, "detail", wrap=True))
            root.addWidget(banner)
        if not self._is_btrfs:
            banner = Card()
            banner.setObjectName("bannerWarn")
            b_lay = QVBoxLayout(banner)
            b_lay.setContentsMargins(16, 12, 16, 12)
            b_lay.addWidget(label("Phoenix Points unavailable", "cardTitle"))
            b_lay.addWidget(label(
                EXT4_BANNER + " The repair toolkit below still works.",
                "detail", wrap=True))
            root.addWidget(banner)

        # ---- Points list --------------------------------------------------
        if self._is_btrfs:
            points_card = Card()
            p_lay = QVBoxLayout(points_card)
            p_lay.setContentsMargins(16, 14, 16, 14)
            p_lay.setSpacing(10)
            head = QHBoxLayout()
            head.addWidget(label("Phoenix Points", "cardTitle"))
            head.addStretch(1)
            refresh = QPushButton("Refresh")
            refresh.setObjectName("quiet")
            refresh.setFixedHeight(28)
            refresh.clicked.connect(self.reload_points)
            head.addWidget(refresh)
            self.restore_btn = QPushButton("Restore selected Point")
            self.restore_btn.setFixedHeight(28)
            self.restore_btn.setEnabled(False)
            self.restore_btn.clicked.connect(self._restore_clicked)
            head.addWidget(self.restore_btn)
            p_lay.addLayout(head)

            self.table = QTableWidget(0, 4)
            self.table.setHorizontalHeaderLabels(["#", "When", "Type", "Description"])
            self.table.verticalHeader().hide()
            self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
            self.table.setSelectionBehavior(
                QAbstractItemView.SelectionBehavior.SelectRows)
            self.table.setSelectionMode(
                QAbstractItemView.SelectionMode.SingleSelection)
            self.table.setShowGrid(False)
            self.table.setMinimumHeight(240)
            header = self.table.horizontalHeader()
            header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
            for col in (0, 1, 2):
                header.setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)
            self.table.itemSelectionChanged.connect(self._selection_changed)
            p_lay.addWidget(self.table)

            self.points_note = label("", "detail", wrap=True)
            p_lay.addWidget(self.points_note)

            self.apt_toggle = QCheckBox(
                "Create a Phoenix Point before every software change (recommended)")
            self.apt_toggle.setChecked(busutil.apt_snapshots_enabled())
            self.apt_toggle.clicked.connect(self._toggle_apt_snapshots)
            p_lay.addWidget(self.apt_toggle)
            root.addWidget(points_card)

        # ---- repair toolkit -----------------------------------------------
        root.addWidget(label("Repair toolkit", "subtitle"))
        tools = QGridLayout()
        tools.setSpacing(12)
        cards = [
            ToolCard("Repair software sources",
                     "Restores the known-good package sources and signing "
                     "keys from the local recovery copy — no network needed "
                     "for the repair itself.",
                     "Repair sources", self._repair_sources),
            ToolCard("Reinstall graphics drivers",
                     "Re-runs the driver setup. On NVIDIA this installs "
                     "packages with apt, so it is wrapped in Phoenix Points "
                     "automatically.",
                     "Reinstall drivers",
                     lambda: busutil.terminal_command("shadowfetch-gpu")),
            ToolCard("Reset desktop layout",
                     "Moves the Plasma panel, window and shortcut settings "
                     "to a timestamped backup and restarts the desktop. "
                     "Personal files are not touched; undo by moving the "
                     "backup back.",
                     "Reset desktop", self._reset_desktop),
            ToolCard("Export recovery report",
                     "Bundles recent error logs, package history and disk "
                     "layout into one archive in your home folder — handy "
                     "when asking for help.",
                     "Export report", self._export_report),
            ToolCard("Open recovery menu",
                     "The text-mode Graphics & Recovery menu: snapshots, "
                     "failed services and critical logs in one place.",
                     "Open recovery menu",
                     lambda: busutil.terminal_command("shadowfetch-recovery")),
        ]
        for index, card in enumerate(cards):
            tools.addWidget(card, index // 2, index % 2)
        root.addLayout(tools)
        root.addStretch(1)

        if self._is_btrfs:
            self.reload_points()

    # ---- routing ----------------------------------------------------------
    def route(self, parts: list[str]) -> None:
        for part in parts:
            if part.startswith("point="):
                try:
                    self._preselect = int(part.split("=", 1)[1])
                except ValueError:
                    continue
                if self._is_btrfs:
                    self.reload_points()

    # ---- Points -----------------------------------------------------------
    def reload_points(self) -> None:
        points = busutil.snapper_list()
        if points is None:
            self.table.setRowCount(0)
            self.points_note.setText(
                "The snapshot service (snapperd) did not answer. On a fresh "
                "install the first Point appears after first boot completes.")
            self.restore_btn.setEnabled(False)
            return
        points = [p for p in points if p["num"] != 0]  # 0 is snapper's "current"
        points.sort(key=lambda p: p["num"], reverse=True)
        self.points_note.setText(
            f"{len(points)} Points. Restoring returns system files to that "
            "moment; your home folder is not touched.")
        self.table.setRowCount(len(points))
        select_row = None
        for r, point in enumerate(points):
            num_item = QTableWidgetItem(str(point["num"]))
            self.table.setItem(r, 0, num_item)
            when = "—"
            if point.get("date"):
                try:
                    when = datetime.datetime.fromtimestamp(
                        point["date"]).strftime("%Y-%m-%d %H:%M")
                except (OverflowError, OSError, ValueError):
                    when = "—"
            self.table.setItem(r, 1, QTableWidgetItem(when))
            self.table.setItem(r, 2, QTableWidgetItem(point["type"]))
            desc = point.get("description") or ""
            userdata = point.get("userdata") or {}
            if userdata.get("fireproof") == "pre":
                desc = desc or "Fireproof: before update"
            self.table.setItem(r, 3, QTableWidgetItem(desc))
            if self._preselect is not None and point["num"] == self._preselect:
                select_row = r
        if select_row is not None:
            self.table.selectRow(select_row)

    def _selection_changed(self) -> None:
        self.restore_btn.setEnabled(bool(self.table.selectedItems()))

    def _selected_point(self) -> int | None:
        items = self.table.selectedItems()
        if not items:
            return None
        try:
            return int(self.table.item(items[0].row(), 0).text())
        except (AttributeError, ValueError):
            return None

    def _restore_clicked(self) -> None:
        num = self._selected_point()
        if num is None:
            return
        if not os.access(busutil.PHOENIX_RESTORE, os.X_OK):
            QMessageBox.warning(
                self, "Phoenix",
                "The restore tool (/usr/libexec/phoenix-restore) is not "
                "installed. Install the shadowfetch-phoenix package first.")
            return
        when = self.table.item(self.table.currentRow(), 1)
        when_text = when.text() if when else "that moment"
        answer = QMessageBox.question(
            self, "Restore Phoenix Point",
            f"Restore Phoenix Point #{num}?\n\n"
            f"System files return to how they were on {when_text}. Personal "
            "files in your home folder are not touched. The replaced system "
            "is kept aside briefly and cleaned up automatically.\n\n"
            "A reboot finishes the restore.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel)
        if answer != QMessageBox.StandardButton.Yes:
            return
        dialog = ProcessDialog(
            self, f"Restoring Phoenix Point #{num}",
            [busutil.PKEXEC, busutil.PHOENIX_RESTORE, str(num)],
            "The restore is crash-safe: at every instant a bootable system "
            "exists, even if power is lost.")
        dialog.completed.connect(lambda code: self._restore_done(code))
        dialog.start()
        dialog.exec()

    def _restore_done(self, code: int) -> None:
        if code != 0:
            return
        answer = QMessageBox.question(
            self, "Restore complete",
            "The Point has been restored. Reboot now to start the restored "
            "system?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No)
        if answer == QMessageBox.StandardButton.Yes:
            subprocess.Popen(["systemctl", "reboot"])

    # ---- apt-snapshot toggle ----------------------------------------------
    def _toggle_apt_snapshots(self, checked: bool) -> None:
        argv = busutil.apt_snapshot_toggle_argv(enable=checked)
        if argv is None:
            # Stage V: the old code answered a missing root helper with
            # `pkexec /bin/sh -c <script>`.  A missing helper is now an
            # honest failure -- putting the switch back where it was -- and
            # never a wider grant.
            self.apt_toggle.blockSignals(True)
            self.apt_toggle.setChecked(busutil.apt_snapshots_enabled())
            self.apt_toggle.blockSignals(False)
            QMessageBox.warning(
                self, "Phoenix",
                "This setting cannot be changed here: the Phoenix helper "
                "that writes it (%s) is not installed."
                % busutil.PHOENIX_APT_SNAPSHOT)
            return
        proc = QProcess(self)

        def done(code, _status):
            actual = busutil.apt_snapshots_enabled()
            self.apt_toggle.blockSignals(True)
            self.apt_toggle.setChecked(actual)
            self.apt_toggle.blockSignals(False)
            if code != 0:
                QMessageBox.warning(
                    self, "Phoenix",
                    "The setting was not changed (authorisation was "
                    "cancelled or the write failed).")

        proc.finished.connect(done)
        proc.start(argv[0], argv[1:])

    # ---- toolkit actions --------------------------------------------------
    def _repair_sources(self) -> None:
        if os.access(busutil.PHOENIX_APT_REPAIR, os.X_OK):
            dialog = ProcessDialog(
                self, "Repairing software sources",
                [busutil.PKEXEC, busutil.PHOENIX_APT_REPAIR],
                "Replaces the package source lists and signing keys with the "
                "known-good copies shipped on this system, then validates "
                "with apt-get update.")
            dialog.start()
            dialog.exec()
        else:
            QMessageBox.information(
                self, "Phoenix",
                "The source-repair tool (/usr/libexec/phoenix-apt-repair) is "
                "not installed. Install the shadowfetch-phoenix package "
                "first.")

    def _reset_desktop(self) -> None:
        answer = QMessageBox.question(
            self, "Reset desktop layout",
            "Move the Plasma desktop settings to a backup folder and restart "
            "the desktop?\n\nPanels, wallpaper layout, window rules and "
            "shortcuts return to defaults. Personal files are untouched, and "
            "the backup lets you undo this by hand.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel)
        if answer != QMessageBox.StandardButton.Yes:
            return
        stamp = time.strftime("%Y%m%d-%H%M%S")
        backup = Path.home() / ".local/share/shadowfetch" / f"desktop-reset-{stamp}"
        backup.mkdir(parents=True, exist_ok=True)
        config = Path.home() / ".config"
        moved = 0
        for name in _RESET_FILES:
            src = config / name
            if src.exists():
                try:
                    shutil.move(str(src), str(backup / name))
                    moved += 1
                except OSError:
                    pass
        kdedefaults = config / "kdedefaults"
        if kdedefaults.exists():
            try:
                shutil.move(str(kdedefaults), str(backup / "kdedefaults"))
                moved += 1
            except OSError:
                pass
        restarted = subprocess.run(
            ["systemctl", "--user", "restart", "plasma-plasmashell.service"],
            timeout=15, check=False).returncode == 0
        if not restarted and shutil.which("plasmashell"):
            subprocess.Popen(["plasmashell", "--replace"],
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
        QMessageBox.information(
            self, "Reset desktop layout",
            f"Moved {moved} settings item(s) to:\n{backup}\n\n"
            "Log out and back in if anything still looks off.")

    def _export_report(self) -> None:
        stamp = time.strftime("%Y%m%d-%H%M")
        target = Path.home() / f"shadowfetch-recovery-report-{stamp}.tar.gz"
        self.setCursor(Qt.CursorShape.WaitCursor)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                tmp_path = Path(tmp)
                collected: list[str] = []

                def run_to(name: str, argv: list[str]) -> None:
                    try:
                        out = subprocess.run(argv, capture_output=True, text=True,
                                             timeout=15, check=False)
                        (tmp_path / name).write_text(
                            out.stdout or out.stderr or "(no output)\n",
                            encoding="utf-8")
                        collected.append(name)
                    except (OSError, subprocess.TimeoutExpired):
                        (tmp_path / name).write_text(
                            f"could not run: {' '.join(argv)}\n", encoding="utf-8")
                        collected.append(name)

                run_to("errors-this-boot.txt",
                       ["journalctl", "-b", "-p", "err", "--no-pager"])
                run_to("kernel-this-boot.txt",
                       ["journalctl", "-k", "-b", "--no-pager", "-n", "2000"])
                run_to("failed-services.txt",
                       ["systemctl", "--failed", "--no-pager"])
                run_to("disks.txt", ["lsblk", "-f"])
                run_to("disk-space.txt", ["df", "-h"])
                run_to("btrfs-usage.txt",
                       ["btrfs", "filesystem", "usage", "/"])
                for logfile in ("/var/log/apt/history.log",):
                    try:
                        shutil.copy(logfile, tmp_path / Path(logfile).name)
                        collected.append(Path(logfile).name)
                    except OSError:
                        pass
                points = busutil.snapper_list()
                if points is not None:
                    import json as _json
                    (tmp_path / "phoenix-points.json").write_text(
                        _json.dumps(points, indent=1), encoding="utf-8")
                    collected.append("phoenix-points.json")
                try:
                    shutil.copy(busutil.HWSCAN_JSON, tmp_path / "hwscan.json")
                    collected.append("hwscan.json")
                except OSError:
                    pass
                (tmp_path / "README.txt").write_text(
                    "Shadowfetch recovery report, created "
                    f"{time.strftime('%Y-%m-%d %H:%M')}\n"
                    "Shadowfetch Linux " + busutil.sf_version() + "\n\n"
                    "Files that needed root (SMART detail, full dmesg) are "
                    "not included; the text-mode recovery menu can show "
                    "those.\n\nContents:\n  " + "\n  ".join(sorted(collected)) +
                    "\n", encoding="utf-8")
                with tarfile.open(target, "w:gz") as tar:
                    for item in tmp_path.iterdir():
                        tar.add(item, arcname=f"recovery-report/{item.name}")
        finally:
            self.unsetCursor()
        QMessageBox.information(
            self, "Recovery report",
            f"Report saved to:\n{target}\n\nIt contains logs and disk "
            "layout, no personal documents.")
