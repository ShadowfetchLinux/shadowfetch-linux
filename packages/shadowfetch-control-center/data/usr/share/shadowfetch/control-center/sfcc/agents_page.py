"""Private workspace folders and measured hardware facts."""
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import QHBoxLayout, QPushButton, QScrollArea, QVBoxLayout, QWidget
from sfcc import busutil
from sfcc.mission_client import workspaces_root
from sfcc.theme import Card, label


class WorkspaceRow(Card):
    def __init__(self, name, on_open):
        super().__init__()
        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        copy = QVBoxLayout()
        copy.addWidget(label(name, "cardTitle"))
        copy.addWidget(label("Private project folder", "detail"))
        layout.addLayout(copy, 1)
        button = QPushButton("Open")
        button.clicked.connect(lambda: on_open(name))
        layout.addWidget(button)


class AgentsPage(QWidget):
    """Workspaces page; class name retained for internal compatibility."""
    def __init__(self, _firewatch, _open_route):
        super().__init__()
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
        banner = Card()
        hardware = QVBoxLayout(banner)
        head = QHBoxLayout()
        head.addWidget(label("This computer", "cardTitle"))
        head.addStretch(1)
        rescan = QPushButton("Re-scan")
        rescan.setObjectName("quiet")
        rescan.clicked.connect(self._rescan)
        head.addWidget(rescan)
        hardware.addLayout(head)
        self.hardware = label("", "detail", wrap=True)
        hardware.addWidget(self.hardware)
        root.addWidget(banner)
        head = QHBoxLayout()
        head.addWidget(label("Workspaces", "subtitle"))
        head.addStretch(1)
        create = QPushButton("New workspace")
        create.clicked.connect(lambda: busutil.terminal_command("shadowfetch-agent-workspace"))
        head.addWidget(create)
        root.addLayout(head)
        root.addWidget(label("Create a project folder, open its files, then choose it when starting a mission. Grok Bot and coding agents are available from their own launchers.", "detail", wrap=True))
        self.ws_area = QVBoxLayout()
        root.addLayout(self.ws_area)
        self._ws_widgets = []
        root.addStretch(1)
        self._ws_timer = QTimer(self)
        self._ws_timer.setInterval(5000)
        self._ws_timer.timeout.connect(self._reload_workspaces)
        self._render_hwscan(busutil.load_hwscan())
        self._reload_workspaces()

    def showEvent(self, event):
        super().showEvent(event)
        self._reload_workspaces()
        self._ws_timer.start()

    def hideEvent(self, event):
        self._ws_timer.stop()
        super().hideEvent(event)

    def _rescan(self):
        self.setCursor(Qt.CursorShape.WaitCursor)
        try:
            self._render_hwscan(busutil.load_hwscan(rescan=True))
        finally:
            self.unsetCursor()

    def _render_hwscan(self, hw):
        if not hw:
            self.hardware.setText("Hardware scan not available yet. Re-scan reads local hardware facts.")
            return
        bits = [str((hw.get("cpu") or {}).get("model") or "Processor unknown")]
        if hw.get("ram_gb") is not None:
            bits.append(f"{hw['ram_gb']} GB RAM")
        if hw.get("scanned_at"):
            bits.append(f"scanned {hw['scanned_at']}")
        self.hardware.setText(" · ".join(bits))

    def _reload_workspaces(self):
        for widget in self._ws_widgets:
            self.ws_area.removeWidget(widget)
            widget.setParent(None)
            widget.deleteLater()
        self._ws_widgets = []
        directory = workspaces_root()
        names = sorted(p.name for p in directory.iterdir()
                       if not p.name.startswith(".") and not p.is_symlink() and p.is_dir()) if directory.is_dir() else []
        for name in names:
            row = WorkspaceRow(name, self._open_ws)
            self.ws_area.addWidget(row)
            self._ws_widgets.append(row)
        if not names:
            note = label("No workspaces yet.", "detail")
            self.ws_area.addWidget(note)
            self._ws_widgets.append(note)

    @staticmethod
    def _open_ws(name):
        busutil.start_detached(["xdg-open", str(workspaces_root() / name)])
