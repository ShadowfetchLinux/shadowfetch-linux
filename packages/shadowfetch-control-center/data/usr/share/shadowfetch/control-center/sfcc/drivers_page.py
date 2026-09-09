"""Drivers — hardware at rest, from the fact file.

The GPU table renders /var/lib/shadowfetch/hwscan.json exactly as scanned:
every VRAM number carries its source label (measured / estimated / shares
system RAM / measured after driver install).  The only action verbs are
"Install NVIDIA driver" (the existing shadowfetch-gpu flow, apt-wrapped so
Phoenix Points cover it) and "Open printer settings" (hidden when
print-manager is not installed).  Wi-Fi devices missing firmware are worded
"may need firmware", never "broken"; unbound devices are named honestly
with no fake fix button.
"""

import subprocess
from pathlib import Path

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QScrollArea,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from sfcc import busutil, theme
from sfcc.theme import Card, label

_PRINTER_KCM = Path("/usr/share/applications/kcm_printer_manager.desktop")


def _vram_text(gpu: dict) -> str:
    source = str(gpu.get("vram_source") or "unknown")
    vram_gb = gpu.get("vram_gb")
    if source == "shared":
        return "shares system RAM"
    if vram_gb is None:
        return "measured after driver install"
    label_map = {"sysfs": "measured", "nvml-smi": "measured",
                 "vulkan": "estimated"}
    src = label_map.get(source, source)
    try:
        return f"{float(vram_gb):g} GB ({src})"
    except (TypeError, ValueError):
        return "measured after driver install"


class DriversPage(QWidget):
    """The Drivers section."""

    def __init__(self):
        super().__init__()
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        outer.addWidget(scroll)
        body = QWidget()
        scroll.setWidget(body)
        self.root = QVBoxLayout(body)
        self.root.setContentsMargins(24, 18, 24, 18)
        self.root.setSpacing(14)

        head = QHBoxLayout()
        head.addWidget(label("Graphics", "subtitle"))
        head.addStretch(1)
        rescan = QPushButton("Re-scan hardware")
        rescan.setObjectName("quiet")
        rescan.setFixedHeight(28)
        rescan.clicked.connect(self._rescan)
        head.addWidget(rescan)
        self.root.addLayout(head)

        self.gpu_table = QTableWidget(0, 3)
        self.gpu_table.setHorizontalHeaderLabels(["Device", "Driver", "VRAM"])
        self.gpu_table.verticalHeader().hide()
        self.gpu_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.gpu_table.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        self.gpu_table.setShowGrid(False)
        self.gpu_table.setMinimumHeight(96)
        header = self.gpu_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.root.addWidget(self.gpu_table)
        self.gpu_note = label("", "detail", wrap=True)
        self.root.addWidget(self.gpu_note)

        self.nvidia_card = Card()
        self.nvidia_card.setObjectName("banner")
        n_lay = QVBoxLayout(self.nvidia_card)
        n_lay.setContentsMargins(16, 12, 16, 12)
        n_lay.setSpacing(6)
        n_lay.addWidget(label("NVIDIA graphics card without its driver",
                              "cardTitle"))
        n_lay.addWidget(label(
            "GPU acceleration is available after the driver install — using "
            "CPU for now. The install goes through apt, so Phoenix Points "
            "wrap it automatically.", "detail", wrap=True))
        install = QPushButton("Install NVIDIA driver")
        install.setFixedHeight(30)
        install.clicked.connect(
            lambda: busutil.terminal_command("shadowfetch-gpu"))
        n_lay.addWidget(install, alignment=Qt.AlignmentFlag.AlignLeft)
        self.nvidia_card.hide()
        self.root.addWidget(self.nvidia_card)

        # ---- printers (row hides when print-manager is absent) ------------
        if _PRINTER_KCM.exists() and busutil.installed_command("systemsettings"):
            printer = Card()
            p_lay = QHBoxLayout(printer)
            p_lay.setContentsMargins(16, 12, 16, 12)
            col = QVBoxLayout()
            col.setSpacing(2)
            col.addWidget(label("Printers", "cardTitle"))
            col.addWidget(label("Add and manage printers in System Settings.",
                                "detail"))
            p_lay.addLayout(col, 1)
            open_btn = QPushButton("Open printer settings")
            open_btn.setObjectName("quiet")
            open_btn.setFixedHeight(30)
            settings = busutil.installed_command("systemsettings")
            open_btn.clicked.connect(
                lambda: subprocess.Popen([settings, "kcm_printer_manager"]))
            p_lay.addWidget(open_btn)
            self.root.addWidget(printer)

        # ---- network devices ---------------------------------------------
        self.root.addWidget(label("Network devices", "subtitle"))
        self.net_area = QVBoxLayout()
        self.net_area.setSpacing(6)
        self.root.addLayout(self.net_area)
        self._net_widgets: list[QWidget] = []

        # ---- radio kill switches ------------------------------------------
        self.root.addWidget(label("Wireless radios", "subtitle"))
        self.radio_area = QVBoxLayout()
        self.radio_area.setSpacing(6)
        self.root.addLayout(self.radio_area)
        self._radio_widgets: list[QWidget] = []

        self.root.addStretch(1)
        self.refresh()

    def _rescan(self) -> None:
        self.setCursor(Qt.CursorShape.WaitCursor)
        try:
            self.refresh(rescan=True)
        finally:
            self.unsetCursor()

    def refresh(self, rescan: bool = False) -> None:
        hw = busutil.load_hwscan(rescan=rescan)
        gpus = (hw or {}).get("gpus") or []
        self.gpu_table.setRowCount(len(gpus))
        missing_driver = False
        for r, gpu in enumerate(gpus):
            if not isinstance(gpu, dict):
                continue
            vendor = str(gpu.get("vendor") or "").strip()
            name = str(gpu.get("name") or "graphics device").strip()
            device = f"{vendor} {name}".strip()
            self.gpu_table.setItem(r, 0, QTableWidgetItem(device))
            driver = str(gpu.get("driver") or "none")
            self.gpu_table.setItem(r, 1, QTableWidgetItem(driver))
            self.gpu_table.setItem(r, 2, QTableWidgetItem(_vram_text(gpu)))
            flags = gpu.get("flags") or []
            if "missing-driver" in flags:
                missing_driver = True
        if not gpus:
            self.gpu_note.setText(
                "Hardware scan not available yet — press Re-scan hardware. "
                "The scan reads local facts only and takes under two "
                "seconds.")
        else:
            self.gpu_note.setText(
                "VRAM numbers are labelled with how they were obtained; "
                "when the scanner cannot know yet, it says so.")
        self.nvidia_card.setVisible(missing_driver)
        self._render_network()
        self._render_radios()

    def _render_network(self) -> None:
        for widget in self._net_widgets:
            widget.setParent(None)
            widget.deleteLater()
        self._net_widgets = []

        def add(widget: QWidget) -> None:
            self.net_area.addWidget(widget)
            self._net_widgets.append(widget)

        devices = busutil.nm_devices()
        if devices is None:
            add(label("NetworkManager did not answer — no device list.",
                      "detail"))
            return
        if not devices:
            add(label("No network devices found.", "detail"))
            return
        for dev in devices:
            row = Card()
            lay = QHBoxLayout(row)
            lay.setContentsMargins(14, 9, 14, 9)
            text = f"{dev['interface']} — {dev['type']} — driver {dev['driver']}"
            lay.addWidget(label(text))
            lay.addStretch(1)
            if dev["firmware_missing"]:
                warn = label("may need firmware", "statusWarn")
                lay.addWidget(warn)
            elif dev["driver"] == "none":
                lay.addWidget(label("no driver bound", "detail"))
            add(row)

    def _render_radios(self) -> None:
        for widget in self._radio_widgets:
            widget.setParent(None)
            widget.deleteLater()
        self._radio_widgets = []

        def add(widget: QWidget) -> None:
            self.radio_area.addWidget(widget)
            self._radio_widgets.append(widget)

        radios = busutil.rfkill_devices()
        if not radios:
            add(label("No wireless radios detected.", "detail"))
            return
        for radio in radios:
            row = Card()
            lay = QHBoxLayout(row)
            lay.setContentsMargins(14, 9, 14, 9)
            kind = {"wlan": "Wi-Fi", "bluetooth": "Bluetooth"}.get(
                radio["type"], radio["type"])
            lay.addWidget(label(f"{radio['name']} — {kind}"))
            lay.addStretch(1)
            if radio["hard"]:
                lay.addWidget(label("switched off in hardware", "detail"))
            elif radio["soft"]:
                lay.addWidget(label("switched off in software", "detail"))
            else:
                on = label("on", "status")
                lay.addWidget(on)
            add(row)
