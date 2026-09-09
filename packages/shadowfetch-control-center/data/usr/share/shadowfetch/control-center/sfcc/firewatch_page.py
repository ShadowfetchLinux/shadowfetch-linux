"""Watch — the Firewatch page.

Two tabs: Overview (sensor tiles), Heat map (the standout view — rows
arrive from firewatchd with display names and icons already resolved; the
UI never sees raw cgroup paths).

Every tile binds to exactly one source — org.shadowfetch.Firewatch1 — and
renders "— sensor not available" when a sensor is absent.  When the daemon
itself is down the page says "Firewatch is not running"; it never shows a
stale number.
"""

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QIcon
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QScrollArea,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from sfcc import busutil, theme
from sfcc.theme import Card, label


def _pick(d, *keys, default=None):
    if not isinstance(d, dict):
        return default
    for k in keys:
        if k in d and d[k] is not None:
            return d[k]
    return default


class SensorTile(Card):
    def __init__(self, title: str):
        super().__init__()
        self.setMinimumHeight(84)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 10, 14, 10)
        lay.setSpacing(3)
        lay.addWidget(label(title, "detail"))
        self._value = label("—", "big")
        lay.addWidget(self._value)
        self._extra = label("", "detail")
        lay.addWidget(self._extra)

    def set_value(self, text: str | None, extra: str = "",
                  color: str | None = None) -> None:
        if text:
            self._value.setText(text)
            self._value.setStyleSheet(f"color: {color};" if color else "")
            self._extra.setText(extra)
        else:
            self._value.setText("— sensor not available")
            self._value.setStyleSheet(
                f"color: {theme.MUTED}; font-size: 13px; font-weight: 400;")
            self._extra.setText(extra)


class FirewatchPage(QWidget):
    """The Watch section."""

    _TAB_ROUTES = {"overview": 0, "heatmap": 1, "heat-map": 1, "heat": 1}

    @classmethod
    def build(cls, context):
        return cls(context.firewatch)

    def __init__(self, firewatch: busutil.FirewatchClient):
        super().__init__()
        self._firewatch = firewatch
        firewatch.updated.connect(self._on_update)

        root = QVBoxLayout(self)
        root.setContentsMargins(24, 18, 24, 18)
        root.setSpacing(12)

        self.down_banner = Card()
        self.down_banner.setObjectName("bannerWarn")
        banner_lay = QVBoxLayout(self.down_banner)
        banner_lay.setContentsMargins(16, 12, 16, 12)
        banner_lay.addWidget(label("Firewatch is not running", "cardTitle"))
        banner_lay.addWidget(label(
            "Live sensors, the heat map and model telemetry come from the "
            "shadowfetch-firewatchd service. Until it answers, no numbers "
            "are shown — Shadowfetch does not display stale readings.",
            "detail", wrap=True))
        self.down_banner.hide()
        root.addWidget(self.down_banner)

        self.tabs = QTabWidget()
        root.addWidget(self.tabs, 1)

        # ---- Overview tab -------------------------------------------------
        overview = QWidget()
        ov_lay = QVBoxLayout(overview)
        ov_lay.setContentsMargins(12, 12, 12, 12)
        ov_lay.setSpacing(12)
        grid = QGridLayout()
        grid.setSpacing(10)
        self.tile_flame = SensorTile("Flame")
        self.tile_cpu = SensorTile("CPU load")
        self.tile_clock = SensorTile("CPU clock")
        self.tile_ram = SensorTile("Memory")
        self.tile_temp = SensorTile("Temperatures")
        self.tile_fans = SensorTile("Fans")
        self.tile_power = SensorTile("Power draw")
        self.tile_gpu = SensorTile("GPU")
        self.tile_storage = SensorTile("Storage health")
        tiles = [self.tile_flame, self.tile_cpu, self.tile_clock, self.tile_ram,
                 self.tile_temp, self.tile_fans, self.tile_power, self.tile_gpu,
                 self.tile_storage]
        for index, tile in enumerate(tiles):
            grid.addWidget(tile, index // 3, index % 3)
        ov_lay.addLayout(grid)
        health_row = QHBoxLayout()
        health_btn = QPushButton("Run health check")
        health_btn.setObjectName("quiet")
        health_btn.clicked.connect(
            lambda: busutil.terminal_command("shadowfetch-health"))
        health_row.addWidget(health_btn)
        health_row.addStretch(1)
        ov_lay.addLayout(health_row)
        ov_lay.addStretch(1)
        self.tabs.addTab(overview, "Overview")

        # ---- Heat map tab -------------------------------------------------
        heat = QWidget()
        heat_lay = QVBoxLayout(heat)
        heat_lay.setContentsMargins(12, 12, 12, 12)
        heat_lay.setSpacing(8)
        self.heat_table = QTableWidget(0, 5)
        self.heat_table.setHorizontalHeaderLabels(
            ["App", "CPU", "Memory", "VRAM", "Heat"])
        self.heat_table.verticalHeader().hide()
        self.heat_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.heat_table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows)
        self.heat_table.setShowGrid(False)
        header = self.heat_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for col in range(1, 5):
            header.setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)
        heat_lay.addWidget(self.heat_table, 1)
        self.heat_empty = label(
            "No heat-map data yet — Firewatch publishes rows a few seconds "
            "after it starts.", "detail")
        heat_lay.addWidget(self.heat_empty)
        heat_lay.addWidget(label(
            "Heat is resource heat — a load-weighted share of CPU, memory "
            "and GPU — not temperature. Memory figures labelled PSS are the "
            "precise per-app share, refreshed for the busiest rows.",
            "detail", wrap=True))
        self.tabs.addTab(heat, "Heat map")

    # ---- lifecycle --------------------------------------------------------
    def showEvent(self, event) -> None:
        super().showEvent(event)
        self._firewatch.acquire()

    def hideEvent(self, event) -> None:
        super().hideEvent(event)
        self._firewatch.release()

    def route(self, parts: list[str]) -> None:
        for part in parts:
            index = self._TAB_ROUTES.get(part.lower())
            if index is not None:
                self.tabs.setCurrentIndex(index)
                return

    # ---- rendering --------------------------------------------------------
    def _on_update(self, data: dict) -> None:
        available = data.get("available", False)
        self.down_banner.setVisible(not available)
        if not available:
            for tile in (self.tile_flame, self.tile_cpu, self.tile_clock,
                         self.tile_ram, self.tile_temp, self.tile_fans,
                         self.tile_power, self.tile_gpu, self.tile_storage):
                tile.set_value(None)
            self.heat_table.setRowCount(0)
            self.heat_empty.setText("Firewatch is not running — no rows to show.")
            self.heat_empty.show()
            return
        self._render_overview(data)
        self._render_heatmap(data.get("heatmap"))

    def _render_overview(self, data: dict) -> None:
        snapshot = data.get("snapshot") or {}
        flame = data.get("flame")
        eli = data.get("eli")
        if flame:
            color = {"warm": theme.GOLD, "hot": theme.ORANGE,
                     "inferno": theme.RED}.get(flame, theme.GOLD)
            extra = f"load index {eli:.0f}%" if eli is not None else ""
            self.tile_flame.set_value(flame.capitalize(), extra, color)
        elif eli is not None:
            self.tile_flame.set_value(f"{eli:.0f}%", "load index")
        else:
            self.tile_flame.set_value(None)

        cpu = snapshot.get("cpu")
        cpu_pct = cpu_mhz = None
        if isinstance(cpu, (int, float)):
            cpu_pct = float(cpu)
        elif isinstance(cpu, dict):
            cpu_pct = _pick(cpu, "percent", "pct", "load_pct", "usage")
            cpu_mhz = _pick(cpu, "freq_mhz", "mhz", "clock_mhz")
        if cpu_pct is None:
            cpu_pct = _pick(snapshot, "cpu_pct")
        self.tile_cpu.set_value(
            f"{float(cpu_pct):.0f}%" if cpu_pct is not None else None)
        self.tile_clock.set_value(
            f"{float(cpu_mhz) / 1000:.2f} GHz" if cpu_mhz else None)

        ram = snapshot.get("ram") or snapshot.get("mem")
        if isinstance(ram, dict):
            used = _pick(ram, "used_bytes", "used")
            total = _pick(ram, "total_bytes", "total")
            pct = _pick(ram, "percent", "pct")
            if used is not None and total:
                self.tile_ram.set_value(theme.fmt_bytes(used),
                                        f"of {theme.fmt_bytes(total)}")
            elif pct is not None:
                self.tile_ram.set_value(f"{float(pct):.0f}%")
            else:
                self.tile_ram.set_value(None)
        elif isinstance(ram, (int, float)):
            self.tile_ram.set_value(f"{float(ram):.0f}%")
        else:
            self.tile_ram.set_value(None)

        temps = snapshot.get("temps")
        if isinstance(temps, dict) and temps:
            shown = []
            for name, value in list(temps.items())[:2]:
                try:
                    shown.append(f"{float(value):.0f}°")
                except (TypeError, ValueError):
                    continue
            names = ", ".join(str(n) for n in list(temps.keys())[:2])
            self.tile_temp.set_value(" / ".join(shown) if shown else None, names)
        elif isinstance(temps, list) and temps:
            try:
                first = temps[0]
                self.tile_temp.set_value(
                    f"{float(first.get('c', first.get('value'))):.0f}°",
                    str(first.get("name", "")))
            except (AttributeError, TypeError, ValueError):
                self.tile_temp.set_value(None)
        else:
            self.tile_temp.set_value(
                None, "no thermal sensors exposed on this hardware")

        fans = snapshot.get("fans")
        if isinstance(fans, dict) and fans:
            try:
                rpm = max(float(v) for v in fans.values())
                self.tile_fans.set_value(f"{rpm:.0f} rpm",
                                         f"{len(fans)} fan(s)")
            except (TypeError, ValueError):
                self.tile_fans.set_value(None)
        elif isinstance(fans, list) and fans:
            try:
                self.tile_fans.set_value(
                    f"{float(fans[0].get('rpm')):.0f} rpm", f"{len(fans)} fan(s)")
            except (AttributeError, TypeError, ValueError):
                self.tile_fans.set_value(None)
        else:
            self.tile_fans.set_value(None, "no fan sensors detected")

        watts = _pick(snapshot, "rapl_watts", "power_watts", "watts")
        self.tile_power.set_value(
            f"{float(watts):.0f} W" if watts is not None else None,
            "CPU package" if watts is not None else "")

        gpus = snapshot.get("gpus") or snapshot.get("per_gpu") or snapshot.get("gpu")
        if isinstance(gpus, dict):
            gpus = [gpus]
        if isinstance(gpus, list) and gpus:
            gpu = gpus[0]
            busy = _pick(gpu, "busy_pct", "util_pct", "busy", "utilization")
            vused = _pick(gpu, "vram_used_bytes", "vram_used")
            vtotal = _pick(gpu, "vram_total_bytes", "vram_total")
            text = f"{float(busy):.0f}%" if busy is not None else None
            extra = ""
            if vused is not None and vtotal:
                extra = f"VRAM {theme.fmt_bytes(vused)} / {theme.fmt_bytes(vtotal)}"
            elif gpu.get("name"):
                extra = str(gpu["name"])
            self.tile_gpu.set_value(text, extra)
        else:
            self.tile_gpu.set_value(None)

        storage = self._firewatch.last.get("storage")
        self._render_storage(storage)

    def _render_storage(self, storage) -> None:
        devices = None
        if isinstance(storage, dict):
            devices = storage.get("devices") or storage.get("drives")
            if devices is None and storage:
                devices = [dict(name=k, status=v) for k, v in storage.items()
                           if isinstance(v, (str, bool))]
        elif isinstance(storage, list):
            devices = storage
        if not devices:
            self.tile_storage.set_value(None)
            return
        bad = []
        for dev in devices:
            if not isinstance(dev, dict):
                continue
            status = str(_pick(dev, "status", "health", "smart",
                               default="")).lower()
            passed = dev.get("passed")
            if passed is False or status in ("failing", "failed", "warning", "bad"):
                bad.append(str(_pick(dev, "name", "device", "dev", default="drive")))
        if bad:
            self.tile_storage.set_value("Needs attention",
                                        ", ".join(bad), theme.RED)
        else:
            self.tile_storage.set_value("Healthy",
                                        f"{len(devices)} drive(s)", theme.GREEN)

    def _render_heatmap(self, rows) -> None:
        if not isinstance(rows, list) or not rows:
            self.heat_table.setRowCount(0)
            self.heat_empty.setText(
                "No heat-map data yet — Firewatch publishes rows a few "
                "seconds after it starts.")
            self.heat_empty.show()
            return
        self.heat_empty.hide()
        self.heat_table.setRowCount(len(rows))
        for r, row in enumerate(rows):
            if not isinstance(row, dict):
                continue
            name = str(_pick(row, "display_name", "name", default="?"))
            name_item = QTableWidgetItem(name)
            icon_name = row.get("icon")
            if icon_name:
                icon = QIcon.fromTheme(str(icon_name))
                if not icon.isNull():
                    name_item.setIcon(icon)
            self.heat_table.setItem(r, 0, name_item)

            cpu = _pick(row, "cpu_pct", "cpu")
            cpu_item = QTableWidgetItem(
                f"{float(cpu):.1f}%" if cpu is not None else "—")
            cpu_item.setTextAlignment(Qt.AlignmentFlag.AlignRight |
                                      Qt.AlignmentFlag.AlignVCenter)
            self.heat_table.setItem(r, 1, cpu_item)

            pss = _pick(row, "pss_bytes", "pss")
            rss = _pick(row, "rss_bytes", "rss")
            if pss is not None:
                mem_text = f"{theme.fmt_bytes(pss)} (PSS)"
            elif rss is not None:
                mem_text = theme.fmt_bytes(rss)
            else:
                mem_text = "—"
            mem_item = QTableWidgetItem(mem_text)
            mem_item.setTextAlignment(Qt.AlignmentFlag.AlignRight |
                                      Qt.AlignmentFlag.AlignVCenter)
            self.heat_table.setItem(r, 2, mem_item)

            vram = _pick(row, "nvidia_vram_bytes", "vram_bytes")
            vram_item = QTableWidgetItem(
                theme.fmt_bytes(vram) if vram is not None else "—")
            vram_item.setTextAlignment(Qt.AlignmentFlag.AlignRight |
                                       Qt.AlignmentFlag.AlignVCenter)
            self.heat_table.setItem(r, 3, vram_item)

            tier = str(_pick(row, "heat_tier", "tier", default="")).strip()
            tier_item = QTableWidgetItem(tier.capitalize() if tier else "—")
            tier_item.setForeground(QColor(theme.tier_color(tier)))
            self.heat_table.setItem(r, 4, tier_item)
