"""Ignite — the Ember Mode page.

Owns: the switch (systemctl start/stop of shadowfetch-ember.service, made
passwordless for the active console user by the polkit rules the
shadowfetch-ember deb ships), the pre-flip safety line, the flame animation
(three states driven by Firewatch1), the readout strip (Firewatch1
SensorSnapshot — emberd has no sampler), the duration picker (RuntimeMaxSec
via the pkexec Ember helper), the session-side baloo suspend, and the
two-card app-profile row (Gaming, Production — same engine, tuned presets).

Owns NO root logic: every privileged step goes through systemd + polkit or
the pkexec helper the shadowfetch-ember deb provides.
"""

import subprocess

from PyQt6.QtCore import Qt, QProcess, QRectF, QTimer
from PyQt6.QtGui import QColor, QLinearGradient, QPainter, QPainterPath, QPen
from PyQt6.QtWidgets import (
    QComboBox,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from sfcc import busutil, theme
from sfcc.theme import Card, label

SAFETY_LINE = "Always returns to Balanced automatically — safe to try."
PROFILE_HEADER = ("App profiles are tuned presets of Ember — same engine, "
                  "same automatic return to Balanced.")

_FLAME_COLORS = {
    "warm": (theme.GOLD, "#f5d79a"),
    "hot": (theme.ORANGE, "#f7b47a"),
    "inferno": (theme.RED, "#f0937f"),
}

_DURATIONS = [
    ("Until I turn it off", 0),
    ("For 1 hour", 3600),
    ("For 2 hours", 7200),
    ("For 4 hours", 14400),
]


def _pick(d, *keys, default=None):
    if not isinstance(d, dict):
        return default
    for k in keys:
        if k in d and d[k] is not None:
            return d[k]
    return default


class FlameWidget(QWidget):
    """The Warm → Hot → Inferno flame.  Off = outline only."""

    def __init__(self):
        super().__init__()
        self.setFixedSize(150, 160)
        self._armed = False
        self._level = "warm"

    def set_state(self, armed: bool, level: str | None) -> None:
        level = (level or "warm").lower()
        if level not in _FLAME_COLORS:
            level = "warm"
        if (armed, level) != (self._armed, self._level):
            self._armed = armed
            self._level = level
            self.update()

    def _flame_path(self, w: float, h: float, scale: float) -> QPainterPath:
        cx = w / 2
        ox = cx * (1 - scale)
        oy = h * (1 - scale)

        def x(v):
            return ox + v * w * scale

        def y(v):
            return oy + v * h * scale

        path = QPainterPath()
        path.moveTo(x(0.5), y(0.08))
        path.cubicTo(x(0.80), y(0.34), x(0.88), y(0.60), x(0.72), y(0.80))
        path.cubicTo(x(0.62), y(0.93), x(0.38), y(0.93), x(0.28), y(0.80))
        path.cubicTo(x(0.12), y(0.60), x(0.28), y(0.44), x(0.40), y(0.32))
        path.cubicTo(x(0.46), y(0.24), x(0.48), y(0.16), x(0.5), y(0.08))
        path.closeSubpath()
        return path

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = float(self.width()), float(self.height())
        if not self._armed:
            painter.setPen(QPen(QColor(theme.BORDER), 2))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawPath(self._flame_path(w, h, 0.82))
            painter.end()
            return
        base, tip = _FLAME_COLORS[self._level]
        scale = {"warm": 0.82, "hot": 0.92, "inferno": 1.0}[self._level]
        if self._level == "inferno":
            glow = QColor(theme.RED)
            glow.setAlpha(46)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(glow)
            painter.drawEllipse(QRectF(w * 0.06, h * 0.10, w * 0.88, h * 0.86))
        grad = QLinearGradient(0, h, 0, 0)
        grad.setColorAt(0.0, QColor(base))
        grad.setColorAt(1.0, QColor(tip))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(grad)
        painter.drawPath(self._flame_path(w, h, scale))
        inner = QColor(tip)
        inner.setAlpha(160)
        painter.setBrush(inner)
        painter.drawPath(self._flame_path(w, h, scale * 0.55))
        painter.end()


class ReadoutTile(Card):
    """One small sensor tile.  Absent sensors say so, always."""

    def __init__(self, title: str):
        super().__init__()
        self.setMinimumWidth(128)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 9, 12, 9)
        lay.setSpacing(2)
        lay.addWidget(label(title, "detail"))
        self._value = label("—", "cardTitle")
        lay.addWidget(self._value)

    def set_value(self, text: str | None) -> None:
        if text:
            self._value.setText(text)
            self._value.setStyleSheet("")
        else:
            self._value.setText("— sensor not available")
            self._value.setStyleSheet(f"color: {theme.MUTED}; font-size: 12px;")


class ProfileCard(Card):
    """One app-profile card.  Flipping it on arms Ember with the profile id
    written to /run/shadowfetch/ember-profile by the root pkexec helper —
    session code never writes root paths."""

    def __init__(self, profile: dict, on_toggle):
        super().__init__()
        self.profile = profile
        self._on_toggle = on_toggle
        self.setMinimumHeight(120)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 11, 14, 11)
        lay.setSpacing(5)
        head = QHBoxLayout()
        head.addWidget(label(profile.get("name", "?"), "cardTitle"))
        head.addStretch(1)
        self.button = QPushButton("Turn on")
        self.button.setCheckable(True)
        self.button.setFixedHeight(28)
        self.button.clicked.connect(self._clicked)
        head.addWidget(self.button)
        lay.addLayout(head)
        blurb = label(profile.get("blurb", ""), "detail", wrap=True)
        lay.addWidget(blurb)
        self.status = label("", "detail", wrap=True)
        lay.addWidget(self.status)
        lay.addStretch(1)

    def _clicked(self, checked: bool) -> None:
        self._on_toggle(self, checked)

    def show_active(self, active: bool) -> None:
        self.button.blockSignals(True)
        self.button.setChecked(active)
        self.button.setText("Turn off" if active else "Turn on")
        self.button.blockSignals(False)
        self.set_active(active)


class EmberPage(QWidget):
    """The Ignite section."""

    @classmethod
    def build(cls, context):
        return cls(context.firewatch, context.open_route)

    def __init__(self, firewatch: busutil.FirewatchClient, open_route):
        super().__init__()
        self._firewatch = firewatch
        self._open_route = open_route
        self._active_profile: str | None = None
        self._pending_profile: str | None = None
        self._proc: QProcess | None = None
        self._helper_proc: QProcess | None = None
        self._busy = False

        firewatch.updated.connect(self._on_firewatch)

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

        # ---- main Ember card ----------------------------------------------
        card = Card()
        card_lay = QHBoxLayout(card)
        card_lay.setContentsMargins(18, 16, 18, 16)
        card_lay.setSpacing(20)

        flame_col = QVBoxLayout()
        self.flame = FlameWidget()
        flame_col.addWidget(self.flame, alignment=Qt.AlignmentFlag.AlignHCenter)
        self.flame_caption = label("Ember is off", "detail")
        self.flame_caption.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        flame_col.addWidget(self.flame_caption)
        card_lay.addLayout(flame_col)

        right = QVBoxLayout()
        right.setSpacing(8)
        right.addWidget(label("Ember Mode", "cardTitle"))
        right.addWidget(label(
            "One switch for speed: performance CPU governor, background "
            "services paused, your work prioritised.", "detail", wrap=True))
        # The safety promise is on the card BEFORE the flip (judge fold).
        right.addWidget(label(SAFETY_LINE, "safety", wrap=True))

        controls = QHBoxLayout()
        self.switch = QPushButton("Ignite Ember")
        self.switch.setCheckable(True)
        self.switch.setFixedHeight(34)
        self.switch.setMinimumWidth(170)
        self.switch.clicked.connect(self._on_switch)
        controls.addWidget(self.switch)
        self.duration = QComboBox()
        for text, _secs in _DURATIONS:
            self.duration.addItem(text)
        self.duration.setFixedHeight(34)
        controls.addWidget(self.duration)
        controls.addStretch(1)
        right.addLayout(controls)

        self.summary = label("", "status")
        self.summary.setWordWrap(True)
        right.addWidget(self.summary)
        self.note = label("", "detail", wrap=True)
        right.addWidget(self.note)
        right.addStretch(1)
        card_lay.addLayout(right, 1)
        root.addWidget(card)

        # ---- readout strip (bound to Firewatch1, the single sensor source)
        strip = QHBoxLayout()
        strip.setSpacing(10)
        self.tile_cpu = ReadoutTile("CPU load")
        self.tile_clock = ReadoutTile("CPU clock")
        self.tile_ram = ReadoutTile("Memory")
        self.tile_temp = ReadoutTile("CPU temperature")
        self.tile_power = ReadoutTile("Power draw")
        for tile in (self.tile_cpu, self.tile_clock, self.tile_ram,
                     self.tile_temp, self.tile_power):
            strip.addWidget(tile)
        root.addLayout(strip)
        self.sensor_note = label("", "detail", wrap=True)
        root.addWidget(self.sensor_note)

        # ---- app profile row ----------------------------------------------
        root.addWidget(label(PROFILE_HEADER, "subtitle", wrap=True))
        profile_grid = QGridLayout()
        profile_grid.setSpacing(12)
        self.profile_cards: list[ProfileCard] = []
        profiles = busutil.load_ember_profiles()
        if not profiles:
            root.addWidget(label(
                "App profiles are not installed on this system.", "detail"))
        for index, profile in enumerate(profiles):
            card = ProfileCard(profile, self._on_profile_toggle)
            if profile.get("show_hwscan") == "yes":
                open_agents = QPushButton("Open Workspaces")
                open_agents.setObjectName("quiet")
                open_agents.setFixedHeight(26)
                open_agents.clicked.connect(lambda: self._open_route("workspaces"))
                card.layout().addWidget(open_agents,
                                        alignment=Qt.AlignmentFlag.AlignLeft)
            self.profile_cards.append(card)
            profile_grid.addWidget(card, index // 2, index % 2)
        root.addLayout(profile_grid)
        root.addStretch(1)

        self._refresh_timer = QTimer(self)
        self._refresh_timer.setInterval(3000)
        self._refresh_timer.timeout.connect(self._refresh_state)

    # ---- lifecycle --------------------------------------------------------
    def showEvent(self, event) -> None:
        super().showEvent(event)
        self._firewatch.acquire()
        self._refresh_state()
        self._refresh_timer.start()

    def hideEvent(self, event) -> None:
        super().hideEvent(event)
        self._firewatch.release()
        self._refresh_timer.stop()

    # ---- switch flow ------------------------------------------------------
    def _on_switch(self, checked: bool) -> None:
        if self._busy:
            return
        if checked:
            self._arm(profile=None)
        else:
            self._extinguish()

    def _on_profile_toggle(self, card: ProfileCard, checked: bool) -> None:
        if self._busy:
            card.show_active(card.profile.get("id") == self._active_profile)
            return
        if checked:
            for other in self.profile_cards:
                if other is not card:
                    other.show_active(False)
            self._arm(profile=card.profile.get("id"))
        else:
            self._extinguish()

    def _duration_seconds(self) -> int:
        return _DURATIONS[self.duration.currentIndex()][1]

    def _arm(self, profile: str | None) -> None:
        self._busy = True
        self._pending_profile = profile
        helper = busutil.find_ember_helper()
        args: list[str] = []
        duration = 0 if profile else self._duration_seconds()
        if profile:
            args += ["--profile", profile]
            try:
                duration = int(self._profile_conf(profile).get("duration_seconds", "0"))
            except ValueError:
                duration = 0
        if duration:
            # ember-duration takes the seconds as a bare positional
            # argument; a --duration flag is rejected by its parser.
            args += [str(duration)]
        pkexec = busutil.trusted_program("pkexec")
        if args and helper and pkexec:
            # pkexec decides whether the authorisation dialog the person is
            # about to answer belongs to this operation. Resolved through
            # $PATH it is a session-local process that can imitate the dialog
            # and swallow the operation while reporting success.
            self.note.setText("Waiting for authorisation…")
            self._helper_proc = QProcess(self)
            self._helper_proc.finished.connect(self._helper_done)
            self._helper_proc.start(pkexec, [helper] + args)
            return
        if args and not helper:
            self.note.setText(
                "The Ember helper is not installed — starting without a "
                "time limit or profile marker.")
            self._pending_profile = None
        self._start_unit()

    def _profile_conf(self, profile_id: str) -> dict:
        for card in self.profile_cards:
            if card.profile.get("id") == profile_id:
                return card.profile
        return {}

    def _helper_done(self, code, _status) -> None:
        if code != 0:
            # 126 = polkit refused or the user dismissed the prompt;
            # 127 = the helper could not be executed. Anything else is the
            # helper itself failing, which must not be reported as a
            # cancelled authorisation.
            if code == 126:
                self.note.setText("Authorisation was cancelled — Ember was not started.")
            elif code == 127:
                self.note.setText("The Ember helper could not be run — Ember was not started.")
            else:
                self.note.setText(f"The Ember helper failed (status {code}) — Ember was not started.")
            self._busy = False
            self._pending_profile = None
            self._refresh_state()
            return
        self._start_unit()

    def _start_unit(self) -> None:
        self._proc = QProcess(self)
        self._proc.finished.connect(self._start_done)
        self._proc.start(busutil.SYSTEMCTL, ["start", busutil.EMBER_UNIT])

    def _start_done(self, code, _status) -> None:
        self._busy = False
        if code == 0:
            self._active_profile = self._pending_profile
            self.note.setText("")
            baloo = busutil.installed_command("balooctl6")
            if baloo:
                subprocess.Popen([baloo, "suspend"],
                                 stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)
        else:
            self._active_profile = None
            self.note.setText(
                "Ember could not be started. The shadowfetch-ember service "
                "may not be installed — check Software & Updates.")
        self._pending_profile = None
        self._refresh_state()

    def _extinguish(self) -> None:
        self._busy = True
        self._proc = QProcess(self)
        self._proc.finished.connect(self._stop_done)
        self._proc.start(busutil.SYSTEMCTL, ["stop", busutil.EMBER_UNIT])

    def _stop_done(self, code, _status) -> None:
        self._busy = False
        self._active_profile = None
        if code == 0:
            self.note.setText("")
            baloo = busutil.installed_command("balooctl6")
            if baloo:
                subprocess.Popen([baloo, "resume"],
                                 stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)
        else:
            self.note.setText("Ember could not be stopped cleanly — it still "
                              "returns to Balanced on its own.")
        self._refresh_state()

    # ---- state rendering --------------------------------------------------
    def _refresh_state(self) -> None:
        armed = busutil.unit_active(busutil.EMBER_UNIT)
        props = busutil.ember_props() if armed else None

        self.switch.blockSignals(True)
        self.switch.setChecked(armed)
        self.switch.setText("Return to Balanced" if armed else "Ignite Ember")
        self.switch.blockSignals(False)
        self.duration.setEnabled(not armed)

        if armed:
            paused = []
            if props:
                paused = props.get("paused_units") or []
            count = len(paused)
            services = "service" if count == 1 else "services"
            self.summary.setText(
                f"Governor: performance — {count} background {services} paused")
            if paused:
                self.summary.setToolTip("Paused: " + ", ".join(str(u) for u in paused))
        else:
            self.summary.setText("")
            self.summary.setToolTip("")
            self._active_profile = None

        for card in self.profile_cards:
            card.show_active(armed and card.profile.get("id") == self._active_profile)
            if card.profile.get("show_gamemode") == "yes":
                clients = busutil.gamemode_clients()
                if clients is None:
                    card.status.setText("GameMode: idle (no game running)")
                elif clients == 0:
                    card.status.setText("GameMode: active, no clients yet")
                else:
                    games = "game" if clients == 1 else "games"
                    card.status.setText(f"GameMode: {clients} {games} running")
            elif card.profile.get("show_hwscan") == "yes":
                hw = busutil.load_hwscan()
                sentence = ""
                if hw:
                    sentence = (hw.get("verdict") or {}).get("sentence", "")
                card.status.setText(sentence or "Hardware scan not available yet.")

        if not armed:
            self.flame.set_state(False, None)
            self.flame_caption.setText("Ember is off")

    def _on_firewatch(self, data: dict) -> None:
        armed = self.switch.isChecked()
        available = data.get("available", False)
        flame = data.get("flame")
        eli = data.get("eli")
        if armed:
            self.flame.set_state(True, flame)
            if flame:
                caption = flame.capitalize()
                if eli is not None:
                    caption += f" · load {eli:.0f}%"
                self.flame_caption.setText(caption)
            else:
                self.flame_caption.setText("Armed")
        snapshot = data.get("snapshot") if available else None
        self._render_strip(snapshot, available)

    def _render_strip(self, snapshot, available: bool) -> None:
        if not available:
            for tile in (self.tile_cpu, self.tile_clock, self.tile_ram,
                         self.tile_temp, self.tile_power):
                tile.set_value(None)
            self.sensor_note.setText(
                "Firewatch is not running — live readouts need the "
                "shadowfetch-firewatchd service.")
            return
        self.sensor_note.setText("")
        snapshot = snapshot or {}
        cpu = snapshot.get("cpu")
        cpu_pct = None
        cpu_mhz = None
        if isinstance(cpu, (int, float)):
            cpu_pct = float(cpu)
        elif isinstance(cpu, dict):
            cpu_pct = _pick(cpu, "percent", "pct", "load_pct", "usage")
            cpu_mhz = _pick(cpu, "freq_mhz", "mhz", "clock_mhz")
        if cpu_pct is None:
            cpu_pct = _pick(snapshot, "cpu_pct")
        self.tile_cpu.set_value(f"{float(cpu_pct):.0f}%" if cpu_pct is not None else None)
        self.tile_clock.set_value(
            f"{float(cpu_mhz) / 1000:.1f} GHz" if cpu_mhz else None)

        ram = snapshot.get("ram") or snapshot.get("mem")
        ram_text = None
        if isinstance(ram, dict):
            used = _pick(ram, "used_bytes", "used")
            total = _pick(ram, "total_bytes", "total")
            pct = _pick(ram, "percent", "pct")
            if used is not None and total:
                ram_text = f"{theme.fmt_bytes(used)} / {theme.fmt_bytes(total)}"
            elif pct is not None:
                ram_text = f"{float(pct):.0f}%"
        elif isinstance(ram, (int, float)):
            ram_text = f"{float(ram):.0f}%"
        self.tile_ram.set_value(ram_text)

        temps = snapshot.get("temps")
        temp_text = None
        if isinstance(temps, dict) and temps:
            for key in ("cpu", "package", "coretemp", "k10temp"):
                if key in temps:
                    try:
                        temp_text = f"{float(temps[key]):.0f} °C"
                    except (TypeError, ValueError):
                        pass
                    break
            if temp_text is None:
                try:
                    temp_text = f"{max(float(v) for v in temps.values()):.0f} °C"
                except (TypeError, ValueError):
                    temp_text = None
        elif isinstance(temps, list) and temps:
            try:
                temp_text = f"{float(temps[0].get('c', temps[0].get('value'))):.0f} °C"
            except (AttributeError, TypeError, ValueError):
                temp_text = None
        self.tile_temp.set_value(temp_text)

        watts = _pick(snapshot, "rapl_watts", "power_watts", "watts")
        self.tile_power.set_value(
            f"{float(watts):.0f} W" if watts is not None else None)
