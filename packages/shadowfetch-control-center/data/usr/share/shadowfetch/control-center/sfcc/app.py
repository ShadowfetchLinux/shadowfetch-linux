"""Native Mission Control shell, featured Grok Bot and system care pages.

Single-instance deep links route over the local session bus.
"""

import sys

from PyQt6.QtCore import QSize, Qt, QTimer
from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from sfcc import busutil, theme
from sfcc.agents_page import AgentsPage
from sfcc.drivers_page import DriversPage
from sfcc.ember_page import EmberPage
from sfcc.firewatch_page import FirewatchPage
from sfcc.guide_page import GuidePage
from sfcc.missions_page import MissionsPage
from sfcc.grok_bot_page import GrokBotPage
from sfcc.phoenix_page import PhoenixPage
from sfcc.software_page import SoftwarePage
from sfcc.workbench_page import WorkbenchPage
from sfcc.theme import label

BUS_NAME = "com.shadowfetch.ControlCenter"
OBJ_PATH = "/com/shadowfetch/ControlCenter"

SECTIONS = [
    ("missions", "Mission Control", "Work you can inspect"),
    ("grok-bot", "Grok Bot", "Featured teammate"),
    ("guide", "Guide", "System Passport"),
    ("workbench", "Workbench", "Fire & Ice projects"),
    ("ignite", "Ignite", None),
    ("watch", "Watch", None),
    ("recover", "Recover", None),
    ("local-ai", "Local AI", "Buzz & models"),
    ("drivers", "Drivers", None),
    ("software", "Software & Updates", "Updates & bundles"),
]

ALIASES = {
    "missions": "missions", "mission-control": "missions", "home": "missions",
    "grok-bot": "grok-bot", "grokbot": "grok-bot",
    "guide": "guide", "passport": "guide", "system-passport": "guide",
    "workbench": "workbench", "forge": "workbench", "projects": "workbench",
    "ignite": "ignite", "ember": "ignite",
    "watch": "watch", "firewatch": "watch",
    "recover": "recover", "phoenix": "recover", "recovery": "recover",
    "local-ai": "local-ai", "agents": "local-ai", "ai": "local-ai", "buzz": "local-ai",
    "drivers": "drivers",
    "software": "software", "software-updates": "software",
    "updates": "software", "bundles": "software",
}

try:
    import dbus
    import dbus.service

    class ControlService(dbus.service.Object):
        """Single-instance activation endpoint."""

        def __init__(self, bus, window):
            super().__init__(bus, OBJ_PATH)
            self._window = window

        @dbus.service.method(dbus_interface=BUS_NAME,
                             in_signature="s", out_signature="")
        def Activate(self, page):
            window = self._window
            if page:
                window.open_route(str(page))
            window.showNormal()
            window.raise_()
            window.activateWindow()

    HAVE_DBUS = True
except ImportError:  # pragma: no cover
    ControlService = None
    HAVE_DBUS = False


class SidebarEntry(QWidget):
    def __init__(self, title: str, subtitle: str | None):
        super().__init__()
        self.setObjectName("sideItem")
        self.setStyleSheet("background: transparent;")
        lay = QHBoxLayout(self)
        lay.setContentsMargins(10, 6, 10, 6)
        lay.setSpacing(6)
        col = QVBoxLayout()
        col.setSpacing(0)
        name = QLabel(title)
        name.setStyleSheet("background: transparent; font-weight: 650; font-size: 14px;")
        col.addWidget(name)
        if subtitle:
            sub = QLabel(subtitle)
            sub.setStyleSheet(f"background: transparent; color: {theme.MUTED};"
                              "font-size: 11px;")
            col.addWidget(sub)
        lay.addLayout(col, 1)
        self.badge = QLabel("")
        self.badge.setObjectName("badge")
        self.badge.hide()
        lay.addWidget(self.badge)

    def set_badge(self, count: int | None) -> None:
        if count:
            self.badge.setText(str(count))
            self.badge.show()
        else:
            self.badge.hide()


class ControlCenterWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Shadowfetch · Mission Control")
        self.setMinimumSize(960, 640)
        self.resize(1200, 720)
        icon = QIcon.fromTheme("shadowfetch")
        if not icon.isNull():
            self.setWindowIcon(icon)
        self.setStyleSheet(theme.STYLESHEET)

        self.firewatch = busutil.FirewatchClient(self)

        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ---- sidebar ------------------------------------------------------
        side = QVBoxLayout()
        side.setContentsMargins(0, 0, 0, 0)
        side.setSpacing(0)
        side_wrap = QWidget()
        side_wrap.setStyleSheet("background: #101114;")
        side_wrap.setFixedWidth(216)
        side_wrap.setLayout(side)

        brand = QLabel("Shadowfetch")
        brand.setStyleSheet("background: transparent; font-size: 18px;"
                            f"font-weight: 700; color: {theme.GOLD};"
                            "padding: 16px 16px 2px 16px;")
        side.addWidget(brand)
        brand_sub = QLabel("MISSION CONTROL  /  4.0")
        brand_sub.setStyleSheet(f"background: transparent; color: {theme.MUTED};"
                                "padding: 0 16px 10px 16px;")
        side.addWidget(brand_sub)

        self.sidebar = QListWidget()
        self.sidebar.setObjectName("sidebar")
        self._entries: list[SidebarEntry] = []
        for _key, title, subtitle in SECTIONS:
            item = QListWidgetItem()
            entry = SidebarEntry(title, subtitle)
            item.setSizeHint(QSize(200, 46 if subtitle else 36))
            self.sidebar.addItem(item)
            self.sidebar.setItemWidget(item, entry)
            self._entries.append(entry)
        side.addWidget(self.sidebar, 1)

        footer = QLabel(f"Shadowfetch Linux {busutil.sf_version()}\n"
                        "Local-first · No account required")
        footer.setStyleSheet(f"background: transparent; color: {theme.MUTED};"
                             "font-size: 11px; padding: 10px 16px;")
        side.addWidget(footer)
        root.addWidget(side_wrap)

        # ---- content column ----------------------------------------------
        content = QVBoxLayout()
        content.setContentsMargins(0, 0, 0, 0)
        content.setSpacing(0)
        header = QWidget()
        h_lay = QHBoxLayout(header)
        h_lay.setContentsMargins(24, 16, 24, 8)
        self.page_title = label("Ignite", "title")
        h_lay.addWidget(self.page_title)
        h_lay.addStretch(1)
        self.status = label("", "status")
        h_lay.addWidget(self.status)
        content.addWidget(header)

        self.stack = QStackedWidget()
        self.pages = [
            MissionsPage(self.open_route),
            GrokBotPage(self.open_route),
            GuidePage(self.open_route),
            WorkbenchPage(self.open_route),
            EmberPage(self.firewatch, self.open_route),
            FirewatchPage(self.firewatch),
            PhoenixPage(),
            AgentsPage(self.firewatch, self.open_route),
            DriversPage(),
            SoftwarePage(),
        ]
        for page in self.pages:
            self.stack.addWidget(page)
        content.addWidget(self.stack, 1)
        content_wrap = QWidget()
        content_wrap.setLayout(content)
        root.addWidget(content_wrap, 1)

        self.sidebar.currentRowChanged.connect(self._section_changed)
        self.sidebar.setCurrentRow(0)

        self._refresh_status()
        status_timer = QTimer(self)
        status_timer.setInterval(30_000)
        status_timer.timeout.connect(self._refresh_status)
        status_timer.start()

        self._refresh_badge()
        badge_timer = QTimer(self)
        badge_timer.setInterval(60_000)
        badge_timer.timeout.connect(self._refresh_badge)
        badge_timer.start()

    # ---- shell behaviour --------------------------------------------------
    def _section_changed(self, row: int) -> None:
        if 0 <= row < len(self.pages):
            self.stack.setCurrentIndex(row)
            self.page_title.setText(SECTIONS[row][1])

    def _refresh_status(self) -> None:
        state, detail = busutil.system_summary()
        self.status.setText(f"●  {state}    {detail}")
        self.status.setObjectName(
            "statusWarn" if state == "Needs attention" else "status")
        self.status.style().unpolish(self.status)
        self.status.style().polish(self.status)
        self.status.setAccessibleName(f"{state}. {detail}")

    def _refresh_badge(self) -> None:
        # Only Software & Updates ever shows a badge; fireproofd suppresses
        # the count itself for a set the user already rolled back.
        count = busutil.fireproof_updates()
        index = next(i for i, (key, _title, _subtitle) in enumerate(SECTIONS)
                     if key == "software")
        self._entries[index].set_badge(count if count else None)

    def open_route(self, route: str) -> None:
        parts = [p for p in str(route).split(":") if p]
        if not parts:
            return
        section = ALIASES.get(parts[0].strip().lower())
        if section is None:
            return
        index = next(i for i, (key, _t, _s) in enumerate(SECTIONS)
                     if key == section)
        self.sidebar.setCurrentRow(index)
        page = self.pages[index]
        rest = parts[1:]
        if rest and hasattr(page, "route"):
            page.route(rest)


def _parse_page(argv: list[str]) -> str:
    for i, arg in enumerate(argv):
        if arg == "--page" and i + 1 < len(argv):
            return argv[i + 1]
        if arg.startswith("--page="):
            return arg.split("=", 1)[1]
    return "missions"


def run(argv: list[str]) -> int:
    route = _parse_page(argv)
    # Encode paths for the existing single-instance D-Bus route. Shell and
    # route separators in filenames never become command syntax.
    from urllib.parse import quote
    if "--workspace" in argv:
        index = argv.index("--workspace")
        if index + 1 < len(argv):
            kind = "code"
            if "--kind" in argv and argv.index("--kind") + 1 < len(argv):
                candidate = argv[argv.index("--kind") + 1]
                if candidate in ("code", "report", "media"):
                    kind = candidate
            route = "missions:new:workspace=" + quote(argv[index + 1], safe="") + ":kind=" + kind

    bus = busutil.session_bus()
    bus_name = None
    if HAVE_DBUS and bus is not None:
        try:
            bus_name = dbus.service.BusName(BUS_NAME, bus, do_not_queue=True)
        except dbus.exceptions.NameExistsException:
            # A Control Center is already open: hand it the route and front it.
            try:
                remote = bus.get_object(BUS_NAME, OBJ_PATH)
                remote.get_dbus_method("Activate", dbus_interface=BUS_NAME)(route)
                return 0
            except Exception:
                bus_name = None  # unreachable instance; open our own window

    app = QApplication(argv)
    app.setApplicationName("shadowfetch-control")
    app.setDesktopFileName("shadowfetch-control")
    window = ControlCenterWindow()
    service = None
    if bus_name is not None and ControlService is not None:
        service = ControlService(bus, window)  # noqa: F841 (kept alive)
    if route:
        window.open_route(route)
    window.show()
    return app.exec()
