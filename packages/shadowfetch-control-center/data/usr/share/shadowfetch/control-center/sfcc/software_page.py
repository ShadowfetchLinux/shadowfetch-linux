"""Software & Updates — updates first, bundles second.

Tab 1 mounts the Fireproof page when the shadowfetch-fireproof package has
installed one (sfcc.fireproof_page); otherwise it shows the honest
built-in updates card, keeping 2.1.1's Safe Update reachable either way.

Tab 2 renders the same Ignition bundle records Welcome uses, straight from
the root-owned catalog JSON, installs through the id-locked pkexec helper
(pkexec shadowfetch-bundle-install <catalog-id>), and every transaction is
wrapped in Phoenix Points by the apt hooks — zero snapshot code here.
Installs are strictly user-initiated; offline the buttons disable with a
plain-words note.
"""

import subprocess

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

import os

from sfcc import busutil, theme
from sfcc.theme import Card, ProcessDialog, label


class BundleCard(Card):
    def __init__(self, record: dict, parent_page):
        super().__init__()
        self.record = record
        self._page = parent_page
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 13, 16, 13)
        lay.setSpacing(6)

        head = QHBoxLayout()
        head.addWidget(label(str(record.get("name", record.get("id", "?"))),
                             "cardTitle"))
        head.addStretch(1)
        self.button = QPushButton("Install")
        self.button.setFixedHeight(28)
        head.addWidget(self.button)
        lay.addLayout(head)

        blurb = record.get("blurb") or ""
        if blurb:
            lay.addWidget(label(str(blurb), "detail", wrap=True))

        packages = [str(p) for p in (record.get("packages") or [])]
        self.packages = packages
        download = record.get("download_bytes") or record.get("size_bytes")
        installed_size = record.get("installed_bytes")
        size_bits = []
        if download:
            size_bits.append(f"download {theme.fmt_mb(download)}")
        if installed_size:
            size_bits.append(f"installed {theme.fmt_mb(installed_size)}")
        if size_bits:
            lay.addWidget(label(" · ".join(size_bits), "detail"))

        self.state = label("", "detail", wrap=True)
        lay.addWidget(self.state)
        self.button.clicked.connect(self._install)
        self.refresh_state(online=None)

    def refresh_state(self, online: bool | None) -> None:
        if not self.packages:
            # ignition-core is empty by construction: the Core system is
            # what is already running.
            self.button.setText("Included")
            self.button.setEnabled(False)
            self.state.setText("Core is the system you are running — "
                               "nothing to install.")
            return
        installed = busutil.installed_map(self.packages)
        have = sum(1 for v in installed.values() if v)
        total = len(self.packages)
        if have == total:
            self.button.setText("Installed")
            self.button.setEnabled(False)
            self.state.setText(f"All {total} packages already on your system.")
            return
        self.state.setText(f"{have} of {total} packages already on your system.")
        helper_ok = os.access(busutil.BUNDLE_INSTALL, os.X_OK)
        if not helper_ok:
            self.button.setEnabled(False)
            self.state.setText(self.state.text() +
                               " Bundle installer not available — open "
                               "Welcome to install bundles.")
            return
        if online is False:
            self.button.setEnabled(False)
            self.state.setText(self.state.text() +
                               " No internet connection — choosing in "
                               "Welcome saves your pick for later.")
        else:
            self.button.setText("Install")
            self.button.setEnabled(True)

    def _install(self) -> None:
        bundle_id = str(self.record.get("id", ""))
        if not bundle_id:
            return
        dialog = ProcessDialog(
            self._page, f"Installing {self.record.get('name', bundle_id)}",
            ["pkexec", busutil.BUNDLE_INSTALL, bundle_id],
            "One apt transaction from the pinned archive, wrapped in a "
            "Phoenix Point automatically. Safe to leave running.")
        dialog.completed.connect(lambda _code: self._page.reload_bundles())
        dialog.start()
        dialog.exec()


class SoftwarePage(QWidget):
    """The Software & Updates section (subtitle: Updates & bundles)."""

    _TAB_ROUTES = {"updates": 0, "fireproof": 0, "bundles": 1}

    def __init__(self):
        super().__init__()
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 18, 24, 18)
        root.setSpacing(12)
        self.tabs = QTabWidget()
        root.addWidget(self.tabs, 1)

        # ---- Tab 1: updates ----------------------------------------------
        fireproof_widget = None
        try:
            from sfcc.fireproof_page import FireproofPage  # provided by shadowfetch-fireproof's page module when present
            fireproof_widget = FireproofPage()
        except Exception:
            fireproof_widget = None
        if fireproof_widget is not None:
            self.tabs.addTab(fireproof_widget, "Updates")
        else:
            self.tabs.addTab(self._builtin_updates(), "Updates")

        # ---- Tab 2: bundles ----------------------------------------------
        bundles = QWidget()
        outer = QVBoxLayout(bundles)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        outer.addWidget(scroll)
        body = QWidget()
        scroll.setWidget(body)
        self.bundle_lay = QVBoxLayout(body)
        self.bundle_lay.setContentsMargins(12, 12, 12, 12)
        self.bundle_lay.setSpacing(10)
        self._bundle_cards: list[BundleCard] = []
        self._bundle_note = label("", "detail", wrap=True)
        self.bundle_lay.addWidget(self._bundle_note)
        self.bundle_lay.addStretch(1)
        self.tabs.addTab(bundles, "Bundles")
        self.reload_bundles()

        root.addWidget(label("App store: Discover — updates happen here.",
                             "detail"))

    def _builtin_updates(self) -> QWidget:
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setContentsMargins(12, 12, 12, 12)
        lay.setSpacing(12)

        card = Card()
        c_lay = QVBoxLayout(card)
        c_lay.setContentsMargins(16, 13, 16, 13)
        c_lay.setSpacing(6)
        c_lay.addWidget(label("Updates", "cardTitle"))
        count = busutil.fireproof_updates()
        if count is None:
            status = ("Fireproof (the update analyzer) is not answering — "
                      "Safe Update below still works.")
        elif count == 0:
            status = "Your system is up to date."
        else:
            plural = "update" if count == 1 else "updates"
            status = f"{count} {plural} ready for review."
        c_lay.addWidget(label(status, "subtitle", wrap=True))
        c_lay.addWidget(label(
            "Updates warn before removing anything, wrap themselves in a "
            "Phoenix Point, and verify the system afterward.",
            "detail", wrap=True))
        row = QHBoxLayout()
        import shutil as _shutil
        if _shutil.which("fireproof"):
            analyze = QPushButton("Review and update (Fireproof)")
            analyze.clicked.connect(
                lambda: busutil.terminal_command("fireproof update"))
            row.addWidget(analyze)
        safe = QPushButton("Check for updates (Safe Update)")
        safe.setObjectName("quiet")
        safe.clicked.connect(lambda: busutil.terminal_command("shadowfetch-update"))
        row.addWidget(safe)
        row.addStretch(1)
        c_lay.addLayout(row)
        lay.addWidget(card)

        setup = Card()
        s_lay = QVBoxLayout(setup)
        s_lay.setContentsMargins(16, 13, 16, 13)
        s_lay.setSpacing(6)
        s_lay.addWidget(label("First-run setup", "cardTitle"))
        s_lay.addWidget(label(
            "Reopen app, appearance, graphics and local AI setup at any "
            "time.", "detail", wrap=True))
        open_welcome = QPushButton("Open setup")
        open_welcome.setObjectName("quiet")
        open_welcome.setFixedHeight(30)
        open_welcome.clicked.connect(
            lambda: busutil.start_detached(["shadowfetch-welcome"]))
        s_lay.addWidget(open_welcome, alignment=Qt.AlignmentFlag.AlignLeft)
        lay.addWidget(setup)
        lay.addStretch(1)
        return page

    # ---- bundles ----------------------------------------------------------
    def reload_bundles(self) -> None:
        for card in self._bundle_cards:
            card.setParent(None)
            card.deleteLater()
        self._bundle_cards = []
        records = [record for record in busutil.load_catalog(kinds=("preset",))
                   if record.get("section") != "workbench"]
        if not records:
            self._bundle_note.setText(
                "No bundle catalog is installed. Bundles are curated "
                "one-click sets (Creator, Developer, AI Workstation, Full "
                "Flame) — open Welcome to set them up.")
            return
        online = busutil.nm_connectivity_full()
        self._bundle_note.setText(
            "Bundles are one apt transaction each, from the pinned archive, "
            "wrapped in a Phoenix Point automatically.")
        insert_at = self.bundle_lay.count() - 1  # before the stretch
        for record in records:
            card = BundleCard(record, self)
            card.refresh_state(online=online)
            self.bundle_lay.insertWidget(insert_at, card)
            insert_at += 1
            self._bundle_cards.append(card)

    def route(self, parts: list[str]) -> None:
        for part in parts:
            index = self._TAB_ROUTES.get(part.lower())
            if index is not None:
                self.tabs.setCurrentIndex(index)
                return
