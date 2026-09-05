"""Featured integration for the official Grok Bot desktop, distinct from CLI agents."""
from PyQt6.QtCore import Qt, QTimer, QUrl
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtWidgets import QGridLayout, QHBoxLayout, QMessageBox, QPushButton, QScrollArea, QVBoxLayout, QWidget
from sfcc import theme
from sfcc.mission_client import GROK_COMMAND, MissionClient
from sfcc.theme import Card, ProcessDialog, label, fmt_bytes


class GrokBotPage(QWidget):
    def __init__(self, open_route):
        super().__init__()
        self.open_route = open_route
        self.client = MissionClient(self)
        self.record = {}
        self._refreshing = False
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 10, 24, 18)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        body = QWidget()
        layout = QVBoxLayout(body)
        layout.setContentsMargins(0, 0, 4, 0)
        layout.setSpacing(12)
        hero = Card(active=True)
        hero.setStyleSheet("QFrame#cardActive {background: #101115; border: 1px solid #71634b; border-radius: 12px;}")
        hero_layout = QVBoxLayout(hero)
        hero_layout.setContentsMargins(24, 20, 24, 20)
        hero_layout.setSpacing(10)
        eyebrow = QHBoxLayout()
        eyebrow.addWidget(label("FEATURED TEAMMATE", "safety"))
        eyebrow.addStretch(1)
        eyebrow.addWidget(label("OFFICIAL LINUX DESKTOP", "detail"))
        hero_layout.addLayout(eyebrow)
        wordmark = label("Grok Bot")
        wordmark.setStyleSheet("font-size: 46px; font-weight: 700; letter-spacing: -1px; color: #f5f4ef;")
        hero_layout.addWidget(wordmark)
        hero_layout.addWidget(label("Give it real work.", "pageTitle"))
        hero_layout.addWidget(label("The native Grok Bot desktop joins your Shadowfetch workspace. Open the official app, sign in with your eligible account, and manage its cloud teammates there.", "subtitle", wrap=True))
        self.state = label("Checking this computer…", "statusWarn", wrap=True)
        hero_layout.addWidget(self.state)
        self.progress = label("", "detail", wrap=True)
        hero_layout.addWidget(self.progress)
        buttons = QHBoxLayout()
        self.install = QPushButton("Install Grok Bot")
        self.install.setMinimumHeight(40)
        self.install.setEnabled(False)
        self.install.clicked.connect(self._install)
        self.launch = QPushButton("Open Grok Bot  ↗")
        self.launch.setMinimumHeight(40)
        self.launch.setEnabled(False)
        self.launch.clicked.connect(self._launch)
        buttons.addWidget(self.install)
        buttons.addWidget(self.launch)
        buttons.addStretch(1)
        refresh = QPushButton("Refresh")
        refresh.setObjectName("quiet")
        refresh.clicked.connect(self.refresh)
        buttons.addWidget(refresh)
        hero_layout.addLayout(buttons)
        layout.addWidget(hero)
        facts = QGridLayout()
        facts.setSpacing(10)
        for i, (heading, content) in enumerate((
            ("Native app, native sign-in", "Sign in inside Grok Bot. A model API key does not replace the app's account or subscription."),
            ("A deliberate cloud connection", "Grok Bot uses its vendor's cloud services. Review its permissions and data handling before connecting projects."),
            ("Verified installation", "Shadowfetch checks the pinned download, package identity and installed version. Setup requires administrator approval and enables the vendor's package update source."),
            ("Your local missions stay visible", "Mission Control runs scoped code, source reports and media workflows. Grok Bot tasks and permissions are managed in the official native app."),
        )):
            card = Card()
            row = QVBoxLayout(card)
            row.setContentsMargins(16, 13, 16, 13)
            row.addWidget(label(heading, "cardTitle", wrap=True))
            row.addWidget(label(content, "detail", wrap=True))
            facts.addWidget(card, i // 2, i % 2)
        layout.addLayout(facts)
        self.ice = label("Ice is active. Grok Bot installation and cloud launch are paused. Switch to Fire deliberately when you want to use this cloud app.", "statusWarn", wrap=True)
        self.ice.setVisible(theme.ELEMENT == "ice")
        layout.addWidget(self.ice)
        links = QHBoxLayout()
        for title, callback in (("Getting started", lambda: self._url("https://docs.x.ai/grok-bot/get-started")), ("Vendor terms", lambda: self._url("https://cursor.com/terms/grok-bot")), ("Open Mission Control", lambda: self.open_route("missions"))):
            button = QPushButton(title)
            button.setObjectName("quiet")
            button.clicked.connect(callback)
            links.addWidget(button)
        links.addStretch(1)
        layout.addLayout(links)
        layout.addWidget(label("Grok Bot is provided by its vendor. Shadowfetch's installer integration does not imply vendor sponsorship or endorsement.", "detail", wrap=True))
        layout.addStretch(1)
        scroll.setWidget(body)
        root.addWidget(scroll)
        self.timer = QTimer(self)
        self.timer.setInterval(60_000)
        self.timer.timeout.connect(lambda: self.refresh() if self.isVisible() else None)
        self.timer.start()
        QTimer.singleShot(0, self.refresh)

    def refresh(self):
        if self._refreshing:
            return
        self._refreshing = True
        self.client.grok_status(self._status)

    def _status(self, data, error):
        self._refreshing = False
        if error or not isinstance(data, dict):
            self.state.setText(error or "The Grok Bot helper returned an unexpected response.")
            self.install.setEnabled(False)
            self.launch.setEnabled(False)
            return
        self.record = data
        ready = bool(data.get("verified") and data.get("launchable"))
        if ready:
            self.state.setText(f"Native app {data.get('installed_version') or data.get('version')} verified on this computer")
            self.state.setObjectName("status")
            self.progress.setText("Sign-in status is managed inside Grok Bot. Open it to finish account setup.")
        elif data.get("installed"):
            self.state.setText("The native app is installed and needs verification or repair.")
            self.state.setObjectName("statusWarn")
            self.progress.setText(f"Installed: {data.get('installed_version') or 'unknown'} · Pinned installer: {data.get('version', 'unknown')}")
        else:
            self.state.setText("Ready to install the official native app")
            self.state.setObjectName("statusWarn")
            self.progress.setText(f"Download: {fmt_bytes(data.get('download_bytes'))} · Eligible account and plan required")
        self.state.style().unpolish(self.state)
        self.state.style().polish(self.state)
        self.install.setText("Installed" if ready else "Repair installation" if data.get("installed") else "Install Grok Bot")
        self.install.setEnabled(not ready and theme.ELEMENT != "ice")
        self.launch.setEnabled(ready and theme.ELEMENT != "ice")

    def _install(self):
        if theme.ELEMENT == "ice":
            return
        message = ("Install the official Grok Bot Linux package?\n\n"
                   f"Download: {fmt_bytes(self.record.get('download_bytes'))}. Shadowfetch verifies the pinned artifact before requesting administrator approval. "
                   "The package installs a vendor update source.\n\n"
                   "Grok Bot is a cloud service requiring an eligible account and plan. Sign in in the native app; API keys are not a replacement. "
                   "Review the vendor terms and permissions before connecting your projects.")
        if QMessageBox.question(self, "Install Grok Bot", message, QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel, QMessageBox.StandardButton.Cancel) != QMessageBox.StandardButton.Yes:
            return
        dialog = ProcessDialog(self, "Installing official Grok Bot", [GROK_COMMAND, "setup", "--yes", "--no-open"], "Verifies the download, requests administrator approval, then checks the installed native app. Account sign-in happens after installation.")
        dialog.completed.connect(lambda _code: self.refresh())
        dialog.start()
        dialog.exec()

    def _launch(self):
        if theme.ELEMENT == "ice":
            return
        dialog = ProcessDialog(self, "Opening Grok Bot", [GROK_COMMAND, "open"], "The native app handles sign-in and its own task permissions.")
        dialog.completed.connect(lambda _code: self.refresh())
        dialog.start()
        dialog.exec()

    def _url(self, url):
        if theme.ELEMENT == "ice":
            QMessageBox.information(self, "Ice connection scope", "This opens a public website. Switch to Fire when you want to connect, or use the installed local guide.")
            return
        QDesktopServices.openUrl(QUrl(url))
