"""Shadowfetch Guide - private compatibility passport and safe next steps."""

import html
import json
from pathlib import Path

from PyQt6.QtCore import QProcess, Qt, QTimer
from PyQt6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from sfcc import theme
from sfcc.theme import Card, label


STATUS_COLORS = {
    "ready": theme.GREEN,
    "note": theme.GOLD,
    "attention": theme.RED,
    "unknown": theme.MUTED,
    "not-present": theme.MUTED,
}


def _badge_style(background: str) -> str:
    return (
        f"background: {background}; color: {theme.INK}; border-radius: 9px; "
        "padding: 1px 7px; font-weight: 700; font-size: 12px;"
    )


def _clear(layout) -> None:
    while layout.count():
        item = layout.takeAt(0)
        widget = item.widget()
        child = item.layout()
        if widget is not None:
            widget.deleteLater()
        elif child is not None:
            _clear(child)


def _report_html(document: dict) -> str:
    verdict = document.get("verdict") or {}
    cards = []
    for item in document.get("checks") or []:
        if not isinstance(item, dict):
            continue
        cards.append(
            '<section class="check %s"><div class="row"><h2>%s</h2>'
            '<strong>%s</strong></div><p>%s</p><small>Source: %s</small></section>' % (
                html.escape(str(item.get("status") or "unknown")),
                html.escape(str(item.get("label") or "Check")),
                html.escape(str(item.get("status_label") or "Unknown")),
                html.escape(str(item.get("summary") or "")),
                html.escape(str(item.get("source") or "local probe")),
            )
        )
    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Shadowfetch System Passport</title><style>
body{margin:0;background:#0b0e12;color:#e6e9ed;font:16px system-ui,sans-serif}
main{max-width:920px;margin:auto;padding:48px 24px 64px}h1{font-size:36px;margin:8px 0}
.eyebrow{color:%(accent)s;font-weight:700}.hero{border-bottom:1px solid #2c333b;padding-bottom:28px}
.verdict{font-size:21px}.check{background:#141922;border:1px solid #2c333b;border-radius:8px;
padding:18px;margin:12px 0}.row{display:flex;gap:16px;align-items:center;justify-content:space-between}
h2{font-size:18px;margin:0}.ready strong{color:#7fb069}.attention strong{color:%(alarm)s}
.note strong{color:%(accent)s}.unknown strong,.not-present strong,small{color:#9aa3ad}
p{line-height:1.5}.privacy{margin-top:28px;padding-top:20px;border-top:1px solid #2c333b;color:#9aa3ad}
</style></head><body><main><header class="hero"><div class="eyebrow">SHADOWFETCH GUIDE</div>
<h1>System Passport</h1><p class="verdict"><strong>%(title)s</strong><br>%(summary)s</p>
<small>Shadowfetch Linux %(version)s | %(generated)s</small></header>%(cards)s
<p class="privacy">Generated locally. No upload was performed. Host, account, network,
serial, and filesystem identifiers are omitted.</p></main></body></html>
""" % {
        # The accent and the alarm colour come from sfcc.theme, so the element
        # a person chose reaches this page too. They used to be literals here,
        # which meant the System Passport stayed Fire gold on an Ice desktop
        # and one of them was a second spelling of theme.RED. The remaining
        # literals above are this document's own web palette, named nowhere
        # else; tools/drift_gate.py reports the unnamed shipped colours as a
        # separate BLOCKED finding whose remedy is a palette.json shipped from
        # shadowfetch-branding.
        "accent": theme.GOLD,
        "alarm": theme.RED,
        "title": html.escape(str(verdict.get("title") or "Passport complete")),
        "summary": html.escape(str(verdict.get("summary") or "")),
        "version": html.escape(str(document.get("release_version") or "unknown")),
        "generated": html.escape(str(document.get("generated_at") or "")),
        "cards": "".join(cards),
    }


class GuidePage(QWidget):
    """A local-only, read-only system explanation surface."""

    @classmethod
    def build(cls, context):
        return cls(context.open_route)

    def __init__(self, open_route):
        super().__init__()
        self._open_route = open_route
        self._document: dict | None = None
        self._started = False
        self._process = QProcess(self)
        self._process.setProcessChannelMode(QProcess.ProcessChannelMode.SeparateChannels)
        self._process.finished.connect(self._finished)
        self._process.errorOccurred.connect(self._process_error)

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

        hero = Card()
        hero.setObjectName("banner")
        hero_lay = QVBoxLayout(hero)
        hero_lay.setContentsMargins(18, 15, 18, 15)
        hero_lay.setSpacing(7)
        hero_lay.addWidget(label("The Linux desktop that can explain itself.",
                                 "cardTitle"))
        hero_lay.addWidget(label(
            "Before you install, it proves what works. After you install, it "
            "helps you reach the right safe fix.", "subtitle", wrap=True))
        hero_lay.addWidget(label(
            "Every check runs on this computer. Nothing is uploaded, and the "
            "shareable report omits host, account, network, serial and filesystem "
            "identifiers.", "detail", wrap=True))
        root.addWidget(hero)

        result = Card()
        result_lay = QVBoxLayout(result)
        result_lay.setContentsMargins(16, 13, 16, 13)
        result_lay.setSpacing(6)
        top = QHBoxLayout()
        self.title = label("System Passport", "subtitle")
        top.addWidget(self.title)
        top.addStretch(1)
        self.state = QLabel("Not checked")
        self.state.setObjectName("badge")
        top.addWidget(self.state)
        result_lay.addLayout(top)
        self.summary = label(
            "Run a private compatibility check for graphics, networking, audio, "
            "firmware, storage, recovery and local AI.", "detail", wrap=True)
        result_lay.addWidget(self.summary)
        self.context = label("", "detail", wrap=True)
        result_lay.addWidget(self.context)
        buttons = QHBoxLayout()
        self.run_button = QPushButton("Check this computer")
        self.run_button.setFixedHeight(32)
        self.run_button.clicked.connect(self.run_check)
        buttons.addWidget(self.run_button)
        self.save_button = QPushButton("Save redacted report")
        self.save_button.setObjectName("quiet")
        self.save_button.setFixedHeight(32)
        self.save_button.setEnabled(False)
        self.save_button.clicked.connect(self._save)
        buttons.addWidget(self.save_button)
        buttons.addStretch(1)
        result_lay.addLayout(buttons)
        root.addWidget(result)

        self.capabilities = label("", "detail", wrap=True)
        root.addWidget(self.capabilities)
        root.addWidget(label("Compatibility checks", "subtitle"))
        self.checks = QVBoxLayout()
        self.checks.setSpacing(8)
        root.addLayout(self.checks)
        root.addStretch(1)

    def showEvent(self, event) -> None:
        super().showEvent(event)
        if not self._started:
            self._started = True
            QTimer.singleShot(0, self.run_check)

    def run_check(self) -> None:
        if self._process.state() != QProcess.ProcessState.NotRunning:
            return
        program = busutil.trusted_program("shadowfetch-passport")
        if not program:
            self._show_error("The System Passport tool is not installed.")
            return
        self._document = None
        self.run_button.setEnabled(False)
        self.save_button.setEnabled(False)
        self.run_button.setText("Checking...")
        self.state.setText("Checking locally")
        self.state.setStyleSheet(_badge_style(theme.GOLD))
        self.title.setText("Reading this computer")
        self.summary.setText(
            "The read-only probes may take a few seconds. No network request is made.")
        self.context.setText("")
        self.capabilities.setText("")
        _clear(self.checks)
        self._process.start(program, ["--json"])

    def _finished(self, exit_code: int, _status) -> None:
        self.run_button.setEnabled(True)
        self.run_button.setText("Check again")
        if exit_code != 0:
            detail = bytes(self._process.readAllStandardError()).decode(
                "utf-8", "replace").strip()
            self._show_error(detail or f"The local check exited with status {exit_code}.")
            return
        raw = bytes(self._process.readAllStandardOutput()).decode("utf-8", "replace")
        try:
            document = json.loads(raw)
        except (TypeError, ValueError):
            self._show_error("The local check returned an unreadable report.")
            return
        if not isinstance(document, dict) or document.get("schema_version") != 1:
            self._show_error("The local check returned an unsupported report.")
            return
        self._document = document
        self.save_button.setEnabled(True)
        self._render(document)

    def _process_error(self, _error) -> None:
        if self._process.state() == QProcess.ProcessState.NotRunning:
            self.run_button.setEnabled(True)
            self.run_button.setText("Check again")
            self._show_error("The System Passport process could not start.")

    def _show_error(self, message: str) -> None:
        self.state.setText("Could not verify")
        self.state.setStyleSheet(_badge_style(theme.MUTED))
        self.title.setText("System Passport unavailable")
        self.summary.setText(message[:360])
        self.context.setText("Nothing was changed and no data was uploaded.")

    def _render(self, document: dict) -> None:
        verdict = document.get("verdict") or {}
        status = str(verdict.get("status") or "unknown")
        self.title.setText(str(verdict.get("title") or "Passport complete"))
        self.summary.setText(str(verdict.get("summary") or ""))
        display = {
            "ready": "Ready",
            "ready-with-notes": "Ready with notes",
            "needs-attention": "Needs attention",
            "unknown": "Could not verify",
        }.get(status, "Complete")
        color = {
            "ready": theme.GREEN,
            "ready-with-notes": theme.GOLD,
            "needs-attention": theme.RED,
        }.get(status, theme.MUTED)
        self.state.setText(display)
        self.state.setStyleSheet(_badge_style(color))

        context = document.get("context") or {}
        mode = str(context.get("mode") or "unknown").replace("-", " ")
        parts = [
            mode.capitalize(),
            str(context.get("operating_system") or "unknown system"),
            str(context.get("architecture") or "unknown architecture"),
        ]
        self.context.setText(" | ".join(parts))

        caps = document.get("capabilities") or {}
        bits = []
        if caps.get("camera_count"):
            bits.append(f"{caps['camera_count']} camera device(s)")
        if caps.get("bluetooth_controller_count"):
            bits.append(f"{caps['bluetooth_controller_count']} Bluetooth controller(s)")
        if caps.get("wireless_adapter_count"):
            bits.append(f"{caps['wireless_adapter_count']} Wi-Fi adapter(s)")
        self.capabilities.setText(
            "Also detected: " + ", ".join(bits) if bits
            else "No camera, Bluetooth controller or Wi-Fi adapter was additionally detected.")

        _clear(self.checks)
        for item in document.get("checks") or []:
            if not isinstance(item, dict):
                continue
            card = Card()
            row = QHBoxLayout(card)
            row.setContentsMargins(14, 10, 14, 10)
            row.setSpacing(12)
            text = QVBoxLayout()
            text.setSpacing(3)
            heading = QHBoxLayout()
            heading.addWidget(label(str(item.get("label") or "Check"), "cardTitle"))
            heading.addStretch(1)
            state = QLabel(str(item.get("status_label") or "Unknown"))
            state.setStyleSheet(
                "background: transparent; font-weight: 700; color: %s;" %
                STATUS_COLORS.get(str(item.get("status")), theme.MUTED))
            heading.addWidget(state)
            text.addLayout(heading)
            text.addWidget(label(str(item.get("summary") or ""), "detail", wrap=True))
            text.addWidget(label("Source: " + str(item.get("source") or "local probe"),
                                 "detail", wrap=True))
            row.addLayout(text, 1)
            route = item.get("route")
            action = item.get("action")
            if route and action:
                button = QPushButton(str(action))
                button.setObjectName("quiet")
                button.setFixedHeight(30)
                button.clicked.connect(
                    lambda _=False, destination=str(route):
                    self._open_route(destination))
                row.addWidget(button, alignment=Qt.AlignmentFlag.AlignVCenter)
            self.checks.addWidget(card)

    def _save(self) -> None:
        if self._document is None:
            return
        suggested = str(Path.home() / "Shadowfetch-System-Passport.html")
        destination, selected = QFileDialog.getSaveFileName(
            self, "Save redacted System Passport", suggested,
            "Web report (*.html);;JSON report (*.json)")
        if not destination:
            return
        path = Path(destination)
        try:
            if selected.startswith("JSON") or path.suffix.lower() == ".json":
                if path.suffix.lower() != ".json":
                    path = path.with_suffix(".json")
                content = json.dumps(self._document, indent=2) + "\n"
            else:
                if path.suffix.lower() not in (".html", ".htm"):
                    path = path.with_suffix(".html")
                content = _report_html(self._document)
            path.write_text(content, encoding="utf-8")
            self.summary.setText(f"Redacted report saved as {path.name}.")
        except OSError as error:
            self.summary.setText(f"The report could not be saved: {error.strerror or error}")
