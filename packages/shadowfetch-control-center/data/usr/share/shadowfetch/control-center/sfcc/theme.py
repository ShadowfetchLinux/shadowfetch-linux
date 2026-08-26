"""Shared palette, stylesheet and small widgets for the Control Center.

The palette is the one the 2.1.1 Control Center shipped with (deep graphite
plus Umbra Gold); every 2.1.2 page draws from here so Ignite, Watch,
Recover, Guide, Local AI, Drivers and Software & Updates read as one application.
"""

from PyQt6.QtCore import Qt, QProcess, pyqtSignal
from PyQt6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
)

# ---- palette ---------------------------------------------------------------

BG = "#151619"
CARD = "#202126"
CARD_HOVER = "#26272d"
BORDER = "#34363d"
GOLD = "#d8a24a"
GOLD_HOVER = "#efb95d"
GOLD_PRESS = "#bf8735"

# --- Fire and Ice (3.1) -----------------------------------------------------
# The element mirrors the brand accents: Fire keeps Umbra gold, Ice swaps the
# warm trio for its azure reflection (#d8a24a -> #4aa2d8 is a literal R/B
# mirror). Semantic colors (GREEN/AMBER/ORANGE/RED) keep their meanings in
# both elements — a warning must stay warning-colored on a cold desktop.
def _element() -> str:
    import os
    v = os.environ.get("SHADOWFETCH_ELEMENT", "")
    for path in (
        os.path.join(os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config")), "shadowfetch/element"),
        "/etc/shadowfetch/element",
    ):
        if v:
            break
        try:
            with open(path, encoding="utf-8") as fh:
                v = fh.readline().strip()
        except OSError:
            continue
    return v if v in ("fire", "ice") else "fire"

ELEMENT = _element()
if ELEMENT == "ice":
    GOLD = "#4aa2d8"
    GOLD_HOVER = "#5db9ef"
    GOLD_PRESS = "#3587bf"
TEXT = "#f0eee9"
MUTED = "#aaa69f"
GREEN = "#72c69c"
AMBER = "#e8b65e"
ORANGE = "#ef8b3a"
RED = "#e2533b"
INK = "#151515"

STYLESHEET = f"""
    QWidget {{ background: {BG}; color: {TEXT}; font-size: 13px; }}

    QFrame#card {{ background: {CARD}; border: 1px solid {BORDER}; border-radius: 8px; }}
    QFrame#card:hover {{ border-color: {GOLD}; }}
    QFrame#cardActive {{ background: {CARD}; border: 2px solid {GOLD}; border-radius: 8px; }}
    QFrame#tile {{ background: {CARD}; border: 1px solid {BORDER}; border-radius: 8px; }}
    QFrame#banner {{ background: #2a2413; border: 1px solid {GOLD}; border-radius: 8px; }}
    QFrame#bannerWarn {{ background: #2a1815; border: 1px solid {RED}; border-radius: 8px; }}

    QLabel {{ background: transparent; }}
    QLabel#title {{ font-size: 26px; font-weight: 700; }}
    QLabel#pageTitle {{ font-size: 22px; font-weight: 700; }}
    QLabel#subtitle {{ color: {MUTED}; }}
    QLabel#detail {{ color: {MUTED}; font-size: 12px; }}
    QLabel#cardTitle {{ font-size: 16px; font-weight: 650; }}
    QLabel#status {{ color: {GREEN}; font-weight: 650; }}
    QLabel#statusWarn {{ color: {AMBER}; font-weight: 650; }}
    QLabel#safety {{ color: {GOLD}; font-weight: 650; }}
    QLabel#big {{ font-size: 20px; font-weight: 700; }}
    QLabel#badge {{ background: {GOLD}; color: {INK}; border-radius: 9px;
                    padding: 1px 7px; font-weight: 700; font-size: 12px; }}

    QPushButton {{ background: {GOLD}; color: {INK}; border: 0; border-radius: 6px;
                   padding: 6px 12px; font-weight: 700; }}
    QPushButton:hover {{ background: {GOLD_HOVER}; }}
    QPushButton:pressed {{ background: {GOLD_PRESS}; }}
    QPushButton:disabled {{ background: {BORDER}; color: {MUTED}; }}
    QPushButton#quiet {{ background: {CARD}; color: {TEXT}; border: 1px solid {BORDER}; }}
    QPushButton#quiet:hover {{ border-color: {GOLD}; }}
    QPushButton#quiet:disabled {{ color: {MUTED}; }}

    QListWidget#sidebar {{ background: #101114; border: 0; outline: 0; padding-top: 8px; }}
    QListWidget#sidebar::item {{ border: 0; border-left: 3px solid transparent;
                                 padding: 2px 6px; margin: 1px 0; }}
    QListWidget#sidebar::item:selected {{ background: {CARD}; border-left: 3px solid {GOLD}; }}
    QListWidget#sidebar::item:hover {{ background: #191b1f; }}

    QTabWidget::pane {{ border: 1px solid {BORDER}; border-radius: 6px; top: -1px; }}
    QTabBar::tab {{ background: transparent; color: {MUTED}; padding: 7px 16px;
                    border: 0; font-weight: 650; }}
    QTabBar::tab:selected {{ color: {TEXT}; border-bottom: 2px solid {GOLD}; }}

    QTableWidget {{ background: {CARD}; border: 1px solid {BORDER}; border-radius: 6px;
                    gridline-color: {BORDER}; }}
    QTableWidget::item {{ padding: 4px 8px; }}
    QTableWidget::item:selected {{ background: #33342e; color: {TEXT}; }}
    QHeaderView::section {{ background: {CARD}; color: {MUTED}; border: 0;
                            border-bottom: 1px solid {BORDER}; padding: 6px 8px;
                            font-weight: 650; }}
    QTableCornerButton::section {{ background: {CARD}; border: 0; }}

    QComboBox {{ background: {CARD}; border: 1px solid {BORDER}; border-radius: 6px;
                 padding: 5px 10px; }}
    QComboBox:hover {{ border-color: {GOLD}; }}
    QComboBox QAbstractItemView {{ background: {CARD}; border: 1px solid {BORDER};
                                   selection-background-color: #33342e; }}

    QCheckBox {{ spacing: 8px; }}
    QCheckBox::indicator {{ width: 18px; height: 18px; border: 1px solid {BORDER};
                            border-radius: 4px; background: {CARD}; }}
    QCheckBox::indicator:checked {{ background: {GOLD}; border-color: {GOLD}; }}

    QPlainTextEdit {{ background: #101114; border: 1px solid {BORDER}; border-radius: 6px;
                      color: {TEXT}; font-family: monospace; font-size: 12px; }}
    QScrollArea {{ border: 0; }}
"""


# ---- small helpers ---------------------------------------------------------

def label(text: str, object_name: str | None = None, wrap: bool = False) -> QLabel:
    lab = QLabel(text)
    if object_name:
        lab.setObjectName(object_name)
    if wrap:
        lab.setWordWrap(True)
    return lab


class Card(QFrame):
    """A rounded card with the standard border; pass active=True for the
    gold-outlined variant used by armed profile cards."""

    def __init__(self, active: bool = False):
        super().__init__()
        self.setObjectName("cardActive" if active else "card")

    def set_active(self, active: bool) -> None:
        self.setObjectName("cardActive" if active else "card")
        # Re-polish so the objectName change takes effect immediately.
        self.style().unpolish(self)
        self.style().polish(self)


def tier_color(tier: str) -> str:
    t = (tier or "").strip().lower()
    if t in ("high", "hot", "inferno"):
        return RED
    if t in ("warm", "medium", "elevated"):
        return AMBER
    return GREEN


def fmt_bytes(n) -> str:
    """1234567890 -> '1.1 GB'.  Returns em dash for anything non-numeric."""
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "—"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            if unit == "B":
                return f"{int(n)} B"
            return f"{n:.1f} {unit}"
        n /= 1024
    return "—"


def fmt_mb(n) -> str:
    """Bytes -> whole megabytes, for download sizes on cards."""
    try:
        return f"{int(round(float(n) / (1024 * 1024)))} MB"
    except (TypeError, ValueError):
        return "—"


class ProcessDialog(QDialog):
    """Runs one command, streams its output into a read-only log, and only
    enables Close when the command has finished.  Used for pkexec helpers
    (phoenix-restore, bundle installs) so the user always sees what the
    privileged tool actually did."""

    completed = pyqtSignal(int)

    def __init__(self, parent, title: str, argv: list[str], intro: str = ""):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumSize(640, 420)
        self.setStyleSheet(STYLESHEET)
        self._argv = argv
        self.exit_code: int | None = None

        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 14, 16, 14)
        lay.setSpacing(10)
        lay.addWidget(label(title, "cardTitle"))
        if intro:
            lay.addWidget(label(intro, "detail", wrap=True))
        self._log = QPlainTextEdit()
        self._log.setReadOnly(True)
        lay.addWidget(self._log, 1)
        self._state = label("Running…", "statusWarn")
        row = QHBoxLayout()
        row.addWidget(self._state)
        row.addStretch(1)
        self._close = QPushButton("Close")
        self._close.setEnabled(False)
        self._close.clicked.connect(self.accept)
        row.addWidget(self._close)
        lay.addLayout(row)

        self._proc = QProcess(self)
        self._proc.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        self._proc.readyReadStandardOutput.connect(self._read)
        self._proc.finished.connect(self._done)
        self._proc.errorOccurred.connect(self._error)

    def start(self) -> None:
        self._log.appendPlainText("$ " + " ".join(self._argv) + "\n")
        self._proc.start(self._argv[0], self._argv[1:])

    def _read(self) -> None:
        data = bytes(self._proc.readAllStandardOutput()).decode("utf-8", "replace")
        if data:
            self._log.insertPlainText(data)
            self._log.verticalScrollBar().setValue(self._log.verticalScrollBar().maximum())

    def _done(self, code, _status) -> None:
        self._read()
        self.exit_code = int(code)
        if code == 0:
            self._state.setText("Finished successfully.")
            self._state.setObjectName("status")
        else:
            self._state.setText(f"Finished with status {code}.")
            self._state.setObjectName("statusWarn")
        self._state.style().unpolish(self._state)
        self._state.style().polish(self._state)
        self._close.setEnabled(True)
        self.completed.emit(int(code))

    def _error(self, _err) -> None:
        if self.exit_code is None:
            self._log.appendPlainText("\nThe command could not be started.")
            self.exit_code = 127
            self._state.setText("Could not start the command.")
            self._close.setEnabled(True)
            self.completed.emit(127)
