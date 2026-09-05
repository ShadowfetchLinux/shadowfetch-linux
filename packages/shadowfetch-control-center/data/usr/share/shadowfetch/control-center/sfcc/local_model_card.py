"""Hardware facts and an explicit, real local completion check. No downloads."""
import os
from PyQt6.QtCore import QTimer, pyqtSignal
from PyQt6.QtWidgets import QComboBox, QHBoxLayout, QPushButton, QVBoxLayout
from sfcc.mission_client import JsonCommand
from sfcc.theme import Card, label, fmt_bytes

MODEL_CHECK = os.environ.get("SHADOWFETCH_MODEL_CHECK_COMMAND", "shadowfetch-model-check")


class ModelChooser(QComboBox):
    """Editable model IDs with QLineEdit-compatible helpers for the mission form."""
    def __init__(self):
        super().__init__()
        self.records = {}
        self.setEditable(True)
        self.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
        self.setAccessibleName("Local Buzz model")

    def text(self):
        return self.currentText()

    def setText(self, text):
        self.setEditText(text)

    def setPlaceholderText(self, text):
        self.lineEdit().setPlaceholderText(text)

    def current_record(self):
        return self.records.get(self.text().strip(), {})

    def set_models(self, models, default=""):
        selected = self.text().strip()
        self.records = {}
        for model in models:
            if isinstance(model, dict):
                key = model.get("id") or model.get("name")
                if key:
                    self.records[str(key)] = dict(model)
        self.clear()
        for model in models:
            value = model.get("id") or model.get("name") if isinstance(model, dict) else str(model)
            if value:
                self.addItem(str(value))
        self.setEditText(selected or default or (self.itemText(0) if self.count() else ""))


class LocalModelCard(Card):
    def __init__(self):
        super().__init__()
        self._busy = False
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 13, 16, 13)
        layout.setSpacing(8)
        heading = QHBoxLayout()
        heading.addWidget(label("Prove your local model works", "cardTitle"))
        heading.addStretch(1)
        self.refresh_button = QPushButton("Refresh models")
        self.refresh_button.setObjectName("quiet")
        self.refresh_button.clicked.connect(self.refresh)
        heading.addWidget(self.refresh_button)
        layout.addLayout(heading)
        layout.addWidget(label("Read local hardware and Buzz's available models, then run one real completion. No model is downloaded and nothing is uploaded.", "detail", wrap=True))
        self.hardware = label("", "detail", wrap=True)
        layout.addWidget(self.hardware)
        model_row = QHBoxLayout()
        self.model = ModelChooser()
        self.model.setPlaceholderText("Select an installed Buzz model")
        model_row.addWidget(self.model, 1)
        self.verify_button = QPushButton("Verify with a real task")
        self.verify_button.setEnabled(False)
        self.verify_button.clicked.connect(self.verify)
        model_row.addWidget(self.verify_button)
        layout.addLayout(model_row)
        self.state = label("Refresh to inspect local compute.", "statusWarn", wrap=True)
        layout.addWidget(self.state)
        self.receipt = label("", "detail", wrap=True)
        layout.addWidget(self.receipt)
        self.model.editTextChanged.connect(lambda value: self.verify_button.setEnabled(bool(value.strip()) and not self._busy))

    def refresh(self):
        if self._busy:
            return
        self._busy = True
        self.refresh_button.setEnabled(False)
        self.verify_button.setEnabled(False)
        self.state.setText("Reading local hardware and Buzz models…")
        JsonCommand(self, MODEL_CHECK, ["status", "--json"], self._status).start()

    def _status(self, data, error):
        self._busy = False
        self.refresh_button.setEnabled(True)
        if error or not isinstance(data, dict):
            self.state.setText(error or "The model helper returned an unexpected response.")
            self.verify_button.setEnabled(False)
            return
        hardware = data.get("hardware") or {}
        gpu = ", ".join(str(item.get("name", "")) for item in hardware.get("nvidia_gpus", []) if isinstance(item, dict))
        self.hardware.setText(f"RAM: {fmt_bytes(hardware.get('ram_total_bytes'))} total / {fmt_bytes(hardware.get('ram_available_bytes'))} available · Disk free: {fmt_bytes(hardware.get('disk_free_bytes'))}" + (f"\nGPU: {gpu}" if gpu else ""))
        self.model.set_models(data.get("models") or [])
        self.state.setText(("Models are listed. Run verification to prove inference works." if data.get("models") else str(data.get("message") or "No local model is available. Open Buzz to select one.")))
        self.verify_button.setEnabled(bool(self.model.text().strip()))

    def verify(self):
        if self._busy or not self.model.text().strip():
            return
        self._busy = True
        self.refresh_button.setEnabled(False)
        self.verify_button.setEnabled(False)
        self.state.setText("Running a real local completion… this may take up to two minutes.")
        self.receipt.setText("")
        JsonCommand(self, MODEL_CHECK, ["verify", "--model", self.model.text().strip(), "--json"], self._verified, timeout_ms=135_000).start()

    def _verified(self, data, error):
        self._busy = False
        self.refresh_button.setEnabled(True)
        self.verify_button.setEnabled(bool(self.model.text().strip()))
        passed = isinstance(data, dict) and (data.get("status") == "pass") and not error
        self.state.setObjectName("status" if passed else "statusWarn")
        if passed:
            seconds = data.get("elapsed_seconds", data.get("elapsed", "unknown"))
            self.state.setText(f"Real local inference passed · {seconds} seconds")
            self.receipt.setText("Receipt: " + str(data.get("receipt", "recorded by the local helper")))
        else:
            self.state.setText(error or str((data or {}).get("message") or (data or {}).get("error") or "The real completion did not pass. Open Buzz to inspect the model and retry."))
        self.state.style().unpolish(self.state)
        self.state.style().polish(self.state)
