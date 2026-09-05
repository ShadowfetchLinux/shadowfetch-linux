"""Shadowfetch Linux 4.0: persistent work with scope, evidence and review."""
import json
import shlex
from pathlib import Path
from urllib.parse import unquote

from PyQt6.QtCore import Qt, QTimer, QUrl
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtWidgets import (
    QAbstractItemView, QComboBox, QDialog, QFileDialog, QFormLayout,
    QGridLayout, QHBoxLayout, QLabel, QLineEdit, QListWidget, QListWidgetItem,
    QMessageBox, QPlainTextEdit, QPushButton, QScrollArea, QSplitter,
    QTabWidget, QVBoxLayout, QWidget,
)
from sfcc import theme
from sfcc.mission_client import MissionClient, JsonCommand, workspace_path, workspaces_root
from sfcc.local_model_card import MODEL_CHECK, ModelChooser
from sfcc.theme import Card, label

STATES = {
    "queued": "Queued", "running": "Working", "waiting-review": "Ready for review",
    "completed": "Accepted", "failed": "Needs attention", "cancelled": "Cancelled",
    "undone": "Restored",
}
KINDS = {"code": "Code & tests", "report": "Source report", "media": "Media export"}
TEMPLATES = {
    "code": ("Improve this project", "Describe the change and what proves it works. The agent works inside this project; review the diff and tests before accepting."),
    "report": ("A report from my documents", "Summarize the selected source documents. Cite the source for factual claims, distinguish uncertainty, and finish with practical next steps."),
    "media": ("Export my media", "Export the selected media with ffmpeg and write a verification receipt."),
}


def mission_summary(mission):
    return f"{STATES.get(mission.get('state'), str(mission.get('state', 'Unknown')))}  ·  {KINDS.get(mission.get('kind'), mission.get('kind', 'Mission'))}"


class NewMissionDialog(QDialog):
    """Queue only after the user can inspect scope and explicit network access."""
    def __init__(self, parent, client, on_created, workspace="", kind="code", capabilities=None):
        super().__init__(parent)
        self.client, self.on_created = client, on_created
        self.setWindowTitle("New mission · Shadowfetch")
        self.setMinimumSize(640, 580)
        self.resize(760, 680)
        self.setStyleSheet(theme.STYLESHEET)
        root = QVBoxLayout(self)
        root.setContentsMargins(20, 18, 20, 18)
        root.addWidget(label("What should we get done?", "pageTitle"))
        root.addWidget(label("Approve the project and connection. Your mission waits in the persistent queue.", "detail", wrap=True))
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        body = QWidget()
        form = QFormLayout(body)
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)
        form.setVerticalSpacing(10)
        self.kind = QComboBox()
        for key, name in KINDS.items():
            self.kind.addItem(name, key)
        self.kind.setCurrentIndex(max(0, self.kind.findData(kind)))
        form.addRow("Workflow", self.kind)
        self.title = QLineEdit()
        self.title.setMaxLength(160)
        self.title.setAccessibleName("Mission title")
        form.addRow("Title", self.title)
        self.workspace = QLineEdit(workspace)
        self.workspace.setPlaceholderText("Existing project name, e.g. launch-site")
        self.workspace.setAccessibleName("Approved project folder")
        browse = QPushButton("Choose folder")
        browse.setObjectName("quiet")
        browse.clicked.connect(self._browse)
        folder_row = QHBoxLayout()
        folder_row.addWidget(self.workspace, 1)
        folder_row.addWidget(browse)
        form.addRow("Project", folder_row)
        form.addRow("", label(f"One existing project directly inside {workspaces_root()}. No access to other personal folders.", "detail", wrap=True))
        self.prompt = QPlainTextEdit()
        self.prompt.setAccessibleName("Mission instructions")
        self.prompt.setMinimumHeight(100)
        self.prompt.setMaximumHeight(150)
        form.addRow("Instructions", self.prompt)
        self.runtime = QComboBox()
        self.runtime.addItem("Buzz compute · choose local or shared", "local")
        self.runtime.addItem("Codex · cloud account", "codex")
        self.runtime.setAccessibleName("Execution provider")
        form.addRow("Provider", self.runtime)
        self.model = ModelChooser()
        self.model.setPlaceholderText("Select or enter an installed Buzz model")
        model_row = QHBoxLayout()
        model_row.addWidget(self.model, 1)
        self.refresh_models = QPushButton("Refresh models")
        self.refresh_models.setObjectName("quiet")
        self.refresh_models.clicked.connect(self._load_models)
        model_row.addWidget(self.refresh_models)
        form.addRow("Buzz model", model_row)
        self.model_scope = label("Refresh models to inspect the execution route.", "detail", wrap=True)
        self.model.editTextChanged.connect(self._model_scope)
        form.addRow("", self.model_scope)
        self.network = QComboBox()
        self.network.addItem("Ice · no external network", "none")
        self.network.addItem("Fire · allow network for this mission", "allow")
        self.network.setCurrentIndex(0 if theme.ELEMENT == "ice" else 1)
        form.addRow("Connection", self.network)
        self.inputs = QPlainTextEdit()
        self.inputs.setPlaceholderText("One relative path per line, e.g. notes/brief.md")
        self.inputs.setAccessibleName("Selected input files")
        self.inputs.setMaximumHeight(68)
        form.addRow("Source files", self.inputs)
        self.tests = QLineEdit()
        self.tests.setPlaceholderText("e.g. python3 -m unittest discover -s tests")
        self.tests.setAccessibleName("Verification command")
        form.addRow("Code test", self.tests)
        self.workflow_note = label("", "detail", wrap=True)
        form.addRow("", self.workflow_note)
        if capabilities:
            ready = capabilities.get("summary")
            if isinstance(ready, str):
                form.addRow("Readiness", label(ready, "detail", wrap=True))
        scroll.setWidget(body)
        root.addWidget(scroll, 1)
        self.error = label("", "statusWarn", wrap=True)
        self.error.setAccessibleName("Mission validation result")
        root.addWidget(self.error)
        row = QHBoxLayout()
        row.addWidget(label("Changes stay pending until review.", "detail"))
        row.addStretch(1)
        cancel = QPushButton("Cancel")
        cancel.setObjectName("quiet")
        cancel.clicked.connect(self.reject)
        row.addWidget(cancel)
        self.queue = QPushButton("Queue mission")
        self.queue.clicked.connect(self._submit)
        row.addWidget(self.queue)
        root.addLayout(row)
        self.kind.currentIndexChanged.connect(self._template)
        self.runtime.currentIndexChanged.connect(self._provider)
        self._template()
        if isinstance(capabilities, dict):
            local = (capabilities.get("runtimes") or {}).get("local") or {}
            self.model.set_models(local.get("models") or [], local.get("default_model") or "")

    def _load_models(self):
        self.refresh_models.setEnabled(False)
        JsonCommand(self, MODEL_CHECK, ["status", "--json"], self._models_loaded).start()

    def _models_loaded(self, data, error):
        self.refresh_models.setEnabled(True)
        if error or not isinstance(data, dict):
            self.error.setText(error or "The local model service returned an unexpected response.")
            return
        self.model.set_models(data.get("models") or [])
        self.error.setText("Models listed. Use Local AI's real-task verification before relying on a new model." if data.get("models") else str(data.get("message") or "No model is installed. Open Buzz in Local AI to choose one."))

    def _browse(self):
        folder = QFileDialog.getExistingDirectory(self, "Choose an approved project", str(workspaces_root()))
        if folder:
            self.workspace.setText(folder)

    def _template(self):
        kind = self.kind.currentData()
        title, prompt = TEMPLATES[kind]
        self.title.setText(title)
        self.prompt.setPlainText(prompt)
        is_code = kind == "code"
        is_media = kind == "media"
        self.runtime.setEnabled(is_code)
        if not is_code:
            self.runtime.setCurrentIndex(0)
        self.model.setEnabled(not is_media)
        self.tests.setEnabled(is_code)
        self.inputs.setPlaceholderText("One relative media path per line" if is_media else "One relative document path per line")
        self.workflow_note.setText({
            "code": "Provide a test command so the result can be checked. Shell syntax is not evaluated; enter a program and its arguments.",
            "report": "Uses your selected Buzz model and text documents. The result includes source citations and a receipt.",
            "media": "Uses deterministic ffmpeg exports. Select one or more source media files; exported files and verification appear in Results.",
        }[kind])
        self._provider()

    def _model_scope(self, _value=None):
        if self.kind.currentData() == "media":
            self.model_scope.setText("FFmpeg export runs on this computer; no model is used.")
        elif self.runtime.currentData() == "codex":
            self.model_scope.setText("Codex uses its cloud service with your explicit connection approval.")
        elif self.model.current_record().get("local_only_verified") is True:
            self.model_scope.setText("Verified native model process on this computer. Locality is checked again before execution.")
        elif self.model.current_record().get("local_only_verified") is False:
            self.model_scope.setText("Buzz shared compute may run elsewhere. Fire network approval is required for this model.")
        else:
            self.model_scope.setText("Model route not yet verified. Refresh models; Ice will refuse execution unless its native process is proven local.")

    def _provider(self):
        cloud = self.runtime.currentData() == "codex" and self.kind.currentData() == "code"
        self.model.setEnabled(not cloud and self.kind.currentData() != "media")
        self.refresh_models.setEnabled(self.model.isEnabled())
        self.model.setPlaceholderText("Not used by Codex" if cloud else "Select or enter an installed Buzz model")
        self._model_scope()

    def arguments(self):
        title = self.title.text().strip()
        prompt = self.prompt.toPlainText().strip()
        if not title or not prompt:
            raise ValueError("Give the mission a title and instructions.")
        if not self.workspace.text().strip():
            raise ValueError("Choose an existing project folder or enter its name.")
        workspace = workspace_path(self.workspace.text().strip())
        runtime = self.runtime.currentData()
        kind = self.kind.currentData()
        network = self.network.currentData()
        if runtime == "codex" and network == "none":
            raise ValueError("Codex needs a cloud connection. Choose Fire for this mission or use a local model.")
        if kind != "media" and runtime == "local" and not self.model.text().strip():
            raise ValueError("Enter an installed Buzz model. Local AI helps you select and verify one for this computer.")
        if runtime == "local" and kind != "media" and network == "none" and self.model.current_record().get("local_only_verified") is False:
            raise ValueError("This model uses shared compute. Choose a verified native model or explicitly allow a Fire connection.")
        inputs = [line.strip() for line in self.inputs.toPlainText().splitlines() if line.strip()]
        for value in inputs:
            path = Path(value)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError("Source files must be relative paths inside the selected project.")
        if kind in ("report", "media") and not inputs:
            raise ValueError("Select at least one source file by its path inside the project.")
        args = ["create", "--kind", kind, "--workspace", str(workspace), "--title", title,
                "--prompt", prompt, "--runtime", runtime, "--network", network]
        if self.model.isEnabled() and self.model.text().strip():
            args += ["--model", self.model.text().strip()]
        for value in inputs:
            args += ["--input", value]
        if kind == "code":
            if not self.tests.text().strip():
                raise ValueError("Provide a code test command so completion can be verified.")
            command = shlex.split(self.tests.text())
            if not command:
                raise ValueError("The test command cannot be empty.")
            args += ["--test-json", json.dumps(command)]
        return args

    def _submit(self):
        try:
            args = self.arguments()
        except ValueError as error:
            self.error.setText(str(error))
            return
        self.queue.setEnabled(False)
        self.error.setText("Creating the mission…")
        self.client.call(args, self._created)

    def _created(self, data, error):
        self.queue.setEnabled(True)
        if error:
            self.error.setText(error)
            return
        self.on_created(data)
        self.accept()


class MissionsPage(QWidget):
    def __init__(self, open_route):
        super().__init__()
        self.open_route = open_route
        self.client = MissionClient(self)
        self.records = []
        self.selected_id = None
        self.selected = None
        self.capabilities = None
        self._refreshing = False
        self._detail_pending = False
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 10, 24, 18)
        root.setSpacing(10)
        hero = QHBoxLayout()
        words = QVBoxLayout()
        words.addWidget(label("Your computer. Your agents.", "pageTitle"))
        words.addWidget(label("Work you can inspect. Every mission has a scope, a result and a review.", "subtitle", wrap=True))
        hero.addLayout(words, 1)
        self.new_button = QPushButton("＋  New mission")
        self.new_button.setMinimumHeight(40)
        self.new_button.clicked.connect(lambda: self.new_mission())
        hero.addWidget(self.new_button)
        root.addLayout(hero)
        featured = Card(active=True)
        featured_row = QHBoxLayout(featured)
        featured_row.setContentsMargins(16, 11, 16, 11)
        featured_copy = QVBoxLayout()
        featured_copy.addWidget(label("GROK BOT   /   FEATURED TEAMMATE", "safety"))
        featured_copy.addWidget(label("Give real work to the official Grok Bot desktop.", "cardTitle", wrap=True))
        self.grok_state = label("Checking native app…", "detail", wrap=True)
        featured_copy.addWidget(self.grok_state)
        featured_row.addLayout(featured_copy, 1)
        grok = QPushButton("Explore Grok Bot  →")
        grok.setObjectName("quiet")
        grok.clicked.connect(lambda: self.open_route("grok-bot"))
        featured_row.addWidget(grok)
        root.addWidget(featured)
        metrics = QHBoxLayout()
        self.stats = label("Reading the local queue…", "safety", wrap=True)
        metrics.addWidget(self.stats, 1)
        self.filter = QComboBox()
        for title, key in (("All missions", "all"), ("Active", "active"), ("Review", "waiting-review"), ("Needs attention", "failed"), ("Finished", "finished")):
            self.filter.addItem(title, key)
        self.filter.currentIndexChanged.connect(self._populate)
        metrics.addWidget(self.filter)
        refresh = QPushButton("Refresh")
        refresh.setObjectName("quiet")
        refresh.clicked.connect(self.refresh)
        metrics.addWidget(refresh)
        root.addLayout(metrics)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        self.queue = QListWidget()
        self.queue.setAccessibleName("Persistent mission queue")
        self.queue.setMinimumWidth(215)
        self.queue.currentItemChanged.connect(self._selection_changed)
        splitter.addWidget(self.queue)
        detail = QWidget()
        self.detail_layout = QVBoxLayout(detail)
        self.detail_layout.setContentsMargins(12, 0, 0, 0)
        self.detail_layout.setSpacing(8)
        self.detail_title = label("Choose a mission, or start with a small task.", "cardTitle", wrap=True)
        self.detail_layout.addWidget(self.detail_title)
        self.detail_meta = label("Code with verified tests · Reports with sources · Media with receipts", "detail", wrap=True)
        self.detail_layout.addWidget(self.detail_meta)
        self.tabs = QTabWidget()
        self.overview = QPlainTextEdit()
        self.overview.setReadOnly(True)
        self.overview.setPlainText("Get started\n\n1. Create a project in Workbench, then select it in New mission.\n2. Choose code, a source report or a media export.\n3. Approve the folder and connection.\n4. Inspect the results, tests and changes before you accept.\n\nQueued work survives logout and restart. Interrupted work needs review or retry; the queue never silently repeats a task.")
        self.events = QPlainTextEdit()
        self.events.setReadOnly(True)
        self.diff = QPlainTextEdit()
        self.diff.setReadOnly(True)
        self.artifacts = QListWidget()
        self.artifacts.setAccessibleName("Mission output files")
        self.artifacts.itemDoubleClicked.connect(self._open_artifact)
        self.tabs.addTab(self.overview, "Overview")
        self.tabs.addTab(self.events, "Activity")
        self.tabs.addTab(self.diff, "Changes")
        self.tabs.addTab(self.artifacts, "Results")
        self.detail_layout.addWidget(self.tabs, 1)
        self.action_row = QGridLayout()
        self.actions = {}
        for index, (key, title) in enumerate((("accept", "Accept result"), ("undo", "Restore changes"), ("cancel", "Cancel"), ("retry", "Retry"), ("folder", "Open project"), ("receipt", "Receipt"))):
            button = QPushButton(title)
            if key != "accept":
                button.setObjectName("quiet")
            button.setEnabled(False)
            button.clicked.connect(lambda _checked=False, action=key: self._action(action))
            self.actions[key] = button
            self.action_row.addWidget(button, index // 3, index % 3)
        self.detail_layout.addLayout(self.action_row)
        splitter.addWidget(detail)
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 3)
        splitter.setSizes([270, 490])
        root.addWidget(splitter, 1)
        self.notice = label("", "statusWarn", wrap=True)
        self.notice.setAccessibleName("Mission service status")
        root.addWidget(self.notice)
        self.timer = QTimer(self)
        self.timer.setInterval(3000)
        self.timer.timeout.connect(self._poll)
        self.timer.start()
        QTimer.singleShot(0, self.refresh)
        self.client.grok_status(self._grok_ready)
        self.client.call(["capabilities"], self._capabilities_ready)

    def _poll(self):
        if self.isVisible():
            self.refresh()

    def refresh(self):
        if self._refreshing:
            return
        self._refreshing = True
        self.client.call(["list"], self._listed)

    def _listed(self, data, error):
        self._refreshing = False
        if error:
            self.notice.setText(error)
            self.stats.setText("Queue unavailable")
            return
        if not isinstance(data, list):
            self.notice.setText("The mission queue returned an unexpected response.")
            return
        self.notice.setText("")
        self.records = [m for m in data if isinstance(m, dict) and m.get("id")]
        counts = {state: sum(1 for mission in self.records if mission.get("state") == state) for state in STATES}
        self.stats.setText(f"{counts['running']} working    {counts['queued']} queued    {counts['waiting-review']} to review    {counts['completed']} accepted")
        self._populate()
        self._refresh_detail()

    def _populate(self):
        key = self.filter.currentData()
        selected = self.selected_id
        self.queue.blockSignals(True)
        self.queue.clear()
        visible = []
        for mission in self.records:
            state = mission.get("state")
            if key == "active" and state not in ("queued", "running"):
                continue
            if key == "finished" and state not in ("completed", "cancelled", "undone"):
                continue
            if key not in ("all", "active", "finished") and state != key:
                continue
            item = QListWidgetItem(f"{mission.get('title', 'Untitled mission')}\n{mission_summary(mission)}")
            item.setData(Qt.ItemDataRole.UserRole, mission["id"])
            item.setToolTip(str(mission.get("workspace", "")))
            self.queue.addItem(item)
            visible.append(item)
            if mission["id"] == selected:
                self.queue.setCurrentItem(item)
        self.queue.blockSignals(False)
        if self.queue.currentItem() is None and visible:
            self.queue.setCurrentItem(visible[0])
        elif not visible:
            self.selected_id = None
            self.selected = None
            self._buttons()
            self.detail_title.setText("No missions in this view.")
            self.detail_meta.setText("Create a mission to begin, or change the filter.")
            self.events.clear()
            self.diff.clear()
            self.artifacts.clear()
            self.overview.setPlainText("Your results will appear here.\n\nUse New mission to choose an approved project, task and provider. The local queue records progress and keeps reviewable evidence.")

    def _selection_changed(self, current, _previous):
        if current:
            self.selected_id = current.data(Qt.ItemDataRole.UserRole)
            self._refresh_detail()

    def _refresh_detail(self):
        if not self.selected_id or self._detail_pending:
            return
        requested = self.selected_id
        self._detail_pending = True
        self.client.call(["show", requested], lambda data, error: self._shown(requested, data, error))

    def _shown(self, requested, data, error):
        self._detail_pending = False
        if requested != self.selected_id:
            self._refresh_detail()
            return
        if error:
            self.notice.setText(error)
            return
        if not isinstance(data, dict):
            return
        self.selected = data
        self.detail_title.setText(str(data.get("title", "Untitled mission")))
        self.detail_meta.setText(mission_summary(data) + "\n" + str(data.get("workspace", "")))
        config = data.get("config") or {}
        lines = [str(data.get("prompt", "")), "", f"Mission: {data.get('id')}",
                 f"Provider: {config.get('runtime', 'local')} · Network: {config.get('network', 'none')}",
                 f"Created: {data.get('created_at', 'unknown')}", f"Updated: {data.get('updated_at', 'unknown')}",
                 f"Attempt: {data.get('attempt', 0)}"]
        if data.get("error"):
            lines += ["", "Needs attention", str(data["error"])]
        if data.get("state") == "waiting-review":
            lines += ["", "The result is ready. Inspect Changes, Results and the receipt; accept it or restore the mission's local changes."]
        self._replace_text(self.overview, "\n".join(lines))
        self.artifacts.clear()
        for artifact in data.get("artifacts", []):
            path = artifact.get("path", "") if isinstance(artifact, dict) else str(artifact)
            item = QListWidgetItem(Path(path).name or path)
            item.setData(Qt.ItemDataRole.UserRole, path)
            item.setToolTip(f"{path}\nDouble-click to open this output file")
            self.artifacts.addItem(item)
        if not self.artifacts.count():
            item = QListWidgetItem("No output files recorded yet.")
            item.setFlags(Qt.ItemFlag.NoItemFlags)
            self.artifacts.addItem(item)
        self._buttons()
        self.client.call(["events", requested], lambda value, err: self._events_ready(requested, value, err))
        self.client.call(["diff", requested], lambda value, err: self._diff_ready(requested, value, err))

    @staticmethod
    def _replace_text(widget, text):
        if widget.toPlainText() != text:
            position = widget.verticalScrollBar().value()
            widget.setPlainText(text)
            widget.verticalScrollBar().setValue(position)

    def _events_ready(self, requested, data, error):
        if requested != self.selected_id:
            return
        if error:
            self._replace_text(self.events, error)
        elif isinstance(data, list):
            self._replace_text(self.events, "\n\n".join(f"{e.get('at', '')}  {e.get('event', '')}\n{e.get('detail', '')}" for e in data if isinstance(e, dict)) or "No activity recorded yet.")

    def _diff_ready(self, requested, data, error):
        if requested == self.selected_id:
            self._replace_text(self.diff, error or (str(data.get("diff", "")) if isinstance(data, dict) else "") or "No text changes recorded yet.")

    def _buttons(self):
        mission = self.selected or {}
        state = mission.get("state")
        for key, button in self.actions.items():
            button.setEnabled(bool(mission) and {
                "accept": state == "waiting-review",
                "undo": state in ("waiting-review", "completed", "failed", "cancelled") and bool(mission.get("checkpoint")),
                "cancel": state in ("queued", "running"),
                "retry": state in ("failed", "cancelled"),
                "folder": bool(mission.get("workspace")),
                "receipt": bool(mission.get("receipt")),
            }[key])

    def _action(self, action):
        mission = self.selected
        if not mission:
            return
        if action in ("folder", "receipt"):
            self._open_path(mission.get("workspace" if action == "folder" else "receipt", ""))
            return
        if action == "undo":
            answer = QMessageBox.question(self, "Restore this mission's changes?", "The engine will restore the project checkpoint for this mission. Review the diff first. Files changed since the mission may cause a conflict; the engine will report that instead of silently overwriting them.", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel, QMessageBox.StandardButton.Cancel)
            if answer != QMessageBox.StandardButton.Yes:
                return
        args = ["review", mission["id"], "--decision", action] if action in ("accept", "undo") else [action, mission["id"]]
        for button in self.actions.values():
            button.setEnabled(False)
        self.client.call(args, self._mutated)

    def _mutated(self, data, error):
        if error:
            self.notice.setText(error)
            self._buttons()
            QMessageBox.warning(self, "Mission needs attention", error)
        else:
            self.refresh()

    def _open_path(self, value):
        path = Path(str(value)).expanduser()
        if not path.is_absolute() and self.selected:
            path = Path(self.selected["workspace"]) / path
        if not path.exists():
            self.notice.setText(f"This file is not available: {path}")
        elif not QDesktopServices.openUrl(QUrl.fromLocalFile(str(path))):
            self.notice.setText("The desktop could not open this file. Its path is shown in Results.")

    def _open_artifact(self, item):
        value = item.data(Qt.ItemDataRole.UserRole)
        if value:
            self._open_path(value)

    def _grok_ready(self, data, error):
        if error or not isinstance(data, dict):
            self.grok_state.setText("Setup helper unavailable. Open Grok Bot for repair details.")
        elif data.get("verified") and data.get("launchable"):
            self.grok_state.setText(f"Native app {data.get('installed_version', '')} verified · Sign in inside Grok Bot")
        else:
            self.grok_state.setText("Install the native app · Cloud service · Eligible account and plan required")

    def _capabilities_ready(self, data, error):
        if not error and isinstance(data, dict):
            self.capabilities = data

    def new_mission(self, workspace="", kind="code"):
        dialog = NewMissionDialog(self, self.client, self._created, workspace, kind, self.capabilities)
        dialog.exec()

    def _created(self, data):
        if isinstance(data, dict):
            self.selected_id = data.get("id")
        self.filter.setCurrentIndex(0)
        self.refresh()

    def route(self, parts):
        if not parts:
            return
        if parts[0] == "new":
            params = dict(p.split("=", 1) for p in parts[1:] if "=" in p)
            QTimer.singleShot(0, lambda: self.new_mission(unquote(params.get("workspace", "")), params.get("kind", "code")))
        else:
            self.selected_id = parts[0]
            self.refresh()
