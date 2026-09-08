"""Shadowfetch Linux 4.0: persistent work with scope, evidence and review."""
import json
import shlex
from pathlib import Path
from urllib.parse import unquote

from PyQt6.QtCore import Qt, QTimer, QUrl, QProcess
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtWidgets import (
    QAbstractItemView, QComboBox, QDialog, QFileDialog, QFormLayout,
    QGridLayout, QHBoxLayout, QLabel, QLayout, QLineEdit, QListWidget, QListWidgetItem,
    QMessageBox, QPlainTextEdit, QPushButton, QScrollArea, QSplitter,
    QTabWidget, QVBoxLayout, QWidget,
)
from sfcc import theme
from sfcc.mission_client import MissionClient, JsonCommand, workspace_path, workspaces_root
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


# What the engine publishes for each record set and the fields worth showing.
# The keys and the field names are the engine's own, so a person reading this
# panel and a person reading the database are looking at the same words.
RECORD_SECTIONS = (
    ("tasks", "Steps",
     ("seq", "kind", "state", "started_at", "finished_at", "exit_code", "error")),
    ("sessions", "Agent sessions",
     ("id", "provider_id", "provider_version", "provider_trust", "attempt",
      "network_requested", "network_effective", "started_at", "ended_at",
      "exit_code", "outcome")),
    ("test_runs", "Test runs",
     ("started_at", "command", "network_requested", "network_effective",
      "guard_state", "duration_ms", "exit_code", "result")),
    ("git_changes", "Repository structure",
     ("observed_at", "head_before", "head_after", "refs_changed",
      "remotes_changed", "hooks_changed", "new_executables")),
    ("reviews", "Review",
     ("requested_at", "summary", "diff_truncated", "blast_radius",
      "decided_at", "decision", "decided_by")),
)

NOT_ENFORCED_HEADING = "Relied on by this decision and NOT enforced:"


def field_text(value):
    if value is None:
        return "not recorded"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (list, tuple)):
        return ", ".join(str(item) for item in value) or "none"
    if isinstance(value, dict):
        return json.dumps(value, sort_keys=True)[:300]
    return str(value)[:300]


def mission_text(mission):
    """State, who performs it, and what was asked for -- as recorded."""
    config = mission.get("config") or {}
    return "\n".join([
        "State: " + STATES.get(mission.get("state"), field_text(mission.get("state"))),
        "Performed by: " + field_text(mission.get("provider_id") or config.get("provider_id"))
        + "   ·   capability: " + field_text(mission.get("capability") or config.get("capability")),
        "Connection requested: " + field_text(config.get("network")),
        "Stop requested: " + ("yes" if mission.get("cancel_requested") else "no"),
        "Approval recorded against this mission: " + field_text(mission.get("approval_id")),
        "Attempt: " + field_text(mission.get("attempt")),
    ])


def decision_text(decision):
    """The engine's decision, quoted. Nothing here re-derives one."""
    if not isinstance(decision, dict):
        return "No policy decision was returned for this mission."
    scope = decision.get("scope") or {}
    lines = ["Decision: " + field_text(decision.get("outcome"))]
    lines += ["  " + str(reason) for reason in decision.get("reasons") or []]
    lines.append("Scope: " + "   ·   ".join(
        key + ": " + field_text(value) for key, value in sorted(scope.items())))
    return "\n".join(lines)


def caveat_text(decision):
    """The controls this decision leans on that nothing actually applies.

    A scope shown on its own reads as a list of rules in force. The engine
    already separates what it decided from what it can make happen, and names
    the difference per field; this repeats both rather than letting the scope
    stand unqualified.
    """
    if not isinstance(decision, dict):
        return ""
    mediation = decision.get("mediation") or {}
    if "advisory_fields" not in decision:
        # ABSENT is not EMPTY. A reply that never carried the field means this
        # build could not ask, and printing the reassuring sentence for it would
        # turn "we do not know" into "there is nothing to know".
        return ("This build could not determine which controls the decision "
                "relies on. Treat nothing here as enforced.")
    names = decision.get("advisory_fields") or []
    if not names:
        return ("This decision relies on no control that Mission Control cannot "
                "enforce.")
    lines = [NOT_ENFORCED_HEADING]
    for name in names:
        entry = mediation.get(name) or {}
        lines.append("  " + str(name) + " — " + field_text(entry.get("mediation"))
                     + " — " + field_text(entry.get("mechanism")))
    return "\n".join(lines)


def audit_text(report, error=None):
    """What the chain proves, and separately what the external anchor proves.

    An intact chain says the rows agree with each other. Only the anchor speaks
    to truncation, so its verdict is printed beside the chain's and never folded
    into it.
    """
    if error:
        return "The audit log could not be verified: " + error
    if not isinstance(report, dict):
        return "The audit log has not been verified in this session."
    anchor = report.get("anchor") or {}
    lines = [
        "Chain: " + ("intact" if report.get("ok") else "BROKEN"),
        "Events: " + field_text(report.get("events"))
        + "   ·   chained: " + field_text(report.get("chained"))
        + "   ·   unchained: " + field_text(report.get("unchained")),
        "Head: seq " + field_text(report.get("head_seq")) + " "
        + str(report.get("head") or "")[:16],
        "External anchor: " + field_text(anchor.get("verdict"))
        + " (" + field_text(anchor.get("identifier")) + ")",
    ]
    if report.get("unchained"):
        lines.append("  Unchained rows were written before the chain existed. They "
                     "are pinned by the genesis digest and are not individually "
                     "verifiable.")
    if anchor.get("reason"):
        lines.append("  " + str(anchor["reason"]))
    if anchor.get("mirror_failures"):
        lines.append("  Mirror failures: " + field_text(anchor.get("mirror_failures"))
                     + " (last: " + field_text(anchor.get("last_mirror_error")) + ")")
    lines += ["  PROBLEM: " + str(problem) for problem in report.get("problems") or []]
    return "\n".join(lines)


def approval_line(row):
    return ("{id}   ·   granted {granted_at} by {granted_by} via {method}"
            "   ·   expires: {expires}   ·   revoked: {revoked}").format(
        id=field_text(row.get("id")), granted_at=field_text(row.get("granted_at")),
        granted_by=field_text(row.get("granted_by")), method=field_text(row.get("method")),
        expires=field_text(row.get("expires_at")), revoked=field_text(row.get("revoked_at")))


def records_text(mission):
    """Steps, sessions, test runs, repository change and review, as reported.

    Absent and empty are different facts. This engine's CLI publishes no record
    sets at all, so each section says that rather than rendering an empty list a
    reader would take for "nothing happened".
    """
    lines = []
    for key, heading, fields in RECORD_SECTIONS:
        rows = mission.get(key)
        if rows is None:
            lines.append(heading + ": not reported. The mission CLI has no command "
                         "that returns " + key + "; their events appear in Activity.")
        elif not rows:
            lines.append(heading + ": none recorded.")
        else:
            lines.append(heading + ":")
            lines += ["    " + "   ·   ".join(
                name + ": " + field_text(row.get(name)) for name in fields if name in row)
                for row in rows if isinstance(row, dict)]
    return "\n".join(lines)


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
        self.form = form
        form.setSizeConstraint(QLayout.SizeConstraint.SetMinimumSize)
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        form.setVerticalSpacing(10)
        self.kind = QComboBox()
        for key, name in KINDS.items():
            self.kind.addItem(name, key)
        self.kind.setCurrentIndex(max(0, self.kind.findData(kind)))
        self.capabilities = capabilities or {}
        # Who performs it. Populated from the engine's provider registry, so a
        # provider installed after this release still appears here without the
        # Control Center being changed. Hidden while only one provider can do
        # the job, which is today's experience.
        self.provider_choice = QComboBox()
        self.provider_choice.setAccessibleName("Which agent performs this mission")
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
        self.provider = label("", "detail", wrap=True)
        form.addRow("Provider", self.provider)
        self.provider_setup = label("", "detail", wrap=True)
        form.addRow("", self.provider_setup)
        self.account_login = QPushButton("Sign in to Codex for missions…")
        self.account_login.clicked.connect(self._login_account)
        form.addRow("", self.account_login)
        self.network = QComboBox()
        self.network.addItem("Ice · no external network", "none")
        self.network.addItem("Fire · allow network for this mission", "allow")
        self.network.setCurrentIndex(0 if theme.ELEMENT == "ice" else 1)
        form.addRow("Performed by", self.provider_choice)
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
        self._template()
    def _browse(self):
        folder = QFileDialog.getExistingDirectory(self, "Choose an approved project", str(workspaces_root()))
        if folder:
            self.workspace.setText(folder)

    def providers_for(self, kind):
        """(capability, [(provider_id, info)]) for a legacy mission kind.

        The engine publishes capability_kinds and providers; this reads them.
        There is no provider name in this file any more.
        """
        kinds = self.capabilities.get("capability_kinds") or {}
        capability = next((c for c, k in kinds.items() if k == kind), None)
        options = []
        for provider_id, info in sorted((self.capabilities.get("providers") or {}).items()):
            if capability and capability in (info.get("capabilities") or []):
                options.append((provider_id, info))
        return capability, options

    def _template(self):
        kind = self.kind.currentData()
        title, prompt = TEMPLATES[kind]
        self.title.setText(title)
        self.prompt.setPlainText(prompt)
        is_code = kind == "code"
        is_media = kind == "media"
        capability, options = self.providers_for(kind)
        chosen = self.provider_choice.currentData()
        self.provider_choice.blockSignals(True)
        self.provider_choice.clear()
        for provider_id, info in options:
            suffix = "" if info.get("available") else " · needs setup"
            self.provider_choice.addItem(info.get("display_name", provider_id) + suffix, provider_id)
        if chosen:
            self.provider_choice.setCurrentIndex(max(0, self.provider_choice.findData(chosen)))
        self.provider_choice.blockSignals(False)
        # One provider is the ordinary case; do not make a person choose.
        self.form.setRowVisible(self.provider_choice, len(options) > 1)
        info = dict(options).get(self.provider_choice.currentData(), {})
        known = bool(options)
        # If the engine has not described itself, the honest position is that
        # we do not know who will perform this -- so leave the connection
        # choice with the person and let Mission Control choose the provider.
        needs_network = bool(info.get("requires_network_approval")) if known else True
        self.provider.setText(
            info.get("display_name") or ("Chosen by Mission Control" if not known
                                         else "No installed agent performs this"))
        self.provider_setup.setText("" if not known or info.get("available")
                                    else (info.get("reason") or ""))
        self.network.setEnabled(needs_network and theme.ELEMENT != "ice")
        if known:
            self.network.setCurrentIndex(0 if not needs_network or theme.ELEMENT == "ice" else 1)
        self.tests.setEnabled(is_code)
        self.form.setRowVisible(self.tests, is_code)
        self.form.setRowVisible(self.provider_setup, bool(self.provider_setup.text()))
        self.form.setRowVisible(self.account_login, needs_network)
        self.account_login.setEnabled(theme.ELEMENT != "ice")
        self.inputs.setPlaceholderText("One relative media path per line" if is_media else "One relative document path per line")
        self.workflow_note.setText({
            "code": "Provide a test command so the result can be checked. Shell syntax is not evaluated; enter a program and its arguments.",
            "report": "Uses Codex with your selected text documents. Cloud connection approval and configured worker credentials are required. Results include source citations and a receipt.",
            "media": "Uses deterministic ffmpeg exports. Select one or more source media files; exported files and verification appear in Results.",
        }[kind])



    def arguments(self):
        title = self.title.text().strip()
        prompt = self.prompt.toPlainText().strip()
        if not title or not prompt:
            raise ValueError("Give the mission a title and instructions.")
        if not self.workspace.text().strip():
            raise ValueError("Choose an existing project folder or enter its name.")
        workspace = workspace_path(self.workspace.text().strip())
        kind = self.kind.currentData()
        capability, options = self.providers_for(kind)
        provider = self.provider_choice.currentData() or (options[0][0] if options else None)
        if capability and self.capabilities.get("providers") and not provider:
            raise ValueError("No installed agent performs this kind of mission.")
        info = dict(options).get(provider, {})
        # Unknown provider -> keep the person's explicit connection choice and
        # let the engine decide who performs it. Never widen network silently.
        needs_network = bool(info.get("requires_network_approval")) if info else True
        network = self.network.currentData() if needs_network else "none"
        if needs_network and network == "none":
            raise ValueError(
                f"{info.get('display_name', provider)} needs a cloud connection. "
                "Switch to Fire and allow a connection for this mission; offline "
                "providers remain offline.")
        inputs = [line.strip() for line in self.inputs.toPlainText().splitlines() if line.strip()]
        for value in inputs:
            path = Path(value)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError("Source files must be relative paths inside the selected project.")
        if kind in ("report", "media") and not inputs:
            raise ValueError("Select at least one source file by its path inside the project.")
        args = ["create", "--kind", kind, "--workspace", str(workspace), "--title", title,
                "--prompt", prompt, "--network", network]
        if provider:
            args += ["--provider", provider]
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

    def _login_account(self):
        if theme.ELEMENT == "ice":
            self.error.setText("Switch to Fire deliberately before signing in to a cloud account.")
            return
        started, _ = QProcess.startDetached("konsole", ["--hold", "-e", "shadowfetch-mission-account", "login"])
        if not started:
            self.error.setText("Could not open Konsole. Run shadowfetch-mission-account login in a terminal.")

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
        self.review_pending = False
        self._mutation_pending = False
        self._operation_notice = ""
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
        self.tabs.addTab(self._control_tab(), "Control")
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
        self._verify_audit()

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
            self.notice.setText(self._operation_notice or error)
            self.stats.setText("Queue unavailable")
            return
        if not isinstance(data, list):
            self.notice.setText("The mission queue returned an unexpected response.")
            return
        self.notice.setText(self._operation_notice)
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
            self._clear_control()
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
            self.notice.setText(self._operation_notice or error)
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
        self.mission_view.setText(mission_text(data))
        self.records_view.setText(records_text(data))
        self.client.call(["events", requested], lambda value, err: self._events_ready(requested, value, err))
        self.client.call(["diff", requested], lambda value, err: self._diff_ready(requested, value, err))
        self.client.call(["policy", "show", requested], lambda value, err: self._policy_ready(requested, value, err))
        self.client.call(["approvals", requested], lambda value, err: self._approvals_ready(requested, value, err))

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
            button.setEnabled(not self._mutation_pending and bool(mission) and {
                "accept": state == "waiting-review",
                "undo": state in ("waiting-review", "completed", "failed", "cancelled") and bool(mission.get("checkpoint")),
                "cancel": state in ("queued", "running"),
                "retry": state in ("failed", "cancelled"),
                "folder": bool(mission.get("workspace")),
                "receipt": bool(mission.get("receipt")),
            }[key])

    def _action(self, action):
        mission = self.selected
        if not mission or self._mutation_pending:
            return
        if action in ("folder", "receipt"):
            self._open_path(mission.get("workspace" if action == "folder" else "receipt", ""))
            return
        if action == "undo":
            answer = QMessageBox.question(self, "Restore this mission's changes?", "The engine will restore the project checkpoint for this mission. Review the diff first. Files changed since the mission may cause a conflict; the engine will report that instead of silently overwriting them.", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel, QMessageBox.StandardButton.Cancel)
            if answer != QMessageBox.StandardButton.Yes:
                return
        args = ["review", mission["id"], "--decision", action] if action in ("accept", "undo") else [action, mission["id"]]
        self._mutation_pending = True
        self.review_pending = action in ("accept", "undo")
        self._operation_notice = "Review is in progress. Keep this window open; you can minimize it." if self.review_pending else "Updating mission…"
        self.notice.setText(self._operation_notice)
        self._buttons()
        if self.review_pending:
            self.client.review(args, self._mutated, self._review_waiting)
        else:
            self.client.call(args, self._mutated)

    def _review_waiting(self, message):
        self._operation_notice = message
        self.notice.setText(message)

    def _mutated(self, data, error):
        self.review_pending = False
        self._mutation_pending = False
        self._operation_notice = error or ""
        self.notice.setText(self._operation_notice)
        if error:
            self._buttons()
            QMessageBox.warning(self, "Mission needs attention", error)
        else:
            if isinstance(data, dict) and data.get("id") == self.selected_id:
                self.selected = data
            self._buttons()
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

    def _control_tab(self):
        """The control plane, rendered.

        Nothing in this panel decides whether an action is permitted. The
        buttons ask the engine and the reply is what the panel then shows,
        because a second copy of those rules here is a second answer to
        "is this allowed".
        """
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        body = QWidget()
        column = QVBoxLayout(body)
        column.setContentsMargins(4, 4, 4, 4)
        column.setSpacing(6)
        column.addWidget(label("MISSION", "safety"))
        self.mission_view = label("", "detail", wrap=True)
        column.addWidget(self.mission_view)
        column.addWidget(label("POLICY DECISION", "safety"))
        self.decision_view = label("", "detail", wrap=True)
        column.addWidget(self.decision_view)
        # Directly beneath the scope on purpose: a scope read on its own is a
        # list of controls the reader will assume are in force.
        self.caveat_view = label("", "statusWarn", wrap=True)
        column.addWidget(self.caveat_view)
        column.addWidget(label("APPROVALS", "safety"))
        column.addWidget(label(
            "A mission that needs approval STARTS only if one covers it. The "
            "check runs once, before it begins: revoking an approval does not "
            "stop a mission already running -- use Stop for that. Withholding "
            "an approval, or revoking it before the mission starts, is how the "
            "work is refused; the engine records no separate refusal object.",
            "detail", wrap=True))
        self.approvals = QListWidget()
        self.approvals.setAccessibleName("Approvals recorded for this mission")
        self.approvals.setMaximumHeight(84)
        self.approvals.currentItemChanged.connect(lambda *_: self._approval_buttons())
        column.addWidget(self.approvals)
        buttons = QHBoxLayout()
        self.approve_button = QPushButton("Approve")
        self.approve_button.clicked.connect(self._approve)
        buttons.addWidget(self.approve_button)
        self.revoke_button = QPushButton("Revoke")
        self.revoke_button.setObjectName("quiet")
        self.revoke_button.clicked.connect(self._revoke)
        buttons.addWidget(self.revoke_button)
        buttons.addStretch(1)
        column.addLayout(buttons)
        self.approval_notice = label("", "statusWarn", wrap=True)
        self.approval_notice.setAccessibleName("Approval result")
        column.addWidget(self.approval_notice)
        column.addWidget(label("AUDIT LOG", "safety"))
        self.audit_view = label("", "detail", wrap=True)
        column.addWidget(self.audit_view)
        audit_row = QHBoxLayout()
        # Verification recomputes the whole chain, so it is asked for and never
        # attached to the three-second queue poll.
        verify = QPushButton("Verify the audit chain")
        verify.setObjectName("quiet")
        verify.clicked.connect(self._verify_audit)
        audit_row.addWidget(verify)
        audit_row.addStretch(1)
        column.addLayout(audit_row)
        column.addWidget(label("STEPS, SESSIONS, TESTS AND REVIEW", "safety"))
        self.records_view = label("", "detail", wrap=True)
        column.addWidget(self.records_view)
        column.addStretch(1)
        scroll.setWidget(body)
        self._clear_control()
        return scroll

    def _clear_control(self):
        self.mission_view.setText("Choose a mission to see its state, its approvals "
                                  "and what this system cannot enforce for it.")
        self.decision_view.setText("")
        self.caveat_view.setText("")
        self.approvals.clear()
        self.approval_notice.setText("")
        self.records_view.setText("")
        self._approval_buttons()

    def _approval_buttons(self):
        # Approve is not gated on a local reading of the decision: asked about a
        # mission that needs no approval, the engine says so in its own words,
        # which a copy of its rules here could only paraphrase.
        item = self.approvals.currentItem()
        self.approve_button.setEnabled(bool(self.selected_id) and not self._mutation_pending)
        self.revoke_button.setEnabled(
            not self._mutation_pending and item is not None
            and bool(item.data(Qt.ItemDataRole.UserRole)))

    def _policy_ready(self, requested, data, error):
        if requested != self.selected_id:
            return
        if error:
            self.decision_view.setText("The engine did not return a decision for this "
                                       "mission: " + error)
            self.caveat_view.setText("")
            return
        self.decision_view.setText(decision_text(data))
        self.caveat_view.setText(caveat_text(data))

    def _approvals_ready(self, requested, data, error):
        if requested != self.selected_id:
            return
        if error:
            self.approvals.clear()
            self.approval_notice.setText(error)
            self._approval_buttons()
            return
        rows = [row for row in (data or []) if isinstance(row, dict) and row.get("id")]
        current = self.approvals.currentItem()
        keep = current.data(Qt.ItemDataRole.UserRole) if current else None
        self.approvals.clear()
        for row in rows:
            item = QListWidgetItem(approval_line(row))
            item.setData(Qt.ItemDataRole.UserRole, row["id"])
            self.approvals.addItem(item)
            if row["id"] == keep:
                self.approvals.setCurrentItem(item)
        if not rows:
            item = QListWidgetItem("No approval has been granted for this mission.")
            item.setFlags(Qt.ItemFlag.NoItemFlags)
            self.approvals.addItem(item)
        self._approval_buttons()

    def _approve(self):
        if self.selected_id:
            self._control_action(["approve", str(self.selected_id)])

    def _revoke(self):
        item = self.approvals.currentItem()
        approval = item.data(Qt.ItemDataRole.UserRole) if item else None
        if approval:
            self._control_action(["revoke", str(approval)])

    def _control_action(self, arguments):
        if self._mutation_pending or not self.selected_id:
            return
        self._mutation_pending = True
        self.approval_notice.setText("")
        self._approval_buttons()
        self._buttons()
        self.client.call(arguments, self._control_done)

    def _control_done(self, data, error):
        """The engine's answer is the only thing that changes anything here.

        A refusal applies nothing locally: the mission, the decision and the
        approval list are all re-read from the engine afterwards, so what the
        panel shows next is what the engine actually holds.
        """
        self._mutation_pending = False
        if error:
            self.approval_notice.setText(error)
        elif isinstance(data, dict) and data.get("reason"):
            self.approval_notice.setText(str(data["reason"]))
        else:
            self.approval_notice.setText("")
        self._approval_buttons()
        self._buttons()
        self.refresh()

    def _verify_audit(self):
        self.audit_view.setText("Verifying the audit chain…")
        self.client.call(["audit", "verify"], self._audit_ready)

    def _audit_ready(self, data, error):
        self.audit_view.setText(audit_text(data, error))

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
