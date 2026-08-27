"""Element Workbench - four honest, installable production profiles."""

import json
import os
import shutil
from pathlib import Path

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import (
    QGridLayout,
    QHBoxLayout,
    QInputDialog,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from sfcc import busutil, theme
from sfcc.theme import Card, ProcessDialog, label


MANIFEST = Path("/usr/share/shadowfetch/workbench/profiles.json")
WORKBENCH = "/usr/bin/shadowfetch-workbench"


def load_profiles() -> list[dict]:
    try:
        data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    profiles = data.get("profiles") if isinstance(data, dict) else None
    return [profile for profile in (profiles or [])
            if isinstance(profile, dict) and profile.get("id")]


class ProfileCard(Card):
    def __init__(self, profile: dict, page):
        super().__init__()
        self.profile = profile
        self.page = page
        self.ready = False
        self.setMinimumHeight(250)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(16, 14, 16, 14)
        outer.setSpacing(7)

        heading = QHBoxLayout()
        heading.addWidget(label(profile["name"], "cardTitle"))
        heading.addStretch(1)
        recommendation = profile.get("recommended_element", "fire").title()
        heading.addWidget(label(f"{recommendation} recommended", "safety"))
        outer.addLayout(heading)
        outer.addWidget(label(profile.get("tagline", ""), "detail", wrap=True))

        capability_text = "  |  ".join(profile.get("capabilities", [])[:4])
        outer.addWidget(label(capability_text, "detail", wrap=True))
        outer.addSpacing(2)
        outer.addWidget(label(
            f"About {profile.get('installed_disk_gb', '?')} GB before projects or models. "
            + profile.get("accelerator", ""), "detail", wrap=True))
        outer.addWidget(label(profile.get("network", ""), "detail", wrap=True))

        self.state = label("Checking...", "statusWarn", wrap=True)
        outer.addWidget(self.state)
        outer.addStretch(1)

        # Keep icon-and-text actions readable without making two cards wider
        # than the 1366x768 Control Center viewport.
        actions = QGridLayout()
        actions.setHorizontalSpacing(6)
        actions.setVerticalSpacing(6)
        self.install = QPushButton("Install tools")
        self.install.setIcon(QIcon.fromTheme("download"))
        self.install.clicked.connect(lambda: page.install_profile(self))
        actions.addWidget(self.install, 0, 0, 1, 2)
        create = QPushButton("New project")
        create.setObjectName("quiet")
        create.setIcon(QIcon.fromTheme("document-new"))
        create.clicked.connect(lambda: page.create_project(self.profile))
        actions.addWidget(create, 1, 0)
        plan = QPushButton("View plan")
        plan.setObjectName("quiet")
        plan.setIcon(QIcon.fromTheme("document-preview"))
        plan.clicked.connect(lambda: page.show_plan(self.profile))
        actions.addWidget(plan, 1, 1)
        actions.setColumnStretch(0, 1)
        actions.setColumnStretch(1, 1)
        outer.addLayout(actions)
        self.refresh()

    def refresh(self) -> None:
        record = next((item for item in busutil.load_catalog(kinds=("preset",))
                       if item.get("id") == self.profile.get("catalog_id")), None)
        if record is None:
            self.ready = False
            self.state.setText("Profile package record is unavailable.")
            self.state.setObjectName("statusWarn")
            self.install.setEnabled(False)
            return
        packages = [str(value) for value in record.get("packages", [])]
        package_state = busutil.installed_map(packages)
        have_packages = sum(package_state.values())
        commands = [str(value) for value in self.profile.get("commands", [])]
        have_commands = sum(1 for command in commands if shutil.which(command))
        ready = have_packages == len(packages) and have_commands == len(commands)
        self.ready = ready
        if ready:
            self.state.setText(f"Ready: {len(packages)} packages and {len(commands)} commands verified.")
            self.state.setObjectName("status")
            self.install.setText("Installed")
            self.install.setEnabled(False)
        else:
            self.state.setText(
                f"Setup needed: {have_packages}/{len(packages)} packages, "
                f"{have_commands}/{len(commands)} commands ready.")
            self.state.setObjectName("statusWarn")
            self.install.setText("Install tools")
            self.install.setEnabled(os.access(busutil.BUNDLE_INSTALL, os.X_OK))
        self.state.style().unpolish(self.state)
        self.state.style().polish(self.state)


class WorkbenchPage(QWidget):
    """Operational profile launcher; all root work stays in the bundle helper."""

    def __init__(self):
        super().__init__()
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 12, 24, 18)
        root.setSpacing(10)

        element = theme.ELEMENT.title()
        posture = ("agent sessions start without network access"
                   if theme.ELEMENT == "ice"
                   else "agent sessions may use the network")
        root.addWidget(label(
            f"{element} posture: {posture}. Each setup shows disk, network, account "
            "and accelerator requirements before it changes the system.",
            "subtitle", wrap=True))

        head = QHBoxLayout()
        self.summary = label("", "detail")
        head.addWidget(self.summary)
        head.addStretch(1)
        refresh = QPushButton("Refresh")
        refresh.setObjectName("quiet")
        refresh.setIcon(QIcon.fromTheme("view-refresh"))
        refresh.clicked.connect(self.refresh)
        head.addWidget(refresh)
        root.addLayout(head)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        body = QWidget()
        self.grid = QGridLayout(body)
        self.grid.setContentsMargins(0, 4, 0, 4)
        self.grid.setHorizontalSpacing(10)
        self.grid.setVerticalSpacing(10)
        scroll.setWidget(body)
        root.addWidget(scroll, 1)

        self.cards: list[ProfileCard] = []
        profiles = load_profiles()
        if not profiles:
            self.grid.addWidget(label(
                "The Workbench manifest is missing. Repair shadowfetch-defaults and refresh.",
                "statusWarn", wrap=True), 0, 0)
            self.summary.setText("Workbench unavailable")
            return
        for index, profile in enumerate(profiles):
            card = ProfileCard(profile, self)
            self.cards.append(card)
            self.grid.addWidget(card, index // 2, index % 2)
        self.grid.setRowStretch((len(profiles) + 1) // 2, 1)
        self.refresh()

    def refresh(self) -> None:
        for card in self.cards:
            card.refresh()
        ready = sum(1 for card in self.cards if card.ready)
        self.summary.setText(f"{ready} of {len(self.cards)} profiles ready on this computer")

    def install_profile(self, card: ProfileCard) -> None:
        profile = card.profile
        if busutil.nm_connectivity_full() is False:
            QMessageBox.information(
                self, "Connection needed",
                "This profile installs signed packages. Nothing changed; connect to the internet and retry.")
            return
        dialog = ProcessDialog(
            self,
            f"Installing {profile['name']}",
            ["pkexec", busutil.BUNDLE_INSTALL, "install", profile["catalog_id"]],
            "The package plan is fixed by the root-owned catalog. On Btrfs, a Phoenix Point protects this transaction.",
        )
        dialog.completed.connect(lambda _code: self.refresh())
        dialog.start()
        dialog.exec()

    def create_project(self, profile: dict) -> None:
        name, accepted = QInputDialog.getText(
            self, f"New {profile['name']} project", "Project name:")
        if not accepted or not name.strip():
            return
        dialog = ProcessDialog(
            self,
            f"Creating {profile['name']} project",
            [WORKBENCH, "create", profile["id"], name.strip()],
            "Creates a private project under ~/Workspaces with instructions, safety rules, provenance and receipts.",
        )
        dialog.start()
        dialog.exec()

    def show_plan(self, profile: dict) -> None:
        dialog = ProcessDialog(
            self,
            f"{profile['name']} plan",
            [WORKBENCH, "plan", profile["id"]],
            "Read-only check. No packages, models or accounts are changed.",
        )
        dialog.start()
        dialog.exec()
