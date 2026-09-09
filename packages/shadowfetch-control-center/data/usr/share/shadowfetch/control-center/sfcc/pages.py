"""The Page protocol and the one section registry (W-31).

What W-31 (ARCHITECTURE_AUDIT.md:849) asks for:

    `sfcc` Page protocol + single registry; context-object constructors;
    `badge_count`/`blocking_reason`; rename `AgentsPage`

What it was before this module.  app.py held the registry as TWO lists --
`SECTIONS` (key, title, subtitle) and a `self.pages` list literal -- joined by
nothing but list index, plus a third structure, `ALIASES`, whose values had to
name a key in the first.  A page added to one and not the other silently showed
the wrong screen, and a key removed from `SECTIONS` turned two `next(...)`
lookups into an uncaught StopIteration.  Nothing in the program checked; the
pairing was pinned in a test file instead, which is a record of the coupling,
not a removal of it.

Now: ONE tuple, `REGISTRY`.  A section is a `Section` and carries its own key,
title, subtitle, aliases and the callable that builds its widget.  There is no
index arithmetic between two lists because there is only one list, and the
alias map and the badge lookup are derived from it rather than restated.

Three things a section may declare, all optional, all with honest defaults:

    build(context)     construct the widget.  The knowledge of what a page
                       needs (sensors, a router, both, neither) lives WITH the
                       page, as a classmethod, not in the shell.  That is the
                       "context-object constructor" this finding asks for: the
                       shell passes one PageContext and knows nothing else.
    badge_count()      the number on the sidebar, or None.  app.py used to
                       hard-code `if key == "software"`; now the page that has
                       a badge is the page that answers.
    blocking_reason()  a sentence explaining why the window must not close
                       right now, or None.  app.py used to test one duck-typed
                       attribute name (`review_pending`) and then supply the
                       sentence itself, so a second page with a reason to
                       block had no way to say so and no way to say why.

This module deliberately imports no page module at import time.  Sections name
their module and class as strings, resolved when the section is built.  Be
precise about what that buys: the REGISTRY can be read, and its aliases and row
lookups exercised, without constructing a single Qt widget -- which is what
lets the tests above check the routing table cheaply.  It is NOT containment.
A first-party page that raises still takes the window down with it, because a
shipped page failing to construct is a bug, and an error card in its place
would hide it.  Containment is for code this package does not own: see
sfcc.plugins.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import importlib
from typing import Any, Callable, Protocol, runtime_checkable

# Bumped when the Page protocol below changes shape. Plugins declare the
# version they were written against (see sfcc.plugins).
PAGE_API = 1


@dataclass(frozen=True)
class PageContext:
    """Everything the shell offers a page, in one object.

    Frozen: a page reads what the shell gives it and does not reach back to
    reconfigure the shell.  `open_route` is the one capability, and it is the
    same router the deep-link handler uses, so a page navigating and a person
    typing `--page` end up in the same code.
    """

    open_route: Callable[[str], None]
    firewatch: Any = None
    version: str = ""


@runtime_checkable
class Page(Protocol):
    """What the shell may call on a page widget.

    A QWidget satisfies this by doing nothing; the three members are optional
    and `section_*` below supplies the honest default for each.  It is a
    Protocol rather than a base class on purpose: the pages are QWidgets and
    Qt's metaclass does not mix with ABCMeta.
    """

    def route(self, parts: list[str]) -> None: ...
    def badge_count(self) -> int | None: ...
    def blocking_reason(self) -> str | None: ...


@dataclass(frozen=True)
class Section:
    """One sidebar row and the page behind it."""

    key: str
    title: str
    subtitle: str | None
    module: str
    factory: str
    aliases: tuple[str, ...] = field(default_factory=tuple)

    def build(self, context: PageContext):
        """Construct this section's widget from the context object.

        The page's own `build(context)` classmethod is preferred; a page that
        has not got one is constructed directly, which is what makes this
        adoptable one page at a time instead of in a single flag day.
        """
        target = getattr(importlib.import_module(self.module), self.factory)
        builder = getattr(target, "build", None)
        if callable(builder):
            return builder(context)
        return target()


# The registry.  One row per sidebar section, in sidebar order.
#
# `workspaces` is served by WorkspacesPage.  It was AgentsPage, named for a
# concept the section stopped being about: the page lists project folders and
# the measured hardware, and the agents live in Mission Control and Grok Bot.
# W-31 asks for the rename; "agents" survives as an alias so every existing
# deep link, .desktop file and servicemenu keeps working.
REGISTRY: tuple[Section, ...] = (
    Section("missions", "Mission Control", "Work you can inspect",
            "sfcc.missions_page", "MissionsPage",
            ("mission-control", "home")),
    Section("grok-bot", "Grok Bot", "Featured teammate",
            "sfcc.grok_bot_page", "GrokBotPage", ("grokbot",)),
    Section("guide", "Guide", "System Passport",
            "sfcc.guide_page", "GuidePage", ("passport", "system-passport")),
    Section("workbench", "Workbench", "Fire & Ice projects",
            "sfcc.workbench_page", "WorkbenchPage", ("forge", "projects")),
    Section("ignite", "Ignite", None,
            "sfcc.ember_page", "EmberPage", ("ember",)),
    Section("watch", "Watch", None,
            "sfcc.firewatch_page", "FirewatchPage", ("firewatch",)),
    Section("recover", "Recover", None,
            "sfcc.phoenix_page", "PhoenixPage", ("phoenix", "recovery")),
    Section("workspaces", "Workspaces", "Project folders",
            "sfcc.workspaces_page", "WorkspacesPage",
            ("local-ai", "agents", "ai", "buzz")),
    Section("drivers", "Drivers", None,
            "sfcc.drivers_page", "DriversPage"),
    Section("software", "Software", "Updates & bundles",
            "sfcc.software_page", "SoftwarePage",
            ("software-updates", "updates", "bundles")),
)


def aliases() -> dict[str, str]:
    """Every accepted route word -> section key.

    Derived, not restated: an alias cannot name a section that does not exist,
    because there is nowhere else to write one down.
    """
    table: dict[str, str] = {}
    for section in REGISTRY:
        for word in (section.key, *section.aliases):
            if word in table and table[word] != section.key:
                raise ValueError(
                    f"route word {word!r} is claimed by both {table[word]!r} "
                    f"and {section.key!r}")
            table[word] = section.key
    return table


def index_of(key: str) -> int | None:
    """The row for a section key, or None. Never raises StopIteration."""
    for position, section in enumerate(REGISTRY):
        if section.key == key:
            return position
    return None


def resolve(route: str) -> tuple[int, list[str]] | None:
    """('workspaces:tab:x') -> (row, ['tab', 'x']), or None for an unknown word."""
    parts = [part for part in str(route).split(":") if part]
    if not parts:
        return None
    key = aliases().get(parts[0].strip().lower())
    if key is None:
        return None
    position = index_of(key)
    return None if position is None else (position, parts[1:])


# ---- the optional half of the protocol, with honest defaults ---------------

def section_badge(page) -> int | None:
    """The badge for a page, asked OF the page.

    A page that does not answer has no badge.  It is not the shell's business
    to know that one particular section counts something.
    """
    counter = getattr(page, "badge_count", None)
    if not callable(counter):
        return None
    try:
        count = counter()
    except Exception:
        # A sidebar number is not worth taking the window down for, and a
        # daemon that is not answering is exactly when this is called.
        return None
    return count if isinstance(count, int) and count > 0 else None


def section_blocking_reason(page) -> str | None:
    """Why this page says the window must not close yet, or None.

    The page supplies the SENTENCE as well as the verdict.  The shell showing a
    message it wrote itself about an operation it does not own is how a warning
    ends up describing the wrong thing after the page changes.
    """
    reason = getattr(page, "blocking_reason", None)
    if not callable(reason):
        return None
    try:
        text = reason()
    except Exception:
        return None
    return str(text) if text else None


def section_route(page, parts: list[str]) -> None:
    router = getattr(page, "route", None)
    if parts and callable(router):
        router(parts)
