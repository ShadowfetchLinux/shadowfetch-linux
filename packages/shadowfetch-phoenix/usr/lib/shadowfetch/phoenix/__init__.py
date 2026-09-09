"""Phoenix root recovery - the part of it that can be tested.

Root recovery used to be shell only. The shell is still the crash-atomic
driver (phoenix-restore: snapshot-aside, one renameat2 exchange), because that
sequence is short, has no interpreter to load and is proven; what moved here is
everything that is a DECISION rather than a mutation:

    layout       - what is on the volume top-level, and is it a shape we may
                   touch at all
    journal      - the intent journal phoenix-restore writes before every
                   mutation, given a grammar so a program can read it back
    transaction  - what an interrupted restore left behind, and what finishing
                   or undoing it means
    gc           - bounded collection of previous roots and kernel backups
    trusted      - the absolute-path executable table every mutation goes
                   through

Nothing here imports anything outside the standard library, and nothing here
resolves a program through PATH.
"""

from .journal import IntentJournal, Record
from .layout import Layout, LayoutError, Problem
from .transaction import Decision, RestoreState, RestoreTransaction
from .trusted import ExecutableError, ExecutableTrust, TrustedExecutor

__all__ = [
    "IntentJournal", "Record",
    "Layout", "LayoutError", "Problem",
    "Decision", "RestoreState", "RestoreTransaction",
    "ExecutableError", "ExecutableTrust", "TrustedExecutor",
]

VERSION = "4.0.0"
