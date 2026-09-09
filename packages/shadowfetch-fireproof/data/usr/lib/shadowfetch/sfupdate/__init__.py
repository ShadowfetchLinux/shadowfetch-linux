"""sfupdate - the shared update logic of Shadowfetch Linux.

ONE update system. Stage U collapsed two.

  fireproofd            the only program that simulates, commits, verifies
                        and records an update. D-Bus, polkit-gated.
  fireproof(1)          the canonical command line over that daemon.
  shadowfetch-update    a thin compatibility shim that execs fireproof(1).
                        It contains no apt, no snapper and no sudo.

and this package, which holds the parts that more than one of them needs:

  vocabulary   the five verbs - simulate, approve, commit, verify,
               rollback - and the claim each is and is NOT allowed to make
  trusted      the absolute-path executable table every security-deciding
               program is invoked through, over phoenix.trusted's
               classifier (one classifier, not two)
  snapshots    the single implementation of "which Phoenix Point precedes
               this update"
  state        the single store of what the last update did to this machine

Nothing here creates a snapshot, and nothing here installs a package.

The module name is `sfupdate`, not `update`: it lands on sys.path beside
`phoenix`, and a top-level module called `update` is exactly the kind of
generic name that shadows somebody else's.
"""

from . import snapshots, state, trusted, vocabulary  # noqa: F401
from .vocabulary import ORDER, STEPS, Step

__all__ = ["Step", "STEPS", "ORDER", "trusted", "snapshots", "state",
           "vocabulary"]

VERSION = "4.0.0"
