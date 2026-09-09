"""The ONE vocabulary of a Shadowfetch update.

Before Stage U this tree had two updaters that each invented their own
words for the same five things, and - worse - each kept its own idea of
what state the machine was in. `shadowfetch-update` called step 1 a
"simulation", hashed it with its own `plan_fingerprint`, relabelled the
snapper Point "Shadowfetch: before safe update" and wrote nothing
anywhere; `fireproofd` called step 1 "analyze", hashed it with
`change_set_hash`, relabelled the SAME Point "Fireproof: before update"
with `fireproof=pre,txn=<uuid>` userdata and recorded it in
fireproof-state.json. A rollback issued after a `shadowfetch-update` run
therefore restored the Point of the PREVIOUS Fireproof transaction: the
rollback and the update disagreed about what state the machine was in.

There is now one implementation (fireproofd) behind one vocabulary. This
module is that vocabulary in executable form: the CLI, the compatibility
shim, the Qt page and the tests all name the steps from here, so a sixth
word cannot be introduced without failing a test.

THE STEPS ARE NOT INTERCHANGEABLE AND MUST NEVER BE COLLAPSED
------------------------------------------------------------
Each step is a distinct claim about the world. Reporting one when you
only did the previous one is the exact dishonesty this module exists to
prevent, so each carries the claim it is allowed to make and the claim it
is NOT allowed to make.

Nothing here executes anything. It is a contract, not a mechanism: the
enforcement of each step lives in fireproofd, and a step listed here is
NOT thereby enforced.
"""

from __future__ import annotations

import enum

__all__ = ["Step", "STEPS", "ORDER", "describe", "claims", "forbids"]


class Step(str, enum.Enum):
    """The five - and only five - verbs of an update."""

    SIMULATE = "simulate"
    APPROVE = "approve"
    COMMIT = "commit"
    VERIFY = "verify"
    ROLLBACK = "rollback"


#: Canonical order. Every step's precondition is the step before it,
#: except ROLLBACK, whose precondition is a recorded COMMIT.
ORDER = (Step.SIMULATE, Step.APPROVE, Step.COMMIT, Step.VERIFY, Step.ROLLBACK)


STEPS = {
    Step.SIMULATE: {
        "summary":
            "Resolve the pending upgrade read-only and describe it.",
        "mechanism":
            "fireproofd.build_analysis() over a python3-apt cache - the same "
            "libapt-pkg apt itself uses, so the resolver answers identically "
            "to `apt full-upgrade`. Takes NO dpkg lock, downloads nothing, "
            "writes nothing to the apt cache.",
        "produces":
            "a change set plus its change_set_hash: sha256 over the sorted "
            "'Inst name=ver' / 'Remv name=ver' lines. The hash IS the "
            "identity of the update.",
        "claims":
            "this is what the archive would do right now",
        "forbids":
            "that anything was locked, downloaded, installed or approved",
        "surfaces": ("fireproof check", "Fireproof1.Analyze",
                     "shadowfetch-update --check"),
    },
    Step.APPROVE: {
        "summary":
            "A human accepts one specific change_set_hash.",
        "mechanism":
            "the y/N prompt in fireproof(1) or the Update button on the "
            "Fireproof page, followed by polkit "
            "(org.shadowfetch.fireproof.update) on Fireproof1.Update. The "
            "approved hash is passed as the method argument.",
        "produces":
            "an approved change_set_hash, and nothing else",
        "claims":
            "a human agreed to this exact set of packages",
        "forbids":
            "that the set is still current, or that anything was installed",
        "surfaces": ("fireproof update", "Fireproof1.Update(expected_hash)"),
    },
    Step.COMMIT: {
        "summary":
            "Install the approved change set, once, under the lock.",
        "mechanism":
            "take /var/lib/dpkg/lock-frontend, re-simulate UNDER the lock, "
            "compare the live hash with the approved hash and abandon on "
            "drift; then download (cancellable, nothing installed), the "
            "NEWS gate, and cache.commit(). snapper's own 80snapper apt "
            "hooks create the Phoenix Point - Fireproof creates none.",
        "produces":
            "an installed change set, a transaction uuid, and the recorded "
            "pre-Point: the FIRST type=pre snapshot above the pre-commit "
            "maximum, relabelled with fireproof=pre,txn=<uuid>",
        "claims":
            "these packages are on disk and this Point precedes them",
        "forbids":
            "that the system still works - that is VERIFY - and that a "
            "Point exists at all on a non-Btrfs root",
        "surfaces": ("fireproof update", "Fireproof1.Update"),
    },
    Step.VERIFY: {
        "summary":
            "Judge the machine after a commit and return one verdict.",
        "mechanism":
            "fireproofd.run_verify(): dpkg --audit, apt -f consistency, "
            "initrd freshness per new kernel, grub.cfg regeneration, dkms "
            "state on the new kernel, newly-failed units diffed against a "
            "pre-commit baseline, needrestart, default route and mirror "
            "resolution, and a WARN-ONLY graphics scan. Every one of those "
            "programs is resolved through sfupdate.trusted.",
        "produces":
            "verdict in {ok, reboot-recommended, restore-recommended} plus "
            "the per-check list",
        "claims":
            "what these checks found",
        "forbids":
            "that a graphical login will succeed - only the next boot "
            "proves that - and that a restore has happened",
        "surfaces": ("fireproof verify", "Fireproof1.Verify",
                     "Fireproof1.Inspect (last result, executes nothing)"),
    },
    Step.ROLLBACK: {
        "summary":
            "Restore the Phoenix Point recorded by a commit.",
        "mechanism":
            "pkexec /usr/libexec/phoenix-restore <point>, which Phoenix "
            "owns; Fireproof never re-implements a restore. Afterwards "
            "Fireproof1.RecordRollback marks the change_set_hash as "
            "rolled-back so the same set re-simulates as 'Don't proceed'.",
        "produces":
            "a restored root subvolume, pending a reboot",
        "claims":
            "the previous root is staged to boot",
        "forbids":
            "that the running system is the restored one before the reboot, "
            "and that a rollback is possible at all when no Point was "
            "recorded (say 'rollback unavailable', never a silent Point 0)",
        "surfaces": ("fireproof rollback", "Fireproof1.RollbackTarget",
                     "Fireproof1.RecordRollback"),
    },
}


def describe(step: Step | str) -> dict:
    return STEPS[Step(step)]


def claims(step: Step | str) -> str:
    return STEPS[Step(step)]["claims"]


def forbids(step: Step | str) -> str:
    return STEPS[Step(step)]["forbids"]
