"""What could happen, as opposed to what was asked for.

An approval tells a person what a mission may USE: a capability, a provider, a
workspace, a network posture, credential identities, read grants and (since
Stage C) destinations. It does not tell them what could HAPPEN. Two missions
with identical scopes differ enormously in consequence -- one edits three files
in a scratch directory with no network, the other holds a cloud credential and
a writable workspace that turns out to be a git checkout with a push remote --
and sf_policy.Scope is identical for both, because a scope is a list of
privileges and a consequence is a property of the world those privileges point
at.

This module reads that world and says what is REACHABLE, what is DESTRUCTIBLE,
what is EXFILTRATABLE and what is DURABLE beyond the sandbox.

THREE RULES, AND THE DEFECT EACH ONE PREVENTS
---------------------------------------------
DERIVED, NEVER DECLARED. Nothing here reads a provider's opinion of its own
danger. A manifest field saying "risk": "low" is a sentence written by the
thing being classified; honouring it would make the classification a restating
of the claim it exists to check. Every finding below comes from the resolved
ceiling, from the mission's own config, or from stat()ing the filesystem.

A CLASSIFICATION IS AN OBSERVATION, NEVER AN ENFORCEMENT CLAIM. sf_providers
owns the words enforced / partial / not_enforced / not_representable and they
describe mechanisms. Nothing in this file may put a mission in one of them: the
levels here are a different vocabulary on purpose, so no reader and no renderer
can mistake "this mission's blast radius is contained" for "a layer stopped
it". Where a finding rests on a mechanism, it names the mechanism and what was
MEASURED about it, and the measurement is a probe in tools/probes that anybody
can re-run.

UNKNOWN IS NOT SAFE. UNKNOWN is the TOP of the level ladder, above BROAD, not a
neutral middle and not an absence. A caller ranking, sorting or thresholding on
level therefore gets the things nobody could see first, which is the only
ordering that fails safe. A classifier that emitted a separate "confidence"
field would let a renderer show the level and drop the confidence, and the
mission nobody could see into would render as the mission with nothing in it.

AND THE FAILURE MODE THAT MATTERS MOST: NOISE. A genuinely contained mission
must come out contained. A classifier that marks everything dangerous is
identical in practice to no classifier, because the second week nobody reads
it. So findings are emitted for contained things too, saying WHY they are
contained and naming the layer -- a reader can tell "we looked and it is fine"
from "we did not look", and neither is silence.

A REASSURING ROW NEEDS EVIDENCE. This rule was stated from the start and was
not kept, and six landed attacks came through the gap. A parse that failed, a
file that could not be read, or a place that was not looked at must produce
UNKNOWN and appear in `unseen` -- never a sentence that reassures. The old code
held that by hand at each site, and every site it forgot became an attack: an
unreadable .git/config, a git key with no value, an include.path, a checkout one
directory down. In four of them the classifier did not merely fall silent, it
emitted an ACTIVELY REASSURING row -- "a git repository with no remote
configured, so nothing it commits can be published from here", about a
repository with a push remote -- and the party being classified could cause that
itself, because the workspace is bound workspace-write and .git/config is inside
it. The verifier's summary: the defence was aimed one step to the left of the
attack, and there was no defence at all against the alarming row never being
generated.

So the rule is now STRUCTURAL rather than per-site. Every NONE or CONTAINED
finding is built by _reassure(), which takes the Reading its comfort rests on
and refuses to produce a row from a Reading that did not complete -- emitting
that Reading's own UNKNOWN instead, on the axis the reader is looking at.
Finding.__post_init__ rejects a reassuring level that names no reading, so the
comfortable object cannot be constructed by hand at a site somebody forgets, and
a test walks this module's own AST to prove no call site tries. The seventh
attack, on a site nobody has thought of yet, meets a wall instead of a fix aimed
at the last six.

THE EVIDENCE IS AUTHORED BY THE PARTY BEING CLASSIFIED. The workspace is bound
read-write and .git/config is inside it -- measured, in
tools/probes/blast_workspace_socket.py, where the payload rewrites its own
.git/config from inside the sandbox and binds itself a fresh unix socket. So
every workspace-derived row here is a statement about a file AT READ TIME and
not a control over what it will say while the mission runs. A classifier cannot
close that; it can refuse to hide it, so the rows say it and inputs_seen records
it.

ONE SUBPROCESS, AT A PINNED ABSOLUTE PATH. An earlier draft ran no program at
all and parsed .git/config with configparser, reasoning that the cheapest way to
hold this codebase's permanent invariant -- an executable that establishes a
security fact is reached by an explicit trusted absolute path with its child
PATH pinned -- is to have no executable. That was wrong, and measurably so:
git's config format is not an ini file. tools/probes/blast_git_config.py runs
both readers over the same bytes and prints five divergences, each one a way for
a mission to buy the reassuring row by editing its own config:

    valueless key       git defines it as boolean true; configparser RAISES,
                        and the caller read the exception as "no remotes".
    include.path        git expands it. The old parse did not, though the old
                        docstring admitted git honours it. Fires by accident.
    includeIf           same, conditionally.
    [remote.origin]     git's legacy spelling for [remote "origin"];
                        configparser makes a section no remote lookup matches.
    multivar            two urls on one remote; the parse kept one.

A hand parser will keep missing details git has, because git's semantics are
defined by git. So this module now runs exactly one program, and the invariant
is held the expensive way instead of the cheap way: GIT_BINARY is an absolute
path, checked to be an executable regular file before each use; GIT_ENV replaces
the environment wholesale with a pinned PATH and closes git's own config escape
hatches, so what is read is the file named on the command line and nothing the
caller's environment adds to it; stdin is /dev/null and there is a timeout.

AND WHAT THAT COSTS, SAID PLAINLY. Running git against a workspace the mission
controls runs git's own config machinery on attacker-authored input. The probe
measures the three consequences. An include.path naming a fifo makes git BLOCK
and never return. An include.path naming a non-config file makes git exit 128.
An include.path naming any readable host file pulls that file's config-shaped
keys into the reading. The first two are paid in UNKNOWN, which is the correct
answer and not a regression. The third is real and is not silently absorbed:
--show-origin names the file every key came from, and an origin outside the
workspace is reported as its own finding. The probe also measures the bound on
all of it -- `git config --list` does NOT execute an alias, a credential helper,
core.pager or core.sshCommand; the marker file it plants is never created -- so
reading the config is a read.

(Two defects in sf_missions are visible from here and are reported to the lead
rather than changed, because that file is not this module's to edit: _git()
resolves the name "git" through the caller's PATH, and git_structure()'s
executable_config list has the same credential-helper gap fixed below.)
"""
from __future__ import annotations

import dataclasses
import os
import posixpath
import stat
import subprocess
import time
from pathlib import Path, PurePosixPath

# --------------------------------------------------------------------------- #
# Vocabulary
# --------------------------------------------------------------------------- #
# The four questions. Named as adjectives about the WORLD, not as verbs about
# the mission, because "what can be destroyed" is answerable and "what will it
# destroy" is not.
REACHABLE = "reachable"
DESTRUCTIBLE = "destructible"
EXFILTRATABLE = "exfiltratable"
DURABLE = "durable"
DIMENSIONS = (REACHABLE, DESTRUCTIBLE, EXFILTRATABLE, DURABLE)

# The ladder. Deliberately NOT the enforcement vocabulary -- see the module
# docstring. UNKNOWN sits at the top so that max() and any sort put it above
# BROAD; a ladder with UNKNOWN in the middle reads as "moderate" and a ladder
# with it at the bottom reads as "nothing here".
NONE = "none"
CONTAINED = "contained"
BOUNDED = "bounded"
BROAD = "broad"
UNKNOWN = "unknown"
LEVELS = (NONE, CONTAINED, BOUNDED, BROAD, UNKNOWN)
LEVEL_ORDER = {name: index for index, name in enumerate(LEVELS)}

# What a level MEANS, in one sentence each, so a UI does not invent its own
# gloss and drift from the classifier that produced the word.
LEVEL_MEANING = {
    NONE: "nothing on this axis: there is no path at all",
    CONTAINED: "bounded, and the whole of the bound was enumerated here",
    BOUNDED: "reaches past the workspace, to named things that were enumerated",
    BROAD: "reaches things this classifier enumerated and cannot put a bound on",
    UNKNOWN: "the extent could not be seen. NOT a clean bill: read the findings",
}

# How a finding was arrived at. This is per-FINDING, never per-dimension: a
# dimension's honesty is carried by its level, where a renderer cannot drop it.
OBSERVED = "observed"        # this classifier looked at the thing itself
UNOBSERVABLE = "unobservable"  # it looked, and the extent is not visible from here

# A walk has to stop somewhere. A budget that is hit is NOT a walk that found
# nothing: it raises an UNKNOWN finding naming the tree it could not finish.
WALK_BUDGET = 20000

# Shells whose "-c" argument is a program this module will not parse. Matched on
# the basename, because /bin/sh and /usr/bin/env-resolved sh are the same fact.
SHELLS = frozenset({"sh", "bash", "dash", "zsh", "ksh", "ash", "fish", "csh", "tcsh"})
SHELL_COMMAND_FLAGS = frozenset({"-c", "-lc", "-ic", "-lic", "-cl"})

# MIRRORS sf_missions.VALIDATION_CONFIG_NAMES / VALIDATION_CONFIG_STEMS.
# Executor.guards_validation() refuses a mission that edited any of these, so a
# test entry point that IS one of them is protected and must not be reported as
# author-controlled -- that would be a warning about a control that is working,
# which is the exact noise this module is built to avoid. The mirror is asserted
# equal in test_blast_radius.py: if that list grows and this one does not, the
# test goes red rather than this module quietly over-warning.
GUARDED_CONFIG_NAMES = frozenset({
    "conftest.py", "pytest.ini", "tox.ini", "karma.conf.js", ".mocharc.json",
    ".mocharc.yml", ".mocharc.yaml", ".mocharc.js", ".mocharc.cjs"})
GUARDED_CONFIG_STEMS = frozenset({
    "jest.config", "vitest.config", "playwright.config", "cypress.config"})

# Build drivers, and the workspace file each one takes its instructions from.
# A test command of ["make", "test"] names no path at all, so an earlier draft
# that only looked for path-shaped argv elements found nothing and reported a
# Makefile-driven mission as fully predictable -- which is the exact
# false-negative this module exists to prevent. What `make` will run is
# whatever the Makefile says, and the Makefile is a workspace file the mission
# may rewrite.
DRIVER_ENTRY_POINTS = {
    "make": ("Makefile", "makefile", "GNUmakefile"),
    "gmake": ("Makefile", "makefile", "GNUmakefile"),
    "cargo": ("Cargo.toml",),
    "gradle": ("build.gradle", "build.gradle.kts"),
    "gradlew": ("build.gradle", "build.gradle.kts"),
    "meson": ("meson.build",),
    "ninja": ("build.ninja",),
    "cmake": ("CMakeLists.txt",),
    "tox": ("tox.ini",),
}

# MIRRORS the last clause of sf_missions.Executor.guards_validation(), which
# protects package.json only when the command is one of these. So an
# npm/pnpm/yarn mission is NOT reported here: the guard already refuses a
# mission that edited its package.json, and warning about a control that works
# is the noise this module is built to avoid. Asserted against that function's
# source in test_blast_radius.py.
GUARDED_DRIVERS = frozenset({"npm", "pnpm", "yarn"})

# git remote URL schemes that RUN A PROGRAM rather than speak a wire protocol.
# git's ext:: and its cousins hand the URL body to a shell; a fetch from one is
# code execution, not a transfer.
EXECUTING_GIT_SCHEMES = ("ext::", "fd::")

# The one program this module runs, and the terms it runs it on. See ONE
# SUBPROCESS, AT A PINNED ABSOLUTE PATH in the module docstring. Module-level and
# rebindable on purpose: a test asserts what happens when the pinned path does
# not resolve, and that has to be provable rather than asserted.
GIT_BINARY = "/usr/bin/git"

# The child environment, REPLACED rather than updated. os.environ is the
# caller's, and git reads a dozen things out of it; an inherited GIT_CONFIG_GLOBAL
# or a PATH entry the caller controls would make this reading a statement about
# the caller's shell instead of about the repository. Measured in
# tools/probes/blast_git_config.py: with these set, a ~/.gitconfig in the
# ambient HOME does not appear in the output, and without them it does.
GIT_ENV = {
    "PATH": "/usr/bin:/bin",         # pinned; git execs its own helpers
    "GIT_CONFIG_NOSYSTEM": "1",      # no /etc/gitconfig
    "GIT_CONFIG_GLOBAL": "/dev/null",  # no ~/.gitconfig
    "GIT_CONFIG_SYSTEM": "/dev/null",
    "GIT_TERMINAL_PROMPT": "0",      # never stop to ask a human
    "GIT_ASKPASS": "/bin/false",
    "GIT_OPTIONAL_LOCKS": "0",       # a classification writes nothing
    "HOME": "/nonexistent",
    "LC_ALL": "C",
}

# A mission can make git block for ever: an include.path naming a fifo never
# returns. MEASURED in tools/probes/blast_git_config.py. Ten seconds is far
# beyond a real config read -- the probe's 20 calls took 21ms in total -- so a
# timeout here means something is wrong, and the answer to that is UNKNOWN.
GIT_TIMEOUT = 10

# And a ceiling on how much git ONE classification may run in total. Choosing
# git over a hand parser means the classified party can now cost the classifier
# TIME as well as make it wrong: every .git in the workspace is one invocation,
# and each can be made to block for GIT_TIMEOUT. Both budgets are shared across
# the whole classification, and a repository that falls outside either one is
# reported UNKNOWN rather than skipped -- the same answer as any other place
# that was not looked at.
GIT_TOTAL_TIMEOUT = 30
GIT_REPO_BUDGET = 64

# Config keys whose VALUE is a program git runs. The first rule is not in these
# tables at all: git's own marker for "this value is a shell command" is a
# leading '!', on ANY key, and _executing_config() checks that first. THE
# DEFECT these tables used to have: they listed core.sshcommand and not
# credential.helper, and a '!'-prefixed credential helper that curls
# /home/agent/.codex/auth.json to an attacker went unreported. A longer list is
# the same defence one step to the left of the next key nobody listed, so the
# list is now the SECOND net, for keys that name a program without a '!'.
EXECUTING_KEY_PREFIXES = ("alias.", "filter.", "difftool.", "mergetool.")
EXECUTING_KEY_SUFFIXES = (".sshcommand", ".process", ".clean", ".smudge",
                          ".textconv", ".hookspath", ".helper", ".command",
                          ".driver", ".packobjectshook")
EXECUTING_KEY_EXACT = frozenset({
    "core.fsmonitor", "core.editor", "core.pager", "core.sshcommand",
    "core.hookspath", "credential.helper", "sequence.editor", "diff.external",
    "init.templatedir", "uploadpack.packobjectshook"})

# The two levels that tell a reader there is nothing here. Named, because the
# whole of this module's honesty is a rule about which rows may carry them.
REASSURING = (NONE, CONTAINED)


# --------------------------------------------------------------------------- #
# Value types
# --------------------------------------------------------------------------- #

@dataclasses.dataclass(frozen=True)
class Finding:
    """One fact, on one axis.

    A fact that touches three axes produces three Findings sharing a `code` and
    a `subject`. That is deliberately repetitive: the alternative was a level
    map inside one Finding, and every consumer -- the review record, the
    desktop, a test -- then had to reach into it correctly to get the level for
    the axis it cared about. Three flat rows cannot be read wrongly.
    """

    code: str            # stable machine id; group by this to render one fact once
    dimension: str       # one of DIMENSIONS
    level: str           # one of LEVELS
    basis: str           # OBSERVED or UNOBSERVABLE
    subject: str         # the thing: a path, a host, a credential identity
    detail: str          # what a person needs to know, in a sentence
    mechanism: str = ""  # the layer this rests on, and what was measured about it
    evidence: str = ""   # the Reading this rests on; REQUIRED for NONE/CONTAINED

    def __post_init__(self):
        """The reassuring row cannot be constructed without its evidence.

        THE DEFECT: six attacks all ended at a site that emitted CONTAINED or
        NONE from evidence it had not obtained -- a config parse that raised, a
        file it could not open, a directory it never walked. Each was fixed at
        its own site, and each fix was aimed one step to the left of the next
        site. A rule enforced in a constructor cannot be forgotten at a site,
        which is the only version of this rule worth having. _reassure() is the
        only thing that fills `evidence` in, and it fills it only from a Reading
        that completed.
        """
        if self.level in REASSURING and not self.evidence:
            raise ValueError(
                "a reassuring finding must name the reading it rests on -- build "
                "it with _reassure(), not with Finding(): code=%r level=%r"
                % (self.code, self.level))
        if self.level == UNKNOWN and self.basis != UNOBSERVABLE:
            raise ValueError("an UNKNOWN finding is UNOBSERVABLE by definition: "
                             "code=%r basis=%r" % (self.code, self.basis))
        if self.level != UNKNOWN and self.basis != OBSERVED:
            raise ValueError("only an UNKNOWN finding may be UNOBSERVABLE: "
                             "code=%r level=%r" % (self.code, self.level))

    def as_dict(self):
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True)
class BlastRadius:
    """The whole answer. An OBSERVATION -- see the module docstring."""

    levels: dict         # dimension -> level
    findings: tuple      # Finding, most severe first
    inputs_seen: dict    # what was examined, so "found nothing" is distinguishable
                         # from "did not look"
    kind: str = "observation"

    def level(self, dimension):
        return self.levels[dimension]

    def by_dimension(self, dimension):
        return tuple(f for f in self.findings if f.dimension == dimension)

    def contained(self, dimension):
        """True only for NONE and CONTAINED.

        The one predicate a renderer should use to say "nothing to worry about
        here". It is written as a membership test in the two safe levels rather
        than as an exclusion of the unsafe ones, so a level added later is
        unsafe by default instead of quietly joining the reassuring branch.
        """
        return self.levels[dimension] in (NONE, CONTAINED)

    @property
    def worst(self):
        return max(self.levels.values(), key=lambda name: LEVEL_ORDER[name])

    @property
    def unseen(self):
        """The axes whose extent nobody could see. Never empty-by-accident: a
        caller printing "no unknowns" is printing this being empty."""
        return tuple(d for d in DIMENSIONS if self.levels[d] == UNKNOWN)

    def as_dict(self):
        return {
            "kind": self.kind,
            "schema": 1,
            "levels": dict(self.levels),
            "level_meaning": {name: LEVEL_MEANING[name]
                              for name in sorted(set(self.levels.values()),
                                                 key=lambda n: LEVEL_ORDER[n])},
            "worst": self.worst,
            "unseen": list(self.unseen),
            "findings": [f.as_dict() for f in self.findings],
            "inputs_seen": dict(self.inputs_seen),
            # Said in the record itself, not only in this file's docstring. A
            # receipt that carries the levels without this sentence invites the
            # reader to treat "contained" as "the system stopped it".
            "note": ("An observation of what the resolved ceiling and the workspace "
                     "make possible. It is not a claim that anything was enforced: "
                     "enforcement statuses live in the session record's own "
                     "enforcement table."),
        }


# --------------------------------------------------------------------------- #
# Evidence: the one gate every reassuring row goes through
# --------------------------------------------------------------------------- #

class Reading:
    """Evidence actually obtained about one subject, and what stopped it if not.

    The named thing a NONE or CONTAINED row is allowed to rest on. It is
    deliberately not a boolean: a caller holding a bare False still has to
    remember to say WHY, on the axis the reader is looking at, in a sentence --
    and the six landed attacks were six sites where somebody did not. A Reading
    carries its own failure code and its own sentence, so the honest row writes
    itself at whatever site the comfortable one would have appeared.

    Mutable on purpose. A reading is built optimistic and marked failed by
    whichever step could not finish, which may be several functions away from
    the row that wanted to rest on it.
    """

    __slots__ = ("name", "subject", "mechanism", "code", "detail", "reported")

    def __init__(self, name, subject, mechanism=""):
        self.name = name              # stable id, recorded on the rows it supports
        self.subject = str(subject)
        self.mechanism = mechanism
        self.code = ""                # the finding code to emit if it FAILED
        self.detail = ""
        self.reported = set()         # dimensions its failure has been said on

    @property
    def complete(self):
        return not self.code

    def failed(self, code, detail, mechanism=""):
        """Record why this reading did not complete.

        FIRST failure wins. The thing that went wrong first is the thing a
        person can act on; a later one is usually its consequence, and a reader
        shown the consequence goes and fixes the wrong file.
        """
        if self.complete:
            self.code = code
            self.detail = detail
            if mechanism:
                self.mechanism = mechanism
        return self

    def __repr__(self):
        return "Reading(%r, complete=%r, code=%r)" % (
            self.name, self.complete, self.code)


def _unseen(findings, reading, dimensions):
    """Say, on every axis it would have decided, that a reading did not complete.

    Returns True if the reading had failed. Deduplicated per axis, because one
    unreadable config suppresses several reassuring rows and a reader does not
    need the same sentence four times -- but it IS said on every axis, not only
    on the one whose row happened to be suppressed. That distinction is the
    whole of attack 5: an unreadable .git/config leaves the remote's effect on
    durability, exfiltration, destruction AND reachability unestablished, and
    reporting it on one of them would leave the other three reading as clean.
    """
    if reading.complete:
        return False
    for dimension in dimensions:
        if dimension in reading.reported:
            continue
        reading.reported.add(dimension)
        findings.append(Finding(reading.code, dimension, UNKNOWN, UNOBSERVABLE,
                                reading.subject, reading.detail, reading.mechanism))
    return True


def _reassure(findings, evidence, code, dimension, level, subject, detail,
              mechanism=""):
    """The ONE door a NONE or CONTAINED finding goes through.

    `evidence` is a Reading or a tuple of them -- a tuple when a row rests on
    more than one, in which case the FIRST incomplete one is the one reported,
    since it is the first thing a person can go and fix.

    If the evidence completed, the reassuring row is emitted and carries the
    reading's name, so a receipt says what each comfortable sentence was read
    from. If it did not, the row is NOT emitted and the reading's UNKNOWN takes
    its place on that axis. There is no third branch and no way to opt out: see
    Finding.__post_init__, which refuses a reassuring level with no evidence, so
    a site that tries to sidestep this helper raises instead of reassuring.
    """
    if level not in REASSURING:
        raise ValueError("_reassure builds NONE and CONTAINED rows, not %r" % (level,))
    readings = evidence if isinstance(evidence, tuple) else (evidence,)
    blocked = next((r for r in readings if not r.complete), None)
    if blocked is not None:
        _unseen(findings, blocked, (dimension,))
        return False
    findings.append(Finding(code, dimension, level, OBSERVED, subject, detail,
                            mechanism,
                            evidence="+".join(r.name for r in readings)))
    return True


# --------------------------------------------------------------------------- #
# Filesystem observation, all of it failure-tolerant
# --------------------------------------------------------------------------- #

def _lstat(path):
    """stat without following, or None. A path that cannot be stat'd is a fact
    to report, never an exception to escape through: this runs against a
    workspace a person owns and a mission may have half-written."""
    try:
        return os.lstat(str(path))
    except OSError:
        return None


def _walk(root, budget):
    """(entries, truncated, unreadable). Never follows a symlink.

    Returns every entry with its lstat so a caller can ask several questions of
    one traversal. `truncated` is the whole point of the return shape: a walk
    that ran out of budget must not be reported as a walk that found nothing.
    """
    entries, unreadable, seen = [], [], 0
    stack = [Path(root)]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as scan:
                children = list(scan)
        except OSError as exc:
            unreadable.append("%s (%s)" % (current, type(exc).__name__))
            continue
        for child in children:
            seen += 1
            if seen > budget:
                return entries, True, unreadable
            info = _lstat(child.path)
            if info is None:
                unreadable.append(child.path)
                continue
            entries.append((Path(child.path), info))
            if stat.S_ISDIR(info.st_mode):
                stack.append(Path(child.path))
    return entries, False, unreadable


def _inode(info):
    return (info.st_dev, info.st_ino)


# --------------------------------------------------------------------------- #
# git, read as data
# --------------------------------------------------------------------------- #

class _GitBudget:
    """The shared wall-clock allowance for the git calls of one classification.

    Deliberately not a per-call timeout. A per-call timeout bounds each read and
    bounds nothing about a workspace holding five hundred of them, which is a
    shape the mission chooses.
    """

    __slots__ = ("remaining",)

    def __init__(self, total=None):
        self.remaining = GIT_TOTAL_TIMEOUT if total is None else total

    def take(self):
        """Seconds this call may have: the per-call cap, or what is left."""
        return min(GIT_TIMEOUT, self.remaining)

    def spend(self, seconds):
        self.remaining = max(0.0, self.remaining - seconds)


def _git_dir_from(candidate, ws):
    """(path, external, note) for ONE .git entry. Handles .git as a FILE.

    A worktree, a submodule checkout and `git worktree add` all leave a .git
    FILE holding "gitdir: <path>". The object store then lives somewhere the
    checkpoint does not snapshot, which changes the durability answer for every
    commit the mission makes -- and a directory listing of the workspace looks
    exactly like an ordinary checkout.

    A relative gitdir resolves against the directory HOLDING the .git file, the
    way git resolves it, not against the workspace root. Those are the same path
    only for a repository at the workspace root, which is the only case the
    previous version of this function could see at all.
    """
    info = _lstat(candidate)
    if info is None:
        return None, False, ""
    if stat.S_ISDIR(info.st_mode):
        return Path(candidate), False, ""
    if not stat.S_ISREG(info.st_mode):
        return None, False, ("a .git that is neither a directory nor a file: %s"
                             % candidate)
    try:
        text = Path(candidate).read_text(errors="replace")
    except OSError as exc:
        return None, False, ("the .git file %s could not be read: %s"
                             % (candidate, type(exc).__name__))
    for line in text.splitlines():
        if line.strip().lower().startswith("gitdir:"):
            target = line.split(":", 1)[1].strip()
            resolved = Path(target)
            if not resolved.is_absolute():
                resolved = Path(candidate).parent / target
            try:
                resolved = Path(os.path.normpath(str(resolved)))
            except ValueError:
                pass
            external = Path(ws) not in resolved.parents and resolved != Path(ws)
            return resolved, external, ""
    return None, False, "the .git file %s names no gitdir" % candidate


def _repositories(ws, entries):
    """(repositories, notes) -- every git repository IN the workspace.

    THE DEFECT: the old _git_dir() looked at <ws>/.git and nowhere else, so a
    workspace CONTAINING a checkout -- the ordinary shape when an agent is told
    to clone into its scratch directory -- produced total SILENCE. Not the
    reassuring row: no row at all, and git_examined False. Silence is the one
    output a reader cannot argue with, which is why the verifier called this the
    attack with no defence aimed at it.

    Both shapes are found off the traversal that has already happened, so this
    costs no syscalls of its own:

      a .git entry   at any depth, directory or worktree file.
      a bare repo    a directory holding HEAD, config and objects/ and not
                     itself called .git. `git clone --bare mirror.git` inside
                     the workspace is the same move without the .git name.
    """
    found, notes = [], []
    directories = {str(path) for path, info in entries if stat.S_ISDIR(info.st_mode)}
    files = {str(path) for path, info in entries if stat.S_ISREG(info.st_mode)}
    for path, _info in entries:
        if path.name != ".git":
            continue
        git_dir, external, note = _git_dir_from(path, ws)
        if note:
            notes.append(note)
        elif git_dir is not None:
            found.append((path.parent, git_dir, external))
    already = {str(git_dir) for _work, git_dir, _external in found}
    for directory in sorted(directories):
        if Path(directory).name == ".git" or directory in already:
            continue
        if (directory + "/HEAD" in files and directory + "/config" in files
                and directory + "/objects" in directories):
            found.append((Path(directory), Path(directory), False))
    return found, notes


def _git_config(git_dir, budget):
    """(Reading, [(key, value, origin)]) -- git's own answer, not a re-parse.

    THE DEFECT this replaces: the old version parsed .git/config with
    configparser and returned None on any exception, and every caller read None
    as "nothing is configured". git's config format is not an ini file, and
    tools/probes/blast_git_config.py runs both readers over the same bytes and
    prints five shapes where they disagree -- each one a way for a mission to
    buy itself the reassuring row by appending to its own config.

    --file names the file outright instead of letting git discover a repository.
    That is not stylistic either: MEASURED in the same probe,
    `git --git-dir=X config --list` on a .git that git does not recognise as a
    repository exits 0 with NO OUTPUT, which is the reassuring answer arriving
    by another route. --file on a file it cannot read is a nonzero exit.

    --includes is passed explicitly because it defaults OFF for --file, and
    include.path was attack 2. --show-origin so that a key read from outside the
    workspace can be reported rather than folded in silently. -z because a
    config VALUE may legally contain a newline, which against line-separated
    output forges a whole extra key.

    Anything but a clean exit 0 and a well-formed output shape FAILS the
    Reading: a missing binary, a timeout, a config git refuses, a permission
    error. It never returns an empty answer that reads like an empty config.
    """
    reading = Reading(
        "git.config", str(git_dir),
        "git config --file <gitdir>/config --list --show-origin --includes -z, "
        "run at a pinned absolute path with a replaced environment. Read at "
        "classification time from a file this mission can rewrite while it runs "
        "-- measured in tools/probes/blast_workspace_socket.py -- so it is a "
        "statement about read time and not a control")
    path = Path(git_dir) / "config"
    binary = _lstat(GIT_BINARY)
    if (binary is None or not stat.S_ISREG(binary.st_mode)
            or not os.access(GIT_BINARY, os.X_OK)):
        reading.failed(
            "git.config_unreadable",
            "The git this classifier is pinned to (%s) is not an executable "
            "file, so this repository's configuration was not read at all. "
            "Whether it has a remote, a hook path or a key that makes git run "
            "something was NOT established -- in particular it is not a "
            "repository with no remote." % GIT_BINARY)
        return reading, []
    allowance = budget.take()
    if allowance <= 0:
        reading.failed(
            "git.config_unreadable",
            "The %ds allowance this classification has for reading git "
            "configuration was already spent when %s was reached, so its "
            "configuration was not read. Whether it can publish was NOT "
            "established." % (GIT_TOTAL_TIMEOUT, path))
        return reading, []
    started = time.monotonic()
    try:
        done = subprocess.run(
            [GIT_BINARY, "config", "--file", str(path), "--list",
             "--show-origin", "--includes", "-z"],
            capture_output=True, env=dict(GIT_ENV), timeout=allowance,
            stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        budget.spend(time.monotonic() - started)
        reading.failed(
            "git.config_unreadable",
            "Reading %s did not finish within %.1fs. That is reachable from "
            "inside the workspace: an include.path naming a fifo makes git "
            "block and never return, measured in "
            "tools/probes/blast_git_config.py. Nothing about this repository's "
            "configuration was established." % (path, allowance))
        return reading, []
    except OSError as exc:
        budget.spend(time.monotonic() - started)
        reading.failed(
            "git.config_unreadable",
            "Reading %s failed with %s, so nothing about this repository's "
            "configuration was established." % (path, type(exc).__name__))
        return reading, []
    budget.spend(time.monotonic() - started)
    if done.returncode != 0:
        lines = (done.stderr or b"").decode("utf-8", "replace").strip().splitlines()
        reading.failed(
            "git.config_unreadable",
            "git refused to read %s (exit %d)%s. This is the same situation "
            "workspace.unreadable reports and it gets the same answer: whether "
            "this repository can publish was NOT established, and it is "
            "specifically NOT a repository with no remote."
            % (path, done.returncode, (": " + lines[-1]) if lines else ""))
        return reading, []
    records = [r for r in done.stdout.decode("utf-8", "replace").split("\0") if r]
    if len(records) % 2:
        # --show-origin emits an origin record before every key record. An odd
        # count means the output is not the shape this parse assumes, and a
        # parse that does not understand its input reports UNKNOWN rather than
        # whatever it managed to make of it.
        reading.failed(
            "git.config_unreadable",
            "git's --show-origin output for %s held %d records, which is not "
            "the origin/key pairing this reading assumes, so it was not "
            "interpreted." % (path, len(records)))
        return reading, []
    entries = []
    for index in range(0, len(records), 2):
        origin = records[index]
        key, separator, value = records[index + 1].partition("\n")
        # No separator is git's spelling of a variable with NO VALUE, which git
        # defines as boolean true. configparser raised on it; that was attack 1.
        entries.append((key.strip(), value if separator else None, origin))
    return reading, entries


def _remotes(entries):
    """name -> {"url": [...], "pushurl": [...]}, from git's own key names.

    git prints remote.<name>.url with the section and key lowercased and the
    subsection -- the remote's name -- as written, so this splits on dots rather
    than on quoting. Two shapes the configparser draft got wrong arrive here as
    ordinary keys: the legacy [remote.origin] spelling, which it read as a
    section no remote lookup matched, and a multivar remote carrying two urls,
    of which it kept one.
    """
    result = {}
    for key, value, _origin in entries:
        parts = key.split(".")
        if len(parts) < 3 or parts[0] != "remote":
            continue
        field = parts[-1]
        if field not in ("url", "pushurl"):
            continue
        text = (value or "").strip()
        if not text:
            continue
        result.setdefault(".".join(parts[1:-1]),
                          {"url": [], "pushurl": []})[field].append(text)
    return result


def _executing_config(entries):
    """Config keys that make a later, innocent git command run something.

    THE DEFECT: the old list caught core.sshcommand and missed credential.helper,
    and the verifier used a '!'-prefixed helper that curls
    /home/agent/.codex/auth.json to an attacker. Adding credential.helper to the
    list would be the same defence one step to the left of the next key nobody
    listed, so the FIRST rule here is git's own marker rather than a key name: a
    value beginning with '!' is a shell command to git, on ANY key, including
    keys invented after this was written. The tables are the second net, for the
    keys that name a program without a '!'.

    Keys come back lowercased, from git itself. That is the spelling
    `git config --list` prints, so this row and the tool a reader checks it
    against agree. (sf_missions.git_structure() builds the same list from the
    same git output and still has the gap this closes; it is reported to the
    lead rather than edited here.)
    """
    found = {}
    for key, value, _origin in entries:
        lowered = key.lower()
        text = "" if value is None else value
        if text.startswith("!"):
            why = ("its value begins with '!', which is git's own marker for a "
                   "shell command")
        elif (lowered.startswith(EXECUTING_KEY_PREFIXES)
              or lowered.endswith(EXECUTING_KEY_SUFFIXES)
              or lowered in EXECUTING_KEY_EXACT):
            why = "this key names a program git runs"
        else:
            continue
        found[key] = ("true" if value is None else text, why)
    return found


def _hooks(git_dir):
    """(names, Reading). Installed hooks, excluding git's own .sample files.

    THE DEFECT: this swallowed OSError and returned [], which is the same value
    it returns for a repository that has no hooks -- so a hooks directory that
    could not be listed became "there are no hooks here". Same class as the four
    git ones, found while fixing them.
    """
    hook_dir = Path(git_dir) / "hooks"
    reading = Reading("git.hooks", str(hook_dir),
                      "os.scandir of the repository's hooks directory")
    try:
        names = sorted(entry.name for entry in os.scandir(hook_dir)
                       if entry.is_file() and not entry.name.endswith(".sample"))
    except FileNotFoundError:
        # A repository with no hooks directory has no hooks. That is an answer,
        # not a failure to obtain one.
        return [], reading
    except OSError as exc:
        reading.failed(
            "git.hooks_unreadable",
            "The hooks directory %s could not be listed (%s), so whether a "
            "program runs on this machine the next time anybody uses this "
            "repository was not established." % (hook_dir, type(exc).__name__))
        return [], reading
    return names, reading


def _remote_reachability(url, network, bound_paths):
    """(reachable, why). Where a remote actually is, from inside the sandbox.

    A remote is not automatically a channel. bwrap --unshare-net in posture
    'none' leaves the namespace with no route, so a https:// remote is simply
    unreachable, and reporting it as an exfiltration path would be the noise
    that gets a classifier ignored. A file:// or plain-path remote is different:
    it is reachable exactly when its path is one the sandbox has mounted.
    """
    lowered = url.lower()
    for scheme in EXECUTING_GIT_SCHEMES:
        if lowered.startswith(scheme):
            return True, ("this remote's transport runs a command rather than "
                          "speaking a wire protocol")
    network_schemes = ("http://", "https://", "ssh://", "git://", "ftp://", "ftps://")
    if lowered.startswith(network_schemes) or ("@" in url and ":" in url
                                               and not lowered.startswith("file://")
                                               and not url.startswith("/")):
        if network == "none":
            return False, ("the sandbox has no route at all -- bwrap --unshare-net "
                           "with no NAT attached -- so this remote is unreachable "
                           "from inside")
        return True, "the sandbox has a route and this remote is addressed over it"
    path = url[len("file://"):] if lowered.startswith("file://") else url
    if not path.startswith("/"):
        return False, ("a relative remote path; it resolves inside the sandbox, "
                       "where the surrounding directories are not mounted")
    for bound in bound_paths:
        try:
            if os.path.commonpath([path, str(bound)]) == str(bound):
                return True, "this remote is a path inside " + str(bound)
        except ValueError:
            continue
    return False, ("this remote is a host path that the sandbox does not mount, "
                   "so it is absent inside")


# --------------------------------------------------------------------------- #
# The classifier
# --------------------------------------------------------------------------- #

def classify(mission, ceiling, *, workspace=None, walk_budget=WALK_BUDGET):
    """The blast radius of one mission under one resolved ceiling.

    `mission` is the mission row as Store.unpack() returns it -- a mapping with
    `workspace`, `config` and optionally `checkpoint`. `ceiling` is the
    SandboxSpec that sf_missions.mission_decision() resolved; it is read through
    getattr so this module never imports sf_providers and a test can pass any
    object with the same field names. Nothing is read from the provider
    manifest: see DERIVED, NEVER DECLARED.
    """
    config = dict(mission.get("config") or {})
    ws = Path(workspace or mission.get("workspace") or ".")

    network = getattr(ceiling, "network", "none") or "none"
    egress = tuple(getattr(ceiling, "egress_allowlist", ()) or ())
    grants = tuple(str(g) for g in (getattr(ceiling, "read_grants", ()) or ()))
    masks = tuple(str(m) for m in (getattr(ceiling, "masked_paths", ()) or ()))
    credentials = tuple(str(c) for c in (getattr(ceiling, "credential_ids", ()) or ()))
    account_mount = str(getattr(ceiling, "account_mount", "") or "")
    writable = (getattr(ceiling, "workspace_mode", "workspace-write") != "read-only")

    findings = []
    seen = {"workspace": str(ws), "read_grants": list(grants),
            "masked_paths": list(masks), "network": network,
            "egress_allowlist": list(egress), "credential_ids": list(credentials),
            "account_mount": account_mount, "workspace_writable": writable,
            "walk_budget": walk_budget, "walks_truncated": [],
            "unreadable": [], "git_examined": False,
            "git_search": "not_attempted",
            "checkpoint": mission.get("checkpoint") or None,
            # In the record, not only in this file's docstring. Everything below
            # that comes off the workspace was read while the mission could still
            # be writing to it -- measured in
            # tools/probes/blast_workspace_socket.py, where the payload rewrites
            # its own .git/config from inside the sandbox.
            "workspace_authored_by_the_mission": writable}

    # THE READINGS. Every NONE or CONTAINED row below names one of these, and
    # _reassure() refuses to build one from a reading that did not complete. See
    # A REASSURING ROW NEEDS EVIDENCE in the module docstring.
    ceiling_read = Reading(
        "ceiling", "the resolved SandboxSpec",
        "read field by field off the ceiling object. It is this classifier's "
        "INPUT rather than an observation of the world, so it is complete by "
        "construction -- and it is the only reading here that is")
    tree = Reading(
        "workspace.tree", str(ws),
        "one os.scandir traversal of the workspace, never following a symlink, "
        "bounded by sf_blast.WALK_BUDGET")

    # ONE traversal of the workspace, shared. It was walked twice in an earlier
    # draft -- once for escaping symlinks, once for hardlink candidates -- which
    # doubled the cost on the largest input and, worse, could disagree with
    # itself if the mission wrote to the tree between the two passes.
    ws_entries, ws_truncated, ws_unreadable = _walk(ws, walk_budget)
    _workspace_findings(findings, seen, ws, writable, mission,
                        ws_entries, ws_truncated, ws_unreadable, walk_budget,
                        tree, ceiling_read)

    # What the hardlink question rests on: every path the sandbox can read that
    # this classifier actually enumerated. A truncated or partly unreadable walk
    # -- of the workspace OR of a grant -- means a second name for a masked
    # inode could be sitting in the part nobody saw, and "this mask is applied"
    # stops being sayable. The old code checked only the MASK's own walk.
    hardlinks = Reading(
        "hardlinks", str(ws),
        "the workspace and read-grant traversals, which are where a second "
        "directory entry for a masked inode would be seen")
    if not tree.complete:
        hardlinks.failed(
            "mask.unverified",
            "The workspace was not enumerated to the end, so whether a masked "
            "file is reachable under a second name inside it was not "
            "established.")

    inodes = _grant_findings(findings, seen, grants, ws_entries, walk_budget,
                             hardlinks)
    _mask_findings(findings, seen, masks, inodes, walk_budget, hardlinks)
    _account_findings(findings, account_mount, network)
    _network_findings(findings, network, egress, ceiling_read)
    _credential_findings(findings, credentials, network, account_mount)

    search = Reading(
        "git.search", str(ws),
        "every entry of the workspace traversal, examined for a .git entry and "
        "for a bare repository shape")
    if not tree.complete:
        search.failed(
            "git.search_incomplete",
            "The workspace was not enumerated to the end, so whether it holds a "
            "git repository -- and with it a way to publish outside this "
            "machine -- was not established.")
    _git_findings(findings, seen, ws, network, grants, account_mount,
                  ws_entries, search)
    _test_findings(findings, config, ws, (ceiling_read, tree, hardlinks, search))

    levels = {}
    for dimension in DIMENSIONS:
        applicable = [f.level for f in findings if f.dimension == dimension]
        levels[dimension] = max(applicable, key=lambda n: LEVEL_ORDER[n]) if applicable else NONE
    ordered = tuple(sorted(findings, key=lambda f: (-LEVEL_ORDER[f.level], f.dimension, f.code, f.subject)))
    return BlastRadius(levels=levels, findings=ordered, inputs_seen=seen)


def _workspace_findings(findings, seen, ws, writable, mission,
                        entries, truncated, unreadable, budget, tree, ceiling):
    info = _lstat(ws)
    if info is None:
        # Cannot see the workspace at all. Every axis that depends on its
        # contents is unknown, and saying "contained" here would be a claim
        # about a directory this process could not open.
        tree.failed(
            "workspace.unreadable",
            "The workspace could not be read, so nothing about its contents "
            "was established. This is not an empty workspace.",
            "os.lstat failed on the workspace path")
        _unseen(findings, tree, (REACHABLE, DESTRUCTIBLE, DURABLE))
        return

    # The traversal's own honesty, decided BEFORE anything rests on it. Both
    # shapes are "we did not see all of it", and the difference between them is
    # only which sentence helps the reader.
    if truncated:
        seen["walks_truncated"].append(str(ws))
        tree.failed(
            "workspace.too_large",
            "The workspace has more than %d entries, so it was not enumerated "
            "to the end. What else is in it -- a git checkout with a push "
            "remote, a live socket, a second name for a masked file -- was not "
            "established." % budget,
            "traversal budget in sf_blast.WALK_BUDGET")
    elif unreadable:
        listed = ", ".join(unreadable[:3])
        more = (" and %d more" % (len(unreadable) - 3)) if len(unreadable) > 3 else ""
        tree.failed(
            "workspace.partly_unreadable",
            "Part of the workspace could not be listed (%s%s), so what is in it "
            "was not established. A subtree nobody could open holds a checkout "
            "with a push remote or a live socket exactly as easily as it holds "
            "nothing." % (listed, more),
            "os.scandir or os.lstat failed inside the traversal")
    seen["unreadable"].extend(unreadable[:20])
    # Said on REACHABLE unconditionally rather than only where it happens to
    # suppress a reassuring row: an incomplete traversal is a fact about this
    # classification whether or not anything comfortable was going to rest on it.
    _unseen(findings, tree, (REACHABLE,))

    _reassure(
        findings, ceiling, "workspace.reach", REACHABLE, CONTAINED, str(ws),
        "The workspace tree, and the read-only system tree every sandbox gets "
        "(/usr, /bin, /sbin, /lib, and the public /etc files). The host "
        "filesystem outside those is not mounted, so it is absent rather than "
        "merely forbidden.",
        "bwrap binds exactly one workspace and --dir /etc with a named public "
        "subset; nothing else of the host is in the mount namespace. This row is "
        "about the MOUNT SET, which is a ceiling fact -- what is INSIDE the tree "
        "is carried by the traversal rows, which outrank it when the traversal "
        "did not finish")

    # Sockets in the workspace. THE DEFECT: _grant_findings scanned read GRANTS
    # for S_ISSOCK and read the workspace entries only for S_ISREG with
    # st_nlink > 1, so a live AF_UNIX socket sitting in the workspace was
    # invisible and `exfiltratable` came out 'none'. The narrower of the two
    # mounts was the one being watched: a grant is --ro-bind and the workspace is
    # --bind. Scanned in BOTH modes, because a --ro-bind does not make a socket
    # read-only -- the kernel exempts special files from the read-only mount
    # check, which is the measured fact the grant row already rests on.
    mount = ("the workspace, which is bound read-write (bwrap --bind, not "
             "--ro-bind)" if writable else
             "the workspace, which is bound read-only -- and a --ro-bind does "
             "not make a socket read-only")
    for path, entry in entries:
        if stat.S_ISSOCK(entry.st_mode):
            _socket_findings(
                findings, str(path), "workspace.socket", mount,
                "measured: tools/probes/blast_workspace_socket.py -- through the "
                "shipped Firebreak at --net none, connect REACHED, the host "
                "process received b'WORKSPACE-BYTES-LEAVING', a plain file in "
                "the same mount took a write (WROTE) where the --ro-bind grant "
                "refuses one with EROFS 30, and the payload bound a socket of "
                "its own in the workspace")

    if not writable:
        _reassure(
            findings, ceiling, "workspace.readonly", DESTRUCTIBLE, NONE, str(ws),
            "The workspace is bound read-only, so this mission cannot destroy "
            "anything in it.",
            "bwrap --ro-bind of the workspace. Measured in "
            "tools/probes/blast_socket_grant.py: a write to a --ro-bind path "
            "fails EROFS (errno 30)")
        return

    checkpoint = mission.get("checkpoint")
    _reassure(
        findings, ceiling, "workspace.write", DESTRUCTIBLE, CONTAINED, str(ws),
        "Every file in the workspace can be changed or deleted."
        + (" A recovery point exists (%s), so this is reversible." % checkpoint
           if checkpoint else
           " Execution takes a recovery point before any provider runs, so this "
           "becomes reversible at that moment and is not reversible before it."),
        "sf_mcp.CheckpointEngine snapshots the workspace tree into "
        "<parent>/.sf-checkpoints/<name> and undo() restores it")
    _reassure(
        findings, ceiling, "workspace.write", DURABLE, CONTAINED, str(ws),
        "Workspace changes do not outlive an Undo: the checkpoint covers this "
        "tree exactly.",
        "the checkpoint store is a sibling of the workspace, outside it and "
        "outside every sandbox bind, so a mission cannot reach its own undo")

    # Symlinks that leave the workspace. Most are harmless because their target
    # is not mounted at all; the ones that matter point INTO something the
    # sandbox does mount. Reported either way, because "we checked the symlinks"
    # is information and silence is not.
    escaping = []
    for path, info in entries:
        if not stat.S_ISLNK(info.st_mode):
            continue
        try:
            target = os.path.realpath(str(path))
        except OSError:
            continue
        if not target.startswith(str(ws) + os.sep) and target != str(ws):
            escaping.append((str(path), target))
    for path, target in escaping[:10]:
        _reassure(
            findings, tree, "workspace.symlink_escapes", REACHABLE, CONTAINED,
            path,
            "A symbolic link in the workspace points outside it, at %s. Inside "
            "the sandbox it resolves in the sandbox's own mount namespace, where "
            "that path exists only if some bind put it there." % target,
            "bwrap mount namespace: a link is followed inside the sandbox, not "
            "on the host, so a link to an unmounted path dangles")


def _grant_findings(findings, seen, grants, ws_entries, budget, hardlinks):
    """Read grants, and the two things that make one more than a read.

    Returns the (dev, ino) set of multiply-linked files seen under the grants
    and the workspace, which _mask_findings needs to decide whether a mask over
    a file is a mask over its content. A grant walk that did not finish fails the
    `hardlinks` reading rather than quietly contributing fewer inodes: the mask
    row that rests on this enumeration must not be able to say "applied" from a
    search that stopped early.
    """
    linked = {}
    for path, info in ws_entries:
        if stat.S_ISREG(info.st_mode) and info.st_nlink > 1:
            linked.setdefault(_inode(info), []).append(str(path))
    for grant in grants:
        info = _lstat(grant)
        if info is None:
            findings.append(Finding(
                "grant.unreadable", REACHABLE, UNKNOWN, UNOBSERVABLE, grant,
                "A read grant that could not be examined from here. Its contents "
                "were not established.",
                "os.lstat failed on the granted path"))
            hardlinks.failed(
                "mask.unverified",
                "A read grant (%s) could not be examined, so whether a masked "
                "file is reachable under a second name inside it was not "
                "established." % grant)
            continue
        findings.append(Finding(
            "grant.reach", REACHABLE, BOUNDED, OBSERVED, grant,
            "Everything under this path is readable inside the sandbox.",
            "bwrap --ro-bind per grant. Writes to it fail EROFS -- measured in "
            "tools/probes/blast_socket_grant.py (plain_write blocked:OSError:30)"))
        if not stat.S_ISDIR(info.st_mode):
            if stat.S_ISSOCK(info.st_mode):
                _socket_findings(findings, grant, "grant.socket", "a read grant",
                                 GRANT_SOCKET_MEASUREMENT)
            continue
        entries, truncated, unreadable = _walk(grant, budget)
        seen["unreadable"].extend(unreadable[:20])
        if truncated:
            seen["walks_truncated"].append(grant)
            hardlinks.failed(
                "mask.unverified",
                "A read grant (%s) holds more than %d entries and was not "
                "enumerated to the end, so whether a masked file is reachable "
                "under a second name inside it was not established."
                % (grant, budget))
            findings.append(Finding(
                "grant.too_large", REACHABLE, UNKNOWN, UNOBSERVABLE, grant,
                "This grant holds more than %d entries and was not enumerated to "
                "the end, so what else it exposes was not established." % budget,
                "traversal budget in sf_blast.WALK_BUDGET"))
        elif unreadable:
            hardlinks.failed(
                "mask.unverified",
                "Part of a read grant (%s) could not be listed, so whether a "
                "masked file is reachable under a second name inside it was not "
                "established." % grant)
        for path, child in entries:
            if stat.S_ISSOCK(child.st_mode):
                _socket_findings(findings, str(path), "grant.socket",
                                 "a read grant", GRANT_SOCKET_MEASUREMENT)
            if stat.S_ISREG(child.st_mode) and child.st_nlink > 1:
                linked.setdefault(_inode(child), []).append(str(path))
    return linked


# What the grant socket row rests on. Kept as a constant because the workspace
# socket row now rests on a different measurement of the same kernel behaviour,
# and a reader comparing the two rows should be able to see that they are two
# probes and not one sentence copied twice.
GRANT_SOCKET_MEASUREMENT = (
    "measured: tools/probes/blast_socket_grant.py -- connect REACHED, host "
    "received b'WORKSPACE-BYTES-LEAVING', control arm blocked ENOENT")


def _socket_findings(findings, path, code, mount, measurement):
    """A unix socket is a channel, not a file, wherever it is mounted.

    MEASURED, not reasoned. tools/probes/blast_socket_grant.py runs the shipped
    Firebreak at network posture 'none', connects to a socket inside a read
    grant, sends bytes and receives the host process's reply -- while the control
    arm without the grant gets ENOENT. The kernel exempts special files from the
    read-only mount check, so --ro-bind does not make a socket read-only; and
    AF_UNIX is addressed by filesystem path, so an empty network namespace is no
    obstacle at all.

    THE DEFECT this function's callers used to have: only the GRANT called it.
    The workspace -- the WIDER mount, bound --bind -- was read for hardlink
    candidates and nothing else, so a live socket in it was invisible and
    exfiltratable came out 'none'. tools/probes/blast_workspace_socket.py
    measures that arm separately; `mount` and `measurement` name which one a row
    came from, so the two rows cannot be mistaken for one fact stated twice.

    The shipped localmodel provider depends on exactly this and says so in its
    manifest notes. That is the reason this is reported rather than refused: it
    is a designed channel whose FAR SIDE is not visible from here.
    """
    findings.append(Finding(
        code, EXFILTRATABLE, UNKNOWN, UNOBSERVABLE, path,
        "A unix socket in %s. Bytes can leave the sandbox through it even at "
        "network posture 'none', and what the process on the other end does "
        "with them is not visible from here." % mount,
        measurement))
    findings.append(Finding(
        code, REACHABLE, UNKNOWN, UNOBSERVABLE, path,
        "Whatever that socket's peer will serve is reachable. The peer is a host "
        "process outside the sandbox and its behaviour is not derivable from %s."
        % mount,
        "AF_UNIX is addressed by filesystem path, so the sandbox's own empty "
        "network namespace does not bound it"))


def _mask_findings(findings, seen, masks, linked, budget, hardlinks):
    """Masks, and whether each one masks content or only a name.

    A mask is a REDUCTION, so its findings are the one place where a level of
    CONTAINED is the interesting result. The failure it can have is specific and
    measured: masking is BY PATH, and a second directory entry for the same
    inode is a different path.

    Which is why every reassuring row here rests on `hardlinks` as well as on
    this mask's own look: "no file inside it has a second name anywhere else the
    sandbox can read" is a claim about an ENUMERATION, and an enumeration that
    stopped early cannot support it.
    """
    for mask in masks:
        look = Reading("mask.stat", mask, "os.lstat of the declared masked path")
        info = _lstat(mask)
        if info is None:
            _reassure(
                findings, look, "mask.absent", REACHABLE, CONTAINED, mask,
                "This masked path does not exist on the host, so the sandbox sees "
                "an empty file where the declaration expected something.",
                "bwrap creates the mount point for --ro-bind /dev/null")
            continue
        if stat.S_ISDIR(info.st_mode):
            entries, truncated, unreadable = _walk(mask, budget)
            walk = Reading("mask.walk", mask,
                           "traversal of the masked directory")
            if truncated:
                seen["walks_truncated"].append(mask)
                walk.failed(
                    "mask.unverified",
                    "This masked directory holds more than %d entries, so "
                    "whether any of its files is reachable under a second name "
                    "was not established." % budget,
                    "traversal budget in sf_blast.WALK_BUDGET")
            elif unreadable:
                walk.failed(
                    "mask.unverified",
                    "Part of this masked directory could not be listed, so "
                    "whether any of its files is reachable under a second name "
                    "was not established.",
                    "os.scandir failed inside the traversal")
            defeated = [(str(path), linked[_inode(child)])
                        for path, child in entries
                        if stat.S_ISREG(child.st_mode) and _inode(child) in linked]
            if not defeated:
                _reassure(
                    findings, (walk, hardlinks), "mask.applied", REACHABLE,
                    CONTAINED, mask,
                    "This directory is hidden and no file inside it has a second "
                    "name anywhere else the sandbox can read.",
                    "bwrap mounts an empty tmpfs over the directory in the "
                    "sandbox's own mount namespace; the second-name search "
                    "covered the workspace and every read grant, to the end")
                continue
            for path, elsewhere in defeated[:10]:
                findings.append(Finding(
                    "mask.defeated", REACHABLE, UNKNOWN, UNOBSERVABLE, path,
                    "A file inside this masked directory is the same inode as %s, "
                    "which the mask does not name. The content is still readable "
                    "there." % ", ".join(sorted(elsewhere)[:3]),
                    "masking is BY PATH; measured in "
                    "tools/probes/blast_hardlink_mask.py"))
            continue
        if info.st_nlink > 1:
            findings.append(Finding(
                "mask.defeated", REACHABLE, UNKNOWN, UNOBSERVABLE, mask,
                "This masked file has %d names on its filesystem. A mask covers "
                "the name it was given; the other names still return the content, "
                "and this classifier cannot enumerate names outside the paths the "
                "sandbox mounts." % info.st_nlink,
                "measured: tools/probes/blast_hardlink_mask.py -- the declared "
                "name reads denied:PermissionError while a hardlinked sibling "
                "reads the secret"))
            continue
        # st_nlink is the FILESYSTEM's own count of names for this inode, not a
        # count of the names this classifier managed to enumerate, so a single
        # name is a complete answer from the lstat alone and this row does not
        # rest on `hardlinks`.
        _reassure(
            findings, look, "mask.applied", REACHABLE, CONTAINED, mask,
            "This file is masked and has a single name, so the mask covers its "
            "content and not merely one route to it.",
            "bwrap ro-binds /dev/null over it; the mount is nodev, so the read "
            "fails rather than returning empty -- measured in "
            "tools/probes/blast_hardlink_mask.py")


def _account_findings(findings, account_mount, network):
    """The provider account home. Writable, and outside the checkpoint.

    This is the field most likely to be read as harmless -- it is a mount of the
    provider's own credential directory, it is not in read_grants and it is not
    in the workspace. It is bound READ-WRITE, and undo() restores the workspace
    and nothing else.
    """
    if not account_mount:
        return
    findings.append(Finding(
        "account.mount", REACHABLE, BOUNDED, OBSERVED, account_mount,
        "The dedicated provider account home is mounted into the sandbox, "
        "including the credentials it stores.",
        "bwrap --bind of the account home onto /home/agent/.codex"))
    findings.append(Finding(
        "account.mount", DESTRUCTIBLE, BOUNDED, OBSERVED, account_mount,
        "That mount is read-write, so the mission can alter or delete the stored "
        "session there.",
        "bwrap --bind, not --ro-bind"))
    findings.append(Finding(
        "account.mount", DURABLE, BOUNDED, OBSERVED, account_mount,
        "Changes there outlive the mission and outlive an Undo: the checkpoint "
        "snapshots the workspace tree, and this path is not in it.",
        "sf_mcp.CheckpointEngine is workspace-scoped"))
    if network != "none":
        findings.append(Finding(
            "account.mount", EXFILTRATABLE, BOUNDED, OBSERVED, account_mount,
            "A stored credential is readable inside a sandbox that also has a "
            "route out.",
            "the account bind and the network namespace's NAT are both present "
            "in this posture"))


def _network_findings(findings, network, egress, ceiling):
    if network == "none":
        _reassure(
            findings, ceiling, "network.none", EXFILTRATABLE, NONE, "network",
            "No route out. Not a filtered route -- no route at all, so no "
            "destination is reachable, including the host's own loopback and LAN.",
            "bwrap --unshare-net with no NAT attached to the namespace. This is a "
            "statement about the IP stack ONLY: an AF_UNIX socket is addressed by "
            "filesystem path and is not bounded by it, which is why the socket "
            "rows outrank this one on the same axis")
        return
    hosts = ", ".join(sorted(egress)) if egress else ""
    if egress:
        findings.append(Finding(
            "network.allowlist", REACHABLE, BOUNDED, OBSERVED, hosts,
            "Whatever these hosts serve is readable: " + hosts,
            "nftables default DROP in the sandbox's own network namespace, "
            "permitting only the addresses these names resolved to at launch"))
        findings.append(Finding(
            "network.allowlist", EXFILTRATABLE, BOUNDED, OBSERVED, hosts,
            "Bulk transfer out is confined to these destinations: " + hosts,
            "nftables default DROP by ADDRESS. A host that shares an address "
            "with an allowed one is reachable, and an address set that changes "
            "after launch is not"))
    else:
        findings.append(Finding(
            "network.unfiltered", REACHABLE, BROAD, OBSERVED, "network",
            "The sandbox has a route and no destination was declared, so "
            "anything the host can reach is reachable.",
            "a NAT is attached and no ruleset is installed"))
        findings.append(Finding(
            "network.unfiltered", EXFILTRATABLE, BROAD, OBSERVED, "network",
            "Anything readable inside the sandbox can be sent anywhere.",
            "a NAT is attached and no ruleset is installed"))
    # True in EVERY networked posture, allowlist included. Firebreak states it
    # in its own source and it is the reason a declared allowlist must not be
    # reported as a bound on what can leave.
    findings.append(Finding(
        "network.dns_channel", EXFILTRATABLE, BROAD, OBSERVED, "10.0.2.3",
        "DNS queries leave through the NAT's forwarder, which the egress "
        "ruleset accepts along with the rest of the NAT subnet. A payload can "
        "encode data in query names, and a filter that matches on address does "
        "not see it. Low bandwidth; arbitrary destination.",
        "egress_ruleset() accepts ip daddr 10.0.2.0/24, which is the NAT and "
        "its resolver"))
    # Durability of remote state, split by whether the destinations are named.
    # An earlier draft put both at UNKNOWN, which made every networked mission
    # unknown-durable and buried the finding that actually distinguishes them --
    # a git push remote. A named allowlist bounds WHERE state can be changed
    # even though it cannot say WHAT changes, and that difference is the whole
    # value of the axis.
    if egress:
        findings.append(Finding(
            "network.reaches_remote_state", DURABLE, BOUNDED, OBSERVED, hosts,
            "State changed at these destinations outlives the mission and an Undo "
            "cannot reach it: " + hosts + ". What is held there was not "
            "enumerated; the destinations were.",
            "the checkpoint restores the workspace tree and nothing beyond it; "
            "nftables bounds which destinations exist"))
    else:
        findings.append(Finding(
            "network.reaches_remote_state", DURABLE, UNKNOWN, UNOBSERVABLE,
            "network",
            "Anything this mission changes anywhere on the network outlives it, "
            "an Undo cannot reach it, and no destination was declared, so where "
            "that could be was not established.",
            "the checkpoint restores the workspace tree and nothing beyond it; "
            "no ruleset bounds the destinations"))


def _credential_findings(findings, credentials, network, account_mount):
    if not credentials:
        return
    names = ", ".join(sorted(credentials))
    findings.append(Finding(
        "credential.present", REACHABLE, BOUNDED, OBSERVED, names,
        "These credential VALUES are in the sandbox's environment, readable by "
        "anything running in it: " + names,
        "bwrap --clearenv then one --setenv per declared identity; the value is "
        "resolved outside the sandbox and injected at the boundary"))
    if network == "none" and not account_mount:
        # Deliberately no exfiltration row. A credential with no channel is
        # already covered by network.none's EXFILTRATABLE=NONE, and a second row
        # saying the same thing in different words is how a findings list stops
        # being read. The reachability row above still names the credential, so
        # the credential is not silent -- only the duplicate is.
        return
    findings.append(Finding(
        "credential.exfiltratable", EXFILTRATABLE, BOUNDED, OBSERVED, names,
        "A credential value and a channel out are present in the same sandbox, "
        "so the credential is among the things that can leave.",
        "the environment injection and the network namespace's NAT are both "
        "present in this posture"))


def _config_origin_findings(findings, ws, config):
    """Where the configuration git obeyed actually came from.

    --show-origin names the file every key was read from, and with --includes
    that is not always the repository's own config. An include.path can name any
    readable file on the host -- measured in tools/probes/blast_git_config.py --
    so the price of asking git for git's semantics is that git may read
    somewhere else. It is not paid silently: an origin outside the workspace is
    its own row, because the effective configuration of this repository is then
    not covered by the checkpoint that covers the workspace, and a reader told
    "the workspace has this config" should know the workspace is not where all
    of it lives.
    """
    root = str(ws)
    outside = []
    for origin in sorted({origin for _key, _value, origin in config}):
        path = origin.split(":", 1)[1] if origin.startswith("file:") else origin
        normalized = os.path.normpath(path)
        if normalized == root or normalized.startswith(root + os.sep):
            continue
        outside.append(normalized)
    if not outside:
        return
    joined = ", ".join(outside)
    findings.append(Finding(
        "git.config_outside", DURABLE, BOUNDED, OBSERVED, joined,
        "git assembled this repository's configuration from %d file(s) outside "
        "the workspace, reached through include directives: %s. An Undo restores "
        "the workspace tree, so it does not restore these, and what they set is "
        "in force the next time anybody runs git here."
        % (len(outside), joined),
        "git config --show-origin names the file each key was read from"))


def _remote_findings(findings, name, label, url, network, bound, reading):
    """One configured remote URL, and whether it is a channel from in here."""
    reachable, why = _remote_reachability(url, network, bound)
    subject = "%s.%s %s" % (name, label, url)
    if not reachable:
        _reassure(
            findings, reading, "git.remote_unreachable", DURABLE, CONTAINED,
            subject,
            "A git remote is configured, and it cannot be reached from inside "
            "this sandbox: " + why + ".",
            "the remote is read with git's own config reader; reachability is "
            "decided by the resolved network posture and the sandbox's binds")
        return
    findings.append(Finding(
        "git.remote_push", DURABLE, UNKNOWN, UNOBSERVABLE, subject,
        "A reachable git remote. A push publishes work outside this machine and "
        "an Undo cannot retract it; a force-push can destroy history there. What "
        "is on that remote is not visible from here.",
        why))
    findings.append(Finding(
        "git.remote_push", EXFILTRATABLE, UNKNOWN, UNOBSERVABLE, subject,
        "Anything readable in the workspace can be committed and pushed to this "
        "remote.",
        why))
    findings.append(Finding(
        "git.remote_push", DESTRUCTIBLE, UNKNOWN, UNOBSERVABLE, subject,
        "History on that remote can be destroyed by a force-push, and what is "
        "there was not enumerated.",
        why))
    if any(url.lower().startswith(scheme) for scheme in EXECUTING_GIT_SCHEMES):
        findings.append(Finding(
            "git.remote_executes", REACHABLE, UNKNOWN, UNOBSERVABLE, subject,
            "This remote's transport hands its URL body to a command rather than "
            "to a wire protocol, so a fetch from it is code execution inside the "
            "sandbox.",
            "git ext::/fd:: transports run a program"))


def _git_findings(findings, seen, ws, network, grants, account_mount, entries,
                  search):
    """Git repositories IN the workspace, which a directory listing does not say.

    This is the case the brief calls a scratch-looking workspace that is not:
    the mission's scope is identical either way, and a push remote turns a
    reversible edit into an irreversible publication.

    Every fact below is read from files the mission can rewrite while it runs --
    measured in tools/probes/blast_workspace_socket.py, where the payload
    appends to its own .git/config from inside the sandbox. A classifier is not
    an enforcement point and cannot close that, so the rows say what they are
    statements about rather than leaving a reader to assume they are controls.
    """
    repositories, notes = _repositories(ws, entries)
    for note in notes:
        findings.append(Finding(
            "git.unreadable", DURABLE, UNKNOWN, UNOBSERVABLE, str(ws),
            "There is a .git in the workspace that this classifier could not "
            "interpret: " + note + ". Whether the repository reaches beyond the "
            "workspace was not established.",
            "the .git pointer is read as data before git is asked anything"))
    seen["git_search"] = "complete" if search.complete else "incomplete"
    seen["git_repositories"] = sorted(str(work) for work, _d, _e in repositories)
    # Said whether or not the search found anything. An earlier version of this
    # fix surfaced the search failure only through the git.none row below, and
    # git.none is reached only when NOTHING was found -- so a truncated
    # workspace that held one visible checkout reported that checkout in full
    # and never said there might be more in the part nobody enumerated. That is
    # the alarming row never being generated, one level down, inside the fix
    # for it.
    _unseen(findings, search, (DURABLE,))
    if not repositories:
        if not notes:
            # ATTACK 3, closed structurally rather than by looking one directory
            # further down. "We enumerated the tree and there is none" is now a
            # row a reader can see, so silence stops being a legal output of this
            # function -- and the row can only be emitted from a traversal that
            # finished, so "there is no repository" and "we could not tell"
            # are different words instead of the same absence.
            _reassure(
                findings, search, "git.none", DURABLE, CONTAINED, str(ws),
                "The workspace tree was enumerated and holds no git repository, "
                "so there is nothing here that can publish work outside this "
                "machine.",
                "every entry of the traversal was examined for a .git entry and "
                "for a bare repository shape")
        return
    seen["git_examined"] = True
    bound = [str(ws)] + list(grants) + ([account_mount] if account_mount else [])
    remote_names = []
    budget = _GitBudget()
    ordered = sorted(repositories, key=lambda row: str(row[1]))
    if len(ordered) > GIT_REPO_BUDGET:
        findings.append(Finding(
            "git.too_many_repositories", DURABLE, UNKNOWN, UNOBSERVABLE, str(ws),
            "The workspace holds %d git repositories and this classification "
            "read the first %d. What the rest can publish was not established. "
            "A workspace that holds hundreds of repositories is itself worth a "
            "look." % (len(ordered), GIT_REPO_BUDGET),
            "sf_blast.GIT_REPO_BUDGET, which bounds how many times one "
            "classification runs git"))
        ordered = ordered[:GIT_REPO_BUDGET]
    seen["git_time_budget_seconds"] = GIT_TOTAL_TIMEOUT
    for work_tree, git_dir, external in ordered:
        if external:
            for dimension in (DURABLE, REACHABLE):
                findings.append(Finding(
                    "git.gitdir_external", dimension, UNKNOWN, UNOBSERVABLE,
                    str(git_dir),
                    "This checkout is a worktree or submodule: its real git "
                    "directory is at %s, outside the workspace. The checkpoint "
                    "snapshots the workspace tree, so commits and ref changes "
                    "made there are not covered by an Undo." % git_dir,
                    "sf_mcp.CheckpointEngine is workspace-scoped; the .git FILE "
                    "names a gitdir elsewhere"))
        reading, config = _git_config(git_dir, budget)
        # Reported on EVERY axis the configuration would have decided, not only
        # on the one whose reassuring row it suppressed. That is attack 5: an
        # unreadable config leaves durability, exfiltration, destruction and
        # reachability all unestablished, and saying so on one of them would
        # leave the other three reading as clean.
        if _unseen(findings, reading,
                   (DURABLE, EXFILTRATABLE, DESTRUCTIBLE, REACHABLE)):
            continue
        _config_origin_findings(findings, ws, config)
        conditional = sorted(key for key, _value, _origin in config
                             if key.lower().startswith("includeif."))
        if conditional:
            # git evaluates a conditional include against a REPOSITORY context,
            # and this reading names a FILE, so git may obey keys that are not in
            # what was read. What was read is still reported -- it is real -- but
            # it can no longer be called complete, so nothing reassuring may rest
            # on it. This is the same rule as attack 2, applied to the half of
            # include handling that --file cannot do.
            reading.failed(
                "git.config_conditional",
                "This repository's config carries conditional include(s) -- %s "
                "-- whose condition git evaluates against a repository context "
                "that this reading does not establish. Keys git would obey may "
                "therefore be missing from what was read. What WAS read is "
                "reported; it is not the whole configuration."
                % ", ".join(conditional))
            _unseen(findings, reading,
                    (DURABLE, EXFILTRATABLE, DESTRUCTIBLE, REACHABLE))
        remotes = _remotes(config)
        remote_names.extend(remotes)
        if not remotes:
            _reassure(
                findings, reading, "git.no_remote", DURABLE, CONTAINED,
                str(work_tree),
                "This git repository has no remote configured, so nothing it "
                "commits can be published from here.",
                "read with git's own config reader, which honours include.path, "
                "valueless keys and the legacy [remote.origin] spelling that the "
                "hand parser this replaced got wrong")
        for name, urls in sorted(remotes.items()):
            for label in ("url", "pushurl"):
                for url in urls[label]:
                    _remote_findings(findings, name, label, url, network, bound,
                                     reading)
        for key, (value, why) in sorted(_executing_config(config).items()):
            findings.append(Finding(
                "git.exec_config", DURABLE, BOUNDED, OBSERVED, key,
                "A git config key that makes git run something: %s = %s -- %s. "
                "If it is inside the workspace an Undo removes it, but it "
                "executes on this machine the next time anybody runs git here, "
                "which may be before anybody reviews." % (key, value, why),
                "read with git's own config reader; the leading-'!' rule is "
                "git's own marker for a shell command, so a key nobody put on a "
                "list is still caught"))
        hooks, hooks_reading = _hooks(git_dir)
        if _unseen(findings, hooks_reading, (DURABLE,)):
            continue
        if hooks:
            findings.append(Finding(
                "git.hooks", DURABLE, BOUNDED, OBSERVED, ", ".join(hooks),
                "Installed git hooks: %s. A hook is a program git runs on this "
                "machine on the person's behalf. An Undo removes it if the "
                "repository is inside the workspace, and it runs before anybody "
                "has to decide to run it." % ", ".join(hooks),
                "listed from the repository's hooks directory, excluding git's "
                "own .sample files"))
    seen["git_remotes"] = sorted(set(remote_names))


def _test_findings(findings, config, ws, evidence):
    """The validation command, judged for PREDICTABILITY, never for reach.

    THE RULE, and it is one rule so that it can be reasoned about: a test
    command runs inside the same ceiling as the provider turn, so it can never
    widen an axis the ceiling closed. What it can do is make an axis the ceiling
    OPENED unpredictable -- the approver is shown an argv, and what actually
    executes is a shell string this module will not parse, or a program the
    mission itself may have written.

    So a shell one-liner in an offline, read-only mission is reported as
    contained, with the reason, and a shell one-liner in a networked mission
    with a credential is reported as unknown on exactly the axes that mission
    already had open. The alternative -- flagging every arbitrary command --
    would flag every code mission, which is every mission that has a test
    command at all, and a warning that is always on is not a warning.

    `evidence` is every Reading this classification took. The CONTAINED branch
    below says "the ceiling opens nothing, so its unpredictability has nowhere
    to go", and that is a claim about the WHOLE of this classification, not
    about the test command -- so a classification with a reading that did not
    complete cannot make it. Mostly this changes nothing, because a failed
    reading already puts an UNKNOWN on one of the axes `opened` is computed
    from; it matters in the case where the only thing nobody could see was on
    REACHABLE, which `opened` does not look at.
    """
    test = list(config.get("test") or [])
    if not test:
        return
    reasons = []
    program = PurePosixPath(str(test[0])).name
    if program in SHELLS and any(arg in SHELL_COMMAND_FLAGS for arg in test[1:]):
        reasons.append("the command is a shell and a script string, so what runs "
                       "is not derivable from the argv a person approved")
    entry = _authorable_entry(test, ws)
    if entry:
        reasons.append("its entry point is %s, a workspace file this mission may "
                       "rewrite and that the validation guard does not protect "
                       "(the guard covers test files and test-runner configs)"
                       % entry)
    if not reasons:
        return
    detail = "The validation command %r is not predictable from what was "\
             "approved: %s." % (test, "; and ".join(reasons))
    # The axes this mission already has open, and only those. Recomputed from
    # the findings already gathered rather than from the ceiling a second time,
    # so this cannot disagree with the rest of the record.
    opened = {dimension for dimension in (DESTRUCTIBLE, EXFILTRATABLE, DURABLE)
              if any(f.dimension == dimension and f.level not in (NONE, CONTAINED)
                     for f in findings)}
    if not opened:
        _reassure(
            findings, evidence,
            "test.unpredictable", DESTRUCTIBLE, CONTAINED, str(test),
            detail + " It runs under the same ceiling as the provider turn, and "
            "that ceiling opens nothing: no route out, and nothing writable "
            "outside the workspace. So its unpredictability has nowhere to go.",
            "the validation run is launched into the same Firebreak posture as "
            "inference -- sf_missions.Executor.code() records "
            "network_effective=requested")
        return
    for dimension in sorted(opened):
        findings.append(Finding(
            "test.unpredictable", dimension, UNKNOWN, UNOBSERVABLE, str(test),
            detail + " It runs under the same ceiling as the provider turn, which "
            "leaves this axis open, so what it does with it was not established.",
            "the validation run is launched into the same Firebreak posture as "
            "inference -- sf_missions.Executor.code() records "
            "network_effective=requested, so validation is never stricter"))


def _authorable_entry(test, ws):
    """The workspace file that decides what this command actually runs, or None.

    Two shapes, because a test command has two ways of pointing at code the
    mission may have written:

      the driver shape   ["make", "test"] names no path. What runs is whatever
                         the Makefile says. Resolved through DRIVER_ENTRY_POINTS
                         and confirmed to exist -- `make` in a workspace with no
                         Makefile is a command that will fail, not a risk.

      the path shape     ["./build.sh"] or ["python", "scripts/check.py"] names
                         the file outright.

    In both, anything guards_validation() protects is skipped: naming a
    conftest.py or an npm package.json here would be a warning about a control
    that is already working, and those are the warnings that get a panel
    ignored.
    """
    program = PurePosixPath(str(test[0])).name if test else ""
    if program in GUARDED_DRIVERS:
        return None
    for candidate in DRIVER_ENTRY_POINTS.get(program, ()):
        if (Path(ws) / candidate).is_file():
            return candidate
    for arg in test[1:] if program in DRIVER_ENTRY_POINTS else test:
        if arg.startswith("-"):
            continue
        name = PurePosixPath(arg).name
        stem = PurePosixPath(name).stem.lower()
        if name in GUARDED_CONFIG_NAMES or stem in GUARDED_CONFIG_STEMS:
            continue
        relative = arg[2:] if arg.startswith("./") else arg
        if posixpath.isabs(relative):
            continue
        if (arg.startswith("./") or "/" in relative) and (Path(ws) / relative).is_file():
            return relative
    return None
