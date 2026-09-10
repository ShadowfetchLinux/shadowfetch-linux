#!/usr/bin/env python3
"""Rewrite every anchored copy of the release version -- all of them, or none.

WHAT THIS GUARANTEES, EXACTLY
-----------------------------
Not atomicity across files.  POSIX has no multi-file commit and this tool does
not pretend to one.  What it does guarantee, in decreasing strength:

  * Nothing is written until EVERY new file body has been computed and EVERY
    anchor has been confirmed to match exactly once, and a second pass has
    confirmed that the gate's own pattern now reads the new version out of the
    computed body.  A moved anchor, a missing file, a file that is not UTF-8,
    a pattern that matches twice -- every one of those is found in the compute
    phase, and the tree is left UNCHANGED.
  * Each file is replaced through a temporary in the same directory: written,
    fsynced, chmod'ed back to the original mode, os.replace()d, and the
    directory fsynced afterwards.  A reader sees the whole old file or the
    whole new one.  A crash cannot leave the truncated half-file that
    write_text() can.
  * If a replace fails partway through the sequence, the files already replaced
    are restored from the bodies captured in the compute phase, through that
    same temporary-and-rename path.  (ADR-0009 asks for precisely this:
    "validate all, then write, with a restore-on-failure backup".)  If the
    restore ITSELF fails, the error names every file left at the new version
    rather than swallowing it.

  * What is left, and cannot be removed at this layer: a SIGKILL or a power cut
    BETWEEN two os.replace() calls leaves some files stamped and some not.
    Nothing short of a filesystem transaction prevents that.  `git diff` and
    tools/drift_gate.py both show it.

The defect this shape replaces.  stamp() was nine sequential write_text()
calls.  Injecting a failure at write #5 of 9 left six of the gate's twelve
version sites reading 4.1.0 and six reading 4.0.0 -- a tree in a state no
release was ever in, with no backup and no revert.  Every injection point is
pinned now by tools/tests/test_stamp_version.py.

WHICH SITES
-----------
The list is tools/drift_gate.py's VERSION_SITES, IMPORTED rather than retyped.
The gate is what decides whether a stamp was complete, so a stamper carrying
its own copy of the list is a second authority that can only drift from the
first -- and it did: the previous stamper wrote nine of the gate's twelve
sites and left the grok-bot --version string, the drkonqi-pickup CMake project
version and the README fact table at the old version, which is exactly the
drift the gate then reported.  check_version's own remedy text admitted it
("the Makefile, README, the CMake project version and the acceptance manifest
are hand-maintained").

Plus one site the gate checks in check_release_data instead: the Makefile's
`VERSION ?=`.  It is the same fact and it is stampable, so it is stamped.

Anchor-driven, never search-and-replace.  The old version string legitimately
survives a bump in several of these files: shadowfetch-grok-bot carries
VERSION = "0.43.0" (upstream Grok Bot's version, not ours), and sf_missions.py
says "4.0.0" twelve times in comments describing the on-disk format 4.0.0
wrote -- those must keep saying 4.0.0.  Only the byte range captured by the
gate's own group(1) is replaced.

REMOVED, and why.  The previous stamper also rewrote LICENSES.md and
SOURCES.md through `(Shadowfetch Linux\\s+)[0-9.]+`.  Neither file has carried
a version since its heading became "# Shadowfetch Linux - Licensing", so that
re.sub() matched nothing and rewrote each file with its own bytes; re.sub
reports no error for zero matches, so two of the nine writes were silent
no-ops and the tool still printed success.  They are not version sites.  If one
gains a version string it belongs in the gate's VERSION_SITES first, and this
tool will pick it up from there.

SITES THIS TOOL MUST NOT WRITE
------------------------------
Two of the facts the gate compares are not this tool's to invent, so it
verifies them, names them, and exits non-zero rather than reporting a success
it cannot support:

  * qa/<version>/acceptance.json -- the acceptance manifest.  It records
    MEASURED facts (iso_sha256, iso_size_bytes, source_commit, per-case
    evidence hashes).  A stamper that created one, or that rewrote an older
    release's manifest to name the new version, would be attaching the
    previous ISO's measurements to this release.  It is produced by the
    acceptance run.
  * tools/release/versions/<version>.toml -- the release data the gate reads as
    the authority for what the version IS.  It carries the edition, subtitle,
    codename, package lists and the signing fingerprint: release decisions, not
    a version string.  Until it names the stamped version, drift_gate compares
    every site against the older release and reports drift at all of them.

Exit codes: 0 every site (including those two) agrees with the stamped version;
1 the anchored sites were stamped but the sites above still disagree, each one
named; 2 refused, nothing written.  --outstanding-ok turns 1 into 0 for a
caller that legitimately runs before the acceptance run exists (`make packages`
depends on stamp-version); it prints the same report either way.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]

GATE_REL = "tools/drift_gate.py"
VERSIONS_REL = "tools/release/versions"

# Sites the drift gate checks under check_release_data rather than
# check_version.  Same fact, same file shape, so the same machinery stamps it.
EXTRA_SITES: tuple[tuple[str, str, str], ...] = (
    ("Makefile", r"(?m)^VERSION\s*\?=\s*(\S+)\s*$", "Makefile VERSION ?="),
)

SEMVER = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")


class StampError(ValueError):
    """A refusal.  Raised only where the tree has not been modified, or where
    it has been modified and restored -- the message says which.

    Subclasses ValueError because that is what stamp() used to raise for a
    malformed version, and a caller written against that contract should keep
    catching this one.
    """


class StampResult:
    __slots__ = ("version", "sites", "written", "unchanged", "before", "outstanding")

    def __init__(self, version, sites, written, unchanged, before, outstanding):
        self.version = version
        self.sites = sites            # [(rel, pattern, label)] actually stamped
        self.written = written        # [rel] whose bytes changed on disk
        self.unchanged = unchanged    # [rel] already correct, not touched
        self.before = before          # {(rel, label): old value}
        self.outstanding = outstanding  # [(site, why)] not this tool's to write


# --------------------------------------------------------------------------- #
# the site list, taken from the gate rather than restated
# --------------------------------------------------------------------------- #

def gate_version_sites(root: Path) -> list[tuple[str, str, str]]:
    """tools/drift_gate.py's VERSION_SITES, loaded from the tree being stamped.

    Loaded by path, under a private module name, with sys.path restored:
    drift_gate inserts its own tools/ directory on import, and a stamper that
    left that behind would change what a later `import` in the same process
    resolves to.
    """
    path = root / GATE_REL
    if not path.is_file():
        raise StampError(
            f"{GATE_REL} is missing from {root}; it holds the list of sites "
            "this tool stamps, and inventing a second list is the defect this "
            "import exists to prevent")
    name = "_drift_gate_version_sites"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    saved_path, saved_module = list(sys.path), sys.modules.get(name)
    saved_bytecode = sys.dont_write_bytecode
    # Reading a list of tuples is not a reason to leave __pycache__ entries in
    # the tree being stamped: this tool's whole claim is that it changes the
    # files it says it changes and nothing else.
    sys.dont_write_bytecode = True
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as exc:  # noqa: BLE001 - report it as a refusal, not a traceback
        raise StampError(f"{GATE_REL} could not be imported: "
                         f"{type(exc).__name__}: {exc}") from exc
    finally:
        sys.dont_write_bytecode = saved_bytecode
        sys.path[:] = saved_path
        if saved_module is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = saved_module
    sites = getattr(module, "VERSION_SITES", None)
    if not sites:
        raise StampError(f"{GATE_REL} defines no VERSION_SITES")
    return [tuple(site) for site in sites]


# --------------------------------------------------------------------------- #
# compute phase: every body, every anchor, before any write
# --------------------------------------------------------------------------- #

def plan(version: str, root: Path) -> tuple[list, dict, dict, dict]:
    """Compute the new body of every site file.  Writes nothing, ever."""
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise StampError(f"version must be MAJOR.MINOR.PATCH, not {version!r}")

    sites = gate_version_sites(root) + list(EXTRA_SITES)
    originals: dict[str, bytes] = {}
    bodies: dict[str, str] = {}
    before: dict[tuple[str, str], str] = {}

    for rel, pattern, label in sites:
        path = root / rel
        if rel not in bodies:
            try:
                raw = path.read_bytes()
            except OSError as exc:
                raise StampError(f"{rel}: {label}: unreadable ({exc})") from exc
            try:
                # Strict, and via bytes: drift_gate reads with errors="replace"
                # because it only looks.  Decoding a byte it cannot represent and
                # then writing the result back would silently corrupt the file,
                # and read_text()'s universal-newline translation would rewrite
                # every CRLF in a file this tool was only asked to renumber.
                bodies[rel] = raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise StampError(
                    f"{rel}: not valid UTF-8 ({exc}); refusing to rewrite it") from exc
            originals[rel] = raw

        compiled = re.compile(pattern)
        if compiled.groups < 1:
            raise StampError(
                f"{rel}: {label}: the gate's pattern {pattern!r} has no capture "
                "group, so there is no byte range to replace")
        matches = list(compiled.finditer(bodies[rel]))
        if len(matches) != 1:
            raise StampError(
                f"{rel}: {label}: the anchor {pattern!r} matched {len(matches)} "
                f"time(s), expected exactly once. Two matches means the stamper "
                f"would rewrite one of them and leave the other; none means the "
                f"anchor moved. Fix the file, or fix VERSION_SITES in "
                f"{GATE_REL}. Nothing has been written.")
        match = matches[0]
        before[(rel, label)] = match.group(1)
        bodies[rel] = bodies[rel][:match.start(1)] + version + bodies[rel][match.end(1):]

    # Second pass, on the computed bodies: read every site back with the gate's
    # own pattern and require it to yield the new version exactly once. This is
    # what makes "the stamp succeeded" and "the gate is clean" the same claim --
    # a rewrite that broke a neighbouring anchor is caught here, still with
    # nothing written.
    for rel, pattern, label in sites:
        found = [m.group(1) for m in re.finditer(pattern, bodies[rel])]
        if found != [version]:
            raise StampError(
                f"{rel}: {label}: after rewriting, the gate's own pattern reads "
                f"{found!r} rather than exactly [{version!r}]. Nothing written.")
    return sites, originals, bodies, before


# --------------------------------------------------------------------------- #
# write phase: temporary + fsync + os.replace, with restore on failure
# --------------------------------------------------------------------------- #

def _replace(path: Path, data: bytes) -> None:
    """Replace path's contents with data, whole or not at all."""
    directory = path.parent
    status = path.stat()
    handle_fd, temporary = tempfile.mkstemp(dir=str(directory), prefix=".stamp-",
                                            suffix=".tmp")
    try:
        with os.fdopen(handle_fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        # mkstemp creates 0600. shadowfetch-element, shadowfetch-grok-bot and
        # shadowfetch-firebreak are 0755/0775 executables that get packaged as
        # they sit here, so a stamp that dropped the mode would ship a payload
        # /usr/bin script nobody can run.
        os.chmod(temporary, status.st_mode & 0o7777)
        try:
            os.chown(temporary, status.st_uid, status.st_gid)
        except (OSError, AttributeError):
            # Best effort: only reachable when the stamp runs as a user who
            # does not own the tree, where in-place writing would have failed
            # outright.  Never a reason to abandon a correct rewrite.
            pass
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise
    try:
        directory_fd = os.open(str(directory), os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException as exc:
        # The rename ALREADY happened, so this file holds the NEW bytes even
        # though _replace is about to raise. Without this flag the caller left
        # it out of the rollback set -- it is added to `written` only on a
        # clean return -- and then reported "the tree is as it was found",
        # which was false for exactly the file that failed.
        exc.shadowfetch_file_was_replaced = True
        raise


def stamp(version: str, root: Path | str | None = None) -> StampResult:
    """Stamp every anchored site, or leave the tree as it was found."""
    root = Path(root) if root is not None else ROOT
    sites, originals, bodies, before = plan(version, root)

    written: list[str] = []
    unchanged: list[str] = []
    for rel, body in bodies.items():
        data = body.encode("utf-8")
        if data == originals[rel]:
            # Already correct. Not rewriting it keeps mtimes -- and therefore
            # make's rebuild decisions -- honest, and makes re-stamping the
            # current version a no-op rather than a tree full of touched files.
            unchanged.append(rel)
            continue
        try:
            _replace(root / rel, data)
        except BaseException as exc:
            if getattr(exc, "shadowfetch_file_was_replaced", False):
                # os.replace succeeded and only the durability step failed:
                # roll this one back with the rest rather than reporting a
                # clean tree over a file that already reads the new version.
                written.append(rel)
            restored, failed = _restore(root, written, originals)
            message = (f"{rel}: write failed ({type(exc).__name__}: {exc}); "
                       f"restored {len(restored)} file(s) already written")
            if failed:
                message += (". THE RESTORE ALSO FAILED for: " + "; ".join(failed) +
                            ". The tree is MIXED: those files read the new version "
                            "and the rest read the old one. Fix them by hand or "
                            "with git before building anything.")
            else:
                message += "; the tree is as it was found."
            if isinstance(exc, Exception):
                raise StampError(message) from exc
            # Ctrl-C, or SystemExit: stop the way the caller asked, but do not
            # let the report of what was rolled back disappear with it.
            print(f"stamp_version: {message}", file=sys.stderr)
            raise
        written.append(rel)

    return StampResult(version, sites, written, unchanged, before,
                       outstanding(version, root))


def _restore(root: Path, written: list[str], originals: dict[str, bytes]):
    """Put back the files already replaced.  Returns (restored, failed)."""
    restored: list[str] = []
    failed: list[str] = []
    for rel in reversed(written):
        try:
            _replace(root / rel, originals[rel])
            restored.append(rel)
        except OSError as exc:
            failed.append(f"{rel} ({exc})")
    return restored, failed


# --------------------------------------------------------------------------- #
# sites this tool must not write: verified, named, never invented
# --------------------------------------------------------------------------- #

def outstanding(version: str, root: Path) -> list[tuple[str, str]]:
    """Facts the gate compares that this tool refuses to author.  [(site, why)]"""
    out: list[tuple[str, str]] = []

    directory = root / VERSIONS_REL
    live: list[tuple[Path, str]] = []
    unreadable: list[str] = []
    for path in sorted(directory.glob("*.toml")):
        try:
            with path.open("rb") as handle:
                data = tomllib.load(handle)
        except (OSError, tomllib.TOMLDecodeError) as exc:
            unreadable.append(f"{path.name} ({exc})")
            continue
        release = data.get("release", {})
        if not release.get("historical", False):
            live.append((path, str(release.get("version"))))
    reason = (
        "It carries the edition, subtitle, codename, package lists and the "
        "signing fingerprint -- release decisions, not a version string. "
        f"{GATE_REL} reads it as the authority for what the release IS, so "
        f"until it names {version} the gate reports drift at every site above.")
    if unreadable:
        out.append((f"{VERSIONS_REL}/*.toml",
                    "unreadable release data: " + "; ".join(unreadable)))
    elif len(live) != 1:
        # The site is the SET, not one file: with two live files the question
        # is which release this tree builds, and naming one of them would be
        # answering it.
        out.append((f"{VERSIONS_REL}/*.toml",
                    f"{len(live)} non-historical release data file(s) "
                    f"({', '.join(p.name for p, _ in live) or 'none'}); the gate "
                    f"loads exactly one. " + reason))
    elif live[0][1] != version:
        out.append((str(live[0][0].relative_to(root)),
                    f"the live release data names {live[0][1]}, not {version}. "
                    + reason))

    manifest_rel = f"qa/{version}/acceptance.json"
    manifest = root / manifest_rel
    measured = ("It records MEASURED facts -- iso_sha256, iso_size_bytes, "
                "source_commit and per-case evidence hashes -- which a stamper "
                "cannot produce and must not copy from the previous release. "
                "The acceptance run writes it.")
    if not manifest.exists():
        out.append((manifest_rel, "does not exist. " + measured))
    else:
        try:
            data = json.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            out.append((manifest_rel, f"unreadable ({exc}). " + measured))
        else:
            says = data.get("release", {}).get("version")
            iso = data.get("artifact", {}).get("iso_path")
            want_iso = f"shadowfetch-{version}-amd64.iso"
            if says != version:
                out.append((manifest_rel,
                            f"release.version is {says!r}, not {version!r}. " + measured))
            if iso != want_iso:
                out.append((manifest_rel,
                            f"artifact.iso_path is {iso!r}, not {want_iso!r}. " + measured))
    return out


# --------------------------------------------------------------------------- #
# report
# --------------------------------------------------------------------------- #

def report(result: StampResult) -> list[str]:
    lines = []
    by_file: dict[str, list[str]] = {}
    for rel, _pattern, label in result.sites:
        by_file.setdefault(rel, []).append(label)
    for rel, labels in by_file.items():
        was = sorted({result.before[(rel, label)] for label in labels})
        action = "wrote    " if rel in result.written else "unchanged"
        lines.append(f"  {action} {rel}")
        lines.append(f"            {', '.join(labels)}  ({', '.join(was)} -> "
                     f"{result.version})")
    lines.append(f"  {len(result.sites)} anchored site(s) in {len(by_file)} file(s) "
                 f"now read {result.version}: {len(result.written)} file(s) written, "
                 f"{len(result.unchanged)} already correct.")
    if result.outstanding:
        lines.append("")
        lines.append("NOT STAMPED -- this tool must not write these:")
        for site, why in result.outstanding:
            lines.append(f"  {site}")
            lines.append(f"      {why}")
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("version", help="the release version, MAJOR.MINOR.PATCH")
    parser.add_argument("--root", default=None,
                        help="tree to stamp (default: this file's repository)")
    parser.add_argument("--outstanding-ok", action="store_true",
                        help="exit 0 even when the sites this tool must not "
                             "write still disagree; they are still listed")
    args = parser.parse_args(argv)

    try:
        result = stamp(args.version, args.root)
    except StampError as exc:
        print(f"stamp_version: REFUSED\n  {exc}", file=sys.stderr)
        return 2

    print(f"stamp_version: Shadowfetch Linux {result.version}")
    for line in report(result):
        print(line)
    if result.outstanding and not args.outstanding_ok:
        print("STAMP INCOMPLETE", file=sys.stderr)
        return 1
    if result.outstanding:
        print("STAMP INCOMPLETE (--outstanding-ok: reported, not enforced)")
        return 0
    print("STAMP COMPLETE")
    return 0


if __name__ == '__main__':
    sys.exit(main())
