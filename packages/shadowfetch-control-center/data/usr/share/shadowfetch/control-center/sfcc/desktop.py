"""The shared desktop library: one implementation of every desktop FACT.

W-30 (ARCHITECTURE_AUDIT.md:848) asks for a shared desktop library carrying
`catalog`, `hwscan`, `net`, `launch` and `bundle_install_argv`, imported by
both `sfcc` and Welcome, because those five are implemented twice in two
divergent shapes.  tools/drift_gate.py detects the divergence today and
reports it BLOCKED:

    BLOCKED [desktop-helpers] sfcc/busutil.py + shadowfetch-welcome
      load_catalog(), the hwscan freshness rule and the five helper paths are
      still implemented twice, in two divergent shapes ...

This module is the sfcc half, and only the sfcc half.  Welcome is a different
package and outside this stage's file territory, so W-30 is HALF done: there
is now ONE implementation inside the Control Center, written so Welcome can
adopt it verbatim, and the second copy still exists in
packages/shadowfetch-welcome/src/shadowfetch-welcome.  See the Stage P report
for the exact three-line change that finishes it.  Until that lands, do not
describe W-30 as complete.

Two properties this module has that the code it replaces did not:

1.  It imports no Qt.  A fact about the machine is not a widget, Welcome does
    not use PyQt in the same way, and a helper that cannot be imported without
    a display server cannot be shared, tested cheaply, or reused by a CLI.

2.  Every program it executes is named by an explicit absolute path from
    PROGRAMS below, resolved through `trusted_program()`, which walks a fixed
    tuple of system directories with os.access -- not shutil.which, and never
    the caller's PATH.  The permanent invariant is that an executable whose
    output establishes or attests a security fact is invoked through a trusted
    absolute path with a defined trust classification.  This mattered here:
    `system_summary()` printed "System check passed" from a bare `systemctl`
    argv, and `installed_map()` decided which packages a person is told they
    already have from a bare `dpkg-query` argv.  Both inherit the session's
    PATH, and both feed a sentence the reader takes as a statement of fact.
"""

from __future__ import annotations

import glob
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

# ---------------------------------------------------------------- programs --

# System directories only, in this order.  A user-writable directory must never
# be able to decide which binary the user is about to authenticate with a root
# password, so this tuple -- not $PATH -- is the whole search space.
TRUSTED_DIRS = ("/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin",
                "/sbin", "/bin")

# Kept as a string for the child environment.  A resolved program is not enough
# on its own: dpkg-deb was made to report "Package: totally-not-this-package"
# by a forged `tar` on the child's PATH, so the child's PATH is pinned too.
TRUSTED_PATH = ":".join(TRUSTED_DIRS)

# Programs whose OUTPUT this desktop turns into a statement about the machine,
# or whose EXECUTION asks the user for an administrator password.  Each is an
# absolute path with a trust classification:
#
#   system      shipped by the distribution into a root-owned system directory
#   shadowfetch shipped by a Shadowfetch package into a root-owned directory
#
# Nothing here is resolved through PATH, and nothing here has an environment
# override.  SHADOWFETCH_MISSIONS_COMMAND and GROK_BOT_COMMAND were exactly
# that and were removed (W-09).
PROGRAMS = {
    # Authenticates a privileged operation.  If this is not the real pkexec,
    # the user approves one thing and another thing runs.
    "pkexec": ("/usr/bin/pkexec", "system"),
    # Decides which packages the Software page tells a person they already have.
    "dpkg-query": ("/usr/bin/dpkg-query", "system"),
    # Decides the words "System check passed" in the window header.
    "systemctl": ("/usr/bin/systemctl", "system"),
    "xdg-open": ("/usr/bin/xdg-open", "system"),
    "konsole": ("/usr/bin/konsole", "system"),
    "x-terminal-emulator": ("/usr/bin/x-terminal-emulator", "system"),
    "shadowfetch-hwscan": ("/usr/libexec/shadowfetch-hwscan", "shadowfetch"),
    "shadowfetch-bundle-install": ("/usr/libexec/shadowfetch-bundle-install",
                                   "shadowfetch"),
    "shadowfetch-missions": ("/usr/bin/shadowfetch-missions", "shadowfetch"),
    "shadowfetch-grok-bot": ("/usr/bin/shadowfetch-grok-bot", "shadowfetch"),
    "shadowfetch-welcome": ("/usr/bin/shadowfetch-welcome", "shadowfetch"),
    "shadowfetch-agent-workspace": ("/usr/bin/shadowfetch-agent-workspace",
                                    "shadowfetch"),
    "shadowfetch-update": ("/usr/bin/shadowfetch-update", "shadowfetch"),
    # Signs the desktop in to a provider account. Which binary handles a
    # credential is the definition of a security-relevant program.
    "shadowfetch-mission-account": ("/usr/bin/shadowfetch-mission-account",
                                    "shadowfetch"),
    "shadowfetch-gpu": ("/usr/bin/shadowfetch-gpu", "shadowfetch"),
    "shadowfetch-health": ("/usr/bin/shadowfetch-health", "shadowfetch"),
    "shadowfetch-recovery": ("/usr/bin/shadowfetch-recovery", "shadowfetch"),
    "shadowfetch-passport": ("/usr/bin/shadowfetch-passport", "shadowfetch"),
    "fireproof": ("/usr/bin/fireproof", "shadowfetch"),
    "phoenix-restore": ("/usr/libexec/phoenix-restore", "shadowfetch"),
    "phoenix-apt-repair": ("/usr/libexec/phoenix-apt-repair", "shadowfetch"),
    "phoenix-apt-snapshot": ("/usr/libexec/phoenix-apt-snapshot", "shadowfetch"),
}

# Named constants for the paths pages refer to directly.  One spelling each.
PKEXEC = PROGRAMS["pkexec"][0]
DPKG_QUERY = PROGRAMS["dpkg-query"][0]
SYSTEMCTL = PROGRAMS["systemctl"][0]
HWSCAN_CLI = PROGRAMS["shadowfetch-hwscan"][0]
BUNDLE_INSTALL = PROGRAMS["shadowfetch-bundle-install"][0]
PHOENIX_RESTORE = PROGRAMS["phoenix-restore"][0]
PHOENIX_APT_REPAIR = PROGRAMS["phoenix-apt-repair"][0]
PHOENIX_APT_SNAPSHOT = PROGRAMS["phoenix-apt-snapshot"][0]

# ------------------------------------------------------------------- files --

HWSCAN_JSON = "/var/lib/shadowfetch/hwscan.json"
CATALOG_DIR = "/usr/share/shadowfetch/welcome/catalog"
PROFILE_DIR = "/usr/share/shadowfetch/ember/profiles"
OVERLAY_MARKER = "/run/phoenix-overlay"
SNAPPER_DEFAULTS = "/etc/default/snapper"
VERSION_FILE = "/usr/share/shadowfetch/version"


class UnknownProgram(KeyError):
    """A caller asked for a program this module does not classify."""


def program(name: str) -> tuple[str, str]:
    """(absolute path, trust classification) for a declared program.

    Raising on an undeclared name is the point: a call site that wants to run
    something has to add it here, where its path and its trust are written
    down, rather than passing a bare name that PATH will resolve.
    """
    try:
        return PROGRAMS[name]
    except KeyError:
        raise UnknownProgram(
            f"{name!r} is not a declared Control Center program. Add it to "
            "sfcc.desktop.PROGRAMS with its absolute path and trust class."
        ) from None


def trusted_program(name: str) -> str | None:
    """The installed absolute path for a declared program, or None.

    Deliberately not shutil.which and deliberately not $PATH.  The declared
    path is checked first; the fixed trusted directories are the only fallback,
    so a distribution that ships `pkexec` in /usr/local/bin still works and a
    user-writable directory still cannot answer.
    """
    declared, _trust = program(name)
    if os.path.isfile(declared) and os.access(declared, os.X_OK):
        return declared
    base = os.path.basename(declared)
    for directory in TRUSTED_DIRS:
        candidate = os.path.join(directory, base)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def installed_command(name: str) -> str | None:
    """Is some third-party command present in a system directory?

    Deliberately separate from `trusted_program`, and deliberately NOT for
    anything privileged.  This answers a COSMETIC question -- "3 of 5 tools in
    this bundle are installed", "is there a KDE settings module to open" --
    about names that come from the bundle catalog and cannot be enumerated in
    PROGRAMS.  A wrong answer here changes a count on screen.  A wrong answer
    from `trusted_program` changes which binary a person types their
    administrator password into, which is why that one refuses names it does
    not know.  Never route a privileged launch through this function.
    """
    if not name or "/" in name:
        return None
    for directory in TRUSTED_DIRS:
        candidate = os.path.join(directory, name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def trusted_env() -> dict:
    """The environment for a Control Center child: a fixed system PATH and no
    shell-startup or loader hooks."""
    env = dict(os.environ)
    env["PATH"] = TRUSTED_PATH
    for hook in ("BASH_ENV", "ENV", "SHELLOPTS", "LD_PRELOAD",
                 "LD_LIBRARY_PATH", "LD_AUDIT", "PYTHONPATH", "PYTHONSTARTUP"):
        env.pop(hook, None)
    return env


def _run(name: str, arguments: list[str], timeout: float):
    """Run a declared program, or return None when it is not installed."""
    path = trusted_program(name)
    if path is None:
        return None
    try:
        return subprocess.run([path, *arguments], capture_output=True, text=True,
                              timeout=timeout, check=False, env=trusted_env())
    except (OSError, subprocess.SubprocessError):
        return None


# ------------------------------------------------------------------ launch --

def start_detached(name: str, arguments: list[str] | None = None) -> bool:
    """Start a declared program detached.  False when it is not installed."""
    path = trusted_program(name)
    if path is None:
        return False
    try:
        subprocess.Popen([path, *(arguments or [])], env=trusted_env())
        return True
    except OSError:
        return False


def terminal_command(name: str, arguments: list[str] | None = None) -> bool:
    """Run a declared Control Center tool in a visible terminal.

    The shell is deliberately NOT a login shell.  `bash -lc` sources
    /etc/profile and then ~/.bash_profile or ~/.profile, every one of which the
    unprivileged user can write, and the tools started here go on to ask for an
    administrator password.  A non-login `sh -c` in a fixed system PATH with no
    BASH_ENV means the button runs the packaged tool.

    The command is built from an argv list, quoted for the shell -- it is never
    a caller-supplied string that the shell then re-parses.
    """
    path = trusted_program(name)
    if path is None:
        return False
    import shlex
    line = " ".join(shlex.quote(part) for part in [path, *(arguments or [])])
    wrapped = (f"{line}; rc=$?; echo; "
               "printf 'Finished (status %s). Press Enter to close...' \"$rc\"; "
               "read -r _; exit $rc")
    env = trusted_env()
    terminal = trusted_program("konsole") or trusted_program("x-terminal-emulator")
    try:
        if terminal:
            subprocess.Popen([terminal, "-e", "/bin/sh", "-c", wrapped], env=env)
        else:
            subprocess.Popen(["/bin/sh", "-c", wrapped], env=env)
        return True
    except OSError:
        return False


# ----------------------------------------------------------------- catalog --

def load_catalog(kinds: tuple[str, ...] | None = ("preset",)) -> list[dict]:
    """Bundle records from the root-owned catalog directory.

    One implementation of the shape both front-ends need: a file may hold one
    record or a JSON array of them (Welcome's copy did not accept the array
    form), unreadable files are skipped rather than fatal, and `kinds=None`
    means every kind.  Order is by filename so two readers list the same
    bundles in the same order.
    """
    entries: list[dict] = []
    for path in sorted(glob.glob(os.path.join(CATALOG_DIR, "*.json"))):
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        for record in (data if isinstance(data, list) else [data]):
            if not isinstance(record, dict):
                continue
            if kinds is None or record.get("kind") in kinds:
                entries.append(record)
    return entries


def catalog_by_id(kinds: tuple[str, ...] | None = ("preset",)) -> dict[str, dict]:
    """The same records keyed by id -- Welcome's shape, same source."""
    return {str(record["id"]): record for record in load_catalog(kinds)
            if record.get("id")}


def installed_map(packages: list[str]) -> dict[str, bool]:
    """One dpkg-query for a whole bundle; unknown packages count as absent.

    dpkg-query is named by absolute path (PROGRAMS above).  Its answer decides
    the sentence "N of M packages already on your system", which a person reads
    as a fact about their machine.
    """
    result = {p: False for p in packages}
    if not packages:
        return result
    out = _run("dpkg-query",
               ["-W", "-f", "${Package} ${db:Status-Status}\n", *packages],
               timeout=10)
    if out is None:
        return result
    for line in out.stdout.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0] in result:
            result[parts[0]] = parts[1] == "installed"
    return result


def bundle_install_argv(bundle_id: str) -> list[str] | None:
    """The privileged argv that installs one catalog bundle, or None.

    ONE spelling of this argv for the whole desktop.  Both front-ends offer the
    same button; the audit's opening finding is that "the correct argv existed
    in two places", and Welcome's copy still spells pkexec as a bare name that
    $PATH resolves.  Returning None when either half is missing is deliberate:
    a missing helper must never widen the grant into something more general.
    """
    if not bundle_id or "/" in bundle_id or bundle_id.startswith("-"):
        return None
    pkexec = trusted_program("pkexec")
    helper = trusted_program("shadowfetch-bundle-install")
    if pkexec is None or helper is None:
        return None
    return [pkexec, helper, "install", bundle_id]


def apt_snapshot_toggle_argv(enable: bool) -> list[str] | None:
    """The pkexec argv that flips DISABLE_APT_SNAPSHOT, or None.

    Stage V: there is no shell fallback.  A missing helper reports that the
    setting cannot be changed rather than authorising pkexec on a shell, which
    would be a generic root shell and not this operation.
    """
    pkexec = trusted_program("pkexec")
    helper = trusted_program("phoenix-apt-snapshot")
    if pkexec is None or helper is None:
        return None
    return [pkexec, helper, "enable" if enable else "disable"]


# ------------------------------------------------------------------ hwscan --

def boot_timestamp() -> float:
    try:
        uptime = float(Path("/proc/uptime").read_text().split()[0])
        return time.time() - uptime
    except (OSError, ValueError, IndexError):
        return 0.0


def hwscan_is_fresh(path: str = HWSCAN_JSON) -> bool:
    """The freshness rule, written once.  Both front-ends had their own."""
    try:
        return os.stat(path).st_mtime >= boot_timestamp()
    except OSError:
        return False


def load_hwscan(rescan: bool = False) -> dict | None:
    """The hardware fact file.

    The boot-time service writes /var/lib/shadowfetch/hwscan.json; if the file
    predates this boot (or a rescan is asked for) the unprivileged CLI runs
    instead.  A stale file is returned in preference to nothing because the
    page labels the scan timestamp -- staleness is visible, never silent.
    """
    if not rescan and hwscan_is_fresh():
        try:
            return json.loads(Path(HWSCAN_JSON).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
    out = _run("shadowfetch-hwscan", ["--json"], timeout=8)
    if out is not None and out.returncode == 0 and out.stdout.strip():
        try:
            return json.loads(out.stdout)
        except ValueError:
            pass
    try:
        return json.loads(Path(HWSCAN_JSON).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


# ------------------------------------------------------------------- units --

def unit_active(unit: str) -> bool:
    out = _run("systemctl", ["is-active", "--quiet", unit], timeout=5)
    return out is not None and out.returncode == 0


def user_unit_active(unit: str) -> bool:
    out = _run("systemctl", ["--user", "is-active", "--quiet", unit], timeout=5)
    return out is not None and out.returncode == 0


def failed_units() -> list[str] | None:
    """Failed system units, or None when systemctl could not answer.

    None and [] are different facts and the header says so: an empty list means
    nothing is failing, and None means nobody asked or nobody answered.
    """
    out = _run("systemctl", ["--failed", "--no-legend", "--plain"], timeout=3)
    if out is None or out.returncode:
        return None
    return out.stdout.strip().splitlines()


def sf_version() -> str:
    try:
        return Path(VERSION_FILE).read_text().strip()
    except OSError:
        return "unknown"


def system_summary() -> tuple[str, str]:
    """(state, detail) for the window header.

    "System check passed" is an assertion about the machine, so it is made only
    when the trusted systemctl actually answered.  When it did not, the header
    says the status is unavailable instead of quietly reporting good news.
    """
    try:
        usage = shutil.disk_usage("/")
        used = round((usage.used / usage.total) * 100)
    except OSError:
        return "Status unavailable", "Open Watch for a complete report"
    failed = failed_units()
    if failed is None:
        return "Status unavailable", f"disk {used}% used · open Watch for a report"
    if failed or used >= 90:
        return ("Needs attention",
                f"{len(failed)} failed system units · disk {used}% used")
    return ("System check passed",
            f"No failed system units · disk {used}% used")


# ------------------------------------------------------------- phoenix bits --

def root_fstype() -> str:
    try:
        for line in Path("/proc/mounts").read_text(encoding="utf-8").splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[1] == "/":
                return parts[2]
    except OSError:
        pass
    return "unknown"


def overlay_boot() -> bool:
    """True when this session is riding a read-only Phoenix Point via the
    grub-btrfs overlay hook."""
    if os.path.exists(OVERLAY_MARKER):
        return True
    return root_fstype() == "overlay"


def overlay_point() -> int | None:
    """The snapshot number this overlay session was booted from."""
    try:
        text = Path(OVERLAY_MARKER).read_text(encoding="utf-8").strip()
        for token in text.replace("=", " ").split():
            if token.isdigit():
                return int(token)
    except OSError:
        pass
    try:
        cmdline = Path("/proc/cmdline").read_text(encoding="utf-8")
    except OSError:
        return None
    import re
    match = re.search(r"@snapshots/(\d+)/snapshot", cmdline)
    return int(match.group(1)) if match else None


def apt_snapshots_enabled() -> bool:
    """True unless /etc/default/snapper carries DISABLE_APT_SNAPSHOT=yes."""
    try:
        for line in Path(SNAPPER_DEFAULTS).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line.startswith("DISABLE_APT_SNAPSHOT="):
                value = line.split("=", 1)[1].strip().strip('"').strip("'").lower()
                return value not in ("yes", "true", "1")
    except OSError:
        pass
    return True


def load_ember_profiles() -> list[dict]:
    """The root-owned Ember profile cards (key=value lines)."""
    profiles = []
    for path in sorted(glob.glob(os.path.join(PROFILE_DIR, "*.conf"))):
        entry: dict = {}
        try:
            for line in Path(path).read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                entry[key.strip()] = value.strip()
        except OSError:
            continue
        if entry.get("id") and entry.get("name"):
            profiles.append(entry)
    return profiles


def rfkill_devices() -> list[dict]:
    """Bluetooth/Wi-Fi kill-switch state straight from /sys/class/rfkill."""
    out = []
    for entry in sorted(glob.glob("/sys/class/rfkill/rfkill*")):
        try:
            rtype = Path(entry, "type").read_text().strip()
            name = Path(entry, "name").read_text().strip()
            soft = Path(entry, "soft").read_text().strip() == "1"
            hard = Path(entry, "hard").read_text().strip() == "1"
        except OSError:
            continue
        out.append({"type": rtype, "name": name, "soft": soft, "hard": hard})
    return out
