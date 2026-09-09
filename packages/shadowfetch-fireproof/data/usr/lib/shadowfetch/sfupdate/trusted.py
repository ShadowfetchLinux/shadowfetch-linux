"""Trusted executable resolution for the update domain.

PERMANENT INVARIANT. Any executable used to establish, verify, enforce or
attest a security fact is invoked through an explicit trusted ABSOLUTE path
and has a defined trust classification. No shutil.which(), no PATH lookup,
anywhere its output decides a question. Resolving the PROGRAM is not enough:
the child's PATH is pinned too, because a resolved shell script resolves its
own helpers through whatever PATH it inherits.

WHY THIS MODULE EXISTS AT ALL. fireproofd runs as root on the system bus and
decided every one of these facts from a bare-name subprocess:

  * `snapper ... list` decides WHICH SNAPSHOT NUMBER is offered as the
    rollback target. A forged snapper prints a row, Fireproof records it,
    and `fireproof rollback` hands that number to phoenix-restore - i.e. an
    attacker chooses which subvolume becomes the user's root.
  * `findmnt -o FSTYPE /` decides phoenix_available(), i.e. whether the
    product claims a rollback exists.
  * `dpkg --audit` and `apt-get -s -f install` decide the VERIFY verdict.
    A forged pair turns "restore-recommended" into "ok" on a machine that
    an update just broke - the audit-suppression shape, one layer down.
  * `dkms status` decides whether an NVIDIA module failure is reported;
    `needrestart` decides which services are restarted AS ROOT, so a
    forged NEEDRESTART-SVC line is a root-service-restart primitive.

The classification itself is NOT re-implemented here. phoenix.trusted owns
it (it is the same question - "can somebody other than root substitute this
program?"), and Stage U's job was to delete duplicate mechanisms, not add a
second copy of the one that guards subvolume deletion. shadowfetch-fireproof
already Depends on shadowfetch-phoenix, so the import is a declared seam.

What IS domain-specific and therefore lives here: the table of absolute
candidate paths, and the split between programs whose refusal must be fatal
to a security claim and programs whose refusal only costs a soft check.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

# Installed layout: /usr/lib/shadowfetch/sfupdate/trusted.py, with
# phoenix at /usr/lib/shadowfetch/phoenix/. Derived from this file's own
# path so it is true in the source tree as well - never from PYTHONPATH,
# which the caller controls.
_LIB = Path(__file__).resolve().parent.parent
if str(_LIB) not in sys.path:
    sys.path.insert(0, str(_LIB))

try:
    from phoenix.trusted import (  # noqa: E402
        SAFE_ENV,
        SAFE_PATH,
        ExecutableError,
        ExecutableTrust,
        classify,
    )
except ImportError as exc:  # pragma: no cover - packaging failure
    raise ImportError(
        "sfupdate.trusted requires phoenix.trusted (shadowfetch-phoenix). "
        "Refusing to fall back to a second classifier: two implementations "
        "of 'is this binary substitutable' is the defect, not the fix."
    ) from exc

__all__ = [
    "ExecutableError", "ExecutableTrust", "classify",
    "SAFE_PATH", "SAFE_ENV",
    "TRUSTED_PATHS", "SECURITY_CRITICAL", "UpdateExecutor", "EXECUTOR",
]


# Absolute candidate paths, in preference order. Both merged-/usr and split
# spellings are listed because a non-merged host really installs to /sbin;
# the CLASSIFICATION, never the spelling, grants trust, so listing an extra
# candidate cannot widen the trust boundary.
TRUSTED_PATHS: dict[str, tuple[str, ...]] = {
    # -- decides the rollback target and whether rollback exists at all ----
    "snapper": ("/usr/bin/snapper", "/usr/sbin/snapper",
                "/bin/snapper", "/sbin/snapper"),
    "findmnt": ("/usr/bin/findmnt", "/bin/findmnt",
                "/usr/sbin/findmnt", "/sbin/findmnt"),
    # -- decides the VERIFY verdict ---------------------------------------
    "dpkg": ("/usr/bin/dpkg", "/bin/dpkg"),
    "apt-get": ("/usr/bin/apt-get", "/bin/apt-get"),
    "dkms": ("/usr/bin/dkms", "/usr/sbin/dkms", "/bin/dkms", "/sbin/dkms"),
    "needrestart": ("/usr/sbin/needrestart", "/sbin/needrestart",
                    "/usr/bin/needrestart"),
    # -- restarts services as root, and reports unit state ----------------
    "systemctl": ("/usr/bin/systemctl", "/bin/systemctl"),
    # -- the NEWS gate text a human approves ------------------------------
    "apt-listchanges": ("/usr/bin/apt-listchanges", "/bin/apt-listchanges"),
    # -- soft checks: their refusal costs a warn, never a verdict ----------
    "ip": ("/usr/bin/ip", "/usr/sbin/ip", "/bin/ip", "/sbin/ip"),
    "getent": ("/usr/bin/getent", "/bin/getent"),
    "ldd": ("/usr/bin/ldd", "/bin/ldd"),
}


# Programs whose output decides a SECURITY claim: the rollback target, the
# existence of a rollback, the verify verdict, the NEWS text a human
# approves, or a root service restart. A refusal here must propagate as a
# refusal - never degrade to "warn" and never be answered from a fallback.
SECURITY_CRITICAL = frozenset({
    "snapper", "findmnt", "dpkg", "apt-get", "dkms", "needrestart",
    "systemctl", "apt-listchanges",
})


class UpdateExecutor:
    """Resolve and run the small set of programs an update genuinely needs.

    Resolution is cached per name so a path cannot be swapped between the
    check and the call within one update, and so the classification a
    report names is the one the run actually used.
    """

    def __init__(self, paths: dict[str, tuple[str, ...]] | None = None,
                 timeout: float = 300.0) -> None:
        self._paths = dict(TRUSTED_PATHS if paths is None else paths)
        self._timeout = timeout
        self._resolved: dict[str, tuple[str | None, ExecutableTrust]] = {}

    # -- resolution --------------------------------------------------------
    def trust(self, name: str) -> tuple[str | None, ExecutableTrust]:
        """(path, classification); path is None when nothing qualifies."""
        if name in self._resolved:
            return self._resolved[name]
        candidates = self._paths.get(name)
        if not candidates:
            raise ExecutableError(
                "%r is not in the update trusted-executable table" % name)
        best: tuple[str | None, ExecutableTrust] = (
            None, ExecutableTrust.ABSENT)
        for candidate in candidates:
            verdict = classify(candidate)
            if verdict is ExecutableTrust.DISTRO_MANAGED:
                best = (candidate, verdict)
                break
            if (verdict is ExecutableTrust.UNTRUSTED
                    and best[1] is ExecutableTrust.ABSENT):
                # Remembered only so a refusal can say WHY. Never used.
                best = (candidate, verdict)
        self._resolved[name] = best
        return best

    def resolve(self, name: str) -> str:
        path, verdict = self.trust(name)
        if verdict is not ExecutableTrust.DISTRO_MANAGED:
            raise ExecutableError(
                "no trusted %s: %s is %s"
                % (name, path or "not installed", verdict.value))
        assert path is not None
        return path

    def available(self, name: str) -> bool:
        """True only when a DISTRO_MANAGED path exists.

        This is the replacement for shutil.which(). An UNTRUSTED binary
        reports as unavailable on purpose: 'present but substitutable' must
        never open a code path that a trusted absence would have closed.
        """
        try:
            self.resolve(name)
        except ExecutableError:
            return False
        return True

    def explain(self, name: str) -> str:
        """Human-readable classification, for reports and refusals."""
        try:
            path, verdict = self.trust(name)
        except ExecutableError as exc:
            return str(exc)
        return "%s is %s" % (path or name, verdict.value)

    # -- running -----------------------------------------------------------
    def run(self, name: str, *args: str, timeout: float | None = None):
        """Run a trusted program. Raises ExecutableError if none qualifies.

        The child gets SAFE_ENV's fixed PATH plus C locale: several callers
        parse the output (apt's counts line, needrestart's NEEDRESTART-*
        keys, snapper's CSV) and a translated message must never flip a
        check, while an inherited PATH would let a resolved shell script
        reintroduce the defect one level down.
        """
        argv = [self.resolve(name), *args]
        env = dict(os.environ)
        env.update(SAFE_ENV)
        env["LANGUAGE"] = "C"
        try:
            proc = subprocess.run(
                argv, capture_output=True, text=True,
                timeout=self._timeout if timeout is None else timeout,
                env=env, check=False)
        except subprocess.TimeoutExpired:
            return 124, "", "timeout"
        except OSError as exc:
            return 127, "", str(exc)
        return proc.returncode, proc.stdout, proc.stderr


#: Process-wide executor. One cache per process is deliberate: see the
#: class docstring on swap-between-check-and-call.
EXECUTOR = UpdateExecutor()
