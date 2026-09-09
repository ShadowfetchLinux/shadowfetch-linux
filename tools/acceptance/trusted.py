#!/usr/bin/env python3
"""Trusted executable resolution for the VM acceptance harness.

PERMANENT INVARIANT. Any executable used to establish, verify, enforce or
attest a security fact must be invoked through an explicit trusted ABSOLUTE
path and must carry a defined trust classification. No shutil.which(), no PATH
lookup, anywhere its output decides a security question. This was a real
CRITICAL defect elsewhere in the tree: journalctl resolved through a
user-writable PATH could forge a clean audit.

Resolution is DELEGATED to tools/release/gate.py's ProgramResolver, which is
the release's one implementation of that invariant: it searches only root-owned
system directories, re-checks the file and every parent directory on every
resolution, follows symlinks and checks each hop, and accepts a program outside
those directories only against a recorded SHA-256 pin that is re-verified
immediately before each invocation.

Restating any of that here would give the release two answers to "is this
binary trusted", which is the drift that put the evidence floors in one of six
copies of the acceptance verifier.

What this module adds is the one classification a release gate has no reason to
model: GUEST_SUBJECT. A command executed inside the machine under test is the
subject speaking about itself. Its output is EVIDENCE -- captured, hashed and
quoted -- and never a trusted attestation. Guest-side paths are still spelled
absolutely (/bin/sh, /usr/libexec/phoenix-restore) so the subject cannot choose
what runs, but no amount of absoluteness promotes a guest's word to proof.
"""

from __future__ import annotations

from pathlib import Path
import subprocess

from . import release_link

# Trust classifications used in this harness's receipts.
GUEST_SUBJECT = "guest-subject"


def _gate():
    return release_link.gate()


class TrustError(RuntimeError):
    """A binary that must be trusted is missing, wrong, or hijackable."""


# Every host program this harness runs, with what its output is allowed to
# decide. Both QEMU programs are ROLE_SECURITY deliberately: the hypervisor
# hosts the machine every observation is made against, so a substituted
# qemu-system-x86_64 could forge an entire acceptance run. python3 runs the
# release recorder that writes the acceptance manifest.
def _requirements() -> tuple[tuple[str, str], ...]:
    gate = _gate()
    return (
        ("qemu-system-x86_64", gate.ROLE_SECURITY),
        ("qemu-img", gate.ROLE_SECURITY),
        ("python3", gate.ROLE_SECURITY),
    )


_ROLES: dict[str, str] = {}
_RESOLVER = None


def _resolver():
    global _RESOLVER
    if _RESOLVER is None:
        _RESOLVER = _gate().ProgramResolver()
        _ROLES.update(dict(_requirements()))
    return _RESOLVER


def classification(name: str) -> str:
    _resolver()
    try:
        return _ROLES[name]
    except KeyError:
        raise TrustError(f"no trust classification declared for {name!r}") from None


def program(name: str):
    """Return the gate's TrustedProgram record for a declared program."""
    role = classification(name)
    try:
        return _resolver().resolve(name, role)
    except Exception as error:  # gate raises UntrustedProgram
        raise TrustError(str(error)) from error


def resolve(name: str) -> Path:
    return program(name).path


def describe() -> list[dict[str, str]]:
    """The trust base, recorded in every receipt: which binary decided what."""
    rows = []
    for name, role in _requirements():
        row = {"name": name, "role": role}
        try:
            found = program(name)
        except TrustError as error:
            row.update({"path": "", "trust": "unresolved", "error": str(error)})
        else:
            row.update(
                {
                    "path": str(found.path),
                    "trust": found.trust,
                    "sha256": found.digest or "",
                }
            )
        rows.append(row)
    return rows


# A deliberately small, fixed environment for every child process. Inheriting
# the caller's PATH would reintroduce for the child exactly the defect this
# module exists to prevent for the parent.
SAFE_ENV = {
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    "LC_ALL": "C.UTF-8",
    "LANG": "C.UTF-8",
    "HOME": "/nonexistent",
}


def argv(name: str, arguments: list[str]) -> list[str]:
    """Absolute argv, with any digest pin re-verified immediately before use."""
    try:
        return program(name).argv(*arguments)
    except TrustError:
        raise
    except Exception as error:
        raise TrustError(str(error)) from error


def run(
    name: str,
    arguments: list[str],
    *,
    timeout: float = 300.0,
    check: bool = True,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a declared trusted program. Never a shell, never a PATH lookup."""
    env = dict(SAFE_ENV)
    if extra_env:
        env.update(extra_env)
    result = subprocess.run(  # noqa: S603 - argv[0] is a trusted absolute path
        argv(name, arguments),
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
        check=False,
    )
    if check and result.returncode != 0:
        raise TrustError(
            f"{name} exited {result.returncode}: "
            f"{(result.stderr or result.stdout).strip()[:2000]}"
        )
    return result
