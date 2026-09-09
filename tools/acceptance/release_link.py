#!/usr/bin/env python3
"""The single link from this harness to the release gate implementation.

Everything version-shaped or release-shaped -- which version is live, where the
acceptance manifest lives, what counts as usable evidence, how a program becomes
trusted -- is owned by tools/release/. This module imports that code rather than
restating it.

That is not tidiness. tools/ previously held six copies each of source_gate,
package_gate, iso_gate and verify_acceptance, and the evidence-entropy floor and
waiver contract existed in exactly one of them, so a "pass" recorded against an
archived copy proved nothing. A VM harness with its own private copy of the
evidence floors would have recreated that split immediately.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
from types import ModuleType

ROOT = Path(__file__).resolve().parents[2]
RELEASE_DIR = ROOT / "tools" / "release"


class ReleaseToolingError(RuntimeError):
    pass


def _load(name: str, path: Path) -> ModuleType:
    if name in sys.modules:
        return sys.modules[name]
    if not path.is_file():
        raise ReleaseToolingError(f"release tooling is missing: {path}")
    # tools/release/acceptance.py does a plain `import gate`, so its own
    # directory has to be importable. It is inserted rather than appended
    # because gate.py puts tools/ on the path itself, and tools/ contains a
    # DIFFERENT module named acceptance (this package).
    if str(RELEASE_DIR) not in sys.path:
        sys.path.insert(0, str(RELEASE_DIR))
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ReleaseToolingError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def gate() -> ModuleType:
    """tools/release/gate.py: trusted program resolution and version data."""
    return _load("sf_release_gate", RELEASE_DIR / "gate.py")


def recorder() -> ModuleType:
    """tools/release/acceptance.py: the release acceptance manifest recorder."""
    return _load("sf_release_acceptance", RELEASE_DIR / "acceptance.py")


def recorder_path() -> Path:
    return RELEASE_DIR / "acceptance.py"


def load_release(version: str | None = None):
    """Resolve which release is under test. Two candidates is an error."""
    return gate().load_release(version)
