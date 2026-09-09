"""The plugin contract for out-of-tree Control Center pages (W-32).

What W-32 (ARCHITECTURE_AUDIT.md:850) asks for:

    Explicit plugin contract for `fireproof_page.py` (`plugins/` dir,
    `PAGE_API`, `build_page(context)`); catch `BaseException`; declare the
    dependency

What the seam is today, verified rather than assumed.  `shadowfetch-fireproof`
writes a module named `fireproof_page.py` directly INTO
`shadowfetch-control-center`'s own Python package directory
(/usr/share/shadowfetch/control-center/sfcc/), and `software_page.py` imports
it by name.  ARCHITECTURE_AUDIT.md:189 records both halves of why that is a
seam and not an interface:

  * neither package declared the relationship.  The Control Center now
    Recommends shadowfetch-fireproof (debian/control), so half of that is
    fixed; shadowfetch-fireproof still declares nothing about the package
    whose directory it writes into.
  * `from sfcc.fireproof_page import ...` EXECUTES a 667-line application
    script inside the Control Center's process, and that script raises
    SystemExit at module scope.  SystemExit is not an Exception, so the
    `except Exception` that guarded the import could not catch it: a
    `--help`-shaped code path in another package's script took the whole
    window down.  It is `except BaseException` here, and a test in
    tests/test_page_registry.py fails if the script stops exiting at module
    scope without somebody deliberately relaxing the guard.

What this module adds.  A named contract with a version, one loader that
enforces it, and one place where a plugin failure is contained:

    PAGE_API      the integer a plugin declares it was written against.
                  A plugin that declares nothing, or a different number, is
                  REFUSED rather than loaded and hoped for.
    build_page(context) -> QWidget
                  the entry point.  It receives an sfcc.pages.PageContext and
                  returns a widget.  Nothing else is called on the module.
    PLUGIN_DIRS   /usr/share/shadowfetch/control-center/plugins, a directory
                  that is NOT the host's Python package, so a plugin can no
                  longer collide with, shadow or be mistaken for a first-party
                  module.

Honest status, because this distinction is the whole point of the finding:
the CONTRACT and its ENFORCEMENT are here and tested, including against a
plugin that exits at import.  ADOPTION is not: the one shipped plugin lives in
packages/shadowfetch-fireproof, which is outside this stage's file territory,
so `load_updates_page()` still accepts the legacy `sfcc.fireproof_page` shape
as a second, clearly-labelled path.  Do not read "the plugin contract exists"
as "the Fireproof page uses it".  The Stage P report names the exact change
that would move it.
"""

from __future__ import annotations

from dataclasses import dataclass
import importlib
import importlib.util
import os
from pathlib import Path
import sys

from sfcc.pages import PAGE_API, PageContext

# Where a first-party or third-party page plugin is installed. NOT the sfcc
# package directory: a plugin that can write into the host's own package can
# shadow any module in it.
PLUGIN_DIRS: tuple[str, ...] = (
    "/usr/share/shadowfetch/control-center/plugins",
)

# The legacy seam, kept working while shadowfetch-fireproof still uses it.
LEGACY_UPDATES_MODULE = "sfcc.fireproof_page"
LEGACY_UPDATES_CLASS = "FireproofPage"


@dataclass(frozen=True)
class LoadResult:
    """What happened to one plugin. `widget` is None unless it built."""

    name: str
    source: str
    widget: object = None
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.widget is not None


def _plugin_dirs() -> list[Path]:
    dirs = [Path(d) for d in PLUGIN_DIRS]
    # A source tree runs the same loader against the same layout.
    for parent in Path(__file__).resolve().parents:
        candidate = (parent / "data/usr/share/shadowfetch/control-center/plugins")
        if candidate.is_dir():
            dirs.append(candidate)
    return [d for d in dirs if d.is_dir()]


def _import_file(path: Path):
    """Import one plugin file under a private module name.

    The name is prefixed so a plugin can never be imported as, or shadow, an
    sfcc module -- `sfcc.theme` from a plugin directory would be a page
    replacing the host's palette and stylesheet.
    """
    name = "sfcc_plugin_" + path.stem
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"{path} is not an importable module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


def _check(module, path) -> None:
    declared = getattr(module, "PAGE_API", None)
    if declared is None:
        raise ValueError(
            f"{path} declares no PAGE_API. A page plugin must declare the "
            f"contract version it was written against (currently {PAGE_API}).")
    if declared != PAGE_API:
        raise ValueError(
            f"{path} declares PAGE_API {declared!r}; this Control Center "
            f"implements {PAGE_API}. Refusing to load it rather than calling "
            "an entry point that may have changed shape.")
    if not callable(getattr(module, "build_page", None)):
        raise ValueError(
            f"{path} has no build_page(context) entry point.")


def load_plugin(path: Path, context: PageContext) -> LoadResult:
    """Import one plugin file and build its page. Never raises.

    `except BaseException` is deliberate and is the finding.  This call
    executes another package's code inside the Control Center's process; a
    SystemExit, a KeyboardInterrupt reaching the wrong frame, or a
    RecursionError from that code is not this window's to die of.  The two
    exceptions that must still travel are re-raised below.
    """
    try:
        module = _import_file(path)
        _check(module, path)
        widget = module.build_page(context)
        if widget is None:
            raise ValueError("build_page(context) returned None")
        return LoadResult(path.stem, str(path), widget=widget)
    except (KeyboardInterrupt, MemoryError):
        # A person interrupting the process, and a machine that is out of
        # memory, are conditions the whole application must honour.
        raise
    except BaseException as error:  # noqa: BLE001 - see the docstring
        return LoadResult(path.stem, str(path),
                          error=f"{type(error).__name__}: {error}")


def discover(context: PageContext) -> list[LoadResult]:
    """Every plugin in the plugin directories, loaded or refused with a reason.

    Refusals are RETURNED, not swallowed: a page that did not load is a fact a
    person should be able to see, and a silent absence is the failure mode this
    contract exists to end.
    """
    results: list[LoadResult] = []
    for directory in _plugin_dirs():
        for path in sorted(directory.glob("*.py")):
            if path.name.startswith("_"):
                continue
            results.append(load_plugin(path, context))
    return results


def load_updates_page(context: PageContext) -> LoadResult:
    """The Updates page: a contract plugin if there is one, else the legacy seam.

    Order matters.  A plugin that declares the contract wins, so the migration
    is "ship a plugin file" and nothing here changes.  Only if none is present
    is the legacy `sfcc.fireproof_page` import attempted, under the same
    BaseException containment.
    """
    for result in discover(context):
        if result.ok and result.name in ("updates", "fireproof"):
            return result

    try:
        module = importlib.import_module(LEGACY_UPDATES_MODULE)
        widget = getattr(module, LEGACY_UPDATES_CLASS)()
        if widget is None:
            raise ValueError(f"{LEGACY_UPDATES_CLASS}() returned None")
        return LoadResult("fireproof", LEGACY_UPDATES_MODULE + " (legacy seam)",
                          widget=widget)
    except (KeyboardInterrupt, MemoryError):
        raise
    except BaseException as error:  # noqa: BLE001
        # ModuleNotFoundError is the ORDINARY case: shadowfetch-fireproof is a
        # Recommends, and the built-in updates card is what a system without it
        # is supposed to show.
        return LoadResult("fireproof", LEGACY_UPDATES_MODULE + " (legacy seam)",
                          error=f"{type(error).__name__}: {error}")


def legacy_plugin_installed() -> bool:
    """Is the legacy module physically present beside this one?

    Used only to tell "no plugin is installed" apart from "a plugin is
    installed and failed", which are different sentences on screen.
    """
    return os.path.isfile(os.path.join(os.path.dirname(__file__),
                                       "fireproof_page.py"))
