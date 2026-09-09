"""sfcc.desktop IS the shared desktop library.  It is not a second copy of it.

W-30's shared library moved to the package both desktop front-ends depend on:

    /usr/lib/shadowfetch/desktop/sf_desktop.py   (shadowfetch-defaults)

This file executes that file -- by path, never by module name -- and then
replaces itself with it in sys.modules.
`import sfcc.desktop`, `from sfcc import desktop` and busutil's re-exported
`busutil.PKEXEC` therefore all name objects inside that ONE module, and there
is no second binding anywhere that can drift from it.

A re-export list -- `from sf_desktop import PKEXEC, load_catalog, ...` -- is
the obvious shape here and is the wrong one.  It creates a second set of names
that has to be kept in step by hand, and a name added to the library and
forgotten here is an AttributeError nobody sees until a button is clicked.
That is not hypothetical: while Stage P was being written, four pages called
`busutil.desktop.SYSTEMCTL` after busutil stopped importing the module under
that name.  Every page still constructed, every test still passed, and Ignite's
start button would have raised on the first click.  Aliasing the module rather
than copying its names removes that whole failure mode from this seam.

The search order -- installed path first, then the sibling source tree -- is
the one sfcc/mission_client.py already uses to borrow the mission engine's
modules, so the tests run against a checkout with nothing installed.
"""
import importlib.util
import sys
from pathlib import Path

MODULE = "sf_desktop.py"
MODULE_NAME = "sf_desktop"
INSTALLED_DIR = Path("/usr/lib/shadowfetch/desktop")
SOURCE_DIR = "packages/shadowfetch-defaults/data/usr/lib/shadowfetch/desktop"


def _is_that_file(candidate, path):
    """True when a module's __file__ is the file at `path`."""
    if not candidate:
        return False
    try:
        return Path(candidate).resolve() == path.resolve()
    except OSError:
        return False


def _exec_file(path):
    """Execute the library AT `path`, and return the module.

    ATTACK B, and the reason this is not `import sf_desktop`.  This loader used
    to check that <dir>/sf_desktop.py existed, put <dir> on sys.path, and then
    run `import sf_desktop` -- and `import` consults sys.modules BEFORE
    sys.path, so a module already registered under that name was handed back
    and the existence check performed one line earlier decided nothing.  A
    planted module was accepted with `sfcc.desktop.__file__ = /tmp/evil.py`,
    `PKEXEC` back to the bare word "pkexec", and the bundle-install argv
    resolved through $PATH again.

    That needs code execution inside the Control Center process already, so it
    is defence in depth rather than a privilege boundary.  It is fixed anyway
    for two reasons: it is the PATH-shadowing shape this program has been
    bitten by before, and the module docstring above rests its whole safety
    case on this file BEING the library -- a loader that can be handed a
    different module makes that sentence false.

    importlib.util.spec_from_file_location never consults sys.modules.  The
    package's own test helper has always loaded the library this way; the
    shipped loader simply did not.
    """
    spec = importlib.util.spec_from_file_location(MODULE_NAME, path)
    module = importlib.util.module_from_spec(spec)
    # Registered BEFORE exec so that the module is not executed a second time
    # if anything it imports imports it back, and so that a poisoned entry is
    # REPLACED rather than left behind for the next importer to find.
    sys.modules[MODULE_NAME] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        # A half-executed module is not the library, and leaving it registered
        # would hand the next importer exactly the object this fix is about.
        sys.modules.pop(MODULE_NAME, None)
        raise
    return module


def _load():
    locations = [INSTALLED_DIR]
    locations += [parent / SOURCE_DIR
                  for parent in Path(__file__).resolve().parents]
    for location in locations:
        path = location / MODULE
        if path.is_file():
            cached = sys.modules.get(MODULE_NAME)
            # Reuse an already-loaded module ONLY when it is this very file:
            # one module object for every importer in the process, and never a
            # stand-in for it.  The identity test is the file, not the name.
            if cached is not None and _is_that_file(
                    getattr(cached, "__file__", None), path):
                return cached
            return _exec_file(path)
    raise ImportError(
        "sf_desktop.py was not found. shadowfetch-control-center requires the "
        "matching shadowfetch-defaults package, which ships the shared desktop "
        "library at /usr/lib/shadowfetch/desktop; repair the installation.")


_library = _load()

# Two ways in, one module object, and no copy of anything in it.
#
#   sys.modules  so that `import sfcc.desktop` yields the library itself.  This
#                is what makes patching work the way a reader expects: a test
#                that patches sfcc.desktop.CATALOG_DIR is patching the very
#                attribute the library's own load_catalog() reads.
#   globals()    so that a caller which loads THIS FILE by path -- importlib's
#                spec_from_file_location, which never consults sys.modules --
#                still gets the names rather than an almost-empty module.
globals().update({name: value for name, value in vars(_library).items()
                  if not name.startswith("__")})
sys.modules[__name__] = _library
