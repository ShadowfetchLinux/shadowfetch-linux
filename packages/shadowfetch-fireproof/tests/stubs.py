"""Offline test scaffolding: load fireproofd against stub modules.

fireproofd imports apt, apt_pkg, dbus and gi at module scope; none of
them are needed to exercise its pure logic (analyzer diff, cache
filename derivation, hashes). These stubs satisfy the imports so the
tests run on any machine with only the standard library.
"""
import importlib.machinery
import importlib.util
import os
import sys
import types

FIREPROOFD = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "data", "usr", "libexec", "fireproofd"))
# sfupdate.trusted deliberately refuses to re-implement phoenix.trusted's
# classifier, so the daemon needs shadowfetch-phoenix's module directory on
# sys.path. Installed, both live in /usr/lib/shadowfetch and fireproofd's
# own path finds them; in the SOURCE tree they are in two package
# directories, so the test harness bridges that - and only that.
PHOENIX_LIB = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "..", "shadowfetch-phoenix", "usr",
    "lib", "shadowfetch"))
SFUPDATE_LIB = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "data", "usr", "lib", "shadowfetch"))
POSTBOOT = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "data", "usr", "libexec",
    "fireproof-postboot"))
FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def install_stubs():
    for lib in (SFUPDATE_LIB, PHOENIX_LIB):
        if lib not in sys.path:
            sys.path.insert(0, lib)
    if getattr(sys.modules.get("apt"), "_fireproof_stub", False):
        return

    # ---- apt -------------------------------------------------------------
    apt = types.ModuleType("apt")
    apt._fireproof_stub = True

    class _Base:
        def __init__(self, *a, **k):
            pass

    progress = types.ModuleType("apt.progress")
    base = types.ModuleType("apt.progress.base")
    base.AcquireProgress = type("AcquireProgress", (_Base,), {
        "total_bytes": 0, "current_bytes": 0,
        "total_items": 0, "current_items": 0})
    base.InstallProgress = type("InstallProgress", (_Base,), {})
    base.OpProgress = type("OpProgress", (_Base,), {})
    progress.base = base
    apt.progress = progress

    cache_mod = types.ModuleType("apt.cache")
    cache_mod.FetchCancelledException = type(
        "FetchCancelledException", (Exception,), {})
    apt.cache = cache_mod
    apt.Cache = None   # tests never open a real cache

    sys.modules["apt"] = apt
    sys.modules["apt.progress"] = progress
    sys.modules["apt.progress.base"] = base
    sys.modules["apt.cache"] = cache_mod

    # ---- apt_pkg ---------------------------------------------------------
    apt_pkg = types.ModuleType("apt_pkg")
    apt_pkg._fireproof_stub = True
    apt_pkg.SELSTATE_HOLD = 2
    apt_pkg.get_lock = lambda *a, **k: -1
    apt_pkg.config = types.SimpleNamespace(set=lambda *a, **k: None)
    sys.modules["apt_pkg"] = apt_pkg

    # ---- dbus ------------------------------------------------------------
    dbus = types.ModuleType("dbus")
    dbus._fireproof_stub = True

    class DBusException(Exception):
        def get_dbus_message(self):
            return str(self)

        def get_dbus_name(self):
            return getattr(type(self), "_dbus_error_name", "")

    dbus.DBusException = DBusException
    dbus.PROPERTIES_IFACE = "org.freedesktop.DBus.Properties"
    dbus.Int32 = dbus.Boolean = dbus.String = dbus.UInt32 = (
        lambda v, variant_level=0: v)
    dbus.Interface = lambda *a, **k: None
    dbus.SystemBus = type("SystemBus", (), {
        "get_object": lambda self, *a, **k: None})

    service = types.ModuleType("dbus.service")
    service.Object = type("Object", (), {
        "__init__": lambda self, *a, **k: None})
    service.BusName = type("BusName", (), {
        "__init__": lambda self, *a, **k: None})

    def _passthrough_decorator(*_a, **_k):
        return lambda f: f

    service.method = _passthrough_decorator
    service.signal = _passthrough_decorator
    dbus.service = service

    mainloop = types.ModuleType("dbus.mainloop")
    glib_ml = types.ModuleType("dbus.mainloop.glib")
    glib_ml.DBusGMainLoop = lambda **k: None
    mainloop.glib = glib_ml
    dbus.mainloop = mainloop

    sys.modules["dbus"] = dbus
    sys.modules["dbus.service"] = service
    sys.modules["dbus.mainloop"] = mainloop
    sys.modules["dbus.mainloop.glib"] = glib_ml

    # ---- gi --------------------------------------------------------------
    gi = types.ModuleType("gi")
    repository = types.ModuleType("gi.repository")
    GLib = types.ModuleType("gi.repository.GLib")
    GLib.idle_add = lambda f, *a: f(*a)
    GLib.timeout_add_seconds = lambda *a, **k: 0
    GLib.unix_signal_add = lambda *a, **k: 0
    GLib.PRIORITY_HIGH = 0
    GLib.MainLoop = type("MainLoop", (), {
        "run": lambda self: None, "quit": lambda self: None})
    repository.GLib = GLib
    gi.repository = repository
    sys.modules["gi"] = gi
    sys.modules["gi.repository"] = repository
    sys.modules["gi.repository.GLib"] = GLib


_cached = None


def load_fireproofd():
    """Import the daemon script (no .py extension) with stubs installed."""
    global _cached
    if _cached is not None:
        return _cached
    install_stubs()
    old_argv = sys.argv
    sys.argv = ["fireproofd"]     # the script inspects argv at import
    try:
        loader = importlib.machinery.SourceFileLoader(
            "fireproofd_under_test", FIREPROOFD)
        spec = importlib.util.spec_from_loader("fireproofd_under_test", loader)
        mod = importlib.util.module_from_spec(spec)
        loader.exec_module(mod)
    finally:
        sys.argv = old_argv
    _cached = mod
    return mod
