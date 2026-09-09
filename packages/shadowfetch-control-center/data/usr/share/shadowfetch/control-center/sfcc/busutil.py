"""Local D-Bus clients for the Control Center.

Every function here is tolerant: a missing daemon, a missing python3-dbus, or
an unexpected member name returns None (or a False-ish value) instead of
raising, and the calling page renders its honest degradation state.

Scope, since Stage P: this module is the D-BUS half only.  Facts that do not
need a bus -- the bundle catalog, the hwscan file, the trusted program table,
launch helpers, the privileged argv builders -- moved to sfcc.desktop, which
imports no Qt and no dbus and is therefore shareable with the other desktop
front-end (W-30).  The names below are re-exported so existing call sites and
`busutil.X` spellings keep working; sfcc.desktop is the one implementation.

Network facts stay here on purpose and are NOT shared with Welcome: this
process talks to NetworkManager through dbus-python, Welcome talks to it
through Qt DBus.  Sharing them means one of the two changing its D-Bus stack,
which is a larger change than this stage owns.
"""

import json
import os

from PyQt6.QtCore import QObject, QTimer, pyqtSignal

# Re-exported for call sites and for tests that reach through busutil. One
# implementation, in sfcc.desktop; these are names for it, not copies of it.
from sfcc.desktop import (  # noqa: F401
    BUNDLE_INSTALL,
    CATALOG_DIR,
    DPKG_QUERY,
    HWSCAN_CLI,
    HWSCAN_JSON,
    OVERLAY_MARKER,
    PHOENIX_APT_REPAIR,
    PHOENIX_APT_SNAPSHOT,
    PHOENIX_RESTORE,
    PKEXEC,
    PROFILE_DIR,
    SNAPPER_DEFAULTS,
    SYSTEMCTL,
    TRUSTED_PATH,
    apt_snapshot_toggle_argv,
    apt_snapshots_enabled,
    bundle_install_argv,
    catalog_by_id,
    installed_command,
    installed_map,
    load_catalog,
    load_ember_profiles,
    load_hwscan,
    overlay_boot,
    overlay_point,
    rfkill_devices,
    root_fstype,
    sf_version,
    start_detached,
    system_summary,
    terminal_command,
    trusted_env,
    trusted_program,
    unit_active,
    user_unit_active,
)

try:
    import dbus
    import dbus.service  # noqa: F401  (imported so app.py can rely on it)
    from dbus.mainloop.glib import DBusGMainLoop
    HAVE_DBUS = True
except ImportError:  # pragma: no cover - python3-dbus is a hard Depends
    dbus = None
    HAVE_DBUS = False

_mainloop_ready = False
_system_bus = None
_session_bus = None

FIREWATCH_BUS = "org.shadowfetch.Firewatch1"
FIREWATCH_PATH = "/org/shadowfetch/Firewatch1"
FIREWATCH_IFACE = "org.shadowfetch.Firewatch1"

EMBER_BUS = "com.shadowfetch.Ember1"
EMBER_PATH = "/com/shadowfetch/Ember1"
EMBER_IFACE = "com.shadowfetch.Ember1"

FIREPROOF_BUS = "org.shadowfetch.Fireproof1"
FIREPROOF_PATH = "/org/shadowfetch/Fireproof1"
FIREPROOF_IFACE = "org.shadowfetch.Fireproof1"

SNAPPER_BUS = "org.opensuse.Snapper"
SNAPPER_PATH = "/org/opensuse/Snapper"
SNAPPER_IFACE = "org.opensuse.Snapper"

PROPS_IFACE = "org.freedesktop.DBus.Properties"

EMBER_UNIT = "shadowfetch-ember.service"
FIREWATCH_UNIT = "shadowfetch-firewatchd.service"

# The pkexec duration/profile helper is owned by the shadowfetch-ember deb.
# Its path is probed rather than hard-coded so a helper rename there cannot
# strand this page; if none exists the page degrades honestly.
EMBER_HELPER_CANDIDATES = (
    "/usr/libexec/shadowfetch-ember-helper",
    "/usr/libexec/ember-helper",
    "/usr/libexec/ember-duration",
)

# ---- bus plumbing ----------------------------------------------------------

def ensure_mainloop() -> None:
    """Install the GLib main loop for dbus-python.  Qt's Linux event
    dispatcher runs the default GLib main context, so D-Bus signals and the
    exported single-instance object work inside the Qt event loop."""
    global _mainloop_ready
    if HAVE_DBUS and not _mainloop_ready:
        DBusGMainLoop(set_as_default=True)
        _mainloop_ready = True


def system_bus():
    global _system_bus
    if not HAVE_DBUS:
        return None
    ensure_mainloop()
    if _system_bus is None:
        try:
            _system_bus = dbus.SystemBus()
        except Exception:
            return None
    return _system_bus


def session_bus():
    global _session_bus
    if not HAVE_DBUS:
        return None
    ensure_mainloop()
    if _session_bus is None:
        try:
            _session_bus = dbus.SessionBus()
        except Exception:
            return None
    return _session_bus


def unwrap(value):
    """Recursively convert dbus types to plain Python."""
    if not HAVE_DBUS:
        return value
    if isinstance(value, (dbus.String, dbus.ObjectPath, dbus.Signature)):
        return str(value)
    if isinstance(value, dbus.Boolean):
        return bool(value)
    if isinstance(value, (dbus.Byte, dbus.Int16, dbus.UInt16, dbus.Int32,
                          dbus.UInt32, dbus.Int64, dbus.UInt64)):
        return int(value)
    if isinstance(value, dbus.Double):
        return float(value)
    if isinstance(value, dict):
        return {unwrap(k): unwrap(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [unwrap(v) for v in value]
    return value


def _parse_payload(value):
    """Daemon payloads may arrive as JSON strings or native D-Bus
    containers; accept both."""
    value = unwrap(value)
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (ValueError, TypeError):
            return None
    return value


# ---- Firewatch client ------------------------------------------------------

class FirewatchClient(QObject):
    """Polls org.shadowfetch.Firewatch1 every 2 s while at least one page is
    showing (acquire/release refcount) and emits one consolidated dict:

        {"available": bool, "snapshot": dict|None, "heatmap": list|None,
         "models": list|None, "storage": dict|list|None,
         "flame": str|None, "eli": float|None}

    Member names are probed from a candidate list once and cached, so a
    daemon-side rename costs one failed call, not one per tick."""

    updated = pyqtSignal(dict)

    _CANDIDATES = {
        "snapshot": (("GetSensorSnapshot", "SensorSnapshot", "GetSnapshot"),
                     ("SensorSnapshot", "Snapshot")),
        "heatmap": (("GetHeatMap", "HeatMap"), ("HeatMap",)),
        "models": (("GetModels", "Models", "GetJobs"), ("Models", "Jobs")),
        "storage": (("GetStorageHealth", "StorageHealth"), ("StorageHealth",)),
    }

    def __init__(self, parent=None):
        super().__init__(parent)
        self._refs = 0
        self._resolved: dict[str, tuple[str, str]] = {}
        self._timer = QTimer(self)
        self._timer.setInterval(2000)
        self._timer.timeout.connect(self._tick)
        self.last: dict = {"available": False}

    # -- refcounted subscription --------------------------------------------
    def acquire(self) -> None:
        self._refs += 1
        if self._refs == 1:
            self._simple_call("Subscribe")
            self._tick()
            self._timer.start()

    def release(self) -> None:
        self._refs = max(0, self._refs - 1)
        if self._refs == 0:
            self._timer.stop()
            self._simple_call("Unsubscribe")

    # -- internals ----------------------------------------------------------
    def _object(self):
        bus = system_bus()
        if bus is None:
            return None
        try:
            return bus.get_object(FIREWATCH_BUS, FIREWATCH_PATH)
        except Exception:
            return None

    def _simple_call(self, member: str) -> None:
        obj = self._object()
        if obj is None:
            return
        try:
            obj.get_dbus_method(member, dbus_interface=FIREWATCH_IFACE)()
        except Exception:
            pass

    def _get(self, obj, key: str):
        methods, props = self._CANDIDATES[key]
        kind_member = self._resolved.get(key)
        if kind_member:
            kind, member = kind_member
            try:
                if kind == "method":
                    return _parse_payload(
                        obj.get_dbus_method(member, dbus_interface=FIREWATCH_IFACE)())
                return _parse_payload(
                    obj.get_dbus_method("Get", dbus_interface=PROPS_IFACE)(
                        FIREWATCH_IFACE, member))
            except Exception:
                self._resolved.pop(key, None)
                return None
        for member in methods:
            try:
                value = obj.get_dbus_method(member, dbus_interface=FIREWATCH_IFACE)()
            except Exception:
                continue
            self._resolved[key] = ("method", member)
            return _parse_payload(value)
        for member in props:
            try:
                value = obj.get_dbus_method("Get", dbus_interface=PROPS_IFACE)(
                    FIREWATCH_IFACE, member)
            except Exception:
                continue
            self._resolved[key] = ("prop", member)
            return _parse_payload(value)
        return None

    def _get_flame(self, obj):
        flame = None
        eli = None
        try:
            get = obj.get_dbus_method("Get", dbus_interface=PROPS_IFACE)
            try:
                flame = unwrap(get(FIREWATCH_IFACE, "FlameLevel"))
            except Exception:
                pass
            try:
                eli = float(unwrap(get(FIREWATCH_IFACE, "ELI")))
            except Exception:
                pass
        except Exception:
            pass
        if flame is None:
            # firewatchd exposes flame as a method, not a property.
            try:
                gf = obj.get_dbus_method("GetFlame", dbus_interface=FIREWATCH_IFACE)
                lvl, e, _work = gf()
                flame = str(lvl)
                eli = float(e)
            except Exception:
                pass
        if flame is None:
            snap = self.last.get("snapshot") or {}
            if isinstance(snap, dict):
                flame = snap.get("flame") or snap.get("flame_level")
                if eli is None:
                    try:
                        eli = float(snap.get("eli"))
                    except (TypeError, ValueError):
                        eli = None
        if isinstance(flame, int):
            flame = {0: "warm", 1: "warm", 2: "hot", 3: "inferno"}.get(flame, "warm")
        if isinstance(flame, str):
            flame = flame.strip().lower() or None
        return flame, eli

    def _tick(self) -> None:
        obj = self._object()
        if obj is None:
            if self.last.get("available", True):
                self.last = {"available": False}
                self.updated.emit(self.last)
            return
        result = {"available": False}
        for key in ("snapshot", "heatmap", "models", "storage"):
            result[key] = self._get(obj, key)
        # The daemon is "available" if any payload answered, even partially.
        result["available"] = any(result.get(k) is not None
                                  for k in ("snapshot", "heatmap", "models", "storage"))
        self.last = result
        flame, eli = self._get_flame(obj)
        result["flame"] = flame
        result["eli"] = eli
        self.updated.emit(result)


# ---- Ember ----------------------------------------------------------------

def ember_props() -> dict | None:
    """{armed, hold_active, paused_units, state_file_hash} from
    com.shadowfetch.Ember1, keys normalised to snake_case lower."""
    bus = system_bus()
    if bus is None:
        return None
    try:
        obj = bus.get_object(EMBER_BUS, EMBER_PATH)
        raw = obj.get_dbus_method("GetAll", dbus_interface=PROPS_IFACE)(EMBER_IFACE)
    except Exception:
        return None
    out = {}
    for key, value in unwrap(raw).items():
        norm = "".join(("_" + c.lower()) if c.isupper() else c for c in str(key)).lstrip("_")
        out[norm.replace("__", "_")] = value
    return out


def find_ember_helper() -> str | None:
    for path in EMBER_HELPER_CANDIDATES:
        if os.access(path, os.X_OK):
            return path
    return None


def gamemode_clients() -> int | None:
    """Live GameMode status from the session bus; None when GameMode is not
    on the bus (which is normal when no game is running)."""
    bus = session_bus()
    if bus is None:
        return None
    try:
        obj = bus.get_object("com.feralinteractive.GameMode",
                             "/com/feralinteractive/GameMode")
        value = obj.get_dbus_method("Get", dbus_interface=PROPS_IFACE)(
            "com.feralinteractive.GameMode", "ClientCount")
        return int(unwrap(value))
    except Exception:
        return None


# ---- Fireproof -------------------------------------------------------------

def fireproof_updates() -> int | None:
    """Pending update count from fireproofd, feeding the one permitted
    sidebar badge.  None when the daemon is absent or unreadable."""
    bus = system_bus()
    if bus is None:
        return None
    try:
        obj = bus.get_object(FIREPROOF_BUS, FIREPROOF_PATH)
        raw = unwrap(obj.get_dbus_method("GetAll", dbus_interface=PROPS_IFACE)(
            FIREPROOF_IFACE))
    except Exception:
        return None
    for key in ("UpdatesAvailable", "updates_available", "PendingUpdates",
                "pending_updates", "UpdateCount", "update_count"):
        if key in raw:
            try:
                return int(raw[key])
            except (TypeError, ValueError):
                return None
    return None


# ---- Phoenix / snapper -----------------------------------------------------

def snapper_list() -> list[dict] | None:
    """Phoenix Points via snapperd's D-Bus (bus-activated).  Returns a list
    of {num, type, pre, date, description, cleanup, userdata} or None when
    snapperd cannot answer (ext4 systems, missing config)."""
    bus = system_bus()
    if bus is None:
        return None
    try:
        obj = bus.get_object(SNAPPER_BUS, SNAPPER_PATH)
        rows = obj.get_dbus_method("ListSnapshots", dbus_interface=SNAPPER_IFACE)("root")
    except Exception:
        return None
    out = []
    type_names = {0: "single", 1: "pre", 2: "post"}
    for row in unwrap(rows):
        try:
            entry = {
                "num": int(row[0]),
                "type": type_names.get(int(row[1]), str(row[1])),
                "pre": int(row[2]),
                "date": int(row[3]),
                "description": str(row[5]) if len(row) > 5 else "",
                "cleanup": str(row[6]) if len(row) > 6 else "",
                "userdata": row[7] if len(row) > 7 and isinstance(row[7], dict) else {},
            }
        except (IndexError, TypeError, ValueError):
            continue
        out.append(entry)
    return out


# ---- hwscan ----------------------------------------------------------------


# ---- Welcome catalog / bundles --------------------------------------------


def nm_connectivity_full() -> bool | None:
    """True when NetworkManager reports full connectivity (4), False when
    limited/none, None when NM is unreachable."""
    bus = system_bus()
    if bus is None:
        return None
    try:
        obj = bus.get_object("org.freedesktop.NetworkManager",
                             "/org/freedesktop/NetworkManager")
        value = obj.get_dbus_method("Get", dbus_interface=PROPS_IFACE)(
            "org.freedesktop.NetworkManager", "Connectivity")
        return int(unwrap(value)) == 4
    except Exception:
        return None


_NM_DEVICE_TYPES = {
    1: "Ethernet", 2: "Wi-Fi", 5: "Bluetooth", 6: "OLPC mesh", 7: "WiMAX",
    8: "Modem", 13: "Bridge", 14: "Generic", 16: "TUN", 17: "IP tunnel",
    22: "Dummy", 29: "WireGuard", 30: "Wi-Fi P2P", 32: "Loopback",
}


def nm_devices() -> list[dict] | None:
    """Network devices with driver and firmware state, for the Drivers
    page.  'May need firmware' wording is decided by the page."""
    bus = system_bus()
    if bus is None:
        return None
    try:
        nm = bus.get_object("org.freedesktop.NetworkManager",
                            "/org/freedesktop/NetworkManager")
        paths = nm.get_dbus_method("GetDevices",
                                   dbus_interface="org.freedesktop.NetworkManager")()
    except Exception:
        return None
    devices = []
    for path in unwrap(paths):
        try:
            dev = bus.get_object("org.freedesktop.NetworkManager", path)
            props = unwrap(dev.get_dbus_method("GetAll", dbus_interface=PROPS_IFACE)(
                "org.freedesktop.NetworkManager.Device"))
        except Exception:
            continue
        dtype = int(props.get("DeviceType", 14))
        if dtype == 32:  # loopback is noise
            continue
        devices.append({
            "interface": props.get("Interface", "?"),
            "type": _NM_DEVICE_TYPES.get(dtype, f"type {dtype}"),
            "driver": props.get("Driver", "") or "none",
            "firmware_missing": bool(props.get("FirmwareMissing", False)),
        })
    return devices
