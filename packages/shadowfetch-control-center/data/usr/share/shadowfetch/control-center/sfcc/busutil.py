"""Local D-Bus and system helpers for the Control Center.

Every function here is tolerant: a missing daemon, a missing python3-dbus,
or an unexpected member name returns None (or a False-ish value) instead of
raising, and the calling page renders its honest degradation state.  Pages
read hardware sensors through Firewatch1. Mission and model verification use
the separate mission client and its explicit runtime/connection policy.

The bus connections here use the local system and session buses. Subprocess
helpers and optional applications retain their declared connection behavior.
"""

import glob
import json
import os
import shutil
import subprocess
import time
from pathlib import Path

from PyQt6.QtCore import QObject, QTimer, pyqtSignal

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

PHOENIX_RESTORE = "/usr/libexec/phoenix-restore"
PHOENIX_APT_REPAIR = "/usr/libexec/phoenix-apt-repair"
BUNDLE_INSTALL = "/usr/libexec/shadowfetch-bundle-install"
HWSCAN_CLI = "/usr/libexec/shadowfetch-hwscan"
HWSCAN_JSON = "/var/lib/shadowfetch/hwscan.json"
CATALOG_DIR = "/usr/share/shadowfetch/welcome/catalog"
PROFILE_DIR = "/usr/share/shadowfetch/ember/profiles"
OVERLAY_MARKER = "/run/phoenix-overlay"
SNAPPER_DEFAULTS = "/etc/default/snapper"


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


def unit_active(unit: str) -> bool:
    try:
        rc = subprocess.run(["systemctl", "is-active", "--quiet", unit],
                            timeout=5, check=False)
        return rc.returncode == 0
    except Exception:
        return False


def user_unit_active(unit: str) -> bool:
    try:
        rc = subprocess.run(["systemctl", "--user", "is-active", "--quiet", unit],
                            timeout=5, check=False)
        return rc.returncode == 0
    except Exception:
        return False


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


def load_ember_profiles() -> list[dict]:
    """Read the root-owned profile cards from
    /usr/share/shadowfetch/ember/profiles/*.conf (key=value lines)."""
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
    """The snapshot number this overlay session was booted from, taken from
    the marker file or the kernel cmdline."""
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
    if match:
        return int(match.group(1))
    return None


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


# Fixed scripts (no interpolation, ever) for the DISABLE_APT_SNAPSHOT toggle.
_TOGGLE_SCRIPT = (
    "if grep -q '^DISABLE_APT_SNAPSHOT=' /etc/default/snapper; then "
    "sed -i 's/^DISABLE_APT_SNAPSHOT=.*/DISABLE_APT_SNAPSHOT=\"{value}\"/' "
    "/etc/default/snapper; else "
    "printf 'DISABLE_APT_SNAPSHOT=\"{value}\"\\n' >> /etc/default/snapper; fi"
)


def apt_snapshot_toggle_argv(enable: bool) -> list[str]:
    """The pkexec command that flips DISABLE_APT_SNAPSHOT.  Prefers a
    phoenix helper when one is installed; otherwise a fixed sed script."""
    for helper in ("/usr/libexec/phoenix-apt-snapshot",
                   "/usr/libexec/phoenix-snapshot-toggle"):
        if os.access(helper, os.X_OK):
            return ["pkexec", helper, "enable" if enable else "disable"]
    script = _TOGGLE_SCRIPT.format(value="no" if enable else "yes")
    return ["pkexec", "/bin/sh", "-c", script]


# ---- hwscan ----------------------------------------------------------------

def _boot_timestamp() -> float:
    try:
        uptime = float(Path("/proc/uptime").read_text().split()[0])
        return time.time() - uptime
    except (OSError, ValueError, IndexError):
        return 0.0


def load_hwscan(rescan: bool = False) -> dict | None:
    """The hardware fact file.  The boot-time service writes
    /var/lib/shadowfetch/hwscan.json; if the file predates this boot (or a
    rescan is requested) the unprivileged CLI is executed instead."""
    if not rescan:
        try:
            stat = os.stat(HWSCAN_JSON)
            if stat.st_mtime >= _boot_timestamp():
                return json.loads(Path(HWSCAN_JSON).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
    if os.access(HWSCAN_CLI, os.X_OK):
        try:
            out = subprocess.run([HWSCAN_CLI, "--json"], capture_output=True,
                                 text=True, timeout=8, check=False)
            if out.returncode == 0 and out.stdout.strip():
                return json.loads(out.stdout)
        except (OSError, ValueError, subprocess.TimeoutExpired):
            pass
    # Fall back to a stale file rather than nothing: the page labels the
    # scan timestamp, so staleness is visible, never silent.
    try:
        return json.loads(Path(HWSCAN_JSON).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


# ---- Welcome catalog / bundles --------------------------------------------

def load_catalog(kinds: tuple[str, ...] = ("preset",)) -> list[dict]:
    entries = []
    for path in sorted(glob.glob(os.path.join(CATALOG_DIR, "*.json"))):
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        records = data if isinstance(data, list) else [data]
        for record in records:
            if isinstance(record, dict) and record.get("kind") in kinds:
                entries.append(record)
    return entries


def installed_map(packages: list[str]) -> dict[str, bool]:
    """One dpkg-query for a whole bundle; unknown packages count as not
    installed."""
    result = {p: False for p in packages}
    if not packages:
        return result
    try:
        out = subprocess.run(
            ["dpkg-query", "-W", "-f", "${Package} ${db:Status-Status}\n"] + packages,
            capture_output=True, text=True, timeout=10, check=False)
        for line in out.stdout.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[0] in result:
                result[parts[0]] = parts[1] == "installed"
    except (OSError, subprocess.TimeoutExpired):
        pass
    return result


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


# ---- shared shell helpers --------------------------------------------------

def terminal_command(command: str) -> None:
    """Run a command in a visible terminal — the pattern the 2.1.1 Control
    Center established for the text-mode tools."""
    wrapped = (f"{command}; rc=$?; echo; "
               f"printf 'Finished (status %s). Press Enter to close...' \"$rc\"; "
               f"read -r _; exit $rc")
    if shutil.which("konsole"):
        subprocess.Popen(["konsole", "-e", "bash", "-lc", wrapped])
    elif shutil.which("x-terminal-emulator"):
        subprocess.Popen(["x-terminal-emulator", "-e", "bash", "-lc", wrapped])
    else:
        subprocess.Popen(["bash", "-lc", command])


def start_detached(argv: list[str]) -> bool:
    try:
        subprocess.Popen(argv)
        return True
    except OSError:
        return False


def sf_version() -> str:
    try:
        return Path("/usr/share/shadowfetch/version").read_text().strip()
    except OSError:
        return "unknown"


def system_summary() -> tuple[str, str]:
    """Summarize disk use and system units; desktop user units are separate."""
    try:
        usage = shutil.disk_usage("/")
        used = round((usage.used / usage.total) * 100)
        result = subprocess.run(
            ["systemctl", "--failed", "--no-legend", "--plain"],
            capture_output=True, text=True, timeout=3, check=False,
        )
        if result.returncode:
            return "Status unavailable", "Open Watch for a complete report"
        failed = result.stdout.strip().splitlines()
        if failed or used >= 90:
            return "Needs attention", f"{len(failed)} failed system units · disk {used}% used"
        return "System check passed", f"No failed system units · disk {used}% used"
    except Exception:
        return "Status available", "Open Watch for a complete report"
