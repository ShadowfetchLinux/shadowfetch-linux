"""W-20 regressions.

Three defects in a daemon that runs as root for the uptime of the machine:

  1. caches keyed on per-process-instance names grew without bound;
  2. unit lookups went through systemd's Manager.LoadUnit, which is a
     mutation -- it makes PID 1 load and keep every name asked about;
  3. the unit granted write access to every block device.

Each test below fails against the pre-fix code. Where the old shape can be
reconstructed cheaply (the plain-dict caches) it is exercised side by side
with the fixed one, so the test also demonstrates the growth it prevents.
"""

import importlib.machinery
import importlib.util
from pathlib import Path
import unittest


HERE = Path(__file__).resolve().parent
PKG = HERE.parent
SRC = PKG / "usr" / "libexec" / "firewatchd"
UNIT = PKG / "usr" / "lib" / "systemd" / "system" / "shadowfetch-firewatchd.service"

_loader = importlib.machinery.SourceFileLoader("firewatchd_cache_test", str(SRC))
_spec = importlib.util.spec_from_loader("firewatchd_cache_test", _loader)
firewatchd = importlib.util.module_from_spec(_spec)
_loader.exec_module(firewatchd)


# One unit name per process instance -- the shape that made these caches grow.
CHURN = 3000


def churn_units(count=CHURN):
    return ["app-org.example.Editor-%d.scope" % i for i in range(count)]


class BoundedCacheTests(unittest.TestCase):
    def test_evicts_the_least_recently_used_entry_past_the_cap(self):
        cache = firewatchd.BoundedCache(3)
        for i in range(3):
            cache[i] = str(i)
        self.assertEqual("0", cache[0])        # 0 is now the most recent
        cache[3] = "3"                          # 1 is now the least recent
        self.assertEqual(3, len(cache))
        self.assertIn(0, cache)
        self.assertNotIn(1, cache)
        self.assertEqual("3", cache[3])
        self.assertIsNone(cache.get(1))
        self.assertEqual("sentinel", cache.get(1, "sentinel"))

    def test_reads_through_get_also_refresh_recency(self):
        cache = firewatchd.BoundedCache(2)
        cache["a"] = 1
        cache["b"] = 2
        cache.get("a")
        cache["c"] = 3
        self.assertIn("a", cache)
        self.assertNotIn("b", cache)

    def test_never_exceeds_the_cap_however_many_keys_arrive(self):
        cache = firewatchd.BoundedCache(64)
        for i in range(10000):
            cache[i] = i
            self.assertLessEqual(len(cache), 64)
        self.assertEqual(64, len(cache))

    def test_overwriting_a_key_does_not_grow_the_cache(self):
        cache = firewatchd.BoundedCache(4)
        for _ in range(100):
            cache["same"] = 1
        self.assertEqual(1, len(cache))

    def test_retain_drops_everything_not_listed(self):
        cache = firewatchd.BoundedCache(10)
        for i in range(5):
            cache[i] = i
        cache.retain({1, 3})
        self.assertEqual(2, len(cache))
        self.assertIn(1, cache)
        self.assertIn(3, cache)
        self.assertNotIn(0, cache)

    def test_a_zero_cap_is_rejected_rather_than_silently_useless(self):
        with self.assertRaises(ValueError):
            firewatchd.BoundedCache(0)


class _PreFixHumanizer(firewatchd.Humanizer):
    """The Humanizer as it was: identical logic, plain dict caches."""

    def __init__(self, systemd_desc_lookup=None):
        super().__init__(systemd_desc_lookup)
        self._cache = {}
        self._desktop_cache = {}


class HumanizerCacheTests(unittest.TestCase):
    @staticmethod
    def _drive(humanizer, units):
        for unit in units:
            humanizer.resolve(unit, "editor")

    def test_unit_cache_is_capped_where_the_old_dict_grew_without_bound(self):
        units = churn_units()

        def describe(unit):
            return "Editor " + unit

        old = _PreFixHumanizer(describe)
        self._drive(old, units)
        self.assertEqual(CHURN, len(old._cache))   # the defect, reproduced

        new = firewatchd.Humanizer(describe)
        self._drive(new, units)
        self.assertEqual(firewatchd.UNIT_CACHE_MAX, len(new._cache))

    def test_desktop_entry_cache_is_capped_too(self):
        units = churn_units()

        old = _PreFixHumanizer()
        self._drive(old, units)
        self.assertGreater(len(old._desktop_cache), firewatchd.DESKTOP_CACHE_MAX)

        new = firewatchd.Humanizer()
        self._drive(new, units)
        self.assertEqual(firewatchd.DESKTOP_CACHE_MAX, len(new._desktop_cache))

    def test_resolution_is_unchanged_by_the_cap(self):
        """The invariant: what resolve() returns must not move."""
        units = churn_units(50)

        def describe(unit):
            return "Editor " + unit

        old = _PreFixHumanizer(describe)
        new = firewatchd.Humanizer(describe)
        for unit in units:
            self.assertEqual(old.resolve(unit, "editor"),
                             new.resolve(unit, "editor"))
        # an evicted entry is recomputed to the same answer, not lost
        new._cache.retain(set())
        self.assertEqual(old.resolve(units[0], "editor"),
                         new.resolve(units[0], "editor"))

    def test_comm_fallback_is_still_not_cached(self):
        humanizer = firewatchd.Humanizer()      # no systemd description lookup
        self.assertEqual(("editor", "application-x-executable"),
                         humanizer.resolve("app-org.example.Editor-1.scope",
                                           "editor"))
        self.assertEqual(0, len(humanizer._cache))


class HeatMapCgroupCacheTests(unittest.TestCase):
    @staticmethod
    def _heatmap():
        return firewatchd.HeatMap(firewatchd.Humanizer())

    def test_pid_cgroup_cache_is_capped(self):
        heat = self._heatmap()
        cap = firewatchd.PID_CGROUP_CACHE_MAX
        for pid in range(1, cap + 250):
            heat._pid_cgroup_unit(pid, pid)
        self.assertEqual(cap, len(heat._cgroup_cache))

    def test_dead_pids_are_still_pruned_every_sweep(self):
        heat = self._heatmap()
        for pid in range(10):
            heat._cgroup_cache[(pid, pid)] = "u%d.scope" % pid
        heat._cgroup_cache.retain({(3, 3): 0, (7, 7): 0})
        self.assertEqual(2, len(heat._cgroup_cache))
        self.assertIn((3, 3), heat._cgroup_cache)
        self.assertNotIn((4, 4), heat._cgroup_cache)

    def test_a_live_sweep_still_publishes_rows(self):
        """Invariant: the published row shape did not change."""
        heat = self._heatmap()
        heat.sweep()
        rows = heat.sweep()
        self.assertLessEqual(len(rows), firewatchd.PUBLISHED_ROWS)
        self.assertTrue(rows, "no processes visible in /proc")
        for row in rows:
            self.assertEqual(
                {"display_name", "icon", "cgroup", "cpu_pct", "rss_bytes",
                 "pss_bytes", "nvidia_vram_bytes", "heat_tier", "heat_score"},
                set(row))
            self.assertIn(row["heat_tier"], ("low", "medium", "high"))


class _FakeDBusError(Exception):
    def __init__(self, name):
        super().__init__(name)
        self._name = name

    def get_dbus_name(self):
        return self._name


class _FakeProperties:
    def __init__(self, values):
        self._values = values

    def Get(self, iface, name):
        assert iface == firewatchd.SYSTEMD_UNIT_IFACE, iface
        return self._values[name]


class _FakeManager:
    """Records every manager method firewatchd reaches for."""

    def __init__(self, loaded):
        self.loaded = loaded            # unit name -> {property: value}
        self.calls = []

    @staticmethod
    def _path(unit):
        return "/org/freedesktop/systemd1/unit/" + unit.replace(".", "_2e")

    def GetUnit(self, unit):
        self.calls.append(("GetUnit", unit))
        if unit not in self.loaded:
            raise _FakeDBusError(firewatchd.NO_SUCH_UNIT_ERROR)
        return self._path(unit)

    def LoadUnit(self, unit):
        # The mutating call. Reaching it at all is the defect.
        self.calls.append(("LoadUnit", unit))
        raise AssertionError("firewatchd called the mutating LoadUnit")


def make_units(manager, **kwargs):
    def properties_for_path(path):
        for unit, values in manager.loaded.items():
            if path == manager._path(unit):
                return _FakeProperties(values)
        raise AssertionError("unexpected object path: " + path)
    return firewatchd.SystemdUnits(manager, properties_for_path, **kwargs)


class SystemdUnitsTests(unittest.TestCase):
    def _manager(self):
        return _FakeManager({
            "shadowfetch-ember.service": {"Description": "Shadowfetch Ember",
                                          "ActiveState": "active"},
            "cups.service": {"Description": "CUPS Scheduler",
                             "ActiveState": "inactive"},
        })

    def test_lookup_uses_GetUnit_and_never_the_mutating_LoadUnit(self):
        mgr = self._manager()
        units = make_units(mgr)
        self.assertEqual("CUPS Scheduler", units.description("cups.service"))
        self.assertEqual([("GetUnit", "cups.service")], mgr.calls)

    def test_a_unit_that_is_not_loaded_is_not_loaded_by_asking(self):
        mgr = self._manager()
        units = make_units(mgr)
        self.assertIsNone(units.description("app-gone-4711.scope"))
        self.assertFalse(units.is_active("app-gone-4711.scope"))
        self.assertTrue(all(call[0] == "GetUnit" for call in mgr.calls))
        self.assertNotIn("app-gone-4711.scope", mgr.loaded)

    def test_active_state_still_answers_the_ember_question(self):
        mgr = self._manager()
        units = make_units(mgr)
        self.assertTrue(units.is_active("shadowfetch-ember.service"))
        self.assertFalse(units.is_active("cups.service"))

    def test_descriptions_are_cached_and_the_cache_is_bounded(self):
        mgr = self._manager()
        units = make_units(mgr, cap=8)
        for _ in range(5):
            units.description("cups.service")
        self.assertEqual(1, len(mgr.calls))          # cached after the first
        for i in range(100):
            units.description("app-x-%d.scope" % i)   # negative results too
        self.assertEqual(8, len(units._desc_cache))

    def test_an_unexpected_dbus_error_degrades_instead_of_killing_the_tick(self):
        class Broken:
            def GetUnit(self, unit):
                raise _FakeDBusError("org.freedesktop.DBus.Error.NoReply")

        units = firewatchd.SystemdUnits(Broken(), lambda path: None)
        with self.assertRaises(_FakeDBusError):
            units.object_path("cups.service")        # surfaced to the caller
        self.assertIsNone(units.description("cups.service"))   # ...but absorbed
        self.assertFalse(units.is_active("cups.service"))

    def test_source_contains_no_mutating_LoadUnit_call(self):
        source = SRC.read_text()
        self.assertNotRegex(source, r"LoadUnit\s*\(")
        self.assertRegex(source, r"\.GetUnit\(")


class UnitHardeningTests(unittest.TestCase):
    def test_block_devices_are_readable_but_not_writable(self):
        text = UNIT.read_text()
        self.assertIn("\nDeviceAllow=block-* r\n", text)
        self.assertNotIn("DeviceAllow=block-* rw", text)

    def test_the_hardening_the_daemon_still_needs_is_intact(self):
        text = UNIT.read_text()
        for directive in ("ProtectSystem=strict", "NoNewPrivileges=yes",
                          "DeviceAllow=char-nvme rw",
                          "DeviceAllow=char-nvidia* rw"):
            self.assertIn(directive, text)


if __name__ == "__main__":
    unittest.main()
