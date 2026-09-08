"""The Fireproof D-Bus surface: what a caller may reach without authorization.

Phase 1 W-06. Verify() shipped in 4.0.0 with neither sender_keyword nor
_require_auth, on a service whose bus policy let any local sender talk to it.
It executes `dpkg --audit` and `apt-get -s -f install` as root, so any
unprivileged local process could drive unbounded root work and read back a
detailed report of the machine's package state.

Phase 1 W-21. Analyze() is unauthenticated by design and spawned an unbounded
thread per call inside a root daemon.
"""
import os
import re
import threading
import time
import unittest
import xml.etree.ElementTree as ET

from stubs import load_fireproofd

fp = load_fireproofd()

HERE = os.path.dirname(os.path.abspath(__file__))
DAEMON = os.path.join(HERE, "..", "data", "usr", "libexec", "fireproofd")
BUS_POLICY = os.path.join(HERE, "..", "data", "usr", "share", "dbus-1",
                          "system.d", "org.shadowfetch.Fireproof1.conf")

# Methods that mutate the system or execute privileged work. Every one of them
# must take the caller's bus name and put it through polkit.
MUST_AUTHENTICATE = {"Update", "CancelDownload", "ProceedCommit",
                     "AbortCommit", "RecordRollback", "Verify"}

# Methods that may answer an unauthenticated caller: each only reads state the
# daemon already holds, or is bounded (Analyze).
MAY_BE_ANONYMOUS = {"Get", "GetAll", "Set", "GetState", "RollbackTarget",
                    "Inspect", "Analyze"}


def exported_methods():
    """(name -> decorator+body text) for every @dbus.service.method."""
    with open(DAEMON) as fh:
        src = fh.read().splitlines()
    found = {}
    for i, line in enumerate(src):
        if "@dbus.service.method" in line:
            block = "\n".join(src[i:i + 22])
            m = re.search(r"def (\w+)\(", block)
            if m:
                found[m.group(1)] = block
    return found


class ExportedSurface(unittest.TestCase):
    def test_every_privileged_method_authenticates(self):
        methods = exported_methods()
        for name in sorted(MUST_AUTHENTICATE):
            with self.subTest(method=name):
                self.assertIn(name, methods, "%s is no longer exported" % name)
                block = methods[name]
                self.assertIn("sender_keyword", block,
                              "%s does not receive the caller's bus name" % name)
                self.assertIn("_require_auth", block,
                              "%s does not check polkit" % name)

    def test_no_unreviewed_method_appeared(self):
        """A new exported method must be classified deliberately, not by
        default. This is the check that would have caught Verify."""
        unknown = set(exported_methods()) - MUST_AUTHENTICATE - MAY_BE_ANONYMOUS
        self.assertEqual(unknown, set(),
                         "unclassified D-Bus methods: %s" % sorted(unknown))


class BusPolicy(unittest.TestCase):
    def setUp(self):
        self.root = ET.parse(BUS_POLICY).getroot()
        self.default = [p for p in self.root.findall("policy")
                        if p.get("context") == "default"][0]

    def test_default_context_denies_first(self):
        kinds = [child.tag for child in self.default]
        self.assertIn("deny", kinds,
                      "the default context has no deny rule, so every member "
                      "of a root-owned service is reachable")
        self.assertEqual(kinds[0], "deny",
                         "the deny must come before the allowlist")

    def test_allowlist_is_by_member_not_wholesale(self):
        wide = [a for a in self.default.findall("allow")
                if a.get("send_destination") and not a.get("send_interface")]
        self.assertEqual(wide, [],
                         "an allow rule opens the whole destination")

    def test_every_exported_method_is_listed_or_unreachable(self):
        listed = {a.get("send_member") for a in self.default.findall("allow")
                  if a.get("send_member")}
        # Properties/Introspectable/Peer members are covered by interface rules.
        own_iface = set(exported_methods()) - {"Get", "GetAll", "Set"}
        self.assertEqual(own_iface - listed, set(),
                         "exported but not reachable through the bus policy")


class VerifyAuthorization(unittest.TestCase):
    """Behavioural: Verify must refuse before it executes anything."""

    def _service(self, authorized):
        svc = object.__new__(fp.Fireproof)
        svc._state = {"last_txn": {}}
        svc._verify_lock = threading.Lock()
        svc._last_verify = None
        svc._authorized = lambda sender, action=None: authorized
        return svc

    def test_unauthorized_caller_is_refused_without_running_the_battery(self):
        ran = []
        original = fp.run_verify
        fp.run_verify = lambda txn: ran.append(txn) or {}
        try:
            svc = self._service(authorized=False)
            failures = []
            svc.Verify(reply=lambda *a: None, error=failures.append,
                       sender=":1.99")
            time.sleep(0.2)   # a thread, had one been started, would have run
            self.assertEqual(ran, [],
                             "the verify battery executed for an unauthorized caller")
            self.assertEqual(len(failures), 1)
            self.assertIsInstance(failures[0], fp.NotAuthorizedError)
        finally:
            fp.run_verify = original

    def test_authorized_caller_still_runs_the_battery(self):
        """The invariant: authorization is added, behaviour is not removed."""
        done = threading.Event()
        original = fp.run_verify
        fp.run_verify = lambda txn: {"verdict": "ok"}
        try:
            svc = self._service(authorized=True)
            got = []

            def reply(payload):
                got.append(payload)
                done.set()
            # The daemon marshals replies through the GLib loop; call directly.
            fp.GLib.idle_add = lambda fn, *a: fn(*a)
            svc.Verify(reply=reply, error=lambda e: done.set(), sender=":1.5")
            done.wait(5)
            self.assertEqual(got, ['{"verdict": "ok"}'])
            self.assertIsNotNone(svc._last_verify,
                                 "the result was not recorded for Inspect()")
        finally:
            fp.run_verify = original

    def test_inspect_reads_without_executing(self):
        ran = []
        original = fp.run_verify
        fp.run_verify = lambda txn: ran.append(txn) or {}
        try:
            svc = self._service(authorized=False)
            svc._last_verify = {"recorded": "2026-09-08T00:00:00Z",
                                "result": {"verdict": "ok"}}
            self.assertIn("verdict", svc.Inspect())
            self.assertEqual(ran, [], "Inspect executed the battery")
        finally:
            fp.run_verify = original


class AnalyzeIsBounded(unittest.TestCase):
    def _service(self):
        svc = object.__new__(fp.Fireproof)
        svc._state = {}
        svc._analyze_guard = threading.Lock()
        svc._analyze_running = False
        svc._analyze_waiters = []
        svc._analysis = None
        svc._analysis_at = 0.0
        svc._notify_badge = lambda: None
        return svc

    def test_concurrent_callers_coalesce_onto_one_run(self):
        """W-21: previously N callers meant N cache-opening threads in root."""
        runs = []
        gate = threading.Event()
        original = fp.build_analysis
        fp.GLib.idle_add = lambda fn, *a: fn(*a)

        def slow(state):
            runs.append(1)
            gate.wait(2)
            return {"update_count": 0, "notify_suppressed": False}
        fp.build_analysis = slow
        try:
            svc = self._service()
            for _ in range(8):
                svc.Analyze(reply=lambda *a: None, error=lambda *a: None)
            time.sleep(0.3)
            self.assertEqual(len(runs), 1,
                             "%d concurrent analyses started" % len(runs))
            gate.set()
            time.sleep(0.3)
        finally:
            fp.build_analysis = original

    def test_fresh_result_is_served_from_cache(self):
        runs = []
        original = fp.build_analysis
        fp.GLib.idle_add = lambda fn, *a: fn(*a)

        def counted(state):
            runs.append(1)
            return {"update_count": 0, "notify_suppressed": False}
        fp.build_analysis = counted
        try:
            svc = self._service()
            svc.Analyze(reply=lambda *a: None, error=lambda *a: None)
            time.sleep(0.3)
            for _ in range(5):
                svc.Analyze(reply=lambda *a: None, error=lambda *a: None)
            time.sleep(0.2)
            self.assertEqual(len(runs), 1,
                             "the cache did not absorb repeat callers")
        finally:
            fp.build_analysis = original


if __name__ == "__main__":
    unittest.main(verbosity=2)
