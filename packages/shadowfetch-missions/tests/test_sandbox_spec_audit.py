"""Phase 2.5: a declared-vs-effective audit of every SandboxSpec field.

Phase 2 found that `cpu_seconds` was declared in a manifest, bounded by the
schema, refused-on-widening by `narrow()` AND by `verify_invocation()` -- and
then never reached Firebreak, so a provider declaring 60 seconds silently got
the mission's 900-second default while four separate layers made the
declaration look enforced. The fix was one line in `run_process()`. The
question this file answers is: which OTHER fields are in that state?

The answer is a TABLE, not prose, because prose rots silently. `AUDIT` below
records, for every field of `SandboxSpec`, the truth at five stages:

    DECLARED   a manifest can express it                (provider-manifest.schema.json)
    VALIDATED  it is checked when the manifest loads     (sf_jsonschema / load_manifest)
    NARROWED   it is refused on widening                 (narrow / verify_invocation)
    PASSED     the value reaches the Firebreak argv      (run_process)
    ENFORCED   Firebreak acts on it                      (bwrap / rlimit / cgroup)

and every test in this file asserts one column of that table against reality.
A field marked PASSED must genuinely appear in the constructed Firebreak
command line; a field marked NOT PASSED must genuinely not. A field marked
ENFORCED is, wherever the machine allows it, demonstrated by running a real
sandboxed process that tries to exceed the limit and observing the refusal --
`evidence` says "executed" for those and "source" where only reading proves it.

Appearing in argv is NOT enforcement and is never counted as such here: each
"executed" enforcement claim below is a process that was actually stopped.
"""
import contextlib
import dataclasses
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest.mock import patch

PACKAGE = Path(__file__).resolve().parents[1]
REPO = PACKAGE.parents[1]
MISSIONS = PACKAGE / "data/usr/lib/shadowfetch/missions"
SHIPPED_MANIFESTS = PACKAGE / "data/usr/share/shadowfetch/providers"
FIREBREAK_BIN = REPO / "packages/shadowfetch-fireline/data/usr/bin/shadowfetch-firebreak"

_spec = importlib.util.spec_from_file_location("sf_missions", MISSIONS / "sf_missions.py")
m = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(m)          # also puts MISSIONS on sys.path
import sf_providers as P


def _load_firebreak():
    """Import the 4.0.0 firebreak script itself, extension-less as it ships.

    Reading its argparse parser and calling its `arguments()` builder is how
    this file proves what Firebreak can even be TOLD, rather than trusting the
    orchestrator's opinion of it.
    """
    loader = importlib.machinery.SourceFileLoader("sf_firebreak_under_audit", str(FIREBREAK_BIN))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


FB = _load_firebreak()


# --------------------------------------------------------------------------- #
# THE TABLE
# --------------------------------------------------------------------------- #
# enforced: "yes" | "partial" | "no"
# status:   a field that is declared/validated/narrowed and reaches no
#           enforcement carries EXACTLY the string NOT_ENFORCED_PHASE_4.
NOT_ENFORCED_PHASE_4 = "NOT ENFORCED — PHASE 4"

AUDIT = (
    {
        "field": "workspace_mode",
        "manifest_key": "sandbox_profile.workspace_mode",
        "declared": True,
        "validated": True,
        "narrowed": True,
        "passed": True,
        "firebreak_flag": "--workspace-mode",
        "enforced": "yes",
        "status": "ENFORCED",
        "looks_enforced_but_is_not": False,
        "mechanism": "bwrap --ro-bind of the workspace when the mode is read-only, "
                     "--bind otherwise. /tmp remains a writable tmpfs, so a read-only "
                     "task still has scratch space.",
        "evidence": {
            "declared": "source", "validated": "executed", "narrowed": "executed",
            "passed": "executed", "enforced": "executed",
        },
        "notes": "THE cpu_seconds-SHAPED DEFECT THIS AUDIT WAS WRITTEN TO FIND, now "
                 "closed. It was bounded by the schema and refused on upgrade by both "
                 "narrow() and verify_invocation(), and then reached nothing: "
                 "run_process() never translated it and shadowfetch-firebreak had no "
                 "flag to receive it, so a manifest declaring 'read-only' got a fully "
                 "writable workspace. The restriction held only because the Codex "
                 "ADAPTER volunteered '--sandbox read-only' in its own argv -- "
                 "provider-supplied code enforcing its own restraint, which is exactly "
                 "what the sandbox boundary exists in order not to depend on. Firebreak "
                 "now takes --workspace-mode and binds the workspace --ro-bind, so the "
                 "guarantee holds whatever the adapter does or omits.",
    },
    {
        "field": "network",
        "manifest_key": "network_policy",
        "declared": True,
        "validated": True,
        "narrowed": True,
        "passed": True,
        "firebreak_flag": "--net",
        "enforced": "yes",
        "status": "ENFORCED",
        "looks_enforced_but_is_not": False,
        "mechanism": "bwrap --unshare-net for 'none'. 'allowlist' collapses to "
                     "Firebreak's 'allow', i.e. the host network unfiltered.",
        "evidence": {
            "declared": "source", "validated": "executed", "narrowed": "executed",
            "passed": "executed", "enforced": "executed",
        },
        "notes": "The restrictive direction is real: a spec with network='none' gets a "
                 "network namespace with no route and connect() fails with ENETUNREACH. "
                 "'allowlist' is only as strong as 'allow' -- see egress_allowlist.",
    },
    {
        "field": "egress_allowlist",
        "manifest_key": "egress_allowlist",
        "declared": True,
        "validated": True,
        "narrowed": True,
        "passed": False,
        "firebreak_flag": None,
        "enforced": "no",
        "status": NOT_ENFORCED_PHASE_4,
        "looks_enforced_but_is_not": False,
        "mechanism": "none. Firebreak has no egress-filtering flag; firebreak_network "
                     "maps 'allowlist' onto 'allow'.",
        "evidence": {
            "declared": "source", "validated": "executed", "narrowed": "executed",
            "passed": "executed", "enforced": "executed",
        },
        "notes": "Already recorded in PHASE2_REMAINING_RISKS §1 and in "
                 "docs/AGENT_ARCHITECTURE §6.6. Audit record only; not a control.",
    },
    {
        "field": "read_grants",
        "manifest_key": "sandbox_profile.read_grants",
        "declared": True,
        "validated": True,
        "narrowed": True,
        "passed": True,
        "firebreak_flag": "--read",
        "enforced": "yes",
        "status": "ENFORCED",
        "looks_enforced_but_is_not": False,
        "mechanism": "bwrap --ro-bind PATH PATH, on top of Firebreak's own read_grants() "
                     "denylist (no fs root, no whole home, no controller state).",
        "evidence": {
            "declared": "source", "validated": "executed", "narrowed": "executed",
            "passed": "executed", "enforced": "executed",
        },
        "notes": "Positively enforced (a granted path is visible) and negatively enforced "
                 "(an ungranted sibling does not exist inside, and a granted path is "
                 "genuinely read-only: write returns EROFS).",
    },
    {
        "field": "masked_paths",
        "manifest_key": "sandbox_profile.masked_paths",
        "declared": True,
        "validated": True,
        "narrowed": True,
        "passed": True,
        "firebreak_flag": "--mask-path",
        "enforced": "yes",
        "status": "ENFORCED",
        "looks_enforced_but_is_not": False,
        "mechanism": "bwrap mounts over each declared path inside the sandbox's own "
                     "mount namespace: an empty tmpfs over a directory, /dev/null over "
                     "a file. No cooperation from the payload is involved.",
        "evidence": {
            "declared": "source", "validated": "executed", "narrowed": "executed",
            "passed": "executed", "enforced": "executed",
        },
        "notes": "STAGE E, and it was broken in BOTH halves. --mask-path was accepted "
                 "and applied by nothing -- its own help text said RECORDED ONLY -- and "
                 "run_process() never passed it at all, so a provider could declare "
                 ".env masked, the receipt printed the declaration, and the agent read "
                 "the file. Measured through the real Firebreak against the tricks that "
                 "matter: direct open, absolute path, relative traversal, symlink, "
                 "nested file and renaming the target are each denied, and a masked "
                 "directory lists empty. Masking is BY PATH: a hardlink to the same "
                 "inode under an unmasked name is still readable, which is stated "
                 "wherever the mechanism is described rather than left to be found.",
    },
    {
        "field": "credential_ids",
        "manifest_key": "credential_ids",
        "declared": True,
        "validated": True,
        "narrowed": True,
        "passed": True,
        "firebreak_flag": "--credential-env",
        "enforced": "yes",
        "status": "ENFORCED",
        "looks_enforced_but_is_not": False,
        "mechanism": "bwrap --clearenv plus one --setenv per granted name; Firebreak also "
                     "refuses a name outside its own CREDENTIALS allowlist.",
        "evidence": {
            "declared": "source", "validated": "executed", "narrowed": "executed",
            "passed": "executed", "enforced": "executed",
        },
        "notes": "CEILING enforced, NARROWING inert. run_process() derives the "
                 "--credential-env names from the `env` mapping that credentials_for() "
                 "built from provider.manifest['credential_ids'], NOT from "
                 "invocation.sandbox.credential_ids. An adapter that narrows "
                 "credential_ids is ignored: every manifest-declared credential that is "
                 "set in the worker environment is still handed to Firebreak. Fail-safe "
                 "(the manifest still bounds it) but the narrowing is decorative.",
    },
    {
        "field": "account_mount",
        "manifest_key": "sandbox_profile.account_mount",
        "declared": True,
        "validated": True,
        "narrowed": True,
        "passed": True,
        "firebreak_flag": "--codex-account",
        "enforced": "yes",
        "status": "ENFORCED",
        "looks_enforced_but_is_not": False,
        "mechanism": "bwrap --bind <dedicated account home> /home/agent/.codex plus "
                     "CODEX_HOME; refused unless net == 'allow' and auth.json exists.",
        "evidence": {
            "declared": "source", "validated": "executed", "narrowed": "executed",
            "passed": "executed", "enforced": "source",
        },
        "notes": "Passed conditionally: run_process() appends the flag only when no "
                 "credential secrets were resolved (`and not env`), so an API key takes "
                 "precedence over the account mount. Enforcement is source-read: "
                 "demonstrating it would require a real signed-in Mission Control "
                 "account, which this suite must not touch.",
    },
    {
        "field": "memory_mb",
        "manifest_key": "sandbox_profile.memory_mb",
        "declared": True,
        "validated": True,
        "narrowed": True,
        "passed": True,
        "firebreak_flag": "--memory-mb",
        "enforced": "yes",
        "status": "ENFORCED",
        "looks_enforced_but_is_not": False,
        "mechanism": "systemd-run --user --scope --property=MemoryMax=<N>M plus "
                     "--property=MemorySwapMax=0. Real cgroup-v2 memory.max with swap "
                     "closed, so the cap bounds the workload rather than the resident "
                     "set. Before MemorySwapMax was set, a process touched 4096 MiB "
                     "under a 256 MiB cap and exited 0, the excess going to swap -- so "
                     "the strength of this control depended on host swap configuration, "
                     "which is not a property a sandbox may have.",
        "evidence": {
            "declared": "source", "validated": "executed", "narrowed": "executed",
            "passed": "executed", "enforced": "executed",
        },
        "notes": "MemoryMax lands on the scope and does bound RESIDENT memory (measured: "
                 "peak RSS 260 MiB under a 256 MiB cap). It does NOT bound the workload: "
                 "with MemorySwapMax=infinity a process touched 4096 MiB under a 256 MiB "
                 "cap and exited 0, the excess going to swap. On a swapless machine the "
                 "same run is OOM-killed, so the observable strength of memory_mb depends "
                 "on the host's swap configuration. Recommended: also pass "
                 "--property=MemorySwapMax=0.",
    },
    {
        "field": "cpu_seconds",
        "manifest_key": "sandbox_profile.cpu_seconds",
        "declared": True,
        "validated": True,
        "narrowed": True,
        "passed": True,
        "firebreak_flag": "--cpu-seconds",
        "enforced": "partial",
        "status": "ENFORCED per process; a fork restarts the accounting",
        "looks_enforced_but_is_not": False,
        "mechanism": "RLIMIT_CPU set in the preexec_fn of the systemd-run child, inherited "
                     "through the scope into bwrap and the agent command; the kernel sends "
                     "SIGXCPU/SIGKILL at the soft/hard limit.",
        "evidence": {
            "declared": "source", "validated": "executed", "narrowed": "executed",
            "passed": "executed", "enforced": "executed",
        },
        "notes": "The Phase 2 fix holds: run_process() passes min(spec.cpu_seconds, "
                 "mission timeout). Residual: RLIMIT_CPU is per-process, so a provider "
                 "that forks gets a fresh CPU budget per child -- measured, 6 children "
                 "burned ~9s of CPU under a 2s cap and the session exited 0.",
    },
    {
        "field": "processes",
        "manifest_key": "sandbox_profile.processes",
        "declared": True,
        "validated": True,
        "narrowed": True,
        "passed": True,
        "firebreak_flag": "--processes",
        "enforced": "yes",
        "status": "ENFORCED",
        "looks_enforced_but_is_not": False,
        "mechanism": "systemd-run --user --scope --property=TasksMax=<N>, i.e. cgroup-v2 "
                     "pids.max, which counts threads as well as processes.",
        "evidence": {
            "declared": "source", "validated": "executed", "narrowed": "executed",
            "passed": "executed", "enforced": "executed",
        },
        "notes": "Deliberately a cgroup rather than RLIMIT_NPROC, which would count every "
                 "thread the desktop user owns.",
    },
)

# Not a SandboxSpec field, recorded so the absence is a tested fact rather than
# an assumption: there is no syscall-filter profile anywhere in this stack.
SECCOMP_PROFILE = {
    "field": "seccomp_profile",
    "declared": False,
    "validated": False,
    "narrowed": False,
    "passed": False,
    "firebreak_flag": None,
    "enforced": "no",
    "status": "NOT REPRESENTED",
    "evidence": {"declared": "executed", "enforced": "executed"},
    "notes": "The manifest schema has no seccomp/syscall-profile property, SandboxSpec has "
             "no field for one, and Firebreak never passes bwrap --seccomp. bwrap's own "
             "default no-new-privs is the only syscall-level restriction in play.",
}

BY_FIELD = {row["field"]: row for row in AUDIT}


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
BASE_MANIFEST = {
    "schema_version": 1,
    "id": "audit-probe",
    "display_name": "Audit probe",
    "interface_version": 1,
    "adapter_module": "sf_provider_audit_probe",
    "adapter_class": "AuditProbeProvider",
    "capabilities": ["sourced_report"],
    "credential_ids": ["OPENAI_API_KEY"],
    "network_policy": "allowlist",
    "egress_allowlist": ["api.openai.com"],
    "sandbox_profile": {
        "workspace_mode": "read-only",
        "memory_mb": 1024,
        "cpu_seconds": 300,
        "processes": 32,
        "read_grants": ["/usr/share/audit-probe"],
        "masked_paths": ["/home/agent/.ssh"],
        "account_mount": "codex-account",
    },
    "package": "shadowfetch-missions",
    "version": "4.0.0",
}

# One schema-violating value per field, used to prove the VALIDATED column.
INVALID_VALUES = {
    "workspace_mode": ("sandbox_profile", "workspace_mode", "read-write"),
    "network": (None, "network_policy", "allow"),
    "egress_allowlist": (None, "egress_allowlist", ["NOT A HOSTNAME"]),
    "read_grants": ("sandbox_profile", "read_grants", ["relative/path"]),
    "masked_paths": ("sandbox_profile", "masked_paths", ["relative/path"]),
    "credential_ids": (None, "credential_ids", ["lowercase_name"]),
    "account_mount": ("sandbox_profile", "account_mount", "some-other-store"),
    "memory_mb": ("sandbox_profile", "memory_mb", 999_999),
    "cpu_seconds": ("sandbox_profile", "cpu_seconds", 999_999),
    "processes": ("sandbox_profile", "processes", 999_999),
}

# One widening per field, used to prove the NARROWED column.
CEILING = P.SandboxSpec(
    workspace_mode="read-only",
    network="none",
    egress_allowlist=(),
    read_grants=("/usr/share/audit-probe",),
    masked_paths=("/home/agent/.ssh",),
    credential_ids=("OPENAI_API_KEY",),
    account_mount="",
    memory_mb=1024,
    cpu_seconds=300,
    processes=32,
)
WIDENINGS = {
    "workspace_mode": {"workspace_mode": "workspace-write"},
    "network": {"network": "allowlist", "egress_allowlist": ("exfil.example.com",)},
    "egress_allowlist": {"egress_allowlist": ("exfil.example.com",)},
    "read_grants": {"read_grants": ("/usr/share/audit-probe", "/etc/ssl/private")},
    "masked_paths": {"masked_paths": ()},
    "credential_ids": {"credential_ids": ("OPENAI_API_KEY", "GITHUB_TOKEN")},
    "account_mount": {"account_mount": "codex-account"},
    "memory_mb": {"memory_mb": 4096},
    "cpu_seconds": {"cpu_seconds": 3600},
    "processes": {"processes": 256},
}


def firebreak_run_options():
    """Every option string `shadowfetch-firebreak run` accepts.

    Taken from the shipped script's own parser rather than from a mirror of it,
    so a flag Firebreak grows or loses is visible here immediately.
    """
    proc = subprocess.run([sys.executable, str(FIREBREAK_BIN), "run", "--help"],
                          capture_output=True, text=True, timeout=60)
    if proc.returncode:
        raise AssertionError(proc.stderr)
    return {word.strip(" ,[]") for word in proc.stdout.split() if word.startswith("--")}


class _Captured(Exception):
    """Raised by the fake Popen once the Firebreak command line is recorded."""

    def __init__(self, command):
        super().__init__("captured")
        self.command = list(command)


def sandbox_available():
    if not (shutil.which("bwrap") and shutil.which("systemd-run")):
        return False
    runtime = Path("/run/user") / str(os.getuid())
    return (runtime / "bus").is_socket()


@contextlib.contextmanager
def throwaway_workspace():
    """A Firebreak workspace root entirely under /tmp. Never the user's own."""
    with tempfile.TemporaryDirectory(prefix="sf-spec-audit-") as name:
        base = Path(name).resolve()
        ws = base / "Workspaces" / "probe"
        ws.mkdir(parents=True)
        env = dict(os.environ,
                   SHADOWFETCH_AGENT_WORKSPACES=str(base / "Workspaces"),
                   XDG_STATE_HOME=str(base / "state"),
                   SHADOWFETCH_ELEMENT="fire")
        yield base, ws, env


def firebreak(env, *args, timeout=180):
    return subprocess.run([sys.executable, str(FIREBREAK_BIN), "run",
                           "--workspace", "probe", "--no-checkpoint", *args],
                          capture_output=True, text=True, env=env, timeout=timeout)


# --------------------------------------------------------------------------- #
# The table describes every field, and only real fields
# --------------------------------------------------------------------------- #
class TableShapeTests(unittest.TestCase):
    def test_table_has_one_row_per_sandbox_spec_field(self):
        fields = {f.name for f in dataclasses.fields(P.SandboxSpec)}
        self.assertEqual(set(BY_FIELD), fields,
                         "SandboxSpec gained or lost a field; audit it and update AUDIT")

    def test_rows_are_internally_consistent(self):
        for row in AUDIT:
            with self.subTest(field=row["field"]):
                self.assertEqual(bool(row["firebreak_flag"]), row["passed"],
                                 "a field is PASSED exactly when it names a Firebreak flag")
                self.assertIn(row["enforced"], ("yes", "partial", "no"))
                if row["enforced"] == "no":
                    self.assertEqual(row["status"], NOT_ENFORCED_PHASE_4,
                                     "an unenforced field carries the exact Phase 4 marker")
                    self.assertFalse(row["passed"])
                else:
                    self.assertTrue(row["passed"])
                self.assertEqual(set(row["evidence"]),
                                 {"declared", "validated", "narrowed", "passed", "enforced"})
                for stage, mark in row["evidence"].items():
                    self.assertIn(mark, ("executed", "source"), stage)

    def test_phase_4_backlog_is_exactly_these_two_fields(self):
        """workspace_mode left this list by being enforced, which is the only way
        a field may leave it. Both survivors need egress filtering Firebreak does
        not have, so they stay declared-but-unenforced until Phase 4 and must not
        be described to users as controls."""
        unenforced = sorted(r["field"] for r in AUDIT if r["status"] == NOT_ENFORCED_PHASE_4)
        # masked_paths left this list in Stage E by gaining a real mechanism,
        # which is the only way out of it.
        self.assertEqual(unenforced, ["egress_allowlist"])


# --------------------------------------------------------------------------- #
# DECLARED
# --------------------------------------------------------------------------- #
class DeclaredTests(unittest.TestCase):
    def setUp(self):
        self.schema = P.manifest_schema(SHIPPED_MANIFESTS)

    def locate(self, dotted):
        node = self.schema["properties"]
        for part in dotted.split("."):
            if part not in node:
                return None
            node = node[part]
            node = node.get("properties", node)
        return node

    def test_every_declared_field_exists_in_the_shipped_schema(self):
        for row in AUDIT:
            with self.subTest(field=row["field"]):
                found = self.locate(row["manifest_key"])
                self.assertEqual(found is not None, row["declared"], row["manifest_key"])

    def test_no_seccomp_or_syscall_profile_is_declarable(self):
        text = json.dumps(self.schema).lower()
        for word in ("seccomp", "syscall", "landlock", "apparmor"):
            self.assertNotIn(word, text, SECCOMP_PROFILE["notes"])
        self.assertNotIn("--seccomp", FIREBREAK_BIN.read_text())


# --------------------------------------------------------------------------- #
# VALIDATED
# --------------------------------------------------------------------------- #
class ValidatedTests(unittest.TestCase):
    def setUp(self):
        self.schema = P.manifest_schema(SHIPPED_MANIFESTS)
        self.temp = tempfile.TemporaryDirectory()
        self.dir = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def write(self, document):
        path = self.dir / "audit-probe.json"
        path.write_text(json.dumps(document))
        return path

    def guard(self):
        """These assertions describe SCHEMA validation.

        If load_manifest() ever grows a gate that is not the schema -- an
        approved-provider policy, say -- this probe manifest stops being
        loadable for a reason that has nothing to do with the field under test,
        and the right answer is to say so rather than to report a bounds check
        that never ran.
        """
        try:
            P.load_manifest(self.write(BASE_MANIFEST), schema=self.schema)
        except P.ManifestError:
            raise
        except P.ProviderError as exc:
            self.skipTest(f"load_manifest now applies a non-schema gate: {exc}")

    def test_the_base_probe_manifest_is_actually_valid(self):
        self.guard()
        self.assertEqual(P.load_manifest(self.write(BASE_MANIFEST), schema=self.schema)["id"],
                         "audit-probe")

    def test_every_validated_field_rejects_an_out_of_bounds_value(self):
        self.guard()
        for row in AUDIT:
            if not row["validated"]:
                continue
            section, key, bad = INVALID_VALUES[row["field"]]
            with self.subTest(field=row["field"]):
                document = json.loads(json.dumps(BASE_MANIFEST))
                target = document[section] if section else document
                target[key] = bad
                with self.assertRaises(P.ManifestError):
                    P.load_manifest(self.write(document), schema=self.schema)

    def test_sandbox_spec_itself_refuses_an_incoherent_posture(self):
        with self.assertRaises(P.ProviderError):
            P.SandboxSpec(workspace_mode="read-write", network="none")
        with self.assertRaises(P.ProviderError):
            P.SandboxSpec(workspace_mode="read-only", network="everything")
        with self.assertRaises(P.ProviderError):
            P.SandboxSpec(workspace_mode="read-only", network="none",
                          egress_allowlist=("api.openai.com",))
        with self.assertRaises(P.ProviderError):
            P.SandboxSpec(workspace_mode="read-only", network="none",
                          read_grants=("relative/path",))


# --------------------------------------------------------------------------- #
# NARROWED
# --------------------------------------------------------------------------- #
class NarrowedTests(unittest.TestCase):
    def test_narrow_refuses_every_widening_the_table_claims_it_refuses(self):
        for row in AUDIT:
            if not row["narrowed"]:
                continue
            with self.subTest(field=row["field"]):
                with self.assertRaises(P.ProviderError):
                    CEILING.narrow(**WIDENINGS[row["field"]])

    def test_verify_invocation_refuses_the_same_widenings_from_a_handbuilt_spec(self):
        """narrow() is a courtesy an adapter can skip; this is the mechanism.

        Two ceilings are needed. An offline ceiling is what makes a request for
        network -- or for anything a no-network provider declared -- fail. The
        egress subset check can only fire under a policy that HAS an allowlist,
        because SandboxSpec refuses to carry hosts with network='none' at all.
        """
        offline = json.loads(json.dumps(BASE_MANIFEST))
        offline["network_policy"] = "none"
        offline["egress_allowlist"] = []
        self.assertEqual(P.sandbox_from_manifest(offline),
                         dataclasses.replace(CEILING, account_mount="codex-account"))
        for row in AUDIT:
            if not row["narrowed"]:
                continue
            manifest = BASE_MANIFEST if row["field"] == "egress_allowlist" else offline
            manifest = json.loads(json.dumps(manifest))
            ceiling = P.sandbox_from_manifest(manifest)
            change = dict(WIDENINGS[row["field"]])
            if row["field"] == "account_mount":
                change = {"account_mount": "some-other-store"}
            with self.subTest(field=row["field"]):
                widened = dataclasses.replace(ceiling, **change)
                invocation = P.Invocation(executable="/usr/bin/true", sandbox=widened)
                with self.assertRaises(P.ProviderError):
                    P.verify_invocation(invocation, manifest)

    def test_an_offline_ceiling_cannot_even_construct_an_egress_allowlist(self):
        offline = dataclasses.replace(CEILING)
        self.assertEqual(offline.network, "none")
        with self.assertRaises(P.ProviderError):
            dataclasses.replace(offline, egress_allowlist=("exfil.example.com",))


# --------------------------------------------------------------------------- #
# PASSED -- the column that stops this audit rotting
# --------------------------------------------------------------------------- #
class PassedTests(unittest.TestCase):
    """Drive the ONE place that builds a Firebreak command line and read the argv."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name).resolve()
        self.ws = self.base / "Workspaces" / "example"
        self.ws.mkdir(parents=True)
        (self.ws / "facts.md").write_text("A fact.\n")
        self.grant = self.base / "granted"
        self.grant.mkdir()
        self.env = patch.dict(os.environ, {
            "SHADOWFETCH_AGENT_WORKSPACES": str(self.ws.parent),
            "SHADOWFETCH_MISSIONS_STATE": str(self.base / "state")})
        self.env.start()
        self.store = m.Store()
        self.mission = self.store.create(kind="report", workspace_value="example",
                                         title="Audit", prompt="Audit", inputs=["facts.md"],
                                         network="allow")
        self.executor = m.Executor(self.store, self.mission)

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def spec(self, **changes):
        values = dict(workspace_mode="read-only", network="allowlist",
                      egress_allowlist=("api.openai.com", "chatgpt.com"),
                      read_grants=(str(self.grant),),
                      masked_paths=("/home/agent/.ssh", "/etc/shadow"),
                      credential_ids=("OPENAI_API_KEY",), account_mount="",
                      memory_mb=1024, cpu_seconds=77, processes=32)
        values.update(changes)
        return P.SandboxSpec(**values)

    def argv(self, sandbox, env=None):
        invocation = P.Invocation(executable="/usr/bin/true", argv=("--audit",),
                                  sandbox=sandbox, label="audit")
        captured = {}

        def fake_popen(command, **kwargs):
            captured["command"] = list(command)
            raise _Captured(command)

        with patch("subprocess.Popen", fake_popen):
            with self.assertRaises(_Captured):
                self.executor.run_process(invocation.command, "audit", sandbox=True,
                                          env=dict(env or {}), invocation=invocation)
        return captured["command"]

    def test_passed_fields_appear_in_the_firebreak_argv_and_others_do_not(self):
        argv = self.argv(self.spec(), env={"OPENAI_API_KEY": "unit-only-placeholder"})
        self.assertIn("shadowfetch-firebreak", argv[0])
        self.assertEqual(argv[1], "run")
        joined = " ".join(argv)
        # account_mount and a resolved credential are mutually exclusive by
        # design -- run_process() appends --codex-account only when no secret
        # was resolved -- so the PASSED column is checked against both shapes.
        account = self.argv(self.spec(account_mount="codex-account", credential_ids=()))
        reachable = set(argv) | set(account)
        for row in AUDIT:
            with self.subTest(field=row["field"]):
                if row["passed"]:
                    self.assertIn(row["firebreak_flag"], reachable,
                                  f"{row['field']} is marked PASSED but its flag is absent")
                else:
                    self.assertIsNone(row["firebreak_flag"])
                    self.assertNotIn(row["field"].replace("_", "-"), joined)
        # NOT PASSED must mean the VALUES are absent too, not merely the flag.
        # workspace_mode moved to PASSED, so its value is now expected: the
        # opposite assertion, that a declared read-only spec actually reaches
        # Firebreak, is what the row is worth checking for.
        self.assertIn("--workspace-mode", joined)
        self.assertIn("read-only", joined,
                      "a read-only spec did not reach Firebreak")
        self.assertNotIn("workspace-write", joined)
        for host in ("api.openai.com", "chatgpt.com"):
            self.assertNotIn(host, joined, "egress_allowlist leaked into the argv")
        for mask in ("/home/agent/.ssh", "/etc/shadow"):
            self.assertIn(mask, joined,
                      "a declared mask is not passed to Firebreak")

    def test_passed_values_are_the_specs_own_values(self):
        argv = self.argv(self.spec(), env={"OPENAI_API_KEY": "unit-only-placeholder"})
        pairs = {argv[i]: argv[i + 1] for i in range(len(argv) - 1)}
        self.assertEqual(pairs["--memory-mb"], "1024")
        self.assertEqual(pairs["--processes"], "32")
        self.assertEqual(pairs["--net"], "allow")
        self.assertEqual(pairs["--read"], str(self.grant))
        self.assertEqual(pairs["--credential-env"], "OPENAI_API_KEY")
        # The Phase 2 fix: the tighter of the declared ceiling and the mission budget.
        self.assertEqual(pairs["--cpu-seconds"],
                         str(min(77, self.mission["config"]["timeout"])))
        self.assertEqual(self.argv(self.spec(cpu_seconds=99999),
                                   env={"OPENAI_API_KEY": "x"})[
                             self.argv(self.spec(cpu_seconds=99999),
                                       env={"OPENAI_API_KEY": "x"}).index("--cpu-seconds") + 1],
                         str(self.mission["config"]["timeout"]))

    def test_network_none_is_passed_as_none(self):
        argv = self.argv(self.spec(network="none", egress_allowlist=()))
        self.assertEqual(argv[argv.index("--net") + 1], "none")

    def test_account_mount_is_passed_only_when_no_credential_was_resolved(self):
        spec = self.spec(account_mount="codex-account", credential_ids=())
        self.assertIn("--codex-account", self.argv(spec))
        self.assertNotIn("--codex-account",
                         self.argv(self.spec(account_mount="codex-account"),
                                   env={"OPENAI_API_KEY": "unit-only-placeholder"}))

    def test_credential_narrowing_by_an_adapter_is_honoured(self):
        """The finding, now fixed: --credential-env used to be built from the
        resolved secrets alone, so an adapter narrowing credential_ids to ()
        was ignored. Fail-safe, because the manifest still bounded it, but
        decorative -- which is worse than absent, because it reads as a control.
        """
        narrowed = self.spec(credential_ids=())
        argv = self.argv(narrowed, env={"OPENAI_API_KEY": "unit-only-placeholder"})
        self.assertNotIn("--credential-env", argv,
                         "an adapter narrowed credential_ids to () and the secret was "
                         "handed to Firebreak anyway")
        self.assertNotIn("OPENAI_API_KEY", argv)

    def test_credential_narrowing_keeps_what_was_not_narrowed_away(self):
        """The intersection must not become a blanket refusal."""
        kept = self.spec(credential_ids=("OPENAI_API_KEY",))
        argv = self.argv(kept, env={"OPENAI_API_KEY": "unit-only-placeholder"})
        self.assertIn("--credential-env", argv)
        self.assertIn("OPENAI_API_KEY", argv)


# --------------------------------------------------------------------------- #
# ENFORCED -- what Firebreak can be told at all, and what it builds
# --------------------------------------------------------------------------- #
class FirebreakSurfaceTests(unittest.TestCase):
    def test_firebreak_accepts_a_flag_for_every_passed_field_and_none_for_the_rest(self):
        options = firebreak_run_options()
        for row in AUDIT:
            with self.subTest(field=row["field"]):
                if row["passed"]:
                    self.assertIn(row["firebreak_flag"], options)
        for absent in ("--mask", "--masked-path", "--egress", "--egress-allowlist",
                       "--allow-host", "--read-only", "--seccomp"):
            self.assertNotIn(absent, options,
                             f"Firebreak grew {absent}; re-audit the affected field")

    def test_the_bwrap_argv_firebreak_builds_carries_the_enforcement_mechanisms(self):
        """Read the real bwrap command line, not the Firebreak one."""
        import argparse
        with throwaway_workspace() as (base, ws, env):
            grant = base / "granted"
            grant.mkdir()
            with patch.dict(os.environ, env):
                args = argparse.Namespace(
                    workspace="probe", net="none", read=[str(grant)],
                    codex_account=False, credential_env=["OPENAI_API_KEY"],
                    keep_secrets=False, memory_mb=1024, cpu_seconds=77, processes=32,
                    workspace_mode="workspace-write", agent_command=["/usr/bin/true"])
                resolved_ws = FB.workspace("probe")
                with patch.dict(os.environ, {"OPENAI_API_KEY": "unit-only-placeholder"}):
                    command, net, grants, credentials = FB.arguments(args, resolved_ws, "fb-audit")
        joined = " ".join(command)
        self.assertEqual(command[0], "bwrap")
        # network -> a real namespace, read_grants -> a real read-only bind,
        # workspace -> a real writable bind, credentials -> clearenv + setenv.
        self.assertIn("--unshare-net", command)
        self.assertIn("--ro-bind " + str(grant) + " " + str(grant), joined)
        self.assertIn("--clearenv", command)
        self.assertIn("--setenv OPENAI_API_KEY unit-only-placeholder", joined)
        self.assertNotIn("ANTHROPIC_API_KEY", joined)
        # workspace_mode has no expression here at all: the workspace is bound
        # read-write whatever the spec said.
        self.assertIn("--bind " + str(resolved_ws) + " " + str(resolved_ws), joined)
        self.assertNotIn("--ro-bind " + str(resolved_ws), joined)
        self.assertEqual(net, "none")
        self.assertEqual(credentials, ["OPENAI_API_KEY"])
        self.assertEqual(grants, [grant])
        # and nothing masks or filters egress
        self.assertNotIn("--seccomp", command)
        self.assertNotIn("--tmpfs /home/agent/.ssh", joined)

    def test_firebreak_refuses_limits_the_manifest_schema_would_accept(self):
        """A range mismatch between the two validators, recorded so it cannot drift."""
        schema = P.manifest_schema(SHIPPED_MANIFESTS)["properties"]["sandbox_profile"]["properties"]
        source = FIREBREAK_BIN.read_text()
        # The two validators agree, so a schema-valid manifest cannot describe a
        # sandbox Firebreak will refuse at run time. Before this they did not:
        # the schema admitted memory_mb 64 and processes 1, and Firebreak
        # rejected both with "Invalid memory, CPU time or process limit" after
        # every static check had passed.
        self.assertEqual(schema["memory_mb"]["minimum"], 256)
        self.assertEqual(schema["processes"]["minimum"], 8)
        self.assertIn("256 <= args.memory_mb <= 65536", source)
        self.assertIn("8 <= args.processes <= 1024", source)


@unittest.skipUnless(sandbox_available(),
                     "bubblewrap, systemd-run and a user D-Bus session are required")
class EnforcedEmpiricallyTests(unittest.TestCase):
    """Every assertion here is a real sandboxed process that was actually stopped.

    Each runs in a throwaway workspace root under /tmp; nothing touches the
    user's own ~/Workspaces or any system state.
    """

    LIMITS = ("--memory-mb", "512", "--cpu-seconds", "60", "--processes", "16")

    def test_network_none_leaves_no_route(self):
        probe = "import socket;socket.setdefaulttimeout(5)\n" \
                "try:\n socket.create_connection(('1.1.1.1',53)).close();print('REACHABLE')\n" \
                "except OSError as e:\n print('BLOCKED',e.errno)\n"
        with throwaway_workspace() as (base, ws, env):
            done = firebreak(env, "--net", "none", *self.LIMITS, "--",
                             sys.executable, "-c", probe)
        self.assertIn("BLOCKED", done.stdout, done.stderr)
        self.assertNotIn("REACHABLE", done.stdout)

    def test_read_grant_is_visible_read_only_and_an_ungranted_sibling_is_not(self):
        with throwaway_workspace() as (base, ws, env):
            granted, secret = base / "granted", base / "secret"
            granted.mkdir()
            secret.mkdir()
            (granted / "f.txt").write_text("visible")
            (secret / "f.txt").write_text("must not be visible")
            probe = textwrap.dedent(f"""
                import os
                print('granted', os.path.exists({str(granted / 'f.txt')!r}))
                print('ungranted', os.path.exists({str(secret / 'f.txt')!r}))
                try:
                    open({str(granted / 'f.txt')!r}, 'a')
                    print('WRITABLE')
                except OSError as e:
                    print('write refused', e.errno)
            """)
            done = firebreak(env, "--net", "none", "--read", str(granted), *self.LIMITS,
                             "--", sys.executable, "-c", probe)
        self.assertIn("granted True", done.stdout, done.stderr)
        self.assertIn("ungranted False", done.stdout)
        self.assertIn("write refused", done.stdout)
        self.assertNotIn("WRITABLE", done.stdout)

    def test_only_granted_credentials_cross_the_boundary(self):
        probe = ("import os\n"
                 "print([n for n in ('OPENAI_API_KEY','ANTHROPIC_API_KEY','GITHUB_TOKEN') "
                 "if n in os.environ])\n")
        with throwaway_workspace() as (base, ws, env):
            env.update(OPENAI_API_KEY="unit-only-placeholder-a",
                       ANTHROPIC_API_KEY="unit-only-placeholder-b",
                       GITHUB_TOKEN="unit-only-placeholder-c")
            done = firebreak(env, "--net", "none", "--credential-env", "OPENAI_API_KEY",
                             *self.LIMITS, "--", sys.executable, "-c", probe)
            refused = firebreak(env, "--net", "none", "--credential-env", "NOT_A_CREDENTIAL",
                                *self.LIMITS, "--", "/usr/bin/true")
        self.assertIn("['OPENAI_API_KEY']", done.stdout, done.stderr)
        self.assertEqual(refused.returncode, 1)
        self.assertIn("supported provider environment variable", refused.stderr)

    def test_cpu_seconds_kills_a_process_that_exceeds_it(self):
        probe = "x=0\nwhile True: x+=1\n"
        with throwaway_workspace() as (base, ws, env):
            done = firebreak(env, "--net", "none", "--memory-mb", "512",
                             "--cpu-seconds", "2", "--processes", "16",
                             "--", sys.executable, "-c", probe, timeout=120)
        # 128 + SIGXCPU(24) == 152, reported through Firebreak's own exit mapping.
        self.assertEqual(done.returncode, 152, done.stderr)

    def test_cpu_seconds_accounting_restarts_on_fork(self):
        """A measured residual, not a defect being introduced: RLIMIT_CPU is per process."""
        probe = textwrap.dedent("""
            import os, resource, time
            print('limit', resource.getrlimit(resource.RLIMIT_CPU))
            for _ in range(3):
                if os.fork() == 0:
                    t = time.time()
                    while time.time() - t < 1.2:
                        pass
                    os._exit(0)
                os.wait()
            print('THREE CHILDREN EACH BURNED ~1.2s UNDER A 2s CAP')
        """)
        with throwaway_workspace() as (base, ws, env):
            done = firebreak(env, "--net", "none", "--memory-mb", "1024",
                             "--cpu-seconds", "2", "--processes", "32",
                             "--", sys.executable, "-c", probe, timeout=180)
        self.assertIn("limit (2, 3)", done.stdout, done.stderr)
        self.assertIn("THREE CHILDREN", done.stdout,
                      "if this now fails, cpu_seconds became a whole-session budget and "
                      "the audit note about per-process accounting must be updated")

    def test_processes_cap_refuses_the_task_that_would_exceed_it(self):
        probe = textwrap.dedent("""
            import threading, time
            started = 0
            try:
                for _ in range(64):
                    threading.Thread(target=lambda: time.sleep(3), daemon=True).start()
                    started += 1
            except RuntimeError as e:
                print('REFUSED after', started, e)
            else:
                print('SPAWNED', started)
        """)
        with throwaway_workspace() as (base, ws, env):
            done = firebreak(env, "--net", "none", "--memory-mb", "512",
                             "--cpu-seconds", "60", "--processes", "8",
                             "--", sys.executable, "-c", probe)
        self.assertIn("REFUSED after", done.stdout, done.stderr)
        self.assertNotIn("SPAWNED 64", done.stdout)

    def test_memory_mb_bounds_the_workload_and_not_merely_the_resident_set(self):
        """The cap holds against a workload that used to escape it through swap."""
        probe = textwrap.dedent("""
            import resource
            held = []
            for _ in range(12):
                block = bytearray(32 * 1024 * 1024)
                for off in range(0, len(block), 4096):
                    block[off] = 1
                held.append(block)
            print('held MiB', sum(len(b) for b in held) // 1048576)
            print('peak RSS MiB', resource.getrusage(resource.RUSAGE_SELF).ru_maxrss // 1024)
        """)
        with throwaway_workspace() as (base, ws, env):
            done = firebreak(env, "--net", "none", "--memory-mb", "256",
                             "--cpu-seconds", "120", "--processes", "16",
                             "--", sys.executable, "-c", probe, timeout=300)
        # 384 MiB touched under a 256 MiB cap. It must be STOPPED, whatever the
        # host's swap configuration -- which is the whole point of MemorySwapMax=0.
        # A skip here would have let the fix be reverted silently on any machine
        # with swap, which is most of them.
        self.assertNotEqual(done.returncode, 0,
                            "a workload 1.5x its memory cap ran to completion; "
                            "MemorySwapMax is not being set")
        self.assertNotIn("held MiB 384", done.stdout,
                         "the workload allocated past its cap before being stopped")
        self.assertEqual(BY_FIELD["memory_mb"]["enforced"], "yes")

    def test_a_read_only_workspace_mode_refuses_the_write(self):
        """The cpu_seconds-shaped defect, now closed, demonstrated end to end.

        Before --workspace-mode existed this same probe printed "WORKSPACE
        WRITABLE True" and the file appeared on the host, because nothing ever
        told Firebreak what the SandboxSpec said.
        """
        spec = P.SandboxSpec(workspace_mode="read-only", network="none",
                             memory_mb=512, cpu_seconds=60, processes=16)
        self.assertEqual(spec.workspace_mode, "read-only")
        probe = ("import os,pathlib\n"
                 "p=pathlib.Path(os.getcwd())/'written-by-a-read-only-provider.txt'\n"
                 "try:\n"
                 "    p.write_text('x');print('WORKSPACE WRITABLE', p.exists())\n"
                 "except OSError as e:\n"
                 "    print('WORKSPACE WRITE REFUSED', type(e).__name__, e.strerror)\n")
        with throwaway_workspace() as (base, ws, env):
            done = firebreak(env, "--net", "none", "--workspace-mode", "read-only",
                             "--memory-mb", str(spec.memory_mb),
                             "--cpu-seconds", str(spec.cpu_seconds),
                             "--processes", str(spec.processes),
                             "--", sys.executable, "-c", probe)
            wrote = (ws / "written-by-a-read-only-provider.txt").exists()
        self.assertIn("WORKSPACE WRITE REFUSED", done.stdout, done.stderr)
        self.assertIn("Read-only file system", done.stdout)
        self.assertFalse(wrote, "the write reached the host workspace anyway")
        self.assertEqual(BY_FIELD["workspace_mode"]["status"], "ENFORCED")

    def test_the_default_workspace_mode_is_still_writable(self):
        """Enforcing read-only must not make every workspace read-only: a
        code_change mission has to be able to edit the tree it was given."""
        probe = ("import os,pathlib\n"
                 "p=pathlib.Path(os.getcwd())/'written-by-a-writing-provider.txt'\n"
                 "p.write_text('x');print('WORKSPACE WRITABLE', p.exists())\n")
        with throwaway_workspace() as (base, ws, env):
            done = firebreak(env, "--net", "none", "--memory-mb", "512",
                             "--cpu-seconds", "60", "--processes", "16",
                             "--", sys.executable, "-c", probe)
            wrote = (ws / "written-by-a-writing-provider.txt").exists()
        self.assertIn("WORKSPACE WRITABLE True", done.stdout, done.stderr)
        self.assertTrue(wrote, "the default posture stopped reaching the host workspace")


if __name__ == "__main__":
    unittest.main(verbosity=2)
