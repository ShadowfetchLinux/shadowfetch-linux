"""One place that decides what a mission is allowed to do.

Before this, policy was scattered: the provider adapter chose a sandbox, the CLI
chose a network flag, the desktop decided which buttons to show, Firebreak
decided what it would accept, and nothing decided whether a human had agreed.
"Is this allowed" had five answers and no owner.

THE DISTINCTION THIS MODULE EXISTS TO KEEP
------------------------------------------
A POLICY DECISION is what the system has decided should happen.
TECHNICAL ENFORCEMENT is what it can actually make happen.

They are not the same, and collapsing them is how a product comes to say "this
action was blocked" about something it merely disapproved of afterwards. Every
Decision therefore carries a mediation map saying, per field, which of these the
system can honestly claim:

  fully_mediated    a mechanism outside our own code applies it, and an attempt
                    to exceed it fails
  partially         applied, with a named residual
  observable_only   we can see it and record it; we cannot stop it
  not_observable    we cannot even see it happen

Phase 4 closes the gaps. Until then a DENY on an observable_only field is a
recorded verdict, not a block, and this module says so rather than letting a
caller assume otherwise.
"""
from __future__ import annotations

import dataclasses
import fnmatch
import json

# Decisions. Deliberately three, not two: "needs a human" is a distinct outcome
# from "no" and merging them would either nag about safe work or silently permit
# unsafe work.
AUTO_ALLOW = "auto_allow"
ESCALATE = "escalate"
DENY = "deny"

FULLY_MEDIATED = "fully_mediated"
PARTIALLY_MEDIATED = "partially_mediated"
OBSERVABLE_ONLY = "observable_only"
NOT_OBSERVABLE = "not_observable"

# The capability matrix the Phase 3 brief asks for. Keyed by the thing a policy
# might want to constrain, not by the SandboxSpec field, because a person asking
# "can you stop it writing outside the workspace" is not asking about bind mounts.
POLICY_MEDIATION = {
    "workspace_write": (FULLY_MEDIATED,
                        "bwrap binds the workspace read-only when the mission "
                        "declares read-only; a write then fails with EROFS"),
    "filesystem_read": (FULLY_MEDIATED,
                        "only declared read grants are bound into the sandbox; "
                        "everything else is simply absent"),
    # "or LAN" was in this string and was FALSE for one posture, measured:
    # with the network on and NO allowlist declared, the sandbox reached the
    # host's own LAN address, the docker bridge and the LAN router.
    # --disable-host-loopback blocks 127.0.0.1 and nothing else; it is the
    # nftables ruleset that puts the LAN out of reach, and that only exists
    # where hosts are declared.
    "network_on_off": (FULLY_MEDIATED,
                       "every posture gets its own network namespace, so the "
                       "host's loopback services and its abstract AF_UNIX "
                       "sockets are unreachable. The LAN is reachable when the "
                       "network is on and no destination is declared -- see "
                       "network_destination, which is the row that narrows it"),
    # PARTIAL, and the word is load-bearing. A declared allowlist becomes a
    # default-DROP nftables ruleset in the sandbox's own network namespace, and
    # that is full mediation. A posture that reaches the network while declaring
    # NO hosts gets a NAT and no ruleset, so it reaches anything -- there is
    # nothing to filter against. The static table cannot know which of those a
    # mission is, so it must not claim the better one; _mediation_for() decides
    # it per mission, where the answer is actually knowable.
    "network_destination": (PARTIALLY_MEDIATED,
                            "with declared hosts: nftables in the sandbox's own "
                            "network namespace, default DROP, permitting only the "
                            "addresses those hosts resolved to at launch -- the "
                            "sandbox never chooses what a name means, resolution "
                            "happens on the host before the namespace is handed "
                            "over. With NO declared hosts and the network on: "
                            "nothing filters destinations at all"),
    "credential_identity": (FULLY_MEDIATED,
                            "bwrap --clearenv then one --setenv per declared "
                            "identity; an undeclared name is not in the environment"),
    "credential_value": (FULLY_MEDIATED,
                         "values are resolved outside the sandbox and injected at "
                         "the boundary; no provider code sees the resolution"),
    "path_masking": (FULLY_MEDIATED,
                     "each declared path is mounted over inside the sandbox's own "
                     "mount namespace -- an empty tmpfs over a directory, "
                     "/dev/null over a file -- and Mission Control passes the "
                     "spec's masks to Firebreak. By PATH: a hardlink to the same "
                     "inode under an unmasked name is still readable"),
    "memory": (FULLY_MEDIATED, "systemd MemoryMax with MemorySwapMax=0"),
    "processes": (FULLY_MEDIATED, "systemd TasksMax"),
    "cpu_time": (PARTIALLY_MEDIATED,
                 "RLIMIT_CPU, which is per-process: a provider that forks gets a "
                 "fresh budget for each child"),
    "executable_identity": (FULLY_MEDIATED,
                            "the program is classified from filesystem ownership "
                            "and refused unless the manifest declared it"),
    # MEDIATED, not observed. This said "no seccomp profile is applied and none
    # is expressible", which was true and is not: Firebreak assembles a
    # classic-BPF program in its own source and hands bwrap --seccomp <fd>, and
    # the kernel answers 46 syscalls with EPERM. Mediation is the right word --
    # the calls are PREVENTED. What remains unobservable is which permitted
    # syscalls a payload makes, and that is a different row from this one.
    "syscalls": (FULLY_MEDIATED,
                 "a classic-BPF seccomp filter applied to every sandbox, 46 "
                 "syscalls denied EPERM, self-tested against the real kernel "
                 "before the run starts and refused rather than degraded if "
                 "the kernel will not take it. WHICH permitted syscalls a "
                 "payload makes is still not observed: this row is about what "
                 "cannot happen, not about what is recorded"),
    "tool_actions_inside_a_turn": (NOT_OBSERVABLE,
                                   "a provider's internal tool calls are visible "
                                   "only if it reports them on its own stream; "
                                   "nothing intercepts them"),
}


# Trust classes this build will execute. Named rather than open-ended: an
# approval policy carries whatever string a human sealed, and an unrecognised
# one must be refused rather than treated as merely unfamiliar.
KNOWN_TRUST = ("distro-managed", "developer", "unknown")


class PolicyError(Exception):
    """A policy input that does not make sense, as opposed to a DENY."""


@dataclasses.dataclass(frozen=True)
class Scope:
    """What a mission needs permission for, and what an approval grants.

    The same shape for both, so "does this approval cover this mission" is a
    containment test rather than a pile of comparisons written twice.
    """

    capability: str = ""
    provider: str = ""
    workspace: str = ""
    network: str = "none"
    credential_ids: tuple = ()
    paths: tuple = ()
    # The destinations the sandbox will be ALLOWED to reach. This was absent
    # while nothing filtered destinations: an approval cannot bind a privilege
    # that does not exist, and naming hosts in a grant would have implied a
    # control the system did not have. Stage C installs a default-DROP ruleset
    # in the sandbox's own network namespace, so the host list became a real
    # privilege -- and an enforced privilege outside the scope is one that can
    # be widened after a human has agreed, which is precisely what
    # attack_approval's egress-widened-after-approval demonstrated.
    egress_hosts: tuple = ()

    @staticmethod
    def _sequence(value, field):
        """A list, or nothing. NEVER a bare string.

        `tuple("corp*")` is `('c','o','r','p','*')`, and `'*'` in that tuple is
        the wildcard that makes an approval cover everything. A scope stored
        with `egress_hosts` as a string -- by a future writer, a hand-edited
        row, a migration -- would therefore widen itself into a grant for every
        destination. The normal path always writes a JSON array, so this is not
        reachable today; the deserialiser of an approval scope is the wrong
        place to be relaxed about it.
        """
        if value is None:
            return ()
        if isinstance(value, str) or not isinstance(value, (list, tuple)):
            raise ValueError(
                f"approval scope field {field!r} must be a list, not "
                f"{type(value).__name__}")
        return tuple(value)

    @staticmethod
    def from_json(blob):
        data = json.loads(blob) if isinstance(blob, str) else dict(blob or {})
        return Scope(
            capability=data.get("capability") or "",
            provider=data.get("provider") or "",
            workspace=data.get("workspace") or "",
            network=data.get("network") or "none",
            credential_ids=Scope._sequence(data.get("credential_ids"),
                                           "credential_ids"),
            paths=Scope._sequence(data.get("paths"), "paths"),
            # An approval stored before this field existed reads as no hosts,
            # so it covers a mission that wants none and stops covering one
            # that wants any. That direction is deliberate: the alternative is
            # honouring an old grant for destinations nobody was shown.
            egress_hosts=Scope._sequence(data.get("egress_hosts"),
                                         "egress_hosts"))

    def to_json(self):
        return json.dumps(dataclasses.asdict(self), sort_keys=True)


# Network breadth. A grant for a broader posture covers a narrower request; the
# reverse is what an escalation attempt looks like.
NETWORK_RANK = {"none": 0, "allowlist": 1, "allow": 2}


def _covers_value(granted, requested, *, field):
    """One field of a containment test, returning the reason it failed."""
    if not granted:
        return f"the approval does not name a {field}"
    if granted == requested:
        return None
    # A wildcard is an explicit widening a human typed, not an accident.
    if granted == "*" or fnmatch.fnmatchcase(requested, granted):
        return None
    return f"approved for {field} {granted!r}, this mission wants {requested!r}"


def approval_covers(granted: Scope, requested: Scope):
    """(covered, reason). An approval must cover the request exactly or be a
    legitimate superset -- never merely overlap it."""
    for field in ("capability", "provider", "workspace"):
        problem = _covers_value(getattr(granted, field), getattr(requested, field),
                                field=field)
        if problem:
            return False, problem

    want = NETWORK_RANK.get(requested.network, 99)
    have = NETWORK_RANK.get(granted.network, -1)
    if want > have:
        return False, (f"approved for network {granted.network!r}, this mission "
                       f"wants {requested.network!r}")

    extra = sorted(set(requested.credential_ids) - set(granted.credential_ids))
    if extra:
        return False, ("this mission wants credential identities the approval does "
                       "not cover: " + ", ".join(extra))

    for path in requested.paths:
        if not any(path == allowed or path.startswith(allowed.rstrip("/") + "/")
                   or allowed == "*" for allowed in granted.paths):
            return False, f"this mission wants read access to {path}, which is not approved"

    # Destinations, by exact name. No prefix rule and no suffix rule: 'evil.com'
    # ends with 'l.com' and 'api.example.com.attacker.net' starts with
    # 'api.example.com', and either rule would hand an attacker the widening
    # this check exists to stop. '*' is the one wildcard, because a human types
    # it deliberately.
    if "*" not in granted.egress_hosts:
        extra = sorted(set(requested.egress_hosts) - set(granted.egress_hosts))
        if extra:
            return False, ("this mission may reach destinations the approval does "
                           "not cover: " + ", ".join(extra))
    return True, None


@dataclasses.dataclass(frozen=True)
class Decision:
    outcome: str
    reasons: tuple
    scope: Scope
    mediation: dict
    # Fields the decision RELIES on that the system cannot actually enforce.
    # Named separately so a caller cannot present the decision as protection
    # without also seeing this.
    advisory_fields: tuple = ()

    @property
    def needs_approval(self):
        return self.outcome == ESCALATE

    def as_dict(self):
        return {"outcome": self.outcome, "reasons": list(self.reasons),
                "scope": dataclasses.asdict(self.scope),
                "mediation": self.mediation,
                "advisory_fields": list(self.advisory_fields)}


class PolicyEngine:
    """The single decision point.

    It is deliberately small and deliberately data-driven: the rules below are
    the whole policy, and adding a provider or a capability does not change
    them. There is no provider name anywhere in this file.
    """

    def __init__(self, *, require_approval_for_network=True,
                 require_approval_for_credentials=True,
                 require_approval_for_workspace_write=False):
        self.require_approval_for_network = require_approval_for_network
        self.require_approval_for_credentials = require_approval_for_credentials
        self.require_approval_for_workspace_write = require_approval_for_workspace_write

    def scope_for(self, *, capability, provider_id, workspace, sandbox):
        return Scope(capability=capability, provider=provider_id,
                     workspace=str(workspace),
                     network=getattr(sandbox, "network", "none") or "none",
                     credential_ids=tuple(getattr(sandbox, "credential_ids", ()) or ()),
                     paths=tuple(str(p) for p in getattr(sandbox, "read_grants", ()) or ()),
                     egress_hosts=tuple(
                         str(h) for h in getattr(sandbox, "egress_allowlist", ()) or ()))

    def evaluate(self, *, capability, provider_id, workspace, sandbox,
                 provider_trust="unknown"):
        """What should happen, and how much of it we can actually make happen.

        Note what is NOT here: whether the provider is installed or
        authenticated. That is READINESS, and the engine already refuses it at
        execution with a message that tells a person what to do. A policy DENY
        would replace "run shadowfetch-mission-account login" with "policy
        refuses this mission", which is true and useless.
        """
        scope = self.scope_for(capability=capability, provider_id=provider_id,
                               workspace=workspace, sandbox=sandbox)
        reasons = []
        outcome = AUTO_ALLOW

        if provider_trust not in KNOWN_TRUST:
            return self._decide(DENY,
                                (f"provider trust {provider_trust!r} is not one this "
                                 "build will execute",), scope, sandbox)

        if self.require_approval_for_network and scope.network != "none":
            outcome = ESCALATE
            reasons.append(
                f"this mission requests network access ({scope.network}), which "
                "reaches the internet from inside the sandbox")

        if self.require_approval_for_credentials and scope.credential_ids:
            outcome = ESCALATE
            reasons.append(
                "this mission is given credential identities: "
                + ", ".join(sorted(scope.credential_ids)))

        writes = getattr(sandbox, "workspace_mode", "workspace-write") != "read-only"
        if self.require_approval_for_workspace_write and writes:
            outcome = ESCALATE
            reasons.append("this mission may modify the workspace")

        if outcome == AUTO_ALLOW:
            reasons.append(
                "offline, no credentials, and bounded by an enforced sandbox")

        return self._decide(outcome, tuple(reasons), scope, sandbox)

    def _decide(self, outcome, reasons, scope, sandbox=None):
        """The ONLY place a Decision is built.

        Every path computes advisory_fields, including DENY. A Decision that
        skipped it returned an empty tuple, and a caller rendering "no unenforced
        controls" from an empty list then printed an affirmative enforcement
        claim about a decision that had never looked. Two constructors for one
        type is how a field comes to be optional in practice while looking
        required in the dataclass.
        """
        mediation = self._mediation_for(scope, sandbox)
        advisory = tuple(sorted(
            name for name, entry in mediation.items()
            if entry["mediation"] in (OBSERVABLE_ONLY, NOT_OBSERVABLE)
            and entry.get("relied_on")))
        return Decision(outcome, tuple(reasons), scope, mediation, advisory)

    def _mediation_for(self, scope, sandbox=None):
        """The matrix, annotated with whether THIS mission relies on each row.

        A mission with no egress allowlist is not relying on egress filtering,
        so reporting it as an unenforced control it depends on would be noise --
        and noise is how real caveats get ignored.
        """
        result = {}
        for name, (level, mechanism) in POLICY_MEDIATION.items():
            relied_on = False
            if name == "network_destination":
                # ANY posture that is not "none" reaches the host network, so the
                # destination caveat applies to all of them. Testing for the
                # exact string "allowlist" meant a broader posture escalated for
                # network access and then dropped the caveat.
                relied_on = scope.network != "none"
                # And now the level itself, because it is knowable HERE and not
                # in the static table. Declared hosts are filtered; the same
                # posture with no hosts is a NAT and no ruleset, which is the
                # honest observable_only -- the destinations are recorded in the
                # session and stopped by nothing.
                hosts = tuple(getattr(sandbox, "egress_allowlist", ()) or ())
                if not relied_on:
                    # Fully mediated by absence: no NAT is attached, so every
                    # destination is unreachable. A weaker word here would read
                    # as a gap on the most contained posture there is.
                    level = FULLY_MEDIATED
                    mechanism = ("the sandbox has its own network namespace and "
                                 "no NAT was attached to it, so no destination "
                                 "is reachable at all")
                elif hosts:
                    level = FULLY_MEDIATED
                    mechanism = ("nftables in the sandbox's own network "
                                 "namespace, default DROP, permitting only the "
                                 "addresses these declared hosts resolved to at "
                                 "launch: " + ", ".join(sorted(hosts)))
                else:
                    level = OBSERVABLE_ONLY
                    mechanism = ("the network is on and NO destination was "
                                 "declared, so a NAT is attached and no ruleset "
                                 "is installed: the sandbox reaches anything the "
                                 "host can reach. The session records what was "
                                 "asked for; nothing stops it")
            elif name == "path_masking":
                # This used to be hard-coded False with a comment saying the
                # caller would set it. No caller did, so a mission declaring
                # masks was never told masking reaches nothing -- on the one
                # surface built to disclose that.
                relied_on = bool(getattr(sandbox, "masked_paths", None))
            elif name == "tool_actions_inside_a_turn":
                relied_on = True            # every provider turn relies on this
            elif name == "syscalls":
                relied_on = True
            result[name] = {"mediation": level, "mechanism": mechanism,
                            "relied_on": relied_on}
        return result

    @staticmethod
    def capability_matrix():
        """For documentation and the UI: what this system can and cannot make
        happen, independent of any particular mission."""
        return {name: {"mediation": level, "mechanism": mechanism}
                for name, (level, mechanism) in POLICY_MEDIATION.items()}
