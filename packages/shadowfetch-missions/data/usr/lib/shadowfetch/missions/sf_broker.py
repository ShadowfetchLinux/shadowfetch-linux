"""Stage D: the credential broker, missions half.

WHAT THIS REPLACES, AND WHAT IT DOES NOT
----------------------------------------
Today a granted credential reaches the sandbox as an ENVIRONMENT VALUE. The
boundary resolves the declared identity on the host and Firebreak passes it with
`bwrap --clearenv --setenv NAME <value>` on the sandbox's init process. The
claude manifest says so out loud, and the sentence is exact:

    the credential VALUE ... does reach the sandbox as an environment value,
    because no credential broker exists yet, so an agent that runs a shell
    inside the sandbox can read it.

An environment value has four properties that make it the weakest possible
delivery. It is AMBIENT (every descendant of the init process inherits it, at
any depth, without asking). It is PERSISTENT (it is readable for the whole life
of the sandbox, not only at the moment the agent needs it). It is UNLIMITED (it
can be read any number of times). And it is SILENT (nothing anywhere records
that it was read, so a theft and a normal start-up are indistinguishable after
the fact).

This module removes three of those four for the sandbox, and it does not remove
the fourth. Read that again before writing a claim about it:

    AMBIENT      -> addressed. The value is never placed in the sandbox's
                    environment at all. It lives in the broker's address space,
                    in a process that is in a different mount namespace and is
                    not even VISIBLE in the sandbox's PID namespace (Firebreak
                    runs bwrap with --unshare-pid), so it cannot be read out of
                    /proc and cannot be ptraced.
    PERSISTENT   -> addressed. A grant carries an expiry checked on the
                    MONOTONIC clock, and is revoked when the mission ends. After
                    that the socket is gone and the value is zeroed.
    UNLIMITED    -> addressed. A grant carries max_issues, and the shipped
                    default is 1. The second request for the same identity in
                    the same session is refused, whoever makes it.
    SILENT       -> NOT addressed by hiding anything; addressed by recording.
                    Every request that reached a DECISION -- issued or refused,
                    and that is every request that arrived complete and on time
                    -- appends a hash-chained record naming who asked, for which
                    identity, when, and what the broker answered, mirrored to
                    journald. Refusals decided by how a CONNECTION behaved
                    rather than by what it asked for (a flood of connections
                    that never finish a request) are recorded first-in-full and
                    then as one counted summary per second: see
                    FLOOD_RECORD_WINDOW for why one fsync per connection would
                    hand a flood a second target.

WHAT AN ATTACKER MUST NOW DO THAT THEY DID NOT HAVE TO DO BEFORE
----------------------------------------------------------------
Before: run `env`. One command, no evidence, any time during the run, any
number of times.

After: find the endpoint socket in the one granted directory, present a valid
ticket for THIS session and THIS identity, and BE FIRST, because the first issue
is the only issue. Every one of those attempts -- the winning one and the losing
ones -- is on the audit chain with the peer's pid, and the loser's failure is
visible to the person running the mission because their agent could not
authenticate.

Read "be first" narrowly. It does NOT mean the attacker must outrun a fair race
it might lose; an attacker sharing the sandbox holds the same ticket as the
consumer and can simply ask before the consumer gets round to it. What it now
excludes -- and did not, in the first version of this file -- is REMOVING the
other runner. That version took a handler slot at accept() and read the request
inside it, so 24 connections that never sent a newline held all sixteen slots
for two seconds at a time, the consumer's one call was answered 'overloaded' as
a verdict, and the attacker released the flood and redeemed at leisure. That is
not winning a race, it is evicting the other party, and it made the broker
strictly worse than the environment delivery it replaces, in which the consumer
always gets its key. It is fixed in two places, both measured in
tests/test_credential_broker.py::TheFloodMustNotEvictTheConsumer: an incomplete
connection now holds no decision slot at all, and an 'overloaded' answer is a
"not now" the shipped client retries inside its own deadline.

WHAT THE BROKER COSTS THAT THE ENVIRONMENT DID NOT
--------------------------------------------------
An environment value cannot fail to be delivered: it is in the process's
environment before the process runs. A broker is a LIVE DEPENDENCY. If the
broker is gone, wedged, or its endpoint was never bound, the consumer gets no
credential and the mission cannot authenticate. A flood can no longer cause
that -- measured above -- but a bug, a crash or an unbindable endpoint can, and
that is an availability cost the environment does not have. Two things make it
an acceptable one, and neither is an accident: the failure is LOUD (the consumer
cannot authenticate, and every refusal is on the chain), and it cannot turn into
a theft, because a refusal never spends the grant. See
BROKER_CLAIMS["broker_availability"].

WHAT IS STILL READABLE. DO NOT LOSE THIS PARAGRAPH.
---------------------------------------------------
If the agent can ASK the broker for the token, the agent still GETS the token.
A broker that hands over a value cannot be a barrier against the process it
hands the value to. Concretely, for a provider like the Claude Code CLI whose
consumer reads its key from its own environment:

  * whichever process redeems the ticket holds the value, and if that process
    is the agent, every shell the agent starts inherits it from there. The
    broker has moved the exposure from "every process in the sandbox, for the
    whole run, unrecorded" to "the consumer's own process tree, from redemption
    onwards, with the redemption recorded" -- which is a real narrowing and is
    NOT the same thing as unreachable;
  * the ticket itself is carried into the sandbox and is readable. That is
    deliberate: a ticket is not a credential. It is single-use, session-bound,
    identity-bound and expiring, and reading a spent one buys nothing.

The ONLY shape that removes the value from the sandbox entirely is a PROXYING
broker, which terminates the provider's protocol itself so the secret never
crosses the boundary in any form. That is not what this is. See
DELIVERY_ALTERNATIVES below for what it would cost, measured rather than
guessed.

TRANSPORT
---------
One AF_UNIX SOCK_STREAM socket per mission session, in a directory that contains
that socket and nothing else. AF_UNIX is addressed by filesystem path rather
than by network namespace, so the socket is reachable from a sandbox with no
interfaces at all -- the same property the localmodel provider already relies
on, proved on this kernel in tests/test_localmodel_transport.py, and re-proved
against THIS socket in tests/test_credential_broker.py and
tools/probes/stage_d_broker.py. Nothing here needs the sandbox to have a
network, and nothing here gives it one.

The DIRECTORY is what gets granted, which is exactly why the audit log lives
somewhere else: putting it beside the socket would bind-mount the record of the
theft into the reach of the thief.

WHERE THE ENDPOINT LIVES, AND WHY THAT IS NOT A DETAIL
------------------------------------------------------
The binding mechanism is Firebreak's existing `--read` grant and no new one is
needed -- but that is a claim about read_grants() in
packages/shadowfetch-fireline/data/usr/bin/shadowfetch-firebreak, and it was
FALSE as shipped. read_grants() reserves /run, the endpoint root was
/run/user/<uid>/shadowfetch-broker, and so every endpoint this module created by
default was refused:

    read_grants(/run/user/1000/shadowfetch-broker/<hash>)
        -> Error: Read grant overlaps protected sandbox/controller storage
    read_grants(~/.local/state/shadowfetch/broker/<hash>)
        -> accepted

Nothing caught it because the tests and the probe both passed a /tmp root and
the probe hand-rolled its own --ro-bind instead of going through read_grants().
The endpoint therefore lives under the user's own state tree now (see
default_endpoint_root() for why an exception in read_grants() was the wrong
trade), and BOTH the suite and tools/probes/stage_d_broker.py call the real
read_grants() on the real default path. A claim about another program's
behaviour is measured against that program or it is not measured.

WHAT NO EXECUTABLE HERE DECIDES
-------------------------------
This module runs no external program. The one program the audit path depends on
is journalctl, which sf_audit resolves by absolute path with a pinned child
environment, for the reason recorded there: a normal desktop uid controls PATH,
and a shadowed journalctl turned a truncated log into a clean bill of health.
The endpoint root and the audit root are likewise CONSTRUCTED -- from getuid()
and from the passwd entry -- rather than read from XDG_RUNTIME_DIR, XDG_STATE_HOME
or $HOME. An environment variable choosing where a credential socket lives, or
where a security record is written, is the same defect class as an environment
variable choosing which journalctl answers. $HOME did choose the audit location
until it was fixed, and nothing recorded that it had; a caller may still choose
that location deliberately through the API, and BrokerAudit writes that choice
into the chain itself.

NOT WIRED YET, AND NOT CLAIMED
------------------------------
Nothing in the shipped orchestrator calls this yet, and Firebreak still passes
--setenv. Binding the endpoint into the sandbox, dropping the --setenv, and the
manifest key that selects a delivery mode are all outside this package and are
reported as blocked rather than half-done. Until they land, the delivery a
mission actually gets is "environment", which is what
sf_providers.credential_delivery() returns for every shipped manifest.
"""
from __future__ import annotations

import collections
import contextlib
import dataclasses
import datetime
import hashlib
import hmac
import json
import os
import pwd
import secrets
import selectors
import socket
import stat
import struct
import sys
import threading
import time
from pathlib import Path

try:
    import sf_audit
except ImportError:  # source tree
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import sf_audit

try:
    import sf_redact
except ImportError:  # source tree
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import sf_redact


__all__ = [
    "PROTOCOL_VERSION", "GENESIS", "BrokerError", "LISTEN_BACKLOG",
    "Refusal", "REFUSAL_CODES", "Grant", "Peer",
    "BrokerAudit", "CredentialBroker",
    "DELIVERY_ALTERNATIVES", "BROKER_CLAIMS", "UNGRANTABLE_PREFIXES",
    "default_endpoint_root", "default_audit_root", "endpoint_directory_name",
    "passwd_home", "redeem",
]

PROTOCOL_VERSION = 1
"""Wire version. A request that does not carry exactly this is refused rather
than interpreted: a broker that guesses at an unknown protocol is a broker that
can be talked into answering a question it did not understand."""

GENESIS = "0" * 64

# A request is one line of JSON. Both bounds are enforced before parsing,
# because the parser is the thing being protected.
MAX_REQUEST_BYTES = 4096
REQUEST_DEADLINE = 2.0
"""Wall-clock seconds a single connection may take from accept to answer. A
per-recv timeout alone does not bound a caller that dribbles one byte at a
time -- the same defect the localmodel probe found in its own reader -- so the
deadline is what is actually checked."""

REPLY_TIMEOUT = 0.5
"""How long a write of one answer may take before it is abandoned. Refusals are
written from the serving thread, so a caller that never reads its answer would
otherwise be able to hold that thread by leaving its receive buffer full."""

MAX_CONCURRENT_REQUESTS = 16
"""DECISIONS taken at once, which is not the same as connections held at once.

It used to be connections, and the difference was the whole of a denial of
service. A slot was taken at accept() and released after the request had been
READ, so a caller that connected and never finished a line held one for the full
REQUEST_DEADLINE; 24 of those held all sixteen, and the legitimate consumer's
single call was answered 'overloaded' while the attacker waited, released the
flood and redeemed. A slot is now taken only when a COMPLETE request is in hand,
and what it bounds is the work of deciding -- dictionary lookups under a lock,
plus whatever an approver or a value_factory does, both of which need a valid
ticket to reach. Nothing an unauthenticated caller does can occupy one."""

MAX_PENDING_CONNECTIONS = 256
"""Accepted connections that have not yet finished sending a request.

The resource an incomplete connection costs is now a file descriptor and at most
MAX_REQUEST_BYTES of buffer, so the cap is about file descriptors rather than
about work. Above it somebody has to be dropped, and it is the STALEST
connection -- the one that has been failing to finish for longest -- never the
one that just arrived. Dropping the newest would refuse the legitimate consumer
in order to keep serving the flood, which is the eviction this cap exists to
prevent."""

FLOOD_RECORD_WINDOW = 1.0
FLOOD_PEER_SAMPLE = 8
"""How a burst of identical pre-decision refusals is recorded: the first in
full, then one summary per window carrying the count and up to
FLOOD_PEER_SAMPLE peer pids. One fsync'd, journald-mirrored record per
connection would let a flood aim itself at the recorder, and through it at the
loop that has to answer the consumer."""

LISTEN_BACKLOG = 128
"""How many connections the KERNEL will queue, which is a different question
from how many the broker serves at once, and conflating the two was a real
denial of service.

Measured: with the backlog set to MAX_CONCURRENT_REQUESTS, 24 simultaneous
redemptions produced one issue, eighteen honest 'replayed' refusals, one
'overloaded' -- and four callers that got

    BlockingIOError: [Errno 11] Resource temporarily unavailable

out of connect() and never reached the broker at all. AF_UNIX connect() returns
EAGAIN rather than ECONNREFUSED when the backlog is full (unix(7)), so those
four were not refused, they were dropped BEFORE accept(), which means no audit
record and no answer. A payload flooding the endpoint could therefore stop the
legitimate consumer from ever connecting, silently. The backlog is cheap -- a
queued connection costs a kernel struct, not a thread -- so it is set far above
the handler cap, and redeem() additionally retries EAGAIN within its own
deadline so the shipped client is correct even under a flood that exceeds any
backlog."""

DEFAULT_MAX_ISSUES = 1
DEFAULT_TTL_SECONDS = 3600

MAX_TOMBSTONES = 256
"""How many closed grants are remembered, so that a ticket presented AFTER the
mission ended is recognised as that rather than as a random guess.

Without them, close_grant() simply forgot the grant and a post-mission
redemption was audited as unknown_ticket -- identical in the record to someone
typing hex at the socket. That destroyed the signal the operator most wants: a
payload still trying to spend a credential after its mission was over. The
CALLER is still told unknown_ticket, in the same words, because telling it
apart would turn the broker into an oracle for grant lifetimes; only the audit
knows the difference. Bounded so a long-lived worker does not accumulate one
entry per mission forever; the oldest is dropped first."""


class BrokerError(Exception):
    """The broker could not be set up. Shown to a person, never to the sandbox."""


class Refusal:
    """Why the broker said no.

    These are the vocabulary of the audit record, so they are plain strings with
    a stable spelling rather than an Enum, for the same reason Capability is.
    Every one of them has an adversarial test in
    tests/test_credential_broker.py; a code with no test is a refusal path
    nobody has proved exists.
    """

    MALFORMED = "malformed"                    # not one bounded line of JSON v1
    UNKNOWN_TICKET = "unknown_ticket"          # no grant answers to this ticket
    WRONG_SESSION = "wrong_session"            # valid ticket, other session's socket
    IDENTITY_NOT_GRANTED = "identity_not_granted"
    REPLAYED = "replayed"                      # issues exhausted
    EXPIRED = "expired"
    REVOKED = "revoked"                        # the mission ended
    PEER_REFUSED = "peer_refused"              # a different uid on the host
    NOT_APPROVED = "not_approved"              # a per-request approver said no
    MINT_FAILED = "mint_failed"                # short-lived credential could not be minted
    OVERLOADED = "overloaded"                  # more concurrent callers than the cap


REFUSAL_CODES = tuple(sorted(
    value for name, value in vars(Refusal).items()
    if name.isupper() and isinstance(value, str)))


# --------------------------------------------------------------------------- #
# The alternatives, and what each one costs. Written down because the choice
# between them is the whole design decision, and a reader who only sees the
# thing that was built cannot tell whether the others were considered.
# --------------------------------------------------------------------------- #
DELIVERY_ALTERNATIVES = {
    "environment": {
        "value_enters_sandbox": True,
        "built": False,
        "status": "what ships today",
        "removes_residual": False,
        "cost": "none; it is the current behaviour",
        "why_not": "ambient, persistent, unlimited and silent. Every property "
                   "that makes a secret cheap to steal, at once.",
    },
    "broker-value": {
        "value_enters_sandbox": True,
        "built": True,
        "status": "BUILT HERE, not wired",
        "removes_residual": False,
        "cost": "this module, one endpoint directory per session bound into the "
                "sandbox, and a redeeming shim inside the sandbox for any "
                "consumer that reads its credential from its own environment.",
        "why": "it is the only option that is buildable entirely inside this "
               "package, it costs no provider-protocol knowledge, and it "
               "converts an unrecorded ambient read into a single recorded, "
               "refusable, race-losable event.",
        "does_not_buy": "the agent can still ask, and what it asks for it gets.",
        "also_costs": "an availability dependency the environment does not "
                      "have. A value that is already in the process's "
                      "environment cannot fail to arrive; a value that has to "
                      "be asked for can. A flood cannot cause that any more "
                      "-- an incomplete connection holds no handler slot, and "
                      "'overloaded' is retried by the client -- but a broker "
                      "that is not running, or an endpoint that was never "
                      "bound, means the mission cannot authenticate. The "
                      "failure is loud and recorded, and a refusal never "
                      "spends the grant, so it cannot become a theft.",
    },
    "broker-proxy": {
        "value_enters_sandbox": False,
        "built": False,
        "status": "the only shape that removes the residual",
        "removes_residual": True,
        "cost": "the broker must terminate each provider's protocol. For the "
                "shipped cloud CLI that means: an HTTP listener the sandbox can "
                "reach (the CLI takes a base URL from its environment as an "
                "http(s) URL, and cannot be pointed at an AF_UNIX path, so this "
                "needs a TCP listener inside the sandbox's own network "
                "namespace -- Firebreak territory, not this package), a "
                "request-forwarding path that adds the Authorization header on "
                "the host side, and a per-provider allowlist of methods and "
                "paths, or the proxy is an open relay to the vendor API with "
                "the user's key on it. It also changes the egress story in the "
                "right direction: the sandbox could then be network 'none', "
                "because the only thing talking to the vendor is the broker.",
        "why_not_now": "it needs the Firebreak side, a manifest key, and "
                       "per-provider protocol code -- three things this stage "
                       "was told not to touch -- and half of it would be worse "
                       "than none of it.",
    },
    "short-lived": {
        "value_enters_sandbox": True,
        "built": "seam only",
        "status": "supported by this module wherever the identity supports it",
        "removes_residual": False,
        "cost": "an exchange endpoint per identity. open_grant(value_factory=) "
                "mints a fresh value per issue, so a credential that CAN be "
                "made short-lived already has its seam here. No shipped "
                "manifest declares one, and the identity the claude manifest "
                "declares is a long-lived API key with no public exchange "
                "endpoint, so for that provider this is not_applicable rather "
                "than not_done. It IS applicable to several identities "
                "Firebreak already accepts -- session tokens and installation "
                "tokens are exchangeable by construction.",
    },
    "per-request-approval": {
        "value_enters_sandbox": True,
        "built": True,
        "status": "supported: open_grant(approver=)",
        "removes_residual": False,
        "cost": "a person, present, for every request. A batch mission has "
                "nobody watching, so an approver that blocks on a human turns "
                "an unattended run into a hang.",
        "why_default_is_not_this": "max_issues=1 is the unattended "
                                   "approximation of it: the first request is "
                                   "allowed and every later one is refused, "
                                   "which is the answer a person would have "
                                   "given without needing to be there.",
    },
}


# The claims-matrix row this stage is entitled to, in the vocabulary the
# codebase already uses. Machine-readable so a receipt, a UI and a review read
# the same words, and deliberately NOT merged into
# sf_providers.SANDBOX_ENFORCEMENT: that table is cross-checked field-by-field
# against the audited table in tests/test_sandbox_spec_audit.py, which is not
# this stage's file, and adding a row to one side alone would fail that check
# rather than record anything.
BROKER_CLAIMS = {
    "credential_delivery": {
        "status": "not_enforced",
        "mechanism": "nothing yet. The orchestrator does not construct a broker "
                     "and Firebreak still passes --setenv, so the delivery a "
                     "mission gets today is the environment.",
        "note": "This row is about the SHIPPED PATH, not about this module. It "
                "goes to 'partial' -- never to 'enforced' -- on the day "
                "Firebreak binds the endpoint and drops the --setenv, because "
                "the value would still reach the sandbox, just once and on the "
                "record. What is left to do for that is now wiring only: the "
                "endpoint is a directory read_grants() accepts, proved against "
                "read_grants() itself, so no change to the grant mechanism is "
                "needed.",
    },
    "broker_single_issue": {
        "status": "enforced",
        "mechanism": "the issue counter is incremented under a lock held across "
                     "the whole decision, in a process the sandbox cannot see "
                     "or ptrace (bwrap --unshare-pid), so the second request "
                     "for a grant is refused whoever makes it and whenever.",
        "measured": "tests/test_credential_broker.py ReplayAndRace: 24 threads "
                    "redeem one ticket at once; exactly one issue is returned "
                    "and 23 are refused 'replayed'.",
    },
    "broker_session_binding": {
        "status": "enforced",
        "mechanism": "a grant records the session it was opened for, and the "
                     "decision compares it against the session that owns the "
                     "socket the request arrived on. A ticket is worthless on "
                     "another mission's endpoint.",
        "measured": "tests/test_credential_broker.py OutsideTheSession.",
    },
    "broker_endpoint_is_grantable": {
        "status": "enforced",
        "mechanism": "the endpoint directory is created somewhere Firebreak's "
                     "read_grants() accepts, and the broker refuses at "
                     "construction to create one under a tree read_grants() "
                     "reserves. The default was /run/user/<uid>/"
                     "shadowfetch-broker, which read_grants() refuses, so every "
                     "endpoint shipped was unbindable while the module claimed "
                     "the existing --read grant was the whole binding "
                     "mechanism.",
        "measured": "tests/test_credential_broker.py TheEndpointMustBeBindable "
                    "and tools/probes/stage_d_broker.py both call the REAL "
                    "read_grants() out of the shipped shadowfetch-firebreak, on "
                    "the real default endpoint.",
        "note": "This says the endpoint CAN be granted. It does not say anyone "
                "grants it: nothing wires this yet, and that row is "
                "credential_delivery.",
    },
    "broker_availability": {
        "status": "partial",
        "mechanism": "a connection that has not sent a complete request holds a "
                     "file descriptor and a bounded buffer, and no decision "
                     "slot; above the pending-connection cap the STALEST "
                     "connection is dropped rather than the newest; and "
                     "'overloaded' is a 'not now' that redeem() retries inside "
                     "its own deadline.",
        "measured": "tests/test_credential_broker.py "
                    "TheFloodMustNotEvictTheConsumer: 24 and 288 slow-loris "
                    "connections held open, and the legitimate consumer is "
                    "still answered with the value while the flood runs. "
                    "Before: the same 24 connections made the consumer's single "
                    "call return 'overloaded', after which the attacker "
                    "redeemed and the consumer was told 'replayed'.",
        "note": "'partial', not 'enforced', and the missing part is stated "
                "rather than implied: the environment delivery this replaces "
                "CANNOT fail to deliver, and a broker can. A dead or wedged "
                "broker, or an endpoint that was never bound, is a mission that "
                "cannot authenticate. It fails loudly and a refusal never "
                "spends the grant, so the failure mode is denial and never "
                "theft -- but it is a failure mode the environment does not "
                "have, and anyone comparing the two must be told so.",
    },
    "broker_audit_tamper_evidence": {
        "status": "partial",
        "mechanism": "hash chain over every request, mirrored to journald "
                     "through sf_audit. Alteration and reordering are detected "
                     "by the chain; a file rewritten end to end -- including "
                     "one re-chained under a fresh chain id, which is what "
                     "defeated the first version of the anchor -- is detected "
                     "only where journald still remembers this store; "
                     "truncation likewise, and only while the journal is "
                     "readable and has not rotated.",
        "note": "The broker runs as the mission uid, so an attacker holding "
                "that uid OUTSIDE the sandbox can rewrite the file. This is "
                "tamper-EVIDENT, not tamper-proof, exactly as sf_audit says of "
                "the mission chain. From INSIDE the sandbox the file is not "
                "reachable at all, because it is not in the granted directory "
                "-- which is asserted, not assumed.",
        "measured": "tests/test_credential_broker.py ForgingTheAudit and "
                    "RechainingUnderAFreshId.",
    },
    "value_unreachable_in_sandbox": {
        "status": "not_enforced",
        "mechanism": "none, and none is possible for a value broker. The "
                     "sandbox that may ask for the value receives the value.",
        "note": "Only broker-proxy would make this row anything else. Anyone "
                "who writes 'the credential is no longer reachable from the "
                "sandbox' is contradicted by running one shell in it.",
    },
}


# --------------------------------------------------------------------------- #
# Where the endpoint lives
# --------------------------------------------------------------------------- #

# AF_UNIX sun_path is a fixed 108-byte field including its NUL. A path that
# overflows it does not fail at bind() with a clear message on every libc and
# every kernel -- it can silently truncate, which would bind a DIFFERENT path
# than the one handed to Firebreak and produce a socket the sandbox cannot see
# and an operator cannot find. The length is therefore checked before bind, and
# the session directory is a HASH rather than the session id so its contribution
# to the length is constant whatever the orchestrator names a session.
SUN_PATH_MAX = 108
SOCKET_NAME = "cred.sock"


def endpoint_directory_name(session: str) -> str:
    """A fixed-width directory name for one session's endpoint."""
    return hashlib.sha256(str(session).encode("utf-8")).hexdigest()[:16]


UNGRANTABLE_PREFIXES = (
    Path("/proc"), Path("/dev"), Path("/run"), Path("/sys"), Path("/home/agent"),
)
"""Trees Firebreak's read_grants() reserves UNCONDITIONALLY, so a socket placed
under one of them can never be bound into a sandbox.

Copied from the `reserved` tuple in
packages/shadowfetch-fireline/data/usr/bin/shadowfetch-firebreak, minus the two
entries that depend on that process's own configuration (its audit state
directory and the workspace root's checkpoint store), which this module cannot
evaluate and does not guess at. It is a duplicate of somebody else's rule, so it
is checked against the real function in
tests/test_credential_broker.py::TheEndpointMustBeBindable, which fails if the
two ever drift apart."""


def passwd_home() -> Path:
    """This user's home from the passwd database, never from $HOME.

    $HOME is settable by anything that launches this process, and it decided
    where the audit chain was written until this was fixed: the environment
    chose where a security record lived, which is the same defect class as
    letting PATH choose which journalctl answers a question about that record.
    The passwd entry is not rewritable by this uid.
    """
    try:
        entry = pwd.getpwuid(os.geteuid())
    except KeyError as exc:
        raise BrokerError(
            "this user has no passwd entry, so neither the credential endpoint "
            "nor the audit chain has a location that the environment cannot "
            "move") from exc
    home = (entry.pw_dir or "").strip()
    if not home.startswith("/"):
        raise BrokerError(
            "the passwd entry gives no absolute home directory, so the "
            "credential endpoint has no location this process can verify")
    return Path(home)


def default_endpoint_root() -> Path:
    """Where endpoint sockets go: <passwd home>/.local/state/shadowfetch/broker.

    THIS IS THE DIRECTORY FIREBREAK IS ASKED TO GRANT, so the only locations
    available are the ones its read_grants() accepts. It was
    /run/user/<uid>/shadowfetch-broker, and that was unbindable: read_grants()
    lists /run in its `reserved` tuple and refuses any path with /run among its
    parents, so EVERY endpoint this module created by default was refused with
    "Read grant overlaps protected sandbox/controller storage" -- while the
    module claimed the existing --read grant was the whole binding mechanism and
    no new one was needed. Measured, not reasoned about:

        read_grants(/run/user/1000/shadowfetch-broker/<hash>)  -> REFUSED
        read_grants(~/.local/state/shadowfetch/broker/<hash>)  -> accepted

    /run is reserved for a good reason and asking for an exception was the wrong
    trade: one directory up from the endpoint sits /run/user/<uid>, which holds
    the session bus, the keyring, the gpg-agent and ssh-agent sockets, and an
    exception evaluated by pattern is one resolve() bug away from granting those.
    The shipped precedent for a socket a sandbox must reach is the localmodel
    provider, whose manifest grants /var/lib/shadowfetch/localmodel -- a plain
    directory outside every reserved tree. That directory is root-owned and a
    per-user broker cannot create in it, so this is its per-user equivalent.

    What moving costs, stated rather than glossed: /run/user is a tmpfs that is
    wiped at logout, and this is not, so a crash can leave an endpoint directory
    behind. A socket inode holds no data -- the value never touches this
    filesystem -- and stale endpoints are swept at construction, so the cost is
    housekeeping, not exposure.

    CONSTRUCTED from the passwd entry, never read from $HOME, XDG_STATE_HOME or
    XDG_RUNTIME_DIR. Every component from the home down is checked to be a real
    directory owned by this user that no other user can write, before anything
    is created in it.
    """
    home = passwd_home()
    root = home / ".local/state/shadowfetch/broker"
    _verify_private_ancestry(home)
    return root


def _verify_private_ancestry(home: Path) -> None:
    """Refuse to build an endpoint under a directory somebody else can rewrite.

    A path component another user can write is a path component another user can
    replace with a symlink between the check and the bind. Group bits are NOT
    refused here and the reason is written down rather than left implied: this
    tree is created by the desktop with a umask that makes ~/.local/state/
    shadowfetch group-writable on a normal install, the group is the user's own,
    and refusing it would mean the broker never starts on a stock system. Other
    is what is checked, because "other" is what a second human on the host is.
    """
    for component in (home, home / ".local", home / ".local/state",
                      home / ".local/state/shadowfetch"):
        try:
            info = component.lstat()
        except FileNotFoundError:
            continue                      # created below, by us, with our mode
        except OSError as exc:
            raise BrokerError(f"cannot inspect {component}: {exc}") from exc
        if stat.S_ISLNK(info.st_mode):
            raise BrokerError(
                f"{component} is a symbolic link. The endpoint tree is not built "
                "through a link, because the link can be repointed after it was "
                "checked.")
        if info.st_uid != os.geteuid():
            raise BrokerError(
                f"{component} is owned by uid {info.st_uid}, not by this user")
        if info.st_mode & 0o002 and not info.st_mode & stat.S_ISVTX:
            raise BrokerError(
                f"{component} is mode {info.st_mode & 0o777:04o}; a credential "
                "endpoint is not created under a directory any user can write")


def default_audit_root() -> Path:
    """Where the broker's audit chain lives when the caller does not say.

    NOT under the endpoint root, and asserted so in CredentialBroker.__init__:
    the endpoint root is what gets bind-mounted into the sandbox, so an audit
    file inside it would be the record of the theft, mounted for the thief.

    Durable, next to the mission database. This was never on the runtime tmpfs
    and must not move there: a log that disappears at logout cannot answer the
    question it exists for, which is asked afterwards.

    Constructed from the PASSWD entry. It used to be Path.home(), which reads
    $HOME first -- so anything that could set one environment variable chose
    where this security record was written, and nothing recorded that it had.
    When the orchestrator wires this up it should pass its OWN state root
    explicitly; that relocation is deliberate, is not the environment's doing,
    and is written into the chain by BrokerAudit itself.
    """
    return passwd_home() / ".local/state/shadowfetch/missions"


# --------------------------------------------------------------------------- #
# Value types
# --------------------------------------------------------------------------- #

@dataclasses.dataclass(frozen=True)
class Peer:
    """Who connected, as the KERNEL reports it, not as they said.

    SO_PEERCRED is filled in by the kernel at connect time and the caller cannot
    forge it. Read the limit before using it as an authorisation input: the
    sandbox payload is uid 0 inside an unshared user namespace that maps to the
    mission uid, so from the host it connects AS THE MISSION UID -- the same uid
    the broker runs as. So uid does not tell the agent apart from the
    orchestrator and is not used to. What it does do is tell a DIFFERENT user on
    this host apart from both, and that refusal is real. The pid is recorded for
    forensics and is deliberately not trusted for anything: it is meaningful
    only in the namespace it was observed from and it is reused.
    """

    pid: int
    uid: int
    gid: int

    @classmethod
    def of(cls, sock) -> "Peer":
        fmt = "3i"
        raw = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                              struct.calcsize(fmt))
        pid, uid, gid = struct.unpack(fmt, raw)
        return cls(pid=pid, uid=uid, gid=gid)

    def as_dict(self) -> dict:
        return {"pid": self.pid, "uid": self.uid, "gid": self.gid}


@dataclasses.dataclass(eq=False)
class _Pending:
    """One accepted connection that has not yet produced a whole request.

    Deliberately cheap: a descriptor, a bounded buffer, the session the socket
    belongs to, the kernel's answer about the peer taken at accept time, and the
    wall-clock instant after which this connection has had long enough. It holds
    no thread and no decision slot, which is the entire difference between this
    version and the one a slow-loris flood could evict the consumer from.
    """

    conn: object
    session: str
    peer: object
    buffer: bytearray
    deadline: float


@dataclasses.dataclass
class Grant:
    """One identity, promised to one session, a bounded number of times.

    The ticket is NOT stored. Its SHA-256 is, so a grant table read out of a core
    dump or a heap snapshot does not hand over working tickets, and so the
    lookup can be a dict get on the digest instead of a scan that leaks timing.
    """

    grant_id: str
    mission: str
    session: str
    provider: str
    identity: str
    ticket_sha: str
    max_issues: int
    expires_monotonic: float
    expires_at: str
    issues: int = 0
    revoked: bool = False
    # Held as a bytearray so close() can zero the broker's own copy. This does
    # NOT erase the copy the worker already holds in os.environ, and does not
    # pretend to: it bounds how long the BROKER retains one, which is the only
    # copy this module is responsible for. CPython may also have copied the
    # source string during construction; that is stated rather than denied.
    _value: bytearray | None = None
    _factory = None
    _approver = None

    def spent(self) -> bool:
        return self.issues >= self.max_issues

    def describe(self) -> dict:
        """Everything about this grant except anything derived from the value."""
        return {"grant": self.grant_id, "mission": self.mission,
                "session": self.session, "provider": self.provider,
                "identity": self.identity, "issues": self.issues,
                "max_issues": self.max_issues, "expires_at": self.expires_at,
                "revoked": self.revoked}

    def wipe(self) -> None:
        if self._value is not None:
            for index in range(len(self._value)):
                self._value[index] = 0
            self._value = None


# --------------------------------------------------------------------------- #
# The audit chain
# --------------------------------------------------------------------------- #

class BrokerAudit:
    """Every request the broker answered, chained, and mirrored to journald.

    Separate from the mission chain in SQLite on purpose. The broker must be
    able to record a refusal at a moment when the mission database may be busy,
    locked, or -- in the case this record exists for -- being rewritten by
    whoever is also asking for the credential. A flat append-only file with its
    own chain has no lock to contend for and no schema to migrate.

    The chain proves no row was ALTERED. It cannot prove no row was REMOVED FROM
    THE END; that is what a chain is, and it is why every head is mirrored to
    journald, which the mission uid can append to but not rewrite.
    """

    FILENAME = "credential-broker-audit.jsonl"

    # Kept out of the endpoint directory on purpose. The endpoint directory is
    # what Firebreak bind-mounts into the sandbox, so an audit file beside the
    # socket would be the record of the theft, mounted for the thief.
    def __init__(self, root, *, mirror=True, clock=None):
        self.root = Path(root)
        self.path = self.root / self.FILENAME
        self.store = sf_audit.store_identity(str(self.path.resolve()))
        self._mirror_enabled = bool(mirror)
        self._clock = clock or (lambda: datetime.datetime.now(datetime.timezone.utc))
        self._lock = threading.Lock()
        self._seq = 0
        self._head = GENESIS
        self._chain = None
        self.mirror_failures = 0
        self.last_mirror_error = None
        # Where this record would live if nobody had said otherwise, and
        # whether somebody did. A record written somewhere other than the
        # canonical place is not wrong -- the orchestrator SHOULD pass its own
        # state root -- but it must not be silent, because "the log is not where
        # you are looking" and "there is no log" read identically to whoever
        # goes looking afterwards. Note also that relocating changes
        # store_identity(), so journald's memory of the old location shows up in
        # the anchor as foreign_store_entries: the relocation is visible from
        # both sides.
        try:
            self.canonical_root = default_audit_root()
        except BrokerError:
            self.canonical_root = None
        self.relocated = (self.canonical_root is None
                          or self.root.resolve() != self.canonical_root.resolve())
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        self._resume()

    # -- chain ------------------------------------------------------------
    def _resume(self) -> None:
        """Adopt an existing chain, or mint one.

        Resuming rather than re-minting matters: a broker restart that minted a
        fresh chain id would produce exactly the signature sf_audit reports as a
        re-mint, and an operator would be told a forgery had happened every time
        the worker was restarted. Then nobody reads the alarm.
        """
        rows = self.rows()
        if rows:
            last = rows[-1]
            self._seq = int(last.get("seq") or 0)
            self._head = str(last.get("hash") or GENESIS)
            self._chain = str(last.get("chain") or "") or None
        where = {"audit_path": str(self.path),
                 "canonical_audit_root": (str(self.canonical_root)
                                          if self.canonical_root else None),
                 "relocated": bool(self.relocated)}
        if self._chain is None:
            self._chain = secrets.token_hex(16)
            self._append({"event": "chain-opened", "op": "open",
                          "decision": "recorded",
                          "reason": "credential broker audit chain opened",
                          **where})
        elif self.relocated:
            # A resumed chain writes no chain-opened row, so a relocation
            # recorded only at mint time is a relocation the next reader cannot
            # see. Every start at a non-canonical location says so.
            self._append({"event": "audit-relocated", "op": "open",
                          "decision": "recorded",
                          "reason": "this chain is not at the canonical audit "
                                    "root; the caller chose where it is written",
                          **where})

    @property
    def chain(self) -> str:
        return self._chain

    @staticmethod
    def digest(record: dict, previous: str) -> str:
        """SHA-256 over the previous hash and this record's canonical form.

        Canonical means sorted keys and no insignificant whitespace: a verifier
        that re-serialised differently from the writer would report every honest
        row as forged, which is the failure mode that gets a checker switched
        off.
        """
        body = {k: v for k, v in record.items() if k != "hash"}
        payload = json.dumps(body, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True)
        return hashlib.sha256((previous + payload).encode("utf-8")).hexdigest()

    def _append(self, fields: dict) -> dict:
        record = dict(fields)
        record["seq"] = self._seq + 1
        record["prev"] = self._head
        record["chain"] = self._chain
        record["store"] = self.store
        record.setdefault("at", self._clock().isoformat(timespec="microseconds"))
        record["hash"] = self.digest(record, self._head)
        line = json.dumps(record, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True)
        # Open with O_APPEND every time rather than holding a handle: an append
        # to an O_APPEND fd is atomic up to a pipe buffer, and re-opening means a
        # broker that is killed mid-run leaves a complete file rather than a
        # buffer nobody flushed.
        fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, (line + "\n").encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
        self._seq = record["seq"]
        self._head = record["hash"]
        if self._mirror_enabled:
            ok, reason = sf_audit.mirror(record)
            if not ok:
                # A mirror failure must never lose the record: the FILE is the
                # record of truth and it is already written. It is counted, so a
                # degraded audit is reported rather than discovered later.
                self.mirror_failures += 1
                self.last_mirror_error = reason
        return record

    def append(self, fields: dict) -> dict:
        with self._lock:
            return self._append(fields)

    # -- reading ----------------------------------------------------------
    def rows(self) -> list:
        try:
            text = self.path.read_text(encoding="utf-8")
        except OSError:
            return []
        out = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except ValueError:
                # A line that is not JSON is not skipped quietly -- it is a
                # break in the record, and verify() has to see it as one.
                out.append({"_unparseable": line[:200]})
                continue
            out.append(row)
        return out

    def verify(self, *, anchor=True) -> dict:
        """Recompute the chain, and compare it with what journald remembers.

        Returns a report rather than a boolean. "The chain is intact but the
        journal has a higher sequence number than the file" and "the chain
        breaks at row 7" are different facts about different attacks, and
        collapsing them into one True/False is how a truncation comes to look
        like a pass.
        """
        report = {"ok": True, "rows": 0, "chain": self._chain, "store": self.store,
                  "first_bad_seq": None, "reason": "", "head_seq": None,
                  "head_hash": None, "anchor": None}
        previous = GENESIS
        expected_seq = 1
        for row in self.rows():
            report["rows"] += 1
            if "_unparseable" in row:
                report["ok"] = False
                report["first_bad_seq"] = expected_seq
                report["reason"] = "a record is not readable JSON"
                return report
            if row.get("seq") != expected_seq:
                report["ok"] = False
                report["first_bad_seq"] = expected_seq
                report["reason"] = (
                    f"sequence jumps: expected {expected_seq}, found {row.get('seq')!r}")
                return report
            if row.get("prev") != previous:
                report["ok"] = False
                report["first_bad_seq"] = expected_seq
                report["reason"] = "a record does not link to its predecessor"
                return report
            recomputed = self.digest(row, previous)
            if not hmac.compare_digest(str(row.get("hash") or ""), recomputed):
                report["ok"] = False
                report["first_bad_seq"] = expected_seq
                report["reason"] = "a record's contents do not match its hash"
                return report
            previous = recomputed
            report["head_seq"] = row["seq"]
            report["head_hash"] = recomputed
            expected_seq += 1
        if anchor:
            report["anchor"] = self.anchor(report["head_seq"], report["head_hash"])
            # A file rewritten END TO END and re-chained VERIFIES -- that is
            # what a hash chain is -- so the only evidence is journald
            # disagreeing about what it already saw, and a caller reads the
            # boolean.
            #
            # This used to test three named fields: truncated, rewritten,
            # conflicts. Re-chaining the file under a FRESH chain id set none of
            # them, because anchor() returned early whenever the journal had no
            # entries FOR THE CHAIN THE FILE NOW CLAIMS -- which a forger
            # guarantees by choosing an id journald has never seen. The
            # disagreement was sitting in a fourth field, other_chains, and
            # verify() did not look at it: the same defect the rewritten check
            # was added to fix, one field over.
            #
            # So the list is gone. anchor() reports every way it found the
            # journal to contradict this file, in one place, and verify() fails
            # if that place is not empty. A new detection cannot be added
            # without reaching the boolean.
            if report["anchor"].get("contradictions"):
                report["ok"] = False
                report["reason"] = (
                    report["anchor"].get("reason")
                    or "journald contradicts this file: "
                       + "; ".join(report["anchor"]["contradictions"]))
        return report

    def anchor(self, head_seq, head_hash) -> dict:
        """What journald says about this chain, and every way it disagrees.

        The result carries a CONTRADICTIONS list, and verify() fails if it is
        not empty. It is a list rather than a set of booleans because the
        booleans were the bug: three of them were enumerated at the call site
        and a fourth kind of disagreement went unread.

        Three answers, not two. AGREES is True when the journal was readable,
        had entries for this chain, and none of them disagreed; False when
        something disagreed; and None for "cannot tell" -- a user who is not in
        the systemd-journal group sees an empty journal, and calling that
        agreement would turn the one control that detects truncation into a
        rubber stamp. "Cannot tell" is not a contradiction either: a check that
        fails everywhere it cannot run gets switched off as fast as one that
        passes.

        Every field sf_audit.read_head() can report is read here. That is
        asserted, not intended: tests/test_credential_broker.py builds its stubs
        from the real function's shape and refuses to run if a field appears
        that this method has not been taught about.
        """
        seen = sf_audit.read_head(self._chain, store=self.store)
        out = {"available": bool(seen.get("available")),
               "reason": seen.get("reason") or "",
               "journal_head_seq": seen.get("head_seq"),
               "entries": seen.get("entries"),
               "conflicts": dict(seen.get("conflicts") or {}),
               "other_chains": dict(seen.get("other_chains") or {}),
               "foreign_store_entries": int(seen.get("foreign_store_entries") or 0),
               "uids": list(seen.get("uids") or []),
               "truncated": None, "rewritten": [], "rechained": None,
               "contradictions": [], "agrees": None}
        reasons = []

        # --- the checks that do NOT depend on this chain having entries ----
        # This is the whole of the fix. A file rewritten end to end under a
        # chain id journald has never seen has, by construction, no entries for
        # "this chain" -- so anything evaluated only after an entries check is
        # evaluated never, exactly when it matters most.
        if out["other_chains"]:
            out["rechained"] = True
            named = ", ".join(sorted(out["other_chains"]))
            reasons.append(
                f"journald holds {sum(out['other_chains'].values())} entr(ies) "
                f"for chain(s) {named} mirrored by THIS store, and this file "
                f"claims chain {self._chain}, which journald has "
                f"{seen.get('entries') or 0} entr(ies) for: the file's history "
                "is attributed to a chain it no longer claims")
        else:
            out["rechained"] = False
        if out["conflicts"]:
            reasons.append(
                "sequence(s) "
                + ", ".join(str(s) for s in sorted(out["conflicts"]))
                + " were mirrored more than once with different hashes, so "
                  "something other than this broker wrote one of them")
        if out["foreign_store_entries"]:
            reasons.append(
                f"{out['foreign_store_entries']} entr(ies) for this chain were "
                "mirrored by a store at a different path, which is what a copied "
                "or relocated audit file looks like")
        if len(out["uids"]) > 1:
            reasons.append(
                "more than one uid has mirrored this chain: "
                + ", ".join(str(u) for u in out["uids"]))

        if not out["available"] or not seen.get("entries"):
            # Cannot rule out truncation, but the checks above still stand: they
            # are about what journald DOES hold, not about what it is missing.
            if not reasons:
                out["reason"] = out["reason"] or (
                    "the journal has no entries for this chain, so truncation of "
                    "this file cannot be ruled out")
            else:
                out["agrees"] = False
                out["contradictions"] = reasons
                out["reason"] = "; ".join(reasons)
            return out

        journal_head = seen.get("head_seq")
        local = head_seq or 0
        if journal_head is not None and journal_head > local:
            out["truncated"] = True
            reasons.append(
                f"journald has sequence {journal_head} for this chain and the "
                f"file ends at {local}: {journal_head - local} record(s) were "
                "removed from the end of the file")
        else:
            out["truncated"] = False
        # An attacker holding the mission uid can also APPEND to journald --
        # /dev/log is a local datagram socket -- so a forged line claiming a
        # higher sequence than the file has produces a false TRUNCATION alarm
        # above. That direction is deliberate and is the only acceptable one
        # here: a forgeable input may raise an alarm that turns out to be
        # nothing, and may never silence a real one. sf_audit's earliest-wins
        # ordering, which uses journald's own monotonic clock rather than
        # anything the sender supplies, is what stops the reverse.
        heads = seen.get("heads") or {}
        by_seq = {int(row["seq"]): row.get("hash") for row in self.rows()
                  if isinstance(row.get("seq"), int)}
        for seq, mirrored in heads.items():
            local_hash = by_seq.get(int(seq))
            if local_hash and mirrored and local_hash != mirrored:
                out["rewritten"].append(int(seq))
        if out["rewritten"]:
            reasons.append(
                "record(s) " + ", ".join(str(s) for s in sorted(out["rewritten"]))
                + " differ from what journald recorded for the same sequence")
        out["contradictions"] = reasons
        out["agrees"] = not reasons
        if reasons:
            out["reason"] = "; ".join(reasons)
        return out


# --------------------------------------------------------------------------- #
# The broker
# --------------------------------------------------------------------------- #

class CredentialBroker:
    """Holds credential values outside the sandbox and answers for them.

    Lifecycle, and the order matters:

        broker = CredentialBroker(root=..., audit_root=...)
        ticket = broker.open_grant(mission=..., session=..., provider=...,
                                   identity="ANTHROPIC_API_KEY", value=secret)
        # the endpoint directory now exists and holds exactly one socket;
        # Firebreak binds broker.endpoint(session) into the sandbox and the
        # payload is given the ticket -- never the value.
        ...
        broker.close_grant(session=...)   # when the mission ends
        broker.close()

    open_grant() before the sandbox starts is not a convenience: a grant created
    afterwards would mean a window in which the socket exists and answers to
    nothing, and a payload that connected in that window would get an
    unknown_ticket refusal that looks exactly like an attack in the audit.
    """

    def __init__(self, *, root=None, audit_root=None, mirror=True,
                 clock=None, monotonic=None):
        self.root = Path(root) if root is not None else default_endpoint_root()
        # BEFORE the directory is created, not after. An endpoint under a tree
        # Firebreak reserves can never be bound into a sandbox, so building one
        # produces a socket that works perfectly in every test and cannot be
        # granted to the one caller it exists for. That is exactly how this
        # module shipped: the default endpoint root was /run/user/<uid>/
        # shadowfetch-broker, read_grants() reserves /run, and nothing measured
        # the pair together.
        self._refuse_ungrantable(self.root)
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        self.stale_endpoints_removed = self._sweep_stale_endpoints()
        self.audit = BrokerAudit(
            Path(audit_root) if audit_root is not None else default_audit_root(),
            mirror=mirror, clock=clock)
        # Checked BEFORE anything is listening, so a misconfiguration is a
        # refusal to start rather than a socket that already exists. The
        # invariant is asserted rather than documented: the record of who asked
        # for a credential must not sit inside the directory the asker gets
        # bind-mounted.
        if self._within(self.audit.path, self.root):
            raise BrokerError(
                "the broker audit log is inside the endpoint root, which is the "
                "directory the sandbox is granted. That would mount the record "
                "of the request into the reach of whoever made it.")
        self._monotonic = monotonic or time.monotonic
        self._lock = threading.RLock()
        self._grants: dict = {}            # ticket_sha -> Grant
        self._tombstones: dict = {}        # ticket_sha -> revoked Grant, bounded
        self._listeners: dict = {}         # session -> socket
        self._selector = selectors.DefaultSelector()
        self._wake_r, self._wake_w = socket.socketpair()
        self._wake_r.setblocking(False)
        self._selector.register(self._wake_r, selectors.EVENT_READ, "wake")
        self._slots = threading.BoundedSemaphore(MAX_CONCURRENT_REQUESTS)
        # Connections that have been accepted but have NOT yet produced a whole
        # request line, and completed requests waiting for a decision slot. Both
        # are touched only by the serving thread; see _serve().
        self._pending: dict = {}           # socket -> _Pending
        self._ready = collections.deque()  # _Pending, request complete
        self._flood: dict = {}             # refusal code -> burst being counted
        self._flood_lock = threading.Lock()
        self._closed = False
        self._thread = threading.Thread(target=self._serve, name="sf-cred-broker",
                                        daemon=True)
        self._thread.start()

    # -- paths -------------------------------------------------------------
    @staticmethod
    def _within(path, root) -> bool:
        try:
            Path(path).resolve().relative_to(Path(root).resolve())
        except (ValueError, OSError):
            return False
        return True

    @staticmethod
    def _refuse_ungrantable(root) -> None:
        """Refuse an endpoint root no --read grant could ever name."""
        candidate = Path(root).expanduser()
        try:
            resolved = candidate.resolve()
        except OSError as exc:
            raise BrokerError(f"cannot resolve the endpoint root {candidate}: {exc}") from exc
        if not candidate.is_absolute():
            raise BrokerError("the endpoint root must be an absolute path, "
                              "because that is what a read grant names")
        if len(resolved.parts) < 3:
            raise BrokerError(
                f"{resolved} is a top-level directory, and read_grants() refuses "
                "to expose one")
        for reserved in UNGRANTABLE_PREFIXES:
            if resolved == reserved or reserved in resolved.parents:
                raise BrokerError(
                    f"the credential endpoint cannot live under {reserved}: "
                    f"Firebreak's read_grants() reserves that tree and answers "
                    f"'Read grant overlaps protected sandbox/controller storage' "
                    f"for {resolved}, so the socket would be created, would work, "
                    "and could never be bound into the sandbox it exists for. "
                    "See default_endpoint_root().")

    def _sweep_stale_endpoints(self) -> int:
        """Remove endpoint directories left behind by a broker that died.

        The endpoint root is durable storage now rather than a tmpfs wiped at
        logout, so a crash leaves a directory holding a socket nothing listens
        on. A LIVE endpoint is left strictly alone -- another mission's broker
        may be running -- and liveness is decided by connecting, which is the
        only answer that is not a guess: ECONNREFUSED means the listener is
        gone. Nothing here removes a file it did not recognise: the directory
        must contain exactly one entry, that entry must be a socket, and it must
        be named cred.sock.
        """
        removed = 0
        try:
            children = sorted(self.root.iterdir())
        except OSError:
            return 0
        for directory in children:
            try:
                if not directory.is_dir() or directory.is_symlink():
                    continue
                entries = list(directory.iterdir())
                if len(entries) != 1 or entries[0].name != SOCKET_NAME:
                    continue
                if not stat.S_ISSOCK(entries[0].lstat().st_mode):
                    continue
                probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                probe.settimeout(0.25)
                try:
                    probe.connect(str(entries[0]))
                except ConnectionRefusedError:
                    os.unlink(entries[0])
                    os.rmdir(directory)
                    removed += 1
                except OSError:
                    continue              # answering, or busy: not ours to clear
                else:
                    continue              # a live broker owns this endpoint
                finally:
                    probe.close()
            except OSError:
                continue
        return removed

    def endpoint(self, session: str) -> Path:
        """The DIRECTORY to grant. Firebreak's read_grants() refuses a socket
        path and accepts a directory, which is why the grant is shaped this way
        and why this directory must hold the socket and nothing else."""
        return self.root / endpoint_directory_name(session)

    def socket_path(self, session: str) -> Path:
        return self.endpoint(session) / SOCKET_NAME

    # -- grants ------------------------------------------------------------
    def open_grant(self, *, mission: str, session: str, provider: str,
                   identity: str, value=None, value_factory=None,
                   max_issues: int = DEFAULT_MAX_ISSUES,
                   ttl_seconds: float = DEFAULT_TTL_SECONDS,
                   approver=None) -> str:
        """Promise one identity to one session. Returns the TICKET.

        value          the credential, held here and nowhere else the sandbox
                       can reach.
        value_factory  called per issue instead, for an identity that can be
                       minted short-lived. This is the seam a short-lived
                       credential needs and it is the whole of what that option
                       costs on this side.
        max_issues     defaults to 1. This is the control that turns an
                       unlimited ambient read into a single event.
        approver       called before each issue; return False or (False, reason)
                       to refuse. Unattended missions leave this None, because
                       an approver that waits for a person hangs a batch run.
        """
        if not identity or not isinstance(identity, str):
            raise BrokerError("a grant must name a credential identity")
        if (value is None) == (value_factory is None):
            raise BrokerError(
                "a grant carries either a value or a value_factory, never both "
                "and never neither")
        if int(max_issues) < 1:
            raise BrokerError("a grant that can never be issued is not a grant")
        with self._lock:
            if self._closed:
                raise BrokerError("the broker is closed")
            self._ensure_listener(session)
            ticket = secrets.token_hex(32)
            expires_at = (datetime.datetime.now(datetime.timezone.utc)
                          + datetime.timedelta(seconds=float(ttl_seconds)))
            grant = Grant(
                grant_id="grant-" + secrets.token_hex(8),
                mission=str(mission), session=str(session),
                provider=str(provider), identity=identity,
                ticket_sha=hashlib.sha256(ticket.encode("utf-8")).hexdigest(),
                max_issues=int(max_issues),
                # MONOTONIC, not the wall clock. Expiry is a security decision
                # and the wall clock is settable; a grant that could be revived
                # by moving the clock back is not expiring, it is suggesting.
                expires_monotonic=self._monotonic() + float(ttl_seconds),
                expires_at=expires_at.isoformat(timespec="seconds"),
            )
            if value is not None:
                grant._value = bytearray(str(value).encode("utf-8"))
            grant._factory = value_factory
            grant._approver = approver
            self._grants[grant.ticket_sha] = grant
        self.audit.append({"event": "grant-opened", "op": "open",
                           "decision": "recorded", "code": "", "reason": "",
                           **grant.describe(),
                           "peer": None})
        return ticket

    def close_grant(self, *, session: str = None, grant_id: str = None) -> int:
        """Revoke, wipe, and take the endpoint away. Returns how many closed."""
        closed = []
        with self._lock:
            for sha, grant in list(self._grants.items()):
                if session is not None and grant.session != str(session):
                    continue
                if grant_id is not None and grant.grant_id != grant_id:
                    continue
                grant.revoked = True
                grant.wipe()
                closed.append(grant)
                self._grants.pop(sha, None)
                self._tombstones[sha] = grant
                while len(self._tombstones) > MAX_TOMBSTONES:
                    self._tombstones.pop(next(iter(self._tombstones)))
            if session is not None and not any(
                    g.session == str(session) for g in self._grants.values()):
                self._drop_listener(str(session))
        for grant in closed:
            self.audit.append({"event": "grant-closed", "op": "close",
                               "decision": "recorded", "code": "",
                               "reason": "the mission ended", **grant.describe(),
                               "peer": None})
        return len(closed)

    def grants(self) -> list:
        with self._lock:
            return [g.describe() for g in self._grants.values()]

    # -- listeners ---------------------------------------------------------
    def _ensure_listener(self, session: str) -> None:
        session = str(session)
        if session in self._listeners:
            return
        directory = self.endpoint(session)
        directory.mkdir(parents=True, exist_ok=True)
        os.chmod(directory, 0o700)
        path = directory / SOCKET_NAME
        encoded = str(path).encode("utf-8")
        if len(encoded) >= SUN_PATH_MAX:
            # Refuse rather than bind a truncated path. A silently truncated
            # sun_path binds a socket at an address nobody handed to Firebreak,
            # so the sandbox would find nothing and the operator would find a
            # socket at a name they never chose.
            raise BrokerError(
                f"the endpoint path is {len(encoded)} bytes and AF_UNIX allows "
                f"{SUN_PATH_MAX - 1}: {path}")
        with contextlib.suppress(FileNotFoundError):
            os.unlink(path)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.setblocking(False)
        try:
            listener.bind(str(path))
            os.chmod(path, 0o600)
            listener.listen(LISTEN_BACKLOG)
        except OSError as exc:
            listener.close()
            raise BrokerError(f"cannot create the credential endpoint {path}: {exc}") from exc
        self._listeners[session] = listener
        self._selector.register(listener, selectors.EVENT_READ, ("listen", session))
        self._wake()

    def _drop_listener(self, session: str) -> None:
        listener = self._listeners.pop(session, None)
        if listener is None:
            return
        with contextlib.suppress(KeyError, ValueError):
            self._selector.unregister(listener)
        listener.close()
        path = self.socket_path(session)
        with contextlib.suppress(OSError):
            os.unlink(path)
        with contextlib.suppress(OSError):
            os.rmdir(path.parent)
        self._wake()

    def _wake(self) -> None:
        with contextlib.suppress(OSError):
            self._wake_w.send(b"\x00")

    # -- serving -----------------------------------------------------------
    #
    # WHY THIS IS AN EVENT LOOP AND NOT A THREAD PER CONNECTION
    # --------------------------------------------------------
    # It used to be: accept, take one of MAX_CONCURRENT_REQUESTS slots, then
    # READ the request inside that slot. A caller that connects, sends a JSON
    # prefix and never sends a newline therefore held a slot for the whole
    # REQUEST_DEADLINE, and 24 of them held every slot for two seconds at a
    # time. Measured against that version:
    #
    #     consumer's single redemption   -> "overloaded"   (a hard answer)
    #     attacker releases the flood and redeems -> got the value
    #     consumer tries again           -> "replayed"
    #
    # The attacker never had to win the race the threat model described. It
    # removed the other runner and walked. LISTEN_BACKLOG was irrelevant: the
    # flood consumed handler slots, not backlog.
    #
    # So the cost of an INCOMPLETE request is now a file descriptor and a
    # buffer, both held by the serving thread, and a decision slot is taken only
    # once a whole line is in hand -- at which point the decision is
    # microseconds of dictionary work under a lock. The consequence is the
    # property the tests assert: a flood of any size cannot stop the consumer
    # being answered, because the flood never holds the resource the consumer
    # needs. Above MAX_PENDING_CONNECTIONS somebody must be dropped, and it is
    # the STALEST connection, never the one that just arrived -- dropping the
    # newest would be the same eviction with extra steps.
    def _serve(self) -> None:
        while not self._closed:
            try:
                events = self._selector.select(timeout=self._next_timeout())
            except OSError:
                if self._closed:
                    return
                events = []
            for key, _ in events:
                if self._closed:
                    return
                data = key.data
                if data == "wake":
                    with contextlib.suppress(OSError):
                        key.fileobj.recv(4096)
                elif isinstance(data, tuple) and data[0] == "listen":
                    self._accept(key.fileobj, data[1])
                else:
                    self._readable(key.fileobj)
            self._expire()
            self._drain_ready()
            self._flush_flood()

    def _next_timeout(self) -> float:
        """Sleep no longer than the nearest thing that has to happen."""
        timeout = 0.25
        now = time.monotonic()
        for item in list(self._pending.values()) + list(self._ready):
            timeout = min(timeout, max(0.0, item.deadline - now))
        if self._flood:
            timeout = min(timeout, FLOOD_RECORD_WINDOW)
        return timeout

    def _accept(self, listener, session) -> None:
        try:
            conn, _ = listener.accept()
        except (OSError, ValueError):
            return
        try:
            conn.setblocking(False)
            peer = self._peer(conn)
        except OSError:
            with contextlib.suppress(OSError):
                conn.close()
            return
        if len(self._pending) >= MAX_PENDING_CONNECTIONS:
            self._evict_stalest()
        item = _Pending(conn=conn, session=session, peer=peer,
                        buffer=bytearray(),
                        deadline=time.monotonic() + REQUEST_DEADLINE)
        self._pending[conn] = item
        try:
            self._selector.register(conn, selectors.EVENT_READ, ("conn", session))
        except (KeyError, ValueError, OSError):
            self._pending.pop(conn, None)
            with contextlib.suppress(OSError):
                conn.close()

    def _evict_stalest(self) -> None:
        """Drop the connection closest to its deadline, which is the one that
        has been failing to finish a request for longest."""
        if not self._pending:
            return
        victim = min(self._pending.values(), key=lambda item: item.deadline)
        self._finish(victim, Refusal.OVERLOADED,
                     "more connections are waiting to send a request than the "
                     "broker will hold at once, and this one has waited longest",
                     burst=True)

    def _readable(self, conn) -> None:
        item = self._pending.get(conn)
        if item is None:
            return
        try:
            chunk = conn.recv(4096)
        except (BlockingIOError, InterruptedError):
            return
        except OSError:
            self._discard(item)
            return
        if not chunk:
            self._finish(item, Refusal.MALFORMED,
                         "the caller closed without sending a request", burst=True)
            return
        item.buffer += chunk
        if len(item.buffer) > MAX_REQUEST_BYTES:
            # Bounded before parsing, because the parser is the thing being
            # protected: a caller that sends an endless line exhausts memory.
            self._finish(item, Refusal.MALFORMED,
                         f"the request exceeds {MAX_REQUEST_BYTES} bytes",
                         burst=True)
            return
        if b"\n" in item.buffer:
            self._promote(item)

    def _promote(self, item) -> None:
        """A whole line has arrived: stop watching, queue it for a decision."""
        self._pending.pop(item.conn, None)
        with contextlib.suppress(KeyError, ValueError, OSError):
            self._selector.unregister(item.conn)
        if len(self._ready) >= MAX_PENDING_CONNECTIONS:
            # THE OPPOSITE CHOICE FROM _evict_stalest(), DELIBERATELY, AND THE
            # REASON IS THE WHOLE OF THIS STAGE'S BUG.
            #
            # In the PENDING queue, "oldest" means "has been failing to finish a
            # request for longest", which is the flood; dropping it protects the
            # caller that just arrived. In THIS queue every entry is a complete
            # request waiting its turn, so "oldest" means "next to be served" --
            # and the legitimate consumer, having arrived before the burst that
            # filled the queue, is exactly who that is. Evicting it here would
            # be the eviction this rewrite exists to remove, moved one queue
            # over: the consumer refused a millisecond before it was answered
            # while the flood kept its places.
            #
            # So the request that overflows is the one refused, its caller is
            # told 'overloaded', and redeem() retries that inside its own
            # deadline. This is reachable only when decisions themselves are
            # slow -- a blocking approver, or a value_factory waiting on a
            # network -- both of which need a VALID ticket to reach.
            self._finish(item, Refusal.OVERLOADED,
                         "more complete requests are waiting for a decision "
                         "than the broker will hold at once; the ones already "
                         "waiting keep their places", burst=True)
            return
        self._ready.append(item)

    def _expire(self) -> None:
        """The deadline, enforced against the wall clock.

        A per-recv timeout does not bound a caller that dribbles one byte at a
        time: every byte resets it. This is what actually ends such a
        connection, and it ends the wait for a decision slot too, so a request
        that can never be reached in time is answered rather than left hanging.
        """
        now = time.monotonic()
        for item in [i for i in self._pending.values() if i.deadline <= now]:
            self._finish(item, Refusal.MALFORMED,
                         "the request did not arrive within the deadline",
                         burst=True)
        overdue = [i for i in self._ready if i.deadline <= now]
        for item in overdue:
            with contextlib.suppress(ValueError):
                self._ready.remove(item)
            self._finish(item, Refusal.OVERLOADED,
                         "the broker did not reach this request within the "
                         "deadline", burst=True)

    def _drain_ready(self) -> None:
        """Hand complete requests to decision threads while slots are free."""
        while self._ready:
            if not self._slots.acquire(blocking=False):
                return
            item = self._ready.popleft()
            try:
                threading.Thread(target=self._handle, args=(item,),
                                 name="sf-cred-req", daemon=True).start()
            except (RuntimeError, OSError) as exc:
                # A thread that could not be created must not silently keep the
                # slot: sixteen of those and the broker answers nobody, forever,
                # which is the outage this whole rewrite is about.
                self._slots.release()
                self._finish(item, Refusal.OVERLOADED,
                             f"the broker could not start a handler: {exc}",
                             burst=True)

    @staticmethod
    def _peer(conn):
        try:
            return Peer.of(conn)
        except OSError:
            return None

    def _handle(self, item) -> None:
        """Decide one COMPLETE request. Holds a slot; must not block on a
        caller, because a caller can always choose not to speak."""
        try:
            raw = bytes(item.buffer).split(b"\n", 1)[0]
            answer = self.decide(raw, session=item.session, peer=item.peer)
            self._reply(item.conn, answer)
        except Exception as exc:                                   # noqa: BLE001
            # A broker that dies on a malformed connection is a denial of
            # service the sandbox can trigger. Nothing from a caller may take
            # the thread down; the failure is recorded and the connection is
            # closed. The text is redacted because an exception can carry the
            # value it was raised while handling.
            with contextlib.suppress(Exception):
                self._audit_request(session=item.session, grant=None, peer=None,
                                    identity=None, decision="refused",
                                    code=Refusal.MALFORMED,
                                    reason=sf_redact.redact(
                                        f"{exc.__class__.__name__}: {exc}")[:300])
        finally:
            with contextlib.suppress(OSError):
                item.conn.close()
            self._slots.release()
            # A freed slot is an event, not something to poll for: the loop is
            # woken so a queued request is decided now rather than up to one
            # select() timeout later.
            self._wake()

    def _finish(self, item, code, reason, *, burst=False) -> None:
        """Refuse one connection before any decision was made, and record it."""
        self._pending.pop(item.conn, None)
        with contextlib.suppress(KeyError, ValueError, OSError):
            self._selector.unregister(item.conn)
        if burst:
            self._audit_burst(code, session=item.session, peer=item.peer,
                              reason=reason)
        else:
            self._audit_request(session=item.session, grant=None, peer=item.peer,
                                identity=None, decision="refused", code=code,
                                reason=reason)
        self._reply(item.conn, {"ok": False, "op": "issue", "code": code,
                                "error": reason})
        with contextlib.suppress(OSError):
            item.conn.close()

    def _discard(self, item) -> None:
        """The connection broke before it said anything. Nothing to answer."""
        self._pending.pop(item.conn, None)
        with contextlib.suppress(KeyError, ValueError, OSError):
            self._selector.unregister(item.conn)
        with contextlib.suppress(OSError):
            item.conn.close()

    # -- recording a burst without becoming the flood's second target -------
    def _audit_burst(self, code, *, session, peer, reason) -> None:
        """Record the FIRST refusal of a burst in full, then count the rest.

        These refusals are decided by how a connection behaves rather than by
        what it asked for, so a flood can produce one per connection -- and each
        record is an fsync and a journald mirror on the serving thread. Writing
        one per connection would hand the flood a second target: the recorder
        itself, and through it the loop that answers the legitimate consumer.

        So the shape of the record changes with the shape of the attack. One
        occurrence is written exactly as before, with its peer and its reason.
        A burst of the same code within FLOOD_RECORD_WINDOW is written once more
        at the end of the window, as a count and a bounded sample of pids. That
        is a weaker record than one line per connection and it is stated as such
        in the module docstring rather than left to be discovered.
        """
        now = time.monotonic()
        with self._flood_lock:
            burst = self._flood.get(code)
            if burst is None or now - burst["opened"] >= FLOOD_RECORD_WINDOW:
                self._flood[code] = {"opened": now, "count": 0, "peers": [],
                                     "session": session, "reason": reason}
                first = True
            else:
                burst["count"] += 1
                if len(burst["peers"]) < FLOOD_PEER_SAMPLE and peer is not None:
                    burst["peers"].append(peer.pid)
                first = False
        if first:
            self._audit_request(session=session, grant=None, peer=peer,
                                identity=None, decision="refused", code=code,
                                reason=reason)

    def _flush_flood(self) -> None:
        now = time.monotonic()
        due = []
        with self._flood_lock:
            for code, burst in list(self._flood.items()):
                if now - burst["opened"] < FLOOD_RECORD_WINDOW:
                    continue
                self._flood.pop(code, None)
                if burst["count"]:
                    due.append((code, burst))
        for code, burst in due:
            with contextlib.suppress(Exception):
                self.audit.append({
                    "event": "credential-refused-burst", "op": "issue",
                    "decision": "refused", "code": code,
                    "reason": burst["reason"],
                    "session": str(burst["session"]), "identity": None,
                    "peer": None, "count": burst["count"],
                    "peer_pids": list(burst["peers"]),
                    "window_seconds": FLOOD_RECORD_WINDOW,
                    "note": "further connections refused with this code inside "
                            "one window; recorded as a count so a flood cannot "
                            "aim itself at the recorder",
                })

    @staticmethod
    def _reply(conn, payload: dict) -> None:
        body = dict(payload)
        body.setdefault("v", PROTOCOL_VERSION)
        line = json.dumps(body, sort_keys=True, separators=(",", ":")) + "\n"
        with contextlib.suppress(OSError):
            # Short, and bounded: refusals are written from the serving thread,
            # and a caller that never reads its answer must not be able to hold
            # that thread. One line is far smaller than a unix socket's buffer,
            # so this does not block in practice; the timeout is what makes
            # "in practice" unnecessary.
            conn.settimeout(REPLY_TIMEOUT)
            conn.sendall(line.encode("utf-8"))

    # -- the decision ------------------------------------------------------
    def decide(self, raw, *, session, peer=None) -> dict:
        """Answer one request. The whole policy, in one place, testable directly.

        Kept as a function of (bytes, session, peer) rather than of a live
        connection so the adversarial tests can drive every refusal path without
        a socket AND over a real socket, and so the two cannot drift: the socket
        path calls exactly this.
        """
        session = str(session)
        try:
            request = json.loads(raw.decode("utf-8") if isinstance(raw, (bytes, bytearray))
                                 else raw)
        except (ValueError, UnicodeDecodeError) as exc:
            return self._refuse(session, None, peer, None, Refusal.MALFORMED,
                                f"the request is not JSON: {exc}")
        if not isinstance(request, dict):
            return self._refuse(session, None, peer, None, Refusal.MALFORMED,
                                "the request is not an object")
        if request.get("v") != PROTOCOL_VERSION:
            return self._refuse(session, None, peer, None, Refusal.MALFORMED,
                                f"unsupported protocol version {request.get('v')!r}")
        if request.get("op") != "issue":
            return self._refuse(session, None, peer, None, Refusal.MALFORMED,
                                f"unknown operation {request.get('op')!r}")
        ticket = request.get("ticket")
        identity = request.get("identity")
        if not isinstance(ticket, str) or not isinstance(identity, str):
            return self._refuse(session, None, peer, None, Refusal.MALFORMED,
                                "a request names a ticket and an identity, both strings")

        # Peer check before the ticket check. A caller who is not this uid has
        # no business here whatever they are holding, and refusing first means
        # a foreign uid cannot use the broker as a ticket oracle.
        if peer is not None and peer.uid != os.getuid():
            return self._refuse(session, None, peer, identity, Refusal.PEER_REFUSED,
                                f"uid {peer.uid} is not the mission user")

        ticket_sha = hashlib.sha256(ticket.encode("utf-8")).hexdigest()
        with self._lock:
            grant = self._grants.get(ticket_sha)
            if grant is None or not hmac.compare_digest(grant.ticket_sha, ticket_sha):
                # Deliberately the same answer for "never existed" and "was
                # closed and removed": telling a caller which one it is turns
                # the broker into an oracle for guessing grant lifetimes. The
                # AUDIT does tell them apart, because "a payload was still
                # trying to spend this credential after the mission ended" is
                # the single most interesting thing this file can record.
                dead = self._tombstones.get(ticket_sha)
                return self._refuse(
                    session, dead, peer, identity,
                    Refusal.REVOKED if dead is not None else Refusal.UNKNOWN_TICKET,
                    ("the grant was revoked when the mission ended, and the "
                     "ticket was presented afterwards")
                    if dead is not None else "no grant answers to this ticket",
                    reply_code=Refusal.UNKNOWN_TICKET,
                    reply_reason="no grant answers to this ticket")
            if grant.session != session:
                return self._refuse(session, grant, peer, identity,
                                    Refusal.WRONG_SESSION,
                                    f"the ticket belongs to session {grant.session} "
                                    f"and arrived on the endpoint for {session}")
            if grant.revoked:
                return self._refuse(session, grant, peer, identity, Refusal.REVOKED,
                                    "the grant was revoked when the mission ended")
            if grant.identity != identity:
                return self._refuse(session, grant, peer, identity,
                                    Refusal.IDENTITY_NOT_GRANTED,
                                    f"this grant carries {grant.identity} and the "
                                    f"request asked for {identity}")
            if self._monotonic() >= grant.expires_monotonic:
                return self._refuse(session, grant, peer, identity, Refusal.EXPIRED,
                                    f"the grant expired at {grant.expires_at}")
            if grant.spent():
                return self._refuse(session, grant, peer, identity, Refusal.REPLAYED,
                                    f"this grant has already been issued "
                                    f"{grant.issues} time(s) of {grant.max_issues}")
            if grant._approver is not None:
                verdict = grant._approver(grant.describe())
                ok, why = verdict if isinstance(verdict, tuple) else (verdict, "")
                if not ok:
                    return self._refuse(session, grant, peer, identity,
                                        Refusal.NOT_APPROVED,
                                        why or "the request was not approved")
            if grant._factory is not None:
                try:
                    value = str(grant._factory(grant.describe()))
                except Exception as exc:                           # noqa: BLE001
                    return self._refuse(
                        session, grant, peer, identity, Refusal.MINT_FAILED,
                        sf_redact.redact(f"{exc.__class__.__name__}: {exc}")[:300])
            elif grant._value is None:
                # Belt and braces: only close_grant()/close() clear a value and
                # both do it holding this same lock, so reaching here would mean
                # the lock stopped covering the wipe. Refusing is the safe
                # answer; issuing an empty string as if it were the credential
                # is the one that gets debugged for a day.
                return self._refuse(session, grant, peer, identity, Refusal.REVOKED,
                                    "the grant no longer holds a value")
            else:
                value = bytes(grant._value).decode("utf-8")
            # Counted INSIDE the lock and before the answer leaves. A count
            # bumped after the reply would let two callers who arrive together
            # both read issues == 0 and both be issued, which is precisely the
            # race the single-issue rule exists to lose.
            grant.issues += 1
            issued = grant.issues
            described = grant.describe()
        self._audit_request(session=session, grant=None, peer=peer,
                            identity=identity, decision="issued", code="",
                            reason="", extra=described)
        return {"ok": True, "op": "issue", "identity": identity, "value": value,
                "issue": issued, "max_issues": described["max_issues"],
                "expires_at": described["expires_at"],
                "grant": described["grant"]}

    def _refuse(self, session, grant, peer, identity, code, reason,
                *, reply_code=None, reply_reason=None) -> dict:
        """Refuse, record, and answer.

        reply_code/reply_reason exist for the one case where the honest RECORD
        and the safe ANSWER differ: a ticket presented after its mission ended
        is audited as `revoked` and answered as `unknown_ticket`, so the
        operator sees the attempt and the caller learns nothing it did not
        already know. Everywhere else the two are the same string, which is the
        default.
        """
        self._audit_request(session=session, grant=grant, peer=peer,
                            identity=identity, decision="refused", code=code,
                            reason=reason)
        code = reply_code or code
        reason = reply_reason or reason
        # The reason IS returned to the caller. A refusal a caller cannot
        # understand becomes a support ticket that gets closed by widening the
        # grant; and none of these reasons discloses a value, an unspent ticket,
        # or the existence of a grant the caller did not already name.
        return {"ok": False, "op": "issue", "code": code, "error": reason}

    def _audit_request(self, *, session, grant, peer, identity, decision, code,
                       reason, extra=None) -> None:
        record = {
            "event": "credential-issued" if decision == "issued" else "credential-refused",
            "op": "issue",
            "decision": decision,
            "code": code or "",
            "reason": str(reason)[:500],
            "session": str(session),
            "identity": identity,
            "peer": peer.as_dict() if peer is not None else None,
            "mission": None, "provider": None, "grant": None,
            "grant_identity": None, "issues": None, "max_issues": None,
        }
        if grant is not None:
            described = grant.describe()
            # The record must say what was ASKED FOR, not what the grant
            # happens to carry. update() clobbered it, so an
            # identity_not_granted refusal -- a caller with a valid ticket
            # reaching for a DIFFERENT credential, which is the lateral move
            # this refusal exists to catch -- was written down as an ordinary
            # request for the identity the grant already had. The attempt was
            # invisible in the one place it needed to be visible.
            record["grant_identity"] = described.pop("identity", None)
            record.update(described)
        if extra:
            record.update(extra)
        # Never a value, and never anything derived from one. "What it answered"
        # is issued-or-refused and why; a fingerprint of the secret would be a
        # guessing oracle sitting in the file the audit exists to keep honest.
        record.pop("value", None)
        self.audit.append(record)

    # -- shutdown ----------------------------------------------------------
    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            for grant in self._grants.values():
                grant.revoked = True
                grant.wipe()
            self._grants.clear()
            for session in list(self._listeners):
                self._drop_listener(session)
        self._wake()
        self._thread.join(timeout=5)
        # Whatever the last window counted is written now: a burst summary that
        # is only ever flushed by the loop is a summary a shutdown erases.
        with contextlib.suppress(Exception):
            for burst in self._flood.values():
                burst["opened"] = 0.0
            self._flush_flood()
        # After the serving thread has stopped, and only then: _pending and
        # _ready belong to it, so touching them while it runs would be a race
        # rather than a shutdown.
        for item in list(self._pending.values()) + list(self._ready):
            with contextlib.suppress(KeyError, ValueError, OSError):
                self._selector.unregister(item.conn)
            with contextlib.suppress(OSError):
                item.conn.close()
        self._pending.clear()
        self._ready.clear()
        with contextlib.suppress(Exception):
            self._selector.unregister(self._wake_r)
        for sock in (self._wake_r, self._wake_w):
            with contextlib.suppress(OSError):
                sock.close()
        with contextlib.suppress(Exception):
            self._selector.close()
        with contextlib.suppress(OSError):
            os.rmdir(self.root)

    def __enter__(self) -> "CredentialBroker":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


# --------------------------------------------------------------------------- #
# The client half, for whatever ends up redeeming inside the sandbox
# --------------------------------------------------------------------------- #

def redeem(socket_path, ticket: str, identity: str, *, timeout: float = 5.0) -> dict:
    """Ask a broker for one identity. Returns the parsed answer.

    Lives here so the protocol has exactly one implementation. It is written to
    be usable from inside the sandbox -- it needs nothing but the socket and the
    standard library -- and it is what the tests and the probe drive, so the
    thing that is measured is the thing that would ship.

    TWO ANSWERS MEAN "NOT NOW" AND ARE RETRIED INSIDE THE CALLER'S OWN DEADLINE.
    EAGAIN out of connect(), because AF_UNIX returns that rather than
    ECONNREFUSED when the listen backlog is full (unix(7)) and a client that
    treats it as a hard failure gives up while the server is healthy. And an
    `overloaded` refusal, because it is a statement about the broker's queue at
    one instant and not about this caller's right to the credential -- returning
    it as a verdict is what let a flood take the consumer's answer away and
    leave the credential for whoever was still asking. Neither retry widens the
    deadline the caller chose; when it runs out the last answer is returned as
    it stands, because a client that never gives up is its own outage.
    """
    request = json.dumps({"v": PROTOCOL_VERSION, "op": "issue",
                          "ticket": ticket, "identity": identity},
                         sort_keys=True, separators=(",", ":")) + "\n"
    deadline = time.monotonic() + float(timeout)
    attempt = 0
    while True:
        attempt += 1
        answer = _redeem_once(socket_path, request, deadline)
        if answer.get("ok") or answer.get("code") != Refusal.OVERLOADED:
            return answer
        if time.monotonic() >= deadline:
            return answer
        # Backoff, so a retry does not become the flood. Capped, and never past
        # the caller's deadline.
        time.sleep(min(0.02 * attempt, 0.2))


def _redeem_once(socket_path, request, deadline) -> dict:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(max(0.05, deadline - time.monotonic()))
    try:
        while True:
            try:
                sock.connect(str(socket_path))
                break
            except (BlockingIOError, InterruptedError):
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.01)
        sock.sendall(request.encode("utf-8"))
        buffer = bytearray()
        while b"\n" not in buffer and len(buffer) < MAX_REQUEST_BYTES * 8:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buffer += chunk
    finally:
        with contextlib.suppress(OSError):
            sock.close()
    text = bytes(buffer).split(b"\n", 1)[0].decode("utf-8", "replace")
    if not text:
        raise BrokerError("the broker closed without answering")
    try:
        return json.loads(text)
    except ValueError as exc:
        raise BrokerError(f"the broker's answer is not JSON: {exc}") from exc
