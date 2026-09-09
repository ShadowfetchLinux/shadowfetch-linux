#!/usr/bin/env python3
"""Stage D probe: what a real sandbox can and cannot do about a credential.

usage: stage_d_broker.py [--json]

Every line this prints came out of a process that ran. Nothing here is derived
from reading the source, and nothing is asserted -- a probe reports, a test
judges. The two exist for different readers: the suite in
packages/shadowfetch-missions/tests/test_credential_broker.py fails a build, and
this is what you run by hand when you do not believe it.

The measurements, in the order a reviewer would ask for them:

  endpoint-is-grantable        THE REAL read_grants() on THE REAL default path
  bound-through-a-real-grant   the sandbox reaches it through that grant's argv
  env-delivery-readable        what ships today: Firebreak --setenv, then `env`
  broker-value-readable        what this stage built: the value STILL comes back
  broker-env-clean             ...but nothing is in the environment to print
  unbound-endpoint             without the grant the socket is not there at all
  replay-refused               the second redemption from inside the sandbox
  wrong-session-refused        another mission's ticket on this endpoint
  after-close-refused          a ticket presented after the mission ended
  flood-cannot-evict-consumer  288 stalled connections vs one honest redemption
  host-pids-visible            what the sandbox can see of the broker's process
  audit-readable-from-sandbox  whether the thief can reach the record
  audit-chain-detects-edit     one byte changed in the log
  audit-anchor-detects-rechain a file rewritten under a fresh chain id
  tcp-host-loopback            the containment this transport does not reopen

WHY THE FIRST TWO ROWS EXIST
----------------------------
This probe used to create its endpoint under a /tmp root of its own and then
hand-roll `--ro-bind <endpoint> <endpoint>` itself. Both halves of that were
wrong in the same way: the shipped default endpoint root was
/run/user/<uid>/shadowfetch-broker, Firebreak's read_grants() reserves /run and
refuses any path beneath it, and so the socket every real run would have created
could never have been bound into any sandbox -- while the module claimed the
existing --read grant was the whole binding mechanism. A probe that builds its
own bind argument is measuring its own opinion. These two rows call the real
read_grants() out of the shipped shadowfetch-firebreak, on the real default
endpoint, and bind using ONLY what that function returned.

The value is a decoy generated per run, never a real credential; the probe
refuses to be handed one.
"""
from __future__ import annotations

import argparse
import contextlib
import importlib.machinery
import importlib.util
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# Absolute. A probe that decides a security question through PATH is a probe
# whose answer the caller controls, which is the invariant this codebase applies
# everywhere else and does not get to skip here.
BWRAP = "/usr/bin/bwrap"
ENV = "/usr/bin/env"
LS = "/usr/bin/ls"
CAT = "/usr/bin/cat"
PYTHON = "/usr/bin/python3"
CHILD_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}

ROOT = Path(__file__).resolve().parents[2]
MISSIONS = ROOT / "packages/shadowfetch-missions/data/usr/lib/shadowfetch/missions"
FIREBREAK = ROOT / "packages/shadowfetch-fireline/data/usr/bin/shadowfetch-firebreak"
sys.path.insert(0, str(MISSIONS))

import sf_audit                                                    # noqa: E402
import sf_broker                                                   # noqa: E402
from sf_broker import CredentialBroker, redeem                     # noqa: E402

IDENTITY = "ANTHROPIC_API_KEY"


def firebreak_module():
    """The SHIPPED Firebreak, loaded by absolute path.

    Not imported by name and not found by searching: this is the program whose
    answer decides whether the endpoint can be bound at all, and a probe that
    lets a search path choose which copy answers is a probe whose answer the
    caller chooses. Its module body only defines things -- its entry point is
    behind __name__ == "__main__" -- so loading it runs nothing.
    """
    loader = importlib.machinery.SourceFileLoader("sf_firebreak_probe",
                                                  str(FIREBREAK))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module

REDEEM = """
import json, socket, sys
path, ticket, identity = sys.argv[1], sys.argv[2], sys.argv[3]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(5)
try:
    s.connect(path)
except OSError as exc:
    print("RESULT " + json.dumps({"connected": False, "errno": exc.errno,
                                  "error": type(exc).__name__}))
    raise SystemExit(0)
s.sendall((json.dumps({"v": 1, "op": "issue", "ticket": ticket,
                       "identity": identity}) + "\\n").encode())
buf = b""
while b"\\n" not in buf:
    chunk = s.recv(4096)
    if not chunk:
        break
    buf += chunk
print("RESULT " + json.dumps({"connected": True,
                              "answer": json.loads(buf.split(b"\\n", 1)[0].decode())}))
"""

TCP_PROBE = """
import json, socket
try:
    s = socket.create_connection(("127.0.0.1", 22), timeout=3)
    s.close()
    print("RESULT " + json.dumps({"reached": True}))
except OSError as exc:
    print("RESULT " + json.dumps({"reached": False, "error": type(exc).__name__}))
"""


def measure_grantability(report, tmp):
    """Does the REAL read_grants() accept the REAL default endpoint?

    Returns the grants it produced, or None. This is the row the previous
    version of this probe could not have failed, because it never asked.
    """
    say = report["measurements"].__setitem__
    if not FIREBREAK.is_file():
        say("endpoint-is-grantable",
            {"measured": False, "why": f"no Firebreak at {FIREBREAK}"})
        return None, None
    firebreak = firebreak_module()
    workspace = tmp / "workspace"
    workspace.mkdir(exist_ok=True)
    try:
        root = sf_broker.default_endpoint_root()
    except sf_broker.BrokerError as exc:
        say("endpoint-is-grantable", {"measured": False, "why": str(exc)})
        return None, None
    broker = CredentialBroker(root=root, audit_root=tmp / "grant-state",
                              mirror=False)
    ticket = broker.open_grant(mission="probe", session="grantable",
                               provider="probe", identity=IDENTITY,
                               value="decoy-" + secrets.token_hex(8))
    endpoint = broker.endpoint("grantable")
    row = {"measured": True, "endpoint": str(endpoint),
           "default_endpoint_root": str(root),
           "read_grants": None, "accepted": None, "error": None,
           "directory_contents": sorted(p.name for p in endpoint.iterdir())}
    try:
        grants = firebreak.read_grants([str(endpoint)], workspace)
        row["accepted"] = True
        row["read_grants"] = [str(g) for g in grants]
    except Exception as exc:                                        # noqa: BLE001
        grants = None
        row["accepted"] = False
        row["error"] = f"{type(exc).__name__}: {exc}"
    # The location that used to ship, measured against the same function, so
    # the reason for the move is in the output rather than in a comment.
    old = Path("/run/user") / str(os.getuid()) / "shadowfetch-broker-probe"
    try:
        old.mkdir(parents=True, exist_ok=True)
        try:
            firebreak.read_grants([str(old)], workspace)
            row["the_old_run_user_location"] = "accepted"
        except Exception as exc:                                    # noqa: BLE001
            row["the_old_run_user_location"] = f"{type(exc).__name__}: {exc}"
        with contextlib.suppress(OSError):
            os.rmdir(old)
    except OSError as exc:
        row["the_old_run_user_location"] = f"could not be created: {exc}"
    say("endpoint-is-grantable", row)
    return broker, (ticket, grants)


def measure_bound_through_a_real_grant(report, broker, ticket, grants, probe):
    """Reach the broker from a sandbox built ONLY from what read_grants gave."""
    say = report["measurements"].__setitem__
    if not grants:
        say("bound-through-a-real-grant",
            {"measured": False,
             "why": "read_grants() produced no grant to bind"})
        return
    command = sandbox([PYTHON, str(probe),
                       str(broker.socket_path("grantable")), ticket, IDENTITY],
                      binds=[*grants, probe], firebreak_overlays=True)
    done = run(command)
    answer = result_line(done.stdout) or {"error": done.stderr[-200:]}
    say("bound-through-a-real-grant",
        {"measured": True,
         "bind_arguments": [f"--ro-bind {g} {g}" for g in grants],
         "under_firebreaks_own_overlays": True,
         "connected": answer.get("connected"),
         "value_returned": bool(answer.get("answer", {}).get("value")),
         "note": "the bind argument is built from read_grants()' own return "
                 "value and applied after the same tmpfs-over-/run and "
                 "/home/agent mounts Firebreak lays down first, so this row "
                 "cannot pass over a path Firebreak would have refused or "
                 "covered"})


def measure_flood(report, broker, tmp):
    """288 connections that never finish a request, then one honest redemption.

    The attack does not need to win a race if it can evict the other runner.
    Against the first version of this module 24 of these took every handler slot
    for the full deadline, the consumer's single call was answered 'overloaded',
    and the attacker then redeemed at leisure.
    """
    say = report["measurements"].__setitem__
    ticket = broker.open_grant(mission="probe-flood", session="flood",
                               provider="probe", identity=IDENTITY,
                               value="decoy-" + secrets.token_hex(8))
    path = str(broker.socket_path("flood"))
    held = []
    count = sf_broker.MAX_PENDING_CONNECTIONS + 32
    for _ in range(count):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5)
        try:
            sock.connect(path)
            sock.sendall(b'{"v":1,"op":"issue"')          # no newline, ever
        except OSError:
            sock.close()
            continue
        held.append(sock)
    started = time.monotonic()
    try:
        answer = redeem(path, ticket, IDENTITY, timeout=5.0)
    except Exception as exc:                                        # noqa: BLE001
        answer = {"error": f"{type(exc).__name__}: {exc}"}
    elapsed = time.monotonic() - started
    for sock in held:
        with contextlib.suppress(OSError):
            sock.close()
    say("flood-cannot-evict-consumer",
        {"stalled_connections_held": len(held),
         "handler_slots": sf_broker.MAX_CONCURRENT_REQUESTS,
         "pending_cap": sf_broker.MAX_PENDING_CONNECTIONS,
         "consumer_answered": answer.get("ok"),
         "consumer_code": answer.get("code"),
         "consumer_seconds": round(elapsed, 3),
         "note": "the flood holds descriptors, not handler slots; a completed "
                 "request is what takes a slot, and the stalest connection is "
                 "what gets dropped above the cap"})


def measure_rechain(report, broker):
    """Rewrite the audit file under a chain id journald has never seen."""
    say = report["measurements"].__setitem__
    path = broker.audit.path
    real_chain = broker.audit.chain
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    kept = [row for row in rows if row.get("event") in ("chain-opened",
                                                        "audit-relocated")]
    previous = sf_broker.GENESIS
    lines = []
    for index, row in enumerate(kept, start=1):
        row["seq"] = index
        row["chain"] = "d" * 32
        row["prev"] = previous
        row["hash"] = broker.audit.digest(row, previous)
        previous = row["hash"]
        lines.append(json.dumps(row, sort_keys=True, separators=(",", ":")))
    path.write_text("".join(line + "\n" for line in lines))
    broker.audit._chain = "d" * 32
    local_only = broker.audit.verify(anchor=False)
    # journald as it would be: nothing for the id the file now claims, and the
    # real chain's entries still there for this same store.
    real_read_head = sf_audit.read_head
    sf_audit.read_head = lambda chain, **kw: {
        "available": True, "reason": None, "head_seq": None, "head_hash": None,
        "entries": 0, "identifier": "shadowfetch-audit", "heads": {},
        "conflicts": {}, "other_chains": {real_chain: len(rows)},
        "foreign_store_entries": 0, "uids": [os.getuid()],
        "store": broker.audit.store, "chain": chain}
    try:
        anchored = broker.audit.verify()
    finally:
        sf_audit.read_head = real_read_head
    say("audit-anchor-detects-rechain",
        {"issued_rows_left_in_file": len(
            [r for r in broker.audit.rows()
             if r.get("event") == "credential-issued"]),
         "verifies_against_itself": local_only["ok"],
         "verifies_against_the_journal": anchored["ok"],
         "reason": anchored["reason"][:200],
         "note": "the chain cannot see its own re-minting, which is what a "
                 "chain is; journald still holding the old chain id for this "
                 "store is the contradiction"})


def sandbox(argv, *, binds=(), setenv=(), firebreak_overlays=False):
    """bwrap with NO network, its own pid/user namespace, and only what is named.

    The same posture Firebreak uses for network 'none': --unshare-net,
    --unshare-pid, --unshare-user, --clearenv. If the transport works here it
    works there, and if it does not, no amount of wiring will save it.

    firebreak_overlays adds the mounts Firebreak lays down BEFORE it applies its
    read grants -- a fresh tmpfs over /run and the private /home/agent tree --
    in that same order. It matters because a mount laid over the endpoint's
    parent after the bind would hide the socket, and because the endpoint used
    to live under /run, which Firebreak covers with a tmpfs.
    """
    command = [BWRAP,
               "--ro-bind", "/usr", "/usr",
               "--symlink", "usr/bin", "/bin",
               "--symlink", "usr/lib", "/lib",
               "--symlink", "usr/lib64", "/lib64",
               "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
               "--clearenv", "--setenv", "PATH", "/usr/bin:/bin",
               "--unshare-net", "--unshare-pid", "--unshare-user",
               "--die-with-parent"]
    if firebreak_overlays:
        command += ["--tmpfs", "/run", "--dir", "/home", "--dir", "/home/agent",
                    "--dir", "/home/agent/.config", "--dir", "/home/agent/.cache"]
    for name, value in setenv:
        command += ["--setenv", name, value]
    for path in binds:
        command += ["--ro-bind", str(path), str(path)]
    return [*command, "--", *argv]


def run(command):
    done = subprocess.run(command, capture_output=True, text=True, timeout=120,
                          env=dict(CHILD_ENV))
    return done


def result_line(text):
    for line in (text or "").splitlines():
        if line.startswith("RESULT "):
            return json.loads(line[7:])
    return None


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true",
                        help="machine-readable report only")
    args = parser.parse_args(argv)

    if not os.access(BWRAP, os.X_OK):
        print(f"no bubblewrap at {BWRAP}; this probe measures a real sandbox or "
              "it measures nothing", file=sys.stderr)
        return 2

    # A decoy, minted here. A probe that accepted a real credential on the
    # command line would put one in the process table of whatever ran it.
    secret = "decoy-" + secrets.token_hex(16)
    tmp = Path(tempfile.mkdtemp(prefix="sf-stage-d-probe-"))
    report = {"secret_is_a_decoy": True, "measurements": {}}
    say = report["measurements"].__setitem__

    probe = tmp / "redeem.py"
    probe.write_text(REDEEM, encoding="utf-8")

    # The two rows that measure the shipped path rather than a convenient one.
    # Done first and in their own broker, on the REAL default endpoint root, so
    # a failure here is visible before anything else is reported.
    real_broker, grant_pair = measure_grantability(report, tmp)
    try:
        if real_broker is not None:
            ticket, grants = grant_pair
            measure_bound_through_a_real_grant(report, real_broker, ticket,
                                               grants, probe)
    finally:
        if real_broker is not None:
            real_broker.close()

    broker = CredentialBroker(root=tmp / "run", audit_root=tmp / "state",
                              mirror=False)
    try:
        tcp = tmp / "tcp.py"
        tcp.write_text(TCP_PROBE, encoding="utf-8")

        ticket = broker.open_grant(mission="probe", session="live", provider="probe",
                                   identity=IDENTITY, value=secret)
        endpoint = broker.endpoint("live")
        sock = broker.socket_path("live")

        # 1. The residual that ships today.
        done = run(sandbox([ENV], setenv=[(IDENTITY, secret)]))
        say("env-delivery-readable",
            {"readable": secret in done.stdout,
             "how": "bwrap --setenv, then one `env` in the sandbox",
             "note": "this is what Firebreak does now"})

        # 2. The broker, from inside a namespace with no interfaces.
        done = run(sandbox([PYTHON, str(probe), str(sock), ticket, IDENTITY],
                           binds=[endpoint, probe]))
        first = result_line(done.stdout) or {"error": done.stderr[-200:]}
        say("broker-value-readable",
            {"connected": first.get("connected"),
             "value_returned": bool(first.get("answer", {}).get("value") == secret),
             "note": "REACHED, and it is meant to. A value broker hands the "
                     "value to whoever is allowed to ask; what changed is that "
                     "the asking is single, bounded and recorded"})

        # 3. ...and yet there is nothing in the environment.
        done = run(sandbox([ENV], binds=[endpoint]))
        say("broker-env-clean",
            {"identity_present": IDENTITY in done.stdout,
             "value_present": secret in done.stdout})

        # 4. The grant is what makes it reachable.
        done = run(sandbox([PYTHON, str(probe), str(sock), ticket, IDENTITY],
                           binds=[probe]))
        unbound = result_line(done.stdout) or {"error": done.stderr[-200:]}
        say("unbound-endpoint",
            {"connected": unbound.get("connected"), "errno": unbound.get("errno"),
             "error": unbound.get("error")})

        # 5. Replay, from inside.
        done = run(sandbox([PYTHON, str(probe), str(sock), ticket, IDENTITY],
                           binds=[endpoint, probe]))
        second = result_line(done.stdout) or {"error": done.stderr[-200:]}
        say("replay-refused",
            {"ok": second.get("answer", {}).get("ok"),
             "code": second.get("answer", {}).get("code")})

        # 6. Another mission's ticket on this endpoint.
        other = broker.open_grant(mission="probe-2", session="other",
                                  provider="probe", identity=IDENTITY, value=secret)
        done = run(sandbox([PYTHON, str(probe), str(sock), other, IDENTITY],
                           binds=[endpoint, probe]))
        cross = result_line(done.stdout) or {"error": done.stderr[-200:]}
        say("wrong-session-refused",
            {"ok": cross.get("answer", {}).get("ok"),
             "code": cross.get("answer", {}).get("code")})

        # 7. What the sandbox can see of the broker's own process.
        done = run(sandbox([LS, "/proc"], binds=[endpoint]))
        pids = sorted(int(n) for n in done.stdout.split() if n.isdigit())
        say("host-pids-visible",
            {"broker_pid": os.getpid(), "broker_pid_visible": os.getpid() in pids,
             "pids_in_sandbox": pids,
             "note": "--unshare-pid, so there is no /proc/<broker>/mem to read "
                     "and nothing to ptrace"})

        # 8. Can the thief reach the record of the theft?
        done = run(sandbox([CAT, str(broker.audit.path)], binds=[endpoint]))
        say("audit-readable-from-sandbox",
            {"exit_code": done.returncode,
             "readable": done.returncode == 0 and secret[:8] in done.stdout,
             "path": str(broker.audit.path)})

        # 9. TCP to the host's loopback, from the same sandbox.
        done = run(sandbox([PYTHON, str(tcp)], binds=[endpoint, tcp]))
        say("tcp-host-loopback", result_line(done.stdout)
            or {"error": done.stderr[-200:]})

        # 10. A ticket presented after the mission ended.
        third = broker.open_grant(mission="probe-3", session="ending",
                                  provider="probe", identity=IDENTITY, value=secret)
        ending_sock = broker.socket_path("ending")
        ending_endpoint = broker.endpoint("ending")
        broker.close_grant(session="ending")
        socket_gone = not ending_sock.exists()
        broker.open_grant(mission="probe-4", session="ending", provider="probe",
                          identity=IDENTITY, value=secret)
        done = run(sandbox([PYTHON, str(probe), str(ending_sock), third, IDENTITY],
                           binds=[ending_endpoint, probe]))
        after = result_line(done.stdout) or {"error": done.stderr[-200:]}
        audited = [r for r in broker.audit.rows()
                   if r.get("code") == sf_broker.Refusal.REVOKED]
        say("after-close-refused",
            {"socket_removed_on_close": socket_gone,
             "answer_to_caller": after.get("answer", {}).get("code"),
             "recorded_in_audit_as": audited[-1]["code"] if audited else None,
             "note": "the caller is told unknown_ticket so the broker is not an "
                     "oracle for grant lifetimes; the audit knows the difference"})

        # 11. The flood that used to evict the consumer.
        measure_flood(report, broker, tmp)

        # 12. The chain, before and after one edited byte.
        before = broker.audit.verify(anchor=False)
        rows = broker.audit.path.read_text(encoding="utf-8").splitlines()
        target = next(i for i, line in enumerate(rows)
                      if '"credential-issued"' in line)
        rows[target] = rows[target].replace('"decision":"issued"',
                                            '"decision":"refused"')
        broker.audit.path.write_text("".join(r + "\n" for r in rows),
                                     encoding="utf-8")
        after_edit = broker.audit.verify(anchor=False)
        say("audit-chain-detects-edit",
            {"clean_before": before["ok"], "rows": before["rows"],
             "clean_after_one_edited_field": after_edit["ok"],
             "first_bad_seq": after_edit["first_bad_seq"],
             "reason": after_edit["reason"]})

        # 13. The bypass the three enumerated anchor checks did not cover.
        # Done LAST, because it rewrites the audit file out from under
        # everything above.
        measure_rechain(report, broker)
    finally:
        broker.close()
        shutil.rmtree(tmp, ignore_errors=True)

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    print("stage D -- credential broker, measured on this kernel")
    print("=" * 62)
    for name, value in report["measurements"].items():
        print("%-28s %s" % (name, json.dumps(value, sort_keys=True)))
    print("=" * 62)
    print("The value came back through the broker on purpose. A value broker "
          "bounds WHO asks,\nHOW OFTEN, FOR WHICH identity and WITH WHAT RECORD. "
          "It does not make the value\nunreachable, and no row above says it does."
          "\n\nWhat it also does not buy: an environment value cannot fail to be "
          "delivered and a\nbroker can. A flood no longer takes the consumer's "
          "answer away -- that is the\nflood-cannot-evict-consumer row -- but a "
          "broker that is not running is a mission\nthat cannot authenticate, "
          "which is a failure mode --setenv does not have.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
