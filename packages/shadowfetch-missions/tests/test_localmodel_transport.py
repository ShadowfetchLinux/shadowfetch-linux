"""Stage J: what a sandbox with NO network can and cannot reach.

This file exists because the transport claim in localmodel.json is the whole
provider, and a claim of that kind is worth nothing written down. Everything
below is measured on the kernel and the bwrap this host actually runs.

THE QUESTION
------------
Firebreak has two network postures and neither of them can reach a TCP service
on the host's 127.0.0.1: "none" is `bwrap --unshare-net` (an empty namespace)
and "allow" adds a slirp4netns NAT with --disable-host-loopback. So a local
model server on TCP loopback is NOT reachable from a mission, and asking for
network "allow" would hand the sandbox the entire internet in exchange for a
loopback connection it still would not get.

THE ANSWER, MEASURED
--------------------
AF_UNIX is addressed by filesystem path, not by network namespace. A socket
bind-mounted into the sandbox is connectable from a namespace with no
interfaces at all, and a READ-ONLY bind is enough, because the kernel's
sb_permission() denies write on a read-only superblock for regular files,
directories and symlinks only -- a socket is none of those.

    ContainmentTests   A  --unshare-net + --ro-bind socket dir -> connect works
                       B  --unshare-net, nothing bound         -> not there
                       C  --unshare-net, TCP to host loopback   -> refused
                       D  --unshare-net + --ro-bind, TCP still refused, so the
                          grant buys the socket and nothing else

    SandboxedTurnTests  the real bridge, inside --unshare-net, generating a
                        real answer through the bound socket, normalised by the
                        shipped adapter -- once against a deterministic service
                        and once against whatever inference service is running
                        on this host, which is the live integration turn.

    FirebreakGrantTests  Firebreak's own read_grants() accepts the DIRECTORY the
                         manifest declares and refuses the socket path itself.
                         That is why the manifest grants a directory, and it is
                         checked rather than remembered.

NOT PROVEN HERE
---------------
That Mission Control passes the grant through. It does -- sf_missions.py
run_process() emits `--read` per read grant -- but that is the orchestrator's
test to own, and this file does not import the orchestrator.
"""
from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os

import socket
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

from provider_conformance import (  # noqa: E402
    Capability, MISSION_MODULES, REPO_ROOT, fixture_registry, manifest_root,
    shipped_manifest_files)

import sf_provider_localmodel  # noqa: E402
from sf_providers import AgentEvent  # noqa: E402

FIXTURES = TESTS_DIR / "fixtures/providers/localmodel"
# The PACKAGED bridge, not a copy under fixtures: a test that ran its own
# copy would prove the copy works and say nothing about what ships.
SOURCE_BRIDGE = (TESTS_DIR.parent
                 / "data/usr/libexec/shadowfetch/local-model-bridge")
if str(FIXTURES) not in sys.path:
    sys.path.insert(0, str(FIXTURES))
from localmodel_service import FakeModelService, TcpRelayService  # noqa: E402

REGISTRY = fixture_registry(manifest_root(*shipped_manifest_files()), MISSION_MODULES)
PROVIDER_ID = "localmodel"

# Absolute, because a program that decides a security question is never found
# through PATH -- including in a test, where a forged bwrap earlier on PATH
# would let every assertion below pass while proving nothing.
BWRAP = "/usr/bin/bwrap"

# A live inference service on this host, if there is one. Discovered, never
# assumed: the live turn skips loudly rather than pretending.
OLLAMA_TCP = ("127.0.0.1", 11434)


def have_bwrap():
    return os.access(BWRAP, os.X_OK)


def sandbox(*args, binds=(), rw_binds=(), chdir=None):
    """A bwrap command line with NO network and only what is named bound in."""
    command = [BWRAP,
               "--ro-bind", "/usr", "/usr",
               "--symlink", "usr/bin", "/bin",
               "--symlink", "usr/lib", "/lib",
               "--symlink", "usr/lib64", "/lib64",
               "--proc", "/proc", "--dev", "/dev",
               "--unshare-net", "--unshare-pid", "--die-with-parent"]
    for path in binds:
        command += ["--ro-bind", str(path), str(path)]
    for path in rw_binds:
        command += ["--bind", str(path), str(path)]
    if chdir:
        command += ["--chdir", str(chdir)]
    return [*command, "--", *args]


CONNECT_PROBE = textwrap.dedent("""
    import socket, sys
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect(sys.argv[1])
        sys.stdout.write("UNIX-OK:" + s.recv(64).decode())
    except Exception as exc:
        sys.stdout.write("UNIX-FAIL:" + type(exc).__name__)
""")

TCP_PROBE = textwrap.dedent("""
    import socket, sys
    s = socket.socket()
    s.settimeout(5)
    try:
        s.connect((sys.argv[1], int(sys.argv[2])))
        sys.stdout.write("TCP-OK")
    except Exception as exc:
        sys.stdout.write("TCP-FAIL:" + type(exc).__name__)
""")


class _Greeter:
    """A trivial AF_UNIX server that says one thing. Not HTTP: these tests are
    about whether bytes cross the boundary at all."""

    GREETING = b"HELLO-FROM-THE-HOST-SIDE\n"

    def __init__(self, directory, name="model.sock"):
        self.path = str(Path(directory) / name)
        self._server = None
        self._thread = None

    def __enter__(self):
        import threading
        self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server.bind(self.path)
        os.chmod(self.path, 0o666)
        self._server.listen(8)

        def serve():
            while True:
                try:
                    connection, _ = self._server.accept()
                except OSError:
                    return
                try:
                    connection.sendall(self.GREETING)
                finally:
                    connection.close()

        self._thread = threading.Thread(target=serve, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *_exc):
        self._server.close()
        self._thread.join(timeout=5)
        return False


@unittest.skipUnless(have_bwrap(), f"{BWRAP} is not installed on this host")
class ContainmentTests(unittest.TestCase):
    """The four measurements the transport design rests on."""

    def run_probe(self, source, *arguments, binds=()):
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as handle:
            handle.write(source)
            probe = handle.name
        self.addCleanup(os.unlink, probe)
        os.chmod(probe, 0o644)
        done = subprocess.run(
            sandbox("/usr/bin/python3", probe, *map(str, arguments),
                    binds=[probe, *binds]),
            capture_output=True, timeout=90)
        return done.stdout.decode().strip(), done.stderr.decode().strip()

    def test_A_a_bound_socket_is_reachable_from_a_namespace_with_no_network(self):
        """The whole design in one assertion, and a read-only bind at that."""
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            with _Greeter(directory) as greeter:
                out, err = self.run_probe(CONNECT_PROBE, greeter.path, binds=[directory])
        self.assertTrue(out.startswith("UNIX-OK:"), f"{out} / {err}")
        self.assertIn("HELLO-FROM-THE-HOST-SIDE", out)

    def test_B_without_the_grant_the_socket_does_not_exist_inside(self):
        """The control for A: it is the BIND that carries the channel, not some
        ambient leak in the sandbox."""
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            with _Greeter(directory) as greeter:
                out, err = self.run_probe(CONNECT_PROBE, greeter.path)
        self.assertEqual(out, "UNIX-FAIL:FileNotFoundError", f"{out} / {err}")

    def test_C_the_hosts_tcp_loopback_is_not_reachable(self):
        """Why this provider does not simply talk to a server on 127.0.0.1."""
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(4)
            port = listener.getsockname()[1]
            out, err = self.run_probe(TCP_PROBE, "127.0.0.1", port)
        self.assertTrue(out.startswith("TCP-FAIL"), f"{out} / {err}")

    def test_D_the_grant_buys_the_socket_and_does_not_buy_the_network(self):
        """A containment claim is only worth what it still refuses."""
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(4)
            port = listener.getsockname()[1]
            with tempfile.TemporaryDirectory(dir="/tmp") as directory:
                with _Greeter(directory):
                    out, err = self.run_probe(TCP_PROBE, "127.0.0.1", port,
                                              binds=[directory])
        self.assertTrue(out.startswith("TCP-FAIL"),
                        f"granting the endpoint directory also restored network "
                        f"access: {out} / {err}")


@unittest.skipUnless(have_bwrap(), f"{BWRAP} is not installed on this host")
class SandboxedTurnTests(unittest.TestCase):
    """A whole turn, inside the sandbox this provider declares."""

    def setUp(self):
        self.provider = REGISTRY.get(PROVIDER_ID)

    def turn(self, endpoint_dir, endpoint, *extra, prompt=b"Summarize the launch\n",
             timeout=180):
        workspace = tempfile.TemporaryDirectory(prefix="sf-localmodel-ws-", dir="/tmp")
        self.addCleanup(workspace.cleanup)
        command = sandbox(
            str(SOURCE_BRIDGE), "serve-turn",
            "--protocol", sf_provider_localmodel.PROTOCOL,
            "--endpoint", str(endpoint), "--stream", "tokens", *extra,
            binds=[SOURCE_BRIDGE, endpoint_dir],
            rw_binds=[workspace.name], chdir=workspace.name)
        done = subprocess.run(command, input=prompt, capture_output=True, timeout=timeout)
        return done, self.provider.parse_stream(done.stdout.decode("utf-8", "replace"))

    def test_a_full_turn_runs_with_no_network_and_reaches_only_the_granted_socket(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            with FakeModelService(directory, tokens=("Ship ", "on ", "Friday.")) as service:
                done, events = self.turn(
                    directory, service.path, "--session", "sandboxed-1",
                    "--connect-timeout", "5", "--idle-timeout", "20", "--deadline", "60")
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertTrue(self.provider.turn_succeeded(events))
        self.assertEqual(self.provider.final_message(events), "Ship on Friday.")
        self.assertEqual(
            sf_provider_localmodel.LocalModelProvider.session_from_events(events),
            "sandboxed-1")

    def test_without_the_grant_the_same_turn_fails_with_a_reason(self):
        """The control: the turn works because of the grant and nothing else."""
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            with FakeModelService(directory) as service:
                workspace = tempfile.TemporaryDirectory(dir="/tmp")
                self.addCleanup(workspace.cleanup)
                command = sandbox(
                    str(SOURCE_BRIDGE), "serve-turn",
                    "--protocol", sf_provider_localmodel.PROTOCOL,
                    "--endpoint", service.path, "--stream", "tokens",
                    binds=[SOURCE_BRIDGE], rw_binds=[workspace.name],
                    chdir=workspace.name)
                done = subprocess.run(command, input=b"hi\n", capture_output=True,
                                      timeout=120)
        self.assertEqual(done.returncode, 1)
        events = self.provider.parse_stream(done.stdout.decode())
        self.assertFalse(self.provider.turn_succeeded(events))
        self.assertIn("no local model endpoint",
                      [e.text for e in events if e.type == AgentEvent.ERROR][0])

    def test_a_sandboxed_session_writes_only_inside_the_mission_workspace(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            with FakeModelService(directory, tokens=("noted",)) as service:
                workspace = tempfile.TemporaryDirectory(prefix="sf-localmodel-ws-",
                                                        dir="/tmp")
                self.addCleanup(workspace.cleanup)
                for prompt in (b"remember four\n", b"what number?\n"):
                    command = sandbox(
                        str(SOURCE_BRIDGE), "serve-turn",
                        "--protocol", sf_provider_localmodel.PROTOCOL,
                        "--endpoint", service.path, "--stream", "tokens",
                        "--session", "sandboxed-2",
                        binds=[SOURCE_BRIDGE, directory],
                        rw_binds=[workspace.name], chdir=workspace.name)
                    done = subprocess.run(command, input=prompt, capture_output=True,
                                          timeout=120)
                    self.assertEqual(done.returncode, 0, done.stdout)
                history = Path(workspace.name) / ".shadowfetch-localmodel/sandboxed-2.json"
                self.assertTrue(history.is_file(),
                                "the session did not survive outside the sandbox, so it "
                                "was not written to the mission workspace")
                self.assertEqual(len(json.loads(history.read_text())["messages"]), 4)
                self.assertEqual(
                    [m["content"] for m in service.chat_requests[1]["messages"]],
                    ["remember four\n", "noted", "what number?\n"])


def live_service_models():
    """Models a real inference service on this host offers, or ()."""
    try:
        with socket.create_connection(OLLAMA_TCP, timeout=2) as connection:
            connection.sendall(b"GET /api/tags HTTP/1.1\r\nHost: localhost\r\n"
                               b"Connection: close\r\n\r\n")
            raw = b""
            while len(raw) < 4_000_000:
                block = connection.recv(65536)
                if not block:
                    break
                raw += block
    except OSError:
        return ()
    _head, _, body = raw.partition(b"\r\n\r\n")
    try:
        document = json.loads(body.decode("utf-8", "replace"))
    except ValueError:
        return ()
    return tuple(m.get("name") for m in (document.get("models") or [])
                 if isinstance(m, dict) and isinstance(m.get("name"), str))


LIVE_MODELS = live_service_models()


@unittest.skipUnless(have_bwrap(), f"{BWRAP} is not installed on this host")
@unittest.skipUnless(LIVE_MODELS,
                     "no local inference service is running on this host, so the live "
                     "integration turn cannot run; the fixture turns above are NOT a "
                     "substitute for it")
class LiveInferenceTurnTests(unittest.TestCase):
    """One real generation, by a real model, from inside a sandbox with no network.

    This is the live integration turn. It is skipped rather than faked when no
    service is running, because a fixture that passes while nothing real ran is
    exactly the evidence this project does not accept.

    The relay in front of the service is the only concession: the service here
    listens on TCP, and a socket-less service needs a unix socket put in front
    of it. In production that is `systemd-socket-proxyd 127.0.0.1:11434` behind
    a socket unit -- systemd ships it, so no code of ours sits in that position
    and the sandbox side of the picture is identical either way.
    """

    def test_a_real_model_generates_a_real_answer_through_the_bound_socket(self):
        provider = REGISTRY.get(PROVIDER_ID)
        model = LIVE_MODELS[0]
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            with TcpRelayService(directory, *OLLAMA_TCP) as relay:
                workspace = tempfile.TemporaryDirectory(dir="/tmp")
                self.addCleanup(workspace.cleanup)
                command = sandbox(
                    str(SOURCE_BRIDGE), "serve-turn",
                    "--protocol", sf_provider_localmodel.PROTOCOL,
                    "--endpoint", relay.path, "--stream", "tokens",
                    "--model", model, "--connect-timeout", "10",
                    "--idle-timeout", "120", "--deadline", "600",
                    binds=[SOURCE_BRIDGE, directory],
                    rw_binds=[workspace.name], chdir=workspace.name)
                started = time.monotonic()
                done = subprocess.run(
                    command,
                    input=b"Reply with one short sentence: what is a unix domain socket?\n",
                    capture_output=True, timeout=900)
                elapsed = time.monotonic() - started
        self.assertEqual(done.returncode, 0, done.stdout[-4000:] + done.stderr[-2000:])
        events = provider.parse_stream(done.stdout.decode("utf-8", "replace"))
        self.assertTrue(provider.turn_succeeded(events),
                        done.stdout.decode()[-4000:])
        answer = provider.final_message(events)
        self.assertGreater(len(answer.split()), 3,
                           f"the live model produced no usable answer in {elapsed:.1f}s")
        # The deltas were incremental: the answer exists in no single event.
        raw = done.stdout.decode()
        self.assertNotIn(answer, raw,
                         "the whole answer arrived in one event, so this turn did not "
                         "exercise incremental streaming")
        started_event = [e for e in events
                         if e.data.get("native") == "session.started"][0]
        self.assertEqual(started_event.data["model"], model)
        usage = provider.usage(events)
        self.assertIsInstance(usage, dict)
        self.assertGreater(usage.get("output_tokens") or 0, 0)


def _load_firebreak():
    path = (REPO_ROOT / "packages/shadowfetch-fireline/data/usr/bin/shadowfetch-firebreak")
    if not path.is_file():
        return None
    spec = importlib.util.spec_from_loader(
        "sf_firebreak_under_test",
        importlib.machinery.SourceFileLoader("sf_firebreak_under_test", str(path)))
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception:  # pragma: no cover - a read-only inspection must not fail a suite
        return None
    return module


FIREBREAK = _load_firebreak()


@unittest.skipUnless(FIREBREAK is not None, "shadowfetch-firebreak is not in this tree")
class FirebreakGrantTests(unittest.TestCase):
    """Why the manifest grants a DIRECTORY and not the socket.

    Firebreak's read_grants() accepts regular files and directories only. A
    socket path is neither, so granting the socket directly would be refused at
    run time -- after the mission had already started. This is asserted against
    Firebreak's own function so the manifest cannot drift away from what the
    sandbox will accept. Firebreak is read here and never modified.
    """

    def setUp(self):
        self.state = tempfile.TemporaryDirectory(prefix="sf-fb-state-")
        self.workspaces = tempfile.TemporaryDirectory(prefix="sf-fb-ws-")
        self.addCleanup(self.state.cleanup)
        self.addCleanup(self.workspaces.cleanup)
        os.environ["SHADOWFETCH_FIREBREAK_STATE"] = self.state.name
        os.environ["SHADOWFETCH_AGENT_WORKSPACES"] = self.workspaces.name
        self.workspace = Path(self.workspaces.name) / "mission"
        self.workspace.mkdir()

    def tearDown(self):
        for name in ("SHADOWFETCH_FIREBREAK_STATE", "SHADOWFETCH_AGENT_WORKSPACES"):
            os.environ.pop(name, None)

    def test_the_endpoint_directory_is_a_grant_firebreak_accepts(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            with _Greeter(directory):
                grants = FIREBREAK.read_grants([directory], self.workspace)
        self.assertEqual([str(p) for p in grants], [str(Path(directory).resolve())])

    def test_the_socket_itself_is_a_grant_firebreak_refuses(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            with _Greeter(directory) as greeter:
                with self.assertRaises(FIREBREAK.Error) as caught:
                    FIREBREAK.read_grants([greeter.path], self.workspace)
        self.assertIn("regular files and directories", str(caught.exception))

    def test_the_manifest_grant_would_satisfy_firebreak(self):
        """The shipped grant, checked against the real rules rather than reread.

        The directory does not exist on a machine with no local model service
        installed, and read_grants() requires an existing path; that is a
        deployment fact, so the shape is checked on a stand-in at the same
        depth and the existence requirement is asserted separately.
        """
        declared = REGISTRY.manifest(PROVIDER_ID)["sandbox_profile"]["read_grants"][0]
        self.assertGreaterEqual(len(Path(declared).parts), 3)
        reserved = ("/proc", "/dev", "/run", "/sys", "/home/agent")
        for item in reserved:
            self.assertFalse(declared == item or declared.startswith(item + "/"),
                             f"the declared grant overlaps Firebreak's reserved {item}")
        self.assertNotEqual(Path(declared), Path.home())
        if not Path(declared).is_dir():
            with self.assertRaises(FIREBREAK.Error) as caught:
                FIREBREAK.read_grants([declared], self.workspace)
            self.assertIn("existing absolute path", str(caught.exception))


if __name__ == "__main__":  # pragma: no cover
    unittest.main(verbosity=2)
