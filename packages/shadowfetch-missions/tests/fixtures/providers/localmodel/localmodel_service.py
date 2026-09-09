"""A real local inference service on a real unix socket, for tests.

Not a mock and not an injected transport object: this is an actual AF_UNIX
server speaking the actual HTTP dialect the bridge speaks, so the bridge, the
socket, the chunked decoding and the sandbox bind are all exercised for real.
The only thing that is fake is the model, which emits a scripted token stream
so that assertions can be exact.

Two shapes are provided:

  FakeModelService   deterministic, scriptable -- tokens, stalls, HTTP errors,
                     malformed lines, and a variant that hangs after accepting
  TcpRelayService    forwards a unix socket to a TCP inference service, which
                     is how a live Ollama on 127.0.0.1:11434 is reached from a
                     sandbox that has no network. In production this job is
                     done by systemd-socket-proxyd and no code of ours runs.
"""
from __future__ import annotations

import json
import os
import socket
import socketserver
import sys
import threading
import time
import traceback
from pathlib import Path


class _UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 16

    def handle_error(self, request, client_address):
        """A client that hangs up mid-response is the POINT of several of these
        tests -- cancellation, both timeouts, an oversized line. socketserver
        prints a traceback for each one, which buries the actual test output;
        anything that is not a hang-up is still re-raised."""
        exception = sys.exc_info()[1]
        if isinstance(exception, (BrokenPipeError, ConnectionResetError)):
            return
        traceback.print_exc()


class _Base:
    """Common lifecycle: bind, serve on a thread, unlink on exit."""

    def __init__(self, directory, name="model.sock"):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.path = str(self.directory / name)
        self._server = None
        self._thread = None

    def _handler(self):  # pragma: no cover - subclasses supply one
        raise NotImplementedError

    def __enter__(self):
        try:
            os.unlink(self.path)
        except OSError:
            pass
        self._server = _UnixServer(self.path, self._handler())
        # World-connectable on purpose: the sandbox process is the same uid in
        # these tests, but a production socket is 0660 root:shadowfetch-agent.
        os.chmod(self.path, 0o666)
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        kwargs={"poll_interval": 0.05}, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *_exc):
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
        try:
            os.unlink(self.path)
        except OSError:
            pass
        return False


def _read_request(rfile):
    """Return (method, target, body). Minimal but correct for what we serve."""
    line = rfile.readline()
    if not line:
        return None, None, b""
    try:
        method, target, _version = line.decode("latin-1").split()
    except ValueError:
        return None, None, b""
    length = 0
    while True:
        header = rfile.readline()
        if header in (b"\r\n", b"\n", b""):
            break
        name, _, value = header.decode("latin-1").partition(":")
        if name.strip().lower() == "content-length":
            try:
                length = int(value.strip())
            except ValueError:
                length = 0
    body = rfile.read(length) if length else b""
    return method, target, body


def _send_json(wfile, status, document):
    body = json.dumps(document).encode("utf-8")
    wfile.write(f"HTTP/1.1 {status} X\r\n".encode("latin-1"))
    wfile.write(b"Content-Type: application/json\r\n")
    wfile.write(f"Content-Length: {len(body)}\r\n\r\n".encode("latin-1"))
    wfile.write(body)
    wfile.flush()


def _begin_chunked(wfile):
    wfile.write(b"HTTP/1.1 200 OK\r\n")
    wfile.write(b"Content-Type: application/x-ndjson\r\n")
    wfile.write(b"Transfer-Encoding: chunked\r\n\r\n")
    wfile.flush()


def _chunk(wfile, payload: bytes):
    wfile.write(f"{len(payload):x}\r\n".encode("latin-1"))
    wfile.write(payload)
    wfile.write(b"\r\n")
    wfile.flush()


def _end_chunked(wfile):
    wfile.write(b"0\r\n\r\n")
    wfile.flush()


class FakeModelService(_Base):
    """A scriptable local inference service.

    models        model ids /api/tags reports
    tokens        the deltas /api/chat streams
    delay         seconds between tokens (used for cancel and idle tests)
    status        HTTP status /api/chat answers with (non-200 exercises errors)
    malformed     stream one line that is not JSON, then stop
    stall_after   emit this many tokens and then never write again
    dribble       answer /api/tags one byte at a time, forever. A per-read
                  timeout cannot see this: every recv succeeds. Only a wall
                  clock bound ends it.
    oversized     answer /api/chat with one enormous line and no newline
    """

    def __init__(self, directory, *, models=("test-model:1b",),
                 tokens=("Hello", ", ", "world", "."), delay=0.0, status=200,
                 malformed=False, stall_after=None, dribble=False,
                 oversized=False, name="model.sock"):
        super().__init__(directory, name=name)
        self.dribble = dribble
        self.oversized = oversized
        self.models = tuple(models)
        self.tokens = tuple(tokens)
        self.delay = delay
        self.status = status
        self.malformed = malformed
        self.stall_after = stall_after
        self.chat_requests = []

    def _handler(self):
        service = self

        class Handler(socketserver.StreamRequestHandler):
            timeout = 60

            def handle(self):
                method, target, body = _read_request(self.rfile)
                if target is None:
                    return
                if target.startswith("/api/tags"):
                    if service.dribble:
                        self.wfile.write(b"HTTP/1.1 200 OK\r\n")
                        self.wfile.flush()
                        for _ in range(100_000):
                            self.wfile.write(b"X")
                            self.wfile.flush()
                            time.sleep(0.5)
                        return
                    _send_json(self.wfile, 200, {
                        "models": [{"name": m, "model": m} for m in service.models]})
                    return
                if target.startswith("/api/chat") and method == "POST":
                    try:
                        service.chat_requests.append(json.loads(body.decode("utf-8")))
                    except ValueError:
                        service.chat_requests.append(None)
                    if service.status != 200:
                        _send_json(self.wfile, service.status,
                                   {"error": "the model is not available"})
                        return
                    _begin_chunked(self.wfile)
                    if service.oversized:
                        # One line, no newline, far past any sane bound.
                        for _ in range(4):
                            _chunk(self.wfile, b"x" * 500_000)
                        _end_chunked(self.wfile)
                        return
                    if service.malformed:
                        _chunk(self.wfile, b"this is not json\n")
                        _end_chunked(self.wfile)
                        return
                    for index, token in enumerate(service.tokens):
                        if service.stall_after is not None and index >= service.stall_after:
                            # Accepted, streamed a little, then silent forever.
                            # This is what the idle bound and cancellation are
                            # for, and it is a real socket doing it.
                            time.sleep(600)
                            return
                        if service.delay:
                            time.sleep(service.delay)
                        _chunk(self.wfile, (json.dumps(
                            {"model": service.models[0] if service.models else "none",
                             "message": {"role": "assistant", "content": token},
                             "done": False}) + "\n").encode("utf-8"))
                    _chunk(self.wfile, (json.dumps({
                        "model": service.models[0] if service.models else "none",
                        "message": {"role": "assistant", "content": ""},
                        "done": True, "done_reason": "stop",
                        "prompt_eval_count": 11, "eval_count": len(service.tokens),
                        "total_duration": 123456789}) + "\n").encode("utf-8"))
                    _end_chunked(self.wfile)
                    return
                _send_json(self.wfile, 404, {"error": "no such endpoint"})

        return Handler


class TcpRelayService(_Base):
    """Forward a unix socket to a TCP inference service.

    This is the only piece that has to exist for a socket-less service like
    Ollama, and in production it is `systemd-socket-proxyd 127.0.0.1:11434`
    behind a socket unit -- systemd already ships it, so nothing of ours runs
    in that position. Here it is a few lines so the live test can run without
    installing units on a shared build host.
    """

    def __init__(self, directory, host="127.0.0.1", port=11434, name="model.sock"):
        super().__init__(directory, name=name)
        self.host = host
        self.port = port

    def _handler(self):
        relay = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                upstream = socket.create_connection((relay.host, relay.port), timeout=30)
                try:
                    self.request.settimeout(300)
                    upstream.settimeout(300)
                    pump = threading.Thread(
                        target=_pump, args=(self.request, upstream), daemon=True)
                    pump.start()
                    _pump(upstream, self.request)
                    pump.join(timeout=5)
                finally:
                    for sock in (upstream, self.request):
                        try:
                            sock.close()
                        except OSError:
                            pass

        return Handler


def _pump(source, destination):
    try:
        while True:
            block = source.recv(65536)
            if not block:
                break
            destination.sendall(block)
    except OSError:
        pass
    try:
        destination.shutdown(socket.SHUT_WR)
    except OSError:
        pass
