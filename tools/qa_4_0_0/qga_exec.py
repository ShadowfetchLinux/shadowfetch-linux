#!/usr/bin/env python3
"""Execute one shell command through a QEMU guest-agent Unix socket."""

from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
from pathlib import Path
import json
import socket
import sys
import time
from typing import Any


class GuestAgentError(RuntimeError):
    pass


def send_request(connection: socket.socket, payload: dict[str, Any]) -> None:
    connection.sendall(json.dumps(payload, separators=(",", ":")).encode() + b"\n")


def receive_response(connection: socket.socket, buffer: bytearray) -> dict[str, Any]:
    while True:
        newline = buffer.find(b"\n")
        if newline >= 0:
            raw = bytes(buffer[:newline]).lstrip(b"\xff")
            del buffer[: newline + 1]
            if not raw:
                continue
            response = json.loads(raw)
            if "event" not in response:
                return response

        chunk = connection.recv(65536)
        if not chunk:
            raise GuestAgentError("guest-agent socket closed before a response arrived")
        buffer.extend(chunk)


def rpc(
    connection: socket.socket,
    buffer: bytearray,
    execute: str,
    arguments: dict[str, Any] | None = None,
) -> Any:
    request: dict[str, Any] = {"execute": execute}
    if arguments is not None:
        request["arguments"] = arguments
    send_request(connection, request)
    response = receive_response(connection, buffer)
    if "error" in response:
        error = response["error"]
        raise GuestAgentError(
            f"{error.get('class', 'GuestAgentError')}: {error.get('desc', error)}"
        )
    return response.get("return")


def decode_output(result: dict[str, Any], field: str) -> bytes:
    encoded = result.get(field)
    return base64.b64decode(encoded) if encoded else b""


def request_once(socket_path, execute, arguments, timeout=10):
    """Serialize one short RPC transaction, not a command's full running time."""
    with open(socket_path + ".client.lock", "a") as lock:
        end = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= end:
                    raise GuestAgentError("another guest-agent RPC is still in progress")
                time.sleep(.05)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(timeout)
            connection.connect(socket_path)
            buffer = bytearray()
            sync_id = time.time_ns() & 0x7FFFFFFF
            connection.sendall(b"\xff")
            send_request(connection, {"execute": "guest-sync-delimited", "arguments": {"id": sync_id}})
            while time.monotonic() < end:
                if receive_response(connection, buffer).get("return") == sync_id:
                    return rpc(connection, buffer, execute, arguments)
            raise GuestAgentError("guest-agent synchronization observation expired")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("socket_path")
    parser.add_argument("command", nargs="?")
    parser.add_argument("--timeout", type=float, default=120.0, help="Observation timeout; never kills a running guest command")
    parser.add_argument("--pid", type=int, help="Resume observing this existing guest-exec handle; never relaunch")
    parser.add_argument("--detach", action="store_true", help="Return the durable running handle immediately")
    parser.add_argument("--handle-file", type=Path)
    args = parser.parse_args()
    if args.timeout <= 0 or (args.command is None) == (args.pid is None) or (args.pid is not None and args.pid <= 0):
        parser.error("Provide either one command or --pid, and a positive observation timeout")
    pid = args.pid
    handle_file = args.handle_file
    deadline = time.monotonic() + args.timeout
    def save(state, **values):
        nonlocal handle_file
        if pid is None:
            return
        if handle_file is None:
            handle_file = Path(args.socket_path).parent / f"guest-command-{pid}.json"
        data = {"pid": pid, "socket_path": args.socket_path, "state": state, "handle_file": str(handle_file), **values}
        if args.command is not None:
            data["command_sha256"] = hashlib.sha256(args.command.encode()).hexdigest()
        handle_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = handle_file.with_name(handle_file.name + ".tmp")
        tmp.write_text(json.dumps(data, indent=2) + "\n")
        tmp.replace(handle_file)
        return data
    try:
        if pid is None:
            launched = request_once(args.socket_path, "guest-exec", {"path": "/bin/bash", "arg": ["-lc", args.command], "capture-output": True}, min(args.timeout, 10))
            pid = int(launched["pid"])
        handle = save("running")
        if args.detach:
            print(json.dumps(handle))
            return 0
        while True:
            if time.monotonic() >= deadline:
                handle = save("observation-expired", terminal=False)
                print(json.dumps(handle), file=sys.stderr)
                print(f"Guest command may still be running. Resume the same handle with --pid {pid}; do not restart it.", file=sys.stderr)
                return 124
            result = request_once(args.socket_path, "guest-exec-status", {"pid": pid}, min(10, max(.1, deadline - time.monotonic())))
            if result.get("exited"):
                break
            time.sleep(.25)
        code = int(result.get("exitcode", 128 + int(result.get("signal", 0)) if "signal" in result else 1))
        save("exited", terminal=True, exitcode=code, stdout_truncated=bool(result.get("out-truncated")), stderr_truncated=bool(result.get("err-truncated")))
        sys.stdout.buffer.write(decode_output(result, "out-data"))
        sys.stdout.buffer.flush()
        sys.stderr.buffer.write(decode_output(result, "err-data"))
        sys.stderr.buffer.flush()
        if result.get("out-truncated") or result.get("err-truncated"):
            print("QGA output was truncated; read the command's guest log files before claiming complete evidence.", file=sys.stderr)
        return code
    except (GuestAgentError, OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        handle = save("observation-error", terminal=False, error=str(exc))
        if handle:
            print(json.dumps(handle), file=sys.stderr)
        print(f"qga_exec: {exc}", file=sys.stderr)
        if pid is not None:
            print(f"No restart was attempted. Reinspect guest-exec handle {pid} or current VM state.", file=sys.stderr)
        return 125


if __name__ == "__main__":
    raise SystemExit(main())
