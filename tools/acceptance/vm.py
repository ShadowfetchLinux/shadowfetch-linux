#!/usr/bin/env python3
"""QEMU guest control for the VM acceptance harness.

Everything here is deliberately self-contained: no socat, no ffmpeg, no
xdotool. Each external binary is one more thing that must be trusted, and the
framebuffer conversion and guest-agent protocol are small enough to do in
process. The only host binaries used are qemu-system-x86_64 and qemu-img, both
resolved through tools/acceptance/trusted.py.

The harness owns the QEMU process (no -daemonize) for one reason that matters
to the power-loss case: kill_hard() must be able to SIGKILL exactly the process
it started, at a known instant, and observe that it is gone. A daemonised QEMU
found again by PID file is a different, weaker claim.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
import re
import signal
import socket
import struct
import subprocess
import tempfile
import time
import zlib

from . import trusted


class GuestError(RuntimeError):
    pass


class GuestCommandError(GuestError):
    pass


# --- framebuffer -------------------------------------------------------------


def ppm_to_png(ppm: Path, png: Path) -> tuple[int, int]:
    """Convert QEMU's screendump P6 output to PNG. Returns (width, height).

    Written in process rather than shelling out to ffmpeg: a screenshot is
    evidence, and the fewer binaries between the framebuffer and the recorded
    bytes, the shorter the story a reviewer has to believe.
    """
    data = ppm.read_bytes()
    match = re.match(rb"P6\s+(\d+)\s+(\d+)\s+(\d+)\s", data)
    if not match:
        raise GuestError(f"not a binary PPM framebuffer: {ppm}")
    width, height, maximum = (int(value) for value in match.groups())
    if maximum != 255:
        raise GuestError(f"unsupported PPM maximum value {maximum}: {ppm}")
    pixels = data[match.end():]
    expected = width * height * 3
    if len(pixels) != expected:
        raise GuestError(
            f"truncated framebuffer: {len(pixels)} bytes of pixel data, expected "
            f"{expected} for {width}x{height}"
        )
    raw = bytearray()
    stride = width * 3
    for row in range(height):
        raw.append(0)  # PNG filter type 0 (None)
        raw += pixels[row * stride:(row + 1) * stride]

    def chunk(tag: bytes, payload: bytes) -> bytes:
        return (
            struct.pack(">I", len(payload))
            + tag
            + payload
            + struct.pack(">I", zlib.crc32(tag + payload) & 0xFFFFFFFF)
        )

    header = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    png.write_bytes(
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(bytes(raw), 6))
        + chunk(b"IEND", b"")
    )
    return width, height


# --- guest agent -------------------------------------------------------------


class GuestAgent:
    """Minimal QEMU guest-agent client over the VM's Unix socket."""

    def __init__(self, socket_path: Path) -> None:
        self.socket_path = socket_path

    def _connect(self, timeout: float) -> socket.socket:
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(timeout)
        try:
            connection.connect(str(self.socket_path))
        except OSError as error:
            connection.close()
            raise GuestError(f"guest agent socket unavailable: {error}") from error
        return connection

    def _rpc(
        self,
        connection: socket.socket,
        buffer: bytearray,
        execute: str,
        arguments: dict | None = None,
    ):
        request: dict = {"execute": execute}
        if arguments is not None:
            request["arguments"] = arguments
        connection.sendall(json.dumps(request, separators=(",", ":")).encode() + b"\n")
        while True:
            newline = buffer.find(b"\n")
            if newline >= 0:
                raw = bytes(buffer[:newline]).lstrip(b"\xff")
                del buffer[: newline + 1]
                if not raw:
                    continue
                response = json.loads(raw)
                if "event" in response:
                    continue
                if "error" in response:
                    raise GuestError(f"guest agent error: {response['error']}")
                return response.get("return")
            chunk = connection.recv(65536)
            if not chunk:
                raise GuestError("guest agent closed the connection")
            buffer.extend(chunk)

    def _sync(
        self, connection: socket.socket, buffer: bytearray, timeout: float = 15.0
    ) -> int:
        """Resynchronise the agent stream and discard everything stale.

        The 0xFF resync byte is not optional -- it recovers a socket a previous
        client left mid-message -- but the agent answers it with a JSON parse
        error of its own before the sync reply arrives. Treating that error as a
        failure made every guest look dead: the agent was answering perfectly
        and the harness was rejecting its first word. Everything up to the
        matching token is stale by definition and is discarded; only the token
        proves the stream is back in step.
        """
        token = int(time.time() * 1000) & 0x7FFFFFFF
        connection.sendall(
            b"\xff"
            + json.dumps(
                {"execute": "guest-sync-delimited", "arguments": {"id": token}},
                separators=(",", ":"),
            ).encode()
            + b"\n"
        )
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            newline = buffer.find(b"\n")
            if newline < 0:
                chunk = connection.recv(65536)
                if not chunk:
                    raise GuestError("guest agent closed the connection")
                buffer.extend(chunk)
                continue
            raw = bytes(buffer[:newline]).lstrip(b"\xff")
            del buffer[: newline + 1]
            if not raw:
                continue
            try:
                response = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if response.get("return") == token:
                return token
        raise GuestError("guest agent did not synchronise within the deadline")

    def ping(self, timeout: float = 5.0) -> bool:
        try:
            connection = self._connect(timeout)
        except GuestError:
            return False
        buffer = bytearray()
        try:
            self._sync(connection, buffer, timeout=timeout)
            return True
        except (GuestError, OSError, json.JSONDecodeError):
            return False
        finally:
            connection.close()

    def execute(
        self, command: str, timeout: float = 300.0, *, user: str | None = None
    ) -> dict:
        """Run one shell command in the guest and collect its output.

        /bin/sh is spelled absolutely for the same reason every host binary is:
        a relative or PATH-resolved interpreter inside the subject under test
        would let the subject choose what runs. Output from here is EVIDENCE
        (trusted.GUEST_SUBJECT), never a trusted attestation.
        """
        argv = ["-c", command]
        path = "/bin/sh"
        if user is not None:
            path = "/usr/sbin/runuser"
            argv = ["-u", user, "--", "/bin/sh", "-c", command]
        connection = self._connect(30.0)
        buffer = bytearray()
        try:
            self._sync(connection, buffer)
            started = self._rpc(
                connection,
                buffer,
                "guest-exec",
                {"path": path, "arg": argv, "capture-output": True},
            )
            pid = started["pid"]
            deadline = time.monotonic() + timeout
            while True:
                status = self._rpc(
                    connection, buffer, "guest-exec-status", {"pid": pid}
                )
                if status.get("exited"):
                    break
                if time.monotonic() > deadline:
                    raise GuestError(
                        f"guest command did not finish within {timeout}s: {command}"
                    )
                time.sleep(0.5)
        finally:
            connection.close()
        return {
            "command": command,
            "exitcode": status.get("exitcode", status.get("signal", -1)),
            "signal": status.get("signal"),
            "stdout": base64.b64decode(status.get("out-data", "")).decode(
                "utf-8", "replace"
            ),
            "stderr": base64.b64decode(status.get("err-data", "")).decode(
                "utf-8", "replace"
            ),
        }

    def execute_detached(self, command: str) -> int:
        """Start a guest command and return immediately with its guest PID.

        Used by the power-loss case: the restore must be genuinely in flight
        when the machine loses power, so the harness must not be waiting on it.
        """
        connection = self._connect(30.0)
        buffer = bytearray()
        try:
            self._sync(connection, buffer)
            started = self._rpc(
                connection,
                buffer,
                "guest-exec",
                {"path": "/bin/sh", "arg": ["-c", command], "capture-output": False},
            )
            return int(started["pid"])
        finally:
            connection.close()


# --- the machine -------------------------------------------------------------


class Guest:
    """One QEMU virtual machine, owned by this process."""

    def __init__(
        self,
        directory: Path,
        name: str,
        *,
        firmware: str = "bios",
        cpus: int = 6,
        memory_mb: int = 8192,
    ) -> None:
        if firmware not in ("bios", "uefi"):
            raise GuestError(f"firmware must be bios or uefi, got {firmware!r}")
        self.directory = directory
        self.name = name
        self.firmware = firmware
        self.cpus = cpus
        self.memory_mb = memory_mb
        self.directory.mkdir(parents=True, exist_ok=True)
        self.disk = directory / "disk.qcow2"
        # A Unix socket path is limited to 107 bytes. The run directory carries
        # a case name, a UTC stamp and an artifact digest, which is well past
        # that -- QEMU refused to start rather than truncating, which is the
        # right failure but a fatal one. The sockets therefore live in a short
        # private directory; everything durable still lives in the run directory.
        self.socket_dir = Path(tempfile.mkdtemp(prefix="sfa-", dir="/tmp"))
        self.qga_socket = self.socket_dir / "qga.sock"
        self.hmp_socket = self.socket_dir / "hmp.sock"
        self.serial_log = directory / "serial.log"
        self.qemu_log = directory / "qemu.log"
        self.process: subprocess.Popen | None = None
        self.agent = GuestAgent(self.qga_socket)
        self.boots: list[dict] = []

    # -- disks --

    def create_disk(self, gib: int) -> None:
        if self.disk.exists():
            raise GuestError(f"refusing to replace an existing disk: {self.disk}")
        trusted.run("qemu-img", ["create", "-f", "qcow2", str(self.disk), f"{gib}G"])

    def clone_disk(self, base: Path) -> dict:
        """Copy-on-write clone. The base image is never written to.

        Returned provenance goes into the receipt: a case that runs on a disk
        somebody else built must say so rather than imply it installed one.
        """
        base = base.resolve()
        if not base.is_file():
            raise GuestError(f"base image does not exist: {base}")
        if self.disk.exists():
            raise GuestError(f"refusing to replace an existing disk: {self.disk}")
        trusted.run(
            "qemu-img",
            [
                "create",
                "-f",
                "qcow2",
                "-F",
                "qcow2",
                "-b",
                str(base),
                str(self.disk),
            ],
        )
        info = json.loads(
            trusted.run("qemu-img", ["info", "--output=json", str(base)]).stdout
        )
        return {
            "base_image": str(base),
            "base_image_bytes": base.stat().st_size,
            "base_image_mtime_utc": time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime(base.stat().st_mtime)
            ),
            "base_virtual_size": info.get("virtual-size"),
        }

    # -- lifecycle --

    def boot(self, medium: str, iso: Path | None = None, *, note: str = "") -> None:
        if self.is_running():
            raise GuestError(f"{self.name} is already running")
        if medium not in ("live", "installed"):
            raise GuestError(f"medium must be live or installed, got {medium!r}")
        for stale in (self.qga_socket, self.hmp_socket):
            stale.unlink(missing_ok=True)

        argv = [
            "-name",
            f"sf-acceptance-{self.name}",
            "-enable-kvm",
            "-machine",
            "q35,accel=kvm",
            "-cpu",
            "host",
            "-smp",
            str(self.cpus),
            "-m",
            str(self.memory_mb),
            "-drive",
            f"file={self.disk},format=qcow2,if=virtio,cache=writeback,discard=unmap",
            # The plain VGA device is the one that honours EDID here; virtio-vga
            # ignored it and produced a framebuffer too small to be evidence.
            "-device",
            "VGA,edid=on,xres=1920,yres=1080,vgamem_mb=64",
            "-device",
            "qemu-xhci",
            "-device",
            "usb-tablet",
            "-display",
            "none",
            "-device",
            "virtio-serial-pci",
            "-chardev",
            f"socket,path={self.qga_socket},server=on,wait=off,id=qga0",
            "-device",
            "virtserialport,chardev=qga0,name=org.qemu.guest_agent.0",
            "-monitor",
            f"unix:{self.hmp_socket},server=on,wait=off",
            "-serial",
            f"file:{self.serial_log}",
            "-netdev",
            "user,id=net0",
            "-device",
            "virtio-net-pci,netdev=net0",
        ]
        if self.firmware == "uefi":
            code = Path("/usr/share/OVMF/OVMF_CODE_4M.fd")
            template = Path("/usr/share/OVMF/OVMF_VARS_4M.fd")
            variables = self.directory / "OVMF_VARS_4M.fd"
            if not code.is_file() or not template.is_file():
                raise GuestError("OVMF 4M firmware is not installed on this host")
            if not variables.exists():
                variables.write_bytes(template.read_bytes())
            argv[1:1] = [
                "-drive",
                f"if=pflash,format=raw,readonly=on,file={code}",
                "-drive",
                f"if=pflash,format=raw,file={variables}",
            ]
        if medium == "live":
            if iso is None or not iso.is_file():
                raise GuestError(f"live boot needs an ISO: {iso}")
            argv += ["-drive", f"file={iso},media=cdrom,readonly=on", "-boot", "order=d"]
        else:
            argv += ["-boot", "order=c"]

        executable = trusted.resolve("qemu-system-x86_64")
        handle = self.qemu_log.open("ab")
        handle.write(
            f"\n=== boot {len(self.boots) + 1} medium={medium} "
            f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} {note}\n".encode()
        )
        handle.flush()
        self.process = subprocess.Popen(  # noqa: S603 - trusted absolute path
            [str(executable), *argv],
            stdout=handle,
            stderr=handle,
            stdin=subprocess.DEVNULL,
            env=dict(trusted.SAFE_ENV),
            start_new_session=True,
        )
        handle.close()
        self.boots.append(
            {
                "index": len(self.boots) + 1,
                "medium": medium,
                "note": note,
                "pid": self.process.pid,
                "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
        )

    def is_running(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def wait_agent(self, timeout: float = 600.0) -> float:
        """Block until the guest agent answers. Returns seconds waited."""
        started = time.monotonic()
        deadline = started + timeout
        while time.monotonic() < deadline:
            if not self.is_running():
                raise GuestError(
                    f"{self.name} exited before the guest agent came up "
                    f"(qemu rc={self.process.returncode if self.process else '?'})"
                )
            if self.qga_socket.exists() and self.agent.ping():
                return time.monotonic() - started
            time.sleep(2.0)
        raise GuestError(
            f"{self.name}: guest agent did not answer within {timeout:.0f}s"
        )

    def run(self, command: str, timeout: float = 300.0, *, check: bool = False) -> dict:
        result = self.agent.execute(command, timeout=timeout)
        if check and result["exitcode"] != 0:
            raise GuestCommandError(
                f"guest command failed ({result['exitcode']}): {command}\n"
                f"{result['stdout']}{result['stderr']}"
            )
        return result

    def out(self, command: str, timeout: float = 120.0) -> str:
        return self.run(command, timeout=timeout)["stdout"].strip()

    # -- monitor --

    def monitor(self, command: str, timeout: float = 30.0) -> str:
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(timeout)
        try:
            connection.connect(str(self.hmp_socket))
            time.sleep(0.2)
            try:
                connection.recv(65536)  # banner
            except socket.timeout:
                pass
            connection.sendall(command.encode() + b"\n")
            time.sleep(0.4)
            chunks = b""
            connection.settimeout(2.0)
            try:
                while True:
                    data = connection.recv(65536)
                    if not data:
                        break
                    chunks += data
            except socket.timeout:
                pass
            return chunks.decode("utf-8", "replace")
        finally:
            connection.close()

    def screenshot(self, output: Path) -> dict:
        """Capture the framebuffer as a PNG.

        QEMU acknowledges screendump before its asynchronous write finishes, so
        a fresh path is used every time (never accept a previous frame) and the
        file is only read once its declared P6 length is complete and stable.
        """
        output.parent.mkdir(parents=True, exist_ok=True)
        ppm = output.with_suffix(f".{int(time.time() * 1000)}.ppm")
        self.monitor(f'screendump "{ppm}"')
        deadline = time.monotonic() + 10.0
        previous = None
        while time.monotonic() < deadline:
            try:
                header = ppm.open("rb").read(512)
                info = ppm.stat()
            except OSError:
                time.sleep(0.05)
                continue
            match = re.match(rb"P6\s+(\d+)\s+(\d+)\s+(\d+)\s", header)
            if match:
                width, height, maximum = (int(value) for value in match.groups())
                complete = match.end() + width * height * 3
                if width and height and maximum == 255 and info.st_size == complete:
                    signature = (info.st_size, info.st_mtime_ns)
                    if signature == previous:
                        break
                    previous = signature
                else:
                    previous = None
            time.sleep(0.05)
        else:
            ppm.unlink(missing_ok=True)
            raise GuestError(f"QEMU did not finish a framebuffer within 10s: {ppm}")
        width, height = ppm_to_png(ppm, output)
        ppm.unlink(missing_ok=True)
        return {"path": str(output), "width": width, "height": height}

    # -- shutdown --

    def kill_hard(self) -> dict:
        """Power loss. SIGKILL the QEMU process this harness started.

        No graceful anything: no ACPI, no guest sync, no flush. This is the
        negative test's whole point, so it must be the real thing.
        """
        if self.process is None:
            raise GuestError("no QEMU process to kill")
        pid = self.process.pid
        moment = time.strftime("%Y-%m-%dT%H:%M:%S.", time.gmtime()) + f"{time.time() % 1:.3f}"[2:]
        try:
            self.process.send_signal(signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            self.process.wait(timeout=30)
        except subprocess.TimeoutExpired as error:
            raise GuestError(f"QEMU {pid} survived SIGKILL") from error
        returncode = self.process.returncode
        self.process = None
        return {
            "pid": pid,
            "signal": "SIGKILL",
            "at_utc": moment,
            "qemu_returncode": returncode,
        }

    def dispose(self) -> None:
        """Remove the private socket directory once the machine is gone."""
        if self.is_running():
            return
        for path in (self.qga_socket, self.hmp_socket):
            path.unlink(missing_ok=True)
        try:
            self.socket_dir.rmdir()
        except OSError:
            pass

    def shutdown(self, timeout: float = 180.0) -> str:
        if not self.is_running():
            return "already-stopped"
        try:
            self.agent.execute("/usr/bin/systemctl poweroff", timeout=15)
        except (GuestError, OSError):
            pass
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not self.is_running():
                self.process = None
                return "guest-poweroff"
            time.sleep(1.0)
        try:
            self.monitor("quit")
        except OSError:
            pass
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if not self.is_running():
                self.process = None
                return "monitor-quit"
            time.sleep(0.5)
        self.kill_hard()
        return "killed"

    def reboot(self, timeout: float = 600.0) -> dict:
        """Reboot through the guest and prove it really rebooted.

        Comparing boot_id is what makes this an observation rather than a hope:
        a guest that ignored the reboot would otherwise answer the agent
        immediately and look like a successful restart.
        """
        before = self.out("cat /proc/sys/kernel/random/boot_id")
        try:
            self.agent.execute_detached("/usr/bin/systemctl reboot")
        except GuestError:
            pass
        time.sleep(8.0)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not self.is_running():
                raise GuestError("QEMU exited during reboot")
            if self.qga_socket.exists() and self.agent.ping():
                after = self.out("cat /proc/sys/kernel/random/boot_id")
                if after and after != before:
                    return {"boot_id_before": before, "boot_id_after": after}
            time.sleep(3.0)
        raise GuestError(f"guest did not come back within {timeout:.0f}s of reboot")
