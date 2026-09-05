"""Verified native Buzz compute without passing prompts to its mesh router.

Contract: Buzz desktop-v0.5.17 pins MeshLLM v0.75.1 (3295c902).
Its /api/runtime/processes exposes local process records. We select only a ready
native inference process, prove that PID owns the advertised listening socket,
and call that native endpoint directly. The 9337 mesh router is never an offline
inference target. This starts no additional model and mutates no Buzz settings.
"""
from __future__ import annotations
import json
import functools
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import urllib.error
import urllib.request

MANAGEMENT = "http://127.0.0.1:3131"
ROUTER = "http://127.0.0.1:9337"
MAX_BODY = 2_000_000
# These are native inference server identities, not an installation mechanism.
NATIVE_EXECUTABLES = {"llama": {"llama-server"}, "skippy": {"skippy-server", "skippy"}}
BUZZ_EXECUTABLE = Path("/usr/bin/buzz-desktop")
BUZZ_MANIFEST = Path("/var/lib/dpkg/info/buzz.md5sums")
BUZZ_VERSION = "0.5.17"

class ComputeError(ValueError):
    pass

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ComputeError("Compute HTTP redirects are refused")

def request(url, payload=None, timeout=3):
    if not re.fullmatch(r"http://127\.0\.0\.1:[0-9]{1,5}/[A-Za-z0-9/_-]+", url):
        raise ComputeError("Only literal loopback compute URLs are accepted")
    body = json.dumps(payload).encode() if payload is not None else None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    call = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    with opener.open(call, timeout=timeout) as response:
        raw = response.read(MAX_BODY + 1)
    if len(raw) > MAX_BODY:
        raise ComputeError("Compute response exceeded the bounded output size")
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ComputeError("Compute response is not an object")
    return data

def valid_name(value):
    return isinstance(value, str) and 0 < len(value.strip()) <= 256 and not any(ord(char) < 32 for char in value)

def protected_file(path):
    metadata = path.lstat()
    return stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0 and not metadata.st_mode & 0o022

@functools.lru_cache(maxsize=2)
def file_hashes(path, identity):
    # Cache only within this controller process, keyed by inode/mtime/ctime/size.
    md5, sha = hashlib.md5(), hashlib.sha256()
    with Path(path).open("rb") as stream:
        while block := stream.read(1024 * 1024):
            md5.update(block)
            sha.update(block)
    return md5.hexdigest(), sha.hexdigest()

def buzz_binary_proof(binary):
    if binary != BUZZ_EXECUTABLE or not protected_file(binary) or not protected_file(BUZZ_MANIFEST):
        raise ComputeError("Embedded Buzz inference requires the protected system package executable")
    try:
        package = subprocess.run(["/usr/bin/dpkg-query", "-W", "-f=${Version} ${db:Status-Abbrev}", "buzz"], capture_output=True, text=True, timeout=3)
    except subprocess.SubprocessError as exc:
        raise ComputeError("Could not verify the embedded Buzz package: " + str(exc))
    if package.returncode or package.stdout.strip() != BUZZ_VERSION + " ii":
        raise ComputeError("Embedded native inference requires the verified Buzz " + BUZZ_VERSION + " package")
    entries = [line.split(None, 1) for line in BUZZ_MANIFEST.read_text().splitlines() if line.strip()]
    expected = [checksum for checksum, name in entries if name == "usr/bin/buzz-desktop"]
    if len(expected) != 1 or not re.fullmatch(r"[a-f0-9]{32}", expected[0]):
        raise ComputeError("Buzz executable is missing from its protected package manifest")
    before = binary.stat()
    identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
    md5, sha = file_hashes(str(binary), identity)
    after = binary.stat()
    if identity != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) or md5 != expected[0]:
        raise ComputeError("Buzz executable does not match the installed package manifest")
    return {"package": "buzz", "version": BUZZ_VERSION, "sha256": sha, "integrity": "root-owned pinned package and matching dpkg file manifest", "mode": "embedded-native-skippy"}

def process_proof(record, proc_root=Path("/proc")):
    if not isinstance(record, dict) or not valid_name(record.get("name")):
        raise ComputeError("Invalid native process record")
    pid, port, backend = record.get("pid"), record.get("port"), record.get("backend")
    if type(pid) is not int or pid < 2 or type(port) is not int or not 1024 <= port <= 65535 or port in (3131, 9337):
        raise ComputeError("Native compute must have a distinct local process and port")
    if backend not in NATIVE_EXECUTABLES or record.get("status") not in ("ready", "serving"):
        raise ComputeError("Model is not a ready supported native backend")
    proc = proc_root / str(pid)
    try:
        if proc.stat().st_uid != os.getuid():
            raise ComputeError("Native model process belongs to a different user")
        binary = Path(os.readlink(proc / "exe"))
        package_proof = None
        if backend == "skippy" and binary == BUZZ_EXECUTABLE:
            package_proof = buzz_binary_proof(binary)
        elif binary.name not in NATIVE_EXECUTABLES[backend]:
            raise ComputeError("Model process executable does not match its native backend")
        # Field 22 is process start time. The command can contain spaces/parens.
        started = (proc / "stat").read_text().rsplit(")", 1)[1].split()[19]
        sockets = set()
        for fd in (proc / "fd").iterdir():
            try:
                target = os.readlink(fd)
            except OSError:
                continue
            if target.startswith("socket:[") and target.endswith("]"):
                sockets.add(target[8:-1])
        owns_port = False
        for line in (proc / "net/tcp").read_text().splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 10 and parts[1] == f"0100007F:{port:04X}" and parts[3] == "0A" and parts[9] in sockets:
                owns_port = True
                break
        if not owns_port:
            raise ComputeError("Native process does not own the advertised loopback listening port")
    except OSError as exc:
        raise ComputeError("Cannot prove native model process/socket ownership: " + str(exc))
    return {"name": record["name"].strip(), "pid": pid, "port": port, "backend": backend, "instance_id": record.get("instance_id"), "process_start": started, "executable": str(binary), "package_identity": package_proof, "local_only_verified": True, "endpoint": f"http://127.0.0.1:{port}", "proof": "Buzz native process inventory + same-user executable + owned loopback socket"}

def local_models():
    try:
        records = request(MANAGEMENT + "/api/runtime/processes").get("processes")
        if not isinstance(records, list):
            return []
        if not no_distributed_stages():
            return []
        models = []
        for record in records[:64]:
            try:
                proof = process_proof(record)
            except (ComputeError, ValueError, IndexError):
                continue
            models.append(proof)
        return models
    except (OSError, ValueError):
        return []

def no_distributed_stages():
    # Pinned MeshLLM exposes stage deployment separately from local processes.
    # Be conservative when any pipeline is present, even beside a local model.
    state = request(MANAGEMENT + "/api/runtime/stages")
    return state.get("stages") == [] and state.get("topologies") == []

def shared_models():
    try:
        records = request(ROUTER + "/v1/models").get("data")
        if not isinstance(records, list):
            return []
        return [{"name": item["id"].strip(), "local_only_verified": False} for item in records[:64] if isinstance(item, dict) and valid_name(item.get("id"))]
    except (OSError, ValueError):
        return []

def target(model, allow_network=False):
    models = local_models()
    candidates = [item for item in models if item["name"] == model] if model else models
    if candidates:
        return candidates[0]
    if allow_network:
        advertised = shared_models()
        if not model and advertised:
            model = advertised[0]["name"]
        if model and any(item["name"] == model for item in advertised):
            return {"name": model, "endpoint": ROUTER, "local_only_verified": False, "proof": "Explicitly allowed Buzz community routing"}
    raise ComputeError("No verified native Buzz model is ready. Open Buzz Settings > Compute and load a model on this computer. Offline missions never send prompts to the mesh router")

def complete(payload, allow_network=False, timeout=180):
    selected = target(payload.get("model", ""), allow_network)
    payload = dict(payload, model=selected["name"])
    if selected["local_only_verified"]:
        # Native Skippy also supports automatic peer-consultation hooks. The
        # pinned vendor request switch must disable every hook for local work.
        payload["mesh_hooks"] = False
        selected["mesh_hooks_enabled"] = False
        if selected.get("backend") == "skippy":
            # Pinned Skippy hides unfinished reasoning; a short task can exhaust
            # its budget with no answer unless the supported template switch
            # explicitly requests direct output.
            payload["reasoning_effort"] = "none"
            payload["chat_template_kwargs"] = dict(payload.get("chat_template_kwargs") or {}, enable_thinking=False)
            selected["reasoning_mode"] = "disabled for bounded artifact generation"
    response = request(selected["endpoint"] + "/v1/chat/completions", payload, timeout=timeout)
    if selected["local_only_verified"]:
        # Detect a disappeared/replaced process before reporting a verified run.
        verified = process_proof(dict(selected, status="ready"))
        if verified["process_start"] != selected["process_start"]:
            raise ComputeError("Native model process changed while inference was running")
        if not no_distributed_stages():
            raise ComputeError("Distributed model stages appeared during native inference; locality cannot be verified")
        selected["distributed_stages"] = "No stage or topology deployments observed before and after inference"
    response["shadowfetch_compute"] = selected
    return response
