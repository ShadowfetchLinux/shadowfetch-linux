#!/usr/bin/env python3
"""Publish the accepted 4.0 artifacts; preserve every previous release object.

Run on the Linux publisher with AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and
SHADOWFETCH_R2_ENDPOINT in the process environment. Credentials are never
written into the source tree. A plan is the default; --apply performs uploads.
The signed APT InRelease is the final object written.
"""
from __future__ import annotations
import argparse
from dataclasses import dataclass
import getpass
import hashlib
import json
import mimetypes
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

VERSION = "4.0.0"
BUCKET = "shadowfetch-linux"
PUBLISHER = Path("/home/rtx5060ti/projects/shadowfetch-4.0.0")
ROOT = Path(__file__).resolve().parents[1]
FINGERPRINT = "8F13CE1535EE1F4A2916A1F73C5C900B7BE80CA1"
ISO = f"shadowfetch-{VERSION}-amd64.iso"
EVIDENCE = (
    f"dossier-{VERSION}.md", f"packages-{VERSION}.manifest",
    f"sbom-{VERSION}.cdx.json", f"sbom-sources-{VERSION}.txt",
    f"release-facts-{VERSION}.json", f"release-evidence-{VERSION}.sha256",
    f"evidence-bundle-{VERSION}.tar.gz", f"evidence-bundle-{VERSION}.contents",
)

@dataclass(frozen=True)
class Object:
    path: Path
    key: str
    sha256: str
    size: int
    mutable: bool = False

def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

def object_for(path, key, mutable=False):
    if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
        raise ValueError(f"Missing, empty or symbolic-link release file: {path}")
    if key.startswith("/") or ".." in key.split("/"):
        raise ValueError("Object key escapes its release prefix")
    return Object(path, key, digest(path), path.stat().st_size, mutable)

def publication_plan(root):
    manifest = json.loads((root / "qa/4.0.0/acceptance.json").read_text())
    artifact = manifest.get("artifact", {})
    iso = object_for(root / ISO, "releases/" + ISO)
    if iso.sha256 != artifact.get("iso_sha256") or iso.size != artifact.get("iso_size_bytes"):
        raise ValueError("ISO differs from the accepted artifact")
    release = root / "work/release-4.0.0"
    objects = [iso]
    objects.extend(object_for(root / name, "releases/" + name) for name in (ISO + ".sha256", ISO + ".asc"))
    objects.extend(object_for(release / name, "releases/" + name) for name in EVIDENCE)
    bundle = next(item for item in objects if item.path.name == f"evidence-bundle-{VERSION}.tar.gz")
    if bundle.sha256 != artifact.get("evidence_bundle_sha256"):
        raise ValueError("Evidence bundle differs from the accepted artifact")
    objects.append(object_for(root / "repo/shadowfetch.gpg.asc", "shadowfetch.gpg.asc"))
    pool = root / "repo/pool"
    pool_files = sorted(path for path in pool.rglob("*") if path.is_file())
    if not pool_files:
        raise ValueError("APT package/source pool is empty")
    objects.extend(object_for(path, "apt/pool/" + path.relative_to(pool).as_posix()) for path in pool_files)
    dists = root / "repo/dists"
    metadata = [object_for(path, "apt/dists/" + path.relative_to(dists).as_posix(), True) for path in dists.rglob("*") if path.is_file()]
    # Indices first, detached metadata next, atomic signed index last.
    def order(item):
        terminal = {"apt/dists/umbra/Release.gpg": 1, "apt/dists/umbra/Release": 2, "apt/dists/umbra/InRelease": 3}
        return terminal.get(item.key, 0), item.key
    metadata.sort(key=order)
    if not metadata or metadata[-1].key != "apt/dists/umbra/InRelease":
        raise ValueError("APT signed InRelease is absent")
    objects.extend(metadata)
    if len({item.key for item in objects}) != len(objects):
        raise ValueError("Duplicate publication object key")
    return objects

def remote_digest(client, key):
    response = client.get_object(Bucket=BUCKET, Key=key)
    checksum = hashlib.sha256()
    try:
        for chunk in response["Body"].iter_chunks(chunk_size=8 * 1024**2):
            checksum.update(chunk)
    finally:
        response["Body"].close()
    return checksum.hexdigest()

def existing_matches(client, item):
    try:
        head = client.head_object(Bucket=BUCKET, Key=item.key)
    except Exception as error:
        if str(getattr(error, "response", {}).get("Error", {}).get("Code")) in ("404", "NoSuchKey", "NotFound"):
            return False
        raise
    if head["ContentLength"] == item.size:
        actual = head.get("Metadata", {}).get("sha256") or remote_digest(client, item.key)
        if actual == item.sha256:
            return True
    if not item.mutable:
        raise ValueError(f"Refusing to replace a different immutable object: {item.key}")
    return False

def publish(client, objects):
    from boto3.s3.transfer import TransferConfig
    config = TransferConfig(multipart_threshold=64 * 1024**2, multipart_chunksize=64 * 1024**2, max_concurrency=4)
    # Resolve collisions across the entire plan before the first upload.
    matches = {item.key: existing_matches(client, item) for item in objects}
    for item in objects:
        if matches[item.key]:
            print("UNCHANGED " + item.key, flush=True)
            continue
        media_type = "application/x-iso9660-image" if item.path.name.endswith(".iso") else mimetypes.guess_type(item.path.name)[0] or "application/octet-stream"
        if item.path.name.endswith(".asc"):
            media_type = "application/pgp-signature" if item.path.name != "shadowfetch.gpg.asc" else "application/pgp-keys"
        print(f"UPLOAD {item.key} {item.size} bytes", flush=True)
        client.upload_file(str(item.path), BUCKET, item.key, Config=config, ExtraArgs={
            "ContentType": media_type,
            "CacheControl": "public, max-age=0, must-revalidate" if item.mutable else "public, max-age=3600",
            "Metadata": {"release": VERSION, "sha256": item.sha256},
        })
        head = client.head_object(Bucket=BUCKET, Key=item.key)
        if head["ContentLength"] != item.size or head.get("Metadata", {}).get("sha256") != item.sha256:
            raise ValueError("Uploaded object readback failed: " + item.key)
    # Independently stream the large object back; metadata alone is not proof.
    iso = next(item for item in objects if item.path.name == ISO)
    if remote_digest(client, iso.key) != iso.sha256:
        raise ValueError("R2 ISO bytes do not match the accepted artifact")
    print("R2_RELEASE_BYTES_VERIFIED", flush=True)

def verify_signatures(root):
    key = root / "repo/shadowfetch.gpg.asc"
    fingerprints = subprocess.check_output(["gpg", "--batch", "--with-colons", "--show-keys", str(key)], text=True)
    if FINGERPRINT not in [row.split(":")[9] for row in fingerprints.splitlines() if row.startswith("fpr:")]:
        raise ValueError("Repository key differs from the official release fingerprint")
    with tempfile.TemporaryDirectory(prefix="shadowfetch-publication-key-") as temporary:
        keyring = Path(temporary) / "release.gpg"
        subprocess.run(["gpg", "--batch", "--yes", "--dearmor", "--output", str(keyring), str(key)], check=True)
        subprocess.run(["gpgv", "--keyring", str(keyring), str(root / (ISO + ".asc")), str(root / ISO)], check=True)
        subprocess.run(["gpgv", "--keyring", str(keyring), str(root / "repo/dists/umbra/InRelease")], check=True)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    subprocess.run([sys.executable, str(ROOT / "tools/verify_acceptance_4_0_0.py"), "verify"], check=True)
    subprocess.run([str(ROOT / "tools/pre_release_check.sh")], check=True, env=dict(os.environ, ROOT=str(ROOT), REPO_MIN_VALID_FOR_SECONDS=str(7 * 86400)))
    subprocess.run(["sha256sum", "--check", ISO + ".sha256"], cwd=ROOT, check=True)
    verify_signatures(ROOT)
    plan = publication_plan(ROOT)
    if not args.apply:
        print(json.dumps([{"key": item.key, "bytes": item.size, "sha256": item.sha256, "mutable": item.mutable} for item in plan], indent=2))
        return 0
    if sys.platform != "linux" or ROOT != PUBLISHER or getpass.getuser() != "rtx5060ti":
        raise ValueError("Release publication must run from the authorized Linux 4.0 source tree")
    endpoint = os.environ.get("SHADOWFETCH_R2_ENDPOINT", "")
    if not re.fullmatch(r"https://[a-f0-9]{32}\.r2\.cloudflarestorage\.com", endpoint):
        raise ValueError("Set the account's HTTPS R2 endpoint")
    for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"):
        if not os.environ.get(name):
            raise ValueError("Missing process credential: " + name)
    import boto3
    client = boto3.client("s3", endpoint_url=endpoint, region_name="auto")
    publish(client, plan)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
