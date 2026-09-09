#!/usr/bin/env python3
"""Upload one large R2 object with a scoped Cloudflare API token.

This exists because wrangler's object-upload API cannot carry a multi-GB ISO and
the gated publisher (tools/publish_release_4_0_0.py) needs S3 credentials this
operator may not have. It is the SMALL path, and it is deliberately fenced:

  * It refuses to overwrite an existing immutable artifact. A published ISO or
    its checksum/signature is the object a published SHA-256 refers to; replacing
    those bytes in place makes every prior verification instruction a lie. Only
    mutable APT index objects may be replaced, and only with --replace.
  * It refuses to write releases/CURRENT.json. The current-release pointer is
    written LAST by the gated publisher, after the artifacts it names exist.
  * It refuses to write an ISO that policy/retirement.json declares retired, so
    a retired URL cannot be quietly re-armed with new bytes.
  * It stamps the object with the sha256 it actually computed from the file, and
    with the version parsed from the filename. The previous version stamped
    every object "release": "1.9.0" and wrote no digest at all, which left the
    gated publisher's readback with nothing to compare against.
  * It verifies the upload by size AND by the stamped digest; --verify-bytes
    additionally streams the object back and re-digests it.

It is NOT a release process. It has no acceptance gate, no signature check and
no ordering. Publishing a release is tools/publish_release_4_0_0.py.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import threading
import urllib.request

import boto3
from boto3.s3.transfer import TransferConfig

sys.path.insert(0, str(Path(__file__).resolve().parent))
import r2_prune_release
import release_pointer

RELEASE_PREFIX = "releases/"
IMMUTABLE_SUFFIXES = (".iso", ".sha256", ".asc", ".sig", ".torrent")
VERSION_IN_NAME = re.compile(r"(\d+\.\d+\.\d+)")


class Progress:
    def __init__(self, total: int) -> None:
        self.total = total
        self.seen = 0
        self.next_percent = 10
        self.lock = threading.Lock()

    def __call__(self, amount: int) -> None:
        with self.lock:
            self.seen += amount
            percent = int(self.seen * 100 / self.total)
            if percent >= self.next_percent:
                print(f"Upload progress: {percent}%", flush=True)
                self.next_percent = ((percent // 10) + 1) * 10


def token_id(value: str) -> str:
    request = urllib.request.Request(
        "https://api.cloudflare.com/client/v4/user/tokens/verify",
        headers={"Authorization": f"Bearer {value}"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        body = json.load(response)
    if not body.get("success") or body.get("result", {}).get("status") != "active":
        raise RuntimeError("Cloudflare API token is not active")
    return body["result"]["id"]


def is_immutable(key: str) -> bool:
    """Release artifacts are immutable: their digests are published elsewhere."""
    return key.startswith(RELEASE_PREFIX) and key.endswith(IMMUTABLE_SUFFIXES)


def content_type(key: str) -> str:
    if key.endswith(".iso"):
        return "application/x-iso9660-image"
    if key.endswith(".gpg.asc") or key.endswith(".gpg"):
        return "application/pgp-keys"
    if key.endswith(".asc") or key.endswith(".sig"):
        return "application/pgp-signature"
    if key.endswith(".sha256") or key.endswith(".txt"):
        return "text/plain; charset=utf-8"
    if key.endswith(".json"):
        return "application/json; charset=utf-8"
    if key.endswith(".torrent"):
        return "application/x-bittorrent"
    if key.endswith(".deb"):
        return "application/vnd.debian.binary-package"
    if key.endswith(".gz"):
        return "application/gzip"
    return "application/octet-stream"


def head_or_none(client, bucket: str, key: str):
    try:
        return client.head_object(Bucket=bucket, Key=key)
    except Exception as error:  # noqa: BLE001 - boto3 raises a client-specific error
        code = str(getattr(error, "response", {}).get("Error", {}).get("Code", ""))
        if code in ("404", "NoSuchKey", "NotFound") or "NoSuchKey" in type(error).__name__:
            return None
        raise


def check_key_allowed(key: str, policy: dict) -> None:
    """Refuse keys this tool must never write, whatever the bucket holds."""
    if key.startswith("/") or ".." in key.split("/"):
        raise RuntimeError(f"Object key escapes its prefix: {key}")
    if key == release_pointer.KEY:
        raise RuntimeError(
            f"{key} is the current-release pointer; only the gated publisher writes it, "
            "and only after the artifacts it names exist"
        )
    name = key[len(RELEASE_PREFIX):] if key.startswith(RELEASE_PREFIX) else ""
    if name and name in r2_prune_release.retired_index(policy):
        raise RuntimeError(
            f"{key} is declared retired in policy/retirement.json; that URL answers 410 "
            "and must not be re-armed with new bytes"
        )


def check_overwrite_allowed(client, bucket: str, key: str, replace: bool) -> None:
    existing = head_or_none(client, bucket, key)
    if existing is None:
        return
    if is_immutable(key):
        raise RuntimeError(
            f"{key} already exists and is an immutable release artifact "
            f"({existing['ContentLength']} bytes); refusing to replace it. Publish under "
            "a new version rather than changing bytes a published checksum refers to."
        )
    if not replace:
        raise RuntimeError(
            f"{key} already exists ({existing['ContentLength']} bytes); pass --replace to "
            "overwrite a mutable object"
        )


def file_digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def remote_digest(client, bucket: str, key: str) -> str:
    response = client.get_object(Bucket=bucket, Key=key)
    checksum = hashlib.sha256()
    try:
        for chunk in response["Body"].iter_chunks(chunk_size=8 * 1024**2):
            checksum.update(chunk)
    finally:
        response["Body"].close()
    return checksum.hexdigest()


def metadata_for(path: Path, digest: str) -> dict[str, str]:
    metadata = {"sha256": digest}
    match = VERSION_IN_NAME.search(path.name)
    if match:
        metadata["release"] = match.group(1)
    return metadata


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path)
    parser.add_argument("key")
    parser.add_argument("--token-file", type=Path, required=True)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--bucket", required=True)
    parser.add_argument("--part-mib", type=int, default=64)
    parser.add_argument("--workers", type=int, default=12)
    parser.add_argument("--abort-existing", action="store_true")
    parser.add_argument(
        "--replace",
        action="store_true",
        help="overwrite an existing MUTABLE object; immutable release artifacts are refused regardless",
    )
    parser.add_argument(
        "--verify-bytes",
        action="store_true",
        help="stream the uploaded object back and re-digest it (slow, exact)",
    )
    parser.add_argument("--policy", type=Path, default=r2_prune_release.POLICY_PATH)
    args = parser.parse_args()

    path = args.file.resolve()
    if not path.is_file():
        raise SystemExit(f"Not a file: {path}")
    policy = r2_prune_release.load_policy(args.policy)
    check_key_allowed(args.key, policy)

    value = args.token_file.read_text(encoding="utf-8").strip()
    client = boto3.client(
        "s3",
        endpoint_url=args.endpoint,
        aws_access_key_id=token_id(value),
        aws_secret_access_key=hashlib.sha256(value.encode("utf-8")).hexdigest(),
        region_name="auto",
    )

    check_overwrite_allowed(client, args.bucket, args.key, args.replace)

    if args.abort_existing:
        marker = None
        aborted = 0
        while True:
            params = {"Bucket": args.bucket, "Prefix": args.key}
            if marker:
                params["KeyMarker"] = marker
            result = client.list_multipart_uploads(**params)
            for upload in result.get("Uploads", []):
                if upload["Key"] == args.key:
                    client.abort_multipart_upload(
                        Bucket=args.bucket, Key=args.key, UploadId=upload["UploadId"],
                    )
                    aborted += 1
            if not result.get("IsTruncated"):
                break
            marker = result.get("NextKeyMarker")
        print(f"Aborted {aborted} incomplete upload(s)", flush=True)

    digest = file_digest(path)
    size = path.stat().st_size
    part_size = args.part_mib * 1024 * 1024
    client.upload_file(
        str(path),
        args.bucket,
        args.key,
        ExtraArgs={
            "ContentType": content_type(args.key),
            "ContentDisposition": f'attachment; filename="{path.name}"',
            "CacheControl": "public, max-age=3600",
            "Metadata": metadata_for(path, digest),
        },
        Config=TransferConfig(
            multipart_threshold=part_size,
            multipart_chunksize=part_size,
            max_concurrency=args.workers,
            use_threads=True,
        ),
        Callback=Progress(size),
    )

    head = client.head_object(Bucket=args.bucket, Key=args.key)
    if head["ContentLength"] != size:
        raise RuntimeError("Published object size does not match the source")
    if head.get("Metadata", {}).get("sha256") != digest:
        raise RuntimeError("Published object digest metadata does not match the source")
    verified = "metadata"
    if args.verify_bytes:
        if remote_digest(client, args.bucket, args.key) != digest:
            raise RuntimeError("Published object bytes do not match the source")
        verified = "bytes"
    print(json.dumps({
        "key": args.key,
        "size": head["ContentLength"],
        "sha256": digest,
        "verified": verified,
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
