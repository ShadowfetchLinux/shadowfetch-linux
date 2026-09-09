#!/usr/bin/env python3
"""Delete only what has been declared obsolete: retired ISO bodies and unreferenced packages.

This is the one program in the tree that deletes published release artifacts, so
it is written to be boring and refusing.

WHAT IT DELETES
  releases/   an ISO body whose version is declared retired in
              policy/retirement.json, and nothing else. Not "everything that is
              not the release being kept" -- that rule is what deleted the
              retired 2.1.x checksums and signatures the 410 pages still link,
              and it would delete the current release's published evidence
              bundle, SBOM and dossier too, because none of those start with the
              kept ISO key.
  apt/pool/   package and source files not referenced by the live Packages and
              Sources indices.

GUARDS, each one for a failure that has actually happened or is one typo away
  * --version must be a bare semantic version. A malformed value is rejected
    before an S3 client exists.
  * The ISO being kept must be present in the bucket. A keep-prefix that matches
    nothing is an abort, never a licence to delete everything.
  * When releases/CURRENT.json exists it decides which release is live: pruning
    while keeping a DIFFERENT version is refused, and a corrupt pointer is
    refused rather than ignored.
  * Retired sidecars (.sha256, .asc, .sig, .torrent) are retained unless the
    policy entry says otherwise, because the 410 page for that image offers them.
  * An ISO that is not declared retired is never deleted -- it is reported. That
    is what makes the 410 pages and the bucket agree: an image leaves the bucket
    only after somebody wrote down that it is retired and where it went.
  * --max-deletes (default 200) bounds the delete set; over the bound the tool
    prints the full preview and aborts.
  * Deleting requires --apply. Without it every line is WOULD_DELETE.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import sys
import urllib.request

import boto3

sys.path.insert(0, str(Path(__file__).resolve().parent))
import release_pointer

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "policy" / "retirement.json"

RELEASE_VERSION = re.compile(r"^\d+\.\d+\.\d+$")
DEFAULT_MAX_DELETES = 200
RELEASE_PREFIX = "releases/"
POINTER_KEY = release_pointer.KEY


def load_policy(path: Path | None = None) -> dict:
    return json.loads((path or POLICY_PATH).read_text(encoding="utf-8"))


def binary_pool_keys(packages: str) -> set[str]:
    return {
        "apt/" + line.split(":", 1)[1].strip()
        for line in packages.splitlines()
        if line.startswith("Filename:")
    }


def source_pool_keys(sources: str) -> set[str]:
    """Return source artifacts referenced by a Debian Sources index."""
    active: set[str] = set()
    for paragraph in sources.split("\n\n"):
        fields: dict[str, list[str]] = {}
        current_field: str | None = None
        for line in paragraph.splitlines():
            if line.startswith((" ", "\t")) and current_field:
                fields[current_field].append(line.strip())
                continue
            if ":" not in line:
                current_field = None
                continue
            name, value = line.split(":", 1)
            current_field = name
            fields[current_field] = [value.strip()] if value.strip() else []

        directory_values = fields.get("Directory", [])
        if not directory_values:
            continue
        directory = directory_values[0].rstrip("/")
        checksum_lines = fields.get("Files") or fields.get("Checksums-Sha256", [])
        for checksum_line in checksum_lines:
            parts = checksum_line.split()
            if len(parts) >= 3:
                active.add(f"apt/{directory}/{parts[-1]}")
    return active


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


def list_prefix(client, bucket: str, prefix: str) -> list[dict]:
    paginator = client.get_paginator("list_objects_v2")
    objects: list[dict] = []
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        objects.extend(page.get("Contents", []))
    return objects


# --------------------------------------------------------------------------- #
# Classification -- pure functions, so the delete set is testable without R2
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Decision:
    key: str
    delete: bool
    reason: str


def release_iso_key(version: str, policy: dict | None = None) -> str:
    """The R2 key of the ISO to keep, refusing an unparseable version.

    A malformed --version used to build a keep-prefix that matched nothing, so
    every object under releases/ looked obsolete and the whole published release
    history was deletable by a typo.
    """
    if not isinstance(version, str) or not RELEASE_VERSION.match(version):
        raise ValueError(
            f"--version must be a semantic version like 4.0.0 (got {version!r})"
        )
    return RELEASE_PREFIX + policy_iso_name(version, policy)


def policy_iso_name(version: str, policy: dict | None = None) -> str:
    template = (policy or {}).get("iso_name_template", "shadowfetch-{version}-amd64.iso")
    return template.replace("{version}", version)


def sidecar_suffixes(policy: dict) -> tuple[str, ...]:
    return tuple(policy.get("sidecar_suffixes", (".sha256", ".asc", ".sig", ".torrent")))


def protected_release_keys(iso_key: str, policy: dict | None = None) -> set[str]:
    """The kept ISO plus the sidecars that must survive it."""
    suffixes = sidecar_suffixes(policy or {})
    return {iso_key} | {iso_key + suffix for suffix in suffixes}


def retired_index(policy: dict) -> dict[str, dict]:
    """Retired ISO filename -> policy entry."""
    return {
        policy_iso_name(entry["version"], policy): entry
        for entry in policy.get("retired", [])
    }


def check_pointer_agreement(document: object, version: str) -> None:
    """Refuse to prune when the published pointer names a different release.

    The pointer is what the world is told is current. Deleting around it on the
    strength of a command-line argument is how a live release gets pruned.
    """
    release_pointer.validate(document)  # raises ValueError, listing every fault
    named = document["version"]  # type: ignore[index]
    if named != version:
        raise RuntimeError(
            f"{POINTER_KEY} names {named} as the current release but --version is "
            f"{version}; refusing to prune. Publish a pointer for {version} first, "
            "or prune the release the pointer actually names."
        )


def classify_release_objects(objects: list[dict], version: str, policy: dict) -> list[Decision]:
    """Decide, for every object under releases/, whether it may be deleted.

    Whitelist, not blacklist: an object is deleted only when it is positively
    identified as a retired release body (or a sidecar the policy says not to
    retain). Everything else is kept and reported, including objects this tool
    has never heard of.
    """
    iso_key = release_iso_key(version, policy)
    keys = {item["Key"] for item in objects}
    if iso_key not in keys:
        raise RuntimeError(
            f"Kept release {iso_key} is not present in the bucket; refusing to prune"
        )

    kept = protected_release_keys(iso_key, policy)
    retired = retired_index(policy)
    suffixes = sidecar_suffixes(policy)

    decisions: list[Decision] = []
    for item in objects:
        key = item["Key"]
        name = key[len(RELEASE_PREFIX):] if key.startswith(RELEASE_PREFIX) else key

        if key in kept:
            decisions.append(Decision(key, False, f"current release {version}"))
            continue
        if key == POINTER_KEY:
            decisions.append(Decision(key, False, "current-release pointer"))
            continue

        entry = retired.get(name)
        if entry is not None:
            decisions.append(Decision(key, True, f"retired {entry['version']} ({entry['status']})"))
            continue

        owner = None
        for suffix in suffixes:
            if name.endswith(suffix):
                owner = retired.get(name[: -len(suffix)])
                if owner is not None:
                    break
        if owner is not None:
            if owner.get("retain_sidecars", True):
                decisions.append(Decision(
                    key, False,
                    f"sidecar retained for retired {owner['version']}: its 410 page offers it",
                ))
            else:
                decisions.append(Decision(
                    key, True, f"sidecar of retired {owner['version']}, retain_sidecars false",
                ))
            continue

        if name.endswith(".iso"):
            decisions.append(Decision(
                key, False,
                "ISO not declared in policy/retirement.json: retiring it is a decision, "
                "not a side effect of a prune",
            ))
            continue

        decisions.append(Decision(key, False, "not classified by the retirement policy"))
    return decisions


def obsolete_release_objects(objects: list[dict], version: str, policy: dict) -> list[dict]:
    """The subset of `objects` this tool is allowed to delete."""
    deletable = {d.key for d in classify_release_objects(objects, version, policy) if d.delete}
    leaked = protected_release_keys(release_iso_key(version, policy), policy) & deletable
    if leaked:
        raise RuntimeError(
            "Delete set contains kept-release sidecars; refusing to prune: "
            + ", ".join(sorted(leaked))
        )
    if POINTER_KEY in deletable:
        raise RuntimeError("Delete set contains the current-release pointer; refusing to prune")
    return [item for item in objects if item["Key"] in deletable]


# --------------------------------------------------------------------------- #
# Command
# --------------------------------------------------------------------------- #

def read_pointer(client, bucket: str) -> object | None:
    """The published pointer document, or None when no pointer exists yet."""
    try:
        body = client.get_object(Bucket=bucket, Key=POINTER_KEY)["Body"].read()
    except Exception as error:  # noqa: BLE001 - boto3 raises a client-specific error
        code = str(getattr(error, "response", {}).get("Error", {}).get("Code", ""))
        if code in ("404", "NoSuchKey", "NotFound") or "NoSuchKey" in type(error).__name__:
            return None
        raise
    return json.loads(body.decode("utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--token-file", type=Path, required=True)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--bucket", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="preview only; this is already the default when --apply is absent",
    )
    parser.add_argument(
        "--max-deletes",
        type=int,
        default=DEFAULT_MAX_DELETES,
        help=(
            "abort instead of deleting when the delete set is larger than this "
            f"(default {DEFAULT_MAX_DELETES})"
        ),
    )
    parser.add_argument(
        "--policy",
        type=Path,
        default=POLICY_PATH,
        help="retirement policy (default policy/retirement.json)",
    )
    args = parser.parse_args()

    if args.apply and args.dry_run:
        parser.error("--apply and --dry-run are mutually exclusive")
    if args.max_deletes < 1:
        parser.error("--max-deletes must be at least 1")
    try:
        release_iso = release_iso_key(args.version)
    except ValueError as error:
        parser.error(str(error))
    policy = load_policy(args.policy)

    value = args.token_file.read_text(encoding="utf-8").strip()
    client = boto3.client(
        "s3",
        endpoint_url=args.endpoint,
        aws_access_key_id=token_id(value),
        aws_secret_access_key=hashlib.sha256(value.encode("utf-8")).hexdigest(),
        region_name="auto",
    )

    pointer = read_pointer(client, args.bucket)
    if pointer is None:
        pointer_state = "absent"
    else:
        check_pointer_agreement(pointer, args.version)
        pointer_state = "agrees"

    packages = client.get_object(
        Bucket=args.bucket,
        Key="apt/dists/umbra/main/binary-amd64/Packages",
    )["Body"].read().decode("utf-8")
    sources = client.get_object(
        Bucket=args.bucket,
        Key="apt/dists/umbra/main/source/Sources",
    )["Body"].read().decode("utf-8")
    active_binary = binary_pool_keys(packages)
    active_sources = source_pool_keys(sources)
    active_pool = active_binary | active_sources
    if not active_binary:
        raise RuntimeError("Active Packages index contains no filenames; refusing to prune")
    if not active_sources:
        raise RuntimeError("Active Sources index contains no filenames; refusing to prune")

    release_objects = list_prefix(client, args.bucket, RELEASE_PREFIX)
    decisions = classify_release_objects(release_objects, args.version, policy)
    obsolete = obsolete_release_objects(release_objects, args.version, policy)
    obsolete.extend(
        item
        for item in list_prefix(client, args.bucket, "apt/pool/")
        if item["Key"] not in active_pool
    )
    obsolete.sort(key=lambda item: item["Key"])
    bytes_to_remove = sum(item["Size"] for item in obsolete)
    over_bound = len(obsolete) > args.max_deletes
    print(
        json.dumps(
            {
                "apply": args.apply,
                "pointer": pointer_state,
                "active_packages": len(active_pool),
                "active_binary_packages": len(active_binary),
                "active_source_files": len(active_sources),
                "objects_to_remove": len(obsolete),
                "bytes_to_remove": bytes_to_remove,
                "kept_release": release_iso,
                "release_objects_retained": sum(1 for d in decisions if not d.delete),
                "max_deletes": args.max_deletes,
                "over_max_deletes": over_bound,
            }
        )
    )
    for decision in sorted(decisions, key=lambda d: d.key):
        if not decision.delete:
            print(f"RETAIN {decision.key} ({decision.reason})")
    deleting = args.apply and not over_bound
    for item in obsolete:
        print(f"{'DELETE' if deleting else 'WOULD_DELETE'} {item['Key']}")

    if over_bound:
        raise RuntimeError(
            f"Delete set of {len(obsolete)} objects exceeds --max-deletes="
            f"{args.max_deletes}; inspect the preview above and re-run with a "
            "higher bound only if every listed key is genuinely obsolete"
        )

    if args.apply:
        for offset in range(0, len(obsolete), 1000):
            batch = obsolete[offset : offset + 1000]
            if batch:
                client.delete_objects(
                    Bucket=args.bucket,
                    Delete={"Objects": [{"Key": item["Key"]} for item in batch]},
                )
        print("Prune complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
