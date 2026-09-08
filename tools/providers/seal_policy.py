#!/usr/bin/env python3
"""Regenerate the approved-provider policy from the shipped manifests.

RUN THIS ONLY WHEN YOU HAVE REVIEWED THE MANIFEST CHANGE.

The approved-provider policy pins each provider by manifest digest. When a
manifest legitimately changes -- a new capability, a new egress host, a version
bump -- the pin must be regenerated, and that regeneration is the moment a human
decides the new privileges are acceptable. This tool prints the privilege diff
and requires --yes so that moment cannot pass unnoticed.

It is deliberately NOT called by make, by any gate, or by CI. A tool that
silently re-digests whatever manifests happen to be present turns the pin into
decoration.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MANIFESTS = ROOT / "packages/shadowfetch-missions/data/usr/share/shadowfetch/providers"
POLICY = (ROOT / "packages/shadowfetch-missions/data/usr/share/shadowfetch"
          / "provider-policy/approved.json")

PINNED = ("package", "interface_version", "capabilities", "credential_ids",
          "network_policy", "egress_allowlist")


def shipped():
    out = {}
    for path in sorted(MANIFESTS.glob("*.json")):
        if path.name == "provider-manifest.schema.json":
            continue
        raw = path.read_bytes()
        out[path.stem] = (json.loads(raw), hashlib.sha256(raw).hexdigest())
    return out


def entry_for(manifest, digest, previous=None):
    entry = {field: manifest.get(field) for field in PINNED}
    entry["manifest_sha256"] = digest
    entry["trust"] = (previous or {}).get("trust", "distro-managed")
    entry["approved_note"] = (previous or {}).get(
        "approved_note", "Reviewed as part of the Shadowfetch release.")
    return entry


def main(argv=None):
    parser = argparse.ArgumentParser(description="Seal the approved-provider policy.")
    parser.add_argument("--yes", action="store_true",
                        help="write the policy; without it this is a dry run")
    args = parser.parse_args(argv)

    try:
        current = json.loads(POLICY.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        current = {"schema_version": 1, "providers": {}}

    found = shipped()
    proposed = {"schema_version": 1, "providers": {}}
    changes = []

    for provider_id, (manifest, digest) in sorted(found.items()):
        was = current["providers"].get(provider_id)
        entry = entry_for(manifest, digest, was)
        proposed["providers"][provider_id] = entry
        if was is None:
            changes.append(
                "NEW PROVIDER   %s: caps=%s net=%s creds=%s"
                % (provider_id, entry["capabilities"], entry["network_policy"],
                   entry["credential_ids"]))
            continue
        for field in PINNED:
            if was.get(field) != entry.get(field):
                changes.append("PRIVILEGE      %s.%s: %r -> %r"
                               % (provider_id, field, was.get(field), entry.get(field)))
        if was.get("manifest_sha256") != digest:
            changes.append("DIGEST         %s: %s... -> %s..."
                           % (provider_id, str(was.get("manifest_sha256"))[:16], digest[:16]))

    for provider_id in sorted(set(current["providers"]) - set(found)):
        changes.append("REMOVED        %s no longer ships" % provider_id)

    print("=" * 72)
    print("APPROVED-PROVIDER POLICY")
    print("  policy:    %s" % POLICY)
    print("  manifests: %d shipped" % len(found))
    print("=" * 72)
    if not changes:
        print("No change. The policy already matches the shipped manifests.")
        return 0
    print("The following PRIVILEGE changes would be approved:\n")
    for line in changes:
        print("  " + line)
    print("\nEach line above is a privilege a provider will be permitted to request.")
    if not args.yes:
        print("\nDry run. Re-run with --yes once you have reviewed these.")
        return 1
    POLICY.parent.mkdir(parents=True, exist_ok=True)
    POLICY.write_text(json.dumps(proposed, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("\nSealed %s" % POLICY)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
