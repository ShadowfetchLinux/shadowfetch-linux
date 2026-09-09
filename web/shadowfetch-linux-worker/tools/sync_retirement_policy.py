#!/usr/bin/env python3
"""Keep src/retirement.js identical to policy/retirement.json.

The retirement policy has two consumers in two languages: the Cloudflare Worker
(JavaScript, bundled — it cannot read a repository file at request time) and the
prune tool (Python). Restating the policy in both is how the 410 pages and the
delete set drifted apart in the first place: the pages promised checksum and
signature sidecars for retired images while the prune tool deleted exactly those
sidecars.

So the JSON is the source and the JavaScript is a mirror containing nothing but
that JSON, generated here and gated by tests/test_retirement_policy.py. JSON is
a subset of JavaScript object-literal syntax, so the mirror is literal, not a
translation, and the check is an exact document comparison rather than a
best-effort parse of hand-written code.

    python3 tools/sync_retirement_policy.py --check    # exits 1 on divergence
    python3 tools/sync_retirement_policy.py --write    # regenerate the mirror
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "policy" / "retirement.json"
MIRROR_PATH = ROOT / "src" / "retirement.js"

BINDING = "export const RETIREMENT_POLICY ="

HEADER = """// GENERATED MIRROR of ../policy/retirement.json -- do not hand-edit.
//
// The Worker is bundled and cannot read a repository file at request time, so
// the retirement policy is mirrored here as a literal. policy/retirement.json
// is the source; regenerate with
//     python3 tools/sync_retirement_policy.py --write
// and tests/test_retirement_policy.py fails the build if the two diverge.
"""

VALID_STATUSES = {"superseded", "withdrawn"}


def load_policy() -> dict:
    return json.loads(POLICY_PATH.read_text(encoding="utf-8"))


def render(policy: dict) -> str:
    body = json.dumps(policy, indent=2, ensure_ascii=False)
    return f"{HEADER}\n{BINDING} {body};\n"


def mirror_document(text: str) -> dict:
    """Parse the object literal out of the generated mirror.

    Deliberately strict: the mirror must be exactly one binding to one JSON
    literal. Anything else -- a hand-added helper, a computed value, a second
    export -- is a divergence in itself and is reported as one.
    """
    marker = text.find(BINDING)
    if marker < 0:
        raise ValueError(f"{MIRROR_PATH.name} does not bind RETIREMENT_POLICY")
    # Everything to end of file: anything appended after the literal (a helper,
    # a second export) stays in this slice and fails to parse, which is the
    # intended outcome -- the mirror holds the policy and nothing else.
    literal = text[marker + len(BINDING):].strip()
    if not literal.endswith(";"):
        raise ValueError(f"{MIRROR_PATH.name} binding does not end in a semicolon")
    return json.loads(literal[:-1])


def validate(policy: dict) -> list[str]:
    """Structural problems that would make a 410 page or a delete set wrong."""
    problems: list[str] = []
    if policy.get("schema") != "shadowfetch.linux-retirement.v1":
        problems.append(f"unexpected schema {policy.get('schema')!r}")
    template = policy.get("iso_name_template", "")
    if "{version}" not in template:
        problems.append("iso_name_template does not contain {version}")
    if not policy.get("sidecar_suffixes"):
        problems.append("sidecar_suffixes is empty")
    seen: set[str] = set()
    for entry in policy.get("retired", []):
        version = entry.get("version", "")
        where = f"retired[{version or '?'}]"
        if version in seen:
            problems.append(f"{where}: declared twice")
        seen.add(version)
        if not version or version.count(".") != 2:
            problems.append(f"{where}: version is not X.Y.Z")
        if entry.get("status") not in VALID_STATUSES:
            problems.append(f"{where}: status {entry.get('status')!r} is not one of {sorted(VALID_STATUSES)}")
        if entry.get("status") == "withdrawn" and not entry.get("decision"):
            problems.append(f"{where}: a withdrawal must name the decision that ordered it")
        archive = entry.get("archive")
        if archive is not None and not str(archive).startswith("https://"):
            problems.append(f"{where}: archive URL is not https")
        if "retain_sidecars" in entry and not isinstance(entry["retain_sidecars"], bool):
            problems.append(f"{where}: retain_sidecars is not a boolean")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--check", action="store_true")
    group.add_argument("--write", action="store_true")
    args = parser.parse_args(argv)

    policy = load_policy()
    problems = validate(policy)
    if problems:
        for problem in problems:
            print(f"policy/retirement.json: {problem}", file=sys.stderr)
        return 1

    rendered = render(policy)
    if args.write:
        MIRROR_PATH.write_text(rendered, encoding="utf-8")
        print(f"wrote {MIRROR_PATH.relative_to(ROOT)}")
        return 0

    if not MIRROR_PATH.exists():
        print(f"{MIRROR_PATH} is missing; run --write", file=sys.stderr)
        return 1
    if mirror_document(MIRROR_PATH.read_text(encoding="utf-8")) != policy:
        print(f"{MIRROR_PATH} has diverged from {POLICY_PATH}; run --write", file=sys.stderr)
        return 1
    print("retirement policy mirror is in sync")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
