#!/usr/bin/env python3
"""The classifier against real missions, through the real engine.

test_blast_radius.py drives classify() with hand-built SandboxSpecs, which
proves the rules and not the seam. This builds actual missions with
sf_missions.Store.create(), resolves the ceiling exactly the way
mission_decision() does -- from the provider's declared manifest, before
execution, which is when an approval has to be decidable -- and classifies
that. If the shapes ever stop lining up, this is where it shows.

It also demonstrates the reason the classifier exists, side by side: two
missions whose sf_policy.Scope is IDENTICAL, one of which is a git checkout
with a reachable remote. The approval a person is shown cannot tell them apart.
"""
import json
import os
import sys
import tempfile
from pathlib import Path

REPO = Path.home() / "projects/shadowfetch-4.0.0"
ENGINE = REPO / "packages/shadowfetch-missions/data/usr/lib/shadowfetch/missions"
sys.path.insert(0, str(ENGINE))

ROOT = tempfile.mkdtemp(prefix="blast-real-")
os.environ["SHADOWFETCH_MISSIONS_STATE"] = ROOT
os.environ["SHADOWFETCH_AGENT_WORKSPACES"] = ROOT + "/ws"

import sf_blast                          # noqa: E402
import sf_missions as sf                 # noqa: E402
import sf_policy                         # noqa: E402


def workspace(name, *, repo_remote=None):
    ws = Path(ROOT) / "ws" / name
    ws.mkdir(parents=True, exist_ok=True)
    (ws / "a.mkv").write_bytes(b"clip")
    (ws / "notes.md").write_text("ordinary work\n")
    if repo_remote:
        (ws / ".git" / "hooks").mkdir(parents=True, exist_ok=True)
        (ws / ".git" / "config").write_text(
            "[core]\n\trepositoryformatversion = 0\n"
            '[remote "origin"]\n\turl = %s\n' % repo_remote)
    return ws


def show(label, store, mid):
    mission = store.get(mid)
    decision, ceiling = sf.mission_decision(store, mission)
    radius = sf_blast.classify(mission, ceiling)
    print("\n%s" % label)
    print("  scope     %s" % decision.scope.to_json())
    print("  outcome   %s" % decision.outcome)
    print("  LEVELS    " + "  ".join(
        "%s=%s" % (d, radius.level(d)) for d in sf_blast.DIMENSIONS))
    print("  worst     %s     unseen: %s"
          % (radius.worst, ", ".join(radius.unseen) or "none"))
    for finding in radius.findings:
        if finding.level in (sf_blast.NONE, sf_blast.CONTAINED):
            continue
        print("    [%-9s] %-13s %s" % (finding.level, finding.dimension,
                                       finding.detail[:96]))
    json.dumps(radius.as_dict())          # it has to survive the reviews table
    return decision.scope.to_json(), radius


def under(label, mission, ceiling):
    """One classification against a ceiling supplied directly.

    Used for the A/B demonstration, where the whole point is that NOTHING an
    approval can see changes between the two runs -- same mission row, same
    ceiling, therefore the same sf_policy.Scope byte for byte. An earlier draft
    of this probe used two different workspaces and the scopes differed by their
    directory name, which made the comparison prove nothing.
    """
    engine = sf_policy.PolicyEngine()
    scope = engine.scope_for(capability=mission["capability"],
                             provider_id="codex", workspace=mission["workspace"],
                             sandbox=ceiling)
    radius = sf_blast.classify(mission, ceiling)
    print("\n%s" % label)
    print("  scope     %s" % scope.to_json())
    print("  LEVELS    " + "  ".join(
        "%s=%s" % (d, radius.level(d)) for d in sf_blast.DIMENSIONS))
    print("  worst     %s     unseen: %s"
          % (radius.worst, ", ".join(radius.unseen) or "none"))
    for finding in radius.findings:
        if finding.level in (sf_blast.NONE, sf_blast.CONTAINED):
            continue
        print("    [%-9s] %-13s %s" % (finding.level, finding.dimension,
                                       finding.detail[:96]))
    json.dumps(radius.as_dict())
    return scope.to_json(), radius


def codex_ceiling():
    """The shipped codex manifest's ceiling. sandbox_from_manifest() is a pure
    function of the manifest, so this needs no codex installed -- and it is the
    real declared ceiling rather than one invented for a demonstration."""
    manifest = json.loads(
        (REPO / "packages/shadowfetch-missions/data/usr/share/shadowfetch/providers"
              / "codex.json").read_text())
    return sf.sandbox_from_manifest(manifest)


def main():
    store = sf.Store(ROOT)

    ws = workspace("plain")
    plain = store.create(capability="media_export", provider_id="offline-media",
                         workspace_value="plain", title="Export a clip",
                         prompt="export", inputs=["a.mkv"])["id"]
    _, radius_a = show("A. a real mission, end to end through mission_decision()",
                       store, plain)

    # B and C: ONE mission row, ONE ceiling, and the only difference is what is
    # on the disk the mission was pointed at.
    row = dict(store.get(plain))
    row["config"] = dict(row["config"], test=["pytest", "-q"])
    ceiling = codex_ceiling()
    scope_b, radius_b = under(
        "B. that workspace under the shipped codex ceiling", row, ceiling)
    (ws / ".git" / "hooks").mkdir(parents=True, exist_ok=True)
    (ws / ".git" / "config").write_text(
        "[core]\n\trepositoryformatversion = 0\n"
        '[remote "origin"]\n\turl = https://github.com/acme/private.git\n')
    scope_c, radius_c2 = under(
        "C. the SAME mission and ceiling, after a .git appears in that directory",
        row, ceiling)

    workspace("local")
    grant = Path(ROOT) / "modeldir"
    grant.mkdir(exist_ok=True)
    import socket as socket_module
    server = socket_module.socket(socket_module.AF_UNIX, socket_module.SOCK_STREAM)
    server.bind(str(grant / "model.sock"))
    manifest = json.loads(
        (REPO / "packages/shadowfetch-missions/data/usr/share/shadowfetch/providers"
              / "localmodel.json").read_text())
    # The shipped localmodel ceiling, with its read grant pointed at a directory
    # that exists here. The manifest's own notes say that grant holds a unix
    # socket by design; this is that ceiling, not an invented one.
    import dataclasses
    ceiling = dataclasses.replace(sf.sandbox_from_manifest(manifest),
                                  read_grants=(str(grant),))
    mission = {"id": "mission-local", "workspace": str(Path(ROOT) / "ws" / "local"),
               "capability": "code_change", "checkpoint": None,
               "config": {"test": ["pytest", "-q"], "network": "none"}}
    radius_d = sf_blast.classify(mission, ceiling)
    print("\nD. the shipped localmodel ceiling: network 'none', no credentials")
    print("  LEVELS    " + "  ".join(
        "%s=%s" % (d, radius_d.level(d)) for d in sf_blast.DIMENSIONS))
    for finding in radius_d.findings:
        if finding.level in (sf_blast.NONE, sf_blast.CONTAINED):
            continue
        print("    [%-9s] %-13s %s" % (finding.level, finding.dimension,
                                       finding.detail[:96]))
    server.close()

    print("\nWHAT THIS SHOWS")
    print("  B and C have the SAME approval scope: %s"
          % ("yes" if scope_b == scope_c else "no -- the demonstration is broken"))
    print("  B worst=%s (unseen: %s)"
          % (radius_b.worst, ", ".join(radius_b.unseen) or "none"))
    print("  C worst=%s (unseen: %s)"
          % (radius_c2.worst, ", ".join(radius_c2.unseen) or "none"))
    print("  A, a real mission resolved through mission_decision(), is %s."
          % radius_a.worst)
    print("  D is offline with no credentials and is still %s on %s."
          % (radius_d.worst, ", ".join(radius_d.unseen) or "nothing"))
    ok = (scope_b == scope_c
          and radius_a.worst == sf_blast.CONTAINED
          and radius_b.worst != sf_blast.UNKNOWN
          and radius_c2.worst == sf_blast.UNKNOWN
          and sf_blast.EXFILTRATABLE in radius_d.unseen)
    print("\n%s" % ("The classifier separates missions an approval cannot."
                    if ok else "UNEXPECTED: re-read the levels above."))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
