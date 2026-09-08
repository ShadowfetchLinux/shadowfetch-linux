"""Approve a mission in a test the way a person would.

The engine now refuses to run a mission whose policy decision escalates unless a
persisted approval covers exactly what it will be allowed to do. Tests that are
about EXECUTION rather than about approval therefore have to grant one, and this
grants it the same way the CLI does -- through the real PolicyEngine, with the
real scope -- so a test cannot accidentally approve something broader than the
mission it is running.

Deliberately NOT folded into the harness's create(): auto-approving everything
would make an approval regression invisible, which is the failure mode this
whole step exists to prevent.
"""
def approve(store, mission, *, granted_by="test-suite", method="test-fixture",
            expires_at=None, scope=None):
    """Grant the exact scope this mission's policy decision asks for."""
    # Imported here, not at module scope: the test modules put sf_missions on
    # sys.path themselves, and importing it at the top made this helper depend
    # on being imported second.
    import sf_missions as sf

    row = mission if isinstance(mission, dict) else store.get(mission)
    decision, _ceiling = sf.mission_decision(store, row)
    if decision is None or not decision.needs_approval:
        return None
    return store.grant_approval(
        subject="mission:" + row["id"], scope=scope or decision.scope,
        granted_by=granted_by, method=method, expires_at=expires_at,
        reason="granted by the test suite")
