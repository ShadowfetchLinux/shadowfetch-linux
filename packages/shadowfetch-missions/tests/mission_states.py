"""Reach a mission state in a test the way the engine reaches it.

Tests used to write `store.update(mid, state="failed")`. Phase 3 removed that
seam, and reinstating it for tests would leave the state machine with a hole
exactly where it is easiest to reach for. Walking the real edges costs one line
per test and buys two things: a test asking for an unreachable state fails
loudly instead of fabricating one, and every test mission carries the same event
trail a real one would.

The states are spelled literally rather than imported: the test modules load
sf_missions by path AFTER importing this one, and sf_missions itself documents
these values as plain strings with a stable spelling because they are persisted.
A drift between the two is caught by test_states.py, which asserts this table
against MISSION_TRANSITIONS.
"""

ROUTES = {
    "queued": (),
    "running": ("running",),
    "waiting-review": ("running", "waiting-review"),
    "failed": ("running", "failed"),
    "cancelled": ("running", "cancelled"),
    "completed": ("running", "waiting-review", "completed"),
    "undone": ("running", "waiting-review", "undone"),
}


def reach(store, mid, target, **fields):
    """Walk legal transitions to `target`; apply `fields` on the final edge."""
    route = ROUTES.get(target)
    if route is None:
        raise AssertionError(f"no legal route to {target!r} from a new mission")
    current = store.get(mid)["state"]
    if current == target:
        return store.get(mid)
    remaining = list(route)
    if current in remaining:
        remaining = remaining[remaining.index(current) + 1:]
    elif current != "queued":
        raise AssertionError(
            f"no legal route to {target!r} from {current!r}; this route starts at queued")
    if not remaining:
        raise AssertionError(f"cannot reach {target!r} from {current!r}")
    result = None
    for index, state in enumerate(remaining):
        extra = fields if index == len(remaining) - 1 else {}
        result = store.transition(mid, state, detail="test fixture", **extra)
    return result or store.get(mid)


def fabricate(store, mid, state, **fields):
    """Write a state the engine could NOT reach from here. Tests only.

    Some tests are about behaviour DOWNSTREAM of a state, and need a mission
    that already has artifacts and is also retriable -- "published a report,
    then failed". The engine reaches that as running -> failed; a test that has
    already driven the mission to waiting-review cannot, and waiting-review ->
    failed is not an edge the engine has. Adding one to the transition table to
    suit a test would be backwards: the table describes the engine, not the
    fixtures.

    So this writes the row directly, and is deliberately ugly to reach for. It
    bypasses transition(), which means NO EVENT IS EMITTED -- exactly the defect
    Phase 3 removed from the engine. Every caller should say which real
    scenario it is standing in for.
    """
    with store.db() as db:
        assignments = dict(fields)
        assignments["state"] = state
        db.execute("UPDATE missions SET " + ",".join(k + "=?" for k in assignments)
                   + ",updated_at=? WHERE id=?",
                   [*assignments.values(), store.get(mid)["updated_at"], mid])
    return store.get(mid)
