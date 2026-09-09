# Approval Policy

*Shadowfetch Linux 4.0.x — Phase 3, Steps 8, 9 and 10, brought forward to
**Phase 3.1**. Companion to `AGENT_ARCHITECTURE.md` (what the seam is),
`PROVIDER_TRUST.md` (what is known about a provider before it runs) and
`SESSION_LIFECYCLE.md` (what is recorded once it does).*

This document answers one question: **what does a human have to agree to before
a mission runs, and what does that agreement actually control?**

Everything below is either read out of `sf_policy.py` / `sf_missions.py` and
pinned by a test, or listed in §7 as a limitation. There is no third category.
A claim here that is in neither list is a bug in this document.

**What Phase 3.1 changed here.** §7.3 (expiry compared as an instant, unreadable
expiry refused), §7.4 (`path_masking` reaches `advisory_fields`, and the reason
the control is unenforced restated correctly) and §7.6 (the approval row is
checked against the chain on every use) all described **defects** in earlier
revisions of this document, one of them with an operator workaround attached.
Those descriptions are kept only under **Historical note** headings. Nothing
under a Historical note is current guidance.

---

## 1. Why there is a policy module at all

Before Phase 3, "is this allowed" had five answers and no owner: the provider
adapter chose a sandbox, the CLI chose a network flag, the desktop chose which
buttons to show, Firebreak chose what it would accept, and **nothing decided
whether a human had agreed**.

`sf_policy.py` is now the only place that decides. It contains no provider name,
and the rules are data rather than branches: adding a provider or a capability
does not change it.

It keeps one distinction throughout, and the rest of this document depends on it:

* a **policy decision** is what the system has decided should happen;
* **technical enforcement** is what it can actually make happen.

Collapsing the two is how a product comes to say "this action was blocked" about
something it merely disapproved of afterwards. Every `Decision` therefore carries
a per-field mediation map (§6) rather than an overall posture.

---

## 2. What requires approval, and what does not

`PolicyEngine.evaluate()` asks four questions of the scope it derives, in order:

| # | question | if yes | flag that governs it | shipped default |
|---|---|---|---|---|
| 1 | Is the provider's trust class one this build will execute? | `DENY` if **not** | `KNOWN_TRUST` | `("distro-managed", "developer", "unknown")` |
| 2 | Does the mission get network access (`network != "none"`)? | `ESCALATE` | `require_approval_for_network` | `True` |
| 3 | Is it given any credential identity? | `ESCALATE` | `require_approval_for_credentials` | `True` |
| 4 | May it modify the workspace? | `ESCALATE` | `require_approval_for_workspace_write` | **`False`** |

Read question 4 carefully: **in the shipped configuration a mission that writes
to your workspace does not require approval.** Only network access and
credential identities escalate. The flag exists and works; the engine is
constructed with its default in `policy_engine()`, and nothing in this build
turns it on.

Read question 1 carefully too: `"unknown"` is *inside* `KNOWN_TRUST`. A provider
whose approved-policy entry records no trust class is executed with the trust
string `"unknown"`, not refused. `DENY` is reserved for a trust string that is
none of the three — a policy file naming something this build has never heard of.
Both providers shipped in 4.0.0 (`codex`, `offline-media`) declare
`"trust": "distro-managed"` in `provider-policy/approved.json`, so no shipped
configuration reaches `DENY`.

A mission that escalates for both reasons, quoted from the engine:

```
$ shadowfetch-missions --json policy show mission-c84f7ff5c1224afb
{
    "outcome": "escalate",
    "reasons": [
        "this mission requests network access (allowlist), which reaches the internet from inside the sandbox",
        "this mission is given credential identities: CODEX_API_KEY"
    ],
    "scope": {
        "capability": "sourced_report",
        "provider": "codex",
        "workspace": "/tmp/tmp.P4xwv8fmZl/ws/demo",
        "network": "allowlist",
        "credential_ids": ["CODEX_API_KEY"],
        "paths": []
    },
    ...
    "advisory_fields": ["network_destination", "syscalls", "tool_actions_inside_a_turn"]
}
```

And one that does not escalate at all:

```
$ shadowfetch-missions --json policy show mission-4d0321aa4d074280
outcome: auto_allow
reasons: ['offline, no credentials, and bounded by an enforced sandbox']
advisory_fields: ['syscalls', 'tool_actions_inside_a_turn']
```

### 2.1 What is deliberately NOT a policy question

**Readiness is not policy.** Whether the provider is installed, authenticated or
has a usable account is a different question with a different, actionable answer.
A policy `DENY` there would replace *"run `shadowfetch-mission-account login`"*
with *"policy refuses this mission"* — true and useless. A test asserts that
`sf_policy.py` never mentions provider availability. The consequence is visible:
an approved mission can still fail, and the failure names the fix.

```
$ shadowfetch-missions run mission-c84f7ff5c1224afb      # after approval
  "state": "failed",
  "error": "Codex CLI (cloud) authentication is not configured: Account storage
            parents must not be writable by other users",
  "approval_id": "appr-0527ab7553494549"
```

**Some refusals happen earlier still.** Asking for the cloud provider with the
network switched off is refused at mission creation, before any policy decision
exists:

```
$ shadowfetch-missions --json create --kind report --network none ...
{"error": "Codex is a cloud agent and requires explicit network approval for this
mission. Allow a connection for it, or choose a provider that works offline."}
```

### 2.2 Where the scope comes from

`mission_decision()` derives the scope from the **provider's declared ceiling** —
`sandbox_from_manifest(manifest)` — not from whatever the adapter builds at run
time. An approval has to be decidable before execution, and a scope derived from
something the provider chooses later would be an approval for whatever it felt
like doing.

The mission's own `--network` choice may only *narrow* that ceiling: `none`
forces `network="none"` and empties the egress allowlist. It can never widen it.

---

## 3. The three outcomes

```python
AUTO_ALLOW = "auto_allow"
ESCALATE   = "escalate"
DENY       = "deny"
```

Deliberately three, not two. "Needs a human" is a distinct outcome from "no", and
merging them would either nag about safe work or silently permit unsafe work.

| outcome | meaning | what the engine does |
|---|---|---|
| `auto_allow` | offline, no credentials, bounded by an enforced sandbox | runs; no approval row is written or needed |
| `escalate` | a human must agree to this scope | `require_approval()` looks for a covering approval; without one it raises `ApprovalRequired` and the mission stays `queued` |
| `deny` | this build will not execute it | records a `policy-denied` event and raises `MissionError`; **no approval can lift it** |

`ApprovalRequired` is its own exception class so a UI can offer an Approve button
for exactly this case and not for a mission that failed some other way. `DENY`
raises the ordinary `MissionError`, because there is nothing to offer.

---

## 4. Where the gate sits, and why it is before the state moves

The gate is one call, in `run_mission()`, before the transition to `running`:

```
$ grep -n 'def require_approval\|^        require_approval' sf_missions.py
3804:def require_approval(store, mission):
3952:        require_approval(store, mission)
```

One definition, one call site. The surrounding code says why:

```python
# BEFORE the state moves. A mission that needs approval and has none
# never reaches running, so there is no window in which it is executing
# unapproved, and every entry point -- CLI, worker, desktop -- is covered
# because they all come through here.
require_approval(store, mission)
store.transition(mid, MissionState.RUNNING, ...)
```

Two properties follow, and both are asserted by tests rather than argued:

1. **No unapproved-running window.** The refusal happens before any state write,
   so there is no instant at which the mission is `running` without an approval.
   `test_the_refusal_happens_before_the_state_moves` asserts the event log
   contains `approval-required` and does **not** contain `running`.
2. **Entry points cannot route around it.** The CLI `run`, the idle worker and
   the desktop all reach execution through `run_mission()`. The desktop shells
   out to the same CLI; it never imports the engine.

What a refusal looks like, unedited:

```
$ shadowfetch-missions run mission-c84f7ff5c1224afb
{"error": "This mission needs approval before it can run: this mission requests
network access (allowlist), which reaches the internet from inside the sandbox;
this mission is given credential identities: CODEX_API_KEY. no approval exists
for mission:mission-c84f7ff5c1224afb"}
exit=1

$ shadowfetch-missions --json show mission-c84f7ff5c1224afb
queued None                      # state, approval_id
```

`find_approval()` returns the **reason** it refused, not just "no": *"expired at
14:02"* and *"approved for a different workspace"* send a person to different
places.

On the accepted path the engine records the use before it starts:

```
approval-granted | mission:mission-3da... by uid:1000 via cli; expires ...
approval-used    | appr-b7f54b2a22a64156 granted by uid:1000 via cli
running          | the worker claimed a queued mission
```

and writes the approval id onto the mission row (`approval_id`), which the
receipt then carries alongside the scope, the granter and the method — never a
credential value.

---

## 5. How scope containment works

An approval and a request are the **same shape** — `sf_policy.Scope` — so "does
this approval cover this mission" is a containment test rather than a pile of
comparisons written twice.

```python
Scope(capability="", provider="", workspace="", network="none",
      credential_ids=(), paths=())
```

`approval_covers(granted, requested)` returns `(covered, reason)`. An approval
must cover the request **exactly or as a legitimate superset — never merely
overlap it.**

| field | rule | refusal |
|---|---|---|
| `capability`, `provider`, `workspace` | equal, or `granted == "*"`, or `fnmatchcase(requested, granted)` | `approved for workspace 'x', this mission wants 'y'` |
| any of those three, empty in the approval | covers nothing at all | `the approval does not name a workspace` |
| `network` | rank of requested ≤ rank of granted, where `none < allowlist < allow` | `approved for network 'none', this mission wants 'allowlist'` |
| `credential_ids` | requested must be a **subset** of granted | `this mission wants credential identities the approval does not cover: ANTHROPIC_API_KEY` |
| `paths` | each requested path equals a granted path, is under it (`granted.rstrip("/") + "/"` prefix), or granted is `"*"` | `this mission wants read access to /etc, which is not approved` |

Three consequences worth stating explicitly, each with a test of its own:

* **Narrower is covered.** An approval for `allowlist` covers a run that ends up
  asking for `none`; an approval naming two credentials covers a run that asks
  for one.
* **A shared prefix is not containment.** `/usr/share/database` is *not* inside
  `/usr/share/data`. The `+ "/"` in the prefix test is the whole reason.
* **An unknown value never sneaks through.** An unrecognised requested network
  ranks 99 and an unrecognised granted network ranks −1, so neither is coverable.

The subject is matched by exact string. `find_approval()` queries
`WHERE subject=?` with `"mission:" + mission_id`, so **there are no standing or
account-wide approvals**: an approval belongs to one mission and is invisible to
every other one.

---

## 6. The policy capability matrix

The matrix is published by the engine, not asserted by this document. Every row
states its **mechanism**; a row without one fails a test.

```
$ shadowfetch-missions --json policy matrix
```

| capability | mediation | mechanism |
|---|---|---|
| `workspace_write` | fully_mediated | bwrap binds the workspace read-only when the mission declares read-only; a write then fails with EROFS |
| `filesystem_read` | fully_mediated | only declared read grants are bound into the sandbox; everything else is simply absent |
| `network_on_off` | fully_mediated | bwrap `--unshare-net` gives a namespace with no route |
| `network_destination` | **observable_only** | Firebreak has two postures, none and allow. An allowlist collapses to allow, so declared hosts are recorded and nothing filters packets. Phase 4 |
| `credential_identity` | fully_mediated | bwrap `--clearenv` then one `--setenv` per declared identity; an undeclared name is not in the environment |
| `credential_value` | fully_mediated | values are resolved outside the sandbox and injected at the boundary; no provider code sees the resolution |
| `path_masking` | **observable_only** | Firebreak's `--mask-path` is record-only and reaches no bwrap argument, and Mission Control does not pass it; declared masks reach nothing. Phase 4 |
| `memory` | fully_mediated | systemd `MemoryMax` with `MemorySwapMax=0` |
| `processes` | fully_mediated | systemd `TasksMax` |
| `cpu_time` | partially_mediated | `RLIMIT_CPU`, which is per-process: a provider that forks gets a fresh budget for each child |
| `executable_identity` | fully_mediated | the program is classified from filesystem ownership and refused unless the manifest declared it |
| `syscalls` | **not_observable** | no seccomp profile is applied and none is expressible |
| `tool_actions_inside_a_turn` | **not_observable** | a provider's internal tool calls are visible only if it reports them on its own stream; nothing intercepts them |

The four levels mean:

* **fully_mediated** — a mechanism outside our own code applies it, and an
  attempt to exceed it fails.
* **partially_mediated** — applied, with a named residual.
* **observable_only** — we can see it and record it; we cannot stop it.
* **not_observable** — we cannot even see it happen.

**A `DENY` on an observable_only field would be a recorded verdict, not a block.**
The module says so rather than letting a caller assume otherwise.

### 6.1 Per-decision honesty: `advisory_fields`

The matrix is static. Each `Decision` additionally carries `advisory_fields`: the
unenforceable rows **that decision relies on**. A mission with no egress
allowlist is not relying on egress filtering, and reporting it would be noise —
noise is how real caveats come to be ignored.

```
escalating cloud mission : ["network_destination", "syscalls", "tool_actions_inside_a_turn"]
offline media mission    : ["syscalls", "tool_actions_inside_a_turn"]
```

`_decide()` is the **only** place a `Decision` is built, including on the `DENY`
path. It was not always: a second constructor skipped `advisory_fields`, a denied
mission returned an empty tuple, and the desktop rendered that as *"This decision
relies on no control that Mission Control cannot enforce"* — an affirmative
enforcement claim about a decision that had never looked. Absent and empty are
now different: the desktop prints *"This build could not determine which controls
the decision relies on"* when the field is missing.

`shadowfetch-missions approve` echoes the same list under the key `not_enforced`,
so the person granting the approval sees it at the moment they grant it.

---

## 7. What approval does NOT do

This section is as load-bearing as §5. Each item is a property of the shipped
code, not a roadmap entry.

**7.1 Approval is checked once, at the start. Revoking mid-run stops nothing.**
`require_approval()` runs exactly once per attempt, before the state moves. There
is no re-check during execution, no watchdog on the approvals table, and revoking
an approval while its mission is running does not terminate anything. **Stop
(`shadowfetch-missions cancel`) is what stops a running mission.** Withholding an
approval, or revoking it before the mission starts, is how work is refused; the
engine records no separate refusal object. The desktop prints this sentence
verbatim beside the Approve button.

**7.2 There is no tool-level approval.** Approval is mission-level only. A
provider's internal tool calls are `not_observable`: they are visible only if the
provider reports them on its own stream, and nothing intercepts them. Rows in
`tool_executions` are written with `decision="observed"` — a record, not a
verdict. Building an approval prompt for actions that nothing can stop is the
theatrical approval this phase refuses to build.

**7.3 `expires_at` is compared as an INSTANT, and an unreadable expiry is
refused rather than assumed.** `Store.parse_instant()` reads the stored string
with `datetime.fromisoformat()` and treats a naive stamp as UTC, because `now()`
writes UTC and guessing the operator's zone would reintroduce the defect this
replaced. Measured, same machine, same minute:

```
now (UTC): 2026-09-09T05:14:02+00:00

A  expiry one hour ago, written in UTC   2026-09-09T04:14:02+00:00
   -> refused: "appr-9d7b380fab104ac9 expired at 2026-09-09T04:14:02+00:00"

B  the SAME INSTANT, written as +10:00   2026-09-09T14:14:02+10:00
   -> refused: "appr-05cbac4a158544bf expired at 2026-09-09T14:14:02+10:00"

C  not a timestamp at all                "never"
   -> refused AT GRANT TIME, while a person is watching:
      MissionError: Cannot read 'never' as an expiry. Use an ISO-8601 instant
      such as 2026-09-09T17:00:00Z; an expiry that cannot be read would
      otherwise mean no expiry at all.

C2 the same value written straight into the table with SQL
   -> "appr-6e6dfa53e1254756 has an unreadable expiry ('never') and is treated
       as expired"
```

Two guards, deliberately, because they fail in different directions: `C` is
refused at write time so nobody carries a broken expiry for the life of an
approval, and `C2` catches the row that was already there or was edited since.
An expiry nobody can read is not a licence to run forever.

> **Historical note.** `find_approval()` used to evaluate `row["expires_at"] <=
> now()` — a lexical comparison. `B` was **accepted** and the mission ran,
> because an approval stamped in UTC+10 sorted as later than it was and outlived
> its own expiry by ten hours; `C` was accepted too, because any non-timestamp
> string that sorts high enough never expires. Earlier versions of this document
> carried an operator instruction to *"write `--expires-at` in UTC with a
> `+00:00` offset"* as a workaround. **Do not follow it as guidance** — it
> described a defect, not a rule, and any offset is now read correctly.

**7.4 A declared `masked_paths` does reach `advisory_fields`, and the control it
names is still unenforced.** `_mediation_for()` sets
`relied_on = bool(sandbox.masked_paths)`, so a mission that declares a mask is
told, on the one surface built to disclose exactly that, that masking reaches
nothing. Neither shipped provider declares one, so the caveat is latent today —
but it is now latent because nothing asks for it, not because nothing reports
it. The `SandboxSpec` enforcement map (`sf_providers.sandbox_enforcement`) and
Firebreak's own session record both report `masked_paths: not_enforced` for such
a session, so all three surfaces agree.

What remains true is the gap itself, and the **reason** for it is worth stating
precisely because it was recorded wrongly for a long time: Firebreak **has** a
`--mask-path` flag. It is record-only — it reaches no bwrap argument — and
Mission Control never passes it, so a declared mask does not even appear in the
session record. Saying "Firebreak has no masking flag" implied the fix was to
add a flag that already exists; the fix is a mechanism behind it.

> **Historical note.** `_mediation_for()` hard-coded `relied_on = False` for
> `path_masking` with a comment saying the caller would set it. No caller did,
> and nothing outside `sf_policy.py` touches the mediation map, so a mission
> declaring masks was never warned.

**7.5 `approve` on a denied mission talks about approval, not about refusal.**
`decision.needs_approval` is true only for `ESCALATE`, so `approve` on a `DENY`
prints `{"approved": false, "outcome": "deny", "reason": "this mission does not
require approval: ..."}`. The behaviour is right — a `DENY` cannot be approved —
but the sentence is about approval when the fact is refusal.

**7.6 An approval row is evidence, not a lock — and the row is now checked
against the chain on every use.** The database is owned by the user running the
missions. Anyone who can write it can insert or edit an approval row. What the
design guarantees is that a tampered row is not silently honoured, and
`find_approval()` is where that is enforced, on the path every mission takes.

Four checks, each with the defect it closes:

* **`approval_witness()` — was this granted at all?** The chained
  `approval-granted` event is looked up by approval id. `None` means nobody
  granted it through the engine: the row exists and the audit chain has never
  heard of it.

  ```
  appr-inserted-by-sql has no approval-granted event in the audit chain;
  it was written straight into the table and no human granted it
  ```

* **`approval_digest()` — is it still what was granted?** The grant event carries
  `record_sha256` over **every** field of `APPROVAL_WITNESSED_FIELDS`
  (`approval`, `subject`, `scope_sha256`, `granted_by`, `method`, `granted_at`,
  `expires_at`, `reason`), and the check recomputes the same digest from the
  stored row. Both sides come from **one** list, so a field added later is
  covered by both or by neither — never by one. Editing any witnessed field with
  SQL, one at a time:

  ```
  granted_by -> appr-… does not match what was granted: the chained record and
                the stored row disagree about granted_by. It was edited after it
                was granted
  method     -> … disagree about method. It was edited after it was granted
  granted_at -> … disagree about granted_at. It was edited after it was granted
  reason     -> … disagree about reason. It was edited after it was granted
  ```

  An approval granted before 3.1 carries the individual fields but no
  whole-record digest; those are compared field by field on what the event does
  carry, rather than falling back to the scope alone.

* **`approval_revocation()` — was it withdrawn?** Revocation is read from the
  **chain**, not from the `revoked_at` column, so clearing the column with SQL
  does not revive an approval:

  ```
  after revoke                      -> appr-a3af65fa30c34486 was revoked at …
  after clearing revoked_at with SQL -> appr-a3af65fa30c34486 has a revocation in
        the audit chain (2026-09-09T05:14:02+00:00) but the row does not; the
        revocation was erased from the table
  ```

* **The scope is re-checked against a scope recomputed at run time** (§2.2), and
  an unreadable scope is refused rather than ignored.

`revoke_approval()` also no longer overwrites the grant's `reason`. That field is
part of the grant's witnessed provenance, and letting a revoke rewrite it made an
honest revocation look like a tampered grant; the revoke's own reason belongs to
the revoke event, which is where it goes. `revoked_at` is deliberately **absent**
from the witnessed digest for the same reason in reverse: revocation is
legitimately mutable and has its own chained event, and folding it into a digest
taken at creation would make every honest revoke look like tampering.

What this does **not** do: it detects at use time and prevents nothing at write
time, and it cannot help an approval whose grant event has itself been removed —
that is a chain problem, and `audit verify` is what reports it.

> **Historical note.** Both halves were readable and **nothing compared them**;
> earlier versions of this document said noticing the mismatch was a person's job.
> The comparison that did exist enumerated fields at the checking site and
> compared `scope_sha256` alone, so eight of ten direct edits to the `approvals`
> table went undetected — including reviving an expired approval.

**7.7 The CLI cannot grant a wildcard.** `_covers_value()` honours `"*"` and
fnmatch patterns, because a wildcard is an explicit widening a human typed. The
shipped `approve` verb never writes one: it grants exactly
`decision.scope`. A wildcard can only enter through a direct database write.

**7.8 Approval does not survive a change of scope.** A retry re-enters
`run_mission()` and the gate runs again against a freshly recomputed scope. If
anything about the ceiling changed, the old approval stops covering it.

---

## 8. The CLI surface

| command | what it does |
|---|---|
| `policy matrix` | the static capability matrix of §6, no mission needed |
| `policy show <mission>` | that mission's `Decision`: outcome, reasons, scope, per-field mediation, `advisory_fields` |
| `approve <mission> [--expires-at ISO] [--reason TEXT]` | grants exactly the decision's scope; refuses politely if the mission does not escalate |
| `revoke <approval-id> [--reason TEXT]` | marks it revoked; refuses if it does not exist or is already revoked |
| `approvals [<mission>]` | the rows, newest first |
| `records <mission>` | everything recorded about the mission, including its `approvals` |

`grant_approval()` requires `granted_by` and `method` — *"an approval that cannot
say who granted it and how is not evidence of anything"* — and both are checked
at write time. The CLI supplies `granted_by = "uid:<invoking uid>"` and
`method = "cli"`. **There is no way to record somebody else's decision**, which
is the point.

```
$ shadowfetch-missions --json approvals mission-c84f7ff5c1224afb
[
    {
        "id": "appr-0527ab7553494549",
        "subject": "mission:mission-c84f7ff5c1224afb",
        "scope": "{\"capability\": \"sourced_report\", \"credential_ids\": [\"CODEX_API_KEY\"], \"network\": \"allowlist\", \"paths\": [], \"provider\": \"codex\", \"workspace\": \"/tmp/tmp.P4xwv8fmZl/ws/demo\"}",
        "granted_by": "uid:1000",
        "method": "cli",
        "granted_at": "2026-09-08T23:54:01+00:00",
        "expires_at": null,
        "revoked_at": null,
        "reason": "documentation demo"
    }
]
```

The desktop Control tab renders these same answers and owns none of them: it
calls `show`, `events`, `diff`, `policy show` and `approvals`, prints the words
the engine returns, and never gates its own Approve button on a local reading of
the decision — it asks, and the engine's refusal is what appears.

---

## 9. Every bypass that was attempted, and what refused it

Twelve attempts, in `packages/shadowfetch-missions/tests/test_approvals.py`.
**None of them goes through the UI**, because the UI is not what an attacker or a
script uses: they call the engine, the shipped CLI in a subprocess, and the
worker. Each asserts the mission is **still `queued`** afterwards — *"it raised"*
is a weaker claim than *"it did not start"*.

| # | attempt | refused by |
|---|---|---|
| 1 | approval whose `expires_at` is in the past | `find_approval`: `"appr-… expired at 2000-01-01T00:00:00"` |
| 2 | approval that was revoked after being granted | `find_approval`: `"appr-… was revoked at …"` |
| 3 | approval granted for a different workspace | `approval_covers`, workspace field |
| 4 | approval granted for a different provider | `approval_covers`, provider field |
| 5 | approval granted before credentials were widened | scope recomputed at run time; requested credentials are not a subset |
| 6 | approval granted before the network was widened | `NETWORK_RANK`: requested rank exceeds granted rank |
| 7 | another mission's valid approval | subject is matched exactly; nothing is found for this mission |
| 8 | approval row edited directly in SQLite to `{"capability": "*"}` | `approval_covers`: the other fields are now empty and cover nothing |
| 9 | approval row's scope replaced with `'not json'` | `find_approval`: `"appr-… has an unreadable scope"` — refused, not ignored |
| 10 | the idle **worker** instead of the CLI | `worker()` catches `ApprovalRequired`, leaves the mission queued, logs `approval-required` |
| 11 | the shipped **CLI in a subprocess** | non-zero exit, "approval" in the output, mission still queued |
| 12 | writing an approval with no `granted_by` / no `method` | `grant_approval` raises at write time |

A thirteenth test asserts that granting **and** revoking both appear in the hash
chain and that the chain still verifies afterwards.

The unit suite is where a bypass is *pinned*; it is not where the bypasses were
*found*. `tools/attacks/attack_approval.py` is the adversarial suite, re-derived
against the tree on every run rather than transcribed, and it is what found the
row-versus-chain gaps in §7.6 and the expiry defects in §7.3 — its attacks include
`forged-approval-row`, `approval-scope-widened-after-grant`,
`approval-for-an-unknown-mission`, `expiry-in-a-nonzero-offset`,
`expiry-that-is-not-a-date`, `revoke-inside-the-check-window`,
`provider-swapped-after-approval` and `credential-ceiling-widened`. `make attacks`
runs it, and `make test` ends with `$(MAKE) attacks`.

One refusal worth naming here because it has no row in the table above:
`grant_approval()` calls `self.get(mission)` before writing, so an approval for a
mission that **does not exist** is refused. It used to chain an event no reader
could ever see — `Store.events()` checks the mission first — leaving a real,
hashed, invisible approval that a later mission id could collide with. A
pre-plantable approval is worth refusing on its own.

The suite, run whole:

```
$ python3 -m unittest test_approvals -v
...
Ran 37 tests in 1.614s

OK
```

It is picked up by `make test`, which runs
`python3 -m unittest discover -s packages/shadowfetch-missions/tests -v`.

---

## 10. Summary of the honest gaps

| gap | consequence today |
|---|---|
| workspace-write does not escalate | a mission may modify your workspace without an approval |
| approval is checked once, at start | revoking mid-run does not stop a running mission; Stop does |
| no tool-level approval | actions inside a provider turn are recorded if reported, and never gated |
| `path_masking` is `observable_only` | a declared mask reaches no mechanism; the decision, the enforcement map and the session record all say so (§7.4) |
| `network_destination` is `observable_only` | an egress allowlist is recorded and filters nothing |
| `syscalls` is `not_observable` | no seccomp profile is applied and none is expressible |
| `"unknown"` is a known trust class | a provider with no recorded trust runs rather than being denied |
| row-versus-chain checks run at **use** time | a tampered approval row is refused when a mission tries to use it, not at the moment it is written (§7.6) |

Each of these is stated somewhere the person acting on it will see it: in the
`Decision`'s `advisory_fields`, in the `approve` output's `not_enforced`, in the
receipt's `declared_but_not_enforced`, and in the desktop's caveat panel.

> **Historical note — two rows that were on this list and are not now.**
> *"`expires_at` is compared as a string"* was fixed by comparing instants and by
> refusing an unreadable expiry at grant time (§7.3). *"`path_masking` never
> enters `advisory_fields`"* was fixed by deriving `relied_on` from the sandbox
> spec (§7.4); what survives is the underlying gap, now stated with the right
> reason. Neither carries an operator workaround any more.
