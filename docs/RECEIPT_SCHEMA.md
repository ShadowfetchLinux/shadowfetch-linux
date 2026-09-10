# Receipt schema

A receipt is written at the end of every mission execution, to
`<mission dir>/receipt.json`. It is the artifact a person reads when deciding
whether to accept the work, so everything the phase claims has to be visible in
it — including the gaps.

`"schema": 2`. Version 1 receipts have no `tasks`, `sessions`, `approval`,
`audit`, or `declared_but_not_enforced`; readers should branch on `schema`.

## Identity and outcome

| field | meaning |
|---|---|
| `mission`, `title`, `kind`, `capability` | what was asked for |
| `provider_id`, `provider_version` | who performed it, resolved by `mission_provider_id()` |
| `state` | `waiting-review`, `failed` or `cancelled` at the time of writing |
| `workspace`, `checkpoint` | where, and the checkpoint Undo would restore |
| `started_at`, `finished_at`, `error` | when, and why not, if not |

## What ran

`tasks[]` — `id`, `seq`, `kind`, `state`, `started_at`, `finished_at`,
`exit_code`, `error`.

`sessions[]` — one entry per provider execution. This is where the
requested/effective/enforced distinction lives, and none of the three columns
is derived from either of the others:

* `provider_id`, `provider_version`, `provider_trust`, `attempt`
* `firebreak_session` — the id shared with Firebreak's `.session` record
* `executable`, `executable_trust` — what actually started, classified
  `distro-managed` / `developer` / `unknown`
* `requested_sandbox` — what the manifest declared
* `effective_sandbox` — what survived `narrow()` (adapters can only remove)
* `enforcement` — **per field**, the vocabulary below
* `credentials_requested` vs `credentials_granted`
* `network_requested`, `egress_requested`, `network_effective`
* `exit_code`, `outcome`, `usage`

`tool_executions[]` — tool actions the provider reported. `args_digest` is
computed **before** redaction, so it identifies what actually ran rather than
its scrubbed form; `args_redacted`, `tool` and `requested_action` all go
through the same redactor. Nothing here is fabricated from prose: an event
becomes a tool record only if it carries a `tool` key, because a wrong
`ToolExecution` row is worse than a missing one — a reviewer believes it.

`test_runs[]` — `command`, `executable`, `sandbox_mode`, `network_requested`,
`network_effective`, `guard_state`, `started_at`, `duration_ms`, `exit_code`,
`log_path`, `result`, and an `enforcement` map derived from the posture the run
actually received.

`git_changes[]`, `artifacts[]`, `diff`, `changes`, `diff_truncated`.

## Who authorised it

`approval` — `id`, `subject`, `scope`, `granted_by`, `method`, `granted_at`,
`expires_at`, `revoked_at`. Never a credential value; an approval row has never
held one. `approval_required` says whether the mission needed one at all.

## Whether the record can be believed

```json
"audit": {
  "ok": true,          // the log verifies AND the mission rows agree with it
  "chain_ok": true,    // the hash chain alone
  "states": "agrees",  // the transition-table replay
  "events": 31, "chained": 31, "unchained": 0,
  "head_seq": 31, "head": "…",
  "anchor": "agrees"   // agrees | behind | truncated | conflict | unverified | degraded
}
```

`unverified` is **not** a pass. It means the external anchor could not be read,
so truncation remains undetectable.

## The gaps, in the same file

```json
"declared_but_not_enforced": [],
"enforcement_note": "Fields listed in declared_but_not_enforced were declared and recorded but reach no mechanism. …Do not read them as controls."
```

**As of 4.1.0 this array is empty**, and the example above used to read
`["egress_allowlist", "masked_paths", "syscall_profile"]`. All three now reach a
mechanism. The key is still emitted rather than dropped: a reader who branches on
its presence must be able to tell "nothing unenforced" from "this receipt does
not say", and only the empty array makes that difference checkable.

What replaced it is not nothing. Enforced fields carry RESIDUALS —
`--net allow` with no declared destination installs no ruleset, DNS leaves
through the NAT's forwarder, masking is by path so a hardlink under an unmasked
name is still readable, `cpu_seconds` is per-process — and those are reported as
`partial` in the enforcement map rather than as absent controls. Listing these
anywhere else and not here would be the omission that matters.

## Enforcement vocabulary

| value | meaning |
|---|---|
| `enforced` | a named mechanism applies it, and the mechanism ran |
| `partial` | a mechanism applies part of it; the message says which part |
| `not_enforced` | declared, recorded, reaches no mechanism |
| `not_representable` | the schema cannot express it and no mechanism exists |
| `not_applicable` | this session did not use the field, so nothing was applied |
| `observed` | recorded from outside; not a control |

`not_applicable` exists because `all([]) is True` made empty fields report
themselves working.

## Limits

`limits` and `recovery_scope` state the sandbox ceiling and the honest bound on
Undo: *"Workspace files only; external network effects cannot be undone."*
