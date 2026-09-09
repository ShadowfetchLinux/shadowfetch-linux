# Security claims matrix

What Shadowfetch 4.0.0 Mission Control may honestly say about itself, claim by
claim, with the evidence for each cell gathered by running the tree at
`release/4.0.0` HEAD `822d5bb` on 2026-09-09.

This file exists because the same sentence -- "the sandbox blocks that" -- was
being written by four surfaces (the CLI, the desktop, the receipt and the
README) with four different amounts of mechanism behind it. A claim with no
mechanism is not a weaker claim, it is a false one, and the specific way this
project has failed before is a DECLARED control being read back as an ENFORCED
one. So every row below separates what the code does, what a test proves, what
an attack could not get past, and what marketing is allowed to repeat.

## How to read a row

**IMPLEMENTED** names the function and line that actually applies the control.
Paths are relative to the repository root. The engine lives at
`packages/shadowfetch-missions/data/usr/lib/shadowfetch/missions/`; the
`packages/shadowfetch-missions/debian/` copies are stale build output and were
not consulted.

**UNIT TESTED** names a test file and test function that were confirmed to
exist by grep and confirmed to pass by running them. "NO" means no test asserts
the claim -- not that the claim is false.

**ADVERSARIAL TESTED** names an attack in `tools/attacks/` that tried to break
the claim. An attack that PASSES has *not* necessarily prevented the action:
several of these pass on the narrower claim that the system refused to lie
about what it had just failed to stop. Where that is the case the row says so.

**ENFORCEMENT LAYER** names the mechanism that applies the control -- a bwrap
flag, a systemd directive, a SQL transaction, a hash chain, a file lock,
journald -- or "none". Python control flow inside the engine is named as such,
because a guard a caller can decline to call is not the same kind of thing as a
namespace the kernel maintains.

**USER-FACING CLAIM ALLOWED** is the only column that answers "may we say this
in the UI or in marketing". For anything not enforced it is NO.

The vocabulary is fixed and the words are not synonyms:
`enforced` / `partial` / `not_enforced` / `not_representable` /
`not_applicable` / `observed`. They come from
`sf_providers.SANDBOX_ENFORCEMENT` (sf_providers.py:890) and
`sf_policy.POLICY_MEDIATION` (sf_policy.py:49), which are the tables the code
itself reports from.

## At a glance

Scan this, then read the row. `unit` / `integ` / `adv` are the three test
columns; `may claim?` is the only one that answers "may the UI say this".

| # | Claim | Enforcement layer | unit | integ | adv | May claim? |
|---|---|---|---|---|---|---|
| 1 | Mission approval required | Python gate + flock + SQL txn | YES | YES | YES | YES, scoped |
| 2 | Approval scope cannot widen | Python containment over a re-derived scope | YES | YES | YES | YES, except hosts |
| 3 | Approval provenance tamper-evident | SHA-256 digest inside the hash chain | **NO** | PARTIAL | PARTIAL | YES, as evidence |
| 4 | Mission history reconstructable | Event replay vs transition table + chained pin | **NO** | PARTIAL | YES | YES, as detection |
| 5 | Audit chain tamper-evident | SHA-256 hash chain, `BEGIN IMMEDIATE` | YES | YES | YES | YES, as evidence |
| 6 | External chain anchor trusted | journald via `/dev/log` | PARTIAL | YES | YES | YES, bounded |
| 7 | Audit CLI reports failure correctly | Process exit status | **NO** | YES (by hand) | YES | YES |
| 8 | Mission state transitions validated | Transition table + SQL txn | YES | YES | YES | YES, engine API only |
| 9 | Retry budget enforced | One edge guard in both verbs | PARTIAL | NO | YES | YES |
| 10 | Mission creation/audit atomic | SQLite `BEGIN IMMEDIATE` | PARTIAL | PARTIAL | INDIRECT | internal |
| 11 | Cancellation recorded | SQL txn + `kill_tree` + systemd scope | YES | YES | YES | YES |
| 12 | Provider executable trust classified | `stat` walk + manifest path allowlist | YES | YES | **NO** | YES |
| 13 | masked_paths enforced | `bwrap --tmpfs` / `--ro-bind /dev/null` | YES | YES (live) | YES | YES |
| 14 | workspace_mode enforced | `bwrap --ro-bind` | YES | YES (live) | PARTIAL | YES |
| 15 | egress_allowlist enforced | nftables default-DROP in the sandbox's own netns | YES | YES (live) | YES | YES, by address, when hosts are declared |
| 16 | Credential isolation | `bwrap --clearenv` + `--setenv` | YES | YES (live) | YES | YES |
| 17 | Network namespace isolation | `bwrap --unshare-net`, or `unshare --net` + slirp4netns NAT | YES | YES (live) | YES | YES, both postures |
| 18 | Resource limits (mem/proc/CPU) | systemd `MemoryMax`/`TasksMax`; `RLIMIT_CPU` | YES | YES (live) | PARTIAL | YES for mem+proc, PARTIAL for CPU |
| 19 | MCP destructive gated and audited | Python gate + hash-chained JSONL + journald | YES | YES | YES | YES as "withheld and audited" only |

"YES (honesty)" means the tests prove the system correctly reports the control
as unenforced. There is nothing else there to test.

---

## 1. Mission approval required

| | |
|---|---|
| **CLAIM** | A mission whose policy decision escalates does not begin execution until a valid approval covers it. |
| **IMPLEMENTED** | `require_approval()` sf_missions.py:3721, called from `run_mission()` sf_missions.py:3869 -- before the `queued -> running` transition at :3879 and inside the per-workspace execution lock taken at :3858. `mission_decision()` sf_missions.py:3683 fails closed: a mission that cannot name a capability and a provider returns DENY (:3701) rather than "nothing to decide". `mission_provider_id()` sf_missions.py:3665 is the single resolution the gate and the executor share. |
| **UNIT TESTED** | YES -- tests/test_approvals.py `test_a_mission_needing_approval_cannot_run_without_one` (:177), `test_the_refusal_happens_before_the_state_moves` (:185), `test_bypass_via_the_worker_rather_than_the_cli` (:296), `test_bypass_via_the_cli_subprocess` (:304), `test_bypass_approval_belonging_to_another_mission` (:270). 37 passed. |
| **INTEGRATION TESTED** | YES -- `test_bypass_via_the_cli_subprocess` runs the real CLI as a subprocess and asserts the mission is still `queued`; `test_bypass_via_the_worker_rather_than_the_cli` drives `sf.worker()`. Both entry points reach the gate because both go through `run_mission()`. |
| **ADVERSARIAL TESTED** | YES -- tools/attacks/attack_approval.py `unapproved-start-disguised-as-offline`, `provider-id-laundering`, `forged-approval-row`, `approval-for-an-unknown-mission`, `approval-subject-is-not-a-mission`. 20/20 PASS on this run. |
| **ENFORCEMENT LAYER** | Python control flow in `run_mission()`, serialised by an `fcntl.flock` execution lock (`Store.lock` sf_missions.py:2148) and committed by a SQL transaction. No kernel mechanism: an in-process caller that reaches `Executor.execute()` directly bypasses it. |
| **USER-FACING CLAIM ALLOWED?** | YES, with the scope stated. Say: "a mission that wants network access or a credential does not start until a person approves it." Do NOT say "every mission requires approval": `PolicyEngine.__init__` sf_policy.py:202 ships `require_approval_for_workspace_write=False`, so an offline, credential-free mission that MODIFIES THE WORKSPACE is auto-allowed with no human in the loop (`test_offline_and_credential_free_work_is_auto_allowed`, tests/test_approvals.py:44). |
| **NOTES** | The gate is only as good as the single entry point. `run_mission()` is currently that point for the CLI, the worker and the desktop, and `mission_provider_id()` exists because the resolution used to be written twice and the two copies disagreed -- which was an unapproved run with no approval event at all. |

---

## 2. Approval scope cannot widen

| | |
|---|---|
| **CLAIM** | An approval covers what was agreed and nothing broader; a mission that grows after the grant stops being covered. |
| **IMPLEMENTED** | `sf_policy.approval_covers()` sf_policy.py:145 -- capability, provider and workspace by `_covers_value()` (:133), network by `NETWORK_RANK` ordering (:130, :154), credential identities by set difference (:160), read paths by prefix containment that requires a `/` boundary (:165). The scope compared against is re-derived from the provider manifest ceiling at every start (`mission_decision()` sf_missions.py:3707), never from what the mission declared when it was approved. |
| **UNIT TESTED** | YES -- tests/test_approvals.py `test_a_broader_network_is_refused` (:115), `test_an_extra_credential_is_refused` (:120), `test_a_different_workspace_is_refused` (:125), `test_a_different_provider_is_refused` (:130), `test_a_different_capability_is_refused` (:135), `test_a_path_that_merely_shares_a_prefix_is_refused` (:146), `test_an_empty_approval_field_covers_nothing` (:150). |
| **INTEGRATION TESTED** | YES -- tests/test_approvals.py `test_bypass_by_widening_credentials_after_approval` (:248) and `test_bypass_by_widening_network_after_approval` (:260) drive `run_mission()` end to end. |
| **ADVERSARIAL TESTED** | YES -- attack_approval.py `approval-scope-widened-after-grant`, `credential-ceiling-widened`, `network-value-forged-in-config`, `workspace-prefix-sibling`, `workspace-glob-in-the-scope`, `workspace-root-repointed`, `capability-swapped-after-approval`, `provider-swapped-after-approval`, `provider-upgraded-after-approval`. All PASS. |
| **ENFORCEMENT LAYER** | Python containment test over a scope re-derived from the manifest, evaluated under the workspace execution lock. |
| **USER-FACING CLAIM ALLOWED?** | YES for capability, provider, workspace, network POSTURE, credential identity and read path. NO for network DESTINATION -- see row 15. |
| **NOTES** | Two honest caveats. (a) `_covers_value()` honours `*` and `fnmatch` globs, so a human who types a wildcard workspace has genuinely widened the grant; `workspace-glob-in-the-scope` treats that as intended and the UI must render the granted string rather than "this workspace". (b) `Scope` now carries `egress_hosts`, because Stage C made destinations an enforced privilege and a privilege outside the approved scope is one that can be widened after the human agreed -- `egress-widened-after-approval` had observed exactly that. Consequence, stated rather than hidden: an approval stored before that field existed reads as NO hosts, so it stops covering a mission that wants any, and the mission goes back for a fresh grant. That direction is deliberate; the alternative is honouring an old grant for destinations nobody was shown. |

---

## 3. Approval provenance tamper-evident

| | |
|---|---|
| **CLAIM** | An approval row edited after it was granted, or written straight into the table, is detected at the moment it is used. |
| **IMPLEMENTED** | `APPROVAL_WITNESSED_FIELDS` sf_missions.py:63 and `Store.approval_digest()` sf_missions.py:1255 compute one digest over approval, subject, scope_sha256, granted_by, method, granted_at, expires_at and reason. `grant_approval()` sf_missions.py:1172 writes that digest as `record_sha256` inside the CHAINED `approval-granted` event (:1211-1217). `find_approval()` sf_missions.py:1329 recomputes it from the stored row and compares the whole record (:1385-1400), names the differing fields, and refuses. `approval_witness()` :1299 refuses a row the chain never heard of. `approval_revocation()` :1272 reads revocation FROM THE CHAIN, so clearing `revoked_at` with SQL no longer revives an approval. `revoke_approval()` :1222 no longer overwrites `reason`, which used to make an honest revoke look like tampering. |
| **UNIT TESTED** | NO. `grep -rn "approval_digest\|APPROVAL_WITNESSED\|record_sha256\|approval_revocation" packages/*/tests/` returns nothing. The closest existing tests predate Phase 3.1 and cover strictly less: tests/test_approvals.py `test_bypass_a_tampered_approval_row` (:276) edits only the SCOPE column, `test_bypass_an_unreadable_scope_is_refused_not_ignored` (:287) edits only the scope, and `test_granting_and_revoking_are_both_audited` (:325) asserts the two events exist but never erases `revoked_at`. Whole-record coverage and chain-sourced revocation are untested. |
| **INTEGRATION TESTED** | PARTIAL -- exercised through `run_mission()` only for the scope-edit case (`test_bypass_a_tampered_approval_row`). Verified by hand this session on a throwaway store: editing `granted_by` from `alice` to `mallory` produced "the chained record and the stored row disagree about granted_by. It was edited after it was granted", and clearing `revoked_at` after a revoke produced "has a revocation in the audit chain ... but the row does not; the revocation was erased from the table". Both refused. |
| **ADVERSARIAL TESTED** | PARTIAL -- attack_approval.py `forged-approval-row` covers a row inserted with no chained grant. tools/probes/approval_baseline.py is the probe that measured the pre-3.1 gap (eight of ten direct edits undetected). No attack in tools/attacks/ exercises the per-field digest or the chain-sourced revocation, so the fix has a probe and a manual check behind it but no attack that will fail if it regresses. |
| **ENFORCEMENT LAYER** | SHA-256 digest carried inside the append-only event hash chain; SQL `BEGIN IMMEDIATE` transaction pairs the row and its grant event. The approvals table itself is a plain mutable table owned by the mission uid -- the chain is what makes an edit to it visible, not what prevents it. |
| **USER-FACING CLAIM ALLOWED?** | YES as tamper-EVIDENT: "an approval that was altered after it was granted is refused, and the audit trail says which field changed." NO as tamper-PROOF: the row can be edited freely; what cannot be forged without also forging the chain is agreement about it. |
| **NOTES** | The gap here is test coverage, not mechanism. This is the single largest untested area in the matrix and the one most likely to rot silently, because a regression would restore a *permissive* behaviour that no failing test would announce. |

---

## 4. Mission history reconstructable

| | |
|---|---|
| **CLAIM** | Every mission's state can be replayed from recorded events, and a state the row claims but no event records is reported. |
| **IMPLEMENTED** | `Store.verify_states()` sf_missions.py:1840 replays each mission's `STATE_EVENTS` trail through `transition_allowed()` (:145) and classifies it `LEGACY_PRECHAIN` / `VALID_CURRENT` / `MISSING_HISTORY` / `STATE_DIVERGENCE` / `CORRUPTED_HISTORY` (:139-143). The v4 migration writes a CHAINED `legacy-missions-pinned` event naming the missions that had no history at upgrade time (`pin_legacy_missions()` :755); `legacy_missions()` :800 reads it back. An event-less mission not in that pin is `MISSING_HISTORY` and a problem (:1890-1900). An empty pin is deliberately not written (:786-793). |
| **UNIT TESTED** | NO. `grep -rn "verify_states\|legacy_missions\|LEGACY_PIN\|MISSING_HISTORY\|STATE_DIVERGENCE" packages/*/tests/` returns nothing. tests/test_state_machine.py covers the transition TABLE (`test_every_transition_names_a_known_state` :22, `test_every_state_is_reachable` :31) and tests/test_schema_migration.py covers v2 (13 passed), but no test asserts the classification, the pin, or that an event-less row is now a finding. |
| **INTEGRATION TESTED** | PARTIAL -- reached through `Store.verify_chain()` (:1833) and therefore through `audit verify`, which tests/test_audit_chain.py exercises for the chain but not for the classes. Verified by hand this session: a forged `INSERT INTO missions ... state='completed'` with no events classified `MISSING_HISTORY`, `verify_chain()["ok"]` went False, and `audit verify` exited 1. |
| **ADVERSARIAL TESTED** | YES -- attack_integrity.py `state-jump-forged-row`. Observed this run: `UPDATE missions SET state='completed'` was accepted by SQLite, the subsequent `transition(mid, 'undone')` was accepted by the engine, and `verify_chain()` then reported `mission ...: event 3 records queued -> undone, which the transition table forbids; the row was changed outside the engine`, `audit verify` exit 1. The attack's own NOTE text is stale prose from the pre-3.1 baseline and says "Not prevented, not detected"; the OBSERVED block from this run contradicts it on detection. |
| **ENFORCEMENT LAYER** | Replay of an append-only hash-chained event log against the static transition table, plus one chained pin event for the pre-chain population. The missions table is NOT chained; this is detection after the fact, not prevention. |
| **USER-FACING CLAIM ALLOWED?** | YES as reconstruction and detection: "a mission's history can be replayed, and a state nothing recorded is reported as such." NO as prevention: a uid that can write the SQLite file can still set any state it likes; what it cannot do is make the replay agree. |
| **NOTES** | The pin is trust-on-first-use and says so in its own docstring (:768-772). It believes the database as it stood at upgrade time and cannot recover provenance that was never recorded. That is the strongest claim available to a build that was not present when those rows were written, and it must not be described as verification of them. |

---

## 5. Audit chain tamper-evident

| | |
|---|---|
| **CLAIM** | An event altered, inserted, reordered or renumbered after it was written is detected. |
| **IMPLEMENTED** | `event_hash()` sf_missions.py:502 = sha256(prev_hash ‖ canonical(row)) over `HASHED_FIELDS` (:486) which includes `seq`, so renumbering is detectable. `canonical()` :490 fixes key order, spacing and non-ASCII spelling. `Store._append()` :861 is the only INSERT into events and chooses `seq` explicitly. `append_event()` :897 takes `BEGIN IMMEDIATE` so two concurrent appends cannot fork the chain. `verify_chain()` :1644 recomputes every row, checks `prev_hash` linkage and `seq` contiguity, and refuses to hash a non-text `detail` with a verdict rather than a traceback (:1690). |
| **UNIT TESTED** | YES -- tests/test_schema_v3.py `test_a_modified_detail_is_detected` (:238), `test_a_modified_mission_id_is_detected` (:242), `test_a_modified_actor_is_detected` (:246), `test_a_deleted_row_is_detected` (:250), `test_an_inserted_row_is_detected` (:285), `test_a_reordered_pair_is_detected` (:291), `test_a_corrupted_prev_hash_is_detected` (:300), `test_rewriting_a_row_AND_its_hash_still_breaks_the_successor` (:308), `test_a_hash_on_a_pre_chain_row_is_detected` (:321), `test_only_the_named_fields_are_hashed` (:342), `test_every_hashed_field_actually_changes_the_hash` (:347), `test_parallel_appends_produce_one_unforked_chain` (:361). 33 passed. |
| **INTEGRATION TESTED** | YES -- tests/test_audit_chain.py `test_a_broken_chain_exits_nonzero` (:246) and `test_verify_reports_the_chain_and_the_anchor_separately` (:239) drive the CLI. |
| **ADVERSARIAL TESTED** | YES -- attack_integrity.py `event-field-coverage` (every stored column rewritten one at a time; "columns that are neither hashed nor chain metadata: []"), `event-detail-not-utf8`, `event-insert-bypassing-append`, `event-rechain-then-cover`. 15/15 PASS. |
| **ENFORCEMENT LAYER** | SHA-256 hash chain in the `events` table, appended under SQL `BEGIN IMMEDIATE`. |
| **USER-FACING CLAIM ALLOWED?** | YES as tamper-EVIDENT. NO as tamper-proof, and NO as covering truncation on its own -- deleting the last N events leaves every surviving row verifying, which is what a chain is (sf_audit.py:3-6). Truncation is row 6's claim, not this one's. |
| **NOTES** | The chain proves nothing about the `missions`, `approvals`, `tasks` or `agent_sessions` tables, which are unchained and mutable. Rows 3 and 4 are the compensating checks. |

---

## 6. External chain anchor trusted

| | |
|---|---|
| **CLAIM** | Truncation and rewriting of the log are detectable because each event's head is mirrored to a record the mission uid cannot rewrite. |
| **IMPLEMENTED** | `sf_audit.mirror()` sf_audit.py:105 sends `MIRRORED_FIELDS` (:42 -- store, chain, seq, hash, mission, event, at) to `/dev/log` at authpriv.notice; never raises. `Store.mirror()` sf_missions.py:1620 records success or failure into `MirrorState` (sf_audit.py:61). `sf_audit.read_head()` :126 keeps the EARLIEST line per seq (:199-204), records per-seq hash `conflicts` (:205), and records `other_chains` for entries this store mirrored under a different chain id (:193). `store_identity()` :45 is sha256 of the absolute db path -- the one name in the record the database cannot restate about itself. `verify_chain()` compares every mirrored seq, not only the head (sf_missions.py:1765-1770), and treats a re-minted chain id as a conflict (:1782-1793). |
| **UNIT TESTED** | PARTIAL. YES for the older behaviour: tests/test_audit_chain.py `test_a_journal_ahead_of_the_database_is_truncation` (:132), `test_a_hash_disagreement_at_the_same_seq_is_a_conflict` (:145), `test_an_unreadable_journal_is_unverified_not_ok` (:152), `test_an_empty_journal_is_unverified_not_a_pass` (:158), `test_deleting_the_tail_is_caught_by_the_journal_alone` (:214), `test_an_event_round_trips_through_journald` (:206). NO for the Phase 3.1 additions: nothing in any test names `store_identity`, `other_chains` or the per-seq `heads` map. |
| **INTEGRATION TESTED** | YES -- `test_an_event_round_trips_through_journald` and `test_deleting_the_tail_is_caught_by_the_journal_alone` use the real journal; `journalctl`, `bwrap` and `systemd-run` are all present on the build host, so these did not skip. |
| **ADVERSARIAL TESTED** | YES -- attack_integrity.py `chain-truncate-anchored`, `chain-truncate-unanchored`, `chain-truncate-mirror-forged`, `event-delete-last-anchored`, `event-delete-last-unanchored`, `event-delete-genesis`, `event-rechain-then-cover`. Also tools/probes/journal_attack.py and tools/probes/genesis_attack.py. All PASS. `event-rechain-then-cover` observed: rewriting seq 3 and re-chaining is caught as `the journal and the database disagree about the hash of event(s) 3, 4, 5`, and stays caught after a legitimate append -- the per-seq comparison, not the head comparison, is what holds. `event-delete-genesis` stage 2 observed: a forged genesis with a new chain id is caught as `this store has previously mirrored chain id(s) 57bc218357ff ... and now presents 89c203dc1931`, exit 1. |
| **ENFORCEMENT LAYER** | journald, written over the `/dev/log` unix datagram socket, read back with `journalctl -t shadowfetch-audit`. Root-owned; the mission worker is unprivileged. |
| **USER-FACING CLAIM ALLOWED?** | YES, bounded exactly as sf_audit.py:14-19 bounds it: root can rewrite the journal; `/dev/log` is a local socket with no transit protection; a rotated journal reports the horizon it can see rather than a failure. Say "externally anchored", never "tamper proof". |
| **NOTES** | Two live horizons a claim must not outrun. (a) `read_head()` reads `-n 5000` (sf_audit.py:127, :163) -- beyond that the per-seq evidence is simply not fetched, and a store with more than 5000 mirrored events has an unexamined tail. (b) A database copied to a new path is a new `store_identity` with no journal history and verifies `unverified`, which is honest but is not a pass. Note also that `read_head()` counts an entry whose `chain` matches even if its `store` does not (:188); the store filter is used only to attribute foreign chain ids. |

---

## 7. Audit CLI reports failure correctly

| | |
|---|---|
| **CLAIM** | `audit verify` exits 0 only when the log verified and the anchor was actually read; text and `--json` return the same code. |
| **IMPLEMENTED** | `audit_exit_code()` sf_missions.py:4213 -- 0 ok, 1 tampered, 2 unverified-or-degraded -- and it fails closed: a report with no `ok` key at all returns 1. Called once at sf_missions.py:4365, BEFORE any rendering, so the ladder cannot differ between output modes. `AUDIT_EXIT_*` constants at :4208-4210. |
| **UNIT TESTED** | NO for the function itself -- `grep -rn "audit_exit_code" packages/*/tests/` returns nothing. PARTIAL for the behaviour: tests/test_audit_chain.py `test_a_broken_chain_exits_nonzero` (:246) and `test_json_mode_returns_the_whole_report` (:256) cover a broken chain and the JSON payload, but nothing asserts that the two modes return the SAME code, which is the defect Phase 3.1 fixed. |
| **INTEGRATION TESTED** | YES, by hand this session. Against a store carrying one forged mission row: `audit verify` exit 1 and `--json audit verify` exit 1 -- identical. Text output printed `chain intact`, `mission states disagrees (1 replayed against the transition table)`, and the PROBLEM line. |
| **ADVERSARIAL TESTED** | YES -- attack_integrity.py checks the CLI exit code inside `state_jump_forged_row`, `chain-truncate-*`, `event-delete-*` and `event-delete-genesis`. Observed codes this run: 1 for a broken chain, 1 for a forged state, 2 for `unverified` with no journal. |
| **ENFORCEMENT LAYER** | Process exit status. Nothing more -- this is a reporting contract, not a control. |
| **USER-FACING CLAIM ALLOWED?** | YES: "exit 0 means verified, 1 means tampered, 2 means it could not be verified." The important half is the second: 2 is NOT a pass, and any wrapper or LaunchAgent that treats non-zero-is-bad-only-if-1 would reintroduce the exact false claim this exists to remove. |
| **NOTES** | This is the row most exposed to regression by a caller rather than by the engine. A CI gate or cron job that runs `--json` and reads `.ok` instead of the exit status gets the right answer today only because `ok` and the ladder currently agree for cases 0 and 1 -- they diverge at 2, where `ok` is True and the exit code is 2. |

---

## 8. Mission state transitions validated

| | |
|---|---|
| **CLAIM** | A mission moves only along a declared edge, and the move and its event land together or not at all. |
| **IMPLEMENTED** | `MISSION_TRANSITIONS` sf_missions.py:70 is the whole machine, each edge carrying the reason a refusal quotes back. `transition_allowed()` :145 is the single answer. `Store.transition()` :1950 does the read, the validation, the UPDATE and the `_append` in one `BEGIN IMMEDIATE` transaction, with `expect=` optimistic concurrency (:1982). `Store.update()` :1929 raises `TransitionError` if `state` is passed at all (:1940) -- it used to accept `state="banana"`. |
| **UNIT TESTED** | YES -- tests/test_state_machine.py `test_each_edge_moves_the_state_and_emits_its_event` (:87), `test_the_named_illegal_transitions_are_refused_and_change_nothing` (:134), `test_an_unknown_state_string_is_refused` (:143), `test_update_can_no_longer_set_the_state_at_all` (:153), `test_expect_refuses_when_the_state_moved_underneath` (:182), `test_the_event_and_the_state_share_one_transaction` (:211), `test_an_undone_mission_can_never_run_again` (:170). 25 passed. Also tests/test_schema_v3.py `test_a_failed_state_change_leaves_no_event_behind` (:389). |
| **INTEGRATION TESTED** | YES -- tests/test_review_lock.py `test_final_state_and_event_become_visible_in_one_transaction` (:224), `test_failed_final_state_rolls_back_its_inserted_event` (:270). 11 passed. |
| **ADVERSARIAL TESTED** | YES -- attack_integrity.py `state-jump-illegal-target` (capitalised, trailing space, underscore, newline, `None`, integer, unhashable list, SQL injection in the target, plus `update(state=...)` and `SET state=NULL`) -- every one refused, the row byte-identical afterwards, the `events` table still present. And `state-jump-forged-row` for the SQL path (row 4). |
| **ENFORCEMENT LAYER** | Static transition table plus a SQLite `BEGIN IMMEDIATE` transaction. In-process only: the guard lives in the engine API, not in the database schema. |
| **USER-FACING CLAIM ALLOWED?** | YES for the engine API: "the mission lifecycle is a validated state machine; an illegal move is refused and changes nothing." NO for the file: anyone who can write missions.sqlite3 can set any state, and the compensating control is detection (row 4), not refusal. |
| **NOTES** | One wart the attack recorded and this row should not hide: an unhashable target (a list) raises `TypeError` from inside `transition_allowed()`'s dict lookup rather than `TransitionError`. It is raised inside the transaction so nothing is written, but a caller catching `TransitionError` will not catch it. |

---

## 9. Retry budget enforced

| | |
|---|---|
| **CLAIM** | A mission cannot be requeued for a fourth attempt, whichever verb asks. |
| **IMPLEMENTED** | `MAX_ATTEMPTS = 3` sf_missions.py:104 and `requeue_refusal(event, attempt)` :107 -- keyed on the EDGE'S EVENT (`retry-queued`), not on the caller. Asked by `Store.transition()` :1991 and by `Store.finish_execution()` :2040. Both record a chained `retry-budget-exhausted` event that COMMITS while the mission row is left untouched, then raise (`transition` :1994-2005, `finish_execution` :2041-2052). `Store.retry()` :2330 keeps its own earlier check only so the CLI's wording is unchanged (:2336). |
| **UNIT TESTED** | PARTIAL. tests/test_missions.py `test_retry_budget_is_bounded` (:131) covers the `Store.retry()` path, which was never the broken one. `grep -rn "requeue_refusal\|retry-budget-exhausted" packages/*/tests/` returns nothing: neither the `transition()` guard, the `finish_execution()` guard, nor the refusal event has a test. That is the Phase 3.1 fix, untested. |
| **INTEGRATION TESTED** | NO by test. Verified by hand this session: `requeue_refusal("retry-queued", 3)` returns the refusal string and `requeue_refusal("running", 9)` returns None. |
| **ADVERSARIAL TESTED** | YES -- attack_integrity.py `state-jump-retry-budget`. Observed this run: with `attempt=3`, `store.retry()` raised `MissionError: Retry budget exhausted (three attempts)` AND the direct `store.transition(mid, 'queued')` raised `TransitionError: Refused failed -> queued: retry budget exhausted (3 attempts)`, with the event trail ending `('retry-budget-exhausted', 'Refused failed -> queued: ...')`. The attack's NOTE is stale baseline prose claiming the budget still lives only in `retry()`; the OBSERVED block from this run shows otherwise. |
| **ENFORCEMENT LAYER** | One function consulted by both verbs, inside the same SQL transaction that would otherwise perform the requeue. |
| **USER-FACING CLAIM ALLOWED?** | YES: "three attempts, then the mission stops and says so." The refusal is recorded rather than silent, which is the half worth saying -- "no event" used to read the same as "nobody ever tried". |
| **NOTES** | The budget is enforced at the edge, so a path that reaches a requeue without calling `requeue_refusal()` is the only way back to the old defect. There is exactly one place to look, and no test guarding it. |

---

## 10. Mission creation and its first event are atomic

| | |
|---|---|
| **CLAIM** | A mission row and its `queued` event commit together, so an event-less mission row was not written by the engine. |
| **IMPLEMENTED** | `Store.create()` sf_missions.py:2207 -- one `BEGIN IMMEDIATE` at :2273 covering both the `INSERT INTO missions` (:2274) and the `_append` of the `queued` event (:2275-2278). The event NAME is read from `MISSION_TRANSITIONS[(None, QUEUED)]` (:2266) so the vocabulary has one definition. This is what makes row 4's dichotomy real rather than hopeful. |
| **UNIT TESTED** | PARTIAL. tests/test_state_machine.py `test_create_emits_the_queued_edge` (:104) asserts the event exists after a successful create. Nothing asserts ATOMICITY -- there is no create-side analogue of `test_the_event_and_the_state_share_one_transaction` (:211), which covers `transition()` only. `grep -rn "atomic\|one transaction" packages/shadowfetch-missions/tests/` finds only test_schema_v3.py:390, also about `transition()`. |
| **INTEGRATION TESTED** | PARTIAL -- every suite that creates a mission depends on it, and 428 tests across 20 files passed, but none fails specifically if the two writes are split back onto separate connections. |
| **ADVERSARIAL TESTED** | INDIRECT -- attack_integrity.py `state-jump-forged-row` proves the consequence (an event-less row is now a finding) rather than the mechanism. No attack interrupts a create between the two writes. |
| **ENFORCEMENT LAYER** | SQLite `BEGIN IMMEDIATE` transaction on one connection. |
| **USER-FACING CLAIM ALLOWED?** | YES as an internal integrity property, and it is the premise the reconstructable-history claim rests on. Not worth stating to a user on its own. |
| **NOTES** | Worth naming precisely because it is load-bearing and invisible: if this regresses, row 4 keeps reporting `MISSING_HISTORY` and the finding becomes a false positive on honest missions, which trains an operator to ignore it. |

---

## 11. Cancellation recorded

| | |
|---|---|
| **CLAIM** | A cancellation is recorded once, is refused once the mission is no longer active, and never lands after the mission's terminal event. |
| **IMPLEMENTED** | `Store.cancel()` sf_missions.py:2282. A QUEUED mission cancels as a real transition with `expect=QUEUED` (:2296). A RUNNING mission is ASKED: one `BEGIN IMMEDIATE` (:2312) re-reads the state inside the transaction, refuses anything not ACTIVE (:2317), returns unchanged if already requested (:2321), then sets the flag and appends `cancel-requested` together (:2323-2327). `Executor.check()` :2794 is what observes the flag. |
| **UNIT TESTED** | YES -- tests/test_cancellation.py `test_cancelling_a_queued_mission_is_immediate_and_recorded` (:62), `test_cancelling_a_running_mission_asks_rather_than_tells` (:70), `test_repeated_cancel_is_idempotent` (:79), `test_cancel_is_refused_once_a_mission_is_finished` (:89), `test_a_restart_after_a_cancel_request_records_cancelled_not_failed` (:95), `test_the_cancel_race_with_completion_does_not_lose_the_result` (:184). 13 passed. |
| **INTEGRATION TESTED** | YES -- `test_a_cancel_mid_turn_stops_the_mission_and_preserves_evidence` (:141), `test_a_cancelled_run_closes_its_session_and_settles_its_task` (:162), `test_sigterm_removes_the_process_and_the_scope` (:253), `test_sigkill_with_no_chance_to_clean_up_still_removes_both` (:264). |
| **ADVERSARIAL TESTED** | YES -- attack_lifecycle.py `cancel-completion-race`. Observed this run: 100 barrier-released trials, 90 refused with "This mission is waiting-review, not running", 0 landed a `cancel-requested` event after a terminal event, chain `ok: true, chained: 337, problems: []`. |
| **ENFORCEMENT LAYER** | SQL `BEGIN IMMEDIATE` transaction pairing the flag and the event; `kill_tree()` sf_missions.py:2737 and Firebreak's systemd scope for the process itself. |
| **USER-FACING CLAIM ALLOWED?** | YES: "Stop is recorded once, is refused once the mission has finished, and never appears after the mission's final event." |
| **NOTES** | One honest wording defect the attack surfaced and this row must not paper over: a cancel that lands after the executor's last `check()` still writes the detail "Running process is terminated; workspace checkpoint remains available" (sf_missions.py:2326) for a mission that then completes normally into `waiting-review` with its work published. The record is not false about the DECISION, but the sentence describes an outcome that did not happen. |

---

## 12. Provider executable trust classified

| | |
|---|---|
| **CLAIM** | A provider's program is classified from the filesystem and refused unless its manifest declared that class, and only a program the manifest names may be executed. |
| **IMPLEMENTED** | `classify_executable()` sf_providers.py:157 walks the file AND every parent directory (:180) -- `_substitutable_by_others()` :141 rejects foreign ownership, world-writability and shared-group writability, with `_private_group()` :119 distinguishing a Debian per-user group from a shared one; sticky directories are handled (:150). `ACCEPTED_EXECUTABLE_TRUST` :106 maps a manifest declaration to the classes it accepts; `UNTRUSTED` is accepted by none. `trusted_executable()` :207 refuses an unknown declaration outright. `verify_invocation()` :980 additionally requires the resolved path to be in `declared_executables(manifest)` (:1033-1038) -- checking only the TIER let an adapter substitute any other distro-managed binary and inherit that provider's credentials and network grant. |
| **UNIT TESTED** | YES -- tests/provider_conformance.py `test_the_program_classifies_into_a_tier_its_manifest_declares` (:792), `test_the_manifest_executable_declaration_is_honoured` (:528), `test_a_program_the_manifest_does_not_declare_is_refused` (:926), `test_the_adapter_does_not_resolve_its_program_through_path` (:947), `test_the_declared_resolver_chain_does_not_reach_path_resolution` (:954), `test_every_invocation_uses_an_absolute_executable` (:513). Driven for every shipped provider by tests/test_provider_conformance.py (135 passed) and tests/test_approved_provider_policy.py (23 passed). |
| **INTEGRATION TESTED** | YES -- tests/test_provider_conformance.py `test_every_shipped_provider_loads_without_error` (:344), `test_no_shipped_adapter_resolves_its_program_through_path` (:454), `test_no_shipped_executable_resolver_reaches_path_through_a_helper` (:463). |
| **ADVERSARIAL TESTED** | NO. No attack in tools/attacks/ substitutes a provider binary or moves one into a writable directory. The coverage is entirely unit and conformance. |
| **ENFORCEMENT LAYER** | Filesystem ownership and mode inspection (`stat`) over the full path, plus an exact-path allowlist derived from the manifest, applied before `subprocess.Popen`. Additionally clamped by the sealed approved-provider policy (`ApprovedPolicy` sf_providers.py:700), which pins each manifest by digest. |
| **USER-FACING CLAIM ALLOWED?** | YES: "a provider only runs the program its manifest declares, and only if nobody but root or you can replace it." Do NOT extend this to what the program does once running -- see rows 17 and 18. |
| **NOTES** | Firebreak's own record marks `executable_path` as `observed`, not enforced (shadowfetch-firebreak:395): bwrap resolves argv[0] itself at exec time and Firebreak does not pin it. The pinning above happens in the orchestrator, one layer up. Two layers, two different statuses, and the honest claim is the orchestrator's. |

---

## 13. masked_paths enforced

| | |
|---|---|
| **CLAIM** | Paths a provider declares must not be visible to it are hidden from the sandbox. |
| **IMPLEMENTED** | **YES, since Stage E.** Each declared path is mounted over inside the sandbox's own mount namespace: an empty tmpfs over a directory, `/dev/null` over a file (`mask_targets()`, shadowfetch-firebreak). `enforcement()` reads the mounts back out of the argv about to be spawned rather than echoing the request, so a mask that did not reach bwrap reports `not_enforced`. The anti-widening checks that were the only mechanism before are still there: `SandboxSpec.narrow()` and `verify_invocation()` refuse to DROP a declared mask. |
| **UNIT TESTED** | YES. test_firebreak_records.py `test_a_masked_path_changes_the_sandbox_and_says_so` and `test_a_masked_directory_becomes_an_empty_tmpfs`; tests/test_sandbox_spec_audit.py for the audit table and the remaining backlog. |
| **INTEGRATION TESTED** | YES -- the tests run Firebreak and read the `.session` record back. |
| **ADVERSARIAL TESTED** | YES -- attack_concurrency.py `21-a-declared-mask-reaches-nothing` (which now measures that it reaches something) and `21-declared-masks-are-disclosed`. Measured through the real Firebreak: direct open, absolute path, relative traversal, symlink, nested file and renaming the target are each denied. |
| **ENFORCEMENT LAYER** | The kernel, via the sandbox's own mount namespace. No cooperation from the payload is involved. |
| **USER-FACING CLAIM ALLOWED?** | YES, with its real limit stated: masking is BY PATH. A hardlink to the same inode under an unmasked name is still readable, and a path outside the workspace is refused rather than masked. |
| **NOTES** | The claim that may be made is "this path is not visible in the sandbox", not "this data is unreachable". The shipped `claude` manifest declares no masks and `localmodel` declares none either, so the field is exercised today mainly by the tests -- which is why the adversarial cases matter more here than the shipped ones. |

---

## 14. workspace_mode enforced

| | |
|---|---|
| **CLAIM** | A mission declared read-only cannot write to its workspace. |
| **IMPLEMENTED** | Firebreak binds the workspace `--ro-bind` for read-only and `--bind` otherwise (shadowfetch-firebreak:484-485), and reports the status by reading it back out of the BUILT argv (:380, :382). The orchestrator passes `--workspace-mode` from the SandboxSpec (sf_missions.py:2850-2851). `verify_invocation()` sf_providers.py:1018-1019 refuses an adapter that upgrades a read-only workspace to writable. |
| **UNIT TESTED** | YES -- tests/test_sandbox_spec_audit.py `test_a_read_only_workspace_mode_refuses_the_write` (:968) and `test_the_default_workspace_mode_is_still_writable` (:996); packages/shadowfetch-fireline/tests/test_firebreak_4.py `test_read_only_workspace_mode_binds_the_workspace_read_only` (:38), `test_the_default_workspace_mode_still_binds_writable` (:46). |
| **INTEGRATION TESTED** | YES, empirically, against a real sandbox. `test_a_read_only_workspace_mode_refuses_the_write` spawns bwrap, asserts the probe printed `WORKSPACE WRITE REFUSED ... Read-only file system`, and asserts the file did NOT appear on the host. Confirmed running rather than skipping this session: `pytest -k Empirically` collected and passed 9 tests, and `bwrap`, `systemd-run` and `journalctl` are all installed on the build host. |
| **ADVERSARIAL TESTED** | PARTIAL -- attack_concurrency.py `21-no-vacuously-enforced-field` and `21-session-record-agrees-with-firebreak` check that the reported status is derived rather than echoed, but no attack tries to write through a read-only bind. The empirical unit test is the stronger evidence here. |
| **ENFORCEMENT LAYER** | `bwrap --ro-bind` -- a kernel mount namespace. A write fails with EROFS regardless of what any Python code intended. |
| **USER-FACING CLAIM ALLOWED?** | YES: "a read-only mission cannot modify your files; the attempt fails at the kernel, not at our discretion." |
| **NOTES** | The history is the reason to keep the test: before `--workspace-mode` existed, a provider declaring `read-only` got a fully writable workspace and the restriction held only because the Codex adapter volunteered `--sandbox read-only` in its own argv -- provider code choosing its own restraint, which is what a sandbox boundary exists in order not to depend on. `/tmp` remains a writable tmpfs in both modes, by design. |

---

## 15. egress_allowlist enforced

| | |
|---|---|
| **CLAIM** | A provider only reaches the hosts its allowlist names. |
| **IMPLEMENTED** | **YES, since Stage C, and only where hosts are declared.** A helper unshares user+net BEFORE bwrap, slirp4netns attaches the NAT to that namespace from outside, the helper installs an nftables ruleset in the namespace it owns (default `policy drop`, accepting established/related, `lo`, the NAT's own 10.0.2.0/24, and one `ip daddr` per resolved address), and only then execs bwrap without `--unshare-net`. The sandbox inherits a namespace that is already NAT'd and already filtered. Names are resolved ON THE HOST at launch: the sandbox never chooses what a name means, and a host that resolves to nothing refuses the run rather than starting it unfiltered. |
| **UNIT TESTED** | YES. test_firebreak_records.py `test_an_egress_allowlist_reaches_a_real_filter_and_says_so`, `test_an_egress_allowlist_on_an_unrouted_namespace_is_enforced_by_absence`, `test_the_recorded_argv_is_the_argv_that_was_spawned`; tests/test_approvals.py for the per-decision mediation; tests/test_sandbox_spec_audit.py for the audit table. |
| **INTEGRATION TESTED** | YES -- measured through the real Firebreak: `with allowlist -> allowed REACHED, denied blocked:TimeoutError`; `no allowlist -> both REACHED`; `net=none -> both blocked`. |
| **ADVERSARIAL TESTED** | YES -- attack_concurrency.py `21-an-allowlist-reaches-a-destination-it-never-allowed` (loopback contained, the allowlisted address reached, an un-allowlisted address blocked) and attack_approval.py `egress-widened-after-approval`, which now reports THE DESTINATION CHANGE WAS PREVENTED: `Scope.egress_hosts` carries the destinations, so widening the ceiling after a grant stops the approval covering the mission. |
| **ENFORCEMENT LAYER** | nftables in a network namespace the launcher owns, installed by the process that created it, before the payload runs. |
| **USER-FACING CLAIM ALLOWED?** | YES, with three limits stated. (a) FILTERING IS BY ADDRESS: a name is resolved once, on the host, at launch, so an address set that changes afterwards is unreachable until the next run. (b) IPv4 only -- the ruleset matches `ip daddr`, so an IPv6 destination is not filtered by it, and is unreachable one step earlier instead: slirp4netns provides no IPv6 route, so the connection fails with `Network is unreachable` rather than reaching the default drop. Same outcome, different mechanism, and the difference matters the day the NAT is given IPv6. (c) DNS QUERIES LEAVE: the sandbox resolves through the NAT's forwarder at 10.0.2.3, which the ruleset permits, so a payload can encode data in query names. An allowlist narrows where bytes may be SENT; it is not a claim that nothing can be signalled out. |
| **NOTES** | Declaring NO hosts while the network is on is the case to watch: a NAT is attached and no ruleset is installed, so the sandbox reaches anything. That is why `POLICY_MEDIATION["network_destination"]` is `partially_mediated` in the static table and decided PER MISSION in `_mediation_for()` -- `fully_mediated` with declared hosts, `observable_only` without, and the decision lists it in `advisory_fields` in the second case. |

---

## 16. Credential isolation

| | |
|---|---|
| **CLAIM** | A provider receives only the credential identities its manifest declares and a mission's approval covers, it never sees an undeclared one, and no adapter ever sees a value. |
| **IMPLEMENTED** | Four layers. (a) `Executor.credentials_for()` sf_missions.py:2992 resolves identities to values OUTSIDE the sandbox from the manifest's own list; no provider name appears in it. (b) `run_process()` :2868-2874 intersects the resolved set with the adapter's narrowed `spec.credential_ids` and passes `--credential-env NAME` only; the value never enters an argv. (c) Firebreak refuses a name outside `CREDENTIALS` (shadowfetch-firebreak:514), requires it to be set, and builds `--clearenv` plus one `--setenv` per granted identity (:462, :520-522). (d) `verify_invocation()` sf_providers.py:1045-1049 refuses an invocation whose `env_allowlist` names an undeclared credential. Values that surface in output are struck by `sf_redact.StreamRedactor` across read boundaries (sf_missions.py:2919). |
| **UNIT TESTED** | YES -- tests/test_sandbox_spec_audit.py `test_only_granted_credentials_cross_the_boundary` (:872), `test_credential_narrowing_by_an_adapter_is_honoured` (:741), `test_credential_narrowing_keeps_what_was_not_narrowed_away` (:754); tests/provider_conformance.py `test_environment_allowlist_holds_no_undeclared_name_and_no_value` (:573), `test_credential_identities_are_a_subset_of_the_manifest` (:624); tests/test_provider_conformance.py `test_invocation_refuses_a_credential_value_in_the_environment_allowlist` (:432); packages/shadowfetch-fireline/tests/test_firebreak_4.py `test_individual_credential_only` (:95); tests/test_redact.py (60 tests, 247 subtests) for the value-in-output path. |
| **INTEGRATION TESTED** | YES, empirically. `test_only_granted_credentials_cross_the_boundary` sets three placeholder variables, grants one, and asserts the sandboxed process sees `['OPENAI_API_KEY']` and nothing else; a request for an unsupported name exits 1. Also test_firebreak_records.py `test_the_recorded_argv_never_contains_a_credential_value` (:213) and `test_a_credential_identity_is_recorded_even_though_its_value_is_not` (:231). |
| **ADVERSARIAL TESTED** | YES -- attack_approval.py `credential-ceiling-widened` and `credential-alias-substitution`. Observed this run: approved identities `['CODEX_API_KEY']`, injected identities `['CODEX_API_KEY']`; a manifest that grew a second identity stopped being covered by the existing approval. |
| **ENFORCEMENT LAYER** | `bwrap --clearenv` then one `--setenv` per granted identity -- the undeclared name is simply not in the sandbox's environment. Resolution happens in the orchestrator process, outside the namespace. |
| **USER-FACING CLAIM ALLOWED?** | YES: "a provider is given only the credentials you approved, by name; it never sees the others, and no provider code resolves a value." |
| **NOTES** | One caveat a person granting an approval should be told, surfaced by `credential-alias-substitution`: the Codex manifest declares `OPENAI_API_KEY` as an ALIAS for the identity `CODEX_API_KEY` (`credentials_for()` sf_missions.py:3007-3012). Approving "CODEX_API_KEY" with only `OPENAI_API_KEY` set in your environment hands over that variable's value. The approval names the identity, not the source. |

---

## 17. Network namespace isolation

| | |
|---|---|
| **CLAIM** | A mission declared offline has no network. |
| **IMPLEMENTED** | For `none`: `arguments()` shadowfetch-firebreak:487 adds `--unshare-net`, and `enforcement()` :425-429 reports ENFORCED only after finding that flag in the built argv. For anything else: no namespace is created and `enforcement()` :434-438 reports `not_enforced` with the reason "the sandbox keeps the host's network, its loopback services and its abstract sockets". `sandbox_enforcement()` sf_providers.py:958-967 mirrors that as PARTIAL on the orchestrator side. `Store.create()` sf_missions.py:2228 defaults a mission to `none` unless the provider's manifest declares otherwise, and `mission_decision()` :3711-3713 clamps the ceiling to `network="none", egress_allowlist=()` when the mission asks for none. |
| **UNIT TESTED** | YES -- tests/test_sandbox_spec_audit.py `test_network_none_is_passed_as_none` (:730); test_firebreak_records.py `test_a_network_posture_of_none_without_the_namespace_is_not_enforced` (:252), `test_network_allow_is_never_recorded_as_enforced` (:293); tests/provider_conformance.py `test_no_provider_obtains_an_implicit_network_grant` (:708); packages/shadowfetch-fireline/tests/test_firebreak_4.py `test_private_root_clean_environment_network_off` (:52). |
| **INTEGRATION TESTED** | YES, empirically. tests/test_sandbox_spec_audit.py `test_network_none_leaves_no_route` (:838) spawns a real sandbox that tries `socket.create_connection(('1.1.1.1', 53))` and asserts `BLOCKED`, not `REACHABLE`. Passed this session with bwrap present. |
| **ADVERSARIAL TESTED** | PARTIAL -- attack_concurrency.py `21-an-allowlist-reaches-a-destination-it-never-allowed` proves the `allow` half empirically (the sandbox reached an un-allowlisted destination). No attack tries to escape `--unshare-net`. |
| **ENFORCEMENT LAYER** | `bwrap --unshare-net` -- a kernel network namespace with no interface but loopback. For any other posture: **none**. |
| **USER-FACING CLAIM ALLOWED?** | YES for `none`, in those words: "an offline mission has no network; the namespace has no route." **NO for `allowlist`/`allow`.** Do not describe a networked mission as "restricted", "sandboxed network" or "limited to approved hosts". It has the host's network, including loopback services and abstract unix sockets on the host. |
| **NOTES** | This is the row most likely to be over-summarised into "network isolation: enforced". The status is split by posture and must stay split: ENFORCED for `none`, PARTIAL/not_enforced otherwise, which is precisely what the two tables say (sf_providers.py:892, sf_policy.py:56 vs :58). |

---

## 18. Resource limits: memory, processes, CPU

| | |
|---|---|
| **CLAIM** | A mission is bounded by the memory, task and CPU limits its manifest declares. |
| **IMPLEMENTED** | Memory and processes: `systemd-run --user --scope` with `--property=TasksMax=`, `--property=MemoryMax=`, `--property=MemorySwapMax=0` (shadowfetch-firebreak:567); `enforcement()` :414-422 reads those back out of the argv. CPU: `limits()` :524-531 sets `RLIMIT_CPU` in a `preexec_fn`. The orchestrator passes the tighter of the declared ceiling and the mission timeout (sf_missions.py:2846-2848) -- passing only the mission timeout meant a provider declaring 60s got 900s while `verify_invocation()` made the declaration look enforced. |
| **UNIT TESTED** | YES -- tests/test_sandbox_spec_audit.py `test_memory_mb_bounds_the_workload_and_not_merely_the_resident_set` (:940), `test_processes_cap_refuses_the_task_that_would_exceed_it` (:920), `test_cpu_seconds_kills_a_process_that_exceeds_it` (:888), `test_cpu_seconds_accounting_restarts_on_fork` (:897), `test_firebreak_refuses_limits_the_manifest_schema_would_accept` (:812), `test_passed_values_are_the_specs_own_values` (:713). |
| **INTEGRATION TESTED** | YES, empirically, all four against real sandboxes. |
| **ADVERSARIAL TESTED** | PARTIAL -- attack_concurrency.py `21-no-vacuously-enforced-field` and `21-odd-specs-never-weaken-the-caveats` attack the REPORTING. The limits themselves are covered by the empirical tests rather than by an attack. |
| **ENFORCEMENT LAYER** | memory: systemd `MemoryMax` + `MemorySwapMax=0` on the scope's cgroup -- ENFORCED. processes: systemd `TasksMax` -- ENFORCED. cpu_seconds: `RLIMIT_CPU` -- **PARTIAL**. |
| **USER-FACING CLAIM ALLOWED?** | YES for memory and process count, in full. **PARTIAL for CPU, and the residual must travel with the number.** |
| **NOTES** | `RLIMIT_CPU` is a PER-PROCESS limit, so a provider that forks gets a fresh budget for every child and the declared figure is not a session budget. This is measured, not assumed: `test_cpu_seconds_accounting_restarts_on_fork` (:897) spawns three children that each burn ~1.2s under a 2s cap and asserts all three complete, with a comment saying that if the test ever starts failing the audit note must be updated. Both tables say `partial` (sf_providers.py:903, sf_policy.py:73) and so must any UI. |

---

## 19. MCP destructive actions gated and audited

| | |
|---|---|
| **CLAIM** | The destructive tool on the agent-facing MCP surface is withheld by default, refused without an observable correlation, and every call -- allowed or denied -- is written to a hash-chained audit log before it takes effect. |
| **IMPLEMENTED** | Categories `READ_ONLY` / `MUTATING` / `DESTRUCTIVE` are declared per tool and `Tool.__init__` refuses an unknown one (sf_mcp.py:568-572). `Server._gate()` :635 withholds a DESTRUCTIVE tool unless `SHADOWFETCH_MCP_DESTRUCTIVE=allow` (`destructive_allowed()` :86) AND the correlation status is `observed` (:651). `tools/list` does not even advertise it otherwise (:632). `Server.call()` :675 records `phase="requested"` with `durable=True, required=True` BEFORE the handler runs (:700-706), so a mutation that cannot be recorded does not happen. `correlation()` :183 rejects a malformed id by SHAPE before any path is built. The log is its own hash chain (`audit_hash` :256, `append` :400) with the shared journald anchor (`_shared_anchor` :329). |
| **UNIT TESTED** | YES -- packages/shadowfetch-fireline/tests/test_mcp_audit.py `test_every_tool_declares_a_category` (:159), `test_a_tool_cannot_be_registered_without_a_category` (:181), `test_a_mutation_is_recorded_before_it_happens` (:217), `test_undo_is_not_advertised_to_agents` (:353), `test_a_denied_undo_changes_nothing` (:359), `test_a_denied_undo_is_recorded_as_denied` (:369), `test_undo_is_refused_without_correlation_even_when_enabled` (:377), `test_undo_is_refused_when_the_session_id_is_malformed` (:395), `test_a_mutation_is_refused_when_it_cannot_be_recorded` (:319), `test_the_chain_detects_an_altered_record` (:256), `test_the_chain_detects_a_removed_record` (:268), `test_concurrent_appends_do_not_fork_the_chain` (:282). |
| **INTEGRATION TESTED** | YES -- `test_undo_runs_for_an_operator_with_a_recorded_session` (:404), `test_undo_is_refused_when_it_cannot_be_recorded_and_changes_nothing` (:417). |
| **ADVERSARIAL TESTED** | YES -- attack_lifecycle.py `mcp-destructive-no-correlation`; also attack_integrity.py `firebreak-session-forged` and `firebreak-session-claim`. Observed this run: with no opt-in the tool list was `['diff','list','snapshot']` and the call was refused; nine truthy-but-wrong values for the env var (`1`, `true`, `yes`, `YES`, `ALLOW`, `Allow`, `allowed`, `0`) all failed to enable it, only `allow` (whitespace-stripped) worked; absent, unknown and malformed correlations were each refused with the status named; the workspace was byte-identical after every refusal; and the audit chain verified `ok=True head_seq=16 problems=[]` with all fourteen denials recorded. |
| **ENFORCEMENT LAYER** | Python gate in the MCP server plus a SHA-256 hash-chained JSONL audit log anchored to journald. The server runs with the same uid as the agent it gates, which is the ceiling on what it can prove. |
| **USER-FACING CLAIM ALLOWED?** | YES for "withheld and audited": "the destructive tool is not offered to agents, and every call to this surface is recorded before it takes effect." **NO for "an agent cannot undo your work".** Two live paths defeat that stronger sentence. |
| **NOTES** | Both paths were observed, not inferred. (a) The correlation is `_session_recorded()` = one `is_file()` call (sf_mcp.py:178), and the `.session` file lives under a directory this uid owns -- the attack created its own, reached `observed`, and the undo ran and deleted a file. The server records the status as `observed` and its own comment defines that as weaker than "the session is real", so the refusal to overclaim holds; what stands between an agent and the tool is one environment variable the agent does not set. (b) `shadowfetch-checkpoint undo` at a terminal performs the same destructive operation through the tool handler directly -- no gate, no audit row. It is meant for a person, and it is the one path to this engine that keeps no record. |

---

## Summary: what may be claimed

**Enforced by a mechanism outside our own code, and safe to state plainly:**
workspace read-only binding (bwrap `--ro-bind`); network on/off for the `none`
posture (bwrap `--unshare-net`); credential identity isolation (bwrap
`--clearenv` + `--setenv`); memory (systemd `MemoryMax` + `MemorySwapMax=0`);
process count (systemd `TasksMax`); provider executable identity (filesystem
classification + manifest allowlist).

**Enforced by our own code, honest to state with the boundary named:** mission
approval for escalating missions; approval scope containment; state-machine
validation; retry budget; cancellation recording; MCP destructive gating.
All of these hold against the engine API and are defeated by a uid that writes
the SQLite file directly -- for which the compensating claim is detection, not
prevention.

**Tamper-evident, never tamper-proof:** the audit chain, the approval
provenance digest, the journald anchor, mission history replay. Each detects;
none prevents; root defeats all of them.

**Partial, and the residual must travel with the claim:** `cpu_seconds`
(`RLIMIT_CPU` is per-process; a forking provider gets a fresh budget per child).

**Enforced since this phase, each with its residual stated above:**
`masked_paths` (Stage E, by mount namespace, BY PATH) and `egress_allowlist`
(Stage C, by nftables in the sandbox's own network namespace, BY ADDRESS, IPv4,
and only where hosts are declared). Both were "declared and reaching nothing"
when this document was first written, and both rows above record the measured
before-and-after rather than replacing one claim with another.

**Not enforced, and no surface may present it as a control:** nothing in the
sandbox spec remains. `unenforced_fields()` is `["syscall_profile"]`, which is
the next row rather than a gap in an existing one.

**Enforced, and still not declarable — the two are not in tension.** Syscall
filtering. Firebreak assembles a classic-BPF program in its own source — no
libseccomp, no helper binary, nothing resolved through a search path — seals it
in a memfd and passes `bwrap --seccomp <fd>`; 46 syscalls answer EPERM. A
self-test loads the real program in a throwaway child and makes a denied AND a
permitted call under it before any argv exists, so a kernel that will not take
the filter refuses the run rather than starting it unfiltered, and
`enforcement()` reads the descriptor back and compares it byte-for-byte with the
digest of what this build assembles. There is still no manifest property and no
`SandboxSpec` field, deliberately: the profile is Firebreak's, identical for
every sandbox, and a provider choosing its own syscall surface is exactly what a
sandbox boundary exists in order not to permit.

**Measured, against a byte-identical pre-change control.** 25 of the 46 rows
changed an observed outcome and 16 were outright successes a payload could
perform — `add_key`, `keyctl`, `request_key`, `io_uring_setup`,
`process_vm_readv`/`writev`, `ptrace`, `kcmp`, `adjtimex`, `clock_adjtime`,
`name_to_handle_at` all went from REACHED to `blocked:EPERM`. The escalation is
the load-bearing part: `mount` and `chroot` are EPERM at first attempt only
because bwrap drops capabilities, and that is one `unshare(CLONE_NEWUSER)` from
being undone — measured before, `unshare ok -> mount REACHED`; after,
`unshare ok -> mount blocked:EPERM`, and the same for `chroot`, `pivot_root`,
`fsopen` and `open_tree`. `unshare` itself is still permitted, deliberately, and
now buys nothing, because a seccomp filter is inherited into the namespace it
creates and cannot be removed.

**Why the rest of the table is not decoration**, also measured: a filter denying
only `open`/`openat`/`openat2` on this kernel gave `open blocked:EPERM` and
`io_uring_openat REACHED:fd5`, which then read `/etc/hostname` through the
smuggled descriptor. Inside a filtered sandbox the same probe reports
`blocked-at-setup:EPERM`.

**The residuals, stated rather than rounded up.** 21 of the 46 rows changed
nothing today — they were already EPERM and stayed EPERM through the escalation,
so they are defence in depth and not new enforcement; the source table carries
the measured baseline per row so a later reader cannot round that up. Nested
user namespaces are still creatable on purpose, because glibc, node and chrome
build their own (`bwrap --disable-userns` works here and is deliberately not
shipped). A 32-bit payload dies with SIGSYS, because seccomp matches syscall
NUMBERS and 165 is `mount` on x86_64 and `getpgrp` on i386, so the architecture
gate refuses the personality rather than filtering the wrong table. No `ptrace`
means no debugger inside the sandbox; no `perf_event_open` means no `perf`; no
`syslog` means no `dmesg`; no nested bwrap. And only the PAYLOAD is filtered:
systemd-run, the namespace helper and slirp4netns are Firebreak's own code.

**Landlock is not used, and the reason is a measurement.** ABI 9 is present on
this kernel, and `bubblewrap 0.11.0` here has no Landlock support at all
(`bwrap --help` and `strings /usr/bin/bwrap` both return zero matches). A
ruleset installed before bwrap is inherited across `execve` and would forbid
bwrap its own bind mounts; using it would need a shim between bwrap and the
payload. What it expresses — filesystem paths and TCP ports — is already the
mount namespace's job and the egress filter's, and neither of those can express
a syscall.

## Where the evidence is thinnest

Ranked by the gap between what the code now does and what a test will notice if
it stops doing it. None of these is a defect in the mechanism; each is a
mechanism with nothing guarding it.

1. **Approval provenance (row 3).** No unit test names `approval_digest`,
   `APPROVAL_WITNESSED_FIELDS`, `record_sha256` or `approval_revocation`. A
   regression restores a permissive behaviour, which fails silently.
2. **Mission history classification (row 4).** No test names `verify_states`,
   the legacy pin, or any of the five classes.
3. **Retry budget at the edge (row 9).** The only test covers `Store.retry()`,
   which was never the broken verb.
4. **Audit exit ladder (row 7).** No test asserts that text and `--json` return
   the same code -- the exact defect Phase 3.1 fixed.
5. **Anchor identity and per-seq comparison (row 6).** `store_identity`,
   `other_chains` and the `heads` map are covered by probes and attacks but by
   no unit test.
6. **Create atomicity (row 10).** Load-bearing for row 4 and asserted nowhere.
7. **Provider executable substitution (row 12).** Strong unit coverage, no
   adversarial coverage.

## How this was verified

On the build host, against `release/4.0.0` HEAD `822d5bb`, 2026-09-09:

- Every test file under `packages/shadowfetch-missions/tests/` run with
  `python3 -m pytest -q`: 428 passed, 4 skipped, 0 failed. `bwrap`,
  `systemd-run` and `journalctl` are all installed, so the empirical sandbox
  tests ran rather than skipping (confirmed with `pytest -k Empirically`:
  9 passed, 0 skipped).
- `tools/attacks/attack_integrity.py` -- 15/15 PASS.
- `tools/attacks/attack_approval.py` -- 20/20 PASS.
- `tools/attacks/attack_concurrency.py` -- 18 passed, 0 FAILED.
- `tools/attacks/attack_lifecycle.py mcp-destructive-no-correlation
  cancel-completion-race` -- 2 PASS.
- Hand probes on throwaway stores for: forged mission row classification,
  `audit verify` exit-code parity between text and `--json`, approval
  `granted_by` tampering, and revocation erased from the approvals table.

A caveat about the attack transcripts quoted above. As of the committed HEAD,
several `tools/attacks/attack_integrity.py` NOTE texts were hard-coded prose
carried over from the pre-3.1 baseline and contradicted their own OBSERVED
blocks: `state-jump-retry-budget` and `state-jump-forged-row` both still
asserted the defect the engine now catches, and `event-delete-genesis` stage 2
described an unverified-not-conflict outcome that the store-identity check has
since turned into `ok=False` and exit 1. Everywhere those disagree, the OBSERVED
block is the evidence and the note is not -- every cell above was taken from
OBSERVED, never from a note. That file was being rewritten in the working tree
while this was compiled, to assemble each note from live values instead, so a
reader who finds the notes agreeing with the observations should take that as
the fix having landed rather than as a contradiction here.

`packages/shadowfetch-missions/debian/` was not consulted -- those are stale
build copies. Everything above is from the `data/usr/lib/shadowfetch/missions/`
source of truth.
