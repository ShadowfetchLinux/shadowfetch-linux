# Trust boundaries

Who can change what, and whether the change would be noticed.

Measured on the release/4.0.0 branch at 822d5bb, on shadowfetch-linux
(Pop!_OS, kernel `pop-os`, machine `a75ce2fd…`), 2026-09-09. Every claim below
was checked by running the thing named beside it. Where the box disagrees with
the branch, the box is reported too — see **Deployment discrepancies**.

## Two vocabularies, deliberately not merged

`sf_providers.SANDBOX_ENFORCEMENT` and `sf_policy.POLICY_MEDIATION` answer
"does a declared restriction reach a mechanism": **enforced / partial /
not_enforced / not_representable / not_applicable / observed**. That vocabulary
is about a mission's own limits and is not reused here.

This document answers a different question — "if this actor corrupts this
asset, what happens" — and uses three words only:

| word | means |
| --- | --- |
| **PREVENTED** | the actor cannot make the change. A mechanism outside this codebase refuses it: file ownership, mount namespace, kernel permission check. |
| **DETECTABLE** | the actor can make the change, and a verifier we ship reports it. The mechanism is named, and the naming is testable. |
| **UNDETECTABLE** | the actor can make the change and nothing we ship reports it. Said plainly, not softened. |

"Tamper-evident" appears in this document only where the evidence can be
pointed at. It is never a synonym for "protected".

## The actors

| actor | who that is here |
| --- | --- |
| **MISSION USER** | the unprivileged uid that runs the CLI and the worker and owns the state directory. On this box `rtx5060ti`, uid 1000. This is the engine's own identity — the engine has no privilege the attacker in this row lacks. |
| **SANDBOXED AGENT** | provider code executing inside Firebreak. Same uid, different mount and network namespace. |
| **ROOT** | uid 0. |
| **PACKAGE MANAGER** | dpkg/apt acting as root, replacing files under `/usr`. Separated from ROOT because it is the routine, unattended path to root-owned data. |
| **LOCAL ADMIN** | a human who can become root. On this box the MISSION USER is in `sudo`, so LOCAL ADMIN and MISSION USER are the same person one command apart. That is a fact about this box, not a design property. |

The mission worker does **not** run as root. There is no systemd unit for it
(`systemctl list-units | grep -i mission` returns nothing for the engine);
`grep -n "sudo\|pkexec\|setuid\|seteuid" sf_missions.py` returns nothing;
`run_process()` calls `subprocess.Popen(...)` with no escalation; and
`/usr/bin/bwrap` is `-rwxr-xr-x root root`, not setuid — the sandbox is built
from unprivileged user namespaces. Confirmed.

## The assets

| asset | where it lives | owner / mode as measured |
| --- | --- | --- |
| **missions DB** | `$SHADOWFETCH_MISSIONS_STATE` or `$XDG_STATE_HOME/shadowfetch/missions/missions.sqlite3` — tables `missions`, `tasks`, `agent_sessions`, `tool_executions`, `test_runs`, `git_changes`, `steps` | state root `drwx------`, db `-rw-------`, both the mission uid |
| **events DB** | the `events` table **in that same file** — the hash chain | same file, same mode. There is no separate database and no separate permission. |
| **approval rows** | the `approvals` table, same file | same file, same mode |
| **local receipts** | `<state root>/<mission-id>/receipt.json`, `changes.diff`, `changes.json`, `*.log` (`Store.directory()`, `mkdir(mode=0o700)`) | `drwx------`, files written by `atomic()` at default umask, mission uid |
| **Firebreak manifests** | `~/.local/state/shadowfetch/firebreak/*.session` | `-rw-------`, mission uid |
| **journald anchor** | the journal store, `/var/log/journal/<machine-id>/` | dir `2755 root:systemd-journal` plus ACL `group:adm:r-x` and `other::r-x`; journal files `640 root:systemd-journal`. No FSS key (`…/fss` does not exist). |
| **external chain anchor** | lines under `SYSLOG_IDENTIFIER=shadowfetch-audit` inside that journal, plus the local bookkeeping file `<state root>/audit-mirror.json` | the journal is root-owned; `audit-mirror.json` is `-rw-------` mission uid |
| **provider manifests** | `/usr/share/shadowfetch/providers/*.json` | root-owned when packaged. **Not installed on this box** — the loader falls back to the repo tree, where they are `-rw-r--r-- rtx5060ti`. |
| **approved-provider policy** | `/usr/share/shadowfetch/provider-policy/approved.json` | root-owned when packaged. **Not installed on this box** — falls back to `packages/shadowfetch-missions/data/usr/share/shadowfetch/provider-policy/approved.json`, `-rw-rw-r-- rtx5060ti`. |

Two facts about that table matter more than the rest:

1. **The chain and the rows it verifies are one file with one permission.**
   There is no boundary between "the record" and "the thing recorded"; the
   only boundary is the hash chain, which is arithmetic, not access control.
2. **`audit-mirror.json` is inside the attacker's own trust domain.** It is
   bookkeeping, not evidence, and `verify_chain()` treats it that way — see
   the note under MISSION USER.

## MISSION USER

The uid that owns everything above. This is the row that matters, because it
is also the uid the engine itself runs as.

| asset | verdict | mechanism |
| --- | --- | --- |
| missions DB | **DETECTABLE** for `state`; **UNDETECTABLE** for the rest | `Store.verify_states()` replays each mission's events through `MISSION_TRANSITIONS`. Measured: `UPDATE missions SET state='completed'` → `STATE_DIVERGENCE`, `ok=False`, exit 1. An inserted mission row with no events → `MISSING_HISTORY`, exit 1, because `Store.create()` writes the row and its first event in one transaction and the v4 `legacy-missions-pinned` event names the only rows allowed to have none. Nothing replays `agent_sessions`, `tool_executions`, `test_runs`, `git_changes` or `tasks`: `record_tool_execution()` chains an event whose detail is `f"{tool}: {requested_action}"` and carries **no digest of the row**, so editing `decision`, `approval_id`, `exit_status` or `args_digest` changes nothing a verifier compares. |
| events DB | **DETECTABLE** for edits and for truncation-so-far; see the anchor row for the limit | `verify_chain()` recomputes `event_hash(prev, row)` per row. Measured: `UPDATE events SET detail='rewritten' WHERE seq=2` → "content does not match its hash", `chain_ok=False`, exit 1. Truncation is caught only by the external anchor: measured, deleting the last event → anchor `truncated`, exit 1. A re-minted chain (delete the genesis, re-chain) is caught by `sf_audit.store_identity()` — a path-derived id the database cannot restate about itself — surfacing as `other_chains_for_this_store` → verdict `conflict`. |
| approval rows | **DETECTABLE** | The grant event carries `record_sha256` over every field in `APPROVAL_WITNESSED_FIELDS`, and `find_approval()` recomputes it from the stored row, so an edit to `granted_by`, `method`, `granted_at`, `expires_at`, `reason` or the scope is refused with the differing field names. A row inserted straight into `approvals` has no `approval-granted` event and is refused ("no human granted it"). Clearing `revoked_at` no longer revives an approval: `approval_revocation()` reads the chain, not the column. |
| local receipts | **UNDETECTABLE** | `receipt.json` is written by `atomic()` and `Store.update(mid, receipt=str(path))` records **the path only**. `grep -n receipt …` shows no line that also mentions sha, digest or hash. Measured: rewriting a mission's `receipt.json` leaves `verify_chain()` at `ok=True`, exit 0. The receipt embeds an `audit` block asserting the chain was fine — and that block is as editable as the rest of the file. |
| Firebreak manifests | **UNDETECTABLE** | Plain JSON records, `0600`, same uid, no hash and no chain. Firebreak 4 contains no journald/syslog code (`grep -n "journal\|syslog\|/dev/log"` finds only a comment saying the mirror is ADR-0010 future work). Its own source says it: a relocation via `SHADOWFETCH_FIREBREAK_STATE` is made *visible* in the record, and "anything running as this uid can set the variable, and can equally unlink the file afterwards". |
| journald anchor | **PREVENTED** (writing/removing) / not restricted (reading) | Journal files are `640 root:systemd-journal`; this uid is not in `systemd-journal`. It cannot rewrite or delete an entry. It **can** read: the machine-id dir carries `group:adm:r-x` and `other::r-x`, and this uid is in `adm`. Reading the anchor is not corruption, but it does mean the attacker can see exactly what the anchor holds before deciding what to write. |
| external chain anchor | **UNDETECTABLE** in the direction that matters | `/dev/log` is a world-writable datagram socket and `sf_audit.read_head()` runs `journalctl -t shadowfetch-audit -o cat --no-pager -n 5000` — it selects on `SYSLOG_IDENTIFIER`, which the sender supplies, and reads only `MESSAGE`, whose `store`/`chain`/`seq`/`hash` the sender also supplies. Measured: injecting one forged line with `seq: 999` against an **untouched** store flipped the verdict to `truncated`, exit 1 — a false alarm any uid can raise. The other direction is worse and follows from the same two facts plus `-n 5000`: `journalctl -n N` returns the **last** N matching entries (measured: three lines written, `-n 2` returns lines 2 and 3), so an attacker who truncates the database to seq N and then replays seqs 1..N *with their true hashes* until the real N+1..M lines fall out of the window leaves `head_seq == N`, no hash conflict (conflicts need a **differing** hash for a seq), and verdict `agrees`. `audit-mirror.json` is not a defence here — it is attacker-writable, which is why `verify_chain()` reports degradation *alongside* the journal comparison and never in place of it; it can add a caveat, never remove a finding. |
| provider manifests | **PREVENTED** when packaged; **UNDETECTABLE** as deployed here | `_default_manifest_root()` refuses `$SHADOWFETCH_PROVIDER_MANIFESTS` outright ("not environment-selectable in production"), and `ApprovedPolicy.approve()` pins each manifest by `manifest_sha256`, so editing a manifest under a root-owned `/usr/share` fails the digest check. On this box `/usr/share/shadowfetch/providers` does not exist and the loader falls back to the repo tree, which this uid owns — and the same uid owns `approved.json`, so it can edit both and re-seal the digest. |
| approved-provider policy | **PREVENTED** when packaged; **UNDETECTABLE** as deployed here | Same fallback. The policy is the pin; when the pin is user-writable there is no pin. Nothing in the engine records the policy's own digest, so a rewrite leaves no trace to compare against. |

## SANDBOXED AGENT

Firebreak 4 as built by `run_process()` in `sf_missions.py`: `bwrap
--die-with-parent --new-session --unshare-user --unshare-pid --unshare-uts
--unshare-ipc --clearenv`, `--ro-bind` for `/usr /bin /sbin /lib /lib64` and a
short `PUBLIC_ETC` list, `--dev /dev --proc /proc --tmpfs /tmp --tmpfs /run`,
`--dir /home --dir /home/agent …`, then the workspace bound `--bind` (or
`--ro-bind` for `workspace_mode: read-only`) and `--unshare-net` when the
network is `none`.

Probed by running the branch's Firebreak against a real workspace:

```
===SLASH   bin dev etc home lib lib64 proc run sbin tmp usr
===VAR     ls: cannot access '/var': No such file or directory
===HOMECOUNT  3            # only ., .. and Workspaces
===STATE   ls: cannot access '/home/<user>/.local/state/shadowfetch': No such file or directory
===DEVLOG  ls: cannot access '/dev/log': No such file or directory
===JCTL    No journal files were found.
```

So: **the mission state directory is not merely unwritable inside the sandbox,
it is absent**, `/var` is absent so the journal cannot even be read, and
`/dev/log` is absent so no forged anchor line can be sent.

| asset | verdict | mechanism |
| --- | --- | --- |
| missions DB | **PREVENTED** | Not in the mount namespace. Measured above. |
| events DB | **PREVENTED** | Same file, same absence. |
| approval rows | **PREVENTED** | Same file, same absence. |
| local receipts | **PREVENTED** | Written into the state root, which is absent. The agent influences receipt *content* — its stdout, its diff — but cannot touch the file. |
| Firebreak manifests | **PREVENTED** | `~/.local/state/shadowfetch/firebreak` is absent, and `read_grants()` refuses a `--read` that overlaps `state()` or `<workspaces>/.sf-checkpoints`. |
| journald anchor | **PREVENTED** | `/var` is not bound; `journalctl` inside the sandbox reports "No journal files were found." |
| external chain anchor | **PREVENTED** | `/dev/log` is not among the nodes `--dev /dev` creates (`core fd full null ptmx pts random shm stderr stdin stdout tty urandom zero`), so the datagram socket the mirror uses is unreachable. |
| provider manifests | **PREVENTED** | `/usr` is `--ro-bind`; a write fails EROFS. |
| approved-provider policy | **PREVENTED** | Same `--ro-bind`. |

One residual, and it is a **read**, not a write: `read_grants()`'s `reserved`
list covers `state()` (the *Firebreak* audit dir) and `.sf-checkpoints`, but
not the *missions* state dir — a grant of `~/.local/state/shadowfetch/missions`
would be accepted and `--ro-bind`ed in, exposing prompts and approval scopes to
provider code. It is not agent-reachable today: read grants come from the
manifest's `sandbox_profile.read_grants`, and the manifest is digest-pinned by
`approved.json`. It is one policy edit away from being reachable.

### What the agent can send OUT

The table above is about what the agent can REACH and CHANGE on this machine.
Exfiltration is a separate question and the answer changed this phase, so it is
written out rather than left implied.

Both network postures now give the sandbox its OWN network namespace. Posture
`none` leaves it empty: no interface, no route, and the host's loopback services
and abstract AF_UNIX namespace are out of reach — measured, not assumed. Posture
`allow` creates the namespace BEFORE bwrap (an `unshare --user --net` helper),
attaches a `slirp4netns` NAT to it with `--disable-host-loopback`, and installs
an nftables ruleset inside it before the payload runs.

| channel | verdict | mechanism |
| --- | --- | --- |
| host loopback services | **PREVENTED** in both postures | own netns; `--disable-host-loopback` on the NAT |
| abstract AF_UNIX sockets | **PREVENTED** in both postures | own netns; the abstract namespace is per-netns |
| the LAN | **PREVENTED** | the NAT forwards outward only |
| an un-allowlisted internet address | **PREVENTED** where hosts are declared | nftables `policy drop` in the sandbox's own netns; measured `blocked:TimeoutError` against 8.8.8.8 with 1.1.1.1 allowlisted |
| an IPv6 destination | **PREVENTED**, incidentally | the ruleset matches `ip daddr`, so IPv6 falls to the default drop. Stated because it is a side effect, not a decision |
| any internet address, when the network is on and NO host is declared | **NOT PREVENTED** | a NAT is attached and no ruleset is installed. The decision reports `network_destination` as `observable_only` and lists it in `advisory_fields`, so no surface calls it a control |
| **data encoded in a DNS query name** | **NOT PREVENTED** | the sandbox resolves through the NAT's forwarder at 10.0.2.3, which the ruleset must permit or nothing routes. This is the honest limit of an address filter: it narrows where bytes may be SENT and is not a claim that nothing can be signalled out |
| a granted credential's value | **NOT PREVENTED** | it is in the sandbox's environment (`bwrap --setenv`), so anything the agent starts can read it. There is no credential broker |

The last two are the ones to carry into any user-facing sentence. An egress
allowlist is a real control with a real mechanism, and it is not a claim of
containment.

## ROOT

| asset | verdict | mechanism |
| --- | --- | --- |
| missions DB | **DETECTABLE** to the same extent as MISSION USER, and no further | Root has no extra power over the hash chain — the chain is arithmetic — but it has no *less* either. Same verdicts as the MISSION USER row. |
| events DB | **UNDETECTABLE** | Root can rewrite the database *and* the journal, so the one asymmetry the design rests on disappears. `sf_audit`'s own docstring says it: "It is not tamper PROOF. Root can rewrite the journal." |
| approval rows | **UNDETECTABLE** | Root can forge a grant event, recompute `record_sha256`, re-chain from that seq forward, and rewrite the mirrored journal lines to match. |
| local receipts | **UNDETECTABLE** | Unanchored for anyone. |
| Firebreak manifests | **UNDETECTABLE** | Unanchored for anyone. |
| journald anchor | **UNDETECTABLE** | Root owns `/var/log/journal` and can delete or replace journal files. FSS sealing would make offline file rewrites detectable — it is not set up here (no `fss` key), and `Seal=` is unset in `journald.conf`. Even with it, sealing detects *rewrites of sealed history*, not appends. |
| external chain anchor | **UNDETECTABLE** | Root can write it and can delete it. |
| provider manifests | **PREVENTED against silent change; UNDETECTABLE against deliberate change** | Root editing a manifest breaks `manifest_sha256` and the provider is refused — that is a real integrity check and it fires. Root editing the manifest *and* `approved.json` together defeats it, and nothing records what the policy used to say. |
| approved-provider policy | **UNDETECTABLE** | The policy is the root of the provider trust chain. Nothing anchors it. |

Root is outside the threat model this build defends against, and the code says
so rather than implying otherwise. This section exists to keep that written
down.

## PACKAGE MANAGER

dpkg/apt as root, in the normal course of an upgrade.

| asset | verdict | mechanism |
| --- | --- | --- |
| missions DB | **PREVENTED** in practice | No shipped package writes under `$XDG_STATE_HOME`. A maintainer script could; none does. |
| events DB | **PREVENTED** in practice | Same. |
| approval rows | **PREVENTED** in practice | Same. |
| local receipts | **PREVENTED** in practice | Same. |
| Firebreak manifests | **PREVENTED** in practice | Same. |
| journald anchor | **PREVENTED** | Package scripts do not rewrite journal files; journald owns them. |
| external chain anchor | **UNDETECTABLE** | A package can add a unit, or a program, that writes to `/dev/log` under any identifier. This is not hypothetical privilege — it is what "shipped by a package" means. |
| provider manifests | **DETECTABLE** | This is the case `POLICY_DIR` exists for. A third-party package may drop a file into `/usr/share/shadowfetch/providers` without a dpkg file conflict, but it **cannot overwrite `approved.json`**, which `shadowfetch-missions` owns. The unapproved manifest is refused with "a schema-valid manifest is not sufficient to become a provider", and a changed approved one fails the digest check. |
| approved-provider policy | **DETECTABLE only as a package conflict** | Replacing `approved.json` requires either owning the file (i.e. replacing `shadowfetch-missions`) or a dpkg diversion; both are visible to `dpkg -S` / `dpkg-divert --list`, and neither is anything this codebase checks at runtime. The engine never verifies who owns the policy file it read. |

## LOCAL ADMIN

A human with sudo. On this box that is the mission user (`groups` includes
`sudo`), so every ROOT verdict above is available to them by typing one word.

| asset | verdict | mechanism |
| --- | --- | --- |
| missions DB | as ROOT — **DETECTABLE** for mission `state`, **UNDETECTABLE** for sibling tables | `verify_states()` |
| events DB | as ROOT — **UNDETECTABLE** | can rewrite both sides of the comparison |
| approval rows | as ROOT — **UNDETECTABLE** | can forge grant, digest and mirror together |
| local receipts | **UNDETECTABLE** | unanchored |
| Firebreak manifests | **UNDETECTABLE** | unanchored |
| journald anchor | **UNDETECTABLE** | can `journalctl --rotate --vacuum-time=1s`, or delete the files |
| external chain anchor | **UNDETECTABLE** | both halves are theirs |
| provider manifests | **UNDETECTABLE** | can edit the manifest and re-seal the policy |
| approved-provider policy | **UNDETECTABLE** | can rewrite it |

There is one honest consolation and it is small: an admin who tampers *without
also tampering with the journal* is caught, because the anchor lives outside
their process even though it does not live outside their authority. That is a
mistake-detector, not a control.

## What journald actually gives us, and what we actually use

Written by uid 1000 to `/dev/log` and read back with `journalctl -o json`, the
entry carries these fields **stamped by journald from the socket's credentials
— the sender cannot set them**:

```
_UID=1000  _GID=1000  _PID=147512  _COMM=python3
_EXE=/usr/bin/python3.12  _CMDLINE="python3 -"
_SYSTEMD_UNIT=session-51411.scope  _SYSTEMD_CGROUP=/user.slice/user-1000.slice/session-51411.scope
_SYSTEMD_OWNER_UID=1000  _AUDIT_LOGINUID=1000  _AUDIT_SESSION=51411
_BOOT_ID=…  _MACHINE_ID=…  _TRANSPORT=syslog  _CAP_EFFECTIVE=0
_SELINUX_CONTEXT=unconfined  __CURSOR=…  __SEQNUM=…
```

and these fields **taken from the message the sender wrote**:

```
SYSLOG_IDENTIFIER=trustdoc-probe   SYSLOG_PID=147512
PRIORITY / SYSLOG_FACILITY         MESSAGE={"store":"FAKESTORE","chain":"FAKECHAIN","seq":9999,…}
```

**The design trusts the second list and ignores the first.** `read_head()`
matches with `-t <identifier>` — that is `SYSLOG_IDENTIFIER`, sender-supplied —
and renders with `-o cat`, which returns `MESSAGE` and discards every trusted
field. So `store`, `chain`, `seq` and `hash` are believed because they were
typed into a datagram, not because journald attested anything about who sent
it. Say it plainly: **the external anchor currently authenticates nothing.**
It raises the cost of tampering (you must remember to forge the journal too);
it does not establish who wrote a line.

### What it would take to use the trusted fields instead

1. **Read structured.** Replace `-o cat` with `-o json` and keep `_UID`,
   `_PID`, `_EXE`, `_SYSTEMD_UNIT`, `_BOOT_ID`, `__CURSOR`. Reject any entry
   whose trusted fields do not match the expected writer, rather than any
   entry whose `MESSAGE` does not parse.
2. **Give the writer an identity this uid cannot assume.** `_UID` on its own
   separates nothing, because the attacker in the interesting row *is* uid
   1000 — the same uid the engine runs as, so a forged line and a real line
   are byte-identical in every trusted field. The anchor only becomes
   authenticated once the mirror is sent to a small appender running under its
   own system uid (or root) over its own socket; journald then stamps *that*
   uid, and `read_head()` can require `_UID == <appender uid>` and
   `_SYSTEMD_UNIT == shadowfetch-audit-anchor.service`. A user session cannot
   produce a system unit name — as measured, a uid-1000 write is stamped
   `session-N.scope`. Until that appender exists, no amount of reading
   `-o json` helps.
3. **Stop reading a window.** `-n 5000` is flushable: the last-N semantics are
   measured above, and an attacker who can append can evict. Walk from a
   stored `__CURSOR` with `--after-cursor` instead, and treat a lost cursor as
   `unverified` rather than as a fresh start.
4. **Optionally, `journalctl --setup-keys` (root) for FSS.** It makes offline
   rewrites of sealed history detectable. It does nothing about appends, and
   it is not set up on this box.

Steps 1, 3 and 4 are worth doing. Step 2 is the one that changes the verdict.

## Deployment discrepancies found while measuring

These are facts about this box, not about the branch, and they change what the
matrix means in practice:

* **The installed Firebreak is not the one the branch describes.** `dpkg -l`
  shows `shadowfetch-fireline 3.0.0`, and `/usr/bin/shadowfetch-firebreak` is
  the 3.x **bash** implementation whose argv is `bwrap --ro-bind / /` — the
  whole real filesystem, read-only. Probed through it, the sandbox sees 427
  entries in the real home, sees `/var`, and `journalctl -t shadowfetch-audit`
  **succeeds inside the sandbox**, returning real mirrored chain heads.
  `executable()` in `sf_missions.py` calls `shutil.which()` first and only then
  falls back to the repo tree, so on this box the orchestrator would select
  that 3.x script — which does not implement `--workspace-mode`,
  `--credential-env` or `--session-id`. Every SANDBOXED AGENT verdict above is
  measured against the branch's Firebreak 4 and holds only where Firebreak 4 is
  what runs.
* **The provider manifest and policy directories are not installed.**
  `/usr/share/shadowfetch/providers` and `/usr/share/shadowfetch/provider-policy`
  do not exist, so both loaders fall back to the repo tree. `approved.json`
  there is `-rw-rw-r--` owned by the mission uid. The pin that makes a manifest
  meaningful against a package is, here, a file the mission uid can rewrite.
* **`SHADOWFETCH_MISSIONS_STATE` is ambient.** `Store.__init__` honours it,
  unlike Firebreak, which deliberately refused `$XDG_STATE_HOME` for exactly
  this reason. Pointing it elsewhere gives a store whose `store_identity()`
  (sha256 of the absolute path) has no journal history, so the anchor reports
  `unverified` — exit 2, not a pass. Visible, not prevented.

## What a normal user uid can still do

No mitigations, no framing. Each line is something uid 1000 can do today on
this box, with the verdict a person running `audit verify` would get.

* Rewrite any `receipt.json`, including its embedded `audit` block that claims
  the chain was intact — **undetectable** (measured: exit 0).
* Rewrite or delete any Firebreak `.session` manifest, or relocate the whole
  audit directory with `SHADOWFETCH_FIREBREAK_STATE` and delete what lands
  there — **undetectable**.
* Edit any column of `agent_sessions`, `tool_executions`, `test_runs`,
  `git_changes` or `tasks` — including a tool call's `decision`, its
  `approval_id` and its `exit_status` — **undetectable**; the chained event
  records the tool's name and nothing that would disagree.
* Inject lines into the external anchor under the `shadowfetch-audit`
  identifier claiming any `store`, `chain`, `seq` and `hash` — **undetectable
  as forgery**; the injection itself is anything but silent (measured: one
  forged line turned a clean store into `truncated`, exit 1), which makes it a
  usable denial-of-service against the audit verdict.
* Truncate the events table and then flush the journal's 5000-line read window
  by replaying the surviving seqs with their true hashes — **undetectable**;
  no hash conflict arises because the replayed hashes match, and the heads
  agree again.
* Delete the entire database and start over at the same path — **detectable**;
  `store_identity()` is path-derived, so the journal still holds entries for
  this store under the old chain id and `other_chains_for_this_store` forces
  verdict `conflict`.
* Point the engine at a different state directory with
  `SHADOWFETCH_MISSIONS_STATE` — **detectable** as `unverified` (exit 2), not
  as a pass. The store is new, so the anchor has never heard of it.
* Edit `approved.json` and the provider manifests it pins, on this box, and run
  an unreviewed provider with any capability, credential id and executable
  trust tier — **undetectable**; when packaged correctly this is PREVENTED,
  and here it is not packaged.
* Read the whole journal, including every mirrored chain head, before deciding
  what to forge — **not corruption, and not restricted**; the machine-id
  directory carries `other::r-x` and this uid is additionally in `adm`.
* Set the mission state directly to a state the work never reached —
  **detectable** (`STATE_DIVERGENCE`, exit 1).
* Fabricate a whole mission row — **detectable** (`MISSING_HISTORY`, exit 1).
* Alter any event's content — **detectable** (hash mismatch, exit 1).
* Edit an approval row, insert one, or erase a revocation — **detectable**;
  the whole-record digest and the chain-read revocation both fire.
* Run `sudo` — this uid is in the `sudo` group, at which point every ROOT row
  above applies and none of the detections in this list survive.
