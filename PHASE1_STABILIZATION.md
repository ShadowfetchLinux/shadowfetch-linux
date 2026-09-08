# Phase 1 — Stabilise: work log

**Scope.** Make the existing Shadowfetch 4.0.x codebase safe and structurally
trustworthy enough that the AgentProvider and Mission Control refactors can
begin without building on known P0 defects. This phase implements no new
architecture: no AgentProvider, no credential broker, no new providers, no
Mission Control redesign, and no new privileged services.

**Method applied to every item.** Read the exact implementation and quote the
lines to be changed; find every caller; inspect existing tests; state the
invariant that must remain true; make the smallest defensible change; add a
regression test and demonstrate it fails against the shipped code.

**Branch.** `release/4.0.0`, starting from `57e637a` (tag `v4.0.0`).

---

## W-02 — Version control for the release tree — **COMPLETE**

**Finding.** `.git` was a dangling pointer file reading
`gitdir: /home/rtx5060ti/projects/shadowfetch-3.5.0/.git/worktrees/shadowfetch-4.0.0`.
That parent repository no longer exists, so every git command in the 4.0.0
release tree failed. This silently disabled the history-based secret scan in
`source_gate`, the release diff, and any ability to review what shipped.

**Files changed.** `.git` (restored), ten tracked `*.debhelper` build outputs
untracked, four `work/candidate-source*.bundle` deleted.

**Fix.** `git init` + `git remote add` + `git fetch --tags` +
`git reset --mixed 57e637a`. `reset --mixed` writes the index only.

**Invariant preserved — proven, not asserted.** The working tree was hashed
before and after the repair:

```
BEFORE: 1be19a729b5b559c92b767b5d16abfb4ef77ec222855bf8c78a2ee0243fafd61
AFTER : 1be19a729b5b559c92b767b5d16abfb4ef77ec222855bf8c78a2ee0243fafd61
✅ INVARIANT HELD: zero working-tree bytes modified by the git repair
```

Against `v4.0.0` the restored tree showed only two differing files, both
generated `*.debhelper` outputs already covered by `.gitignore:76`. **The
local tree is byte-identical to the published 4.0.0 tag.**

**Unresolved.** None. The `.debhelper` files remain on disk, merely untracked.

---

## W-04 — Fireline polkit action (local root) — **COMPLETE**

**Finding.** `org.shadowfetch.fireline.policy` declared:

```xml
<allow_active>yes</allow_active>
<annotate key="org.freedesktop.policykit.exec.path">/usr/bin/shadowfetch-firebreak</annotate>
```

`allow_active=yes` means *allowed with no authentication at all*.
`shadowfetch-firebreak` takes an arbitrary command
(`argparse.REMAINDER`, line 248) and runs it. Therefore

```
pkexec shadowfetch-firebreak run -- sh
```

was a **passwordless root shell for any active local session**. The sandbox
that exists to contain an agent shipped the escalation that defeats it.

**Callers.** `git grep org.shadowfetch.fireline` matched only the policy file
and its `.install` line. Nothing invoked it; `shadowfetch-firebreak check`
reads kernel sysctls and needs no privilege. Deletion is behaviour-preserving.

**Fix.** Policy file and its packaging line deleted.

**Tests.** `packages/shadowfetch-fireline/tests/test_fireline_privilege.py`
asserts no `.policy` ships, packaging installs no polkit action, and that
firebreak still accepts arbitrary argv — so re-adding an action stays
obviously wrong.

---

## W-05 — `fs` MCP server read oracle — **COMPLETE**

**Finding.** `sf_mcp.py:468`

```python
root_env = os.environ.get("SF_MCP_FS_ROOT", str(Path.cwd()))
```

Nothing set that variable — not the packaging, not `shadowfetch-mcp config`.
So the "scoped, read-only" server was scoped to whatever directory the agent
started in. Launched from `$HOME`, as an agent normally is, it served the
whole home directory. Demonstrated on the build host against the shipped code:

```
OLD, launched from $HOME with no scope set -> agent can list:
   d .adal
   d .aider
   f .anthropic_new_token
   d .appstore
   ... (422 entries of the home directory)
```

The server's own advertised description told the model it was safely scoped.

**Fix.** `build_fs()` refuses to start unless `SF_MCP_FS_ROOT` names an
existing absolute directory, and applies the same denylist
`shadowfetch-firebreak` already uses for `--read` grants: no filesystem root
or top-level directory, not the whole home directory, nothing under
`/proc /sys /dev /run /boot /etc`, and none of the well-known credential
stores. The refusal is one line on stderr with exit 2, not a traceback.
`shadowfetch-mcp config` now emits the scope so the documented workflow still
produces a server that starts.

**Invariant preserved.** The `_resolve()` path-escape check is unchanged and
still correct, including for absolute arguments (pathlib's
`root / "/etc/passwd"` yields `/etc/passwd`, which the check rejects). A
regression test now pins that.

**Same launch, after the fix:**

```
fs: SF_MCP_FS_ROOT is not set. The fs server refuses to start without an
explicit scope -- it will not silently fall back to the working directory.
```

---

## W-06 — `fireproofd.Verify` unauthenticated — **COMPLETE**

**Finding.** `Verify()` was exported with neither `sender_keyword` nor
`_require_auth`. It executes `dpkg --audit` and `apt-get -s -f install` as
root and returns a detailed report of the machine's package state. The bus
policy allowed `context="default"` to send to the destination, so any local
process could drive that root work in a loop and read the result.

The bus policy's own comment listed the mutating methods "every one of which
checks polkit". `Verify` was simply missing from that list and nothing
enforced it.

**Fix, three parts.**
1. `Verify` takes the caller's bus name, goes through `_require_auth`, and
   holds a non-blocking lock so a second battery is refused with `Busy`.
2. New read-only `Inspect()` returns the last recorded result and executes
   nothing — preserving the unprivileged read path `Verify` was providing by
   accident, without the root execution.
3. The bus policy became **default-deny plus an explicit per-member
   allowlist**. The property that failed here was that a method could be added
   without an auth check and be instantly reachable.

**Tests.** `test_dbus_authorization.py` — asserts every privileged method
carries both `sender_keyword` and `_require_auth`, that no exported method
escapes classification, that the policy denies before it allows and never
opens a whole destination, and behaviourally that an unauthorized `Verify`
refuses **without `run_verify` ever being called** while an authorized one
still runs and records.

Against the shipped code: **6 failures, 3 errors.**

---

## W-21 — Unauthenticated `Analyze` was unbounded — **COMPLETE**

**Finding.** `Analyze()` is unauthenticated on purpose (the tray badge needs
the update count without a password) but spawned a new thread running
`build_analysis()`, which opens the apt cache, on **every call**. Any local
process could start an unbounded number of cache-opening threads in a root
daemon.

**Fix.** Authorization would put a password prompt behind the badge, so the
work is bounded instead: a result younger than `ANALYZE_CACHE_SECONDS` (30) is
served from cache, and callers arriving while a run is in flight coalesce onto
it. Worst case is one analysis per 30s regardless of caller count.

**Test.** Eight concurrent callers start exactly one `build_analysis`; five
repeat callers after a completed run start zero.

---

## W-07 — R2 prune could delete every published release — **COMPLETE**

**Finding.** `r2_prune_release.py` computed its delete set as "everything under
`releases/` that is not the version I was given", interpolating `--version`
into a keep prefix with **no validation**. A malformed version made that
prefix match nothing, so every ISO, signature and checksum was classified
obsolete.

Reproduced against a stubbed client — `--version 4.0.O` (letter O):

```
OBJECTS ACTUALLY DELETED: 7
   destroyed -> releases/shadowfetch-4.0.0-amd64.iso        <-- the LIVE release
   destroyed -> releases/shadowfetch-4.0.0-amd64.iso.asc
   destroyed -> releases/shadowfetch-4.0.0-amd64.iso.sha256
   ...
```

`--version ''` and `--version 4.0` behave identically.

**Fix — four guards, all of which only abort.**
1. `--version` must match `^\d+\.\d+\.\d+$`, checked before the S3 client is
   built, so a bad value never reaches R2.
2. **Nothing is classified obsolete unless the ISO being kept is actually
   present in the listing.** This is the property that matters: an unmatched
   keep prefix now aborts instead of meaning "delete everything".
3. `--max-deletes` (default 200) bounds a runaway match.
4. The kept release's `.sha256/.asc/.sig/.torrent` sidecars are intersected
   with the delete set as a standing assertion.

**Invariant preserved.** The keep rule itself is unchanged; `--version 4.0.0
--apply` still removes exactly the four genuinely obsolete 2.1.1 objects.

**Tests.** 13 tests, entirely against a fake S3 client. **No network call and
no real delete was issued at any point.** The suite pins the old logic verbatim
as `legacy_obsolete_release_objects()` and asserts it destroys everything for
six malformed versions.

---

## W-08 — Two privileged helpers called with argv they reject — **COMPLETE**

Both defects fail **after** the user has typed their administrator password.

**8a.** `shadowfetch-bundle-install` dispatches on a verb
(`verb, rest = args[0], args[1:]`, then `if verb == "install"`).
`software_page.py:113` passed the catalog id as `args[0]`, which matches no
verb, so the helper printed usage and exited 2. **Every "Install" button on
the Bundles tab was dead.** `workbench_page.py:202` calls the same helper
correctly with the verb — the two call sites disagreed and nothing checked.

**8b.** `ember-duration` takes seconds as a bare positional integer; its
argument loop dies on `*[!0-9]*`, so the `--duration` flag `ember_page.py`
sent was rejected as an unrecognised argument. **Every timed Ember profile
failed.**

That failure was invisible because `_helper_done` reported *any* non-zero exit
as "Authorisation was cancelled". 126 (polkit refused / dismissed), 127
(helper not executable) and a helper's own failure are now distinguished, in
both the Ember page and the shared `ProcessDialog`.

**Tests.** `test_privileged_invocation.py` pins each caller's argv against the
helper's real parser, so the two bundle-install call sites can no longer drift.

---

## W-09 — Privileged buttons ran through a login shell — **COMPLETE**

**Finding.** `terminal_command` ran every text-mode tool as `bash -lc`. A login
shell sources `/etc/profile` then the first of `~/.bash_profile`,
`~/.bash_login`, `~/.profile` — all writable by the unprivileged user. The
tools launched this way (`shadowfetch-gpu`, `shadowfetch-recovery`,
`shadowfetch-update`, `shadowfetch-health`, `shadowfetch-agent-workspace`,
`fireproof update`) are invoked by **bare name through PATH**, and each goes
on to ask for an administrator password.

The attack needs no privilege: write `~/.profile`, wait for the user to click
a button in a trusted system application, and the password prompt they answer
belongs to code of your choosing.

**Fix.** Non-login, non-interactive `sh -c`; fixed system PATH; `BASH_ENV`,
`ENV`, `SHELLOPTS`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, `PYTHONPATH` and
`PYTHONSTARTUP` removed. Tool and terminal emulator both resolved against the
trusted PATH.

`mission_client` took its command from `SHADOWFETCH_MISSIONS_COMMAND` /
`SHADOWFETCH_GROK_BOT_COMMAND`, letting anything able to set a variable in the
session choose the binary the Control Center executes. Nothing read those
variables, including the tests. They are gone.

**Tests.** `terminal_command` is driven with a stubbed `Popen`: no login shell,
fixed PATH, hooks stripped, and the environment cannot select the mission
binary. Against the shipped code the W-08/W-09 suite gives **7 failures, 3
errors**.

---

## W-12 — Containment suite never ran — **COMPLETE**

**Finding.** `test_firebreak.sh` is the only test that proves Firebreak
actually contains anything — outside-workspace files unreadable, environment
scrubbed, network namespace isolated, undo restores. `make test` ran the three
Python Fireline tests and **never ran it**, so the security property the
package exists to provide was unverified on every build.

**Fix.** Wired into `make test` with the in-tree binaries (no installed package
needed). Added three assertions with no prior coverage: a whole-home `--read`
grant, a filesystem-root `--read` grant, and a traversing `--workspace` name
must each be refused.

**Result.** 19 assertions, all passing.

---

## W-01 — Published APT index expires; refresh required a rebuild — **COMPLETE (tooling); PUBLISH PENDING OWNER DECISION**

**Finding.** The repository was published with `ValidFor: 14d`, so the Release
shipped with 4.0.0 on 2026-09-06 carries `Valid-Until: 2026-09-20`. apt refuses
a repository whose Release has expired. **Every installed machine loses
`apt update` on 20 September 2026** — 12 days out when this was found.

A fortnight is only safe for a repository something republishes on a schedule.
Nothing republishes this one, and there was no way to refresh the metadata
short of `make repo`, which rebuilds every package and re-signs every source
tarball.

**Fix.**
- `REPO_VALID_FOR` 14d → **180d**, with the trade-off documented in place.
- **`make refresh-index`** re-exports and re-signs the indices over the
  existing pool — no package rebuild, no ISO — and asserts the package list is
  identical across the export, so a "metadata refresh" can never quietly alter
  what the repository offers.
- **`make check-index`** fails when the index is expired or expiring, standing
  alone so it can run as a monitoring check.

**Exercised on the build host:**

```
BEFORE:  >>> umbra Valid-Until Sun, 20 Sep 2026 20:04:56 UTC (12.4 days remaining)
AFTER:   >>> umbra Valid-Until Sun, 07 Mar 2027 09:57:47 UTC (180.0 days remaining)
gpg: Good signature from "Shadowfetch Project <signing@shadowfetch.com>"
     using EDDSA key 8F13CE1535EE1F4A2916A1F73C5C900B7BE80CA1
34 index entries identical before and after; 6/6 SHA256 entries match.
```

**⚠ Not done, deliberately.** This commit republishes nothing. The **live**
index still expires 2026-09-20. Making the fix effective means publishing the
refreshed `dists/`, which is an outward-facing release action and the owner's
decision. See `PHASE1_REMAINING_RISKS.md`.

---

## W-15 / W-16 / W-17 — Missions subsystem — **COMPLETE**

**W-15.** `Store.list` carried a hard-coded `LIMIT 1000`. Past a thousand
records the queue silently showed an incomplete picture, and five internal
correctness scans — recovery, the waiting-review check, `review()`, and the
worker's stop and queue scans — silently stopped seeing rows. `list()` is now
complete by default; `Store.page()` serves bounded pages with an explicit
`truncated`/`next_offset` signal; the hot worker scans were narrowed by state.
The CLI gained `--limit`/`--offset` while stdout stays a plain JSON array,
which is what the Qt client and the QA harness parse.

`review()` also used a bare `next(...)` to find a mission's queue position.
Once a reviewed mission fell past the window that raised `StopIteration`, which
escaped `main()`'s `except (MissionError, ValueError, OSError)` and gave the
user a traceback instead of the `{"error": ...}` contract the UI parses. Fixed
at the call site and with a narrowed CLI backstop.

**W-16.** `verify_validation_guard` only compared files that already existed,
and recomputed its baseline from the live workspace on **every attempt**. So an
agent could add a brand-new trivially-passing test, or simply fail once and
have its own tampered test adopted as the baseline for the retry. The baseline
is now recorded once at the first attempt and reused, and newly added
test/validation files are refused. `pyproject.toml`/`setup.cfg` deliberately
excluded — they have legitimate non-test edits.

**W-17.** The change summary interpolated raw file names into diff headers and
marker lines, so a crafted name could **forge a `+++` header and fabricate
structure in the record a human reviews**. Paths are escaped, rows are typed,
truncation cuts on a line boundary and states what was omitted.

**Proof against the shipped module** (each scenario re-run on the pristine
HEAD code):

```
[OLD] rows in table = 1001; Store.list() returned 1000; complete = False
[OLD] review(undo) raised: StopIteration
[OLD] agent added conftest.py + test_added.py -> state=waiting-review
[OLD] attempt 2 with the weakened test still on disk -> state=waiting-review
[OLD] '+++ ' header lines in output = 2 (1 is correct); forged header present = True
[OLD] announces truncation = False; cut mid-diff with no trailer
```

**58 tests pass** (47 pre-existing + 11 new).

---

## Adversarial second pass — privilege surface

An independent sweep of the **whole** tree, not only what Phase 1 touched.

**Q: Can an unprivileged user turn any remaining polkit action into arbitrary
execution?  → No.** Six actions ship. After W-04, two remain passwordless
(`allow_active=yes`) and both were audited:

| Action | Verdict |
|---|---|
| `com.shadowfetch.ember.duration` | Safe. `profile` constrained to `[a-z0-9-]` **and** must resolve to a root-owned `$PROFILES_DIR/$profile.conf`; `duration` numeric, range-checked 60–86400, written only as `RuntimeMaxSec=`. No path traversal, no interpolation of caller data into a command. |
| `org.shadowfetch.ignition-state` | Safe by construction. `exec`s `shadowfetch-bundle-install --state-entry "$@"`, and the implementation refuses the `install` verb through that path regardless of what the caller asks. |

The other four are `auth_admin_keep`.

**Q: Can a local process invoke a root D-Bus mutation without authorization?
→ Not on Fireproof, after W-06.** Cross-checking every exported method against
its bus policy: `emberd` exposes only `GetStatus` and read-only properties
(`Set` raises `PropertyReadOnly`); `firewatchd` exposes only `Get*`/`Subscribe`
readers. Neither mutates. **Residual:** both still open their whole interface
to any sender rather than an allowlist — see remaining risks.

**Q: Can an agent reach files outside its intended scope through the MCP
server? → No, after W-05.** Scope is mandatory, denylisted, and the resolve
check rejects relative traversal, absolute paths and symlink escapes.

**Q: Can PATH/environment manipulation replace a trusted executable?
→ Not in the Control Center, after W-09.** The sweep found two further
env-selected executables outside that surface — see remaining risks.

**Q: Can a malformed prune command delete the wrong release? → No, after
W-07.** Four independent guards, each of which aborts.

---

## W-03 — A gate that cannot scan must fail, not skip — **COMPLETE**

**Finding.** `source_gate`'s `candidate_files()` ran `git ls-files` with
`check=True`. In this tree, whose git was broken (W-02), that raised a bare
`CalledProcessError` — and the gitleaks **history** scan simply did not run.
**That is how 4.0.0 shipped having never been secret-scanned against its
history.**

`pre_release_check.sh` was worse. It wrapped its check in
`if command -v git && git rev-parse ...`, so an unusable git **skipped** the
tracked-credential-state check and the script still printed
`PRE_RELEASE_CHECK_PASSED`, having verified nothing.

**Fix.**
- `candidate_files()` probes git first and raises a named
  `GitHistoryUnavailable` that says history cannot be scanned and what to do,
  instead of an opaque exit-128 traceback.
- `--no-git` is an explicit fallback that still runs `gitleaks dir` over the
  working tree, so **a secret scan always happens**, and prints
  `SOURCE_GATE_PASSED_WITHOUT_GIT_HISTORY` — an operator cannot mistake it for
  a full run.
- `pre_release_check.sh` records three distinct `add_failure` cases (git
  absent, not a work tree, `ls-files` failed) instead of skipping.

**Invariant.** With a healthy git the candidate list is byte-identical:
HEAD's implementation and the new one were loaded side by side against the real
repository — **696 files each, IDENTICAL: True**. A full run now reports
`SOURCE_GATE_PASSED` including `PASS: Gitleaks Git history`, the scan that had
been silently absent.

**Note for whoever maintains `.gitleaks.toml`:** its allowlists are
path-pinned, so the fallback walk had to prune `packages/*/debian/<binary>/`
staging roots — an allowlisted file copied to a second path is flagged again.

---

## W-14 — The acceptance gate could not fail — **COMPLETE**

**Finding.** `make acceptance-audit` runs the verifier with `--allow-pending`
hard-coded. On the real 4.0.0 manifest that prints `ACCEPTANCE_PASSED` and
exits **0** while listing twelve pending required cases. **That is how a
release with no evidence for thirteen of eighteen required cases reported
success: the only gate anyone ran was the one that could not fail for the
reason that mattered.**

**Fix.**
- `acceptance-gate` refuses unless every required case is `pass` or `waived`
  and every artifact field is recorded.
- `acceptance-audit` remains the soft reporting path and now prints a
  `REPORT:` line per pending case instead of burying them.
- `waived` is a real status requiring an approver and a written reason, so
  "we consciously accepted this gap" stops being indistinguishable from
  "nobody ran it".
- Evidence is checked for substance: zero-byte files, files under 8 bytes
  (1024 for a screenshot) and files whose Shannon entropy is under 1.5
  bits/byte are rejected at both record and verify.

**Thresholds are calibrated against real artifacts, not guessed.** The shipped
`candidate12-ice/identity.txt` is 12 bytes at 2.92 bits/byte and passes; a
solid-black 1280×720 PNG is 2759 bytes at 0.26 bits/byte and is rejected.

**Measured on the real manifest:**

```
make acceptance-audit  -> ACCEPTANCE_PASSED  exit 0   required=17 passed=5 pending=12
make acceptance-gate   -> ACCEPTANCE_FAILED  errors=13, tool exit 1
```

`qa/4.0.0/acceptance.json` is deliberately **not** modified — see W-13.

---

## W-13 — Regenerate 4.0.0 acceptance evidence — **BLOCKED (cannot be done honestly)**

W-13 asked for the 4.0.0 evidence to be regenerated and the release finished
through the credentialled path. A forensic pass over the evidence tree shows
that is not a recording exercise.

**The evidence does not exist for the shipped artifact.** The tree holds 3,977
files; only **16** postdate the shipped ISO's build, and all 16 are already
bound to the five cases that pass. Everything else describes an earlier build
candidate.

| Case | Reality |
|---|---|
| SRC-01, PKG-01 | The last gates ran at commit `c551dfcd`. The published artifact is `e1293bfa`. **The shipped source was never source-gated or package-gated.** |
| RESOURCE-01, STRESS-01 | Their own notes document runs that **FAILED** — bridge 503s, a 120s container timeout, a 2704s stress run failing on Redis admission. Recording them as `pending` misrepresents a failure as an absence. |
| UPGRADE-01, RECOVERY-01, DURABLE-01, SCOPE-01, GROK-01, GROK-VISUAL-01 | Evidence only for candidates 6–8, a different binary. DURABLE-01's nearest artifact is a 9-second developer smoke against a 60-second requirement. |
| VISUAL-01 | The candidate12 screenshots are 1024×768, below the recorder's own 1280×720 floor. Not recordable even if accepted. |
| EVIDENCE-01 | No SBOM. `evidence_bundle_path` names a file that does not exist. |
| PUB-01 | No publish log, GitHub, R2 or site artifact anywhere. |

**Nothing was recorded.** Mapping candidate6 evidence onto cases about
candidate12 would convert an honest gap into a false attestation about a
published operating system — the one outcome worse than the current state.

**What W-13 delivered instead:** the exact inventory above, and (via W-14) a
gate that now refuses this manifest. The remaining decision is the owner's and
is written up in `PHASE1_REMAINING_RISKS.md`.

---

## W-19 — APT repository was trusted, not authenticated — **COMPLETE**

**Finding.** `shadowfetch.list.chroot` carried `[trusted=yes]`, which tells apt
to accept the repository **without verifying its signature**;
`shadowfetch.list.binary` named no keyring at all. Every package the
distribution installs — at build time and on the installed system — was taken
on the transport's word. The project signs its repository with a key it
already ships; nothing was checking it.

**Fix.** Both entries carry
`signed-by=/usr/share/keyrings/shadowfetch.gpg`, matching the path
`package_gate_4_0_0.py:493` already expects. The late chroot hook writes the
same form into the shipped image, plus a `test -s` so the build fails rather
than shipping an entry it cannot satisfy.

**The ordering problem, and why it is solved this way.** The keyring must exist
before live-build's own `apt-get update`, which runs inside
`lb_chroot_archives` — earlier than hooks, `includes.chroot`, or any package
install. `config/archives/*.deb` is the one slot that lands in the chroot ahead
of that update, and the package it installs also carries the key into the
squashfs, so build time and installed system resolve the same path from one
source of truth.

**Verified against the live repository, not assumed:**

```
key shipped in the package: 8F13CE1535EE1F4A2916A1F73C5C900B7BE80CA1
gpgv on the LIVE published InRelease, using ONLY that key:
    Good signature from "Shadowfetch Project <signing@shadowfetch.com>"   exit 0
real apt-get update against https://www.shadowfetch.com/linux/apt         exit 0

NEGATIVE CONTROL (Debian keyring substituted):
    E: The repository 'http://127.0.0.1:8189 umbra InRelease' is not signed.
                                                                          exit 100
```

The negative control is what proves verification is now actually enforced.

**Not done:** `make iso` was not run (multi-hour, and out of scope). The
component path is proven; the live-build-integrated path is not. See remaining
risks.

---

## W-20 — firewatchd caches and privilege — **COMPLETE**

**Findings and fixes.**
- Four caches — unit display names, desktop entries, unit descriptions and the
  pid/cgroup map — were plain dicts that only ever grew inside a long-running
  **root** daemon. A `BoundedCache` (OrderedDict LRU) caps them at
  512/512/512/8192, and the per-sweep prune keeps its exact semantics.
- `Manager.LoadUnit` is not a lookup: it makes PID 1 **load** the named unit.
  A read-only telemetry daemon was growing init's unit table as a side effect
  of observing it. Replaced with the non-mutating `Manager.GetUnit`.
- `DeviceAllow=block-* rw` gave a daemon that only reads SMART data **write**
  access to every block device. Now `r`.

**Invariant proven by output comparison:** `--once` from the pre-fix daemon and
the patched one produce **65 JSON leaf keys each, nothing only-in-old, nothing
only-in-new — shape identical.**

**The device rule was verified empirically**, with transient `systemd-run`
units:

```
### DeviceAllow=block-* r ###   O_RDONLY: OK      O_RDWR: DENIED errno=1
### DeviceAllow=block-* rw ###  O_RDONLY: OK      O_RDWR: OK
### closed, no block rule ###   O_RDONLY: DENIED  O_RDWR: DENIED
```

---

## Note on process: one contamination caught and corrected

Work ran in parallel across disjoint file groups. One commit
(`787d130`, phoenix test suite) swept in another stream's in-flight Makefile
edits under an unrelated message. It was caught in the final per-commit diff
review, the history was corrected before anything was pushed, and the Makefile
was verified byte-identical across the correction
(`601e681dccbb654aec67c8f86297d0ab06df1713f4e065f6545c2dc0f6f78e18` before and
after). Every Phase 1 commit was then re-audited file by file; all are cleanly
scoped.

A second process defect was caught the same way: the phoenix "would-have-caught"
tests read the pre-fix script with `git show HEAD:`, which was true while the
fix was uncommitted and false the moment it landed — `make test` failed. They
are now pinned to `v4.0.0` with a guard that raises if that revision ever
resolves to the current script, because a regression proof that compares the
fix against itself passes while proving nothing.

---

# Final status — W-01 through W-21

| ID | Severity | Status | What changed |
|---|---|---|---|
| W-01 | P0 | **COMPLETE** (publish pending owner) | `REPO_VALID_FOR` 14d→180d; `make refresh-index`, `make check-index`. Live index still expires 2026-09-20. |
| W-02 | P0 | **COMPLETE** | Git restored; working tree proven byte-identical to `v4.0.0`. |
| W-03 | P0 | **COMPLETE** | Gates raise a named error and record failures instead of skipping; `--no-git` still secret-scans. |
| W-04 | P0 | **COMPLETE** | Passwordless-root polkit action deleted. |
| W-05 | P0 | **COMPLETE** | `fs` MCP server fails closed; scope denylisted; config emits the scope. |
| W-06 | P0 | **COMPLETE** | `Verify` polkit-gated; read-only `Inspect()`; bus policy default-deny + allowlist. |
| W-07 | P0 | **COMPLETE** | Four guards; a typo can no longer delete every published release. |
| W-08 | P0 | **COMPLETE** | Both broken pkexec argv fixed; 126/127 distinguished. |
| W-09 | P0 | **COMPLETE** | Non-login shell, fixed PATH, hooks stripped; two env-selected executables removed (one found in the adversarial pass). |
| W-10 | P0 | **COMPLETE** | Duplicate snapper initialiser deleted; ordering fixed; `phoenix-check-layout` added. |
| W-11 | P0 | **COMPLETE** | Trap covers `/boot` rollback with an `EXCHANGED` guard; intent journal; `--dry-run`. |
| W-12 | P0 | **COMPLETE** | Containment suite wired into `make test`; three assertions added. |
| W-13 | P0 | **BLOCKED — evidence does not exist** | Nothing recorded, deliberately. Inventory produced; decision is the owner's. |
| W-14 | P0 | **COMPLETE** | `acceptance-gate` split from `acceptance-audit`; `waived` status; junk-evidence rejection. |
| W-15 | P1 | **COMPLETE** | Truncation made explicit; `StopIteration` guarded at call site and CLI. |
| W-16 | P1 | **COMPLETE** | New test/config files guarded; baseline recorded once, not per attempt. |
| W-17 | P1 | **COMPLETE** | Typed change rows; paths escaped; truncation trailer. |
| W-18 | P1 | **COMPLETE** | Report confined to a basename, 0600, serials and dmesg redacted. |
| W-19 | P1 | **COMPLETE** (needs one ISO build) | `[trusted=yes]` → `signed-by=`; keyring package staged ahead of live-build's apt. |
| W-20 | P1 | **COMPLETE** | Caches bounded (LRU); `LoadUnit`→`GetUnit`; `DeviceAllow=block-* r`. |
| W-21 | P1 | **COMPLETE** | `Analyze` cached and coalesced; one run per 30s regardless of callers. |

**20 of 21 complete. 1 blocked on absent evidence, not on engineering.**

## Remaining P0 / P1

| | Count | Detail |
|---|---|---|
| P0 remaining | **1** | W-13 — 4.0.0's acceptance evidence does not exist for the shipped artifact. Not fixable by code. |
| P1 remaining | **0** | |

## Tests

`make test` exits **0**. 447 automated tests plus two shell suites:

```
missions 58 · control-center 43 · defaults 98 · firewatchd 26 · fireproof 36
hwscan 49 · phoenix 26 · fireline 11+12+20 · tools 140 · worker 13
containment (test_firebreak.sh) 19 assertions
```

**Net new in Phase 1: ~150 tests, and a package (phoenix) that had no suite at
all now has 26 covering the recovery path.** No test was weakened, skipped or
deleted to obtain a pass.

## Release blockers

1. **The live APT index expires 2026-09-20.** Tooling is fixed and proven;
   publishing the refreshed `dists/` is an owner decision. **12 days.**
2. **4.0.0 has no acceptance evidence for 13 of 18 required cases**, and its
   shipped source was never source- or package-gated. The new
   `make acceptance-gate` refuses the manifest as it stands.
3. **`SHA256SUMS` has no 4.0.0 entry** and its signature predates the ISO.
   (The ISO's own detached `.asc` is valid, so per-ISO verification works.)
4. **W-19 needs one `make iso`** to prove the keyring lands before live-build's
   first `apt-get update`. Component path verified; integrated path not run.

## Recommended next action

**Publish the refreshed APT index.** It is the only item with a deadline, it
touches no package and no ISO, and `make refresh-index` has been exercised
end-to-end.

Then decide W-13: re-run the QA battery against the shipped artifact, or waive
the cases with a named approver and written reasons. Either is legitimate;
leaving them as `pending` is not, because two of them are recorded failures.

**Phase 2 can begin.** The defects that would have been built upon are closed:
no passwordless root path, no unauthenticated root D-Bus mutation, no
unscoped agent filesystem access, no PATH- or environment-selected privileged
executable, a prune that cannot destroy the release history, a recovery path
that rolls back what it changed, and gates that fail closed. One structural
warning for Phase 2's first commit: `tools/mission_provider_contract.py` pins
the provider set to `{codex, offline}` and is enforced by three separate gates,
so the AgentProvider abstraction must move the contract and all three call
sites together.
