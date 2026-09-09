# Privileged operations

Stage V of the 4.0.0 final engineering programme: a complete inventory of every
way code in this tree gains, keeps or attests root, and the authorization and
input grammar attached to each one.

Everything below was read out of the current sources on `release/4.0.0`, not
from earlier documents. Build copies under `packages/*/debian/<pkgname>/` and
the `live-build/chroot` tree are stale duplicates and are excluded.

Contract tests added by this stage — 53 in total:

* `tools/tests/test_privileged_operations.py` (26) — tree-wide invariants plus
  the adversarial suite for the passwordless `ember-duration` helper;
* `packages/shadowfetch-phoenix/tests/test_phoenix_apt_snapshot.py` (14);
* `packages/shadowfetch-defaults/tests/test_gpu_privileged_reexec.py` (13).

---

## 1. The invariant this document defends

> Every privileged operation has a narrowly scoped authorization mechanism and
> a validated input grammar.

with the permanent sub-invariant established earlier in the programme:

> Any executable used to establish, verify, enforce or attest a security fact
> MUST be invoked through an explicit trusted ABSOLUTE path and must have a
> defined trust classification. No `shutil.which()`, no PATH lookup, anywhere
> its output decides a security question.

Two failure modes follow from the first sentence and are hunted specifically:

* **Unscoped authorization.** `pkexec /bin/sh -c …` authorises
  `org.freedesktop.policykit.exec` on a shell. The grant is "a shell, as root",
  the dialog names the shell, and nothing in the authorization constrains what
  the shell does. That the argv happened to be a constant is a property of the
  *caller's source file*, not of the grant.
* **Unvalidated grammar.** A helper that accepts free-form argument text is a
  root-write primitive with extra steps, whatever its polkit action says.

### Vocabulary

These are kept distinct throughout and never collapsed:

| Term | Means |
|---|---|
| REQUESTED | a caller asked for the operation |
| VALIDATED | the argument grammar accepted the input |
| APPROVED | polkit returned yes for a specific action and subject |
| NARROWED | the action is pinned to one executable (`exec.path`) |
| PASSED | a check inside the helper succeeded |
| ENFORCED | the enforcement layer prevents the prohibited behaviour **and** an adversarial test proves it |
| OBSERVED | the behaviour was seen once, on one host |
| AUDITED | a durable record exists that a third party can re-check |

---

## 2. polkit actions

Seven actions ship. `exec.path` is the polkit annotation that pins an action to
exactly one program; without it, pkexec will authorise that action for whatever
program the caller names.

| Action | Policy file | allow_active | Pinned to | Grammar | Tested |
|---|---|---|---|---|---|
| `org.shadowfetch.phoenix.restore` | shadowfetch-phoenix | `auth_admin_keep` | `/usr/libexec/phoenix-restore` | one positive integer, or none inside an overlay session; `--dry-run`, `--help`, `--version` | yes — `test_phoenix_restore.py` |
| `org.shadowfetch.phoenix.recovery-report` | shadowfetch-phoenix | `auth_admin_keep` | `/usr/libexec/phoenix-recovery-report` | optional file **name** (basename only, no `.`/`..`/leading `-`) | yes — `test_phoenix_recovery_report.py` |
| `org.shadowfetch.phoenix.apt-snapshot` **(new, Stage V)** | shadowfetch-phoenix | `auth_admin_keep` | `/usr/libexec/phoenix-apt-snapshot` | exactly one word from `{enable, disable, status}` | yes — `test_phoenix_apt_snapshot.py` |
| `com.shadowfetch.ember.duration` | shadowfetch-ember | **`yes` (no password)** | `/usr/libexec/ember-duration` | `[--profile <id|off>] [<seconds>|off]`; id is `[a-z0-9-]+` **and** must resolve to a root-owned `.conf` in `/usr/share/shadowfetch/ember/profiles/`; seconds is digits, 60..86400 | yes — `EmberDurationTests` (added by Stage V; nothing covered it before) |
| `org.shadowfetch.bundle-install` | shadowfetch-welcome | `auth_admin_keep` | `/usr/libexec/shadowfetch-bundle-install` | `install <catalog-id>`; id matched against `ID_RE`, resolved only to a root-owned, non-group/other-writable `.json` in `/usr/share/shadowfetch/welcome/catalog/`, whose `id` field must equal the argument and whose package names must all match `PKG_RE` | yes — `test_catalog_actions.py`, `test_privileged_invocation.py` |
| `org.shadowfetch.ignition-state` | shadowfetch-welcome | **`yes` (no password)** | `/usr/libexec/shadowfetch-ignition-state` | `save-choice <catalog-id>` or `mark-done`; the shim prepends `--state-entry`, which makes the shared implementation refuse `install` through this path whatever the caller asks for | yes — `test_catalog_actions.py` |
| `org.shadowfetch.fireproof.update` | shadowfetch-fireproof | `auth_admin_keep` | *(not a pkexec action — checked inside fireproofd against the D-Bus sender)* | see §5 | yes — fireproof suite |

One polkit **rule** ships:
`packages/shadowfetch-ember/usr/share/polkit-1/rules.d/50-shadowfetch-ember.rules`
allows `org.freedesktop.systemd1.manage-units` without a password for exactly
one unit (`shadowfetch-ember.service`), exactly three verbs (start/stop/restart),
and only for `subject.local && subject.active`. Everything else falls through to
the distribution default. This is correctly scoped: it names the unit rather
than accepting any unit, which is the usual defect in this file shape.

### Why the two passwordless actions are acceptable

Both are ENFORCED-narrow rather than trusted-broad:

* `com.shadowfetch.ember.duration` — everything it writes is on tmpfs
  (`/run/shadowfetch/ember-profile`, a `RuntimeMaxSec` runtime drop-in),
  is undone by `ember-restore` on every stop path, and cannot outlive a reboot.
  Its argv grammar is a closed set and profile ids resolve only against
  root-owned definition files. Adversarial coverage added in Stage V.
* `org.shadowfetch.ignition-state` — writes two ~200-byte state files and
  cannot reach the installer verb.

The risk in both cases is not the authorization; it is the grammar. That is why
the grammar, not the policy, is where the tests are.

---

## 3. pkexec call sites

Fourteen call sites. "Program absolute" is about the *escalator* itself; the
target program is an absolute path or a module constant at every site.

| # | Caller | Line | Target | Escalator absolute? |
|---|---|---|---|---|
| 1 | `sfcc/phoenix_page.py` | 294 | `PHOENIX_RESTORE` | yes (fixed in Stage V) |
| 2 | `sfcc/phoenix_page.py` | 351 | `PHOENIX_APT_REPAIR` | yes (fixed in Stage V) |
| 3 | `sfcc/busutil.py` | 520 | `PHOENIX_APT_SNAPSHOT` | yes (rewritten in Stage V) |
| 4 | `sfcc/ember_page.py` | 362 | probed ember helper | **no** — open finding O-2 |
| 5 | `sfcc/workbench_page.py` | 202 | `BUNDLE_INSTALL` | **no** — open finding O-2 |
| 6 | `sfcc/software_page.py` | 113 | `BUNDLE_INSTALL` | **no** — open finding O-2 |
| 7 | `shadowfetch-workbench` | 328 | fixed helper path | **no** — open finding O-2 |
| 8 | `shadowfetch-grok-bot` | 268 | `/usr/bin/shadowfetch-grok-bot _install` | yes |
| 9 | `shadowfetch-gpu` | `as_root()` | itself, `--apply` | yes (fixed in Stage V) |
| 10 | `fireproof` (CLI) | 252 | `/usr/libexec/phoenix-restore` | **no** — open finding O-2 |
| 11 | `shadowfetch-fireproof` (QML) | 597 | phoenix-restore | **no** — open finding O-2 |
| 12 | `shadowfetch-welcome` | 962 | `BUNDLE_HELPER install <id>` | **no** — open finding O-2 |
| 13 | `shadowfetch-welcome` | 1201 | `PHOENIX_RESTORE <n>` | **no** — open finding O-2 |
| 14 | `shadowfetch-welcome` | 1629 | `STATE_HELPER <verb>` | **no** — open finding O-2 |

`shadowfetch-grok-bot` is the model to copy: absolute escalator, absolute
helper, and `trusted_regular()` checks the helper is a root-owned regular file
that is not group/other-writable *before* handing it to the escalator.

---

## 4. Root helpers (`/usr/libexec`)

| Helper | Reached by | Argv grammar | Environment | Filesystem inputs |
|---|---|---|---|---|
| `phoenix-restore` | pkexec (pinned) | integer snapshot id, validated `*[!0-9]*` → refuse; `--dry-run`, `--help`, `--version` | sources `/run/phoenix-overlay` (root-owned tmpfs) for a preselected id, which is then put through the same integer validation | the Btrfs volume; `/boot` is a compile-time constant, never taken from the environment |
| `phoenix-recovery-report` | pkexec (pinned) | optional report **name**; `${1##*/}` strips any directory part, and `''`/`.`/`..`/`-*` are refused; refuses to write through a symlink | reads `PKEXEC_UID` only, digit-validated, only to `chown` the finished bundle | writes 0600 inside a 0700 `/var/lib/shadowfetch/recovery-reports/` |
| `phoenix-apt-snapshot` **(new)** | pkexec (pinned) | exactly one word from a closed set | none | `/etc/default/snapper` only; refuses a symlink, a missing file, or a non-root-owned target; atomic `mktemp`+rename |
| `phoenix-apt-repair` | pkexec (unpinned action) | `--check` \| `--repair` | none | compares/restores from root-owned known-good copies under `/usr/share/shadowfetch/apt-recovery/` |
| `ember-duration` | pkexec (pinned, **passwordless**) | see §2 | none | writes only `/run/shadowfetch/ember-profile` and a `RuntimeMaxSec` drop-in under `/run/systemd/system/` |
| `ember-restore` | systemd `ExecStartPre`/`ExecStopPost` | `--help`/`--version` only | reads `SERVICE_RESULT`, which only systemd sets, and only to distinguish the stop path | replays `/run/shadowfetch/ember.state` (root-owned tmpfs) through a three-kind grammar; cpu ids matched `cpu[0-9]{1,3}`, unit names refuse `/` and `..` and must end `.service`; unknown kinds ignored |
| `shadowfetch-bundle-install` | pkexec (pinned) | three verbs; `--state-entry` restricts to two of them | none | catalog record must be root-owned, not group/other-writable, self-consistent, and every package name must match `PKG_RE` |
| `shadowfetch-ignition-state` | pkexec (pinned, **passwordless**) | thin shim: `exec /usr/libexec/shadowfetch-bundle-install --state-entry "$@"` (absolute) | none | delegates |
| `fireproofd` | systemd + D-Bus activation | n/a (daemon) | see §5 | see §5 |
| `firewatchd` | systemd | n/a (daemon) | see §6 | see §6 |
| `shadowfetch-hwscan` | systemd oneshot, and unprivileged CLI | argparse; `--write-state` takes an optional path that only root can use | none | writes `/var/lib/shadowfetch/hwscan.json` |
| `fireproof-postboot`, `fireproof-session-check`, `phoenix-firstboot`, `phoenix-postboot`, `phoenix-check-layout`, `phoenix-space-check`, `phoenix-desktop-reset`, `phoenix-overlay-banner`, `shadowfetch-migrate-2.1.3-ai`, `shadowfetch-retire-buzz` | systemd / apt hooks only — no polkit action names them and no shipped caller pkexecs them | n/a | none | own state only |

---

## 5. Root D-Bus: `org.shadowfetch.Fireproof1`

Owned by `/usr/libexec/fireproofd`, `User=root`, activated by
`fireproofd.service`.

The bus policy (`org.shadowfetch.Fireproof1.conf`) is default-deny plus an
explicit member allowlist. That shape matters: it means a method added without
an auth check is unreachable until someone lists it deliberately. The comment in
the file records why — `Verify` previously ran `dpkg --audit` and an apt
dependency simulation as root for any caller.

| Member | Signature | Authorization |
|---|---|---|
| `GetState`, `RollbackTarget`, `Inspect` | `→s` | none needed — read recorded state, execute nothing |
| `Analyze` | `→s` | unauthenticated by design (tray badge), bounded by a result cache and caller coalescing |
| `Verify` | `→s` | polkit `org.shadowfetch.fireproof.update` against the D-Bus sender |
| `Update` | `s→s` | same; the string is an expected content hash, carried into the commit worker as `str()` and compared — never interpolated into a command |
| `CancelDownload`, `ProceedCommit`, `AbortCommit` | `→` | same — an unprivileged local user must not be able to answer the NEWS gate or abort an administrator's update |
| `RecordRollback` | `s→b` | same; the argument only has to equal the recorded `last_txn`, otherwise it returns false |
| `org.freedesktop.DBus.Properties` | | `Set` always raises |

`_authorized()` builds a `system-bus-name` subject from the sender's unique
name, which is the correct subject type here: it cannot be spoofed by a client
and does not race a pid the way `unix-process` does.

---

## 6. Other root services

* **`shadowfetch-firewatchd.service`** — root, read-only telemetry. Bus policy
  lets any local user call it because there is nothing privileged to protect.
  The smartd warning path deliberately does **not** go over D-Bus: it is a unix
  socket in `/run/shadowfetch`, created 0600 and checked with `SO_PEERCRED`.
  Unit hardening: `ProtectSystem=strict`, `NoNewPrivileges=yes`,
  `RestrictAddressFamilies`, `SystemCallArchitectures=native`.
* **`com.shadowfetch.Ember1`** — read-only status only; `Properties.Set` always
  refuses. Arming and disarming never traverse this bus name; they are systemd
  unit verbs governed by the polkit rule in §2.
* **Root systemd units** — every `ExecStart`/`ExecStopPost` in the tree is an
  absolute path. Checked mechanically.
* **`sudo` call sites** — all in interactive terminal tools
  (`shadowfetch-update`, `shadowfetch-hardware`, `shadowfetch-recovery`,
  `shadowfetch-gpu`). Each has fixed argv; the one variable target,
  `$MIGRATION_HELPER`, is the constant `/usr/libexec/shadowfetch-migrate-2.1.3-ai`,
  and `shadowfetch-hardware`'s package list comes from the hardcoded
  `FIRMWARE_MAP`, never from a file or the network. None is a passwordless path.

---

## 7. What Stage V changed

### F-1 — generic root shell in the Control Center (fixed)

`sfcc/busutil.py:apt_snapshot_toggle_argv()` probed two helper paths and, when
neither existed, returned an argv that ran the system shell as root with `-c`
and a sed script. **Neither probed name was ever shipped by any package in this
tree**, so on a real install the shell fallback was not a fallback: it was the
only path the "Point before every software change" switch ever took.

Two distinct defects:

1. The authorization was `org.freedesktop.policykit.exec` on a shell. The user
   was asked to approve running a program as another user, and the dialog named
   the shell, not the setting being changed. Nothing about the grant was scoped
   to this operation.
2. The operation had no name, no argument grammar and no test.

Fix:

* new root helper `packages/shadowfetch-phoenix/usr/libexec/phoenix-apt-snapshot`
  — one word of argv from a closed set, refuses a symlink or non-root-owned
  target, atomic rename, preserves every other line of the file byte for byte,
  and names `mktemp`/`chmod`/`mv` by absolute path;
* new polkit action `org.shadowfetch.phoenix.apt-snapshot`, pinned to that path,
  `auth_admin` / `auth_admin_keep` (this *is* a system mutation — unlike Ember,
  it survives a reboot, so it is not passwordless);
* added to `debian/shadowfetch-phoenix.install`, so it is actually shipped;
* `apt_snapshot_toggle_argv()` now returns `None` when the helper is absent, and
  `phoenix_page.py` reports that honestly instead of widening the grant. **A
  missing helper must never make the authorization broader.**

### F-2 — PATH-resolved root re-exec in `shadowfetch-gpu` (fixed)

`as_root "$0" --apply "$hybrid"` with

```
elif [[ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]] && command -v pkexec …; then
    pkexec "$@"
else
    sudo "$@"
```

`$0` is what the shell was told, not where the script is. Invoked through PATH,
`argv[0]` is the bare word `shadowfetch-gpu`, so the program handed to
pkexec/sudo was re-resolved through PATH **by the privileged runner** — and what
it re-enters is the driver installer. `command -v pkexec` picked the escalator
itself out of PATH, and nothing checked that the file about to run as root was
not writable by the caller.

Fix: `self_path()` resolves to an absolute path (pinning to
`/usr/bin/shadowfetch-gpu` for the bare-name case); `root_safe_program()`
refuses to re-enter unless the target is a root-owned file with no group/other
write bit, using `/usr/bin/stat`; `PKEXEC`, `SUDO` and `STAT` are absolute.

### F-3 — no coverage of the passwordless helper (fixed)

`ember-duration` is the one root helper an active local user runs with **no
password at all**, and nothing in the tree tested it — `shadowfetch-ember` has
no test directory and is not in the `test` target. `EmberDurationTests` in
`tools/tests/test_privileged_operations.py` now exercises it adversarially in a
path-rewritten sandbox: traversal, charset, unknown ids, out-of-range and
non-numeric durations, missing flag values, unknown flags, and the rule that
**a refused invocation writes nothing at all**.

The traversal and charset tests deliberately plant *reachable* definition files
outside and inside the profiles directory, so they prove the charset rule
rather than the file-existence check. Verified by mutation: loosening the
charset to `[a-zA-Z0-9._/-]` reds 15 tests; deleting the definition-existence
check reds 1.

---

## 8. Open findings

### O-1 — `org.shadowfetch.fireproof.update` has no `exec.path` (by design)

`org.shadowfetch.fireproof.update` carries no `exec.path` annotation. This is
**correct as it stands**: the action is never used as a pkexec action, only as a
`CheckAuthorization` subject inside fireproofd. Recorded so a future author does
not add a pkexec call site against it without adding the annotation. Not a
defect today; the contract test only requires `exec.path` on passwordless
actions and on actions that name a program.

### O-2 — `pkexec` resolved through PATH at nine call sites — **NOT FIXED**

Severity: moderate. **Not** a root escalation — a hostile `pkexec` earlier on
PATH runs as the user, not as root. What it buys an attacker who already has
same-user code execution is: swallow the privileged operation while returning
0, or present an imitation of the authentication dialog and capture the admin
password. It violates the letter of the permanent invariant, because whether
the operation was authorised at all is a security fact.

Exact change at each site — replace the program token `"pkexec"` with
`/usr/bin/pkexec` (in `sfcc/*`, with the existing `busutil.PKEXEC` constant):

| File | Line |
|---|---|
| `packages/shadowfetch-control-center/data/usr/share/shadowfetch/control-center/sfcc/ember_page.py` | 362 |
| `packages/shadowfetch-control-center/data/usr/share/shadowfetch/control-center/sfcc/workbench_page.py` | 202 |
| `packages/shadowfetch-control-center/data/usr/share/shadowfetch/control-center/sfcc/software_page.py` | 113 |
| `packages/shadowfetch-defaults/data/usr/bin/shadowfetch-workbench` | 328 |
| `packages/shadowfetch-fireproof/data/usr/bin/fireproof` | 252 |
| `packages/shadowfetch-fireproof/data/usr/bin/shadowfetch-fireproof` | 597 (`process.setProgram("pkexec")`) |
| `packages/shadowfetch-welcome/src/shadowfetch-welcome` | 962, 1201, 1629 |

**Why it is BLOCKED rather than done.** Four of these sites are pinned by
literal-string assertions in a release gate and three package test files, so
changing the source alone reds the gate. A correct fix is one coordinated
change across all of:

* `tools/iso_gate_4_0_0.py:817` — `'subprocess.run(["pkexec", str(helper), "install"'`
* `packages/shadowfetch-defaults/tests/test_workbench_3_5_0.py:158` — same literal
* `packages/shadowfetch-defaults/tests/test_workbench_privileged_helper.py:40` — `r'"pkexec"[^\]]*\]'`
* `packages/shadowfetch-control-center/tests/test_privileged_invocation.py:44,53`
* `packages/shadowfetch-welcome/tests/test_catalog_actions.py:130,132`

`tools/iso_gate_4_0_0.py` and the `shadowfetch-welcome` / `shadowfetch-fireproof`
sources are outside Stage V's file territory, and the lead runs that gate.

`PkexecResolutionTests` in `tools/tests/test_privileged_operations.py` records
these nine sites in `PKEXEC_ABSOLUTE_EXEMPT` with the reason for each. That list
is a ratchet, not a waiver: a **new** unpinned call site fails
`test_only_the_recorded_sites_resolve_pkexec_through_path`, and fixing a
recorded one fails `test_the_exemption_list_does_not_rot` until its entry is
deleted.

### O-3 — `busutil.find_ember_helper()` probes names nothing ships

`EMBER_HELPER_CANDIDATES` lists `/usr/libexec/shadowfetch-ember-helper` and
`/usr/libexec/ember-helper` ahead of the real `/usr/libexec/ember-duration`.
Only the last is annotated on the passwordless polkit action. `/usr/libexec` is
root-owned, so this is not exploitable; the consequence of a future package
shipping one of the first two names would be that the Ember switch silently
starts prompting for an admin password. Recorded, not changed —
`test_the_control_center_probe_can_reach_the_pinned_helper` fails if the pinned
name is ever dropped from the probe list.

### O-4 — `fireproofd` resolves three optional tools through PATH

`shutil.which("dkms")` (l.604), `shutil.which("needrestart")` (l.638),
`shutil.which("apt-listchanges")` (l.1038), executed as root. The unit inherits
systemd's default `PATH`, whose writable directories are root-only, so this is
not reachable by an unprivileged local user. Of the three, `apt-listchanges`
output feeds the NEWS gate, which steers a commit decision — so it is closest to
"decides a security question" and is the one to pin first. `shadowfetch-fireproof`
is outside Stage V's file territory; recorded, not changed.

### O-5 — two pkexec targets have no dedicated polkit action

`/usr/libexec/phoenix-apt-repair` (called from `sfcc/phoenix_page.py:351`) and
`/usr/bin/shadowfetch-grok-bot _install` (called from
`shadowfetch-grok-bot:268`) are pkexec targets with no action of their own, so
they fall through to `org.freedesktop.policykit.exec` — `auth_admin_keep` for an
active local user.

This is narrower than the F-1 defect, because pkexec's generic action still
pins the *program* it is authorising and names it in the dialog, and both
helpers validate their own argv (`--check`/`--repair`; a single `_install`
subcommand that reads no caller paths). What is missing is a description: the
user is asked to approve "run a program as another user", not "repair the
software sources". Both belong behind named actions with `exec.path`
annotations, the way `phoenix-restore` and the new `phoenix-apt-snapshot` are.

Not fixed: `shadowfetch-grok-bot` and the fireproof/grok packaging are outside
Stage V's file territory, and adding an action for `phoenix-apt-repair` alone
would leave the pair inconsistent. Recorded, with no test — this is a
"description quality" finding, not an enforcement gap, and a test asserting
"every pkexec target has a named action" would fail today and be a claim the
code does not yet support.

---

## 9. Coverage: what is ENFORCED

| Property | Enforced by | Proven by |
|---|---|---|
| No shipped code escalates to a generic shell | absence + contract test | `test_no_shipped_file_escalates_to_a_generic_shell` — reds when the pattern is reintroduced |
| No shipped code passes its own argv to an escalator | absence + contract test | `test_no_shipped_file_passes_its_own_argv_through_an_escalator` |
| Every passwordless polkit action is pinned to one absolute executable | polkit `exec.path` | `test_passwordless_actions_are_pinned_to_one_executable` — reds when the annotation is deleted |
| Passwordless actions never cover inactive or remote callers | policy defaults | `test_passwordless_actions_never_grant_inactive_or_remote_callers` |
| Every `exec.path` names a helper this tree ships **and installs** | packaging | `test_every_exec_path_names_a_helper_this_tree_ships`, `test_every_exec_path_helper_is_actually_shipped_by_its_package` — reds when the `.install` line is removed |
| Every pkexec-target helper refuses to run unprivileged, directly or through an absolute-path shim | helper code | `test_helpers_behind_polkit_actions_refuse_to_run_unprivileged` |
| `ember-duration` accepts only its documented grammar, and writes nothing when it refuses | helper code | `EmberDurationTests` (15 tests) — reds under charset and existence-check mutation |
| `phoenix-apt-snapshot` accepts only its documented grammar, never follows a symlink, and its root-path tools are not PATH-resolved | helper code | `test_phoenix_apt_snapshot.py` (14 tests), including a hostile `mv` planted earlier on PATH |
| `shadowfetch-gpu` never re-executes a PATH-resolved or caller-writable program as root | script guard | `test_gpu_privileged_reexec.py` (13 tests) — every `self_path()` resolution is absolute, `root_safe_program()` refuses a caller-owned target, and `as_root()` refuses rather than falling back when no escalator exists |

## 10. What is NOT enforced

Stated plainly, because a partial result honestly reported is worth more than a
claim that does not hold:

* **O-2 stands.** Nine call sites still resolve `pkexec` through PATH. They are
  recorded and ratcheted, not fixed.
* **O-4 stands.** `fireproofd` still resolves three optional tools through PATH
  as root.
* **`shadowfetch-gpu`'s `--apply` path is not exercised end to end.** The guard
  functions are, and the call site is asserted to use `self_path()` — that
  assertion caught a real defect while this work was being written: the first
  edit replaced the string inside its own explanatory comment and left the live
  call site on `$0`. What is *not* covered is running the installer as root on
  a machine with an NVIDIA GPU; that stays an acceptance-time observation.
* **Nothing here is proven on a booted system.** Every claim above is about the
  sources and is proven by tests that run against the sources. Whether polkit on
  a running installation resolves these actions as written is OBSERVED at
  release-gate time, not by this document.
* **The `ember-duration` tests run against a path-rewritten copy** in a sandbox,
  with `id` and `systemctl` stubbed. That is the same technique the
  `phoenix-restore` harness uses, and each rewrite asserts its hit count so a
  future edit that changes how a root path is reached fails loudly — but it is
  still a copy, not the installed helper.
