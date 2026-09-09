# VM acceptance harness

Automated acceptance against a real machine: the harness boots the artifact
under test in QEMU/KVM, executes a case, captures evidence, binds that evidence
to the artifact digest, and records the result.

    tools/acceptance/vm_acceptance.py list
    tools/acceptance/vm_acceptance.py run --case recovery \
        --artifact shadowfetch-4.0.0-amd64.iso --base-image <installed.qcow2>
    tools/acceptance/vm_acceptance.py status
    tools/acceptance/vm_acceptance.py verify --all

    make vm-acceptance VM_CASE=live-boot
    make vm-acceptance-status
    make vm-acceptance-verify

A run takes minutes and holds a VM open, so drive it with `setsid`/`nohup` from
a session you may lose.

## The one design rule

Executing a case and recording its result are a single command. There is no
subcommand that marks a case passed and no flag that accepts a verdict from
outside. `--record` is a switch on `run`; it is reachable only at the end of a
run that just happened, only for a `PASS`, and only with the evidence files that
run produced.

4.0.0 was published with thirteen of eighteen required acceptance cases
unproven, because "run the test" and "write PASS in the manifest" were two acts
with a human in between. This harness removes the gap rather than documenting
it.

## What a run produces

* **Evidence** under `work/<qa-version>/evidence/vm-acceptance/<run-id>/` --
  inside the release evidence root, so the release recorder can consume it
  directly. Every file is checked against the release gate's own quality floors
  (imported from `tools/release/acceptance.py`, not reimplemented) before it
  counts: empty files, files below the size floor, informationless files and
  undersized screenshots are refused. A zero-byte artifact is not evidence.
* **A receipt** at `work/<qa-version>/vm-acceptance/<run-id>/receipt.json`: the
  artifact digest, the release data file it was resolved against, every check
  with its verdict, every observation, every evidence file with its SHA-256, the
  harness's own source digest, the trusted-program table, and the boots that
  happened. The receipt carries a digest over all of that.
* **A ledger entry** appended to
  `work/<qa-version>/vm-acceptance/ledger.jsonl`, hash-chained to the entry
  before it. Every run appends one -- pass, fail or blocked. Deleting the four
  failures that preceded a pass breaks the chain.

`verify` re-reads all of it: chain, receipt digests, and every evidence byte.

The chain is tamper-**evident**, not tamper-proof. There is no signing key on
this host. What it enforces is that a rewrite must be a rewrite of everything,
and that a receipt lifted from one run does not verify against another. Do not
describe it as more than that.

## Vocabulary

The harness keeps these apart and so should any report of its output:

| term | meaning |
| --- | --- |
| OBSERVED | the harness saw a fact and recorded it. No judgement. |
| PASSED | an observation was compared against a stated expectation and met it. |
| FAILED | an expectation was stated and the system did not meet it. |
| BLOCKED | the case could not be executed here. Not a failure of the artifact, and not a pass. |

Exit status: `0` PASS, `1` FAIL, `2` harness error, `3` BLOCKED. A blocked case
never exits 0. A case that evaluated no check is BLOCKED, never PASS.

## What this harness does not own

Version identity, the manifest location, the evidence quality floors and
trusted-program resolution all live in `tools/release/` and are imported
(`release_link.py`). Restating any of them here would give the release two
answers to the same question -- the drift that left the evidence-entropy floor
in one of six copies of the acceptance verifier.

Trusted programs resolve through `tools/release/gate.py`'s `ProgramResolver`:
absolute paths under root-owned system directories, re-checked on every
resolution, PATH never consulted. `trusted.py` adds only the classification a
release gate has no reason to model -- `GUEST_SUBJECT`. A command run inside the
machine under test is the subject speaking about itself: its output is evidence,
captured and hashed, never a trusted attestation.

## Cases

| case | contributes to | what it proves |
| --- | --- | --- |
| `live-boot` | - | The ISO under test boots to a live session that reports the release version and reaches a running systemd, with a real 1920x1080 desktop framebuffer. |
| `install` | `INSTALL-01` (half) | Calamares installs to a blank disk under one firmware and the result boots, driven page by page through the installer's own accessible controls. |
| `install-both-firmwares` | `INSTALL-01` | Boots the BIOS install and the UEFI install of the same artifact. The case INSTALL-01 is recorded from. |
| `upgrade` | `UPGRADE-01` | An installed previous release upgrades to this one with user data, machine identity and package consistency intact. Needs `--upgrade-base-image`. |
| `recovery` | `RECOVERY-01` | A Phoenix Point is restored and the restored generation is what boots, with root and `/boot` from the same generation. |
| `recovery-interrupted` | companion of `RECOVERY-01` | Power is cut mid-restore. |
| `recovery-project` | `RECOVERY-01` | Fireline's project diff/undo, against a workspace an agent has damaged. The case RECOVERY-01 is recorded from. |

### Contributing to a required case is not proving it

A case may carry a `manifest_gap`: the part of the required release case it does
**not** cover. With a gap recorded, `--record` refuses no matter how many checks
the run passed. This is enforced, not documented, and unit-tested as such.

* `RECOVERY-01` is *project diff/undo* **and** supported system rollback. The two
  recovery cases prove the rollback half against a real injected failure and
  still carry that gap; the project diff/undo half is `recovery-project`, which
  is where RECOVERY-01 is recorded from. Like the install composite it refuses
  to run unless the ledger already holds the other half -- a PASSING `recovery`
  and `recovery-interrupted` against the same artifact, produced by this same
  harness -- and it re-verifies their receipts and evidence bytes before
  believing them.
* `UPGRADE-01` also asks for working recovery on the upgraded system.
* `INSTALL-01` asks for BIOS **and** UEFI; one `install` run proves one
  firmware, and it still carries that gap. It is closed by a second case rather
  than by a judgement call: `install-both-firmwares` refuses to run unless the
  ledger holds a PASSING `install` of the same artifact under each firmware,
  produced by this same harness, and then **boots both of those installed disks
  again**, one under each firmware, and checks the claim on each. Nothing there
  reads a verdict and repeats it.

  Because it pins the harness digest of the runs it consumes, changing anything
  under `tools/acceptance/*.py` means the two `install` legs have to be re-run
  before `install-both-firmwares` will accept them. That is deliberate: a leg
  produced by an older, weaker version of the case must not be able to support a
  composite produced by a newer one.

Closing any of those gaps is a case-registry change plus the missing steps -- not
a judgement call at recording time.

### The power-loss case

`recovery-interrupted` SIGKILLs the QEMU process during a Phoenix restore, then
boots the same disk again. The kill is **aimed, not timed**: the harness watches
the volume's subvolume list through the guest agent and pulls the plug the
moment `@new` exists and no new `@_prev_*` does -- the writable copy of the Point
is made and the atomic exchange has not happened. That is the one window in
which a half-applied restore is possible.

If the restore finishes first (about 1.6s on this hardware) the case reports
BLOCKED. An interruption that interrupted nothing proves nothing, and must not
be allowed to look like a pass.

What it then asserts:

1. The machine still boots.
2. The booted root is exactly one generation, not a blend of two.
3. **No completed restore is claimed unless the restore completed.** Under-
   claiming is safe -- the cut can land after the exchange but before anything
   durable says so. Over-claiming is the defect.
4. A leftover writable copy is not what the machine booted.
5. Root and `/boot` are the same generation.
6. Diagnosability, judged against what the shipped implementation promises (see
   below).
7. The recovered system is usable: release version, clean `dpkg --audit`,
   running systemd.
8. A restore attempted after the power cut either succeeds or refuses out loud,
   and if it succeeds it lands the Point it names.

Two honest limits on what a run of this case proves:

* **It does not journal.** The `/usr/libexec/phoenix-restore` inside the 4.0.0
  ISO (sha256 `b730de43...`, 254 lines) contains no journalling at all; the
  intent journal and the W-11 interrupt rollback are newer, uncommitted work in
  the tree. The case therefore identifies the implementation it is running
  against, records it in the receipt, and only requires a durable journal from
  an implementation that has one -- while checking that a binary which does not
  journal does not claim to.
* **Same-kernel base image.** On a base whose Point and current root share a
  kernel version, the external `/boot` staging moves no kernel, so check 5 is
  necessary but not sufficient. A base image whose Point carries a different
  kernel would test the root-versus-`/boot` claim much harder.

### Install: how it is driven, and the defect that used to block it

The harness boots the artifact, waits for the live desktop, starts the
installer, and drives it page by page through the guest's AT-SPI bus. It is
driven through accessibility rather than blind keystrokes deliberately:
keystrokes into a wizard can "succeed" against a dialog that is not the one
anybody thinks it is, which proves nothing about which page was on screen. Every
step here asserts the page it is about to act on, from that page's own controls,
and stops as BLOCKED with the observed page recorded if it does not recognise
it.

Two obstacles were found. Both are now solved.

* **pkexec.** The desktop launcher `calamares-install-debian` runs `xhost` and
  then `pkexec`, and pkexec cannot be authorised without a human: through the
  guest agent it answers `Error executing command as another user: Not
  authorized` and nothing starts. The harness starts `/usr/bin/calamares`
  directly as root instead. The cost is recorded in the receipt: driven this
  way the case covers the INSTALLER, not the polkit path a user takes to reach
  it.

* **A root process cannot use the live user's session bus at all.** This is what
  five consecutive runs were reporting as `expected exactly one 'calamares'
  application, found 0`. Measured inside the live session: connecting to
  `unix:path=/run/user/1000/bus` as uid 0 is dropped at EXTERNAL authentication
  (`org.freedesktop.DBus.Error.NoReply`), and the running installer holds
  exactly two sockets -- one to the Wayland compositor, and none to any
  accessibility bus. Qt attaches its AT-SPI bridge (compiled into libQt6Gui
  here, not a loadable plugin) only after it can read `org.a11y.Status` from a
  session bus, so with no session bus there is no bridge and no registration.
  Setting `QT_ACCESSIBILITY`, or switching `org.a11y.Status.IsEnabled` on for
  the session user, cannot help: both fix an obstacle the root process never
  reaches. The earlier note in this file blamed the registry belonging to the
  session user; the process never got that far.

  The installer is therefore given a session bus of its own uid -- a private
  `dbus-daemon` started as root, on which `org.a11y.Bus` activates a root-owned
  at-spi bus and registry -- and the driver reads that same bus. The installer
  is the shipped binary, on the live session's real compositor, installing to a
  real disk.

**Typing.** Setting a field through AT-SPI's `EditableText` interface lands the
characters and Calamares ignores them: its users page listens for
`QLineEdit::textEdited`, the signal that means a person typed. Measured: all
five account fields set that way, all five reading back correctly, and the Next
button still disabled; one real keystroke enabled it. So the keys are real --
QEMU's own input device, the path a physical keyboard takes -- while the
assertions stay on the accessibility bus: focus is verified before typing and
the content is read back after. A password field reads back as bullets, so for
those the character count is what can honestly be compared.

**What the case checks.** That the installer registers on the bus at all; that
each page is the page it is supposed to be; that the partition page offers the
machine's disk and reports the firmware the machine booted under; that the
installer *refuses* to advance before a partitioning choice is made and before
the account is filled in, and advances once they are; that the summary describes
erasing this disk, installing this release, and the partition table that
firmware requires; that the installation reaches Calamares' own "All done"
rather than its failure page. Then the live medium is shut down and the disk is
booted on its own, and the installed system has to report the release version,
boot through the firmware it was installed under, carry the account and host
name that were typed into the accessible fields, keep a clean `dpkg --audit`,
and reach a running systemd. The account check is the end-to-end one: it is the
same string that went in through the accessibility bus, read back out of
`/etc/passwd` on a machine booted from the disk.

### Upgrade: what it needs### Upgrade: what it needs

A previous-release installed image. The 3.5.0 QA base that this tree's existing
upgrade clones are layered on
(`~/projects/shadowfetch-3.5.0/work/qa-3.5.0/vm/bios-fire-2af853b1/disk.qcow2`)
no longer exists on this host, so every one of those clones is unopenable --
`qemu-img check` fails on the missing backing file. Until a 3.5.0 image is
rebuilt or restored, the case is BLOCKED, not assumed.

Its `manifest_gap` is deliberately still there. UPGRADE-01 also asks for
working recovery on the upgraded system, and the leg that would prove it -- take
a Phoenix Point on the upgraded machine, restore it, reboot, confirm the
restored generation is what boots -- is the same shape as `case_recovery`'s and
would be easy to write. It has not been written, because on this host it could
never be executed even once: adding an unrunnable leg would close the recorded
gap while proving nothing, which is precisely the move this harness exists to
prevent.

### Project diff/undo

`recovery-project` acts as the desktop user, not as root. It creates a
workspace under `~/Workspaces`, takes a checkpoint with
`/usr/bin/shadowfetch-checkpoint`, and then injects the damage an agent that ran
wild would do: one file edited, one deleted, one added, one deleted along with
its directory. The diff must name **exactly** those four changes and no others
-- a file nobody touched appearing in the diff fails the check as surely as a
missing one. The undo then has to bring the workspace back to the checkpoint
byte for byte, judged from a digest of every file rather than from the tool's
own report, after which the tool is asked again and must agree there is nothing
left to restore. A canary file beside the workspace root proves the undo stayed
inside the workspace it names.

Two things it records rather than hides. The shipped
`/usr/bin/shadowfetch-checkpoint` in this release is the four-subcommand
version (`snapshot`, `list`, `diff`, `undo`); the tree has a newer one with
`verify`, `recover` and `--json`, and the case identifies which one it ran
against. And the QA base image ships `~/Workspaces` owned by **root**, so the
desktop user cannot create the checkpoint store inside it and cannot take a
checkpoint at all until the ownership is corrected. The case corrects it,
records the ownership it found, and goes on to test the mechanism it is there to
test -- but that ownership is worth somebody's attention, because a user who
hits it sees the feature simply fail.

## Host requirements

QEMU with KVM (`/usr/bin/qemu-system-x86_64`, `/usr/bin/qemu-img`), OVMF 4M
firmware for `--firmware uefi`, and a base image for the recovery cases. No
Xvfb, ffmpeg, socat or xdotool: framebuffer capture converts QEMU's `screendump`
P6 output to PNG in process, and the guest agent protocol is spoken directly.
Each external binary is one more thing that would have to be trusted.
