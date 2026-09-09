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
| `install` | `INSTALL-01` | Calamares installs to a blank disk and the result boots. **Partly implemented** -- see below. |
| `upgrade` | `UPGRADE-01` | An installed previous release upgrades to this one with user data, machine identity and package consistency intact. Needs `--upgrade-base-image`. |
| `recovery` | `RECOVERY-01` | A Phoenix Point is restored and the restored generation is what boots, with root and `/boot` from the same generation. |
| `recovery-interrupted` | companion of `RECOVERY-01` | Power is cut mid-restore. |

### Contributing to a required case is not proving it

A case may carry a `manifest_gap`: the part of the required release case it does
**not** cover. With a gap recorded, `--record` refuses no matter how many checks
the run passed. This is enforced, not documented, and unit-tested as such.

All three mapped cases currently carry a gap, so none of them can record today:

* `RECOVERY-01` is *project diff/undo* **and** supported system rollback. The two
  recovery cases prove the rollback half against a real injected failure; the
  Fireline project diff/undo half is not covered here.
* `UPGRADE-01` also asks for working recovery on the upgraded system.
* `INSTALL-01` asks for BIOS **and** UEFI; one run proves one firmware.

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

### Install: what is and is not implemented

The harness boots the artifact, waits for the live desktop, locates the session,
starts the installer and tries to read its accessible controls through the
guest's AT-SPI bus. It is driven through accessibility rather than blind
keystrokes deliberately: keystrokes into a wizard can "succeed" against a dialog
that is not the one anybody thinks it is, which proves nothing about which page
was on screen.

Two obstacles were found and one is solved:

* **pkexec.** The desktop launcher `calamares-install-debian` runs `xhost` and
  then `pkexec`, and pkexec cannot be authorised without a human: through the
  guest agent it answers `Error executing command as another user: Not
  authorized` and nothing starts. The harness now starts `/usr/bin/calamares`
  directly as root on the live session's Wayland/D-Bus environment, and
  Calamares 3.4.2 comes up cleanly -- eight view steps loaded, all requirements
  satisfied, `/dev/vda` detected. The cost is recorded in the receipt: driven
  this way the case covers the INSTALLER, not the polkit path a user takes to
  reach it.
* **Toolkit accessibility is off.** Qt attaches its AT-SPI bridge only when
  `org.a11y.Status.IsEnabled` is true, and a stock KDE session leaves it false
  until an assistive client asks. Until it is on, the installer runs perfectly
  and is simply invisible to the bus -- which reads exactly like a failure to
  start. The harness switches it on before launching and records the result.

With accessibility switched on the bus fills up properly -- seventeen
applications including `plasmashell`, `kwin` and `Shadowfetch Welcome`, against
six before -- but Calamares is still not among them, because the harness runs it
as **root** while the AT-SPI registry being read belongs to the session user.
That is where the case stands: the installer is running and healthy (its log and
the process list are recorded as evidence), and it is invisible to the driver.

The next step is one of:

* start Calamares as the session user with a polkit rule in the QA image that
  allows the install action without a prompt, so it registers on the user's
  accessibility bus like every other application; or
* drive it through QEMU's `sendkey` monitor command with a screenshot assertion
  per page -- weaker, because a screenshot check is a much coarser way to know
  which page is on screen than reading its controls.

Mapping the controls to the welcome/locale/keyboard/partition/users/summary
sequence remains unimplemented either way, so the case ends BLOCKED with the
installer log, the applications the bus could see, the accessibility result and
a framebuffer capture attached as evidence.

### Upgrade: what it needs

A previous-release installed image. The 3.5.0 QA base that this tree's existing
upgrade clones are layered on
(`~/projects/shadowfetch-3.5.0/work/qa-3.5.0/vm/bios-fire-2af853b1/disk.qcow2`)
no longer exists on this host, so every one of those clones is unopenable --
`qemu-img check` fails on the missing backing file. Until a 3.5.0 image is
rebuilt or restored, the case is BLOCKED, not assumed.

## Host requirements

QEMU with KVM (`/usr/bin/qemu-system-x86_64`, `/usr/bin/qemu-img`), OVMF 4M
firmware for `--firmware uefi`, and a base image for the recovery cases. No
Xvfb, ffmpeg, socat or xdotool: framebuffer capture converts QEMU's `screendump`
P6 output to PNG in process, and the guest agent protocol is spoken directly.
Each external binary is one more thing that would have to be trusted.
