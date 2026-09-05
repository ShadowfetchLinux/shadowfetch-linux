# Shadowfetch Linux 4.0 installed-image QA

These helpers operate disposable QEMU guests. A development disk upgraded from
3.5 is useful integration evidence, but it is not acceptance of the final 4.0
ISO. Record the exact ISO SHA256, installation method, firmware and guest disk
identity alongside every final release run.

## Durable guest commands

`vm_harness.sh exec NAME COMMAND SECONDS` observes one real guest command. An
observation timeout returns 124 and preserves its guest PID; it does not kill or
restart the command. Use `resume NAME PID SECONDS` to observe that same command.
`exec-detach NAME COMMAND` immediately returns the durable PID and handle file.
Each short QGA RPC takes a shared lock, so independent observers can coexist
without holding the socket for the lifetime of a long workload.

Example after the exact installed test guest is ready:

```sh
tools/qa_4_0_0/vm_harness.sh exec-detach final-fire \
  'QA_STRESS_VM_BYTES=1G /opt/shadowfetch-qa/stress_45m.sh /var/tmp/release-stress'
tools/qa_4_0_0/vm_harness.sh resume final-fire GUEST_PID 30
```

`GUEST_PID` above must be the returned number, never a new guessed command.
Inspect the guest's durable log files if QGA reports truncated output. After an
RPC or connection error, inspect the existing handle and VM before taking any
action; do not launch a duplicate stress process.

The default virtual display is QXL. Existing virtio guests can use a supported
1920x1080 mode. Corrupted or obscured framebuffer captures must be rejected,
never treated as UI proof.

## Sustained workload

Copy `stress_45m.sh`, `mission_stress.py`, `container_stress.py` and
`latency_probe.py` together into a root-owned directory in the guest. Run the
shell as root with a non-root logged-in QA user (default `sfqa`). It refuses
non-VM environments, non-4.0 installed version markers, durations below 45
minutes, and output directories containing a previous result. Development
smokes require `QA_DEVELOPMENT_SMOKE=1`; their successful result is explicitly
`SMOKE_PASS`, never release `PASS`.

Required installed tools include `stress-ng`, rootless `podman`, `ffmpeg`,
`ffprobe`, the production Workbench/Missions helpers, and a verified native Grok
Bot installation. The guest requires at least 8 GiB free disk. The one image
pull happens before timed load; subsequent rootless containers use the exact
resolved image ID with networking disabled.

The default load is three CPU workers, one 3 GiB memory worker, two disk workers
with 1 GiB each, and two I/O workers. `QA_STRESS_CPUS` and `QA_STRESS_VM_BYTES`
allow explicit sizing. With a resident model in an 8 GiB desktop VM, start with
`QA_STRESS_VM_BYTES=1G`; record the selected resources. Do not make intentional
overcommit indistinguishable from a product memory regression.

During the full interval, the run also performs:

- Real rootless offline containers, actual 32 MiB writes, and independently
  calculated SHA256 comparisons, using named containers that can be cleaned up.
- Real queued media missions using the production worker and a private
  controller state. Each exports a generated PCM fixture, checks receipt hashes
  against files, independently decodes and probes the audio, then exercises Undo
  and verifies the original fixture hash and absence of generated output.
- Actual installed CLI response checks, with each latency, timeout, memory,
  system load and pressure sample recorded. These are CLI responsiveness
  measures; desktop responsiveness needs separate native UI evidence.

Failures remain in the output even if a later check succeeds. The final result
includes exit statuses, elapsed load time, cycle counts, and package/system
checks. Kernel OOM, panic, filesystem faults, service failures, incomplete dpkg
state, failed unit lists and applicable Btrfs device errors fail the run.
Minimum cycle counts and time coverage prevent a few early successful commands
from being presented as 45 minutes of sustained agent activity.

`INT`/`TERM` initiates cancellation. `active-handles.txt` records the runner and
workload PIDs. The media helper cancels its current queued/running mission and
stops its private worker; the container helper removes only its own named QA
container. Evidence is retained and the result is `CANCELLED`. Never signal
unrelated desktop, model, or normal queue services.

## Separate inference and UI checks

Media stress verifies real local tools, queue behavior, artifacts and recovery;
it does not claim model inference. After the native Buzz UI downloads and loads
a model, use `shadowfetch-model-check status --json` and `verify --model ID
--json`. The production adapter must verify the real same-user model process
and its owned loopback socket; mesh/router model listings alone do not prove
offline inference.

Use actual framebuffer captures for native Welcome, Mission Control, Grok and
Buzz. Native application installation, verified executable integrity, account
sign-in, cloud connectivity and a completed agent task are separate states.
Exclude dialogs containing private identity material and retain only reviewed
screenshots as release evidence.

`installed_audit.sh fire|ice bios|uefi` requires a completed disk installation
and a logged-in `QA_USER` (default `sfqa`). It checks the installed system; it is
not a live-session substitute. `native_mission_acceptance.py` runs actual code
repair and source report missions against a loaded native model, independently
checks the results, and verifies receipt hashes, local process proof, Accept
and Undo. `engine_acceptance.py` covers bounded deterministic engine behavior.

`upgrade_recovery_acceptance.py` is restricted to the disposable
`sfqa-final-upgrade` QEMU guest with Btrfs. It does not reboot automatically;
retain its evidence and perform the explicit recovery boot/readback before
claiming that a restored system actually starts.

## Prepublication evidence bundle

After genuine required gates pass, keep `EVIDENCE-01` pending while generating
the release documents with `tools/build_release_evidence_4_0_0.py`. Then run:

```sh
python3 tools/package_release_evidence_4_0_0.py \
  --approved-inputs work/release-4.0.0/approved-inputs.json
```

The approval file is an explicit review record. Its exact schema is
`{"schema_version":1,"screenshots":[],"documents":[]}`. Each selected entry must
contain `path`, the actual `sha256`, and `approved: true`. Screenshot paths are
relative to the acceptance evidence root; document paths are relative to the
repository root. Put only inspected final captures in `screenshots`. Optional
reviewer letters should first be copied into the release workspace and named
explicitly in `documents`. Empty arrays are valid only when there are no
selected inputs of that kind; every screenshot referenced by acceptance still
requires approval at its exact digest.

The helper verifies the ISO identity, every referenced evidence hash, the five
generated document checksums, the prepublication release facts, and all selected
capture/document hashes. It includes a fixed list of relevant QA source files.
It rejects symbolic links, path escapes, unapproved raster images, circular
bundle references, and oversized input sets (512 files, 256 MiB per file, 1 GiB
total). It never scans an entire work tree or changes acceptance statuses.

Outputs match the publisher's expected names:
`evidence-bundle-4.0.0.tar.gz` and `evidence-bundle-4.0.0.contents`. Members are
sorted with zero timestamps, normalized owners/modes, and deterministic gzip
headers. The external `.contents` is a SHA256 check file for every archive
member, including its internal `SHA256SUMS`; neither hashes the bundle itself.
After extracting into a new directory, `sha256sum -c` on the external contents
file verifies the extracted members. Preserve the original prepublication
snapshot: existing output files cause a refusal instead of an overwrite.

Inspect the generated bundle, then record its path/hash in the external
acceptance manifest and record the actual `EVIDENCE-01` result separately. The
bundled snapshot intentionally retains the pending packaging case. Do not
regenerate its enclosed facts/dossier after inserting a self-referential bundle
hash. Publication gates remain pending until public verification occurs.
