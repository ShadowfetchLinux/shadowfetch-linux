#!/usr/bin/env python3
"""The acceptance cases themselves.

Vocabulary, kept strictly distinct because collapsing it is how an unproven
release gets published:

  OBSERVED   the harness saw a fact and recorded it. No judgement attached.
  PASSED     an observation was compared against a stated expectation and met it.
  BLOCKED    the case could not be executed here. Not a failure of the artifact,
             and emphatically not a pass.
  FAILED     an expectation was stated and the system did not meet it.

A case function may only return by finishing its checks, by raising Blocked, or
by raising. There is no path that produces PASS without at least one check
having been evaluated against the running system.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
import shlex
import time
from typing import Any, Callable

from .evidence import EvidenceSet, harness_fingerprint, sha256_file
from .ledger import Ledger, receipt_problems
from .vm import Guest, GuestError


class Blocked(Exception):
    """The case cannot be executed in this environment. Never a pass."""


class Context:
    def __init__(
        self,
        *,
        name: str,
        repo_root: Path,
        run_dir: Path,
        evidence: EvidenceSet,
        artifact: dict[str, Any],
        options: dict[str, Any],
        work_root: Path | None = None,
    ) -> None:
        self.name = name
        self.repo_root = repo_root
        # Where this release's runs live: work/qa-<version>. A case that has to
        # consume an earlier run of this harness (INSTALL-01 needs one install
        # per firmware) reads the ledger from here rather than recomputing the
        # layout the runner already knows.
        self.work_root = work_root if work_root is not None else run_dir.parent.parent
        self.run_dir = run_dir
        self.evidence = evidence
        self.artifact = artifact
        self.options = options
        self.checks: list[dict[str, Any]] = []
        self.observations: dict[str, Any] = {}
        self.transcript: list[str] = []
        self.guests: list[Guest] = []

    # -- recording --

    def log(self, message: str) -> None:
        line = f"{time.strftime('%H:%M:%S', time.gmtime())} {message}"
        self.transcript.append(line)
        print(line, flush=True)

    def observe(self, key: str, value: Any) -> Any:
        """Record a fact. An observation is not a verdict; nothing passes here."""
        self.observations[key] = value
        self.log(f"OBSERVED {key} = {value!r}"[:400])
        return value

    def check(self, name: str, condition: bool, detail: str = "") -> bool:
        state = "PASSED" if condition else "FAILED"
        self.checks.append({"name": name, "state": state, "detail": detail})
        self.log(f"{state} {name}" + (f" -- {detail}" if detail else ""))
        return bool(condition)

    def blocked(self, reason: str) -> None:
        raise Blocked(reason)

    # -- guests --

    def guest(self, name: str, **kwargs: Any) -> Guest:
        machine = Guest(self.run_dir / "vm" / name, name, **kwargs)
        self.guests.append(machine)
        return machine

    def collect_machine_evidence(self, machine: Guest, prefix: str) -> None:
        """Serial console and QEMU stderr, always, pass or fail.

        A failed run's evidence is the point: it is what tells the next person
        whether the artifact broke or the harness did.
        """
        for source, kind in ((machine.serial_log, "log"), (machine.qemu_log, "log")):
            if source.is_file() and source.stat().st_size:
                target = self.evidence.path(f"{prefix}-{source.name}")
                target.write_bytes(source.read_bytes())
                self.evidence.try_add(target, kind)

    def snap(self, machine: Guest, name: str, *, required: bool = False) -> dict | None:
        target = self.evidence.path(name)
        try:
            info = machine.screenshot(target)
        except GuestError as error:
            if required:
                raise
            self.log(f"screenshot {name} unavailable: {error}")
            return None
        item = self.evidence.add(target, "screenshot") if required else \
            self.evidence.try_add(target, "screenshot")
        if item is None:
            self.log(f"screenshot {name} did not meet the evidence floor")
        return info


# --- shared guest probes ------------------------------------------------------


def system_report(machine: Guest) -> dict[str, Any]:
    """One structured read of the guest. Guest output is evidence, not proof."""
    def out(command: str) -> str:
        return machine.run(command, timeout=120)["stdout"].strip()

    return {
        "os_release": out("cat /etc/os-release"),
        "version_marker": out("cat /usr/share/shadowfetch/version 2>/dev/null"),
        "cmdline": out("cat /proc/cmdline"),
        "kernel": out("uname -r"),
        "boot_id": out("cat /proc/sys/kernel/random/boot_id"),
        "machine_id": out("cat /etc/machine-id 2>/dev/null"),
        "root_mount": out("findmnt -no SOURCE,FSTYPE,OPTIONS /"),
        "boot_mount": out("findmnt -no SOURCE,FSTYPE /boot 2>/dev/null"),
        "system_state": out("systemctl is-system-running 2>&1"),
        "failed_units": out("systemctl --failed --no-legend --plain 2>&1"),
        "dpkg_audit": out("dpkg --audit 2>&1"),
        "shadowfetch_packages": out(
            "dpkg-query -W -f='${Package}\\t${Version}\\t${db:Status-Abbrev}\\n' "
            "'shadowfetch-*' 2>/dev/null"
        ),
        "modules_present": out(
            "test -d /lib/modules/$(uname -r) && echo yes || echo no"
        ),
        "boot_kernel_present": out(
            "test -f /boot/vmlinuz-$(uname -r) && echo yes || echo no"
        ),
    }


def push_script(machine: Guest, path: str, source: str) -> None:
    """Write a helper into the guest without trusting anything in its PATH."""
    encoded = base64.b64encode(source.encode()).decode()
    machine.run(
        f"printf %s {shlex.quote(encoded)} | /usr/bin/base64 -d > {shlex.quote(path)}",
        check=True,
    )


# --- LIVE-BOOT ----------------------------------------------------------------


def case_live_boot(ctx: Context) -> None:
    """Boot the ISO under test and prove the live system actually came up.

    Cheapest possible run against the real artifact, and the one that proves
    the harness itself is wired to the artifact rather than to a stale disk.
    """
    iso = Path(ctx.artifact["path"])
    machine = ctx.guest("live", firmware=ctx.options.get("firmware", "bios"))
    machine.create_disk(int(ctx.options.get("disk_gib", 32)))
    ctx.log(f"booting {iso.name} ({ctx.artifact['sha256'][:16]}...)")
    machine.boot("live", iso=iso, note="live boot of the artifact under test")
    try:
        waited = machine.wait_agent(float(ctx.options.get("boot_timeout", 900)))
        ctx.observe("guest_agent_seconds", round(waited, 1))
        report = system_report(machine)
        ctx.evidence.write_json("live-system-report.json", report)

        ctx.check(
            "live session boots from the ISO under test",
            "boot=live" in report["cmdline"],
            report["cmdline"][:200],
        )
        ctx.check(
            "live system reports the release version",
            report["version_marker"] == ctx.options["version"],
            f"version marker {report['version_marker']!r}",
        )
        ctx.check(
            "live os-release matches the release version",
            f'VERSION_ID="{ctx.options["version"]}"' in report["os_release"],
        )
        ctx.check(
            "systemd reaches a running state",
            report["system_state"] in ("running", "degraded"),
            f"systemctl is-system-running = {report['system_state']!r}"
            + (f"; failed units: {report['failed_units']}" if report["failed_units"] else ""),
        )
        # Give the desktop session time to paint before the screenshot: an
        # empty framebuffer is not evidence that a desktop came up.
        settle = float(ctx.options.get("desktop_settle", 90))
        ctx.log(f"waiting {settle:.0f}s for the desktop session")
        time.sleep(settle)
        shot = ctx.snap(machine, "live-desktop.png", required=True)
        ctx.check(
            "live desktop framebuffer is captured at release resolution",
            bool(shot) and shot["width"] >= 1280 and shot["height"] >= 720,
            f"{shot['width']}x{shot['height']}" if shot else "no capture",
        )
    finally:
        try:
            machine.shutdown()
        finally:
            ctx.collect_machine_evidence(machine, "live")


# --- RECOVERY -----------------------------------------------------------------

RECOVERY_MARKER = "/etc/shadowfetch-acceptance-marker"
RECOVERY_WITNESS = "/etc/shadowfetch-acceptance-after-point"


def _recovery_base(ctx: Context) -> Path:
    base = ctx.options.get("base_image")
    if not base:
        ctx.blocked(
            "no installed base image supplied. Pass --base-image with a qcow2 "
            "disk holding an installed system of the release under test, or run "
            "the install case first so this case can consume its result."
        )
    path = Path(base).resolve()
    if not path.is_file():
        ctx.blocked(f"base image does not exist: {path}")
    return path


def _prepare_point(ctx: Context, machine: Guest) -> dict[str, Any]:
    """Bring the guest to a known state and take a Phoenix Point of it."""
    report = system_report(machine)
    ctx.evidence.write_json("recovery-baseline.json", report)
    ctx.check(
        "base system is the release under test",
        report["version_marker"] == ctx.options["version"],
        f"version marker {report['version_marker']!r}",
    )
    ctx.check(
        "base system root is Btrfs, as Phoenix Points require",
        "btrfs" in report["root_mount"],
        report["root_mount"],
    )
    ctx.check(
        "base system booted from disk, not from the live medium",
        "boot=live" not in report["cmdline"],
        report["cmdline"][:200],
    )
    if any(check["state"] == "FAILED" for check in ctx.checks):
        ctx.blocked(
            "the supplied base image is not a usable installed system of this "
            "release; see the failed checks above"
        )

    original = f"phoenix-point-content-{int(time.time())}"
    machine.run(
        f"printf %s {shlex.quote(original)} > {RECOVERY_MARKER}", check=True
    )
    machine.run(f"rm -f {RECOVERY_WITNESS}", check=True)
    machine.run("/usr/bin/sync", check=True)

    created = machine.run(
        "snapper --no-dbus -c root create --print-number --description "
        "'VM acceptance: state to restore'",
        timeout=300,
    )
    number = created["stdout"].strip()
    if created["exitcode"] != 0 or not number.isdecimal():
        ctx.blocked(
            "could not create a Phoenix Point on the base image "
            f"(snapper exit {created['exitcode']}): "
            f"{(created['stdout'] + created['stderr']).strip()[:500]}"
        )
    ctx.observe("phoenix_point", int(number))

    # Diverge from the Point so a restore is observable rather than a no-op.
    mutated = f"mutated-after-point-{int(time.time())}"
    machine.run(f"printf %s {shlex.quote(mutated)} > {RECOVERY_MARKER}", check=True)
    machine.run(f"printf %s witness > {RECOVERY_WITNESS}", check=True)
    machine.run("/usr/bin/sync", check=True)
    ctx.check(
        "system state diverges from the Point before the restore",
        machine.out(f"cat {RECOVERY_MARKER}") == mutated
        and machine.out(f"test -f {RECOVERY_WITNESS} && echo yes || echo no") == "yes",
        "marker mutated and witness file created",
    )
    return {
        "point": int(number),
        "original": original,
        "mutated": mutated,
        "root_device": machine.out("findmnt -no SOURCE / | sed 's/\\[.*//'"),
        "baseline": report,
    }


def _marker_state(machine: Guest, state: dict[str, Any]) -> str:
    """Which generation is the booted root? Never 'probably'."""
    marker = machine.out(f"cat {RECOVERY_MARKER} 2>/dev/null")
    witness = machine.out(f"test -f {RECOVERY_WITNESS} && echo yes || echo no")
    if marker == state["original"] and witness == "no":
        return "restored"
    if marker == state["mutated"] and witness == "yes":
        return "pre-restore"
    return f"mixed(marker={marker!r},witness={witness})"


def case_recovery(ctx: Context) -> None:
    """Restore a Phoenix Point and prove the restored state is what boots."""
    base = _recovery_base(ctx)
    machine = ctx.guest("recovery", firmware=ctx.options.get("firmware", "bios"))
    provenance = machine.clone_disk(base)
    ctx.observe("base_image", provenance["base_image"])
    ctx.evidence.write_json("recovery-base-provenance.json", provenance)
    machine.boot("installed", note="installed system before restore")
    try:
        machine.wait_agent(float(ctx.options.get("boot_timeout", 900)))
        state = _prepare_point(ctx, machine)

        started = time.monotonic()
        restore = machine.run(
            f"/usr/libexec/phoenix-restore {state['point']}", timeout=900
        )
        elapsed = time.monotonic() - started
        ctx.observe("restore_seconds", round(elapsed, 1))
        ctx.evidence.write_text(
            "recovery-phoenix-restore.log",
            f"$ /usr/libexec/phoenix-restore {state['point']}\n"
            f"exit={restore['exitcode']}\n\n{restore['stdout']}\n{restore['stderr']}\n",
        )
        ctx.check(
            "phoenix-restore reports success",
            restore["exitcode"] == 0,
            f"exit {restore['exitcode']}",
        )
        if restore["exitcode"] != 0:
            return

        ctx.check(
            "restore does not take effect before the reboot it asks for",
            _marker_state(machine, state) == "pre-restore",
            "the running root is still the pre-restore generation",
        )
        reboot = machine.reboot(float(ctx.options.get("boot_timeout", 900)))
        ctx.check(
            "the machine really rebooted",
            reboot["boot_id_after"] != reboot["boot_id_before"],
            f"boot_id {reboot['boot_id_before'][:8]} -> {reboot['boot_id_after'][:8]}",
        )

        # "starting" is the question asked too early, not an answer: the
        # agent replies while first-boot units are still running.
        after = system_report(machine)
        after["settled_state"] = _settle_system(machine)
        after["system_state"] = after["settled_state"] or after["system_state"]
        ctx.evidence.write_json("recovery-after-restore.json", after)
        generation = _marker_state(machine, state)
        ctx.check(
            "the restored Point is what boots",
            generation == "restored",
            f"booted generation: {generation}",
        )
        ctx.check(
            "the restored root and /boot are the same generation",
            after["modules_present"] == "yes" and after["boot_kernel_present"] == "yes",
            f"modules for {after['kernel']}: {after['modules_present']}, "
            f"/boot/vmlinuz-{after['kernel']}: {after['boot_kernel_present']}",
        )
        ctx.check(
            "the restored system is the release under test",
            after["version_marker"] == ctx.options["version"],
            f"version marker {after['version_marker']!r}",
        )
        ctx.check(
            "the restored system's package database is consistent",
            after["dpkg_audit"] == "",
            after["dpkg_audit"][:300] or "dpkg --audit is clean",
        )
        ctx.check(
            "the restored system reaches a running state",
            after["system_state"] in ("running", "degraded"),
            f"systemctl is-system-running = {after['system_state']!r}"
            + (f"; failed units: {after['failed_units']}" if after["failed_units"] else ""),
        )
        ctx.snap(machine, "recovery-after-restore.png")
    finally:
        try:
            machine.shutdown()
        finally:
            ctx.collect_machine_evidence(machine, "recovery")


# --- INTERRUPTED RECOVERY (power loss) ----------------------------------------


def _subvolumes(machine: Guest) -> list[str]:
    """The volume's subvolume names, as the guest itself reports them.

    This is the harness's window into what a restore is doing, and it works
    against the implementation that actually shipped. The first version of this
    case watched phoenix-restore's intent journal instead and blocked every
    time: the journal is uncommitted work in the tree, and the 4.0.0 binary in
    the ISO under test (sha256 b730de43..., 254 lines) contains no journalling
    at all. Watching filesystem state rather than a log line also observes the
    restore rather than the restore's account of itself.
    """
    listing = machine.out("btrfs subvolume list / 2>/dev/null")
    return [
        line.split(" path ", 1)[1].strip()
        for line in listing.splitlines()
        if " path " in line
    ]


def _restore_implementation(machine: Guest) -> dict[str, Any]:
    """Identify the restore implementation this artifact actually ships.

    Recorded in the receipt because the expectations below depend on it: a
    binary that does not journal cannot be failed for leaving no journal, and a
    reader needs to see which of the two it was.
    """
    def out(command: str) -> str:
        return machine.run(command, timeout=120)["stdout"].strip()

    return {
        "path": "/usr/libexec/phoenix-restore",
        "sha256": out("sha256sum /usr/libexec/phoenix-restore | cut -d' ' -f1"),
        "lines": out("wc -l < /usr/libexec/phoenix-restore"),
        "package_version": out("dpkg-query -W -f='${Version}' shadowfetch-phoenix"),
        "journals": out("grep -c journal /usr/libexec/phoenix-restore || true"),
        "promises_a_journal": out(
            "grep -qi 'journalled' /usr/libexec/phoenix-restore && echo yes || echo no"
        ),
        "stages_external_boot": out(
            "grep -qc prepare_external_boot /usr/libexec/phoenix-restore && echo yes "
            "|| echo no"
        ),
        "rolls_back_boot_on_interrupt": out(
            "grep -q 'rollback_external_boot' /usr/libexec/phoenix-restore && "
            "grep -qE 'trap .*rollback|ROOT_EXCHANGED' /usr/libexec/phoenix-restore "
            "&& echo yes || echo no"
        ),
    }


def _post_crash_state(machine: Guest, device: str) -> dict[str, Any]:
    """Everything the machine says about itself after the power cut."""
    mount = machine.run(
        "mkdir -p /run/sf-acceptance-top && "
        f"mount -t btrfs -o ro,subvolid=5 {shlex.quote(device)} /run/sf-acceptance-top",
        timeout=120,
    )
    toplevel_entries = ""
    toplevel_journal = ""
    if mount["exitcode"] == 0:
        toplevel_entries = machine.out("ls -1 /run/sf-acceptance-top 2>/dev/null")
        toplevel_journal = machine.out(
            "cat /run/sf-acceptance-top/phoenix-restore.journal 2>/dev/null"
        )
        machine.run("umount /run/sf-acceptance-top", timeout=60)
    return {
        "subvolumes": _subvolumes(machine),
        "toplevel_entries": toplevel_entries,
        "toplevel_journal": toplevel_journal,
        "root_journal": machine.out(
            "cat /var/lib/shadowfetch/phoenix-restore.journal 2>/dev/null"
        ),
        "restore_output": machine.out(
            "cat /var/lib/shadowfetch/phoenix-restore.out 2>/dev/null"
        ),
        "update_grub_flag": machine.out(
            "test -f /var/lib/shadowfetch/phoenix-update-grub && "
            "cat /var/lib/shadowfetch/phoenix-update-grub || echo ABSENT"
        ),
        "root_subvol_option": machine.out("findmnt -no OPTIONS / 2>/dev/null"),
        "boot_backups": machine.out("ls -1d /boot/phoenix-kernel-backup-* 2>/dev/null"),
        "boot_contents": machine.out("ls -1 /boot 2>/dev/null"),
        "grub_next_entry": machine.out(
            "grub-editenv /boot/grub/grubenv list 2>/dev/null"
        ),
    }


def case_recovery_interrupted(ctx: Context) -> None:
    """Cut power in the middle of a restore.

    The claim under test is not "the restore succeeds". It is the far more
    important one: whatever the machine does after losing power mid-restore, it
    must never end up reporting a completed restore it did not complete, and it
    must never boot a root from one generation against a /boot from another.

    The kill is aimed, not timed. The harness watches the volume's subvolume
    list through the guest agent and pulls the plug the moment @new exists --
    the writable copy of the Point is made, the atomic exchange has not
    happened, and the external /boot has already been staged. That is the one
    window in which a half-applied restore is possible. If the restore finishes
    before the harness can cut (it takes about 1.6s on this hardware), the case
    reports BLOCKED: an interruption that did not interrupt anything proves
    nothing, and must not be allowed to look like a pass.
    """
    base = _recovery_base(ctx)
    machine = ctx.guest(
        "recovery-interrupted", firmware=ctx.options.get("firmware", "bios")
    )
    provenance = machine.clone_disk(base)
    ctx.observe("base_image", provenance["base_image"])
    ctx.evidence.write_json("interrupted-base-provenance.json", provenance)
    machine.boot("installed", note="installed system before interrupted restore")
    try:
        machine.wait_agent(float(ctx.options.get("boot_timeout", 900)))
        state = _prepare_point(ctx, machine)
        device = state["root_device"]
        ctx.observe("root_device", device)

        implementation = _restore_implementation(machine)
        ctx.evidence.write_json("interrupted-implementation.json", implementation)
        ctx.observe("restore_binary_sha256", implementation["sha256"])
        journals = implementation["journals"].isdigit() and int(
            implementation["journals"]
        ) > 0
        ctx.observe("restore_journals", journals)

        # Both generations here share a kernel version, so the /boot staging
        # moves no kernel out. Recorded rather than assumed: it bounds what the
        # root-versus-/boot check below can prove on this base image.
        kernel = machine.out("uname -r")
        point_kernels = machine.out(
            f"ls -1 /.snapshots/{state['point']}/snapshot/lib/modules 2>/dev/null"
        )
        ctx.observe("running_kernel", kernel)
        ctx.observe("point_kernels", point_kernels.split())

        machine.run("rm -f /var/lib/shadowfetch/phoenix-restore.out", check=True)
        machine.run("/usr/bin/sync", check=True)
        baseline = set(_subvolumes(machine))
        ctx.observe("subvolumes_before_restore", sorted(baseline))

        deadline_seconds = float(ctx.options.get("interrupt_deadline", 90))
        ctx.log(f"starting phoenix-restore {state['point']} detached")
        guest_pid = machine.agent.execute_detached(
            f"/usr/libexec/phoenix-restore {state['point']} "
            "> /var/lib/shadowfetch/phoenix-restore.out 2>&1"
        )
        ctx.observe("restore_guest_pid", guest_pid)

        started = time.monotonic()
        trigger = None
        observed: list[str] = []
        while time.monotonic() - started < deadline_seconds:
            observed = _subvolumes(machine)
            appeared = set(observed) - baseline
            completed = {name for name in appeared if name.startswith("@_prev_")}
            if "@new" in observed:
                trigger = "pre-exchange-window"
                break
            if completed:
                ctx.observe("subvolumes_at_completion", sorted(observed))
                ctx.blocked(
                    "the restore completed in "
                    f"{time.monotonic() - started:.1f}s -- before the harness could "
                    f"cut power (it observed {sorted(completed)}). Nothing was "
                    "interrupted, so this run proves nothing about power loss "
                    "during a restore and is not a pass. Re-run against a Point "
                    "large enough that the writable copy and the /boot staging "
                    "take longer than one guest-agent round trip."
                )
        elapsed = time.monotonic() - started
        if trigger is None:
            ctx.blocked(
                f"no restore was observed in flight within {deadline_seconds:.0f}s "
                f"(subvolumes: {sorted(observed)}). The power cut was not taken, "
                "because cutting power to a machine that is not restoring anything "
                "would prove nothing."
            )

        killed = machine.kill_hard()
        ctx.observe("interrupt_trigger", trigger)
        ctx.observe("interrupt_after_seconds", round(elapsed, 2))
        ctx.observe("subvolumes_at_interrupt", sorted(observed))
        ctx.log(f"power cut: SIGKILL to QEMU {killed['pid']} at {killed['at_utc']}")
        ctx.evidence.write_json(
            "interrupted-power-cut.json",
            {
                "trigger": trigger,
                "elapsed_seconds": round(elapsed, 2),
                "subvolumes_at_interrupt": sorted(observed),
                "subvolumes_before": sorted(baseline),
                "qemu": killed,
                "implementation": implementation,
            },
        )
        ctx.collect_machine_evidence(machine, "interrupted-first")

        # --- and now: what does the machine do next? ---
        machine.boot("installed", note="boot after the power cut")
        recovered = True
        try:
            machine.wait_agent(float(ctx.options.get("boot_timeout", 900)))
        except GuestError as error:
            recovered = False
            ctx.observe("post_crash_boot_error", str(error))
            ctx.snap(machine, "interrupted-post-crash-console.png")
        ctx.check(
            "the machine still boots after power loss during a restore",
            recovered,
            "the guest agent answered after the power cut"
            if recovered
            else "the guest never came back; see the serial log and the console capture",
        )
        if not recovered:
            return

        after = system_report(machine)
        after["settled_state"] = _settle_system(machine)
        after["system_state"] = after["settled_state"] or after["system_state"]
        crash = _post_crash_state(machine, device)
        ctx.evidence.write_json(
            "interrupted-post-crash.json", {"system": after, "state": crash}
        )

        generation = ctx.observe("post_crash_generation", _marker_state(machine, state))
        # What the machine CLAIMS. On the shipped implementation there are two
        # surfaces: the restore's own output, and the machine-readable flag the
        # next boot acts on. Neither may claim a restore that did not happen.
        claimed_complete = ctx.observe(
            "claims_a_completed_restore",
            "is now the permanent system root" in crash["restore_output"]
            or crash["update_grub_flag"] != "ABSENT"
            or "restore complete" in crash["toplevel_journal"]
            or "restore complete" in crash["root_journal"],
        )

        # 1. One coherent generation. Not a blend of two.
        ctx.check(
            "the booted root is exactly one generation, not a mixture",
            generation in ("restored", "pre-restore"),
            f"booted generation: {generation}",
        )
        # 2. The honesty invariant, and the reason this case exists.
        #    Under-claiming is safe: the cut can land after the exchange but
        #    before anything durable says so, and a restore that quietly worked
        #    harms nobody. Over-claiming is the defect -- a completion reported
        #    for work that did not happen.
        ctx.check(
            "no completed restore is claimed unless the restore completed",
            (not claimed_complete) or generation == "restored",
            f"claims completion = {claimed_complete}, booted generation = "
            f"{generation}",
        )
        # 3. The leftover writable copy must not become the running root. The
        #    implementation parks it on the next restore; what matters here is
        #    that the machine did not boot it by accident.
        ctx.check(
            "a leftover writable copy is not what the machine booted",
            "subvol=/@" in crash["root_subvol_option"]
            and "@new" not in crash["root_subvol_option"],
            f"root mount options: {crash['root_subvol_option']}",
        )
        # 4. Root and /boot must never come from different generations. On this
        #    base image both generations carry the same kernel, so the /boot
        #    staging moves nothing; this check is therefore necessary but not
        #    sufficient, and a differing-kernel base image would test it harder.
        ctx.check(
            "root and /boot are the same generation after the power cut",
            after["modules_present"] == "yes" and after["boot_kernel_present"] == "yes",
            f"running kernel {after['kernel']}: modules "
            f"{after['modules_present']}, /boot image {after['boot_kernel_present']}",
        )
        # 5. Diagnosability, judged against what this implementation promises.
        #    A binary that never journals is not failed for leaving no journal;
        #    one whose own help text promises a journal is.
        if journals or implementation["promises_a_journal"] == "yes":
            ctx.check(
                "the interrupted restore left the durable journal it promises",
                bool(
                    crash["toplevel_journal"].strip() or crash["root_journal"].strip()
                ),
                f"top-level journal {len(crash['toplevel_journal'])} bytes, "
                f"root journal {len(crash['root_journal'])} bytes",
            )
        else:
            ctx.observe(
                "diagnosability",
                "the implementation in this artifact does not journal its restore "
                "steps, so an interrupted restore leaves no intent record; the "
                "only trace is the restore's captured output and the on-disk "
                "subvolume layout",
            )
            ctx.check(
                "the implementation does not promise a journal it does not write",
                implementation["promises_a_journal"] == "no",
                "no journalling in the binary and no promise of one in its help",
            )
        # 6. The system is usable, not merely alive.
        ctx.check(
            "the recovered system reports the release version",
            after["version_marker"] == ctx.options["version"],
            f"version marker {after['version_marker']!r}",
        )
        ctx.check(
            "the recovered system's package database is consistent",
            after["dpkg_audit"] == "",
            after["dpkg_audit"][:300] or "dpkg --audit is clean",
        )
        ctx.check(
            "the recovered system reaches a running state",
            after["system_state"] in ("running", "degraded"),
            f"systemctl is-system-running = {after['system_state']!r}"
            + (f"; failed units: {after['failed_units']}" if after["failed_units"] else ""),
        )
        # 7. And it must still be possible to finish the job: a restore run
        #    after the crash has to reach a coherent result rather than trip
        #    over the wreckage of the first one.
        second = machine.run(
            f"/usr/libexec/phoenix-restore {state['point']}", timeout=900
        )
        ctx.evidence.write_text(
            "interrupted-second-restore.log",
            f"exit={second['exitcode']}\n\n{second['stdout']}\n{second['stderr']}\n",
        )
        ctx.check(
            "a restore attempted after the power cut either succeeds or refuses "
            "out loud",
            second["exitcode"] == 0
            or "phoenix-restore:" in (second["stdout"] + second["stderr"]),
            f"exit {second['exitcode']}: "
            f"{(second['stdout'] + second['stderr']).strip()[:200]}",
        )
        if second["exitcode"] == 0:
            machine.reboot(float(ctx.options.get("boot_timeout", 900)))
            recovered_generation = ctx.observe(
                "generation_after_second_restore", _marker_state(machine, state)
            )
            ctx.check(
                "the restore that follows the power cut lands the Point it names",
                recovered_generation == "restored",
                f"booted generation: {recovered_generation}",
            )
        ctx.snap(machine, "interrupted-post-crash.png")
    finally:
        try:
            machine.shutdown()
        finally:
            ctx.collect_machine_evidence(machine, "interrupted-second")


# --- UPGRADE ------------------------------------------------------------------


def case_upgrade(ctx: Context) -> None:
    """Upgrade an installed previous release to the release under test.

    Requires a previous-release installed image. There is no honest way to
    synthesise one from the artifact under test, so without it this case is
    BLOCKED, never assumed.
    """
    base = ctx.options.get("upgrade_base_image")
    if not base:
        ctx.blocked(
            "no previous-release installed image supplied (--upgrade-base-image). "
            "The 3.5.0 QA base this tree's existing upgrade clones are layered on "
            "(~/projects/shadowfetch-3.5.0/work/qa-3.5.0/vm/bios-fire-2af853b1/"
            "disk.qcow2) no longer exists on this host, so every one of those "
            "clones is unopenable. Rebuild or restore a 3.5.0 installed image "
            "before this case can run."
        )
    base_path = Path(base).resolve()
    if not base_path.is_file():
        ctx.blocked(f"previous-release base image does not exist: {base_path}")

    repo = ctx.options.get("upgrade_repo")
    if not repo:
        ctx.blocked(
            "no package source supplied (--upgrade-repo). The upgrade must "
            "install the packages built from the artifact under test, not "
            "whatever a network mirror happens to serve."
        )

    machine = ctx.guest("upgrade", firmware=ctx.options.get("firmware", "bios"))
    provenance = machine.clone_disk(base_path)
    ctx.evidence.write_json("upgrade-base-provenance.json", provenance)
    machine.boot("installed", note="previous release before upgrade")
    try:
        machine.wait_agent(float(ctx.options.get("boot_timeout", 900)))
        before = system_report(machine)
        ctx.evidence.write_json("upgrade-before.json", before)
        previous = ctx.options.get("upgrade_from_version", "")
        ctx.check(
            "base system is the previous release",
            bool(previous) and before["version_marker"] == previous,
            f"version marker {before['version_marker']!r}, expected {previous!r}",
        )
        if before["version_marker"] == ctx.options["version"]:
            ctx.blocked(
                "the supplied base image is already the release under test; an "
                "upgrade case run on it would prove nothing"
            )

        home = machine.out("getent passwd 1000 | cut -d: -f6") or "/root"
        keepsake = f"{home}/vm-acceptance-user-data.txt"
        content = f"user data that must survive the upgrade {time.time()}"
        machine.run(f"printf %s {shlex.quote(content)} > {shlex.quote(keepsake)}", check=True)
        digest = machine.out(f"sha256sum {shlex.quote(keepsake)} | cut -d' ' -f1")

        install = machine.run(
            "DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=180 "
            f"--no-remove -y install {repo}",
            timeout=3600,
        )
        ctx.evidence.write_text(
            "upgrade-apt.log",
            f"exit={install['exitcode']}\n\n{install['stdout']}\n{install['stderr']}\n",
        )
        ctx.check(
            "the upgrade installs without removing packages",
            install["exitcode"] == 0
            and not any(
                line.startswith("Remv ") for line in install["stdout"].splitlines()
            ),
            f"apt-get exit {install['exitcode']}",
        )
        machine.reboot(float(ctx.options.get("boot_timeout", 900)))
        after = system_report(machine)
        after["settled_state"] = _settle_system(machine)
        after["system_state"] = after["settled_state"] or after["system_state"]
        ctx.evidence.write_json("upgrade-after.json", after)
        ctx.check(
            "the upgraded system is the release under test",
            after["version_marker"] == ctx.options["version"],
            f"version marker {after['version_marker']!r}",
        )
        ctx.check(
            "user data survives the upgrade byte for byte",
            machine.out(f"sha256sum {shlex.quote(keepsake)} | cut -d' ' -f1") == digest,
        )
        ctx.check(
            "the machine identity is preserved across the upgrade",
            after["machine_id"] == before["machine_id"],
        )
        ctx.check(
            "the upgraded system's package database is consistent",
            after["dpkg_audit"] == "",
            after["dpkg_audit"][:300] or "dpkg --audit is clean",
        )
        ctx.check(
            "the upgraded system reaches a running state",
            after["system_state"] in ("running", "degraded"),
            f"systemctl is-system-running = {after['system_state']!r}",
        )
        ctx.snap(machine, "upgrade-after.png")
    finally:
        try:
            machine.shutdown()
        finally:
            ctx.collect_machine_evidence(machine, "upgrade")


# --- INSTALL ------------------------------------------------------------------
#
# WHY THIS CASE IS DRIVEN THROUGH ACCESSIBILITY, AND WHAT HAD TO BE FIXED FIRST.
#
# The installer is driven through the guest's AT-SPI bus so that every step
# asserts WHICH page it is acting on before it acts on it. Blind keystrokes
# into a wizard prove nothing: they can "succeed" against a dialog that is not
# the one anybody thinks it is.
#
# Two obstacles stood in the way. The second is the one that blocked this case
# through five consecutive runs with "expected exactly one 'calamares'
# application, found 0".
#
# 1. pkexec. The desktop launcher `calamares-install-debian` runs xhost and
#    then pkexec, and pkexec cannot be authorised without a human at the
#    keyboard: through the guest agent it answers "Error executing command as
#    another user: Not authorized" and nothing starts. The harness starts
#    /usr/bin/calamares directly as root instead. Say plainly what that costs:
#    this case covers the INSTALLER, not the polkit path a user takes to reach
#    it.
#
# 2. A root process cannot use the live user's D-Bus session bus AT ALL, and
#    that -- not the toolkit, not the environment -- is why the installer never
#    appeared on the bus. Measured inside the 4.0.0 live session: connecting to
#    unix:path=/run/user/1000/bus as uid 0 is dropped at EXTERNAL
#    authentication ("org.freedesktop.DBus.Error.NoReply: Did not receive a
#    reply"), and the running installer holds exactly two sockets, one to the
#    Wayland compositor and none to any accessibility bus. Qt's AT-SPI bridge
#    (compiled into libQt6Gui here, not a loadable plugin) attaches only after
#    it can read org.a11y.Status from a session bus, so with no session bus
#    there is no bridge, no registration, and no "calamares" on anybody's
#    accessibility bus. Setting QT_ACCESSIBILITY, or switching
#    org.a11y.Status.IsEnabled on for the SESSION USER, cannot help: both fix
#    an obstacle the root process never reaches.
#
#    So the installer is given a session bus of its own uid -- a private
#    dbus-daemon started as root, on which org.a11y.Bus activates a root-owned
#    at-spi bus and registry -- and the driver reads that same bus. Nothing
#    about the installer is faked or bypassed: it is the shipped binary, on the
#    live session's real compositor, doing a real install of the artifact under
#    test to a real disk that is then booted.

ATSPI_PATH = "/tmp/sf-atspi-driver.py"
A11Y_RUNTIME = "/run/sf-acceptance-a11y"

ATSPI_DRIVER = r'''#!/usr/bin/env python3
"""Read and act on one application's accessible controls.

Runs inside the guest, as the uid that owns the accessibility bus it is given.

Every selector must resolve to EXACTLY ONE showing control of the named role.
An ambiguous selector is an error and never a guess: on the summary page
"Install" is both the sidebar step and the button that starts the installation,
and a driver that quietly picked one of them would be asserting nothing about
which one it pressed.
"""
import json
import re
import sys

import dbus

ACC = "org.a11y.atspi.Accessible"
PROP = "org.freedesktop.DBus.Properties"
ACTION = "org.a11y.atspi.Action"
TEXT = "org.a11y.atspi.Text"
COMPONENT = "org.a11y.atspi.Component"

ROLES = {7: "checkbox", 11: "combo", 16: "dialog", 20: "filler", 23: "frame",
         26: "icon", 27: "image", 29: "label", 30: "layered", 31: "list",
         32: "listitem", 33: "menu", 35: "menuitem", 37: "tab", 38: "tablist",
         39: "panel", 40: "password", 42: "progress", 43: "button",
         44: "radio", 46: "rootpane", 48: "scrollbar", 49: "scrollpane",
         51: "slider", 52: "spin", 53: "split", 55: "table", 56: "cell",
         61: "text", 62: "toggle", 65: "tree", 66: "treetable", 68: "viewport",
         69: "window", 75: "application", 79: "entry", 83: "heading",
         84: "page", 85: "section", 91: "treeitem"}
STATES = {1: "active", 4: "checked", 6: "defunct", 7: "editable", 8: "enabled",
          10: "expanded", 11: "focusable", 12: "focused", 16: "modal",
          20: "pressed", 23: "selected", 24: "sensitive", 25: "showing",
          30: "visible", 39: "default", 41: "checkable"}
# A closed combo box still reports its popup list as showing, so walking into
# one would put sixty language names on every page snapshot.
COLLAPSED = (11,)


def fail(message):
    sys.stderr.write(message + "\n")
    raise SystemExit(1)


def normalise(value):
    """Compare what a person reads, not what the toolkit stores.

    Calamares labels its partitioning choices in rich text, so the accessible
    name of the erase-disk option is a paragraph of HTML. Tags become spaces
    rather than vanishing, so that "<b>Erase</b>disk" cannot be made to match
    "Erasedisk".
    """
    value = re.sub(r"<[^>]+>", " ", value).replace("&", "")
    return re.sub(r"\s+", " ", value).strip().rstrip(".").casefold()


def states_of(obj):
    """AT-SPI reports states as a two-word bitfield, not a list of numbers."""
    words = [int(word) for word in obj.GetState(dbus_interface=ACC)]
    bits = words[0] | (words[1] << 32) if len(words) > 1 else words[0]
    return sorted(name for bit, name in STATES.items() if bits & (1 << bit))


def connect():
    session = dbus.SessionBus()
    status = session.get_object("org.a11y.Bus", "/org/a11y/bus")
    return dbus.bus.BusConnection(
        str(status.GetAddress(dbus_interface="org.a11y.Bus")))


def applications(bus):
    registry = bus.get_object("org.a11y.atspi.Registry",
                              "/org/a11y/atspi/accessible/root")
    found = []
    for name, path in registry.GetChildren(dbus_interface=ACC):
        try:
            obj = bus.get_object(name, path)
            label = str(obj.Get(ACC, "Name", dbus_interface=PROP))
        except dbus.DBusException:
            continue
        found.append((label, str(name), str(path)))
    return found


def walk(bus, name, path, depth, out, limit=2000):
    if depth > 30 or len(out) >= limit:
        return
    try:
        obj = bus.get_object(name, path)
        role = int(obj.GetRole(dbus_interface=ACC))
        out.append({
            "depth": depth,
            "role": ROLES.get(role, str(role)),
            "role_id": role,
            "name": str(obj.Get(ACC, "Name", dbus_interface=PROP)),
            "description": str(obj.Get(ACC, "Description", dbus_interface=PROP)),
            "states": states_of(obj),
            "bus": name,
            "path": path,
        })
        if role in COLLAPSED:
            return
        for child, childpath in obj.GetChildren(dbus_interface=ACC):
            walk(bus, str(child), str(childpath), depth + 1, out, limit)
    except dbus.DBusException:
        return


def select(nodes, role, by, value, index, expect):
    key = "description" if by == "desc" else "name"
    matches = [node for node in nodes
               if node["role"] == role
               and "showing" in node["states"]
               and normalise(node[key]).startswith(normalise(value))]
    if len(matches) != expect:
        fail("expected %d showing %s matching %s %r, found %d: %s"
             % (expect, role, by, value, len(matches),
                json.dumps([(m["name"][:60], m["states"]) for m in matches])))
    return matches[index]


bus = connect()
app_name = sys.argv[1]
mode = sys.argv[2]
present = applications(bus)
if mode == "apps":
    print(json.dumps({"applications": sorted(label for label, _, _ in present)},
                     indent=2))
    raise SystemExit(0)

wanted = [entry for entry in present if entry[0] == app_name]
if len(wanted) != 1:
    fail("expected exactly one %r application on the accessibility bus, found "
         "%d among %r" % (app_name, len(wanted),
                          sorted(label for label, _, _ in present)))
nodes = []
walk(bus, wanted[0][1], wanted[0][2], 0, nodes)

if mode == "dump":
    print(json.dumps(nodes, indent=2))
    raise SystemExit(0)
if mode == "page":
    # What a person can see right now. Qt keeps every wizard page in the widget
    # tree and marks only the current one as showing, so this is the page's own
    # account of itself -- not a guess from a screenshot, and not the step the
    # harness believes it asked for.
    print(json.dumps({"showing": [
        {"role": node["role"], "name": node["name"],
         "description": node["description"], "states": node["states"]}
        for node in nodes
        if "showing" in node["states"] and node["depth"] > 0
        and (node["name"] or node["description"]
             or node["role"] in ("progress", "entry", "text", "password"))
    ]}, indent=2))
    raise SystemExit(0)

role, by, value = sys.argv[3], sys.argv[4], sys.argv[5]
index = int(sys.argv[6]) if len(sys.argv) > 6 else 0
expect = int(sys.argv[7]) if len(sys.argv) > 7 else 1
match = select(nodes, role, by, value, index, expect)
obj = bus.get_object(match["bus"], match["path"])

if mode == "control":
    print(json.dumps({"name": match["name"], "description": match["description"],
                      "states": match["states"]}))
elif mode == "click":
    if "sensitive" not in match["states"]:
        fail("refusing to act on an insensitive %s %r: states %s"
             % (role, value, match["states"]))
    result = bool(obj.DoAction(0, dbus_interface=ACTION, timeout=20))
    print(json.dumps({"clicked": match["name"][:120], "result": result,
                      "states_before": match["states"]}))
elif mode == "focus":
    grabbed = bool(obj.GrabFocus(dbus_interface=COMPONENT, timeout=20))
    print(json.dumps({"grabbed": grabbed, "states": states_of(obj)}))
elif mode == "text":
    print(json.dumps({"text": str(obj.GetText(0, -1, dbus_interface=TEXT,
                                              timeout=20)),
                      "states": states_of(obj)}))
else:
    fail("unknown mode %r" % mode)
'''

# The account the installer is told to create. Every character here has to be
# typeable as a QEMU key name, and the installed system is checked for exactly
# this account afterwards: it is the end-to-end proof that what was typed into
# the accessible fields is what the installer wrote to the disk.
INSTALL_ACCOUNT = {
    "fullname": "QA Acceptance",
    "username": "qa",
    "hostname": "sf-acceptance",
    "password": "acceptance4000",
}

# The users page's three line edits carry no accessible name at all, so they
# are told apart by the hint Calamares shows under each one -- the same thing a
# person reads. Matching them by position in the layout would silently survive
# a reordering of the page, which is exactly the kind of "it passed" this
# harness exists to prevent. The two password fields are indistinguishable by
# description because they say the same thing; they take the same value, and
# the count is asserted (exactly two) so a third one appearing is an error.
USER_FIELDS = (
    ("fullname", "text", "Your Full Name", 1, 0),
    ("username", "text", "<small>If more than one person", 1, 0),
    ("hostname", "text", "<small>This name will be used", 1, 0),
    ("password", "password", "<small>Enter the same password twice", 2, 0),
    ("confirm", "password", "<small>Enter the same password twice", 2, 1),
)

QEMU_KEYS = {" ": "spc", "-": "minus", ".": "dot", "_": "shift-minus",
             "/": "slash", "@": "shift-2"}


def _keys_for(text: str) -> list[str]:
    """QEMU key names for a string, or an error. Never a silent substitution."""
    keys = []
    for char in text:
        if char.islower() or char.isdigit():
            keys.append(char)
        elif char.isupper():
            keys.append("shift-" + char.lower())
        elif char in QEMU_KEYS:
            keys.append(QEMU_KEYS[char])
        else:
            raise GuestError(f"no QEMU key name for {char!r}")
    return keys


def _plain(value: str) -> str:
    """The visible text of a rich-text accessible name."""
    import re as _re

    return _re.sub(r"\s+", " ", _re.sub(r"<[^>]+>", " ", value)).strip()


def _live_session(ctx: Context, machine: Guest) -> dict[str, str]:
    """Find the live desktop session to drive. Observed, not assumed."""
    probe = machine.run(
        "for p in $(pgrep -x plasmashell); do "
        "u=$(stat -c %U /proc/$p); i=$(stat -c %u /proc/$p); "
        "d=$(tr '\\0' '\\n' < /proc/$p/environ | sed -n 's/^DISPLAY=//p' | head -1); "
        "w=$(tr '\\0' '\\n' < /proc/$p/environ | sed -n 's/^WAYLAND_DISPLAY=//p' | head -1); "
        "printf '%s\\t%s\\t%s\\t%s\\n' \"$u\" \"$i\" \"$d\" \"$w\"; done",
        timeout=120,
    )
    rows = [line.split("\t") for line in probe["stdout"].strip().splitlines() if line]
    if len(rows) != 1:
        ctx.blocked(
            "expected exactly one live desktop session to drive, found "
            f"{len(rows)}: {probe['stdout'].strip()[:300]!r}"
        )
    user, uid, display, wayland = (rows[0] + ["", "", "", ""])[:4]
    return {
        "user": user,
        "uid": uid,
        "display": display,
        "wayland_display": wayland,
    }


def _installer_bus(ctx: Context, machine: Guest) -> str:
    """Give the root installer a session bus, and an accessibility bus on it.

    See the note at the top of this section: without this the installer runs
    perfectly and is invisible to every accessibility client, which reads
    exactly like "the installer failed to start".
    """
    machine.run(f"rm -rf {A11Y_RUNTIME}", timeout=60)
    machine.run(f"mkdir -p {A11Y_RUNTIME} && chmod 700 {A11Y_RUNTIME}", check=True)
    started = machine.run(
        f"/usr/bin/env XDG_RUNTIME_DIR={A11Y_RUNTIME} HOME=/root "
        "/usr/bin/dbus-daemon --session --fork --print-address "
        f"--address=unix:path={A11Y_RUNTIME}/bus",
        timeout=120,
    )
    address = started["stdout"].strip().splitlines()[-1].strip() if started["stdout"] else ""
    if started["exitcode"] != 0 or not address.startswith("unix:"):
        ctx.blocked(
            "could not start a session bus for the installer (dbus-daemon exit "
            f"{started['exitcode']}): "
            f"{(started['stdout'] + started['stderr']).strip()[:300]}"
        )
    environment = (
        f"DBUS_SESSION_BUS_ADDRESS={shlex.quote(address)} "
        f"XDG_RUNTIME_DIR={A11Y_RUNTIME} HOME=/root "
    )
    # Setting IsEnabled both switches toolkit accessibility on and activates
    # org.a11y.Bus on this private bus, which starts the at-spi bus and registry
    # as root. Qt attaches its bridge at construction, so this has to happen
    # before the installer starts.
    machine.run(
        f"/usr/bin/env {environment}/usr/bin/dbus-send --session --print-reply "
        "--dest=org.a11y.Bus /org/a11y/bus org.freedesktop.DBus.Properties.Set "
        "string:org.a11y.Status string:IsEnabled variant:boolean:true",
        timeout=120,
    )
    state = machine.run(
        f"/usr/bin/env {environment}/usr/bin/dbus-send --session --print-reply "
        "--dest=org.a11y.Bus /org/a11y/bus org.freedesktop.DBus.Properties.Get "
        "string:org.a11y.Status string:IsEnabled; "
        f"/usr/bin/env {environment}/usr/bin/dbus-send --session --print-reply "
        "--dest=org.a11y.Bus /org/a11y/bus org.a11y.Bus.GetAddress",
        timeout=120,
    )
    ctx.evidence.write_text(
        "install-accessibility.log",
        f"$ dbus-daemon --session --address=unix:path={A11Y_RUNTIME}/bus\n"
        f"{address}\n\n$ dbus-send ... org.a11y.Status IsEnabled / GetAddress\n"
        f"exit={state['exitcode']}\n{state['stdout']}\n{state['stderr']}\n\n"
        "processes:\n"
        + machine.out("ps -eo user:10,pid,args | grep -E 'at-spi|dbus-daemon' "
                      "| grep -v grep"),
    )
    ctx.check(
        "toolkit accessibility is switched on for the installer's own session",
        "boolean true" in state["stdout"] and "at-spi" in state["stdout"],
        _plain(state["stdout"])[:200],
    )
    ctx.observe("installer_a11y_bus", address)
    return address


def _driver(
    ctx: Context,
    machine: Guest,
    bus: str,
    *args: str,
    timeout: float = 240,
) -> dict:
    command = (
        f"/usr/bin/env DBUS_SESSION_BUS_ADDRESS={shlex.quote(bus)} "
        f"XDG_RUNTIME_DIR={A11Y_RUNTIME} HOME=/root LC_ALL=C.UTF-8 "
        f"/usr/bin/python3 {ATSPI_PATH} "
        + " ".join(shlex.quote(argument) for argument in args)
    )
    return machine.run(command, timeout=timeout)


def _page(ctx: Context, machine: Guest, bus: str, timeout: float = 240) -> list[dict]:
    result = _driver(ctx, machine, bus, "calamares", "page", timeout=timeout)
    if result["exitcode"] != 0:
        raise GuestError(
            "could not read the installer's accessible page: "
            f"{(result['stdout'] + result['stderr']).strip()[:400]}"
        )
    return json.loads(result["stdout"])["showing"]


def _visible(page: list[dict], role: str, text: str) -> bool:
    needle = text.casefold()
    return any(
        node["role"] == role and needle in _plain(node["name"]).casefold()
        for node in page
    )


def _labels(page: list[dict]) -> str:
    return " | ".join(
        _plain(node["name"]) for node in page
        if node["role"] in ("label", "heading") and node["name"]
    )


def _await_page(
    ctx: Context,
    machine: Guest,
    bus: str,
    name: str,
    markers: tuple[tuple[str, str], ...],
    timeout: float = 90,
) -> list[dict]:
    """Wait for a page that carries every one of its markers, then assert it.

    The check is on the page's own controls, so "the installer advanced" cannot
    be satisfied by a screenshot that happens to look right, by the step the
    harness asked for, or by a page that merely stopped changing.
    """
    deadline = time.monotonic() + timeout
    page: list[dict] = []
    while time.monotonic() < deadline:
        page = _page(ctx, machine, bus)
        if all(_visible(page, role, text) for role, text in markers):
            break
        time.sleep(3)
    ctx.evidence.write_json(f"install-page-{name}.json", page)
    missing = [text for role, text in markers if not _visible(page, role, text)]
    ctx.check(
        f"the installer is on its {name} page",
        not missing,
        f"missing {missing!r}; showing: {_labels(page)[:300]}"
        if missing else _labels(page)[:300],
    )
    if missing:
        ctx.blocked(
            f"the installer never reached its {name} page (missing {missing!r}). "
            "Acting on an unidentified page would prove nothing, so the run "
            f"stops here. What was on screen: {_labels(page)[:400]}"
        )
    return page


def _click(ctx: Context, machine: Guest, bus: str, role: str, name: str) -> dict:
    result = _driver(ctx, machine, bus, "calamares", "click", role, "name", name)
    if result["exitcode"] != 0:
        ctx.blocked(
            f"could not press the {role} named {name!r}: "
            f"{(result['stdout'] + result['stderr']).strip()[:300]}"
        )
    ctx.log(f"pressed {role} {name!r}: {result['stdout'].strip()[:160]}")
    return json.loads(result["stdout"])


def _control(
    ctx: Context, machine: Guest, bus: str, role: str, name: str
) -> list[str]:
    result = _driver(ctx, machine, bus, "calamares", "control", role, "name", name)
    if result["exitcode"] != 0:
        return []
    return list(json.loads(result["stdout"])["states"])


def _type_into(
    ctx: Context, machine: Guest, bus: str, field: tuple, text: str
) -> dict:
    """Focus a field through accessibility, type real keys, read it back.

    Setting the text through AT-SPI's EditableText interface DOES land the
    characters, and Calamares ignores them. Measured on 4.0.0: all five fields
    set that way, all five reading back correctly, and the Next button still
    insensitive -- the users page listens for QLineEdit::textEdited, the signal
    that means a person typed. One real keystroke enabled it.

    So the keys are real (QEMU's own input device, the path a physical keyboard
    takes) while every assertion stays on the accessibility bus: focus is
    verified before typing, and the content is read back after. A password
    field reads back as bullets, so for those the character count is what can
    honestly be compared.
    """
    name, role, hint, expect, index = field
    for attempt in range(1, 4):
        focus = _driver(
            ctx, machine, bus, "calamares", "focus", role, "desc", hint,
            str(index), str(expect),
        )
        if focus["exitcode"] != 0:
            ctx.blocked(
                f"could not find the {name} field on the users page: "
                f"{(focus['stdout'] + focus['stderr']).strip()[:300]}"
            )
        if "focused" not in json.loads(focus["stdout"])["states"]:
            ctx.log(f"{name}: focus not taken on attempt {attempt}")
            time.sleep(1.0)
            continue
        machine.sendkeys(["ctrl-a", "delete"] + _keys_for(text))
        time.sleep(0.8)
        read = _driver(
            ctx, machine, bus, "calamares", "text", role, "desc", hint,
            str(index), str(expect),
        )
        content = json.loads(read["stdout"])["text"] if read["exitcode"] == 0 else ""
        landed = (
            len(content) == len(text) if role == "password" else content == text
        )
        if landed:
            return {"field": name, "attempts": attempt,
                    "read_back": len(content) if role == "password" else content}
        ctx.log(f"{name}: read back {content!r} after attempt {attempt}")
        time.sleep(1.0)
    ctx.check(
        f"the {name} field holds what was typed into it",
        False,
        f"after 3 attempts the field did not hold the typed value",
    )
    return {"field": name, "attempts": 3, "read_back": None}


def _settle_system(machine: Guest, seconds: float = 300) -> str:
    """Wait for systemd to finish starting before judging the system state.

    A freshly installed system answers the guest agent while it is still
    running its first-boot units, and `systemctl is-system-running` says
    "starting". That is not a degraded system and not a healthy one: it is the
    question asked too early. Measured on the first install this harness drove:
    the agent answered at 45s and systemd reached "running" well after.
    """
    deadline = time.monotonic() + seconds
    state = ""
    while time.monotonic() < deadline:
        state = machine.out("systemctl is-system-running 2>&1")
        if state in ("running", "degraded"):
            return state
        time.sleep(5)
    return state


def _installed_report(ctx: Context, machine: Guest, prefix: str) -> dict:
    settled = _settle_system(machine)
    report = system_report(machine)
    report["settled_state"] = settled
    report["efi"] = machine.out("test -d /sys/firmware/efi && echo yes || echo no")
    report["account"] = machine.out(
        f"getent passwd {shlex.quote(INSTALL_ACCOUNT['username'])} || echo MISSING"
    )
    report["hostname"] = machine.out("cat /etc/hostname 2>/dev/null")
    report["home"] = machine.out(
        f"test -d /home/{shlex.quote(INSTALL_ACCOUNT['username'])} && echo yes || echo no"
    )
    report["root_source"] = machine.out("findmnt -no SOURCE /")
    ctx.evidence.write_json(f"{prefix}-installed-report.json", report)
    return report


def _check_installed_system(
    ctx: Context, machine: Guest, report: dict, firmware: str, label: str
) -> None:
    """Everything INSTALL-01 claims about a fresh install, checked on the disk."""
    ctx.check(
        f"{label}: the installed system boots from disk, not from the live medium",
        "boot=live" not in report["cmdline"] and bool(report["root_source"]),
        f"root {report['root_source']!r}; cmdline {report['cmdline'][:120]}",
    )
    ctx.check(
        f"{label}: the installed system reports the release version",
        report["version_marker"] == ctx.options["version"],
        f"version marker {report['version_marker']!r}",
    )
    ctx.check(
        f"{label}: the installed system booted through the "
        f"{'UEFI' if firmware == 'uefi' else 'BIOS'} firmware it was installed under",
        report["efi"] == ("yes" if firmware == "uefi" else "no"),
        f"/sys/firmware/efi present: {report['efi']}",
    )
    ctx.check(
        f"{label}: the account typed into the installer exists on the installed "
        "system",
        report["account"].startswith(INSTALL_ACCOUNT["username"] + ":")
        and INSTALL_ACCOUNT["fullname"] in report["account"]
        and report["home"] == "yes",
        report["account"][:200],
    )
    ctx.check(
        f"{label}: the host name typed into the installer is the installed "
        "system's host name",
        report["hostname"] == INSTALL_ACCOUNT["hostname"],
        f"/etc/hostname = {report['hostname']!r}",
    )
    ctx.check(
        f"{label}: the installed system's package database is consistent",
        report["dpkg_audit"] == "",
        report["dpkg_audit"][:300] or "dpkg --audit is clean",
    )
    ctx.check(
        f"{label}: the installed system reaches a running state",
        report["system_state"] in ("running", "degraded"),
        f"systemctl is-system-running = {report['system_state']!r}"
        + (f"; failed units: {report['failed_units']}" if report["failed_units"] else ""),
    )


def case_install(ctx: Context) -> None:
    """Install the artifact to a blank disk with Calamares, then boot it.

    Every step asserts which page it is acting on before acting, through the
    installer's own accessible controls. Anything unrecognised stops the run as
    BLOCKED with the observed page recorded -- never a guess, and never a pass.
    """
    iso = Path(ctx.artifact["path"])
    firmware = ctx.options.get("firmware", "bios")
    machine = ctx.guest("install", firmware=firmware)
    machine.create_disk(int(ctx.options.get("disk_gib", 40)))
    ctx.observe("installed_disk", str(machine.disk))
    machine.boot("live", iso=iso, note="live boot for installation")
    try:
        machine.wait_agent(float(ctx.options.get("boot_timeout", 900)))
        live = system_report(machine)
        ctx.evidence.write_json("install-live-report.json", live)
        ctx.check(
            "installation starts from the live artifact under test",
            "boot=live" in live["cmdline"]
            and live["version_marker"] == ctx.options["version"],
            f"version marker {live['version_marker']!r}",
        )
        settle = float(ctx.options.get("desktop_settle", 120))
        ctx.log(f"waiting {settle:.0f}s for the live desktop session")
        time.sleep(settle)

        session = _live_session(ctx, machine)
        ctx.observe("live_session", session)
        push_script(machine, ATSPI_PATH, ATSPI_DRIVER)
        bus = _installer_bus(ctx, machine)

        ctx.observe(
            "installer_launch_path",
            "started directly as root on a private session bus; the desktop's "
            "pkexec wrapper is not exercised and is not covered by this case",
        )
        launcher = ctx.options.get("installer_command", "/usr/bin/calamares")
        environment = (
            f"DBUS_SESSION_BUS_ADDRESS={shlex.quote(bus)} "
            f"XDG_RUNTIME_DIR={A11Y_RUNTIME} HOME=/root QT_ACCESSIBILITY=1 "
        )
        if session.get("wayland_display"):
            # An absolute socket path, because XDG_RUNTIME_DIR now points at the
            # installer's own runtime directory rather than the session user's.
            environment += (
                f"WAYLAND_DISPLAY=/run/user/{session['uid']}/"
                f"{session['wayland_display']} QT_QPA_PLATFORM=wayland "
            )
        elif session.get("display"):
            machine.run(
                f"/usr/sbin/runuser -u {shlex.quote(session['user'])} -- "
                f"/usr/bin/env DISPLAY={session['display']} "
                f"XDG_RUNTIME_DIR=/run/user/{session['uid']} "
                "/usr/bin/xhost +si:localuser:root",
                timeout=60,
            )
            environment += f"DISPLAY={session['display']} "
        machine.run(
            f"setsid /usr/bin/env {environment}{shlex.quote(launcher)} -d "
            ">/tmp/sf-installer.log 2>&1 & echo started",
            timeout=60,
        )

        appeared = None
        deadline = time.monotonic() + float(ctx.options.get("installer_settle", 180))
        while time.monotonic() < deadline:
            probe = _driver(ctx, machine, bus, "calamares", "page")
            if probe["exitcode"] == 0:
                appeared = json.loads(probe["stdout"])["showing"]
                break
            time.sleep(5)
        visible = _driver(ctx, machine, bus, "calamares", "apps")
        ctx.evidence.write_text(
            "install-atspi-applications.json",
            visible["stdout"] or visible["stderr"] or "(no output)",
        )
        ctx.snap(machine, "install-installer-launched.png")
        ctx.check(
            "the installer registers on the accessibility bus it is given",
            appeared is not None,
            "one 'calamares' application on the bus"
            if appeared is not None
            else "no 'calamares' application appeared; see "
            "install-atspi-applications.json and install-launcher.log",
        )
        if appeared is None:
            ctx.evidence.write_text(
                "install-launcher.log",
                f"$ {launcher}\n(guest /tmp/sf-installer.log)\n\n"
                + machine.out("cat /tmp/sf-installer.log 2>/dev/null")
                + "\n\nprocesses:\n"
                + machine.out("ps -eo user:16,pid,args | grep -i calamares "
                              "| grep -v grep"),
            )
            ctx.blocked(
                "the installer never appeared on the accessibility bus, so no "
                "page could be identified before acting on it. Its own log and "
                "the applications the bus could see are recorded as evidence."
            )

        version = ctx.options["version"]
        _await_page(
            ctx, machine, bus, "welcome",
            (("label", f"Welcome to the Calamares installer for Shadowfetch "
                       f"Linux {version}"),
             ("button", "Next")),
        )
        ctx.snap(machine, "install-01-welcome.png")

        _click(ctx, machine, bus, "button", "Next")
        _await_page(ctx, machine, bus, "location",
                    (("label", "Region:"), ("label", "Zone:")))
        _click(ctx, machine, bus, "button", "Next")
        _await_page(ctx, machine, bus, "keyboard", (("label", "Keyboard model:"),))
        ctx.snap(machine, "install-02-keyboard.png")

        _click(ctx, machine, bus, "button", "Next")
        partition = _await_page(
            ctx, machine, bus, "partition",
            (("label", "Select storage device:"), ("radio", "Erase disk")),
        )
        ctx.snap(machine, "install-03-partition.png")
        devices = [node["name"] for node in partition if node["role"] == "combo"]
        ctx.observe("partition_page_devices", devices)
        ctx.check(
            "the partition page offers the machine's disk as the install target",
            any("/dev/vda" in name for name in devices),
            f"storage devices offered: {devices}",
        )
        expected_firmware = "EFI" if firmware == "uefi" else "BIOS"
        firmware_labels = [
            _plain(node["name"]) for node in partition
            if node["role"] == "label"
            and _plain(node["name"]).upper() in ("BIOS", "EFI", "UEFI")
        ]
        ctx.check(
            "the partition page reports the firmware the machine booted under",
            any(label.upper().startswith(expected_firmware)
                for label in firmware_labels),
            f"firmware labels on the page: {firmware_labels}, expected "
            f"{expected_firmware}",
        )
        ctx.check(
            "the installer refuses to go on before a partitioning choice is made",
            "sensitive" not in _control(ctx, machine, bus, "button", "Next"),
            "the Next button is insensitive on arrival at the partition page",
        )
        _click(ctx, machine, bus, "radio", "Erase disk")
        time.sleep(3)
        ctx.check(
            "choosing to erase the disk lets the installer go on",
            "sensitive" in _control(ctx, machine, bus, "button", "Next"),
            "the Next button became sensitive after the choice",
        )

        _click(ctx, machine, bus, "button", "Next")
        _await_page(ctx, machine, bus, "users",
                    (("label", "What is your name?"),
                     ("label", "What is the name of this computer?")))
        ctx.check(
            "the installer refuses to go on before the account is filled in",
            "sensitive" not in _control(ctx, machine, bus, "button", "Next"),
            "the Next button is insensitive on arrival at the users page",
        )
        typed = []
        for field in USER_FIELDS:
            value = INSTALL_ACCOUNT[
                "password" if field[0] == "confirm" else field[0]
            ]
            typed.append(_type_into(ctx, machine, bus, field, value))
        ctx.evidence.write_json("install-users-typed.json", typed)
        ctx.snap(machine, "install-04-users.png")
        ctx.check(
            "the installer accepts the account typed into it",
            "sensitive" in _control(ctx, machine, bus, "button", "Next"),
            "the Next button became sensitive once the account was complete",
        )

        _click(ctx, machine, bus, "button", "Next")
        summary = _await_page(
            ctx, machine, bus, "summary",
            (("label", "This is an overview of what will happen"),
             ("button", "Install")),
        )
        ctx.snap(machine, "install-05-summary.png")
        summary_text = _labels(summary)
        ctx.observe("summary", summary_text[:600])
        ctx.check(
            "the summary describes erasing this machine's disk and installing "
            "this release",
            "/dev/vda" in summary_text and version in summary_text,
            summary_text[:300],
        )
        table = "GPT" if firmware == "uefi" else "MSDOS"
        ctx.check(
            "the summary lays out the partition table this firmware requires",
            table.casefold() in summary_text.casefold(),
            f"expected a {table} partition table for {firmware}; summary says: "
            + summary_text[:300],
        )

        _click(ctx, machine, bus, "button", "Install")
        finished = _run_installation(ctx, machine, bus)
        ctx.snap(machine, "install-06-finished.png")
        ctx.evidence.write_text(
            "install-launcher.log",
            f"$ {launcher}\n(guest /tmp/sf-installer.log)\n\n"
            + machine.out("cat /tmp/sf-installer.log 2>/dev/null | tail -400")
            + "\n\ncalamares session log:\n"
            + machine.out("tail -400 /root/.cache/calamares/session.log 2>/dev/null"),
        )
        if not finished:
            return
        machine.shutdown()
        ctx.collect_machine_evidence(machine, "install-live")

        machine.boot("installed", note="first boot of the installed system")
        machine.wait_agent(float(ctx.options.get("boot_timeout", 900)))
        report = _installed_report(ctx, machine, "install")
        _check_installed_system(ctx, machine, report, firmware, "first boot")
        time.sleep(30)
        ctx.snap(machine, "install-07-installed-system.png")
    finally:
        try:
            machine.shutdown()
        finally:
            ctx.collect_machine_evidence(machine, "install")


def _run_installation(ctx: Context, machine: Guest, bus: str) -> bool:
    """Watch the installation run, and say honestly how it ended.

    Calamares reports its own outcome on the page it ends on: a finished page
    that says the installation is complete, or one that says it failed. Both are
    read here; neither is inferred from the absence of the other.
    """
    timeout = float(ctx.options.get("install_timeout", 5400))
    deadline = time.monotonic() + timeout
    started = time.monotonic()
    steps: list[str] = []
    shots = 0
    page: list[dict] = []
    while time.monotonic() < deadline:
        page = _page(ctx, machine, bus)
        labels = _labels(page)
        current = next(
            (_plain(node["name"]) for node in page
             if node["role"] == "label" and node["name"]),
            "",
        )
        if current and (not steps or steps[-1] != current):
            steps.append(current)
            ctx.log(f"installer: {current[:120]}")
            if shots < 4:
                ctx.snap(machine, f"install-progress-{shots}.png")
                shots += 1
        done = _visible(page, "button", "Done")
        failed = ("did not complete successfully" in labels
                  or "Installation Failed" in labels)
        if done or failed:
            elapsed = time.monotonic() - started
            ctx.observe("installation_seconds", round(elapsed, 1))
            ctx.observe("installer_steps", steps)
            ctx.evidence.write_json("install-page-finished.json", page)
            ctx.check(
                "the installation runs to completion and the installer says so",
                done and not failed
                and ("All done" in labels or "has been installed" in labels),
                _labels(page)[:300],
            )
            return bool(done and not failed)
        time.sleep(15)
    ctx.observe("installer_steps", steps)
    ctx.evidence.write_json("install-page-timeout.json", page)
    ctx.check(
        "the installation runs to completion and the installer says so",
        False,
        f"the installer was still on {steps[-1] if steps else 'no step'!r} after "
        f"{timeout:.0f}s",
    )
    return False


# --- INSTALL-01: both firmwares ------------------------------------------------


def case_install_both_firmwares(ctx: Context) -> None:
    """Boot the BIOS install and the UEFI install this artifact produced.

    INSTALL-01 is "Fresh BIOS and UEFI Calamares installs boot from disk": two
    firmwares. One install run proves one firmware, so recording INSTALL-01
    from a single run would claim the other. This case is what closes that gap
    honestly. It refuses to run unless the ledger holds a PASSING install of
    THIS artifact under each firmware, produced by THIS harness; then it boots
    the two disks those runs actually installed, one under each firmware, and
    checks the claim on both.

    It is not a paperwork case: nothing here reads a verdict and repeats it.
    The disks are booted again, in this process, and every check below is
    evaluated against a running machine.
    """
    ledger_path = ctx.work_root / "vm-acceptance" / "ledger.jsonl"
    ledger = Ledger(ledger_path)
    problems = ledger.verify()
    if problems:
        ctx.blocked(
            "the run ledger does not verify, so no run in it can be trusted to "
            "have happened: " + "; ".join(problems)
        )
    harness = harness_fingerprint(Path(__file__).resolve().parent)["digest"]
    legs = {}
    for firmware in ("bios", "uefi"):
        rows = ledger.find(
            case="install",
            verdict="PASS",
            firmware=firmware,
            artifact_sha256=ctx.artifact["sha256"],
        )
        if not rows:
            ctx.blocked(
                f"the ledger holds no PASSING {firmware} install of this "
                f"artifact ({ctx.artifact['sha256'][:12]}), so there is nothing "
                "to prove INSTALL-01's " + firmware + " half with. Run: "
                "vm_acceptance.py run --case install --firmware " + firmware
                + " --artifact " + ctx.artifact["name"]
            )
        legs[firmware] = rows[-1]

    disks = {}
    for firmware, row in legs.items():
        receipt_path = ctx.repo_root / row["receipt_path"]
        if not receipt_path.is_file():
            ctx.blocked(f"the {firmware} install's receipt is missing: {receipt_path}")
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        faults = receipt_problems(receipt)
        if receipt.get("receipt_sha256") != row["receipt_sha256"]:
            faults.append("the receipt digest differs from its ledger entry")
        for item in receipt.get("evidence", []):
            path = ctx.repo_root / item["relative_path"]
            if not path.is_file():
                faults.append(f"missing evidence {item['name']}")
            elif sha256_file(path) != item["sha256"]:
                faults.append(f"evidence changed since the run: {item['name']}")
        if faults:
            ctx.blocked(
                f"the {firmware} install run {row['run_id']} does not verify, so "
                "it cannot support INSTALL-01: " + "; ".join(faults)
            )
        ctx.check(
            f"the {firmware} install was produced by this harness",
            receipt["harness"]["digest"] == harness,
            f"run {row['run_id']} harness {receipt['harness']['digest'][:16]}, "
            f"this harness {harness[:16]}",
        )
        disk = Path(receipt.get("observations", {}).get("installed_disk", ""))
        if not disk.is_file():
            ctx.blocked(
                f"the disk the {firmware} install wrote is gone: {disk}. The "
                "install run has to be repeated."
            )
        disks[firmware] = {"run_id": row["run_id"], "disk": disk,
                           "receipt": str(receipt_path.relative_to(ctx.repo_root))}
        ctx.observe(f"{firmware}_install_run", row["run_id"])
    ctx.evidence.write_json(
        "install-both-provenance.json",
        {firmware: {**detail, "disk": str(detail["disk"])}
         for firmware, detail in disks.items()},
    )

    for firmware in ("bios", "uefi"):
        detail = disks[firmware]
        machine = ctx.guest(f"boot-{firmware}", firmware=firmware)
        provenance = machine.clone_disk(detail["disk"])
        ctx.evidence.write_json(f"install-both-{firmware}-base.json", provenance)
        variables = detail["disk"].parent / "OVMF_VARS_4M.fd"
        if firmware == "uefi" and variables.is_file():
            # The firmware state the install itself produced. A fresh NVRAM
            # would be testing the removable-media fallback rather than the boot
            # entry the installer wrote.
            (machine.directory / "OVMF_VARS_4M.fd").write_bytes(
                variables.read_bytes()
            )
        machine.boot("installed", note=f"re-boot of the {firmware} install")
        try:
            machine.wait_agent(float(ctx.options.get("boot_timeout", 900)))
            report = _installed_report(ctx, machine, f"install-both-{firmware}")
            _check_installed_system(ctx, machine, report, firmware, firmware)
            ctx.snap(machine, f"install-both-{firmware}.png")
        finally:
            try:
                machine.shutdown()
            finally:
                ctx.collect_machine_evidence(machine, f"install-both-{firmware}")



# --- RECOVERY-01: the project diff/undo half ----------------------------------

CHECKPOINT = "/usr/bin/shadowfetch-checkpoint"
PROJECT_WORKSPACE = "vm-acceptance"

WORKSPACE_MANIFEST = r'''#!/bin/sh
# Byte-for-byte state of a workspace: every file with its digest, sorted.
cd "$1" 2>/dev/null || { echo "WORKSPACE MISSING"; exit 1; }
/usr/bin/find . -type f | LC_ALL=C sort | while IFS= read -r file; do
  printf '%s  %s\n' "$(/usr/bin/sha256sum "$file" | cut -d' ' -f1)" "$file"
done
'''

MANIFEST_PATH = "/tmp/sf-workspace-manifest.sh"

# What the injected failure does to the workspace, and what a diff must then
# say about it. An agent that ran wild edits, deletes and adds; a file it did
# not touch must not appear in the diff at all.
PROJECT_DAMAGE = {
    "edit.txt": "M",
    "remove.txt": "-",
    "spill.txt": "+",
    "sub/deep.txt": "-",
}
PROJECT_UNTOUCHED = "keep.txt"


def _user_run(
    machine: Guest, user: str, home: str, command: str, timeout: float = 300
) -> dict:
    """Run a command as the desktop user, with that user's HOME.

    runuser without -l keeps the caller's environment, so HOME would still be
    root's and the checkpoint engine would look for ~/Workspaces in the wrong
    home.
    """
    return machine.run(
        f"/usr/sbin/runuser -u {shlex.quote(user)} -- /usr/bin/env "
        f"HOME={shlex.quote(home)} LC_ALL=C.UTF-8 /bin/sh -c {shlex.quote(command)}",
        timeout=timeout,
    )


def _require_passing_run(ctx: Context, ledger: Ledger, harness: str, **criteria) -> dict:
    """The receipt of an earlier PASSING run of this artifact, re-verified.

    Verified rather than trusted: the ledger chain, the receipt's own digest and
    every evidence byte are checked here, so a case that leans on an earlier run
    leans on one that still stands.
    """
    rows = ledger.find(
        verdict="PASS", artifact_sha256=ctx.artifact["sha256"], **criteria
    )
    if not rows:
        ctx.blocked(
            f"the ledger holds no PASSING run matching {criteria} against this "
            f"artifact ({ctx.artifact['sha256'][:12]}), so the other half of "
            "this release case is unproven and this run cannot stand in for it."
        )
    row = rows[-1]
    receipt_path = ctx.repo_root / row["receipt_path"]
    if not receipt_path.is_file():
        ctx.blocked(f"the receipt of run {row['run_id']} is missing: {receipt_path}")
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    faults = receipt_problems(receipt)
    if receipt.get("receipt_sha256") != row["receipt_sha256"]:
        faults.append("the receipt digest differs from its ledger entry")
    for item in receipt.get("evidence", []):
        path = ctx.repo_root / item["relative_path"]
        if not path.is_file():
            faults.append(f"missing evidence {item['name']}")
        elif sha256_file(path) != item["sha256"]:
            faults.append(f"evidence changed since the run: {item['name']}")
    if faults:
        ctx.blocked(
            f"run {row['run_id']} does not verify, so it cannot support this "
            "case: " + "; ".join(faults)
        )
    ctx.check(
        f"the {criteria.get('case')} run this case relies on was produced by "
        "this harness",
        receipt["harness"]["digest"] == harness,
        f"run {row['run_id']} harness {receipt['harness']['digest'][:16]}, this "
        f"harness {harness[:16]}",
    )
    ctx.observe(f"{criteria.get('case')}_run", row["run_id"])
    return receipt


def _diff_entries(output: str) -> dict[str, str]:
    """Parse `shadowfetch-checkpoint diff` into {path: marker}."""
    entries = {}
    for line in output.splitlines():
        stripped = line.strip()
        if len(stripped) > 2 and stripped[0] in "M+-" and stripped[1] == " ":
            entries[stripped[2:].strip()] = stripped[0]
    return entries


def case_recovery_project(ctx: Context) -> None:
    """RECOVERY-01's other half: project diff/undo after injected damage.

    The two Phoenix cases prove supported system rollback. RECOVERY-01 also says
    PROJECT DIFF/UNDO, which is Fireline's per-workspace checkpoint store: a
    different mechanism with a different blast radius, and nothing the rollback
    cases touch. This case proves that half against a running system, and
    refuses to run unless the ledger already holds the rollback half for the
    same artifact -- so the case that records RECOVERY-01 is the one that has
    seen both halves proven.
    """
    base = _recovery_base(ctx)
    ledger = Ledger(ctx.work_root / "vm-acceptance" / "ledger.jsonl")
    problems = ledger.verify()
    if problems:
        ctx.blocked(
            "the run ledger does not verify, so no run in it can be trusted to "
            "have happened: " + "; ".join(problems)
        )
    harness = harness_fingerprint(Path(__file__).resolve().parent)["digest"]
    for companion in ("recovery", "recovery-interrupted"):
        _require_passing_run(ctx, ledger, harness, case=companion)

    machine = ctx.guest(
        "recovery-project", firmware=ctx.options.get("firmware", "bios")
    )
    provenance = machine.clone_disk(base)
    ctx.observe("base_image", provenance["base_image"])
    ctx.evidence.write_json("project-base-provenance.json", provenance)
    machine.boot("installed", note="installed system for project diff/undo")
    try:
        machine.wait_agent(float(ctx.options.get("boot_timeout", 900)))
        report = system_report(machine)
        ctx.evidence.write_json("project-system-report.json", report)
        ctx.check(
            "the system under test is the release under test",
            report["version_marker"] == ctx.options["version"],
            f"version marker {report['version_marker']!r}",
        )
        user = machine.out("getent passwd 1000 | cut -d: -f1")
        home = machine.out("getent passwd 1000 | cut -d: -f6")
        if not user or not home:
            ctx.blocked("the base image has no uid 1000 desktop user to act as")
        ctx.observe("desktop_user", user)

        implementation = {
            "path": CHECKPOINT,
            "sha256": machine.out(f"sha256sum {CHECKPOINT} | cut -d' ' -f1"),
            "package_version": machine.out(
                "dpkg-query -W -f='${Version}' shadowfetch-fireline"
            ),
            "subcommands": machine.out(
                f"{CHECKPOINT} --help 2>&1 | sed -n 's/.*{{\\(.*\\)}}.*/\\1/p'"
            ),
            "engine_sha256": machine.out(
                "sha256sum /usr/lib/shadowfetch/mcp/sf_mcp.py | cut -d' ' -f1"
            ),
        }
        ctx.evidence.write_json("project-implementation.json", implementation)
        ctx.observe("checkpoint_sha256", implementation["sha256"])

        workspaces = f"{home}/Workspaces"
        owner = machine.out(
            f"stat -c %U {shlex.quote(workspaces)} 2>/dev/null || echo ABSENT"
        )
        # Recorded, not hidden: on the QA base image this directory ships owned
        # by root, and the checkpoint store lives inside it, so the desktop user
        # cannot take a checkpoint at all until the ownership is corrected. That
        # is a fact about the image, not about diff/undo, so the case fixes it,
        # says it did, and goes on to test the mechanism it is here to test.
        ctx.observe("workspaces_root_owner_before", owner)
        machine.run(
            f"mkdir -p {shlex.quote(workspaces)} && "
            f"chown {shlex.quote(user)}:{shlex.quote(user)} {shlex.quote(workspaces)}",
            check=True,
        )
        workspace = f"{workspaces}/{PROJECT_WORKSPACE}"
        push_script(machine, MANIFEST_PATH, WORKSPACE_MANIFEST)
        machine.run(
            f"rm -rf {shlex.quote(workspace)} && mkdir -p {shlex.quote(workspace)}/sub "
            f"&& chown -R {shlex.quote(user)}:{shlex.quote(user)} {shlex.quote(workspace)}",
            check=True,
        )
        _user_run(
            machine, user, home,
            f"cd {shlex.quote(workspace)} && printf keep > keep.txt && "
            "printf original > edit.txt && printf doomed > remove.txt && "
            "printf nested > sub/deep.txt",
        )
        # A canary outside the workspace: undo must not reach it.
        canary = f"{home}/vm-acceptance-canary.txt"
        _user_run(machine, user, home, f"printf canary > {shlex.quote(canary)}")
        before = _user_run(
            machine, user, home, f"/bin/sh {MANIFEST_PATH} {shlex.quote(workspace)}"
        )["stdout"].strip()
        ctx.evidence.write_text("project-workspace-before.txt", before + "\n")

        snapshot = _user_run(
            machine, user, home,
            f"{CHECKPOINT} snapshot {PROJECT_WORKSPACE} --label vm-acceptance",
            timeout=600,
        )
        listing = _user_run(
            machine, user, home, f"{CHECKPOINT} list {PROJECT_WORKSPACE}", timeout=300
        )
        point = ""
        for word in snapshot["stdout"].split():
            if len(word) == 22 and word[:8].isdigit() and word.count("-") == 2:
                point = word
        ctx.observe("checkpoint", point)
        ctx.evidence.write_text(
            "project-checkpoint.log",
            f"$ {CHECKPOINT} snapshot {PROJECT_WORKSPACE}\nexit="
            f"{snapshot['exitcode']}\n{snapshot['stdout']}{snapshot['stderr']}\n"
            f"$ {CHECKPOINT} list {PROJECT_WORKSPACE}\nexit={listing['exitcode']}\n"
            f"{listing['stdout']}{listing['stderr']}\n",
        )
        ctx.check(
            "the desktop user can take a project checkpoint of a workspace",
            snapshot["exitcode"] == 0 and bool(point)
            and point in listing["stdout"],
            f"snapshot exit {snapshot['exitcode']}, checkpoint {point!r}, listed: "
            f"{listing['stdout'].strip()[:200]}",
        )
        if not point:
            return

        # The injected failure: an agent that edited, deleted and added things.
        _user_run(
            machine, user, home,
            f"cd {shlex.quote(workspace)} && printf CORRUPTED > edit.txt && "
            "rm -f remove.txt && printf spill > spill.txt && rm -rf sub",
        )
        damaged = _user_run(
            machine, user, home, f"/bin/sh {MANIFEST_PATH} {shlex.quote(workspace)}"
        )["stdout"].strip()
        ctx.evidence.write_text("project-workspace-damaged.txt", damaged + "\n")
        ctx.check(
            "the injected failure really changed the workspace",
            damaged != before,
            "the workspace differs from its checkpoint before the undo",
        )

        diff = _user_run(
            machine, user, home,
            f"{CHECKPOINT} diff {PROJECT_WORKSPACE} {shlex.quote(point)}",
            timeout=300,
        )
        entries = _diff_entries(diff["stdout"])
        ctx.evidence.write_text(
            "project-diff.log",
            f"$ {CHECKPOINT} diff {PROJECT_WORKSPACE} {point}\n"
            f"exit={diff['exitcode']}\n{diff['stdout']}{diff['stderr']}\n",
        )
        ctx.check(
            "the diff names every change the injected failure made, and nothing "
            "else",
            diff["exitcode"] == 0 and entries == PROJECT_DAMAGE,
            f"diff reported {entries}, expected {PROJECT_DAMAGE}"
            + (f"; {PROJECT_UNTOUCHED} must not appear"
               if PROJECT_UNTOUCHED in entries else ""),
        )

        undo = _user_run(
            machine, user, home,
            f"{CHECKPOINT} undo {PROJECT_WORKSPACE} {shlex.quote(point)}",
            timeout=900,
        )
        ctx.evidence.write_text(
            "project-undo.log",
            f"$ {CHECKPOINT} undo {PROJECT_WORKSPACE} {point}\n"
            f"exit={undo['exitcode']}\n{undo['stdout']}{undo['stderr']}\n",
        )
        ctx.check(
            "the undo reports success",
            undo["exitcode"] == 0,
            f"exit {undo['exitcode']}: {(undo['stdout'] + undo['stderr']).strip()[:200]}",
        )
        after = _user_run(
            machine, user, home, f"/bin/sh {MANIFEST_PATH} {shlex.quote(workspace)}"
        )["stdout"].strip()
        ctx.evidence.write_text("project-workspace-after.txt", after + "\n")
        ctx.check(
            "the undone workspace is the checkpointed workspace, byte for byte",
            after == before,
            "every file and digest matches the pre-damage manifest"
            if after == before
            else f"after: {after[:200]!r} vs before: {before[:200]!r}",
        )
        confirm = _user_run(
            machine, user, home,
            f"{CHECKPOINT} diff {PROJECT_WORKSPACE} {shlex.quote(point)}",
            timeout=300,
        )
        ctx.check(
            "the tool itself reports no remaining difference after the undo",
            confirm["exitcode"] == 0 and not _diff_entries(confirm["stdout"]),
            confirm["stdout"].strip()[:200],
        )
        outside = machine.out(f"cat {shlex.quote(canary)} 2>/dev/null || echo GONE")
        ctx.check(
            "the undo touched nothing outside the workspace it names",
            outside == "canary",
            f"the file beside the workspace root reads {outside!r}",
        )
        ctx.snap(machine, "project-desktop.png")
    finally:
        try:
            machine.shutdown()
        finally:
            ctx.collect_machine_evidence(machine, "project")

# --- registry -----------------------------------------------------------------


class Case:
    """One acceptance case, and exactly how much of a release case it proves.

    `manifest_gap` is the honest half of `manifest_case`. A case may contribute
    to a required release case without proving all of it, and the difference
    has to be ENFORCED rather than noted: with a gap recorded here, the harness
    refuses to record that case as passed no matter how many checks the run
    evaluated. Writing "pass" against a case whose other half nobody ran is the
    exact failure this whole stage exists to make impossible.
    """

    def __init__(
        self,
        name: str,
        run: Callable[[Context], None],
        *,
        summary: str,
        manifest_case: str | None = None,
        manifest_gap: str | None = None,
        companions: tuple[str, ...] = (),
        required_runs: tuple[dict[str, Any], ...] = (),
        consumes_artifact: bool = True,
        minutes: int = 10,
    ) -> None:
        self.name = name
        self.run = run
        self.summary = summary
        self.manifest_case = manifest_case
        self.manifest_gap = manifest_gap
        self.companions = companions
        # Ledger rows that must exist, PASSED, against the same artifact before
        # this case's result may be recorded. `companions` names a case;
        # `required_runs` can also pin the options a run was made with, which is
        # what "a BIOS pass AND a UEFI pass" needs -- the two runs are the same
        # case and differ only in how they were driven.
        self.required_runs = required_runs
        self.consumes_artifact = consumes_artifact
        self.minutes = minutes


CASES: dict[str, Case] = {
    case.name: case
    for case in (
        Case(
            "live-boot",
            case_live_boot,
            summary="Boot the ISO under test and prove the live system comes up",
            minutes=8,
        ),
        Case(
            "install",
            case_install,
            summary="Install to a blank disk with Calamares and boot the result",
            manifest_case="INSTALL-01",
            manifest_gap=(
                "INSTALL-01 is \"Fresh BIOS and UEFI Calamares installs boot from "
                "disk\": two firmwares. One run proves one firmware, so recording "
                "from a single run would claim the other. Run this case under "
                "--firmware bios and --firmware uefi, then record INSTALL-01 from "
                "the install-both-firmwares case, which boots both results."
            ),
            minutes=40,
        ),
        Case(
            "install-both-firmwares",
            case_install_both_firmwares,
            summary="Boot the BIOS and the UEFI install of this artifact; "
            "the case INSTALL-01 is recorded from",
            manifest_case="INSTALL-01",
            required_runs=(
                {"case": "install", "firmware": "bios"},
                {"case": "install", "firmware": "uefi"},
            ),
            minutes=12,
        ),
        Case(
            "upgrade",
            case_upgrade,
            summary="Upgrade an installed previous release, preserving user data",
            manifest_case="UPGRADE-01",
            manifest_gap=(
                "UPGRADE-01 is \"Existing 4.0 installed system upgrades with "
                "preserved user data AND WORKING RECOVERY\". This case proves the "
                "upgrade and the data preservation; it does not restore a Phoenix "
                "Point on the upgraded system, which the required case also asks "
                "for."
            ),
            consumes_artifact=False,
            minutes=45,
        ),
        Case(
            "recovery",
            case_recovery,
            summary="Restore a Phoenix Point and prove the restored state boots",
            manifest_case="RECOVERY-01",
            manifest_gap=(
                "RECOVERY-01 is \"PROJECT DIFF/UNDO and supported system rollback "
                "verified after injected failures\". This case and its power-loss "
                "companion prove the system-rollback half against a real injected "
                "failure. The Fireline project diff/undo half is proven by the "
                "recovery-project case, which is where RECOVERY-01 is recorded "
                "from: it refuses to run unless both of these have passed against "
                "the same artifact."
            ),
            companions=("recovery-interrupted",),
            consumes_artifact=False,
            minutes=20,
        ),
        Case(
            "recovery-project",
            case_recovery_project,
            summary="Fireline project diff/undo after injected damage; the case "
            "RECOVERY-01 is recorded from",
            manifest_case="RECOVERY-01",
            required_runs=(
                {"case": "recovery"},
                {"case": "recovery-interrupted"},
            ),
            consumes_artifact=False,
            minutes=8,
        ),
        Case(
            "recovery-interrupted",
            case_recovery_interrupted,
            summary="Cut power mid-restore; the system must never claim a "
            "restore it did not complete",
            consumes_artifact=False,
            minutes=25,
        ),
    )
}
