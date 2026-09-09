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

from .evidence import EvidenceSet
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
    ) -> None:
        self.name = name
        self.repo_root = repo_root
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

        after = system_report(machine)
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

# Driving the installer needs the guest's own accessibility bus, because that
# is the only way to assert WHICH page is on screen before acting on it.
# Blind keystrokes into a wizard prove nothing: they can "succeed" against a
# dialog that is not the one anybody thinks it is.
ATSPI_DRIVER = r'''#!/usr/bin/env python3
"""Enumerate or activate accessible controls of one running application."""
import json, sys
import dbus

want_app = sys.argv[1]
action = sys.argv[2] if len(sys.argv) > 2 else "dump"
target = sys.argv[3] if len(sys.argv) > 3 else ""
text = sys.argv[4] if len(sys.argv) > 4 else ""

session = dbus.SessionBus()
status = session.get_object("org.a11y.Bus", "/org/a11y/bus")
if action == "enable":
    # Qt only attaches its AT-SPI bridge when toolkit accessibility is switched
    # on, and on a stock KDE session it is off until an assistive client asks
    # for it. Without this the installer runs perfectly and is simply invisible
    # to the bus, which reads exactly like "the installer failed to start".
    result = {}
    for prop in ("IsEnabled", "ScreenReaderEnabled"):
        try:
            status.Set("org.a11y.Status", prop,
                       dbus.Boolean(True, variant_level=1),
                       dbus_interface="org.freedesktop.DBus.Properties")
        except dbus.DBusException as error:
            result[prop + "_error"] = str(error)
        try:
            result[prop] = bool(status.Get("org.a11y.Status", prop,
                                dbus_interface="org.freedesktop.DBus.Properties"))
        except dbus.DBusException as error:
            result[prop] = None
            result[prop + "_read_error"] = str(error)
    print(json.dumps(result))
    raise SystemExit(0)
address = status.GetAddress(dbus_interface="org.a11y.Bus")
bus = dbus.bus.BusConnection(address)
ACC = "org.a11y.atspi.Accessible"
PROP = "org.freedesktop.DBus.Properties"
registry = bus.get_object("org.a11y.atspi.Registry",
                          "/org/a11y/atspi/accessible/root")
apps = []
present = []
for name, path in registry.GetChildren(dbus_interface=ACC):
    obj = bus.get_object(name, path)
    label = str(obj.Get(ACC, "Name", dbus_interface=PROP))
    present.append(label)
    if label == want_app:
        apps.append((str(name), str(path)))
if action == "apps":
    # Every application the accessibility bus can see. Recorded when the
    # installer cannot be found, so the block says what WAS there instead of
    # only what was missing.
    print(json.dumps({"applications": sorted(present)}, indent=2))
    raise SystemExit(0)
if len(apps) != 1:
    raise SystemExit("expected exactly one %r application, found %d among %r"
                     % (want_app, len(apps), sorted(present)))

seen, controls, fields, labels = set(), [], [], []


def walk(name, path, depth=0):
    if depth > 25 or (name, path) in seen or len(seen) > 3000:
        return
    seen.add((name, path))
    try:
        obj = bus.get_object(name, path)
        role = int(obj.GetRole(dbus_interface=ACC))
        label = str(obj.Get(ACC, "Name", dbus_interface=PROP))
        state = [int(v) for v in obj.GetState(dbus_interface=ACC)]
        if role in (7, 8, 11, 32, 35, 43, 44, 45, 62):
            controls.append({"label": label, "role": role, "bus": name,
                             "path": path, "state": state})
        ifaces = [str(v) for v in obj.GetInterfaces(dbus_interface=ACC)]
        if role == 79 or "org.a11y.atspi.EditableText" in ifaces:
            fields.append({"label": label, "role": role, "bus": name,
                           "path": path, "state": state})
        if role in (29, 81, 83) and label:
            labels.append(label)
        for cname, cpath in obj.GetChildren(dbus_interface=ACC):
            walk(str(cname), str(cpath), depth + 1)
    except dbus.DBusException:
        return


walk(*apps[0])


def normalise(value):
    return value.replace("&", "").strip().rstrip(".").casefold()


if action == "dump":
    print(json.dumps({"controls": controls, "fields": fields,
                      "labels": labels}, indent=2))
elif action == "click":
    matches = [c for c in controls if normalise(c["label"]) == normalise(target)]
    if len(matches) != 1:
        raise SystemExit("expected one control named %r, found %d"
                         % (target, len(matches)))
    obj = bus.get_object(matches[0]["bus"], matches[0]["path"])
    count = int(obj.Get("org.a11y.atspi.Action", "NActions",
                        dbus_interface=PROP, timeout=5))
    if count < 1:
        raise SystemExit("control %r exposes no action" % target)
    print(json.dumps({"clicked": target, "result": bool(
        obj.DoAction(0, dbus_interface="org.a11y.atspi.Action", timeout=10))}))
elif action == "fill":
    matches = [f for f in fields if normalise(f["label"]) == normalise(target)]
    if len(matches) != 1:
        raise SystemExit("expected one field named %r, found %d"
                         % (target, len(matches)))
    obj = bus.get_object(matches[0]["bus"], matches[0]["path"])
    print(json.dumps({"filled": target, "result": bool(
        obj.SetTextContents(text, dbus_interface="org.a11y.atspi.EditableText",
                            timeout=10))}))
else:
    raise SystemExit("unknown action %r" % action)
'''


def _live_session(ctx: Context, machine: Guest) -> dict[str, str]:
    """Find the live desktop session to drive. Observed, not assumed."""
    probe = machine.run(
        "for p in $(pgrep -x plasmashell); do "
        "u=$(stat -c %U /proc/$p); i=$(stat -c %u /proc/$p); "
        "d=$(tr '\\0' '\\n' < /proc/$p/environ | sed -n 's/^DISPLAY=//p' | head -1); "
        "w=$(tr '\\0' '\\n' < /proc/$p/environ | sed -n 's/^WAYLAND_DISPLAY=//p' | head -1); "
        f"printf '%s\\t%s\\t%s\\t%s\\n' \"$u\" \"$i\" \"$d\" \"$w\"; done",
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


def _atspi(
    ctx: Context, machine: Guest, session: dict[str, str], *args: str, timeout: float = 120
) -> dict:
    env = (
        f"HOME=/home/{session['user']} XDG_RUNTIME_DIR=/run/user/{session['uid']} "
        f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{session['uid']}/bus "
        f"QT_ACCESSIBILITY=1 GTK_MODULES=gail:atk-bridge "
    )
    if session.get("display"):
        env += f"DISPLAY={session['display']} "
    if session.get("wayland_display"):
        env += f"WAYLAND_DISPLAY={session['wayland_display']} "
    command = (
        f"/usr/sbin/runuser -u {shlex.quote(session['user'])} -- /usr/bin/env {env}"
        f"/usr/bin/python3 /tmp/sf-atspi-driver.py "
        + " ".join(shlex.quote(argument) for argument in args)
    )
    return machine.run(command, timeout=timeout)


def case_install(ctx: Context) -> None:
    """Install the artifact to a blank disk with Calamares, then boot it.

    The installer is driven through the guest's accessibility bus so that each
    step asserts which page it is acting on. Anything unrecognised stops the
    run as BLOCKED with the observed page recorded -- never a guess, and never
    a pass.
    """
    iso = Path(ctx.artifact["path"])
    machine = ctx.guest("install", firmware=ctx.options.get("firmware", "bios"))
    machine.create_disk(int(ctx.options.get("disk_gib", 40)))
    machine.boot("live", iso=iso, note="live boot for installation")
    try:
        machine.wait_agent(float(ctx.options.get("boot_timeout", 900)))
        live = system_report(machine)
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
        push_script(machine, "/tmp/sf-atspi-driver.py", ATSPI_DRIVER)
        # Switch toolkit accessibility on BEFORE the installer starts: Qt
        # attaches its AT-SPI bridge at construction, so a window that opened
        # first never appears on the bus.
        enabled = _atspi(ctx, machine, session, "-", "enable")
        ctx.observe(
            "accessibility_enabled",
            (enabled["stdout"] or enabled["stderr"]).strip()[:200],
        )
        # Not a block: whether this worked is a fact to record, not a reason to
        # stop. A run that goes on to read the installer's controls anyway is
        # worth more than one that stops at the diagnostic.
        ctx.evidence.write_text(
            "install-accessibility.log",
            f"exit={enabled['exitcode']}\n\n{enabled['stdout']}\n{enabled['stderr']}\n",
        )

        # The desktop's launcher (calamares-install-debian) is a wrapper that
        # calls xhost and then pkexec. pkexec cannot be authorised without a
        # human at the keyboard: through the guest agent it answers "Error
        # executing command as another user: Not authorized" and nothing
        # starts. The harness therefore starts the installer binary directly as
        # root, on the live session's own Wayland/D-Bus environment.
        #
        # Say plainly what that costs: this case then covers the INSTALLER, not
        # the polkit path a user takes to reach it. An install case driven this
        # way must not be read as proving that the desktop icon works.
        ctx.observe(
            "installer_launch_path",
            "started directly as root on the live session bus; the desktop's "
            "pkexec wrapper is not exercised and is not covered by this case",
        )
        launcher = ctx.options.get("installer_command", "/usr/bin/calamares")
        environment = (
            f"XDG_RUNTIME_DIR=/run/user/{session['uid']} "
            f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{session['uid']}/bus "
            "QT_ACCESSIBILITY=1 HOME=/root "
        )
        if session.get("wayland_display"):
            environment += (
                f"WAYLAND_DISPLAY={session['wayland_display']} QT_QPA_PLATFORM=wayland "
            )
        elif session.get("display"):
            environment += f"DISPLAY={session['display']} "
        started = machine.run(
            f"setsid /usr/bin/env {environment}{shlex.quote(launcher)} -d "
            ">/tmp/sf-installer.log 2>&1 & echo started",
            timeout=60,
        )
        ctx.log(f"installer launch: {started['stdout'].strip()[:200]}")
        time.sleep(float(ctx.options.get("installer_settle", 60)))
        ctx.snap(machine, "install-installer-launched.png")

        application = ctx.options.get("installer_atspi_name", "calamares")
        dump = _atspi(ctx, machine, session, application, "dump")
        ctx.evidence.write_text(
            "install-atspi-first-page.json",
            dump["stdout"] or dump["stderr"] or "(no output)",
        )
        launcher_log = machine.out("cat /tmp/sf-installer.log 2>/dev/null")
        ctx.evidence.write_text(
            "install-launcher.log",
            f"$ {launcher}\n(guest /tmp/sf-installer.log)\n\n{launcher_log}\n"
            f"\nprocesses:\n"
            + machine.out("ps -eo user:16,pid,args | grep -i calamares | grep -v grep"),
        )
        if dump["exitcode"] != 0:
            visible = _atspi(ctx, machine, session, application, "apps")
            ctx.evidence.write_text(
                "install-atspi-applications.json",
                visible["stdout"] or visible["stderr"] or "(no output)",
            )
            ctx.blocked(
                "the installer's accessible interface could not be read, so no "
                "page could be identified before acting on it: "
                f"{(dump['stdout'] + dump['stderr']).strip()[:400]}. The "
                "applications the accessibility bus could see, and the "
                "installer's own launch log, are recorded as evidence."
            )
        ctx.blocked(
            "the page-by-page installer drive is not implemented. The harness "
            "boots the artifact, launches the installer and can read its "
            "accessible controls (recorded in install-atspi-first-page.json); "
            "mapping those observed controls to the welcome/locale/keyboard/"
            "partition/users/summary sequence is the remaining work."
        )
    finally:
        try:
            machine.shutdown()
        finally:
            ctx.collect_machine_evidence(machine, "install")


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
        consumes_artifact: bool = True,
        minutes: int = 10,
    ) -> None:
        self.name = name
        self.run = run
        self.summary = summary
        self.manifest_case = manifest_case
        self.manifest_gap = manifest_gap
        self.companions = companions
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
                "from a single run would claim the other. Recording needs a case "
                "that consumes a BIOS and a UEFI PASS for the same artifact."
            ),
            minutes=40,
        ),
        Case(
            "upgrade",
            case_upgrade,
            summary="Upgrade an installed previous release, preserving user data",
            manifest_case="UPGRADE-01",
            manifest_gap=(
                "UPGRADE-01 is \"Existing 3.5 installed system upgrades with "
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
                "failure. The Fireline project diff/undo half is not covered here, "
                "so recording RECOVERY-01 as passed from these runs would claim "
                "something nobody ran."
            ),
            companions=("recovery-interrupted",),
            consumes_artifact=False,
            minutes=20,
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
