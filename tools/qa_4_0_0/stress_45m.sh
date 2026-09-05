#!/usr/bin/env bash
set -uo pipefail

duration="${QA_DURATION_SECONDS:-2700}"
smoke="${QA_DEVELOPMENT_SMOKE:-0}"
[[ $smoke == 0 || $smoke == 1 ]] || { echo "QA_DEVELOPMENT_SMOKE must be 0 or 1" >&2; exit 2; }
qa_user="${QA_USER:-sfqa}"
qa_uid="$(id -u "$qa_user")"
qa_home="$(getent passwd "$qa_user" | cut -d: -f6)"
[[ $EUID -eq 0 && $qa_uid -ne 0 && $duration =~ ^[0-9]+$ && $duration -ge 10 ]] || { echo "Run as root in the QA VM, with a non-root QA_USER and duration >=10" >&2; exit 2; }
systemd-detect-virt --quiet --vm || { echo "Refusing stress outside a VM" >&2; exit 2; }
release="$(cat /usr/share/shadowfetch/version)"
[[ $release == 4.0.0 || ${QA_DEVELOPMENT_SMOKE:-0} == 1 ]] || { echo "Exact installed 4.0.0 required" >&2; exit 2; }
[[ $duration -ge 2700 || ${QA_DEVELOPMENT_SMOKE:-0} == 1 ]] || { echo "Short runs require QA_DEVELOPMENT_SMOKE=1 and cannot produce release PASS" >&2; exit 2; }
for tool in stress-ng podman shadowfetch-missions shadowfetch-grok-bot ffmpeg ffprobe timeout; do
    command -v "$tool" >/dev/null || { echo "Missing QA tool: $tool" >&2; exit 2; }
done
helper_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ -f "$helper_dir/classify_service_journal.py" && ! -L "$helper_dir/classify_service_journal.py" ]] || { echo "Missing structured journal classifier" >&2; exit 2; }
run_id="$(date +%s)-$$"
cancelled=0
stress_pid=0
container_pid=0
probe_pid=0
mission_pid=0
out="${1:-/var/tmp/shadowfetch-qa-4.0.0-$run_id}"
[[ ! -e "$out/result.json" && ! -e "$out/timing.txt" ]] || { echo "Refusing to overwrite earlier QA evidence" >&2; exit 2; }
image="docker.io/library/alpine:3.22"
expected_image_id="b66e0ce64844f5c6435b0c4bfd965558199ab0f53270846861c979cb1ac29365"

mkdir -p "$out"
chmod 0755 "$out"

as_user() {
    runuser -u "$qa_user" -- env -i PATH=/usr/local/bin:/usr/bin:/bin USER="$qa_user" LOGNAME="$qa_user" \
        HOME="$qa_home" \
        XDG_RUNTIME_DIR="/run/user/$qa_uid" \
        DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$qa_uid/bus" \
        "$@"
}

AS_USER=(runuser -u "$qa_user" -- env -i PATH=/usr/local/bin:/usr/bin:/bin USER="$qa_user" LOGNAME="$qa_user" HOME="$qa_home" XDG_RUNTIME_DIR="/run/user/$qa_uid" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$qa_uid/bus")
record_failure() { printf '%s %s\n' "$(date --iso-8601=seconds)" "$*" >> "$out/failures.log"; }
cancel_load() {
    cancelled=1
    record_failure "cancelled by signal"
    for pid in "$stress_pid" "$container_pid" "$probe_pid" "$mission_pid"; do
        if ((pid > 0)); then kill -TERM -- "-$pid" 2>/dev/null || true; fi
    done
}
trap cancel_load INT TERM
start_epoch="$(date +%s)"
start_iso="$(date --iso-8601=seconds)"
boot_id="$(cat /proc/sys/kernel/random/boot_id)"
printf 'start=%s\nepoch=%s\nboot_id=%s\nduration_seconds=%s\n' \
    "$start_iso" "$start_epoch" "$boot_id" "$duration" > "$out/timing.txt"

systemctl --failed --no-legend --plain > "$out/failed-units-before.txt" || true
as_user systemctl --user --failed --no-legend --plain > "$out/failed-user-units-before.txt" || record_failure "initial user service status unavailable"
dpkg --audit > "$out/dpkg-audit-before.txt" || record_failure "initial dpkg audit command failed"
as_user timeout --signal=TERM --kill-after=5s 120s podman info --format json > "$out/podman-info-before.json" 2> "$out/podman-info-before.stderr" || record_failure "initial rootless podman info failed"
as_user timeout --signal=TERM --kill-after=5s 120s podman image inspect "$image" > "$out/container-image-before.json" 2> "$out/container-image-before.stderr" || record_failure "container image inspection failed"
image_id="$(as_user timeout --signal=TERM --kill-after=5s 120s podman image inspect --format '{{.Id}}' "$image" 2> "$out/container-image-resolution.stderr")"
image_resolution_rc=$?
[[ $image_resolution_rc -eq 0 && ${image_id#sha256:} == "$expected_image_id" ]] || { record_failure "Approved cached immutable container image is unavailable; no pull attempted"; exit 2; }
scratch="$qa_home/Workspaces/qa-load-$run_id"
as_user mkdir -p "$scratch" || exit 2
available_bytes="$(df -B1 --output=avail "$scratch" | tail -n1 | tr -d ' ')"
[[ $available_bytes =~ ^[0-9]+$ && $available_bytes -ge 8589934592 ]] || { record_failure "8 GiB free space required for load and retained evidence"; exit 2; }

# The quoted program is intentionally evaluated by the user shell.
# shellcheck disable=SC2016
as_user bash -lc '
set -eu
root="$HOME/Workspaces"
mkdir -p "$root"
for profile in software-studio ai-lab production-ops creative-ai; do
    shadowfetch-workbench plan "$profile" --json
done
' > "$out/workbench-plans.jsonl" 2>&1
plans_rc=$?

load_started="$(date +%s)"
load_started_monotonic="$(python3 -c 'import time; print(time.monotonic())')"
printf 'load_started_epoch=%s\n' "$load_started" >> "$out/timing.txt"
printf 'load_started_monotonic=%s\nqa_profile=production-default900s-v2\n' "$load_started_monotonic" >> "$out/timing.txt"
setsid "${AS_USER[@]}" stress-ng \
    --cpu "${QA_STRESS_CPUS:-3}" --cpu-method all \
    --vm 1 --vm-bytes "${QA_STRESS_VM_BYTES:-3G}" --vm-keep \
    --hdd 2 --hdd-bytes 1G \
    --io 2 \
    --temp-path "$scratch" \
    --timeout "${duration}s" --verify --metrics-brief \
    > "$out/stress-ng.log" 2>&1 &
stress_pid=$!

container_outer_seconds=$((duration + 420))
container_result="$qa_home/.local/state/shadowfetch/qa-container-$run_id.json"
setsid "${AS_USER[@]}" timeout --signal=TERM --kill-after=15s "${container_outer_seconds}s" python3 "$helper_dir/container_stress.py" --duration "$duration" --load-start-monotonic "$load_started_monotonic" --image "$image_id" --run-id "$run_id" --output "$container_result" > "$out/container-loop.log" 2>&1 &
container_pid=$!

mission_outer_seconds=$((duration + 1020 + 120 + 15))
setsid "${AS_USER[@]}" timeout --signal=TERM --kill-after=15s "${mission_outer_seconds}s" python3 "$helper_dir/mission_stress.py" --duration "$duration" --load-start-monotonic "$load_started_monotonic" --run-id "$run_id" --output "$qa_home/.local/state/shadowfetch/qa-stress-$run_id" > "$out/mission-loop.log" 2>&1 &
mission_pid=$!
setsid "${AS_USER[@]}" python3 "$helper_dir/latency_probe.py" --duration "$duration" > "$out/probe-loop.jsonl" 2> "$out/probe-loop.err" &
probe_pid=$!
printf 'runner_pid=%s\nstress_pid=%s\ncontainer_pid=%s\nmission_pid=%s\nprobe_pid=%s\n' "$$" "$stress_pid" "$container_pid" "$mission_pid" "$probe_pid" > "$out/active-handles.txt"

wait_child() {
    local pid="$1" rc
    wait "$pid"; rc=$?
    if ((cancelled)) && kill -0 "$pid" 2>/dev/null; then
        # Python helpers first cancel the real mission/container, then exit.
        local until_epoch=$(( $(date +%s) + 45 ))
        while kill -0 "$pid" 2>/dev/null && (( $(date +%s) < until_epoch )); do sleep 1; done
        if kill -0 "$pid" 2>/dev/null; then
            record_failure "workload $pid exceeded graceful cancellation deadline"
            kill -KILL -- "-$pid" 2>/dev/null || true
        fi
        wait "$pid" 2>/dev/null || true
    fi
    return "$rc"
}
wait_child "$stress_pid"
stress_rc=$?
stress_finished_epoch="$(date +%s)"
wait_child "$container_pid"
container_rc=$?
cp -- "$container_result" "$out/container-result.json" || record_failure "could not preserve container lifecycle result"
wait_child "$probe_pid"
probe_rc=$?
wait_child "$mission_pid"
mission_rc=$?
cp -a "$qa_home/.local/state/shadowfetch/qa-stress-$run_id" "$out/mission-evidence" || record_failure "could not preserve mission receipts"
trap - INT TERM

end_epoch="$(date +%s)"
end_iso="$(date --iso-8601=seconds)"
elapsed=$((end_epoch - start_epoch))
load_elapsed=$((stress_finished_epoch - load_started))
drain_elapsed=$((end_epoch - stress_finished_epoch))
printf 'end=%s\nend_epoch=%s\nelapsed_seconds=%s\n' \
    "$end_iso" "$end_epoch" "$elapsed" >> "$out/timing.txt"

journal_end_utc="$(date -u '+%Y-%m-%d %H:%M:%S.%6N UTC')"
journal_end_epoch="$(date -u --date "$journal_end_utc" +%s)"
journalctl -b --since "@$start_epoch" --until "$journal_end_utc" --no-pager --all > "$out/journal-since-start.log" || record_failure "system journal unavailable"
# Keep the historical raw regex output as evidence, including possible command
# echoes. Structured provenance determines service failures, not these matches.
grep -Eai "Failed to start |Failed with result|Main process exited, code=|core-dump" "$out/journal-since-start.log" > "$out/service-faults-legacy-matches.txt" || true
journalctl -b --since "@$start_epoch" --until "$journal_end_utc" --no-pager --all --output=json > "$out/journal-since-start.jsonl" 2> "$out/journal-json.stderr" || record_failure "structured system journal unavailable"
python3 "$helper_dir/classify_service_journal.py" --journal "$out/journal-since-start.jsonl" \
    --output "$out/service-fault-classification.json" --faults-text "$out/service-faults.txt" \
    > "$out/service-classifier.stdout" 2> "$out/service-classifier.stderr"
service_classifier_rc=$?
journalctl -k -b --since "@$start_epoch" --no-pager > "$out/kernel-since-start.log" || record_failure "kernel journal unavailable"
grep -Eai 'kernel panic|BUG:|Oops:|Call Trace:|out of memory|oom-kill|general protection fault|segfault|I/O error|EXT4-fs error|BTRFS.*(error|corrupt)' \
    "$out/kernel-since-start.log" > "$out/kernel-faults.txt" || true
systemctl --failed --no-legend --plain > "$out/failed-units-after.txt" || true
as_user systemctl --user --failed --no-legend --plain > "$out/failed-user-units-after.txt" || record_failure "final user service status unavailable"
systemctl --failed --no-legend --plain | grep -E 'shadowfetch|phoenix|fireproof' \
    > "$out/failed-shadowfetch-units.txt" || true
dpkg --audit > "$out/dpkg-audit-after.txt" || record_failure "final dpkg audit command failed"
if [[ $(findmnt -n -o FSTYPE /) == btrfs ]]; then
    btrfs device stats / > "$out/btrfs-device-stats.txt" 2>&1 || record_failure "Btrfs device statistics unavailable"
    grep -Ev '[[:space:]]0$' "$out/btrfs-device-stats.txt" > "$out/btrfs-device-errors.txt" || true
else
    echo "Not applicable: root filesystem is not Btrfs" > "$out/btrfs-device-stats.txt"
fi
as_user timeout --signal=TERM --kill-after=5s 120s podman info --format json > "$out/podman-info-after.json" 2> "$out/podman-info-after.stderr" || record_failure "rootless podman info failed after load"
as_user timeout --signal=TERM --kill-after=5s 120s podman image inspect "$image_id" > "$out/container-image-inspect.json" 2> "$out/container-image-inspect.stderr" || record_failure "final immutable container image inspection failed"
as_user shadowfetch-health --quick --json > "$out/health-after.json" || true

failures=0
container_cycles="$(grep -c '"container_cycle"' "$out/container-loop.log" || true)"
probe_cycles="$(grep -c '"probe_cycle"' "$out/probe-loop.jsonl" || true)"
for rc in "$image_resolution_rc" "$plans_rc" "$stress_rc" "$container_rc" "$probe_rc" "$mission_rc" "$service_classifier_rc"; do
    if (( rc != 0 )); then
        failures=$((failures + 1))
    fi
done
if (( load_elapsed < duration )); then failures=$((failures + 1)); fi
minimum_cycles=$((duration / 120)); ((minimum_cycles >= 1)) || minimum_cycles=1
if (( container_cycles < minimum_cycles )); then failures=$((failures + 1)); record_failure "too few container cycles"; fi
if (( probe_cycles < minimum_cycles )); then failures=$((failures + 1)); record_failure "too few responsiveness probes"; fi
for file in failures.log service-faults.txt dpkg-audit-before.txt failed-units-before.txt failed-user-units-before.txt kernel-faults.txt failed-units-after.txt failed-user-units-after.txt failed-shadowfetch-units.txt dpkg-audit-after.txt btrfs-device-errors.txt; do
    if [[ -s "$out/$file" ]]; then failures=$((failures + 1)); fi
done

cat > "$out/result.json" <<EOF
{
  "release": "4.0.0",
  "qa_profile": "production-default900s-v2",
  "boot_id": "$boot_id",
  "start": "$start_iso",
  "end": "$end_iso",
  "required_seconds": $duration,
  "elapsed_seconds": $elapsed,
  "load_elapsed_seconds": $load_elapsed,
  "post_load_drain_seconds": $drain_elapsed,
  "mission_outer_observation_seconds": $mission_outer_seconds,
  "container_outer_observation_seconds": $container_outer_seconds,
  "container_image_id": "$image_id",
  "cached_image_resolution_rc": $image_resolution_rc,
  "container_image_pull_attempted": false,
  "workbench_plans_rc": $plans_rc,
  "stress_ng_rc": $stress_rc,
  "container_loop_rc": $container_rc,
  "container_cycles": $container_cycles,
  "mission_loop_rc": $mission_rc,
  "probe_loop_rc": $probe_rc,
  "service_classifier_schema": 1,
  "service_classifier_rc": $service_classifier_rc,
  "journal_window_end_epoch": $journal_end_epoch,
  "journal_window_end_utc": "$journal_end_utc",
  "cancelled": $cancelled,
  "installed_release": "$release",
  "development_smoke": ${QA_DEVELOPMENT_SMOKE:-0},
  "probe_cycles": $probe_cycles,
  "failure_count": $failures,
  "status": "$([[ $cancelled -eq 1 ]] && printf CANCELLED || { [[ $failures -eq 0 ]] && { [[ ${QA_DEVELOPMENT_SMOKE:-0} == 1 ]] && printf SMOKE_PASS || printf PASS; } || printf FAIL; })"
}
EOF

if (( failures != 0 )); then
    exit 1
fi
