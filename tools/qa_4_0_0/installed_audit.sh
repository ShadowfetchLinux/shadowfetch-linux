#!/usr/bin/env bash
# Read-only acceptance of a completed, disposable 4.0 installation.
set -euo pipefail
element=${1:?usage: installed_audit.sh fire|ice bios|uefi}
firmware=${2:?usage: installed_audit.sh fire|ice bios|uefi}
qa_user=${QA_USER:-sfqa}
[[ $element == fire || $element == ice ]]
[[ $firmware == bios || $firmware == uefi ]]
[[ $qa_user =~ ^[a-z_][a-z0-9_-]*$ ]]
[[ $(systemd-detect-virt) == kvm || $(systemd-detect-virt) == qemu ]]
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
[[ $(< /etc/shadowfetch/element) == "$element" ]] || fail 'wrong edition'
[[ $(< /usr/share/shadowfetch/version) == 4.0.0 ]] || fail 'wrong release marker'
rg -q '^VERSION_ID="4.0.0"$' /etc/os-release || fail 'wrong os-release version'
rg -q '^VERSION_CODENAME=umbra$' /etc/os-release || fail 'wrong codename'
! rg -q 'boot=live|findiso=' /proc/cmdline || fail 'still running live media'
[[ $(findmnt -no FSTYPE /) == btrfs ]] || fail 'root is not Btrfs'
[[ $(findmnt -no FSTYPE /boot) == ext4 ]] || fail '/boot is not ext4'
[[ $(findmnt -no SOURCE /home) == *'[/@home]' ]] || fail 'personal data is not on separate @home'
if [[ $firmware == uefi ]]; then
    [[ -d /sys/firmware/efi ]] || fail 'UEFI interface absent'
    mountpoint -q /boot/efi || fail 'EFI not mounted'
    [[ $(findmnt -no FSTYPE /boot/efi) == vfat ]] || fail 'EFI filesystem is not vfat'
else
    [[ ! -d /sys/firmware/efi ]] || fail 'unexpected UEFI firmware'
fi
[[ -s /etc/machine-id ]] || fail 'empty machine identity'
[[ $(readlink -f /var/lib/dbus/machine-id) == /etc/machine-id ]] || fail 'D-Bus identity differs'
for command in hwclock lvm ffmpeg ffprobe bwrap shadowfetch-missions shadowfetch-model-check shadowfetch-grok-bot; do
    command -v "$command" >/dev/null || fail "missing $command"
done
mapfile -t packages < <(dpkg-query -W -f='${Package}\t${Version}\t${db:Status-Abbrev}\n' 'shadowfetch-*' | awk -F '\t' '$3 == "ii " { print $1 "\t" $2 }' | sort)
[[ ${#packages[@]} -eq 15 ]] || fail "expected15 installed Shadowfetch packages, got${#packages[@]}"
printf '%s\n' "${packages[@]}" | awk -F '\t' '$2 != "4.0.0-1" { exit 1 }' || fail 'mixed package release versions'
[[ -z $(dpkg --audit) ]] || fail 'incomplete package transaction'
[[ -z $(systemctl --failed --no-legend --plain) ]] || fail 'failed system units'
for unit in shadowfetch-firewatchd.service shadowfetch-hwscan.service phoenix-postboot.service; do
    systemctl is-active --quiet "$unit" || fail "$unit inactive"
done
[[ -f /var/lib/shadowfetch/phoenix-firstboot.done ]] || fail 'Phoenix first boot incomplete'
[[ ! -f /var/lib/shadowfetch/phoenix-update-grub ]] || fail 'Phoenix GRUB completion pending'
systemctl is-enabled --quiet fireproof-postboot.timer || fail 'Fireproof timer disabled'
uid=$(id -u "$qa_user")
qa_home=$(getent passwd "$qa_user" | cut -d: -f6)
user_env=(runuser -u "$qa_user" -- env "HOME=$qa_home" "XDG_RUNTIME_DIR=/run/user/$uid" "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$uid/bus")
"${user_env[@]}" systemctl --user is-enabled --quiet shadowfetch-missions.service || fail 'mission worker is not enabled'
"${user_env[@]}" systemctl --user is-active --quiet shadowfetch-missions.service || fail 'mission worker is not running'
[[ -z $("${user_env[@]}" systemctl --user --failed --no-legend --plain) ]] || fail 'failed desktop user units'
"${user_env[@]}" shadowfetch-missions --json list
"${user_env[@]}" shadowfetch-model-check status --json
"${user_env[@]}" shadowfetch-grok-bot status --json
printf 'HOSTNAME=%s\nELEMENT=%s\nFIRMWARE=%s\nKERNEL=%s\nBOOT_ID=%s\n' "$(hostname)" "$element" "$firmware" "$(uname -r)" "$(< /proc/sys/kernel/random/boot_id)"
printf 'ROOT=%s\nHOME=%s\nBOOT=%s\n' "$(findmnt -no SOURCE,FSTYPE,OPTIONS /)" "$(findmnt -no SOURCE,FSTYPE /home)" "$(findmnt -no SOURCE,FSTYPE /boot)"
printf '%s\n' "${packages[@]}"
printf 'INSTALLED_AUDIT_PASS element=%s firmware=%s packages=%d\n' "$element" "$firmware" "${#packages[@]}"
