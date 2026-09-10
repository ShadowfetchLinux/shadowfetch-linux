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
# See stress_45m.sh: QA_RELEASE is the operator's claim about which release is
# under test, required and never derived from the guest.
[[ -n ${QA_RELEASE:-} ]] || fail 'set QA_RELEASE to the release under test; it is not derived from the guest, because this check exists to catch auditing the wrong image'
[[ $QA_RELEASE =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail 'QA_RELEASE must be MAJOR.MINOR.PATCH'
[[ $(< /usr/share/shadowfetch/version) == "$QA_RELEASE" ]] || fail 'wrong release marker'
rg -q "^VERSION_ID=\"$QA_RELEASE\"\$" /etc/os-release || fail 'wrong os-release version'
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
for command in hwclock lvm ffmpeg ffprobe bwrap shadowfetch-missions shadowfetch-grok-bot; do
    command -v "$command" >/dev/null || fail "missing $command"
done
mapfile -t packages < <(dpkg-query -W -f='${Package}\t${Version}\t${db:Status-Abbrev}\n' 'shadowfetch-*' | awk -F '\t' '$3 == "ii " { print $1 "\t" $2 }' | sort)
[[ ${#packages[@]} -eq 16 ]] || fail "expected 16 installed Shadowfetch packages, got ${#packages[@]}"
printf '%s\n' "${packages[@]}" | awk -F '\t' -v want="$QA_RELEASE-1" '$2 != want { exit 1 }' || fail 'mixed package release versions'
[[ -z $(dpkg --audit) ]] || fail 'incomplete package transaction'
[[ $(dpkg-query -W -f='${Version}' drkonqi) == 6.6.5-3 ]] || fail 'unexpected DrKonqi protocol version'
[[ -z $(dpkg --verify drkonqi) ]] || fail 'upstream DrKonqi package was modified'
[[ -z $(dpkg --verify shadowfetch-drkonqi-pickup) ]] || fail 'pickup correction package was modified'
[[ -x /usr/libexec/shadowfetch-drkonqi-pickup ]] || fail 'pickup correction helper absent'
/usr/libexec/shadowfetch-drkonqi-pickup --help >/dev/null
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
pickup_exec=$("${user_env[@]}" systemctl --user show drkonqi-coredump-pickup.service -p ExecStart --value)
[[ $pickup_exec == *'/usr/libexec/shadowfetch-drkonqi-pickup --settle-first --pickup --uid '* ]] || fail 'pickup service is not using the narrow correction'
"${user_env[@]}" systemctl --user show drkonqi-coredump-pickup.service -p FragmentPath -p DropInPaths -p ActiveState -p SubState -p Result -p ExecStart
"${user_env[@]}" shadowfetch-missions --json list
"${user_env[@]}" shadowfetch-missions --json capabilities
[[ ! -e /usr/bin/shadowfetch-model-check && ! -e /usr/bin/shadowfetch-buzz && ! -e /usr/lib/systemd/user/shadowfetch-buzz.service ]] || fail 'the retired Buzz relay integration is still present: it is the stack whose Redis AOF fsync stalls produced every recorded STRESS-01 fault, and a candidate carrying it cannot be stressed for a clean result'
"${user_env[@]}" shadowfetch-grok-bot status --json
printf 'HOSTNAME=%s\nELEMENT=%s\nFIRMWARE=%s\nKERNEL=%s\nBOOT_ID=%s\n' "$(hostname)" "$element" "$firmware" "$(uname -r)" "$(< /proc/sys/kernel/random/boot_id)"
printf 'ROOT=%s\nHOME=%s\nBOOT=%s\n' "$(findmnt -no SOURCE,FSTYPE,OPTIONS /)" "$(findmnt -no SOURCE,FSTYPE /home)" "$(findmnt -no SOURCE,FSTYPE /boot)"
printf '%s\n' "${packages[@]}"
printf 'INSTALLED_AUDIT_PASS element=%s firmware=%s packages=%d\n' "$element" "$firmware" "${#packages[@]}"
