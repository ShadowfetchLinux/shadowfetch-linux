#!/bin/sh
# Stamp /etc/shadowfetch/element from the kernel command line (sf.element=fire|ice).
# Runs once per boot, before the display manager, so the whole session — Welcome,
# Control Center, Firebreak — agrees on the element the user chose at the boot menu.
# Never overwrites an element already chosen on an installed system unless the
# cmdline explicitly names one (the boot menu wins when the user used it).
set -u
el=""
for tok in $(cat /proc/cmdline); do
    case "$tok" in sf.element=fire) el=fire ;; sf.element=ice) el=ice ;; esac
done
[ -n "$el" ] || exit 0
mkdir -p /etc/shadowfetch
printf '%s\n' "$el" > /etc/shadowfetch/element
exit 0
