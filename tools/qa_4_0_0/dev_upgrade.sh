#!/bin/bash
# Run only inside the disposable development/upgrade VM.
set -euo pipefail
test "$(hostname)" != pop-os
test -d /home/sfqa
destination=/var/tmp/shadowfetch-4.0-upgrade
install -d -m 0755 "$destination"
cd "$destination"
dpkg-query -W -f='${Package}\t${Version}\n' 'shadowfetch-*' > packages-before.txt
runuser -u sfqa -- sh -c 'mkdir -p "$HOME/Workspaces/upgrade-proof"; printf "Preserve my project across 3.5 to 4.0\n" > "$HOME/Workspaces/upgrade-proof/keep.txt"'
sha256sum /home/sfqa/Workspaces/upgrade-proof/keep.txt > user-data.sha256
while read -r package version; do
    [[ "$version" == 3.5.0-1 || "$version" == 4.0.0-1 ]] || continue
    architecture=$(dpkg-query -W -f='${Architecture}' "$package")
    curl --fail --silent --show-error --max-time 120 "http://10.0.2.2:8094/build/${package}_4.0.0-1_${architecture}.deb" -o "${package}_4.0.0-1_${architecture}.deb"
done < packages-before.txt
curl --fail --silent --show-error --max-time 120 http://10.0.2.2:8094/build/shadowfetch-missions_4.0.0-1_all.deb -o shadowfetch-missions_4.0.0-1_all.deb
DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=120 --no-remove -s install ./*.deb > simulation.txt
! rg '^Remv ' simulation.txt
DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=120 --no-remove -y install ./*.deb
sha256sum -c user-data.sha256
dpkg --audit
dpkg-query -W -f='${Package}\t${Version}\n' 'shadowfetch-*' > packages-after.txt
cat /etc/os-release
shadowfetch-missions --version
runuser -u sfqa -- env XDG_RUNTIME_DIR=/run/user/1000 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus systemctl --user daemon-reload
runuser -u sfqa -- env XDG_RUNTIME_DIR=/run/user/1000 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus systemctl --user enable --now shadowfetch-missions.service
runuser -u sfqa -- shadowfetch-missions --json capabilities
echo DEVELOPMENT_UPGRADE_COMPLETED
