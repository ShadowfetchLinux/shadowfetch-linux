#!/bin/sh
# Apply the Fire/Ice element to this user's session, once per element change.
# Runs from XDG autostart; no-ops instantly when the look is already applied.
set -u
el="$(shadowfetch-element 2>/dev/null || echo fire)"
stamp="${XDG_CONFIG_HOME:-$HOME/.config}/shadowfetch/.element-applied"
[ "$(cat "$stamp" 2>/dev/null)" = "$el" ] && exit 0
shadowfetch-element apply >/dev/null 2>&1 || exit 0
mkdir -p "$(dirname "$stamp")"
printf '%s\n' "$el" > "$stamp"
