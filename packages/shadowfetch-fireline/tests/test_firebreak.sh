#!/usr/bin/env bash
# Firebreak containment acceptance test (uses installed /usr/bin binaries).
set -uo pipefail
FB=shadowfetch-firebreak
export SHADOWFETCH_AGENT_WORKSPACES=/tmp/fb-accept
rm -rf "$SHADOWFETCH_AGENT_WORKSPACES"; mkdir -p "$SHADOWFETCH_AGENT_WORKSPACES/w"
echo "seed" > "$SHADOWFETCH_AGENT_WORKSPACES/w/keep.txt"
pass=0; fail=0
ck(){ if [ "$2" = "$3" ]; then echo "  PASS $1"; pass=$((pass+1)); else echo "  FAIL $1 (got '$3' want '$2')"; fail=$((fail+1)); fi; }
run(){ "$FB" run "$@" 2>/dev/null | grep -oE 'PROBE:[^ ]+' | head -1; }

# workspace writable
$FB run --workspace w -- bash -c 'echo x > wrote.txt' >/dev/null 2>&1
ck "workspace is writable" "yes" "$([ -f "$SHADOWFETCH_AGENT_WORKSPACES/w/wrote.txt" ] && echo yes || echo no)"
# /etc read-only
$FB run --workspace w -- bash -c 'echo x > /etc/sf_pwn 2>/dev/null' >/dev/null 2>&1
ck "/etc is read-only" "no" "$([ -f /etc/sf_pwn ] && echo yes || echo no)"
# /usr read-only
$FB run --workspace w -- bash -c 'echo x > /usr/sf_pwn 2>/dev/null' >/dev/null 2>&1
ck "/usr is read-only" "no" "$([ -f /usr/sf_pwn ] && echo yes || echo no)"
# $HOME (outside workspace) read-only
$FB run --workspace w -- bash -c "echo x > $HOME/sf_pwn 2>/dev/null" >/dev/null 2>&1
ck "\$HOME outside workspace read-only" "no" "$([ -f "$HOME/sf_pwn" ] && { rm -f "$HOME/sf_pwn"; echo yes; } || echo no)"
# network: --net none leaves ONLY loopback; robust and offline-safe
nifaces_none=$(run --workspace w --net none -- bash -c 'echo PROBE:$(ip -o link show 2>/dev/null | wc -l)')
ck "--net none exposes only loopback (1 iface)" "PROBE:1" "$nifaces_none"
nifaces_allow=$(run --workspace w -- bash -c 'echo PROBE:$(ip -o link show 2>/dev/null | wc -l)')
ck "--net allow exposes host interfaces (>1)" "yes" "$([ "${nifaces_allow#PROBE:}" -gt 1 ] 2>/dev/null && echo yes || echo no)"
# secret scrub
key_default=$(run --workspace w -- env OPENAI_API_KEY=sk-SECRET bash -c 'echo PROBE:${OPENAI_API_KEY:-ABSENT}')
# NOTE: env inside is set AFTER scrub by our own probe; test the real path instead:
key_default=$(OPENAI_API_KEY=sk-SECRET $FB run --workspace w -- bash -c 'echo PROBE:${OPENAI_API_KEY:-ABSENT}' 2>/dev/null | grep -oE 'PROBE:[^ ]+')
ck "credential var scrubbed by default" "PROBE:ABSENT" "$key_default"
key_keep=$(OPENAI_API_KEY=sk-SECRET $FB run --workspace w --keep-secrets -- bash -c 'echo PROBE:${OPENAI_API_KEY:-ABSENT}' 2>/dev/null | grep -oE 'PROBE:[^ ]+')
ck "--keep-secrets passes it through" "PROBE:sk-SECRET" "$key_keep"
# audit: pre-run checkpoint + session manifest + undo reverses
out=$($FB run --workspace w -- bash -c 'echo CLOBBER > keep.txt; echo j > junk.txt' 2>&1)
cid=$(printf '%s' "$out" | grep -oE 'checkpoint [0-9-]+ taken' | grep -oE '[0-9-]+' | head -1)
ck "firebreak took a checkpoint" "yes" "$([ -n "$cid" ] && echo yes || echo no)"
sdir="${XDG_STATE_HOME:-$HOME/.local/state}/shadowfetch/firebreak"
ck "firebreak wrote a session manifest" "yes" "$(ls "$sdir"/*.session >/dev/null 2>&1 && echo yes || echo no)"
shadowfetch-checkpoint undo w "$cid" >/dev/null 2>&1
ck "undo restored clobbered file" "seed" "$(cat "$SHADOWFETCH_AGENT_WORKSPACES/w/keep.txt")"
ck "undo removed agent's junk" "no" "$([ -f "$SHADOWFETCH_AGENT_WORKSPACES/w/junk.txt" ] && echo yes || echo no)"
echo ""; echo "  $pass passed, $fail failed"
exit $((fail>0))
