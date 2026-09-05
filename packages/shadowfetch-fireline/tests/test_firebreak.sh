#!/usr/bin/env bash
# Linux containment acceptance. Missing/unusable namespaces are a FAILURE.
set -euo pipefail
FB=${SHADOWFETCH_FIREBREAK_TEST_BIN:-shadowfetch-firebreak}
CP=${SHADOWFETCH_CHECKPOINT_BIN:-shadowfetch-checkpoint}
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT
export SHADOWFETCH_AGENT_WORKSPACES="$fixture/Workspaces"
export XDG_STATE_HOME="$fixture/controller-state"
mkdir -p "$SHADOWFETCH_AGENT_WORKSPACES/w"
printf 'seed\n' > "$SHADOWFETCH_AGENT_WORKSPACES/w/keep.txt"
printf 'private\n' > "$fixture/outside-secret"
printf 'approved\n' > "$fixture/selected-document"
export CUSTOM_PRIVATE_SECRET='secret-environment-sentinel'
pass=0
fail=0
ck() { if [[ "$2" == "$3" ]]; then echo "PASS $1"; pass=$((pass+1)); else echo "FAIL $1: expected $2 got $3"; fail=$((fail+1)); fi; }
run() { "$FB" run --workspace w --no-checkpoint "$@" 2>/dev/null; }
"$FB" check
run --net none -- sh -c 'echo written > wrote.txt'
ck 'workspace writable' written "$(cat "$SHADOWFETCH_AGENT_WORKSPACES/w/wrote.txt")"
ck 'outside home unreadable' hidden "$(run --net none -- sh -c 'test ! -r "$1" && echo hidden' sh "$fixture/outside-secret")"
ck 'controller state hidden' hidden "$(run --net none -- sh -c 'test ! -e "$1" && echo hidden' sh "$XDG_STATE_HOME")"
ck 'private home' /home/agent "$(run --net none -- sh -c 'printf %s "$HOME"')"
ck 'arbitrary env scrubbed' absent "$(run --net none -- sh -c 'printf %s "${CUSTOM_PRIVATE_SECRET:-absent}"')"
ck 'provider env scrubbed' absent "$(CODEX_API_KEY=test-provider-key run --net none -- sh -c 'printf %s "${CODEX_API_KEY:-absent}"')"
ck 'specific provider grant' test-provider-key "$(CODEX_API_KEY=test-provider-key run --net none --credential-env CODEX_API_KEY -- sh -c 'printf %s "$CODEX_API_KEY"')"
ck 'selected document readable' approved "$(run --net none --read "$fixture/selected-document" -- cat "$fixture/selected-document")"
ck 'read parent stays hidden' hidden "$(run --net none --read "$fixture/selected-document" -- sh -c 'test ! -r "$1" && echo hidden' sh "$fixture/outside-secret")"
ck 'root shadow hidden' hidden "$(run --net none -- sh -c 'test ! -e /etc/shadow && echo hidden')"
ck 'network namespace isolated' 1 "$(run --net none -- sh -c 'ip -o link show | wc -l' | tr -d ' ')"
ck 'memory resource limit' 524288 "$(run --net none --memory-mb 512 -- sh -c 'ulimit -v')"
if run --net nonsense -- true; then ck 'invalid network rejected' yes no; else ck 'invalid network rejected' yes yes; fi
out=$("$FB" run --workspace w --net none -- sh -c 'echo CLOBBER > keep.txt; echo junk > junk.txt' 2>/dev/null)
cid=$(printf '%s\n' "$out" | awk '$1=="checkpoint" {print $2;exit}')
ck 'checkpoint before mutation' yes "$([[ -n "$cid" ]] && echo yes || echo no)"
"$CP" undo w "$cid" >/dev/null
ck 'undo restores content' seed "$(cat "$SHADOWFETCH_AGENT_WORKSPACES/w/keep.txt")"
ck 'undo removes additions' no "$([[ -e "$SHADOWFETCH_AGENT_WORKSPACES/w/junk.txt" ]] && echo yes || echo no)"
echo "$pass passed, $fail failed"
[[ "$fail" == 0 ]]
