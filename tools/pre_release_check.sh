#!/usr/bin/env bash
# Shadowfetch Linux pre-release publication gate.
# Fails before publication if the APT repo metadata can expire clients or if
# local/generated credential state is present in the release tree.
set -euo pipefail

ROOT="${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
CODENAME="${CODENAME:-umbra}"
REPO_DIR="${REPO_DIR:-$ROOT/repo}"
INRELEASE="$REPO_DIR/dists/$CODENAME/InRelease"
MIN_VALID_FOR_SECONDS="${REPO_MIN_VALID_FOR_SECONDS:-86400}"

failures=()

add_failure() {
  failures+=("$1")
}

if [[ ! -f "$INRELEASE" ]]; then
  add_failure "missing APT metadata: $INRELEASE"
elif ! valid_until_line=$(grep -m1 '^Valid-Until:' "$INRELEASE"); then
  add_failure "missing Valid-Until in $INRELEASE"
else
  valid_until_value="${valid_until_line#Valid-Until: }"
  if ! valid_until_epoch=$(date -u -d "$valid_until_value" +%s 2>/dev/null); then
    add_failure "unparseable Valid-Until in $INRELEASE: $valid_until_value"
  else
    now_epoch=$(date -u +%s)
    remaining=$((valid_until_epoch - now_epoch))
    if (( remaining <= 0 )); then
      add_failure "expired Valid-Until in $INRELEASE: $valid_until_value"
    elif (( remaining < MIN_VALID_FOR_SECONDS )); then
      add_failure "Valid-Until in $INRELEASE expires too soon: $valid_until_value (${remaining}s remaining, minimum ${MIN_VALID_FOR_SECONDS}s)"
    fi
  fi
fi

# An unusable git is a hard failure, not a skip: without it this check cannot see
# tracked credential/cache state, and the release would print PRE_RELEASE_CHECK_PASSED
# having verified nothing.
if ! command -v git >/dev/null 2>&1; then
  add_failure "git is not installed: the tracked-credential-state check cannot run"
elif ! git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  add_failure "git cannot read $ROOT as a work tree: the tracked-credential-state check cannot run"
elif ! tracked_files=$(git -C "$ROOT" ls-files); then
  add_failure "git ls-files failed in $ROOT: the tracked-credential-state check cannot run"
else
  tracked_cache=$(printf '%s\n' "$tracked_files" | grep -E '(^|/)\.wrangler(/|$)' || true)
  if [[ -n "$tracked_cache" ]]; then
    add_failure "tracked Wrangler cache/state files must be removed from git before release: $(printf '%s' "$tracked_cache" | paste -sd, -)"
  fi
fi

while IFS= read -r token_file; do
  add_failure "local write token file present in release tree: ${token_file#$ROOT/}"
done < <(
  find "$ROOT" \
    \( -path "$ROOT/.git" -o -path "$ROOT/live-build/chroot" -o -path "$ROOT/live-build/cache" \) -prune \
    -o -name '.write-token.txt' -type f -print 2>/dev/null
)

# ---- Corresponding-source gate -------------------------------------------------
# /linux/licensing carries a written offer that the complete corresponding source
# is published in main/source alongside the binaries. Derive the required source
# set from the binary index rather than trusting that someone remembered to build
# it, and refuse to publish binaries whose source is missing.
PACKAGES_IDX="$REPO_DIR/dists/$CODENAME/main/binary-amd64/Packages"
SOURCES_IDX="$REPO_DIR/dists/$CODENAME/main/source/Sources"

if [[ ! -f "$PACKAGES_IDX" ]]; then
  add_failure "missing binary index: $PACKAGES_IDX"
elif [[ ! -s "$SOURCES_IDX" ]]; then
  add_failure "empty or missing source index: $SOURCES_IDX — the written offer for corresponding source on /linux/licensing would be false"
else
  # binary -> source name (Source: when present, else the binary's own name)
  required=$(awk '
    /^Package: /{pkg=$2; src=""}
    /^Source: /{src=$2}
    /^[[:space:]]*$/{if(pkg!=""){print (src!=""?src:pkg); pkg=""; src=""}}
    END{if(pkg!="")print (src!=""?src:pkg)}
  ' "$PACKAGES_IDX" | sort -u)
  available=$(awk '/^Package: /{print $2}' "$SOURCES_IDX" | sort -u)
  missing=$(comm -23 <(printf '%s\n' "$required") <(printf '%s\n' "$available"))
  if [[ -n "$missing" ]]; then
    add_failure "published binaries with no corresponding source in main/source: $(printf '%s' "$missing" | paste -sd, -)"
  fi
  n_req=$(printf '%s\n' "$required" | grep -c . || true)
  n_avail=$(printf '%s\n' "$available" | grep -c . || true)
  printf 'corresponding-source check: %s source packages required, %s published\n' "$n_req" "$n_avail"
fi

if (( ${#failures[@]} )); then
  printf 'PRE_RELEASE_CHECK_FAILED\n' >&2
  for failure in "${failures[@]}"; do
    printf ' - %s\n' "$failure" >&2
  done
  exit 1
fi

printf 'PRE_RELEASE_CHECK_PASSED repo=%s codename=%s inrelease=%s\n' "$REPO_DIR" "$CODENAME" "$INRELEASE"
