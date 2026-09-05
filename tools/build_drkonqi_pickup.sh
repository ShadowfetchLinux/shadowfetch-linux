#!/usr/bin/env bash
# Build the native correction against Debian 13, without installing host deps.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
mode=${1:---build}
[[ $mode == --build || $mode == --test ]] || { echo 'usage: build_drkonqi_pickup.sh [--build|--test]' >&2; exit 2; }
command -v podman >/dev/null
recipe="$root/tools/containers/drkonqi-build.Containerfile"
recipe_sha=$(sha256sum "$recipe" | awk '{print $1}')
builder=localhost/shadowfetch-drkonqi-build:4.0.0
existing=$(podman image inspect --format '{{ index .Labels "org.shadowfetch.build-recipe" }}' "$builder" 2>/dev/null || true)
if [[ $existing != "$recipe_sha" ]]; then
    podman build --pull=missing --build-arg "RECIPE_SHA=$recipe_sha" \
        --file "$recipe" --tag "$builder" "$root/tools/containers"
fi
builder_id=$(podman image inspect --format '{{.Id}}' "$builder")
[[ $(podman image inspect --format '{{ index .Labels "org.shadowfetch.build-recipe" }}' "$builder_id") == "$recipe_sha" ]]
base_image=$(awk '$1 == "FROM" {print $2; exit}' "$recipe")
mkdir -p "$root/build"
temporary=$(mktemp -d "$root/build/.drkonqi-build.XXXXXX")
cleanup() {
    if [[ -s $temporary/container-id ]]; then
        podman rm --force "$(< "$temporary/container-id")" >/dev/null 2>&1 || true
    fi
    rm -rf -- "$temporary"
}
trap cleanup EXIT
podman run --rm --network=none --cpus=2 --memory=2g --pids-limit=256 \
    --cidfile "$temporary/container-id" \
    --volume "$root/packages/shadowfetch-drkonqi-pickup:/input:ro" \
    --volume "$temporary:/out:rw" \
    "$builder_id" sh -ec '
        mkdir -p /tmp/build
        cp -a /input /tmp/build/shadowfetch-drkonqi-pickup
        cd /tmp/build/shadowfetch-drkonqi-pickup
        dpkg-buildpackage -us -uc -b -j2
        cp ../*.deb ../*.buildinfo ../*.changes /out/
        cp build-debian/validation-results.json /out/validation-results.json
    '
shopt -s nullglob
debs=("$temporary"/*.deb)
[[ ${#debs[@]} == 1 ]] || { echo 'Expected exactly one pickup binary package' >&2; exit 1; }
expected=shadowfetch-drkonqi-pickup_4.0.0-1_amd64.deb
[[ ${debs[0]##*/} == "$expected" ]] || { echo 'Unexpected pickup package filename' >&2; exit 1; }
[[ $(dpkg-deb -f "${debs[0]}" Package) == shadowfetch-drkonqi-pickup ]]
[[ $(dpkg-deb -f "${debs[0]}" Version) == 4.0.0-1 ]]
[[ $(dpkg-deb -f "${debs[0]}" Architecture) == amd64 ]]
validation="$root/build/drkonqi-${mode#--}-validation.json"
cp -- "$temporary/validation-results.json" "$validation"
validation_sha=$(sha256sum "$validation" | awk '{print $1}')
if [[ $mode == --build ]]; then
    cp -- "$temporary"/*.deb "$temporary"/*.buildinfo "$temporary"/*.changes "$root/build/"
fi
printf 'DRKONQI_%s_PASS builder_id=%s recipe_sha256=%s base=%s validation_sha256=%s\n' "${mode#--}" "$builder_id" "$recipe_sha" "$base_image" "$validation_sha"
