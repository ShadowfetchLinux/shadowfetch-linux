# CI secrets

**There are none, and that is the point of this file.**

## What the pipeline actually is

`.github/workflows/build-iso.yml` is named *Source and package checks*. It runs
`make test` and `make packages` on `ubuntu-24.04`, on pushes to `main` and
`release/**`, on pull requests, and on demand. It has `permissions: contents:
read`, contains **zero** `secrets.` references, and uploads its build output as
`unsigned-candidate-packages`.

It does not build an ISO, sign anything, publish anything, or touch R2, and it
has no access to a credential that would let it.

## What this file used to say

It described a release pipeline that did not exist, and instructed exporting
the ISO and APT **signing private key** into GitHub Actions for it. Writing
down how to hand a signing key to a workflow that has no use for it is not a
neutral inaccuracy: it is an instruction, sitting in the repository, to widen
the blast radius of a CI account for no gain. `RELEASE_GITHUB_TOKEN`, named
there and used by nothing, should be revoked if it still exists.

## Where signing and publishing actually happen

On the maintainer's Linux publisher, by hand, from the authorized source tree:

* `make sign` — a detached GPG signature over the ISO, with the maintainer's
  private key, which is not in this repository and is not reachable from CI.
* `tools/publish_release_4_0_0.py --apply` — uploads to R2 with credentials
  taken from the process environment and never written into the tree. It
  refuses to run unless the platform, the tree and the invoking user all match
  the authorized publisher, verifies the ISO's signature against the release
  fingerprint before uploading anything, streams the uploaded bytes back and
  re-hashes them, and only then writes `releases/CURRENT.json`.

If a future pipeline needs a secret, this file is where its scope, its owner
and its rotation belong — described after it exists, not before.
