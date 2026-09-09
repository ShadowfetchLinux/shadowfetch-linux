# Release gates

One implementation per gate family, plus a version DATA file per release.

    gate.py         shared foundation: trusted program resolution, version data
    source_gate.py  make source-gate
    package_gate.py make package-gate
    iso_gate.py     make iso-gate
    acceptance.py   make acceptance-audit / make acceptance-gate
    evidence.py     builds the SBOM, dossier and release-facts bundle

    versions/<version>.toml   everything that varies because the version changed
    trusted-programs.toml     HOST policy: absolute paths + digests for programs
                              that are not packaged into a root-owned directory

## Cutting a release

Add `versions/<new version>.toml`, set `historical = true` in the previous one,
and set `VERSION` in the Makefile. That is the whole change. Do not copy a gate
module.

Run a gate against a specific release explicitly:

    tools/release/package_gate.py --version 4.1.0

With no `--version`, a gate uses `SHADOWFETCH_RELEASE_VERSION`, and failing that
the single non-historical data file. Two candidates is an error, not a guess.

## What belongs in the data file, and what does not

In the TOML: the version, the edition and codename, the package allowlist, the
smoke set, the signing fingerprint, the container smoke commands, and any
literal that carries the version number (written with a `{version}` placeholder).

In the module: structural facts about the product -- which payload paths must
exist, which safety contract a script must contain, how the Calamares sequence
must be ordered. These change when the PRODUCT changes, are reviewed once, and
must not be duplicated per release.

## Why the historical gates are gone

`tools/` used to hold six copies each of `source_gate`, `package_gate`,
`iso_gate` and `verify_acceptance` and five of `build_release_evidence` --
15,265 lines, of which only about 3,000 were live. Two defects followed:

* the unit tests were left pointing at old copies. The only ISO-gate tests
  targeted `iso_gate_2_1_5.py`, so the gate logic that actually ran for 4.0.0
  had none; the package gate had no test at any version.
* fixes landed in one copy. The Git-unavailable handling, the evidence entropy
  floor and the waiver contract exist only in the 4.0.0 copies, so the archived
  copies still accept a 0-byte "pass".

The old modules are recoverable from Git (tags `v2.1.5`, `v3.0.0`, `v3.5.0`,
`v4.0.0`), which is a better reproducibility record than a working-tree copy
because it also carries the tree that gate ran against.

**Honesty note.** Running today's implementation against an old version's data
file re-gates that release with TODAY's logic. It does not reproduce the gate
that shipped it. To reproduce a historical gate, check out the tag and run the
module that was in that tree.

## Trusted program resolution

Any executable whose output establishes, verifies, enforces or attests a
security fact is invoked through an explicit trusted ABSOLUTE path with a
recorded trust classification. PATH is never consulted.

* `TRUST_SYSTEM` -- found under `/usr/bin`, `/bin`, `/usr/sbin`, `/sbin`,
  `/usr/local/bin` or `/usr/local/sbin`, with the file and every parent
  directory root-owned and not group- or world-writable (checked on every
  resolution, not assumed). This is the wanted state.
* `TRUST_PINNED` -- an absolute path recorded in `trusted-programs.toml`
  together with its SHA-256, re-verified immediately before every invocation.
  Weaker: a replacement written between the check and `execve` is not caught.
  Use it only until the program can be installed into a root-owned directory.

Each gate prints its resolution table before doing any work, so a run's log says
which binary decided which fact.

The build host currently pins `gitleaks` and `shellcheck`, which live in
`/home/<builder>/.local/bin`. `gitleaks` is the only control that decides "no
credential shipped in this release", and until Stage Q it was found by PATH
lookup and run by bare name. Moving both under `/usr/local/bin` as root and
deleting their pins removes the exposure entirely.
