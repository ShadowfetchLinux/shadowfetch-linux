# FINAL_RELEASE_REPORT

**Shadowfetch Linux 4.0.0 is NOT releasable today, and the reason is not a
missing feature. It is that the accepted artifact no longer describes the
software.** This document says exactly what stands in the way, in the order it
has to be dealt with.

## The one-sentence answer

The ISO on disk (`137c1f29…`, cut 2026-09-06 16:22) predates Stages A, B, C and
E, so the Firebreak inside it is not the Firebreak this tree ships; the ISO gate
will detect that and fail; and a new image invalidates every recorded acceptance
case. Everything else on this list is smaller than that.

## What the gates say right now

| gate | verdict | note |
| --- | --- | --- |
| `make test` | PASS | 839 tests + the six adversarial suites |
| adversarial suites | PASS | 20/20, 18/18, 0-of-16-undetected, 15/15, 7/7, 21/21 |
| `drift_gate` | PASS with BLOCKED | 0 DRIFT; the remaining BLOCKED items are named duplications with remedies |
| `source_gate` | PASS once `make test` is green | it runs `make test`, so it inherits that verdict |
| `package_gate` | PASS | after the renames and deletions are staged |
| `iso_gate` | **WILL FAIL** | see below — and it is the gate doing its job |
| `acceptance` (strict) | **FAILS, 21 errors** | 12 required cases pending, 5 recorded passes now refused as unbound |

## Why the ISO gate will fail, and why that is correct

`critical_payload_parity_gate` compares the squashfs payload BYTE FOR BYTE
against freshly built packages, to catch a stale live-build cache hit. Measured:

```
                                    ISO chroot (Sep 6)  fresh .deb (Sep 9)   source (now)
usr/bin/shadowfetch-firebreak       d559b8a2…           2d699338…            20640c3a…
usr/bin/shadowfetch-checkpoint      bc077315…           7703a2d0…            7703a2d0…
usr/bin/shadowfetch-mcp             6b2dbfb5…           c058597f…            c058597f…
usr/lib/shadowfetch/mcp/sf_mcp.py   cba98e3f…           9902143a…            0fba2c10…
```

All four `shadowfetch-fireline` critical payloads differ. The network namespace
work, the egress filter, the masked paths and the sandbox resolver all landed in
Firebreak after that image was cut. There is no way to make the gate pass except
by cutting a new image, and the gate is right to refuse.

## Four gates that would have PASSED while the thing they gate was untrue

Found by audit and **fixed in this commit**. These matter more than the pending
cases, because a pending case is visibly unproven and a false pass is not.

**1. The acceptance gate never opened the artifact it accepts.** `verify()`
checked that `artifact.iso_sha256` was a non-empty string and stopped. A
manifest could name the digest of an image that did not exist, or of a
different image entirely, and `make acceptance-gate` printed
`ACCEPTANCE_PASSED`. Two tools downstream — `evidence.py` and
`package_release_evidence` — already re-hashed the real file and refused on
mismatch, so the check existed twice and zero times in the gate the release
criteria point at. It re-hashes now, in both phases, and absence of the file is
an error rather than a skip.

**2. Evidence was bound to nothing, and a REQUIRED case was passing on twelve
bytes.** An evidence entry was `{kind, path, sha256}` and nothing more. ICE-01's
sole evidence is `identity.txt`, 12 bytes reading `ice\noffline\n` — over the
8-byte floor, over the 1.5 bits/byte entropy floor, and about no particular
image. FIRE-01's is 334 bytes of `os-release` text. The floors were built to
stop 0-byte files and blank screenshots and they do that; they cannot tell a
real result from a plausible-looking one, and nothing else was trying. Evidence
entries now carry `artifact_sha256`, stamped by `record` from the manifest so a
person can neither forget it nor choose it, and `verify` refuses an entry that
names a different image or none. **All five previously recorded passes fail this
check and should**: 13 errors became 21.

**3. `make iso-gate` teed its verdict into its own evidence file.** `ISO_GATE_LOG`
was `work/qa-4.0.0/evidence/iso/iso-gate.log`, which is precisely the path
ISO-01 records as evidence. The proof that the ISO gate passed was the gate
saying so; and re-running it overwrote the file whose SHA-256 the manifest
pinned, so the next `verify` failed on a hash mismatch for a case nobody had
touched. The log is run-stamped now, and a gate never writes into the file it
will be graded on.

**4. The Makefile claimed a gap it had not closed.** *"There is deliberately no
target that marks a case passed"* is true of the VM harness and false of the
system: `acceptance.py record <case> --status pass --evidence <file>` is a
supported command with no run behind it, and it is how every recorded pass in
the manifest was written. The comment now says which half is closed and what
actually stands between that command and a false pass — which, after fix 2, is
that the evidence must name the image under test.

## The twelve required cases that are pending

`SRC-01, PKG-01, UPGRADE-01, DURABLE-01, SCOPE-01, GROK-01, GROK-VISUAL-01,
RESOURCE-01, RECOVERY-01, STRESS-01, VISUAL-01, EVIDENCE-01`.

Two of them are worse than pending and this must not be lost: **RESOURCE-01 and
STRESS-01 carry recorded FAILURES in their notes** — a 2704-second concurrent
load run that failed with repeated Redis admission / HTTP 503 and health-exec
faults, and a later 16 GiB rerun that also failed with seven bridge 503s, one
relay readiness 503 and a 120-second container timeout. They sit at `pending`,
which reads to the gate exactly like never having been run. They need
remediation and a clean 45-minute run, or an explicit waiver with a named
approver. Silence is the one option that should be off the table.

Two more cannot run at all:

* **UPGRADE-01** — the 3.5.0 installed base image the upgrade clones are layered
  on no longer exists on this host, so every clone is unopenable.
* **INSTALL-01** — five consecutive runs BLOCKED at ~294 s each: *"expected
  exactly one 'calamares' application, found 0"*. The installer never appears on
  the accessibility bus. A live harness/guest defect, not a flake.

And three required cases can never be promoted by the VM harness as it stands,
because each VM case proves only part of the manifest case and the harness
refuses to record a partial proof — which is the right refusal, and means
criterion 28 currently buys evidence and not acceptance:

* INSTALL-01 needs one case consuming a BIOS *and* a UEFI pass for the same
  artifact; that composite case does not exist.
* UPGRADE-01 needs a Phoenix Point restore leg.
* RECOVERY-01 needs the Fireline project diff/undo leg.

## Release evidence does not exist yet

`work/release-4.0.0/` contains none of the five generated documents
(`dossier-4.0.0.md`, `packages-4.0.0.manifest`, `sbom-4.0.0.cdx.json`,
`sbom-sources-4.0.0.txt`,
`release-facts.json`) nor `release-evidence-4.0.0.sha256`. `tools/release/evidence.py`
produces them and nothing in the Makefile invokes it. `approved-inputs.json`,
a required argument of the evidence packager, has never been authored.
`artifact.evidence_bundle_sha256` is `null` and is set by hand after the bundle
is inspected — chicken-and-egg by design, and a manual step in the critical path.

## "Reproducibly" is currently a recorded claim, not a check

The manifest records `source_commit e1293bfa…` and `source_tree 2cb7ad6a…`, and
both resolve. **Nothing reads them.** There is no rebuild-and-compare step
anywhere, and `live-build` is not bit-reproducible. Either add the comparison or
stop using the word: what exists today is provenance written down, which is
worth having and is not the same claim.

## The order to do this in

1. **Cut candidate 13** from a quiesced tree, record its commit and tree, run
   `make iso-gate`. Everything below depends on this.
2. **Re-record the five passes** against the new artifact. They will now carry
   its digest, which is the point.
3. **Fix the two harness blockers** — the Calamares AT-SPI defect and the
   missing 3.5.0 base image. These can start now, in parallel with 1.
4. **Add the three composite VM cases** so INSTALL-01, UPGRADE-01 and
   RECOVERY-01 can be promoted honestly rather than by hand.
5. **Deal with RESOURCE-01 and STRESS-01** — remediate or waive with a name.
6. **Produce the release evidence**: run `evidence.py`, author
   `approved-inputs.json`, build and inspect the bundle, record its digest.
7. **Then** `acceptance.py verify` strict, `pre_release_check.sh`, and the
   publish plan.

## What is genuinely ready

Worth stating, because the list above is long and the engineering underneath it
is not the problem:

* The sandbox: two postures, both namespaced, egress filtered by nftables where
  hosts are declared, paths masked by the mount namespace, resource limits by
  systemd, and a resolver that works.
* Four providers behind one interface, each conformance-cased, each sealed by
  digest, none of them a branch in the engine.
* A tamper-evident audit chain with domain records bound into it, approvals
  witnessed field by field and now covering destinations, and a verifier that
  distinguishes fabricated from legacy from rewritten.
* Six adversarial suites, all passing, that measure refusals rather than
  behaviour.
* A publisher whose ordering is correct: signed InRelease last among the
  objects, the ISO's bytes streamed back and re-hashed, and the current-release
  pointer written only after that.
