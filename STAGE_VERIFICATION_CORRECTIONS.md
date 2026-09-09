# What the verifiers found, and what it changed

Eight stages ran in parallel; each was then checked by an independent agent that
re-ran the evidence rather than reading the report. The corrections below are
worth more than the successes, because every one is a claim that would otherwise
have shipped as true.

## The finding that mattered most

**The release gate carried the defect it was built to fix, one hop further out.**

Stage Q correctly closed a live CRITICAL: `source_gate` resolved `gitleaks`
through `PATH`, and on the build host `~/.local/bin` precedes `/usr/bin` and is
builder-writable. Gitleaks is the only control deciding "no credential shipped
in this release". Anything able to drop a file there could have made the release
secret scan pass unconditionally.

Its verifier then showed that resolving the *program* is not enough, because the
program resolves **its own helpers** through the PATH it inherits:

```
/usr/bin/dpkg-deb -f <pkg>.deb Package Version
  -> Package: grub-btrfs / Version: 4.14-2
PATH=$FORGED:$PATH /usr/bin/dpkg-deb -f <same deb> Package Version
  -> Package: totally-not-this-package / Version: 9.9.9-forged      exit 0
```

`dpkg-deb` shells out to `tar` to read the control member. `package_gate` builds
its "exact binary inventory" from exactly those calls and classifies `dpkg-deb`
ROLE_SECURITY. **Fixed**: `gate.run`/`gate.output` pin the child's PATH to
trusted directories. Verified by re-running the same forgery — the direct call
still reports `totally-not-this-package`, the call through `gate.output` reports
`grub-btrfs`.

Two relatives went with it:

* `publish_release_4_0_0.py` ran `gpg`, `gpgv` and `sha256sum` by bare name.
  Those decide whether the **shipped ISO's** signature and digest are genuine —
  the last check before an artifact reaches the public. Now absolute, with a
  pinned child PATH.
* `ProgramResolver` honoured `SHADOWFETCH_TRUSTED_PROGRAMS` from the
  environment, so an env var could redirect the entire pin policy for
  security-role programs. Removed: a test passes its trust file explicitly,
  which is a caller decision rather than ambient state.

## Stragglers of the same invariant, found by three different agents

Each was reported rather than edited, because the file belonged to someone else
that session. All are now fixed:

| where | what it decided |
|---|---|
| `shadowfetch-firebreak` `check` | printed "Firebreak ready" after a bare `which("bwrap")` |
| `sf_mcp` `system_passport` | preferred `which("shadowfetch-passport")` over the absolute path — an **attestation of the machine's security posture** that an agent reads back |
| `shadowfetch-passport` `_hwscan_command` | preferred `which("shadowfetch-hwscan")` — the hardware half of that attestation |
| `sf_missions` ×3 | reported `bwrap`/`shadowfetch-firebreak` availability as a capability, and resolved a command it then executed |
| `shadowfetch-firebreak` `checkpoint_bin` | resolved the binary that takes the snapshot Undo restores from |

The corrected pattern already existed in the tree (`busutil.py` uses
`shutil.which(..., path=TRUSTED_PATH)`), so these were stragglers rather than a
design position.

## Over-claims the verifiers broke

Recorded because "ENFORCED" is the word this program exists to protect.

* **Stage Z** — two properties listed as mutation-proven are not. Mutating
  `if not chosen.usable:` to `if False:` leaves all 41 tests passing. The test
  named for it, `test_run_refuses_a_tool_that_does_not_classify`, actually
  exercises the *path is None* branch, not the trust-class branch. The mechanism
  exists in code; nothing would notice if it were deleted.
* **Stage V** — over-claims ENFORCED on two of eight items, and its central
  BLOCKED citation is stale.
* **Stage T** — one ENFORCED bullet has no test behind it; the trust check is
  covered only in its positive case, and nothing exercises the refusal path in
  `main()`. The verifier proved the refusal works by hand, which is evidence
  that the mechanism is right and the *suite* is incomplete.
* **Stage X** — one false enforcement claim, which the verifier reproduced and
  broke.

None of these were corrected in the code by the stage that made them. They are
listed here so the claims matrix does not inherit them.

## Still open from this pass

* `pkexec` is resolved through PATH at nine call sites. Not a root escalation —
  a hostile `pkexec` earlier on PATH runs as the user — but it is the same
  shape and should be closed.
* `evidence.py` and the ISO gate have never been run end to end; both mount the
  4 GB ISO. They are VALIDATED, not PASSED, and the distinction is kept.
* The btrfs checkpoint path is written and compiles but is **unproven**: the
  build box's `/tmp` is ext4, so every test took the tar path.
* Phoenix's `phoenix-restore` remains the shell driver of the exchange by
  design, so `RestoreTransaction` governs RESUME, not restore.
* Nothing was recorded into `qa/4.0.0/acceptance.json`. Three VM cases pass, but
  each carries a coverage gap against its required release case, and the harness
  refuses to record a partial as a PASS. That refusal is the feature.
