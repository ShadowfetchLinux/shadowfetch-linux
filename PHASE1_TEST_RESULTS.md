# Phase 1 — Test results

Every figure here is literal output from the build host
(`shadowfetch-linux`), not a summary of intent.

## Validation strategy

For each defect the same two runs were made:

1. **Against the shipped 4.0.0 code** — the new test must FAIL. A regression
   test that has never seen the bug proves nothing. Where the fix and the test
   live in the same file, the pre-fix source was reconstructed with
   `git show HEAD:<path>` into a scratch tree and driven through the identical
   scenario.
2. **Against the fix** — the new test must pass, and every pre-existing suite
   for that package must still pass.

---

## Suite totals after Phase 1

| Suite | Result |
|---|---|
| `packages/shadowfetch-missions/tests` | **58 passed** (47 pre-existing + 11 new) |
| `packages/shadowfetch-control-center/tests` | **43 passed** (31 pre-existing + 12 new) |
| `packages/shadowfetch-defaults/tests` | **98 passed** (95 pre-existing + 3 new) |
| `packages/shadowfetch-fireproof/tests` | **36 passed** (26 pre-existing + 10 new) |
| `packages/shadowfetch-phoenix/tests` | **26 passed** (all new — the package had no suite) |
| `packages/shadowfetch-firewatchd/tests` | **5 passed** |
| `packages/shadowfetch-hwscan/tests` | **49 passed** |
| `packages/shadowfetch-fireline/tests/test_fireline_mcp.py` | **12 passed, 0 failed** |
| `packages/shadowfetch-fireline/tests/test_fireline_privilege.py` | **20 passed, 0 failed** (new) |
| `packages/shadowfetch-fireline/tests/test_firebreak_4.py` | **11 passed** |
| `packages/shadowfetch-fireline/tests/test_firebreak.sh` | **19 passed, 0 failed** (newly wired into `make test`) |
| `web/shadowfetch-linux-worker/tests` | **13 passed** (2 pre-existing + 11 new) |

**No test was weakened, skipped or deleted to obtain a pass.** One existing
assertion was changed: `test_fireline_mcp.py`'s handshake loop opened the `fs`
server with no scope, which only worked because of the W-05 defect. It now
passes an explicit scope, and the fail-closed behaviour it used to rely on is
asserted directly in the new privilege suite.

---

## Proof each test catches the original defect

### W-04 / W-05 — Fireline privilege

New suite run against the shipped code:

```
  FAIL no polkit action ships in the Fireline package
  FAIL packaging installs no polkit action
  FAIL fs refuses to start with no scope set
  FAIL fs refuses an empty scope
  FAIL fs refuses the whole home directory
  FAIL fs refuses a filesystem root
  FAIL fs refuses a top-level directory
  FAIL fs refuses /etc
  FAIL fs refuses a credential store
  FAIL fs refuses a relative scope
  FAIL fs refuses a scope that does not exist
  FAIL unscoped launch exits 2
  FAIL unscoped launch explains itself without a traceback
```

13 failures. After the fix: **20 passed, 0 failed.**

The W-05 defect demonstrated concretely — the shipped server, launched from
`$HOME` as an agent normally is:

```
OLD, launched from $HOME with no scope set -> agent can list:
   d .adal
   d .aider
   f .anthropic_new_token
   d .appstore
   ... (422 entries of the home directory)

--- same launch, patched code ---
   fs: SF_MCP_FS_ROOT is not set. The fs server refuses to start without an
   explicit scope -- it will not silently fall back to the working directory.
```

### W-06 / W-21 — Fireproof D-Bus

```
Ran 10 tests            (against shipped code)
FAILED (failures=6, errors=3)

Ran 10 tests            (after the fix)
OK
```

Including the behavioural assertion that an unauthorized `Verify` refuses
**without `run_verify` ever being called**, and that eight concurrent
`Analyze` callers start exactly one `build_analysis`.

### W-07 — R2 prune

Old logic, pinned verbatim in the test as `legacy_obsolete_release_objects()`,
given `--version 4.0.O`:

```
OBJECTS ACTUALLY DELETED: 7
   destroyed -> releases/shadowfetch-4.0.0-amd64.iso        <-- the LIVE release
   destroyed -> releases/shadowfetch-4.0.0-amd64.iso.asc
   destroyed -> releases/shadowfetch-4.0.0-amd64.iso.sha256
```

New code, same inputs:

```
--version '4.0.O'  REFUSED -> SystemExit: 2
--version ''       REFUSED -> SystemExit: 2
--version '4.0'    REFUSED -> SystemExit: 2
--version '4.0.1'  REFUSED -> RuntimeError: Kept release ... is not present
                              in the bucket; refusing to prune
OBJECTS ACTUALLY DELETED: 0   (all four cases)
```

Invariant, same run:

```
--version '4.0.0' --apply
OBJECTS ACTUALLY DELETED: 4
   apt/pool/.../shadowfetch-meta_2.1.1-1_all.deb
   releases/shadowfetch-2.1.1-amd64.iso{,.asc,.sha256}
```

**No network call and no real delete was issued at any point** — the entire
suite runs against a fake S3 client.

### W-08 / W-09 — Control Center privileged invocation

```
Ran 12 tests            (against shipped code)
FAILED (failures=7, errors=3)

Ran 12 tests            (after the fix)
OK
```

Sample failure, the login-shell assertion:

```
AssertionError: '-lc' unexpectedly found in
'x-terminal-emulator -e bash -lc shadowfetch-gpu; rc=$?; ...'
: a login shell sources user-writable ~/.profile before running a tool
  that asks for an admin password
```

### W-09 (adversarial) — workbench pkexec target

Against the shipped code, with the fix stashed:

```
FAIL: test_helper_is_not_read_from_the_environment
AssertionError: 'SHADOWFETCH_WORKBENCH_HELPER' unexpectedly found
```

After: **3 passed**, full defaults suite **98 passed**.

### W-15 / W-16 / W-17 — Missions

Each scenario replayed against the pristine HEAD module:

```
[OLD] rows in table = 1001; Store.list() returned 1000; complete = False
[OLD] Store.page() does not exist: truncation is silent, no signal exists
[OLD] review(undo) raised: StopIteration
[OLD] CLI review escaped its JSON error path: StopIteration
[OLD] agent added conftest.py + test_added.py -> state=waiting-review
[OLD] attempt 2 with the weakened test still on disk -> state=waiting-review
[OLD] '+++ ' header lines = 2 (1 is correct); forged header present = True
[OLD] announces truncation = False; cut mid-diff, no trailer
```

All corrected, 58 tests passing.

### W-10 / W-11 / W-18 — Recovery

```
Ran 26 tests in 2.712s   OK
dash -n OK (4 files) · SHELLCHECK CLEAN (4 files, --severity=warning -x)
```

Would-have-caught cases, replayed against `git show HEAD:`:

- **W-11** — same SIGTERM after `/boot` staging: the shipped script exits **0**,
  completes the exchange the user interrupted, leaves the archive in place and
  writes no journal. The fixed script exits 143, restores every kernel, removes
  the archive, unsets `next_entry`, leaves `@` untouched, and journals it.
- **W-18** — the shipped report is 0644, writes to whatever absolute path it is
  given, and leaks the drive serial, a MAC address and a `psk=`.
- **W-10** — replaying the layout suite against a HEAD-only tree: **10 of 12
  fail**, including nested-`/.snapshots` detection.

The harness invokes `renameat2(RENAME_EXCHANGE)` through `ctypes` because the
build host's coreutils 9.4 predates `mv --exchange`, so the exchange under test
is the real syscall. **Nothing was run against the real root, `/boot`, GRUB
environment or snapper.**

---

## W-01 — APT index, exercised end to end

```
BEFORE:  >>> umbra Valid-Until Sun, 20 Sep 2026 20:04:56 UTC (12.4 days remaining)
AFTER:   >>> umbra Valid-Until Sun, 07 Mar 2027 09:57:47 UTC (180.0 days remaining)

gpg: Good signature from "Shadowfetch Project <signing@shadowfetch.com>"
     using EDDSA key 8F13CE1535EE1F4A2916A1F73C5C900B7BE80CA1

34 index entries, identical before and after
6 SHA256 entries checked, 0 mismatched
```

No package was rebuilt and nothing was published.

---

## Independent verification of release-integrity claims

Checked directly rather than taken on report:

```
-- repo-root SHA256SUMS contents --
   ...shadowfetch-2.1.3-amd64.iso
   ...shadowfetch-2.1.4-amd64.iso
   ...shadowfetch-2.1.5-amd64.iso
   ...shadowfetch-3.0.0-amd64.iso
-- does it mention 4.0.0? --   0 matches
-- SHA256SUMS.asc --           Sep  4 22:37   (ISO was built Sep 6 16:22)

-- evidence bundle the manifest names --
   evidence_bundle_path    work/release-4.0.0/evidence-bundle-4.0.0.tar.gz
   evidence_bundle_sha256  None
   ls: cannot access '...evidence-bundle-4.0.0.tar.gz': No such file or directory

-- ISO's own detached signature --
   -rw-rw-r-- 1 rtx5060ti rtx5060ti 228 Sep  6 16:22 shadowfetch-4.0.0-amd64.iso.asc
```

The per-ISO signature path is intact; the aggregate-checksum path does not
cover 4.0.0.
