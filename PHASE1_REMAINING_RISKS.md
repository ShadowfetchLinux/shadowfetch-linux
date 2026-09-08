# Phase 1 — Remaining risks

Everything Phase 1 did **not** close, with an explicit owner or decision for
each. Ordered by consequence, not by work-item number.

---

## 1. RELEASE BLOCKER — the live APT index expires 2026-09-20

**State.** The tooling is fixed and proven (W-01): `REPO_VALID_FOR` is 180d,
`make refresh-index` re-signs the indices over the existing pool with no
rebuild, `make check-index` fails on an expiring index. Exercised on the build
host: 12.4 days → 180.0 days, good EDDSA signature, 34 index entries identical
before and after, 6/6 checksums matching.

**Risk.** None of that is live. The **published** `dists/umbra/Release` still
carries `Valid-Until: Sun, 20 Sep 2026`. On that date every installed
Shadowfetch machine begins failing `apt update` with an expired-repository
error, including the security-update path.

**Why Phase 1 stopped short.** Publishing is an outward-facing release action
against production R2. That is the owner's call, not a stabilisation task.

**Decision required.** Authorise publishing the refreshed `dists/` (and
`shadowfetch.gpg.asc`). This changes no package and no ISO — it republishes
metadata only. **There are 12 days.**

---

## 2. 4.0.0 was published without acceptance evidence, and the shipped source was never gated

This is the most serious governance finding of the phase, and it is worse than
"the manifest was not filled in".

**What the manifest claims.** 18 cases; 13 required cases `pending` with zero
evidence; `evidence_bundle_sha256: null`.

**What the disk shows.** The evidence tree holds 3,977 files, but only **16**
postdate the shipped ISO's build, and all 16 are already bound to the five
cases that pass. Everything else describes an earlier build candidate.

**The specific gaps.**

| Case | Reality |
|---|---|
| SRC-01, PKG-01 | **Never run on the shipped source.** The last source and package gates ran at commit `c551dfcd`. The published artifact is `e1293bfa` — the candidate12 change itself. The shipped tree has no source gate and no package gate. |
| RESOURCE-01, STRESS-01 | **Recorded as `pending`, but their own notes document runs that FAILED** — bridge 503s, relay readiness 503, a 120s container timeout, a 2704s stress run failing on Redis admission. `pending` reads as "nobody ran it"; the honest status is `fail` or an attributed `waived`. |
| UPGRADE-01, RECOVERY-01, DURABLE-01, SCOPE-01, GROK-01, GROK-VISUAL-01 | Evidence exists only for candidates 6–8, i.e. a different binary. `DURABLE-01`'s nearest artifact is a 9-second developer smoke against a 60-second requirement. |
| VISUAL-01 | The 10 candidate12 screenshots are 1024×768, below the recorder's own 1280×720 floor. They cannot be recorded even if someone wanted to. |
| EVIDENCE-01 | No SBOM anywhere. `evidence_bundle_path` names `work/release-4.0.0/evidence-bundle-4.0.0.tar.gz`, **which does not exist** — hence the null hash. |
| PUB-01 | No publish log, GitHub, R2 or site artifact anywhere. |

**How it shipped.** `make acceptance-audit` hard-codes `--allow-pending`, so it
prints a passing line while listing the gaps. The strict path
(`acceptance-gate`) is what would have blocked. W-14 splits these.

**Phase 1 deliberately recorded nothing.** Mapping candidate6 evidence onto
cases about candidate12 would have converted an honest gap into a false
attestation about a published operating system. That is the one outcome worse
than the current state.

**Decision required.** Either (a) re-run the QA battery against the shipped
artifact and record it, or (b) mark the cases `waived` with a named approver
and a written reason. Both are legitimate; silence is not. At minimum,
RESOURCE-01 and STRESS-01 should stop being described as `pending`.

---

## 3. The signed `SHA256SUMS` does not cover the 4.0.0 ISO

**Verified directly.** `SHA256SUMS` at the repo root lists 2.1.3, 2.1.4, 2.1.5
and 3.0.0 and contains **no 4.0.0 line**; `SHA256SUMS.asc` is dated
2026-09-04, two days before the ISO was built.

**Mitigation already in place.** The ISO carries its own detached signature
`shadowfetch-4.0.0-amd64.iso.asc`, which verifies against
`8F13CE1535EE1F4A2916A1F73C5C900B7BE80CA1`. A user following the per-ISO
verification path is fine.

**Residual.** A user following the aggregate-checksum path finds no entry for
the release they downloaded. Regenerate and re-sign `SHA256SUMS` at next
publish.

---

## 4. Guarding new test files changes mission behaviour (product decision)

W-16 makes an agent that **adds** a test or validation-config file fail the
validation guard. That is the correct security reading — a new
trivially-passing test is unreviewed validation — but it means a mission whose
legitimate task is "add unit tests for X" now fails, naming the files so a
person can inspect the diff.

**Decision required.** Either accept this, or route such missions to
`waiting-review` instead of `failed` so a human approves the added tests
rather than the mission dying. The second is friendlier and equally safe, but
it is a product call, not a security one.

---

## 5. Two D-Bus services still open their whole interface

W-06 converted Fireproof's bus policy to default-deny plus a per-member
allowlist. `com.shadowfetch.Ember1` and `org.shadowfetch.Firewatch1` still
carry a blanket `allow send_destination=… send_interface=…` for
`context="default"`.

**Assessed, not assumed.** Every exported method on both was enumerated:
`emberd` exposes `GetStatus` plus read-only properties (`Set` raises
`PropertyReadOnly`); `firewatchd` exposes only `Get*` readers and
`Subscribe`/`Unsubscribe`. **Neither mutates state.** The residual is
resource consumption via unbounded subscription, which W-20 addresses.

**Recommendation.** Apply the same allowlist shape to both in Phase 2. It is
cheap and it makes "a new method is unreachable until listed" a property of
the whole system rather than of one daemon.

---

## 6. `SHADOWFETCH_CHECKPOINT_BIN` remains an environment seam

`shadowfetch-firebreak` still honours this variable to locate the checkpoint
binary, and the containment test suite depends on it — `make test` sets it to
run against in-tree binaries.

**Severity is low but non-zero.** A sandboxed agent cannot set it: firebreak
builds its bwrap command with `--clearenv`. But anything in the launching
user's session can, and doing so replaces the tool that takes the
pre-mutation checkpoint — the undo safety net.

**Recommendation.** Keep it as a test seam but honour it only when an explicit
test flag is present, so a production launch cannot be redirected.

---

## 7. Prune bound is a judgement call

`--max-deletes` defaults to 200. It comfortably covers the `releases/` side,
but the same listing carries obsolete `apt/pool/` objects and the real bucket
was never measured (no R2 call was made — deliberately). A legitimate large
prune will abort **after** printing its full preview, and the operator raises
the bound. Safe by default; one extra deliberate step the first time.

The prune's `apt/pool/` branch still trusts the `Packages`/`Sources` indexes.
It has its own pre-existing non-empty guards, left alone as outside W-07.

---

## 8. Phase 2 will have to change a contract three gates enforce

`tools/mission_provider_contract.py` asserts:

```python
if set(runtimes) != {"codex", "offline"} or ast.literal_eval(fields["local_ai"]) != "deferred":
    raise RuntimeError("Mission capabilities advertise a removed or unsupported provider")
```

It is enforced by `source_gate_4_0_0.py:217`, `package_gate_4_0_0.py:239` and
`iso_gate_4_0_0.py:774`. **Adding any provider — which is the entire point of
the AgentProvider abstraction — fails all three gates until the contract and
its three call sites move together.** This is not a defect; it is a deliberate
anti-drift guard that Phase 2 must plan around in its first commit rather than
discover in CI.

---

## 9. Not attempted in this phase, by instruction

No AgentProvider abstraction, no credential broker, no Claude/Grok/Cursor
providers, no Mission Control redesign, and **no new privileged services** —
Phase 1 removed one polkit action and added none.

---

## 10. W-19 is correct but not yet complete end to end

Three loose ends, none of which undo the fix:

**a. `make iso` was not run.** The component path is proven — the keyring
package builds, contains exactly `/usr/share/keyrings/shadowfetch.gpg`
(root:root 0644), and `apt-get update` succeeds with `signed-by=` against both
the local repo and the live published one. What has *not* been executed is
live-build actually installing that `.deb` from `config/archives/` before its
own first `apt-get update` inside `lb_chroot_archives`. The reasoning is sound
and matches live-build's documented ordering, but **run one ISO build before
release**; if the ordering were wrong the build fails loudly rather than
shipping something broken.

**b. The key is still globally trusted as well as scoped.**
`/etc/apt/trusted.gpg.d/shadowfetch.gpg` continues to ship, so the key remains
valid for *any* repository, which is exactly what `signed-by=` exists to
prevent. Removing it would break
`packages/shadowfetch-phoenix/usr/libexec/phoenix-apt-repair` and its recovery
contract, so it was deliberately left. **Follow-up:** migrate
phoenix-apt-repair to the scoped keyring, then drop the global copy.

**c. Two source definitions were left alone**, both outside the work item's
scope and both recorded here rather than silently changed:
- `packages/shadowfetch-phoenix/.../apt-recovery/umbra.sources` — no
  `signed-by=`, relies on the global keyring above. Still functional.
- `web/shadowfetch-linux-worker/src/index.js:1005` — already uses
  `signed-by=`, but points at `/etc/apt/keyrings/shadowfetch.gpg` rather than
  `/usr/share/keyrings/`. **Two documented paths for one key is a defect
  waiting to happen; reconcile them.**

---

## 11. One W-20 claim rests on upstream source, not execution

`DeviceAllow=block-* r` was verified empirically to permit `O_RDONLY` and deny
`O_RDWR`. The claim that `smartctl` and `nvme smart-log` open the device
`O_RDONLY` and issue their ioctls on that descriptor comes from upstream
source, **not** from running them — smartmontools and nvme-cli are not
installed on the build host and installing them was out of scope.

**Confirm on a built ISO** that SMART data still appears in Firewatch. If it
does not, the fix is one character: `block-* r` back to `block-* rw` for the
specific node type that needs it.

---

## 12. Screenshot floor vs. what the release actually captured

The acceptance recorder now requires screenshots to be at least 1280×720. The
candidate12 captures are 1024×768. This is not a regression introduced by
Phase 1 — it means the shipped release's visual evidence was below the
project's own stated bar and could not have been recorded honestly either way.
Any re-run for VISUAL-01 needs captures at 1920×1080 and true 1366×768.

---

## 13. Deliberately unchanged

- **`qa/4.0.0/acceptance.json`.** Converting pending cases to `waived` needs an
  approver and written reasons that cannot be invented. The gate now refuses
  the manifest as it stands, which is the honest state.
- **The `apt/pool/` branch of the R2 prune.** It trusts the `Packages` and
  `Sources` indexes and has its own pre-existing non-empty guards. Outside
  W-07; not touched.
- **`SHADOWFETCH_AGENT_WORKSPACES`, `SHADOWFETCH_WORKBENCH_MANIFEST`,
  `SHADOWFETCH_WORKBENCH_ROOT`, `SHADOWFETCH_ELEMENT`.** These select *data*,
  not executables, and several are load-bearing for the test suites. Only the
  variables that chose a **program** were removed.
