# Phase 3.1 — operations checkpoint

Operational state, recorded separately from code health so release debt does not
disappear behind engineering progress. Nothing here was changed in order to make
this document green; where something was changed, it is because it was an open
production incident and it is recorded as such.

## Source control

| | |
|---|---|
| branch | `release/4.0.0` |
| HEAD at the time of writing | `822d5bb` |
| pushed? | **yes** — this phase began by pushing 67 commits that existed in exactly one worktree on one machine |
| pre-hardening reference | tag `phase3-audited` and branch `phase3-audited-e623c13`, both at `e623c13`, both pushed, neither will move |
| released `v4.0.0` tag | `57e637a` — **70 commits behind HEAD** |

The released 4.0.0 contains none of the Phase 1/2/2.5/3/3.1 work. That is a
deliberate state, not an oversight: the development branch has not been
released.

## Production incident — CLOSED during this phase

Six App Store URLs (privacy, support and marketing for **Beverlys Voice**,
ASC 6806444535, and **Vouchspire**, ASC 6799457861) returned 404 on
`www.shadowfetch.app` for roughly 24 hours.

**Cause.** Not the known Cloudflare Pages whole-directory hazard. A Workers
deploy at 2026-09-08T01:04Z shipped from branch `posthog-install-6fac`, which had
been cut from a stale `origin/main` and never contained the 2026-09-06 cutover
commits. Those commits carry the *hand-authored* per-app pages:
`src/pages/apps/` holds 22 files on `main` and 3 on the deployed branch. Only 2
of the 7 apps on that host broke because the other 5 are generated from
`catalog.json`; these two are hand-authored only, and Apple's iTunes lookup
returns `resultCount: 0` for both, so the catalog can never generate them.

**Repair.** Branched from `main`, cherry-picked only the PostHog commit
(`143a161`), rebuilt, and verified the output was a **strict superset** of what
was live before deploying: 0 pages removed, +7 added, app directories 582 → 584.
Rollback id recorded first (`61092dc8-b70d-44de-8252-b831261655df`).
Deployed as version `d1ebce78-198c-4489-95ec-30888e75ff0f`.

**Verification.** All six URLs 200. The other five apps on that host still 200.
The cutover redirect intact (`/` → 301 `www.shadowfetch.com`, `/apps/adiabat` →
301). The watchdog's own run then recorded:

```json
{"finishedAt": "2026-09-09T05:08:32Z", "result": "ok",
 "checked": 1765, "failures": "0", "repaired": "no", "exit": 0}
```

**What it touched.** Only the Worker `shadowfetch-app-site` and its asset
bundle. It did not touch the `shadowfetch-ios-apps` Pages project that carries
the bulk of the compliance pages, and it did not touch `shadowfetch-astro`
(.com).

## Operational debt still open

* **`shadowfetch-app` `main` has diverged from its remote.** Local `main` is
  `00b00d0`; `origin/main` is `04f8421`, and neither is an ancestor of the
  other. The fix branch `fix-compliance-pages-20260909` IS pushed, so nothing
  deployed is at risk, but the divergence needs a human merge decision. It was
  not force-pushed.
* **The gate hole that allowed the incident.** `npm run deploy` runs a
  catalog-freshness `verify`; a bare `npx wrangler deploy` skips it, and nothing
  asserts that `dist/apps` never shrinks. A build that loses pages can still
  ship. That assertion does not exist yet.
* **`managed.json` has a data error.** ASC id `6799457861` is attached to two
  different names — "Vouchspire: Verify Calls" and "Watershedlog: Basin Notes".
  One record is wrong.
* **Neither repaired app is publicly listed.** Both return `resultCount: 0` from
  Apple's lookup in US/GB/CA/AU/DE. The exposure was therefore review-time
  rather than live-public — which does not reduce its urgency, since a reviewer
  fetches exactly these URLs, but it does correct the framing.
* **CLAUDE.md understates the blast radius.** It says the repair verifies
  "1,014 managed URLs" for "~530 live apps". The managed set is now **1,765 URLs
  across 658 apps and 24 Pages projects**.
* **An orphaned mission worker was found burning a full CPU core** for 4h25m on
  the build box. It was a development-era process started at 17:49:48 on
  2026-09-08, an hour before the inotify worker-loop commit, holding an
  intermediate loop in memory and bound to a throwaway `/tmp` database. Killed.
  The current committed worker does not reproduce it (measured: 0% CPU across
  three independent 20s windows). **There is no systemd unit for the mission
  worker at all**, which is why one could escape and run unsupervised.

## Gates

| gate | result |
|---|---|
| `make test` | see PHASE3_1_TEST_RESULTS.md |
| `make source-gate` | see PHASE3_1_TEST_RESULTS.md |
| `make package-gate` | see PHASE3_1_TEST_RESULTS.md |

## Environment limits worth stating

* The Firebreak installed at `/usr/bin/shadowfetch-firebreak` on the build box
  **predates the repo** and rejects `--memory-mb`. A real mission fails with an
  unrelated-looking error ("Cannot inspect media") unless the repo's Fireline
  binary is ahead of it on `PATH`. The engine has no runtime version check for
  the Firebreak it invokes.
* Live APT `Valid-Until` could not be read from this host during this phase; the
  package repository was not reachable. Recorded as unknown rather than assumed.
* No live cloud provider has been exercised end to end. `offline-media` and
  `codex` are the only wired providers.
