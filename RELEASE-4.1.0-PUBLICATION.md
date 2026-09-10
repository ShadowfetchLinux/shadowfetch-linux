# RELEASE-4.1.0-PUBLICATION

How 4.1.0 reaches its three surfaces — GitHub, archive.org, shadowfetchlinux.org
— what each one needs, in what order, and what breaks if the order is wrong.

Reconnaissance only. Nothing in this document has been executed. Every fact
below was measured on `shadowfetch-linux` on 2026-09-09 with the command quoted
beside it; where something could not be measured it says so instead of guessing.

There is no press release, no reviewer package and no social post in this
release. That is a decision, not an omission.

---

## 1. What CANNOT be done yet, and why

**None of the three surfaces can be published today, because 4.1.0 does not
exist as an artifact.** All three publish the same thing: an ISO, its SHA-256,
its detached signature, and prose that restates both. There is no such ISO.

Five blockers, in the order they bite. **B1 has since been resolved** by the
change this document ships with; it is kept, with its original readings, so the
resolution is auditable rather than silently absorbed.

### B1 — the version identity (RESOLVED in the change this ships with)

```
$ cat packages/shadowfetch-branding/data/usr/share/shadowfetch/version
4.0.0
$ grep "VERSION_ID\|PRETTY_NAME" packages/shadowfetch-branding/data/usr/share/shadowfetch/os-release.shadowfetch
PRETTY_NAME="Shadowfetch Linux 4.0.0 (Umbra)"
VERSION_ID="4.0.0"
$ head -1 packages/shadowfetch-defaults/debian/changelog
shadowfetch-defaults (4.0.0-1) umbra; urgency=medium
$ ls shadowfetch-4.1.0*
ls: cannot access 'shadowfetch-4.1.0*': No such file or directory
$ ls qa/ | grep 4.1            → qa/4.1.0 ABSENT
$ ls ~/.sfbuild/release-sources/shadowfetch-linux-site/releases/ | grep 4.1
                               → site releases/4.1.0.json ABSENT
```

**Every reading in the block above is superseded.** It was taken on
2026-09-09 between 17:45 and 18:02, while other agents were working this tree,
and it is kept verbatim because it is what the blocker looked like and because
the sentences below say precisely which parts stopped being true. Treat any
"absent" elsewhere in this document the same way: a timestamped reading, not a
standing fact.

Re-measured at 23:34 on the same day, after the stamp landed:

```
$ cat packages/shadowfetch-branding/data/usr/share/shadowfetch/version
4.1.0
$ head -1 packages/shadowfetch-defaults/debian/changelog
shadowfetch-defaults (4.1.0-1) umbra; urgency=medium
$ grep historical tools/release/versions/4.0.0.toml tools/release/versions/4.1.0.toml
4.0.0.toml:historical = true
4.1.0.toml:historical = false
$ ls qa/4.1.0/
acceptance.json
$ python3 tools/drift_gate.py | tail -2
drift gate: 0 DRIFT, 5 BLOCKED across 10 checks
```

So B1 is closed: `python3 tools/stamp_version.py 4.1.0` reports STAMP COMPLETE
and exits 0, `Makefile:13` is `VERSION ?= 4.1.0`, and
`RELEASE_DATA := $(RELEASE_TOOLS)/versions/$(VERSION).toml` resolves. What is
still true, and is the reason this section is not deleted: **there is no 4.1.0
ISO.** Stamping the identity is not building the artifact, and every surface
below publishes the artifact.

Building and signing that ISO is out of this session's remit and is not in this
checklist. This document starts at the point where a signed, accepted
`shadowfetch-4.1.0-amd64.iso` is on disk.

### B2 — the R2 publisher cannot build a plan, and could not for 4.0.0 either

`tools/publish_release_4_0_0.py` is a precondition for all three surfaces
(§3). It refuses at `publication_plan()` for two independent reasons:

*The eight evidence files it requires are not on disk.*

```
$ ls work/release-4.0.0/ | grep -E "dossier|sbom|manifest|evidence|facts"
candidate6-preserved-artifacts
```

That is the only match, and it is a directory, not one of the eight. The
publisher's `EVIDENCE` tuple (`tools/publish_release_4_0_0.py:41-44`) names
`dossier-`, `packages-…manifest`, `sbom-…cdx.json`, `sbom-sources-`,
`release-facts-`, `release-evidence-…sha256`, `evidence-bundle-…tar.gz` and
`evidence-bundle-…contents`, and `object_for()` raises
`Missing, empty or symbolic-link release file` on the first one absent.

They are also absent from the live artifact host, which is how 4.0.0 shipped:

```
$ for f in dossier-4.0.0.md packages-4.0.0.manifest sbom-4.0.0.cdx.json \
           release-facts-4.0.0.json evidence-bundle-4.0.0.tar.gz \
           shadowfetch-4.0.0-amd64.iso.sha256 shadowfetch-4.0.0-amd64.iso.asc; do
    curl -sS -o /dev/null -w "$f -> %{http_code}\n" \
      https://www.shadowfetch.com/linux/download/$f; done
dossier-4.0.0.md -> 404
packages-4.0.0.manifest -> 404
sbom-4.0.0.cdx.json -> 404
release-facts-4.0.0.json -> 404
evidence-bundle-4.0.0.tar.gz -> 404
shadowfetch-4.0.0-amd64.iso.sha256 -> 200
shadowfetch-4.0.0-amd64.iso.asc -> 200
```

*The accepted manifest declares no bundle hash.* `qa/4.0.0/acceptance.json` has
`"evidence_bundle_sha256": null`, and the publisher compares against it at
`:76-78`. A 4.1.0 manifest with a null there fails the same way.

So 4.1.0 needs a real `qa/4.1.0/acceptance.json` and a real evidence bundle
(`tools/package_release_evidence_4_0_0.py` is the producer) before the publisher
will emit even a plan.

### B3 — the R2 credentials are not on this machine

The publisher takes them from the process environment and refuses without them
(`:239-244`). Nothing on disk holds them:

```
$ grep -rIl "SHADOWFETCH_R2_ENDPOINT\|AWS_ACCESS_KEY_ID" ~/.config ~/.bashrc ~/.profile ~/.zshrc
   (no output)
$ ls ~/.config/shadowfetch/
cf_deploy_token  github.env  ntfy.topic  pexels_key  unsplash_key  zernio.key
```

`~/.config/shadowfetch/cf_deploy_token` is a Cloudflare API token, not an R2
S3 key pair. The maintainer supplies `AWS_ACCESS_KEY_ID`,
`AWS_SECRET_ACCESS_KEY` and `SHADOWFETCH_R2_ENDPOINT` by hand, per run. That is
deliberate — the publisher's docstring says credentials are never written into
the source tree — and it is not a defect to fix.

### B4 — the site's own test suite will refuse the deploy

`tests/content.test.mjs:181` is a test named for 4.0.0 that is **not**
version-guarded, unlike its neighbour at `:218`:

```
181:test("4.0.0 is the signed download and remaining cases stay honest", () => {
192:  assert.match(download, /shadowfetch-4\.0\.0-amd64\.iso/);
193:  assert.doesNotMatch(download, /shadowfetch-3\.5\.0-amd64\.iso/);
218:  if (currentRelease().version !== "4.0.0") return;       // ← the guard the other test has
```

`src/data/release.ts` globs `releases/*.json` and takes the newest by date, so
the moment `releases/4.1.0.json` exists, `dist/download/index.html` renders
4.1.0 and line 192 fails. `npm run deploy` is
`npm run release:verify && wrangler deploy`, and `release:verify` starts with
`npm test`. The deploy therefore stops before Wrangler is reached. This must be
fixed in the site repo first — see §6.3.

### B5 — a dated deadline on the site deploy: 2026-09-13 18:10:14 GMT

`npm run deploy` runs `npm run data:apt:freshness`, which fails the release when
the signed APT metadata has fewer than seven full days left:

```
$ curl -sS https://www.shadowfetch.com/linux/apt/dists/umbra/InRelease | grep -m3 -i "^Date:\|^Valid-Until:\|^Codename:"
Codename: umbra
Date: Sun, 06 Sep 2026 18:10:14 GMT
Valid-Until: Sun, 20 Sep 2026 18:10:14 GMT
$ cat src/data/apt-freshness.js | head -1
export const APT_MINIMUM_VALIDITY_DAYS = 7;
```

Valid-Until minus seven days is **2026-09-13 18:10:14 GMT**. After that instant,
the site cannot be deployed at all — not for 4.1.0, not for a typo fix — until a
fresh signed `InRelease` is published to `.com/linux/apt/dists/umbra`. That
republish is part of the R2 publish (§3), so the dependency is real, not
cosmetic.

Related, and worth stating plainly: the live APT tree still serves 3.5.0-1.

```
$ curl -sS https://www.shadowfetch.com/linux/apt/dists/umbra/main/binary-amd64/Packages | grep -c "^Package:"
16
$ ... | grep -m5 "^Version:"
Version: 4.14-2
Version: 3.5.0-1
Version: 3.5.0-1
Version: 3.5.0-1
Version: 3.5.0-1
```

---

## 2. The surfaces, and one prerequisite that is not a surface

| # | Surface | Deployed from | Worker / service | Credential |
|---|---|---|---|---|
| 0 | **R2 artifact bucket** (prerequisite) | `~/projects/shadowfetch-4.0.0` | bucket `shadowfetch-linux` | R2 S3 keys, process env only |
| 0b | **artifact worker** (optional, see §3.3) | `~/projects/shadowfetch-4.0.0/web/shadowfetch-linux-worker` | Worker `shadowfetch-linux` | Wrangler OAuth |
| 1 | **GitHub** | `~/projects/shadowfetch-4.0.0` | `ShadowfetchLinux/shadowfetch-linux` | `GH_TOKEN` in `~/.config/shadowfetch/github.env` |
| 2 | **archive.org** | anywhere the ISO is | item `shadowfetch-linux-4-1-0` | `~/.config/ia.ini` |
| 3 | **shadowfetchlinux.org** | `~/.sfbuild/release-sources/shadowfetch-linux-site` | Worker `shadowfetch-linux-site` | Wrangler OAuth |

Surface 0 is not one of the three the maintainer named, but all three of those
publish URLs that resolve to it. It is the floor.

---

## 3. Surface 0 — R2, and the pointer that decides what is live

### 3.1 The tool and the invocation

```sh
cd /home/rtx5060ti/projects/shadowfetch-4.0.0
python3 tools/publish_release_4_0_0.py            # plan only, prints JSON
python3 tools/publish_release_4_0_0.py --apply    # uploads
```

`make publish` (`Makefile:493-494`) wraps the `--apply` form behind
`pre-release-check`.

Before it uploads anything it runs, in this order (`main()`, `:220-231`):
`tools/release/acceptance.py --version 4.0.0 verify`, then
`tools/pre_release_check.sh` with a seven-day repo-validity floor, then
`sha256sum --check` on the ISO's sidecar, then `verify_signatures()` — which
checks the repository key's fingerprint is
`8F13CE1535EE1F4A2916A1F73C5C900B7BE80CA1`, `gpgv`-verifies the ISO's detached
signature, and `gpgv`-verifies `repo/dists/umbra/InRelease`.

It refuses to run anywhere else (`:233`):

```python
if sys.platform != "linux" or ROOT != PUBLISHER or getpass.getuser() != "rtx5060ti":
    raise ValueError("Release publication must run from the authorized Linux 4.0 source tree")
```

### 3.2 What it uploads, and the order inside it

Bucket `shadowfetch-linux`. Objects, in the tool's own order: the ISO, then
`.sha256` and `.asc`, then the eight evidence files, then
`shadowfetch.gpg.asc`, then every file under `repo/pool`, then
`apt/dists/**` — sorted so `Release.gpg`, `Release` and finally `InRelease` are
last among them (`order()`, `:85-89`). Then the ISO's bytes are streamed back
from R2 and re-hashed (`R2_RELEASE_BYTES_VERIFIED`). Only then is
`releases/CURRENT.json` written (`R2_CURRENT_POINTER_WRITTEN`).

The comment at `:167-170` states the rule the whole release order follows:

> nothing that DIRECTS a reader is written before the thing it directs them to
> is present and proven.

**You do not get to reorder this.** It is one command; the pointer is inside it.
What you control is what happens *around* it, and every one of those things —
GitHub, archive.org, the website — is a thing that directs a reader.

`--published` defaults to the ISO's mtime, so re-running rewrites nothing and
prints `UNCHANGED` per key. An immutable key whose bytes differ is refused
outright (`existing_matches()`, `:141`).

### 3.3 The reader of that pointer is not deployed — measured

The worker in `web/shadowfetch-linux-worker` reads `releases/CURRENT.json`
(`src/index.js:45`, `:314-372`) and answers 410 for any ISO its
`policy/retirement.json` declares retired. The deployed worker does neither:

```
$ python3 -c "import json;d=json.load(open('web/shadowfetch-linux-worker/policy/retirement.json'));print([e['version'] for e in d['retired']])"
['1.0.1', '1.5.0', '1.8.1', '1.9.0', '2.0.0', '2.0.1', '2.1.0', '2.1.1', '2.1.2', '2.1.3', '2.1.4']

$ curl -sS -o /dev/null -w "%{http_code}\n" https://www.shadowfetch.com/linux/download/shadowfetch-2.1.3-amd64.iso
404
$ curl -sS -o /dev/null -w "%{http_code}\n" https://www.shadowfetch.com/linux/download/shadowfetch-2.1.4-amd64.iso
404
$ curl -sS -o /dev/null -w "%{http_code}\n" -r 0-1 https://www.shadowfetch.com/linux/download/shadowfetch-3.5.0-amd64.iso
206
```

2.1.3 and 2.1.4 are declared retired and answer **404**, which is the exact
defect `retirement.json`'s own note describes as fixed. 3.5.0 serves.

**CORRECTED.** An earlier draft of this section concluded from those two probes
that "the artifact worker in this repository has never been deployed." That is
wrong, and the correction matters because it changes the size of the step. A
worker from this codebase IS live, and it says so in a header this repository
sets:

```
x-shadowfetch-linux-build: 2026.08.11.1          (live)
src/index.js:35  const WORKER_BUILD = "2026.09.09.1";   (this tree)
```

It is about a month behind. The 404s mean its retirement mirror predates the
2.1.3/2.1.4 entries — STALE, not absent. Two sources in the tree said so and
the draft quoted one of them truncated a clause before the refutation:
`web/shadowfetch-linux-worker/README.md:44-45` continues "...and the listing
fallback is what answers today; that changes on the next publish, not on this
commit", and `:57-58` gives the actual cause: "2.1.3 and 2.1.4 were published,
pruned, and answered 404 until they were declared here."

Consequence for 4.1.0, restated correctly: writing `releases/CURRENT.json` is
correct, and the live reader does not consult it yet because it is running the
listing fallback. Deploying `web/shadowfetch-linux-worker` is therefore **not**
"ship a worker that has never shipped" — it is **roll a live worker forward by
a month**, carrying every change between 2026.08.11.1 and 2026.09.09.1, not
only the 404 -> 410 flip. Read that diff before deploying. The 2.1.3/2.1.4 flip
is still a visible public change and still deserves to be a decision rather
than a side effect.

The worker's own README is honest about this and dates it:

> Nothing has been published from this tree, so `CURRENT.json` was still absent
> from the bucket when this was written (checked 2026-09-09)

### 3.4 What I could not determine here

`/linux/releases.json` redirects rather than serving the pointer view:

```
$ curl -sSI https://www.shadowfetch.com/linux/releases.json | grep -i "^HTTP\|^location"
HTTP/2 301
location: https://www.shadowfetchlinux.org/releases.json
```

`src/index.js:124` routes that path to `releaseJson(env)`, so either the
deployed worker is older (consistent with §3.3) **or** the `.com` edge router
never delegates that path to the LINUX binding at all. I cannot distinguish
them: the `.com` router's source is not persistently on this box. The Wrangler
log from 2026-09-07 13:15 shows it was built at
`~/.sfbuild/release-ops/shadowfetch-public-release/runtime/release-work`, with
bindings `env.VISITORS (shadowfetch-visitors) D1`, `env.LINUX
(shadowfetch-linux) Worker`, `env.ASSETS`, and that directory no longer exists.
The run was `--dry-run`, so it is not even evidence of a deploy.

---

## 4. Surface 1 — GitHub

### 4.1 The remote, and whether the rename left anything stale

The remote is already the renamed account. It is not stale.

```
$ git remote -v
origin	https://github.com/ShadowfetchLinux/shadowfetch-linux.git (fetch)
origin	https://github.com/ShadowfetchLinux/shadowfetch-linux.git (push)
```

The stale artifact from the rename is the **gh CLI's own stored credential**,
which still names the old account and no longer works:

```
$ gh auth status
github.com
  X Failed to log in to github.com account Realbobcorbin (/home/rtx5060ti/.config/gh/hosts.yml)
  - The token in /home/rtx5060ti/.config/gh/hosts.yml is invalid.
```

The working credential is a separate file:

```
$ set -a; . ~/.config/shadowfetch/github.env; set +a; gh auth status
github.com
  ✓ Logged in to github.com account ShadowfetchLinux (GH_TOKEN)
  - Token scopes: 'gist', 'read:org', 'repo'
```

`~/.config/shadowfetch/github.env` is mode 0600 and contains one line,
`GH_TOKEN=…`. The `repo` scope covers both `git push` and `gh release create`.
Source it for the GitHub steps; do not `gh auth login` (that would rewrite
`hosts.yml` and is not needed).

The other token reference in the tree is documented-stale already.
`.github/CI-SECRETS.md:22` says `RELEASE_GITHUB_TOKEN` is "named there and used
by nothing, should be revoked if it still exists". Nothing reads it: the only
workflow is `.github/workflows/build-iso.yml`, named *Source and package
checks*, with `permissions: contents: read` and zero `secrets.` references. It
runs `make test` and `make packages` and publishes nothing.

**There is no release script.** `grep -rIn "gh release" --include="*.md"
--include="*.py" --include="*.sh" .` over the repository returns nothing. Every
GitHub release so far was made by hand.

### 4.2 The convention 4.0.0 used

Branch `release/X.Y.Z`; **annotated** tag `vX.Y.Z`:

```
$ for t in v3.0.0 v3.5.0 v4.0.0 v4.0.0-preview; do echo -n "$t: "; git cat-file -t $t; done
v3.0.0: tag
v3.5.0: tag
v4.0.0: tag
v4.0.0-preview: commit
```

Only the preview marker is lightweight; every stable tag is annotated. Match
that.

The current ref state — note this before pushing anything:

```
$ git ls-remote --heads origin
270f6a2e2438661d69eb228fd36615adbefa7be3	refs/heads/main
705fa75f2ee54dfce2d35be60830c64b5491558b	refs/heads/release/4.0.0
4a07d8f62e40a4a283536008402964c386efa853	refs/heads/release/3.0.0
dac7997dd508ae04e2813de09cc5b1b1f37ff834	refs/heads/release/3.5.0
$ git rev-parse HEAD
362c68f72919aef0917333f004f330cf7abf4081
$ git rev-parse main
57e637a712d0a337017ad820a89d84ebcc04f255
```

Two things follow. First, `release/4.0.0` on the remote is two commits behind
this working tree — `9ca3a58` (Stage C egress filter…) and `362c68f` (Close what
the adversarial verifiers broke…) are unpushed. Second, local `main` is
`57e637a`, which is what tag `v4.0.0` dereferences to, while remote `main` is
`270f6a2e`. This checkout has **no fetched remote-tracking refs**, so I could not
determine how those two relate. Establish that before deciding what `main`
should be for 4.1.0 — do not assume a fast-forward.

The GitHub release itself (read through the public API, no credential):

```
$ curl -sS https://api.github.com/repos/ShadowfetchLinux/shadowfetch-linux/releases
v4.0.0 | Shadowfetch Linux 4.0.0 (Umbra) — Mission Control | draft: False | prerelease: False | published: 2026-09-06T20:57:12Z
    asset: shadowfetch-4.0.0-amd64.iso.asc 228 1
    asset: shadowfetch-4.0.0-amd64.iso.sha256 94 1
v3.5.0 | Shadowfetch Linux 3.5.0 "Umbra" - Fire and Ice Workbench | ...
    asset: dossier-3.5.0.md / packages-3.5.0.manifest / sbom-3.5.0.cdx.json 1850271
    asset: evidence-bundle-3.5.0.tar.gz 23373545 / evidence-bundle-3.5.0.contents
    asset: release-evidence-3.5.0.sha256 / release-facts-3.5.0.json
    asset: publication-3.5.0.log 3504 / shadowfetch-release.asc 677
    asset: shadowfetch-3.5.0-amd64.iso.asc / .sha256
```

The ISO is never attached — at 3,980,261,376 bytes it exceeds GitHub's per-asset
limit. 3.5.0 attached the eleven evidence files; 4.0.0 attached two. That
narrowing tracks B2: 4.0.0's evidence was never produced. If 4.1.0's evidence
bundle exists, follow the 3.5.0 asset set, not the 4.0.0 one.

### 4.3 The steps

```sh
set -a; . ~/.config/shadowfetch/github.env; set +a
cd /home/rtx5060ti/projects/shadowfetch-4.0.0

git push origin release/4.1.0
git tag -a v4.1.0 -m "Shadowfetch Linux 4.1.0 (Umbra)"       # annotated
git push origin v4.1.0

gh release create v4.1.0 \
  --title "Shadowfetch Linux 4.1.0 (Umbra) — <subtitle>" \
  --notes-file RELEASE-4.1.0.md \
  shadowfetch-4.1.0-amd64.iso.sha256 \
  shadowfetch-4.1.0-amd64.iso.asc \
  shadowfetch-release.asc \
  work/release-4.1.0/dossier-4.1.0.md \
  work/release-4.1.0/packages-4.1.0.manifest \
  work/release-4.1.0/sbom-4.1.0.cdx.json \
  work/release-4.1.0/release-facts-4.1.0.json \
  work/release-4.1.0/release-evidence-4.1.0.sha256 \
  work/release-4.1.0/evidence-bundle-4.1.0.tar.gz \
  work/release-4.1.0/evidence-bundle-4.1.0.contents
```

The release body must say what §1 of this document's parent brief says: that a
mission without `--provider` now fails, that a stored approval no longer covers
a mission naming destinations, that `--net allow` no longer reaches host
loopback, that `flatpak update --user` has no replacement, and that
`52shadowfetch-unattended.conf` is removed by maintscript. Those are the reasons
this is 4.1.0 and not 4.0.1, and a reader upgrading needs them before the
download link, not after.

**Note the branch-cut trap this program has already paid for.** Cut
`release/4.1.0` from the commit that was actually gated, and verify the tag
target is that commit, not whatever `main` happens to be.

### 4.4 What success looks like

`gh release view v4.1.0` lists the assets; the tag page loads;
`git ls-remote --tags origin | grep v4.1.0` shows both the tag object and its
`^{}` dereference.

### 4.5 Failure mode if done in the wrong order

The release notes and the tag page link `https://www.shadowfetch.com/linux/download/…`.
Publishing GitHub **before** the R2 publish means every download link in the
release 404s, on a page that is indexed and mirrored immediately. The GitHub
release is also the URL the archive item's readme and the site manifest both
cite (§5, §6), so it must exist before those two — but only after R2.

---

## 5. Surface 2 — archive.org

### 5.1 There is no tooling. Say it plainly.

Searching the release repository for archive.org tooling returns only vendored
third-party files under `live-build/chroot/` (kdenlive's resource provider,
calibre's store plugin, upstream docstring URLs). Nothing first-party. The site
repository references archive.org only as **links** —
`src/components/PreviewFilms.astro:4`, `src/pages/preview.astro:9-10`,
`src/components/Footer.astro:82`, `src/pages/download.astro:283`, and the
historical entries in `public/releases.json`.

The one upload script on the machine is `~/archive_upload.sh`, and it is a 2.1.2
relic, not a tool:

```sh
# archive.org mirror for 2.1.2. Self-gates: waits until the primary publish (R2 +
# github) is done so three big uploads don't fight over the uplink. Detached-safe.
cd ~/projects/shadowfetch          # ← this directory does not exist any more
IA=~/.local/bin/ia
ID=shadowfetch-linux-2-1-2
ISO=shadowfetch-2.1.2-amd64.iso
...
for i in $(seq 1 160); do [ -f ~/.publish-rest-done ] && break; sleep 30; done
```

`ls -d ~/projects/shadowfetch` → *No such file or directory*. And
`~/.publish-rest-done` exists, dated 30 Jul 2026, so the wait loop would fall
through instantly. **Read it for the metadata shape and the ordering intent it
encodes — that archive.org goes last, after R2 and GitHub — then write the
command by hand.** Do not run it.

### 5.2 The item convention, from the 4.0.0 item

Identifier is the version with dots as dashes: `shadowfetch-linux-4-1-0`.

```
$ ia metadata shadowfetch-linux-4-0-0
identifier  = shadowfetch-linux-4-0-0
title       = Shadowfetch Linux 4.0.0 (Umbra) — Mission Control signed ISO
mediatype   = software
creator     = Shadowfetch Project
date        = 2026-09-06
publicdate  = 2026-09-06 23:14:15
collection  = opensource
uploader    = robertcorbin84@gmail.com
licenseurl  = https://www.gnu.org/licenses/gpl-3.0.html
FILES:
    sf40-SHA256SUMS                          94
    sf40-ia-readme.txt                      664
    shadowfetch-4.0.0-amd64.iso    3980261376
    shadowfetch-4.0.0-amd64.iso.asc         228
    shadowfetch-4.0.0-amd64.iso.sha256       94
    shadowfetch-linux-4-0-0_archive.torrent   40945   ← generated by archive.org
    shadowfetch-linux-4-0-0_files.xml                 ← generated
    shadowfetch-linux-4-0-0_meta.sqlite       40960   ← generated
    shadowfetch-linux-4-0-0_meta.xml           1946   ← generated
```

Five files are uploaded; the torrent and the XML/sqlite are derived by
archive.org. The readme is the item's own honesty statement:

```
$ curl -sSL https://archive.org/download/shadowfetch-linux-4-0-0/sf40-ia-readme.txt
Shadowfetch Linux 4.0.0 (Umbra) — Mission Control
This is the signed 4.0.0 amd64 hybrid ISO (Fire and Ice).
SHA-256: 137c1f29e206c0d0e26e524c8c34a7dfe43b24c1d1df29f85d6b15283bab67fc
Size: 3980261376 bytes
OpenPGP fingerprint: 8F13CE1535EE1F4A2916A1F73C5C900B7BE80CA1
Firebreak source commit: e1293bfad3bffaecd1ff869e378438f9f36398f7
Acceptance commit: 57e637a712d0a337017ad820a89d84ebcc04f255
...
Website: https://www.shadowfetchlinux.org/download
Source: https://github.com/ShadowfetchLinux/shadowfetch-linux/releases/tag/v4.0.0
```

It cites the GitHub tag URL and the site URL. Both must exist first.

### 5.3 The credential — verified working

`~/.config/ia.ini` and `~/.config/internetarchive/ia.ini`, both mode 0600, both
`[s3]` with `access` and `secret`. The CLI is
`/home/rtx5060ti/.local/bin/ia`, version 5.8.0.

Verified with an authenticated **read** (task history is not public):

```
$ ia tasks shadowfetch-linux-4-0-0
{"category":"history","identifier":"shadowfetch-linux-4-0-0","task_id":5611294982,
 "cmd":"archive.php", ... "submittime":"2026-09-06 23:14:11.088537",
 "submitter":"robertcorbin84@gmail.com", ...}
{... "cmd":"book_op.php","args":{"op0":"VirusCheck" ...}}
{... "cmd":"derive.php" ...}
```

The credential authenticates as `robertcorbin84@gmail.com`, the same account
that uploaded 4.0.0. I did not test a write, and a write is the only thing that
would prove upload permission on a *new* item; the account holds the publisher
collection `@rcorbin125` and created `shadowfetch-linux-4-0-0` three days ago,
so there is no reason to expect otherwise.

### 5.4 The steps

```sh
cd /home/rtx5060ti/projects/shadowfetch-4.0.0
~/.local/bin/ia upload shadowfetch-linux-4-1-0 \
  shadowfetch-4.1.0-amd64.iso \
  shadowfetch-4.1.0-amd64.iso.sha256 \
  shadowfetch-4.1.0-amd64.iso.asc \
  sf41-SHA256SUMS \
  sf41-ia-readme.txt \
  --metadata="title:Shadowfetch Linux 4.1.0 (Umbra) — <subtitle> signed ISO" \
  --metadata="mediatype:software" \
  --metadata="creator:Shadowfetch Project" \
  --metadata="date:<release date YYYY-MM-DD>" \
  --metadata="collection:opensource" \
  --metadata="licenseurl:https://www.gnu.org/licenses/gpl-3.0.html" \
  --metadata="description:<the 4.1.0 behaviour changes, then SHA-256, then fingerprint>"
```

Write `sf41-ia-readme.txt` first, in the shape quoted in §5.2, with the real
4.1.0 SHA-256, size, source commit and acceptance commit. Run it detached — the
4.0.0 upload's ancestor took 1h16m for the ISO alone:

```sh
setsid nohup ~/.local/bin/ia upload … </dev/null >/tmp/ia-4.1.0.log 2>&1 &
```

### 5.5 What success looks like

`ia metadata shadowfetch-linux-4-1-0` lists the five uploaded files plus the
four generated ones, and `ia tasks shadowfetch-linux-4-1-0` shows `archive.php`,
`VirusCheck` and `derive.php` finished. `https://archive.org/details/shadowfetch-linux-4-1-0`
returns 200. The derive lags the upload by roughly seven minutes — 4.0.0's
`archive.php` submitted at 23:14:11 and `derive.php` at 23:21:43.

### 5.6 Failure mode if done in the wrong order

Archive.org items are effectively permanent. Uploading before the ISO is final
publishes a superseded image under a name that says it is 4.1.0, forever, and
`ia delete` needs privileges the release account may not have. Uploading before
GitHub and the site exist ships a readme whose two citation URLs 404.

There is also a downstream rule to respect: `policy/retirement.json`'s note says
`archive` entries were verified reachable on 2026-09-09 and *"Do not add an
archive URL that has not been checked: a 410 page that points at a dead archive
is worse than one that admits the image is gone."* Do not add a 4.1.0 archive
URL anywhere until the item actually answers.

---

## 6. Surface 3 — shadowfetchlinux.org

### 6.1 Where it lives, and what serves it

**Not this repository.** Canonical source is
`/home/rtx5060ti/.sfbuild/release-sources/shadowfetch-linux-site`, git remote
`https://github.com/ShadowfetchLinux/shadowfetch-linux-site.git`, branch `main`,
HEAD `68d3b71`.

It is an Astro site wrapped in Cloudflare Worker `shadowfetch-linux-site`
(`wrangler.jsonc`: `"name": "shadowfetch-linux-site"`, `"main":
"src-worker/index.js"`, assets `./dist`). `src-worker/index.js` sets
`CANONICAL_HOST = "www.shadowfetchlinux.org"`. Its own `AGENTS.md` states the
split:

> - Worker: `shadowfetch-linux-site`
> - Canonical host: `https://www.shadowfetchlinux.org`
> - Do not attach Worker `shadowfetch-linux` as the public site (artifact Worker).
> - APT, GPG, ISO bytes, and `_stats` stay on `https://www.shadowfetch.com/linux/...`

That is the answer to which worker serves what: `shadowfetch-linux-site` serves
the **pages**; `shadowfetch-linux` (in this repo, `web/shadowfetch-linux-worker`)
serves the **bytes** behind `shadowfetch.com/linux/*`. Confirmed live:

```
$ curl -sSI https://www.shadowfetch.com/linux/ | grep -i "^HTTP\|^location"
HTTP/2 301
location: https://www.shadowfetchlinux.org/
$ for p in / /download /changelog /verify /releases.json /preview; do … done
root code=200 / /download 200 / /changelog 200 / /verify 200 / /releases.json 200 / /preview 200
```

### 6.2 What a release actually changes there — one file

`src/data/release.ts` is explicit that this is by design:

> `import.meta.glob` pulls in every manifest under releases/ eagerly, and the
> newest by date wins, so cutting a release means adding one manifest file and
> touching no page at all.

So: **add `releases/4.1.0.json`** — and then keep reading, because "nothing
else is version-edited" is what `src/data/release.ts`'s own docstring says
about ITSELF, and an earlier draft of this section adopted it as a measured
fact about the whole site. It is not:

```
$ grep -rn "4\.0\.0\|Linux 4\.0" src/ | wc -l
46
```

46 hardcoded version strings across about twelve files. Two are load-bearing
and would ship a false front page:

* `src/data/flagship.ts:4` — `FLAGSHIP_TITLE = "Shadowfetch Linux 4.0 —
  Mission Control"`, which becomes the home page `<title>` and `og:title`
  (`index.astro:12` -> `Base.astro:45`). Deploy 4.1.0 without touching it and
  the front page still announces 4.0.
* `src/pages/known-issues.astro:18` — "4.0.0 is the signed ISO", with the
  digest `137c1f29…` written out longhand. After a 4.1.0 deploy that is a false
  statement about the current download, on the one page whose whole job is
  saying true things about what is wrong.

Others to sweep: `src/pages/local-ai.astro:4` ("Local AI is deferred in 4.0" —
no longer true, an on-device provider ships), `screenshots.astro`,
`benchmarks.astro`. The manifest-only claim holds for the download, changelog
and verify pages, which do read `release.ts`; it does not hold for the pages
that name the version in prose.

`npm run
build` runs `npm run data:release` first, which regenerates
`public/releases.json` and `public/releases.atom.xml` from `releases/*.json`
(`scripts/build_release_feed.mjs`). The download page, changelog, verify page
and structured data all read `src/data/release.ts`.

Copy the shape from `releases/4.0.0.json`. The fields that must be true and are
easy to get wrong: `iso.filename` must equal `shadowfetch-4.1.0-amd64.iso`
(asserted at `tests/content.test.mjs:86`); the filename `4.1.0.json` must equal
the `version` field and `date` must be `YYYY-MM-DD` (both enforced in
`build_release_feed.mjs:34-40`); `iso.sha256` must be 64 lowercase hex;
`iso.sizeBytes` a positive integer; `signingKey.fingerprint` stays
`8F13CE1535EE1F4A2916A1F73C5C900B7BE80CA1`;
`mirrors.githubRelease` points at `…/releases/tag/v4.1.0`.

`limitations` is where the honesty standard lands on this surface. 4.0.0's
manifest names five, including that the APT snapshot still lists 3.5.0-1
packages. Whatever remains unproven for 4.1.0 goes there, in the same voice.

Screenshots: the eight named `public/linux-assets/linux-4.0.0-<scene>.webp`
captures are required only by the test at `:217`, which is guarded by
`if (currentRelease().version !== "4.0.0") return;` — so for 4.1.0 that test
becomes a no-op and does not force new captures. If 4.1.0 ships with 4.0.0
screenshots, that is a choice; nothing enforces it either way.

### 6.3 The one edit that must happen in the site repo first

Fix B4 before adding the manifest, or the deploy cannot run.

**Not by guarding it the way `:218` is guarded.** An earlier draft of this
section said to copy that pattern and insert
`if (currentRelease().version !== "4.0.0") return;` as the test's first
statement, on the reasoning that "every assertion in the body is about 4.0.0
being current". That reasoning is wrong, and the instruction would have done
the opposite of what the sentence after it demanded. Nine assertions sit in
that one function:

| assertion | about |
| --- | --- |
| `preview` × 5 — signed-ISO sentence, source commit, ISO sha256, the archive.org item, the SIGTRAP line | the 4.0 preview page, a **historical record** that must not change |
| `home` × 2 — `href="/preview"`, the landscape-review mp4 | the home page's link to that record |
| `download` × 2 — names `4.0.0`, does not name `3.5.0` | the page that renders **whatever is current** |

An early `return` is not a guard on the two that go stale; it switches off all
nine — including the preview assertions the draft's own comment promised
"stays asserted", and including the very lines the draft then said not to
delete. `:218` gets away with the pattern because every assertion in *that*
test is a `linux-4.0.0-*.webp` filename.

Split it instead. Leave the preview and home assertions exactly as they are,
and make the two download assertions say what they actually mean — the
download page names the current ISO, and only that one:

```
anchor (lines 192-193):
  assert.match(download, /shadowfetch-4\.0\.0-amd64\.iso/);
  assert.doesNotMatch(download, /shadowfetch-3\.5\.0-amd64\.iso/);

replacement:
  // The download page renders whatever releases/*.json says is current, so
  // pinning a version here fails the next release instead of catching a
  // defect -- and an early `return` over the whole test would switch off the
  // seven preview/home assertions above, which are about a historical page.
  const iso = currentRelease().iso.filename;
  assert.match(download, new RegExp(iso.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  const named = [...download.matchAll(/shadowfetch-\d+\.\d+\.\d+-amd64\.iso/g)]
    .map((m) => m[0]);
  assert.deepEqual([...new Set(named)], [iso],
    `the download page names ${[...new Set(named)].join(", ")}`);
```

That keeps the check the draft was right to insist on — the download page names
exactly one ISO — and it now survives every future release instead of
switching itself off at the first one. Rename the test too: it is no longer
"4.0.0 is the signed download".

### 6.4 The steps

```sh
cd /home/rtx5060ti/.sfbuild/release-sources/shadowfetch-linux-site
python3 scripts/build_apt_repo.py          # regenerate src/data/apt-repo.json from the LIVE .com APT tree
# add releases/4.1.0.json; apply the §6.3 test fix
npm ci
npm run deploy
```

`npm run deploy` is `npm run release:verify && wrangler deploy`, and
`release:verify` is
`npm test && npm run data:apt:check:gpgv && npm run data:apt:freshness && wrangler deploy --dry-run …`.
`npm test` is itself `data:apt:check && data:release:check && astro check && build && test:worker && test:content`.

### 6.5 The credential

Wrangler OAuth at `~/.wrangler/config/default.toml`, mode 0600, scopes including
`workers_scripts:write` and `workers_routes:write`. Its
`expiration_time = "2026-07-16T04:00:00.000Z"` is in the past, but a
`refresh_token` is present and a real deploy succeeded two days ago:

```
$ ls -t ~/.wrangler/logs/ | head -2
wrangler-2026-09-08_02-15-07_170.log     (2026-09-07 22:15:14)
$ grep -c Deployed …/wrangler-2026-09-08_02-15-07_170.log   → 1, for shadowfetch-linux-site
```

`~/.config/shadowfetch/cf_deploy_token` (54 bytes, 0600) is the API-token
fallback if the OAuth refresh fails.

Per `AGENTS.md`: *"Jen/ops (`rtx5060ti`) deploys. Shannon and Sally never
wrangler."*

### 6.6 What success looks like

Wrangler prints `Deployed shadowfetch-linux-site`;
`https://www.shadowfetchlinux.org/download` names
`shadowfetch-4.1.0-amd64.iso`; `https://www.shadowfetchlinux.org/releases.json`
has `latest.version == "4.1.0"`; the Atom feed's newest entry says 4.1.0.

### 6.7 Failure mode if done in the wrong order

Two, both real:

1. **Site before R2.** The manifest's `iso.url` is
   `https://www.shadowfetch.com/linux/download/shadowfetch-4.1.0-amd64.iso`.
   Deploy first and the download button on the front page of the project 404s
   for however long the R2 upload takes — and the ISO upload alone ran 1h16m for
   a comparable image.
2. **APT check before the APT publish.** `npm run data:apt:check:gpgv` compares
   `src/data/apt-repo.json` against the *live*
   `https://www.shadowfetch.com/linux/apt/dists/umbra` (`build_apt_repo.py:24`,
   `DEFAULT_SOURCE`). Regenerate it before the R2 publish and it captures the
   3.5.0-1 tree; regenerate after, and it captures 4.1.0. Either is internally
   consistent — but a *stale* `apt-repo.json` against a *fresh* live tree fails
   the check and blocks the deploy, so the regeneration has to happen on the
   correct side of the publish.

### 6.8 DO NOT TOUCH — two CSP changes that exist only here

This checkout carries two commits that are **not on any remote**. They are the
worker-side and asset-side halves of one CSP change:

```
$ git log --oneline -3
68d3b71 site: replace 3.5 walkthrough with the Shadowfetch Linux 4 (Grok Bot) video
9748e0b Always apply HTML_CSP from worker (override asset _headers)     ← src-worker/index.js, +1 -3
2feaa2c Allow PostHog hosts in public/_headers CSP                      ← public/_headers, +1 -1
```

There are no remote-tracking refs in this repository at all
(`.git/refs/remotes` does not exist, `.git/packed-refs` does not exist,
`.git/FETCH_HEAD` is 0 bytes), and the remote cannot be read from this machine:

```
$ git ls-remote --heads origin
remote: Invalid username or token. Password authentication is not supported for Git operations.
fatal: Authentication failed for 'https://github.com/ShadowfetchLinux/shadowfetch-linux-site.git/'
```

That repository is private and the *ambient* git credential does not open it —
the `GH_TOKEN` in `~/.config/shadowfetch/github.env` has `repo` scope and is the
credential to try, but I did not test it against this remote.

**Consequences, and they are the point of this section:** these two commits are
a single local copy with no backup and no pushed mirror. `git reset`,
`git checkout`, `git clean`, a reclone, or a "let me just start fresh" on this
directory destroys them. The live site was deployed from them on 2026-09-07, so
discarding them and redeploying would silently revert the production CSP —
including the PostHog allowances the site's own `public/_headers` now needs.
Leave them alone. If anything, push them; never drop them.

The working tree is otherwise clean apart from one untracked file,
`public/og-card-3.5.jpg`, which is also not backed up anywhere.

---

## 7. The order

```
  ┌─ prerequisites (not publication) ─────────────────────────────┐
  │ stamp 4.1.0 · versions/4.1.0.toml · qa/4.1.0/acceptance.json  │
  │ make iso · make sign · gates · evidence bundle                │
  └───────────────────────────────────────────────────────────────┘
                              │
          ╔═══════════════════▼════════════════════════╗
   STEP 1 ║ R2:  publish_release_4_1_0.py --apply      ║
          ║   … evidence, ISO, APT, InRelease last …   ║
          ║   … ISO streamed back and re-hashed …      ║
          ║   … releases/CURRENT.json written LAST     ║
          ╚═══════════════════╤════════════════════════╝
                              │  every URL below now resolves
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
   STEP 2 GitHub        STEP 2b artifact       (wait for STEP 2:
   push branch+tag      worker deploy           both cite the tag)
   gh release create    (optional, §3.3)
        │
        ├──────────────────┬──────────────────────┐
        ▼                  ▼                      ▼
   STEP 3 archive.org  STEP 4 site           (3 and 4 are
   ia upload           npm run deploy         independent of
                                              each other)
```

The rules, stated as prohibitions:

* **Nothing may be published before STEP 1.** GitHub release notes, the archive
  readme and the site manifest all name `shadowfetch.com/linux/download/…`. This
  is the publisher's own rule — *nothing that DIRECTS a reader is written before
  the thing it directs them to is present and proven* — applied one level up.
* **`releases/CURRENT.json` must not be written before the ISO's bytes are
  proven in the bucket.** You cannot get this wrong by hand; it is inside STEP 1.
  You can only get it wrong by writing the pointer some other way. Don't.
* **archive.org must not precede GitHub.** `sf41-ia-readme.txt` cites
  `…/releases/tag/v4.1.0`, measured in the 4.0.0 readme.
* **The site must not precede GitHub** if its manifest sets
  `mirrors.githubRelease`, which 4.0.0's does.
* **`scripts/build_apt_repo.py` must not run before the APT half of STEP 1.**
  It reads the live tree; running it early bakes in 3.5.0-1 and the later
  freshness/diff check fails (§6.7).
* **archive.org and the site do not depend on each other** — 4.0.0's manifest
  claims no archive mirror, and `src/pages/download.astro:283` says a
  current-release archive mirror is not claimed unless it appears in the
  manifest. If you decide to add one for 4.1.0, then archive.org must precede
  the site, and the URL must be checked first (§5.6).
* **STEP 2b is a separate decision.** It is not required for 4.1.0 to be live,
  and it changes 2.1.3/2.1.4 from 404 to 410 as a side effect (§3.3).

The one deadline: STEP 4 becomes impossible after **2026-09-13 18:10:14 GMT**
unless STEP 1 has republished a fresh signed `InRelease` (§B5).

---

## 8. Finding — `tools/publish_release_4_0_0.py` is only half version-parameterised

Reported, not edited. This file was not modified.

`VERSION = "4.0.0"` (`:28`) does drive most of the tool: the ISO name (`:39`),
all eight evidence filenames (`:41-44`), the pointer document (`:113`) and the
per-object R2 metadata (`:162`, `:181`). Setting it to `"4.1.0"` correctly
renames all of those.

**Four literals do not derive from `VERSION` and would silently keep pointing at
4.0.0:**

| Line | Text |
|---|---|
| `:67` | `manifest = json.loads((root / "qa/4.0.0/acceptance.json").read_text())` |
| `:72` | `release = root / "work/release-4.0.0"` |
| `:115` | `path = root / "work/release-4.0.0/CURRENT.json"` |
| `:224` | `"--version", "4.0.0", "verify"],` |

`:67` and `:224` are the dangerous pair: they would verify and compare against
**4.0.0's** acceptance manifest while uploading 4.1.0's bytes — a publish that
passes its own gate by checking the wrong release. `:72` and `:115` would read
and write the 4.0.0 evidence directory.

A fifth is outside the file. `Makefile:494`:

```make
	@python3 $(ROOT)/tools/publish_release_4_0_0.py --apply
```

names the 4.0.0 file by hand, even though `Makefile:13` (`VERSION ?= 4.0.0`) and
`Makefile:16` (`VERSION_TOKEN := $(subst .,_,$(VERSION))`) already exist and are
used elsewhere to select version-suffixed tools.

**Recommendation: parameterise, do not fork.** Adding
`publish_release_4_1_0.py` alongside repeats the defect this codebase has
already diagnosed in writing — `ARCHITECTURE_DECISIONS.md:127` records six
copies each of `source_gate`, `package_gate`, `iso_gate` and `verify_acceptance`
totalling 14,461 lines, of which only ~2,717 are the live 4.0.0 copies, and
notes that the copies which actually run have no tests because the tests target
the 2.1.4/2.1.5 copies. A seventh family member would be the same mistake with a
new number on it.

The parameterised route: take `--version` (defaulting to `VERSION`), derive all
four literals from it, and use `$(VERSION)` in `Makefile:494`.

**Two tests load this file by path and would break on a rename**, so a rename is
not free either:

* `tools/tests/test_publish_pointer.py:24` —
  `"publish_release_under_test", str(ROOT / "tools/publish_release_4_0_0.py")`
* `tools/tests/test_publish_pointer.py:81` —
  `source = (ROOT / "tools/publish_release_4_0_0.py").read_text()`
* also `tools/tests/test_publish_release_4_0_0.py:9`, and
  `tools/package_release_evidence_4_0_0.py:59` lists the publisher among the
  tool paths it hashes into the evidence bundle.

Whatever is decided, `tools/package_release_evidence_4_0_0.py` has the same
shape of problem and should be looked at in the same pass.

---

## 9. Credentials, in one place

| Surface | Credential | Location | Verified |
|---|---|---|---|
| R2 | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `SHADOWFETCH_R2_ENDPOINT` | process environment only; **not on this machine** | absent — searched `~/.config`, `~/.bashrc`, `~/.profile`, `~/.zshrc` |
| GitHub | `GH_TOKEN` | `~/.config/shadowfetch/github.env` (0600) | **yes** — `gh auth status` → `ShadowfetchLinux`, scopes `gist, read:org, repo` |
| GitHub (broken) | gh CLI's own token | `~/.config/gh/hosts.yml` | **invalid** — account `Realbobcorbin`, pre-rename |
| archive.org | `[s3] access` / `secret` | `~/.config/ia.ini` and `~/.config/internetarchive/ia.ini` (0600) | **yes** — `ia tasks` returned authenticated history for `robertcorbin84@gmail.com` |
| Cloudflare Workers | Wrangler OAuth | `~/.wrangler/config/default.toml` (0600) | **yes** — real deploy 2026-09-07 22:15 |
| Cloudflare (alt) | API token | `~/.config/shadowfetch/cf_deploy_token` (0600) | not tested |

The signing key is not on this list. `make sign` uses the maintainer's private
key for `8F13CE1535EE1F4A2916A1F73C5C900B7BE80CA1`; it is not in the repository
and, per `.github/CI-SECRETS.md`, is not reachable from CI and must not be made
so.

---

## 10. What could not be verified

Stated plainly, because a checklist that hides its gaps is worse than one that
admits them.

* **Whether `/linux/releases.json` 301s because the artifact worker is stale or
  because the `.com` router never delegates it.** The router's source is not on
  this box (§3.4). The stale-worker conclusion in §3.3 rests on the 2.1.3/2.1.4
  404s, which is independent evidence and does hold.
* **Whether `releases/CURRENT.json` exists in the bucket.** No R2 credential
  here, and the worker route that would report `pointer.source` is the one that
  redirects. The worker's README asserts it was absent on 2026-09-09; I could
  not confirm that independently.
* **Whether local `main` (`57e637a`) is an ancestor of remote `main`
  (`270f6a2e`).** This checkout has no fetched remote-tracking refs and I did
  not fetch.
* **Whether the two unpushed site CSP commits also exist on the site's remote.**
  `git ls-remote` fails auth from this machine (§6.8). Treat them as
  single-copy.
* **Whether the archive.org credential can create a *new* item.** Only a write
  proves that, and no write was performed.
* **The GitHub release body 4.0.0 actually shipped.** The API listing gives
  title, assets and dates; I did not fetch the body text.
* **Anything about 4.1.0's content.** No 4.1.0 artifact exists to inspect. The
  behaviour changes listed in §4.3 come from the release brief, not from a
  measurement of a built image.

---

## 11. Checklist

Prerequisites (out of scope here, but nothing below works without them):

- [ ] `python3 tools/stamp_version.py 4.1.0`; update every `debian/changelog`
- [x] `tools/release/versions/4.1.0.toml` — written by a sibling agent 17:56,
      `subtitle` marked PROVISIONAL; confirm the subtitle before it reaches a
      gate, the site manifest or the archive title
- [ ] Set `historical = true` in `tools/release/versions/4.0.0.toml:26`
- [ ] `qa/4.1.0/acceptance.json` with required cases passing and a **non-null**
      `evidence_bundle_sha256`
- [ ] `make iso`, `make sign`, gates, evidence bundle into `work/release-4.1.0/`
- [ ] Resolve §8 — parameterise the publisher or accept the four-literal edit

STEP 1 — R2:

- [ ] Export `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `SHADOWFETCH_R2_ENDPOINT`
- [ ] Plan first: `python3 tools/publish_release_4_1_0.py` — read the JSON
- [ ] `python3 tools/publish_release_4_1_0.py --apply`
- [ ] Confirm `R2_RELEASE_BYTES_VERIFIED` **and** `R2_CURRENT_POINTER_WRITTEN`
- [ ] `curl -sSI …/linux/download/shadowfetch-4.1.0-amd64.iso` → 200; the eight
      evidence keys → 200; `…/apt/dists/umbra/InRelease` shows a new Valid-Until

STEP 2 — GitHub:

- [ ] `set -a; . ~/.config/shadowfetch/github.env; set +a`
- [ ] `git push origin release/4.1.0` (note: `release/4.0.0` is 2 commits behind)
- [ ] `git tag -a v4.1.0 -m …` — **annotated**; `git push origin v4.1.0`
- [ ] `gh release create v4.1.0 …` with the 3.5.0-style asset set
- [ ] Release notes lead with the five behaviour changes, then the links
- [ ] `gh release view v4.1.0`

STEP 2b — artifact worker (decide explicitly):

- [ ] Deploy `web/shadowfetch-linux-worker`? It makes CURRENT.json readable and
      turns 2.1.3/2.1.4 from 404 into 410

STEP 3 — archive.org:

- [ ] Write `sf41-SHA256SUMS` and `sf41-ia-readme.txt`
- [ ] `setsid nohup ia upload shadowfetch-linux-4-1-0 … &` — do **not** run
      `~/archive_upload.sh`
- [ ] `ia metadata shadowfetch-linux-4-1-0`; `ia tasks …` shows derive finished

STEP 4 — shadowfetchlinux.org:

- [ ] **Before 2026-09-13 18:10:14 GMT**, or after a fresh InRelease is live
- [ ] Apply the §6.3 guard to `tests/content.test.mjs:181`
- [ ] `python3 scripts/build_apt_repo.py` — after STEP 1, not before
- [ ] Add `releases/4.1.0.json` with honest `limitations`
- [ ] `npm ci && npm run deploy`
- [ ] `/download` names 4.1.0; `/releases.json` `latest.version == "4.1.0"`
- [ ] **Do not** touch, reset or reclone over commits `9748e0b` and `2feaa2c`
