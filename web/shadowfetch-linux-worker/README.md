# shadowfetch-linux artifact worker

Cloudflare Worker behind `shadowfetch.com/linux/*`. It serves **artifacts**, and
answers one question about them: which release is current.

Human-facing pages belong to the public site, `https://www.shadowfetchlinux.org`.
They are not served here. The routes that used to render them are explicit 301s
(see `LEGACY_PAGES` in `src/index.js`).

| Route | What it does |
| --- | --- |
| `/linux/download/<filename>` | streams `releases/<filename>` (Range + HEAD), or answers 410 when the retirement policy retires it |
| `/linux/apt/...` | APT repo passthrough of the reprepro tree, plus a directory index for trailing-slash URLs (the written offer for corresponding source links one) |
| `/linux/shadowfetch.gpg.asc` | public signing key, also at `/linux/apt/shadowfetch.gpg.asc` for `signed-by=` |
| `/linux/assets/...` | brand assets held in R2 |
| `/linux/releases.json` | artifact-side view of `releases/CURRENT.json` |
| `/linux/_stats` | download counters, behind `STATS_TOKEN` |
| every page route | 301 to the public site |
| `/linux/agents` | 410; the feature was removed and stays removed |

## The current release

`releases/CURRENT.json` is the one answer to "which release is live" (ADR-0009).
The publisher writes it **last**; this worker reads that key, and:

* validates schema, version, filename/key agreement, size, digest shape, and
  that it names **this** signing key;
* refuses a pointer that names an image the retirement policy retires;
* HEADs the named object and refuses a pointer the bucket contradicts (missing,
  or a different size);
* falls back to a listing **only while no pointer exists at all** — and that
  fallback is paginated and ordered by semantic version, not by upload time.

`releases.json` reports which of the two it used, in `pointer.source`.

**Status, honestly:** the reader is implemented and tested, and the writer is
now wired: `tools/publish_release_4_0_0.py` builds the document with
`tools/release_pointer.py` (the same module the reader validates against, so a
writer cannot invent its own schema) and uploads it LAST -- after the ISO's own
bytes have been uploaded and streamed back, because a pointer written earlier
advertises an image the bucket does not yet hold. Its `published` field defaults
to the ISO's mtime, so re-running the publisher rewrites nothing. Nothing has
been published from this tree, so `CURRENT.json` was still absent from the
bucket when this was written (checked 2026-09-09) and the listing fallback is
what answers today; that changes on the next publish, not on this commit.

## Retirement

`policy/retirement.json` is the single declaration of which published images are
retired. `src/retirement.js` is its generated mirror (the Worker is bundled and
cannot read a repository file at request time); `tools/sync_retirement_policy.py
--write` regenerates it and `tests/test_retirement_policy.py` fails if they
diverge.

A retired image URL answers **410** — never 404, never a redirect:

* 404 would claim the image never existed. 2.1.3 and 2.1.4 were published,
  pruned, and answered 404 until they were declared here.
* A redirect would hand back different bytes under a URL whose published SHA-256
  belongs to the image that was asked for.

The 410 page links the checksum and signature **only after HEADing them**. The
previous page linked them unconditionally, and both 2.0.0's and 2.1.1's had
already been pruned — the page told people to verify against two 404s.

An image that is merely old is not retired: 2.1.5, 3.0.0 and 3.5.0 still serve
their bytes and are deliberately absent from the policy, which is why the prune
tool refuses to delete them.

## R2 layout

Bucket `shadowfetch-linux`, bound as `RELEASES`.

```
releases/CURRENT.json                              current-release pointer (mutable)
releases/shadowfetch-<version>-amd64.iso           release body   (immutable)
releases/shadowfetch-<version>-amd64.iso.sha256    checksum       (immutable)
releases/shadowfetch-<version>-amd64.iso.asc       signature      (immutable)
releases/<dossier|sbom|evidence-bundle|...>        published evidence
apt/dists/umbra/...                                reprepro output (mutable)
apt/pool/main/s/shadowfetch-*/...                  .debs and sources
assets/...                                         brand assets
stats/downloads.json                               download counters
shadowfetch.gpg.asc                                public signing key
```

## Tools

### `tools/r2_prune_release.py` — the only deleter

It deletes exactly two classes of object and reports everything else it kept:

* under `releases/`: an ISO body whose version is **declared retired**, and (only
  when that entry sets `retain_sidecars: false`) its sidecars;
* under `apt/pool/`: files not referenced by the live `Packages` and `Sources`.

Whitelist, not blacklist. The old rule — "everything that is not the release
being kept" — deleted the retired sidecars the 410 pages link, and would have
deleted the current release's own dossier, SBOM and evidence bundle, because
none of those start with the kept ISO key.

Guards, all tested in `tests/test_r2_prune_release.py`:

* `--version` must be a bare semantic version; a typo is rejected before a client
  is constructed.
* The kept ISO must be present in the bucket; a keep-prefix that matches nothing
  aborts.
* When `releases/CURRENT.json` exists it decides which release is live: pruning
  while keeping a different version is refused, and a corrupt pointer aborts
  rather than being ignored.
* Retired sidecars are retained; the pointer object is never deletable.
* An ISO not declared retired is never deleted — retiring an image is a decision
  someone writes down, not a side effect of a prune.
* `--max-deletes` (default 200) bounds the delete set; over the bound it prints
  the preview and aborts.
* Deleting requires `--apply`; otherwise every line is `WOULD_DELETE`.

### `tools/release_pointer.py`

Builds and validates `releases/CURRENT.json`. Size and digest come from the ISO
on disk, so a pointer cannot describe bytes that were never published.

### `tools/r2_s3_publish.py` — the small upload path

For one large object when wrangler cannot carry it. It refuses to overwrite an
existing immutable release artifact at all, refuses any other existing object
without `--replace`, refuses `releases/CURRENT.json`, refuses a key the
retirement policy retires, stamps the digest it actually computed, and verifies
the readback. It is not a release process: that is
`tools/publish_release_4_0_0.py`, which runs the acceptance gate, checks the
signatures and orders the uploads.

## Tests

```sh
python3 -m unittest discover -s tests     # 65 tests: prune, pointer, policy, upload
node --test tests/worker.test.mjs         # 33 tests: the worker through fetch()
bash tests/run.sh                         # both
```

The Worker tests drive the real `fetch()` entry point against a fake R2 binding,
including the cases that motivated the code: a retired URL that must not 404, a
pointer that names another signing key, an old ISO uploaded after the current one,
a listing that only pages, encoded path traversal, and a counter write that never
settles.

`make test` at the repository root does **not** run this directory yet — see the
Stage Y report.

## Deploy

Not performed by this work. `wrangler deploy` from this directory registers the
Worker and binds the routes in `wrangler.toml`; the routing claim that the edge
delegates only artifact paths (verified live on 2026-09-09) is a property of the
edge router, not of this file.
