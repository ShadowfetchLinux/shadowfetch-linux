# shadowfetch-linux Worker

Cloudflare Worker that serves the `shadowfetch.com/linux/*` subtree:

- `/linux/` — landing page (auto-detects latest ISO in R2 and surfaces it)
- `/linux/download` — download page with checksum + signature instructions
- `/linux/download/<filename>` — streams from R2 `releases/<filename>` (Range-supporting)
- `/linux/install` — install guide (Calamares walkthrough + add-to-existing-Debian flow)
- `/linux/docs` — documentation index for install, verification, hardware, security, recovery, and release notes
- `/linux/changelog` — release notes
- `/linux/releases.json` — machine-readable metadata for the current signed release
- `/linux/releases.atom.xml` — Atom feed containing the current signed release
- `/linux/shadowfetch.gpg.asc` — public signing key (also at `/linux/apt/shadowfetch.gpg.asc` for `signed-by=`)
- `/linux/apt/...` — APT repo proxy, passes through R2 `apt/...` (reprepro output)

The existing `shadowfetch-home` Worker handles `shadowfetch.com/` (the apps studio). It is **not modified** by this Worker — Cloudflare's most-specific route match means `/linux*` lands here and everything else still goes to shadowfetch-home.

## R2 layout

Bucket: `shadowfetch-linux` (bound as `RELEASES`).

```
releases/shadowfetch-2.1.5-amd64.iso          (current/latest ISO body)
releases/shadowfetch-2.1.5-amd64.iso.sha256   (matching checksum sidecar)
releases/shadowfetch-2.1.5-amd64.iso.asc      (matching detached signature)
apt/dists/umbra/InRelease
apt/dists/umbra/Release
apt/dists/umbra/main/binary-amd64/Packages.gz
apt/pool/main/s/shadowfetch-*/...
shadowfetch.gpg.asc
```

The Worker discovers the current release from `releases/*.iso` by upload time and streams `/linux/download/<filename>` from `releases/<filename>`. Retired versioned ISO body URLs stay explicit HTTP 410 pages with links to their version-specific Internet Archive copy and the current `/linux/download` page; they must not redirect to current ISO bytes under an old filename. Matching retired `.sha256` and `.asc` sidecars remain streamable from R2 when present so users can verify copies they already downloaded.

## Deploy

From this directory on a machine with `wrangler` installed and logged into the Cloudflare account that owns shadowfetch.com:

```sh
wrangler deploy
```

That registers the Worker and binds the routes from `wrangler.toml`. First deploy will prompt for `wrangler login` if not authenticated.

## Publish a release

Publish in this order so an ISO is never surfaced without its supporting files:

1. Upload the signed APT `dists/` and `pool/` trees, public key, screenshots, checksum, and detached signature.
2. Upload the ISO last.
3. Verify the public object size, a byte range, full SHA-256, GPG signature, download page, and release metadata.
4. Deploy this Worker.
5. Run the pruning tool in dry-run mode, inspect the count and byte total, then apply it.

Wrangler's object-upload API is limited to small objects. `tools/r2_s3_publish.py` uses Cloudflare's R2 S3 credential derivation in memory and boto3 multipart upload for a full ISO. It does not write the derived access key or secret to disk. Pass an active, bucket-scoped Cloudflare API token file; do not use a broad account token.

`tools/r2_prune_release.py` keeps the named ISO release and every package referenced by the live `Packages` index. It only deletes after `--apply` is supplied; without that flag (or with `--dry-run`) it is a dry run that prints every `WOULD_DELETE` key.

Because the tool works by keeping one release and deleting the rest, a bad `--version` used to mean "delete every published ISO". It now refuses to run unless all of these hold:

- `--version` is a bare semantic version (`4.0.0`); anything else is rejected before a client is even constructed.
- The ISO being kept, `releases/shadowfetch-<version>-amd64.iso`, is actually present in the bucket. A keep-prefix that matches nothing is an abort, never a licence to delete everything.
- The delete set is no larger than `--max-deletes` (default 200). Over the bound it prints the preview and aborts without deleting.
- The kept ISO's `.sha256`, `.asc`, `.sig` and `.torrent` sidecars are never in the delete set.

## Local dev

```sh
wrangler dev
```

Visit `http://localhost:8787/linux/`. The R2 binding may be empty unless objects have been uploaded. When verified release metadata is unavailable, the site withholds the download link and presents an operational status instead of inventing a release.
