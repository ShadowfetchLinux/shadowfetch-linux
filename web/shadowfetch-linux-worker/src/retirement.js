// GENERATED MIRROR of ../policy/retirement.json -- do not hand-edit.
//
// The Worker is bundled and cannot read a repository file at request time, so
// the retirement policy is mirrored here as a literal. policy/retirement.json
// is the source; regenerate with
//     python3 tools/sync_retirement_policy.py --write
// and tests/test_retirement_policy.py fails the build if the two diverge.

export const RETIREMENT_POLICY = {
  "schema": "shadowfetch.linux-retirement.v1",
  "_note": [
    "The one declaration of which published Shadowfetch Linux images are retired.",
    "",
    "Two consumers read THIS file, so a retirement is stated once:",
    "  src/retirement.js          generated mirror, imported by the artifact worker,",
    "                             which answers a retired ISO URL with an explicit 410",
    "  tools/r2_prune_release.py  which may delete an ISO body ONLY when it appears",
    "                             here, and never deletes a retained sidecar",
    "",
    "Deleting a release from R2 without declaring it here is what produced the",
    "2.1.3 and 2.1.4 defect: both were published, both were pruned, and both",
    "answered 404 -- 'this never existed' -- instead of 410.",
    "",
    "'archive' entries were verified reachable on 2026-09-09 (archive.org item",
    "returned 200, the file URL returned a 302 to a live mirror). Do not add an",
    "archive URL that has not been checked: a 410 page that points at a dead",
    "archive is worse than one that admits the image is gone.",
    "",
    "An image that is merely OLD is not retired. 2.1.5, 3.0.0 and 3.5.0 still",
    "serve their bytes today and are deliberately absent from this file, which is",
    "exactly why the prune tool refuses to delete them."
  ],
  "iso_name_template": "shadowfetch-{version}-amd64.iso",
  "sidecar_suffixes": [
    ".sha256",
    ".asc",
    ".sig",
    ".torrent"
  ],
  "successor_page": "https://www.shadowfetchlinux.org/download",
  "retired": [
    {
      "version": "1.0.1",
      "status": "superseded",
      "retain_sidecars": true,
      "archive": "https://archive.org/download/shadowfetch-linux-1-0-1/shadowfetch-1.0.1-amd64.iso",
      "archive_details": "https://archive.org/details/shadowfetch-linux-1-0-1"
    },
    {
      "version": "1.5.0",
      "status": "superseded",
      "retain_sidecars": true,
      "archive": "https://archive.org/download/shadowfetch-linux-1-5-0/shadowfetch-1.5.0-amd64.iso",
      "archive_details": "https://archive.org/details/shadowfetch-linux-1-5-0"
    },
    {
      "version": "1.8.1",
      "status": "superseded",
      "retain_sidecars": true,
      "archive": "https://archive.org/download/shadowfetch-linux-1-8-1/shadowfetch-1.8.1-amd64.iso",
      "archive_details": "https://archive.org/details/shadowfetch-linux-1-8-1"
    },
    {
      "version": "1.9.0",
      "status": "superseded",
      "retain_sidecars": true,
      "archive": "https://archive.org/download/shadowfetch-linux-1-9-0/shadowfetch-1.9.0-amd64.iso",
      "archive_details": "https://archive.org/details/shadowfetch-linux-1-9-0"
    },
    {
      "version": "2.0.0",
      "status": "withdrawn",
      "decision": "20260724-5b83",
      "reason": "Its installer overwrote the system's package sources with Debian's stable template while the system itself tracks testing, so apt broke on the first install. 2.0.1 fixes that and four smaller faults.",
      "retain_sidecars": true,
      "archive": "https://archive.org/download/shadowfetch-linux-2-0-0/shadowfetch-2.0.0-amd64.iso",
      "archive_details": "https://archive.org/details/shadowfetch-linux-2-0-0"
    },
    {
      "version": "2.0.1",
      "status": "superseded",
      "retain_sidecars": true,
      "archive": "https://archive.org/download/shadowfetch-linux-2-0-1/shadowfetch-2.0.1-amd64.iso",
      "archive_details": "https://archive.org/details/shadowfetch-linux-2-0-1"
    },
    {
      "version": "2.1.0",
      "status": "superseded",
      "retain_sidecars": true,
      "archive": "https://archive.org/download/shadowfetch-linux-2-1-0/shadowfetch-2.1.0-amd64.iso",
      "archive_details": "https://archive.org/details/shadowfetch-linux-2-1-0"
    },
    {
      "version": "2.1.1",
      "status": "superseded",
      "retain_sidecars": true,
      "archive": "https://archive.org/download/shadowfetch-linux-2-1-1/shadowfetch-2.1.1-amd64.iso",
      "archive_details": "https://archive.org/details/shadowfetch-linux-2-1-1",
      "torrent": "https://github.com/Realbobcorbin/shadowfetch-linux/releases/download/v2.1.1/shadowfetch-2.1.1-amd64.iso.torrent"
    },
    {
      "version": "2.1.2",
      "status": "superseded",
      "retain_sidecars": true,
      "archive": "https://archive.org/download/shadowfetch-linux-2-1-2/shadowfetch-2.1.2-amd64.iso",
      "archive_details": "https://archive.org/details/shadowfetch-linux-2-1-2"
    },
    {
      "version": "2.1.3",
      "status": "superseded",
      "retain_sidecars": true,
      "archive": "https://archive.org/download/shadowfetch-linux-2-1-3/shadowfetch-2.1.3-amd64.iso",
      "archive_details": "https://archive.org/details/shadowfetch-linux-2-1-3",
      "note": "Published, then removed from the bucket without a retirement entry; its URL answered 404 until this declaration existed."
    },
    {
      "version": "2.1.4",
      "status": "superseded",
      "retain_sidecars": true,
      "archive": "https://archive.org/download/shadowfetch-linux-2-1-4/shadowfetch-2.1.4-amd64.iso",
      "archive_details": "https://archive.org/details/shadowfetch-linux-2-1-4",
      "note": "Published, then removed from the bucket without a retirement entry; its URL answered 404 until this declaration existed."
    }
  ]
};
