// shadowfetch.com/linux/* — the ARTIFACT worker.
//
// Scope, deliberately narrow: this worker answers for bytes in R2 and for the
// question "which release is current". Human-facing pages belong to the public
// site (https://www.shadowfetchlinux.org) and are NOT served here. Every page
// route this worker used to render is now an explicit 301 to that site — the
// edge already redirects them, so the ~1,100 lines of HTML behind them were
// unreachable, and the changelog they carried was frozen at 1.9.0.
//
// Endpoints:
//   /linux/download/<filename>      stream releases/<filename> (Range + HEAD)
//                                   or 410 when the retirement policy retires it
//   /linux/apt/...                  reprepro tree passthrough + directory index
//   /linux/shadowfetch.gpg.asc      public signing key (also under /linux/apt/)
//   /linux/assets/...               brand assets held in R2
//   /linux/releases.json            artifact-side view of releases/CURRENT.json
//   /linux/_stats                   token-gated download counters
//   everything else under /linux/   301 to the public site, or 404
//
// Bindings: RELEASES (R2 bucket "shadowfetch-linux"), STATS_TOKEN (secret).
//
// R2 layout:
//   releases/CURRENT.json                              the current-release pointer
//   releases/shadowfetch-<version>-amd64.iso           release body
//   releases/shadowfetch-<version>-amd64.iso.sha256    checksum sidecar
//   releases/shadowfetch-<version>-amd64.iso.asc       detached signature sidecar
//   apt/dists/umbra/...                                reprepro output
//   apt/pool/main/s/shadowfetch-*/...                  the .debs and sources
//   shadowfetch.gpg.asc                                public signing key

import { RETIREMENT_POLICY } from "./retirement.js";

const PUBLIC_SITE = "https://www.shadowfetchlinux.org";
const ARTIFACT_BASE = "https://www.shadowfetch.com/linux";
const WORKER_BUILD = "2026.09.09.1";

// The key that signs every release. A pointer naming any other key is refused
// rather than trusted: which key verifies a release is a security fact, not a
// field a bucket object gets to choose.
const GPG_FINGERPRINT = "8F13CE1535EE1F4A2916A1F73C5C900B7BE80CA1";

// ADR-0009: the release publisher writes releases/CURRENT.json LAST and this
// worker reads that one key, instead of sorting an R2 listing by upload time
// (which silently promoted any re-uploaded old ISO to "current").
const CURRENT_KEY = "releases/CURRENT.json";
const POINTER_SCHEMA = "shadowfetch.linux-current.v1";

const RELEASE_PREFIX = "releases/";
const SEMVER = /^\d+\.\d+\.\d+$/;
const SHA256 = /^[a-f0-9]{64}$/;

// ---------------------------------------------------------------------------
// Retirement policy (see ../policy/retirement.json — src/retirement.js is its
// generated mirror, and tests/test_retirement_policy.py fails if they diverge).
// ---------------------------------------------------------------------------

function isoNameFor(version) {
  return RETIREMENT_POLICY.iso_name_template.replace("{version}", version);
}

const RETIRED_BY_ISO = new Map(
  RETIREMENT_POLICY.retired.map((entry) => [isoNameFor(entry.version), entry]),
);

/** The retirement entry whose ISO body this filename IS, or null. */
function retiredIso(filename) {
  return RETIRED_BY_ISO.get(filename) || null;
}

/** The retirement entry this filename is a SIDECAR of, or null. */
function retiredSidecarOwner(filename) {
  for (const suffix of RETIREMENT_POLICY.sidecar_suffixes) {
    if (filename.endsWith(suffix)) {
      const entry = RETIRED_BY_ISO.get(filename.slice(0, -suffix.length));
      if (entry) return { entry, suffix };
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Legacy page routes. Each one is a page this worker used to render and the
// public site owns. They are listed explicitly, not pattern-matched: a silent
// catch-all redirect would turn a typo into a 301 and hide a real 404.
// ---------------------------------------------------------------------------

const LEGACY_PAGES = new Map([
  ["/linux/", "/"],
  ["/linux/download", "/download"],
  ["/linux/download/", "/download"],
  ["/linux/install", "/install"],
  ["/linux/verify", "/verify"],
  ["/linux/known-issues", "/known-issues"],
  ["/linux/hardware", "/hardware"],
  ["/linux/security", "/security"],
  ["/linux/roadmap", "/roadmap"],
  ["/linux/faq", "/faq"],
  ["/linux/docs", "/docs"],
  ["/linux/docs/", "/docs"],
  ["/linux/changelog", "/changelog"],
  ["/linux/licensing", "/licensing"],
  ["/linux/screenshots", "/screenshots"],
  ["/linux/local-ai", "/local-ai"],
  ["/linux/apt", "/apt"],
  ["/linux/releases.atom.xml", "/releases.atom.xml"],
]);

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const route = url.pathname === "/linux" ? "/linux/" : url.pathname;

    if (request.method !== "GET" && request.method !== "HEAD") {
      return text("method not allowed\n", 405);
    }

    try {
      // A removed feature stays removed. Never redirect this to a live page.
      if (route === "/linux/agents") return text("This feature has been removed.\n", 410);

      const legacy = LEGACY_PAGES.get(route);
      if (legacy) return movedTo(PUBLIC_SITE + legacy + url.search);

      if (route === "/linux/releases.json") return releaseJson(env);
      if (route === "/linux/_stats") return downloadStats(env, request);

      if (route === "/linux/shadowfetch.gpg.asc" || route === "/linux/apt/shadowfetch.gpg.asc") {
        return r2Stream(env, "shadowfetch.gpg.asc", request);
      }

      if (route.startsWith("/linux/assets/")) {
        const key = safeKey("assets/", route.slice("/linux/assets/".length));
        return key ? r2Stream(env, key, request) : notFound();
      }

      if (route.startsWith("/linux/download/")) {
        return downloadRoute(env, request, ctx, route.slice("/linux/download/".length));
      }

      if (route.startsWith("/linux/apt/")) {
        const rest = route.slice("/linux/apt/".length);
        // "/linux/apt/" itself is the root of the repository index.
        const key = rest === "" ? "apt/" : safeKey("apt/", rest);
        if (!key) return notFound();
        // R2 keys are flat, so a trailing-slash URL has no object behind it.
        // List the prefix instead: the written offer for corresponding source
        // links the source component's directory URL as a browsable index.
        if (key.endsWith("/")) return aptIndex(env, route, key);
        return r2Stream(env, key, request);
      }

      return notFound();
    } catch (err) {
      return text(`Server error: ${err.message}\n`, 500);
    }
  },
};

/**
 * Decode one path segment set and refuse anything that could leave the prefix.
 * Percent-encoding is decoded first: %2F arrives intact in url.pathname, so a
 * check that ran before decoding would let "..%2F.." through.
 */
function safeKey(prefix, rest) {
  let decoded;
  try {
    decoded = decodeURIComponent(rest);
  } catch {
    return null;
  }
  if (!decoded) return null;
  if (decoded.startsWith("/") || decoded.includes("\\") || decoded.includes("\0")) return null;
  if (decoded.split("/").some((part) => part === "." || part === "..")) return null;
  return prefix + decoded;
}

// ---------------------------------------------------------------------------
// Downloads
// ---------------------------------------------------------------------------

async function downloadRoute(env, request, ctx, rawFilename) {
  let filename;
  try {
    filename = decodeURIComponent(rawFilename);
  } catch {
    return notFound();
  }
  if (!filename || filename.includes("/") || filename.includes("\\") ||
      filename.includes("..") || filename.startsWith(".")) {
    return notFound();
  }

  const retired = retiredIso(filename);
  if (retired) return retiredResponse(env, request, filename, retired);

  // A retired image's torrent is published elsewhere; the policy carries the URL.
  const sidecar = retiredSidecarOwner(filename);
  if (sidecar && sidecar.suffix === ".torrent" && sidecar.entry.torrent) {
    return movedTo(sidecar.entry.torrent, 302);
  }

  const track = filename.endsWith(".iso") ? { ctx, filename, request } : null;
  return r2Stream(env, RELEASE_PREFIX + filename, request, { download: true, track });
}

/**
 * A retired image URL answers 410 — never 404, never a redirect to current bytes.
 *
 * 404 would claim the image never existed. A redirect would hand back a
 * different ISO under a URL whose published SHA-256 belongs to the one asked
 * for, which would make the verification instructions a lie.
 *
 * The sidecar links are HEADed before they are offered. The previous page
 * linked <filename>.sha256 and .asc unconditionally; both were pruned from the
 * bucket for 2.0.0 and 2.1.1, so the 410 page told people to verify against two
 * URLs that answered 404 (checked live, 2026-09-09).
 */
async function retiredResponse(env, request, filename, entry) {
  const successor = RETIREMENT_POLICY.successor_page;
  const sidecars = entry.retain_sidecars === false
    ? []
    : await presentSidecars(env, filename);

  const withdrawn = entry.status === "withdrawn";
  const headline = withdrawn
    ? "This image has been withdrawn"
    : "This Shadowfetch Linux image is superseded";
  const why = withdrawn
    ? `<p>${escapeHtml(entry.reason || "Withdrawn from active service.")}</p>
       <p class="muted">Withdrawn by decision ${escapeHtml(entry.decision || "unrecorded")}.</p>`
    : `<p>We keep retired versioned links explicit instead of silently redirecting
        them to a different image. That protects checksum expectations and tells
        you exactly which image you asked for.</p>`;
  const archive = entry.archive
    ? `<p>If you genuinely need the historical ${escapeHtml(entry.version)} image, use its
        preserved copy:<br><a href="${escapeAttr(entry.archive)}">${escapeHtml(entry.archive)}</a></p>`
    : `<p class="muted">No archived copy of this image is recorded.</p>`;
  const verify = sidecars.length
    ? `<p>If you already downloaded this image, these verification files are still
        served: ${sidecars.map((s) => `<a href="${escapeAttr(s.href)}">${escapeHtml(s.label)}</a>`).join(" \u00b7 ")}
        \u00b7 <a href="${escapeAttr(PUBLIC_SITE + "/verify")}">how to verify</a></p>`
    : `<p class="muted">No checksum or signature for this image remains in the
        download bucket, so this page does not offer one.</p>`;
  // A torrent is not a verification file, and saying so keeps the sentence above
  // true when the checksum and signature are gone but the torrent is not.
  const torrent = entry.torrent
    ? `<p>A torrent for this image is published at
        <a href="${escapeAttr(entry.torrent)}">${escapeHtml(entry.torrent)}</a>.</p>`
    : "";

  const body = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(filename)} is ${withdrawn ? "withdrawn" : "superseded"} — Shadowfetch Linux</title>
<style>
 body{margin:0;background:#12110f;color:#e9e6df;
      font:16px/1.6 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
 main{max-width:44rem;margin:0 auto;padding:3.5rem 1.5rem}
 h1{font-size:1.6rem;line-height:1.25;margin:0 0 1rem}
 a{color:#D8A24A} code{background:#1e1c19;padding:.15em .4em;border-radius:4px;
   font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;overflow-wrap:anywhere}
 .why{border-left:2px solid #D8A24A;padding:.6rem 0 .6rem 1rem;margin:1.5rem 0;color:#c3bdb2}
 .muted{color:#8d8779}
 .cta{display:inline-block;margin:1.4rem 0;padding:.7rem 1.4rem;background:#D8A24A;
      color:#12110f;font-weight:700;text-decoration:none;border-radius:6px}
 footer{margin-top:2.5rem;padding-top:1rem;border-top:1px solid #2a2823;
        color:#8d8779;font-size:.85rem}
</style></head><body><main>
<h1>${headline}</h1>
<p><code>${escapeHtml(filename)}</code> is the ${escapeHtml(entry.version)} image and is no longer
served from the active download bucket.</p>
<div class="why">${why}</div>
<p><a class="cta" href="${escapeAttr(successor)}">Get the current Shadowfetch Linux release</a></p>
${archive}
${verify}
${torrent}
<footer>HTTP 410 Gone · ${escapeHtml(entry.status)} image · current release:
<a href="${escapeAttr(successor)}">${escapeHtml(successor)}</a></footer>
</main></body></html>
`;

  const headers = new Headers({
    "content-type": "text/html; charset=utf-8",
    // Short cache: a retirement should be reversible within the hour if the
    // decision changes, not pinned at the edge for a day.
    "cache-control": "public, max-age=900",
    "x-shadowfetch-retired": entry.status,
    "x-shadowfetch-retired-version": entry.version,
    "link": entry.archive
      ? `<${entry.archive}>; rel="archives", <${successor}>; rel="successor-version"`
      : `<${successor}>; rel="successor-version"`,
  });
  if (entry.decision) headers.set("x-withdrawn-by", entry.decision);
  applySec(headers);
  headers.set("x-shadowfetch-artifact-worker", WORKER_BUILD);
  return new Response(request.method === "HEAD" ? null : body, { status: 410, headers });
}

/** Sidecars of a retired image that are actually still in the bucket. */
async function presentSidecars(env, filename) {
  const present = [];
  for (const suffix of [".sha256", ".asc"]) {
    const head = await env.RELEASES.head(RELEASE_PREFIX + filename + suffix);
    if (head) present.push({ label: suffix, href: `${ARTIFACT_BASE}/download/${filename}${suffix}` });
  }
  return present;
}

// ---------------------------------------------------------------------------
// The current release
// ---------------------------------------------------------------------------

/**
 * Read releases/CURRENT.json and validate every field that decides what the
 * world is told is current.
 *
 * Three outcomes, kept distinct on purpose:
 *   absent       no pointer published yet -> fall back to a paginated listing
 *   unusable     a pointer exists but is malformed, names another signing key,
 *                or names a retired image -> refuse; do NOT guess
 *   contradicted the named object is missing or a different size -> refuse
 */
async function readPointer(env) {
  let object;
  try {
    object = await env.RELEASES.get(CURRENT_KEY);
  } catch (err) {
    return { state: "unusable", reason: `pointer unreadable: ${err.message}` };
  }
  if (!object) return { state: "absent", reason: "no releases/CURRENT.json in the bucket" };

  let doc;
  try {
    doc = JSON.parse(await object.text());
  } catch {
    return { state: "unusable", reason: "pointer is not valid JSON" };
  }

  const problem = pointerProblem(doc);
  if (problem) return { state: "unusable", reason: problem };
  if (retiredIso(doc.iso.filename)) {
    return { state: "unusable", reason: "pointer names an image the retirement policy retires" };
  }

  const head = await env.RELEASES.head(doc.iso.key);
  if (!head) {
    return { state: "contradicted", reason: `pointer names ${doc.iso.key}, which is not in the bucket` };
  }
  if (head.size !== doc.iso.size_bytes) {
    return {
      state: "contradicted",
      reason: `pointer says ${doc.iso.size_bytes} bytes, bucket holds ${head.size}`,
    };
  }

  return {
    state: "ok",
    release: {
      source: "pointer",
      version: doc.version,
      filename: doc.iso.filename,
      key: doc.iso.key,
      size: head.size,
      sizeHuman: humanBytes(head.size),
      sha256: doc.iso.sha256,
      published: doc.published || null,
      hasSignature: Boolean(await env.RELEASES.head(doc.iso.key + ".asc")),
    },
  };
}

/** Returns a human-readable problem string, or "" when the document is sound. */
function pointerProblem(doc) {
  if (!doc || typeof doc !== "object") return "pointer is not an object";
  if (doc.schema !== POINTER_SCHEMA) return `pointer schema is ${JSON.stringify(doc.schema)}`;
  if (typeof doc.version !== "string" || !SEMVER.test(doc.version)) return "pointer version is not X.Y.Z";
  const iso = doc.iso;
  if (!iso || typeof iso !== "object") return "pointer has no iso object";
  if (iso.filename !== isoNameFor(doc.version)) return "pointer iso filename does not match its version";
  if (iso.key !== RELEASE_PREFIX + iso.filename) return "pointer iso key is not releases/<filename>";
  if (!Number.isSafeInteger(iso.size_bytes) || iso.size_bytes <= 0) return "pointer iso size_bytes is not a positive integer";
  if (typeof iso.sha256 !== "string" || !SHA256.test(iso.sha256)) return "pointer iso sha256 is not 64 lowercase hex";
  if (doc.signing_key_fingerprint !== GPG_FINGERPRINT) return "pointer names a different signing key";
  return "";
}

/**
 * Fallback used only while no pointer has ever been published. Paginated (the
 * previous implementation truncated at 100 objects) and ordered by semantic
 * version, not upload time, so re-uploading an old ISO cannot promote it.
 * Retired images are never eligible.
 */
async function listingFallback(env) {
  let cursor;
  const candidates = [];
  do {
    const listed = await env.RELEASES.list({ prefix: RELEASE_PREFIX, cursor });
    for (const object of listed.objects || []) {
      const filename = object.key.slice(RELEASE_PREFIX.length);
      if (!filename.endsWith(".iso") || filename.includes("/")) continue;
      if (retiredIso(filename)) continue;
      const version = versionOf(filename);
      if (!version || filename !== isoNameFor(version)) continue;
      candidates.push({ object, filename, version });
    }
    cursor = listed.truncated ? listed.cursor : undefined;
  } while (cursor);

  if (!candidates.length) return null;
  candidates.sort((a, b) => {
    const order = compareVersions(b.version, a.version);
    return order !== 0 ? order : new Date(b.object.uploaded) - new Date(a.object.uploaded);
  });
  const chosen = candidates[0];

  let sha256 = null;
  try {
    const shaObject = await env.RELEASES.get(chosen.object.key + ".sha256");
    if (shaObject) {
      const match = /([a-f0-9]{64})/i.exec(await shaObject.text());
      if (match) sha256 = match[1].toLowerCase();
    }
  } catch { /* a missing checksum is reported as null, not invented */ }

  return {
    source: "listing-fallback",
    version: chosen.version,
    filename: chosen.filename,
    key: chosen.object.key,
    size: chosen.object.size,
    sizeHuman: humanBytes(chosen.object.size),
    sha256,
    published: chosen.object.uploaded ? new Date(chosen.object.uploaded).toISOString() : null,
    hasSignature: Boolean(await env.RELEASES.head(chosen.object.key + ".asc")),
  };
}

async function currentRelease(env) {
  const pointer = await readPointer(env);
  if (pointer.state === "ok") return { release: pointer.release, reason: "" };
  if (pointer.state !== "absent") {
    // A published pointer that does not hold is an active inconsistency. Saying
    // nothing is correct; quietly falling back would hide it.
    return { release: null, reason: pointer.reason };
  }
  const release = await listingFallback(env);
  return {
    release,
    reason: release ? pointer.reason : "no release ISO found under releases/",
  };
}

function compareVersions(a, b) {
  const left = a.split(".").map(Number);
  const right = b.split(".").map(Number);
  for (let i = 0; i < 3; i++) {
    if (left[i] !== right[i]) return left[i] - right[i];
  }
  return 0;
}

/**
 * The artifact-side answer to "what is published right now", derived from the
 * pointer (or, until one exists, from the bucket). The public site's own
 * release feed is built from its manifests; this endpoint reports what the
 * bucket actually holds, and says which of the two sources it used.
 */
async function releaseJson(env) {
  const { release, reason } = await currentRelease(env);
  const body = {
    schema: "shadowfetch.linux-release-feed.v1",
    product: "Shadowfetch Linux",
    homepage: PUBLIC_SITE,
    self: `${ARTIFACT_BASE}/releases.json`,
    pointer: { key: CURRENT_KEY, source: release ? release.source : null, note: reason || null },
    latest: release
      ? {
          schema: "shadowfetch.linux-release.v1",
          version: release.version,
          codename: "Umbra",
          channel: "stable",
          architecture: "amd64",
          published: release.published,
          iso: {
            filename: release.filename,
            url: `${ARTIFACT_BASE}/download/${release.filename}`,
            mediaType: "application/x-iso9660-image",
            sizeBytes: release.size,
            sizeLabel: release.sizeHuman,
            sha256: release.sha256,
            hybrid: true,
          },
          signature: release.hasSignature
            ? { url: `${ARTIFACT_BASE}/download/${release.filename}.asc`, type: "openpgp-detached-armored" }
            : null,
          signingKey: { fingerprint: GPG_FINGERPRINT, url: `${ARTIFACT_BASE}/shadowfetch.gpg.asc` },
          pages: {
            download: `${PUBLIC_SITE}/download`,
            verify: `${PUBLIC_SITE}/verify`,
            install: `${PUBLIC_SITE}/install`,
            changelog: `${PUBLIC_SITE}/changelog`,
          },
        }
      : null,
    retired: RETIREMENT_POLICY.retired.map((entry) => ({
      version: entry.version,
      status: entry.status,
      decision: entry.decision || null,
      url: `${ARTIFACT_BASE}/download/${isoNameFor(entry.version)}`,
      archive: entry.archive || null,
    })),
  };
  const headers = new Headers({
    "content-type": "application/json; charset=utf-8",
    "cache-control": release ? "public, max-age=300" : "no-store",
  });
  applySec(headers);
  headers.set("x-shadowfetch-artifact-worker", WORKER_BUILD);
  return new Response(`${JSON.stringify(body, null, 2)}\n`, {
    status: release ? 200 : 503,
    headers,
  });
}

// ---------------------------------------------------------------------------
// APT directory index
// ---------------------------------------------------------------------------

async function aptIndex(env, route, prefix) {
  let cursor;
  const objects = [];
  const prefixes = new Set();
  do {
    const listed = await env.RELEASES.list({ prefix, delimiter: "/", cursor });
    for (const object of listed.objects || []) {
      if (object.key !== prefix) objects.push(object);
    }
    for (const child of listed.delimitedPrefixes || []) prefixes.add(child);
    cursor = listed.truncated ? listed.cursor : undefined;
  } while (cursor);

  if (!objects.length && !prefixes.size) return notFound();

  const parent = route.replace(/[^/]*\/$/, "").replace(/\/$/, "") || "/linux/apt";
  const rows = [
    `<tr><td><a href="${escapeAttr(parent + "/")}">../</a></td><td>-</td><td>-</td></tr>`,
    ...[...prefixes].sort().map((child) => {
      const name = child.slice(prefix.length);
      return `<tr><td><a href="${escapeAttr(route + name)}">${escapeHtml(name)}</a></td><td>dir</td><td>-</td></tr>`;
    }),
    ...objects.sort((a, b) => a.key.localeCompare(b.key)).map((object) => {
      const name = object.key.slice(prefix.length);
      const when = object.uploaded ? new Date(object.uploaded).toISOString().slice(0, 10) : "";
      return `<tr><td><a href="${escapeAttr(route + name)}">${escapeHtml(name)}</a></td>` +
             `<td>${object.size}</td><td>${escapeHtml(when)}</td></tr>`;
    }),
  ];

  const body = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Index of ${escapeHtml(route)}</title>
<style>
 body{margin:0;background:#12110f;color:#e9e6df;font:15px/1.6 ui-monospace,SFMono-Regular,Menlo,monospace}
 main{max-width:60rem;margin:0 auto;padding:2.5rem 1.5rem}
 a{color:#D8A24A} table{width:100%;border-collapse:collapse}
 th,td{text-align:left;padding:.2rem .8rem .2rem 0;border-bottom:1px solid #2a2823}
 p{color:#8d8779}
</style></head><body><main>
<h1>Index of ${escapeHtml(route)}</h1>
<p>Signed APT repository. Verify with <code>/linux/apt/dists/umbra/InRelease</code>.</p>
<table><thead><tr><th>Name</th><th>Bytes</th><th>Uploaded</th></tr></thead>
<tbody>${rows.join("")}</tbody></table>
<p><a href="${escapeAttr(PUBLIC_SITE + "/licensing")}">Licensing &amp; source</a></p>
</main></body></html>
`;
  const headers = new Headers({
    "content-type": "text/html; charset=utf-8",
    "cache-control": "public, max-age=300",
  });
  applySec(headers);
  headers.set("x-shadowfetch-artifact-worker", WORKER_BUILD);
  return new Response(body, { headers });
}

// ---------------------------------------------------------------------------
// Download counters
// ---------------------------------------------------------------------------

function uaClass(ua) {
  const value = (ua || "").toLowerCase();
  if (!value) return "other";
  if (/(bot|crawl|spider|scan|monitor|python|go-http|libwww|httpclient|java|headless|wget)/.test(value)) return "bot";
  if (value.startsWith("curl")) return "curl";
  if (value.includes("mozilla")) return "browser";
  return "other";
}

function migrateEntry(value) {
  if (typeof value === "number") return { starts: value, rangeStarts: 0, size: 0, ua: {}, cc: {}, days: {} };
  value.ua = value.ua || {}; value.cc = value.cc || {}; value.days = value.days || {};
  return value;
}

/**
 * Start-only counters. There is no end-of-stream hook — the R2 body is handed
 * straight to the client, because piping a multi-GB download through a
 * TransformStream truncates it — so completions and delivered bytes are not
 * measured and are not claimed.
 *
 * KNOWN LIMITATION, not fixed here: this is a read-modify-write of one JSON
 * object with no compare-and-set, so simultaneous downloads lose counts. It
 * runs in ctx.waitUntil so it can never delay or fail an ISO download, but the
 * numbers are a floor, not a ledger. W-66 moves this to Analytics Engine.
 */
async function recordDownload(env, filename, request, meta) {
  const key = "stats/downloads.json";
  let data = {};
  try {
    const object = await env.RELEASES.get(key);
    if (object) data = JSON.parse(await object.text());
  } catch { /* a corrupt or absent counter file must not break a download */ }
  const entry = migrateEntry(data[filename] || {});
  const day = new Date().toISOString().slice(0, 10);
  const perDay = entry.days[day] || { s: 0 };
  entry.size = meta.size || entry.size || 0;
  const cls = uaClass(request.headers.get("user-agent"));
  const country = (request.cf && request.cf.country) || "??";
  if (meta.isFull) { entry.starts = (entry.starts || 0) + 1; perDay.s = (perDay.s || 0) + 1; }
  else if (meta.rangeOffset === 0) entry.rangeStarts = (entry.rangeStarts || 0) + 1;
  entry.ua[cls] = (entry.ua[cls] || 0) + 1;
  entry.cc[country] = (entry.cc[country] || 0) + 1;
  entry.days[day] = perDay;
  const days = Object.keys(entry.days).sort();
  while (days.length > 90) delete entry.days[days.shift()];
  data[filename] = entry;
  await env.RELEASES.put(key, JSON.stringify(data), {
    httpMetadata: { contentType: "application/json" },
  });
}

async function downloadStats(env, request) {
  const url = new URL(request.url);
  const presented = (request.headers.get("authorization") || "").replace(/^Bearer\s+/i, "")
    || request.headers.get("x-shadowfetch-stats-key")
    || url.searchParams.get("token") || "";
  if (!env.STATS_TOKEN || presented !== env.STATS_TOKEN) {
    return text("unauthorized\n", 401, { "cache-control": "no-store", "x-robots-tag": "noindex" });
  }

  let data = {};
  try {
    const object = await env.RELEASES.get("stats/downloads.json");
    if (object) data = JSON.parse(await object.text());
  } catch { /* reported as empty rather than as an error page */ }
  const files = {};
  let starts = 0;
  let rangeStarts = 0;
  for (const [name, raw] of Object.entries(data)) {
    const entry = migrateEntry(typeof raw === "number" ? raw : { ...raw });
    starts += entry.starts || 0;
    rangeStarts += entry.rangeStarts || 0;
    files[name] = {
      starts: entry.starts || 0,
      rangeStarts: entry.rangeStarts || 0,
      ua: entry.ua,
      countries: entry.cc,
      days: entry.days,
    };
  }
  const headers = new Headers({
    "content-type": "application/json",
    "cache-control": "no-store",
    "x-robots-tag": "noindex",
  });
  applySec(headers);
  return new Response(JSON.stringify({
    note: "Start-only metrics, counted without compare-and-set: concurrent downloads lose counts, so these are a floor. starts = a full-file GET began; rangeStarts = a fresh ranged GET began at offset 0. Completion and delivered bytes are NOT measured.",
    totals: { starts, rangeStarts },
    files,
  }, null, 1), { headers });
}

// ---------------------------------------------------------------------------
// R2 streaming
// ---------------------------------------------------------------------------

async function r2Stream(env, key, request, opts = {}) {
  const range = request.headers.get("range");
  const r2opts = {};
  if (range) {
    const match = /bytes=(\d+)-(\d+)?/.exec(range);
    if (match) {
      const offset = parseInt(match[1], 10);
      const end = match[2] ? parseInt(match[2], 10) : undefined;
      r2opts.range = end !== undefined ? { offset, length: end - offset + 1 } : { offset };
    }
  }

  if (request.method === "HEAD") {
    const head = await env.RELEASES.head(key);
    if (!head) return notFound();
    return new Response(null, { status: 200, headers: baseHeaders(head, opts) });
  }

  const object = await env.RELEASES.get(key, r2opts);
  if (!object) return notFound();

  const headers = baseHeaders(object, opts);
  let status = 200;
  if (range && object.range) {
    status = 206;
    const total = object.size;
    const start = object.range.offset || 0;
    const length = object.range.length || (total - start);
    headers.set("content-range", `bytes ${start}-${start + length - 1}/${total}`);
    headers.set("content-length", String(length));
  }

  if (opts.track && opts.track.ctx) {
    const meta = {
      isFull: !range,
      rangeOffset: (r2opts.range && r2opts.range.offset) || 0,
      size: object.size,
    };
    // Never on the critical path: a slow or failing counter write must not delay
    // or abort an ISO download.
    opts.track.ctx.waitUntil(
      recordDownload(env, opts.track.filename, opts.track.request, meta).catch(() => {}),
    );
  }
  return new Response(object.body, { status, headers });
}

// ---------------------------------------------------------------------------
// Responses and headers
// ---------------------------------------------------------------------------

// This worker serves bytes and two small generated documents. It loads no
// script and no third-party resource, so the policy says exactly that.
const SEC_HEADERS = {
  "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "strict-origin-when-cross-origin",
  "permissions-policy": "geolocation=(), microphone=(), camera=()",
  "content-security-policy":
    "default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'; " +
    "object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
};

function applySec(headers) {
  for (const name in SEC_HEADERS) headers.set(name, SEC_HEADERS[name]);
  return headers;
}

function baseHeaders(object, opts) {
  const headers = new Headers();
  headers.set("accept-ranges", "bytes");
  if (object.httpEtag) headers.set("etag", object.httpEtag);
  if (object.size != null) headers.set("content-length", String(object.size));
  headers.set("content-type", guessContentType(object.key || ""));
  if (opts.download) {
    const filename = (object.key || "download").split("/").pop();
    headers.set("content-disposition", `attachment; filename="${filename}"`);
  }
  headers.set(
    "cache-control",
    /\.iso$|\.deb$|\.tar\.|\.gpg$|\.asc$/.test(object.key || "")
      ? "public, max-age=86400, immutable"
      : "public, max-age=300",
  );
  return applySec(headers);
}

function guessContentType(key) {
  // Checked before ".asc": the armoured public key is shadowfetch.gpg.asc, and
  // the old suffix order labelled the signing key as a detached signature.
  if (key.endsWith(".gpg.asc") || key.endsWith(".gpg")) return "application/pgp-keys";
  if (key.endsWith(".iso")) return "application/x-iso9660-image";
  if (key.endsWith(".sha256")) return "text/plain; charset=utf-8";
  if (key.endsWith(".asc") || key.endsWith(".sig")) return "application/pgp-signature";
  if (key.endsWith(".deb")) return "application/vnd.debian.binary-package";
  if (key.endsWith(".torrent")) return "application/x-bittorrent";
  if (key.endsWith(".gz")) return "application/gzip";
  if (key.endsWith(".xz")) return "application/x-xz";
  if (key.endsWith(".json")) return "application/json; charset=utf-8";
  if (key.endsWith(".md")) return "text/markdown; charset=utf-8";
  if (key.endsWith(".txt") || key.endsWith("Release") || key.endsWith("InRelease") || key.endsWith("Packages")) {
    return "text/plain; charset=utf-8";
  }
  if (key.endsWith(".png")) return "image/png";
  if (key.endsWith(".jpg") || key.endsWith(".jpeg")) return "image/jpeg";
  if (key.endsWith(".webp")) return "image/webp";
  if (key.endsWith(".svg")) return "image/svg+xml";
  if (key.endsWith(".ico")) return "image/x-icon";
  return "application/octet-stream";
}

function movedTo(location, status = 301) {
  const headers = new Headers({
    location,
    "content-type": "text/plain; charset=utf-8",
    "cache-control": "public, max-age=3600",
  });
  applySec(headers);
  headers.set("x-shadowfetch-artifact-worker", WORKER_BUILD);
  return new Response(`Moved to ${location}\n`, { status, headers });
}

function text(body, status = 200, extra = {}) {
  const headers = new Headers({ "content-type": "text/plain; charset=utf-8", ...extra });
  applySec(headers);
  headers.set("x-shadowfetch-artifact-worker", WORKER_BUILD);
  return new Response(body, { status, headers });
}

/**
 * Artifact endpoints answer a missing object in plain text. They used to render
 * a full site page, which meant a mistyped filename returned 14 KB of marketing
 * to `curl` and `apt`.
 */
function notFound() {
  return text("Not found. Artifacts live under /linux/download/ and /linux/apt/.\n", 404);
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function versionOf(filename) {
  const match = /(\d+\.\d+\.\d+)/.exec(filename || "");
  return match ? match[1] : "";
}

function humanBytes(n) {
  if (n == null) return "?";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let index = 0;
  let value = n;
  while (value >= 1024 && index < units.length - 1) { value /= 1024; index++; }
  return `${value.toFixed(value >= 10 ? 0 : 1)} ${units[index]}`;
}

function escapeHtml(s) {
  return String(s)
    .replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;").replaceAll("'", "&#39;");
}

function escapeAttr(s) { return escapeHtml(s); }

// Exported for tests only; the Worker entry point is the default export.
export const __test__ = {
  LEGACY_PAGES,
  RETIRED_BY_ISO,
  compareVersions,
  guessContentType,
  isoNameFor,
  pointerProblem,
  retiredIso,
  retiredSidecarOwner,
  safeKey,
};
