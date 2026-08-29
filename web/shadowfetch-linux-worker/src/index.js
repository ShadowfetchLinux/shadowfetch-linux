// shadowfetch.com/linux/* — landing + download + APT repo proxy
// Bindings: RELEASES (R2 bucket "shadowfetch-linux")
//
// R2 layout:
//   releases/shadowfetch-<version>-amd64.iso
//   releases/shadowfetch-<version>-amd64.iso.sha256
//   releases/shadowfetch-<version>-amd64.iso.asc       (detached signature)
//   apt/dists/umbra/...                                (reprepro output)
//   apt/pool/main/s/shadowfetch-*/...                  (the .debs)
//   shadowfetch.gpg.asc                                (public signing key)

const GPG_FINGERPRINT = "8F13CE1535EE1F4A2916A1F73C5C900B7BE80CA1";
const SHADOWFETCH_211_TORRENT_ALIAS =
  "/linux/download/shadowfetch-2.1.1-amd64.iso.torrent";
const SHADOWFETCH_211_TORRENT_RELEASE =
  "https://github.com/Realbobcorbin/shadowfetch-linux/releases/download/v2.1.1/shadowfetch-2.1.1-amd64.iso.torrent";

// The raw download stats at /linux/_stats are gated behind a secret. Set it once:
//   wrangler secret put STATS_TOKEN
// then read them with ?token=<value> (or an Authorization: Bearer <value> /
// x-shadowfetch-stats-key header). With no STATS_TOKEN configured, /linux/_stats
// always 401s and reveals nothing.

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    // Strip trailing slash for routing consistency, except for root and obvious dirs
    const route = path === "/linux" ? "/linux/" : path;

    try {
      // -------- HTML pages --------
      if (route === "/linux/")                return html(landingPage(await latestRelease(env)));
      if (route === "/linux/install")         return html(installPage(await latestRelease(env)));
      if (route === "/linux/verify")          return html(verifyPage(await latestRelease(env)));
      if (route === "/linux/known-issues")    return html(knownIssuesPage());
      if (route === "/linux/hardware")        return html(hardwarePage());
      if (route === "/linux/security")        return html(securityPage());
      if (route === "/linux/roadmap")         return html(roadmapPage(await latestRelease(env)));
      if (route === "/linux/faq")             return html(faqPage());
      if (route === "/linux/benchmarks")      return html(benchmarksPage());
      if (route === "/linux/agents") {
        return new Response("This feature has been removed.\n", {
          status: 410,
          headers: { "content-type": "text/plain; charset=utf-8" },
        });
      }
      if (route === "/linux/docs" ||
          route === "/linux/docs/")           return html(docsIndex());
      if (route === "/linux/changelog")       return html(changelogPage());
      if (route === "/linux/releases.json") {
        return releaseJson(await latestRelease(env));
      }
      if (route === "/linux/releases.atom.xml") {
        return releaseAtom(await latestRelease(env));
      }
      if (route === "/linux/_stats")          return downloadStats(env, request);

      // -------- Static asset: the GPG public key (also at /linux/apt/ for apt) --------
      if (route === "/linux/shadowfetch.gpg.asc")    return r2Stream(env, "shadowfetch.gpg.asc", request);
      if (route === "/linux/apt/shadowfetch.gpg.asc") return r2Stream(env, "shadowfetch.gpg.asc", request);

      // -------- Brand assets (logo, wallpaper) --------
      if (route.startsWith("/linux/assets/")) {
        const key = "assets/" + route.slice("/linux/assets/".length);
        if (key.includes("..")) return notFound();
        return r2Stream(env, key, request);
      }

      // -------- ISO + checksum downloads --------
      // Board decision 20260724-5b83 withdrew the 2.0.0 image from active
      // service. Its installer overwrote sources.list with Debian's stable
      // template on a testing userland, so apt broke on the first install.
      //
      // Only the .iso is withdrawn. The .sha256 and .asc keep serving on
      // purpose: someone who downloaded 2.0.0 before the withdrawal still needs
      // to verify the copy they hold, and removing the signature would take
      // that away from precisely the users careful enough to check.
      //
      // 410, not 404 and not a redirect. 404 would claim it never existed.
      // A redirect would hand back 2.0.1 bytes under a URL whose published
      // SHA-256 belongs to 2.0.0, which would make /linux/verify a liar.
      if (route === "/linux/download/") return Response.redirect(new URL("/linux/download", url), 302);
      if (route === SHADOWFETCH_211_TORRENT_ALIAS) {
        return Response.redirect(SHADOWFETCH_211_TORRENT_RELEASE, 302);
      }
      if (route.startsWith("/linux/download/")) {
        const filename = route.slice("/linux/download/".length);
        if (!filename || filename.includes("..") || filename.includes("/")) return notFound();
        if (SUPERSEDED_ISOS.has(filename)) return superseded(filename, await latestRelease(env));
        if (WITHDRAWN.has(filename)) return withdrawn(filename, await latestRelease(env));
        const track = filename.endsWith(".iso") ? { ctx, filename, request } : null;
        return r2Stream(env, `releases/${filename}`, request, { download: true, track });
      }
      if (route === "/linux/download")        return html(downloadPage(await latestRelease(env)));

      // -------- APT repo proxy (passes through reprepro structure) --------
      if (route === "/linux/apt") {
        return aptIndex(env, "/linux/apt/", "apt/");
      }
      if (route.startsWith("/linux/apt/")) {
        const key = "apt/" + route.slice("/linux/apt/".length);
        if (key.includes("..")) return notFound();
        // A trailing slash is a directory request. R2 keys are flat, so there is
        // no object to stream — list the prefix instead. The written offer for
        // corresponding source on /linux/licensing links the source component's
        // directory URL as a browsable index, so it has to resolve.
        if (key.endsWith("/")) return aptIndex(env, route, key);
        return r2Stream(env, key, request);
      }

      return notFound();
    } catch (err) {
      return new Response(`Server error: ${err.message}\n`, { status: 500 });
    }
  },
};

// ---------- Directory index for the APT subtree ----------
// R2 has no directory objects, so a trailing-slash URL under /linux/apt/ is
// answered by listing the key prefix. Used by the corresponding-source offer.
async function aptIndex(env, route, prefix) {
  let cursor;
  const objects = [];
  const prefixes = new Set();
  do {
    const listed = await env.RELEASES.list({ prefix, delimiter: "/", cursor });
    for (const o of listed.objects || []) {
      if (o.key !== prefix) objects.push(o);
    }
    for (const p of listed.delimitedPrefixes || []) prefixes.add(p);
    cursor = listed.truncated ? listed.cursor : undefined;
  } while (cursor);

  if (!objects.length && !prefixes.size) return notFound();

  const parent = route.replace(/[^/]*\/$/, "").replace(/\/$/, "") || "/linux/apt";
  const dirRows = [...prefixes].sort().map((p) => {
    const name = p.slice(prefix.length);
    return `<tr><td><a href="${escapeAttr(route + name)}">${escapeHtml(name)}</a></td>` +
           `<td class="muted">dir</td><td class="muted">-</td></tr>`;
  });
  const fileRows = objects
    .sort((a, b) => a.key.localeCompare(b.key))
    .map((o) => {
      const name = o.key.slice(prefix.length);
      const when = o.uploaded ? new Date(o.uploaded).toISOString().slice(0, 10) : "";
      return `<tr><td><a href="${escapeAttr(route + name)}">${escapeHtml(name)}</a></td>` +
             `<td>${o.size}</td><td class="muted">${escapeHtml(when)}</td></tr>`;
    });

  return html(shell({
    title: `Index of ${route} — Shadowfetch Linux`,
    canonical: route,
    body: `
<section class="narrow">
  <h1>Index of <code>${escapeHtml(route)}</code></h1>
  <p class="muted">Signed APT repository. Verify with
    <code>${escapeHtml("/linux/apt/dists/umbra/InRelease")}</code>.</p>
  <table class="index">
    <thead><tr><th>Name</th><th>Bytes</th><th>Uploaded</th></tr></thead>
    <tbody>
      <tr><td><a href="${escapeAttr(parent + "/")}">../</a></td><td class="muted">-</td><td class="muted">-</td></tr>
      ${dirRows.join("\n      ")}
      ${fileRows.join("\n      ")}
    </tbody>
  </table>
  <p><a href="/linux/licensing">Licensing &amp; source</a></p>
</section>
`,
  }));
}

// ---------- R2 streaming with Range + HEAD ----------

// Download analytics: per-file start counts (full vs. ranged), UA class, country, per-day.
function uaClass(ua) {
  const u = (ua || "").toLowerCase();
  if (!u) return "other";
  if (/(bot|crawl|spider|scan|monitor|python|go-http|libwww|httpclient|java|headless|wget)/.test(u)) return "bot";
  if (u.startsWith("curl")) return "curl";
  if (u.includes("mozilla")) return "browser";
  return "other";
}

function migrateEntry(v) {
  if (typeof v === "number") return { starts: v, rangeStarts: 0, size: 0, ua: {}, cc: {}, days: {} };
  v.ua = v.ua || {}; v.cc = v.cc || {}; v.days = v.days || {};
  return v;
}

// We only ever record the START of a download: counts (full-GET starts vs.
// range starts), UA class, and country. There is no end-of-stream hook --
// the R2 body is streamed directly to the client (piping multi-GB downloads
// through a TransformStream truncates them), so completes / delivered bytes
// cannot be measured and are not claimed.
async function recordDownload(env, filename, request, m) {
  const key = "stats/downloads.json";
  let data = {};
  try { const o = await env.RELEASES.get(key); if (o) data = JSON.parse(await o.text()); } catch (e) {}
  const f = migrateEntry(data[filename] || {});
  const day = new Date().toISOString().slice(0, 10);
  const d = f.days[day] || { s: 0 };
  f.size = m.size || f.size || 0;
  const cls = uaClass(request.headers.get("user-agent"));
  const cc = (request.cf && request.cf.country) || "??";
  if (m.isFull) { f.starts = (f.starts || 0) + 1; d.s = (d.s || 0) + 1; }
  else if (m.rangeOffset === 0) f.rangeStarts = (f.rangeStarts || 0) + 1;
  f.ua[cls] = (f.ua[cls] || 0) + 1;
  f.cc[cc] = (f.cc[cc] || 0) + 1;
  f.days[day] = d;
  const dk = Object.keys(f.days).sort();
  while (dk.length > 90) delete f.days[dk.shift()];
  data[filename] = f;
  await env.RELEASES.put(key, JSON.stringify(data), { httpMetadata: { contentType: "application/json" } });
}

async function downloadStats(env, request) {
  // Gated endpoint: mirrors the home worker's token auth (?token= / Bearer /
  // x-shadowfetch-stats-key vs. env.STATS_TOKEN). Without a configured token
  // or a matching request token, return 401 -- the raw stats are not public.
  const url = new URL(request.url);
  const tok = (request.headers.get("authorization") || "").replace(/^Bearer\s+/i, "")
    || request.headers.get("x-shadowfetch-stats-key")
    || url.searchParams.get("token") || "";
  if (!env.STATS_TOKEN || tok !== env.STATS_TOKEN) {
    return new Response("unauthorized\n", {
      status: 401,
      headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store", "x-robots-tag": "noindex" },
    });
  }

  let data = {};
  try { const o = await env.RELEASES.get("stats/downloads.json"); if (o) data = JSON.parse(await o.text()); } catch (e) {}
  const files = {}; let tStarts = 0, tRangeStarts = 0;
  for (const [name, raw] of Object.entries(data)) {
    const f = migrateEntry(typeof raw === "number" ? raw : { ...raw });
    tStarts += f.starts || 0; tRangeStarts += f.rangeStarts || 0;
    files[name] = {
      starts: f.starts || 0, rangeStarts: f.rangeStarts || 0,
      ua: f.ua, countries: f.cc, days: f.days,
    };
  }
  const out = {
    note: "Start-only metrics. starts = a full-file GET was begun; rangeStarts = a fresh ranged GET began at offset 0 (download managers / resumes). Completion and delivered bytes are NOT measured: the ISO body streams straight from R2 with no end-of-stream hook. ua = requesting-client class; countries = Cloudflare-reported country; days = per-day full-GET starts (last 90 days).",
    totals: { starts: tStarts, rangeStarts: tRangeStarts },
    files,
  };
  return new Response(JSON.stringify(out, null, 1), {
    headers: {
      "content-type": "application/json",
      "cache-control": "no-store",
      "x-robots-tag": "noindex",
    },
  });
}

async function r2Stream(env, key, request, opts = {}) {
  const range = request.headers.get("range");
  const r2opts = {};
  if (range) {
    const m = /bytes=(\d+)-(\d+)?/.exec(range);
    if (m) {
      const offset = parseInt(m[1], 10);
      const end = m[2] ? parseInt(m[2], 10) : undefined;
      r2opts.range = end !== undefined ? { offset, length: end - offset + 1 } : { offset };
    }
  }

  // HEAD: just check existence/metadata
  if (request.method === "HEAD") {
    const head = await env.RELEASES.head(key);
    if (!head) return notFound();
    const headers = baseHeaders(head, opts);
    return new Response(null, { status: 200, headers });
  }

  if (request.method !== "GET") return new Response("method not allowed", { status: 405 });

  const obj = await env.RELEASES.get(key, r2opts);
  if (!obj) return notFound();

  const headers = baseHeaders(obj, opts);
  let status = 200;
  if (range && obj.range) {
    status = 206;
    const total = obj.size;
    const start = obj.range.offset || 0;
    const len = obj.range.length || (total - start);
    headers.set("content-range", `bytes ${start}-${start + len - 1}/${total}`);
    headers.set("content-length", String(len));
  }
  // Delivered-bytes tracking (ISO downloads): count what the client actually pulls,
  // including aborted transfers, and record it after the stream settles.
  if (opts.track && opts.track.ctx) {
    const t = opts.track;
    const isFull = !range;
    const rangeOffset = (r2opts.range && r2opts.range.offset) || 0;
    // Record the start (counts + UA + country) synchronously, then stream the R2 body
    // DIRECTLY. Do NOT pipe multi-GB downloads through a TransformStream: the Workers
    // runtime truncates large piped streams (~88 MB), which corrupts ISO downloads.
    try { await recordDownload(env, t.filename, t.request, { isFull, rangeOffset, size: obj.size }); } catch (e) {}
    return new Response(obj.body, { status, headers });
  }
  return new Response(obj.body, { status, headers });
}

// ---------- Security headers (parity with the main shadowfetch-home worker) ----------
// The only external script is Cloudflare's cookie-free analytics beacon.
// Styles remain inline and images are same-origin under /linux/assets/.
const SEC_HEADERS = {
  "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "strict-origin-when-cross-origin",
  "permissions-policy": "geolocation=(), microphone=(), camera=()",
  "content-security-policy": "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src https://static.cloudflareinsights.com; font-src 'self'; connect-src 'self' https://cloudflareinsights.com https://static.cloudflareinsights.com; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'",
};
function applySec(h) { for (const k in SEC_HEADERS) h.set(k, SEC_HEADERS[k]); return h; }

function baseHeaders(obj, opts) {
  const h = new Headers();
  h.set("accept-ranges", "bytes");
  if (obj.httpEtag) h.set("etag", obj.httpEtag);
  if (obj.size != null) h.set("content-length", String(obj.size));
  const ct = guessContentType(obj.key || "");
  h.set("content-type", ct);
  if (opts.download) {
    const filename = (obj.key || "download").split("/").pop();
    h.set("content-disposition", `attachment; filename="${filename}"`);
  }
  // Encourage CDN caching of large immutable artifacts
  if (/\.iso$|\.deb$|\.tar\.|\.gpg$|\.asc$/.test(obj.key || "")) {
    h.set("cache-control", "public, max-age=86400, immutable");
  } else {
    h.set("cache-control", "public, max-age=300");
  }
  applySec(h);
  return h;
}

function guessContentType(key) {
  if (key.endsWith(".iso"))   return "application/x-iso9660-image";
  if (key.endsWith(".sha256")) return "text/plain; charset=utf-8";
  if (key.endsWith(".asc"))   return "application/pgp-signature";
  if (key.endsWith(".gpg"))   return "application/pgp-keys";
  if (key.endsWith(".deb"))   return "application/vnd.debian.binary-package";
  if (key.endsWith(".gz"))    return "application/gzip";
  if (key.endsWith(".xz"))    return "application/x-xz";
  if (key.endsWith(".html"))  return "text/html; charset=utf-8";
  if (key.endsWith(".txt") || key.endsWith("Release") || key.endsWith("InRelease") || key.endsWith("Packages")) {
    return "text/plain; charset=utf-8";
  }
  if (key.endsWith(".png"))   return "image/png";
  if (key.endsWith(".jpg") || key.endsWith(".jpeg")) return "image/jpeg";
  if (key.endsWith(".webp"))  return "image/webp";
  if (key.endsWith(".svg"))   return "image/svg+xml";
  if (key.endsWith(".ico"))   return "image/x-icon";
  if (key.endsWith(".css"))   return "text/css; charset=utf-8";
  if (key.endsWith(".js"))    return "application/javascript; charset=utf-8";
  if (key.endsWith(".json"))  return "application/json; charset=utf-8";
  return "application/octet-stream";
}

function notFound() {
  return html(notFoundPage(), 404);
}

/**
 * Historical ISO body URLs are kept permanent with an explicit HTTP 410 page,
 * not a silent redirect. The maintainer chose the superseded/410 treatment for retired
 * direct image links on 2026-07-27: show the version-specific Internet Archive
 * copy and the current /linux/download page, while avoiding old active-bucket
 * bytes or a redirect to a differently named Shadowfetch ISO.
 *
 * Sidecars are intentionally not listed here: users who already hold an old
 * image still need the exact checksum/signature for verification.
 */
const SUPERSEDED_ISOS = new Map([
  ["shadowfetch-1.0.1-amd64.iso", "https://archive.org/download/shadowfetch-linux-1-0-1/shadowfetch-1.0.1-amd64.iso"],
  ["shadowfetch-1.5.0-amd64.iso", "https://archive.org/download/shadowfetch-linux-1-5-0/shadowfetch-1.5.0-amd64.iso"],
  ["shadowfetch-1.8.1-amd64.iso", "https://archive.org/download/shadowfetch-linux-1-8-1/shadowfetch-1.8.1-amd64.iso"],
  ["shadowfetch-1.9.0-amd64.iso", "https://archive.org/download/shadowfetch-linux-1-9-0/shadowfetch-1.9.0-amd64.iso"],
  ["shadowfetch-2.0.1-amd64.iso", "https://archive.org/download/shadowfetch-linux-2-0-1/shadowfetch-2.0.1-amd64.iso"],
  ["shadowfetch-2.1.0-amd64.iso", "https://archive.org/download/shadowfetch-linux-2-1-0/shadowfetch-2.1.0-amd64.iso"],
  ["shadowfetch-2.1.1-amd64.iso", "https://archive.org/download/shadowfetch-linux-2-1-1/shadowfetch-2.1.1-amd64.iso"],
  ["shadowfetch-2.1.2-amd64.iso", "https://archive.org/download/shadowfetch-linux-2-1-2/shadowfetch-2.1.2-amd64.iso"],
]);

function superseded(filename, currentRelease = null) {
  const archiveUrl = SUPERSEDED_ISOS.get(filename);
  const version = versionOf(filename) || filename;
  const currentVersion = versionOf(currentRelease && currentRelease.filename) || "current";
  const body = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${filename} is superseded — Shadowfetch Linux</title>
<style>
 body{margin:0;background:#12110f;color:#e9e6df;
      font:16px/1.6 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
 main{max-width:44rem;margin:0 auto;padding:3.5rem 1.5rem}
 h1{font-size:1.6rem;line-height:1.25;margin:0 0 1rem}
 a{color:#D8A24A} code{background:#1e1c19;padding:.15em .4em;border-radius:4px;
   font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;overflow-wrap:anywhere}
 .notice{border-left:2px solid #D8A24A;padding:.6rem 0 .6rem 1rem;margin:1.5rem 0;color:#c3bdb2}
 .cta{display:inline-block;margin:1.4rem 0;padding:.7rem 1.4rem;background:#D8A24A;
      color:#12110f;font-weight:700;text-decoration:none;border-radius:6px}
 footer{margin-top:2.5rem;padding-top:1rem;border-top:1px solid #2a2823;
        color:#8d8779;font-size:.85rem}
</style></head><body><main>
<h1>This Shadowfetch Linux image is superseded</h1>
<p><code>${filename}</code> is a historical ${version} ISO and is no longer served from the active download bucket.</p>
<div class="notice">
<p>We keep retired versioned links explicit instead of silently redirecting them to a different ISO. That protects checksum expectations and tells you exactly which image you asked for.</p>
</div>
<p><a class="cta" href="/linux/download">Get the current Shadowfetch Linux release${currentVersion === "current" ? "" : ` (${currentVersion})`}</a></p>
<p>If you genuinely need the historical ${version} image, use its preserved Internet Archive copy:<br>
<a href="${archiveUrl}">${archiveUrl}</a></p>
<p>If you already downloaded this image, verify it against the matching sidecars when available:
<a href="/linux/download/${filename}.sha256">.sha256</a> ·
<a href="/linux/download/${filename}.asc">.asc</a> ·
<a href="/linux/verify">how to verify</a></p>
<footer>HTTP 410 Gone · superseded image · current release page: <a href="/linux/download">/linux/download</a></footer>
</main></body></html>`;
  return new Response(body, {
    status: 410,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "public, max-age=900",
      "x-shadowfetch-superseded-iso": filename,
      "link": `<${archiveUrl}>; rel="archives", </linux/download>; rel="successor-version"`,
    },
  });
}

/**
 * Images withdrawn from active service by board decision. The value is the
 * decision id, so the reason for any 410 here is traceable to the record that
 * ordered it rather than to somebody's memory. Prefer SUPERSEDED_ISOS for retired
 * historical body URLs that have a verified archive.org copy.
 */
const WITHDRAWN = new Map([
  // Board decision 20260724-5b83 withdrew only the 2.0.0 ISO body.
  // Do not list its .sha256 or .asc sidecars here; those must continue to
  // stream from R2 so already-downloaded copies remain verifiable.
  ["shadowfetch-2.0.0-amd64.iso", "20260724-5b83"],
]);

/**
 * A 410 that is actually useful to the person who hit it: what happened, what
 * to take instead, and where the original still lives if they genuinely need it.
 */
function withdrawn(filename, currentRelease = null) {
  const decision = WITHDRAWN.get(filename);
  const currentVersion = versionOf(currentRelease && currentRelease.filename) || "current";
  const body = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${filename} has been withdrawn — Shadowfetch Linux</title>
<style>
 body{margin:0;background:#12110f;color:#e9e6df;
      font:16px/1.6 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
 main{max-width:44rem;margin:0 auto;padding:3.5rem 1.5rem}
 h1{font-size:1.6rem;line-height:1.25;margin:0 0 1rem}
 a{color:#D8A24A} code{background:#1e1c19;padding:.15em .4em;border-radius:4px;
   font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;overflow-wrap:anywhere}
 .why{border-left:2px solid #D8A24A;padding:.6rem 0 .6rem 1rem;margin:1.5rem 0;color:#c3bdb2}
 .cta{display:inline-block;margin:1.4rem 0;padding:.7rem 1.4rem;background:#D8A24A;
      color:#12110f;font-weight:700;text-decoration:none;border-radius:6px}
 footer{margin-top:2.5rem;padding-top:1rem;border-top:1px solid #2a2823;
        color:#8d8779;font-size:.85rem}
</style></head><body><main>
<h1>This image has been withdrawn</h1>
<p><code>${filename}</code> is no longer served.</p>
<div class="why">
<p>Its installer overwrote the system's package sources with Debian's
<em>stable</em> template while the system itself tracks <em>testing</em>. The first
time you installed a package, apt could propose removing much of the
preinstalled software, and later failed outright.</p>
<p>2.0.1 fixes that, and four smaller faults.</p>
</div>
<p><a class="cta" href="/linux/download">Get the current Shadowfetch Linux release${currentVersion === "current" ? "" : ` (${currentVersion})`}</a></p>
<p>The checksum and signature for this withdrawn image are still available, so
if you already downloaded it you can still verify what you have:
<a href="/linux/download/${filename}.sha256">.sha256</a> ·
<a href="/linux/download/${filename}.asc">.asc</a> ·
<a href="/linux/verify">how to verify</a></p>
<p>Every release, including this one, is preserved at the
<a href="https://archive.org/details/shadowfetch-linux-2-0-0">Internet Archive</a>
if you need the historical image.</p>
<footer>HTTP 410 Gone · withdrawn by board decision ${decision} ·
<a href="/linux/changelog#v2-0-1">what changed in 2.0.1</a></footer>
</main></body></html>`;
  return new Response(body, {
    status: 410,
    headers: {
      "content-type": "text/html; charset=utf-8",
      // Short cache: a withdrawal should be reversible within an hour if the
      // board changes its mind, not pinned at the edge for a day.
      "cache-control": "public, max-age=900",
      "x-withdrawn-by": decision,
    },
  });
}

function html(body, status = 200) {
  const h = new Headers({
    "content-type": "text/html; charset=utf-8",
    "cache-control": "public, max-age=60",
  });
  h.set("x-shadowfetch-linux-build", SITE_BUILD);
  applySec(h);
  return new Response(body, { status, headers: h });
}

function releaseHeaders(contentType) {
  const headers = new Headers({
    "content-type": contentType,
    "cache-control": "public, max-age=300",
  });
  headers.set("x-shadowfetch-linux-build", SITE_BUILD);
  applySec(headers);
  return headers;
}

function releaseRecord(release) {
  if (!release) return null;
  const version = versionOf(release.filename);
  const date = new Date(release.uploaded).toISOString().slice(0, 10);
  return {
    schema: "shadowfetch.linux-release.v1",
    version,
    codename: "Umbra",
    channel: "stable",
    date,
    architecture: "amd64",
    iso: {
      filename: release.filename,
      url: `https://www.shadowfetch.com/linux/download/${release.filename}`,
      mediaType: "application/x-iso9660-image",
      sizeBytes: release.size,
      sizeLabel: release.sizeHuman,
      sha256: release.sha256,
      hybrid: true,
    },
    signature: release.hasSignature
      ? {
          url: `https://www.shadowfetch.com/linux/download/${release.filename}.asc`,
          type: "openpgp-detached-armored",
        }
      : null,
    signingKey: {
      fingerprint: GPG_FINGERPRINT,
      url: "https://www.shadowfetch.com/linux/shadowfetch.gpg.asc",
    },
    archive: `https://archive.org/details/shadowfetch-linux-${version.replaceAll(".", "-")}`,
    pages: {
      download: "https://www.shadowfetch.com/linux/download",
      verify: "https://www.shadowfetch.com/linux/verify",
      install: "https://www.shadowfetch.com/linux/install",
      changelog: `https://www.shadowfetch.com/linux/changelog#v${version.replaceAll(".", "-")}`,
    },
  };
}

function releaseJson(release) {
  const current = releaseRecord(release);
  const body = {
    schema: "shadowfetch.linux-release-feed.v1",
    product: "Shadowfetch Linux",
    homepage: "https://www.shadowfetch.com/linux",
    self: "https://www.shadowfetch.com/linux/releases.json",
    atom: "https://www.shadowfetch.com/linux/releases.atom.xml",
    latest: current,
    releases: current ? [current] : [],
  };
  return new Response(`${JSON.stringify(body, null, 2)}\n`, {
    status: current ? 200 : 503,
    headers: releaseHeaders("application/json; charset=utf-8"),
  });
}

function releaseAtom(release) {
  const current = releaseRecord(release);
  if (!current) {
    return new Response("Release metadata is temporarily unavailable.\n", {
      status: 503,
      headers: releaseHeaders("text/plain; charset=utf-8"),
    });
  }
  const updated = `${current.date}T00:00:00Z`;
  const title = `Shadowfetch Linux ${current.version} Umbra`;
  const body = `<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <id>https://www.shadowfetch.com/linux/releases.atom.xml</id>
  <title>Shadowfetch Linux releases</title>
  <updated>${updated}</updated>
  <link rel="self" type="application/atom+xml" href="https://www.shadowfetch.com/linux/releases.atom.xml"/>
  <link rel="alternate" type="text/html" href="https://www.shadowfetch.com/linux/changelog"/>
  <entry>
    <id>${current.pages.changelog}</id>
    <title>${escapeHtml(title)}</title>
    <updated>${updated}</updated>
    <link rel="alternate" type="text/html" href="${current.pages.changelog}"/>
    <link rel="enclosure" type="${current.iso.mediaType}" length="${current.iso.sizeBytes}" href="${current.iso.url}"/>
    <category term="stable"/>
    <summary type="text">Current signed Shadowfetch Linux release.</summary>
  </entry>
</feed>
`;
  return new Response(body, {
    headers: releaseHeaders("application/atom+xml; charset=utf-8"),
  });
}

// ---------- Release discovery ----------

async function latestRelease(env) {
  try {
    const list = await env.RELEASES.list({ prefix: "releases/", limit: 100 });
    const isos = list.objects.filter(o => o.key.endsWith(".iso"));
    if (!isos.length) return null;
    isos.sort((a, b) => new Date(b.uploaded) - new Date(a.uploaded));
    const iso = isos[0];
    const base = iso.key.slice("releases/".length);

    // Try to fetch the sha256 alongside (small, ~80 bytes)
    let sha256 = null;
    try {
      const shaObj = await env.RELEASES.get(`releases/${base}.sha256`);
      if (shaObj) {
        const txt = await shaObj.text();
        const m = /([a-f0-9]{64})/i.exec(txt);
        if (m) sha256 = m[1];
      }
    } catch (_) {}

    return {
      filename: base,
      size: iso.size,
      sizeHuman: humanBytes(iso.size),
      uploaded: iso.uploaded,
      sha256,
      hasSignature: list.objects.some(o => o.key === `releases/${base}.asc`),
    };
  } catch {
    return null;
  }
}

function versionOf(filename) {
  const m = /(\d+\.\d+\.\d+)/.exec(filename || "");
  return m ? m[1] : "";
}

function humanBytes(n) {
  if (n == null) return "?";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(n >= 10 ? 0 : 1)} ${u[i]}`;
}

// ---------- HTML pages ----------

const SITE = "https://www.shadowfetch.com";
const OG_IMAGE = SITE + "/linux/assets/sf-logo-nav.png";
const SITE_BUILD = "2026.08.11.1";
const CLOUDFLARE_WEB_ANALYTICS_TOKEN = "1433629b72d147acb61f41a951d81de1";
const DEFAULT_DESC = "Shadowfetch Linux (Umbra) — a private, AI-ready creative workstation built honestly on Debian. KDE Plasma 6, themed in shadow and gold, local AI built in, every creative tool ready out of the box.";

function shell({ title, head = "", body, canonical = "/linux/", description = DEFAULT_DESC, ogImage = OG_IMAGE }) {
  const canonUrl = SITE + canonical;
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${escapeHtml(title)}</title>
<meta name="description" content="${escapeAttr(description)}">
<link rel="canonical" href="${escapeAttr(canonUrl)}">
<meta property="og:type" content="website">
<meta property="og:site_name" content="Shadowfetch Linux">
<meta property="og:title" content="${escapeAttr(title)}">
<meta property="og:description" content="${escapeAttr(description)}">
<meta property="og:url" content="${escapeAttr(canonUrl)}">
<meta property="og:image" content="${escapeAttr(ogImage)}">
<meta name="twitter:card" content="summary">
<meta name="twitter:title" content="${escapeAttr(title)}">
<meta name="twitter:description" content="${escapeAttr(description)}">
<meta name="twitter:image" content="${escapeAttr(ogImage)}">
<meta name="shadowfetch-linux-build" content="${escapeAttr(SITE_BUILD)}">
<style>${styles()}</style>
${head}
</head>
<body>
<a class="skip-link" href="#main-content">Skip to main content</a>
<header class="topbar">
  <a href="/linux/" class="brand">
    <img class="brand-mark" src="/linux/assets/sf-logo-nav.png" alt="" width="32" height="32">
    <span class="wordmark">Shadowfetch <em>Linux</em></span>
  </a>
  <nav class="desktop-nav" aria-label="Primary">
    <a href="/linux/download">Download</a>
    <a href="/linux/install">Install</a>
    <a href="/linux/verify">Verify</a>
    <a href="/linux/hardware">Hardware</a>
    <a href="/linux/security">Security</a>
    <a href="/linux/known-issues">Known issues</a>
    <a href="/linux/roadmap">Roadmap</a>
    <a href="/#apps" class="ghost">App&nbsp;Shelf →</a>
  </nav>
  <details class="mobile-menu">
    <summary>Menu</summary>
    <nav aria-label="Mobile navigation">
      <a href="/linux/download">Download</a>
      <a href="/linux/install">Install</a>
      <a href="/linux/verify">Verify</a>
      <a href="/linux/hardware">Hardware</a>
      <a href="/linux/security">Security</a>
      <a href="/linux/known-issues">Known issues</a>
      <a href="/linux/roadmap">Roadmap</a>
      <a href="/#apps" class="ghost">App&nbsp;Shelf →</a>
    </nav>
  </details>
</header>
<main id="main-content">${body}</main>
<footer>
  <div class="foot-grid">
    <div>
      <strong>Shadowfetch Linux</strong><br>
      A private, AI-ready creative workstation, built on Debian.<br>
      <span class="muted">Part of the <a href="/">Shadowfetch</a> family. Site build ${escapeHtml(SITE_BUILD)}.</span>
    </div>
    <div>
      <strong>Get it</strong><br>
      <a href="/linux/download">ISO download</a><br>
      <a href="/linux/apt/">APT repo</a><br>
      <a href="/linux/shadowfetch.gpg.asc">GPG signing key</a><br>
      <a href="https://archive.org/search?query=shadowfetch%20linux" rel="noreferrer noopener">Internet Archive mirror</a><br>
    </div>
    <div>
      <strong>Learn</strong><br>
      <a href="/linux/install">Install guide</a><br>
      <a href="/linux/verify">Verify release</a><br>
      <a href="/linux/hardware">Hardware notes</a><br>
      <a href="/linux/security">Security model</a><br>
      <a href="/linux/known-issues">Known issues</a><br>
      <a href="/linux/roadmap">Roadmap</a><br>
      <a href="/linux/faq">FAQ</a><br>
      <a href="/linux/changelog">Release notes</a>
    </div>
  </div>
  <p class="muted small">Debian is a registered trademark of Software in the Public Interest, Inc. Shadowfetch Linux is an independent derivative and is not affiliated with or endorsed by the Debian project.</p>
</footer>
<script type="module" src="https://static.cloudflareinsights.com/beacon.min.js" data-cf-beacon='${JSON.stringify({ token: CLOUDFLARE_WEB_ANALYTICS_TOKEN })}'></script>
</body>
</html>`;
}

function landingPage(release) {
  const ver = release ? versionOf(release.filename) : "";
  const dlButton = release
    ? `<a class="btn primary" href="/linux/download/${escapeAttr(release.filename)}">Download ${escapeHtml(release.sizeHuman)} ISO</a>`
    : `<a class="btn primary muted-btn" href="/linux/download">Release status unavailable</a>`;
  const meta = release
    ? `<p class="release-meta">Shadowfetch Linux ${escapeHtml(ver)} "Umbra" · ${escapeHtml(release.filename)} · <a href="/linux/download">checksum + signature</a> · <a href="/linux/changelog#v${escapeAttr(ver.replaceAll(".", "-"))}">What's new in ${escapeHtml(ver)} →</a> · site build ${escapeHtml(SITE_BUILD)}</p>`
    : `<p class="release-meta">Release metadata is temporarily unavailable. Downloads remain withheld until verification data is available.</p>`;

  return shell({
    title: "Shadowfetch Linux — a private, AI-ready creative workstation on Debian",
    canonical: "/linux/",
    body: `
<section class="hero">
  <div class="hero-copy">
    <h1>Shadowfetch Linux</h1>
    <p class="lede">A private, AI-ready creative workstation built honestly on Debian — KDE Plasma 6, themed end to end in shadow and gold, with safe updates, recovery, local AI, and the creative tools you'd otherwise spend a weekend installing already working.</p>
    <div class="cta-row">
      ${dlButton}
      <a class="btn ghost" href="/linux/install">Install guide →</a>
    </div>
    ${meta}
  </div>
  <div class="hero-side">
    <figure class="hero-shot">
      <img src="/linux/assets/desktop-umbra.webp" alt="The Shadowfetch Linux Umbra desktop" width="1280" height="800" decoding="async">
    </figure>
  </div>
</section>

<section class="band">
  <h2>See it running</h2>
  <div class="shots">
    <figure class="shot">
      <img src="/linux/assets/desktop-umbra.webp" alt="The Shadowfetch Linux Umbra desktop with the silver emblem wallpaper and KDE Plasma 6 panel" width="1280" height="800" loading="lazy" decoding="async">
      <figcaption>The Umbra desktop</figcaption>
    </figure>
    <figure class="shot">
      <img src="/linux/assets/welcome.webp" alt="The first-boot Welcome to Shadowfetch Linux Umbra app on the desktop" width="1280" height="800" loading="lazy" decoding="async">
      <figcaption>First-boot welcome</figcaption>
    </figure>
    <figure class="shot">
      <img src="/linux/assets/apps-menu.webp" alt="The KDE Plasma application launcher showing app categories: Development, Graphics, Office, Multimedia and more" width="1280" height="800" loading="lazy" decoding="async">
      <figcaption>Application menu</figcaption>
    </figure>
    <figure class="shot">
      <img src="/linux/assets/terminal.webp" alt="A Konsole terminal running fastfetch on Shadowfetch Linux Umbra with KDE Plasma 6" width="1280" height="800" loading="lazy" decoding="async">
      <figcaption>Shadowfetch Linux 1.9.0</figcaption>
    </figure>
  </div>
</section>

<section class="band">
  <h2>What you get out of the box</h2>
  <div class="grid-4">
    <div class="card">
      <h3>Private by default</h3>
      <p>UFW firewall on, MAC-address randomization, hardened sysctl. Your machine, your data.</p>
    </div>
    <div class="card">
      <h3>Private local AI</h3>
      <p>Run a hardware-matched model and local web chat through Ollama without sending prompts or files to a cloud account.</p>
    </div>
    <div class="card">
      <h3>Themed end to end</h3>
      <p>GRUB, boot splash, login, and desktop unified in the Umbra gold-on-graphite look.</p>
    </div>
    <div class="card">
      <h3>Easy to keep healthy</h3>
      <p>The Control Center puts safe updates, plain-language health checks, snapshots, recovery and graphics tools in one place.</p>
    </div>
    <div class="card">
      <h3>2D · Photo</h3>
      <p>GIMP, Krita, Inkscape, Scribus, darktable, RawTherapee, digiKam</p>
    </div>
    <div class="card">
      <h3>Audio · Video</h3>
      <p>Ardour, Audacity, Hydrogen, Kdenlive, Shotcut, OBS Studio, full LV2 plugin set</p>
    </div>
    <div class="card">
      <h3>3D · Color</h3>
      <p>Blender, FreeCAD, OpenSCAD, ArgyllCMS, DisplayCAL, colord</p>
    </div>
    <div class="card">
      <h3>Bring your browser with you</h3>
      <p>The Browser Migration assistant validates bookmark and password exports, stages them privately, and handles temporary Flatpak access for Brave.</p>
    </div>
  </div>
</section>

<section class="band">
  <h2>Local AI without the model maze</h2>
  <p class="lede">Choose one model that fits the computer, keep it on the device, and use it through a familiar local chat interface.</p>
  <div class="grid-4">
    <div class="card">
      <h3>Hardware-aware setup</h3>
      <p>The model picker checks memory, graphics hardware and disk space before recommending a download.</p>
    </div>
    <div class="card">
      <h3>Local by default</h3>
      <p>Ollama listens on localhost and the firewall blocks its model port from the network.</p>
    </div>
    <div class="card">
      <h3>One clear starting point</h3>
      <p>Run one recommended on-device model and local web chat with <code>shadowfetch-ai</code>. The wider model catalog stays available as an advanced option.</p>
    </div>
    <div class="card">
      <h3>Your choice remains yours</h3>
      <p>Skip local AI during setup, remove it later, or replace the recommended model whenever your needs change.</p>
    </div>
  </div>
</section>

<section class="band alt">
  <h2>Built honestly on Debian</h2>
  <div class="two-col">
    <div>
      <p>Shadowfetch is a Debian-testing derivative. Security updates and 99% of the package archive come straight from upstream Debian. We layer on top — a curated stack, the Umbra theme, a graphical installer, a first-boot wizard, private-by-default networking, and a one-command local-AI stack — and that's it. We don't fork anything we don't have to.</p>
      <p>If you've used Debian, you already know how to use Shadowfetch. <code>apt</code> works. <code>dpkg</code> works. Everything you can install on Debian, you can install here.</p>
    </div>
    <div>
      <h4>System requirements</h4>
      <ul>
        <li>64-bit x86 CPU (Intel or AMD)</li>
        <li>4 GB RAM minimum, 8 GB+ recommended</li>
        <li>40 GB disk minimum, 100 GB+ recommended</li>
        <li>UEFI or legacy BIOS boot</li>
        <li>NVIDIA, AMD, or Intel GPU (NVIDIA gets the proprietary stack out of the box)</li>
      </ul>
    </div>
  </div>
</section>
`,
  });
}

function downloadPage(release) {
  const hasRelease = !!release;
  const dl = release ? `/linux/download/${escapeAttr(release.filename)}` : "#";
  const shaLine = release && release.sha256
    ? `<code>${escapeHtml(release.sha256)}  ${escapeHtml(release.filename)}</code>`
    : `<span class="muted">Release checksum is temporarily unavailable.</span>`;

  return shell({
    title: "Download — Shadowfetch Linux",
    canonical: "/linux/download",
    description: "Download Shadowfetch Linux (Umbra) — the latest signed amd64 ISO, with SHA-256 checksum and GPG signature. A private, AI-ready KDE Plasma 6 creative workstation on Debian.",
    body: `
<section class="narrow">
  <h1>Download Shadowfetch Linux</h1>
  ${hasRelease
    ? `<p class="lede">${escapeHtml(versionOf(release.filename))} "Umbra" — built ${escapeHtml(formatDate(release.uploaded))}. ${escapeHtml(release.sizeHuman)}, amd64, hybrid ISO (BIOS + UEFI). <a href="/linux/changelog#v${escapeAttr(versionOf(release.filename).replaceAll(".", "-"))}">What's new in ${escapeHtml(versionOf(release.filename))} →</a></p>`
    : `<p class="lede">Release metadata is temporarily unavailable. Shadowfetch does not show an ISO download until its checksum and signature can be confirmed.</p>`}

  <div class="dl-card ${hasRelease ? "" : "disabled"}">
    <div>
      <div class="dl-name">${hasRelease ? escapeHtml(release.filename) : "Release unavailable"}</div>
      <div class="dl-meta">${hasRelease ? escapeHtml(release.sizeHuman) + " · amd64 · hybrid ISO" : "Download withheld pending verification metadata"}</div>
    </div>
    <a class="btn primary" href="${dl}" ${hasRelease ? "" : 'aria-disabled="true"'}>${hasRelease ? "Download ISO" : "Unavailable"}</a>
  </div>

  <h2>Verify your download</h2>
  <p>Every release is checksummed and signed with the Shadowfetch GPG key.</p>
  <h4>SHA-256</h4>
  <pre class="kv">${shaLine}</pre>
  <h4>GPG signing key</h4>
  <p>Fingerprint: <code>${GPG_FINGERPRINT}</code></p>
  <p><a class="btn ghost" href="/linux/shadowfetch.gpg.asc">Download public key (.asc)</a> <a class="btn ghost" href="/linux/verify">Full verification guide (Linux · macOS · Windows) →</a></p>
  <p class="muted small">Verify on Linux/macOS with:<br>
  <code>gpg --import shadowfetch.gpg.asc</code><br>
  <code>gpg --verify ${hasRelease ? escapeHtml(release.filename) : "shadowfetch-*.iso"}.asc</code><br>
  <code>shasum -a 256 ${hasRelease ? escapeHtml(release.filename) : "shadowfetch-*.iso"}</code></p>

  <h2>Write the ISO to a USB stick</h2>
  <p>You need an 8&nbsp;GB or larger USB stick &mdash; writing the ISO <strong>erases everything on it</strong>, so back up anything you want to keep first. The easiest, hardest-to-get-wrong way is a graphical writer:</p>
  <ul>
    <li><strong><a href="https://etcher.balena.io/" rel="noreferrer noopener">balenaEtcher</a></strong> (Windows, macOS, Linux) &mdash; the simplest cross-platform option. Pick the ISO, pick the USB drive, click <em>Flash</em>. It validates the write for you.</li>
    <li><strong>KDE ISO Image Writer</strong> &mdash; built right into Shadowfetch and KDE Plasma (search "ISO Image Writer" in the menu). Choose the ISO and the target USB, write.</li>
    <li><strong>GNOME Disks</strong> (on GNOME systems) &mdash; open the USB device, use the menu's <em>Restore Disk Image…</em>, and select the ISO.</li>
  </ul>
  <p class="muted small">Whichever tool you use, double-check you selected the <strong>USB stick</strong> and not an internal drive before you write.</p>

  <details class="adv-callout">
    <summary>Advanced: write from the command line with <code>dd</code></summary>
    <p>If you prefer the terminal on macOS or Linux, <code>dd</code> works &mdash; but it has no undo and no confirmation.</p>
    <pre><code>sudo dd if=${hasRelease ? escapeHtml(release.filename) : "shadowfetch-*.iso"} of=/dev/sdX bs=4M status=progress conv=fdatasync</code></pre>
    <p><strong>Replace <code>/dev/sdX</code> with your USB stick's device</strong> (find it with <code>lsblk</code> on Linux or <code>diskutil list</code> on macOS). Get this wrong and <code>dd</code> will silently overwrite whatever disk you point it at &mdash; including the one you booted from. There is no warning and no recovery. If you are not certain which device is the USB stick, use a graphical writer above instead.</p>
  </details>

  <p><a class="btn ghost" href="/linux/install">Next: install guide →</a></p>
</section>
`,
  });
}

function installPage(release) {
  const fn = release?.filename || "shadowfetch-*.iso";
  return shell({
    title: "Install — Shadowfetch Linux",
    canonical: "/linux/install",
    description: "Install Shadowfetch Linux in about 15 minutes: write the ISO to USB (balenaEtcher / KDE ISO Image Writer), boot, and click through the Calamares installer.",
    body: `
<section class="narrow">
  <h1>Installing Shadowfetch Linux</h1>
  <p class="lede">It's the standard Debian live-install experience — boot the ISO, click through Calamares, reboot. About 15 minutes start to finish.</p>

  <ol class="steps">
    <li>
      <h3>Boot from the USB stick</h3>
      <p>Plug in the USB, power on, hit your system's boot-menu key (usually <kbd>F12</kbd>, <kbd>F11</kbd>, <kbd>F2</kbd>, or <kbd>Del</kbd>), select the USB device. You'll land in a live session — you can try Shadowfetch before installing.</p>
      <p class="muted small"><strong>Secure Boot:</strong> the Shadowfetch ISO isn't Secure-Boot-signed yet. If the USB doesn't appear in the boot menu or refuses to boot, enter your firmware (UEFI) setup and <strong>disable Secure Boot</strong> first.</p>
    </li>
    <li>
      <h3>Launch the installer</h3>
      <p>From the desktop, double-click <strong>"Install Shadowfetch Linux"</strong> (or run <code>calamares</code> from a terminal). Calamares walks you through region, keyboard, partitioning, user account, and a final summary.</p>
    </li>
    <li>
      <h3>Partition</h3>
      <p>For most users, pick "Erase disk" with default options. If you're dual-booting, use "Manual partitioning" and shrink an existing partition. Shadowfetch defaults to ext4; pick btrfs if you want snapshots. To encrypt the whole disk, tick <strong>"Encrypt system"</strong> and set a strong passphrase — you'll enter it at every boot (it's LUKS; the keyboard at the unlock prompt uses your installer keyboard layout).</p>
    </li>
    <li>
      <h3>Wait ~10 minutes</h3>
      <p>The installer copies the live system to disk, installs the bootloader (GRUB), and configures your user. Make a coffee.</p>
    </li>
    <li>
      <h3>Reboot into your installed system</h3>
      <p>Remove the USB when prompted, boot back up. On first login the <strong>Shadowfetch Welcome</strong> wizard runs — pick your accent colour, optionally install curated Flatpak apps, and choose the recommended one-model local AI setup. A Browser Migration assistant validates bookmark and password exports before import.</p>
    </li>
  </ol>

  <h2>First-boot notes</h2>
  <ul>
    <li><strong>NVIDIA:</strong> If your system has an NVIDIA GPU, the proprietary driver is already installed. If not, a first-boot service detects this and removes the NVIDIA stack to reclaim ~2 GB.</li>
    <li><strong>Multi-GPU laptops:</strong> PRIME is set to on-demand mode automatically. Run apps with <code>__NV_PRIME_RENDER_OFFLOAD=1 __GLX_VENDOR_LIBRARY_NAME=nvidia &lt;app&gt;</code> to use the discrete GPU.</li>
    <li><strong>Updates:</strong> Run <code>sudo apt update && sudo apt upgrade</code>, or use Discover (KDE's app/update store). Shadowfetch updates flow from <code>https://www.shadowfetch.com/linux/apt/</code>; Debian updates flow from the usual mirrors.</li>
    <li><strong>Flathub:</strong> Pre-configured. Open Discover, search, install — works.</li>
  </ul>

  <h2>Add the Shadowfetch APT repo to an existing Debian system</h2>
  <p>If you already run Debian and just want the Shadowfetch metapackages without reinstalling, you can pull them via apt:</p>
  <pre><code>curl -fsSL https://www.shadowfetch.com/linux/apt/shadowfetch.gpg.asc \\
  | sudo gpg --dearmor -o /etc/apt/keyrings/shadowfetch.gpg

echo "deb [signed-by=/etc/apt/keyrings/shadowfetch.gpg] https://www.shadowfetch.com/linux/apt/ umbra main" \\
  | sudo tee /etc/apt/sources.list.d/shadowfetch.list

sudo apt update
sudo apt install shadowfetch-desktop      # full creative workstation
# or pick à la carte:
sudo apt install shadowfetch-themes shadowfetch-defaults
sudo apt install shadowfetch-creative-base</code></pre>
</section>
`,
  });
}

function docsIndex() {
  return shell({
    title: "Docs — Shadowfetch Linux",
    canonical: "/linux/docs",
    body: `
<section class="narrow">
  <h1>Documentation</h1>
  <p class="lede">Docs are still being written. Here's what's solid today:</p>
  <ul>
    <li><a href="/linux/install">Installation guide</a> — get Shadowfetch onto a machine</li>
    <li><a href="/linux/download">Download &amp; verify</a> — checksums, signatures, USB writing</li>
    <li><a href="/linux/verify">Verification guide</a> — SHA-256, GPG signature, and signing key</li>
    <li><a href="/linux/hardware">Hardware notes</a> — requirements, NVIDIA, Wi-Fi, VMs, and Secure Boot</li>
    <li><a href="/linux/security">Security model</a> — what Shadowfetch changes, inherits, and does not claim</li>
    <li><a href="/linux/known-issues">Known issues</a> — current caveats before you install</li>
    <li><a href="/linux/roadmap">Roadmap</a> — what is planned next, labeled as roadmap</li>
    <li><a href="/linux/faq">FAQ</a> — direct answers for reviewers and testers</li>
    <li><a href="/linux/changelog">Changelog</a> — what's in each release</li>
  </ul>
  <p>These guides cover installation, daily operation, verification, hardware support, recovery, updates, and private local AI setup. Each page separates current behavior from planned work.</p>
</section>
`,
  });
}

function changelogPage() {
  return shell({
    title: "Changelog — Shadowfetch Linux",
    canonical: "/linux/changelog",
    description: "Release notes for Shadowfetch Linux — what changed in each version, newest first.",
    body: `
<section class="narrow">
  <h1>Changelog</h1>

  <article class="release">
    <h2>1.9.0 "Umbra" <span class="muted">&mdash; 2026-07-12 &middot; Command Center</span></h2>
    <ul>
      <li><strong>One calm place to manage the system.</strong> The new Shadowfetch Control Center brings safe updates, system health, first-run setup, graphics, snapshots, and recovery together without burying people in settings panels.</li>
      <li><strong>Updates with a safety net.</strong> Safe Update checks power, disk space, network reachability, package locks and package consistency first, creates Btrfs pre/post snapshots when available, logs the complete run, and finishes with a health report.</li>
      <li><strong>Diagnostics in two useful formats.</strong> System Health provides a clear terminal report or structured JSON covering storage, memory, load, failed services, package state and update access.</li>
      <li><strong>Safer browser migration.</strong> A new assistant validates bookmark HTML and password CSV exports, copies them into a private staging folder, and gives a Flatpak browser temporary read-only access only to that folder.</li>
      <li><strong>Local AI without the model maze.</strong> The recommended path now installs one model suited to the computer and sets up the local web chat by default. The wider model catalog is still available as an explicitly advanced choice.</li>
      <li><strong>Validated on the Linux build host.</strong> Package, live-boot, feature, CPU, memory, filesystem and random-I/O tests are run against the release image before publication.</li>
    </ul>
  </article>

  <article class="release">
    <h2>1.8.1 "Umbra" <span class="muted">&mdash; 2026-07-09 &middot; Setup + Agent Refresh</span></h2>
    <ul>
      <li><strong>Full system refresh.</strong> Rebuilt against the current Debian testing archive with the 1.8.1 package set published in the Shadowfetch APT repo: desktop, creative base, NVIDIA helper, welcome app, themes, defaults, and branding.</li>
      <li><strong>A smoother first setup.</strong> The welcome wizard now includes role presets for Creative, Developer, Gaming, Office, Local AI, and Maker workflows, with clearer app choices and a larger, crisper layout.</li>
      <li><strong>Stress-tested before release.</strong> The ISO passed a KVM boot and mixed CPU, memory, filesystem, and random disk I/O stress test with no failed services after the run.</li>
    </ul>
  </article>

  <article class="release">
    <h2>1.8.0 "Umbra" <span class="muted">&mdash; 2026-06-26 &middot; Ready on First Boot</span></h2>
    <ul>
      <li><strong>The apps a new user reaches for first, already installed.</strong> <strong>LibreOffice</strong> (documents, spreadsheets, slides), <strong>Thunderbird</strong> (email and calendar), <strong>kamoso</strong> (webcam photos and video), and <strong>ISO Image Writer</strong> (make your next bootable USB straight from the desktop) now ship on the live image &mdash; no first-run download, no hunting through a store.</li>
      <li><strong>A Shadowfetch identity on the desktop.</strong> A new Shadowfetch emblem wallpaper sets the default desktop, so the gold-on-graphite Umbra look now carries all the way from GRUB and the boot splash through login to a branded desktop.</li>
      <li><strong>Signed, and the signature matches.</strong> The release is GPG-signed with the Shadowfetch key, and the published SHA-256 is the checksum of the exact ISO that was built &mdash; <a href="/linux/verify">verify it yourself</a> in a couple of commands before installing.</li>
      <li><strong>Latest Debian packages.</strong> Rebuilt against the current Debian testing archive, so the base system, KDE Plasma 6 and the creative stack all come up to date.</li>
    </ul>
  </article>

  <article class="release">
    <h2>1.6.0 "Umbra" <span class="muted">&mdash; 2026-06</span></h2>
    <ul>
      <li><strong>Media, ready on first boot.</strong> Haruna video player, Elisa music library, Kasts podcasts, screenshots, CD ripping in the file manager, MKVToolNix and tagging tools join VLC and mpv &mdash; with hardware video decoding on by default and every common format correctly associated.</li>
      <li><strong>A visual identity from power-on.</strong> Five new premium Umbra wallpapers in 4K and ultrawide with live preview in the welcome app, refreshed boot art so GRUB, the splash screen, login and desktop share one continuous look, and a branded avatar and terminal.</li>
      <li><strong>Quietly more stable.</strong> Snapshot cleanup runs automatically, defaults were audited and corrected, and the whole release was install-tested on both UEFI and BIOS before publishing.</li>
    </ul>
  </article>

  <article class="release">
    <h2>1.5.0 "Umbra" <span class="muted">&mdash; 2026-06</span></h2>
    <ul>
      <li><strong>Built for creators and builders.</strong> A full creator audio stack now ships out of the box - EasyEffects for live mic cleanup, EQ and noise-suppression, plus the pipewire-jack pro-audio bridge alongside Ardour, Audacity, OBS and Kdenlive.</li>
      <li><strong>A real maker toolbox.</strong> A new "Maker &amp; hardware" one-click category adds OrcaSlicer, PrusaSlicer, FreeCAD, KiCad and the Arduino IDE - the full design to slice to print to flash pipeline - and developers gain shellcheck, valgrind, direnv, hyperfine, yq, the docker CLI over podman, OpenSSH, and one-click editors like Zed and Ghostty.</li>
      <li><strong>Smoother and more correct.</strong> A full stress-test-and-fix pass: faster boot, a corrected power-management setup, MS-compatible document fonts, and a fixed system identity on installed machines.</li>
    </ul>
  </article>

  <article class="release">
    <h2>1.4.0 "Umbra" <span class="muted">&mdash; 2026-06</span></h2>
    <ul>
      <li><strong>A premium desktop, out of the box.</strong> A redesigned floating dock puts your apps &mdash; including the creative suite of Krita, GIMP, Calibre and Shotcut &mdash; front and centre, alongside refined window styling, smoother, tasteful animations and crisp Inter typography throughout.</li>
      <li><strong>A calmer, designed look.</strong> A new Umbra wallpaper &mdash; deep graphite with a soft gold glow &mdash; now flows seamlessly from boot splash to login to lock screen to desktop, for one cohesive, high-end feel.</li>
      <li><strong>Polished to match.</strong> Flatpak apps now follow the dark theme automatically, a new gold app-menu icon, sharper Wayland defaults, and dozens of small refinements that make the whole system feel considered.</li>
    </ul>
  </article>

  <article class="release">
    <h2>1.3.1 "Umbra" <span class="muted">&mdash; 2026-06</span></h2>
    <ul>
      <li><strong>Game on, out of the box.</strong> Built-in gaming tools (GameMode, MangoHud, vkBasalt) give you better frame rates and overlays from the first boot, and the welcome wizard now installs Steam, Heroic, Lutris and ProtonUp-Qt in one click &mdash; your whole library, Windows games included, ready to play.</li>
      <li><strong>A richer app catalogue.</strong> The first-run app picker is now organised by category with more of what people actually use &mdash; Telegram, Element, Zoom, Jellyfin, Plex, Joplin, Cryptomator, DBeaver and more &mdash; plus baked-in favourites like btop, Calibre, KeePassXC and a one-click Vorta backup.</li>
      <li><strong>Smarter graphics setup.</strong> The one-click GPU helper now recognises brand-new cards and avoids installing a driver that cannot support them yet.</li>
    </ul>
  </article>

  <article class="release">
    <h2>1.3.0 "Umbra" <span class="muted">&mdash; 2026-06</span></h2>
    <ul>
      <li><strong>One-click graphics drivers.</strong> A new GPU setup tool detects your card and installs the right driver for you &mdash; NVIDIA proprietary or open, with the correct branch, repositories and Secure-Boot handling done automatically. AMD and Intel just work out of the box, with the full Mesa, Vulkan and hardware video-acceleration stack now baked in.</li>
      <li><strong>Wi-Fi that just connects.</strong> Much broader wireless firmware (Intel, Realtek, MediaTek, Broadcom, Atheros, Marvell and more) plus fixes for the classic Linux Wi-Fi headaches &mdash; no more random drops after suspend, correct regulatory channels, and reliable Bluetooth on combo cards.</li>
      <li><strong>Streamlined onboarding.</strong> A single, crisp first-run wizard walks you from Wi-Fi &rarr; graphics drivers &rarr; look &amp; feel &rarr; apps &rarr; local AI in a few clicks.</li>
      <li><strong>Crisp, professional desktop.</strong> A refined gold cursor, sharper fonts and sensible &ldquo;made for work&rdquo; defaults throughout.</li>
    </ul>
  </article>

  <article class="release">
    <h2>1.2.10 "Umbra" <span class="muted">&mdash; 2026-06</span></h2>
    <ul>
      <li><strong>Installs on everything.</strong> The installer now writes a universal boot layout that works on both modern UEFI systems and older legacy-BIOS machines &mdash; Shadowfetch sets up cleanly on hardware spanning more than a decade, with the same Btrfs snapshots and one-click rollback on either firmware.</li>
      <li><strong>Hardened partitioning.</strong> A dedicated BIOS-boot partition plus a tidy ESP and Btrfs root make the bootloader install rock-solid on both firmware types.</li>
    </ul>
  </article>

  <article class="release">
    <h2>1.2.9 "Umbra" <span class="muted">&mdash; 2026-06</span></h2>
    <ul>
      <li><strong>Snapshots &amp; rollback.</strong> Fresh installs now use Btrfs by default and automatically snapshot your system before and after every update. If something breaks, roll back in seconds with the built-in Btrfs Assistant &mdash; your desktop is self-healing.</li>
      <li><strong>Installer hardening.</strong> Rock-solid UEFI boot setup (firmware-agnostic fallback bootloader) and a cleaner, de-duplicated installer welcome screen.</li>
    </ul>
  </article>

  <article class="release">
    <h2>1.2.8 "Umbra" <span class="muted">&mdash; 2026-06</span></h2>
    <ul>
      <li><strong>Local-AI polish.</strong> The Hugging Face model picker now checks your free disk space and warns before downloading a model that will not fit, and first-boot setup runs your chosen AI steps in one terminal so Ollama is only ever installed once. Both came straight out of the 1.2.7 release stress test.</li>
      <li><strong>Cleaner first boot.</strong> Fixed a harmless but alarming &ldquo;degraded&rdquo; status that some fresh installs showed on the very first boot (caused by the background firmware-metadata refresh running before the network was fully ready). Your system now reports a clean &ldquo;running&rdquo; state from the start.</li>
    </ul>
  </article>

  <article class="release">
    <h2>1.2.7 "Umbra" <span class="muted">&mdash; 2026-05</span></h2>
    <ul>
      <li><strong>Pick a model that fits.</strong> A new hardware-aware picker matches the computer to a <strong>Hugging Face</strong> model it can actually run: it detects RAM and graphics hardware, recommends a fitting GGUF, and runs it locally through Ollama. Advanced users can also enter another compatible repository.</li>
    </ul>
  </article>

  <article class="release">
    <h2>1.2.6 "Umbra" <span class="muted">&mdash; 2026-05</span></h2>
    <ul>
      <li><strong>More apps out of the box.</strong> The image now bundles everyday tools &mdash; <code>mpv</code>, <code>yt-dlp</code>, Syncthing, qBittorrent, PDF&nbsp;Arranger, Node.js, and a font manager &mdash; and the first-boot Welcome wizard adds one-click LibreOffice, OnlyOffice, Thunderbird, Blender, and Obsidian.</li>
    </ul>
  </article>

  <article class="release">
    <h2>1.2.5 "Umbra" <span class="muted">&mdash; 2026-05</span></h2>
    <ul>
      <li><strong>Console polish + diagnostics.</strong> The text-console login banner now reports the correct version (it had been stuck on an old string), and the image ships <code>stress-ng</code> and <code>fio</code> for built-in stress-testing and disk benchmarking.</li>
    </ul>
  </article>

  <article class="release">
    <h2>1.2.4 "Umbra" <span class="muted">&mdash; 2026-05</span></h2>
    <ul>
      <li><strong>Cleaner first boot.</strong> A freshly installed system no longer briefly reports a systemd &ldquo;degraded&rdquo; state. The firmware-metadata refresh (fwupd) now waits for real network connectivity before running instead of racing it at boot, so it stops failing on the first-boot network warm-up. Existing systems pick up the same fix via <code>apt upgrade</code>.</li>
    </ul>
  </article>

  <article class="release">
    <h2>1.2.3 "Umbra" <span class="muted">&mdash; 2026-05</span></h2>
    <ul>
      <li><strong>One-click local AI.</strong> The first-boot Welcome wizard now sets up <code>Ollama</code> with two curated on-device models &mdash; <strong>Gemma&nbsp;3</strong> and <strong>Llama&nbsp;3.2</strong> &mdash; in a single click. Everything runs 100% locally and is hardened to localhost.</li>
      <li>Bundled developer tooling behind the AI on-ramp: <code>python3-pip</code>, <code>python3-venv</code>, and <code>ripgrep</code>.</li>
    </ul>
  </article>

  <article class="release">
    <h2>1.2.2 "Umbra" <span class="muted">— 2026-05</span></h2>
    <ul>
      <li><strong>Working update channel.</strong> Installed systems now fetch Shadowfetch updates from the signed public repo — earlier builds baked in a build-time localhost source that could never reach it, so <code>apt upgrade</code> for Shadowfetch packages now works end to end.</li>
      <li><strong>Security hardening</strong> from a full release stress-test: removed a stale passwordless-sudo leftover from the live user, and masked unused standalone VPN/NFS daemons (openvpn / strongSwan / rpcbind) that were listening by default.</li>
      <li>Per-package licensing declared (MIT for Shadowfetch components, LGPL-2.1+ for the Breeze-derived themes); default console keymap set.</li>
    </ul>
  </article>

  <article class="release">
    <h2>1.2.1 "Umbra" <span class="muted">— 2026-05</span></h2>
    <ul>
      <li>Graphical <strong>Calamares installer</strong>, fully Shadowfetch-branded — install to disk in minutes.</li>
      <li>Reserved-name safety: the installer rejects system names (e.g. <code>shadow</code>) with a clear message instead of failing mid-install.</li>
      <li>Umbra <strong>GRUB theme</strong> on both the live ISO and installed systems — gold-on-graphite, emblem, tagline.</li>
      <li>Refreshed first-boot <strong>Welcome</strong> wizard: gold accent picker, curated Flatpak apps, and one-click local AI setup.</li>
      <li>Clean SDDM login greeter on installed systems; ext4 by default, btrfs + snapshots optional.</li>
    </ul>
  </article>

  <article class="release">
    <h2>1.1.0 <span class="muted">— 2026-05</span></h2>
    <ul>
      <li><strong>Local AI</strong> stack: <code>shadowfetch-ai</code> sets up Ollama + Open-WebUI, 100% on-device, hardened to localhost.</li>
      <li>Additional KDE utilities and quality-of-life tools.</li>
    </ul>
  </article>

  <article class="release">
    <h2>1.0.8 "Polish &amp; Protect" <span class="muted">— 2026-05</span></h2>
    <ul>
      <li><strong>Private by default:</strong> UFW firewall enabled, MAC-address randomization, hardened sysctl and zram.</li>
      <li>First-boot service wires up services, Flathub, and the firewall.</li>
      <li>Quality-of-life fixes driven by community feedback.</li>
    </ul>
  </article>

  <article class="release">
    <h2>1.0.7 "Umbra Identity" <span class="muted">— 2026-05</span></h2>
    <ul>
      <li>The <strong>Umbra</strong> visual identity: a gold-on-graphite theme unified across GRUB, boot splash, login, and desktop.</li>
    </ul>
  </article>

  <article class="release">
    <h2>1.0.0 <span class="muted">— 2026-05</span></h2>
    <ul>
      <li>Initial release of Shadowfetch Linux — KDE Plasma 6 creative workstation on Debian testing.</li>
      <li>Full creative stack: GIMP, Krita, Inkscape, darktable, Ardour, Audacity, Kdenlive, OBS Studio.</li>
      <li>Proprietary NVIDIA driver baked in, auto-removed on non-NVIDIA hardware at first boot.</li>
      <li>PipeWire audio with the full LV2 plugin baseline; APT repo for incremental updates.</li>
    </ul>
  </article>
</section>
`,
  });
}

function verifyPage(release) {
  const filename = release ? release.filename : "shadowfetch-amd64.iso";
  const sha = release && release.sha256 ? release.sha256 : "(published checksum appears here once the ISO is live)";
  return shell({
    title: "Verify Shadowfetch Linux",
    canonical: "/linux/verify",
    description: "Verify your Shadowfetch Linux download: confirm the SHA-256 checksum and the GPG signature on Linux, macOS, or Windows before you install.",
    body: `
<section class="narrow">
  <h1>Verify Shadowfetch Linux</h1>
  <p class="lede">Every public Shadowfetch Linux ISO is shipped with a SHA-256 checksum, a detached GPG signature, and the Shadowfetch signing key. Check those before installing.</p>

  <h2>Why verify?</h2>
  <p>Two quick checks, two different guarantees: the <strong>SHA-256 checksum</strong> proves the file downloaded <strong>intact</strong> (no corruption, no truncated transfer), and the <strong>GPG signature</strong> proves it is <strong>authentic</strong> &mdash; the exact ISO Shadowfetch published, not a tampered copy from a mirror or a bad network. It takes a minute and means you can install with confidence.</p>

  <h2>Current release</h2>
  <p><strong>${escapeHtml(filename)}</strong></p>
  <pre><code>${escapeHtml(sha)}  ${escapeHtml(filename)}</code></pre>

  <h2>Signing key</h2>
  <p>Fingerprint: <code>8F13CE1535EE1F4A2916A1F73C5C900B7BE80CA1</code></p>
  <p><a href="/linux/shadowfetch.gpg.asc">Download the public key</a></p>

  <h2>Verify on Linux or macOS</h2>
  <p>Put the ISO, the <code>.asc</code> signature, and <code>shadowfetch.gpg.asc</code> in the same folder, open a terminal there, and run:</p>
  <pre><code>gpg --import shadowfetch.gpg.asc
gpg --verify ${escapeHtml(filename)}.asc
shasum -a 256 ${escapeHtml(filename)}</code></pre>
  <p>For the <strong>signature</strong>, you want a line that reads:</p>
  <pre><code>gpg: Good signature from "Shadowfetch &lt;...&gt;"</code></pre>
  <div class="callout">
    <strong>A warning here is normal &mdash; not an error.</strong> Right after <em>Good signature</em>, GPG will almost always also print:
    <pre><code>gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.</code></pre>
    That is <strong>expected</strong>. It only means you have not personally marked the Shadowfetch key as trusted in your own keyring &mdash; it does <em>not</em> mean the signature failed. As long as you see <strong>Good signature</strong> and the fingerprint matches <code>8F13&nbsp;CE15&nbsp;35EE&nbsp;1F4A&nbsp;2916&nbsp;A1F7&nbsp;3C5C&nbsp;900B&nbsp;7BE8&nbsp;0CA1</code> above, you are good.
  </div>
  <p>For the <strong>checksum</strong>, the 64-character hash that <code>shasum</code> prints must match the value shown under <em>Current release</em> above. (On most Linux distros the command is <code>sha256sum ${escapeHtml(filename)}</code> instead of <code>shasum -a 256</code>.)</p>

  <h2>Verify on Windows</h2>
  <p>No extra tools needed for the checksum. Open <strong>PowerShell</strong> or <strong>Command Prompt</strong> in the folder with the ISO and run:</p>
  <pre><code>CertUtil -hashfile ${escapeHtml(filename)} SHA256</code></pre>
  <p>Compare the hash it prints to the value under <em>Current release</em> &mdash; they must match (case does not matter).</p>
  <p>To check the <strong>GPG signature</strong> on Windows, install <a href="https://www.gpg4win.org/" rel="noreferrer noopener">Gpg4win</a> (which includes the <strong>Kleopatra</strong> app):</p>
  <ol>
    <li>Open <strong>Kleopatra</strong> &rarr; <em>File &rarr; Import</em> and import <code>shadowfetch.gpg.asc</code> (the signing key).</li>
    <li>Choose <em>File &rarr; Decrypt/Verify Files</em> and select <code>${escapeHtml(filename)}.asc</code> (Kleopatra finds the ISO beside it automatically).</li>
    <li>A green <strong>"Valid signature"</strong> from Shadowfetch is what you want. As on Linux, a note that the key is <em>not certified / not trusted</em> is normal &mdash; verify the fingerprint matches the one above and you are done.</li>
  </ol>

  <h2>What Shadowfetch provides</h2>
  <ul>
    <li>Shadowfetch packages, themes, defaults, Welcome flow, privacy defaults, and local-AI setup.</li>
    <li>A signed APT repository at <code>https://www.shadowfetch.com/linux/apt/</code>.</li>
    <li>Debian testing remains the base package ecosystem. Shadowfetch is independent and not endorsed by Debian.</li>
  </ul>

  <p>Shadowfetch Linux is free, and it stays free &mdash; verifying it costs you nothing extra. If it turns out to be useful to you and you would like to help fund the development time behind it, there is a <a href="/linux/donate">tip jar</a>. It is optional and changes nothing about the ISO you just verified.</p>
</section>
`,
  });
}

function knownIssuesPage() {
  return shell({
    title: "Known issues — Shadowfetch Linux",
    canonical: "/linux/known-issues",
    body: `
<section class="narrow">
  <h1>Known issues</h1>
  <p class="lede">The honest caveats. Shadowfetch Linux is active and installable, but it is still a young Debian-testing derivative.</p>

  <h2>Current known issues</h2>
  <ul>
    <li><strong>Secure Boot is not signed yet.</strong> If the USB does not appear or refuses to boot, disable Secure Boot in firmware before installing.</li>
    <li><strong>Debian testing can move underneath us.</strong> Most packages come from upstream Debian testing, so update behavior can change faster than on Debian stable.</li>
    <li><strong>NVIDIA hardware varies.</strong> The proprietary NVIDIA stack is included and non-NVIDIA systems remove it after first boot, but hybrid laptops and unusual GPUs may still need manual tuning.</li>
    <li><strong>Local AI needs disk/RAM headroom.</strong> The recommended setup selects one model for the machine, but advanced models still require real storage and memory. Check the size before adding another model.</li>
  </ul>

  <h2>Before reporting a bug</h2>
  <ul>
    <li>Record the exact ISO filename and whether the checksum matched.</li>
    <li>Note UEFI vs legacy BIOS, Secure Boot state, CPU/GPU, RAM, and disk layout.</li>
    <li>For install failures, include where Calamares stopped and whether the live session worked.</li>
    <li>Run <code>shadowfetch-health --json</code> and attach the report after removing anything you consider private.</li>
    <li>For browser migration problems, note the source browser, export format, browser package source, and the assistant's validation result. Never attach a password CSV.</li>
  </ul>
</section>
`,
  });
}


function hardwarePage() {
  return shell({
    title: "Hardware notes — Shadowfetch Linux",
    canonical: "/linux/hardware",
    body: `
<section class="narrow">
  <h1>Hardware notes</h1>
  <p class="lede">Shadowfetch Linux targets ordinary 64-bit Intel and AMD PCs. The short version: 8 GB RAM and 100 GB disk is comfortable; 16 GB+ is better if you plan to run local AI models.</p>

  <h2>Recommended system</h2>
  <ul>
    <li><strong>CPU:</strong> 64-bit Intel or AMD processor. Newer multi-core CPUs make local AI, video, and creative workloads much nicer.</li>
    <li><strong>Memory:</strong> 4 GB minimum, 8 GB recommended for the desktop, 16 GB+ recommended for local AI and heavier creative work.</li>
    <li><strong>Storage:</strong> 40 GB minimum, 100 GB+ recommended. Local AI models can consume several GB each.</li>
    <li><strong>Graphics:</strong> Intel and AMD graphics use the normal Mesa stack. NVIDIA setup is an explicit, simulate-first workflow that refuses removals and can create Phoenix Points on Btrfs. Hybrid laptops and physical accelerator performance still need hardware-specific validation.</li>
    <li><strong>Firmware:</strong> UEFI or legacy BIOS. Secure Boot is not signed yet, so disable Secure Boot before booting the ISO.</li>
  </ul>

  <h2>NVIDIA and hybrid laptops</h2>
  <p>NVIDIA is an explicit, simulate-first path. The proprietary stack is not auto-installed and is not included then removed after first boot. The workflow refuses removals and can create Phoenix Points on Btrfs. Hybrid laptops and physical accelerator performance still need hardware-specific validation. After a user-installed NVIDIA driver, PRIME offload is the intended path for discrete-GPU apps.</p>
  <pre><code>__NV_PRIME_RENDER_OFFLOAD=1 __GLX_VENDOR_LIBRARY_NAME=nvidia blender</code></pre>

  <h2>Wi-Fi, Bluetooth, and peripherals</h2>
  <p>Hardware support comes mostly from Debian testing firmware and kernel packages. Intel Wi-Fi is usually uneventful. Some Broadcom, Realtek, fingerprint readers, RGB controllers, and very new Bluetooth chipsets may need follow-up firmware work.</p>

  <h2>Virtual machines</h2>
  <p>Shadowfetch boots in common VMs. Allocate at least 2 CPU cores, 4 GB RAM, and 40 GB disk. Enable 3D acceleration if your hypervisor supports it. Local AI inside a VM is possible, but bare metal is the real target.</p>

  <h2>What to include in hardware reports</h2>
  <ul>
    <li>Exact ISO filename and checksum result.</li>
    <li>Computer model, CPU, GPU, RAM, disk type, and Wi-Fi chipset if known.</li>
    <li>UEFI vs legacy BIOS, Secure Boot state, and whether the live session booted.</li>
    <li>For installer issues, the Calamares step where it failed.</li>
  </ul>
</section>
`,
  });
}

function securityPage() {
  return shell({
    title: "Security model — Shadowfetch Linux",
    canonical: "/linux/security",
    body: `
<section class="narrow">
  <h1>Security model</h1>
  <p class="lede">Shadowfetch Linux is a Debian-testing derivative with a small Shadowfetch layer: branding, defaults, curated packages, local-AI setup, installer polish, and a signed APT repository. We do not claim Debian endorsement, magic anonymity, or enterprise hardening.</p>

  <h2>What is inherited</h2>
  <ul>
    <li>Most packages come directly from Debian testing and its normal security/update flow.</li>
    <li>KDE Plasma, Calamares, PipeWire, Mesa, systemd, apt, dpkg, and core userland follow their upstream projects.</li>
    <li>Debian tooling still works: <code>apt</code>, <code>dpkg</code>, <code>systemctl</code>, and standard logs are intact.</li>
  </ul>

  <h2>What Shadowfetch adds</h2>
  <ul>
    <li>Signed ISO artifacts and a public GPG key for verification.</li>
    <li>A signed APT repository at <code>https://www.shadowfetch.com/linux/apt/</code> for Shadowfetch packages.</li>
    <li>UFW firewall enabled, MAC-address randomization defaults, hardened sysctl settings, zram, theming, Welcome flow, and local-AI setup helpers.</li>
    <li>Local AI is designed to run on your machine through Ollama/Open-WebUI. Model downloads still come from their original model hosts when you choose to download them.</li>
  </ul>

  <h2>What Shadowfetch does not collect</h2>
  <p>The installed OS does not include a Shadowfetch telemetry daemon, account requirement, or background analytics service. The website and download infrastructure may still produce ordinary web/CDN logs at the hosting layer.</p>

  <h2>Current security caveats</h2>
  <ul>
    <li>Secure Boot signing is not available yet.</li>
    <li>Debian testing moves faster than Debian stable; update risk is part of the model.</li>
    <li>The distribution is young. Treat the known-issues page as required reading before installing on a production machine.</li>
  </ul>

  <p><a class="btn ghost" href="/linux/verify">Verify the current release →</a></p>
</section>
`,
  });
}

function roadmapPage(release) {
  const ver = release ? versionOf(release.filename) : "";
  return shell({
    title: "Roadmap — Shadowfetch Linux",
    canonical: "/linux/roadmap",
    body: `
<section class="narrow">
  <h1>Roadmap</h1>
  <p class="lede">This page separates what is shipping from what is planned. Dates are targets, not promises.</p>

  <h2>Now shipping: ${ver ? escapeHtml(ver) + " " : ""}"Umbra"</h2>
  <ul>
    <li>Debian-testing/KDE Plasma 6 creative workstation.</li>
    <li>Calamares installer, Umbra visual identity, signed ISO, signed APT repo.</li>
    <li>Local AI setup through Ollama/Open-WebUI and a hardware-aware model picker.</li>
    <li>Creative app baseline for 2D, photo, video, audio, 3D, documents, and developer work.</li>
    <li>Control Center, preflighted updates, Btrfs-aware recovery, and plain-language system health.</li>
  </ul>

  <h2>Next release focus</h2>
  <ul>
    <li>Hardware-specific health guidance and exportable support bundles.</li>
    <li>More installer and post-install diagnostics that produce better bug reports.</li>
    <li>More hardware notes from real tester installs.</li>
    <li>NVIDIA/hybrid laptop documentation improvements.</li>
    <li>Website trust layer: hardware, security, FAQ, known issues, and verification pages kept current.</li>
  </ul>

  <h2>Near-term targets</h2>
  <ul>
    <li>Reviewer kit with screenshots, press brief, verification commands, hardware notes, and known issues.</li>
    <li>Directory submissions for Linux discovery sites.</li>
    <li>Demo videos showing boot, install, local AI, creative tools, and update path.</li>
    <li>Community feedback loop: collect install reports, update known issues, cut the next ISO from actual problems.</li>
  </ul>

  <h2>Later, after the basics are boring</h2>
  <ul>
    <li>Secure Boot signing path.</li>
    <li>More reproducible build documentation.</li>
    <li>Expanded hardware test matrix.</li>
    <li>Better disaster recovery and rollback guidance.</li>
  </ul>
</section>
`,
  });
}

function faqPage() {
  return shell({
    title: "FAQ — Shadowfetch Linux",
    canonical: "/linux/faq",
    body: `
<section class="narrow">
  <h1>FAQ</h1>

  <h2>Is Shadowfetch Linux just Debian?</h2>
  <p>It is a Debian-testing derivative. Debian provides the base ecosystem; Shadowfetch adds the curated creative workstation layer, Umbra theme, installer defaults, Welcome flow, local-AI setup, privacy defaults, signed ISO, and signed APT repo.</p>

  <h2>Is Shadowfetch affiliated with Debian?</h2>
  <p>No. Shadowfetch Linux is independent and is not endorsed by Debian; it is not affiliated with the Debian project.</p>

  <h2>Who should try it?</h2>
  <p>Creators, developers, AI tinkerers, and Linux users who want a pre-curated KDE workstation with local AI and creative tools ready quickly.</p>

  <h2>Who should wait?</h2>
  <p>Anyone who needs Secure Boot signing, enterprise support, a Debian-stable base, or a zero-surprise production workstation should wait and follow the changelog.</p>

  <h2>Does it support NVIDIA?</h2>
  <p>NVIDIA setup is an explicit, simulate-first workflow that refuses removals and can create Phoenix Points on Btrfs. It is not auto-installed and is not included then removed after first boot. Hybrid laptops and physical accelerator performance still need hardware-specific validation. Read the hardware notes and known issues before installing.</p>

  <h2>Does local AI phone home?</h2>
  <p>The local chat stack is designed to run on your machine. If you download models, those downloads come from the model host you choose. Shadowfetch does not add an account requirement or telemetry daemon to use the OS.</p>

  <h2>How do I verify the ISO?</h2>
  <p>Use the SHA-256 checksum, detached GPG signature, and Shadowfetch public key on the <a href="/linux/verify">verification page</a>.</p>

  <h2>Why keep the App Shelf?</h2>
  <p>The 112 public iPhone and iPad apps are proof that Shadowfetch ships focused tools. The Linux workstation is the front door; the App Shelf is the supporting field kit.</p>
</section>
`,
  });
}

function benchmarksPage() {
  return shell({
    title: "Historical 16GB local LLM benchmark — Shadowfetch Linux",
    canonical: "/linux/benchmarks",
    description: "A dated August 2026 Ollama benchmark on one NVIDIA RTX 5060 Ti: measured tokens per second, VRAM footprint, method, and explicit limits. It is not a Shadowfetch Linux 3.5.0 runtime claim.",
    body: `
<section class="narrow">
  <h1>Historical 16GB local LLM benchmark</h1>
  <p class="lede">Dated August 2026. This is the old RTX 5060 Ti / <code>ollama pull</code> run. It is not a Shadowfetch Linux 3.5.0 runtime claim, and no 3.5.0 benchmark results are published here.</p>

  <h2>What fits your card?</h2>
  <p>Speed is measured on the 16 GB card above. Whether a model fits is mostly its memory footprint, which travels between cards far better than its speed does.</p>

  <h2>The measured ladder</h2>
  <div style="overflow-x:auto">
  <table>
    <thead>
      <tr>
        <th>Model</th>
        <th>Params</th>
        <th>Quant</th>
        <th>VRAM used</th>
        <th>On GPU</th>
        <th>Context</th>
        <th>Generation</th>
        <th>Prompt</th>
        <th>Cold load</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td>Gemma 3 · 1B<br><code>ollama pull gemma3:1b</code></td>
        <td>999.89M</td>
        <td>Q4_K_M</td>
        <td>1.3 GB</td>
        <td>100% GPU</td>
        <td>32768</td>
        <td>263 tok/s</td>
        <td>7931 tok/s</td>
        <td>2.61s</td>
      </tr>
      <tr>
        <td>Qwen2.5 · 3B Instruct<br><code>ollama pull qwen2.5:3b-instruct</code></td>
        <td>3.1B</td>
        <td>Q4_K_M</td>
        <td>3.1 GB</td>
        <td>100% GPU</td>
        <td>32768</td>
        <td>175 tok/s</td>
        <td>9768 tok/s</td>
        <td>2.66s</td>
      </tr>
      <tr>
        <td>Gemma 3 · 4B<br><code>ollama pull gemma3:4b</code></td>
        <td>4.3B</td>
        <td>Q4_K_M</td>
        <td>4.6 GB</td>
        <td>100% GPU</td>
        <td>131072</td>
        <td>120 tok/s</td>
        <td>3697 tok/s</td>
        <td>3.14s</td>
      </tr>
      <tr>
        <td>Llama 3.2 · 3B<br><code>ollama pull llama3.2:3b</code></td>
        <td>3.2B</td>
        <td>Q4_K_M</td>
        <td>4.8 GB</td>
        <td>100% GPU</td>
        <td>131072</td>
        <td>174 tok/s</td>
        <td>8985 tok/s</td>
        <td>2.92s</td>
      </tr>
      <tr>
        <td>Qwen2.5 · 7B Instruct<br><code>ollama pull qwen2.5:7b-instruct</code></td>
        <td>7.6B</td>
        <td>Q4_K_M</td>
        <td>6.3 GB</td>
        <td>100% GPU</td>
        <td>32768</td>
        <td>88 tok/s</td>
        <td>4960 tok/s</td>
        <td>8.55s</td>
      </tr>
      <tr>
        <td>Qwen2.5 · 14B<br><code>ollama pull qwen2.5:14b</code></td>
        <td>14.8B</td>
        <td>Q4_K_M</td>
        <td>13 GB</td>
        <td>100% GPU</td>
        <td>32768</td>
        <td>45 tok/s</td>
        <td>2548 tok/s</td>
        <td>9.97s</td>
      </tr>
    </tbody>
  </table>
  </div>

  <h3>Where to start</h3>
  <ul>
    <li>On a 16 GB card, start with Qwen2.5 · 14B — the largest measured model that fits, at 13 GB and 45 tok/s.</li>
    <li>Want it snappier? Drop to Qwen2.5 · 7B Instruct at 6.3 GB and 88 tok/s — about 2× the generation speed.</li>
    <li>On an 8 GB card, run Llama 3.2 · 3B — 4.8 GB and 174 tok/s.</li>
  </ul>
  <p>For the current release boundary, see local AI and coding agents. Buzz owns current model selection and download after confirmation.</p>

  <h2>How these were measured</h2>
  <ul>
    <li>One NVIDIA GeForce RTX 5060 Ti (16 GB). Generation rate is eval tokens ÷ eval time from the Ollama API, taken as the median of 3 timed runs of 200 tokens after a warm-up.</li>
    <li>VRAM used and “on GPU” are what <code>ollama ps</code> reports for the resident model — the model's real footprint, and whether all of it sits on the GPU or spills to the CPU (which is the moment speed falls off a cliff).</li>
    <li>Params, quantisation and architecture are read from <code>ollama show</code> — the model file's own metadata, not typed by us. Everything shown is Q4_K_M-class weights, the quant most people actually run.</li>
    <li>Speed is specific to this card; your tokens/sec will differ on other hardware. Footprint and fit travel much better — that's why fit is judged by memory, not speed.</li>
  </ul>
</section>
`,
  });
}

function notFoundPage() {
  return shell({
    title: "Not found — Shadowfetch Linux",
    body: `
<section class="narrow center">
  <h1>404</h1>
  <p class="lede">Whatever you were looking for, we don't have it.</p>
  <p><a class="btn primary" href="/linux/">Back to Shadowfetch Linux</a></p>
</section>
`,
  });
}

// ---------- utilities ----------

function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));
}
function escapeAttr(s) { return escapeHtml(s); }
function formatDate(d) {
  if (!d) return "";
  const dt = new Date(d);
  return dt.toISOString().slice(0, 10);
}

// ---------- styles ----------

function styles() {
  return `
:root {
  --bg: #0a0a10;
  --bg-2: #14141d;
  --bg-3: #1a1a23;
  --line: #2a2a35;
  --ink: #e8e8f2;
  --ink-dim: #a0a0b0;
  --ink-mute: #6f6f80;
  --accent: #29b6f6;
  --accent-2: #4fc3f7;
  --accent-warm: #fbbf24;
  --accent-crimson: #dc2626;
  --max: 1100px;
  --radius: 8px;
}
* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; }
body {
  background: var(--bg);
  color: var(--ink);
  font: 16px/1.6 -apple-system, "SF Pro Text", "Segoe UI", Inter, system-ui, sans-serif;
  -webkit-font-smoothing: antialiased;
}
a { color: var(--accent); text-decoration: none; }
a:hover { color: var(--accent-2); text-decoration: underline; }
code, pre, kbd { font-family: "JetBrains Mono", "SF Mono", Menlo, Consolas, monospace; }
code { background: var(--bg-3); padding: 2px 6px; border-radius: 4px; font-size: 0.92em; }
pre {
  background: var(--bg-3);
  border: 1px solid var(--line);
  border-radius: var(--radius);
  padding: 14px 16px;
  overflow-x: auto;
  font-size: 0.92em;
}
pre code { background: transparent; padding: 0; }
kbd {
  background: var(--bg-3); border: 1px solid var(--line); border-bottom-width: 2px;
  padding: 2px 6px; border-radius: 5px; font-size: 0.85em;
}
.muted { color: var(--ink-dim); }
.small { font-size: 0.88em; }
.skip-link {
  position: fixed; left: 12px; top: -48px; z-index: 20;
  background: var(--accent); color: #0a0a10; padding: 8px 12px;
  border-radius: 4px; font-weight: 700;
}
.skip-link:focus { top: 8px; }

/* Top bar */
.topbar {
  position: sticky; top: 0; z-index: 10;
  display: flex; align-items: center; justify-content: space-between;
  padding: 14px 24px;
  background: rgba(10,10,16,0.92);
  border-bottom: 1px solid var(--line);
  backdrop-filter: blur(8px);
}
.brand { display: flex; align-items: center; gap: 10px; font-weight: 700; color: var(--ink); }
.brand:hover { text-decoration: none; color: var(--accent-2); }
.brand-mark { height: 32px; width: 32px; object-fit: contain; display: block; }
.brand .wordmark em { font-style: normal; color: var(--accent); font-weight: 600; }
.topbar nav { display: flex; gap: 18px; flex-wrap: wrap; }
.topbar nav a { color: var(--ink-dim); font-size: 0.95em; }
.topbar nav a:hover { color: var(--ink); text-decoration: none; }
.topbar nav a.ghost { color: var(--ink-mute); }
.mobile-menu { display: none; position: relative; }
.mobile-menu summary {
  cursor: pointer; list-style: none; padding: 6px 10px;
  border: 1px solid var(--line); border-radius: 4px;
  color: var(--ink); font-weight: 700;
}
.mobile-menu summary::-webkit-details-marker { display: none; }
.mobile-menu[open] nav {
  position: absolute; right: 0; top: calc(100% + 8px);
  display: grid; width: min(260px, calc(100vw - 32px));
  gap: 0; padding: 8px;
  background: var(--bg-2); border: 1px solid var(--line);
  border-radius: var(--radius); box-shadow: 0 14px 40px rgba(0,0,0,0.45);
}
.mobile-menu[open] nav a { padding: 8px 10px; }

main { max-width: var(--max); margin: 0 auto; padding: 32px 24px 64px; }

/* Hero */
.hero {
  display: grid; grid-template-columns: 1.4fr 1fr; gap: 40px;
  align-items: center;
  padding: 56px 0 64px;
}
.hero h1 { font-size: 48px; line-height: 1.15; margin: 0 0 16px; letter-spacing: 0; }
.lede { font-size: 1.12em; color: var(--ink-dim); margin: 0 0 24px; }
.cta-row { display: flex; gap: 12px; flex-wrap: wrap; }
.release-meta { margin-top: 18px; color: var(--ink-mute); font-size: 0.92em; }
.hero-side { display: flex; justify-content: center; }
.shadowfetch-emblem {
  max-width: 112px; width: 100%; height: auto;
  filter: drop-shadow(0 8px 32px rgba(41,182,246,0.18));
  user-select: none;
}
.hero-shot { margin: 0; width: 100%; }
.hero-shot img,
.shot img {
  display: block; width: 100%; height: auto;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: var(--bg-3);
  box-shadow: 0 14px 40px rgba(0,0,0,0.45);
}
.shots { display: grid; grid-template-columns: 1fr 1fr; gap: 18px; }
.shot { margin: 0; }
.shot figcaption {
  margin-top: 8px; color: var(--ink-dim);
  font-size: 0.9em; text-align: center;
}

/* Buttons */
.btn {
  display: inline-block;
  padding: 12px 22px;
  border-radius: 6px;
  font-weight: 700;
  border: 1px solid transparent;
  transition: transform 0.05s ease, background 0.2s ease;
}
.btn:hover { text-decoration: none; transform: translateY(-1px); }
.btn.primary { background: var(--accent); color: #0a0a10; }
.btn.primary:hover { background: var(--accent-2); color: #0a0a10; }
.btn.ghost { background: transparent; color: var(--ink); border-color: var(--line); }
.btn.ghost:hover { border-color: var(--accent); color: var(--accent); }
.btn.muted-btn { background: var(--bg-3); color: var(--ink-dim); cursor: not-allowed; }

/* Bands / sections */
.band { padding: 56px 0; border-top: 1px solid var(--line); }
.band.alt {
  background: var(--bg-2);
  box-shadow: 0 0 0 100vmax var(--bg-2);
  clip-path: inset(0 -100vmax);
}
.band h2 { font-size: 1.7em; margin: 0 0 28px; letter-spacing: 0; }
.grid-4 { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; }
.card {
  background: var(--bg-3); border: 1px solid var(--line); border-radius: var(--radius);
  padding: 18px;
}
.card h3 { margin: 0 0 6px; font-size: 1em; color: var(--accent); }
.card p { margin: 0; color: var(--ink-dim); font-size: 0.93em; }
.two-col { display: grid; grid-template-columns: 1.4fr 1fr; gap: 40px; align-items: start; }
.two-col h4 { margin: 0 0 8px; font-size: 1em; color: var(--accent); text-transform: uppercase; letter-spacing: 0; }
.two-col ul { margin: 0; padding-left: 20px; color: var(--ink-dim); }
.two-col li { margin: 4px 0; }

/* Narrow content (download/install/docs/changelog) */
.narrow { max-width: 760px; margin: 0 auto; }
.narrow.center { text-align: center; }
.narrow h1 { font-size: 2.2em; margin: 0 0 12px; letter-spacing: 0; }
.narrow h2 { margin-top: 40px; font-size: 1.4em; color: var(--accent); }
.narrow h4 { margin-top: 18px; margin-bottom: 6px; font-size: 0.95em; color: var(--ink-dim); text-transform: uppercase; letter-spacing: 0; }
.narrow p code,
.narrow li code { overflow-wrap: anywhere; word-break: break-word; }

/* Download card */
.dl-card {
  display: flex; align-items: center; justify-content: space-between;
  gap: 16px; flex-wrap: wrap;
  background: var(--bg-3); border: 1px solid var(--line); border-radius: var(--radius);
  padding: 18px 22px; margin: 24px 0 32px;
}
.dl-card.disabled { opacity: 0.7; }
.dl-name { font-weight: 700; font-size: 1.05em; }
.dl-meta { color: var(--ink-dim); font-size: 0.9em; margin-top: 4px; }
.kv { background: var(--bg-3); padding: 12px 16px; word-break: break-all; }

/* Install steps */
.steps { list-style: none; padding: 0; counter-reset: step; }
.steps > li {
  position: relative; padding: 18px 18px 18px 70px; margin: 14px 0;
  background: var(--bg-3); border: 1px solid var(--line); border-radius: var(--radius);
  counter-increment: step;
}
.steps > li::before {
  content: counter(step);
  position: absolute; left: 18px; top: 18px;
  width: 36px; height: 36px; border-radius: 50%;
  display: grid; place-items: center;
  background: var(--accent); color: #0a0a10; font-weight: 800;
}
.steps h3 { margin: 0 0 6px; font-size: 1.05em; }
.steps p { margin: 0; color: var(--ink-dim); }

/* Release entries (changelog) */
.release { padding: 22px 0; border-bottom: 1px solid var(--line); }
.release h2 { margin: 0 0 12px; color: var(--ink); }
.release ul { color: var(--ink-dim); }

/* Footer */
footer {
  max-width: var(--max);
  margin: 0 auto;
  padding: 32px 24px 48px;
  border-top: 1px solid var(--line);
  color: var(--ink-dim);
  font-size: 0.92em;
}
.foot-grid { display: grid; grid-template-columns: 1.4fr 1fr 1fr; gap: 32px; margin-bottom: 24px; }
footer strong { color: var(--ink); }
footer a { color: var(--ink-dim); }
footer a:hover { color: var(--accent); }

.callout {
  background: var(--bg-2);
  border: 1px solid var(--line);
  border-left: 3px solid var(--accent);
  border-radius: var(--radius);
  padding: 14px 16px;
  margin: 16px 0;
  color: var(--ink-dim);
}
.callout pre { margin: 10px 0; }
.adv-callout {
  background: var(--bg-2);
  border: 1px solid var(--line);
  border-left: 3px solid var(--accent-crimson);
  border-radius: var(--radius);
  padding: 14px 16px;
  margin: 16px 0;
}
.adv-callout > summary {
  cursor: pointer;
  font-weight: 600;
  color: var(--ink);
  list-style: none;
}
.adv-callout > summary::-webkit-details-marker { display: none; }
.adv-callout > summary::before { content: "▸  "; color: var(--accent-crimson); }
.adv-callout[open] > summary::before { content: "▾  "; }
.adv-callout p { color: var(--ink-dim); }

/* Responsive */
@media (max-width: 760px) {
  .topbar { flex-wrap: nowrap; gap: 10px; padding: 12px 16px; }
  .desktop-nav { display: none !important; }
  .mobile-menu { display: block; }
  .hero { grid-template-columns: 1fr; gap: 16px; padding: 20px 0 24px; }
  .hero h1 { font-size: 36px; }
  .hero-side { width: 100%; max-width: 240px; justify-self: center; }
  .lede { font-size: 1.02em; margin-bottom: 18px; }
  .cta-row { gap: 8px; }
  .btn { padding: 10px 16px; }
  .release-meta { margin-top: 12px; }
  .shots { grid-template-columns: 1fr; }
  .grid-4 { grid-template-columns: 1fr 1fr; }
  .two-col { grid-template-columns: 1fr; gap: 24px; }
  .foot-grid { grid-template-columns: 1fr; gap: 20px; }
}
@media (max-width: 460px) {
  .hero h1 { font-size: 32px; }
  .grid-4 { grid-template-columns: 1fr; }
}
`;
}
