// Adversarial tests for the artifact worker. Run: node --test tests/
//
// Everything here is driven through the real fetch() entry point against a fake
// R2 binding, so what is asserted is what a request would actually get.

import assert from "node:assert/strict";
import test from "node:test";

import worker, { __test__ } from "../src/index.js";
import { RETIREMENT_POLICY } from "../src/retirement.js";

const FINGERPRINT = "8F13CE1535EE1F4A2916A1F73C5C900B7BE80CA1";
const DIGEST = "a".repeat(64);
const ISO_4 = "shadowfetch-4.0.0-amd64.iso";

class FakeR2 {
  constructor(entries = {}) {
    this.objects = new Map();
    this.puts = [];
    for (const [key, value] of Object.entries(entries)) {
      this.set(key, value.body ?? "x", value.size, value.uploaded);
    }
  }

  set(key, body, size, uploaded) {
    this.objects.set(key, {
      key,
      body,
      size: size ?? (typeof body === "string" ? body.length : 0),
      uploaded: uploaded ?? "2026-09-06T00:00:00.000Z",
      httpEtag: `"${key}"`,
    });
  }

  async head(key) {
    const object = this.objects.get(key);
    return object ? { ...object } : null;
  }

  async get(key) {
    const object = this.objects.get(key);
    if (!object) return null;
    return { ...object, text: async () => String(object.body) };
  }

  async list({ prefix = "", delimiter, cursor } = {}) {
    const all = [...this.objects.values()].filter((o) => o.key.startsWith(prefix));
    const objects = [];
    const delimitedPrefixes = new Set();
    for (const object of all) {
      const rest = object.key.slice(prefix.length);
      if (delimiter && rest.includes(delimiter)) {
        delimitedPrefixes.add(prefix + rest.slice(0, rest.indexOf(delimiter) + 1));
      } else {
        objects.push(object);
      }
    }
    // One object per page, so any caller that does not follow the cursor sees
    // only the first one. The previous implementation asked for 100 and stopped.
    const start = cursor ? Number(cursor) : 0;
    const page = objects.slice(start, start + 1);
    const truncated = start + 1 < objects.length;
    return {
      objects: page,
      delimitedPrefixes: [...delimitedPrefixes],
      truncated,
      cursor: truncated ? String(start + 1) : undefined,
    };
  }

  async put(key, value) {
    this.puts.push(key);
    this.set(key, value);
  }
}

function pointer(overrides = {}) {
  return JSON.stringify({
    schema: "shadowfetch.linux-current.v1",
    version: "4.0.0",
    published: "2026-09-06T00:00:00Z",
    iso: {
      filename: ISO_4,
      key: `releases/${ISO_4}`,
      size_bytes: 3400,
      sha256: DIGEST,
    },
    sidecars: {
      sha256: `releases/${ISO_4}.sha256`,
      signature: `releases/${ISO_4}.asc`,
    },
    signing_key_fingerprint: FINGERPRINT,
    ...overrides,
  });
}

function bucket({ withPointer = true, pointerBody = pointer(), extra = {} } = {}) {
  const entries = {
    [`releases/${ISO_4}`]: { body: "iso-bytes", size: 3400 },
    [`releases/${ISO_4}.sha256`]: { body: `${DIGEST}  ${ISO_4}\n` },
    [`releases/${ISO_4}.asc`]: { body: "-----BEGIN PGP SIGNATURE-----" },
    // Uploaded LATER than the current release, and older by version: the exact
    // shape that used to promote an old image to "current".
    "releases/shadowfetch-3.5.0-amd64.iso": {
      body: "old-iso", size: 3200, uploaded: "2026-09-08T00:00:00.000Z",
    },
    "apt/dists/umbra/InRelease": { body: "signed index" },
    "apt/pool/main/s/shadowfetch-meta/shadowfetch-meta_4.0.0-1_all.deb": { body: "deb" },
    "shadowfetch.gpg.asc": { body: "-----BEGIN PGP PUBLIC KEY BLOCK-----" },
    ...extra,
  };
  if (withPointer) entries["releases/CURRENT.json"] = { body: pointerBody };
  return new FakeR2(entries);
}

function ctx() {
  const promises = [];
  return { waitUntil: (p) => promises.push(p), promises, settle: () => Promise.all(promises) };
}

async function call(path, { env, method = "GET", headers = {}, context } = {}) {
  const RELEASES = env || bucket();
  const c = context || ctx();
  const response = await worker.fetch(
    new Request(`https://www.shadowfetch.com${path}`, { method, headers }),
    { RELEASES, STATS_TOKEN: "secret-token" },
    c,
  );
  return { response, RELEASES, ctx: c };
}

// --------------------------------------------------------------------------
// Dead pages
// --------------------------------------------------------------------------

test("every legacy page route is a 301 to the public site, and renders no HTML", async () => {
  for (const [route, target] of __test__.LEGACY_PAGES) {
    const { response } = await call(route);
    assert.equal(response.status, 301, route);
    assert.equal(
      response.headers.get("location"),
      `https://www.shadowfetchlinux.org${target}`,
      route,
    );
    const body = await response.text();
    assert.ok(body.length < 200, `${route} returned a page body`);
    assert.ok(!body.includes("<html"), `${route} still renders HTML`);
  }
});

test("the changelog frozen at 1.9.0 is gone from the worker entirely", async () => {
  const source = await import("node:fs/promises")
    .then((fs) => fs.readFile(new URL("../src/index.js", import.meta.url), "utf8"));
  for (const dead of ["Command Center", "balenaEtcher", "System requirements", "cta-row"]) {
    assert.ok(!source.includes(dead), `page copy survives: ${dead}`);
  }
});

test("a redirect carries the query string", async () => {
  const { response } = await call("/linux/download?utm=x");
  assert.equal(
    response.headers.get("location"),
    "https://www.shadowfetchlinux.org/download?utm=x",
  );
});

test("a removed feature stays removed rather than becoming a redirect", async () => {
  const { response } = await call("/linux/agents");
  assert.equal(response.status, 410);
  assert.equal(response.headers.get("location"), null);
});

test("an unknown artifact path is a small plain-text 404", async () => {
  const { response } = await call("/linux/download/does-not-exist.iso");
  assert.equal(response.status, 404);
  assert.match(response.headers.get("content-type"), /text\/plain/);
  assert.ok((await response.text()).length < 200);
});

// --------------------------------------------------------------------------
// Retirement
// --------------------------------------------------------------------------

test("a retired image answers 410, never 404 and never a redirect", async () => {
  for (const entry of RETIREMENT_POLICY.retired) {
    const filename = RETIREMENT_POLICY.iso_name_template.replace("{version}", entry.version);
    const { response } = await call(`/linux/download/${filename}`);
    assert.equal(response.status, 410, filename);
    assert.equal(response.headers.get("x-shadowfetch-retired"), entry.status);
    assert.equal(response.headers.get("location"), null);
    const body = await response.text();
    if (entry.archive) assert.ok(body.includes(entry.archive), `${filename}: no archive link`);
    if (entry.status === "withdrawn") {
      assert.equal(response.headers.get("x-withdrawn-by"), entry.decision);
    }
  }
});

test("the two versions that answered 404 in production are now 410", async () => {
  for (const version of ["2.1.3", "2.1.4"]) {
    const { response } = await call(`/linux/download/shadowfetch-${version}-amd64.iso`);
    assert.equal(response.status, 410);
  }
});

test("the retirement declaration wins even when the body is still in the bucket", async () => {
  const env = bucket({
    extra: { "releases/shadowfetch-2.1.1-amd64.iso": { body: "old bytes still here" } },
  });
  const { response } = await call("/linux/download/shadowfetch-2.1.1-amd64.iso", { env });
  assert.equal(response.status, 410);
  assert.ok(!(await response.text()).includes("old bytes still here"));
});

test("a 410 page offers only the sidecars that are actually in the bucket", async () => {
  const absent = await call("/linux/download/shadowfetch-2.1.1-amd64.iso");
  const absentBody = await absent.response.text();
  assert.ok(!absentBody.includes("shadowfetch-2.1.1-amd64.iso.sha256"),
    "linked a checksum that returns 404 -- the live defect this test exists for");
  assert.match(absentBody, /does not offer one/);

  const env = bucket({
    extra: {
      "releases/shadowfetch-2.1.1-amd64.iso.sha256": { body: "digest" },
      "releases/shadowfetch-2.1.1-amd64.iso.asc": { body: "signature" },
    },
  });
  const present = await call("/linux/download/shadowfetch-2.1.1-amd64.iso", { env });
  const presentBody = await present.response.text();
  assert.ok(presentBody.includes("shadowfetch-2.1.1-amd64.iso.sha256"));
  assert.ok(presentBody.includes("shadowfetch-2.1.1-amd64.iso.asc"));
});

test("a retired image's sidecars still stream when they exist", async () => {
  const env = bucket({
    extra: { "releases/shadowfetch-2.1.1-amd64.iso.sha256": { body: "digest-line" } },
  });
  const { response } = await call("/linux/download/shadowfetch-2.1.1-amd64.iso.sha256", { env });
  assert.equal(response.status, 200);
  assert.equal(await response.text(), "digest-line");
});

test("HEAD on a retired image is a bodiless 410", async () => {
  const { response } = await call("/linux/download/shadowfetch-2.1.1-amd64.iso", { method: "HEAD" });
  assert.equal(response.status, 410);
  assert.equal(await response.text(), "");
});

test("a retired torrent goes to its published home", async () => {
  const { response } = await call("/linux/download/shadowfetch-2.1.1-amd64.iso.torrent");
  assert.equal(response.status, 302);
  assert.match(response.headers.get("location"), /github\.com/);
});

// --------------------------------------------------------------------------
// The current-release pointer
// --------------------------------------------------------------------------

test("releases.json reads the pointer, not the newest upload", async () => {
  const { response } = await call("/linux/releases.json");
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.pointer.source, "pointer");
  assert.equal(body.latest.version, "4.0.0");
  assert.equal(body.latest.iso.sha256, DIGEST);
});

test("without a pointer the fallback picks the highest version, not the newest upload", async () => {
  // 3.5.0 was uploaded two days after 4.0.0 in this bucket; upload-time ordering
  // (the previous implementation) would have called it current.
  const { response } = await call("/linux/releases.json", {
    env: bucket({ withPointer: false }),
  });
  const body = await response.json();
  assert.equal(body.pointer.source, "listing-fallback");
  assert.equal(body.latest.version, "4.0.0");
});

test("the fallback follows the list cursor instead of truncating", async () => {
  const extra = {};
  for (let i = 0; i < 150; i++) extra[`releases/filler-${i}.txt`] = { body: "f" };
  const { response } = await call("/linux/releases.json", {
    env: bucket({ withPointer: false, extra }),
  });
  const body = await response.json();
  assert.equal(body.latest.version, "4.0.0");
});

test("the fallback never promotes a retired image", async () => {
  const env = bucket({
    withPointer: false,
    extra: {
      "releases/shadowfetch-2.1.1-amd64.iso": { body: "retired", uploaded: "2027-01-01T00:00:00.000Z" },
    },
  });
  const { response } = await call("/linux/releases.json", { env });
  const body = await response.json();
  assert.equal(body.latest.version, "4.0.0");
});

test("a pointer naming another signing key is refused, with no fallback", async () => {
  const env = bucket({
    pointerBody: pointer({ signing_key_fingerprint: "F".repeat(40) }),
  });
  const { response } = await call("/linux/releases.json", { env });
  assert.equal(response.status, 503);
  const body = await response.json();
  assert.equal(body.latest, null);
  assert.match(body.pointer.note, /different signing key/);
});

test("a pointer naming a retired image is refused", async () => {
  const env = bucket({
    pointerBody: pointer({
      version: "2.1.1",
      iso: {
        filename: "shadowfetch-2.1.1-amd64.iso",
        key: "releases/shadowfetch-2.1.1-amd64.iso",
        size_bytes: 10,
        sha256: DIGEST,
      },
    }),
  });
  const { response } = await call("/linux/releases.json", { env });
  assert.equal(response.status, 503);
  assert.match((await response.json()).pointer.note, /retirement policy/);
});

test("a pointer contradicted by the bucket is refused rather than guessed around", async () => {
  const wrongSize = bucket({ pointerBody: pointer({ iso: { filename: ISO_4, key: `releases/${ISO_4}`, size_bytes: 999, sha256: DIGEST } }) });
  const { response } = await call("/linux/releases.json", { env: wrongSize });
  assert.equal(response.status, 503);
  assert.match((await response.json()).pointer.note, /bucket holds/);

  const missing = bucket();
  missing.objects.delete(`releases/${ISO_4}`);
  const second = await call("/linux/releases.json", { env: missing });
  assert.equal(second.response.status, 503);
  assert.match((await second.response.json()).pointer.note, /not in the bucket/);
});

test("malformed pointers are all rejected by name", async () => {
  const cases = {
    "pointer is not valid JSON": "{ not json",
    "schema": pointer({ schema: "other.v1" }),
    "X.Y.Z": pointer({ version: "4.0" }),
    "does not match its version": pointer({
      iso: { filename: "shadowfetch-3.5.0-amd64.iso", key: "releases/shadowfetch-3.5.0-amd64.iso", size_bytes: 1, sha256: DIGEST },
    }),
    "64 lowercase hex": pointer({
      iso: { filename: ISO_4, key: `releases/${ISO_4}`, size_bytes: 1, sha256: "nope" },
    }),
    "positive integer": pointer({
      iso: { filename: ISO_4, key: `releases/${ISO_4}`, size_bytes: 0, sha256: DIGEST },
    }),
  };
  for (const [expected, body] of Object.entries(cases)) {
    const { response } = await call("/linux/releases.json", { env: bucket({ pointerBody: body }) });
    assert.equal(response.status, 503, expected);
    assert.match((await response.json()).pointer.note, new RegExp(expected));
  }
});

test("releases.json publishes the retirement policy so consumers see the 410s", async () => {
  const { response } = await call("/linux/releases.json");
  const body = await response.json();
  assert.equal(body.retired.length, RETIREMENT_POLICY.retired.length);
  assert.ok(body.retired.every((entry) => entry.url.includes("/linux/download/")));
});

// --------------------------------------------------------------------------
// Artifact serving
// --------------------------------------------------------------------------

test("the current ISO streams with range support and an attachment name", async () => {
  const { response } = await call(`/linux/download/${ISO_4}`);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("accept-ranges"), "bytes");
  assert.match(response.headers.get("content-disposition"), /attachment/);
  assert.equal(response.headers.get("content-type"), "application/x-iso9660-image");
});

test("a download does not wait for the counter", async () => {
  // The counter write never settles. If it were awaited on the request path,
  // this test would hang instead of returning the ISO.
  const env = bucket();
  env.put = () => new Promise(() => {});
  const context = ctx();
  const { response } = await call(`/linux/download/${ISO_4}`, { env, context });
  assert.equal(response.status, 200);
  assert.equal(await response.text(), "iso-bytes");
  assert.equal(context.promises.length, 1, "the counter was not handed to waitUntil");
});

test("the counter is still written, through waitUntil", async () => {
  const context = ctx();
  const { response, RELEASES } = await call(`/linux/download/${ISO_4}`, { context });
  assert.equal(response.status, 200);
  await context.settle();
  assert.deepEqual(RELEASES.puts, ["stats/downloads.json"]);
});

test("a failing counter cannot fail the download", async () => {
  const env = bucket();
  env.put = async () => { throw new Error("R2 is down"); };
  const context = ctx();
  const { response } = await call(`/linux/download/${ISO_4}`, { env, context });
  assert.equal(response.status, 200);
  assert.equal(await response.text(), "iso-bytes");
  await context.settle();  // rejects here would fail the test
});

test("the signing key is served as a public key, not as a signature", async () => {
  for (const path of ["/linux/shadowfetch.gpg.asc", "/linux/apt/shadowfetch.gpg.asc"]) {
    const { response } = await call(path);
    assert.equal(response.status, 200, path);
    assert.equal(response.headers.get("content-type"), "application/pgp-keys", path);
  }
});

test("path traversal is refused in every prefix that takes a path", async () => {
  // A literal ".." is normalised away by the URL parser before the worker sees
  // it (as it is at the edge), so the interesting cases are the encoded ones.
  const attacks = [
    "/linux/apt/..%2F..%2Fstats/downloads.json",
    "/linux/apt/%2e%2e%2fshadowfetch.gpg.asc",
    "/linux/assets/..%2Freleases%2FCURRENT.json",
    "/linux/download/..%2FCURRENT.json",
    "/linux/download/sub/dir.iso",
  ];
  for (const path of attacks) {
    const { response } = await call(path);
    assert.equal(response.status, 404, path);
  }
  assert.equal(__test__.safeKey("apt/", "..%2Fx"), null);
  assert.equal(__test__.safeKey("apt/", "dists/umbra/InRelease"), "apt/dists/umbra/InRelease");
});

test("the apt tree still passes through and indexes", async () => {
  const file = await call("/linux/apt/dists/umbra/InRelease");
  assert.equal(file.response.status, 200);
  assert.equal(await file.response.text(), "signed index");

  const root = await call("/linux/apt/");
  assert.equal(root.response.status, 200);
  assert.ok((await root.response.text()).includes("Index of /linux/apt/"));

  const index = await call("/linux/apt/pool/");
  assert.equal(index.response.status, 200);
  const body = await index.response.text();
  assert.ok(body.includes("Index of /linux/apt/pool/"));
  assert.ok(body.includes("main/"));
});

test("stats stay behind the token", async () => {
  const denied = await call("/linux/_stats");
  assert.equal(denied.response.status, 401);
  const allowed = await call("/linux/_stats?token=secret-token");
  assert.equal(allowed.response.status, 200);
  assert.match((await allowed.response.json()).note, /floor/);
});

test("writing methods are refused", async () => {
  for (const method of ["POST", "PUT", "DELETE"]) {
    const { response } = await call(`/linux/download/${ISO_4}`, { method });
    assert.equal(response.status, 405, method);
  }
});

test("every response carries the security headers, and no script source", async () => {
  for (const path of ["/linux/", `/linux/download/${ISO_4}`, "/linux/releases.json", "/linux/download/shadowfetch-2.1.1-amd64.iso"]) {
    const { response } = await call(path);
    assert.equal(response.headers.get("x-content-type-options"), "nosniff", path);
    const csp = response.headers.get("content-security-policy");
    assert.ok(csp.includes("default-src 'none'"), path);
    assert.ok(!csp.includes("cloudflareinsights"), path);
  }
});

// --------------------------------------------------------------------------
// Pure helpers
// --------------------------------------------------------------------------

test("version ordering is numeric, so 4.10.0 beats 4.9.0", () => {
  assert.ok(__test__.compareVersions("4.10.0", "4.9.0") > 0);
  assert.ok(__test__.compareVersions("4.0.0", "4.0.1") < 0);
  assert.equal(__test__.compareVersions("4.0.0", "4.0.0"), 0);
});

test("pointerProblem agrees with the Python validator's rules", () => {
  const good = JSON.parse(pointer());
  assert.equal(__test__.pointerProblem(good), "");
  assert.match(__test__.pointerProblem({ ...good, version: "4.0" }), /X\.Y\.Z/);
  assert.match(__test__.pointerProblem(null), /not an object/);
});
