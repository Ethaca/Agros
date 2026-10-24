import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { parseConfig, type Config } from "../src/config.js";
import { maskSecret, staticSecrets } from "../src/checks/static-secrets.js";
import { Finding } from "../src/types.js";
import { CHECKS } from "../src/checks/index.js";

const cfg = (secrets: Record<string, unknown> = {}): Config =>
  parseConfig({
    version: 1,
    target: { start: "x" },
    personas: [
      { name: "a", org: "o1", auth: { type: "bearer", token: "t1" } },
      { name: "b", org: "o2", auth: { type: "bearer", token: "t2" } },
      { name: "anon", auth: { type: "none" } },
    ],
    resources: [{ id: "h", route: "GET /h", public: true }],
    secrets,
  });

function repo(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "argos-static-"));
  for (const [name, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, name)), { recursive: true });
    writeFileSync(join(dir, name), text);
  }
  return dir;
}

const SK = "sk-abcdefghijklmnopqrstuvwx1234";
const AWS = "AKIAABCDEFGHIJKLMNOP";

test("finds sk- keys, AWS ids, private key blocks and credential assignments", () => {
  const dir = repo({
    "a.mjs": `const k = "${SK}";\nconst id = "${AWS}";`,
    "b.js": `const pem = "-----BEGIN RSA PRIVATE KEY-----";`,
    "c.ts": `const cfg = { api_key: "live_9f8e7d6c5b4a" };\nconst db_password = 's3cretPass99';`,
  });
  const f = staticSecrets(cfg(), dir);
  f.forEach((x) => Finding.parse(x));
  assert.equal(f.length, 5);
  assert.ok(f.every((x) => x.verdict === "SUSPECTED" && x.check === "secrets" && x.persona === "(static)" && x.resourceId === "(source)"));
  assert.deepEqual(f.map((x) => x.proof.request).sort(), ["a.mjs:1", "a.mjs:2", "b.js:1", "c.ts:1", "c.ts:2"]);
});

test("values are masked: first 4 chars and length, never the full secret or the source line", () => {
  const dir = repo({ "a.mjs": `const k = "${SK}";\nconst id = "${AWS}";`, "c.ts": `const db_password = 's3cretPass99';` });
  const dump = JSON.stringify(staticSecrets(cfg(), dir));
  for (const full of [SK, AWS, "s3cretPass99"]) assert.ok(!dump.includes(full), `leaked ${full}`);
  assert.match(dump, /sk-a… \(31 chars\)/);
  assert.equal(maskSecret("-----BEGIN RSA PRIVATE KEY-----"), "-----BEGIN… (private key block)");
});

test("placeholders and env lookups are not secrets", () => {
  const dir = repo({
    "a.mjs": [
      `const a = process.env.API_KEY ?? "changeme";`,
      `const b = { token: "your-token-here" };`,
      `const c = { password: "xxxxxxxxxx" };`,
      `const d = { secret: "Authorization" };`,
      `const e = { token: "short" };`,
      `const f = { api_key: process.env.API_KEY };`,
    ].join("\n"),
  });
  const f = staticSecrets(cfg(), dir);
  assert.equal(f.length, 1);
  assert.equal(f[0]!.verdict, "OK");
});

test("default exclusions: seeds, tests, fixtures, examples, argos config, node_modules, lockfiles, .env.example", () => {
  const leak = `const k = "${SK}";`;
  const dir = repo({
    "seed.mjs": leak,
    "seed/data.js": leak,
    "app.test.js": leak,
    "test/helper.js": leak,
    "fixtures/x.js": leak,
    "examples/y.js": leak,
    "argos.config.yaml": `token: "tok-live-9f8e7d6c5b4a"`,
    "node_modules/pkg/index.js": leak,
    "package-lock.json": `{"x":"${SK}"}`,
    ".env.example": `API_KEY=${SK}`,
    "app.mjs": `console.log("hi");`,
  });
  const f = staticSecrets(cfg(), dir);
  assert.deepEqual(f.map((x) => x.verdict), ["OK"]);
  assert.match(f[0]!.detail, /1 source files/);
});

test("a committed .env file is scanned; staticExclude adds paths to skip", () => {
  const dir = repo({ ".env": `STRIPE_SECRET_KEY="sk_live_abcdef123456"`, "legacy/old.js": `const k = "${SK}";` });
  const all = staticSecrets(cfg(), dir);
  assert.deepEqual(all.map((x) => x.proof.request).sort(), [".env:1", "legacy/old.js:1"]);
  const skipped = staticSecrets(cfg({ staticExclude: ["legacy/"] }), dir);
  assert.deepEqual(skipped.map((x) => x.proof.request), [".env:1"]);
});

test("nothing to scan is SKIPPED, not a silent pass", () => {
  const dir = repo({ "seed.mjs": `const k = "${SK}";` });
  const f = staticSecrets(cfg(), dir);
  assert.equal(f.length, 1);
  assert.equal(f[0]!.verdict, "SKIPPED");
});

test("config: staticScan defaults on and can be turned off", () => {
  assert.equal(cfg().secrets.staticScan, true);
  assert.equal(cfg({ staticScan: false }).secrets.staticScan, false);
  assert.deepEqual(cfg().secrets.staticExclude, []);
});

test("staticScan: false removes the static findings from the secrets check", async () => {
  const dir = repo({ "a.mjs": `const k = "${SK}";` });
  const base = { baseUrl: "http://127.0.0.1:1", matrix: { personas: [], resources: [], cells: [] }, raw: [], manifest: { markers: {}, secrets: [], ids: {} }, srcDir: dir };
  const on = await CHECKS.secrets({ ...base, cfg: cfg() });
  const off = await CHECKS.secrets({ ...base, cfg: cfg({ staticScan: false }) });
  assert.ok(on.some((f) => f.persona === "(static)" && f.verdict === "SUSPECTED"));
  assert.ok(!off.some((f) => f.persona === "(static)"));
});
