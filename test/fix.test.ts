import { test } from "node:test";
import assert from "node:assert/strict";
import { cpSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { loadConfig } from "../src/config.js";
import { applyEdits, proposeFixes, findingKey } from "../src/fix/rules.js";
import { runFix } from "../src/fix/index.js";
import { runScan } from "../src/scan.js";
import type { Finding } from "../src/types.js";

function fixture(): { dir: string; cfg: string } {
  const dir = mkdtempSync(join(tmpdir(), "argos-fix-"));
  cpSync(resolve("test/fixtures/vuln-app"), dir, { recursive: true });
  return { dir, cfg: join(dir, "argos.config.yaml") };
}
const opts = (cfg: string, extra = {}) => ({ configPath: cfg, outDir: mkdtempSync(join(tmpdir(), "argos-fixout-")), quiet: true, log: () => {}, ...extra });
const secretLeak = (persona: string): Finding => ({
  check: "secrets", resourceId: "vendor-read", persona, verdict: "VULNERABLE",
  proof: { request: "GET /api/vendors/v1" }, detail: "leak", column: "vendors.api_key",
});

test("proposeFixes: SELECT * on the leaking table becomes a column list; other checks are guidance", () => {
  const { dir, cfg } = fixture();
  const ps = proposeFixes(loadConfig(cfg), [secretLeak("anonymous"), secretLeak("vendor2"),
    { check: "bola", resourceId: "dataset-read", persona: "vendor2", verdict: "VULNERABLE", proof: { request: "GET /x" }, detail: "d" }], dir);
  const star = ps.find((p) => p.kind === "select-star")!;
  assert.equal(star.edits.length, 1);
  assert.equal(star.edits[0]!.before, "SELECT * FROM vendors");
  assert.equal(star.edits[0]!.after, "SELECT id, name FROM vendors");
  assert.deepEqual(star.addresses, [findingKey(secretLeak("anonymous")), findingKey(secretLeak("vendor2"))]);
  const g = ps.find((p) => p.kind === "guidance")!;
  assert.deepEqual(g.edits, []);
  assert.match(g.guidance, /ownership check/);
});

test("proposeFixes: no SELECT * to patch -> guidance only, nothing mechanical", () => {
  const { dir, cfg } = fixture();
  writeFileSync(join(dir, "app.mjs"), readFileSync(join(dir, "app.mjs"), "utf8").replaceAll("SELECT * FROM vendors", "SELECT id, name, api_key FROM vendors"));
  const ps = proposeFixes(loadConfig(cfg), [secretLeak("anonymous")], dir);
  assert.equal(ps[0]!.kind, "guidance");
  assert.deepEqual(ps[0]!.edits, []);
});

test("applyEdits throws on stale text and writes nothing", () => {
  const { dir } = fixture();
  const before = readFileSync(join(dir, "app.mjs"), "utf8");
  assert.throws(() => applyEdits(dir, [
    { file: "app.mjs", line: 1, before: "SELECT * FROM vendors", after: "SELECT id FROM vendors" },
    { file: "app.mjs", line: 2, before: "NOT THERE", after: "x" },
  ]), /expected text not found/);
  assert.equal(readFileSync(join(dir, "app.mjs"), "utf8"), before);
});

test("fix: verified patch is adopted but the original is untouched without --apply", async () => {
  const { dir, cfg } = fixture();
  const orig = readFileSync(join(dir, "app.mjs"), "utf8");
  const r = await runFix(opts(cfg));
  assert.equal(r.tried, true);
  assert.equal(r.adopted, true, r.reasons.join("; "));
  assert.equal(r.applied, false);
  assert.ok(r.after!.VULNERABLE < r.before.VULNERABLE);
  assert.equal(readFileSync(join(dir, "app.mjs"), "utf8"), orig);
});

test("fix --apply writes the patch; a re-scan shows the secrets leak gone and nothing new red", async () => {
  const { dir, cfg } = fixture();
  const before = await runScan(opts(cfg));
  const r = await runFix(opts(cfg, { apply: true }));
  assert.equal(r.applied, true);
  assert.match(readFileSync(join(dir, "app.mjs"), "utf8"), /SELECT id, name FROM vendors WHERE id = \?"\)/);

  const after = await runScan(opts(cfg));
  assert.equal(after.findings.filter((f) => f.check === "secrets" && f.column && f.verdict !== "OK").length, 0);
  // the env dump (flaw 5) is not mechanically fixable: still reported, with guidance
  assert.ok(after.findings.some((f) => f.check === "secrets" && f.env && f.verdict === "VULNERABLE"));
  assert.ok(after.counts.VULNERABLE < before.counts.VULNERABLE);
  // same matrix: controls (owner reading own data) still work
  assert.ok(after.matrix.cells.filter((c) => c.persona === "vendor1" && c.target === "v1").every((c) => c.verdict === "OK"));
});

test("fix rejects a patch that does not resolve the leak and leaves files alone even with --apply", async () => {
  const { dir, cfg } = fixture();
  // second query re-adds api_key to the response, so limiting SELECT * cannot fix it
  const src = readFileSync(join(dir, "app.mjs"), "utf8").replace(
    "return row ? void res.end(JSON.stringify(row))",
    'return row ? void res.end(JSON.stringify({ ...row, ...db.prepare("SELECT api_key FROM vendors WHERE id = ?").get(v[1]) }))',
  );
  writeFileSync(join(dir, "app.mjs"), src);
  const r = await runFix(opts(cfg, { apply: true }));
  assert.equal(r.tried, true);
  assert.equal(r.adopted, false);
  assert.equal(r.applied, false);
  assert.ok(r.reasons.some((x) => /not resolved: secrets\|vendor-read/.test(x)), r.reasons.join("; "));
  assert.equal(readFileSync(join(dir, "app.mjs"), "utf8"), src);
});

test("fix on the already-fixed app has nothing to do", async () => {
  const { cfg } = fixture();
  const fixedCfg = cfg.replace("argos.config.yaml", "fixed.config.yaml");
  const r = await runFix(opts(fixedCfg));
  assert.deepEqual(r.proposals, []);
  assert.equal(r.tried, false);
});

test("env exposure gets specific guidance, never an automatic edit", () => {
  const { dir, cfg } = fixture();
  const f: Finding = { check: "secrets", resourceId: "debug-env", persona: "vendor1", verdict: "VULNERABLE", proof: { request: "GET /debug/env" }, detail: "d", env: "JWT_SECRET" };
  const p = proposeFixes(loadConfig(cfg), [f], dir)[0]!;
  assert.deepEqual(p.edits, []);
  assert.match(p.guidance, /process\.env|environment/);
  assert.match(p.guidance, /debug-env|GET \/debug\/env/);
});
