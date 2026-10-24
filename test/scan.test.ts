import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runScan } from "../src/scan.js";
import { Finding, Matrix } from "../src/types.js";

const FX = "test/fixtures/vuln-app";
const out = () => mkdtempSync(join(tmpdir(), "argos-scan-"));
const run = (config: string, extra: Partial<Parameters<typeof runScan>[0]> = {}) =>
  runScan({ configPath: `${FX}/${config}`, outDir: out(), quiet: true, log: () => {}, ...extra });

test("scan on the flawed app: flaws 1 and 2 are red, controls green, files written", async () => {
  const r = await run("argos.config.yaml");
  Matrix.parse(JSON.parse(readFileSync(r.files.matrix, "utf8")));
  JSON.parse(readFileSync(r.files.findings, "utf8")).forEach((f: unknown) => Finding.parse(f));

  const red = r.findings.filter((f) => f.verdict === "VULNERABLE");
  assert.ok(red.some((f) => f.check === "bola" && f.resourceId === "dataset-read"));
  assert.ok(red.some((f) => f.check === "unauth" && f.resourceId === "export" && f.persona === "anonymous"));
  assert.equal(r.counts.SKIPPED, 0);
  assert.equal(r.exitCode, 0, "mode: report never fails the run");
  const own = r.matrix.cells.find((c) => c.persona === "vendor1" && c.target === "v1" && c.resource === "dataset-read")!;
  assert.equal(own.verdict, "OK");
  assert.ok(!r.matrix.cells.some((c) => c.resource === "health" && c.verdict === "VULNERABLE"), "no false positive on public route");
});

test("scan on the fixed app: no red", async () => {
  const r = await run("fixed.config.yaml");
  assert.equal(r.counts.VULNERABLE, 0);
  assert.equal(r.exitCode, 0);
});

test("mode: block exits 2 when something is red", async () => {
  assert.equal((await run("block.config.yaml")).exitCode, 2);
});

test("--checks overrides config; unknown check is an error", async () => {
  const r = await run("argos.config.yaml", { checks: ["unauth"] });
  assert.ok(r.findings.every((f) => f.check === "unauth"));
  await assert.rejects(run("argos.config.yaml", { checks: ["nope"] }), /unknown check "nope"/);
});

test("all four checks are implemented, nothing is silently dropped", async () => {
  const r = await run("argos.config.yaml");
  assert.deepEqual(r.notRun, []);
  assert.deepEqual([...new Set(r.findings.map((f) => f.check))].sort(), ["bola", "secrets", "sqli", "unauth"]);
});

test("sqli (flaw 3) and secrets (flaw 4) are red on the flawed app, with masked proof", async () => {
  const r = await run("argos.config.yaml");
  const sqli = r.findings.find((f) => f.check === "sqli" && f.verdict === "VULNERABLE")!;
  assert.equal(sqli.resourceId, "dataset-search");
  assert.match(sqli.proof.note!, /control 200 \/ ' 500 \/ '' 200/);

  const leaks = r.findings.filter((f) => f.check === "secrets" && f.column && f.verdict === "VULNERABLE");
  assert.deepEqual(leaks.map((f) => f.persona).sort(), ["anonymous", "vendor1", "vendor2"]); // (a) column leaks only
  assert.ok(leaks.every((f) => f.column === "vendors.api_key" && f.proof.marker === "ARGOS_"));
  // owner reading own key: reported as SUSPECTED, not red
  assert.ok(r.findings.some((f) => f.check === "secrets" && f.verdict === "SUSPECTED" && /owner re-exposed/.test(f.detail)));

  const dump = readFileSync(r.files.findings, "utf8") + readFileSync(r.files.matrix, "utf8");
  assert.ok(!/ARGOS_SECRET_\d+_[0-9a-f]{6}/.test(dump), "no full secret marker in output files");
});

test("fixed app: sqli and secrets are green", async () => {
  const r = await run("fixed.config.yaml");
  assert.equal(r.counts.VULNERABLE, 0);
  assert.equal(r.counts.SUSPECTED, 0, JSON.stringify(r.findings.filter((f) => f.verdict === "SUSPECTED")));
  assert.equal(r.findings.find((f) => f.check === "sqli")!.verdict, "OK");
  assert.ok(r.findings.filter((f) => f.check === "secrets").every((f) => f.verdict === "OK"));
});

test("original fixture dir is untouched (scan runs on a temp copy)", async () => {
  await run("argos.config.yaml");
  assert.ok(!existsSync(`${FX}/data.db`));
});

test("whole-scan timeout is enforced and the target is stopped", async () => {
  await assert.rejects(run("argos.config.yaml", { timeoutMs: 1 }), /timed out/);
});

test("CLI: exit codes 0 / 2 / 1 and output files", () => {
  const cli = (args: string[]) =>
    spawnSync("node", ["--import", "tsx", "src/cli.ts", "scan", ...args, "--out", out()], { encoding: "utf8" });
  const ok = cli(["--config", `${FX}/argos.config.yaml`]);
  assert.equal(ok.status, 0, ok.stderr);
  assert.match(ok.stdout, /🔴/);
  assert.match(ok.stderr, /격리 없음/);
  assert.equal(cli(["--config", `${FX}/block.config.yaml`]).status, 2);
  const bad = cli(["--config", "nope.yaml"]);
  assert.equal(bad.status, 1);
  assert.match(bad.stderr, /^argos: .*nope\.yaml: cannot read file/);
});

test("env canary leak (flaw 5) is red on the flawed app and the fixed app is clean", async () => {
  const bad = await run("argos.config.yaml");
  const envLeaks = bad.findings.filter((f) => f.check === "secrets" && f.env && f.verdict === "VULNERABLE");
  assert.ok(envLeaks.length >= 1);
  assert.ok(envLeaks.every((f) => f.resourceId === "debug-env" && f.proof.marker === "ARGOS_"));
  assert.ok(bad.findings.some((f) => f.check === "unauth" && f.resourceId === "debug-env" && f.verdict === "VULNERABLE"));
  const dump = readFileSync(bad.files.findings, "utf8");
  assert.ok(!/ARGOS_ENV_[A-Z_]+_[0-9a-f]{6}/.test(dump), "no full canary value in output");

  const ok = await run("fixed.config.yaml");
  assert.equal(ok.counts.VULNERABLE, 0);
  assert.equal(ok.counts.SKIPPED, 0, JSON.stringify(ok.findings.filter((f) => f.verdict === "SKIPPED")));
});
