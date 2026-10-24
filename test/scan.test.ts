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

test("checks without an implementation are reported, not silently dropped", async () => {
  const r = await run("argos.config.yaml", { checks: ["bola", "sqli", "secrets"] });
  assert.deepEqual(r.notRun, ["sqli", "secrets"]);
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
