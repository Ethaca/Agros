/**
 * Scenario tests: SPEC section 10 acceptance criteria, replayed against A's real demo apps through the real CLI.
 *   vendor-platform  = 5 planted flaws        realistic-app = same app with the flaws fixed
 * Apps are copied to a temp dir, so `fix --apply` never touches demo/.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  APPS, ROOT, cli, copyApp, hasCurl, isRed, manualExploit, pristineScan, readAll, redOn, scan, scanConfig, skipReason, variantConfig,
} from "./helpers.js";

const skip = skipReason();
const VP = pristineScan; // alias for readability

describe("demo scenarios", { skip }, () => {
  describe("S1 customer scans the flawed app (criteria 1, 2)", () => {
    it("flaws 1-5 are red, each under the right check", () => {
      const r = VP("vendor-platform");
      assert.equal(r.status, 0, r.stderr);
      assert.ok(redOn(r.findings, "bola", "dataset-read").length > 0, "flaw 1 bola");
      assert.ok(redOn(r.findings, "unauth", "export").length > 0, "flaw 2 unauth");
      assert.ok(redOn(r.findings, "sqli", "dataset-search").length > 0, "flaw 3 sqli");
      assert.ok(redOn(r.findings, "secrets", "vendor-profile").some((f) => f.column === "vendors.api_key"), "flaw 4 secrets (a)");
      assert.ok(redOn(r.findings, "secrets", "debug-env").some((f) => !!f.env), "flaw 5 secrets (b)");
    });

    it("correctly scoped and public routes have no red finding (0 false positives)", () => {
      const r = VP("vendor-platform");
      for (const id of ["dataset-tasks", "task-read", "health", "products"]) {
        assert.deepEqual(r.findings.filter((f) => f.resourceId === id && isRed(f)), [], id);
      }
    });

    it("controls hold: owners read their own data, public routes answer everyone", () => {
      const m = VP("vendor-platform").matrix;
      const owners = m.cells.filter((c) => c.target && c.persona.replace("vendor", "v") === c.target);
      assert.ok(owners.length >= 15);
      assert.ok(owners.every((c) => c.verdict === "OK" && c.observed === "allow"), "owner cells");
      const pub = m.cells.filter((c) => c.resource === "health" || c.resource === "products");
      assert.equal(pub.length, 8);
      assert.ok(pub.every((c) => c.verdict === "OK"), "public cells");
    });

    it("nothing is SKIPPED (every check had a working control)", () => {
      assert.equal(VP("vendor-platform").counts.SKIPPED, 0);
    });
  });

  describe("S2 customer scans the safe app (criterion 2)", () => {
    it("realistic-app: no red, no yellow, no skipped", () => {
      const r = VP("realistic-app");
      assert.equal(r.status, 0, r.stderr);
      assert.deepEqual([r.counts.VULNERABLE, r.counts.SUSPECTED, r.counts.SKIPPED], [0, 0, 0]);
      assert.ok(r.counts.OK > 0);
      assert.ok(!r.matrix.cells.some((c) => c.verdict !== "OK"));
    });
  });

  describe("S3 Argos agrees with the manual curl reproduction (criterion 1)", { skip: hasCurl() ? false : "curl not available" }, () => {
    it("vendor-platform: same five flaws", () => {
      const m = manualExploit(copyApp("vendor-platform"));
      assert.equal(m.status, 0, m.raw);
      assert.deepEqual(m.flaws, [1, 2, 3, 4, 5]);
      const f = VP("vendor-platform").findings;
      const argos = [
        redOn(f, "bola", "dataset-read").length > 0 ? 1 : 0,
        redOn(f, "unauth", "export").length > 0 ? 2 : 0,
        redOn(f, "sqli", "dataset-search").length > 0 ? 3 : 0,
        redOn(f, "secrets", "vendor-profile").length > 0 ? 4 : 0,
        redOn(f, "secrets", "debug-env").length > 0 ? 5 : 0,
      ].filter(Boolean);
      assert.deepEqual(argos, m.flaws);
    });

    it("realistic-app: neither finds anything", () => {
      const m = manualExploit(copyApp("realistic-app"));
      assert.equal(m.status, 0, m.raw);
      assert.deepEqual(m.flaws, []);
      assert.match(m.summary, /0\/5 flaws reproduced/);
      assert.equal(VP("realistic-app").counts.VULNERABLE, 0);
    });
  });

  describe("S4 fix and re-verify (SHOULD)", () => {
    it("verified patch: original untouched without --apply, applied with --apply, flaw 4 gone everywhere", () => {
      const dir = copyApp("vendor-platform");
      const cfg = join(dir, "argos.config.yaml");
      const appSrc = () => readFileSync(join(dir, "app.mjs"), "utf8");
      const before = appSrc();
      const out = join(dir, "fix-out");

      const dry = cli(["fix", "--config", cfg, "--out", out]);
      assert.equal(dry.status, 0, dry.stderr);
      assert.match(dry.stdout, /verified patch/);
      assert.equal(appSrc(), before, "no --apply: original unchanged");

      const applied = cli(["fix", "--config", cfg, "--out", out, "--apply"]);
      assert.equal(applied.status, 0, applied.stderr);
      assert.match(appSrc(), /SELECT id, name, contact_email FROM vendors/);
      assert.ok(!/SELECT \* FROM vendors/.test(appSrc()));

      const after = scan(cfg);
      assert.equal(after.findings.filter((f) => f.check === "secrets" && f.column && f.verdict !== "OK").length, 0, "api_key no longer leaks");
      assert.ok(after.counts.VULNERABLE < pristineScan("vendor-platform").counts.VULNERABLE);
      const owners = after.matrix.cells.filter((c) => c.target && c.persona.replace("vendor", "v") === c.target);
      assert.ok(owners.every((c) => c.verdict === "OK"), "owner access still works after the patch");

      if (hasCurl()) assert.deepEqual(manualExploit(dir).flaws, [1, 2, 3, 5], "curl agrees: only flaw 4 is gone");
    });
  });

  describe("S5 the app does not start (criterion 5)", () => {
    it("exit 1 with the log tail, never a clean result", () => {
      const dir = copyApp("vendor-platform");
      const cfg = variantConfig(dir, "broken.yaml", (t) => t.replace("node --no-warnings app.mjs", "node --no-warnings does-not-exist.mjs"));
      const r = scanConfig(cfg);
      assert.equal(r.status, 1);
      assert.match(r.stderr, /argos: target exited with code \d+ before becoming ready/);
      assert.match(r.stderr, /does-not-exist\.mjs/, "log tail names the real cause");
      assert.ok(!/🟢|findings:/.test(r.stdout), "no results printed");
      assert.throws(() => readFileSync(join(r.out, "matrix.json")), /ENOENT/, "no matrix written");
    });
  });

  describe("S6 credentials are wrong (criterion 5)", () => {
    it("a failed control is never reported as secure", () => {
      const dir = copyApp("vendor-platform");
      const cfg = variantConfig(dir, "badtokens.yaml", (t) => t.replace(/tok-v(\d)/g, "wrong-v$1"));
      const r = scan(cfg);
      assert.equal(r.status, 0, r.stderr);
      // `export` needs no login at all (flaw 2), so it still leaks with bad tokens: a proven leak is correctly red.
      const needsLogin = (f: { resourceId: string }) => f.resourceId !== "export";
      for (const check of ["bola", "sqli"] as const) {
        const fs = r.findings.filter((f) => f.check === check && needsLogin(f));
        assert.ok(fs.length > 0, check);
        assert.ok(fs.every((f) => f.verdict === "SKIPPED" || f.verdict === "SUSPECTED"), `${check} must not claim OK or red without a working login`);
      }
      assert.ok(r.findings.some((f) => f.check === "bola" && f.resourceId === "export" && f.verdict === "VULNERABLE"), "login-free leak stays red");
      assert.ok(!r.findings.some((f) => f.check === "unauth" && f.verdict === "OK" && f.resourceId !== "health" && f.resourceId !== "products"));
      assert.ok(r.counts.SKIPPED > 0);
    });
  });

  describe("S7 mode and exit codes", () => {
    it("report never fails the run; block exits 2 only when something is red", () => {
      const vp = copyApp("vendor-platform");
      const ra = copyApp("realistic-app");
      const block = (d: string) => variantConfig(d, "block.yaml", (t) => t.replace(/^mode: report$/m, "mode: block"));
      assert.equal(scanConfig(join(vp, "argos.config.yaml")).status, 0, "report + red = 0");
      assert.equal(scanConfig(block(vp)).status, 2, "block + red = 2");
      assert.equal(scanConfig(block(ra)).status, 0, "block + clean = 0");
    });
  });

  describe("S8 reproducibility", () => {
    it("same config, same app: byte-identical matrix and findings", () => {
      const cfg = join(ROOT, "demo", "vendor-platform", "argos.config.yaml");
      const a = scan(cfg);
      const b = scan(cfg);
      assert.equal(readFileSync(join(a.out, "matrix.json"), "utf8"), readFileSync(join(b.out, "matrix.json"), "utf8"));
      assert.equal(readFileSync(join(a.out, "findings.json"), "utf8"), readFileSync(join(b.out, "findings.json"), "utf8"));
    });
  });

  describe("S9 output never carries a full marker or secret", () => {
    const LEAKS: [string, RegExp][] = [
      ["secret marker", /ARGOS_SECRET_\d+_[0-9a-f]{6}/],
      ["env canary", /ARGOS_ENV_[A-Z0-9_]+_[0-9a-f]{6}/],
      ["owner marker", /ARGOS_[A-Za-z0-9-]+_v\d_[0-9a-f]{6}/],
    ];
    it("scan files and terminal output", () => {
      for (const app of APPS) {
        const r = pristineScan(app);
        const all = readAll(r.out) + r.stdout + r.stderr;
        for (const [name, re] of LEAKS) assert.ok(!re.test(all), `${app}: ${name} leaked`);
      }
    });
    it("fix output files and terminal output", () => {
      const dir = copyApp("vendor-platform");
      const out = join(dir, "fix-out");
      const r = cli(["fix", "--config", join(dir, "argos.config.yaml"), "--out", out]);
      const all = readAll(out) + r.stdout + r.stderr;
      for (const [name, re] of LEAKS) assert.ok(!re.test(all), `fix: ${name} leaked`);
    });
  });

  describe("S10 demo timing (criterion 6, target: scan under 60s)", () => {
    it("scan, then fix and re-scan, stays within the 3-minute demo budget", (t) => {
      for (const app of APPS) {
        const r = scanConfig(join(copyApp(app), "argos.config.yaml"));
        t.diagnostic(`scan ${app}: ${(r.ms / 1000).toFixed(1)}s`);
        assert.ok(r.ms < 60_000, `${app} scan took ${r.ms}ms`);
      }
      const dir = copyApp("vendor-platform");
      const cfg = join(dir, "argos.config.yaml");
      const t0 = Date.now();
      scanConfig(cfg);
      cli(["fix", "--config", cfg, "--out", join(dir, "o"), "--apply"]);
      scanConfig(cfg);
      const flow = Date.now() - t0;
      t.diagnostic(`scan + fix --apply + re-scan: ${(flow / 1000).toFixed(1)}s`);
      assert.ok(flow < 180_000, `demo flow took ${flow}ms`);
    });
  });
});
