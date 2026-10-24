/**
 * Scenario tests: SPEC section 10 acceptance criteria, replayed against A's real demo apps through the real CLI.
 *   vendor-platform  = 5 planted flaws        realistic-app = same app with the flaws fixed
 * Apps are copied to a temp dir, so `fix --apply` never touches demo/.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { createHash } from "node:crypto";
import { existsSync, rmSync, writeFileSync } from "node:fs";
import { gitLab } from "../helpers/git-lab.js";
import { join } from "node:path";
import {
  APPS, ROOT, cli, copyApp, hasCurl, hasDocker, isRed, manualExploit, pristineScan, readAll, redOn, scan, scanConfig, skipReason, variantConfig,
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
      assert.match(dry.stdout, /verified patch: limit columns/);
      assert.match(dry.stdout, /verified patch: scope GET \/api\/datasets\/:id/);
      assert.match(dry.stdout, /patch rejected: scope POST \/api\/export/, "export has no auth: a patch that cannot work is rejected on its own");
      assert.equal(appSrc(), before, "no --apply: original unchanged");

      const applied = cli(["fix", "--config", cfg, "--out", out, "--apply"]);
      assert.equal(applied.status, 0, applied.stderr);
      assert.match(appSrc(), /SELECT id, name, contact_email FROM vendors/);
      assert.match(appSrc(), /WHERE id = \? AND vendor_id = \?"\)\s*\.get\(req\.params\.id, req\.user\.vendor_id\)/, "owner check added to GET /api/datasets/:id");
      assert.ok(!/SELECT \* FROM vendors/.test(appSrc()));

      const after = scan(cfg);
      assert.equal(after.findings.filter((f) => f.check === "secrets" && f.column && f.verdict !== "OK").length, 0, "api_key no longer leaks");
      assert.equal(redOn(after.findings, "bola", "dataset-read").length, 0, "cross-vendor dataset read is closed");
      assert.ok(redOn(after.findings, "bola", "export").length > 0, "export is still open: only guidance for it");
      assert.ok(after.counts.VULNERABLE < pristineScan("vendor-platform").counts.VULNERABLE);
      const owners = after.matrix.cells.filter((c) => c.target && c.persona.replace("vendor", "v") === c.target);
      assert.ok(owners.every((c) => c.verdict === "OK"), "owner access still works after the patch");

      if (hasCurl()) assert.deepEqual(manualExploit(dir).flaws, [2, 3, 5], "curl agrees: flaws 1 (owner check) and 4 (columns) are gone");
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
      ["host home path", new RegExp(homedir().replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))],
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

  describe("S12 examples/out stay current", () => {
    it("a fresh scan of vendor-platform reproduces examples/out (times aside)", () => {
      const r = pristineScan("vendor-platform");
      const read = (dir: string, f: string) => readFileSync(join(dir, f), "utf8");
      assert.equal(read(r.out, "matrix.json"), read(join(ROOT, "examples", "out"), "matrix.json"), "matrix.json: run `pnpm run examples:update`");
      assert.equal(read(r.out, "findings.json"), read(join(ROOT, "examples", "out"), "findings.json"), "findings.json: run `pnpm run examples:update`");
      const strip = (t: string) => { const m = JSON.parse(t); delete m.startedAt; delete m.finishedAt; delete m.durationMs; return m; };
      assert.deepEqual(strip(read(r.out, "scan-meta.json")), strip(read(join(ROOT, "examples", "out"), "scan-meta.json")), "scan-meta.json: run `pnpm run examples:update`");
    });
  });

  describe("S13 container isolation gives the same answers (R6)", { skip: hasDocker() ? false : "docker not available" }, () => {
    it("vendor-platform and realistic-app: byte-identical matrix and findings, isolation recorded", () => {
      for (const app of APPS) {
        const host = pristineScan(app);
        const box = scan(join(copyApp(app), "argos.config.yaml"), ["--isolation", "container"]);
        assert.equal(box.status, 0, box.stderr);
        assert.match(box.stderr, /container isolation/);
        assert.equal(readFileSync(join(box.out, "matrix.json"), "utf8"), readFileSync(join(host.out, "matrix.json"), "utf8"), `${app} matrix`);
        assert.equal(readFileSync(join(box.out, "findings.json"), "utf8"), readFileSync(join(host.out, "findings.json"), "utf8"), `${app} findings`);
        const meta = JSON.parse(readFileSync(join(box.out, "scan-meta.json"), "utf8"));
        assert.equal(meta.isolation, "container");
        assert.match(meta.image, /^node:\d+-slim$/);
      }
    });

    it("fix verifies and applies the same patches inside the container", () => {
      const dir = copyApp("vendor-platform");
      const r = cli(["fix", "--config", join(dir, "argos.config.yaml"), "--out", join(dir, "o"), "--isolation", "container"]);
      assert.equal(r.status, 0, r.stderr);
      assert.match(r.stdout, /verified patch: limit columns/);
      assert.match(r.stdout, /verified patch: scope GET \/api\/datasets\/:id/);
    });

    it("docker unavailable is exit 1 with a clear message, never a silent run on the host", () => {
      const dir = copyApp("vendor-platform");
      const r = spawnSync("node", ["--import", "tsx", "src/cli.ts", "scan", "--config", join(dir, "argos.config.yaml"), "--out", join(dir, "o"), "--isolation", "container"], {
        cwd: ROOT, encoding: "utf8", env: { ...process.env, DOCKER_HOST: "unix:///nonexistent/docker.sock" },
      });
      assert.equal(r.status, 1);
      assert.match(r.stderr, /argos: container isolation requested but docker is not available/);
      assert.ok(!/findings:/.test(r.stdout), "nothing was scanned");
    });

    it("scan time in a container stays within the 60s target", (t) => {
      const r = scanConfig(join(copyApp("vendor-platform"), "argos.config.yaml"), ["--isolation", "container"]);
      t.diagnostic(`container scan vendor-platform: ${(r.ms / 1000).toFixed(1)}s`);
      assert.ok(r.ms < 60_000, `${r.ms}ms`);
    });
  });

  describe("S11 evidence report (criterion 3)", () => {
    const sha = (p: string) => createHash("sha256").update(readFileSync(p, "utf8")).digest("hex");

    it("`argos report` writes the header and its hashes match the files recomputed from disk", () => {
      const r = pristineScan("vendor-platform");
      const out = join(r.out, "report.md");
      const run = cli(["report", "--scan", r.out]);
      assert.equal(run.status, 0, run.stderr);
      const md = readFileSync(out, "utf8");
      for (const file of ["matrix.json", "findings.json"]) {
        const m = new RegExp(`\\| ${file} \\| SHA-256 \`([0-9a-f]{16})…\``).exec(md);
        assert.ok(m, file);
        assert.equal(m![1], sha(join(r.out, file)).slice(0, 16), `${file} header hash is current`);
      }
      assert.match(md, /\| Target \| vendor-platform \|/);
      assert.match(md, /does not guarantee security or prove compliance/);
      assert.match(md, /Integrity:\*\* matrix\.json ✅ match · findings\.json ✅ match/);
    });

    it("a result file edited after the scan is refused (exit 1), not reported", () => {
      const r = scan(join(copyApp("vendor-platform"), "argos.config.yaml"));
      const f = join(r.out, "findings.json");
      writeFileSync(f, readFileSync(f, "utf8").replace('"VULNERABLE"', '"OK"'));
      const run = cli(["report", "--scan", r.out]);
      assert.equal(run.status, 1);
      assert.match(run.stderr, /argos: findings\.json does not match the hash/);
      assert.ok(!existsSync(join(r.out, "report.md")));
    });
  });

  describe("S14 `argos ci`: every check, verified fixes, fix PR, report", () => {
    it("one command produces scan results, fix results, report and PR description; the source stays untouched", () => {
      const dir = copyApp("vendor-platform");
      const before = readFileSync(join(dir, "app.mjs"), "utf8");
      const out = join(dir, "ci-out");
      const r = cli(["ci", "--config", join(dir, "argos.config.yaml"), "--out", out]);
      assert.equal(r.status, 0, r.stderr);
      for (const f of ["report.md", "pr-body.md", "ci-summary.json", "fix.json", "before/findings.json", "after/findings.json"]) assert.ok(existsSync(join(out, f)), f);
      const md = readFileSync(join(out, "report.md"), "utf8");
      assert.match(md, /✅ adopted: limit columns/);
      assert.match(md, /✅ adopted: scope GET \/api\/datasets\/:id/);
      assert.match(md, /⚠️ rejected: scope POST \/api\/export/);
      const s = JSON.parse(readFileSync(join(out, "ci-summary.json"), "utf8"));
      assert.equal(s.patches.adopted, 2);
      assert.equal(s.pr, null);
      assert.equal(readFileSync(join(dir, "app.mjs"), "utf8"), before, "no PR / --apply: nothing is written");
    });

    it("--pr: a fix branch with exactly the verified patches, the PR body, and main left alone", () => {
      const lab = gitLab(join(ROOT, "demo", "vendor-platform"));
      const mainSha = lab.git("rev-parse", "main");
      const out = join(lab.root, "ci-out");
      const r = cli(["ci", "--config", join(lab.work, "argos.config.yaml"), "--out", out, "--pr"], { PATH: lab.path });
      assert.equal(r.status, 0, r.stderr);
      assert.match(r.stdout, /opened https:\/\/github\.com\/acme\/app\/pull\/42 \(branch argos\/fix-/);

      const branch = /branch (argos\/fix-[\w-]+)/.exec(r.stdout)![1]!;
      assert.equal(lab.git("rev-parse", "main"), mainSha, "main untouched");
      assert.equal(lab.git("rev-parse", "--abbrev-ref", "HEAD"), "main", "checkout restored");
      assert.equal(lab.git("show", "--name-only", "--format=", branch), "app.mjs", "only the patched file");
      const patched = lab.git("show", `${branch}:app.mjs`);
      assert.match(patched, /SELECT id, name, contact_email FROM vendors/);
      assert.match(patched, /WHERE id = \? AND vendor_id = \?"\)\s*\.get\(req\.params\.id, req\.user\.vendor_id\)/);
      assert.ok(lab.ghBody().includes("2 verified fixes"));
      assert.match(lab.ghBody(), /does not guarantee security or prove compliance/);
      assert.equal(lab.ghCalls().length, 1);
    });

    it("in CI (CI=true) no flag is needed: the verified fixes become a PR on a new branch", () => {
      const lab = gitLab(join(ROOT, "demo", "vendor-platform"));
      const r = cli(["ci", "--config", join(lab.work, "argos.config.yaml"), "--out", join(lab.root, "o")], { PATH: lab.path, CI: "true" });
      assert.equal(r.status, 0, r.stderr);
      assert.match(r.stdout, /\(PR on: CI environment\)/);
      assert.match(r.stdout, /opened https:\/\/github\.com\/acme\/app\/pull\/42 \(branch argos\/fix-/);
      assert.equal(lab.git("rev-parse", "--abbrev-ref", "HEAD"), "main");
      const noPr = cli(["ci", "--config", join(lab.work, "argos.config.yaml"), "--out", join(lab.root, "o2"), "--no-pr"], { PATH: lab.path, CI: "true" });
      assert.equal(noPr.status, 0, noPr.stderr);
      assert.ok(!/opened https/.test(noPr.stdout));
      assert.equal(lab.ghCalls().length, 1, "--no-pr opened nothing more");
    });

    it("exit code follows the scanned code: block mode + red = 2, report mode = 0", () => {
      const dir = copyApp("vendor-platform");
      const block = variantConfig(dir, "block.yaml", (t) => t.replace(/^mode: report$/m, "mode: block"));
      assert.equal(cli(["ci", "--config", block, "--out", join(dir, "o1")]).status, 2);
      assert.equal(cli(["ci", "--config", join(dir, "argos.config.yaml"), "--out", join(dir, "o2")]).status, 0);
    });

    it("on the safe app there is nothing to fix and no PR", () => {
      const lab = gitLab(join(ROOT, "demo", "realistic-app"));
      const r = cli(["ci", "--config", join(lab.work, "argos.config.yaml"), "--out", join(lab.root, "o"), "--pr"], { PATH: lab.path });
      assert.equal(r.status, 0, r.stderr);
      assert.match(r.stdout, /no verified patch, so no PR was opened/);
      assert.equal(lab.ghCalls().length, 0);
      assert.equal(lab.git("branch", "--list", "argos/*"), "");
    });

    it("--pr in a dirty repo is refused with exit 1 and the report is still written", () => {
      const lab = gitLab(join(ROOT, "demo", "vendor-platform"));
      writeFileSync(join(lab.work, "app.mjs"), readFileSync(join(lab.work, "app.mjs"), "utf8") + "\n// local change\n");
      const out = join(lab.root, "o");
      const r = cli(["ci", "--config", join(lab.work, "argos.config.yaml"), "--out", out, "--pr"], { PATH: lab.path });
      assert.equal(r.status, 1);
      assert.match(r.stderr, /argos: the working tree has uncommitted changes/);
      assert.ok(existsSync(join(out, "report.md")), "the evidence is not lost when the PR step fails");
      assert.equal(lab.ghCalls().length, 0);
    });

    it("container isolation end to end: the report states the sandbox", { skip: hasDocker() ? false : "docker not available" }, () => {
      const dir = copyApp("vendor-platform");
      const out = join(dir, "o");
      const r = cli(["ci", "--config", join(dir, "argos.config.yaml"), "--out", out, "--isolation", "container"]);
      assert.equal(r.status, 0, r.stderr);
      assert.match(readFileSync(join(out, "report.md"), "utf8"), /container \(`node:\d+-slim`: no network, read-only root, non-root\)/);
    });
  });

  describe("S15 `argos init`: from a repo with no config to a verified, usable config", () => {
    const bare = (app: (typeof APPS)[number]): string => {
      const dir = copyApp(app);
      rmSync(join(dir, "argos.config.yaml"));
      return dir;
    };
    // the hand-written configs name resources differently from the drafted ones
    const MAP: Record<string, string> = { "dataset-read": "get-datasets-id", "dataset-search": "get-datasets", export: "post-export", "vendor-profile": "get-vendors-id", "debug-env": "get-debug-env" };
    const reds = (fs: { check: string; resourceId: string; verdict: string }[], rename = (x: string) => x): Record<string, number> => {
      const m: Record<string, number> = {};
      for (const f of fs.filter((x) => x.verdict === "VULNERABLE")) {
        const k = `${f.check} ${rename(f.resourceId)}`;
        m[k] = (m[k] ?? 0) + 1;
      }
      return m;
    };

    it("vendor-platform: init finds the same vulnerabilities as the hand-written config, plus the one rule only a person can know", () => {
      const dir = bare("vendor-platform");
      const i = cli(["init", dir, "--isolation", "process", "--report", join(dir, "o")]);
      assert.equal(i.status, 0, i.stderr);
      assert.match(i.stdout, /verified: app starts, 3 personas can read their own data/);
      assert.match(i.stdout, /routes: 10 found, 10 put into the config, 0 not tested/);

      const drafted = scan(join(dir, "argos.config.yaml"));
      const hand = pristineScan("vendor-platform");
      const inverse = Object.fromEntries(Object.entries(MAP).map(([a, b]) => [b, a]));
      const want = reds(hand.findings);
      const got = reds(drafted.findings, (x) => inverse[x] ?? x);
      // conservative default: "other orgs may not read a vendor profile" is not what this app intends
      assert.equal(got["bola vendor-profile"], 6);
      delete got["bola vendor-profile"];
      assert.deepEqual(got, want, "everything else matches the hand-written config exactly");
      assert.ok(drafted.meta.unconfirmed.length > 0);
    });

    it("a person confirms the one business rule and the false alarm is gone (realistic-app: 0 red)", () => {
      const dir = bare("realistic-app");
      assert.equal(cli(["init", dir, "--isolation", "process", "--report", join(dir, "o")]).status, 0);
      const cfg = join(dir, "argos.config.yaml");
      const first = scan(cfg);
      assert.deepEqual(reds(first.findings), { "bola get-vendors-id": 6 }, "the only alarm is the profile rule");

      writeFileSync(cfg, readFileSync(cfg, "utf8").replace(/(id: get-vendors-id[\s\S]*?other: )deny/, "$1allow").replace("resources.get-vendors-id.expect: ai-draft", "resources.get-vendors-id.expect: confirmed"));
      const second = scan(cfg);
      assert.equal(second.counts.VULNERABLE, 0);
      assert.ok(!second.meta.unconfirmed.includes("resources.get-vendors-id.expect"));
      assert.ok(second.meta.unconfirmed.length > 0, "the rest is still unconfirmed and says so");
    });

    it("the generated config works with ci: report with the unconfirmed-rules warning, verified fix PR body", () => {
      const dir = bare("vendor-platform");
      assert.equal(cli(["init", dir, "--isolation", "process", "--report", join(dir, "o")]).status, 0);
      const out = join(dir, "ci-out");
      const r = cli(["ci", "--config", join(dir, "argos.config.yaml"), "--out", out]);
      assert.equal(r.status, 0, r.stderr);
      const md = readFileSync(join(out, "report.md"), "utf8");
      assert.match(md, /\d+ unconfirmed expectations?/);
      assert.match(md, /✅ adopted: limit columns/);
      assert.match(md, /✅ adopted: scope GET \/api\/datasets\/:id/);
    });

    it("default isolation is the container: the draft is verified inside the sandbox", { skip: hasDocker() ? false : "docker not available" }, () => {
      const dir = bare("vendor-platform");
      const i = cli(["init", dir, "--report", join(dir, "o")]);
      assert.equal(i.status, 0, i.stderr);
      assert.match(readFileSync(join(dir, "argos.config.yaml"), "utf8"), /isolation: container/);
      assert.match(i.stdout, /verified: app starts, 3 personas/);
    });

    it("init-report lists what a person must confirm and what was not tested", () => {
      const dir = bare("vendor-platform");
      cli(["init", dir, "--isolation", "process", "--report", join(dir, "o")]);
      const md = readFileSync(join(dir, "o", "init-report.md"), "utf8");
      assert.match(md, /사람이 확인할 것 \(\d+\)/);
      assert.match(md, /no auth middleware found on routes that read tenant data: POST \/api\/export/);
      assert.match(md, /internal-looking routes are expected to be denied to everyone: GET \/debug\/env/);
      assert.match(md, /LLM 사용 \| 아니오/);
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
