import { test } from "node:test";
import assert from "node:assert/strict";
import { cpSync, existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { inCi, runCi } from "../src/ci.js";
import { gitLab } from "./helpers/git-lab.js";

const FX = resolve("test/fixtures/vuln-app");
const copy = (): string => {
  const d = mkdtempSync(join(tmpdir(), "argos-ci-"));
  cpSync(FX, d, { recursive: true });
  return d;
};
const out = () => mkdtempSync(join(tmpdir(), "argos-ci-out-"));
const base = (configPath: string, extra = {}) => ({ configPath, outDir: out(), quiet: true, log: () => {}, ...extra });

test("ci runs every step and leaves the source untouched by default", async () => {
  const dir = copy();
  const before = readFileSync(join(dir, "app.mjs"), "utf8");
  const o = base(join(dir, "argos.config.yaml"));
  const r = await runCi(o);

  for (const f of ["report.md", "pr-body.md", "ci-summary.json", "fix.json", "before/matrix.json", "before/findings.json", "before/scan-meta.json", "after/matrix.json"]) {
    assert.ok(existsSync(join(o.outDir, f)), f);
  }
  assert.equal(r.exitCode, 0);
  assert.equal(r.pr, null);
  assert.equal(readFileSync(join(dir, "app.mjs"), "utf8"), before, "verified patches are not written without --apply/--pr");
  const md = readFileSync(r.reportPath, "utf8");
  assert.match(md, /증빙 헤더/);
  assert.match(md, /✅ 채택: limit columns/);
  assert.match(md, /matrix\.json ✅ 일치/);
  const summary = JSON.parse(readFileSync(r.summaryPath, "utf8"));
  assert.equal(summary.pr, null);
  assert.ok(summary.after.VULNERABLE < summary.before.VULNERABLE);
  assert.equal(summary.patches.adopted, 1);
});

test("the report describes the ORIGINAL code, the fix section describes the patched result", async () => {
  const o = base(join(copy(), "argos.config.yaml"));
  const r = await runCi(o);
  const md = readFileSync(r.reportPath, "utf8");
  assert.match(md, new RegExp(`🔴 취약 ${r.fix.before.VULNERABLE} `));
  assert.match(md, new RegExp(`채택한 패치를 모두 적용한 뒤 🔴 ${r.fix.after!.VULNERABLE}`));
});

test("exit code follows the original code: block mode + red findings = 2 even though a fix was verified", async () => {
  const r = await runCi(base(join(copy(), "block.config.yaml")));
  assert.equal(r.fix.adopted, true);
  assert.equal(r.exitCode, 2);
});

test("--apply writes the verified patches into the working tree (no git)", async () => {
  const dir = copy();
  const r = await runCi(base(join(dir, "argos.config.yaml"), { apply: true }));
  assert.equal(r.pr, null);
  assert.match(readFileSync(join(dir, "app.mjs"), "utf8"), /SELECT id, name FROM vendors/);
});

test("--pr opens a PR with the verified patch and puts the summary in the PR body", async () => {
  const lab = gitLab(FX);
  const saved = process.env.PATH;
  process.env.PATH = lab.path;
  try {
    const o = base(join(lab.work, "argos.config.yaml"), { pr: true });
    const r = await runCi(o);
    assert.equal(r.pr?.url, "https://github.com/acme/app/pull/42");
    assert.equal(lab.git("rev-parse", "--abbrev-ref", "HEAD"), "main");
    assert.equal(lab.git("show", "--name-only", "--format=", r.pr!.branch), "app.mjs");
    assert.match(lab.git("show", `${r.pr!.branch}:app.mjs`), /SELECT id, name FROM vendors/);
    assert.match(lab.git("show", "main:app.mjs"), /"SELECT \* FROM vendors WHERE id = \?"/, "main keeps the vulnerable query");
    assert.ok(!/prepare\("SELECT \* FROM vendors/.test(lab.git("show", `${r.pr!.branch}:app.mjs`)), "the branch has it fixed");
    assert.equal(JSON.parse(readFileSync(r.summaryPath, "utf8")).pr.branch, r.pr!.branch);
    assert.match(readFileSync(r.files.prBody, "utf8"), /검증된 수정 1건/);
    assert.match(lab.ghBody(), /검증된 수정 1건/, "the same summary is the PR description");
  } finally {
    process.env.PATH = saved;
  }
});

test("--pr with nothing to fix opens no PR and does not touch git", async () => {
  const lab = gitLab(FX);
  const saved = process.env.PATH;
  process.env.PATH = lab.path;
  try {
    const r = await runCi(base(join(lab.work, "fixed.config.yaml"), { pr: true }));
    assert.equal(r.pr, null);
    assert.equal(lab.ghCalls().length, 0);
    assert.equal(lab.git("branch", "--list", "argos/*"), "");
  } finally {
    process.env.PATH = saved;
  }
});

async function withEnv<T>(env: Record<string, string | undefined>, fn: () => Promise<T>): Promise<T> {
  const saved = { ...process.env };
  for (const [k, v] of Object.entries(env)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  try {
    return await fn();
  } finally {
    for (const k of Object.keys(env)) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  }
}

test("inCi: CI=true turns the automatic PR on; false/0/empty keep it off", () => {
  assert.equal(inCi({ CI: "true" }), true);
  assert.equal(inCi({ CI: "1" }), true);
  assert.equal(inCi({ CI: "false" }), false);
  assert.equal(inCi({ CI: "0" }), false);
  assert.equal(inCi({ CI: "" }), false);
  assert.equal(inCi({}), false);
});

test("in CI a verified fix opens a PR on a NEW branch with no flag, targeting the user's branch", async () => {
  const lab = gitLab(FX);
  const r = await withEnv({ CI: "true", PATH: lab.path, GITHUB_HEAD_REF: "feature/login", GITHUB_BASE_REF: "main" }, () => runCi(base(join(lab.work, "argos.config.yaml"))));
  assert.ok(r.pr, "automatic in CI");
  assert.match(r.pr!.branch, /^argos\/fix-/);
  assert.equal(r.pr!.base, "feature/login", "stacked on the user's PR, not on its destination");
  assert.notEqual(r.pr!.branch, "main");
  assert.match(lab.ghCalls()[0]!, /--base feature\/login --head argos\/fix-/);
  assert.equal(lab.git("rev-parse", "--abbrev-ref", "HEAD"), "main", "the checked-out branch is not modified");
});

test("--no-pr wins over CI; outside CI the default is no PR", async () => {
  const off = gitLab(FX);
  const a = await withEnv({ CI: "true", PATH: off.path }, () => runCi(base(join(off.work, "argos.config.yaml"), { pr: false })));
  assert.equal(a.pr, null);
  assert.equal(off.ghCalls().length, 0);
  assert.equal(off.git("branch", "--list", "argos/*"), "");

  const local = gitLab(FX);
  const b = await withEnv({ CI: undefined, PATH: local.path }, () => runCi(base(join(local.work, "argos.config.yaml"))));
  assert.equal(b.pr, null);
  assert.equal(local.ghCalls().length, 0);
});

test("on an argos fix branch no PR is opened, so fix PRs cannot loop", async () => {
  const lab = gitLab(FX);
  lab.git("checkout", "-q", "-b", "argos/fix-abc123-loop");
  const r = await withEnv({ CI: "true", PATH: lab.path }, () => runCi(base(join(lab.work, "argos.config.yaml"))));
  assert.equal(r.pr, null);
  assert.equal(lab.ghCalls().length, 0);
});
