import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { dropWriteCredentials, runPrepare } from "../src/ci-prepare.js";
import { runPublish } from "../src/ci-publish.js";
import { loadConfig } from "../src/config.js";
import { RunnerError } from "../src/errors.js";
import { runInit } from "../src/init/index.js";
import { buildEnv } from "../src/runner.js";
import { fakeGh } from "./helpers/fake-gh.js";
import { fakeFix, fakeSpringInit } from "./helpers/fake-scan.js";
import { gitLab } from "./helpers/git-lab.js";

const SPRING = resolve("test/fixtures/spring/maven-app");
const SERVICE = "src/main/java/com/acme/workspace/service/ProjectService.java";
const FIX_EDIT = { file: SERVICE, line: 1, before: "package com.acme.workspace.service;", after: "package com.acme.workspace.service; // argos: org check" };
const quiet = { quiet: true, log: () => {}, lang: "ko" as const };
const art = () => join(mkdtempSync(join(tmpdir(), "argos-art-")), "artifact");
/** CI-free environment: the test runner itself may be in GitHub Actions. */
const env = (extra: Record<string, string> = {}): NodeJS.ProcessEnv => ({ PATH: process.env.PATH, ...extra });
const read = (dir: string, f: string) => readFileSync(join(dir, f), "utf8");
const section = (md: string, title: string) => md.split(`## ${title}`)[1]!.split("\n## ")[0]!;

test("no config, Spring detected: draft config + scan + verified fix -> artifact with config, report, patch, PR body", async () => {
  const lab = gitLab(SPRING);
  const artifactDir = art();
  const r = await runPrepare(
    { dir: lab.work, artifactDir, env: env(), ...quiet },
    { runInit: fakeSpringInit(), runFix: fakeFix({ red: ["project-read"], skipped: { "document-update": "marker not observable: title is not serialized" }, edits: [FIX_EDIT] }) },
  );
  const a = r.artifact;
  assert.equal(a.status, "partial", "one resource could not be verified");
  assert.equal(a.base, "main");
  assert.equal(a.branch, "argos/report-main");
  assert.equal(a.headSha, lab.git("rev-parse", "HEAD"));
  assert.deepEqual(a.files.map((f) => f.to).sort(), [".argos/evidence.md", ".argos/init-report.md", ".argos/report.md", ".argos/result.json", "argos.config.yaml"]);
  assert.equal(a.patch, "fix.patch");
  assert.deepEqual(a.patchFiles, [SERVICE]);
  assert.match(read(artifactDir, "fix.patch"), new RegExp(`^diff --git a/${SERVICE} b/${SERVICE}`, "m"));
  assert.equal(lab.git("status", "--porcelain", "--untracked-files=no"), "", "the checkout is restored after building the patch");
  assert.match(read(artifactDir, "files/argos.config.yaml"), /ai-draft/, "the generated config carries its provenance");

  const report = read(artifactDir, "files/report.md");
  assert.match(report, /Spring Boot \(JVM\)/);
  assert.match(report, /‘bob-member’ 계정으로 다른 조직 또는 다른 사용자의 ‘project-read’/, "plain-language impact");
  assert.match(report, /근거: `GET \/api\/projects\/7 \[200\] marker ARGOS_…`/, "evidence without the full marker");
  assert.match(report, /같은 설정·같은 공격을 수정한 코드에 다시 실행했다: 🔴 1 → 0/, "re-verification result");
  const resources = loadConfig(join(lab.work, "argos.config.yaml")).resources.length;
  assert.match(report, new RegExp(`## 시험 범위: 발견한 API ${resources + 1}개 중 ${resources - 1}개 실행`), "coverage over every discovered API");
  assert.match(report, /`DELETE \/api\/projects\/\{projectId\}` \| ➖ 설정에 넣지 않음 \| 삭제 요청/);
  assert.match(report, /`PUT \/api\/projects\/\{projectId\}\/documents\/\{documentId\}` \| ⚪ 실행 못함 \| marker not observable/);
  // unconfirmed policy and environment problems are separate sections, never vulnerabilities
  assert.match(section(report, "확인되지 않은 정책 (취약점 아님)"), /resources\.project-read\.expect/);
  assert.match(section(report, "환경 오류·미검증 (취약점 아님)"), /resources\.document-update/);
  assert.ok(!section(report, "무엇이 문제였나").includes("document-update"), "an unverified resource is not listed as a problem");

  assert.match(r.body, /검증된 수정 포함/);
  assert.match(r.body, /미검증 1건/);
  assert.match(r.body, /AI 초안/);
  assert.match(a.title, /검증된 수정 1건/);
});

test("no config, Node repo, real init + real scan/fix (process isolation): the verified patch applies on the published branch", async () => {
  const lab = gitLab(resolve("test/fixtures/init-app"));
  const artifactDir = art();
  const r = await runPrepare({ dir: lab.work, artifactDir, isolation: "process", env: env(), ...quiet });
  assert.notEqual(r.artifact.status, "failed");
  assert.ok(r.artifact.files.some((f) => f.to === "argos.config.yaml"));
  assert.match(r.report!, /## 시험 범위: 발견한 API \d+개 중 \d+개 실행/);
  assert.match(r.report!, /➖ 설정에 넣지 않음/, "routes init left out are listed, not hidden");
  const gh = fakeGh();
  const p = runPublish({ artifactDir, remote: lab.remote, env: { ...process.env, PATH: gh.path, GITHUB_REPOSITORY: "" }, log: () => {} });
  assert.equal(p.action, "created");
  if (r.artifact.patch) assert.deepEqual(execFileSync("git", ["--git-dir", lab.remote, "diff", "--name-only", "argos/report-main~1", "argos/report-main"], { encoding: "utf8" }).trim().split("\n"), r.artifact.patchFiles);
});

test("report language follows report.lang / --lang; English is the default", async () => {
  const lab = gitLab(SPRING);
  const r = await runPrepare({ dir: lab.work, artifactDir: art(), env: env(), quiet: true, log: () => {} }, { runInit: fakeSpringInit(), runFix: fakeFix({ red: ["project-read"], skipped: { "document-update": "marker not observable" } }) });
  assert.match(r.report!, /## Test scope: \d+ of \d+ discovered APIs run/);
  assert.match(r.report!, /## Unconfirmed policy \(not a vulnerability\)/);
  assert.match(r.report!, /## Environment errors \/ not verified \(not vulnerabilities\)/);
  assert.match(r.report!, /Account ‘bob-member’ could access ‘project-read’/);
  assert.match(r.body, /\*\*1 not verified\*\*/);
  assert.match(r.artifact.title, /^argos: check report and config draft/);
  assert.ok(!/[가-힣]/.test(r.body), "no Korean in the English body");
});

test("prepare drops write credentials before anything runs: neither the scan nor its children see GITHUB_TOKEN", async () => {
  const lab = gitLab(SPRING);
  const saved = { ...process.env };
  for (const k of Object.keys(process.env)) if (k.startsWith("GITHUB_")) delete process.env[k];
  process.env.GITHUB_TOKEN = "ghs_FAKEFAKEFAKEFAKEFAKEFAKEFAKE00";
  process.env.GH_TOKEN = "gho_FAKEFAKEFAKEFAKEFAKEFAKEFAKE00";
  const seen: Record<string, string | undefined> = {};
  try {
    const r = await runPrepare(
      { dir: lab.work, artifactDir: art(), base: "main", ...quiet },
      {
        runInit: fakeSpringInit(),
        runFix: fakeFix({
          during: (configPath) => {
            seen.scan = process.env.GITHUB_TOKEN ?? process.env.GH_TOKEN;
            seen.child = execFileSync(process.execPath, ["-e", "process.stdout.write(String(process.env.GITHUB_TOKEN ?? process.env.GH_TOKEN ?? 'none'))"], { encoding: "utf8" });
            seen.app = Object.keys(buildEnv(loadConfig(configPath), 8080, "/tmp/home")).find((k) => /TOKEN/.test(k));
          },
        }),
      },
    );
    assert.equal(seen.scan, undefined);
    assert.equal(seen.child, "none");
    assert.equal(seen.app, undefined, "the app env is built from the config, never the host env");
    assert.deepEqual(r.artifact.credentialsDropped, ["GITHUB_TOKEN", "GH_TOKEN"]);
    assert.ok(!JSON.stringify(r.artifact).includes("FAKEFAKE"), "names only, never values");
  } finally {
    for (const k of Object.keys(process.env)) if (!(k in saved)) delete process.env[k];
    Object.assign(process.env, saved);
  }
});

test("runner.buildEnv never forwards host credentials, even if they were not dropped", () => {
  const e = env({ GITHUB_TOKEN: "x" });
  assert.deepEqual(dropWriteCredentials(e), ["GITHUB_TOKEN"]);
  assert.equal(e.GITHUB_TOKEN, undefined);
  const saved = process.env.GH_TOKEN;
  process.env.GH_TOKEN = "gho_x";
  try {
    const cfg = loadConfig(join(resolve("test/fixtures/vuln-app"), "argos.config.yaml"));
    assert.ok(!("GH_TOKEN" in buildEnv(cfg, 1, "/tmp")));
  } finally {
    if (saved === undefined) delete process.env.GH_TOKEN;
    else process.env.GH_TOKEN = saved;
  }
});

test("unsupported stack: no config, no scan, still a report PR stating 미검증 scope and the reason", async () => {
  const src = mkdtempSync(join(tmpdir(), "argos-unsup-"));
  writeFileSync(join(src, "README.md"), "# a Go service\n");
  writeFileSync(join(src, "main.go"), "package main\nfunc main() {}\n");
  const lab = gitLab(src);
  const artifactDir = art();
  let fixCalled = false;
  const r = await runPrepare({ dir: lab.work, artifactDir, env: env(), ...quiet }, { runInit, runFix: async () => ((fixCalled = true), Promise.reject(new Error("must not run"))) });
  assert.equal(fixCalled, false);
  assert.equal(r.artifact.status, "unsupported");
  assert.equal(r.artifact.patch, null);
  assert.ok(!r.artifact.files.some((f) => f.to === "argos.config.yaml"));
  assert.match(r.body, /아직 자동 점검을 지원하지 않는다\. 안전하다는 뜻이 아니다/);
  assert.match(r.body, /미검증 1건/);
  assert.match(r.body, /init: /);
  assert.match(r.report!, /알 수 없음 \(미지원\)/);

  const gh = fakeGh();
  const p = runPublish({ artifactDir, remote: lab.remote, env: { ...process.env, PATH: gh.path, GITHUB_REPOSITORY: "" }, log: () => {} });
  assert.equal(p.action, "created");
  const files = execFileSync("git", ["--git-dir", lab.remote, "ls-tree", "-r", "--name-only", "argos/report-main"], { encoding: "utf8" }).trim().split("\n");
  assert.deepEqual(files.filter((f) => f.startsWith(".argos/")).sort(), [".argos/report.md", ".argos/result.json"]);
  assert.match(gh.prs()[0]!.body, /미검증/);
});

test("Spring init cannot write a config (unsupported security setup): report PR with the init reasons", async () => {
  const lab = gitLab(SPRING);
  const r = await runPrepare({ dir: lab.work, artifactDir: art(), env: env(), ...quiet }, { runInit: fakeSpringInit({ written: false }), runFix: fakeFix() });
  assert.equal(r.artifact.status, "unsupported");
  assert.match(section(r.report!, "환경 오류·미검증 (취약점 아님)"), /커스텀 JWT 필터/);
});

test("preparation fails (build error): report PR with the first line only, log tail and secrets left out", async () => {
  const lab = gitLab(SPRING);
  const err = new RunnerError("maven build failed (exit 1)", ["[ERROR] token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop"]);
  const r = await runPrepare({ dir: lab.work, artifactDir: art(), env: env(), ...quiet }, { runInit: fakeSpringInit(), runFix: fakeFix({ throws: err }) });
  assert.equal(r.artifact.status, "failed");
  assert.match(r.body, /scan: maven build failed \(exit 1\)/);
  assert.match(r.report!, /⚪ 실행 못함 \| maven build failed/);
  assert.ok(!/ghp_|eyJhbGci/.test(r.body + r.report), "no log tail in the PR");
});

test("fix guard: a fix that changed the config (relaxed expectations) or edits a test is not put in the PR", async () => {
  const lab = gitLab(SPRING);
  const tamper = (configPath: string) => writeFileSync(configPath, readFileSync(configPath, "utf8").replace(/other: deny/g, "other: allow"));
  const r = await runPrepare({ dir: lab.work, artifactDir: art(), env: env(), ...quiet }, { runInit: fakeSpringInit(), runFix: fakeFix({ red: ["project-read"], edits: [FIX_EDIT], afterward: tamper }) });
  assert.equal(r.artifact.patch, null);
  assert.match(r.report!, /검증된 수정이 있었지만 PR에 넣지 않았다/);
  assert.match(r.report!, /`resources`가 수정 전후로 달라졌다/);
  assert.match(r.body, /제외했다/);

  const lab2 = gitLab(SPRING);
  const testEdit = { file: "src/test/java/com/acme/workspace/ProjectServiceTest.java", line: 1, before: "x", after: "y" };
  const r2 = await runPrepare({ dir: lab2.work, artifactDir: art(), env: env(), ...quiet }, { runInit: fakeSpringInit(), runFix: fakeFix({ red: ["project-read"], edits: [testEdit] }) });
  assert.equal(r2.artifact.patch, null);
  assert.match(r2.report!, /touches a test/);
});

test("existing config is used as is: no init, no config file in the PR", async () => {
  const lab = gitLab(SPRING);
  await fakeSpringInit()({ dir: lab.work, out: join(lab.work, "argos.config.yaml"), reportDir: mkdtempSync(join(tmpdir(), "argos-x-")) });
  lab.git("add", "-A");
  lab.git("commit", "-qm", "add argos config");
  const r = await runPrepare({ dir: lab.work, artifactDir: art(), env: env(), ...quiet }, { runInit: () => Promise.reject(new Error("init must not run")), runFix: fakeFix() });
  assert.equal(r.artifact.status, "verified");
  assert.ok(!r.artifact.files.some((f) => f.to === "argos.config.yaml"));
  assert.match(r.report!, /기존 `argos\.config\.yaml` 사용/);
});

test("recursion guard: Argos branches (checked out or from the CI env) and Argos commits are skipped, and publish does nothing", async () => {
  const cases: [string, (lab: ReturnType<typeof gitLab>) => NodeJS.ProcessEnv][] = [
    ["checked-out argos branch", (lab) => (lab.git("checkout", "-q", "-b", "argos/report-main"), env())],
    ["GITHUB_HEAD_REF", () => env({ GITHUB_HEAD_REF: "argos/report-main" })],
    ["pushed argos branch", () => env({ GITHUB_REF_TYPE: "branch", GITHUB_REF_NAME: "argos/report-feature" })],
    ["Argos commit at HEAD", (lab) => (lab.git("commit", "-q", "--allow-empty", "-m", "argos: report\n\nArgos-Result: verified\nArgos-Source: abc"), env())],
  ];
  for (const [name, setup] of cases) {
    const lab = gitLab(SPRING);
    const e = setup(lab);
    const artifactDir = art();
    let ran = false;
    const r = await runPrepare({ dir: lab.work, artifactDir, base: "main", env: e, ...quiet }, { runInit: async () => ((ran = true), Promise.reject(new Error("no"))), runFix: fakeFix() });
    assert.equal(r.artifact.status, "skipped", name);
    assert.equal(ran, false, name);
    const gh = fakeGh();
    assert.equal(runPublish({ artifactDir, remote: lab.remote, env: { ...process.env, PATH: gh.path }, log: () => {} }).action, "skipped", name);
    assert.equal(gh.calls().length, 0, name);
  }
});

test("prepare refuses to wipe a non-artifact directory", async () => {
  const lab = gitLab(SPRING);
  const d = mkdtempSync(join(tmpdir(), "argos-notart-"));
  writeFileSync(join(d, "keep.txt"), "x");
  await assert.rejects(runPrepare({ dir: lab.work, artifactDir: d, env: env(), ...quiet }, { runInit: fakeSpringInit(), runFix: fakeFix() }), /not an Argos artifact/);
  assert.ok(existsSync(join(d, "keep.txt")));
});

test("CLI: options after `ci prepare` reach prepare, not the parent `ci` (they share --lang/--base/--timeout/--isolation)", () => {
  // Before positional options, commander gave --lang to `ci`, so prepare ran in English and this did not fail.
  let stderr = "";
  try {
    execFileSync("node", ["--import", "tsx", "src/cli.ts", "ci", "prepare", "--dir", ".", "--artifact", art(), "--lang", "xx"], { encoding: "utf8", stdio: "pipe", env: env() });
  } catch (e) {
    stderr = String((e as { stderr?: string }).stderr);
  }
  assert.match(stderr, /--lang: expected "en" or "ko", got "xx"/);
});
