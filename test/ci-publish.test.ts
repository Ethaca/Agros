import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { parse } from "yaml";
import { findSecrets, forbiddenPatchPath, patchPaths, prMarker } from "../src/ci-artifact.js";
import { runPrepare } from "../src/ci-prepare.js";
import { PublishError, runPublish, validateArtifact } from "../src/ci-publish.js";
import { fakeGh } from "./helpers/fake-gh.js";
import { fakeFix, fakeSpringInit } from "./helpers/fake-scan.js";
import { gitLab, type GitLab } from "./helpers/git-lab.js";

const SPRING = resolve("test/fixtures/spring/maven-app");
const SERVICE = "src/main/java/com/acme/workspace/service/ProjectService.java";
const FIX_EDIT = { file: SERVICE, line: 1, before: "package com.acme.workspace.service;", after: "package com.acme.workspace.service; // argos: org check" };
const env = (): NodeJS.ProcessEnv => ({ PATH: process.env.PATH });
const remoteGit = (lab: GitLab, ...args: string[]) => execFileSync("git", ["--git-dir", lab.remote, ...args], { encoding: "utf8" }).trim();

async function prepare(lab: GitLab, edits = [FIX_EDIT]) {
  const artifactDir = join(mkdtempSync(join(tmpdir(), "argos-art-")), "artifact");
  await runPrepare({ dir: lab.work, artifactDir, env: env(), quiet: true, log: () => {}, lang: "ko" }, { runInit: fakeSpringInit(), runFix: fakeFix({ red: ["project-read"], edits }) });
  return artifactDir;
}
const publish = (lab: GitLab, artifactDir: string, gh: ReturnType<typeof fakeGh>) =>
  runPublish({ artifactDir, remote: lab.remote, env: { ...process.env, PATH: gh.path, GITHUB_REPOSITORY: "" }, log: () => {} });

test("publish: branch with a config/report commit and a separate verified-fix commit on the scanned commit, PR with the hidden marker", async () => {
  const lab = gitLab(SPRING);
  const head = lab.git("rev-parse", "HEAD");
  const artifactDir = await prepare(lab);
  const gh = fakeGh();
  const r = publish(lab, artifactDir, gh);

  assert.equal(r.action, "created");
  assert.equal(r.url, "https://github.com/acme/app/pull/42");
  assert.equal(remoteGit(lab, "rev-parse", "argos/report-main"), r.commit);
  assert.equal(remoteGit(lab, "rev-parse", "main"), head, "the base branch is untouched");
  assert.equal(remoteGit(lab, "rev-parse", "argos/report-main~2"), head, "two commits on top of the scanned commit");
  assert.deepEqual(remoteGit(lab, "diff", "--name-only", head, "argos/report-main~1").split("\n").sort(), [".argos/evidence.md", ".argos/init-report.md", ".argos/report.md", ".argos/result.json", "argos.config.yaml"]);
  assert.equal(remoteGit(lab, "diff", "--name-only", "argos/report-main~1", "argos/report-main"), SERVICE, "the code fix is its own commit");
  assert.match(remoteGit(lab, "show", `argos/report-main:${SERVICE}`), /argos: org check/);
  const msg = remoteGit(lab, "log", "-1", "--format=%B", "argos/report-main");
  assert.match(msg, /^Argos-Result: partial$|^Argos-Result: verified$/m);
  assert.match(msg, new RegExp(`^Argos-Source: ${head}$`, "m"));
  assert.equal(lab.git("rev-parse", "--abbrev-ref", "HEAD"), "main", "publish never touched the customer's checkout");

  const [pr] = gh.prs();
  assert.equal(gh.prs().length, 1);
  assert.equal(pr!.base, "main");
  assert.equal(pr!.head, "argos/report-main");
  assert.ok(pr!.body.includes(prMarker("argos/report-main")));
  assert.match(pr!.body, /전체 보고서: 이 브랜치의 `.argos\/report.md`/);
});

test("idempotent: same commit again changes nothing; a new commit updates the same branch and PR instead of opening another", async () => {
  const lab = gitLab(SPRING);
  const gh = fakeGh();
  const first = publish(lab, await prepare(lab), gh);
  assert.equal(first.action, "created");

  const again = publish(lab, await prepare(lab), gh);
  assert.equal(again.action, "unchanged", "HEAD already has an Argos result for this commit");
  assert.equal(remoteGit(lab, "rev-parse", "argos/report-main"), first.commit, "nothing pushed");
  assert.equal(gh.calls().filter((c) => c.startsWith("pr create")).length, 1);
  assert.equal(gh.calls().filter((c) => c.startsWith("pr edit")).length, 0);

  writeFileSync(join(lab.work, "NOTES.md"), "new work\n");
  lab.git("add", "NOTES.md");
  lab.git("commit", "-qm", "more work");
  lab.git("push", "-q", "origin", "main");
  const head2 = lab.git("rev-parse", "HEAD");
  const updated = publish(lab, await prepare(lab), gh);
  assert.equal(updated.action, "updated");
  assert.equal(updated.url, first.url);
  assert.equal(gh.prs().length, 1, "still one PR");
  assert.match(gh.calls().at(-1)!, /^pr edit 42 --title /);
  assert.equal(remoteGit(lab, "rev-parse", "argos/report-main~2"), head2, "the branch is rebuilt on the new commit");
  assert.match(gh.prs()[0]!.body, new RegExp(head2.slice(0, 7)));
});

test("a commit someone else pushed to the Argos branch is never overwritten", async () => {
  const lab = gitLab(SPRING);
  const gh = fakeGh();
  publish(lab, await prepare(lab), gh);
  rmSync(join(lab.work, "argos.config.yaml"));
  lab.git("fetch", "-q", "origin", "argos/report-main");
  lab.git("checkout", "-q", "-b", "human", "FETCH_HEAD");
  writeFileSync(join(lab.work, "argos.config.yaml"), "# confirmed by a person\n");
  lab.git("add", "-f", "argos.config.yaml");
  lab.git("commit", "-qm", "confirm the rules");
  lab.git("push", "-q", "origin", "human:argos/report-main");
  const human = lab.git("rev-parse", "HEAD");
  lab.git("checkout", "-q", "main");
  rmSync(join(lab.work, "argos.config.yaml"), { force: true });

  writeFileSync(join(lab.work, "NOTES.md"), "x\n");
  lab.git("add", "NOTES.md");
  lab.git("commit", "-qm", "next");
  lab.git("push", "-q", "origin", "main");
  const r = publish(lab, await prepare(lab), gh);
  assert.equal(r.action, "unchanged");
  assert.match(r.warning!, /did not write/);
  assert.equal(remoteGit(lab, "rev-parse", "argos/report-main"), human);
});

function expectRejected(lab: GitLab, artifactDir: string, re: RegExp) {
  const gh = fakeGh();
  assert.throws(() => publish(lab, artifactDir, gh), (e: Error) => e instanceof PublishError && re.test(e.message));
  assert.equal(gh.calls().length, 0, "gh not called");
  assert.equal(remoteGit(lab, "branch", "--list", "argos/*"), "", "nothing pushed");
}

test("publish rejects a patch that touches .github/workflows (or tests, or the Argos config)", async () => {
  const lab = gitLab(SPRING);
  const dir = await prepare(lab);
  const patch = readFileSync(join(dir, "fix.patch"), "utf8");
  writeFileSync(join(dir, "fix.patch"), patch.replaceAll(SERVICE, ".github/workflows/ci.yml"));
  expectRejected(lab, dir, /fix\.patch touches \.github/);
  writeFileSync(join(dir, "fix.patch"), patch.replaceAll(SERVICE, "src/test/java/FooTest.java"));
  expectRejected(lab, dir, /touches a test/);
  writeFileSync(join(dir, "fix.patch"), patch.replaceAll(SERVICE, "argos.config.yaml"));
  expectRejected(lab, dir, /Argos config/);
});

test("publish rejects a body with a JWT, a full ARGOS_ marker, a token, or a forged PR marker", async () => {
  const lab = gitLab(SPRING);
  const dir = await prepare(lab);
  const body = readFileSync(join(dir, "body.md"), "utf8");
  for (const [bad, re] of [
    ["eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJlLXZhbHVl", /body contains a JWT/],
    ["leaked ARGOS_SECRET_1_a1b2c3 in a response", /body contains a full Argos marker/],
    ["ARGOS_R3_deadbeef", /full Argos marker/],
    ["ghs_0123456789abcdefghijABCDEFGHIJ", /GitHub token/],
    [prMarker("argos/report-other"), /Argos PR marker/],
  ] as const) {
    writeFileSync(join(dir, "body.md"), `${body}\n${bad}\n`);
    expectRejected(lab, dir, re);
  }
});

test("publish rejects files outside argos.config.yaml/.argos and a tampered pr.json", async () => {
  const lab = gitLab(SPRING);
  const dir = await prepare(lab);
  const pr = JSON.parse(readFileSync(join(dir, "pr.json"), "utf8"));
  const save = (o: unknown) => writeFileSync(join(dir, "pr.json"), JSON.stringify(o));
  save({ ...pr, files: [...pr.files, { from: "files/report.md", to: ".github/workflows/evil.yml" }] });
  expectRejected(lab, dir, /publish only writes/);
  save({ ...pr, files: [{ from: "../../etc/passwd", to: ".argos/x.md" }] });
  expectRejected(lab, dir, /plain relative path/);
  save({ ...pr, branch: "main" });
  expectRejected(lab, dir, /branch/);
  save({ ...pr, unexpected: true });
  expectRejected(lab, dir, /pr\.json/);
});

test("artifact rules: patch paths, forbidden paths, secret patterns", () => {
  const p = patchPaths("diff --git a/src/A.java b/src/A.java\n--- a/src/A.java\n+++ b/src/A.java\n@@ -1 +1 @@\n-a\n+b\n");
  assert.deepEqual(p.paths, ["src/A.java"]);
  assert.deepEqual(patchPaths("diff --git a/x b/x\nnew file mode 120000\n").problems, ["symlink or submodule change"]);
  assert.match(patchPaths("diff --git a/x b/x\nGIT binary patch\n").problems[0]!, /binary/);
  assert.match(patchPaths("diff --git a/x b/y\nrename from x\nrename to ../../y\n").problems.join(), /unsafe path/);
  assert.equal(forbiddenPatchPath("src/main/java/Foo.java"), undefined);
  assert.equal(forbiddenPatchPath("src/main/java/OrderUnit.java"), undefined);
  assert.ok(forbiddenPatchPath("src/main/resources/db/migration/V2__x.sql"));
  assert.ok(forbiddenPatchPath("app/argos.config.yaml"));
  assert.deepEqual(findSecrets("marker ARGOS_… only the prefix"), []);
  assert.deepEqual(findSecrets("ARGOS_ENV_JWT_SECRET_0a1b2c"), ["full Argos marker"]);
});

test("example workflow: prepare has read-only permissions and no token; publish has write permissions and runs no customer code", () => {
  const wf = parse(readFileSync("examples/github-workflow.yml", "utf8"));
  assert.deepEqual(wf.permissions, {}, "nothing by default");
  const { prepare, publish } = wf.jobs;
  assert.deepEqual(prepare.permissions, { contents: "read" });
  const prepText = JSON.stringify(prepare);
  assert.ok(!/GITHUB_TOKEN|GH_TOKEN|secrets\.|github\.token/.test(prepText), "no write credential in the prepare job");
  const checkout = prepare.steps.find((s: { uses?: string }) => s.uses?.startsWith("actions/checkout"));
  assert.equal(checkout.with["persist-credentials"], false);
  assert.match(prepText, /cli\.ts ci prepare/);
  assert.match(prepText, /upload-artifact/);

  assert.deepEqual(publish.permissions, { contents: "write", "pull-requests": "write" });
  assert.deepEqual(publish.needs, "prepare");
  const pubText = JSON.stringify(publish);
  assert.match(pubText, /download-artifact/);
  assert.match(pubText, /cli\.ts ci publish/);
  for (const s of publish.steps as { uses?: string; with?: Record<string, string>; run?: string }[]) {
    if (s.uses?.startsWith("actions/checkout")) assert.ok(s.with?.repository && s.with.repository !== "${{ github.repository }}", "publish checks out only the Argos tool, never the customer repo");
    assert.ok(!/npm (ci|install)|pnpm install|mvn|gradle|yarn/.test(s.run ?? "") || /--prefix .argos-tool|-C .argos-tool/.test(s.run ?? ""), `no customer build in publish: ${s.run}`);
  }
  assert.match(String(wf.jobs.prepare.if ?? ""), /argos\//, "skipped on Argos branches");
});
