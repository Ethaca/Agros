import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { PrError, openFixPr } from "../src/pr.js";
import { gitLab } from "./helpers/git-lab.js";

const FX = resolve("test/fixtures/vuln-app");
const edit = (work: string) => () => {
  const f = join(work, "app.mjs");
  writeFileSync(f, readFileSync(f, "utf8") + "\n// argos patch\n");
  return [f];
};

async function withPath<T>(path: string, fn: () => T): Promise<T> {
  const saved = process.env.PATH;
  process.env.PATH = path;
  try {
    return fn();
  } finally {
    process.env.PATH = saved;
  }
}

test("opens a PR: branch pushed, only the patched file committed, gh called, checkout restored, base untouched", async () => {
  const lab = gitLab(FX);
  const baseSha = lab.git("rev-parse", "main");
  writeFileSync(join(lab.work, "untracked-notes.txt"), "keep me out of the commit");
  const r = await withPath(lab.path, () => openFixPr({ dir: lab.work, apply: edit(lab.work), title: "argos: fix", body: "body text" }));

  assert.equal(r.url, "https://github.com/acme/app/pull/42");
  assert.equal(r.base, "main");
  assert.match(r.branch, /^argos\/fix-[0-9a-f]+-[0-9a-z]+$/);
  assert.equal(lab.git("rev-parse", "--abbrev-ref", "HEAD"), "main", "back on the original branch");
  assert.equal(lab.git("rev-parse", "main"), baseSha, "base branch untouched");
  assert.equal(lab.git("status", "--porcelain", "--untracked-files=no"), "");
  assert.equal(lab.git("show", "--name-only", "--format=", r.branch), "app.mjs", "only the patched file is committed");
  assert.match(lab.git("ls-remote", "--heads", "origin", r.branch), new RegExp(r.commit));
  const [call] = lab.ghCalls();
  assert.match(call!, new RegExp(`^pr create --base main --head ${r.branch.replace("/", "\\/")} --title argos: fix --body-file `));
  assert.equal(lab.ghBody(), "body text", "the PR body reaches gh");
});

test("refuses a dirty working tree and creates nothing", async () => {
  const lab = gitLab(FX);
  writeFileSync(join(lab.work, "app.mjs"), "// local edit\n");
  await withPath(lab.path, () => assert.throws(() => openFixPr({ dir: lab.work, apply: edit(lab.work), title: "t", body: "b" }), /uncommitted changes/));
  assert.equal(lab.git("branch", "--list", "argos/*"), "");
  assert.equal(lab.ghCalls().length, 0);
});

test("not a repo, no remote, detached HEAD without --base: clear errors", async () => {
  const plain = mkdtempSync(join(tmpdir(), "argos-nogit-"));
  assert.throws(() => openFixPr({ dir: plain, apply: () => [], title: "t", body: "b" }), (e: Error) => e instanceof PrError && /not inside a git repository/.test(e.message));

  const lab = gitLab(FX);
  lab.git("remote", "remove", "origin");
  assert.throws(() => openFixPr({ dir: lab.work, apply: edit(lab.work), title: "t", body: "b" }), /remote "origin" is not configured/);

  const lab2 = gitLab(FX);
  lab2.git("checkout", "--quiet", "--detach");
  const saved = process.env.GITHUB_BASE_REF;
  delete process.env.GITHUB_BASE_REF;
  try {
    assert.throws(() => openFixPr({ dir: lab2.work, apply: edit(lab2.work), title: "t", body: "b" }), /pass --base/);
    process.env.GITHUB_BASE_REF = "main";
    const r = await withPath(lab2.path, () => openFixPr({ dir: lab2.work, apply: edit(lab2.work), title: "t", body: "b" }));
    assert.equal(r.base, "main", "$GITHUB_BASE_REF is used in CI");
  } finally {
    if (saved === undefined) delete process.env.GITHUB_BASE_REF;
    else process.env.GITHUB_BASE_REF = saved;
  }
});

test("patches that change nothing: no commit, no push, no leftover branch", async () => {
  const lab = gitLab(FX);
  await withPath(lab.path, () => assert.throws(() => openFixPr({ dir: lab.work, apply: () => [], title: "t", body: "b" }), /changed no files/));
  assert.equal(lab.git("branch", "--list", "argos/*"), "");
  assert.equal(lab.git("rev-parse", "--abbrev-ref", "HEAD"), "main");
  assert.equal(lab.git("ls-remote", "--heads", "origin"), lab.git("ls-remote", "--heads", "origin"));
  assert.ok(!lab.git("ls-remote", "--heads", "origin").includes("argos/"));
});

test("gh failing after the push is a warning, not a lost branch", async () => {
  const lab = gitLab(FX, { ghExit: 1 });
  const r = await withPath(lab.path, () => openFixPr({ dir: lab.work, apply: edit(lab.work), title: "t", body: "b" }));
  assert.equal(r.url, null);
  assert.match(r.warning!, /was pushed but the PR could not be created/);
  assert.match(lab.git("ls-remote", "--heads", "origin", r.branch), /refs\/heads\/argos\/fix/);
  assert.equal(lab.git("rev-parse", "--abbrev-ref", "HEAD"), "main");
});

test("a failing push removes the unpushed local branch", async () => {
  const lab = gitLab(FX);
  lab.git("remote", "set-url", "origin", join(lab.root, "does-not-exist.git"));
  await withPath(lab.path, () => assert.throws(() => openFixPr({ dir: lab.work, apply: edit(lab.work), title: "t", body: "b" }), /git push failed/));
  assert.equal(lab.git("branch", "--list", "argos/*"), "");
  assert.equal(lab.git("rev-parse", "--abbrev-ref", "HEAD"), "main");
});
