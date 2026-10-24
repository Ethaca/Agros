import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/**
 * Open a pull request with the verified patches. This is the only outward-facing step of `argos ci`, so it is
 * opt-in (`--pr`) and defensive: it refuses to run on a dirty working tree, commits only the files the patches
 * touched, and always returns the checkout to where it started.
 */

export class PrError extends Error {}

export interface PrOptions {
  /** Any directory inside the git repository. */
  dir: string;
  /** Applies the patches on the new branch and returns the absolute paths it changed. */
  apply: () => string[];
  title: string;
  body: string;
  /** Branch the PR targets. Default: $GITHUB_BASE_REF, else the branch that is checked out. */
  base?: string;
  remote?: string;
  branchPrefix?: string;
  /** Commit message. Default: the title. */
  message?: string;
}

export interface PrResult {
  branch: string;
  base: string;
  commit: string;
  /** null when `gh` failed or is missing: the branch is pushed, open the PR by hand. */
  url: string | null;
  warning?: string;
}

function run(cmd: string, args: string[], cwd: string, env: NodeJS.ProcessEnv = process.env): string {
  try {
    return execFileSync(cmd, args, { cwd, env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
  } catch (e) {
    const err = e as { stderr?: Buffer | string; message: string; code?: string };
    if (err.code === "ENOENT") throw new PrError(`${cmd} not found`);
    const detail = (err.stderr?.toString() || err.message).trim().split("\n").slice(-3).join(" ");
    throw new PrError(`${cmd} ${args[0]} failed: ${detail}`);
  }
}

const tryGit = (cwd: string, args: string[]): string | undefined => {
  try {
    return run("git", args, cwd);
  } catch {
    return undefined;
  }
};

export function openFixPr(o: PrOptions): PrResult {
  const remote = o.remote ?? "origin";
  const root = tryGit(o.dir, ["rev-parse", "--show-toplevel"]);
  if (!root) throw new PrError(`${o.dir} is not inside a git repository`);

  if (run("git", ["status", "--porcelain", "--untracked-files=no"], root)) {
    throw new PrError("the working tree has uncommitted changes to tracked files: commit or stash them first (argos only commits its own patches)");
  }
  const head = run("git", ["rev-parse", "--abbrev-ref", "HEAD"], root);
  const original = head === "HEAD" ? run("git", ["rev-parse", "HEAD"], root) : head;
  const base = o.base ?? (process.env.GITHUB_BASE_REF || undefined) ?? (head !== "HEAD" ? head : undefined);
  if (!base) throw new PrError("cannot tell which branch the PR should target (detached HEAD): pass --base <branch>");
  if (!tryGit(root, ["remote", "get-url", remote])) throw new PrError(`git remote "${remote}" is not configured`);

  const branch = `${o.branchPrefix ?? "argos/fix"}-${run("git", ["rev-parse", "--short", "HEAD"], root)}-${Date.now().toString(36)}`;
  const identity: NodeJS.ProcessEnv = { ...process.env };
  if (!tryGit(root, ["config", "user.name"])) Object.assign(identity, { GIT_AUTHOR_NAME: "argos", GIT_COMMITTER_NAME: "argos" });
  if (!tryGit(root, ["config", "user.email"])) Object.assign(identity, { GIT_AUTHOR_EMAIL: "argos@users.noreply.github.com", GIT_COMMITTER_EMAIL: "argos@users.noreply.github.com" });

  let created = false;
  const tmp = mkdtempSync(join(tmpdir(), "argos-pr-"));
  try {
    run("git", ["checkout", "-b", branch], root);
    created = true;
    const changed = o.apply();
    if (!changed.length) throw new PrError("the patches changed no files, nothing to commit");
    run("git", ["add", "--", ...changed], root);
    if (!tryGit(root, ["diff", "--cached", "--name-only"])) throw new PrError("the patches produced no diff, nothing to commit");
    run("git", ["commit", "-m", o.message ?? o.title], root, identity);
    const commit = run("git", ["rev-parse", "HEAD"], root);
    run("git", ["push", "-u", remote, branch], root);

    const bodyFile = join(tmp, "body.md");
    writeFileSync(bodyFile, o.body);
    let url: string | null = null;
    let warning: string | undefined;
    try {
      const out = run("gh", ["pr", "create", "--base", base, "--head", branch, "--title", o.title, "--body-file", bodyFile], root);
      url = out.split("\n").filter(Boolean).pop() ?? null;
    } catch (e) {
      warning = `branch ${branch} was pushed but the PR could not be created (${(e as Error).message}). Open it manually.`;
    }
    return { branch, base, commit, url, ...(warning ? { warning } : {}) };
  } catch (e) {
    // nothing was pushed if we got here before the push: drop the empty local branch
    if (created) {
      tryGit(root, ["checkout", "--quiet", original]);
      if (!tryGit(root, ["ls-remote", "--heads", remote, branch])) tryGit(root, ["branch", "-D", branch]);
    }
    throw e;
  } finally {
    tryGit(root, ["checkout", "--quiet", original]);
    rmSync(tmp, { recursive: true, force: true });
  }
}
