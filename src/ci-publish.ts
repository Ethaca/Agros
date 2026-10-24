import { execFileSync } from "node:child_process";
import { existsSync, lstatSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, sep } from "node:path";
import {
  allowedFileTarget,
  Artifact,
  findSecrets,
  forbiddenPatchPath,
  MARKER_PREFIX,
  patchPaths,
  prMarker,
  TRAILER_RESULT,
  TRAILER_SOURCE,
} from "./ci-artifact.js";

/**
 * `argos ci publish`: the half of CI that holds the write token. It reads ONLY the artifact directory written by
 * `argos ci prepare`, validates it, and creates/updates the Argos branch and PR. It never checks out or runs the
 * customer's code: commits are built in a scratch repository with no working tree (read-tree / hash-object /
 * apply --cached / commit-tree), so no build, hook, or filter from the repository can run here.
 */

export class PublishError extends Error {}

export interface PublishOptions {
  artifactDir: string;
  /** Git remote URL to push to. Default in GitHub Actions: $GITHUB_SERVER_URL/$GITHUB_REPOSITORY.git */
  remote?: string;
  /** owner/name for `gh --repo`. Default: $GITHUB_REPOSITORY. */
  repo?: string;
  env?: NodeJS.ProcessEnv;
  log?: (line: string) => void;
}

export interface PublishResult {
  /** skipped: artifact says nothing to publish · created/updated: PR · unchanged: branch already had this commit's result */
  action: "skipped" | "created" | "updated" | "unchanged";
  branch?: string;
  commit?: string;
  url: string | null;
  warning?: string;
}

export interface ValidatedArtifact {
  artifact: Artifact;
  body: string;
  files: { to: string; path: string }[];
  patchPath?: string;
}

const MAX_BODY = 60_000;
const MAX_FILE = 2_000_000;

function regularFile(dir: string, rel: string, what: string): string {
  const p = resolve(dir, rel);
  if (!p.startsWith(resolve(dir) + sep)) throw new PublishError(`${what}: ${rel} is outside the artifact`);
  if (!existsSync(p)) throw new PublishError(`${what}: ${rel} is missing`);
  const st = lstatSync(p);
  if (!st.isFile()) throw new PublishError(`${what}: ${rel} is not a regular file`);
  if (st.size > MAX_FILE) throw new PublishError(`${what}: ${rel} is too large`);
  return p;
}

/** Everything publish checks before touching git. Throws PublishError listing what is wrong. */
export function validateArtifact(dir: string): ValidatedArtifact {
  const root = resolve(dir);
  const raw = readFileSync(regularFile(root, "pr.json", "pr.json"), "utf8");
  let json: unknown;
  try {
    json = JSON.parse(raw);
  } catch (e) {
    throw new PublishError(`pr.json is not valid JSON: ${(e as Error).message}`);
  }
  const parsed = Artifact.safeParse(json);
  if (!parsed.success) {
    const i = parsed.error.issues[0]!;
    throw new PublishError(`pr.json: ${i.path.map(String).join(".") || "(root)"}: ${i.message}`);
  }
  const artifact = parsed.data;
  if (artifact.status === "skipped") return { artifact, body: "", files: [] };
  if (artifact.branch === artifact.base) throw new PublishError("pr.json: branch and base are the same");

  const problems: string[] = [];
  const bodyPath = regularFile(root, artifact.body, "body");
  const body = readFileSync(bodyPath, "utf8");
  if (body.length > MAX_BODY) problems.push(`body is longer than ${MAX_BODY} characters`);
  const texts: { what: string; text: string }[] = [{ what: "title", text: artifact.title }, { what: "body", text: body }];

  const files = artifact.files.map((f) => {
    if (!f.from.startsWith("files/")) problems.push(`${f.from}: files must come from files/`);
    if (!allowedFileTarget(f.to)) problems.push(`${f.to}: publish only writes argos.config.yaml and .argos/*.md|json`);
    const path = regularFile(root, f.from, "file");
    texts.push({ what: f.to, text: readFileSync(path, "utf8") });
    return { to: f.to, path };
  });
  if (new Set(files.map((f) => f.to)).size !== files.length) problems.push("two files have the same destination");

  let patchPath: string | undefined;
  if (artifact.patch) {
    patchPath = regularFile(root, artifact.patch, "patch");
    const patch = readFileSync(patchPath, "utf8");
    const { paths, problems: structural } = patchPaths(patch);
    problems.push(...structural.map((s) => `fix.patch: ${s}`));
    if (!paths.length) problems.push("fix.patch: no file in the patch");
    for (const p of paths) {
      const why = forbiddenPatchPath(p);
      if (why) problems.push(`fix.patch ${why}: ${p}`);
    }
    texts.push({ what: "fix.patch", text: patch });
  }

  for (const t of texts) {
    for (const s of findSecrets(t.text)) problems.push(`${t.what} contains a ${s}`);
    if (t.text.includes(MARKER_PREFIX)) problems.push(`${t.what} contains an Argos PR marker (only publish writes it)`);
  }
  if (problems.length) throw new PublishError(`artifact rejected:\n  - ${[...new Set(problems)].join("\n  - ")}`);
  return { artifact, body, files, patchPath };
}

function run(cmd: string, args: string[], cwd: string, env: NodeJS.ProcessEnv): string {
  try {
    return execFileSync(cmd, args, { cwd, env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
  } catch (e) {
    const err = e as { stderr?: Buffer | string; message: string; code?: string };
    if (err.code === "ENOENT") throw new PublishError(`${cmd} not found`);
    const detail = (err.stderr?.toString() || err.message).trim().split("\n").slice(-3).join(" ");
    throw new PublishError(`${cmd} ${args.find((a) => !a.startsWith("-")) ?? ""} failed: ${detail}`);
  }
}

export function runPublish(opts: PublishOptions): PublishResult {
  const log = opts.log ?? ((l: string) => console.log(l));
  const env = opts.env ?? process.env;
  const v = validateArtifact(opts.artifactDir);
  const a = v.artifact;
  if (a.status === "skipped") {
    log(`nothing to publish: ${a.skip ?? "skipped"}`);
    return { action: "skipped", url: null };
  }
  const repo = opts.repo ?? env.GITHUB_REPOSITORY;
  const remote = opts.remote ?? (env.GITHUB_REPOSITORY ? `${env.GITHUB_SERVER_URL ?? "https://github.com"}/${env.GITHUB_REPOSITORY}.git` : undefined);
  if (!remote) throw new PublishError("no remote: pass --remote <url> (or run in GitHub Actions, where $GITHUB_REPOSITORY is set)");

  const tmp = mkdtempSync(join(tmpdir(), "argos-publish-"));
  const genv: NodeJS.ProcessEnv = {
    ...env,
    GIT_TERMINAL_PROMPT: "0",
    GIT_INDEX_FILE: join(tmp, "argos.index"),
    GIT_AUTHOR_NAME: env.GIT_AUTHOR_NAME ?? "argos",
    GIT_AUTHOR_EMAIL: env.GIT_AUTHOR_EMAIL ?? "argos@users.noreply.github.com",
    GIT_COMMITTER_NAME: env.GIT_COMMITTER_NAME ?? "argos",
    GIT_COMMITTER_EMAIL: env.GIT_COMMITTER_EMAIL ?? "argos@users.noreply.github.com",
  };
  const g = (...args: string[]) => run("git", args, tmp, genv);
  const tg = (...args: string[]): string | undefined => {
    try {
      return g(...args);
    } catch {
      return undefined;
    }
  };
  const gh = (...args: string[]) => run("gh", [...args, ...(repo ? ["--repo", repo] : [])], tmp, env);

  try {
    g("init", "-q");
    g("remote", "add", "origin", remote);
    // Objects only: nothing of the customer's repository is written to disk as files.
    if (tg("fetch", "-q", "--no-tags", "--depth=1", "origin", a.headSha) === undefined) {
      tg("fetch", "-q", "--no-tags", "origin", `refs/heads/${a.base}`);
    }
    if (tg("cat-file", "-e", `${a.headSha}^{commit}`) === undefined) throw new PublishError(`commit ${a.headSha} was not found on the remote`);

    const existing = tg("ls-remote", "--heads", "origin", `refs/heads/${a.branch}`)?.split(/\s+/)[0] || undefined;
    let upToDate = false;
    if (existing) {
      g("fetch", "-q", "--no-tags", "--depth=1", "origin", `refs/heads/${a.branch}`);
      const msg = g("log", "-1", "--format=%B", existing);
      if (!new RegExp(`^${TRAILER_RESULT}:`, "m").test(msg)) {
        const warning = `${a.branch} has a commit Argos did not write (someone pushed to it): not overwriting it`;
        log(`warning: ${warning}`);
        return { action: "unchanged", branch: a.branch, url: null, warning };
      }
      upToDate = new RegExp(`^${TRAILER_SOURCE}: ${a.headSha}$`, "m").test(msg);
    }

    let commit = existing;
    if (upToDate) log(`${a.branch} already has the Argos result for ${a.headSha.slice(0, 7)}: not pushing again`);
    else {
      const trailers = `\n\n${TRAILER_RESULT}: ${a.status}\n${TRAILER_SOURCE}: ${a.headSha}\n`;
      g("read-tree", a.headSha);
      for (const f of v.files) {
        const blob = g("hash-object", "-w", "--no-filters", "--", f.path);
        g("update-index", "--add", "--cacheinfo", `100644,${blob},${f.to}`);
      }
      const msgFile = join(tmp, "msg.txt");
      writeFileSync(msgFile, `argos: 점검 보고서${v.files.some((f) => f.to.endsWith("argos.config.yaml")) ? "와 설정 초안" : ""}${trailers}`);
      commit = g("commit-tree", g("write-tree"), "-p", a.headSha, "-F", msgFile);
      if (v.patchPath) {
        g("apply", "--cached", "--whitespace=nowarn", v.patchPath);
        const tree = g("write-tree");
        if (tree === g("rev-parse", `${commit}^{tree}`)) throw new PublishError("fix.patch changed nothing");
        writeFileSync(msgFile, `argos: 검증된 수정 (${a.patchFiles.join(", ")})${trailers}`);
        commit = g("commit-tree", tree, "-p", commit, "-F", msgFile);
      }
      g("push", "-q", `--force-with-lease=refs/heads/${a.branch}:${existing ?? ""}`, "origin", `${commit}:refs/heads/${a.branch}`);
      log(`pushed ${a.branch} (${commit.slice(0, 7)} on ${a.headSha.slice(0, 7)})`);
    }

    // ---- PR: update ours (found by branch + hidden marker) instead of opening another
    const marker = prMarker(a.branch);
    const bodyFile = join(tmp, "body.md");
    writeFileSync(bodyFile, `${v.body.trimEnd()}\n\n${marker}\n`);
    try {
      const list = JSON.parse(gh("pr", "list", "--head", a.branch, "--state", "open", "--json", "number,url,body") || "[]") as { number: number; url: string; body?: string }[];
      const mine = list.find((p) => p.body?.includes(marker));
      if (mine) {
        if (!upToDate) gh("pr", "edit", String(mine.number), "--title", a.title, "--body-file", bodyFile);
        log(`${upToDate ? "unchanged" : "updated"} ${mine.url}`);
        return { action: upToDate ? "unchanged" : "updated", branch: a.branch, commit, url: mine.url };
      }
      if (list.length) {
        const warning = `an open PR for ${a.branch} exists without the Argos marker (${list[0]!.url}): left as is`;
        log(`warning: ${warning}`);
        return { action: "unchanged", branch: a.branch, commit, url: list[0]!.url, warning };
      }
      const url = gh("pr", "create", "--base", a.base, "--head", a.branch, "--title", a.title, "--body-file", bodyFile).split("\n").filter(Boolean).pop() ?? null;
      log(`opened ${url}`);
      return { action: "created", branch: a.branch, commit, url };
    } catch (e) {
      const warning = `branch ${a.branch} is pushed but the PR could not be created or updated (${(e as Error).message}). Open it manually.`;
      log(`warning: ${warning}`);
      return { action: upToDate ? "unchanged" : "created", branch: a.branch, commit, url: null, warning };
    }
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}
