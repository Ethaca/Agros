import { execFileSync } from "node:child_process";
import { chmodSync, cpSync, mkdirSync, mkdtempSync, readFileSync, existsSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/** A throwaway git repo with a local bare remote and a fake `gh`, so PR flows never touch GitHub. */
export interface GitLab {
  root: string;
  work: string;
  remote: string;
  /** PATH with the fake gh first; use as `env.PATH` for child processes. */
  path: string;
  /** Arguments of every `gh` call so far, one line per call. */
  ghCalls(): string[];
  /** The PR body as `gh` received it (--body-file is deleted right after the call). */
  ghBody(): string;
  git(...args: string[]): string;
}

export function gitLab(sourceDir: string, opts: { ghExit?: number } = {}): GitLab {
  const root = mkdtempSync(join(tmpdir(), "argos-lab-"));
  const work = join(root, "work");
  const remote = join(root, "remote.git");
  const bin = join(root, "bin");
  mkdirSync(bin);
  const calls = join(root, "gh-calls.txt");
  const bodyCopy = join(root, "gh-body.md");
  writeFileSync(join(bin, "gh"), `#!/bin/sh\necho "$@" >> "${calls}"\nprev=""\nfor a in "$@"; do [ "$prev" = "--body-file" ] && cp "$a" "${bodyCopy}"; prev="$a"; done\n${opts.ghExit ? `echo "gh: boom" >&2\nexit ${opts.ghExit}` : 'echo "https://github.com/acme/app/pull/42"'}\n`);
  chmodSync(join(bin, "gh"), 0o755);

  const run = (cwd: string, ...args: string[]) => execFileSync("git", ["-c", "user.name=t", "-c", "user.email=t@t", ...args], { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
  run(root, "init", "-q", "--bare", remote);
  cpSync(sourceDir, work, { recursive: true });
  writeFileSync(join(work, ".gitignore"), "node_modules/\nout/\n*.db\n");
  run(root, "init", "-q", "-b", "main", work);
  run(work, "add", "-A");
  run(work, "commit", "-qm", "init");
  run(work, "remote", "add", "origin", remote);
  run(work, "push", "-q", "-u", "origin", "main");
  return {
    root, work, remote,
    path: `${bin}:${process.env.PATH}`,
    ghCalls: () => (existsSync(calls) ? readFileSync(calls, "utf8").split("\n").filter(Boolean) : []),
    ghBody: () => (existsSync(bodyCopy) ? readFileSync(bodyCopy, "utf8") : ""),
    git: (...args) => run(work, ...args),
  };
}
