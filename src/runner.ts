import { spawn, type ChildProcess } from "node:child_process";
import { cpSync, mkdtempSync, rmSync, mkdirSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve, sep } from "node:path";
import type { Config } from "./config.js";

export const ISOLATION_WARNING = "격리 없음: 신뢰하는 코드에만 실행하세요 (no sandbox: run trusted code only)";

export class RunnerError extends Error {
  constructor(message: string, readonly logTail: string[] = []) {
    super(logTail.length ? `${message}\n--- last ${logTail.length} log lines ---\n${logTail.join("\n")}` : message);
  }
}

export interface RunnerOptions {
  /** Directory the config lives in; target.cwd resolves against it. Default: process.cwd(). */
  baseDir?: string;
  readyTimeoutMs?: number;
  killGraceMs?: number;
  /** Suppress the isolation warning (tests). */
  quiet?: boolean;
  /** Runs on the temp copy after copying and before the app starts (e.g. seeding the DB). */
  beforeStart?: (workdir: string) => void | Promise<void>;
  /** Extra environment variables for the app (e.g. env canaries). Applied after target.env. */
  extraEnv?: Record<string, string>;
}

export interface RunningTarget {
  baseUrl: string;
  port: number;
  /** Temp copy the app runs in. The original directory is never touched. */
  workdir: string;
  /** Last N lines of combined stdout/stderr. */
  logs(n?: number): string[];
  stop(): Promise<void>;
}

const LOG_LIMIT = 500;
const COPY_EXCLUDES = new Set([".git", "out", ".omc"]);

function freePort(): Promise<number> {
  return new Promise((ok, fail) => {
    const srv = createServer();
    srv.once("error", fail);
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address() as { port: number };
      srv.close(() => ok(port));
    });
  });
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Parent env is NOT forwarded: only PATH, HOME (temp), PORT and target.env. */
export function buildEnv(cfg: Config, port: number, home: string, extra: Record<string, string> = {}): Record<string, string> {
  return {
    PATH: process.env.PATH ?? "/usr/bin:/bin",
    HOME: home,
    PORT: String(port),
    ...cfg.target.env,
    ...extra,
  };
}

async function waitReady(url: string, deadline: number, exited: () => boolean): Promise<boolean> {
  while (Date.now() < deadline) {
    if (exited()) return false;
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(2000) });
      if (res.status === 200) return true;
    } catch {
      /* not up yet */
    }
    await sleep(150);
  }
  return false;
}

export async function startTarget(cfg: Config, opts: RunnerOptions = {}): Promise<RunningTarget> {
  const { readyTimeoutMs = 30_000, killGraceMs = 5_000 } = opts;
  if (!opts.quiet) console.error(`⚠️  ${ISOLATION_WARNING}`);

  const srcDir = resolve(opts.baseDir ?? process.cwd(), cfg.target.cwd);
  const root = mkdtempSync(join(tmpdir(), "argos-run-"));
  const workdir = join(root, "app");
  const home = join(root, "home");
  mkdirSync(home);
  const cleanup = () => rmSync(root, { recursive: true, force: true });

  try {
    cpSync(srcDir, workdir, {
      recursive: true,
      filter: (p) => {
        const rel = p === srcDir ? "" : p.slice(srcDir.length + 1);
        return !COPY_EXCLUDES.has(rel.split(sep)[0] ?? "");
      },
    });
  } catch (e) {
    cleanup();
    throw new RunnerError(`cannot copy target dir ${srcDir}: ${(e as Error).message}`);
  }

  try {
    await opts.beforeStart?.(workdir);
  } catch (e) {
    cleanup();
    throw e;
  }

  const port = await freePort();
  const baseUrl = cfg.target.baseUrl.replace(/:0(?=\/|$)/, `:${port}`);
  const lines: string[] = [];
  const push = (chunk: Buffer) => {
    for (const l of chunk.toString().split("\n")) if (l) lines.push(l);
    if (lines.length > LOG_LIMIT) lines.splice(0, lines.length - LOG_LIMIT);
  };

  // detached: own process group, so stop() also reaches grandchildren of `sh -c`.
  const child: ChildProcess = spawn("sh", ["-c", cfg.target.start], {
    cwd: workdir,
    env: buildEnv(cfg, port, home, opts.extraEnv),
    detached: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stdout?.on("data", push);
  child.stderr?.on("data", push);
  let exitCode: number | null | undefined;
  child.once("exit", (code) => (exitCode = code ?? -1));
  child.once("error", (e) => {
    lines.push(`spawn error: ${e.message}`);
    exitCode = -1;
  });

  const signalGroup = (sig: NodeJS.Signals) => {
    try {
      if (child.pid) process.kill(-child.pid, sig);
    } catch {
      /* already gone */
    }
  };

  let stopped: Promise<void> | undefined;
  const stop = () =>
    (stopped ??= (async () => {
      if (exitCode === undefined) {
        signalGroup("SIGTERM");
        const until = Date.now() + killGraceMs;
        while (exitCode === undefined && Date.now() < until) await sleep(50);
        if (exitCode === undefined) signalGroup("SIGKILL");
      }
      signalGroup("SIGKILL"); // sweep stragglers in the group
      cleanup();
    })());

  const ok = await waitReady(baseUrl + cfg.target.readyPath, Date.now() + readyTimeoutMs, () => exitCode !== undefined);
  if (!ok) {
    const reason =
      exitCode !== undefined
        ? `target exited with code ${exitCode} before becoming ready`
        : `target not ready: GET ${cfg.target.readyPath} did not return 200 within ${readyTimeoutMs}ms`;
    const tail = lines.slice(-50);
    await stop();
    throw new RunnerError(reason, tail);
  }

  return { baseUrl, port, workdir, logs: (n = 50) => lines.slice(-n), stop };
}
