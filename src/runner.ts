import { spawn, type ChildProcess } from "node:child_process";
import { cpSync, mkdtempSync, rmSync, mkdirSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve, sep } from "node:path";
import { realpathSync } from "node:fs";
import type { Config } from "./config.js";
import { containerSpec, startContainer } from "./container.js";
import { RunnerError } from "./errors.js";
import { launchJvm } from "./jvm/launch.js";
import { redactLines } from "./jvm/redact.js";
import { runtimeOf, type Runtime } from "./jvm/settings.js";
import type { StackExtras } from "./stack.js";

export { RunnerError };

export const ISOLATION_WARNING = "격리 없음: 신뢰하는 코드에만 실행하세요 (no sandbox: run trusted code only)";

export type Isolation = "process" | "container";

export interface RunnerOptions {
  /** Directory the config lives in; target.cwd resolves against it. Default: process.cwd(). */
  baseDir?: string;
  /** Readiness budget. Default 30s (node) / 180s (jvm). */
  readyTimeoutMs?: number;
  /** Build budget for the jvm runtime (separate from readiness and scan budgets). Default 15 min. */
  prepareTimeoutMs?: number;
  /**
   * Ready = the readiness path answers with any status < 500 (e.g. 401/403 from a secured app), not only 200.
   * Default false (node) / true (jvm: Spring Boot's web server only accepts connections after the context, incl.
   * Flyway/Liquibase migrations, has started, so any HTTP answer means the app is up).
   */
  readyAnyStatus?: boolean;
  killGraceMs?: number;
  /** Suppress the isolation warning (tests). */
  quiet?: boolean;
  /** Runs on the temp copy after copying and before the app starts (e.g. seeding the DB). */
  beforeStart?: (workdir: string) => void | Promise<void>;
  /** Extra environment variables for the app (e.g. env canaries). Applied after target.env. */
  extraEnv?: Record<string, string>;
  /** Overrides cfg.target.isolation. The jvm runtime always runs in containers. */
  isolation?: Isolation;
  /** Runs once the app is ready (e.g. seeding through `target.db` after the app applied its migrations). A throw stops the target. */
  afterReady?: (target: RunningTarget) => void | Promise<void>;
  /** Aborting stops the build / readiness wait and cleans everything up. */
  signal?: AbortSignal;
}

export interface RunningTarget extends StackExtras {
  isolation: Isolation;
  /** "node" unless target.runtime is "jvm". */
  runtime?: Runtime;
  /** jvm: per-run id; all of the run's containers and networks carry the label argos.run=<id>. */
  runId?: string;
  /** Container image when isolation is "container". */
  image: string | null;
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

async function waitReady(url: string, deadline: number, exited: () => boolean, anyStatus = false, intervalMs = 150, signal?: AbortSignal): Promise<boolean> {
  while (Date.now() < deadline) {
    if (signal?.aborted || exited()) return false;
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(2000) });
      if (res.status === 200 || (anyStatus && res.status < 500)) return true;
    } catch {
      /* not up yet */
    }
    await sleep(intervalMs);
  }
  return false;
}

/** What the two launch modes have in common once the app is started. */
interface Launched {
  baseUrl: string;
  exited(): boolean;
  exitCode(): number | null | undefined;
  logs(n?: number): string[];
  /** Stops the app. The temp copy is removed by the caller. */
  stop(): Promise<void>;
}

function launchProcess(cfg: Config, opts: RunnerOptions, workdir: string, home: string, port: number, killGraceMs: number): Launched {
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
  return {
    baseUrl: cfg.target.baseUrl.replace(/:0(?=\/|$)/, `:${port}`),
    exited: () => exitCode !== undefined,
    exitCode: () => exitCode,
    logs: (n = 50) => lines.slice(-n),
    stop: async () => {
      if (exitCode === undefined) {
        signalGroup("SIGTERM");
        const until = Date.now() + killGraceMs;
        while (exitCode === undefined && Date.now() < until) await sleep(50);
        if (exitCode === undefined) signalGroup("SIGKILL");
      }
      signalGroup("SIGKILL"); // sweep stragglers in the group
    },
  };
}

async function launchContainer(cfg: Config, opts: RunnerOptions, workdir: string, port: number): Promise<Launched & { image: string }> {
  const spec = containerSpec(cfg);
  const c = await startContainer({
    // realpath: on macOS the temp dir is a symlink (/var -> /private/var) that Docker's file sharing does not follow
    workdir: realpathSync(workdir),
    appPort: port,
    env: { PORT: String(port), ...cfg.target.env, ...opts.extraEnv },
    start: cfg.target.start,
    spec,
  });
  return {
    image: spec.image,
    baseUrl: cfg.target.baseUrl.replace(/:0(?=\/|$)/, `:${c.hostPort}`),
    exited: () => c.exitCode() !== undefined,
    exitCode: () => c.exitCode(),
    logs: (n = 50) => c.logs(n),
    stop: () => c.stop(),
  };
}

export async function startTarget(cfg: Config, opts: RunnerOptions = {}): Promise<RunningTarget> {
  if (runtimeOf(cfg) === "jvm") return startJvmTarget(cfg, opts);
  const { readyTimeoutMs = 30_000, killGraceMs = 5_000 } = opts;
  const isolation: Isolation = opts.isolation ?? cfg.target.isolation;
  if (!opts.quiet) {
    console.error(
      isolation === "container"
        ? `🔒 container isolation: ${containerSpec(cfg).image}, no network, read-only root filesystem, non-root, resource limits`
        : `⚠️  ${ISOLATION_WARNING}`,
    );
  }

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
  let launched: Launched & { image?: string };
  try {
    launched = isolation === "container" ? await launchContainer(cfg, opts, workdir, port) : launchProcess(cfg, opts, workdir, home, port, killGraceMs);
  } catch (e) {
    cleanup();
    throw e;
  }

  let stopped: Promise<void> | undefined;
  const stop = () =>
    (stopped ??= (async () => {
      await launched.stop();
      cleanup();
    })());

  const ok = await waitReady(launched.baseUrl + cfg.target.readyPath, Date.now() + readyTimeoutMs, launched.exited);
  if (!ok) {
    const code = launched.exitCode();
    const reason =
      code !== undefined
        ? `target exited with code ${code} before becoming ready`
        : `target not ready: GET ${cfg.target.readyPath} did not return 200 within ${readyTimeoutMs}ms`;
    const tail = launched.logs(50);
    await stop();
    throw new RunnerError(reason, tail);
  }

  const target: RunningTarget = {
    isolation,
    image: launched.image ?? null,
    baseUrl: launched.baseUrl,
    port: Number(new URL(launched.baseUrl).port),
    workdir,
    logs: launched.logs,
    stop,
  };
  if (opts.afterReady) {
    try {
      await opts.afterReady(target);
    } catch (e) {
      await stop();
      throw e;
    }
  }
  return target;
}

function copyTarget(srcDir: string, workdir: string): void {
  cpSync(srcDir, workdir, {
    recursive: true,
    filter: (p) => {
      const rel = p === srcDir ? "" : p.slice(srcDir.length + 1);
      return !COPY_EXCLUDES.has(rel.split(sep)[0] ?? "");
    },
  });
}

/** JVM/Spring: always containerized (build + app + postgres + issuer on a per-run internal network); never the host. */
async function startJvmTarget(cfg: Config, opts: RunnerOptions): Promise<RunningTarget> {
  const { readyTimeoutMs = 180_000, prepareTimeoutMs = 15 * 60_000, readyAnyStatus = true } = opts;
  if (opts.isolation === "process") throw new RunnerError("target.runtime jvm runs only with container isolation (never on the host)");
  if (!opts.quiet) console.error("🔒 jvm runtime: isolated build, internal network (app + postgres + test issuer), read-only root, non-root, resource limits");

  const srcDir = resolve(opts.baseDir ?? process.cwd(), cfg.target.cwd);
  const root = mkdtempSync(join(tmpdir(), "argos-run-"));
  const workdir = join(root, "app");
  const cleanup = () => rmSync(root, { recursive: true, force: true });
  try {
    copyTarget(srcDir, workdir);
  } catch (e) {
    cleanup();
    throw new RunnerError(`cannot copy target dir ${srcDir}: ${(e as Error).message}`);
  }

  let launched: Awaited<ReturnType<typeof launchJvm>>;
  try {
    await opts.beforeStart?.(workdir);
    launched = await launchJvm(cfg, { workdir, root, extraEnv: opts.extraEnv, prepareTimeoutMs, signal: opts.signal });
  } catch (e) {
    cleanup();
    throw e;
  }

  let stopped: Promise<void> | undefined;
  const stop = () =>
    (stopped ??= (async () => {
      await launched.stop();
      cleanup();
    })());

  const ok = await waitReady(launched.baseUrl + cfg.target.readyPath, Date.now() + readyTimeoutMs, launched.exited, readyAnyStatus, 500, opts.signal);
  if (!ok) {
    const code = launched.exitCode();
    const reason = opts.signal?.aborted
      ? "aborted while waiting for the target"
      : code !== undefined
        ? `target exited with code ${code} before becoming ready`
        : `target not ready: GET ${cfg.target.readyPath} did not return ${readyAnyStatus ? "a non-5xx status" : "200"} within ${readyTimeoutMs}ms`;
    const tail = redactLines(launched.logs(80), launched.secrets());
    await stop();
    throw new RunnerError(`${reason} [argos run ${launched.runId}]`, tail);
  }

  const target: RunningTarget = {
    isolation: "container",
    runtime: "jvm",
    runId: launched.runId,
    image: launched.image,
    baseUrl: launched.baseUrl,
    port: Number(new URL(launched.baseUrl).port),
    workdir,
    logs: launched.logs,
    stop,
    ...launched.extras,
    notes: [...(launched.extras.notes ?? []), `readiness: GET ${cfg.target.readyPath} ${readyAnyStatus ? "answered with a non-5xx status" : "returned 200"}`],
  };
  try {
    await opts.afterReady?.(target);
  } catch (e) {
    await stop();
    throw e instanceof RunnerError ? e : new RunnerError(`afterReady failed: ${redactLines([(e as Error).message], launched.secrets())[0]}`);
  }
  return target;
}
