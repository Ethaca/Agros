import { spawn, spawnSync } from "node:child_process";
import { RunnerError } from "../errors.js";

/**
 * docker argv builders for the JVM stack (pure: unit-tested without docker) and small process helpers.
 * Environment values never go on argv: containers get `-e NAME` and the value is passed through the docker CLI's
 * own environment, so secrets (DB password) do not show up in `ps` on the host.
 */

export const HARDEN = ["--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges"];

export interface Limits {
  memory: string;
  cpus: string;
  pids: number;
}

const limitArgs = (l: Limits) => ["--pids-limit", String(l.pids), "--memory", l.memory, "--cpus", l.cpus];
const labelArgs = (runId: string) => ["--label", "argos=1", "--label", `argos.run=${runId}`];
const envNameArgs = (env: Record<string, string>) => Object.keys(env).flatMap((k) => ["-e", k]);

export function networkCreateArgs(name: string, runId: string, internal: boolean): string[] {
  return ["network", "create", ...(internal ? ["--internal"] : []), ...labelArgs(runId), name];
}

export interface PostgresRun {
  name: string;
  runId: string;
  network: string;
  alias: string;
  image: string;
  /** POSTGRES_USER/DB/PASSWORD/PGDATA, passed by name. */
  env: Record<string, string>;
}

/** Trusted image, but still: non-root (image's postgres user), read-only root, data on tmpfs, internal network only. */
export function postgresRunArgs(o: PostgresRun): string[] {
  return [
    "run", "-d", "--name", o.name, ...labelArgs(o.runId),
    "--network", o.network, "--network-alias", o.alias,
    ...HARDEN, "--user", "postgres",
    "--tmpfs", "/var/lib/postgresql/data:rw,nosuid,mode=1777,size=512m",
    "--tmpfs", "/var/run/postgresql:rw,nosuid,mode=1777,size=8m",
    "--tmpfs", "/tmp:rw,nosuid,size=64m",
    ...limitArgs({ memory: "512m", cpus: "1", pids: 256 }),
    ...envNameArgs(o.env),
    o.image,
  ];
}

export interface SidecarRun {
  name: string;
  runId: string;
  network: string;
  alias: string;
  image: string;
  env: Record<string, string>;
  script: string;
}

export function sidecarRunArgs(o: SidecarRun): string[] {
  return [
    "run", "-d", "--init", "--name", o.name, ...labelArgs(o.runId),
    "--network", o.network, "--network-alias", o.alias,
    ...HARDEN, "--user", "1000:1000", "--tmpfs", "/tmp:rw,nosuid,size=16m",
    ...limitArgs({ memory: "128m", cpus: "0.5", pids: 128 }),
    ...envNameArgs(o.env),
    "--entrypoint", "node", o.image, "-e", o.script,
  ];
}

export interface AppRun {
  name: string;
  runId: string;
  network: string;
  alias: string;
  image: string;
  /** Throwaway copy (already realpath'd), mounted at /app. */
  workdir: string;
  env: Record<string, string>;
  start: string;
  limits: Limits;
  user: string;
}

/** Customer code: no docker socket, no host env, internal network only, no published port. */
export function appRunArgs(o: AppRun): string[] {
  return [
    "run", "-d", "--init", "--name", o.name, ...labelArgs(o.runId),
    "--network", o.network, "--network-alias", o.alias,
    ...HARDEN, "--tmpfs", "/tmp:rw,exec,nosuid,size=256m",
    ...limitArgs(o.limits), "--user", o.user,
    "-v", `${o.workdir}:/app:rw`, "-w", "/app",
    ...envNameArgs(o.env),
    o.image, "sh", "-c", o.start,
  ];
}

export interface BuildRun {
  name: string;
  runId: string;
  network: string;
  image: string;
  workdir: string;
  /** Per-run HOME (holds the generated Maven settings.xml). */
  home: string;
  cacheVolume: string;
  env: Record<string, string>;
  command: string;
  limits: Limits;
  user: string;
}

/** Customer build (Maven/Gradle + plugins are customer code): same hardening, only workdir + home + cache mounted. */
export function buildRunArgs(o: BuildRun): string[] {
  return [
    "run", "--name", o.name, ...labelArgs(o.runId),
    "--network", o.network,
    ...HARDEN, "--tmpfs", "/tmp:rw,exec,nosuid,size=1g",
    ...limitArgs(o.limits), "--user", o.user,
    "-v", `${o.workdir}:/app:rw`, "-v", `${o.home}:/argos-home:rw`, "-v", `${o.cacheVolume}:/cache:rw`, "-w", "/app",
    ...envNameArgs(o.env),
    "--entrypoint", "sh", o.image, "-c", o.command,
  ];
}

export interface DockerResult {
  status: number | null;
  stdout: string;
  stderr: string;
  error?: Error;
}

export function dockerSync(args: string[], o: { timeoutMs?: number; env?: Record<string, string>; input?: string } = {}): DockerResult {
  const r = spawnSync("docker", args, {
    encoding: "utf8",
    timeout: o.timeoutMs ?? 30_000,
    env: o.env ? { ...process.env, ...o.env } : process.env,
    input: o.input,
    maxBuffer: 64 * 1024 * 1024,
  });
  return { status: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "", error: r.error };
}

/**
 * Async docker call; `onLine` sees combined output. Resolves with status (null on timeout/abort).
 * With `cancel` (e.g. `docker rm -f <name>` for an attached `docker run`), timeout/abort calls it every 500ms until the
 * CLI exits instead of killing the CLI: killing it mid-create would let the daemon finish creating an orphan container.
 */
export function dockerAsync(
  args: string[],
  o: { timeoutMs: number; signal?: AbortSignal; env?: Record<string, string>; input?: string; onLine?: (l: string) => void; cancel?: () => void },
): Promise<DockerResult & { timedOut: boolean; aborted: boolean }> {
  return new Promise((done) => {
    const p = spawn("docker", args, { env: o.env ? { ...process.env, ...o.env } : process.env, stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    let aborted = false;
    const feed = (which: "out" | "err") => (chunk: Buffer) => {
      const s = chunk.toString();
      if (which === "out") stdout += s;
      else stderr += s;
      if (stdout.length > 8e6) stdout = stdout.slice(-4e6);
      if (stderr.length > 8e6) stderr = stderr.slice(-4e6);
      if (o.onLine) for (const l of s.split("\n")) if (l) o.onLine(l);
    };
    p.stdout.on("data", feed("out"));
    p.stderr.on("data", feed("err"));
    p.stdin.on("error", () => undefined);
    p.stdin.end(o.input ?? "");
    let retry: NodeJS.Timeout | undefined;
    let hardKill: NodeJS.Timeout | undefined;
    const stop = () => {
      if (!o.cancel) return void p.kill("SIGKILL");
      o.cancel();
      retry ??= setInterval(o.cancel, 500);
      hardKill ??= setTimeout(() => p.kill("SIGKILL"), 30_000);
    };
    const timer = setTimeout(() => {
      timedOut = true;
      stop();
    }, o.timeoutMs);
    const onAbort = () => {
      aborted = true;
      stop();
    };
    const settle = () => {
      clearTimeout(timer);
      clearInterval(retry);
      clearTimeout(hardKill);
      o.signal?.removeEventListener("abort", onAbort);
    };
    if (o.signal?.aborted) onAbort();
    else o.signal?.addEventListener("abort", onAbort, { once: true });
    p.on("error", (error) => {
      settle();
      done({ status: null, stdout, stderr, error, timedOut, aborted });
    });
    p.on("close", (code) => {
      settle();
      done({ status: timedOut || aborted ? null : code, stdout, stderr, timedOut, aborted });
    });
  });
}

const firstLine = (s: string): string => s.trim().split("\n")[0] ?? "";

/** Pull if missing; one retry (pulls are the typical transient infra failure). */
export function ensureImageRetry(image: string, what: string): void {
  if (dockerSync(["image", "inspect", image]).status === 0) return;
  let last = "";
  for (let attempt = 0; attempt < 2; attempt++) {
    const pull = dockerSync(["pull", image], { timeoutMs: 600_000 });
    if (pull.status === 0) return;
    last = firstLine(pull.stderr) || pull.error?.message || "unknown error";
  }
  throw new RunnerError(`cannot pull ${what} image "${image}": ${last}`);
}

/** "512m" / "2g" / "1048576" -> bytes. */
export function memBytes(m: string): number {
  const r = /^(\d+(?:\.\d+)?)([kKmMgG]?)$/.exec(m);
  if (!r) return NaN;
  const mult = { "": 1, k: 1024, m: 1024 ** 2, g: 1024 ** 3 }[r[2]!.toLowerCase() as "" | "k" | "m" | "g"];
  return Number(r[1]) * mult;
}
