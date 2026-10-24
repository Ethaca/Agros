import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { randomBytes } from "node:crypto";
import { createServer, type Server, type Socket } from "node:net";
import type { Config } from "./config.js";
import { RunnerError } from "./errors.js";

/**
 * Container isolation for the target app (SPEC R6).
 *
 *   docker run  --network none   no network at all (loopback only): the app cannot call out or be called into
 *               --read-only      root filesystem is read-only; only /tmp (tmpfs) and the throwaway /app copy are writable
 *               --user <host uid> never root          --cap-drop ALL, no-new-privileges
 *               --pids/--memory/--cpus limits         env: only PORT, target.env, extra (no host environment at all)
 *
 * With no network there is no published port, so the host reaches the app through a loopback TCP forwarder:
 * every connection runs `docker exec -i <name> node -e <pipe to 127.0.0.1:PORT>`. The image therefore needs `node`.
 */

export interface ContainerSpec {
  image: string;
  memory: string;
  cpus: string;
  pids: number;
}

const IMAGE_RE = /^[A-Za-z0-9][A-Za-z0-9._\/:@-]*$/;
const MEMORY_RE = /^\d+(?:\.\d+)?[kKmMgG]?$/;
const CPUS_RE = /^\d+(?:\.\d+)?$/;

export const defaultImage = (): string => `node:${process.versions.node.split(".")[0]}-slim`;

export function containerSpec(cfg: Config): ContainerSpec {
  const c = cfg.target.container;
  const spec = { image: c.image ?? defaultImage(), memory: c.memory, cpus: c.cpus, pids: c.pids };
  // Values go to docker as separate argv entries (no shell), but a leading "-" would still be read as an option.
  if (!IMAGE_RE.test(spec.image)) throw new RunnerError(`target.container.image: invalid image name "${spec.image}"`);
  if (!MEMORY_RE.test(spec.memory)) throw new RunnerError(`target.container.memory: invalid value "${spec.memory}" (e.g. 512m)`);
  if (!CPUS_RE.test(spec.cpus)) throw new RunnerError(`target.container.cpus: invalid value "${spec.cpus}" (e.g. 1)`);
  return spec;
}

const docker = (args: string[], timeoutMs = 30_000) => spawnSync("docker", args, { encoding: "utf8", timeout: timeoutMs });
const firstLine = (s: string): string => s.trim().split("\n")[0] ?? "";

/** Is a docker daemon reachable? Never falls back silently: callers turn `ok: false` into an error. */
export function dockerStatus(): { ok: true } | { ok: false; reason: string } {
  const r = docker(["info", "--format", "{{.ServerVersion}}"], 15_000);
  if (r.error) return { ok: false, reason: `docker CLI not found (${r.error.message})` };
  if (r.status !== 0) return { ok: false, reason: firstLine(r.stderr) || "docker daemon not reachable" };
  return { ok: true };
}

function ensureImage(image: string): void {
  if (docker(["image", "inspect", image]).status === 0) return;
  const pull = docker(["pull", image], 600_000);
  if (pull.status !== 0) {
    throw new RunnerError(`cannot pull image "${image}": ${firstLine(pull.stderr)}. Pull it yourself or set target.container.image.`);
  }
}

export interface ContainerHandle {
  name: string;
  /** Host loopback port that reaches the app inside the container. */
  hostPort: number;
  /** Exit code once the container has stopped, undefined while it runs. */
  exitCode(): number | undefined;
  logs(n?: number): string[];
  stop(): Promise<void>;
}

export interface StartContainerOptions {
  /** Throwaway copy of the target, mounted at /app. */
  workdir: string;
  appPort: number;
  /** Complete environment for the app (PORT, target.env, extras). */
  env: Record<string, string>;
  start: string;
  spec: ContainerSpec;
}

/** Runs inside the container: pipes stdin/stdout to `host:port` (the app's loopback port by default). */
const forwardScript = (port: number, host = "127.0.0.1"): string =>
  `const s=require("net").connect(${port},${JSON.stringify(host)});process.stdin.pipe(s);s.pipe(process.stdout);` +
  `s.on("error",()=>process.exit(1));s.on("close",()=>process.exit(0));`;

export interface Forwarder {
  hostPort: number;
  close(): void;
}

/**
 * Host loopback TCP forwarder: every connection runs `docker exec -i <container> node -e <pipe to host:port>`.
 * `container` must have `node`; `host` is resolved inside it (the JVM path relays through a node sidecar to the app alias).
 */
export async function startForwarder(container: string, port: number, host = "127.0.0.1"): Promise<Forwarder> {
  const execs = new Set<ChildProcess>();
  const server: Server = createServer((sock: Socket) => {
    const p = spawn("docker", ["exec", "-i", container, "node", "-e", forwardScript(port, host)], { stdio: ["pipe", "pipe", "ignore"] });
    execs.add(p);
    sock.pipe(p.stdin!);
    p.stdout!.pipe(sock);
    const done = () => {
      execs.delete(p);
      sock.destroy();
      p.kill("SIGKILL");
    };
    sock.on("close", done);
    sock.on("error", done);
    p.on("exit", done);
    p.stdin!.on("error", () => undefined);
  });
  await new Promise<void>((ok, fail) => {
    server.once("error", fail);
    server.listen(0, "127.0.0.1", ok);
  });
  const hostPort = (server.address() as { port: number }).port;
  return {
    hostPort,
    close: () => {
      server.close();
      for (const p of execs) p.kill("SIGKILL");
    },
  };
}

export async function startContainer(o: StartContainerOptions): Promise<ContainerHandle> {
  const status = dockerStatus();
  if (!status.ok) {
    throw new RunnerError(`container isolation requested but docker is not available: ${status.reason}. Start Docker, or use isolation: process for trusted code only.`);
  }
  ensureImage(o.spec.image);

  const name = `argos-${randomBytes(4).toString("hex")}`;
  const uid = process.getuid?.() ?? 1000;
  const gid = process.getgid?.() ?? 1000;
  const envArgs = Object.entries({ ...o.env, HOME: "/tmp" }).flatMap(([k, v]) => ["-e", `${k}=${v}`]);

  const run = docker([
    "run", "-d", "--init",
    "--name", name, "--label", "argos=1",
    "--network", "none",
    "--read-only", "--tmpfs", "/tmp:rw,nosuid,size=64m",
    "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
    "--pids-limit", String(o.spec.pids), "--memory", o.spec.memory, "--cpus", o.spec.cpus,
    "--user", `${uid}:${gid}`,
    "-v", `${o.workdir}:/app:rw`, "-w", "/app",
    ...envArgs,
    o.spec.image, "sh", "-c", o.start,
  ]);
  if (run.status !== 0) {
    docker(["rm", "-f", name]);
    throw new RunnerError(`docker run failed: ${firstLine(run.stderr)}`);
  }

  const fwd = await startForwarder(name, o.appPort);
  const hostPort = fwd.hostPort;

  const exitCode = (): number | undefined => {
    const r = docker(["inspect", "-f", "{{.State.Status}}|{{.State.ExitCode}}", name], 10_000);
    const [state, code] = r.stdout.trim().split("|");
    if (r.status !== 0) return -1; // container vanished
    return state === "exited" || state === "dead" ? Number(code) : undefined;
  };
  const logs = (n = 50): string[] => {
    const r = docker(["logs", "--tail", String(n), name], 10_000);
    return (r.stdout + r.stderr).split("\n").filter(Boolean).slice(-n);
  };

  let stopped: Promise<void> | undefined;
  const stop = () =>
    (stopped ??= (async () => {
      fwd.close();
      docker(["rm", "-f", name], 30_000);
    })());

  return { name, hostPort, exitCode, logs, stop };
}

/**
 * Remove containers and networks left behind by a crashed run (label argos=1). Returns how many were removed.
 * Dependency cache volumes (label argos-cache=1) are intentionally kept. `label` narrows the sweep (e.g. argos.run=<id>).
 */
export function removeStrayContainers(label = "argos=1"): number {
  const ls = docker(["ps", "-aq", "--filter", `label=${label}`]);
  const ids = ls.stdout.split("\n").filter(Boolean);
  if (ids.length) docker(["rm", "-f", ...ids], 60_000);
  const nets = docker(["network", "ls", "-q", "--filter", `label=${label}`]).stdout.split("\n").filter(Boolean);
  if (nets.length) docker(["network", "rm", ...nets], 60_000);
  return ids.length + nets.length;
}
