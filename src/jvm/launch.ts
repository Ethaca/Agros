import { randomBytes } from "node:crypto";
import { mkdirSync, writeFileSync, realpathSync } from "node:fs";
import { join } from "node:path";
import type { Config } from "../config.js";
import { defaultImage, dockerStatus, startForwarder, type Forwarder } from "../container.js";
import { RunnerError } from "../errors.js";
import type { StackExtras } from "../stack.js";
import { dbHandle } from "./db.js";
import { defaultAppImage, defaultBuildCommand, defaultBuildImage, detectJvmProject, type JvmProject } from "./detect.js";
import {
  appRunArgs,
  buildRunArgs,
  dockerAsync,
  dockerSync,
  ensureImageRetry,
  memBytes,
  networkCreateArgs,
  postgresRunArgs,
  sidecarRunArgs,
  type Limits,
} from "./docker.js";
import { createIssuerKeys, issuerHandle } from "./jwt.js";
import { redact, redactLines } from "./redact.js";
import { GRADLE_HOSTS, ISSUER_PORT, MAVEN_HOSTS, PROXY_PORT, SIDECAR_READY, issuerScript, proxyScript } from "./sidecar.js";
import { jvmSettings, type JvmSettings } from "./settings.js";

/**
 * Spring Boot / JVM target in strict isolation (docs/SPRING_SUPPORT_PLAN.md §2-§4):
 *
 *   build    customer build (target.build or detected mvn/gradle) in a hardened build container on an INTERNAL build
 *            network whose only peer is an allowlisting CONNECT proxy (trusted node sidecar, also on a per-run egress
 *            network). Dependencies land in a named cache volume per tool (label argos-cache=1, kept between runs).
 *   run      per-run internal network (no gateway: no internet, no host) with
 *              argos-db      postgres (random password, tmpfs data)          [if cfg.db]
 *              argos-issuer  node sidecar: JWKS/OIDC metadata + host relay   (the app image needs no node)
 *              argos-app     the customer app, hardened, Argos-injected env only, SERVER_PORT=8080
 *   host     reaches the app only through `docker exec -i argos-issuer node -e <connect argos-app:8080>`.
 */

export const APP_PORT = 8080;
export const DB_USER = "argos";
export const DB_NAME = "argos";
const ALIAS = { db: "argos-db", issuer: "argos-issuer", app: "argos-app", proxy: "argos-proxy" };
export const ISSUER_URL = `http://${ALIAS.issuer}:${ISSUER_PORT}`;

export const BUILD_LIMITS: Limits = { memory: "2g", cpus: "2", pids: 1024 };
const APP_MIN_MEMORY = "1g";
const APP_MIN_PIDS = 512;
const IMAGE_RE = /^[A-Za-z0-9][A-Za-z0-9._\/:@-]*$/;

/** Dependency-download hiccups worth one retry (not compile errors, not missing artifacts). */
const TRANSIENT_RE =
  /Read timed out|connect timed out|Connection reset|SocketTimeoutException|Temporary failure in name resolution|502 Bad Gateway|503 Service Unavailable|504 Gateway Timeout|Remote host terminated the handshake|Premature end of Content-Length/i;

export interface JvmLaunchOptions {
  /** Throwaway copy of the target. */
  workdir: string;
  /** Per-run temp root (workdir's parent); build HOME is created under it. */
  root: string;
  extraEnv?: Record<string, string>;
  /** Build time budget (independent of readiness/scan budgets). */
  prepareTimeoutMs: number;
  signal?: AbortSignal;
}

export interface JvmLaunched {
  /** Per-run id; every container/network of the run carries the label argos.run=<id>. */
  runId: string;
  image: string;
  baseUrl: string;
  exited(): boolean;
  exitCode(): number | undefined;
  logs(n?: number): string[];
  stop(): Promise<void>;
  extras: StackExtras;
  /** Values that must never leave the run (DB password); used to redact errors. */
  secrets(): string[];
}

export interface BuildPlan {
  project: JvmProject;
  command: string | null;
  image: string;
  cacheVolume: string;
  allowHosts: string[];
}

export function planBuild(s: JvmSettings, workdir: string): BuildPlan {
  const project = detectJvmProject(workdir);
  const tool = project.tool ?? "maven";
  return {
    project,
    command: s.build ?? defaultBuildCommand(project),
    image: s.buildImage ?? defaultBuildImage(project),
    cacheVolume: `argos-cache-${tool}`,
    allowHosts: project.tool === "gradle" ? [...MAVEN_HOSTS, ...GRADLE_HOSTS] : project.tool === "maven" ? MAVEN_HOSTS : [...MAVEN_HOSTS, ...GRADLE_HOSTS],
  };
}

export function mavenSettingsXml(proxyHost: string, proxyPort: number): string {
  const proxy = (protocol: string) =>
    `<proxy><id>argos-${protocol}</id><active>true</active><protocol>${protocol}</protocol><host>${proxyHost}</host><port>${proxyPort}</port><nonProxyHosts>localhost|127.0.0.1</nonProxyHosts></proxy>`;
  return `<?xml version="1.0" encoding="UTF-8"?>\n<settings><localRepository>/cache/m2/repository</localRepository><proxies>${proxy("http")}${proxy("https")}</proxies></settings>\n`;
}

/** Environment for the build container (no host env, no credentials): proxy + cache locations only. */
export function buildContainerEnv(proxyHost: string, proxyPort: number): Record<string, string> {
  const url = `http://${proxyHost}:${proxyPort}`;
  const props = `-Dhttp.proxyHost=${proxyHost} -Dhttp.proxyPort=${proxyPort} -Dhttps.proxyHost=${proxyHost} -Dhttps.proxyPort=${proxyPort} -Dhttp.nonProxyHosts=localhost|127.0.0.1`;
  return {
    HOME: "/argos-home",
    JAVA_TOOL_OPTIONS: `-Duser.home=/argos-home ${props}`,
    GRADLE_OPTS: props,
    GRADLE_USER_HOME: "/cache/gradle",
    MAVEN_USER_HOME: "/cache/m2",
    http_proxy: url,
    https_proxy: url,
    HTTP_PROXY: url,
    HTTPS_PROXY: url,
    no_proxy: "localhost,127.0.0.1",
    NO_PROXY: "localhost,127.0.0.1",
  };
}

export interface AppEnvInput {
  s: JvmSettings;
  targetEnv: Record<string, string>;
  extraEnv: Record<string, string>;
  dbPassword: string | null;
}

/** App env: target.env and extras first, Argos-injected settings last (they cannot be overridden). */
export function appEnv(i: AppEnvInput): { env: Record<string, string>; injected: string[] } {
  const injected: Record<string, string> = { HOME: "/tmp", SERVER_PORT: String(APP_PORT) };
  if (i.s.db && i.dbPassword !== null) {
    injected[i.s.db.env.url] = `jdbc:postgresql://${ALIAS.db}:5432/${DB_NAME}`;
    injected[i.s.db.env.user] = DB_USER;
    injected[i.s.db.env.password] = i.dbPassword;
  }
  if (i.s.auth) {
    injected[i.s.auth.env.jwkSetUri] = `${ISSUER_URL}/.well-known/jwks.json`;
    if (i.s.auth.env.issuerUri) injected[i.s.auth.env.issuerUri] = ISSUER_URL;
  }
  return { env: { ...i.targetEnv, ...i.extraEnv, ...injected }, injected: Object.keys(injected) };
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const tail = (s: string, n = 60): string[] => s.split("\n").filter(Boolean).slice(-n);

function checkImage(image: string, what: string): string {
  if (!IMAGE_RE.test(image)) throw new RunnerError(`${what}: invalid image name "${image}"`);
  return image;
}

export async function launchJvm(cfg: Config, o: JvmLaunchOptions): Promise<JvmLaunched> {
  const status = dockerStatus();
  if (!status.ok) throw new RunnerError(`jvm runtime needs docker (it never runs on the host): ${status.reason}`);

  const s = jvmSettings(cfg);
  const runId = randomBytes(4).toString("hex");
  const n = (what: string) => `argos-${runId}-${what}`;
  const uid = process.getuid?.() ?? 1000;
  const gid = process.getgid?.() ?? 1000;
  const user = `${uid}:${gid}`;
  const notes: string[] = [];
  const secretValues: string[] = [];
  const secrets = () => secretValues;
  const containers: string[] = [];
  const networks: string[] = [];
  let fwd: Forwarder | undefined;

  const teardown = () => {
    fwd?.close();
    if (containers.length) dockerSync(["rm", "-f", ...containers.splice(0)], { timeoutMs: 60_000 });
    // sweep by run label too (anything created under another name or after a partial failure)
    const stray = dockerSync(["ps", "-aq", "--filter", `label=argos.run=${runId}`]).stdout.split("\n").filter(Boolean);
    if (stray.length) dockerSync(["rm", "-f", ...stray], { timeoutMs: 60_000 });
    for (const net of networks.splice(0).reverse()) dockerSync(["network", "rm", net], { timeoutMs: 30_000 });
  };
  const aborted = () => {
    if (o.signal?.aborted) throw new RunnerError("aborted");
  };
  const fail = (msg: string, lines: string[] = []): never => {
    throw new RunnerError(redact(`${msg} [argos run ${runId}]`, secretValues), redactLines(lines, secretValues));
  };
  const mkNet = (name: string, internal: boolean) => {
    const r = dockerSync(networkCreateArgs(name, runId, internal));
    if (r.status !== 0) fail(`docker network create failed: ${r.stderr.trim()}`);
    networks.push(name);
  };
  const run = (args: string[], name: string, env: Record<string, string>, what: string) => {
    containers.push(name);
    const r = dockerSync(args, { env });
    if (r.status !== 0) fail(`${what}: docker run failed: ${r.stderr.trim().split("\n")[0]}`);
  };
  const waitLog = async (name: string, needle: string, ms: number, what: string) => {
    const until = Date.now() + ms;
    while (Date.now() < until) {
      aborted();
      const l = dockerSync(["logs", name], { timeoutMs: 10_000 });
      if ((l.stdout + l.stderr).includes(needle)) return;
      await sleep(200);
    }
    const l = dockerSync(["logs", "--tail", "30", name], { timeoutMs: 10_000 });
    fail(`${what} did not become ready within ${ms}ms`, tail(l.stdout + l.stderr));
  };

  try {
    const sidecarImage = checkImage(s.sidecarImage ?? defaultImage(), "target.container.sidecarImage");
    const plan = planBuild(s, o.workdir);
    const p = plan.project;
    notes.push(`project: ${p.tool ?? "unknown build tool"}${p.tool ? (p.wrapper ? " (project wrapper)" : " (no wrapper)") : ""}, JDK ${p.jdk} from ${p.jdkSource}`);
    const workdir = realpathSync(o.workdir);
    ensureImageRetry(sidecarImage, "sidecar");

    // ---------- build ----------
    if (plan.command) {
      aborted();
      const buildImage = checkImage(plan.image, "target.container.buildImage");
      ensureImageRetry(buildImage, "build");
      notes.push(`build: \`${plan.command}\` in ${buildImage} (non-root, read-only root, cap-drop ALL, ${BUILD_LIMITS.memory}/${BUILD_LIMITS.cpus} cpu/${BUILD_LIMITS.pids} pids, no host env or credentials)`);

      const egress = n("egress");
      const buildNet = n("buildnet");
      mkNet(egress, false);
      mkNet(buildNet, true);
      const proxy = n("proxy");
      const proxyEnv = { ARGOS_PROXY_ALLOW: plan.allowHosts.join(",") };
      run(sidecarRunArgs({ name: proxy, runId, network: egress, alias: ALIAS.proxy, image: sidecarImage, env: proxyEnv, script: proxyScript() }), proxy, proxyEnv, "build proxy");
      const conn = dockerSync(["network", "connect", "--alias", ALIAS.proxy, buildNet, proxy]);
      if (conn.status !== 0) fail(`docker network connect failed: ${conn.stderr.trim()}`);
      await waitLog(proxy, SIDECAR_READY, 30_000, "build proxy");
      notes.push(`build egress: internal build network; only an allowlisting CONNECT proxy (port 443) to ${plan.allowHosts.join(", ")}`);

      // dependency cache: named volume per tool, kept between runs (label argos-cache=1, not argos=1)
      if (dockerSync(["volume", "inspect", plan.cacheVolume]).status !== 0) {
        const vc = dockerSync(["volume", "create", "--label", "argos-cache=1", plan.cacheVolume]);
        if (vc.status !== 0) fail(`docker volume create failed: ${vc.stderr.trim()}`);
      }
      const own = dockerSync([
        "run", "--rm", "--label", "argos=1", "--label", `argos.run=${runId}`, "--network", "none", "--user", "0", "--cap-drop", "ALL", "--cap-add", "CHOWN",
        "-v", `${plan.cacheVolume}:/cache`, "--entrypoint", "chown", sidecarImage, user, "/cache",
      ], { timeoutMs: 60_000 });
      if (own.status !== 0) fail(`cannot prepare cache volume ${plan.cacheVolume}: ${own.stderr.trim()}`);
      notes.push(`dependency cache: docker volume ${plan.cacheVolume} (shared between runs of this host)`);

      const home = join(o.root, "build-home");
      mkdirSync(join(home, ".m2"), { recursive: true });
      writeFileSync(join(home, ".m2", "settings.xml"), mavenSettingsXml(ALIAS.proxy, PROXY_PORT));
      const env = buildContainerEnv(ALIAS.proxy, PROXY_PORT);
      const deadline = Date.now() + o.prepareTimeoutMs;

      let attempt = 0;
      for (;;) {
        aborted();
        const name = n(`build${attempt}`);
        containers.push(name);
        const r = await dockerAsync(
          buildRunArgs({ name, runId, network: buildNet, image: buildImage, workdir, home: realpathSync(home), cacheVolume: plan.cacheVolume, env, command: plan.command, limits: BUILD_LIMITS, user }),
          { timeoutMs: Math.max(1_000, deadline - Date.now()), signal: o.signal, env, cancel: () => void dockerSync(["rm", "-f", name], { timeoutMs: 30_000 }) },
        );
        dockerSync(["rm", "-f", name], { timeoutMs: 60_000 });
        if (r.status === 0) break;
        const out = r.stdout + "\n" + r.stderr;
        const denied = tail(dockerSync(["logs", proxy], { timeoutMs: 10_000 }).stdout).filter((l) => l.startsWith("argos-proxy"));
        if (r.aborted) fail("aborted during build");
        if (r.timedOut) fail(`build timed out after ${o.prepareTimeoutMs}ms`, [...tail(out), ...denied]);
        if (attempt === 0 && TRANSIENT_RE.test(out)) {
          attempt++;
          notes.push("build: retried once after a transient dependency-download error");
          continue;
        }
        fail(`build failed (exit ${r.status}): \`${plan.command}\``, [...tail(out), ...denied]);
      }
      // build infra is gone before customer code runs again
      dockerSync(["rm", "-f", proxy], { timeoutMs: 30_000 });
      containers.splice(containers.indexOf(proxy), 1);
      for (const net of [buildNet, egress]) {
        dockerSync(["network", "rm", net], { timeoutMs: 30_000 });
        networks.splice(networks.indexOf(net), 1);
      }
    } else {
      notes.push("build: none (no target.build and no Maven/Gradle project detected)");
    }

    // ---------- run ----------
    aborted();
    const appImage = checkImage(s.appImage ?? defaultAppImage(p), "target.container.image");
    ensureImageRetry(appImage, "app");
    const net = n("net");
    mkNet(net, true);

    let dbPassword: string | null = null;
    let pgName: string | undefined;
    if (s.db) {
      const dbImage = checkImage(s.db.image, "db.image");
      ensureImageRetry(dbImage, "db");
      dbPassword = randomBytes(18).toString("base64url");
      secretValues.push(dbPassword);
      pgName = n("db");
      const pgEnv = { POSTGRES_USER: DB_USER, POSTGRES_DB: DB_NAME, POSTGRES_PASSWORD: dbPassword, PGDATA: "/var/lib/postgresql/data/pgdata" };
      run(postgresRunArgs({ name: pgName, runId, network: net, alias: ALIAS.db, image: dbImage, env: pgEnv }), pgName, pgEnv, "postgres");
      const until = Date.now() + 90_000;
      for (;;) {
        aborted();
        // -h 127.0.0.1: the entrypoint's init-time server listens on the socket only, so this waits for the real one
        if (dockerSync(["exec", pgName, "pg_isready", "-q", "-h", "127.0.0.1", "-U", DB_USER, "-d", DB_NAME], { timeoutMs: 10_000 }).status === 0) break;
        const st = dockerSync(["inspect", "-f", "{{.State.Running}}", pgName]).stdout.trim();
        if (st !== "true" || Date.now() > until) {
          const l = dockerSync(["logs", "--tail", "30", pgName], { timeoutMs: 10_000 });
          fail(st !== "true" ? "postgres exited during startup" : "postgres not ready within 90s", tail(l.stdout + l.stderr));
        }
        await sleep(300);
      }
      notes.push(`db: ${dbImage} on the run's internal network (${ALIAS.db}:5432/${DB_NAME}, random per-run password, tmpfs data); migrations: ${s.db.migrations}${s.db.migrations === "none" ? "" : " (applied by the app at boot)"}`);
    }

    const keys = createIssuerKeys();
    const sidecar = n("issuer");
    const scEnv = { ARGOS_ISSUER: ISSUER_URL, ARGOS_JWKS: JSON.stringify(keys.jwks) };
    run(sidecarRunArgs({ name: sidecar, runId, network: net, alias: ALIAS.issuer, image: sidecarImage, env: scEnv, script: issuerScript() }), sidecar, scEnv, "issuer sidecar");
    await waitLog(sidecar, SIDECAR_READY, 30_000, "issuer sidecar");
    notes.push(`issuer: ${ISSUER_URL} (RS256, per-run key ${keys.kid}; private key in memory only)${s.auth ? "" : " — not injected: no auth config"}`);

    const c = cfg.target.container;
    const limits: Limits = {
      memory: memBytes(c.memory) < memBytes(APP_MIN_MEMORY) ? APP_MIN_MEMORY : c.memory,
      cpus: c.cpus,
      pids: Math.max(c.pids, APP_MIN_PIDS),
    };
    if (limits.memory !== c.memory || limits.pids !== c.pids) notes.push(`app limits raised for the JVM: memory ${limits.memory}, pids ${limits.pids}`);
    const { env, injected } = appEnv({ s, targetEnv: cfg.target.env, extraEnv: o.extraEnv ?? {}, dbPassword });
    const app = n("app");
    run(appRunArgs({ name: app, runId, network: net, alias: ALIAS.app, image: appImage, workdir, env, start: cfg.target.start, limits, user }), app, env, "app");
    notes.push(`app: ${appImage}, internal network only (no internet/host), read-only root, non-root ${user}, cap-drop ALL, ${limits.memory}/${limits.cpus} cpu/${limits.pids} pids, SERVER_PORT=${APP_PORT}`);

    fwd = await startForwarder(sidecar, APP_PORT, ALIAS.app);
    const baseUrl = cfg.target.baseUrl.replace(/:0(?=\/|$)/, `:${fwd.hostPort}`);

    const exitCode = (): number | undefined => {
      const r = dockerSync(["inspect", "-f", "{{.State.Status}}|{{.State.ExitCode}}", app], { timeoutMs: 10_000 });
      if (r.status !== 0) return -1;
      const [state, code] = r.stdout.trim().split("|");
      return state === "exited" || state === "dead" ? Number(code) : undefined;
    };
    const logs = (k = 50): string[] => {
      const r = dockerSync(["logs", "--tail", String(k), app], { timeoutMs: 10_000 });
      return redactLines((r.stdout + r.stderr).split("\n").filter(Boolean).slice(-k), secretValues);
    };
    let stopped: Promise<void> | undefined;
    const stop = () => (stopped ??= (async () => teardown())());

    return {
      runId,
      image: appImage,
      baseUrl,
      exited: () => exitCode() !== undefined,
      exitCode,
      logs,
      stop,
      secrets,
      extras: {
        db: pgName ? dbHandle(pgName, DB_USER, DB_NAME, secrets) : undefined,
        issuer: issuerHandle(keys, ISSUER_URL, s.auth?.audience),
        injectedEnv: injected,
        notes,
      },
    };
  } catch (e) {
    teardown();
    if (e instanceof RunnerError) throw e;
    throw new RunnerError(redact(`jvm stack failed: ${(e as Error).message}`, secretValues));
  }
}
