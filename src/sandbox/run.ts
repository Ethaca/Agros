import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { createServer } from "node:net";
import { z } from "zod";
import { Config } from "../config.js";
import { runMatrixDetailed } from "../matrix.js";
import { runChecks } from "../checks/index.js";
import type { SeedManifest } from "../seed.js";
import { MAX_ARCHIVE_BYTES, MAX_RESULT_BYTES, SANDBOX_IMAGE, SandboxResult } from "./protocol.js";

const Prepared = z.discriminatedUnion("supported", [
  z.object({ supported: z.literal(false), reason: z.string().max(1000) }),
  z.object({
    supported: z.literal(true), cfg: Config,
    manifest: z.object({
      markers: z.record(z.string(), z.record(z.string(), z.string().max(256))),
      ids: z.record(z.string(), z.record(z.string(), z.union([z.string().max(256), z.number()]))),
      secrets: z.array(z.object({ table: z.string(), column: z.string(), org: z.string(), marker: z.string().max(256) })).max(1000),
      envCanaries: z.array(z.object({ name: z.string(), marker: z.string().max(256) })).max(10),
    }),
    policy: z.enum(["repository", "draft"]), untested: z.array(z.string().max(512)).max(100),
  }),
]);

export async function docker(args: string[], options: { input?: Uint8Array; signal?: AbortSignal; timeout?: number } = {}): Promise<string> {
  return new Promise((resolve, reject) => {
    const p = spawn("docker", args, {
      env: { PATH: process.env.PATH, HOME: process.env.HOME },
      stdio: ["pipe", "pipe", "pipe"], signal: options.signal,
    });
    let size = 0, output = "", settled = false;
    const timer = setTimeout(() => { p.kill("SIGKILL"); }, options.timeout ?? 60_000);
    p.stdout.on("data", (b: Buffer) => {
      size += b.length;
      if (size > MAX_RESULT_BYTES) p.kill("SIGKILL"); else output += b.toString();
    });
    // Drain logs without forwarding untrusted output or source secrets to the host console.
    p.stderr.on("data", () => {});
    p.stdin.on("error", () => {});
    p.on("error", () => { if (!settled) { settled = true; clearTimeout(timer); reject(new Error("Docker operation unavailable or cancelled")); } });
    p.on("exit", (code) => {
      clearTimeout(timer);
      if (settled) return;
      settled = true;
      if (code === 0 && size <= MAX_RESULT_BYTES) resolve(output.trim());
      else reject(new Error("Docker operation failed, timed out, or exceeded output limits"));
    });
    p.stdin.end(options.input);
  });
}

export function isolationArgs(name: string, volume: string, readOnly: boolean): string[] {
  if (!/^argos-local-[a-f0-9]{24}(?:-prepare|-app|-keep)?$/.test(name) || !/^argos-local-[a-f0-9]{24}$/.test(volume)) throw new Error("Invalid sandbox resource name");
  return [
    "--name", name, "--label", "argos.local-sandbox=1", "--network", "none", "--read-only",
    "--label", `argos.local-expires=${Date.now() + 300_000}`,
    "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", "1000:1000",
    "--pids-limit", "128", "--memory", "512m", "--memory-swap", "512m", "--cpus", "1",
    "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m,uid=1000,gid=1000,mode=0700",
    "--log-driver", "local", "--log-opt", "max-size=1m", "--log-opt", "max-file=2",
    "--mount", `type=volume,src=${volume},dst=/work${readOnly ? ",readonly" : ""}`,
  ];
}

/** Recover only expired resources created by this worker, never unrelated Docker workloads. */
export async function cleanupExpiredSandboxes(now = Date.now()): Promise<void> {
  const names = (await docker(["ps", "-a", "--filter", "label=argos.local-sandbox=1", "--format", "{{.Names}}"])).split("\n").filter((n) => /^argos-local-[a-f0-9]{24}-(?:keep|app|prepare)$/.test(n));
  for (const name of names) {
    const expiry = Number(await docker(["inspect", "--format", '{{index .Config.Labels "argos.local-expires"}}', name]).catch(() => "0"));
    if (expiry > 0 && expiry < now) await docker(["rm", "-f", name]).catch(() => {});
  }
  const volumes = (await docker(["volume", "ls", "--filter", "label=argos.local-sandbox=1", "--format", "{{.Name}}"])).split("\n").filter((n) => /^argos-local-[a-f0-9]{24}$/.test(n));
  for (const name of volumes) {
    const expiry = Number(await docker(["volume", "inspect", "--format", '{{index .Labels "argos.local-expires"}}', name]).catch(() => "0"));
    if (expiry > 0 && expiry < now) await docker(["volume", "rm", name]).catch(() => {});
  }
}

async function relay(container: string) {
  const children = new Set<ReturnType<typeof spawn>>();
  const sockets = new Set<import("node:net").Socket>();
  const server = createServer((socket) => {
    sockets.add(socket);
    const script = 'const s=require("node:net").connect(3000,"127.0.0.1");process.stdin.pipe(s);s.pipe(process.stdout);s.on("error",()=>process.exit(1));';
    const child = spawn("docker", ["exec", "-i", container, "node", "-e", script], { stdio: ["pipe", "pipe", "ignore"] });
    children.add(child);
    socket.pipe(child.stdin!); child.stdout!.pipe(socket);
    const close = () => { sockets.delete(socket); children.delete(child); socket.destroy(); child.kill("SIGKILL"); };
    socket.on("close", close); socket.on("error", close); child.on("exit", close); child.on("error", close);
    child.stdin!.on("error", () => {});
  });
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  return {
    baseUrl: `http://127.0.0.1:${(server.address() as { port: number }).port}`,
    stop: () => { server.close(); for (const s of sockets) s.destroy(); for (const p of children) p.kill("SIGKILL"); },
  };
}

export async function runSandbox(archive: Uint8Array, options: { timeoutMs?: number; image?: string; signal?: AbortSignal } = {}): Promise<SandboxResult> {
  const started = Date.now(), image = options.image ?? SANDBOX_IMAGE;
  if (!/^[\w./:@-]+$/.test(image) || image.startsWith("-")) throw new Error("Invalid image");
  if (archive.byteLength > MAX_ARCHIVE_BYTES || !archive.byteLength) throw new Error("Archive size limit");
  const name = `argos-local-${randomBytes(12).toString("hex")}`;
  const deadline = AbortSignal.timeout(options.timeoutMs ?? 180_000);
  const signal = options.signal ? AbortSignal.any([deadline, options.signal]) : deadline;
  let connection: Awaited<ReturnType<typeof relay>> | undefined;
  const incomplete = (status: "failed" | "unsupported", reason: string): SandboxResult => ({ version: 1, status, image, durationMs: Date.now() - started, reason, routes: [], untested: [], findings: [] });
  try {
    // Refuse a missing image instead of silently downloading or changing isolation mode.
    await docker(["image", "inspect", image], { signal });
    await docker(["volume", "create", "--label", "argos.local-sandbox=1", "--label", `argos.local-expires=${Date.now() + 300_000}`, "--driver", "local", "--opt", "type=tmpfs", "--opt", "device=tmpfs", "--opt", "o=size=256m,uid=1000,gid=1000,mode=0700", name], { signal });
    // A tmpfs volume is erased when its final mount closes. Keep one read-only mount
    // alive between preparation and app startup, then remove it with this run.
    await docker(["run", "-d", ...isolationArgs(`${name}-keep`, name, true), image, "node", "-e", "setInterval(()=>{},1000)"], { signal });
    const text = await docker(["run", "--rm", "-i", ...isolationArgs(`${name}-prepare`, name, false), image, "node", "/opt/argos/prepare.mjs"], { input: archive, signal, timeout: 45_000 });
    const p = Prepared.parse(JSON.parse(text));
    if (!p.supported) return incomplete("unsupported", p.reason);
    const cfg = p.cfg;
    if (cfg.resources.length > 60 || cfg.personas.length > 4 || cfg.resources.some((r) => !/^GET \/[^\s#]*$/.test(r.route) || r.route.length > 256 || r.id.length > 100 || (r.params?.length ?? 0) > 5 || r.route.split('&').length > 5) || !/^\/[\w/.-]*$/.test(cfg.target.readyPath)) return incomplete("unsupported", "Unsupported route or matrix size");
    // The host reads only validated JSON from preparation. It never parses or executes source/SQL.
    await docker(["run", "-d", ...isolationArgs(`${name}-app`, name, true), image, "node", "/opt/argos/start-app.mjs"], { signal });
    connection = await relay(`${name}-app`);
    signal.addEventListener("abort", () => connection?.stop(), { once: true });
    let ready = false;
    const bootUntil = Date.now() + 30_000;
    while (!signal.aborted && Date.now() < bootUntil) {
      try {
        const r = await fetch(connection.baseUrl + cfg.target.readyPath, { redirect: "manual", signal: AbortSignal.any([signal, AbortSignal.timeout(1500)]) });
        await r.body?.cancel();
        if (r.status === 200) { ready = true; break; }
      } catch { /* another bounded readiness attempt */ }
      await new Promise((resolve) => setTimeout(resolve, 200));
    }
    if (!ready) return incomplete("failed", "App did not become ready with the isolated runtime and synthetic credentials");
    const manifest: SeedManifest = p.manifest;
    const task = (async () => {
      const httpLimits = { timeoutMs: 2000, maxResponseBytes: 64 * 1024 };
      const { matrix, raw } = await runMatrixDetailed(cfg, connection!.baseUrl, manifest, httpLimits);
      // Source code can return unknown hardcoded credentials. Never export response
      // snippets, even when they contain no known synthetic secret marker.
      for (const c of matrix.cells) c.evidence.note = c.observed === "error"
        ? "Request unavailable, response limit reached, or resource not observable"
        : "Response body withheld; verdict uses HTTP status and synthetic markers";
      const controls = matrix.cells.filter((c) => {
        const persona = cfg.personas.find((x) => x.name === c.persona);
        return !!persona?.org && c.target === persona.org && c.expected === "allow";
      });
      if (!controls.length || controls.some((c) => c.observed !== "allow" || c.verdict !== "OK")) return incomplete("failed", "Authenticated own-data controls failed; attack results are not accepted as a security verdict");
      const findings = await runChecks({ cfg: { ...cfg, secrets: { ...cfg.secrets, staticScan: false } }, baseUrl: connection!.baseUrl, matrix, raw, manifest, srcDir: ".", httpLimits });
      return SandboxResult.parse({ version: 1, status: "completed", image, durationMs: Date.now() - started, policy: p.policy, routes: cfg.resources.map((r) => r.route), untested: p.untested, matrix, findings });
    })();
    task.catch(() => {});
    const result = await Promise.race([task, new Promise<never>((_, reject) => {
      if (signal.aborted) reject(new Error("deadline"));
      else signal.addEventListener("abort", () => reject(new Error("deadline")), { once: true });
    })]);
    if (Buffer.byteLength(JSON.stringify(result)) > MAX_RESULT_BYTES) return incomplete("failed", "Result size limit exceeded");
    return result;
  } catch {
    return incomplete("failed", signal.aborted ? "Sandbox timed out or was cancelled" : "Sandbox preparation/runtime failed; no host fallback was used");
  } finally {
    connection?.stop();
    // Only this run's exact names are removed, never a broad cleanup of Docker resources.
    await docker(["rm", "-f", `${name}-prepare`, `${name}-app`, `${name}-keep`], { timeout: 15_000 }).catch(() => {});
    await docker(["volume", "rm", "-f", name], { timeout: 15_000 }).catch(() => {});
  }
}
