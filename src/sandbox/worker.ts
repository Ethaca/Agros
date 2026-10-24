import { readFileSync } from "node:fs";
import { parseEnv } from "node:util";
import { fileURLToPath } from "node:url";
import { cleanupExpiredSandboxes, runSandbox } from "./run.js";
import { MAX_ARCHIVE_BYTES, MAX_RESULT_BYTES, SANDBOX_IMAGE, SandboxJob, SandboxResult } from "./protocol.js";

// Only the local worker credential is used here. OAuth/App/LLM secrets stay in the web server.
const vars = parseEnv(readFileSync(fileURLToPath(new URL("../../apps/web/.dev.vars", import.meta.url)), "utf8"));
const token = vars.SANDBOX_WORKER_TOKEN;
if (!token || token.length < 32) throw new Error("Run setup-demo.mjs to create SANDBOX_WORKER_TOKEN");
const base = "http://127.0.0.1:8787/internal/sandbox";
const stopping = new AbortController();
for (const signal of ["SIGINT", "SIGTERM"] as const) process.on(signal, () => stopping.abort());
const once = process.argv.includes("--once");
let lastCleanup = 0;

async function api(path: string, init: RequestInit = {}) {
  return fetch(base + path, { ...init, redirect: "error", signal: AbortSignal.any([stopping.signal, AbortSignal.timeout(45_000)]), headers: { authorization: `Bearer ${token}`, ...init.headers } });
}
async function archiveOf(response: Response) {
  if (!response.ok || !response.body) throw new Error("snapshot unavailable");
  const reader = response.body.getReader(), chunks: Uint8Array[] = []; let bytes = 0;
  while (true) {
    const { done, value } = await reader.read(); if (done) break;
    if ((bytes += value.length) > MAX_ARCHIVE_BYTES) { await reader.cancel(); throw new Error("snapshot limit"); }
    chunks.push(value);
  }
  return Buffer.concat(chunks);
}

console.log("Argos local Docker worker: serial execution, offline containers, no host fallback.");
do {
  try {
    if (Date.now() - lastCleanup > 60_000) { await cleanupExpiredSandboxes(); lastCleanup = Date.now(); }
    const claim = await api("/claim", { method: "POST" });
    if (claim.status === 401) throw new Error("Worker disabled or credential not loaded; restart web server after setup");
    if (claim.status === 204) {
      if (once) break;
    } else {
      if (!claim.ok) throw new Error("Job claim failed");
      const payload = await claim.json() as { job: unknown; result: unknown };
      const job = SandboxJob.parse(payload.job);
      console.log(`sandbox #${job.id}: ${job.repo}#${job.pr}@${job.sha.slice(0, 7)}`);
      const leaseHeader = { "x-argos-lease": job.lease };
      let result: SandboxResult;
      if (payload.result) result = SandboxResult.parse(payload.result);
      else {
        try {
          const source = await archiveOf(await api(`/${job.id}/source`, { headers: leaseHeader }));
          result = await runSandbox(source, { signal: stopping.signal });
        } catch {
          result = { version: 1, status: "failed", image: SANDBOX_IMAGE, durationMs: 0, reason: "Snapshot download failed or job access was revoked", routes: [], untested: [], findings: [] };
        }
      }
      if (stopping.signal.aborted) break;
      const body = JSON.stringify(result);
      if (Buffer.byteLength(body) > MAX_RESULT_BYTES) throw new Error("Result exceeds export limit");
      const published = await api(`/${job.id}/complete`, { method: "POST", headers: { ...leaseHeader, "content-type": "application/json" }, body });
      console.log(`sandbox #${job.id}: ${result.status}, publication=${published.status}`);
      if (!published.ok && published.status !== 409) throw new Error("Publication failed; persisted results will be retried after lease expiry");
      if (once) break;
    }
  } catch (error) {
    if (stopping.signal.aborted) break;
    console.error(error instanceof Error && !error.message.includes("token") ? error.message : "Local worker error");
    if (once) { process.exitCode = 1; break; }
  }
  await new Promise<void>((resolve) => {
    const abort = () => { clearTimeout(timer); resolve(); };
    const timer = setTimeout(() => { stopping.signal.removeEventListener("abort", abort); resolve(); }, 3000);
    if (stopping.signal.aborted) abort();
    else stopping.signal.addEventListener("abort", abort, { once: true });
  });
} while (!stopping.signal.aborted);
