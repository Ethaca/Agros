import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ConfigError, hasCredentials, loadConfig } from "../../config.js";
import { dockerStatus } from "../../container.js";
import { RunnerError } from "../../runner.js";
import { runScan, ScanError } from "../../scan.js";
import { SeedError } from "../../seed.js";
import type { Verification } from "../verify.js";

/**
 * Spring draft verification: build + start in the isolated jvm stack (PostgreSQL, test issuer), seed, and check that
 * every valid persona can use its own data. Anything that prevents a real run is returned as "not run" with the
 * reason: the draft is then explicitly UNVERIFIED, never assumed good.
 */
export async function verifySpringDraft(configPath: string, opts: { timeoutMs?: number } = {}): Promise<Verification> {
  const t0 = Date.now();
  const done = (v: Omit<Verification, "ms">): Verification => ({ ...v, ms: Date.now() - t0 });
  const notRun = (why: string): Verification => done({ ran: false, ok: false, boot: false, problems: [why], skipped: why, loggedIn: [] });

  let cfg;
  try {
    cfg = loadConfig(configPath);
  } catch (e) {
    return done({ ran: true, ok: false, boot: false, problems: [`the drafted config is invalid: ${(e as Error).message}`], loggedIn: [] });
  }
  const d = dockerStatus();
  if (!d.ok) return notRun(`docker is not available (${d.reason}): the jvm runtime only runs in containers`);

  const out = mkdtempSync(join(tmpdir(), "argos-init-verify-"));
  try {
    const r = await runScan({ configPath, outDir: out, quiet: true, log: () => {}, isolation: "container", ...(opts.timeoutMs ? { timeoutMs: opts.timeoutMs } : {}) });
    const problems: string[] = [];
    const loggedIn: string[] = [];
    for (const p of cfg.personas.filter((x) => x.org && hasCredentials(x))) {
      const own = r.matrix.cells.filter((c) => c.persona === p.name && c.target === p.org && !c.relation && c.expected === "allow");
      if (own.some((c) => c.verdict === "OK")) loggedIn.push(p.name);
      else if (own.length) {
        const c = own[0]!;
        problems.push(`${p.name} could not use its own data on ${c.evidence.request} (${c.evidence.status ?? "no response"}, expected allow): check auth.claims (subject/roles) and the seeded users`);
      }
    }
    if (!loggedIn.length && !problems.length) problems.push("no request exercised a persona's own data, so login could not be verified");
    return done({ ran: true, ok: problems.length === 0, boot: true, problems, loggedIn, preview: r.counts });
  } catch (e) {
    if (e instanceof RunnerError) return done({ ran: true, ok: false, boot: false, problems: [`build/start failed: ${e.message}`], loggedIn: [] });
    if (e instanceof ConfigError || e instanceof SeedError || e instanceof ScanError) return done({ ran: true, ok: false, boot: true, problems: [e.message], loggedIn: [] });
    return notRun(`verification could not run: ${(e as Error).message}`);
  } finally {
    rmSync(out, { recursive: true, force: true });
  }
}
