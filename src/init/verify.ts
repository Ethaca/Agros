import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadConfig, ConfigError } from "../config.js";
import { dockerStatus } from "../container.js";
import { RunnerError } from "../runner.js";
import { runScan, ScanError, type ScanResult } from "../scan.js";
import { SeedError } from "../seed.js";
import type { Isolation } from "../runner.js";

/** Step 5 of `argos init`: do not trust the draft until it has actually run. */
export interface Verification {
  ran: boolean;
  /** Why verification did not run. */
  skipped?: string;
  /** Config loads, app boots, and every persona can read its own data. */
  ok: boolean;
  boot: boolean;
  problems: string[];
  /** Personas whose own-data request succeeded. */
  loggedIn: string[];
  /** Counts from a preview scan of the draft. They rest on UNCONFIRMED rules: not a verdict. */
  preview?: ScanResult["counts"];
  ms: number;
}

export async function verifyDraft(configPath: string, opts: { isolation?: Isolation; timeoutMs?: number } = {}): Promise<Verification> {
  const t0 = Date.now();
  const done = (v: Omit<Verification, "ms">): Verification => ({ ...v, ms: Date.now() - t0 });
  const fail = (problems: string[], boot = false): Verification => done({ ran: true, ok: false, boot, problems, loggedIn: [] });

  let cfg;
  try {
    cfg = loadConfig(configPath);
  } catch (e) {
    return fail([`the drafted config is invalid: ${(e as Error).message}`]);
  }
  const isolation = opts.isolation ?? cfg.target.isolation;
  if (isolation === "container") {
    const d = dockerStatus();
    if (!d.ok) {
      return done({
        ran: false,
        ok: false,
        boot: false,
        problems: [`container isolation is configured but docker is not available (${d.reason}). Start Docker, or verify on this machine with --isolation process (trusted code only), or skip with --no-verify.`],
        skipped: "docker not available",
        loggedIn: [],
      });
    }
  }

  const out = mkdtempSync(join(tmpdir(), "argos-init-verify-"));
  try {
    const r = await runScan({ configPath, outDir: out, quiet: true, log: () => {}, isolation, timeoutMs: opts.timeoutMs });
    const problems: string[] = [];
    const loggedIn: string[] = [];
    const personas = cfg.personas.filter((p) => p.org);
    for (const p of personas) {
      const own = r.matrix.cells.filter((c) => c.persona === p.name && c.target === p.org);
      const okCell = own.find((c) => c.verdict === "OK");
      if (okCell) loggedIn.push(p.name);
      else if (own.length) {
        const c = own[0]!;
        problems.push(`${p.name} could not read its own data on ${c.evidence.request} (${c.evidence.status ?? "no response"}, expected ${c.expected}): check the test token and the owner column`);
      } else problems.push(`${p.name}: no request exercised its own data (no resource with an owner), so login could not be verified`);
    }
    return done({ ran: true, ok: problems.length === 0, boot: true, problems, loggedIn, preview: r.counts });
  } catch (e) {
    if (e instanceof RunnerError) return fail([`the app did not start: ${e.message}`]);
    if (e instanceof ConfigError || e instanceof SeedError || e instanceof ScanError) return fail([e.message], true);
    throw e;
  } finally {
    rmSync(out, { recursive: true, force: true });
  }
}
