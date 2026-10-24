import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { CHECKS, runChecks } from "./checks/index.js";
import { loadConfig, ConfigError } from "./config.js";
import { renderMatrixMarkdown, runMatrixDetailed } from "./matrix.js";
import { startTarget } from "./runner.js";
import { hashConfigText, seedDatabase, type SeedManifest } from "./seed.js";
import { CheckName, type Finding, type Matrix, type Verdict } from "./types.js";

export class ScanError extends Error {}

export interface ScanOptions {
  configPath: string;
  /** Override config `checks` (comma list already split). */
  checks?: string[];
  outDir: string;
  /** Whole-scan timeout. Default 5 minutes (R5). */
  timeoutMs?: number;
  quiet?: boolean;
  log?: (line: string) => void;
  /** Edit the temp copy before it is seeded and started (used by `fix` to re-verify a patch). */
  patch?: (workdir: string) => void;
}

export interface ScanResult {
  matrix: Matrix;
  findings: Finding[];
  counts: Record<Verdict, number>;
  notRun: string[];
  /** 0 ok / report mode, 2 when mode is block and something is VULNERABLE. (1 = thrown error.) */
  exitCode: 0 | 2;
  files: { matrix: string; findings: string };
}

const VERDICTS: Verdict[] = ["VULNERABLE", "SUSPECTED", "OK", "SKIPPED"];

export async function runScan(opts: ScanOptions): Promise<ScanResult> {
  const log = opts.log ?? ((l: string) => console.log(l));
  const configPath = resolve(opts.configPath);
  const cfg = loadConfig(configPath);

  if (opts.checks) {
    const bad = opts.checks.filter((c) => !CheckName.safeParse(c).success);
    if (bad.length) throw new ConfigError(`--checks: unknown check "${bad[0]}" (use ${CheckName.options.join(", ")})`);
    cfg.checks = opts.checks as typeof cfg.checks;
  }
  const needsRows = cfg.resources.some((r) => r.owner);
  if (needsRows && !cfg.seed) throw new ConfigError("seed: required when resources have an owner (rows are seeded from them)");

  const seedKey = hashConfigText(readFileSync(configPath, "utf8"));
  let manifest: SeedManifest = { markers: {}, secrets: [], ids: {} };

  const timeoutMs = opts.timeoutMs ?? 300_000;
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, rej) => {
    timer = setTimeout(() => rej(new ScanError(`scan timed out after ${Math.round(timeoutMs / 1000)}s`)), timeoutMs);
  });

  let target: Awaited<ReturnType<typeof startTarget>> | undefined;
  let aborted = false;
  try {
    const work = (async () => {
      target = await startTarget(cfg, {
        baseDir: dirname(configPath),
        quiet: opts.quiet,
        beforeStart: (workdir) => {
          opts.patch?.(workdir);
          if (cfg.seed) manifest = seedDatabase(cfg, { workdir, seedKey });
        },
      });
      // Timeout fired while the app was still booting: don't leave it running.
      if (aborted) {
        await target.stop();
        throw new ScanError("aborted");
      }
      const { matrix, raw } = await runMatrixDetailed(cfg, target.baseUrl, manifest);
      const findings = await runChecks({ cfg, baseUrl: target.baseUrl, matrix, raw, manifest });
      return { matrix, findings };
    })();
    // If the timeout wins, `work` keeps running; swallow its late rejection.
    work.catch(() => undefined);
    const { matrix, findings } = await Promise.race([work, timeout]);

    mkdirSync(opts.outDir, { recursive: true });
    const files = { matrix: join(opts.outDir, "matrix.json"), findings: join(opts.outDir, "findings.json") };
    writeFileSync(files.matrix, JSON.stringify(matrix, null, 2) + "\n");
    writeFileSync(files.findings, JSON.stringify(findings, null, 2) + "\n");

    const counts = Object.fromEntries(VERDICTS.map((v) => [v, 0])) as Record<Verdict, number>;
    for (const f of findings) counts[f.verdict]++;
    const notRun = cfg.checks.filter((c) => !CHECKS[c]);

    log(renderMatrixMarkdown(matrix));
    log("");
    log(`findings: 🔴 ${counts.VULNERABLE}  🟡 ${counts.SUSPECTED}  🟢 ${counts.OK}  ⚪ ${counts.SKIPPED}`);
    for (const f of findings.filter((x) => x.verdict === "VULNERABLE")) log(`  🔴 [${f.check}] ${f.resourceId} (${f.persona}): ${f.detail}`);
    for (const f of findings.filter((x) => x.verdict === "SKIPPED")) log(`  ⚪ [${f.check}] ${f.resourceId} (${f.persona}): ${f.detail}`);
    if (notRun.length) log(`not implemented yet, not run: ${notRun.join(", ")}`);
    log(`wrote ${files.matrix}, ${files.findings}`);

    return { matrix, findings, counts, notRun, exitCode: cfg.mode === "block" && counts.VULNERABLE > 0 ? 2 : 0, files };
  } finally {
    aborted = true;
    clearTimeout(timer);
    await target?.stop();
  }
}
