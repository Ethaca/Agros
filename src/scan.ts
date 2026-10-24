import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { CHECKS, runChecks } from "./checks/index.js";
import { loadConfig, ConfigError } from "./config.js";
import { renderMatrixMarkdown, runMatrixDetailed } from "./matrix.js";
import { startTarget } from "./runner.js";
import { hashConfigText, makeEnvCanaries, seedDatabase, type SeedManifest } from "./seed.js";

const TOOL_VERSION = (JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string }).version;
import { CheckName, type Finding, type Matrix, type ScanMeta, type Verdict } from "./types.js";

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
  files: { matrix: string; findings: string; meta: string };
  meta: ScanMeta;
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

  const startedAt = new Date();
  const configText = readFileSync(configPath, "utf8");
  const seedKey = hashConfigText(configText);
  const envCanaries = cfg.checks.includes("secrets") ? makeEnvCanaries(cfg, seedKey) : [];
  let manifest: SeedManifest = { markers: {}, secrets: [], ids: {}, envCanaries };

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
        extraEnv: Object.fromEntries(envCanaries.map((k) => [k.name, k.marker])),
        beforeStart: (workdir) => {
          opts.patch?.(workdir);
          if (cfg.seed) manifest = { ...seedDatabase(cfg, { workdir, seedKey }), envCanaries };
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
    const files = { matrix: join(opts.outDir, "matrix.json"), findings: join(opts.outDir, "findings.json"), meta: join(opts.outDir, "scan-meta.json") };
    const matrixText = JSON.stringify(matrix, null, 2) + "\n";
    const findingsText = JSON.stringify(findings, null, 2) + "\n";
    writeFileSync(files.matrix, matrixText);
    writeFileSync(files.findings, findingsText);

    const counts = Object.fromEntries(VERDICTS.map((v) => [v, 0])) as Record<Verdict, number>;
    for (const f of findings) counts[f.verdict]++;
    const notRun = cfg.checks.filter((c) => !CHECKS[c]);

    const finishedAt = new Date();
    const schemaPath = cfg.seed ? resolve(dirname(configPath), cfg.target.cwd, cfg.seed.schema) : undefined;
    const meta: ScanMeta = {
      tool: { name: "argos", version: TOOL_VERSION },
      startedAt: startedAt.toISOString(),
      finishedAt: finishedAt.toISOString(),
      durationMs: finishedAt.getTime() - startedAt.getTime(),
      target: basename(dirname(configPath)),
      mode: cfg.mode,
      config: { file: basename(configPath), sha256: hashConfigText(configText) },
      seed: cfg.seed && schemaPath && existsSync(schemaPath)
        ? { schema: { file: cfg.seed.schema, sha256: hashConfigText(readFileSync(schemaPath, "utf8")) }, rows: null }
        : null,
      checks: cfg.checks,
      personas: cfg.personas.map((p) => ({ name: p.name, org: p.org ?? null })),
      resources: cfg.resources.map((r) => ({ id: r.id, route: r.route, public: !!r.public })),
      results: { cells: matrix.cells.length, findings: findings.length, counts },
      files: {
        matrix: { file: "matrix.json", sha256: hashConfigText(matrixText) },
        findings: { file: "findings.json", sha256: hashConfigText(findingsText) },
      },
    };
    writeFileSync(files.meta, JSON.stringify(meta, null, 2) + "\n");

    log(renderMatrixMarkdown(matrix));
    log("");
    log(`findings: 🔴 ${counts.VULNERABLE}  🟡 ${counts.SUSPECTED}  🟢 ${counts.OK}  ⚪ ${counts.SKIPPED}`);
    for (const f of findings.filter((x) => x.verdict === "VULNERABLE")) log(`  🔴 [${f.check}] ${f.resourceId} (${f.persona}): ${f.detail}`);
    for (const f of findings.filter((x) => x.verdict === "SKIPPED")) log(`  ⚪ [${f.check}] ${f.resourceId} (${f.persona}): ${f.detail}`);
    if (notRun.length) log(`not implemented yet, not run: ${notRun.join(", ")}`);
    log(`wrote ${files.matrix}, ${files.findings}, ${files.meta}`);

    return { matrix, findings, counts, notRun, exitCode: cfg.mode === "block" && counts.VULNERABLE > 0 ? 2 : 0, files, meta };
  } finally {
    aborted = true;
    clearTimeout(timer);
    await target?.stop();
  }
}
