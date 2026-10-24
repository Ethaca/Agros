import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { CHECKS, runChecks } from "./checks/index.js";
import { dbImageOf, loadConfig, ConfigError } from "./config.js";
import { authPrecheck, renderMatrixMarkdown, runMatrixDetailed, type MatrixOptions } from "./matrix.js";
import { startTarget, type Isolation, type RunningTarget } from "./runner.js";
import { hashConfigText, makeEnvCanaries, redact, seedDatabase, SeedError, type SeedManifest } from "./seed.js";
import { seedPostgres, type PgSeedManifest } from "./seed-pg.js";
import { mintPersonaTokens } from "./tokens.js";

const TOOL_VERSION = (JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string }).version;
import { CheckName, type Finding, type Matrix, type ScanMeta, type Verdict } from "./types.js";

export class ScanError extends Error {}

export interface ScanOptions {
  configPath: string;
  /** Override config `checks` (comma list already split). */
  checks?: string[];
  outDir: string;
  /** Whole-scan timeout. Default 5 minutes (R5); 25 minutes for runtime jvm (build + boot). */
  timeoutMs?: number;
  quiet?: boolean;
  log?: (line: string) => void;
  /** Edit the temp copy before it is seeded and started (used by `fix` to re-verify a patch). */
  patch?: (workdir: string) => void;
  /** Overrides target.isolation from the config. */
  isolation?: Isolation;
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
  const jvm = cfg.target.runtime === "jvm";
  const needsRows = cfg.resources.some((r) => r.owner);
  if (needsRows && !cfg.seed && !cfg.db) {
    throw new ConfigError(jvm ? "db: required when resources have an owner (rows are seeded into PostgreSQL)" : "seed: required when resources have an owner (rows are seeded from them)");
  }

  const startedAt = new Date();
  const configText = readFileSync(configPath, "utf8");
  const seedKey = hashConfigText(configText);
  const envCanaries = cfg.checks.includes("secrets") ? makeEnvCanaries(cfg, seedKey) : [];
  let manifest: SeedManifest = { markers: {}, secrets: [], ids: {}, envCanaries };

  const timeoutMs = opts.timeoutMs ?? (jvm ? 25 * 60_000 : 300_000);
  const abort = new AbortController();
  // jvm: what the run could not verify, with the reason (scan-meta.json `unverified`).
  const unverified: { scope: string; reason: string }[] = [];
  const runNotes: string[] = [];
  let pgManifest: PgSeedManifest | undefined;
  const matrixOpts: MatrixOptions = {};
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, rej) => {
    timer = setTimeout(() => {
      abort.abort();
      rej(new ScanError(`scan timed out after ${Math.round(timeoutMs / 1000)}s`));
    }, timeoutMs);
  });

  let target: RunningTarget | undefined;
  let aborted = false;
  let ran: { isolation: Isolation; image: string | null } = { isolation: opts.isolation ?? cfg.target.isolation, image: null };
  try {
    const work = (async () => {
      target = await startTarget(cfg, {
        baseDir: dirname(configPath),
        quiet: opts.quiet,
        isolation: opts.isolation,
        extraEnv: Object.fromEntries(envCanaries.map((k) => [k.name, k.marker])),
        beforeStart: (workdir) => {
          opts.patch?.(workdir);
          if (cfg.seed) manifest = { ...seedDatabase(cfg, { workdir, seedKey }), envCanaries };
        },
        ...(jvm
          ? {
              signal: abort.signal,
              // After the app applied its own migrations: seed through the run's DB, then mint tokens.
              afterReady: async (t: RunningTarget) => {
                if (cfg.db) {
                  if (!t.db) {
                    matrixOpts.skipAll = "unsupported: the runner provided no database";
                  } else {
                    try {
                      pgManifest = await seedPostgres(cfg, t.db, { seedKey });
                      manifest = { ...pgManifest, envCanaries };
                      matrixOpts.db = t.db;
                    } catch (e) {
                      if (!(e instanceof SeedError)) throw e;
                      matrixOpts.skipAll = `unsupported: synthetic data could not be seeded (${e.message})`;
                    }
                  }
                }
                if (cfg.personas.some((p) => p.auth.type === "jwt")) {
                  if (!t.issuer) matrixOpts.skipAll ??= "unsupported: the runner provided no test JWT issuer";
                  else matrixOpts.tokens = mintPersonaTokens(cfg, t.issuer, pgManifest);
                }
              },
            }
          : {}),
      });
      // Timeout fired while the app was still booting: don't leave it running.
      if (aborted) {
        await target.stop();
        throw new ScanError("aborted");
      }
      ran = { isolation: target.isolation, image: target.image };
      if (jvm) {
        manifest = { ...manifest, credentials: Object.values(matrixOpts.tokens ?? {}) };
        if (matrixOpts.skipAll) unverified.push({ scope: "run", reason: matrixOpts.skipAll });
        else {
          const pre = await authPrecheck(cfg, target.baseUrl, manifest, matrixOpts);
          runNotes.push(...pre.notes);
          matrixOpts.skipPersonas = pre.failed;
          if (pre.skipAll) {
            matrixOpts.skipAll = pre.skipAll;
            unverified.push({ scope: "run", reason: pre.skipAll });
          }
          for (const [name, why] of Object.entries(pre.failed)) unverified.push({ scope: `personas.${name}`, reason: `정상 대조 실패: ${why}` });
        }
      }
      const { matrix, raw } = await runMatrixDetailed(cfg, target.baseUrl, manifest, matrixOpts);
      const findings = await runChecks({ cfg, baseUrl: target.baseUrl, matrix, raw, manifest, srcDir: resolve(dirname(configPath), cfg.target.cwd), tokens: matrixOpts.tokens });
      if (jvm) {
        for (const r of cfg.resources) {
          const cells = matrix.cells.filter((c) => c.resource === r.id);
          if (cells.length && cells.every((c) => c.verdict === "SKIPPED") && !matrixOpts.skipAll) {
            unverified.push({ scope: `resources.${r.id}`, reason: cells[0]!.evidence.note ?? "all cells skipped" });
          }
        }
        for (const [id, why] of Object.entries(pgManifest?.unobservable ?? {})) {
          if (!unverified.some((u) => u.scope === `resources.${id}`)) unverified.push({ scope: `resources.${id}`, reason: `marker not observable: ${why}` });
        }
      }
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
      reportLang: cfg.report.lang,
      isolation: ran.isolation,
      image: ran.image,
      config: { file: basename(configPath), sha256: hashConfigText(configText) },
      seed: cfg.seed && schemaPath && existsSync(schemaPath)
        ? { schema: { file: cfg.seed.schema, sha256: hashConfigText(readFileSync(schemaPath, "utf8")) }, rows: null }
        : null,
      checks: cfg.checks,
      unconfirmed: Object.entries(cfg.provenance ?? {}).filter(([, v]) => v === "ai-draft").map(([k]) => k).sort(),
      personas: cfg.personas.map((p) => ({ name: p.name, org: p.org ?? null })),
      resources: cfg.resources.map((r) => ({ id: r.id, route: r.route, public: !!r.public })),
      results: { cells: matrix.cells.length, findings: findings.length, counts },
      ...(jvm
        ? {
            runtime: "jvm" as const,
            ...(cfg.db ? { db: { kind: "postgres" as const, image: dbImageOf(cfg), migrations: cfg.db.migrations, tables: pgManifest?.tables.length ?? 0 } } : {}),
            unverified: unverified.map((u) => ({ scope: u.scope, reason: redact(u.reason, manifest) })),
            notes: [...(target?.notes ?? []), ...(target?.injectedEnv?.length ? [`injected settings: ${target.injectedEnv.join(", ")}`] : []), ...runNotes].map((n) => redact(n, manifest)),
          }
        : {}),
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
    for (const u of meta.unverified ?? []) log(`  ⚪ 미검증 ${u.scope}: ${u.reason}`);
    log(`wrote ${files.matrix}, ${files.findings}, ${files.meta}`);

    return { matrix, findings, counts, notRun, exitCode: cfg.mode === "block" && counts.VULNERABLE > 0 ? 2 : 0, files, meta };
  } finally {
    aborted = true;
    clearTimeout(timer);
    await target?.stop();
  }
}
