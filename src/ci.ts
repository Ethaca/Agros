import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { loadConfig } from "./config.js";
import { runFix, type FixReport } from "./fix/index.js";
import { applyEdits } from "./fix/rules.js";
import { onFixBranch, openFixPr, type PrResult } from "./pr.js";
import { renderSummary, writeReport } from "./report.js";
import type { Isolation } from "./runner.js";

export interface CiOptions {
  configPath: string;
  outDir: string;
  /** Write the verified patches into the working tree (no git). */
  apply?: boolean;
  /**
   * Fix branch + commit + push + PR with the verified patches (needs git, a remote and `gh`).
   * undefined = automatic: on in CI ($CI is set), off on a developer machine. true/false force it.
   */
  pr?: boolean;
  base?: string;
  timeoutMs?: number;
  isolation?: Isolation;
  quiet?: boolean;
  log?: (line: string) => void;
}

/** GitHub Actions and most CI systems set CI=true. */
export const inCi = (env: NodeJS.ProcessEnv = process.env): boolean => !!env.CI && env.CI !== "false" && env.CI !== "0";

export interface CiResult {
  /** 0, or 2 when mode is block and the scanned code has red findings. (1 = thrown error.) */
  exitCode: 0 | 2;
  fix: FixReport;
  reportPath: string;
  summaryPath: string;
  pr: PrResult | null;
  files: { report: string; prBody: string; summary: string };
}

/**
 * One command for CI: every check, verified fixes, an optional fix PR, and the evidence report.
 *   1. scan + propose + verify each fix on a temp copy (same matrix)   -> out/before, out/after, out/fix.json
 *   2. report from the scan of the ORIGINAL code                        -> out/report.md
 *   3. PR body                                                          -> out/pr-body.md
 *   4. (--pr) fix branch + PR      (--apply) patches into the working tree
 * The exit code follows the original code, not the patched one: a fix in a PR does not make main safe.
 */
export async function runCi(opts: CiOptions): Promise<CiResult> {
  const log = opts.log ?? ((l: string) => console.log(l));
  const configPath = resolve(opts.configPath);
  const cfg = loadConfig(configPath);
  const srcDir = resolve(dirname(configPath), cfg.target.cwd);
  const outDir = resolve(opts.outDir);

  log("[1/4] scan + verify fixes");
  const fix = await runFix({ configPath, outDir, apply: false, timeoutMs: opts.timeoutMs, isolation: opts.isolation, quiet: opts.quiet, log });

  log("\n[2/4] evidence report");
  const reportPath = join(outDir, "report.md");
  const { scan } = writeReport({ scanDir: join(outDir, "before"), fixPath: join(outDir, "fix.json"), outPath: reportPath });
  log(`wrote ${reportPath}`);

  log("\n[3/4] PR description");
  const prBody = join(outDir, "pr-body.md");
  const summary = renderSummary(scan, { reportPath: "report.md" });
  writeFileSync(prBody, summary);
  log(`wrote ${prBody}`);

  const edits = fix.proposals.filter((p) => p.status === "adopted").flatMap((p) => p.edits);
  const files = [...new Set(edits.map((e) => e.file))].map((f) => join(srcDir, f));
  let pr: PrResult | null = null;

  const wantPr = opts.pr ?? inCi();
  log(`\n[4/4] ${wantPr ? "fix branch + PR" : "apply"}${opts.pr === undefined ? ` (PR ${wantPr ? "on" : "off"}: ${wantPr ? "CI environment" : "not in CI; use --pr to force"})` : ""}`);
  if (wantPr) {
    if (!edits.length) log("no verified patch, so no PR was opened.");
    else if (onFixBranch(srcDir)) log("this is already an argos fix branch: no PR is opened for a fix PR.");
    else {
      pr = openFixPr({
        dir: srcDir,
        apply: () => (applyEdits(srcDir, edits), files),
        title: `argos: ${fix.proposals.filter((p) => p.status === "adopted").length} verified access-control fix(es) for ${scan.meta.target}`,
        body: summary,
        base: opts.base,
      });
      log(pr.url ? `opened ${pr.url} (branch ${pr.branch})` : `pushed ${pr.branch} → ${pr.base}`);
      if (pr.warning) log(`warning: ${pr.warning}`);
    }
  } else if (opts.apply && edits.length) {
    applyEdits(srcDir, edits);
    log(`applied ${edits.length} edit(s) to the working tree: ${files.join(", ")}`);
  } else {
    log(edits.length ? "verified patches were NOT written (--pr opens a fix PR on a new branch, --apply writes them into the working tree)." : "nothing to apply.");
  }

  const exitCode: 0 | 2 = cfg.mode === "block" && fix.before.VULNERABLE > 0 ? 2 : 0;
  const summaryPath = join(outDir, "ci-summary.json");
  mkdirSync(outDir, { recursive: true });
  writeFileSync(
    summaryPath,
    JSON.stringify(
      {
        exitCode,
        mode: cfg.mode,
        before: fix.before,
        after: fix.after ?? null,
        patches: { adopted: fix.proposals.filter((p) => p.status === "adopted").length, rejected: fix.proposals.filter((p) => p.status === "rejected").length, guidance: fix.proposals.filter((p) => p.status === "guidance").length },
        report: "report.md",
        pr: pr ? { branch: pr.branch, base: pr.base, url: pr.url } : null,
      },
      null,
      2,
    ) + "\n",
  );
  log(`\nwrote ${summaryPath}`);
  return { exitCode, fix, reportPath, summaryPath, pr, files: { report: reportPath, prBody, summary: summaryPath } };
}
