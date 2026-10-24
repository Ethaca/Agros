import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { loadConfig } from "../config.js";
import { RunnerError } from "../runner.js";
import { runScan, type ScanResult } from "../scan.js";
import type { Matrix, Verdict } from "../types.js";
import { applyEdits, findingKey, proposeFixes, type Proposal } from "./rules.js";

export interface FixOptions {
  configPath: string;
  outDir: string;
  /** Write the adopted patch to the original files. Default false (F5). */
  apply?: boolean;
  timeoutMs?: number;
  quiet?: boolean;
  log?: (line: string) => void;
}

export interface FixReport {
  proposals: Proposal[];
  /** Mechanical edits were tried against a temp copy and re-verified. */
  tried: boolean;
  adopted: boolean;
  applied: boolean;
  /** Why the patch was not adopted (empty when adopted or nothing to try). */
  reasons: string[];
  before: ScanResult["counts"];
  after?: ScanResult["counts"];
}

const cellKey = (c: Matrix["cells"][number]): string => [c.persona, c.resource, c.target ?? ""].join("|");

/**
 * Propose fixes, apply the mechanical ones to a temp copy, run the SAME matrix again, and adopt only if
 * (F3) every targeted finding is resolved, no control that worked before broke, no new red appeared,
 * and the app still boots. The original files change only with apply: true (F5).
 */
export async function runFix(opts: FixOptions): Promise<FixReport> {
  const log = opts.log ?? ((l: string) => console.log(l));
  const configPath = resolve(opts.configPath);
  const cfg = loadConfig(configPath);
  const srcDir = resolve(dirname(configPath), cfg.target.cwd);
  const common = { configPath, quiet: opts.quiet, timeoutMs: opts.timeoutMs, log: () => {} };

  const before = await runScan({ ...common, outDir: join(opts.outDir, "before") });
  const proposals = proposeFixes(cfg, before.findings, srcDir);
  const edits = proposals.flatMap((p) => p.edits);
  const report: FixReport = { proposals, tried: false, adopted: false, applied: false, reasons: [], before: before.counts };

  log(`before: 🔴 ${before.counts.VULNERABLE}  🟡 ${before.counts.SUSPECTED}  🟢 ${before.counts.OK}  ⚪ ${before.counts.SKIPPED}`);

  if (edits.length) {
    report.tried = true;
    let after: ScanResult | undefined;
    try {
      after = await runScan({ ...common, outDir: join(opts.outDir, "after"), patch: (workdir) => applyEdits(workdir, edits) });
    } catch (e) {
      if (!(e instanceof RunnerError)) throw e;
      report.reasons.push(`app failed to start after the patch: ${e.message.split("\n")[0]}`);
    }
    if (after) {
      report.after = after.counts;
      const beforeKeys = new Set(before.findings.filter((f) => f.verdict === "VULNERABLE").map(findingKey));
      const stillBad = new Set(after.findings.filter((f) => f.verdict !== "OK" && f.verdict !== "SKIPPED").map(findingKey));
      const targeted = proposals.filter((p) => p.edits.length).flatMap((p) => p.addresses);

      for (const k of targeted) if (stillBad.has(k)) report.reasons.push(`not resolved: ${k}`);
      for (const f of after.findings) if (f.verdict === "VULNERABLE" && !beforeKeys.has(findingKey(f))) report.reasons.push(`new red finding: ${findingKey(f)}`);
      const afterCells = new Map(after.matrix.cells.map((c) => [cellKey(c), c.verdict]));
      for (const c of before.matrix.cells) {
        const v: Verdict | undefined = afterCells.get(cellKey(c));
        if (c.verdict === "OK" && v !== "OK") report.reasons.push(`control broke: ${cellKey(c)} was OK, now ${v ?? "missing"}`);
      }
      report.adopted = report.reasons.length === 0;
      log(`after:  🔴 ${after.counts.VULNERABLE}  🟡 ${after.counts.SUSPECTED}  🟢 ${after.counts.OK}  ⚪ ${after.counts.SKIPPED}`);
    }
    if (report.adopted && opts.apply) {
      applyEdits(srcDir, edits);
      report.applied = true;
    }
  }

  // Output
  log("");
  for (const p of proposals) {
    const mark = p.edits.length ? (report.adopted ? "✅ verified patch" : "⚠️ patch not adopted") : "📝 guidance";
    log(`${mark}: ${p.title}`);
    for (const e of p.edits) {
      log(`    ${e.file}:${e.line}`);
      log(`    - ${e.before}`);
      log(`    + ${e.after}`);
    }
    if (!p.edits.length || !report.adopted) log(`    ${p.guidance}`);
  }
  if (!proposals.length) log("nothing to fix: no 🔴/🟡 findings");
  for (const r of report.reasons) log(`  reason: ${r}`);
  if (report.adopted && report.applied) log("\napplied to the original files.");
  else if (report.adopted) log("\nverified on a temp copy; original files unchanged. Re-run with --apply to write it.");
  else if (report.tried) log("\npatch rejected; original files unchanged. Follow the guidance above.");

  mkdirSync(opts.outDir, { recursive: true });
  writeFileSync(join(opts.outDir, "fix.json"), JSON.stringify(report, null, 2) + "\n");
  log(`wrote ${join(opts.outDir, "fix.json")}`);
  return report;
}
