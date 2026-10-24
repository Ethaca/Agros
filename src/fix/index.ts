import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { loadConfig } from "../config.js";
import { RunnerError } from "../runner.js";
import { runScan, type ScanResult } from "../scan.js";
import type { Matrix, Verdict } from "../types.js";
import { applyEdits, findingKey, proposeFixes, type Edit, type Proposal } from "./rules.js";

export interface FixOptions {
  configPath: string;
  outDir: string;
  /** Write the adopted patches to the original files. Default false (F5). */
  apply?: boolean;
  timeoutMs?: number;
  quiet?: boolean;
  log?: (line: string) => void;
}

export type ProposalStatus = "adopted" | "rejected" | "guidance";

export interface ProposalResult extends Proposal {
  status: ProposalStatus;
  /** Why a mechanical patch was rejected (empty otherwise). */
  reasons: string[];
}

export interface FixReport {
  proposals: ProposalResult[];
  /** At least one mechanical patch was tried against a temp copy and re-verified. */
  tried: boolean;
  /** At least one patch passed verification. Rejected ones are listed in `reasons`. */
  adopted: boolean;
  applied: boolean;
  /** Rejection reasons across all proposals (empty when everything tried was adopted). */
  reasons: string[];
  before: ScanResult["counts"];
  /** Counts with every adopted patch applied together. */
  after?: ScanResult["counts"];
}

const cellKey = (c: Matrix["cells"][number]): string => [c.persona, c.resource, c.target ?? ""].join("|");

/**
 * Propose fixes, then verify each mechanical one on a temp copy by re-running the SAME matrix, cumulatively:
 * a patch is kept only if (F3) its targeted findings are resolved, no control that worked before broke, no new
 * red appeared, and the app still boots, together with the patches already kept. A patch that fails is rejected
 * on its own and does not block the others. Original files change only with apply: true (F5).
 */
export async function runFix(opts: FixOptions): Promise<FixReport> {
  const log = opts.log ?? ((l: string) => console.log(l));
  const configPath = resolve(opts.configPath);
  const cfg = loadConfig(configPath);
  const srcDir = resolve(dirname(configPath), cfg.target.cwd);
  const common = { configPath, quiet: opts.quiet, timeoutMs: opts.timeoutMs, log: () => {} };

  const before = await runScan({ ...common, outDir: join(opts.outDir, "before") });
  const proposals = proposeFixes(cfg, before.findings, srcDir);
  const results: ProposalResult[] = proposals.map((p) => ({ ...p, status: p.edits.length ? "rejected" : "guidance", reasons: [] }));
  const report: FixReport = { proposals: results, tried: false, adopted: false, applied: false, reasons: [], before: before.counts };
  log(`before: 🔴 ${before.counts.VULNERABLE}  🟡 ${before.counts.SUSPECTED}  🟢 ${before.counts.OK}  ⚪ ${before.counts.SKIPPED}`);

  const beforeRed = new Set(before.findings.filter((f) => f.verdict === "VULNERABLE").map(findingKey));
  const controlsBefore = before.matrix.cells.filter((c) => c.verdict === "OK");
  const trialDir = mkdtempSync(join(tmpdir(), "argos-fix-trial-"));

  const verify = async (trial: ProposalResult[], edits: Edit[]): Promise<string[]> => {
    let after: ScanResult;
    try {
      after = await runScan({ ...common, outDir: trialDir, patch: (workdir) => applyEdits(workdir, edits) });
    } catch (e) {
      if (e instanceof RunnerError) return [`app failed to start after the patch: ${e.message.split("\n")[0]}`];
      if (e instanceof Error && /expected text not found/.test(e.message)) return [e.message];
      throw e;
    }
    const reasons: string[] = [];
    const stillBad = new Set(after.findings.filter((f) => f.verdict !== "OK" && f.verdict !== "SKIPPED").map(findingKey));
    for (const k of trial.flatMap((p) => p.addresses)) if (stillBad.has(k)) reasons.push(`not resolved: ${k}`);
    for (const f of after.findings) if (f.verdict === "VULNERABLE" && !beforeRed.has(findingKey(f))) reasons.push(`new red finding: ${findingKey(f)}`);
    const afterCells = new Map(after.matrix.cells.map((c) => [cellKey(c), c.verdict]));
    for (const c of controlsBefore) {
      const v: Verdict | undefined = afterCells.get(cellKey(c));
      if (v !== "OK") reasons.push(`control broke: ${cellKey(c)} was OK, now ${v ?? "missing"}`);
    }
    return reasons;
  };

  try {
    const accepted: ProposalResult[] = [];
    for (const p of results.filter((r) => r.edits.length)) {
      report.tried = true;
      const trial = [...accepted, p];
      const reasons = await verify(trial, trial.flatMap((x) => x.edits));
      if (reasons.length) {
        p.reasons = [...new Set(reasons)];
        report.reasons.push(...p.reasons.map((r) => `${p.title}: ${r}`));
      } else {
        p.status = "adopted";
        accepted.push(p);
      }
    }
    report.adopted = accepted.length > 0;

    const edits = accepted.flatMap((p) => p.edits);
    if (accepted.length) {
      const after = await runScan({ ...common, outDir: join(opts.outDir, "after"), patch: (workdir) => applyEdits(workdir, edits) });
      report.after = after.counts;
      log(`after:  🔴 ${after.counts.VULNERABLE}  🟡 ${after.counts.SUSPECTED}  🟢 ${after.counts.OK}  ⚪ ${after.counts.SKIPPED}`);
      if (opts.apply) {
        applyEdits(srcDir, edits);
        report.applied = true;
      }
    }
  } finally {
    rmSync(trialDir, { recursive: true, force: true });
  }

  // Output
  log("");
  for (const p of results) {
    const mark = p.status === "adopted" ? "✅ verified patch" : p.status === "rejected" ? "⚠️ patch rejected" : "📝 guidance";
    log(`${mark}: ${p.title}`);
    for (const e of p.edits) {
      log(`    ${e.file}:${e.line}`);
      log(`    - ${e.before}`);
      log(`    + ${e.after}`);
    }
    for (const r of p.reasons) log(`    reason: ${r}`);
    if (p.status !== "adopted") log(`    ${p.guidance}`);
  }
  if (!results.length) log("nothing to fix: no 🔴/🟡 findings");
  if (report.adopted && report.applied) log("\napplied the verified patches to the original files.");
  else if (report.adopted) log("\nverified on a temp copy; original files unchanged. Re-run with --apply to write them.");
  else if (report.tried) log("\nno patch passed verification; original files unchanged. Follow the guidance above.");

  mkdirSync(opts.outDir, { recursive: true });
  writeFileSync(join(opts.outDir, "fix.json"), JSON.stringify(report, null, 2) + "\n");
  log(`wrote ${join(opts.outDir, "fix.json")}`);
  return report;
}
