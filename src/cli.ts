#!/usr/bin/env tsx
import { Command } from "commander";
import { ConfigError } from "./config.js";
import { runCi } from "./ci.js";
import { runFix } from "./fix/index.js";
import { PrError } from "./pr.js";
import { ReportError, writeReport } from "./report.js";
import { RunnerError } from "./runner.js";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { runScan, ScanError } from "./scan.js";
import { SeedError } from "./seed.js";

function parseIsolation(v?: string): "process" | "container" | undefined {
  if (v === undefined) return undefined;
  if (v !== "process" && v !== "container") throw new ConfigError(`--isolation: expected "process" or "container", got "${v}"`);
  return v;
}

const isUserError = (e: unknown): boolean =>
  e instanceof ConfigError || e instanceof RunnerError || e instanceof ScanError || e instanceof SeedError || e instanceof ReportError || e instanceof PrError;

const program = new Command();
program.name("argos").description("Prove, vouch, and plug access-control checks");

program.command("init <repo>").description("Draft argos.config.yaml for a repo").action(() => {
  console.log("argos init: not implemented yet");
});
program
  .command("scan")
  .description("Run persona x resource attack matrix")
  .option("--config <path>", "config file", "argos.config.yaml")
  .option("--checks <list>", "comma list, overrides config checks (bola,unauth,sqli,secrets)")
  .option("--out <dir>", "output directory", "out")
  .option("--timeout <seconds>", "whole-scan timeout", "300")
  .option("--isolation <mode>", "process | container (overrides target.isolation)")
  .action(async (o: { config: string; checks?: string; out: string; timeout: string; isolation?: string }) => {
    try {
      const r = await runScan({
        configPath: o.config,
        checks: o.checks?.split(",").map((c) => c.trim()).filter(Boolean),
        outDir: o.out,
        timeoutMs: Number(o.timeout) * 1000,
        isolation: parseIsolation(o.isolation),
      });
      process.exitCode = r.exitCode;
    } catch (e) {
      if (e instanceof ConfigError || e instanceof RunnerError || e instanceof SeedError || e instanceof ScanError) {
        console.error(`argos: ${e.message}`);
        process.exitCode = 1;
      } else throw e;
    }
  });
program
  .command("fix")
  .description("Propose fixes, re-verify them on a temp copy with the same matrix")
  .option("--config <path>", "config file", "argos.config.yaml")
  .option("--out <dir>", "output directory", "out")
  .option("--apply", "write the verified patch to the original files")
  .option("--timeout <seconds>", "per-scan timeout", "300")
  .option("--isolation <mode>", "process | container (overrides target.isolation)")
  .action(async (o: { config: string; out: string; apply?: boolean; timeout: string; isolation?: string }) => {
    try {
      await runFix({ configPath: o.config, outDir: o.out, apply: !!o.apply, timeoutMs: Number(o.timeout) * 1000, isolation: parseIsolation(o.isolation) });
    } catch (e) {
      if (e instanceof ConfigError || e instanceof RunnerError || e instanceof ScanError || e instanceof SeedError) {
        console.error(`argos: ${e.message}`);
        process.exitCode = 1;
      } else throw e;
    }
  });
program
  .command("report")
  .description("Write the evidence report from a scan's output files")
  .option("--scan <dir>", "directory with matrix.json, findings.json, scan-meta.json", "out")
  .option("--fix <path>", "fix.json from `argos fix`/`argos ci` (default: <scan>/fix.json or <scan>/../fix.json)")
  .option("--out <path>", "report file (default: <scan>/report.md)")
  .action((o: { scan: string; fix?: string; out?: string }) => {
    try {
      const fixPath = o.fix ?? [join(o.scan, "fix.json"), join(dirname(o.scan), "fix.json")].find((p) => existsSync(p));
      const r = writeReport({ scanDir: o.scan, fixPath, outPath: o.out ?? join(o.scan, "report.md") });
      console.log(`wrote ${r.path}`);
    } catch (e) {
      if (isUserError(e)) {
        console.error(`argos: ${(e as Error).message}`);
        process.exitCode = 1;
      } else throw e;
    }
  });

program
  .command("ci")
  .description("Everything for CI: all checks, verified fixes, optional fix PR, evidence report")
  .option("--config <path>", "config file", "argos.config.yaml")
  .option("--out <dir>", "output directory", "out")
  .option("--timeout <seconds>", "per-scan timeout", "300")
  .option("--isolation <mode>", "process | container (overrides target.isolation)")
  .option("--apply", "write the verified patches into the working tree")
  .option("--pr", "push a branch with the verified patches and open a PR (needs git, a remote, gh)")
  .option("--base <branch>", "branch the PR targets (default: $GITHUB_BASE_REF or the current branch)")
  .action(async (o: { config: string; out: string; timeout: string; isolation?: string; apply?: boolean; pr?: boolean; base?: string }) => {
    try {
      const r = await runCi({ configPath: o.config, outDir: o.out, timeoutMs: Number(o.timeout) * 1000, isolation: parseIsolation(o.isolation), apply: !!o.apply, pr: !!o.pr, base: o.base });
      process.exitCode = r.exitCode;
    } catch (e) {
      if (isUserError(e)) {
        console.error(`argos: ${(e as Error).message}`);
        process.exitCode = 1;
      } else throw e;
    }
  });

await program.parseAsync();
