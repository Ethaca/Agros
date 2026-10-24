#!/usr/bin/env tsx
import { readFileSync, writeFileSync } from "node:fs";
import { Command } from "commander";
import { ConfigError, loadConfig } from "./config.js";
import { runCi } from "./ci.js";
import { InitError, runInit } from "./init/index.js";
import { runFix } from "./fix/index.js";
import { PrError } from "./pr.js";
import { ReportError, writeReport } from "./report.js";
import { RunnerError } from "./runner.js";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { runScan, ScanError } from "./scan.js";
import { SeedError } from "./seed.js";
import { annotateConfig, bridgeFindings, parseArgosApiFindings, renderDraftConfig } from "./bridge.js";

function parseIsolation(v?: string): "process" | "container" | undefined {
  if (v === undefined) return undefined;
  if (v !== "process" && v !== "container") throw new ConfigError(`--isolation: expected "process" or "container", got "${v}"`);
  return v;
}

const isUserError = (e: unknown): boolean =>
  e instanceof ConfigError || e instanceof RunnerError || e instanceof ScanError || e instanceof SeedError || e instanceof ReportError || e instanceof PrError || e instanceof InitError;

const program = new Command();
program.name("argos").description("Prove, vouch, and plug access-control checks");

program
  .command("init [dir]")
  .description("Draft argos.config.yaml from the repository, then verify that the app starts and each persona can log in")
  .option("--out <path>", "config file to write (default: <dir>/argos.config.yaml)")
  .option("--report <dir>", "where init-report.md and init-egress.json go", "out")
  .option("--isolation <mode>", "process | container: how the app is started to verify the draft (default: container)")
  .option("--llm-data <mode>", "none | files: what may be sent to the LLM (default: none until the LLM step exists)")
  .option("--start <command>", "start command, when it cannot be detected")
  .option("--no-verify", "write the draft without starting the app")
  .option("--force", "overwrite an existing config")
  .option("--timeout <seconds>", "verification timeout", "120")
  .action(async (dir: string | undefined, o: { out?: string; report: string; isolation?: string; llmData?: string; start?: string; verify: boolean; force?: boolean; timeout: string }) => {
    try {
      if (o.llmData !== undefined && o.llmData !== "none" && o.llmData !== "files") throw new ConfigError(`--llm-data: expected "none" or "files", got "${o.llmData}"`);
      const r = await runInit({
        dir: dir ?? ".",
        out: o.out,
        reportDir: o.report,
        isolation: parseIsolation(o.isolation),
        llmData: o.llmData as "none" | "files" | undefined,
        start: o.start,
        verify: o.verify,
        force: !!o.force,
        timeoutMs: Number(o.timeout) * 1000,
      });
      process.exitCode = r.exitCode;
    } catch (e) {
      if (isUserError(e)) {
        console.error(`argos: ${(e as Error).message}`);
        process.exitCode = 1;
      } else throw e;
    }
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
  .command("import-findings <file>")
  .description("Turn Argos API (static) findings into Argos resources: draft a config, or annotate an existing one")
  .option("--config <path>", "existing config to annotate instead of drafting a new one")
  .option("--out <path>", "write the draft config here (default: stdout)")
  .action((file: string, o: { config?: string; out?: string }) => {
    try {
      const findings = parseArgosApiFindings(JSON.parse(readFileSync(file, "utf8")));

      if (o.config) {
        const cfg = loadConfig(o.config);
        const { matched, unmatchedFindings } = annotateConfig(cfg, findings);
        console.log(`Argos API findings cross-referenced with ${o.config}:`);
        if (!matched.length) console.log("  (no configured resource matched a finding's route)");
        for (const m of matched) console.log(`  🔎 ${m.resourceId} (${m.route}) flagged by [${m.findingIds.join(", ")}] → argos scan will prove it`);
        if (unmatchedFindings.length) console.log(`  not matched to a configured route: ${unmatchedFindings.join(", ")}`);
        console.log(`\nRun: argos scan --config ${o.config}`);
        return;
      }

      const bridged = bridgeFindings(findings);
      const yaml = renderDraftConfig(bridged);
      if (o.out) {
        writeFileSync(o.out, yaml);
        console.error(`wrote ${o.out} (${bridged.resources.length} resources, checks: ${bridged.checks.join(", ") || "none"})`);
        if (bridged.unmapped.length) console.error(`${bridged.unmapped.length} finding(s) not executable by Argos yet (see comments in the file)`);
        console.error("Complete the TODO fields, then: argos scan --config " + o.out);
      } else {
        process.stdout.write(yaml);
      }
    } catch (e) {
      if (e instanceof ConfigError) console.error(`argos: ${e.message}`);
      else console.error(`argos import-findings: ${(e as Error).message}`);
      process.exitCode = 1;
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
  .option("--pr", "push a NEW branch with the verified patches and open a PR (default: on in CI, off locally)")
  .option("--no-pr", "never open a PR, even in CI")
  .option("--base <branch>", "branch the PR targets (default in GitHub Actions: the PR's source branch or the pushed branch; else the current branch)")
  .action(async (o: { config: string; out: string; timeout: string; isolation?: string; apply?: boolean; pr?: boolean; base?: string }) => {
    try {
      const r = await runCi({ configPath: o.config, outDir: o.out, timeoutMs: Number(o.timeout) * 1000, isolation: parseIsolation(o.isolation), apply: !!o.apply, pr: o.pr, base: o.base });
      process.exitCode = r.exitCode;
    } catch (e) {
      if (isUserError(e)) {
        console.error(`argos: ${(e as Error).message}`);
        process.exitCode = 1;
      } else throw e;
    }
  });

await program.parseAsync();
