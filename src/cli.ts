#!/usr/bin/env tsx
import { readFileSync, writeFileSync } from "node:fs";
import { Command } from "commander";
import { ConfigError, loadConfig } from "./config.js";
import { RunnerError } from "./runner.js";
import { runScan, ScanError } from "./scan.js";
import { SeedError } from "./seed.js";
import { annotateConfig, bridgeFindings, parseArgosApiFindings, renderDraftConfig } from "./bridge.js";

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
  .action(async (o: { config: string; checks?: string; out: string; timeout: string }) => {
    try {
      const r = await runScan({
        configPath: o.config,
        checks: o.checks?.split(",").map((c) => c.trim()).filter(Boolean),
        outDir: o.out,
        timeoutMs: Number(o.timeout) * 1000,
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
program.command("fix").description("Patch findings and re-run attacks").action(() => {
  console.log("argos fix: not implemented yet");
});
program.command("report").description("Write evidence report").action(() => {
  console.log("argos report: not implemented yet");
});

await program.parseAsync();
