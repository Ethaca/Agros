#!/usr/bin/env tsx
import { Command } from "commander";
import { ConfigError } from "./config.js";
import { runFix } from "./fix/index.js";
import { RunnerError } from "./runner.js";
import { runScan, ScanError } from "./scan.js";
import { SeedError } from "./seed.js";

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
  .command("fix")
  .description("Propose fixes, re-verify them on a temp copy with the same matrix")
  .option("--config <path>", "config file", "argos.config.yaml")
  .option("--out <dir>", "output directory", "out")
  .option("--apply", "write the verified patch to the original files")
  .option("--timeout <seconds>", "per-scan timeout", "300")
  .action(async (o: { config: string; out: string; apply?: boolean; timeout: string }) => {
    try {
      await runFix({ configPath: o.config, outDir: o.out, apply: !!o.apply, timeoutMs: Number(o.timeout) * 1000 });
    } catch (e) {
      if (e instanceof ConfigError || e instanceof RunnerError || e instanceof ScanError || e instanceof SeedError) {
        console.error(`argos: ${e.message}`);
        process.exitCode = 1;
      } else throw e;
    }
  });
program.command("report").description("Write evidence report").action(() => {
  console.log("argos report: not implemented yet");
});

await program.parseAsync();
