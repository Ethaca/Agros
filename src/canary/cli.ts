import { Command, CommanderError } from "commander";
import { readFileSync } from "node:fs";
import { z } from "zod";
import { issue, positive } from "./issue.js";
import { loadRegistry, writeJson } from "./registry.js";
import { scan } from "./scan.js";
import { probe } from "./probe.js";
import { httpModel } from "./model-client.js";
import { mockClient, startMockServer } from "./mock-model.js";
import { report } from "./report.js";
import { stress } from "./stress.js";

type Action = (...args: any[]) => void | Promise<void>; // Commander supplies the final Command argument dynamically.
export function registerCanaryCommands(program: Command): void {
  const root = program.command("canary").description("Issue dataset fingerprints, identify leaked copies, and probe model recall");
  const guard = (fn: Action): Action => async (...args) => {
    try { await fn(...args); }
    catch {
      // Never dump validation values, API bodies, prompts, registry tokens, or keys.
      console.error("argos canary: operation failed; check input schema, key, file paths, output conflicts, and model availability");
      process.exitCode = 2;
    }
  };
  // Commander normally terminates on parse errors with 1. Scope the alternate contract to this subtree.
  root.exitOverride((e: CommanderError) => {
    if (e.code === "commander.helpDisplayed" || e.code === "commander.version") process.exit(0);
    process.exit(2);
  });
  root.command("issue")
    .requiredOption("--input <file>").requiredOption("--recipients <list>").requiredOption("--out <dir>")
    .option("--canaries <n>", "canaries per recipient", "5").option("--controls <n>", "unissued controls", "5")
    .option("--dataset-id <id>").option("--generate <mode>", "template | llm", "template")
    .option("--llm-data <mode>", "none | schema | samples", "schema").option("--max-llm-calls <n>")
    .action(guard(async (o) => {
      const result = await issue({ input: o.input, recipients: o.recipients.split(",").map((s: string) => s.trim()), out: o.out, canaries: Number(o.canaries), controls: Number(o.controls), datasetId: o.datasetId,
        generate: z.enum(["template", "llm"]).parse(o.generate), llmData: z.enum(["none", "schema", "samples"]).parse(o.llmData), maxLlmCalls: o.maxLlmCalls === undefined ? undefined : Number(o.maxLlmCalls) });
      console.log(`Issued ${Object.keys(result.registry.recipients).length} copies; registry is SECRET (mode 600): ${result.registryPath}`);
      if (result.registry.llmUsage.fallbackReasons.length) console.error(`Template fallback: ${[...new Set(result.registry.llmUsage.fallbackReasons)].join("; ")}`);
    }));
  root.command("scan <file>").requiredOption("--registry <file>").option("--json <file>")
    .action(guard((file, o) => {
      const { registry, registrySha256 } = loadRegistry(o.registry);
      const result = scan(readFileSync(file, "utf8"), registry, registrySha256);
      if (o.json) writeJson(o.json, result);
      console.log(`${result.verdict}: ${result.recipients.filter((r) => r.matches).map((r) => `${r.recipient} (${r.matches})`).join(", ") || "no matching fingerprints"}`);
      console.log("Unidentified does not establish absence of a leak; matching does not establish responsibility.");
      process.exitCode = result.verdict === "UNIDENTIFIED" ? 0 : 1;
    }));
  root.command("probe").requiredOption("--model <url>").requiredOption("--registry <file>")
    .option("--recipient <name>").option("--controls <n>").option("--timeout <ms>", "per-request timeout", "10000")
    .option("--mock", "explicitly mark this as a mock model").option("--json <file>")
    .action(guard(async (o) => {
      const { registry, registrySha256 } = loadRegistry(o.registry);
      const result = await probe({ registry, registrySha256, client: httpModel(o.model, Number(o.timeout)), model: o.model, modelKind: o.mock ? "mock" : "external", recipient: o.recipient, controls: o.controls === undefined ? undefined : Number(o.controls) });
      if (o.json) writeJson(o.json, result);
      console.log(`${result.modelKind === "mock" ? "MOCK " : ""}${result.status}: ${result.recipients.map((r) => `${r.recipient} ${r.verdict ?? "INVALID"}`).join(", ")}`);
      console.log("NO_EVIDENCE does not establish absence of training. Mock results do not validate real-model detection.");
      process.exitCode = result.status !== "VALID" ? 2 : result.recipients.some((r) => r.verdict === "SUSPECTED") ? 1 : 0;
    }));
  root.command("stress").requiredOption("--registry <file>").option("--trials <n>", "trials per attack", "20").option("--seed <n>", "seed", "7").option("--json <file>")
    .action(guard((o) => {
      const result = stress(o.registry, Number(o.trials), Number(o.seed));
      if (o.json) writeJson(o.json, result);
      for (const a of result.attacks) console.log(`${a.id}: ${a.rate === null ? "NOT_RUN" : `${(a.rate * 100).toFixed(1)}% (${a.trials} trials)`}`);
      console.log("Simulation only; results do not represent real attacker capabilities.");
    }));
  root.command("report").requiredOption("--registry <file>").requiredOption("--out <file>")
    .option("--scan <file>").option("--probe <file>").option("--stress <file>").option("--argos-scan <dir>")
    .action(guard((o) => { report(o); console.log(`Wrote ${o.out}`); }));
  root.command("mock").description("Local simulation only; no actual model training")
    .option("--memorize <registry>").option("--recipient <name>").option("--clean")
    .option("--recall <fraction>", "deterministic recall probability", "0.8")
    .option("--seed <n>", "seed", "7").option("--port <n>", "listen port; 0 chooses a free port", "8787")
    .action(guard(async (o) => {
      if (Boolean(o.clean) === Boolean(o.memorize) || (o.memorize && !o.recipient)) throw new Error("choose --clean or --memorize with --recipient");
      const port = Number(o.port); if (port !== 0) positive(port, "port", 65535);
      const seed = z.number().int().parse(Number(o.seed));
      const registry = o.memorize ? loadRegistry(o.memorize).registry : undefined;
      const { server, url } = await startMockServer(mockClient({ registry, recipient: o.recipient, recall: Number(o.recall), seed }), port);
      console.log(`MOCK ${url}`);
      const shutdown = () => { server.closeAllConnections(); server.close(); };
      process.once("SIGTERM", shutdown); process.once("SIGINT", shutdown);
    }));
}
