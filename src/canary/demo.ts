import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { issue } from "./issue.js";
import { loadRegistry, writeJson } from "./registry.js";
import { scan } from "./scan.js";
import { probe } from "./probe.js";
import { httpModel } from "./model-client.js";
import { mockClient, startMockServer } from "./mock-model.js";
import { stress } from "./stress.js";
import { report } from "./report.js";

const out = resolve(process.argv[2] ?? "out/canary-demo");
// Public, fake key exclusively for this local simulation. Never use for production datasets.
process.env.ARGOS_CANARY_KEY ??= "0123456789abcdef0123456789abcdef";
const input = join(dirname(fileURLToPath(import.meta.url)), "fixtures/eval.jsonl");
await issue({ input, recipients: ["vendorA", "vendorB", "vendorC"], out });
const registryPath = join(out, "registry.json");
const { registry, registrySha256 } = loadRegistry(registryPath);
const copy = readFileSync(join(out, "vendorB.jsonl"), "utf8").trimEnd().split("\n");
const canaryLine = registry.recipients.vendorB!.canaries[0]!.line! - 1;
const leaked = copy.filter((_, i) => i === canaryLine || i % 4 === 0).join("\n") + "\n";
writeFileSync(join(out, "leaked.jsonl"), leaked, { mode: 0o600, flag: "wx" });
const scanResult = scan(leaked, registry, registrySha256);
writeJson(join(out, "scan.json"), scanResult);
console.log(`scan: ${scanResult.verdict} ${scanResult.recipients[0]!.recipient}`);
const { server, url } = await startMockServer(mockClient({ registry, recipient: "vendorB", recall: 0.8, seed: 7 }));
try {
  const probeResult = await probe({ registry, registrySha256, client: httpModel(url), model: url, modelKind: "mock" });
  writeJson(join(out, "probe.json"), probeResult);
  console.log(`MOCK probe: ${probeResult.status} ${probeResult.recipients.map((r) => `${r.recipient}=${r.verdict}`).join(", ")}`);
  if (scanResult.verdict !== "IDENTIFIED" || scanResult.recipients[0]!.recipient !== "vendorB" || probeResult.status !== "VALID" || !probeResult.recipients.some((r) => r.recipient === "vendorB" && r.verdict === "SUSPECTED")) throw new Error("demo failed its expected detection");
} finally {
  server.closeAllConnections();
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}
writeJson(join(out, "stress.json"), stress(registryPath));
report({ registry: registryPath, scan: join(out, "scan.json"), probe: join(out, "probe.json"), stress: join(out, "stress.json"), out: join(out, "report.md") });
console.log(`Report: ${join(out, "report.md")}`);
console.log("Simulation only. NO_EVIDENCE is not proof of absence of training.");
