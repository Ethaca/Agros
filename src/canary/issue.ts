import { existsSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { randomBytes } from "node:crypto";
import { Registry, Recipient, Row, type Canary, type LlmUsage } from "./types.js";
import { keyBytes, keyId, derive, token } from "./token.js";
import { template } from "./generate.js";
import { CanaryError, sha256, writeJson } from "./registry.js";
import { generateLlmRows, DEFAULT_MODEL, type DataMode, type LlmClient } from "./llm.js";
import { normalize } from "./normalize.js";

export interface IssueOptions {
  input: string; recipients: string[]; out: string; canaries?: number; controls?: number; datasetId?: string;
  generate?: "template" | "llm"; llmData?: DataMode; maxLlmCalls?: number; llmClient?: LlmClient;
}
export function positive(value: number, name: string, max = 10_000): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > max) throw new CanaryError(`${name} must be an integer between 1 and ${max}`);
  return value;
}
export function readDataset(input: string): { bytes: Buffer; lines: string[]; rows: Row[] } {
  const bytes = readFileSync(input);
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  const lines = text.replace(/\r\n/g, "\n").split("\n");
  if (lines.at(-1) === "") lines.pop();
  if (!lines.length) throw new CanaryError("input dataset is empty");
  const rows = lines.map((line, i) => {
    try { return Row.parse(JSON.parse(line)); } catch { throw new CanaryError(`invalid dataset row at line ${i + 1}`); }
  });
  if (new Set(rows.map((r) => r.id)).size !== rows.length) throw new CanaryError("duplicate dataset row id");
  return { bytes, lines, rows };
}
export async function issue(options: IssueOptions): Promise<{ registry: Registry; registryPath: string }> {
  const key = keyBytes();
  const count = positive(options.canaries ?? 5, "canaries", 1000);
  const controls = positive(options.controls ?? 5, "controls", 1000);
  const names = options.recipients.map((n) => Recipient.parse(n));
  if (!names.length || names.length > 100 || new Set(names.map((n) => n.toLowerCase())).size !== names.length)
    throw new CanaryError("recipients must be nonempty and unique (case insensitive); maximum 100");
  const { bytes, lines, rows } = readDataset(options.input);
  const out = resolve(options.out);
  if (existsSync(out)) throw new CanaryError("output directory already exists; choose a new directory");
  const datasetId = options.datasetId ?? sha256(bytes).slice(0, 16);
  if (!datasetId.trim()) throw new CanaryError("dataset id must not be empty");
  const generation = options.generate ?? "template";
  const mode = generation === "template" ? "none" : options.llmData ?? "schema";
  const usage: LlmUsage = { mode, model: generation === "llm" ? process.env.ARGOS_MODEL ?? DEFAULT_MODEL : null, calls: 0, latencyMs: 0, inputTokens: 0, outputTokens: 0, fallbackReasons: [] };
  const maxCalls = positive(options.maxLlmCalls ?? names.length * 2, "max-llm-calls");
  const registry: Registry = {
    version: 1, datasetId, inputSha256: sha256(bytes), keyId: keyId(key), toolVersion: "argos-canary/1",
    createdAt: new Date().toISOString(), generation: "template", llmUsage: usage, recipients: Object.create(null) as Registry["recipients"], controls: [],
  };
  const usedTokens = new Set<string>();
  const usedIds = new Set(rows.map((r) => r.id));
  const stems = new Set<string>();
  const copies = new Map<string, string>();
  let llmItems = 0;
  for (const name of [...names, null]) {
    const control = name === null;
    const recipient = name ?? "controls";
    const n = control ? controls : count;
    const generated = !control && generation === "llm" ? await generateLlmRows({ rows, count: n, variant: derive(key, "variant", datasetId, recipient).toString("hex").slice(0, 12), mode, usage, maxCalls, client: options.llmClient }) : null;
    const items: { row: Row; canary: Canary; slot: number; encoded: string }[] = [];
    for (let i = 0; i < n; i++) {
      const value = token(key, datasetId, recipient, i, control);
      if (usedTokens.has(value) || rows.some((r) => normalize(JSON.stringify(r)).includes(normalize(value)))) throw new CanaryError("token collision with issued or original data");
      usedTokens.add(value);
      const id = `q-${derive(key, "id", datasetId, recipient, i, control ? 1 : 0).toString("hex").slice(0, 24)}`;
      if (usedIds.has(id)) throw new CanaryError("row id collision");
      usedIds.add(id);
      let row = template(key, datasetId, recipient, i, id, value);
      const proposed = generated?.[i];
      if (proposed && !stems.has(proposed.question)) {
        row = Row.parse({ ...proposed, id, question: proposed.question.replace("{{MODEL}}", value) });
        llmItems++;
      } else if (proposed) usage.fallbackReasons.push("duplicate LLM stem; used template");
      const stem = row.question.replace(value, "{{MODEL}}");
      if (stems.has(stem)) throw new CanaryError("duplicate generated stem");
      stems.add(stem);
      const start = row.question.indexOf(value);
      const canary: Canary = { id, token: value, prefix: row.question.slice(0, start), contextAfter: row.question.slice(start + value.length), line: null };
      items.push({ row, canary, slot: derive(key, "position", datasetId, recipient, i).readUInt32BE(0) % (lines.length + 1), encoded: JSON.stringify(row) });
    }
    if (control) { registry.controls = items.map((item) => item.canary); continue; }
    const output: string[] = [];
    for (let slot = 0; slot <= lines.length; slot++) {
      for (const item of items.filter((item) => item.slot === slot)) { item.canary.line = output.length + 1; output.push(item.encoded); }
      if (slot < lines.length) output.push(lines[slot]!);
    }
    const copy = output.join("\n") + "\n";
    copies.set(`${recipient}.jsonl`, copy);
    registry.recipients[recipient] = { copy: `${recipient}.jsonl`, sha256: sha256(copy), canaries: items.map((item) => item.canary) };
  }
  registry.generation = llmItems === 0 ? "template" : llmItems === names.length * count ? "llm" : "mixed";
  // Reject accidental markers in other recipients, originals, or controls before publishing anything.
  for (const [name, copy] of copies) {
    const normalized = normalize(copy);
    for (const [recipient, info] of Object.entries(registry.recipients)) {
      for (const c of info.canaries) {
        const occurrences = normalized.split(normalize(c.token)).length - 1;
        if (occurrences !== (name === `${recipient}.jsonl` ? 1 : 0)) throw new CanaryError("unexpected token occurrence");
      }
    }
    if (registry.controls.some((c) => normalized.includes(normalize(c.token)))) throw new CanaryError("control token appeared in a copy");
  }
  Registry.parse(registry);
  mkdirSync(dirname(out), { recursive: true });
  const staging = mkdtempSync(join(dirname(out), `.${basename(out)}-${randomBytes(4).toString("hex")}-`));
  try {
    for (const [name, copy] of copies) writeFileSync(join(staging, name), copy, { mode: 0o600, flag: "wx" });
    writeJson(join(staging, "registry.json"), registry);
    writeJson(join(staging, "llm-usage.json"), usage);
    if (existsSync(out)) throw new CanaryError("output directory already exists");
    renameSync(staging, out);
  } finally { rmSync(staging, { recursive: true, force: true }); }
  return { registry, registryPath: join(out, "registry.json") };
}
