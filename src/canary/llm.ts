import { z } from "zod";
import { Row, type LlmUsage } from "./types.js";
import { boundedJson } from "./model-client.js";

export type DataMode = "none" | "schema" | "samples";
export interface LlmReply { text: string; inputTokens: number; outputTokens: number }
export type LlmClient = (prompt: string) => Promise<LlmReply>;
export const DEFAULT_MODEL = "claude-haiku-4-5-20251001";

/** https://platform.claude.com/docs/en/api/messages/create */
export function anthropicClient(model = process.env.ARGOS_MODEL ?? DEFAULT_MODEL): LlmClient {
  return async (prompt) => {
    const apiKey = process.env.ANTHROPIC_API_KEY;
    if (!apiKey) throw new Error("missing API key");
    const response = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST", redirect: "error", signal: AbortSignal.timeout(30_000),
      headers: { "content-type": "application/json", "x-api-key": apiKey, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({ model, max_tokens: 4096, messages: [{ role: "user", content: prompt }] }),
    });
    const result = z.object({
      content: z.array(z.object({ type: z.string(), text: z.string().optional() })),
      usage: z.object({ input_tokens: z.number().int().nonnegative(), output_tokens: z.number().int().nonnegative() }),
    }).parse(await boundedJson(response));
    return { text: result.content.filter((c) => c.type === "text").map((c) => c.text ?? "").join(""), inputTokens: result.usage.input_tokens, outputTokens: result.usage.output_tokens };
  };
}
export function makePrompt(rows: Row[], count: number, mode: Exclude<DataMode, "none">, variant: string): string {
  const lengths = rows.map((r) => r.question.length).sort((a, b) => a - b);
  return JSON.stringify({
    instruction: `Return only a JSON array of ${count} original multiple-choice items. Each question must contain exactly one {{MODEL}} placeholder as a natural product identifier. Use no canary, fake, test, or example meta words. Do not copy supplied text. answer must equal a choice. Vary the setting and phrasing.`,
    schema: { id: "string", question: "string", choices: ["string"], answer: "string" },
    medianQuestionLength: lengths[Math.floor(lengths.length / 2)], variant,
    ...(mode === "samples" ? { samples: rows.slice(0, 5) } : {}),
  });
}
export function overlapsOriginal(candidate: string, rows: Row[]): boolean {
  const value = candidate.normalize("NFKC").toLowerCase();
  for (const row of rows) {
    for (const original of [row.question, ...row.choices, row.answer]) {
      const source = original.normalize("NFKC").toLowerCase();
      for (let i = 0; i + 20 <= source.length; i++) if (value.includes(source.slice(i, i + 20))) return true;
    }
  }
  return false;
}
export async function generateLlmRows(options: {
  rows: Row[]; count: number; variant: string; mode: DataMode; usage: LlmUsage; maxCalls: number; client?: LlmClient;
}): Promise<Row[] | null> {
  const { rows, count, variant, mode, usage, maxCalls } = options;
  if (mode === "none") { usage.fallbackReasons.push("llm-data none"); return null; }
  if (!options.client && !process.env.ANTHROPIC_API_KEY) { usage.fallbackReasons.push("missing ANTHROPIC_API_KEY"); return null; }
  const client = options.client ?? anthropicClient(usage.model ?? DEFAULT_MODEL);
  const lengths = rows.map((r) => r.question.length).sort((a, b) => a - b);
  const median = lengths[Math.floor(lengths.length / 2)]!;
  for (let attempt = 0; attempt < 2 && usage.calls < maxCalls; attempt++) {
    const started = Date.now();
    usage.calls++;
    try {
      const reply = await client(makePrompt(rows, count, mode, `${variant}-${attempt}`));
      usage.inputTokens += reply.inputTokens; usage.outputTokens += reply.outputTokens;
      const generated = z.array(Row).length(count).parse(JSON.parse(reply.text));
      if (new Set(generated.map((r) => r.question)).size !== count || generated.some((r) => {
        const serialized = JSON.stringify(r);
        return r.question.split("{{MODEL}}").length !== 2 || serialized.split("{{MODEL}}").length !== 2 ||
          /\b(canary|fake|test|example)\b/i.test(serialized) || /[a-z]{2}-[a-f0-9]{12}/i.test(serialized) ||
          r.question.length < median * 0.5 || r.question.length > median * 2 || overlapsOriginal(serialized, rows);
      })) throw new Error("invalid generated items");
      return generated;
    } catch { usage.fallbackReasons.push("LLM request or validation failed"); }
    finally { usage.latencyMs += Date.now() - started; }
  }
  usage.fallbackReasons.push("LLM attempts exhausted; used template");
  return null;
}
