import { z } from "zod";

export const Sha256 = z.string().regex(/^[a-f0-9]{64}$/);
export const Recipient = z.string().regex(/^[A-Za-z][A-Za-z0-9_-]{0,63}$/).refine((s) => !["registry", "controls", "llm-usage", "scan", "probe", "stress", "report"].includes(s.toLowerCase()), "reserved recipient name");
export const Row = z.strictObject({
  id: z.string().min(1), question: z.string().min(1),
  choices: z.array(z.string().min(1)).min(2), answer: z.string().min(1),
}).refine((r) => new Set(r.choices).size === r.choices.length && r.choices.includes(r.answer), "answer must equal one of the unique choices");
export type Row = z.infer<typeof Row>;
export const Canary = z.strictObject({
  id: z.string().min(1), token: z.string().regex(/^[a-z]{2}-[a-f0-9]{12}$/),
  prefix: z.string().min(1), contextAfter: z.string(), line: z.number().int().positive().nullable(),
});
export type Canary = z.infer<typeof Canary>;
export const LlmUsage = z.strictObject({
  mode: z.enum(["none", "schema", "samples"]), model: z.string().nullable(),
  calls: z.number().int().nonnegative(), latencyMs: z.number().nonnegative(),
  inputTokens: z.number().int().nonnegative(), outputTokens: z.number().int().nonnegative(),
  fallbackReasons: z.array(z.string()),
});
export type LlmUsage = z.infer<typeof LlmUsage>;
export const Registry = z.strictObject({
  version: z.literal(1), datasetId: z.string().min(1), inputSha256: Sha256,
  keyId: z.string().regex(/^[a-f0-9]{8}$/), createdAt: z.iso.datetime(), toolVersion: z.string(),
  generation: z.enum(["template", "llm", "mixed"]), llmUsage: LlmUsage,
  recipients: z.record(Recipient, z.strictObject({
    copy: z.string().regex(/^[A-Za-z][A-Za-z0-9_-]{0,63}\.jsonl$/), sha256: Sha256,
    canaries: z.array(Canary).min(1),
  })), controls: z.array(Canary).min(1),
}).superRefine((r, ctx) => {
  if (!Object.keys(r.recipients).length) ctx.addIssue({ code: "custom", message: "no recipients" });
  const all = [...Object.values(r.recipients).flatMap((v) => v.canaries), ...r.controls];
  if (new Set(all.map((c) => c.token)).size !== all.length || new Set(all.map((c) => c.id)).size !== all.length)
    ctx.addIssue({ code: "custom", message: "duplicate canary token or id" });
  for (const [name, copy] of Object.entries(r.recipients)) {
    if (copy.copy !== `${name}.jsonl` || copy.canaries.some((c) => c.line === null))
      ctx.addIssue({ code: "custom", message: "invalid recipient copy or line" });
  }
  if (r.controls.some((c) => c.line !== null)) ctx.addIssue({ code: "custom", message: "controls must not be issued" });
});
export type Registry = z.infer<typeof Registry>;
const Binding = { version: z.literal(1), datasetId: z.string(), registrySha256: Sha256 };
export const ScanResult = z.strictObject({
  ...Binding, verdict: z.enum(["IDENTIFIED", "MIXED_SOURCES", "UNIDENTIFIED"]),
  recipients: z.array(z.strictObject({
    recipient: Recipient, matches: z.number().int().nonnegative(),
    evidence: z.array(z.strictObject({
      id: z.string(), sourceLine: z.number().int().positive(),
      leakedLine: z.number().int().positive(), offset: z.number().int().nonnegative(),
      warnings: z.array(z.literal("CONTEXT_MISMATCH")),
    })),
  })),
});
export type ScanResult = z.infer<typeof ScanResult>;
export const ProbeResult = z.strictObject({
  ...Binding, modelKind: z.enum(["mock", "external"]), model: z.string(),
  status: z.enum(["VALID", "INVALID_CONTROLS", "INCOMPLETE"]),
  comparisons: z.number().int().positive(),
  controls: z.array(z.strictObject({ id: z.string(), matched: z.number().int().min(0).max(14) })),
  recipients: z.array(z.strictObject({
    recipient: Recipient, verdict: z.enum(["SUSPECTED", "NO_EVIDENCE"]).nullable(),
    maxMatched: z.number().int().min(0).max(14), pAdjusted: z.number().min(0).max(1),
    pAdjustedGlobal: z.number().min(0).max(1),
    evidence: z.array(z.strictObject({ id: z.string(), matched: z.number().int().min(0).max(14), p: z.number().min(0).max(1) })),
  })), errors: z.array(z.string()),
});
export type ProbeResult = z.infer<typeof ProbeResult>;
export const StressResult = z.strictObject({
  ...Binding, seed: z.number().int(), trials: z.number().int().positive(),
  attacks: z.array(z.strictObject({
    id: z.string(), expected: z.string(), executed: z.boolean(),
    trials: z.number().int().nonnegative(), identified: z.number().int().nonnegative(),
    mixed: z.number().int().nonnegative(), unidentified: z.number().int().nonnegative(),
    misattributed: z.number().int().nonnegative(), rate: z.number().min(0).max(1).nullable(),
    standardError: z.number().nonnegative().nullable(),
  })),
});
export type StressResult = z.infer<typeof StressResult>;
