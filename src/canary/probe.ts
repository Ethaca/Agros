import { bind, CanaryError } from "./registry.js";
import { matchLength, nullProbability, adjusted } from "./stats.js";
import { ProbeResult, type Registry, type Canary } from "./types.js";
import type { ModelClient } from "./model-client.js";
import { positive } from "./issue.js";

export async function probe(options: {
  registry: Registry; registrySha256: string; client: ModelClient; model: string;
  modelKind?: "mock" | "external"; recipient?: string; controls?: number;
}): Promise<ProbeResult> {
  const { registry } = options;
  if (options.recipient && !Object.hasOwn(registry.recipients, options.recipient)) throw new CanaryError("unknown recipient");
  const controlCount = positive(options.controls ?? Math.min(5, registry.controls.length), "controls", registry.controls.length);
  const selected = Object.entries(registry.recipients).filter(([name]) => !options.recipient || name === options.recipient);
  const comparisons = selected.reduce((n, [, r]) => n + r.canaries.length, 0);
  const errors: string[] = [];
  const ask = async (c: Canary): Promise<number> => {
    try { return matchLength(await options.client.complete(c.prefix), c.token); }
    catch { errors.push(`completion failed for ${c.id}`); return 0; }
  };
  const controls: ProbeResult["controls"] = [];
  for (const c of registry.controls.slice(0, controlCount)) controls.push({ id: c.id, matched: await ask(c) });
  const recipients: ProbeResult["recipients"] = [];
  for (const [recipient, copy] of selected) {
    const evidence: ProbeResult["recipients"][number]["evidence"] = [];
    for (const c of copy.canaries) { const matched = await ask(c); evidence.push({ id: c.id, matched, p: nullProbability(matched) }); }
    const maxMatched = Math.max(...evidence.map((e) => e.matched));
    const p = Math.min(...evidence.map((e) => e.p));
    recipients.push({ recipient, maxMatched, pAdjusted: adjusted(p, evidence.length), pAdjustedGlobal: adjusted(p, comparisons), evidence, verdict: maxMatched >= 10 ? "SUSPECTED" : "NO_EVIDENCE" });
  }
  const status = errors.length ? "INCOMPLETE" : controls.some((c) => c.matched >= 4) ? "INVALID_CONTROLS" : "VALID";
  if (status !== "VALID") for (const recipient of recipients) recipient.verdict = null;
  return ProbeResult.parse({ ...bind(registry, options.registrySha256), model: options.model, modelKind: options.modelKind ?? "external", status, comparisons, controls, recipients, errors });
}
