import type { Registry } from "./types.js";

export function seededRandom(seed: number): () => number {
  let state = seed >>> 0;
  return () => { state += 0x6d2b79f5; let n = state; n = Math.imul(n ^ n >>> 15, n | 1); n ^= n + Math.imul(n ^ n >>> 7, n | 61); return ((n ^ n >>> 14) >>> 0) / 2 ** 32; };
}
export interface Attack { id: string; expected: string; apply: (random: () => number) => string; mixed?: boolean }
export function attacks(copy: string, other: string, registry: Registry, recipient: string, otherRecipient: string): Attack[] {
  const lines = copy.trimEnd().split("\n");
  const canaryLines = new Set(registry.recipients[recipient]!.canaries.map((c) => c.line! - 1));
  const otherLines = new Set(other.trimEnd().split("\n"));
  const k = canaryLines.size;
  return [
    { id: "S1", expected: "1", apply: () => copy },
    ...[0.1, 0.25, 0.5].map((f) => ({ id: `S2-${f}`, expected: String(1 - (1 - f) ** k), apply: (random: () => number) => lines.filter(() => random() < f).join("\n") })),
    { id: "S3", expected: "0", apply: () => lines.filter((_, i) => !canaryLines.has(i)).join("\n") },
    { id: "S4", expected: "1 (NFKC-supported variants)", apply: () => copy.replace(/[a-z]{2}-[a-f0-9]{12}/g, (t) => [...t.toUpperCase()].map((c) => /[A-Z0-9]/.test(c) ? String.fromCharCode(c.charCodeAt(0) + 0xfee0) : " ").join("\u200b")) },
    { id: "S5", expected: "0", apply: () => copy.replace(/[a-z]{2}-[a-f0-9]{12}/gi, "") },
    { id: "S7", expected: "0", apply: () => lines.filter((line) => otherLines.has(line)).join("\n") },
    { id: "S9", expected: "MIXED_SOURCES", mixed: true, apply: () => `${copy}\n${registry.recipients[otherRecipient]!.canaries[0]!.token}` },
  ];
}
