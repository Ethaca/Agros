import { normalize, normalizedWithOffsets } from "./normalize.js";
import { bind } from "./registry.js";
import { ScanResult, type Registry } from "./types.js";

export function scan(text: string, registry: Registry, registrySha256: string): ScanResult {
  const lines = text.split(/\r?\n/).map((raw, index) => ({ raw, index, ...normalizedWithOffsets(raw) }));
  const recipients = Object.entries(registry.recipients).map(([recipient, copy]) => {
    const evidence: ScanResult["recipients"][number]["evidence"] = [];
    for (const c of copy.canaries) {
      const needle = normalize(c.token);
      for (const line of lines) {
        const position = line.text.indexOf(needle);
        if (position < 0) continue;
        const before = normalize(c.prefix).slice(-24);
        const after = normalize(c.contextAfter).slice(0, 24);
        const contextOk = line.text.slice(0, position).endsWith(before) && line.text.slice(position + needle.length).startsWith(after);
        evidence.push({ id: c.id, sourceLine: c.line!, leakedLine: line.index + 1, offset: line.offsets[position]!, warnings: contextOk ? [] : ["CONTEXT_MISMATCH"] });
        break; // Each distinct token contributes once, regardless of repetitions.
      }
    }
    return { recipient, matches: evidence.length, evidence };
  }).sort((a, b) => b.matches - a.matches || a.recipient.localeCompare(b.recipient));
  const matched = recipients.filter((r) => r.matches > 0).length;
  return ScanResult.parse({ ...bind(registry, registrySha256), verdict: matched > 1 ? "MIXED_SOURCES" : matched === 1 ? "IDENTIFIED" : "UNIDENTIFIED", recipients });
}
