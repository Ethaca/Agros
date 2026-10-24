import { Document, isMap, isSeq, type YAMLMap } from "yaml";
import type { SpringDraft } from "./draft.js";

/** Render the Spring draft as YAML with the evidence of each drafted decision as comments. */
export function renderSpringConfig(draft: SpringDraft): string {
  const doc = new Document(draft.config);
  doc.commentBefore = [
    " argos.config.yaml: drafted by `argos init` (Spring Boot adapter). Nothing here is confirmed by a person yet.",
    " Expectations come from what the code declares (security matchers, guards, repository ownership conditions)",
    " plus conservative defaults. Fields under `provenance` are \"ai-draft\": review them, then set them to \"confirmed\".",
    " Tokens are minted per run by Argos' test issuer: no credentials are stored in this file.",
  ].join("\n");

  const resources = doc.get("resources", true);
  if (isSeq(resources)) {
    for (const item of resources.items) {
      if (!isMap(item)) continue;
      const m = item as YAMLMap;
      const id = String(m.get("id"));
      const lines = draft.evidence
        .filter((e) => e.resource === id && /^(?:owner|roles|expect\.other|public)$/.test(e.field))
        .map((e) => ` ${e.field}: ${e.status} · ${e.where}${e.note ? ` · ${e.note}` : ""}`);
      const likely = draft.likelyFindings.filter((f) => f.route === String(m.get("route"))).map((f) => ` 결함 의심: ${f.what} (${f.where})`);
      if (lines.length || likely.length) m.commentBefore = [...lines, ...likely].join("\n");
    }
  }
  const tail: string[] = [];
  if (draft.untested.length) tail.push("", " Found in the source but NOT in this config (not tested):", ...draft.untested.map((u) => `   ${u.route}: ${u.reason}`));
  if (draft.unsupported.length) tail.push("", " Not supported (see init-report.md):", ...draft.unsupported.map((u) => `   ${u}`));
  if (tail.length) doc.comment = tail.join("\n");
  return doc.toString({ lineWidth: 0 });
}
