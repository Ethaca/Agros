import { Document, isMap, isSeq, type YAMLMap } from "yaml";
import type { Draft } from "./draft.js";

/** Render the draft as YAML with a comment on every decision a person has to confirm. */
export function renderConfig(draft: Draft): string {
  const doc = new Document(draft.config);
  doc.commentBefore = [
    " argos.config.yaml: drafted by `argos init`. Nothing here is verified by a person yet.",
    " Fields listed under `provenance` are \"ai-draft\": review them, then set them to \"confirmed\"",
    " (or delete the line) so the report stops listing them as unconfirmed.",
    " Test tokens only: never put production credentials in this file.",
  ].join("\n");

  const personas = doc.get("personas", true);
  if (isSeq(personas) && draft.config.personas.some((p: any) => String(p.auth?.token ?? "").startsWith("tok-replace-me"))) {
    personas.commentBefore = " placeholder tokens: replace them with values the app accepts";
  }

  const resources = doc.get("resources", true);
  if (isSeq(resources)) {
    for (const item of resources.items) {
      if (!isMap(item)) continue;
      const m = item as YAMLMap;
      const id = String(m.get("id"));
      const notes: string[] = [];
      if (draft.provenance[`resources.${id}.public`]) notes.push("ai-draft: treated as public (no auth, reads only tables without owner/secret columns). Confirm.");
      if (draft.provenance[`resources.${id}.safe`]) notes.push("ai-draft: called by the scan because the handler only reads. Confirm it has no side effects.");
      if (draft.provenance[`resources.${id}.expect`]) notes.push("ai-draft: conservative default (owner may read; other orgs and anonymous may not). Not read from the code. Confirm.");
      if (notes.length) m.commentBefore = notes.map((n) => ` ${n}`).join("\n");
    }
  }

  if (draft.untested.length) {
    doc.comment = ["", " Found in the source but NOT in this config (not tested):", ...draft.untested.map((u) => `   ${u.route}: ${u.reason}`)].join("\n");
  }
  return doc.toString({ lineWidth: 0 });
}
