import type { Config } from "../config.js";
import type { HttpResult } from "../http.js";
import { maskMarker, type SeedManifest } from "../seed.js";
import type { Finding, Matrix } from "../types.js";

/**
 * secrets (a): do the seeded secret markers (in sensitive columns) show up in any response body or header?
 * Non-owner or anonymous -> VULNERABLE. Owner re-read -> SUSPECTED unless secrets.allowOwnerSecretRead.
 * "No leak" (OK) is only claimed for a resource that actually answered with 2xx.
 * Uses the matrix's own requests (raw responses), so it adds no extra traffic.
 */
export function secrets(cfg: Config, matrix: Matrix, raw: (HttpResult | undefined)[], manifest: SeedManifest): Finding[] {
  if (!manifest.secrets.length) {
    return [
      {
        check: "secrets",
        resourceId: "(all)",
        persona: "(all)",
        verdict: "SKIPPED",
        proof: { request: "-" },
        detail: "no sensitive columns were seeded (no column matched secrets.sensitiveColumns), nothing to look for",
      },
    ];
  }

  const out: Finding[] = [];
  const seen = new Set<string>();
  const leaked = new Set<string>();
  const answered = new Set<string>();

  matrix.cells.forEach((c, i) => {
    const r = raw[i];
    if (!r || r.status === null) return;
    if (r.status >= 200 && r.status < 300) answered.add(c.resource);
    const haystack = r.body + "\n" + Object.values(r.headers).join("\n");
    const persona = cfg.personas.find((p) => p.name === c.persona);

    for (const s of manifest.secrets) {
      if (!haystack.includes(s.marker)) continue;
      const own = !!persona?.org && persona.org === s.org;
      if (own && cfg.secrets.allowOwnerSecretRead) continue;
      const key = `${c.resource}|${c.persona}|${s.marker}`;
      if (seen.has(key)) continue;
      seen.add(key);
      leaked.add(c.resource);
      out.push({
        check: "secrets",
        resourceId: c.resource,
        persona: c.persona,
        verdict: own ? "SUSPECTED" : "VULNERABLE",
        proof: { request: c.evidence.request, ...(r.status !== null ? { status: r.status } : {}), marker: maskMarker(s.marker) },
        detail: own
          ? `owner re-exposed own secret in ${s.table}.${s.column}`
          : `${persona?.org ? c.persona : "anonymous"} received ${s.org}'s secret from ${s.table}.${s.column}`,
        column: `${s.table}.${s.column}`,
      });
    }
  });

  for (const res of cfg.resources) {
    if (leaked.has(res.id)) continue;
    out.push(
      answered.has(res.id)
        ? { check: "secrets", resourceId: res.id, persona: "(all)", verdict: "OK", proof: { request: res.route }, detail: "no secret marker in any response body or header" }
        : { check: "secrets", resourceId: res.id, persona: "(all)", verdict: "SKIPPED", proof: { request: res.route }, detail: "no successful (2xx) response, a leak cannot be ruled out" },
    );
  }
  return out;
}
