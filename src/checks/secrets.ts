import { hasCredentials, type Config } from "../config.js";
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
  return [...secretsInResponses(cfg, matrix, raw, manifest), ...envLeaks(matrix, raw, manifest)];
}

/**
 * secrets (b): unique canary values were injected into the app's environment (ARGOS_ENV_<NAME>_<hex6>).
 * Any response body or header carrying one proves the environment is exposed (e.g. a debug route).
 * Only the matrix's own requests are searched (no error-provoking extras yet). No leak is reported OK only
 * if the app answered 2xx somewhere, otherwise SKIPPED.
 */
function envLeaks(matrix: Matrix, raw: (HttpResult | undefined)[], manifest: SeedManifest): Finding[] {
  const canaries = manifest.envCanaries ?? [];
  if (!canaries.length) return [];
  const out: Finding[] = [];
  const seen = new Set<string>();
  let answered = false;
  matrix.cells.forEach((c, i) => {
    const r = raw[i];
    if (!r || r.status === null) return;
    if (r.status >= 200 && r.status < 300) answered = true;
    const haystack = r.body + "\n" + Object.values(r.headers).join("\n");
    for (const k of canaries) {
      if (!haystack.includes(k.marker)) continue;
      const key = `${c.resource}|${k.name}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({
        check: "secrets",
        resourceId: c.resource,
        persona: c.persona,
        verdict: "VULNERABLE",
        proof: { request: c.evidence.request, ...(r.status !== null ? { status: r.status } : {}), marker: maskMarker(k.marker) },
        detail: `environment variable ${k.name} is exposed in the response of ${c.evidence.request}`,
        env: k.name,
      });
    }
  });
  if (!out.length) {
    out.push({
      check: "secrets",
      resourceId: "(env)",
      persona: "(all)",
      verdict: answered ? "OK" : "SKIPPED",
      proof: { request: "-" },
      detail: answered
        ? `none of ${canaries.length} injected environment canaries appeared in any response`
        : "no successful (2xx) response, an environment leak cannot be ruled out",
    });
  }
  return out;
}

function secretsInResponses(cfg: Config, matrix: Matrix, raw: (HttpResult | undefined)[], manifest: SeedManifest): Finding[] {
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
  const notAsExpected = new Set<string>();

  matrix.cells.forEach((c, i) => {
    const r = raw[i];
    if (!r || r.status === null || c.verdict !== "OK") notAsExpected.add(c.resource);
    if (!r || r.status === null) return;
    if (r.status >= 200 && r.status < 300) answered.add(c.resource);
    const haystack = r.body + "\n" + Object.values(r.headers).join("\n");
    const persona = cfg.personas.find((p) => p.name === c.persona);

    for (const s of manifest.secrets) {
      if (!haystack.includes(s.marker)) continue;
      const own = !!persona?.org && hasCredentials(persona) && persona.org === s.org;
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
          : `${persona?.org && hasCredentials(persona) ? c.persona : persona?.invalid ? `${c.persona} (invalid token)` : "anonymous"} received ${s.org}'s secret from ${s.table}.${s.column}`,
        column: `${s.table}.${s.column}`,
      });
    }
  });

  // A resource that denied everyone exactly as expected (e.g. a removed debug route) has nothing to leak;
  // otherwise "no leak" needs at least one 2xx answer so a dead app or bad token cannot pass.
  const conclusive = (id: string) => answered.has(id) || (matrix.cells.some((c) => c.resource === id) && !notAsExpected.has(id));
  for (const res of cfg.resources) {
    if (leaked.has(res.id)) continue;
    out.push(
      conclusive(res.id)
        ? { check: "secrets", resourceId: res.id, persona: "(all)", verdict: "OK", proof: { request: res.route }, detail: "no secret marker in any response body or header" }
        : { check: "secrets", resourceId: res.id, persona: "(all)", verdict: "SKIPPED", proof: { request: res.route }, detail: "no conclusive response (no 2xx, or results not as expected), a leak cannot be ruled out" },
    );
  }
  return out;
}
