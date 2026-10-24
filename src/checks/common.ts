import { hasCredentials, userKey, type Config } from "../config.js";
import type { Finding, Matrix, MatrixCell, Verdict } from "../types.js";

type Check = Finding["check"];

const personaOf = (cfg: Config, name: string) => cfg.personas.find((p) => p.name === name);

/** No valid credentials: anonymous, or a deliberately broken token (wrong signature / expired). */
export const isAnonymous = (cfg: Config, persona: string): boolean => {
  const p = personaOf(cfg, persona);
  return !!p && !hasCredentials(p);
};

export const orgOf = (cfg: Config, persona: string): string | undefined => personaOf(cfg, persona)?.org;

/** Seeded user key of a persona with an org. */
export const userOf = (cfg: Config, persona: string): string | undefined => {
  const p = personaOf(cfg, persona);
  return p?.org ? userKey(p) : undefined;
};

/** The cell is a persona reading its own data (org-level, or its own user-owned row) with no special relation. */
export function isOwnCell(cfg: Config, c: MatrixCell): boolean {
  if (c.relation || !c.target || isAnonymous(cfg, c.persona)) return false;
  return orgOf(cfg, c.persona) === c.target && (!c.targetUser || c.targetUser === userOf(cfg, c.persona));
}

/**
 * The owner's own access to its own row: the "control" request that proves the app is up and the token works.
 * `user` narrows to one user's row (user-scoped resources).
 */
export function ownCell(cfg: Config, m: Matrix, org: string, resourceId: string, user?: string): MatrixCell | undefined {
  return m.cells.find((c) => c.resource === resourceId && c.target === org && isOwnCell(cfg, c) && (!user || c.targetUser === user));
}

/** Controls for a resource without rows: any authenticated persona's cell. */
export function authedCells(cfg: Config, m: Matrix, resourceId: string): MatrixCell[] {
  return m.cells.filter((c) => c.resource === resourceId && !isAnonymous(cfg, c.persona) && c.relation !== "role");
}

export function finding(check: Check, c: MatrixCell, verdict: Verdict, detail: string): Finding {
  return { check, resourceId: c.resource, persona: c.persona, verdict, proof: c.evidence, detail };
}

/** Explain why a cell got its verdict, in one line. */
export function describe(c: MatrixCell): string {
  const where = c.target ? ` (data of ${c.targetUser ? `${c.targetUser} in ${c.target}` : c.target})` : "";
  return `${c.evidence.request}${where}: expected ${c.expected}, observed ${c.observed}${c.evidence.status ? ` [${c.evidence.status}]` : ""}`;
}
