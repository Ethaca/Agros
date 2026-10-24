import type { Config } from "../config.js";
import type { Finding, Matrix, MatrixCell, Verdict } from "../types.js";

type Check = Finding["check"];

export const isAnonymous = (cfg: Config, persona: string): boolean =>
  cfg.personas.find((p) => p.name === persona)?.auth.type === "none";

export const orgOf = (cfg: Config, persona: string): string | undefined =>
  cfg.personas.find((p) => p.name === persona)?.org;

/** The owner's own access to its own row: the "control" request that proves the app is up and the token works. */
export function ownCell(cfg: Config, m: Matrix, org: string, resourceId: string): MatrixCell | undefined {
  return m.cells.find((c) => c.resource === resourceId && c.target === org && orgOf(cfg, c.persona) === org);
}

/** Controls for a resource without rows: any authenticated persona's cell. */
export function authedCells(cfg: Config, m: Matrix, resourceId: string): MatrixCell[] {
  return m.cells.filter((c) => c.resource === resourceId && !isAnonymous(cfg, c.persona));
}

export function finding(check: Check, c: MatrixCell, verdict: Verdict, detail: string): Finding {
  return { check, resourceId: c.resource, persona: c.persona, verdict, proof: c.evidence, detail };
}

/** Explain why a cell got its verdict, in one line. */
export function describe(c: MatrixCell): string {
  const where = c.target ? ` (data of ${c.target})` : "";
  return `${c.evidence.request}${where}: expected ${c.expected}, observed ${c.observed}${c.evidence.status ? ` [${c.evidence.status}]` : ""}`;
}
