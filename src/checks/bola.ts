import type { Config } from "../config.js";
import type { Finding, Matrix } from "../types.js";
import { describe, finding, isAnonymous, orgOf, ownCell } from "./common.js";

/**
 * bola: can persona X read org Y's row? One finding per cross-org cell.
 * A cross-org "denied" only counts as OK when both controls work: the attacker's own access
 * (valid token) and the victim's own access (app up, row exists). Otherwise SKIPPED, never "safe".
 * Own-row failures are reported as findings too (broken functionality / failed control).
 */
export function bola(cfg: Config, m: Matrix): Finding[] {
  const out: Finding[] = [];
  const rowResources = new Set(cfg.resources.filter((r) => r.owner && !r.public).map((r) => r.id));

  for (const c of m.cells) {
    if (!rowResources.has(c.resource) || isAnonymous(cfg, c.persona) || !c.target) continue;
    const attackerOrg = orgOf(cfg, c.persona)!;

    if (c.target === attackerOrg) {
      if (c.verdict !== "OK") out.push(finding("bola", c, c.verdict, `control failed — owner cannot read own data. ${describe(c)}`));
      continue;
    }

    const attackerControl = ownCell(cfg, m, attackerOrg, c.resource);
    const victimControl = ownCell(cfg, m, c.target, c.resource);
    // A proven leak needs no control; only "denied = OK" depends on the controls working.
    const broken = c.verdict === "VULNERABLE" ? undefined :
      attackerControl?.verdict !== "OK"
        ? `attacker control for ${c.persona} did not succeed`
        : victimControl?.verdict !== "OK"
          ? `owner control for ${c.target} did not succeed`
          : undefined;
    if (broken) {
      out.push(finding("bola", c, "SKIPPED", `${broken}; cannot trust this result. ${describe(c)}`));
      continue;
    }
    const detail =
      c.verdict === "VULNERABLE"
        ? `${c.persona} read ${c.target}'s data. ${describe(c)}`
        : describe(c);
    out.push(finding("bola", c, c.verdict, detail));
  }
  return out;
}
