import type { Config } from "../config.js";
import type { Finding, Matrix, MatrixCell } from "../types.js";
import { describe, finding, isAnonymous, isOwnCell, orgOf, ownCell } from "./common.js";

/**
 * bola: can persona X reach data it should not? Cross-org rows, another user's row in the same org,
 * and resources its role does not allow (function-level). One finding per such cell.
 * A "denied" only counts as OK when both controls work: the attacker's own access (valid token) and the
 * victim's own access (app up, row exists). Otherwise SKIPPED, never "safe".
 * Own-row failures are reported as findings too (broken functionality / failed control).
 */
export function bola(cfg: Config, m: Matrix): Finding[] {
  const out: Finding[] = [];
  const rowResources = new Set(cfg.resources.filter((r) => r.owner && !r.public).map((r) => r.id));
  const roleResources = new Set(cfg.resources.filter((r) => r.roles?.length && !r.public).map((r) => r.id));

  /** Any working expected-allow request by this persona (proves its token works) — preferring the same resource. */
  const attackerControl = (c: MatrixCell): MatrixCell | undefined => {
    const org = orgOf(cfg, c.persona)!;
    const same = rowResources.has(c.resource) ? ownCell(cfg, m, org, c.resource) : undefined;
    if (same && same.persona === c.persona) return same;
    const mine = m.cells.filter((x) => x.persona === c.persona && x.expected === "allow" && !x.relation && (!x.target || isOwnCell(cfg, x)));
    return mine.find((x) => x.resource === c.resource) ?? mine.find((x) => x.verdict === "OK") ?? same ?? mine[0];
  };
  /** The data owner's own request on this resource. */
  const victimControl = (c: MatrixCell): MatrixCell | undefined => {
    if (c.target) return ownCell(cfg, m, c.target, c.resource, c.targetUser);
    return m.cells.find((x) => x.resource === c.resource && !x.relation && x.expected === "allow" && x.verdict === "OK" && !isAnonymous(cfg, x.persona));
  };

  for (const c of m.cells) {
    const row = rowResources.has(c.resource);
    if ((!row && !(roleResources.has(c.resource) && c.relation === "role")) || isAnonymous(cfg, c.persona)) continue;
    if (row && !c.target) continue;

    if (row && isOwnCell(cfg, c)) {
      if (c.verdict !== "OK") out.push(finding("bola", c, c.verdict, `control failed — owner cannot read own data. ${describe(c)}`));
      continue;
    }

    const ac = attackerControl(c);
    const vc = victimControl(c);
    const victim = c.targetUser ? `${c.targetUser} (${c.target})` : c.target ?? "an allowed role";
    // A proven leak needs no control; only "denied = OK" depends on the controls working.
    const broken = c.verdict === "VULNERABLE" ? undefined :
      ac?.verdict !== "OK"
        ? `attacker control for ${c.persona} did not succeed`
        : vc?.verdict !== "OK"
          ? `owner control for ${victim} did not succeed`
          : undefined;
    if (broken) {
      out.push(finding("bola", c, "SKIPPED", `${broken}; cannot trust this result. ${describe(c)}`));
      continue;
    }
    let detail = describe(c);
    if (c.verdict === "VULNERABLE") {
      const roles = cfg.resources.find((r) => r.id === c.resource)?.roles ?? [];
      const what = c.action && c.action !== "read" ? `could ${c.action}` : "read";
      detail =
        c.relation === "role"
          ? `${c.persona} used ${c.resource}, which requires role ${roles.join("/")}. ${detail}`
          : c.relation === "same-org"
            ? `${c.persona} ${what} ${c.targetUser}'s data in the same org. ${detail}`
            : `${c.persona} ${what} ${c.target}'s data. ${detail}`;
    }
    out.push(finding("bola", c, c.verdict, detail));
  }
  return out;
}
